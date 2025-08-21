from __future__ import annotations
import json
import logging
import os
import re
import subprocess
from pathlib import Path

from typing import List

from ossbom.model.ossbom import OSSBOM
from ossbom.model.component import Component
from ossbom.model.dependency_env import DependencyEnv

logger = logging.getLogger(__name__)


class GitResolve:
    """
    Example github resolved value:
    "git+ssh://git@github.com/ossprey/example_malicious_javascript.git#cd3954ceeb60dd14abc065c909d9c9e1ce9d34e5",
    """

    def __init__(self, resolved):
        self.resolved = resolved
        if not self.resolved.startswith("git+"):
            raise ValueError("Invalid Git resolved value")

        self.url = self.resolved.split("+", 1)[1].split("#", 1)[0]
        self.version = self.resolved.split("#", 1)[1]
        self.name = self.url.split("/", 3)[-1].split(".git")[0]

    def get_type(self):
        return "github"

    def get_name(self):
        return self.name

    def get_version(self):
        return self.version


def resolve_github_duplicates(components: list[Component]) -> list[Component]:

    def hash(name, version, locations):
        ret = name + "-" + version + "-" + "-".join(locations)
        return ret

    # Get a list of npm names, versions and locations from GH components
    github_npm_details = set()
    github_components = [comp for comp in components if comp.type == "github"]
    for comp in github_components:
        metadata = comp.metadata or {}
        github_npm_details.add(
            hash(
                metadata.get("npm_name", ""),
                metadata.get("npm_version", ""),
                comp.location,
            )
        )

    logger.debug(github_npm_details)

    # Remove any NPM packages that match these details
    returned_components = []
    for comp in components:
        if comp.type == "npm":
            if hash(comp.name, comp.version, comp.location) not in github_npm_details:
                returned_components.append(comp)
            else:
                print(f"not appended: {comp.name}, {comp.version}")
        else:
            returned_components.append(comp)
    # returned_components = [
    #    comp
    #    for comp in components
    #    if comp.type == "npm"
    #    and hash(comp.name, comp.version, comp.location) not in github_npm_details
    # ]

    return returned_components


def exec_command(command: str, cwd: str | None = None) -> str:
    try:
        # Run the yarn command with the specified cwd
        result = subprocess.run(
            command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd if cwd else None,  # Explicitly set to None if not used
            check=True,
        )
        # Parse the output
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error("Error while running yarn:", e)
        return e.stdout


def node_modules_directory_exists(project_folder: str | os.PathLike[str]) -> bool:
    return os.path.isdir(os.path.join(project_folder, "node_modules"))


def find_package_json_files(base_path: str | os.PathLike[str]) -> List[str]:
    package_files = []
    for root, dirs, files in os.walk(base_path):
        if "package.json" in files:
            package_files.append(Path(root) / "package.json")
    return package_files


def get_all_node_modules_packages(
    project_folder: str | os.PathLike[str],
) -> List[Component]:

    packages = []

    # Get all instances of the package.json file in the node_modules directory
    package_files = find_package_json_files(
        os.path.join(project_folder, "node_modules")
    )

    # Add all packages to the list
    for package_file in package_files:
        with open(package_file) as f:
            data = json.load(f)
            if "name" in data and "version" in data:
                name = data["name"]
                version = data["version"]

                # Make sure name is valid
                if name.startswith("<%="):
                    continue

                # Extract the name and version for each package
                packages.append({"name": name, "version": version})

    components = [
        Component.create(
            name=component["name"],
            version=component["version"],
            env=DependencyEnv.PROD.value,
            type="npm",
            source="node_modules",
        )
        for component in packages
    ]

    return components


def package_lock_file_exists(project_folder: str | os.PathLike[str]) -> bool:
    return os.path.isfile(os.path.join(project_folder, "package-lock.json"))


def get_all_package_lock_packages(
    project_folder: str | os.PathLike[str],
) -> List[Component]:
    # Get all packages in the package-lock.json file
    with open(os.path.join(project_folder, "package-lock.json")) as f:
        data = json.load(f)

    components = []
    for name, package in data["packages"].items():
        name = name.rsplit("node_modules/", 1)[-1]
        if name == "":
            continue
        version = package["version"]
        source = "package-lock.json"
        env = DependencyEnv.PROD.value
        is_github = package.get("resolved", "").find("github.com") != -1
        if is_github:
            # Create a github component
            type = "github"
            git_details = GitResolve(package["resolved"])
            metadata = {"npm_name": name, "npm_version": version}
            name = git_details.get_name()
            version = git_details.get_version()
            component = Component.create(
                name=name,
                version=version,
                env=env,
                type=type,
                source=source,
                metadata=metadata,
            )
        else:
            # Create an NPM package
            type = "npm"
            component = Component.create(
                name=name, version=version, env=env, type=type, source=source
            )
        components.append(component)

    return components


def package_json_file_exists(project_folder: str | os.PathLike[str]) -> bool:
    return os.path.isfile(os.path.join(project_folder, "package.json"))


def get_all_package_json_packages(project_folder: str | os.PathLike[str]) -> List[dict]:
    # Get all packages in the package.json file
    with open(os.path.join(project_folder, "package.json")) as f:
        data = json.load(f)

        deps = [
            {"name": dependency, "version": data["dependencies"][dependency]}
            for dependency in data["dependencies"]
        ]
        deps.extend(
            [
                {"name": dependency, "version": data["devDependencies"][dependency]}
                for dependency in data["devDependencies"]
            ]
        )

    return deps


def run_npm_dry_run(project_folder: str | os.PathLike[str]) -> str:
    return exec_command("npm install --dry-run --verbose", str(project_folder))


def get_all_npm_dry_run_packages(project_folder: str | os.PathLike[str]) -> List[dict]:
    # Get all packages from npm install --dry-run --verbose

    ret = []

    # Run the command
    result = run_npm_dry_run(project_folder)

    # Parse the output
    for line in result.split("\n"):
        # when the line starts with add
        if line.startswith("add"):
            # Extract the package name and version
            name = line.split(" ")[1]
            version = line.split(" ")[2]
            ret.append({"name": name, "version": version})

    # Extract the packages
    return ret


def yarn_lock_file_exists(project_folder: str | os.PathLike[str]) -> bool:
    return os.path.isfile(os.path.join(project_folder, "yarn.lock"))


def get_all_yarn_lock_packages(
    project_folder: str | os.PathLike[str],
) -> List[Component]:
    # Get all packages in the yarn.lock file
    file_path = os.path.join(project_folder, "yarn.lock")
    with open(file_path, "r") as f:
        content = f.read()

    # Regex to match package entries and their version
    package_regex = r'^(?:"|)([^\s"][^"]*)(?:"|):\n\s+version\s+"([^"]+)"'
    # Filter out all commented out lines first (starting with #)
    content = "\n".join(
        line for line in content.splitlines() if not line.strip().startswith("#")
    )
    # Find all matches in the yarn.lock content
    matches = re.finditer(package_regex, content, re.MULTILINE)

    package_data = []
    for match in matches:
        package_names = match.group(
            1
        )  # Full package spec (can include multiple package names)
        version = match.group(2)  # Version

        # Split package names if there are multiple (comma-separated)
        for name in package_names.split(", "):

            # Remove the last @ and everything after it
            name = name.rsplit("@", 1)[0].strip()

            # Validate the name is not an alias
            alias_match = re.match(r"([^@]+)@npm:([^@]+)", name)

            if alias_match:
                _, name = alias_match.groups()

            package_data.append({"name": name, "version": version.strip()})

    components = [
        Component.create(
            name=component["name"],
            version=component["version"],
            env=DependencyEnv.PROD.value,
            type="npm",
            source="yarn.lock",
        )
        for component in package_data
    ]

    return components


def run_yarn_install(project_folder: str | os.PathLike[str]) -> str:
    return exec_command(
        "yarn install --check-files -non-interactive", str(project_folder)
    )


def get_all_yarn_list_packages(
    project_folder: str | os.PathLike[str],
) -> List[Component]:
    # Get all packages from yarn list

    ret = []

    # Run the command
    result = exec_command("yarn list --json --no-progress", str(project_folder))

    list_json = result.strip().split("\n")[-1]

    # Parse the output
    data = json.loads(list_json)

    # Extract the packages
    for package in data["data"]["trees"]:
        name_and_version = package["name"].rsplit("@", 1)
        ret.append(
            Component.create(
                name=name_and_version[0],
                version=name_and_version[1],
                env=DependencyEnv.PROD.value,
                type="npm",
                source="yarn list",
            )
        )

    return ret


# Global functions
def update_sbom_from_npm(
    ossbom: OSSBOM, project_folder: str | os.PathLike[str]
) -> OSSBOM:

    # get all versions of a package in the node_modules directory
    if node_modules_directory_exists(project_folder):
        components = get_all_node_modules_packages(project_folder)
        ossbom.add_components(components)

    # get all packages in the package-lock.json file
    if package_lock_file_exists(project_folder):
        components = get_all_package_lock_packages(project_folder)
        ossbom.add_components(components)

    # npm install --dry-run --verbose - appears to be broken TODO fix
    # components = get_all_npm_dry_run_packages(project_folder)
    # ossbom.add_components([Component.create(name=component["name"], version=component["version"], env=DependencyEnv.PROD, type="npm", source="install") for component in components])

    return ossbom


def update_sbom_from_yarn(
    ossbom: OSSBOM, project_folder: str | os.PathLike[str], run_install: bool = False
) -> OSSBOM:

    if run_install:
        run_yarn_install(project_folder)

    # get all versions of a package in the node_modules directory
    if node_modules_directory_exists(project_folder):
        components = get_all_node_modules_packages(project_folder)
        ossbom.add_components(components)

    # get all packages in the package-lock.json file
    if yarn_lock_file_exists(project_folder):
        components = get_all_yarn_lock_packages(project_folder)
        ossbom.add_components(components)

    # get all packages in the package.json file
    # if package_json_file_exists(project_folder):
    #    packages.add_list(get_all_package_json_packages(project_folder), "package.json", DependencyEnv.PROD, type="npm")

    # yarn list
    components = get_all_yarn_list_packages(project_folder)
    ossbom.add_components(components)
    return ossbom
