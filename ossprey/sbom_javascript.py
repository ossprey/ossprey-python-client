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
            # stderr=subprocess.STDOUT, # TODO if this errors the json decode goes haywire
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
        # Skip if version is not present
        version = package.get("version", None)
        if version is None:
            continue
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


_NPM_RANGE_PREFIX = re.compile(r"^[\^~>=<v\s]+")
_NPM_VERSION = re.compile(r"^\d+\.\d+\.\d+([.\-+][\w.\-+]+)?$")


def _normalize_npm_version(spec: str) -> str | None:
    """Strip semver range markers and return a concrete version, or None if
    the specifier isn't a version (tag like ``latest``, URL, git ref, etc.)."""
    if not spec:
        return None
    cleaned = _NPM_RANGE_PREFIX.sub("", spec).strip()
    if not _NPM_VERSION.match(cleaned):
        return None
    return cleaned


def get_all_package_json_packages(project_folder: str | os.PathLike[str]) -> List[Component]:
    """Read package.json and return Components for every dependency entry.

    Version specifiers like ``^4.17.21`` are stripped to ``4.17.21``. Entries
    whose specifier isn't a concrete version (``latest``, git URLs, etc.) are
    skipped — we can't pin them without a lockfile.
    """
    with open(os.path.join(project_folder, "package.json")) as f:
        data = json.load(f)

    components: List[Component] = []
    for section, env in (
        ("dependencies", DependencyEnv.PROD.value),
        ("devDependencies", DependencyEnv.DEV.value),
    ):
        for name, spec in (data.get(section) or {}).items():
            version = _normalize_npm_version(spec)
            if version is None:
                continue
            components.append(
                Component.create(
                    name=name,
                    version=version,
                    env=env,
                    type="npm",
                    source="package.json",
                )
            )
    return components


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


def pnpm_lock_file_exists(project_folder: str | os.PathLike[str]) -> bool:
    return os.path.isfile(os.path.join(project_folder, "pnpm-lock.yaml"))


# pnpm lockfile package keys:
#  v6: ``  /name@version:`` or ``  /@scope/name@version:`` (two-space indent)
#  v9: ``  name@version:`` (no leading slash)
# Trailing ``(...)`` suffix carries peer-dep specifiers — strip before parsing.
_PNPM_KEY = re.compile(
    r"^\s{2}/?(?P<name>(?:@[^/]+/)?[^@\s/]+)@(?P<version>[^:\s(]+)(?:\([^)]*\))?:",
    re.MULTILINE,
)


def get_all_pnpm_lock_packages(
    project_folder: str | os.PathLike[str],
) -> List[Component]:
    """Parse pnpm-lock.yaml ``packages:`` block into Components.

    Handles both v6 (``/name@version:``) and v9 (``name@version:``) entry
    shapes. YAML is parsed with a regex over indented keys — adequate because
    pnpm's lockfile is machine-generated with predictable formatting and we
    only need the name+version pair.
    """
    file_path = os.path.join(project_folder, "pnpm-lock.yaml")
    with open(file_path, "r") as f:
        content = f.read()

    # Restrict to the ``packages:`` section to avoid matching keys in
    # ``importers:`` / ``snapshots:`` that share similar shape.
    packages_idx = content.find("\npackages:")
    if packages_idx != -1:
        end_idx = content.find("\nsnapshots:", packages_idx)
        section = content[packages_idx : end_idx if end_idx != -1 else len(content)]
    else:
        section = content

    seen: set[tuple[str, str]] = set()
    components: List[Component] = []
    for match in _PNPM_KEY.finditer(section):
        name = match.group("name")
        version = match.group("version")
        if (name, version) in seen:
            continue
        seen.add((name, version))
        components.append(
            Component.create(
                name=name,
                version=version,
                env=DependencyEnv.PROD.value,
                type="npm",
                source="pnpm-lock.yaml",
            )
        )
    return components


def update_sbom_from_pnpm(
    ossbom: OSSBOM, project_folder: str | os.PathLike[str]
) -> OSSBOM:
    if node_modules_directory_exists(project_folder):
        ossbom.add_components(get_all_node_modules_packages(project_folder))
    if pnpm_lock_file_exists(project_folder):
        ossbom.add_components(get_all_pnpm_lock_packages(project_folder))
    elif package_json_file_exists(project_folder):
        ossbom.add_components(get_all_package_json_packages(project_folder))
    return ossbom


def is_yarn_berry_lockfile(content: str) -> bool:
    """Yarn v2+ (berry) lockfiles start with a ``__metadata:`` block."""
    return "__metadata:" in content


def _parse_yarn_classic_lock(content: str) -> List[dict]:
    """Parse yarn classic (v1) lockfile content into name/version dicts."""
    # Filter commented-out lines first.
    content = "\n".join(
        line for line in content.splitlines() if not line.strip().startswith("#")
    )

    # Classic format: ``"name@spec":\n  version "x.y.z"``.
    package_regex = r'^(?:"|)([^\s"][^"]*)(?:"|):\n\s+version\s+"([^"]+)"'
    matches = re.finditer(package_regex, content, re.MULTILINE)

    package_data: List[dict] = []
    for match in matches:
        package_names = match.group(1)
        version = match.group(2)
        for name in package_names.split(", "):
            name = name.rsplit("@", 1)[0].strip()
            alias_match = re.match(r"([^@]+)@npm:([^@]+)", name)
            if alias_match:
                _, name = alias_match.groups()
            package_data.append({"name": name, "version": version.strip()})
    return package_data


def _parse_yarn_berry_lock(content: str) -> List[dict]:
    """Parse yarn berry (v2+) lockfile content into name/version dicts.

    Berry keys use ``"<name>@npm:<spec>":`` (or comma-separated grouped specs)
    and the version line is unquoted: ``  version: x.y.z``. Skip the
    ``__metadata`` block and the workspace self-entry (``@workspace:``).
    """
    block_regex = r'^([^\s#][^\n]*):\n(?:\s+[^\n]*\n)*?\s+version:\s*([^\s\n]+)'
    matches = re.finditer(block_regex, content, re.MULTILINE)

    package_data: List[dict] = []
    for match in matches:
        key = match.group(1).strip()
        version = match.group(2).strip().strip('"')
        if key.startswith("__metadata"):
            continue
        # Berry groups multiple specs comma-separated, each potentially quoted.
        for entry in key.split(", "):
            entry = entry.strip().strip('"')
            # Workspace self-reference — not a real dependency.
            if "@workspace:" in entry:
                continue
            # Berry resolution syntax: ``name@npm:spec`` or ``@scope/name@npm:spec``.
            # Strip the trailing ``@<protocol>:<spec>`` to get the bare name.
            if entry.startswith("@"):
                scope, _, rest = entry[1:].partition("/")
                pkg_name, _, _ = rest.partition("@")
                name = f"@{scope}/{pkg_name}"
            else:
                name, _, _ = entry.partition("@")
            if not name:
                continue
            package_data.append({"name": name, "version": version})
    return package_data


def get_all_yarn_lock_packages(
    project_folder: str | os.PathLike[str],
) -> List[Component]:
    """Parse yarn.lock (classic v1 or berry v2+) into Components."""
    file_path = os.path.join(project_folder, "yarn.lock")
    with open(file_path, "r") as f:
        content = f.read()

    if is_yarn_berry_lockfile(content):
        package_data = _parse_yarn_berry_lock(content)
    else:
        package_data = _parse_yarn_classic_lock(content)

    return [
        Component.create(
            name=component["name"],
            version=component["version"],
            env=DependencyEnv.PROD.value,
            type="npm",
            source="yarn.lock",
        )
        for component in package_data
    ]


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

    has_node_modules = node_modules_directory_exists(project_folder)
    has_lock = package_lock_file_exists(project_folder)

    # get all versions of a package in the node_modules directory
    if has_node_modules:
        components = get_all_node_modules_packages(project_folder)
        ossbom.add_components(components)

    # get all packages in the package-lock.json file
    if has_lock:
        components = get_all_package_lock_packages(project_folder)
        ossbom.add_components(components)

    # Fall back to package.json manifest when no lockfile or installed modules.
    # Versions are imprecise (semver ranges stripped to base pins) but it's
    # better than emitting an empty SBOM.
    if not has_node_modules and not has_lock and package_json_file_exists(project_folder):
        ossbom.add_components(get_all_package_json_packages(project_folder))

    return ossbom


def update_sbom_from_yarn(
    ossbom: OSSBOM, project_folder: str | os.PathLike[str], run_install: bool = False
) -> OSSBOM:

    if run_install:
        run_yarn_install(project_folder)

    if node_modules_directory_exists(project_folder):
        components = get_all_node_modules_packages(project_folder)
        ossbom.add_components(components)

    is_berry = False
    if yarn_lock_file_exists(project_folder):
        lock_path = os.path.join(project_folder, "yarn.lock")
        with open(lock_path, "r") as f:
            is_berry = is_yarn_berry_lockfile(f.read())
        components = get_all_yarn_lock_packages(project_folder)
        ossbom.add_components(components)

    # `yarn list` shells out to the local yarn binary; classic v1 supports it
    # but berry (v2+) doesn't and errors. Lockfile already captured everything
    # for berry, so skip the redundant call there.
    if not is_berry:
        components = get_all_yarn_list_packages(project_folder)
        ossbom.add_components(components)
    return ossbom
