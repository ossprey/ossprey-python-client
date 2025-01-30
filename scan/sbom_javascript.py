import json
import os
import re
import subprocess
from pathlib import Path

from scan.sbom import DependencyEnv, PackageCollection


def exec_command(command, cwd=None):
    try:
        # Run the yarn command with the specified cwd
        result = subprocess.run(
            command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd if cwd else None,  # Explicitly set to None if not used
            check=True
        )
        # Parse the output
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Error while running yarn:", e)
        return e.stdout


def node_modules_directory_exists(project_folder):
    return os.path.isdir(os.path.join(project_folder, "node_modules"))


def find_package_json_files(base_path):
    package_files = []
    for root, dirs, files in os.walk(base_path):
        if "package.json" in files:
            package_files.append(Path(root) / "package.json")
    return package_files


def get_all_node_modules_packages(project_folder):

    packages = []

    # Get all instances of the package.json file in the node_modules directory
    package_files = find_package_json_files(os.path.join(project_folder, "node_modules"))

    # Add all packages to the list
    for package_file in package_files:
        with open(package_file) as f:
            data = json.load(f)
            if "name" in data and "version" in data:
                # Extract the name and version for each package
                packages.append({"name": data["name"], "version": data["version"]})

    return packages


def package_lock_file_exists(project_folder):
    return os.path.isfile(os.path.join(project_folder, "package-lock.json"))


def get_all_package_lock_packages(project_folder):
    # Get all packages in the package-lock.json file

    with open(os.path.join(project_folder, "package-lock.json")) as f:
        data = json.load(f)

        return [{"name": package.replace("node_modules/", ""), "version": data["packages"][package]["version"]} for package in data["packages"] if package != ""]


def package_json_file_exists(project_folder):
    return os.path.isfile(os.path.join(project_folder, "package.json"))


def get_all_package_json_packages(project_folder):
    # Get all packages in the package.json file
    with open(os.path.join(project_folder, "package.json")) as f:
        data = json.load(f)

        deps = [{"name": dependency, "version": data["dependencies"][dependency]} for dependency in data["dependencies"]]
        deps.extend([{"name": dependency, "version": data["devDependencies"][dependency]} for dependency in data["devDependencies"]])

    return deps


def run_npm_dry_run(project_folder):
    return exec_command("npm install --dry-run --verbose", project_folder)


def get_all_npm_dry_run_packages(project_folder):
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


def yarn_lock_file_exists(project_folder):
    return os.path.isfile(os.path.join(project_folder, "yarn.lock"))


def get_all_yarn_lock_packages(project_folder):
    # Get all packages in the yarn.lock file
    package_data = []
    file_path = os.path.join(project_folder, "yarn.lock")
    with open(file_path, 'r') as f:
        content = f.read()

    # Regex to match package entries and their version
    package_regex = r'^(?:"|)([^\s"][^"]*)(?:"|):\n\s+version\s+"([^"]+)"'

    # Find all matches in the yarn.lock content
    matches = re.finditer(package_regex, content, re.MULTILINE)

    for match in matches:
        package_names = match.group(1)  # Full package spec (can include multiple package names)
        version = match.group(2)       # Version

        # Split package names if there are multiple (comma-separated)
        for name in package_names.split(", "):

            # Remove the last @ and everything after it
            name = name.rsplit("@", 1)[0]
            package_data.append({"name": name.strip(), "version": version.strip()})

    return package_data


def run_yarn_install(project_folder):
    return exec_command("yarn install --check-files -non-interactive", project_folder)


def get_all_yarn_list_packages(project_folder):
    # Get all packages from yarn list

    ret = []

    # Run the command
    result = exec_command("yarn list --json", project_folder)

    # Parse the output
    data = json.loads(result)

    # Extract the packages
    for package in data["data"]["trees"]:
        name_and_version = package["name"].rsplit("@", 1)
        ret.append({"name": name_and_version[0], "version": name_and_version[1]})

    return ret


# Global functions
def create_sbom_from_npm(project_folder):

    packages = PackageCollection()

    # get all versions of a package in the node_modules directory
    if node_modules_directory_exists(project_folder):
        packages.add_list(get_all_node_modules_packages(project_folder), "node_modules", DependencyEnv.PROD, type="npm")

    # get all packages in the package-lock.json file
    if package_lock_file_exists(project_folder):
        packages.add_list(get_all_package_lock_packages(project_folder), "package-lock.json", DependencyEnv.PROD,, type="npm")

    # get all packages in the package.json file
    #if package_json_file_exists(project_folder):
    #    packages.add_list(get_all_package_json_packages(project_folder), "package.json", DependencyEnv.PROD, type="npm")

    # npm install --dry-run --verbose
    packages.add_list(get_all_npm_dry_run_packages(project_folder), "install", DependencyEnv.PROD, type="npm")

    return packages.create_sbom_dict()


def create_sbom_from_yarn(project_folder, run_install=False):

    packages = PackageCollection()

    if run_install:
        run_yarn_install(project_folder)

    # get all versions of a package in the node_modules directory
    if node_modules_directory_exists(project_folder):
        packages.add_list(get_all_node_modules_packages(project_folder), "node_modules", DependencyEnv.PROD, type="npm")

    # get all packages in the package-lock.json file
    if yarn_lock_file_exists(project_folder):
        packages.add_list(get_all_yarn_lock_packages(project_folder), "yarn.lock", DependencyEnv.PROD, type="npm")
        # Get all packages in yarn list

    # get all packages in the package.json file
    #if package_json_file_exists(project_folder):
    #    packages.add_list(get_all_package_json_packages(project_folder), "package.json", DependencyEnv.PROD, type="npm")

    # yarn list
    packages.add_list(get_all_yarn_list_packages(project_folder), "list", DependencyEnv.PROD, type="npm")

    return packages.create_sbom_dict()
