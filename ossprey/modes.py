import os
import logging

logger = logging.getLogger(__name__)


def get_all_modes() -> list[str]:
    return ['pipenv', 'python-requirements', 'poetry', 'npm', 'yarn', 'fs', 'auto']


def get_modes(directory: str) -> list[str]:
    """
    Get the modes from the directory.
    :param directory: The directory to scan.
    :return: A list of modes.
    """
    
    # get all files in the directory
    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    logger.debug(f"Files in directory: {files}")
    modes = []

    # Check for requirements.txt
    if "requirements.txt" in files:
        modes.append("python-requirements")

    poetry_files = [
        "poetry.lock",
        "pyproject.toml"
    ]
    if any(poetry_file in files for poetry_file in poetry_files):
        # TODO handle poetry better in the future
        modes.append("poetry")

    npm_files = [
        "package-lock.json",
        "package.json",
        "node_modules"
    ]
    # Check for package.json
    if any(npm_file in files for npm_file in npm_files):
        modes.append("npm")

    # Check for yarn.lock
    if "yarn.lock" in files:
        modes.append("yarn")

    return modes
