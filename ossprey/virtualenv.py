import json
import logging
import os
import sys
import subprocess
import tempfile
import venv

logger = logging.getLogger(__name__)


class VirtualEnv:

    def __init__(self):
        self.original_sys_path = sys.path[:]
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.temporary_files = []

        self.create_virtualenv()

    def __del__(self):
        self.exit()

        for file in self.temporary_files:
            os.remove(file)

        self.temporary_dir.cleanup()

    # Private methods
    def _exec(self, command, stdout=None):
        """
        Executes the specified command in the virtual environment.

        Parameters:
        command (list): The command to execute
        """
        try:
            if stdout:
                # Run the pip install command with the specified stdout
                result = subprocess.run(command, check=True, stdout=stdout, text=True)
            else:
                # Run the pip install command
                result = subprocess.run(
                    command, check=True, capture_output=True, text=True
                )
        except subprocess.CalledProcessError as e:
            logger.error(f"An error occurred while executing {' '.join(command)}':")
            logger.error(f"stdout:\n{e.stdout}")
            logger.error(f"stderr:\n{e.stderr}")
            # Throw the exception to the caller
            raise e

        return result

    def _get_pip_executable(self):
        """
        Returns the path to the pip executable in the virtual environment.
        """

        return (
            os.path.join(self.get_venv_dir(), "bin", "pip")
            if os.name != "nt"
            else os.path.join(self.temporary_dir, "Scripts", "pip.exe")
        )

    def _pip_install(self, package_path):
        """
        Installs the specified package in the virtual environment.

        Parameters:
        package_path (str): The path to the local package directory or .whl/.tar.gz file.
        """
        pip_executable = self._get_pip_executable()
        result = self._exec([pip_executable, "install", package_path])

        return result

    def _pip_list(self):
        """
        Lists all packages installed in the virtual environment.
        """
        pip_executable = self._get_pip_executable()
        result = self._exec([pip_executable, "list", "--format=json"])
        installed_packages = json.loads(result.stdout)
        return installed_packages

    # Public methods
    def get_venv_dir(self):
        return self.temporary_dir.name

    def create_virtualenv(self):
        """
        Creates a virtual environment in the specified directory.
        """
        venv_builder = venv.EnvBuilder(with_pip=True)
        venv_builder.create(self.get_venv_dir())
        logger.debug(f"Virtual environment created at {self.temporary_dir}")

    def install_package(self, package_path):
        """
        Installs the specified package in the virtual environment.

        Parameters:
        package_path (str): The path to the local package directory or .whl/.tar.gz file.
        """
        self._pip_install(package_path)
        logger.debug(
            f"Package '{package_path}' installed in virtual environment at {self.temporary_dir}"
        )

    def list_installed_packages(self):
        """
        Lists all packages installed in the virtual environment.
        """
        return self._pip_list()

    def create_requirements_file_from_env(self):

        requirements_file = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        self.temporary_files.append(requirements_file.name)

        pip_executable = self._get_pip_executable()
        self._exec([pip_executable, "freeze"], stdout=requirements_file)

        return requirements_file.name

    def enter(self):
        """
        Replaces sys.path with paths from the specified virtual environment.
        """
        site_packages = os.path.join(
            self.get_venv_dir(),
            "lib",
            f"python{sys.version_info.major}.{sys.version_info.minor}",
            "site-packages",
        )
        stdlib = os.path.join(
            self.get_venv_dir(),
            "lib",
            f"python{sys.version_info.major}.{sys.version_info.minor}",
        )

        if not os.path.exists(site_packages):
            logger.error(
                f"Error: The virtual environment path '{site_packages}' does not exist."
            )
            raise FileNotFoundError(
                f"The virtual environment path '{site_packages}' does not exist."
            )

        # Save the original sys.path
        self.original_sys_path = sys.path[:]

        # Clear sys.path and set it to only include the virtualenv's site-packages and standard library
        sys.path[:] = [site_packages, stdlib]

    def exit(self):
        """
        Restores the original sys.path.
        """
        sys.path = self.original_sys_path
