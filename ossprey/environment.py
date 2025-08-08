from __future__ import annotations
import os
import shutil
import subprocess
from typing import Optional

from ossbom.model.environment import Environment


def get_current_git_branch(path: str = ".") -> Optional[str]:

    if shutil.which("git") is None:
        return None  # git binary not available

    try:
        result = subprocess.run(
            ["git", "-C", path, "rev-parse", "--abbrev-ref", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None  # not a git repo or other git error


def get_codespace_environment(package_name: str) -> Environment:
    github_org, github_repo = os.getenv("GITHUB_REPOSITORY").split("/")
    github_branch = get_current_git_branch()
    project = package_name
    machine_name = os.getenv("CODESPACE_NAME")
    product_env = "CODESPACE"
    return Environment.create(github_org, github_repo, github_branch, project, machine_name, product_env)


def get_gh_actions_environment(package_name: str) -> Environment:
    github_org, github_repo = os.getenv("GITHUB_REPOSITORY").split("/")
    github_branch = os.getenv("GITHUB_REF_NAME", None)
    project = package_name
    machine_name = os.getenv("CODESPACE_NAME")
    product_env = "GITHUB_ACTIONS"
    return Environment.create(github_org, github_repo, github_branch, project, machine_name, product_env)


def get_environment_details(package_name: str) -> Environment:

    if os.getenv("CODESPACES"):
        return get_codespace_environment(package_name)
    elif os.getenv("GITHUB_ACTIONS"):
        return get_gh_actions_environment(package_name)

    return Environment()
