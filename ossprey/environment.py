import os
from git import Repo

from ossbom.model.environment import Environment


def get_current_git_branch(path="."):
    repo = Repo(path, search_parent_directories=True)
    return repo.active_branch.name


def get_codespace_environment(package_name):
    github_org, github_repo = os.getenv("GITHUB_REPOSITORY").split("/")
    github_branch = get_current_git_branch()
    project = package_name
    machine_name = os.getenv("CODESPACE_NAME")
    product_env = "CODESPACE"
    return Environment.create(github_org, github_repo, github_branch, project, machine_name, product_env)


def get_gh_actions_environment(package_name):
    github_org, github_repo = os.getenv("GITHUB_REPOSITORY").split("/")
    github_branch = os.getenv("GITHUB_REF_NAME", None)
    project = package_name
    machine_name = os.getenv("CODESPACE_NAME")
    product_env = "GITHUB_ACTIONS"
    return Environment.create(github_org, github_repo, github_branch, project, machine_name, product_env)


def get_environment_details(package_name):

    if os.getenv("CODESPACES"):
        return get_codespace_environment(package_name)
    elif os.getenv("GITHUB_ACTIONS"):
        return get_gh_actions_environment(package_name)

    return Environment()
