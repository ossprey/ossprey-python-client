from __future__ import annotations
import pytest
from unittest.mock import patch, mock_open
from typing import Any
from pathlib import Path
from ossprey.sbom_javascript import (
    GitResolve,
    exec_command,
    node_modules_directory_exists,
    find_package_json_files,
    get_all_node_modules_packages,
    package_lock_file_exists,
    get_all_package_lock_packages,
    package_json_file_exists,
    get_all_package_json_packages,
    run_npm_dry_run,
    get_all_npm_dry_run_packages,
    yarn_lock_file_exists,
    get_all_yarn_lock_packages,
    run_yarn_install,
    get_all_yarn_list_packages,
    update_sbom_from_npm,
    update_sbom_from_yarn,
)

from ossbom.model.ossbom import OSSBOM
from ossbom.model.component import Component


def test_exec_command() -> None:
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = "output"
        assert exec_command("echo test") == "output"


def test_node_modules_directory_exists(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    assert node_modules_directory_exists(tmp_path) is True


def test_find_package_json_files(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}")
    assert find_package_json_files(tmp_path) == [
        tmp_path / "node_modules" / "package.json"
    ]


def test_get_all_node_modules_packages(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text(
        '{"name": "testpkg", "version": "1.0.0"}'
    )
    comps = get_all_node_modules_packages(tmp_path)
    assert len(comps) == 1
    c = comps[0]
    assert isinstance(c, Component)
    assert c.name == "testpkg"
    assert c.version == "1.0.0"


def test_package_lock_file_exists(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{}")
    assert package_lock_file_exists(tmp_path) is True


def test_get_all_package_lock_packages(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/testpkg": {"version": "1.0.0"}}}'
    )
    comps = get_all_package_lock_packages(tmp_path)
    assert len(comps) == 1
    c = comps[0]
    assert isinstance(c, Component)
    assert c.name == "testpkg"
    assert c.version == "1.0.0"
    assert c.source == {"package-lock.json"}


def test_get_all_package_lock_packages_ignore_blanks(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"": {}, "node_modules/testpkg": {"version": "1.0.0"}}}'
    )
    comps = get_all_package_lock_packages(tmp_path)
    assert len(comps) == 1
    c = comps[0]
    assert isinstance(c, Component)
    assert c.name == "testpkg"
    assert c.version == "1.0.0"
    assert c.source == {"package-lock.json"}


def test_package_json_file_exists(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    assert package_json_file_exists(tmp_path) is True


def test_get_all_package_json_packages(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"testpkg": "1.0.0"}, "devDependencies": {"testpkg-dev": "1.0.0"}}'
    )
    assert get_all_package_json_packages(tmp_path) == [
        {"name": "testpkg", "version": "1.0.0"},
        {"name": "testpkg-dev", "version": "1.0.0"},
    ]


def test_run_npm_dry_run() -> None:
    with patch("ossprey.sbom_javascript.exec_command") as mock_exec_command:
        mock_exec_command.return_value = "add testpkg 1.0.0\n"
        assert get_all_npm_dry_run_packages(".") == [
            {"name": "testpkg", "version": "1.0.0"}
        ]


def test_yarn_lock_file_exists(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text("")
    assert yarn_lock_file_exists(tmp_path) is True


def test_get_all_yarn_lock_packages(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text('"testpkg@^1.0.0":\n  version "1.0.0"\n')
    comps = get_all_yarn_lock_packages(tmp_path)
    assert len(comps) == 1
    c = comps[0]
    assert isinstance(c, Component)
    assert c.name == "testpkg"
    assert c.version == "1.0.0"


def test_run_yarn_install() -> None:
    with patch("ossprey.sbom_javascript.exec_command") as mock_exec_command:
        mock_exec_command.return_value = "output"
        assert run_yarn_install(".") == "output"


def test_get_all_yarn_list_packages() -> None:
    with patch("ossprey.sbom_javascript.exec_command") as mock_exec_command:
        mock_exec_command.return_value = (
            '{"data": {"trees": [{"name": "testpkg@1.0.0"}]}}'
        )
        comps = get_all_yarn_list_packages(".")
    assert len(comps) == 1
    c = comps[0]
    assert isinstance(c, Component)
    assert c.name == "testpkg"
    assert c.version == "1.0.0"


# def test_update_sbom_from_npm() -> None:
#        mock_get_all_npm_dry_run_packages.return_value = [{"name": "testpkg", "version": "1.0.0"}]
#    with patch("ossprey.sbom_javascript.get_all_npm_dry_run_packages") as mock_get_all_npm_dry_run_packages:
#        sbom = OSSBOM()
#        sbom = update_sbom_from_npm(sbom, ".")
#        assert len(sbom.components) == 1
#
#        # Get only entry in sbom.components and confirm it's name value is testpkg
#        for component in sbom.components.values():
#            assert component.name == "testpkg"


def test_update_sbom_from_yarn() -> None:
    with patch(
        "ossprey.sbom_javascript.get_all_yarn_list_packages"
    ) as mock_get_all_yarn_list_packages:
        mock_get_all_yarn_list_packages.return_value = [
            Component.create(
                name="testpkg",
                version="1.0.0",
                env=None,
                type="npm",
                source="yarn list",
            )
        ]
        sbom = OSSBOM()
        sbom = update_sbom_from_yarn(sbom, ".")
        assert len(sbom.components) == 1

        # Get only entry in sbom.components and confirm it's name value is testpkg
        for component in sbom.components.values():
            assert component.name == "testpkg"


# GitResolve tests
def test_GitResolve_parses_https_url() -> None:
    gr = GitResolve("git+https://github.com/pallets/flask.git#abcdef0123")
    assert gr.get_type() == "github"
    assert gr.get_version() == "abcdef0123"
    assert gr.url == "https://github.com/pallets/flask.git"
    assert gr.get_name() == "pallets/flask"


def test_GitResolve_parses_ssh_url() -> None:
    gr = GitResolve(
        "git+ssh://git@github.com/ossprey/example_malicious_javascript.git#deadbeef"
    )
    assert gr.get_type() == "github"
    assert gr.get_version() == "deadbeef"
    assert gr.url == "ssh://git@github.com/ossprey/example_malicious_javascript.git"
    assert gr.get_name() == "ossprey/example_malicious_javascript"


def test_GitResolve_raises_without_git_prefix() -> None:
    with pytest.raises(ValueError):
        GitResolve("https://github.com/org/repo.git#123")


def test_GitResolve_without_dot_git_suffix() -> None:
    gr = GitResolve("git+https://github.com/org/repo#main")
    assert gr.get_type() == "github"
    assert gr.url == "https://github.com/org/repo"
    assert gr.get_name() == "org/repo"
    assert gr.get_version() == "main"
