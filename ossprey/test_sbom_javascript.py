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
    pnpm_lock_file_exists,
    get_all_pnpm_lock_packages,
    run_npm_dry_run,
    get_all_npm_dry_run_packages,
    yarn_lock_file_exists,
    get_all_yarn_lock_packages,
    run_yarn_install,
    get_all_yarn_list_packages,
    update_sbom_from_npm,
    update_sbom_from_pnpm,
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
        '{"dependencies": {"testpkg": "^1.0.0", "tagpkg": "latest"},'
        ' "devDependencies": {"testpkg-dev": "~2.3.4"}}'
    )
    components = get_all_package_json_packages(tmp_path)
    by_name = {c.name: c for c in components}

    # Range prefixes stripped; ``latest`` tag skipped (no concrete version).
    assert set(by_name) == {"testpkg", "testpkg-dev"}
    assert by_name["testpkg"].version == "1.0.0"
    assert by_name["testpkg-dev"].version == "2.3.4"
    assert all(c.type == "npm" for c in components)
    assert all(c.source == {"package.json"} for c in components)


def test_get_all_package_json_packages_missing_sections(tmp_path: Path) -> None:
    """Missing dependencies/devDependencies keys must not raise."""
    (tmp_path / "package.json").write_text("{}")
    assert get_all_package_json_packages(tmp_path) == []


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


def test_pnpm_lock_file_exists(tmp_path: Path) -> None:
    assert pnpm_lock_file_exists(tmp_path) is False
    (tmp_path / "pnpm-lock.yaml").write_text("")
    assert pnpm_lock_file_exists(tmp_path) is True


def test_get_all_pnpm_lock_packages_v6(tmp_path: Path) -> None:
    """pnpm v6 entries use ``/name@version:`` keys; trailing ``(peer)`` stripped."""
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '6.0'\n\n"
        "packages:\n\n"
        "  /lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-x}\n"
        "    dev: false\n\n"
        "  /@scope/pkg@2.0.0(react@18.2.0):\n"
        "    resolution: {integrity: sha512-y}\n"
    )
    comps = {c.name: c.version for c in get_all_pnpm_lock_packages(tmp_path)}
    assert comps == {"lodash": "4.17.21", "@scope/pkg": "2.0.0"}


def test_get_all_pnpm_lock_packages_v9(tmp_path: Path) -> None:
    """pnpm v9 drops the leading slash on package keys."""
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n\n"
        "packages:\n\n"
        "  axios@1.6.5:\n"
        "    resolution: {integrity: sha512-z}\n"
    )
    comps = {c.name: c.version for c in get_all_pnpm_lock_packages(tmp_path)}
    assert comps == {"axios": "1.6.5"}


def test_get_all_yarn_lock_packages_berry(tmp_path: Path) -> None:
    """Berry-format lockfile (v2+) is detected via ``__metadata`` and parsed."""
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile\n\n'
        '__metadata:\n'
        '  version: 6\n'
        '  cacheKey: 10c0\n\n'
        '"lodash@npm:4.17.21":\n'
        '  version: 4.17.21\n'
        '  resolution: "lodash@npm:4.17.21"\n'
        '  languageName: node\n'
        '  linkType: hard\n\n'
        '"@scope/pkg@npm:2.0.0":\n'
        '  version: 2.0.0\n'
        '  resolution: "@scope/pkg@npm:2.0.0"\n\n'
        '"my-app@workspace:.":\n'
        '  version: 0.0.0-use.local\n'
        '  resolution: "my-app@workspace:."\n'
    )
    comps = {c.name: c.version for c in get_all_yarn_lock_packages(tmp_path)}
    # Workspace self-entry skipped, scoped name preserved.
    assert comps == {"lodash": "4.17.21", "@scope/pkg": "2.0.0"}


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
