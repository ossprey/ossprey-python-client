import pytest
import subprocess
import json
import os
import tempfile
import shutil

skip_in_gha = pytest.mark.skipif(
    os.getenv("GITHUB_ACTIONS") == "true",
    reason="Skipped on GitHub Actions.",
)


@pytest.fixture(autouse=True)
def cleanup():
    yield
    # subprocess.run(['docker', 'rm', '-f', 'simple_math_container'], check=False)


@pytest.mark.parametrize(
    "docker_folder, expected_packages, not_expected_packages, no_of_packages",
    [
        (
            "../test/docker_js_simple_math",
            {
                "npm": ["lodash", "axios", "@types/ms", "ms"],
                "github": ["ossprey/example_malicious_javascript"],
            },
            {
                "npm": ["mathlib", "send/ms"],
            },
            509,
        ),
        (
            "../test/docker_py_simple_math",
            {
                "pypi": ["fastapi", "uvicorn", "solana", "solders", "pydantic"],
                "github": ["ossprey/example_malicious_python"],
            },
            {
                "pypi": ["ossprey/example_malicious_python"],
            },
            27,
        ),
    ],
)
@skip_in_gha
def test_docker_build(
    docker_folder, expected_packages, not_expected_packages, no_of_packages
) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker not available in environment")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Run the build script from its directory
        script_dir = os.path.join(os.path.dirname(__file__), docker_folder)
        build_script = os.path.join(script_dir, "build.sh")
        subprocess.run(["bash", build_script, tmpdir], cwd=script_dir, check=True)
        sbom_path = os.path.join(tmpdir, "sbom.json")

        print("Attempt to get the sbom from the docker container")
        with open(sbom_path) as f:
            sbom = json.load(f)

    # Component count can vary slightly across platforms; ensure it's reasonable
    assert len(sbom["components"]) >= no_of_packages

    # Verify the GitHub-installed package is represented as a GitHub component
    for type, packages in expected_packages.items():
        for package in packages:
            print(f"Type: {type} Package: {package}")
            comp = next(
                (
                    c
                    for c in sbom["components"]
                    if c.get("type") == type and c.get("name") == package
                ),
                None,
            )
            assert comp is not None, f"Expected {type} {package} to be in SBOM"

    for type, packages in not_expected_packages.items():
        for package in packages:
            print(f"Type: {type} Package: {package}")
            comp = next(
                (
                    c
                    for c in sbom["components"]
                    if c.get("type") == type and c.get("name") == package
                ),
                None,
            )
            assert comp is None, f"Expected {type} {package} to NOT be in SBOM"

    # Basic structure checks
    assert isinstance(sbom.get("components"), list)
    assert all("name" in c and "type" in c for c in sbom["components"])
