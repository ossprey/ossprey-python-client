import pytest
import subprocess
import json
import os
import tempfile
import shutil


@pytest.fixture(autouse=True)
def cleanup():
    yield
    subprocess.run(['docker', 'rm', '-f', 'simple_math_container'], check=False)


def test_docker_build() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker not available in environment")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Run the build script from its directory
        script_dir = os.path.join(os.path.dirname(__file__), '../test/docker_simple_math')
        build_script = os.path.join(script_dir, 'build.sh')
        subprocess.run(['bash', build_script, tmpdir], cwd=script_dir, check=True)
        sbom_path = os.path.join(tmpdir, 'sbom.json')

        print("Attempt to get the sbom from the docker container")
        with open(sbom_path) as f:
            sbom = json.load(f)

    print(sbom)
    # Component count can vary slightly across platforms; ensure it's reasonable
    assert len(sbom['components']) >= 27

    names = {c['name'] for c in sbom['components']}
    # Verify some expected PyPI packages from requirements.txt are present
    assert {"fastapi", "uvicorn", "solana", "solders", "pydantic"}.issubset(names)

    # Verify the GitHub-installed package is represented as a GitHub component
    gh_comp = next(
        (c for c in sbom['components'] if c.get('type') == 'github' and c.get('name') == 'ossprey/example_malicious_python'),
        None,
    )
    assert gh_comp is not None

    # Basic structure checks
    assert isinstance(sbom.get('components'), list)
    assert all('name' in c and 'type' in c for c in sbom['components'])
