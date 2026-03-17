"""
Tests to verify that all script entry points defined in pyproject.toml
are importable, preventing broken CLI after pip install.
"""
import importlib

import tomllib


def _load_script_entrypoints() -> dict[str, str]:
    with open("pyproject.toml", "rb") as f:
        config = tomllib.load(f)
    return config.get("tool", {}).get("poetry", {}).get("scripts", {})


def test_all_entrypoints_importable():
    """Verify every script entry point in pyproject.toml resolves to a real callable."""
    scripts = _load_script_entrypoints()
    assert scripts, "No script entry points found in pyproject.toml"

    for name, ref in scripts.items():
        module_path, func_name = ref.rsplit(":", 1)
        mod = importlib.import_module(module_path)
        func = getattr(mod, func_name, None)
        assert func is not None, (
            f"Entry point '{name} = {ref}': "
            f"function '{func_name}' not found in module '{module_path}'"
        )
        assert callable(func), (
            f"Entry point '{name} = {ref}': "
            f"'{func_name}' in '{module_path}' is not callable"
        )
