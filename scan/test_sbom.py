import pytest
from scan.sbom import Package, PackageCollection, DependencyEnv


def test_package_initialization():
    pkg = Package("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    assert pkg.name == "testpkg"
    assert pkg.version == "1.0.0"
    assert pkg.source == {"pypi"}
    assert pkg.env == {DependencyEnv.PROD}


def test_package_equality():
    pkg1 = Package("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    pkg2 = Package("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    assert pkg1 == pkg2


def test_package_add_source():
    pkg = Package("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    pkg.add_source("github")
    assert "github" in pkg.source


def test_package_add_env():
    pkg = Package("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    pkg.add_env(DependencyEnv.DEV)
    assert DependencyEnv.DEV in pkg.env


def test_add_package():
    collection = PackageCollection()
    collection.add("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    assert "testpkg==1.0.0" in collection.packages


def test_add_list():
    collection = PackageCollection()
    packages = [{"name": "testpkg", "version": "1.0.0"}]
    collection.add_list(packages, "pypi", DependencyEnv.PROD)
    assert "testpkg==1.0.0" in collection.packages


def test_create_sbom():
    collection = PackageCollection()
    collection.add("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    sbom = collection.create_sbom()
    assert len(sbom.components) == 1
    assert sbom.components[0].name == "testpkg"


def test_create_sbom_dict():
    collection = PackageCollection()
    collection.add("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    sbom_dict = collection.create_sbom_dict()
    assert "components" in sbom_dict
    assert len(sbom_dict["components"]) == 1
    assert sbom_dict["components"][0]["name"] == "testpkg"


def test_adding_new_package_to_collection():
    collection = PackageCollection()
    collection.add("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)

    assert "testpkg==1.0.0" in collection.packages
    assert "pypi" in collection.packages["testpkg==1.0.0"].source
    assert DependencyEnv.PROD in collection.packages["testpkg==1.0.0"].env


def test_adding_second_new_package_to_collection():
    collection = PackageCollection()
    collection.add("testpkg", "1.0.0", "pypi", DependencyEnv.PROD)
    collection.add("testpkg", "1.0.0", "new_source", DependencyEnv.DEV)

    assert "testpkg==1.0.0" in collection.packages
    assert "new_source" in collection.packages["testpkg==1.0.0"].source
    assert "pypi" in collection.packages["testpkg==1.0.0"].source
    assert DependencyEnv.PROD in collection.packages["testpkg==1.0.0"].env
    assert DependencyEnv.DEV in collection.packages["testpkg==1.0.0"].env


def test_adding_list_to_collection():
    collection = PackageCollection()
    list = [
        {"name": "testpkg", "version": "1.0.0"},
        {"name": "testpkg2", "version": "2.0.0"},
        {"name": "testpkg3", "version": "3.0.0"}
    ]

    collection.add_list(list, "pypi", DependencyEnv.PROD)
    assert "testpkg==1.0.0" in collection.packages
    assert "testpkg2==2.0.0" in collection.packages
    assert "testpkg3==3.0.0" in collection.packages
    assert "pypi" in collection.packages["testpkg==1.0.0"].source
    assert "pypi" in collection.packages["testpkg2==2.0.0"].source
    assert "pypi" in collection.packages["testpkg3==3.0.0"].source
    assert DependencyEnv.PROD in collection.packages["testpkg==1.0.0"].env
    assert DependencyEnv.PROD in collection.packages["testpkg2==2.0.0"].env
    assert DependencyEnv.PROD in collection.packages["testpkg3==3.0.0"].env
    