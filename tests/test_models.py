import pytest
from pathlib import Path
from src.models import PackageInfo, RepoFile

def test_package_info_creation():
    """Test basic creation and attribute assignment for PackageInfo."""
    pkg = PackageInfo(
        package="test-pkg",
        version_str="1.0-1",
        architecture="amd64",
        filename="pool/main/t/test-pkg/test-pkg_1.0-1_amd64.deb",
        size=1024,
        sha256="abc",
        component="main",
        pocket="-updates",
        type="binary"
    )
    assert pkg.package == "test-pkg"
    assert pkg.version_str == "1.0-1"
    assert pkg.architecture == "amd64"
    assert pkg.filename == "pool/main/t/test-pkg/test-pkg_1.0-1_amd64.deb"
    assert pkg.size == 1024
    assert pkg.sha256 == "abc"
    assert pkg.component == "main"
    assert pkg.pocket == "-updates"
    assert pkg.type == "binary"

def test_package_info_hash():
    """Test hashing consistency for PackageInfo."""
    pkg1 = PackageInfo("a", "1.0", "amd64", "f1", 100)
    pkg2 = PackageInfo("a", "1.0", "amd64", "f1", 100) # Identical
    pkg3 = PackageInfo("b", "1.0", "amd64", "f1", 100) # Different package
    pkg4 = PackageInfo("a", "1.1", "amd64", "f1", 100) # Different version
    pkg5 = PackageInfo("a", "1.0", "arm64", "f1", 100) # Different arch
    pkg6 = PackageInfo("a", "1.0", "amd64", "f2", 100) # Different filename

    assert hash(pkg1) == hash(pkg2)
    assert hash(pkg1) != hash(pkg3)
    assert hash(pkg1) != hash(pkg4)
    assert hash(pkg1) != hash(pkg5)
    assert hash(pkg1) != hash(pkg6)

    s = {pkg1, pkg2, pkg3}
    assert len(s) == 2 # pkg1 and pkg2 are duplicates in the set

def test_repo_file_creation():
    """Test basic creation and attribute assignment for RepoFile."""
    local_path = Path("/tmp/test.deb")
    rf = RepoFile(
        url="http://example.com/test.deb",
        local_path=local_path,
        expected_size=2048,
        expected_sha256="def",
        is_index=False
    )
    assert rf.url == "http://example.com/test.deb"
    assert rf.local_path == local_path
    assert rf.expected_size == 2048
    assert rf.expected_sha256 == "def"
    assert not rf.is_index

def test_repo_file_hash_eq():
    """Test hashing and equality for RepoFile (based on URL)."""
    path1 = Path("/tmp/f1")
    path2 = Path("/tmp/f2")
    rf1 = RepoFile("http://a.com/f", path1, 100, "abc")
    rf2 = RepoFile("http://a.com/f", path1, 100, "abc") # Identical
    rf3 = RepoFile("http://a.com/f", path2, 200, "def") # Same URL, different details
    rf4 = RepoFile("http://b.com/f", path1, 100, "abc") # Different URL

    assert rf1 == rf2
    assert rf1 == rf3 # Equality only checks URL
    assert rf1 != rf4
    assert rf1 != "http://a.com/f" # Check against different type

    assert hash(rf1) == hash(rf2)
    assert hash(rf1) == hash(rf3) # Hash only checks URL
    assert hash(rf1) != hash(rf4)

    s = {rf1, rf2, rf3, rf4}
    assert len(s) == 2 # Only rf1 (or rf2/rf3) and rf4 are unique by URL hash
