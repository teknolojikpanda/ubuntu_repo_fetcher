import pytest
from src.debian_version import compare_debian_versions
# Conditional import to allow tests to be collected even if apt_pkg is missing

@pytest.mark.parametrize("v1, v2, expected", [
    ("1.0", "1.0", 0),
    ("1.0", "1.1", -1),
    ("1.1", "1.0", 1),
    ("1.0-1", "1.0-2", -1),
    ("1.0-2", "1.0-1", 1),
    ("1.0-1ubuntu1", "1.0-1", 1), # Epoch defaults to 0
    ("1:1.0", "1.0", 1),         # Explicit epoch
    ("1.0", "1:1.0", -1),
    ("2.0~beta1", "2.0", -1),    # Tilde versions
    ("2.0", "2.0~beta1", 1),
    ("1.12.1-1", "1.12.1-1~deb10u1", 1),
    ("1.12.1-1~deb10u1", "1.12.1-1", -1),
    ("5.15.0-78.85", "5.15.0-78.85~20.04.1", 1), # Real world example
    ("5.15.0-78.85~20.04.1", "5.15.0-78.85", -1), # Real world example
])
def test_compare_debian_versions(v1, v2, expected):
    """Test comparison of various Debian version strings."""
    assert compare_debian_versions(v1, v2) == expected
