"""Testing the version of the package"""

import torus
from torus import ml


def check_version(version):
    """Check that it looks good"""
    print("version", version)
    assert version.count(".") == 2


def test_version_1():
    """Test that torus.ml.__version__ exists"""
    version = torus.ml.__version__
    check_version(version)


def test_version_2():
    """Test that ml.__version__ exists"""
    version = ml.__version__
    check_version(version)
