from personashield.models import TargetType
from personashield.utils.validators import detect_target_type


def test_detect_email():
    assert detect_target_type("user@example.com") == TargetType.EMAIL


def test_detect_domain():
    assert detect_target_type("example.com") == TargetType.DOMAIN


def test_detect_phone():
    assert detect_target_type("+15550001111") == TargetType.PHONE


def test_detect_username():
    assert detect_target_type("m0xsecX") == TargetType.USERNAME
