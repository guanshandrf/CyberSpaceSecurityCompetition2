import pytest
from safemcp.config import Settings


def test_demo_without_key():
    Settings().validate()


def test_live_requires_key():
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        Settings(mode="live").validate()
