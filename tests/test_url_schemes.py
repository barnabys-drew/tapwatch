"""Outbound URLs from config must be http(s); urllib would also open file://."""
import pytest

from tapwatch import notifiers
from tapwatch.triage import JevClient


def test_jev_client_refuses_non_http_url():
    with pytest.raises(ValueError):
        JevClient("k", url="file:///etc/passwd")


def test_teams_webhook_refuses_non_http_url():
    with pytest.raises(ValueError):
        notifiers.post_teams("file:///etc/passwd", {})
