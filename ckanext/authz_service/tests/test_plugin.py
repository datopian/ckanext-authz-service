"""Tests for plugin.py."""
import ckanext.authz_service.plugin as plugin


def test_plugin():
    p = plugin.AuthzServicePlugin()
    assert p
