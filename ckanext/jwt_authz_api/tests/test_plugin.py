"""Tests for plugin.py."""
import ckanext.jwt_authz_api.plugin as plugin


def test_plugin():
    p = plugin.JwtAuthzApiPlugin()
    assert p
