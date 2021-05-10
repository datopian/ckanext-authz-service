"""Functional tests relying on the full CKAN app stack

This is mainly for testing blueprints
"""
import pytest
from ckan.plugins import toolkit
from ckan.tests import helpers

from . import temporary_file
from .test_actions import RSA_PUB_KEY


def test_get_public_key(app):
    url = toolkit.url_for('authz_service.public_key')
    with temporary_file(RSA_PUB_KEY) as pub_key_file, \
            helpers.changed_config('ckanext.authz_service.jwt_public_key_file', pub_key_file):
        response = app.get(url, status=200)

    assert response.headers['content-type'] == 'application/x-pem-file'
    assert response.body == RSA_PUB_KEY


def test_get_public_key_no_key_configured(app):
    url = toolkit.url_for('authz_service.public_key')
    response = app.get(url, status=204)
    assert not response.body
