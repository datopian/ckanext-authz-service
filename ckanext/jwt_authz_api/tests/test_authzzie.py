"""Tests for the Authzzie permission mapping library
"""
# from nose.tools import assert_raises
from parameterized import parameterized
from six import iteritems

from ckanext.jwt_authz_api import authzzie


class TestAuthzzieScope(object):

    @parameterized([
        ('org:myorg:*', {'entity_type': 'org', 'entity_id': 'myorg', 'action': None, 'subscope': None}),
        ('org:myorg', {'entity_type': 'org', 'entity_id': 'myorg', 'action': None, 'subscope': None}),
        ('ds', {'entity_type': 'ds', 'entity_id': None, 'action': None, 'subscope': None}),
        ('ds:*', {'entity_type': 'ds', 'entity_id': None, 'action': None, 'subscope': None}),
        ('ds:*:read', {'entity_type': 'ds', 'entity_id': None, 'action': 'read', 'subscope': None}),
        ('ds:foobaz:meta:read', {'entity_type': 'ds', 'entity_id': 'foobaz', 'action': 'read', 'subscope': 'meta'}),
        ('ds:foobaz:*:read', {'entity_type': 'ds', 'entity_id': 'foobaz', 'action': 'read', 'subscope': None}),
        ('ds:foobaz:meta:*', {'entity_type': 'ds', 'entity_id': 'foobaz', 'action': None, 'subscope': 'meta'}),
        ('ds:foobaz:delete', {'entity_type': 'ds', 'entity_id': 'foobaz', 'action': 'delete', 'subscope': None}),
    ])
    def test_scope_parsing(self, scope_str, expected):
        """Test scope string parsing works as expected
        """
        scope = authzzie.Scope.from_string(scope_str)
        for k, v in iteritems(expected):
            assert getattr(scope, k) == v

    @parameterized([
        (authzzie.Scope('org', 'myorg'), 'org:myorg'),
        (authzzie.Scope('org', 'myorg', subscope='meta'), 'org:myorg:meta:*'),
        (authzzie.Scope('ds'), 'ds'),
        (authzzie.Scope('ds', 'foobaz', 'read'), 'ds:foobaz:read'),
        (authzzie.Scope('ds', 'foobaz', 'read', 'meta'), 'ds:foobaz:meta:read'),
        (authzzie.Scope('ds', action='read', subscope='meta'), 'ds:*:meta:read'),
    ])
    def test_scope_stringify(self, scope, expected):
        """Test scope stringification works as expected
        """
        assert str(scope) == expected
