"""Tests for the Authzzie permission mapping library
"""
from parameterized import parameterized
from six import iteritems

from ckanext.authz_service import authzzie


class TestAuthzzieScope(object):

    @parameterized([
        ('org:myorg:*', {'entity_type': 'org', 'entity_ref': 'myorg', 'actions': None, 'subscope': None}),
        ('org:myorg', {'entity_type': 'org', 'entity_ref': 'myorg', 'actions': None, 'subscope': None}),
        ('ds', {'entity_type': 'ds', 'entity_ref': None, 'actions': None, 'subscope': None}),
        ('ds:*', {'entity_type': 'ds', 'entity_ref': None, 'actions': None, 'subscope': None}),
        ('ds:*:read', {'entity_type': 'ds', 'entity_ref': None, 'actions': {'read'}, 'subscope': None}),
        ('ds:foobaz:meta:read', {'entity_type': 'ds', 'entity_ref': 'foobaz', 'actions': {'read'}, 'subscope': 'meta'}),
        ('ds:foobaz:*:read', {'entity_type': 'ds', 'entity_ref': 'foobaz', 'actions': {'read'}, 'subscope': None}),
        ('ds:foobaz:meta:*', {'entity_type': 'ds', 'entity_ref': 'foobaz', 'actions': None, 'subscope': 'meta'}),
        ('ds:foobaz:delete', {'entity_type': 'ds', 'entity_ref': 'foobaz', 'actions': {'delete'}, 'subscope': None}),
        ('ds:foobaz:create,delete', {'entity_type': 'ds', 'entity_ref': 'foobaz', 'actions': {'create', 'delete'},
                                     'subscope': None}),

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
        (authzzie.Scope('ds', actions='read', subscope='meta'), 'ds:*:meta:read'),
        (authzzie.Scope('ds', actions=['read', 'write'], subscope='meta'), 'ds:*:meta:read,write'),
    ])
    def test_scope_stringify(self, scope, expected):
        """Test scope stringification works as expected
        """
        assert str(scope) == expected


class TestAuthzzie(object):

    def test_authzzie_non_bound_action_not_granted(self):

        def test_authorizer(_):
            return set()

        az = authzzie.Authzzie()
        az.register_authorizer('foo', test_authorizer, {'read', 'write'})

        scope = authzzie.Scope('foo', 'entity-01', {'delete'})
        granted = az.get_permissions(scope)

        assert granted == set()
