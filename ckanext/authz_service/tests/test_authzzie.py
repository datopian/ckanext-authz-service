"""Tests for the Authzzie permission mapping library
"""
from nose.tools import assert_equals
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
        granted = az.get_granted_actions(scope)

        assert granted == set()

    def test_type_aliases(self):

        def test_authorizer(**_):
            return {'read'}

        def test_id_parser(id):
            return {"id": id}

        def test_scope_normalizer(_, granted):
            return granted

        az = authzzie.Authzzie()
        az.register_authorizer('foo', test_authorizer, {'read', 'write'})
        az.register_entity_ref_parser('foo', test_id_parser)
        az.register_scope_normalizer('foo', test_scope_normalizer)

        az.register_type_alias('bar', 'foo')
        scope = authzzie.Scope('bar', 'entity-01', {'read'})
        granted = az.get_granted_actions(scope)

        assert granted == {'read'}

    def test_action_aliases(self):

        def test_authorizer(**_):
            return {'read'}

        az = authzzie.Authzzie()
        az.register_authorizer('foo', test_authorizer, {'read', 'write'})
        az.register_action_alias('look-at-things', 'read', 'foo')

        scope = authzzie.Scope('foo', 'entity-01', {'look-at-things'})
        granted = az.authorize_scope(scope)
        assert_equals(str(granted), 'foo:entity-01:look-at-things')

    def test_action_aliases_with_type_alias(self):

        def test_authorizer(**_):
            return {'read'}

        az = authzzie.Authzzie()
        az.register_authorizer('foo', test_authorizer, {'read', 'write'})
        az.register_action_alias('look-at-things', 'read', 'foo')
        az.register_type_alias('bar', 'foo')

        scope = authzzie.Scope('bar', 'entity-01', {'look-at-things'})
        granted = az.authorize_scope(scope)
        assert_equals(str(granted), 'bar:entity-01:look-at-things')
