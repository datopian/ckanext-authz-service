"""Authzzie - Generic Authorization Scopes Mapping Library

This is written to be a generic "glue" between systems that have an existing
authorization system and other scopes / grants based authorization paradigms
such as OAuth and JWT.

You can use Authzzie to use an existing system to check if a user in that
system is granted permission X, and if so grant them permission Y in a
different system.
"""

from typing import Any, Dict, List, Set, Union

from six import iteritems

GrantCheckSpec = Union[str, Dict[str, Any]]


class UnknownEntityType(ValueError):
    pass


class Scope:
    """Scope object

    This is an abstraction of a scope representation. Its main purpose is to
    convert scope strings to an object usable by Authzzie. If you need to use a
    specific format to represent scope strings, that is different from the
    Authzzie format, you can replace this class with anything else as long as
    the interface is maintained.
    """

    entity_type = None
    subscope = None
    entity_id = None
    action = None

    def __init__(self, entity_type, entity_id, subscope=None, action=None):
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.subscope = subscope
        self.action = action

    def __repr__(self):
        return '<Scope {}{}>'.format(str(self),
                                     ':{}'.format(self.action) if self.action else '')

    def __str__(self):
        return '{}:{}{}'.format(
            self.entity_type,
            self.entity_id if self.entity_id else '*',
            ':{}'.format(self.subscope) if self.subscope else ''
        )

    @classmethod
    def from_string(cls, scope_str):
        """Create a scope object from string
        """
        parts = scope_str.split(':')
        if len(parts) < 2:
            raise ValueError("Scope string should have at least 2 parts")
        scope = cls(parts[0], None if parts[1] == '*' else parts[1])
        if len(parts) > 2:
            scope.subscope = parts[2]
        if len(parts) > 3:
            scope.action = parts[3]
        return scope


class Authzzie:
    """Authzzie Authorization Permissions Mapper
    """

    def __init__(self, permission_map, authz_wrapper):
        self.permission_map = permission_map
        self.authz_wrapper = authz_wrapper

    def get_permissions(self, scope):
        # type: (Scope) -> Set[str]
        """Get list of granted permissions for an entity / ID
        """
        if scope.entity_type not in self.permission_map.get('entity_scopes', {}):
            raise UnknownEntityType("Unknown entity type: {}".format(scope.entity_type))

        check_cache = {}
        granted = set()
        permission_scope = 'entity_grant_checks' if scope.entity_id else 'global_grant_checks'
        if permission_scope not in self.permission_map['entity_scopes'][scope.entity_type]:
            return granted

        checks = self.permission_map['entity_scopes'][scope.entity_type][permission_scope]
        for permission, check in iteritems(checks):
            if self._check_permission(check, check_cache, entity_id=scope.entity_id):
                granted.add(permission)

        if scope.action:
            granted = granted.intersection([scope.action])

        return granted

    def _check_permission(self, check, check_cache, entity_id=None):
        # type: (Union[GrantCheckSpec, List[GrantCheckSpec]], Dict[GrantCheckSpec, bool]) -> bool
        """Check if a permission is granted based on spec and result of wrapper callable
        """
        if check in check_cache:
            return check_cache[check]

        if isinstance(check, list):
            return all(self._check_permission(c, check_cache, entity_id) for c in check)

        if isinstance(check, dict):
            raise NotImplementedError("Complex check specs are not implemented yet")

        # TODO: the entity ID arg name may need to be different based on check spec
        result = self.authz_wrapper(check, id=entity_id)
        check_cache[check] = result
        return result
