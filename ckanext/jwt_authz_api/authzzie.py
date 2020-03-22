"""Authzzie - Generic Authorization Scopes Mapping Library

This is written to be a generic "glue" between systems that have an existing
authorization system and other scopes / grants based authorization paradigms
such as OAuth.

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

    By default, a scope is represented as a string of between 1 and 4 colon
    separated parts, of one of the following structures:

        <entity_type>[:entity_id[:action]]

    or:

        <entity_type>[:entity_id[:subscope[:action]]]

      `entity_type` is the only required part, and represents the type of
      entity on which actions can be performed.

      `entity_id` is optional, and can be used to limit the scope of actions
      to a specific entity (rather than all entities of the same type).

      `action` is optional, and can be used to limit the scope to a specific
      action (such as 'read' or 'delete'). Omitting typically means "any
      action".

      `subscope` is optional and can further limit actions to a "sub-entity",
      for example a dataset's metadata or an organization's users.

    Each optional part can be replaced with a '*' if a following part is to
    be specified, or simply omitted if no following parts are specified as
    well.

    Examples:

        `org:*:read` - denotes allowing the "read" action on all "org" type
        entities.

        `org:foobar:*` - denotes allowing all actions on the 'foobar' org.
        `org:foobar` means the exact same thing.

        `file:*:meta:read` - denotes allowing reading the metadata of all
        file entities.

        `file:*:meta:*` - denotes allowing all actions on the metadata of all
        file entities.
    """

    entity_type = None
    subscope = None
    entity_id = None
    action = None

    def __init__(self, entity_type, entity_id=None, action=None, subscope=None):
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.action = action
        self.subscope = subscope

    def __repr__(self):
        return '<Scope {}>'.format(str(self))

    def __str__(self):
        """Convert scope to a string
        """
        parts = [self.entity_type]

        if self.subscope:
            extra_parts = (self.action, self.subscope, self.entity_id)
        else:
            extra_parts = (self.action, self.entity_id)

        for p in extra_parts:
            if p and p != '*':
                parts.insert(1, p)
            elif len(parts) > 1:
                parts.insert(1, '*')

        if self.subscope and not self.action:
            parts.append('*')

        return ':'.join(parts)

    @classmethod
    def from_string(cls, scope_str):
        """Create a scope object from string
        """
        parts = scope_str.split(':')
        if len(parts) < 1:
            raise ValueError("Scope string should have at least 1 part")
        scope = cls(parts[0])
        if len(parts) > 1 and parts[1] != '*':
            scope.entity_id = parts[1]
        if len(parts) == 3 and parts[2] != '*':
            scope.action = parts[2]
        if len(parts) == 4:
            if parts[2] != '*':
                scope.subscope = parts[2]
            if parts[3] != '*':
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

        entity_scope = self._get_entity_scope(scope)
        permission_scope = 'entity_actions' if scope.entity_id else 'global_actions'

        if permission_scope not in entity_scope:
            return set()

        check_cache = {}
        granted = set()
        denied_actions = False
        checks = entity_scope[permission_scope]
        for permission, check in iteritems(checks):
            if self._check_permission(check, check_cache, entity_id=scope.entity_id):
                granted.add(permission)
            else:
                denied_actions = True

        if scope.action:
            granted = granted.intersection([scope.action])
        elif not denied_actions:
            granted = set('*')  # All actions were granted

        return granted

    def _get_entity_scope(self, scope):
        # type: (Scope) -> Dict[str, Dict[str, GrantCheckSpec]]
        if scope.subscope:
            if scope.subscope not in self.permission_map['entity_scopes'][scope.entity_type].get('subscopes', {}):
                raise UnknownEntityType("Unkown subscope: {}:{}".format(scope.entity_type, scope.subscope))
            entity_scope = self.permission_map['entity_scopes'][scope.entity_type]['subscopes'][scope.subscope]
        else:
            entity_scope = self.permission_map['entity_scopes'][scope.entity_type]
        return entity_scope

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
