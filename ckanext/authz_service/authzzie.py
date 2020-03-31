"""Authzzie - Generic Authorization Scopes Mapping Library

This is written to be a generic "glue" between systems that have an existing
authorization system and other scopes / grants based authorization paradigms
such as OAuth.

You can use Authzzie to use an existing system to check if a user in that
system is granted permission X, and if so grant them permission Y in a
different system.
"""
from collections import Iterable, defaultdict
from typing import Any, Dict
from typing import Iterable as IterableType
from typing import List, Set, Union

from six import string_types
from typing_extensions import Protocol

GrantCheckSpec = Union[str, Dict[str, Any]]


class AuthCheckCallable(Protocol):
    """Type declaration for authentication check callable
    """
    def __call__(self, **kwargs):
        # type: (**str) -> Set[str]
        raise NotImplementedError('You should not be instantiating this')


class UnknownEntityType(ValueError):
    pass


class Scope(object):
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
    entity_ref = None
    action = None

    def __init__(self, entity_type, entity_id=None, action=None, subscope=None):
        self.entity_type = entity_type
        self.entity_ref = entity_id
        self.action = action
        self.subscope = subscope

    def __repr__(self):
        return '<Scope {}>'.format(str(self))

    def __str__(self):
        """Convert scope to a string
        """
        parts = [self.entity_type]

        if self.subscope:
            extra_parts = (self.action, self.subscope, self.entity_ref)
        else:
            extra_parts = (self.action, self.entity_ref)

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
            scope.entity_ref = parts[1]
        if len(parts) == 3 and parts[2] != '*':
            scope.action = parts[2]
        if len(parts) == 4:
            if parts[2] != '*':
                scope.subscope = parts[2]
            if parts[3] != '*':
                scope.action = parts[3]

        return scope


class Authzzie(object):
    """Authzzie authorization permission mapping class
    """

    def __init__(self):
        self._auth_checks = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        self._id_parsers = {}

    def id_parser(self, entity_type):
        """Decorator for registering an ID parser function
        """
        id_parsers = self._id_parsers

        def decorator(f):
            id_parsers[entity_type] = f
            return f

        return decorator

    def auth_check(self, entity_type, actions=None, subscopes=None, append=False):
        """Decorator for registering an authorization check function
        """
        actions = _to_iterable(actions)
        subscopes = _to_iterable(subscopes)
        auth_checks = self._auth_checks

        def decorator(f):
            for s in subscopes:
                for a in actions:
                    if append:
                        auth_checks[entity_type][s][a].append(f)
                    else:
                        auth_checks[entity_type][s][a] = [f]
            return f

        return decorator

    def get_permissions(self, scope):
        # type: (Scope) -> Set[str]
        """Get list of granted permissions for an entity / ID
        """
        auth_checks = self._get_auth_checks(scope)
        check_results = [self._check_permission(scope, check) for check in auth_checks]
        if scope.action:
            return {scope.action}.intersection(*check_results)
        elif len(check_results) == 0:
            return set()
        else:
            return check_results[0].intersection(*check_results[1:])

    def _get_auth_checks(self, scope):
        # type: (Scope) -> List[AuthCheckCallable]
        """Get the authorization checks matching the requested scope
        """
        if scope.entity_type not in self._auth_checks:
            raise UnknownEntityType("Unknown entity type: {}".format(scope.entity_type))

        e_checks = self._auth_checks[scope.entity_type]
        if scope.subscope and scope.subscope in e_checks:
            e_checks = e_checks[scope.subscope]
        else:
            e_checks = e_checks[None]

        if scope.action and scope.action in e_checks:
            return e_checks[scope.action]

        return e_checks[None]

    def _check_permission(self, scope, check):
        # type: (Scope, AuthCheckCallable) -> Set[str]
        """Call permission check function for scope and return result
        """
        if scope.entity_ref and scope.entity_type in self._id_parsers:
            kwargs = self._id_parsers[scope.entity_type](scope.entity_ref)
        else:
            # TODO: the entity ID arg name may need to be different based on check spec
            kwargs = {"id": scope.entity_ref}

        return check(**kwargs)


def _to_iterable(val):
    # type: (Any) -> IterableType
    """Get something we can iterate over from an unknown type
    """
    if isinstance(val, Iterable) and not isinstance(val, string_types):
        return val
    return (val,)
