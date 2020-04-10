"""Authzzie - Generic Authorization Scopes Mapping Library

This is written to be a generic "glue" between systems that have an existing
authorization system and other scopes / grants based authorization paradigms
such as OAuth.

You can use Authzzie to use an existing system to check if a user in that
system is granted permission X, and if so grant them permission Y in a
different system.
"""
import copy
from collections import Iterable, defaultdict
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from six import string_types
from typing_extensions import Protocol


class AuthorizerCallable(Protocol):
    """Type declaration for authentication check callable
    """
    def __call__(self, **kwargs):
        # type: (**str) -> Set[str]
        raise NotImplementedError('You should not be instantiating this')


IdParserCallable = Callable[[str], Dict[str, str]]

ScopeNormalizerCallable = Callable[['Scope', 'Scope'], 'Scope']


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

        <entity_type>[:entity_id[:actions]]

    or:

        <entity_type>[:entity_id[:subscope[:actions]]]

      `entity_type` is the only required part, and represents the type of
      entity on which actions can be performed.

      `entity_id` is optional, and can be used to limit the scope of actions
      to a specific entity (rather than all entities of the same type).

      `actions` is optional, and can be used to limit the scope to a specific
      action (such as 'read' or 'delete') or actions. Omitting typically means
      "any action". Multiple actions are specified as comma separated.

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

        `file:*:meta:read,update` - denotes allowing reading and updating the
        metadata of all file entities.

        `file:*:meta:*` - denotes allowing all actions on the metadata of all
        file entities.
    """

    entity_type = None
    subscope = None
    entity_ref = None
    actions = None

    def __init__(self, entity_type, entity_id=None, actions=None, subscope=None):
        # type: (str, Optional[str], Union[None, str, Iterable], Optional[str]) -> None
        self.entity_type = entity_type
        self.entity_ref = entity_id
        self.actions = set(to_iterable(actions)) if actions else None
        self.subscope = subscope

    def __repr__(self):
        return '<Scope {}>'.format(str(self))

    def __str__(self):
        """Convert scope to a string
        """
        parts = [self.entity_type]
        entity_ref = self.entity_ref if self.entity_ref != '*' else None
        subscobe = self.subscope if self.subscope != '*' else None
        actions = ','.join(sorted(self.actions)) if self.actions and self.actions != '*' else None

        if entity_ref:
            parts.append(entity_ref)
        elif subscobe or actions:
            parts.append('*')

        if subscobe:
            parts.append(subscobe)
            if not actions:
                parts.append('*')

        if actions:
            parts.append(actions)

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
            scope.actions = cls._parse_actions(parts[2])
        if len(parts) == 4:
            if parts[2] != '*':
                scope.subscope = parts[2]
            if parts[3] != '*':
                scope.actions = cls._parse_actions(parts[3])

        return scope

    @classmethod
    def _parse_actions(cls, actions_str):
        # type: (str) -> Set[str]
        if not actions_str:
            return set()
        return set(actions_str.split(','))


class Authzzie(object):
    """Authzzie authorization permission mapping class
    """

    def __init__(self):
        self._authorizers = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        self._scope_normalizers = {}  # type: Dict[Tuple[str, Optional[str]], ScopeNormalizerCallable]
        self._ref_parsers = {}  # type: Dict[str, IdParserCallable]
        self._type_aliases = {}  # type: Dict[str, str]

    def register_entity_ref_parser(self, entity_type, function):
        # type: (str, IdParserCallable) -> None
        """Register an entity reference parser for an entity type
        """
        self._ref_parsers[entity_type] = function

    def register_authorizer(self, entity_type, function, actions=None, subscopes=None, append=False):
        # type: (str, AuthorizerCallable, Union[Set[str], str, None], Union[Set[str], str, None], bool) -> None
        """Register an authorizer function for an entity type, subscopes and actions
        """
        actions = to_iterable(actions)
        subscopes = to_iterable(subscopes)
        auth_checks = self._authorizers[entity_type]

        for s in subscopes:
            for a in actions:
                if append:
                    auth_checks[s][a].append(function)
                else:
                    auth_checks[s][a] = [function]

    def register_scope_normalizer(self, entity_type, function, subscope=None):
        # type: (str, ScopeNormalizerCallable, Optional[str]) -> None
        """Register a scope normalizer function

        Scope normalizer functions are called, if registered, for each *granted*
        scope. They allow implementors to normalize granted scopes, for example
        by removing actions implied by other granted actions.
        """
        self._scope_normalizers[(entity_type, subscope)] = function

    def register_type_alias(self, alias, original):
        # type: (str, str) -> None
        """Register a type alias

        Type aliases allow aliasing an existing CKAN entity type (or a custom
        type added by an extension) with a new name, acceptable by an external
        service.
        """
        self._type_aliases[alias] = original

    def authorize_scope(self, scope):
        # type: (Scope) -> Optional[Scope]
        """Check a requested permission scope and return a granted scope

        This is a wrapper around `get_permissions` that normalizes granted
        permissions into a scope object. If no permissions are granted, will
        return `None`.
        """
        permissions = self.get_granted_actions(scope)
        if len(permissions) == 0:
            return None

        granted = copy.copy(scope)
        granted.actions = permissions
        entity_type = self._type_aliases.get(scope.entity_type, scope.entity_type)
        if (entity_type, scope.subscope) in self._scope_normalizers:
            normalize = self._scope_normalizers[(entity_type, scope.subscope)]
            granted = normalize(scope, granted)

        return granted

    def get_granted_actions(self, scope):
        # type: (Scope) -> Set[str]
        """Get list of granted permissions for an entity / ID
        """
        granted = self._call_authorizers_for_scope(scope)

        for action in granted:
            k = (scope.entity_type, scope.subscope, action)
            if k in self._action_aliases:
                granted.update(self._action_aliases[k])

        if scope.actions:
            granted = scope.actions.intersection(granted)

        return granted

    def _call_authorizers_for_scope(self, scope):
        # type: (Scope) -> Set[str]
        """Calculate granted permissions based on requested scope
        """
        entity_checks = self._get_entity_authorizers(scope)
        if scope.actions:
            # Check permissions for each requested action,
            check_results = [self._call_authorizer(check, scope.entity_type, scope.entity_ref)
                             for action in scope.actions
                             for check in entity_checks[action]]
        else:
            # Fall back to the default checks
            check_results = [self._call_authorizer(check, scope.entity_type, scope.entity_ref)
                             for check in entity_checks[None]]

        if len(check_results) == 0:
            return set()

        return check_results[0].intersection(*check_results[1:])

    def _get_entity_authorizers(self, scope):
        # type: (Scope) -> Dict[Optional[str], List[AuthorizerCallable]]
        """Get the authorization checks matching the requested entity type and subscope
        """
        if scope.entity_type in self._type_aliases:
            e_type = self._type_aliases[scope.entity_type]
        else:
            e_type = scope.entity_type

        if e_type not in self._authorizers:
            raise UnknownEntityType("Unknown entity type: {}".format(scope.entity_type))

        e_checks = self._authorizers[e_type]

        if scope.subscope and scope.subscope in e_checks:
            e_checks = e_checks[scope.subscope]
        else:
            e_checks = e_checks[None]

        return e_checks

    def _call_authorizer(self, check, entity_type, entity_ref=None):
        # type: (AuthorizerCallable, str, Optional[str]) -> Set[str]
        """Call permission check function for scope and return result
        """
        kwargs = self._parse_entity_ref(entity_type, entity_ref)
        return check(**kwargs)

    def _parse_entity_ref(self, entity_type, entity_ref):
        # type: (str, Optional[str]) -> Dict[str, Any]
        """Parse the entity ref and return a dictionary of arguments to pass to the authorizer
        """
        entity_type = self._type_aliases.get(entity_type, entity_type)
        if entity_ref and entity_type in self._ref_parsers:
            kwargs = self._ref_parsers[entity_type](entity_ref)
        else:
            kwargs = {"id": entity_ref}
        return kwargs


def to_iterable(val):
    # type: (Any) -> Iterable
    """Get something we can iterate over from an unknown type

    >>> i = to_iterable([1, 2, 3])
    >>> next(iter(i))
    1

    >>> i = to_iterable(1)
    >>> next(iter(i))
    1

    >>> i = to_iterable(None)
    >>> next(iter(i)) is None
    True

    >>> i = to_iterable('foobar')
    >>> next(iter(i))
    'foobar'

    >>> i = to_iterable((1, 2, 3))
    >>> next(iter(i))
    1
    """
    if isinstance(val, Iterable) and not isinstance(val, string_types):
        return val
    return (val,)
