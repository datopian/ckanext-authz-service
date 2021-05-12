from typing import Any, Dict, Optional, Set

from ckan import model
from ckan.authz import is_sysadmin, users_role_for_group_or_org
from ckan.common import g
from ckan.plugins import toolkit
from six import iteritems

OptionalCkanContext = Optional[Dict[str, Any]]


def normalize_id_part(id_part):
    # type: (str) -> Optional[str]
    """Normalize an ID part
    """
    return id_part if id_part else None


def check_entity_permissions(permission_checks, data_dict=None, context=None):
    # type: (Dict[str, Optional[str]], Optional[Dict[str, Any]], OptionalCkanContext) -> Set[str]
    """Check a list of CKAN permissions and return granted actions
    """
    granted = (p for p, check in iteritems(permission_checks)
               if check and ckan_auth_check(check, data_dict, context=context))
    return set(granted)


def ckan_auth_check(permission, data_dict=None, context=None):
    # type: (str, Dict[str, Any], OptionalCkanContext) -> bool
    """Wrapper for CKAN permission check
    """
    if context is None:
        context = get_user_context()
    try:
        toolkit.check_access(permission, context=context, data_dict=data_dict)
    except (toolkit.NotAuthorized, toolkit.ObjectNotFound):
        return False
    return True


def ckan_get_user_role_in_group(group_id, context=None):
    # type: (str, OptionalCkanContext) -> Optional[str]
    """Get the current user's role in a group / organization
    """
    user = _get_username(context)
    if not user:
        return None
    return users_role_for_group_or_org(group_id, user)


def ckan_is_sysadmin(context=None):
    # type: (OptionalCkanContext) -> bool
    """Tell if the current user is a CKAN sysadmin
    """
    user = _get_username(context)
    return is_sysadmin(user)


def _get_username(context=None):
    # type: (OptionalCkanContext) -> Optional[str]
    """Get username from provided or global context
    """
    if context is None or 'user' not in context:
        context = get_user_context()
    return context.get('user')


def get_user_context():
    # type: () -> Dict[str, Any]
    """get a default CKAN context

    NOTE: This should be the *only* place we access CKAN's globals or session
    data. All other code that needs access to the current user object should
    call this. This allows tests to patch this function to set the current
    user.
    """
    context = dict(model=model)
    if hasattr(g, 'user'):
        context['user'] = g.user
    if hasattr(g, 'userobj'):
        context['auth_user_obj'] = g.userobj
    return context
