from typing import Optional

from ckan import model
from ckan.common import g
from ckan.plugins import toolkit


def ckan_auth_wrapper(check, **extra_args):
    # type: (str, Optional[str]) -> bool
    """CKAN auth system wrapper for Authzzie
    """
    context = dict(model=model, user=g.user, auth_user_obj=g.userobj)
    try:
        toolkit.check_access(check, context, data_dict=extra_args)
    except (toolkit.NotAuthorized, toolkit.ObjectNotFound):
        return False
    return True
