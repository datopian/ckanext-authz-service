from contextlib import contextmanager
from typing import Any, Dict

from ckan import model
from ckan.tests import helpers
from mock import patch


class FunctionalTestBase(helpers.FunctionalTestBase):

    _load_plugins = ['authz_service']


@contextmanager
def user_context(user):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """Context manager that creates a CKAN context dict for a user, then
    both patches our `get_user_context` function to return it and also
    yields the context for use inside tests
    """
    userobj = model.User.get(user['name'])
    context = {"model": model,
               "user": user['name'],
               "auth_user_obj": userobj,
               "userobj": userobj}

    def mock_context():
        return context

    with patch('ckanext.authz_service.authz_binding.common.get_user_context', mock_context):
        yield context
