from contextlib import contextmanager
from typing import Any, Dict, Optional

from ckan import model
from mock import patch

ANONYMOUS_USER = None


@contextmanager
def user_context(user):
    # type: (Optional[Dict[str, Any]]) -> Dict[str, Any]
    """Context manager that creates a CKAN context dict for a user, then
    both patches our `get_user_context` function to return it and also
    yields the context for use inside tests
    """
    context = {"model": model,
               "user": None,
               "auth_user_obj": None,
               "userobj": None}

    if user is not ANONYMOUS_USER:
        userobj = model.User.get(user['name'])
        context.update({"user": user['name'],
                        "auth_user_obj": userobj,
                        "userobj": userobj})

    with patch('ckanext.authz_service.authz_binding.common.get_user_context', lambda: context):
        yield context


@contextmanager
def temporary_file(content):
    # type: (str) -> str
    """Context manager that creates a temporary file with specified content
    and yields its name. Once the context is exited the file is deleted.
    """
    import tempfile
    file = tempfile.NamedTemporaryFile()
    file.write(content)
    file.flush()
    yield file.name
