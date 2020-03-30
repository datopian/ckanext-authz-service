from ckan.tests import helpers


class FunctionalTestBase(helpers.FunctionalTestBase):

    _load_plugins = ['jwt_authz_api']
