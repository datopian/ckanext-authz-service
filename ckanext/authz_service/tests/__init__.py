from ckan.tests import helpers


class FunctionalTestBase(helpers.FunctionalTestBase):

    _load_plugins = ['authz_service']
