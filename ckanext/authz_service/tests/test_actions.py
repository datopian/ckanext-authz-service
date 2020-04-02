from ckan.plugins import toolkit
from ckan.tests import factories, helpers
from nose.tools import assert_equals, assert_raises

from . import FunctionalTestBase, user_context


class TestAuthorizeAction(FunctionalTestBase):
    """Test cases for the default authorization binding defined in the extension
    for datasets
    """

    def setup(self):

        super(TestAuthorizeAction, self).setup()

        self.org_admin = factories.User()
        self.org_member = factories.User()
        self.org = factories.Organization(
            users=[
                {'name': self.org_member['name'], 'capacity': 'member'},
                {'name': self.org_admin['name'], 'capacity': 'admin'},
            ]
        )

    def test_authorize_request_full_org_access(self):
        """Test some basic authorize request
        """
        scopes = ['org:{}:*'.format(self.org['name'])]
        with user_context(self.org_admin) as context:
            result = helpers.call_action(
                'authz_authorize',
                context,
                scopes=scopes)

        normalized_scopes = ['org:{}'.format(self.org['name'])]
        assert_equals(result['requested_scopes'], normalized_scopes)
        assert_equals(result['granted_scopes'], normalized_scopes)
        assert_equals(result['user_id'], self.org_admin['name'])

    def test_authorize_raises_on_unknown_entity(self):
        """Test that authorize does not accept unknown entity types
        """
        sysadmin = factories.Sysadmin()
        with user_context(sysadmin) as context:
            assert_raises(toolkit.ValidationError, helpers.call_action,
                          'authz_authorize', context,
                          scopes=['spam:*'])
