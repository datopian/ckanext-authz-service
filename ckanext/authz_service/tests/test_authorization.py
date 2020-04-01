from contextlib import contextmanager

from ckan import model
from ckan.tests import factories
from mock import patch

from ckanext.authz_service.authz_binding import authzzie
from ckanext.authz_service.authzzie import Scope

from . import FunctionalTestBase


@contextmanager
def user_context(user):
    def mock_context():
        return {"modle": model,
                "user": user['name'],
                "userobj": model.User.get(user['name'])}

    with patch('ckanext.authz_service.authz_binding.common.get_user_context', mock_context):
        yield


class TestDatasetAuthBinding(FunctionalTestBase):
    """Test cases for the default authorization binding defined in the extension
    for datasets
    """

    def setup(self):

        super(TestDatasetAuthBinding, self).setup()

        self.org_admin = factories.User()
        self.org_member = factories.User()
        self.org = factories.Organization(
            users=[
                {'name': self.org_member['name'], 'capacity': 'member'},
                {'name': self.org_admin['name'], 'capacity': 'admin'},
            ]
        )

    def test_org_member_can_read_all_datasets(self):
        """Test that org member gets 'read' authorized for the entire org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'read')
        with user_context(self.org_member):
            granted = authzzie.get_permissions(scope)
        assert granted == {'read'}

    def test_org_member_cannot_write_all_datasets(self):
        """Test that org member doesn't get 'update' authorized for the entire org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'update')
        with user_context(self.org_member):
            granted = authzzie.get_permissions(scope)
        assert granted == set()

    def test_non_member_cannot_read_all_datasets(self):
        """Test that a user that is not an org member doesn't not get 'read' authorized for the entire org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'read')
        user = factories.User()
        with user_context(user):
            granted = authzzie.get_permissions(scope)
        assert granted == set()

    def test_org_admin_can_update_all_datasets(self):
        """Test that an org admin can update all datasets in the org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'update')
        with user_context(self.org_admin):
            granted = authzzie.get_permissions(scope)
        assert granted == {'update'}

    def test_org_admin_can_patch_all_datasets(self):
        """Test that an org admin can update all datasets in the org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'create')
        with user_context(self.org_admin):
            granted = authzzie.get_permissions(scope)
        assert granted == {'create'}

    def test_org_member_global_dataset_actions(self):
        """Test that an org member can list datasets
        """
        scope = Scope('ds', '{}/'.format(self.org['name']))
        with user_context(self.org_member):
            granted = authzzie.get_permissions(scope)
        assert granted == {'list'}

    def test_org_admin_global_dataset_actions(self):
        """Test that an org admin can create and list datasets
        """
        scope = Scope('ds', '{}/'.format(self.org['name']))
        with user_context(self.org_admin):
            granted = authzzie.get_permissions(scope)
        assert granted == {'create', 'list'}
