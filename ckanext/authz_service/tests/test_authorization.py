from ckan.tests import factories, helpers

from ckanext.authz_service.authzzie import Scope
from ckanext.authz_service.plugin import init_authorizer

from . import user_context


class TestDatasetAuthBinding(helpers.FunctionalTestBase):
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

        self.az = init_authorizer()

    def test_org_member_can_read_all_datasets(self):
        """Test that org member gets 'read' authorized for the entire org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'read')
        with user_context(self.org_member):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'read'}

    def test_org_member_cannot_write_all_datasets(self):
        """Test that org member doesn't get 'update' authorized for the entire org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'update')
        with user_context(self.org_member):
            granted = self.az.get_granted_actions(scope)
        assert granted == set()

    def test_non_member_cannot_read_all_datasets(self):
        """Test that a user that is not an org member doesn't not get 'read' authorized for the entire org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'read')
        user = factories.User()
        with user_context(user):
            granted = self.az.get_granted_actions(scope)
        assert granted == set()

    def test_org_admin_can_update_all_datasets(self):
        """Test that an org admin can update all datasets in the org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'update')
        with user_context(self.org_admin):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'update'}

    def test_org_admin_can_patch_all_datasets(self):
        """Test that an org admin can update all datasets in the org
        """
        scope = Scope('ds', '{}/*'.format(self.org['name']), 'create')
        with user_context(self.org_admin):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'create'}

    def test_org_member_global_dataset_actions(self):
        """Test that an org member can list datasets
        """
        scope = Scope('ds', '{}/'.format(self.org['name']))
        with user_context(self.org_member):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'list'}

    def test_org_admin_global_dataset_actions(self):
        """Test that an org admin can create and list datasets
        """
        scope = Scope('ds', '{}/'.format(self.org['name']))
        with user_context(self.org_admin):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'create', 'list'}


class TestResourceAuthBinding(helpers.FunctionalTestBase):
    """Test cases for the default authorization binding defined in the extension
    for resources
    """

    def setup(self):

        super(TestResourceAuthBinding, self).setup()

        self.org_admin = factories.User()
        self.org_member = factories.User()
        self.org = factories.Organization(
            users=[
                {'name': self.org_member['name'], 'capacity': 'member'},
                {'name': self.org_admin['name'], 'capacity': 'admin'},
            ]
        )

        self.dataset = factories.Dataset(owner_org=self.org['id'])

        self.az = init_authorizer()

    def test_org_member_can_read_all_resources(self):
        """Test that org member gets 'read' authorized for all resources of an org owned dataset
        """
        scope = Scope('res', '{}/{}/*'.format(self.org['name'], self.dataset['name']), 'read')
        with user_context(self.org_member):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'read'}

    def test_org_admin_can_write_all_resources(self):
        """Test that org admin gets 'write' authorized for all resources of an org owned dataset
        """
        scope = Scope('res', '{}/{}/*'.format(self.org['name'], self.dataset['name']), ['update', 'create'])
        with user_context(self.org_admin):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'update'}

    def test_non_member_can_read_resources(self):
        """Test that org member gets 'read' authorized for the entire org
        """
        user = factories.User()
        scope = Scope('res', '{}/{}/*'.format(self.org['name'], self.dataset['name']), ['read'])
        with user_context(user):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'read'}

    def test_non_member_cannot_read_private_resources(self):
        """Test that org member gets 'read' authorized for the entire org
        """
        user = factories.User()
        ds = factories.Dataset(owner_org=self.org['id'], private=True)
        scope = Scope('res', '{}/{}/*'.format(self.org['name'], ds['name']), ['read'])
        with user_context(user):
            granted = self.az.get_granted_actions(scope)
        assert granted == set()

    def test_non_member_cannot_write_resources(self):
        """Test that org member doesn't get to write resources
        """
        user = factories.User()
        scope = Scope('res', '{}/{}/*'.format(self.org['name'], self.dataset['name']), ['update', 'patch', 'delete'])
        with user_context(user):
            granted = self.az.get_granted_actions(scope)
        assert granted == set()


class TestOrganizationAuthBinding(helpers.FunctionalTestBase):
    """Test cases for the default authorization binding defined in the extension
    for resources
    """

    def setup(self):

        super(TestOrganizationAuthBinding, self).setup()

        self.org_admin = factories.User()
        self.org_member = factories.User()
        self.org = factories.Organization(
            users=[
                {'name': self.org_member['name'], 'capacity': 'member'},
                {'name': self.org_admin['name'], 'capacity': 'admin'},
            ]
        )

        self.other_org = factories.Organization()
        self.sysadmin = factories.Sysadmin()

        self.az = init_authorizer()

    def test_org_member_can_read_org(self):
        """Test that org member gets 'read' authorized for the entire org
        """
        scope = Scope('org', self.org['name'], 'read')
        with user_context(self.org_member):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'read'}

    def test_org_member_cannot_update_org(self):
        """Test that org member gets 'read' authorized for the entire org
        """
        scope = Scope('org', self.org['name'], 'update')
        with user_context(self.org_member):
            granted = self.az.get_granted_actions(scope)
        assert granted == set()

    def test_org_admin_can_update_org(self):
        """Test that org member gets 'read' authorized for the entire org
        """
        scope = Scope('org', self.org['name'], 'update')
        with user_context(self.org_admin):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'update'}

    def test_org_admin_cannot_update_other_org(self):
        """Test that org admin doesn't get permission over other org
        """
        scope = Scope('org', self.other_org['name'], 'update')
        with user_context(self.org_admin):
            granted = self.az.get_granted_actions(scope)
        assert granted == set()

    def test_org_admin_cannot_create_new_orgs(self):
        """Test that org admin doesn't get permission to create other organizations

        This actually depends on a configuration option, so we'll check with / without
        this option enabled
        """
        scope = Scope('org', actions=['create', 'list'])

        with helpers.changed_config('ckan.auth.user_create_organizations', False):
            with user_context(self.org_admin):
                granted = self.az.get_granted_actions(scope)
            assert granted == {'list'}

        with helpers.changed_config('ckan.auth.user_create_organizations', True):
            with user_context(self.org_admin):
                granted = self.az.get_granted_actions(scope)
            assert granted == {'list', 'create'}

    def test_sysadmin_can_create_new_orgs(self):
        """Test that sysadmins can create new organizations
        """
        scope = Scope('org', actions=['create', 'list'])
        with user_context(self.sysadmin):
            granted = self.az.get_granted_actions(scope)
        assert granted == {'create', 'list'}

    def test_org_can_be_aliased_as_group(self):
        """Test that sysadmins can create new organizations
        """
        self.az.register_type_alias('grp', 'org')
        scope = Scope('grp', actions=['create', 'list'])
        with user_context(self.sysadmin):
            granted = self.az.authorize_scope(scope)
        assert granted.actions == {'create', 'list'}
        assert granted.entity_type == 'grp'

    def test_update_can_be_aliased_as_write(self):
        """Test that sysadmins can create new organizations
        """
        # Test without alias
        scope = Scope('org', '*', actions=['read', 'write'])
        with user_context(self.sysadmin):
            granted = self.az.authorize_scope(scope)
        assert granted.entity_type == 'org'
        assert granted.actions == {'read'}

        # Now test with alias
        self.az.register_action_alias('write', 'update', 'org')
        with user_context(self.sysadmin):
            granted = self.az.authorize_scope(scope)
        assert granted.actions == {'read', 'write'}
