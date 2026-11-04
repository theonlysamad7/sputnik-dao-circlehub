use crate::policy::{RoleKind, VersionedPolicy};
use crate::*;

#[near]
impl Contract {
    /// Approve a member. Only an existing admin can do this.
    pub fn admin_add_member(&mut self, member_id: AccountId) -> bool {
        let caller = env::predecessor_account_id();
        let mut policy = self.policy.get().unwrap().to_policy();

        let is_admin = policy.roles.iter().any(|role| {
            role.name == "admin"
                && matches!(&role.kind, RoleKind::Group(accounts) if accounts.contains(&caller))
        });
        assert!(is_admin, "ERR_ADMIN_ONLY");

        let members_role = policy.roles.iter_mut()
            .find(|role| role.name == "members")
            .expect("ERR_MEMBERS_ROLE_NOT_FOUND");

        let added = match &mut members_role.kind {
            RoleKind::Group(accounts) => accounts.insert(member_id.clone()),
            _ => env::panic_str("ERR_MEMBERS_ROLE_MUST_BE_GROUP"),
        };

        self.policy.set(&VersionedPolicy::Current(policy));
        env::log_str(&format!(
            "CIRCLEHUB_MEMBER_ADDED: member={}, approved_by={}",
            member_id, caller
        ));

        added
    }

    /// Remove a member. An admin cannot remove another admin's membership.
    pub fn admin_remove_member(&mut self, member_id: AccountId) -> bool {
        let caller = env::predecessor_account_id();
        let mut policy = self.policy.get().unwrap().to_policy();

        let is_admin = policy.roles.iter().any(|role| {
            role.name == "admin"
                && matches!(&role.kind, RoleKind::Group(accounts) if accounts.contains(&caller))
        });
        assert!(is_admin, "ERR_ADMIN_ONLY");

        let is_admin_account = policy.roles.iter().any(|role| {
            role.name == "admin"
                && matches!(&role.kind, RoleKind::Group(accounts) if accounts.contains(&member_id))
        });
        assert!(!is_admin_account, "ERR_CANNOT_REMOVE_ADMIN_MEMBERSHIP");

        let members_role = policy.roles.iter_mut()
            .find(|role| role.name == "members")
            .expect("ERR_MEMBERS_ROLE_NOT_FOUND");

        let removed = match &mut members_role.kind {
            RoleKind::Group(accounts) => accounts.remove(&member_id),
            _ => env::panic_str("ERR_MEMBERS_ROLE_MUST_BE_GROUP"),
        };

        self.policy.set(&VersionedPolicy::Current(policy));
        env::log_str(&format!(
            "CIRCLEHUB_MEMBER_REMOVED: member={}, removed_by={}",
            member_id, caller
        ));

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use std::collections::HashSet;

    fn setup(admin: AccountId) -> Contract {
        let mut policy = crate::policy::default_policy(vec![admin.clone()]);

        policy.roles[0].name = "members".to_string();
        policy.roles[0].kind = RoleKind::Group(
            HashSet::from([admin.clone()])
        );

        policy.roles[1].name = "admin".to_string();

        Contract::new(
            crate::types::Config::test_config(),
            VersionedPolicy::Current(policy),
        )
    }

    #[test]
    fn admin_can_add_member() {
        let admin = accounts(0);
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(admin.clone()).build());

        let mut contract = setup(admin);
        let member = accounts(1);

        assert!(contract.admin_add_member(member.clone()));

        let policy = contract.policy.get().unwrap().to_policy();
        let members = policy.roles.iter()
            .find(|role| role.name == "members")
            .unwrap();

        assert!(matches!(
            &members.kind,
            RoleKind::Group(accounts) if accounts.contains(&member)
        ));
    }

    #[test]
    #[should_panic(expected = "ERR_ADMIN_ONLY")]
    fn non_admin_cannot_add_member() {
        let admin = accounts(0);
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(admin.clone()).build());

        let mut contract = setup(admin);

        testing_env!(
            context.predecessor_account_id(accounts(2)).build()
        );

        contract.admin_add_member(accounts(1));
    }

    #[test]
    fn admin_can_remove_member() {
        let admin = accounts(0);
        let member = accounts(1);
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(admin.clone()).build());

        let mut contract = setup(admin);
        assert!(contract.admin_add_member(member.clone()));
        assert!(contract.admin_remove_member(member.clone()));

        let policy = contract.policy.get().unwrap().to_policy();
        let members = policy.roles.iter()
            .find(|role| role.name == "members")
            .unwrap();

        assert!(!matches!(
            &members.kind,
            RoleKind::Group(accounts) if accounts.contains(&member)
        ));
    }

    #[test]
    #[should_panic(expected = "ERR_CANNOT_REMOVE_ADMIN_MEMBERSHIP")]
    fn admin_cannot_remove_another_admin() {
        let admin = accounts(0);
        let other_admin = accounts(1);
        let mut context = VMContextBuilder::new();
        testing_env!(context.predecessor_account_id(admin.clone()).build());

        let mut contract = setup(admin.clone());

        let mut policy = contract.policy.get().unwrap().to_policy();
        let admin_role = policy.roles.iter_mut()
            .find(|role| role.name == "admin")
            .unwrap();

        if let RoleKind::Group(accounts) = &mut admin_role.kind {
            accounts.insert(other_admin.clone());
        }

        contract.policy.set(&VersionedPolicy::Current(policy));
        contract.admin_remove_member(other_admin);
    }
}
