/// User management and authentication tests.
///
/// Covers: UserStore construction, create/list/delete users, role assignment,
/// set-role, enable/disable, password change, authentication success/failure,
/// session token validation, and Role capability matrix.

#[cfg(test)]
mod tests {
    use std::path::Path;
    use tempfile::TempDir;

    use crate::auth::{Role, UserStore};

    // ── Helpers ───────────────────────────────────────────────────────────

    fn open_store() -> (TempDir, UserStore) {
        let dir = TempDir::new().unwrap();
        let store = UserStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn admin_password(dir: &TempDir) -> String {
        let creds = std::fs::read_to_string(
            dir.path().join(".admin_initial_credentials"),
        )
        .expect("initial credentials file must exist");
        // File format: "...Password:  <pw>\n..."
        creds
            .lines()
            .find(|l| l.starts_with("Password:"))
            .expect("Password line not found")
            .trim_start_matches("Password:")
            .trim()
            .to_string()
    }

    // ══════════════════════════════════════════════════════════════════════
    // USERSTORE CONSTRUCTION
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn userstore_open_creates_admin_user() {
        let (_dir, store) = open_store();
        let users = store.list_users();
        assert_eq!(users.len(), 1);
        let (name, role, enabled) = &users[0];
        assert_eq!(name, "admin");
        assert_eq!(*role, Role::Admin);
        assert!(*enabled);
    }

    #[test]
    fn userstore_open_writes_initial_credentials_file() {
        let (dir, _store) = open_store();
        assert!(
            dir.path().join(".admin_initial_credentials").exists(),
            ".admin_initial_credentials must be created on first open"
        );
    }

    #[test]
    fn userstore_reopen_same_dir_preserves_users() {
        let (dir, store) = open_store();
        store
            .create_user("alice", "password123", Role::Auditor, None)
            .unwrap();
        drop(store);

        // Reopen from same directory.
        let store2 = UserStore::open(dir.path()).unwrap();
        let users = store2.list_users();
        let names: Vec<&str> = users.iter().map(|(n, _, _)| n.as_str()).collect();
        assert!(names.contains(&"alice"), "alice must survive reopen");
        assert!(names.contains(&"admin"), "admin must survive reopen");
    }

    // ══════════════════════════════════════════════════════════════════════
    // CREATE USER
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn create_user_succeeds_with_valid_inputs() {
        let (_dir, store) = open_store();
        store
            .create_user("bob", "securepass!", Role::Operator, None)
            .expect("create_user must succeed");
        let users = store.list_users();
        assert!(users.iter().any(|(n, r, _)| n == "bob" && *r == Role::Operator));
    }

    #[test]
    fn create_user_all_roles() {
        let (_dir, store) = open_store();
        for (username, role) in [
            ("u_admin", Role::Admin),
            ("u_operator", Role::Operator),
            ("u_auditor", Role::Auditor),
            ("u_readonly", Role::ReadOnly),
        ] {
            store.create_user(username, "pass", role, None).unwrap();
        }
        let users = store.list_users();
        assert_eq!(users.len(), 5); // admin + 4 new
    }

    #[test]
    fn create_user_duplicate_username_fails() {
        let (_dir, store) = open_store();
        store.create_user("charlie", "pw1", Role::ReadOnly, None).unwrap();
        let result = store.create_user("charlie", "pw2", Role::ReadOnly, None);
        assert!(result.is_err(), "duplicate username must be rejected");
    }

    // ══════════════════════════════════════════════════════════════════════
    // LIST USERS
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn list_users_returns_correct_count() {
        let (_dir, store) = open_store();
        store.create_user("u1", "pw", Role::ReadOnly, None).unwrap();
        store.create_user("u2", "pw", Role::Auditor, None).unwrap();
        assert_eq!(store.list_users().len(), 3); // admin + u1 + u2
    }

    // ══════════════════════════════════════════════════════════════════════
    // DELETE USER
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_user_removes_user() {
        let (_dir, store) = open_store();
        store.create_user("dave", "pw", Role::ReadOnly, None).unwrap();
        store.delete_user("dave").unwrap();
        let users = store.list_users();
        assert!(!users.iter().any(|(n, _, _)| n == "dave"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_unknown_user_fails() {
        let (_dir, store) = open_store();
        let result = store.delete_user("doesnotexist");
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════════
    // SET ROLE
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn set_role_changes_role() {
        let (_dir, store) = open_store();
        store.create_user("eve", "pw", Role::ReadOnly, None).unwrap();
        store.set_role("eve", Role::Operator).unwrap();
        let users = store.list_users();
        let eve = users.iter().find(|(n, _, _)| n == "eve").unwrap();
        assert_eq!(eve.1, Role::Operator);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_role_unknown_user_fails() {
        let (_dir, store) = open_store();
        let result = store.set_role("ghost", Role::Admin);
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_role_persists_after_reopen() {
        let (dir, store) = open_store();
        store.create_user("frank", "pw", Role::ReadOnly, None).unwrap();
        store.set_role("frank", Role::Auditor).unwrap();
        drop(store);

        let store2 = UserStore::open(dir.path()).unwrap();
        let users = store2.list_users();
        let frank = users.iter().find(|(n, _, _)| n == "frank").unwrap();
        assert_eq!(frank.1, Role::Auditor, "role must persist after reopen");
    }

    // ══════════════════════════════════════════════════════════════════════
    // SET ENABLED / DISABLED
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn set_enabled_false_disables_user() {
        let (_dir, store) = open_store();
        store.create_user("grace", "pw", Role::ReadOnly, None).unwrap();
        store.set_enabled("grace", false).unwrap();
        let users = store.list_users();
        let grace = users.iter().find(|(n, _, _)| n == "grace").unwrap();
        assert!(!grace.2, "grace must be disabled");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_enabled_true_re_enables_user() {
        let (_dir, store) = open_store();
        store.create_user("henry", "pw", Role::ReadOnly, None).unwrap();
        store.set_enabled("henry", false).unwrap();
        store.set_enabled("henry", true).unwrap();
        let users = store.list_users();
        let henry = users.iter().find(|(n, _, _)| n == "henry").unwrap();
        assert!(henry.2, "henry must be re-enabled");
    }

    // ══════════════════════════════════════════════════════════════════════
    // SET PASSWORD
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn set_password_succeeds() {
        let (_dir, store) = open_store();
        store.create_user("iris", "oldpass", Role::ReadOnly, None).unwrap();
        store.set_password("iris", "newpass").unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_password_unknown_user_fails() {
        let (_dir, store) = open_store();
        let result = store.set_password("nobody", "pw");
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════════
    // AUTHENTICATION
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticate_admin_succeeds_with_correct_password() {
        let (dir, store) = open_store();
        let pw = admin_password(&dir);
        let session = store.authenticate("admin", &pw).expect("admin auth must succeed");
        assert_eq!(session.username, "admin");
        assert_eq!(session.role, Role::Admin);
        assert!(!session.token.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticate_wrong_password_fails() {
        let (dir, store) = open_store();
        let _ = admin_password(&dir); // ensure file exists
        let result = store.authenticate("admin", "wrongpassword");
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticate_unknown_user_fails() {
        let (_dir, store) = open_store();
        let result = store.authenticate("nobody", "pw");
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticate_disabled_user_fails() {
        let (_dir, store) = open_store();
        store.create_user("jack", "mypass", Role::ReadOnly, None).unwrap();
        store.set_enabled("jack", false).unwrap();
        let result = store.authenticate("jack", "mypass");
        assert!(result.is_err(), "disabled user must not authenticate");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticate_returns_correct_role() {
        let (_dir, store) = open_store();
        store.create_user("kate", "pw123", Role::Auditor, None).unwrap();
        let session = store.authenticate("kate", "pw123").unwrap();
        assert_eq!(session.role, Role::Auditor);
    }

    // ══════════════════════════════════════════════════════════════════════
    // TOKEN VALIDATION
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_token_succeeds_after_authenticate() {
        let (dir, store) = open_store();
        let pw = admin_password(&dir);
        let session = store.authenticate("admin", &pw).unwrap();
        let validated = store.validate_token(&session.token).await.unwrap();
        assert_eq!(validated.username, "admin");
        assert_eq!(validated.role, Role::Admin);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validate_token_unknown_token_fails() {
        let (_dir, store) = open_store();
        let result = store.validate_token("notarealtoken").await;
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════════
    // ROLE CAPABILITY MATRIX
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn role_admin_has_all_capabilities() {
        assert!(Role::Admin.can_select());
        assert!(Role::Admin.can_insert_ledger());
        assert!(Role::Admin.can_insert_accounts());
        assert!(Role::Admin.can_verify());
        assert!(Role::Admin.can_admin());
    }

    #[test]
    fn role_operator_has_no_admin() {
        assert!(Role::Operator.can_select());
        assert!(Role::Operator.can_insert_ledger());
        assert!(Role::Operator.can_insert_accounts());
        assert!(Role::Operator.can_verify());
        assert!(!Role::Operator.can_admin());
    }

    #[test]
    fn role_auditor_can_only_select_and_verify() {
        assert!(Role::Auditor.can_select());
        assert!(!Role::Auditor.can_insert_ledger());
        assert!(!Role::Auditor.can_insert_accounts());
        assert!(Role::Auditor.can_verify());
        assert!(!Role::Auditor.can_admin());
    }

    #[test]
    fn role_readonly_can_only_select() {
        assert!(Role::ReadOnly.can_select());
        assert!(!Role::ReadOnly.can_insert_ledger());
        assert!(!Role::ReadOnly.can_insert_accounts());
        assert!(!Role::ReadOnly.can_verify());
        assert!(!Role::ReadOnly.can_admin());
    }

    // ══════════════════════════════════════════════════════════════════════
    // ROLE PARSING
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn role_parse_valid_strings() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("operator".parse::<Role>().unwrap(), Role::Operator);
        assert_eq!("auditor".parse::<Role>().unwrap(), Role::Auditor);
        assert_eq!("readonly".parse::<Role>().unwrap(), Role::ReadOnly);
        assert_eq!("read_only".parse::<Role>().unwrap(), Role::ReadOnly);
    }

    #[test]
    fn role_parse_invalid_string_fails() {
        assert!("superuser".parse::<Role>().is_err());
        assert!("".parse::<Role>().is_err());
        assert!("root".parse::<Role>().is_err());
    }
}
