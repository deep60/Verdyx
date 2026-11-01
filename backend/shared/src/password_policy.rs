//! The one password rule, used wherever a password is set.

/// Returns the reason a new password is not acceptable, if any.
pub fn password_policy_error(password: &str) -> Option<&'static str> {
    if password.chars().count() < 8 {
        return Some("Password must be at least 8 characters");
    }
    if !password.chars().any(char::is_uppercase) {
        return Some("Password must contain at least one uppercase letter");
    }
    if !password.chars().any(char::is_lowercase) {
        return Some("Password must contain at least one lowercase letter");
    }
    if !password.chars().any(char::is_numeric) {
        return Some("Password must contain at least one number");
    }
    if password.chars().all(char::is_alphanumeric) {
        return Some("Password must contain at least one special character");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::password_policy_error;

    #[test]
    fn accepts_a_password_meeting_every_rule() {
        assert_eq!(password_policy_error("LongEnough123!"), None);
    }

    #[test]
    fn rejects_each_missing_rule() {
        for weak in ["Aa1!", "aaaaaaaa1!", "AAAAAAAA1!", "Aaaaaaaa!", "Aaaaaaaa1"] {
            assert!(password_policy_error(weak).is_some(), "{weak} was accepted");
        }
    }
}
