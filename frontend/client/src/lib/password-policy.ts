// The build target predates regex literals with the `u` flag.
const UPPERCASE = new RegExp("\\p{Uppercase}", "u");
const LOWERCASE = new RegExp("\\p{Lowercase}", "u");
const NUMBER = new RegExp("\\p{N}", "u");
const SPECIAL = new RegExp("[^\\p{Alphabetic}\\p{N}]", "u");

// Mirrors shared::password_policy in the backend, so people see the reason
// before submitting. The backend still enforces it.
export function passwordPolicyError(password: string): string | null {
  if (Array.from(password).length < 8) return "Password must be at least 8 characters";
  if (!UPPERCASE.test(password)) return "Password must contain at least one uppercase letter";
  if (!LOWERCASE.test(password)) return "Password must contain at least one lowercase letter";
  if (!NUMBER.test(password)) return "Password must contain at least one number";
  if (!SPECIAL.test(password)) return "Password must contain at least one special character";
  return null;
}
