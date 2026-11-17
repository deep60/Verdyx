//! Checks for YARA rules written by users (retrohunt), before they reach the
//! compiler.
//!
//! The gateway runs these to reject a rule straight away; the analysis
//! engine runs them again before compiling, and also refuses `include` at
//! the compiler, so a rule can never read files from the server.
//!
//! - at most [`MAX_RULE_BYTES`] and [`MAX_RULES`] rules, at least one;
//! - no `include` directives;
//! - `import` only of modules in [`ALLOWED_MODULES`] (not `console`, which
//!   writes to the server log, or `cuckoo`, which needs sandbox reports).

pub const MAX_RULE_BYTES: usize = 64 * 1024;
pub const MAX_RULES: usize = 50;
pub const ALLOWED_MODULES: [&str; 7] = ["pe", "elf", "math", "hash", "dotnet", "time", "string"];

/// What a valid rule set declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSummary {
    pub rule_names: Vec<String>,
    pub imports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Str(String),
}

/// Words and string literals outside comments. `$vars`, numbers, hex
/// strings and operators are skipped.
fn tokens(src: &str) -> Vec<Token> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        i += 1;
                    }
                    if let Some(&ch) = c.get(i) {
                        s.push(ch);
                    }
                    i += 1;
                }
                i += 1;
                out.push(Token::Str(s));
            }
            '$' | '#' | '@' | '!' => {
                // A string identifier or count/offset: skip its name.
                i += 1;
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_' || c[i] == '*') {
                    i += 1;
                }
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' => {
                let start = i;
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                out.push(Token::Word(c[start..i].iter().collect()));
            }
            _ => i += 1,
        }
    }
    out
}

/// Check a user's rule set. `Err` says what to change.
pub fn check(src: &str) -> Result<RuleSummary, String> {
    if src.trim().is_empty() {
        return Err("write at least one rule".to_string());
    }
    if src.len() > MAX_RULE_BYTES {
        return Err(format!("rules can be at most {} KB", MAX_RULE_BYTES / 1024));
    }
    let toks = tokens(src);
    let mut names = Vec::new();
    let mut imports = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        let Token::Word(w) = t else { continue };
        match w.as_str() {
            "include" => return Err("include isn't allowed; paste the rules instead".to_string()),
            "import" => match toks.get(i + 1) {
                Some(Token::Str(m)) if ALLOWED_MODULES.contains(&m.as_str()) => {
                    imports.push(m.clone())
                }
                Some(Token::Str(m)) => {
                    return Err(format!(
                        "the {m:?} module isn't available; use {}",
                        ALLOWED_MODULES.join(", ")
                    ))
                }
                _ => return Err("import needs a module name in quotes".to_string()),
            },
            "rule" => match toks.get(i + 1) {
                Some(Token::Word(n)) if !["meta", "strings", "condition"].contains(&n.as_str()) => {
                    names.push(n.clone())
                }
                _ => return Err("every rule needs a name".to_string()),
            },
            _ => {}
        }
    }
    if names.is_empty() {
        return Err("write at least one rule".to_string());
    }
    if names.len() > MAX_RULES {
        return Err(format!("at most {MAX_RULES} rules at a time"));
    }
    Ok(RuleSummary {
        rule_names: names,
        imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_rule_passes() {
        let s = check(
            r#"
            import "pe"
            // a comment with include "x"
            /* include "y" */
            private rule Helper { condition: pe.is_pe }
            rule Injector : tag1 {
                meta: description = "include in a string is fine"
                strings: $include = "CreateRemoteThread" nocase $h = { 6A 40 ?? 68 }
                condition: Helper and #include > 1 and @include[1] < 100
            }"#,
        )
        .unwrap();
        assert_eq!(s.rule_names, vec!["Helper", "Injector"]);
        assert_eq!(s.imports, vec!["pe"]);
    }

    #[test]
    fn includes_and_risky_modules_are_refused() {
        assert!(check("include \"/etc/passwd\"\nrule a { condition: true }").is_err());
        assert!(check("include\"x\" rule a { condition: true }").is_err());
        assert!(check("import \"console\"\nrule a { condition: console.log(\"x\") }").is_err());
        assert!(check("import \"cuckoo\"\nrule a { condition: true }").is_err());
        assert!(check("import pe\nrule a { condition: true }").is_err());
    }

    #[test]
    fn size_and_count_limits() {
        assert!(check("").is_err());
        assert!(check("   \n").is_err());
        assert!(check("// only a comment").is_err());
        assert!(check(&"x".repeat(MAX_RULE_BYTES + 1)).is_err());
        let many: String = (0..=MAX_RULES)
            .map(|i| format!("rule r{i} {{ condition: true }}\n"))
            .collect();
        assert!(check(&many).is_err());
        assert!(check("rule { condition: true }").is_err());
    }
}
