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
    }

    fn add_malware_rules(&mut self) {
        // Suspicious API calls
        self.rules.push(HeuristicRule {
            id: "HEUR_001".to_string(),
            name: "Suspicious Windows API Sequence".to_string(),
            description: "Detects suspicious sequence of Windows API calls commonly used by malware".to_string(),
            pattern: Regex::new(r"(?i)(CreateProcess|WriteProcessMemory|VirtualAllocEx|SetWindowsHookEx|GetProcAddress)").unwrap(),
            severity: HeuristicSeverity::Medium,
            confidence: 0.7,
            file_types: vec!["exe".to_string(), "dll".to_string(), "scr".to_string()],
            context_extractor: Some(extract_api_context),
        });

        // Registry manipulation
        self.rules.push(HeuristicRule {
            id: "HEUR_002".to_string(),
            name: "Registry Persistence".to_string(),
            description: "Detects attempts to modify registry for persistence".to_string(),
            pattern: Regex::new(r"(?i)(HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)").unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.8,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_registry_context),
        });

        // Process hollowing indicators
        self.rules.push(HeuristicRule {
            id: "HEUR_003".to_string(),
            name: "Process Hollowing Pattern".to_string(),
            description: "Detects patterns indicative of process hollowing technique".to_string(),
            pattern: Regex::new(r"(?i)(NtUnmapViewOfSection|CreateProcessA.*SUSPENDED|WriteProcessMemory.*ResumeThread)").unwrap(),
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

        // ROP gadgets
        self.rules.push(HeuristicRule {
            id: "HEUR_102".to_string(),
            name: "ROP Gadget Chain".to_string(),
            description: "Detects potential ROP (Return Oriented Programming) gadgets".to_string(),
            pattern: Regex::new(r"(\x58\xc3|\x5d\xc3|\x5b\xc3)").unwrap(), // pop reg; ret patterns
            severity: HeuristicSeverity::Medium,
            confidence: 0.5,
            file_types: vec!["exe".to_string(), "dll".to_string()],
            context_extractor: None,
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
                r"(?i)(POST.*admin\.php|GET.*gate\.php|User-Agent:\s*(Mozilla/4\.0|curl))",
            )
            .unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.7,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_network_context),
        });

        // Suspicious domains
        self.rules.push(HeuristicRule {
            id: "HEUR_202".to_string(),
            name: "Suspicious Domain Pattern".to_string(),
            description: "Detects connections to suspicious domains".to_string(),
            pattern: Regex::new(r"(?i)([a-z]{10,}\.tk|[a-z]{10,}\.ml|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})").unwrap(),
            severity: HeuristicSeverity::Medium,
            confidence: 0.6,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_domain_context),
        });

        // IRC bot patterns
        self.rules.push(HeuristicRule {
            id: "HEUR_203".to_string(),
            name: "IRC Bot Pattern".to_string(),
            description: "Detects IRC bot communication patterns".to_string(),
            pattern: Regex::new(r"(?i)(PRIVMSG.*!bot|JOIN\s+#[a-z]+|NICK.*bot[0-9]+)").unwrap(),
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

        // XOR obfuscation
        self.rules.push(HeuristicRule {
            id: "HEUR_302".to_string(),
            name: "XOR Obfuscation".to_string(),
            description: "Detects XOR obfuscation patterns".to_string(),
            pattern: Regex::new(r"(\x00[\x01-\xff]\x00[\x01-\xff]){10,}").unwrap(),
            severity: HeuristicSeverity::Medium,
            confidence: 0.5,
            file_types: vec!["exe".to_string(), "dll".to_string()],
            context_extractor: None,
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
            pattern: Regex::new(r"(?i)(stratum\+tcp://|pool\..*\..*:.*|.*\.nicehash\.com)")
                .unwrap(),
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
            pattern: Regex::new(r"(?i)(\.encrypted|\.locked|\.crypto|YOUR_FILES_ARE_ENCRYPTED)")
                .unwrap(),
            severity: HeuristicSeverity::Critical,
            confidence: 0.9,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_ransomware_context),
        });

        // Bitcoin payment demands
        self.rules.push(HeuristicRule {
            id: "HEUR_502".to_string(),
            name: "Bitcoin Payment Demand".to_string(),
            description: "Detects bitcoin addresses and payment demands".to_string(),
            pattern: Regex::new(r"(?i)([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})")
                .unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.8,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_bitcoin_context),
        });
    }

    fn add_stealer_rules(&mut self) {
        // Password/credential stealing patterns
        self.rules.push(HeuristicRule {
            id: "HEUR_601".to_string(),
            name: "Credential Stealer Pattern".to_string(),
            description: "Detects patterns indicative of credential stealing".to_string(),
            pattern: Regex::new(
                r"(?i)(passwords?|login|credential|keylog|\\Cookies\\|\\History\\)",
            )
            .unwrap(),
            severity: HeuristicSeverity::High,
            confidence: 0.6,
            file_types: vec!["*".to_string()],
            context_extractor: Some(extract_stealer_context),
        });

        // Browser data theft
        self.rules.push(HeuristicRule {
            id: "HEUR_602".to_string(),
            name: "Browser Data Theft".to_string(),
            description: "Detects attempts to steal browser data".to_string(),
            pattern: Regex::new(r"(?i)(Chrome\\User Data|Firefox\\Profiles|Opera\\|Safari\\)")
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

    pub fn calculate_risk_score(&self, matches: &[HeuristicMatch]) -> f32 {
        if matches.is_empty() {
            return 0.0;
        }

        let total_weighted_score: f32 = matches
            .iter()
            .map(|m| m.severity.score() as f32 * m.confidence)
            .sum();

        let max_possible_score = matches.len() as f32 * 10.0; // Max severity * max confidence

        (total_weighted_score / max_possible_score) * 100.0
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

// Context extraction functions
fn extract_api_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    // Extract surrounding context (100 chars before and after)
    let start = offset.saturating_sub(100);
    let end = std::cmp::min(offset + 100, content.len());
    let surrounding = &content[start..end];

    context.insert("surrounding_context".to_string(), surrounding.to_string());
    context.insert("api_sequence".to_string(), "detected".to_string());

    context
}

fn extract_registry_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    // Look for registry key patterns
    let start = offset.saturating_sub(50);
    let end = std::cmp::min(offset + 200, content.len());
    let surrounding = &content[start..end];

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
    let pattern = &content[start..end];

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
    let shellcode = &content[start..end];

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
    let network_data = &content[start..end];

    context.insert(
        "network_communication".to_string(),
        network_data.to_string(),
    );
    context.insert("communication_type".to_string(), "c2_pattern".to_string());

    context
}

fn extract_domain_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(30);
    let end = std::cmp::min(offset + 100, content.len());
    let domain_context = &content[start..end];

    context.insert("domain_context".to_string(), domain_context.to_string());

    context
}

fn extract_base64_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset;
    let end = std::cmp::min(offset + 200, content.len());
    let b64_content = &content[start..end];

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
    let obfuscated = &content[start..end];

    context.insert("obfuscated_string".to_string(), obfuscated.to_string());
    context.insert("obfuscation_type".to_string(), "hex_escape".to_string());

    context
}

fn extract_mining_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(30);
    let end = std::cmp::min(offset + 100, content.len());
    let mining_data = &content[start..end];

    context.insert("mining_pool".to_string(), mining_data.to_string());

    context
}

fn extract_ransomware_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(50);
    let end = std::cmp::min(offset + 200, content.len());
    let ransom_context = &content[start..end];

    context.insert("ransom_message".to_string(), ransom_context.to_string());

    context
}

fn extract_bitcoin_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(50);
    let end = std::cmp::min(offset + 100, content.len());
    let payment_context = &content[start..end];

    context.insert("payment_demand".to_string(), payment_context.to_string());

    context
}

fn extract_stealer_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(50);
    let end = std::cmp::min(offset + 150, content.len());
    let stealer_context = &content[start..end];

    context.insert("credential_target".to_string(), stealer_context.to_string());

    context
}

fn extract_browser_context(content: &str, offset: usize) -> HashMap<String, String> {
    let mut context = HashMap::new();

    let start = offset.saturating_sub(30);
    let end = std::cmp::min(offset + 100, content.len());
    let browser_path = &content[start..end];

    context.insert("browser_data_path".to_string(), browser_path.to_string());

    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
        let malicious_content = "CreateProcess WriteProcessMemory VirtualAllocEx";

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
    async fn test_bitcoin_address_detection() {
        let engine = HeuristicEngine::new();
        let bitcoin_content = "Send payment to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

        let matches = engine
            .analyze_content(bitcoin_content, Path::new("test.txt"))
            .await
            .unwrap();
        assert!(!matches.is_empty());

        let bitcoin_match = matches.iter().find(|m| m.rule_id == "HEUR_502");
        assert!(bitcoin_match.is_some());
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

        let risk_score = engine.calculate_risk_score(&matches);
        assert!(risk_score > 0.0);
        assert!(risk_score <= 100.0);
    }

    #[tokio::test]
    async fn test_file_type_filtering() {
        let engine = HeuristicEngine::new();

        // Test with .exe file - should match executable rules
        let exe_content = "CreateProcess WriteProcessMemory";
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

        // Clean files should have low or zero risk scores
        assert!(risk_score < 10.0);
    }

    #[tokio::test]
    async fn test_context_extraction() {
        let engine = HeuristicEngine::new();
        let content_with_context = "Before context CreateProcess WriteProcessMemory After context";

        let matches = engine
            .analyze_content(content_with_context, Path::new("test.exe"))
            .await
            .unwrap();

        if let Some(api_match) = matches.iter().find(|m| m.rule_id == "HEUR_001") {
            assert!(api_match.context.contains_key("surrounding_context"));
            assert!(api_match.context.contains_key("api_sequence"));
        }
    }

    #[tokio::test]
    async fn test_multiple_threat_types() {
        let engine = HeuristicEngine::new();
        let multi_threat_content = r#"
            CreateProcess WriteProcessMemory
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
        assert!(matches.len() >= 5);

        // Verify we have matches from different categories
        let rule_ids: Vec<&String> = matches.iter().map(|m| &m.rule_id).collect();
        assert!(rule_ids.contains(&&"HEUR_001".to_string())); // Malware API
        assert!(rule_ids.contains(&&"HEUR_002".to_string())); // Registry persistence
        assert!(rule_ids.contains(&&"HEUR_401".to_string())); // Mining pool
        assert!(rule_ids.contains(&&"HEUR_501".to_string())); // Ransomware
        assert!(rule_ids.contains(&&"HEUR_502".to_string())); // Bitcoin address

        let risk_score = engine.calculate_risk_score(&matches);
        assert!(risk_score > 50.0); // Should be considered high risk
    }
}
