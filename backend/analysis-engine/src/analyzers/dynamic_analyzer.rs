use crate::sandbox::{Container, Monitor, ReportGenerator};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Verdict for dynamic analysis (local to this module)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Benign,
    Suspicious,
    Malicious,
    Error,
}

/// Threat indicator produced by dynamic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub value: String,
    pub severity: String,
    pub description: String,
    pub source: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Scan job description for dynamic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: Uuid,
    pub file_path: PathBuf,
    pub priority: u8,
}

/// Result of a dynamic analysis run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAnalysisResult {
    pub analysis_id: Uuid,
    pub engine_name: String,
    pub verdict: Verdict,
    pub confidence_score: f32,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub error_message: Option<String>,
}

/// Configuration for dynamic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAnalyzerConfig {
    /// Maximum execution time for analysis
    pub max_execution_time: Duration,
    /// Sandbox environment type (docker, vm, etc.)
    pub sandbox_type: SandboxType,
    /// Resource limits for sandbox
    pub resource_limits: ResourceLimits,
    /// Network isolation settings
    pub network_config: NetworkConfig,
    /// Monitoring settings
    pub monitoring_config: MonitoringConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxType {
    Docker,
    VirtualMachine,
    Container,
    Chroot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: u64,
    pub max_cpu_percent: u8,
    pub max_disk_mb: u64,
    pub max_network_bandwidth_kbps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub internet_access: bool,
    pub allowed_domains: Vec<String>,
    pub blocked_ips: Vec<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub monitor_file_system: bool,
    pub monitor_network: bool,
    pub monitor_registry: bool,
    pub monitor_processes: bool,
    pub capture_screenshots: bool,
    pub capture_pcap: bool,
}

/// Dynamic behavior observed during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicBehavior {
    pub file_operations: Vec<FileOperation>,
    pub network_operations: Vec<NetworkOperation>,
    pub process_operations: Vec<ProcessOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub system_calls: Vec<SystemCall>,
    pub screenshots: Vec<Screenshot>,
    pub network_capture: Option<NetworkCapture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation_type: FileOperationType,
    pub source_path: PathBuf,
    pub target_path: Option<PathBuf>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperationType {
    Create,
    Delete,
    Modify,
    Copy,
    Move,
    Read,
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOperation {
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub connection_state: ConnectionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    Connecting,
    Failed,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperation {
    pub operation_type: ProcessOperationType,
    pub process_name: String,
    pub process_id: u32,
    pub parent_process_id: Option<u32>,
    pub command_line: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessOperationType {
    Create,
    Terminate,
    Inject,
    Hollow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    pub operation_type: RegistryOperationType,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOperationType {
    CreateKey,
    DeleteKey,
    SetValue,
    DeleteValue,
    QueryValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCall {
    pub call_name: String,
    pub parameters: HashMap<String, String>,
    pub return_value: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Screenshot {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub image_data: Vec<u8>,
    pub image_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCapture {
    pub pcap_data: Vec<u8>,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub packet_count: u32,
}

/// Threat indicators derived from dynamic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicThreatIndicators {
    pub malicious_network_connections: Vec<String>,
    pub suspicious_file_operations: Vec<String>,
    pub malicious_processes: Vec<String>,
    pub registry_modifications: Vec<String>,
    pub persistence_mechanisms: Vec<String>,
    pub evasion_techniques: Vec<String>,
    pub data_exfiltration_attempts: Vec<String>,
}

/// Main dynamic analyzer implementation
pub struct DynamicAnalyzer {
    config: DynamicAnalyzerConfig,
    container_manager: Container,
    monitor: Monitor,
    report_generator: ReportGenerator,
}

impl Default for DynamicAnalyzerConfig {
    fn default() -> Self {
        Self {
            max_execution_time: Duration::from_secs(300), // 5 minutes
            sandbox_type: SandboxType::Docker,
            resource_limits: ResourceLimits {
                max_memory_mb: 1024,
                max_cpu_percent: 50,
                max_disk_mb: 2048,
                max_network_bandwidth_kbps: 1000,
            },
            network_config: NetworkConfig {
                internet_access: false,
                allowed_domains: vec![],
                blocked_ips: vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()],
                dns_servers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            },
            monitoring_config: MonitoringConfig {
                monitor_file_system: true,
                monitor_network: true,
                monitor_registry: true,
                monitor_processes: true,
                capture_screenshots: true,
                capture_pcap: true,
            },
        }
    }
}

impl DynamicAnalyzer {
    /// Create a new dynamic analyzer instance
    pub fn new(config: DynamicAnalyzerConfig) -> Result<Self> {
        let container_manager = Container::new(&config)?;
        let monitor = Monitor::new(&config.monitoring_config)?;
        let report_generator = ReportGenerator::new()?;

        Ok(Self {
            config,
            container_manager,
            monitor,
            report_generator,
        })
    }

    /// Analyze a file dynamically in a sandbox environment
    pub async fn analyze_file(
        &mut self,
        file_path: &Path,
        job: &ScanJob,
    ) -> Result<DynamicAnalysisResult> {
        let analysis_id = Uuid::new_v4();
        let start_time = Instant::now();

        info!(
            "Starting dynamic analysis for job {}: {:?}",
            job.id, file_path
        );

        // Create isolated sandbox environment
        let sandbox_id = self
            .create_sandbox(analysis_id)
            .await
            .context("Failed to create sandbox environment")?;

        let mut analysis_result = DynamicAnalysisResult {
            analysis_id,
            engine_name: "dynamic_analyzer".to_string(),
            verdict: Verdict::Benign,
            confidence_score: 0.0,
            threat_indicators: Vec::new(),
            metadata: HashMap::new(),
            error_message: None,
        };

        match self
            .execute_dynamic_analysis(&sandbox_id, file_path, &analysis_id)
            .await
        {
            Ok(behavior) => {
                // Analyze behaviors for threats
                let threat_indicators = self.analyze_behavior(&behavior).await?;

                // Generate comprehensive report
                let report = self
                    .report_generator
                    .generate_dynamic_report(&behavior, &threat_indicators)
                    .await?;

                analysis_result.verdict = self.determine_verdict(&threat_indicators);
                analysis_result.confidence_score =
                    self.calculate_confidence(&behavior, &threat_indicators);
                analysis_result.threat_indicators = threat_indicators.into_generic_indicators();
                analysis_result
                    .metadata
                    .insert("dynamic_report".to_string(), serde_json::to_value(report)?);
                analysis_result.metadata.insert(
                    "execution_time_ms".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(
                        start_time.elapsed().as_millis() as u64,
                    )),
                );
            }
            Err(e) => {
                error!("Dynamic analysis failed for job {}: {}", job.id, e);
                analysis_result.verdict = Verdict::Error;
                analysis_result.error_message = Some(format!("Dynamic analysis failed: {e}"));
            }
        }

        // Cleanup sandbox
        if let Err(e) = self.cleanup_sandbox(&sandbox_id).await {
            warn!("Failed to cleanup sandbox {}: {}", sandbox_id, e);
        }

        Ok(analysis_result)
    }

    /// Create an isolated sandbox environment
    async fn create_sandbox(&mut self, analysis_id: Uuid) -> Result<String> {
        debug!("Creating sandbox for analysis {}", analysis_id);

        let sandbox_config = self.container_manager.create_sandbox_config(&self.config)?;
        let sandbox_id = self
            .container_manager
            .create_container(sandbox_config)
            .await
            .context("Failed to create container")?;

        // Apply resource limits
        self.container_manager
            .apply_resource_limits(&sandbox_id, &self.config.resource_limits)
            .await?;

        // Configure network isolation
        self.container_manager
            .configure_network(&sandbox_id, &self.config.network_config)
            .await?;

        Ok(sandbox_id)
    }

    /// Execute the dynamic analysis within the sandbox
    async fn execute_dynamic_analysis(
        &self,
        sandbox_id: &str,
        file_path: &Path,
        analysis_id: &Uuid,
    ) -> Result<DynamicBehavior> {
        debug!("Executing dynamic analysis in sandbox {}", sandbox_id);

        // Copy file to sandbox
        let sandbox_file_path = self
            .container_manager
            .copy_file_to_sandbox(sandbox_id, file_path)
            .await?;

        // Start monitoring
        let monitor_handle = self
            .monitor
            .start_monitoring(sandbox_id, analysis_id)
            .await?;

        // Execute the file with timeout
        let execution_result = timeout(
            self.config.max_execution_time,
            self.execute_file_in_sandbox(sandbox_id, &sandbox_file_path),
        )
        .await;

        match execution_result {
            Ok(Ok(_)) => {
                info!("File execution completed normally");
            }
            Ok(Err(e)) => {
                warn!("File execution failed: {}", e);
            }
            Err(_) => {
                warn!(
                    "File execution timed out after {:?}",
                    self.config.max_execution_time
                );
            }
        }

        // Stop monitoring and collect results
        let behavior = self
            .monitor
            .stop_monitoring_and_collect(monitor_handle)
            .await?;

        Ok(behavior)
    }

    /// Execute a file within the sandbox
    async fn execute_file_in_sandbox(&self, sandbox_id: &str, file_path: &Path) -> Result<()> {
        let file_extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        let execution_command = match file_extension.to_lowercase().as_str() {
            "exe" | "dll" | "scr" | "com" | "bat" | "cmd" => {
                // Windows executable
                format!("wine {}", file_path.display())
            }
            "sh" | "bash" => {
                // Shell script
                format!("bash {}", file_path.display())
            }
            "py" | "pyc" => {
                // Python script
                format!("python3 {}", file_path.display())
            }
            "js" => {
                // JavaScript
                format!("node {}", file_path.display())
            }
            "jar" => {
                // Java archive
                format!("java -jar {}", file_path.display())
            }
            _ => {
                // Try to execute directly
                file_path.display().to_string()
            }
        };

        debug!("Executing command in sandbox: {}", execution_command);

        let output = self
            .container_manager
            .execute_command(sandbox_id, &execution_command)
            .await
            .context("Failed to execute file in sandbox")?;

        debug!("Execution output: {:?}", output);

        Ok(())
    }

    /// Analyze observed behavior for threat indicators
    async fn analyze_behavior(
        &self,
        behavior: &DynamicBehavior,
    ) -> Result<DynamicThreatIndicators> {
        debug!("Analyzing dynamic behavior for threats");

        let mut indicators = DynamicThreatIndicators {
            malicious_network_connections: Vec::new(),
            suspicious_file_operations: Vec::new(),
            malicious_processes: Vec::new(),
            registry_modifications: Vec::new(),
            persistence_mechanisms: Vec::new(),
            evasion_techniques: Vec::new(),
            data_exfiltration_attempts: Vec::new(),
        };

        // Analyze network operations
        for net_op in &behavior.network_operations {
            if self.is_suspicious_network_operation(net_op) {
                indicators.malicious_network_connections.push(format!(
                    "{}:{} -> {}:{}",
                    net_op.source_ip,
                    net_op.source_port,
                    net_op.destination_ip,
                    net_op.destination_port
                ));
            }
        }

        // Analyze file operations
        for file_op in &behavior.file_operations {
            if self.is_suspicious_file_operation(file_op) {
                indicators.suspicious_file_operations.push(format!(
                    "{:?}: {}",
                    file_op.operation_type,
                    file_op.source_path.display()
                ));
            }
        }

        // Analyze process operations
        for proc_op in &behavior.process_operations {
            if self.is_suspicious_process_operation(proc_op) {
                indicators.malicious_processes.push(format!(
                    "{} (PID: {}): {}",
                    proc_op.process_name, proc_op.process_id, proc_op.command_line
                ));
            }
        }

        // Analyze registry operations
        for reg_op in &behavior.registry_operations {
            if self.is_suspicious_registry_operation(reg_op) {
                indicators
                    .registry_modifications
                    .push(format!("{:?}: {}", reg_op.operation_type, reg_op.key_path));
            }

            if self.is_persistence_mechanism(reg_op) {
                indicators
                    .persistence_mechanisms
                    .push(format!("Registry persistence: {}", reg_op.key_path));
            }
        }

        // Check for evasion techniques
        self.detect_evasion_techniques(behavior, &mut indicators)
            .await?;

        // Check for data exfiltration
        self.detect_data_exfiltration(behavior, &mut indicators)
            .await?;

        Ok(indicators)
    }

    /// Check if a network operation is suspicious
    fn is_suspicious_network_operation(&self, net_op: &NetworkOperation) -> bool {
        // Check for connections to known malicious IPs
        if self.is_known_malicious_ip(&net_op.destination_ip) {
            return true;
        }

        // Check for suspicious ports
        let suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337];
        if suspicious_ports.contains(&net_op.destination_port) {
            return true;
        }

        // Check for high data transfer
        if net_op.bytes_sent > 10_000_000 || net_op.bytes_received > 10_000_000 {
            return true;
        }

        false
    }

    /// Check if a file operation is suspicious
    fn is_suspicious_file_operation(&self, file_op: &FileOperation) -> bool {
        let path_str = file_op.source_path.to_string_lossy().to_lowercase();

        // Check for operations in sensitive directories
        let sensitive_dirs = [
            "system32",
            "windows",
            "program files",
            "appdata",
            "temp",
            "startup",
        ];

        if sensitive_dirs.iter().any(|&dir| path_str.contains(dir)) {
            matches!(
                file_op.operation_type,
                FileOperationType::Create | FileOperationType::Modify | FileOperationType::Delete
            )
        } else {
            false
        }
    }

    /// Check if a process operation is suspicious
    fn is_suspicious_process_operation(&self, proc_op: &ProcessOperation) -> bool {
        let cmd_lower = proc_op.command_line.to_lowercase();

        // Check for suspicious commands
        let suspicious_commands = [
            "powershell",
            "cmd",
            "wmic",
            "reg",
            "sc",
            "net",
            "taskkill",
            "schtasks",
        ];

        if suspicious_commands
            .iter()
            .any(|&cmd| cmd_lower.contains(cmd))
        {
            return true;
        }

        // Check for process injection/hollowing
        matches!(
            proc_op.operation_type,
            ProcessOperationType::Inject | ProcessOperationType::Hollow
        )
    }

    /// Check if a registry operation is suspicious
    fn is_suspicious_registry_operation(&self, reg_op: &RegistryOperation) -> bool {
        let key_lower = reg_op.key_path.to_lowercase();

        // Check for modifications to security-related keys
        let security_keys = [
            "software\\microsoft\\windows\\currentversion\\policies",
            "software\\microsoft\\windows defender",
            "system\\currentcontrolset\\services\\sharedaccess\\parameters\\firewallpolicy",
        ];

        security_keys.iter().any(|&key| key_lower.contains(key))
    }

    /// Check if a registry operation establishes persistence
    fn is_persistence_mechanism(&self, reg_op: &RegistryOperation) -> bool {
        let key_lower = reg_op.key_path.to_lowercase();

        let persistence_keys = [
            "software\\microsoft\\windows\\currentversion\\run",
            "software\\microsoft\\windows\\currentversion\\runonce",
            "system\\currentcontrolset\\services",
        ];

        persistence_keys.iter().any(|&key| key_lower.contains(key))
    }

    /// Detect evasion techniques
    async fn detect_evasion_techniques(
        &self,
        behavior: &DynamicBehavior,
        indicators: &mut DynamicThreatIndicators,
    ) -> Result<()> {
        // Check for timing-based evasion (long sleeps)
        for syscall in &behavior.system_calls {
            if syscall.call_name.contains("sleep") || syscall.call_name.contains("delay") {
                if let Some(param) = syscall.parameters.get("duration") {
                    if let Ok(duration) = param.parse::<u64>() {
                        if duration > 10000 {
                            // 10+ seconds
                            indicators
                                .evasion_techniques
                                .push("Long sleep detected".to_string());
                        }
                    }
                }
            }
        }

        // Check for sandbox detection attempts
        for file_op in &behavior.file_operations {
            let path_str = file_op.source_path.to_string_lossy().to_lowercase();
            let sandbox_indicators = ["vmware", "virtualbox", "qemu", "xen", "vbox", "vmtools"];

            if sandbox_indicators
                .iter()
                .any(|&indicator| path_str.contains(indicator))
            {
                indicators
                    .evasion_techniques
                    .push("Sandbox detection attempt".to_string());
            }
        }

        Ok(())
    }

    /// Detect data exfiltration attempts
    async fn detect_data_exfiltration(
        &self,
        behavior: &DynamicBehavior,
        indicators: &mut DynamicThreatIndicators,
    ) -> Result<()> {
        // Check for large outbound data transfers
        for net_op in &behavior.network_operations {
            if net_op.bytes_sent > 1_000_000 {
                // 1MB+
                indicators.data_exfiltration_attempts.push(format!(
                    "Large data transfer: {} bytes to {}:{}",
                    net_op.bytes_sent, net_op.destination_ip, net_op.destination_port
                ));
            }
        }

        // Check for access to sensitive files
        let sensitive_files = [
            "passwords",
            "credentials",
            "keystore",
            "wallet",
            "private",
            "secret",
        ];

        for file_op in &behavior.file_operations {
            let path_str = file_op.source_path.to_string_lossy().to_lowercase();

            if sensitive_files
                .iter()
                .any(|&pattern| path_str.contains(pattern))
            {
                indicators.data_exfiltration_attempts.push(format!(
                    "Access to sensitive file: {}",
                    file_op.source_path.display()
                ));
            }
        }

        Ok(())
    }

    /// Check if an IP address is known to be malicious
    fn is_known_malicious_ip(&self, ip: &str) -> bool {
        // In a real implementation, this would query threat intelligence feeds
        // For now, just check some basic patterns
        ip.starts_with("10.") || ip.starts_with("192.168.") || ip == "127.0.0.1"
    }

    /// Determine the final verdict based on threat indicators
    fn determine_verdict(&self, indicators: &DynamicThreatIndicators) -> Verdict {
        let total_indicators = indicators.malicious_network_connections.len()
            + indicators.suspicious_file_operations.len()
            + indicators.malicious_processes.len()
            + indicators.registry_modifications.len()
            + indicators.persistence_mechanisms.len()
            + indicators.evasion_techniques.len()
            + indicators.data_exfiltration_attempts.len();

        match total_indicators {
            0 => Verdict::Benign,
            1..=3 => Verdict::Suspicious,
            _ => Verdict::Malicious,
        }
    }

    /// Calculate confidence score based on behavior analysis
    fn calculate_confidence(
        &self,
        behavior: &DynamicBehavior,
        indicators: &DynamicThreatIndicators,
    ) -> f32 {
        let base_confidence = 0.7; // Base confidence for dynamic analysis

        let indicator_count = indicators.malicious_network_connections.len()
            + indicators.suspicious_file_operations.len()
            + indicators.malicious_processes.len()
            + indicators.registry_modifications.len()
            + indicators.persistence_mechanisms.len()
            + indicators.evasion_techniques.len()
            + indicators.data_exfiltration_attempts.len();

        let behavior_richness = (behavior.file_operations.len()
            + behavior.network_operations.len()
            + behavior.process_operations.len()) as f32
            / 100.0;

        let confidence =
            base_confidence + (indicator_count as f32 * 0.05) + behavior_richness.min(0.2);
        confidence.min(1.0)
    }

    /// Cleanup sandbox environment
    async fn cleanup_sandbox(&mut self, sandbox_id: &str) -> Result<()> {
        debug!("Cleaning up sandbox {}", sandbox_id);
        self.container_manager.remove_container(sandbox_id).await
    }
}

impl DynamicThreatIndicators {
    /// Convert to generic threat indicators
    pub fn into_generic_indicators(self) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();

        // Add network indicators
        for conn in self.malicious_network_connections {
            indicators.push(ThreatIndicator {
                indicator_type: "network_connection".to_string(),
                value: conn,
                severity: "high".to_string(),
                description: "Malicious network connection detected".to_string(),
                source: "dynamic_analyzer".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Add file indicators
        for file_op in self.suspicious_file_operations {
            indicators.push(ThreatIndicator {
                indicator_type: "file_operation".to_string(),
                value: file_op,
                severity: "medium".to_string(),
                description: "Suspicious file operation detected".to_string(),
                source: "dynamic_analyzer".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Add process indicators
        for process in self.malicious_processes {
            indicators.push(ThreatIndicator {
                indicator_type: "process".to_string(),
                value: process,
                severity: "high".to_string(),
                description: "Malicious process behavior detected".to_string(),
                source: "dynamic_analyzer".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Add registry indicators
        for reg_mod in self.registry_modifications {
            indicators.push(ThreatIndicator {
                indicator_type: "registry".to_string(),
                value: reg_mod,
                severity: "medium".to_string(),
                description: "Suspicious registry modification detected".to_string(),
                source: "dynamic_analyzer".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Add persistence indicators
        for persistence in self.persistence_mechanisms {
            indicators.push(ThreatIndicator {
                indicator_type: "persistence".to_string(),
                value: persistence,
                severity: "high".to_string(),
                description: "Persistence mechanism detected".to_string(),
                source: "dynamic_analyzer".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Add evasion indicators
        for evasion in self.evasion_techniques {
            indicators.push(ThreatIndicator {
                indicator_type: "evasion".to_string(),
                value: evasion,
                severity: "medium".to_string(),
                description: "Evasion technique detected".to_string(),
                source: "dynamic_analyzer".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Add exfiltration indicators
        for exfiltration in self.data_exfiltration_attempts {
            indicators.push(ThreatIndicator {
                indicator_type: "data_exfiltration".to_string(),
                value: exfiltration,
                severity: "critical".to_string(),
                description: "Data exfiltration attempt detected".to_string(),
                source: "dynamic_analyzer".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        indicators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dynamic_analyzer_creation() {
        let config = DynamicAnalyzerConfig::default();
        let analyzer = DynamicAnalyzer::new(config);
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_suspicious_network_operation_detection() {
        let analyzer = DynamicAnalyzer::new(DynamicAnalyzerConfig::default()).unwrap();

        let suspicious_op = NetworkOperation {
            protocol: "TCP".to_string(),
            source_ip: "192.168.1.100".to_string(),
            source_port: 12345,
            destination_ip: "suspicious.example.com".to_string(),
            destination_port: 4444,
            bytes_sent: 1000,
            bytes_received: 1000,
            timestamp: chrono::Utc::now(),
            connection_state: ConnectionState::Established,
        };

        assert!(analyzer.is_suspicious_network_operation(&suspicious_op));
    }

    #[test]
    fn test_threat_indicators_conversion() {
        let indicators = DynamicThreatIndicators {
            malicious_network_connections: vec!["192.168.1.1:4444".to_string()],
            suspicious_file_operations: vec!["Create: /tmp/suspicious.exe".to_string()],
            malicious_processes: vec!["powershell.exe".to_string()],
            registry_modifications: vec!["HKLM\\Software\\Test".to_string()],
            persistence_mechanisms: vec!["Registry Run key".to_string()],
            evasion_techniques: vec!["Sleep evasion".to_string()],
            data_exfiltration_attempts: vec!["Large upload".to_string()],
        };

        let generic_indicators = indicators.into_generic_indicators();
        assert_eq!(generic_indicators.len(), 7);
        assert!(generic_indicators
            .iter()
            .any(|i| i.indicator_type == "network_connection"));
        assert!(generic_indicators
            .iter()
            .any(|i| i.indicator_type == "persistence"));
    }
}
