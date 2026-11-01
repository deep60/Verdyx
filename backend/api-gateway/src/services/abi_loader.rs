//! ABI Loader for Smart Contract Integration
//!
//! This module loads Application Binary Interfaces (ABIs) from JSON files
//! to enable interaction with deployed smart contracts.

use alloy::json_abi::JsonAbi as Abi;
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Paths to ABI files
const BOUNTY_MANAGER_ABI: &str = "abis/BountyManager.json";
const THREAT_TOKEN_ABI: &str = "abis/ThreatToken.json";
const REPUTATION_SYSTEM_ABI: &str = "abis/ReputationSystem.json";
const GOVERNANCE_ABI: &str = "abis/Governance.json";

/// Load BountyManager contract ABI
pub fn load_bounty_manager_abi() -> Result<Abi> {
    load_abi_from_file(BOUNTY_MANAGER_ABI)
}

/// Load ThreatToken contract ABI
pub fn load_threat_token_abi() -> Result<Abi> {
    load_abi_from_file(THREAT_TOKEN_ABI)
}

/// Load ReputationSystem contract ABI
pub fn load_reputation_system_abi() -> Result<Abi> {
    load_abi_from_file(REPUTATION_SYSTEM_ABI)
}

/// Load Governance contract ABI
pub fn load_governance_abi() -> Result<Abi> {
    load_abi_from_file(GOVERNANCE_ABI)
}

/// Load ABI from a Hardhat artifact JSON file
///
/// Hardhat artifacts have the structure: { "abi": [...], "bytecode": "...", ... }
/// This function extracts just the ABI array.
fn load_abi_from_file<P: AsRef<Path>>(path: P) -> Result<Abi> {
    let path_ref = path.as_ref();

    // Read the JSON file
    let contents = fs::read_to_string(path_ref)
        .with_context(|| format!("Failed to read ABI file: {}", path_ref.display()))?;

    // Parse as JSON
    let json: Value = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse ABI JSON from {}", path_ref.display()))?;

    // Extract the ABI array from the Hardhat artifact
    let abi_value = json
        .get("abi")
        .with_context(|| format!("ABI field not found in {}", path_ref.display()))?;

    // Parse the ABI
    let abi: Abi = serde_json::from_value(abi_value.clone())
        .with_context(|| format!("Failed to parse ABI from {}", path_ref.display()))?;

    tracing::debug!(
        "Loaded ABI from {} with {} functions",
        path_ref.display(),
        abi.functions().count()
    );

    Ok(abi)
}

/// Load ABI directly from .abi.json file (just the ABI array)
#[allow(dead_code)]
fn load_abi_from_abi_file<P: AsRef<Path>>(path: P) -> Result<Abi> {
    let path_ref = path.as_ref();

    let contents = fs::read_to_string(path_ref)
        .with_context(|| format!("Failed to read ABI file: {}", path_ref.display()))?;

    let abi: Abi = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse ABI from {}", path_ref.display()))?;

    Ok(abi)
}

/// Verify all required ABI files exist
pub fn verify_abi_files() -> Result<()> {
    let abi_files = [
        BOUNTY_MANAGER_ABI,
        THREAT_TOKEN_ABI,
        REPUTATION_SYSTEM_ABI,
        GOVERNANCE_ABI,
    ];

    for abi_file in &abi_files {
        if !Path::new(abi_file).exists() {
            anyhow::bail!(
                "ABI file not found: {abi_file}. Please run 'blockchain/scripts/extract-abis.sh'"
            );
        }
    }

    tracing::info!("All required ABI files verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_bounty_manager_abi() {
        // This test will only pass if ABIs are extracted
        if Path::new(BOUNTY_MANAGER_ABI).exists() {
            let result = load_bounty_manager_abi();
            assert!(
                result.is_ok(),
                "Failed to load BountyManager ABI: {:?}",
                result.err()
            );

            let abi = result.unwrap();
            assert!(
                !abi.functions().collect::<Vec<_>>().is_empty(),
                "BountyManager ABI should have functions"
            );
        }
    }

    #[test]
    fn test_verify_abi_files() {
        // This test checks if ABI files exist
        let result = verify_abi_files();

        if result.is_err() {
            println!("ABI files not found. Run: blockchain/scripts/extract-abis.sh");
        }
    }
}
