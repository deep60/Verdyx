// Post-deployment configuration script that:

// Configures roles and permissions between contracts
// Validates system configuration against deployed constants
// Prepares initial analysis engines for registration

import hre, { ethers } from "hardhat";
import { readFileSync } from "fs";
import { join } from "path";
import { DeploymentAddresses } from "./deploy";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

interface SetupConfig {
    // System Roles
    adminAddresses: string[];
    engineAddresses: string[];
}

const DEFAULT_CONFIG: SetupConfig = {
    adminAddresses: [],
    engineAddresses: []
};

async function loadDeploymentAddresses(networkName: string, chainId: number): Promise<DeploymentAddresses> {
    const deploymentFile = join(__dirname, "..", "deployments", `${networkName}-${chainId}.json`);

    try {
        const data = readFileSync(deploymentFile, "utf8");
        return JSON.parse(data);
    } catch (_error) {
        throw new Error(`❌ Could not load deployment addresses from ${deploymentFile}. Run deploy.ts first.`);
    }
}

async function setupRoles(deploymentAddresses: DeploymentAddresses, config: SetupConfig, signer: HardhatEthersSigner) {
    console.log("\n👥 Setting up roles...");

    const reputationSystem = await ethers.getContractAt("ReputationSystem", deploymentAddresses.reputationSystem, signer);
    const bountyManager = await ethers.getContractAt("BountyManager", deploymentAddresses.bountyManager, signer);
    const threatToken = await ethers.getContractAt("ThreatToken", deploymentAddresses.threatToken, signer);

    // Grant BOUNTY_MANAGER_ROLE to BountyManager contract in ReputationSystem
    const BOUNTY_MANAGER_ROLE = await reputationSystem.BOUNTY_MANAGER_ROLE();
    const bountyManagerAddress = await bountyManager.getAddress();

    if (!(await reputationSystem.hasRole(BOUNTY_MANAGER_ROLE, bountyManagerAddress))) {
        const tx = await reputationSystem.grantRole(BOUNTY_MANAGER_ROLE, bountyManagerAddress);
        await tx.wait();
        console.log(`✅ Granted BOUNTY_MANAGER_ROLE to BountyManager in ReputationSystem`);
    } else {
        console.log(`ℹ️  BOUNTY_MANAGER_ROLE already granted to BountyManager in ReputationSystem`);
    }

    // Grant BOUNTY_MANAGER_ROLE to BountyManager contract in ThreatToken (if the token has this role)
    try {
        const TOKEN_BOUNTY_MANAGER_ROLE = await threatToken.BOUNTY_MANAGER_ROLE();
        if (!(await threatToken.hasRole(TOKEN_BOUNTY_MANAGER_ROLE, bountyManagerAddress))) {
            const tx = await threatToken.grantRole(TOKEN_BOUNTY_MANAGER_ROLE, bountyManagerAddress);
            await tx.wait();
            console.log(`✅ Granted BOUNTY_MANAGER_ROLE to BountyManager in ThreatToken`);
        } else {
            console.log(`ℹ️  BOUNTY_MANAGER_ROLE already granted to BountyManager in ThreatToken`);
        }
    } catch {
        console.log(`ℹ️  ThreatToken does not have BOUNTY_MANAGER_ROLE, skipping`);
    }

    // Grant REPUTATION_MANAGER_ROLE to ReputationSystem in ThreatToken (if applicable)
    try {
        const REPUTATION_MANAGER_ROLE = await threatToken.REPUTATION_MANAGER_ROLE();
        const reputationAddress = await reputationSystem.getAddress();
        if (!(await threatToken.hasRole(REPUTATION_MANAGER_ROLE, reputationAddress))) {
            const tx = await threatToken.grantRole(REPUTATION_MANAGER_ROLE, reputationAddress);
            await tx.wait();
            console.log(`✅ Granted REPUTATION_MANAGER_ROLE to ReputationSystem in ThreatToken`);
        } else {
            console.log(`ℹ️  REPUTATION_MANAGER_ROLE already granted to ReputationSystem in ThreatToken`);
        }
    } catch {
        console.log(`ℹ️  ThreatToken does not have REPUTATION_MANAGER_ROLE, skipping`);
    }

    // Setup additional admin roles
    const ADMIN_ROLE = await reputationSystem.ADMIN_ROLE();
    for (const adminAddress of config.adminAddresses) {
        if (ethers.isAddress(adminAddress)) {
            if (!(await reputationSystem.hasRole(ADMIN_ROLE, adminAddress))) {
                const tx = await reputationSystem.grantRole(ADMIN_ROLE, adminAddress);
                await tx.wait();
                console.log(`✅ Granted ADMIN_ROLE to ${adminAddress} in ReputationSystem`);
            }
        }
    }
}

async function registerInitialEngines(
    deploymentAddresses: DeploymentAddresses,
    config: SetupConfig,
    signer: HardhatEthersSigner
) {
    console.log("\n🤖 Registering initial analysis engines...");

    const reputationSystem = await ethers.getContractAt("ReputationSystem", deploymentAddresses.reputationSystem, signer);

    // To register engines, we need to call via an account with BOUNTY_MANAGER_ROLE
    // In setup, we grant ourselves this role temporarily or use the BountyManager contract
    const BOUNTY_MANAGER_ROLE = await reputationSystem.BOUNTY_MANAGER_ROLE();

    // Grant deployer the BOUNTY_MANAGER_ROLE temporarily for engine registration
    const deployerAddress = await signer.getAddress();
    const hadRole = await reputationSystem.hasRole(BOUNTY_MANAGER_ROLE, deployerAddress);

    if (!hadRole) {
        const tx = await reputationSystem.grantRole(BOUNTY_MANAGER_ROLE, deployerAddress);
        await tx.wait();
        console.log(`✅ Temporarily granted BOUNTY_MANAGER_ROLE to deployer for engine registration`);
    }

    for (let i = 0; i < config.engineAddresses.length; i++) {
        const engineAddress = config.engineAddresses[i];

        if (ethers.isAddress(engineAddress)) {
            try {
                const engineInfo = await reputationSystem.getEngineInfo(engineAddress);
                if (!engineInfo.isRegistered) {
                    const tx = await reputationSystem.registerEngine(engineAddress, 0); // 0 = Human type
                    await tx.wait();
                    console.log(`✅ Registered engine ${engineAddress} (type: Human)`);
                } else {
                    console.log(`ℹ️  Engine ${engineAddress} already registered`);
                }
            } catch (error) {
                console.error(`❌ Failed to register engine ${engineAddress}:`, error);
            }
        }
    }

    // Revoke temporary role if we granted it
    if (!hadRole) {
        const tx = await reputationSystem.revokeRole(BOUNTY_MANAGER_ROLE, deployerAddress);
        await tx.wait();
        console.log(`✅ Revoked temporary BOUNTY_MANAGER_ROLE from deployer`);
    }
}

async function displaySystemStatus(deploymentAddresses: DeploymentAddresses, signer: HardhatEthersSigner) {
    console.log("\n📊 System Status:");
    console.log("═".repeat(50));

    const threatToken = await ethers.getContractAt("ThreatToken", deploymentAddresses.threatToken, signer);
    const reputationSystem = await ethers.getContractAt("ReputationSystem", deploymentAddresses.reputationSystem, signer);
    const bountyManager = await ethers.getContractAt("BountyManager", deploymentAddresses.bountyManager, signer);

    // Token information
    const tokenName = await threatToken.name();
    const tokenSymbol = await threatToken.symbol();
    const totalSupply = await threatToken.totalSupply();
    const bountyManagerBalance = await threatToken.balanceOf(deploymentAddresses.bountyManager);

    console.log(`Token: ${tokenName} (${tokenSymbol})`);
    console.log(`Total Supply: ${ethers.formatEther(totalSupply)} ${tokenSymbol}`);
    console.log(`BountyManager Balance: ${ethers.formatEther(bountyManagerBalance)} ${tokenSymbol}`);

    // BountyManager constants (read-only)
    const minStake = await bountyManager.MIN_STAKE_AMOUNT();
    const consensusThreshold = await bountyManager.CONSENSUS_THRESHOLD();
    const platformFee = await bountyManager.PLATFORM_FEE_PERCENT();
    const minAnalyses = await bountyManager.MIN_ANALYSES_TO_RESOLVE();

    console.log(`\nBountyManager Constants:`);
    console.log(`  Min Stake: ${ethers.formatEther(minStake)} ${tokenSymbol}`);
    console.log(`  Consensus Threshold: ${consensusThreshold}%`);
    console.log(`  Platform Fee: ${platformFee}%`);
    console.log(`  Min Analyses to Resolve: ${minAnalyses}`);

    // Reputation System constants
    const initialRep = await reputationSystem.INITIAL_REPUTATION();
    const maxRep = await reputationSystem.MAX_REPUTATION();
    const decayRate = await reputationSystem.DECAY_RATE();
    const totalEngines = await reputationSystem.getTotalAnalysts();

    console.log(`\nReputationSystem Constants:`);
    console.log(`  Initial Reputation: ${initialRep}`);
    console.log(`  Max Reputation: ${maxRep}`);
    console.log(`  Decay Rate: ${decayRate}% per month`);
    console.log(`  Total Active Engines: ${totalEngines}`);

    console.log("═".repeat(50));
}

async function main() {
    console.log("🔧 Starting Verdyx post-deployment setup...\n");

    const network = await ethers.provider.getNetwork();
    const [deployer] = await ethers.getSigners();

    console.log(`📡 Network: ${hre.network.name} (Chain ID: ${network.chainId})`);
    console.log(`👤 Setup Account: ${deployer.address}\n`);

    // Load deployment addresses
    // The Hardhat network name (e.g. baseSepolia), as deploy.ts saves it.
    const deploymentAddresses = await loadDeploymentAddresses(hre.network.name, Number(network.chainId));
    console.log("✅ Loaded deployment addresses");

    // Load configuration
    const config: SetupConfig = { ...DEFAULT_CONFIG };

    // Override with environment variables if available
    if (process.env.ADMIN_ADDRESSES) {
        config.adminAddresses = process.env.ADMIN_ADDRESSES.split(',');
    }
    if (process.env.ENGINE_ADDRESSES) {
        config.engineAddresses = process.env.ENGINE_ADDRESSES.split(',');
    }

    try {
        // Setup roles between contracts
        await setupRoles(deploymentAddresses, config, deployer);

        // Register initial engines
        if (config.engineAddresses.length > 0) {
            await registerInitialEngines(deploymentAddresses, config, deployer);
        }

        // Display final system status
        await displaySystemStatus(deploymentAddresses, deployer);

        console.log("\n🎉 Setup completed successfully!");
        console.log("The Verdyx platform is now configured and ready for use.");

    } catch (error) {
        console.error("❌ Setup failed:");
        console.error(error);
        throw error;
    }
}

// Allow this script to be run directly
if (require.main === module) {
    main()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error("❌ Setup failed:");
            console.error(error);
            process.exit(1);
        });
}

export { main as setupContracts };
export type { SetupConfig };