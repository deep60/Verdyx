// Deploys ThreatToken, ReputationSystem, BountyManager and Governance, wires
// the roles between them, funds the reward pool, and writes the addresses to
// deployments/<network>-<chainId>.json and deployed-addresses.json.
//
//   npx hardhat run scripts/deploy.ts --network baseSepolia

import hre, { ethers } from "hardhat";
import { join } from "path";
import { writeFileSync, mkdirSync, readFileSync, existsSync } from "fs";

interface DeploymentAddresses {
    threatToken: string;
    reputationSystem: string;
    bountyManager: string;
    governance: string;
    /** Test networks only: hands out test THREAT. */
    threatFaucet?: string;
    /** The faucet's constructor arguments, for verification. */
    faucetDripWei?: string;
    faucetCooldownSecs?: number;
    deployer: string;
    feeCollector: string;
    network: string;
    chainId: number;
    blockNumber: number;
    timestamp: number;
}

// Ethereum mainnet needs real headroom; test networks and L2s cost cents.
const MAINNET_CHAIN_IDS = new Set([1n, 137n, 8453n]);
const LOCAL_CHAIN_IDS = new Set([31337n, 1337n]);

function deploymentFile(networkName: string, chainId: bigint | number): string {
    return join(__dirname, "..", "deployments", `${networkName}-${chainId}.json`);
}

async function main(): Promise<DeploymentAddresses> {
    console.log("🚀 Starting Verdyx smart contract deployment...\n");

    const networkName = hre.network.name;
    const { chainId } = await ethers.provider.getNetwork();
    const [deployer] = await ethers.getSigners();
    if (!deployer) {
        throw new Error("❌ No deployer account. Set DEPLOYER_PRIVATE_KEY for this network.");
    }
    const feeCollector = process.env.FEE_COLLECTOR_ADDRESS || deployer.address;
    if (!ethers.isAddress(feeCollector)) {
        throw new Error(`❌ FEE_COLLECTOR_ADDRESS is not an address: ${feeCollector}`);
    }

    console.log(`📡 Network: ${networkName} (Chain ID: ${chainId})`);
    console.log(`👤 Deployer: ${deployer.address}`);
    console.log(`🏦 Fee collector: ${feeCollector}`);

    // Refuse to overwrite a live deployment by accident.
    if (!LOCAL_CHAIN_IDS.has(chainId) && existsSync(deploymentFile(networkName, chainId)) && process.env.REDEPLOY !== "true") {
        throw new Error(
            `❌ ${networkName} already has a deployment (${deploymentFile(networkName, chainId)}). Set REDEPLOY=true to replace it.`
        );
    }

    const balance = await ethers.provider.getBalance(deployer.address);
    console.log(`💰 Deployer balance: ${ethers.formatEther(balance)} ETH\n`);
    const minimum = ethers.parseEther(MAINNET_CHAIN_IDS.has(chainId) ? "0.1" : "0.002");
    if (balance < minimum) {
        throw new Error(`❌ Insufficient balance for deployment. Need at least ${ethers.formatEther(minimum)} ETH`);
    }

    console.log("🗒️ Deploying ThreatToken...");
    const threatToken = await (await ethers.getContractFactory("ThreatToken")).deploy(deployer.address);
    await threatToken.waitForDeployment();
    const threatTokenAddress = await threatToken.getAddress();
    console.log(`✅ ThreatToken deployed at: ${threatTokenAddress}`);

    console.log("\n📋 Deploying ReputationSystem...");
    const reputationSystem = await (await ethers.getContractFactory("ReputationSystem")).deploy();
    await reputationSystem.waitForDeployment();
    const reputationSystemAddress = await reputationSystem.getAddress();
    console.log(`✅ ReputationSystem deployed at: ${reputationSystemAddress}`);

    console.log("\n📋 Deploying BountyManager...");
    const bountyManager = await (await ethers.getContractFactory("BountyManager")).deploy(
        threatTokenAddress,
        reputationSystemAddress,
        feeCollector
    );
    await bountyManager.waitForDeployment();
    const bountyManagerAddress = await bountyManager.getAddress();
    console.log(`✅ BountyManager deployed at: ${bountyManagerAddress}`);

    console.log("\n📋 Deploying Governance...");
    const governance = await (await ethers.getContractFactory("Governance")).deploy(threatTokenAddress);
    await governance.waitForDeployment();
    const governanceAddress = await governance.getAddress();
    console.log(`✅ Governance deployed at: ${governanceAddress}`);

    console.log("\n⚙️  Setting up initial configuration...");

    // Each transaction is mined before the next, so a failure stops here
    // instead of leaving later steps half-applied.
    const BOUNTY_MANAGER_ROLE = await reputationSystem.BOUNTY_MANAGER_ROLE();
    await (await reputationSystem.grantRole(BOUNTY_MANAGER_ROLE, bountyManagerAddress)).wait();
    console.log("✅ Granted BOUNTY_MANAGER_ROLE to BountyManager in ReputationSystem");

    const rewardPoolAmount = ethers.parseEther(process.env.REWARD_POOL_THREAT || "100000");
    await (await threatToken.transfer(bountyManagerAddress, rewardPoolAmount)).wait();
    console.log(`✅ Transferred ${ethers.formatEther(rewardPoolAmount)} THREAT to BountyManager`);

    // A faucet so people can try the marketplace with test THREAT. Never on a
    // mainnet: there, THREAT would have real value.
    let threatFaucet: string | undefined;
    const faucetDrip = ethers.parseEther(process.env.FAUCET_DRIP_THREAT || "100");
    const faucetCooldown = Number(process.env.FAUCET_COOLDOWN_SECS || 24 * 3600);
    if (!MAINNET_CHAIN_IDS.has(chainId)) {
        console.log("\n🚰 Deploying ThreatFaucet...");
        const faucet = await (await ethers.getContractFactory("ThreatFaucet")).deploy(
            threatTokenAddress,
            faucetDrip,
            faucetCooldown
        );
        await faucet.waitForDeployment();
        threatFaucet = await faucet.getAddress();
        const faucetFund = ethers.parseEther(process.env.FAUCET_FUND_THREAT || "1000000");
        await (await threatToken.transfer(threatFaucet, faucetFund)).wait();
        console.log(
            `✅ ThreatFaucet deployed at: ${threatFaucet} with ${ethers.formatEther(faucetFund)} THREAT, ` +
                `${ethers.formatEther(faucetDrip)} per wallet every ${faucetCooldown / 3600} h`
        );
    }

    const currentBlock = await ethers.provider.getBlockNumber();
    const timestamp = Math.floor(Date.now() / 1000);

    const deploymentData: DeploymentAddresses = {
        threatToken: threatTokenAddress,
        reputationSystem: reputationSystemAddress,
        bountyManager: bountyManagerAddress,
        governance: governanceAddress,
        ...(threatFaucet
            ? { threatFaucet, faucetDripWei: faucetDrip.toString(), faucetCooldownSecs: faucetCooldown }
            : {}),
        deployer: deployer.address,
        feeCollector,
        network: networkName,
        chainId: Number(chainId),
        blockNumber: currentBlock,
        timestamp,
    };

    const deploymentsDir = join(__dirname, "..", "deployments");
    mkdirSync(deploymentsDir, { recursive: true });
    const file = deploymentFile(networkName, chainId);
    writeFileSync(file, JSON.stringify(deploymentData, null, 2) + "\n");

    const allDeploymentsFile = join(deploymentsDir, "deployments.json");
    let allDeployments: Record<string, DeploymentAddresses> = {};
    if (existsSync(allDeploymentsFile)) {
        allDeployments = JSON.parse(readFileSync(allDeploymentsFile, "utf8"));
    }
    allDeployments[`${networkName}-${chainId}`] = deploymentData;
    writeFileSync(allDeploymentsFile, JSON.stringify(allDeployments, null, 2) + "\n");

    // The canonical file the backend reads.
    const entry = (address: string) => ({ address, deployer: deployer.address, blockNumber: currentBlock });
    const canonical = {
        network: networkName,
        chainId: Number(chainId),
        deployedAt: new Date(timestamp * 1000).toISOString(),
        contracts: {
            ThreatToken: entry(threatTokenAddress),
            ReputationSystem: entry(reputationSystemAddress),
            BountyManager: entry(bountyManagerAddress),
            Governance: entry(governanceAddress),
            ...(threatFaucet ? { ThreatFaucet: entry(threatFaucet) } : {}),
        },
        notes: `Deployed to ${networkName} (chainId ${chainId}).`,
    };
    writeFileSync(join(__dirname, "..", "deployed-addresses.json"), JSON.stringify(canonical, null, 2) + "\n");

    console.log("\n🎉 Deployment completed successfully!");
    console.log("═".repeat(50));
    console.log(`Network: ${networkName} (${chainId})`);
    console.log(`Block Number: ${currentBlock}`);
    console.log(`Deployer: ${deployer.address}`);
    console.log(`ThreatToken: ${threatTokenAddress}`);
    console.log(`ReputationSystem: ${reputationSystemAddress}`);
    console.log(`BountyManager: ${bountyManagerAddress}`);
    console.log(`Governance: ${governanceAddress}`);
    if (threatFaucet) console.log(`ThreatFaucet: ${threatFaucet}`);
    console.log("═".repeat(50));
    console.log(`📁 Deployment data saved to: ${file}`);
    console.log(`\n🔍 Verify the source with: npx hardhat run scripts/verify/verify.ts --network ${networkName}`);

    return deploymentData;
}

if (require.main === module) {
    main()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error("❌ Deployment failed:");
            console.error(error);
            process.exit(1);
        });
}

export { main as deployContracts, deploymentFile };
export type { DeploymentAddresses };
