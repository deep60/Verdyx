// Publishes the source of a deployment on the block explorer (Etherscan v2,
// which covers Base Sepolia). Reads the addresses deploy.ts saved:
//
//   ETHERSCAN_API_KEY=... npx hardhat run scripts/verify/verify.ts --network baseSepolia

import hre, { ethers, run } from "hardhat";
import { readFileSync } from "fs";
import { deploymentFile, type DeploymentAddresses } from "../deploy";

async function verifyContract(address: string, constructorArguments: unknown[], contract: string) {
    console.log(`\n🔍 Verifying ${contract} at ${address}...`);
    try {
        await run("verify:verify", { address, constructorArguments, contract });
        console.log("   ✅ Verified");
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.toLowerCase().includes("already verified")) {
            console.log("   ℹ️  Already verified");
        } else {
            throw error;
        }
    }
}

async function verifyAllContracts(d: DeploymentAddresses) {
    // Older deployment files predate feeCollector; the deployer was the collector then.
    const feeCollector = d.feeCollector || d.deployer;
    await verifyContract(d.threatToken, [d.deployer], "contracts/core/ThreatToken.sol:ThreatToken");
    await verifyContract(d.reputationSystem, [], "contracts/core/ReputationSystem.sol:ReputationSystem");
    await verifyContract(
        d.bountyManager,
        [d.threatToken, d.reputationSystem, feeCollector],
        "contracts/core/BountyManager.sol:BountyManager"
    );
    await verifyContract(d.governance, [d.threatToken], "contracts/core/Governance.sol:Governance");
    if (d.threatFaucet && d.faucetDripWei && d.faucetCooldownSecs) {
        await verifyContract(
            d.threatFaucet,
            [d.threatToken, d.faucetDripWei, d.faucetCooldownSecs],
            "contracts/core/ThreatFaucet.sol:ThreatFaucet"
        );
    }
    console.log("\n✅ All contracts verified");
}

async function main() {
    if (["hardhat", "localhost"].includes(hre.network.name)) {
        console.log("Verification is not needed on a local network.");
        return;
    }
    if (!process.env.ETHERSCAN_API_KEY) {
        throw new Error("❌ Set ETHERSCAN_API_KEY to verify on the block explorer.");
    }
    const { chainId } = await ethers.provider.getNetwork();
    const file = deploymentFile(hre.network.name, chainId);
    const deployment: DeploymentAddresses = JSON.parse(readFileSync(file, "utf8"));
    await verifyAllContracts(deployment);
}

if (require.main === module) {
    main()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error("❌ Verification failed:");
            console.error(error);
            process.exit(1);
        });
}

export { verifyContract, verifyAllContracts };
