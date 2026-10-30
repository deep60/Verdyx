import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";
import "@nomicfoundation/hardhat-network-helpers";
import "@nomicfoundation/hardhat-verify";
import "hardhat-gas-reporter";
import "solidity-coverage";
import "dotenv/config";

// Helper to check if private key is valid (64 hex chars = 32 bytes)
const getPrivateKey = (): string[] => {
  const pk = process.env.PRIVATE_KEY || process.env.DEPLOYER_PRIVATE_KEY;
  if (!pk) return [];

  // Remove 0x prefix if present
  const cleanPk = pk.startsWith("0x") ? pk.slice(2) : pk;

  // Check if it's a valid 64-character hex string
  if (cleanPk.length === 64 && /^[0-9a-fA-F]{64}$/.test(cleanPk)) {
    return ["0x" + cleanPk];
  }

  return [];
};

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC || process.env.RPC_URL || "",
      accounts: getPrivateKey(),
    },
    mainnet: {
      url: process.env.MAINNET_RPC || "",
      accounts: getPrivateKey(),
    },
    polygon: {
      url: process.env.POLYGON_RPC || "",
      accounts: getPrivateKey(),
    },
    mumbai: {
      url: process.env.MUMBAI_RPC || "",
      accounts: getPrivateKey(),
    },
  },
  etherscan: {
    apiKey: {
      mainnet: process.env.ETHERSCAN_API || process.env.ETHERSCAN_API_KEY || "",
      sepolia: process.env.ETHERSCAN_API || process.env.ETHERSCAN_API_KEY || "",
      polygon: process.env.POLYGONSCAN_API || "",
      polygonMumbai: process.env.POLYGONSCAN_API || "",
    },
  },
  gasReporter: {
    enabled: true,
    currency: "USD",
    coinmarketcap: process.env.CMC_API_KEY || "",
  },
};

export default config;
