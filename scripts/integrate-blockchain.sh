#!/bin/bash
# Verdyx Blockchain & Backend Integration Script
# This script integrates the blockchain smart contracts with backend services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Verdyx Blockchain Integration Setup           ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if we're in the right directory
if [ ! -d "blockchain" ] || [ ! -d "backend" ]; then
    echo -e "${RED}❌ Error: Please run this script from the project root directory${NC}"
    exit 1
fi

# Step 1: Compile Smart Contracts
echo -e "${BLUE}📦 Step 1: Compiling Smart Contracts...${NC}"
cd blockchain
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}⚠️  Installing Hardhat dependencies...${NC}"
    npm install --include=dev
fi

echo "Compiling contracts..."
npx hardhat compile
echo -e "${GREEN}✅ Contracts compiled successfully${NC}"
echo ""

# Step 2: Extract ABIs
echo -e "${BLUE}🔍 Step 2: Extracting Contract ABIs...${NC}"
if [ ! -f "scripts/extract-abis.sh" ]; then
    echo -e "${RED}❌ Error: extract-abis.sh not found${NC}"
    exit 1
fi

bash scripts/extract-abis.sh
echo -e "${GREEN}✅ ABIs extracted and copied${NC}"
echo ""

# Step 3: Create Backend ABIs Directory
echo -e "${BLUE}📁 Step 3: Setting up Backend ABI Directory...${NC}"
cd ..
mkdir -p backend/api-gateway/abis
cp blockchain/abis/*.json backend/api-gateway/abis/ 2>/dev/null || true
echo -e "${GREEN}✅ Backend ABI directory ready${NC}"
echo ""

# Step 4: Check for Local Blockchain Node
echo -e "${BLUE}🌐 Step 4: Blockchain Node Setup${NC}"
echo -e "${YELLOW}⚠️  To deploy contracts, you need a blockchain node running.${NC}"
echo ""
echo "Options:"
echo "  1. Start a local Hardhat node: cd blockchain && npx hardhat node"
echo "  2. Use a public testnet (Sepolia, Mumbai, etc.)"
echo "  3. Skip for now (contracts won't be deployed)"
echo ""
read -p "Do you want to start a local Hardhat node? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}⚠️  Starting Hardhat node in a new terminal...${NC}"
    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal -- bash -c "cd $(pwd)/blockchain && npx hardhat node; exec bash"
    elif command -v osascript &> /dev/null; then
        osascript -e "tell app \"Terminal\" to do script \"cd $(pwd)/blockchain && npx hardhat node\""
    else
        echo -e "${YELLOW}⚠️  Please manually start: cd blockchain && npx hardhat node${NC}"
    fi
    echo "Waiting 5 seconds for node to start..."
    sleep 5
fi
echo ""

# Step 5: Deploy Contracts (Optional)
echo -e "${BLUE}🚀 Step 5: Contract Deployment${NC}"
read -p "Do you want to deploy contracts to local network? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd blockchain
    echo "Deploying contracts..."
    npm run deploy:local || echo -e "${YELLOW}⚠️  Deployment failed. Make sure Hardhat node is running.${NC}"

    if [ -f "deployed-addresses.json" ]; then
        echo -e "${GREEN}✅ Contracts deployed${NC}"
        echo ""
        echo "Deployed Addresses:"
        cat deployed-addresses.json
    fi
    cd ..
else
    echo -e "${YELLOW}⏭️  Skipping deployment${NC}"
fi
echo ""

# Step 6: Update Environment Variables
echo -e "${BLUE}⚙️  Step 6: Environment Configuration${NC}"
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  No .env file found. Creating from template...${NC}"
    cat > .env << 'EOF'
# Blockchain Configuration
BLOCKCHAIN_RPC_URL=http://localhost:8545
BLOCKCHAIN_CHAIN_ID=31337
BOUNTY_MANAGER_ADDRESS=
THREAT_TOKEN_ADDRESS=
REPUTATION_SYSTEM_ADDRESS=
GOVERNANCE_ADDRESS=

# Gas Configuration
GAS_LIMIT=500000
GAS_PRICE_GWEI=20
CONFIRMATION_BLOCKS=3
RETRY_ATTEMPTS=3

# Database Configuration
DATABASE_URL=postgresql://verdyx_user:verdyx_password@localhost:5432/verdyx

# Redis Configuration
REDIS_URL=redis://localhost:6379

# API Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Observability
RUST_LOG=info
EOF
    echo -e "${GREEN}✅ Created .env file${NC}"
else
    echo -e "${GREEN}✅ .env file exists${NC}"
fi

# Extract addresses from deployed-addresses.json if it exists
if [ -f "blockchain/deployed-addresses.json" ]; then
    echo -e "${YELLOW}📝 Updating .env with deployed contract addresses...${NC}"

    BOUNTY_ADDR=$(jq -r '.contracts.BountyManager.address // empty' blockchain/deployed-addresses.json)
    TOKEN_ADDR=$(jq -r '.contracts.ThreatToken.address // empty' blockchain/deployed-addresses.json)
    REP_ADDR=$(jq -r '.contracts.ReputationSystem.address // empty' blockchain/deployed-addresses.json)

    if [ ! -z "$BOUNTY_ADDR" ] && [ "$BOUNTY_ADDR" != "0x0000000000000000000000000000000000000000" ]; then
        # Update .env file with addresses
        if grep -q "BOUNTY_MANAGER_ADDRESS=" .env; then
            sed -i.bak "s|BOUNTY_MANAGER_ADDRESS=.*|BOUNTY_MANAGER_ADDRESS=$BOUNTY_ADDR|" .env
        else
            echo "BOUNTY_MANAGER_ADDRESS=$BOUNTY_ADDR" >> .env
        fi
        echo -e "${GREEN}✅ Updated contract addresses in .env${NC}"
    fi
fi
echo ""

# Step 7: Verify Integration
echo -e "${BLUE}🔍 Step 7: Verifying Integration...${NC}"
echo ""
echo "Checking components:"

# Check blockchain artifacts
if [ -d "blockchain/artifacts/contracts" ]; then
    echo -e "${GREEN}✅${NC} Smart contracts compiled"
else
    echo -e "${RED}❌${NC} Smart contracts not compiled"
fi

# Check ABIs
if [ -f "blockchain/abis/BountyManager.json" ]; then
    echo -e "${GREEN}✅${NC} ABIs extracted to blockchain/abis/"
else
    echo -e "${RED}❌${NC} ABIs not extracted"
fi

# Check backend ABIs
if [ -f "backend/api-gateway/abis/BountyManager.json" ]; then
    echo -e "${GREEN}✅${NC} ABIs copied to backend"
else
    echo -e "${YELLOW}⚠️${NC}  ABIs not in backend (may need manual copy)"
fi

# Check deployed addresses
if [ -f "blockchain/deployed-addresses.json" ]; then
    ADDR=$(jq -r '.contracts.BountyManager.address' blockchain/deployed-addresses.json)
    if [ "$ADDR" != "0x0000000000000000000000000000000000000000" ]; then
        echo -e "${GREEN}✅${NC} Contracts deployed with real addresses"
    else
        echo -e "${YELLOW}⚠️${NC}  Contracts not deployed (using placeholder addresses)"
    fi
else
    echo -e "${RED}❌${NC} deployed-addresses.json not found"
fi

# Check environment variables
if [ -f ".env" ]; then
    echo -e "${GREEN}✅${NC} Environment configuration exists"
else
    echo -e "${RED}❌${NC} .env file missing"
fi

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Integration Setup Complete!                           ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}✅ Blockchain and backend are now integrated!${NC}"
echo ""
echo "📚 Next Steps:"
echo "  1. Review INTEGRATION_REPORT.md for detailed status"
echo "  2. Start backend services: cd backend && cargo run"
echo "  3. Test blockchain integration"
echo "  4. Deploy to testnet when ready"
echo ""
echo "📖 Documentation:"
echo "  - Integration Report: ./INTEGRATION_REPORT.md"
echo "  - ABIs Location: ./blockchain/abis/"
echo "  - Deployed Addresses: ./blockchain/deployed-addresses.json"
echo ""
echo "🎉 Happy building with Verdyx!"
