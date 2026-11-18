# Deploying the contracts to Base Sepolia

The marketplace contracts (ThreatToken, ReputationSystem, BountyManager,
Governance) run on **Base Sepolia** (chain id 84532), a test network: its ETH
is free and has no value. Nothing here touches real money. Real funds wait for
an external audit.

The deployment runs from GitHub Actions (**Actions → Deploy contracts**), so
the deployer key lives only in a GitHub secret.

## One-time setup

### 1. Create a deployer wallet used only for this

Make a **new** wallet, never one that holds real funds. For example, in
MetaMask: *Add account → Create a new account*, name it "Verdyx deployer",
then *Account details → Show private key*.

The deployer becomes the admin of every contract (it can mint THREAT, pause
the token and grant roles). Keep its key only in the GitHub secret below.

### 2. Get test ETH

Deployment and setup cost well under 0.002 ETH on Base Sepolia. Send some to
the deployer's address from a faucet:

- Coinbase Developer Platform faucet: https://portal.cdp.coinbase.com/products/faucet (Base Sepolia)
- Alchemy faucet: https://www.alchemy.com/faucets/base-sepolia

### 3. Get an Etherscan API key

Sign in at https://etherscan.io/myapikey and create a key. One Etherscan (v2)
key verifies source on Basescan too. Verification is optional; without it
the contracts still work, but nobody can read their code on the explorer.

### 4. Add them to GitHub

In the repository: **Settings → Environments → New environment**, name it
`base-sepolia`. Under it add:

| Kind | Name | Value |
|---|---|---|
| Secret | `DEPLOYER_PRIVATE_KEY` | the deployer's private key |
| Secret | `ETHERSCAN_API_KEY` | the Etherscan key |
| Variable (optional) | `BASE_SEPOLIA_RPC` | your own RPC URL (Alchemy, QuickNode…). Defaults to `https://sepolia.base.org`, which is rate-limited but fine for a deployment |
| Variable (optional) | `FEE_COLLECTOR_ADDRESS` | where the 5% platform fee goes. Defaults to the deployer |

Optionally add yourself as a **required reviewer** on the environment, so
every deployment waits for your approval.

## Deploying

**Actions → Deploy contracts → Run workflow** (network `baseSepolia`).

It runs the tests, deploys the four contracts, grants the roles between
them, funds the BountyManager reward pool with 100,000 THREAT, and verifies
the source. The run summary lists every address with a Basescan link.

Then commit the addresses: download the run's **contract-deployment**
artifact and copy `deployments/` and `deployed-addresses.json` into
`blockchain/`. The backend reads `deployed-addresses.json`.

The deploy script refuses to run again on a network that already has a
recorded deployment. Tick **redeploy** to replace it (the old contracts stay
on chain; they are just no longer used).

## Turning the marketplace on in the website

The marketplace is **non-custodial**: people post bounties, stake and
withdraw from their own wallets (MetaMask, Coinbase Wallet, Rabby…), and
every transaction is signed there. The server never holds anyone's tokens.

The website learns which network and contracts to use from
`GET /api/v1/chain`. Set these on the server (in `/opt/verdyx/.env`) from
`deployed-addresses.json`, then restart the API gateway:

| Setting | Value |
|---|---|
| `CHAIN_ID` | `84532` |
| `THREAT_TOKEN_ADDRESS` | ThreatToken's address |
| `BOUNTY_MANAGER_ADDRESS` | BountyManager's address |
| `REPUTATION_SYSTEM_ADDRESS` | ReputationSystem's address |
| `PUBLIC_CHAIN_RPC_URL` (optional) | what browsers use; defaults to `https://sepolia.base.org`. Never put a URL with a private provider key here: it is published |
| `CHAIN_EXPLORER_URL` (optional) | defaults to `https://sepolia.basescan.org` |

`BLOCKCHAIN_RPC_URL` stays the server's own RPC and is never sent to
browsers. Until the addresses are set, the website says the marketplace
isn't deployed yet.

To try it, people need test ETH for gas (from the faucets above) and some
THREAT: the deployer holds the supply and can send it from its wallet.

## Running it from your own machine instead

```bash
cd blockchain
npm ci
export DEPLOYER_PRIVATE_KEY=...   # in your shell only; never in a file in the repo
export ETHERSCAN_API_KEY=...
npm run full-deploy:base-sepolia
```

## Rehearsing locally

```bash
cd blockchain
npx hardhat node                                  # in one terminal
npm run deploy:local && npm run setup:local       # in another
```

CI runs the same rehearsal on every change under `blockchain/`.
