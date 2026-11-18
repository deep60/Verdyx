import { expect } from "chai";
import { ethers } from "hardhat";
import { ThreatToken } from "../../typechain-types";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

describe("ThreatToken", function () {
    async function deployTokenFixture() {
        const [owner, addr1, addr2, engine1] = await ethers.getSigners();

        const ThreatToken = await ethers.getContractFactory("ThreatToken");
        const token = await ThreatToken.deploy(owner.address);
        await token.waitForDeployment();

        return { token: token as unknown as ThreatToken, owner, addr1, addr2, engine1 };
    }

    describe("Deployment", function () {
        it("Should set the correct name and symbol", async function () {
            const { token } = await loadFixture(deployTokenFixture);
            expect(await token.name()).to.equal("ThreatToken");
            expect(await token.symbol()).to.equal("THREAT");
        });

        it("Should mint initial supply to owner", async function () {
            const { token, owner } = await loadFixture(deployTokenFixture);
            const INITIAL_SUPPLY = await token.INITIAL_SUPPLY();
            expect(await token.balanceOf(owner.address)).to.equal(INITIAL_SUPPLY);
        });

        it("Should set correct max supply", async function () {
            const { token } = await loadFixture(deployTokenFixture);
            const MAX_SUPPLY = await token.MAX_SUPPLY();
            expect(MAX_SUPPLY).to.equal(ethers.parseEther("1000000000"));
        });

        it("Should grant all roles to admin", async function () {
            const { token, owner } = await loadFixture(deployTokenFixture);
            const DEFAULT_ADMIN = await token.DEFAULT_ADMIN_ROLE();
            const PAUSER = await token.PAUSER_ROLE();
            const MINTER = await token.MINTER_ROLE();

            expect(await token.hasRole(DEFAULT_ADMIN, owner.address)).to.be.true;
            expect(await token.hasRole(PAUSER, owner.address)).to.be.true;
            expect(await token.hasRole(MINTER, owner.address)).to.be.true;
        });
    });

    describe("Minting", function () {
        it("Should allow minter to mint tokens", async function () {
            const { token, owner: _owner, addr1 } = await loadFixture(deployTokenFixture);
            const mintAmount = ethers.parseEther("1000");

            await token.mint(addr1.address, mintAmount);
            expect(await token.balanceOf(addr1.address)).to.equal(mintAmount);
        });

        it("Should not exceed max supply", async function () {
            const { token, addr1 } = await loadFixture(deployTokenFixture);
            const MAX_SUPPLY = await token.MAX_SUPPLY();
            const currentSupply = await token.totalSupply();
            const excessAmount = MAX_SUPPLY - currentSupply + 1n;

            await expect(token.mint(addr1.address, excessAmount)).to.be.revertedWith("Exceeds max supply");
        });

        it("Should prevent non-minter from minting", async function () {
            const { token, addr1, addr2 } = await loadFixture(deployTokenFixture);
            const mintAmount = ethers.parseEther("100");

            await expect(
                token.connect(addr1).mint(addr2.address, mintAmount)
            ).to.be.reverted;
        });
    });

    describe("Staking", function () {
        it("Should allow authorized engines to stake", async function () {
            const { token, owner: _owner, engine1 } = await loadFixture(deployTokenFixture);

            // Authorize engine and fund it
            await token.setEngineAuthorization(engine1.address, true);
            const stakeAmount = ethers.parseEther("100");
            await token.transfer(engine1.address, stakeAmount);

            const analysisId = ethers.id("test-analysis-1");
            await token.connect(engine1).stakeForAnalysis(stakeAmount, analysisId);

            expect(await token.totalStaked(engine1.address)).to.equal(stakeAmount);
        });

        it("Should not allow unauthorized engines to stake", async function () {
            const { token, owner: _owner, engine1 } = await loadFixture(deployTokenFixture);

            const stakeAmount = ethers.parseEther("100");
            await token.transfer(engine1.address, stakeAmount);

            const analysisId = ethers.id("test-analysis-1");
            await expect(
                token.connect(engine1).stakeForAnalysis(stakeAmount, analysisId)
            ).to.be.revertedWith("Engine not authorized");
        });

        it("Should enforce minimum stake amount", async function () {
            const { token, owner: _owner, engine1 } = await loadFixture(deployTokenFixture);

            await token.setEngineAuthorization(engine1.address, true);
            const lowStake = ethers.parseEther("50"); // Below 100 minimum
            await token.transfer(engine1.address, lowStake);

            const analysisId = ethers.id("test-analysis-1");
            await expect(
                token.connect(engine1).stakeForAnalysis(lowStake, analysisId)
            ).to.be.revertedWith("Amount below minimum stake");
        });
    });

    describe("Pause/Unpause", function () {
        it("Should allow pauser to pause", async function () {
            const { token } = await loadFixture(deployTokenFixture);
            await token.pause();
            expect(await token.paused()).to.be.true;
        });

        it("Should prevent transfers when paused", async function () {
            const { token, owner: _owner, addr1 } = await loadFixture(deployTokenFixture);
            await token.pause();

            await expect(
                token.transfer(addr1.address, ethers.parseEther("100"))
            ).to.be.reverted;
        });

        it("Should allow unpausing", async function () {
            const { token, addr1 } = await loadFixture(deployTokenFixture);
            await token.pause();
            await token.unpause();

            await expect(token.transfer(addr1.address, ethers.parseEther("100"))).to.not.be.reverted;
        });
    });

    describe("Reward Distribution", function () {
        it("Should distribute rewards to correct engines", async function () {
            const { token, owner, engine1, addr1 } = await loadFixture(deployTokenFixture);

            await token.setEngineAuthorization(engine1.address, true);
            await token.setEngineAuthorization(addr1.address, true);

            const analysisId = ethers.id("test-analysis-1");
            const correctEngines = [engine1.address, addr1.address];
            const isFirstCorrect = [true, false];

            const BOUNTY_MANAGER_ROLE = await token.BOUNTY_MANAGER_ROLE();
            await token.grantRole(BOUNTY_MANAGER_ROLE, owner.address);

            await expect(
                token.distributeRewards(analysisId, correctEngines, isFirstCorrect)
            ).to.not.be.reverted;
        });
    });
});
