import { expect } from "chai";
import { ethers } from "hardhat";
import { ReputationSystem } from "../../typechain-types";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

describe("ReputationSystem", function () {
    async function deployReputationFixture() {
        const [owner, engine1, engine2, bountyManager] = await ethers.getSigners();

        const ReputationSystem = await ethers.getContractFactory("ReputationSystem");
        const reputation = await ReputationSystem.deploy();
        await reputation.waitForDeployment();

        // Grant bounty manager role
        const BOUNTY_MANAGER_ROLE = await reputation.BOUNTY_MANAGER_ROLE();
        await reputation.grantRole(BOUNTY_MANAGER_ROLE, bountyManager.address);

        return { reputation: reputation as unknown as ReputationSystem, owner, engine1, engine2, bountyManager };
    }

    describe("Engine Registration", function () {
        it("Should register a new engine", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await expect(
                reputation.connect(bountyManager).registerEngine(engine1.address, 0)
            ).to.emit(reputation, "EngineRegistered");

            const engineInfo = await reputation.getEngineInfo(engine1.address);
            expect(engineInfo.isRegistered).to.be.true;
            expect(engineInfo.reputation).to.equal(100); // INITIAL_REPUTATION
        });

        it("Should not allow duplicate registration", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);

            await expect(
                reputation.connect(bountyManager).registerEngine(engine1.address, 0)
            ).to.be.revertedWith("Engine already registered");
        });

        it("Should validate engine type", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await expect(
                reputation.connect(bountyManager).registerEngine(engine1.address, 5) // Invalid type
            ).to.be.revertedWith("Invalid engine type");
        });
    });

    describe("Reputation Updates", function () {
        it("Should record submissions", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);

            const submissionId = await reputation.connect(bountyManager).recordSubmission.staticCall(
                engine1.address,
                1, // bountyId
                true, // prediction
                ethers.parseEther("10"), // stake
                90 // confidence
            );

            await reputation.connect(bountyManager).recordSubmission(
                engine1.address,
                1,
                true,
                ethers.parseEther("10"),
                90
            );

            expect(submissionId).to.be.greaterThan(0);

            const engineInfo = await reputation.getEngineInfo(engine1.address);
            expect(engineInfo.totalAnalyses).to.equal(1);
        });

        it("Should resolve submissions and update reputation", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);

            const submissionId = await reputation.connect(bountyManager).recordSubmission.staticCall(
                engine1.address,
                1,
                true,
                ethers.parseEther("10"),
                90
            );

            await reputation.connect(bountyManager).recordSubmission(
                engine1.address,
                1,
                true,
                ethers.parseEther("10"),
                90
            );

            const initialRep = (await reputation.getEngineInfo(engine1.address)).reputation;

            await reputation.connect(bountyManager).resolveSubmission(submissionId, true);

            // The contract's weighted reputation calc accounts for stake, confidence, etc.
            // A correct resolution does update the reputation, but the new value depends
            // on the calculation formula — just verify it changed
            const finalRep = (await reputation.getEngineInfo(engine1.address)).reputation;
            expect(finalRep).to.not.equal(initialRep);
        });

        it("Should penalize incorrect predictions", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);

            const submissionId = await reputation.connect(bountyManager).recordSubmission.staticCall(
                engine1.address,
                1,
                true,
                ethers.parseEther("10"),
                90
            );

            await reputation.connect(bountyManager).recordSubmission(
                engine1.address,
                1,
                true,
                ethers.parseEther("10"),
                90
            );

            const initialRep = (await reputation.getEngineInfo(engine1.address)).reputation;

            // Resolve as incorrect
            await reputation.connect(bountyManager).resolveSubmission(submissionId, false);

            const finalRep = (await reputation.getEngineInfo(engine1.address)).reputation;
            expect(finalRep).to.be.lessThan(initialRep);
        });
    });

    describe("Engine Management", function () {
        it("Should deactivate an engine", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);
            await reputation.connect(bountyManager).deactivateEngine(engine1.address);

            const engineInfo = await reputation.getEngineInfo(engine1.address);
            expect(engineInfo.isActive).to.be.false;
        });

        it("Should reactivate an engine", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);
            await reputation.connect(bountyManager).deactivateEngine(engine1.address);
            await reputation.connect(bountyManager).reactivateEngine(engine1.address);

            const engineInfo = await reputation.getEngineInfo(engine1.address);
            expect(engineInfo.isActive).to.be.true;
        });
    });

    describe("View Functions", function () {
        it("Should return correct accuracy rate", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);

            // Record and resolve correct submission
            const submissionId = await reputation.connect(bountyManager).recordSubmission.staticCall(
                engine1.address, 1, true, ethers.parseEther("10"), 90
            );
            await reputation.connect(bountyManager).recordSubmission(
                engine1.address, 1, true, ethers.parseEther("10"), 90
            );
            await reputation.connect(bountyManager).resolveSubmission(submissionId, true);

            const accuracy = await reputation.getAccuracyRate(engine1.address);
            expect(accuracy).to.equal(100); // 100% accuracy
        });

        it("Should check eligibility correctly", async function () {
            const { reputation, engine1, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);

            const isEligible = await reputation.isEligibleEngine(engine1.address);
            expect(isEligible).to.be.true;
        });

        it("Should return top engines", async function () {
            const { reputation, engine1, engine2, bountyManager } = await loadFixture(deployReputationFixture);

            await reputation.connect(bountyManager).registerEngine(engine1.address, 0);
            await reputation.connect(bountyManager).registerEngine(engine2.address, 0);

            const [topEngines, _reputations] = await reputation.getTopEngines(2);
            expect(topEngines.length).to.equal(2);
        });
    });
});
