import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployFixture, createTestBounty, submitTestAnalysis, advanceTime } from "../fixtures/setup";

describe("BountyManager", function () {
    describe("Bounty Creation", function () {
        it("Should create a bounty successfully", async function () {
            const { bountyManager, threatToken, submitter } = await loadFixture(deployFixture);

            const rewardAmount = ethers.parseEther("100");
            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter, rewardAmount);

            const bounty = await bountyManager.getBounty(bountyId);
            expect(bounty.creator).to.equal(submitter.address);
            expect(bounty.rewardAmount).to.equal(rewardAmount);
            expect(bounty.status).to.equal(0); // Active
        });

        it("Should fail with insufficient token approval", async function () {
            const { bountyManager, submitter } = await loadFixture(deployFixture);

            const deadline = Math.floor(Date.now() / 1000) + 86400;
            await expect(
                bountyManager.connect(submitter).createBounty(
                    "QmTest",
                    "file",
                    ethers.parseEther("100"),
                    deadline,
                    "Test"
                )
            ).to.be.reverted; // Custom error from ERC20 InsufficientAllowance
        });

        it("Should reject deadline that is too soon", async function () {
            const { bountyManager, threatToken, submitter } = await loadFixture(deployFixture);

            const rewardAmount = ethers.parseEther("100");
            await threatToken.connect(submitter).approve(await bountyManager.getAddress(), rewardAmount);

            const deadline = Math.floor(Date.now() / 1000) + 3000; // Less than 1 hour
            await expect(
                bountyManager.connect(submitter).createBounty(
                    "QmTest",
                    "file",
                    rewardAmount,
                    deadline,
                    "Test"
                )
            ).to.be.revertedWith("Deadline too soon");
        });
    });

    describe("Analysis Submission", function () {
        it("Should allow analyst to submit analysis", async function () {
            const { bountyManager, threatToken, submitter, analyst1 } = await loadFixture(deployFixture);

            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);

            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId);

            const analysis = await bountyManager.getAnalysis(bountyId, analyst1.address);
            expect(analysis.analyst).to.equal(analyst1.address);
            expect(analysis.verdict).to.equal(1); // Benign
        });

        it("Should enforce minimum stake", async function () {
            const { bountyManager, threatToken, submitter, analyst1 } = await loadFixture(deployFixture);

            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);

            const lowStake = ethers.parseEther("5"); // Below minimum
            await threatToken.connect(analyst1).approve(await bountyManager.getAddress(), lowStake);

            await expect(
                bountyManager.connect(analyst1).submitAnalysis(
                    bountyId,
                    1,
                    90,
                    lowStake,
                    "QmAnalysis"
                )
            ).to.be.revertedWith("Insufficient stake");
        });

        it("Should prevent duplicate submissions", async function () {
            const { bountyManager, threatToken, submitter, analyst1 } = await loadFixture(deployFixture);

            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);

            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId);

            await expect(
                submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId)
            ).to.be.revertedWith("Already submitted");
        });
    });

    describe("Consensus and Resolution", function () {
        it("Should reach consensus with majority agreement", async function () {
            const { bountyManager, threatToken, submitter, analyst1, analyst2, analyst3 } = await loadFixture(deployFixture);

            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);

            // All analysts agree: Benign
            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId, 1); // Benign
            await submitTestAnalysis(bountyManager, threatToken, analyst2, bountyId, 1); // Benign
            await submitTestAnalysis(bountyManager, threatToken, analyst3, bountyId, 1); // Benign

            // Advance time past deadline
            await advanceTime(86400 + 1);

            // Resolve bounty
            await bountyManager.resolveBounty(bountyId);

            const bounty = await bountyManager.getBounty(bountyId);
            expect(bounty.consensusVerdict).to.equal(1); // Benign
            expect(bounty.status).to.equal(2); // Completed
        });

        it("Should distribute rewards to correct analysts", async function () {
            const { bountyManager, threatToken, submitter, analyst1, analyst2 } = await loadFixture(deployFixture);

            const rewardAmount = ethers.parseEther("100");
            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter, rewardAmount);

            const initialBalance1 = await threatToken.balanceOf(analyst1.address);
            const initialBalance2 = await threatToken.balanceOf(analyst2.address);

            // Both agree: Benign
            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId, 1);
            await submitTestAnalysis(bountyManager, threatToken, analyst2, bountyId, 1);

            // Add more submissions so analysisCount >= MIN_ANALYSES_TO_RESOLVE
            for (let i = 3; i <= 10; i++) {
                const [, , , , , , ...users] = await ethers.getSigners();
                const analyst = users[i];

                // Authorize and register
                await threatToken.setEngineAuthorization(analyst.address, true);
                await (await ethers.getContractAt("ReputationSystem", await bountyManager.reputationSystem())).registerEngine(analyst.address, 0);

                // Fund analyst
                await threatToken.transfer(analyst.address, ethers.parseEther("1000"));

                await submitTestAnalysis(bountyManager, threatToken, analyst, bountyId, 1);
            }

            // Resolution is decoupled from submission; trigger it explicitly.
            await bountyManager.resolveBounty(bountyId);

            // Payouts use a pull-payment pattern: winners must withdraw().
            await bountyManager.connect(analyst1).withdraw();
            await bountyManager.connect(analyst2).withdraw();

            // Check balances increased (stake returned + reward)
            const finalBalance1 = await threatToken.balanceOf(analyst1.address);
            const finalBalance2 = await threatToken.balanceOf(analyst2.address);

            expect(finalBalance1).to.be.greaterThan(initialBalance1);
            expect(finalBalance2).to.be.greaterThan(initialBalance2);
        });

        it("Should slash stakes for incorrect analysts", async function () {
            const { bountyManager, threatToken, submitter, analyst1, analyst2, analyst3 } = await loadFixture(deployFixture);

            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);

            const initialBalance = await threatToken.balanceOf(analyst3.address);

            // Majority says Benign, analyst3 says Malicious
            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId, 1); // Benign
            await submitTestAnalysis(bountyManager, threatToken, analyst2, bountyId, 1); // Benign
            await submitTestAnalysis(bountyManager, threatToken, analyst3, bountyId, 2, 90); // Malicious - outvoted

            // Add more correct submissions — keep under auto-resolve threshold (10 total)
            // 3 already submitted above, add 4 more = 7 total (under 10)
            for (let i = 3; i <= 6; i++) {
                const [, , , , , , ...users] = await ethers.getSigners();
                const analyst = users[i];

                await threatToken.setEngineAuthorization(analyst.address, true);
                await (await ethers.getContractAt("ReputationSystem", await bountyManager.reputationSystem())).registerEngine(analyst.address, 0);
                await threatToken.transfer(analyst.address, ethers.parseEther("1000"));

                await submitTestAnalysis(bountyManager, threatToken, analyst, bountyId, 1); // Benign
            }

            // Advance time past deadline and resolve manually
            await advanceTime(86400 + 1);
            await bountyManager.resolveBounty(bountyId);

            // Analyst3's balance should be less (stake slashed)
            const finalBalance = await threatToken.balanceOf(analyst3.address);
            expect(finalBalance).to.be.lessThan(initialBalance);
        });
    });

    describe("View Functions", function () {
        it("Should return bounty analysts", async function () {
            const { bountyManager, threatToken, submitter, analyst1, analyst2 } = await loadFixture(deployFixture);

            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);

            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId);
            await submitTestAnalysis(bountyManager, threatToken, analyst2, bountyId);

            const analysts = await bountyManager.getBountyAnalysts(bountyId);
            expect(analysts.length).to.equal(2);
            expect(analysts).to.include(analyst1.address);
            expect(analysts).to.include(analyst2.address);
        });

        it("Should return user bounties", async function () {
            const { bountyManager, threatToken, submitter } = await loadFixture(deployFixture);

            await createTestBounty(bountyManager, threatToken, submitter);
            await createTestBounty(bountyManager, threatToken, submitter);

            const userBounties = await bountyManager.getUserBounties(submitter.address);
            expect(userBounties.length).to.equal(2);
        });

        it("Should return total bounties", async function () {
            const { bountyManager, threatToken, submitter } = await loadFixture(deployFixture);

            const initialCount = await bountyManager.getTotalBounties();

            await createTestBounty(bountyManager, threatToken, submitter);
            await createTestBounty(bountyManager, threatToken, submitter);

            const finalCount = await bountyManager.getTotalBounties();
            expect(finalCount).to.equal(initialCount + 2n);
        });
    });

    describe("Admin Functions", function () {
        it("Should allow owner to pause", async function () {
            const { bountyManager, deployer } = await loadFixture(deployFixture);

            await bountyManager.connect(deployer).pause();
            // Note: There's no public paused() getter in the contract, would need to try creating a bounty
        });

        it("Should allow owner to set fee collector", async function () {
            const { bountyManager, deployer, analyst1 } = await loadFixture(deployFixture);

            await expect(
                bountyManager.connect(deployer).setFeeCollector(analyst1.address)
            ).to.not.be.reverted;
        });
    });

    describe("Ownership Transfer (two-step)", function () {
        it("Should not change owner until the new owner accepts", async function () {
            const { bountyManager, deployer, analyst1 } = await loadFixture(deployFixture);

            await expect(bountyManager.connect(deployer).transferOwnership(analyst1.address))
                .to.emit(bountyManager, "OwnershipTransferStarted")
                .withArgs(deployer.address, analyst1.address);

            // Owner is unchanged; only pendingOwner is set.
            expect(await bountyManager.owner()).to.equal(deployer.address);
            expect(await bountyManager.pendingOwner()).to.equal(analyst1.address);
        });

        it("Should complete the transfer when the pending owner accepts", async function () {
            const { bountyManager, deployer, analyst1 } = await loadFixture(deployFixture);

            await bountyManager.connect(deployer).transferOwnership(analyst1.address);

            await expect(bountyManager.connect(analyst1).acceptOwnership())
                .to.emit(bountyManager, "OwnershipTransferred")
                .withArgs(deployer.address, analyst1.address);

            expect(await bountyManager.owner()).to.equal(analyst1.address);
            expect(await bountyManager.pendingOwner()).to.equal(ethers.ZeroAddress);

            // New owner can use admin functions; old owner cannot.
            await expect(bountyManager.connect(analyst1).pause()).to.not.be.reverted;
            await expect(bountyManager.connect(deployer).unpause()).to.be.revertedWith("Not authorized");
        });

        it("Should reject acceptOwnership from a non-pending account", async function () {
            const { bountyManager, deployer, analyst1, analyst2 } = await loadFixture(deployFixture);

            await bountyManager.connect(deployer).transferOwnership(analyst1.address);

            await expect(bountyManager.connect(analyst2).acceptOwnership()).to.be.revertedWith(
                "Not pending owner"
            );
        });

        it("Should only let the owner start a transfer", async function () {
            const { bountyManager, analyst1, analyst2 } = await loadFixture(deployFixture);

            await expect(
                bountyManager.connect(analyst1).transferOwnership(analyst2.address)
            ).to.be.revertedWith("Not authorized");
        });

        it("Should reject transferring ownership to the zero address", async function () {
            const { bountyManager, deployer } = await loadFixture(deployFixture);

            await expect(
                bountyManager.connect(deployer).transferOwnership(ethers.ZeroAddress)
            ).to.be.revertedWith("New owner is zero address");
        });
    });

    describe("emergencyWithdraw escrow protection", function () {
        it("Should not let the owner withdraw escrowed user funds", async function () {
            const { bountyManager, threatToken, deployer, submitter, analyst1 } =
                await loadFixture(deployFixture);

            const rewardAmount = ethers.parseEther("100");
            const { bountyId } = await createTestBounty(
                bountyManager,
                threatToken,
                submitter,
                rewardAmount
            );
            const stakeAmount = ethers.parseEther("10");
            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId, 1, 90, stakeAmount);

            // Reward + stake are now escrowed and fully accounted.
            const escrowed = await bountyManager.totalEscrowed();
            expect(escrowed).to.equal(rewardAmount + stakeAmount);

            await bountyManager.connect(deployer).pause();

            // With no surplus, the owner cannot pull any threatToken.
            await expect(
                bountyManager
                    .connect(deployer)
                    .emergencyWithdraw(await threatToken.getAddress(), 1n)
            ).to.be.revertedWith("Exceeds unescrowed surplus");

            // Escrowed balance is untouched.
            expect(await threatToken.balanceOf(await bountyManager.getAddress())).to.equal(escrowed);
        });

        it("Should let the owner rescue only the unescrowed surplus", async function () {
            const { bountyManager, threatToken, deployer, submitter, analyst1 } =
                await loadFixture(deployFixture);

            const rewardAmount = ethers.parseEther("100");
            const { bountyId } = await createTestBounty(
                bountyManager,
                threatToken,
                submitter,
                rewardAmount
            );
            const stakeAmount = ethers.parseEther("10");
            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId, 1, 90, stakeAmount);

            // Simulate tokens accidentally sent straight to the contract (not escrow).
            const surplus = ethers.parseEther("25");
            await threatToken.transfer(await bountyManager.getAddress(), surplus);

            await bountyManager.connect(deployer).pause();

            // Cannot take more than the surplus...
            await expect(
                bountyManager
                    .connect(deployer)
                    .emergencyWithdraw(await threatToken.getAddress(), surplus + 1n)
            ).to.be.revertedWith("Exceeds unescrowed surplus");

            // ...but can rescue exactly the surplus.
            const ownerBefore = await threatToken.balanceOf(deployer.address);
            await bountyManager
                .connect(deployer)
                .emergencyWithdraw(await threatToken.getAddress(), surplus);
            const ownerAfter = await threatToken.balanceOf(deployer.address);
            expect(ownerAfter - ownerBefore).to.equal(surplus);

            // Escrow is still intact and analyst can still withdraw their payout later.
            expect(await threatToken.balanceOf(await bountyManager.getAddress())).to.equal(
                rewardAmount + stakeAmount
            );
        });

        it("Should require the contract to be paused", async function () {
            const { bountyManager, threatToken, deployer } = await loadFixture(deployFixture);

            await expect(
                bountyManager
                    .connect(deployer)
                    .emergencyWithdraw(await threatToken.getAddress(), 1n)
            ).to.be.revertedWith("Contract must be paused");
        });
    });

    describe("Analyst registration", function () {
        it("Should reject an analysis from an unregistered wallet", async function () {
            const { bountyManager, threatToken, submitter, users } = await loadFixture(deployFixture);
            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);
            const stranger = users[0];
            await threatToken.transfer(stranger.address, ethers.parseEther("100"));

            await expect(
                submitTestAnalysis(bountyManager, threatToken, stranger, bountyId)
            ).to.be.revertedWith("Not a registered analyst");
        });

        it("Should let a wallet register itself and then be paid", async function () {
            const { bountyManager, threatToken, reputationSystem, submitter, users } = await loadFixture(deployFixture);
            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);
            const newcomer = users[1];
            await threatToken.transfer(newcomer.address, ethers.parseEther("100"));

            expect(await bountyManager.isAnalyst(newcomer.address)).to.equal(false);
            await expect(bountyManager.connect(newcomer).registerAnalyst())
                .to.emit(reputationSystem, "EngineRegistered")
                .withArgs(newcomer.address, 0, 100);
            expect(await bountyManager.isAnalyst(newcomer.address)).to.equal(true);

            await submitTestAnalysis(bountyManager, threatToken, newcomer, bountyId, 1);
            await advanceTime(86400 + 1);
            await bountyManager.resolveBounty(bountyId);

            // Sole analyst: stake back plus the reward minus the 5% fee.
            expect(await bountyManager.pendingWithdrawals(newcomer.address)).to.equal(
                ethers.parseEther("10") + ethers.parseEther("95")
            );
            expect(await reputationSystem.getReputation(newcomer.address)).to.be.greaterThan(100n);
        });

        it("Should refuse to register the same wallet twice", async function () {
            const { bountyManager, users } = await loadFixture(deployFixture);
            await bountyManager.connect(users[2]).registerAnalyst();
            await expect(bountyManager.connect(users[2]).registerAnalyst()).to.be.revertedWith(
                "Engine already registered"
            );
        });

        it("Should not let a deactivated analyst register again for a fresh score", async function () {
            const { bountyManager, reputationSystem, analyst1 } = await loadFixture(deployFixture);
            await reputationSystem.deactivateEngine(analyst1.address);

            await expect(bountyManager.connect(analyst1).registerAnalyst()).to.be.revertedWith(
                "Engine already registered"
            );
            expect(await bountyManager.isAnalyst(analyst1.address)).to.equal(false);
        });

        it("Should still resolve when an analyst was deactivated after submitting", async function () {
            const { bountyManager, threatToken, reputationSystem, submitter, analyst1, analyst2 } =
                await loadFixture(deployFixture);
            const { bountyId } = await createTestBounty(bountyManager, threatToken, submitter);

            await submitTestAnalysis(bountyManager, threatToken, analyst1, bountyId, 1);
            await submitTestAnalysis(bountyManager, threatToken, analyst2, bountyId, 1);
            await reputationSystem.deactivateEngine(analyst2.address);

            await advanceTime(86400 + 1);
            await bountyManager.resolveBounty(bountyId);

            expect((await bountyManager.getBounty(bountyId)).status).to.equal(2); // Completed
            expect(await bountyManager.pendingWithdrawals(analyst2.address)).to.be.greaterThan(0n);
        });
    });
});
