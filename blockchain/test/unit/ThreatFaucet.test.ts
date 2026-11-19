import { expect } from "chai";
import { ethers } from "hardhat";
import type { Contract } from "ethers";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { advanceTime } from "../fixtures/setup";

const DAY = 24 * 3600;

async function faucetFixture() {
    const [owner, alice, bob, other] = await ethers.getSigners();
    const token = await (await ethers.getContractFactory("ThreatToken")).deploy(owner.address);
    // Typechain's generator is broken in this repo, so the faucet is typed as a plain contract.
    const faucet = (await (await ethers.getContractFactory("ThreatFaucet")).deploy(
        await token.getAddress(),
        ethers.parseEther("100"),
        DAY
    )) as unknown as Contract;
    await token.transfer(await faucet.getAddress(), ethers.parseEther("250"));
    return { token, faucet, owner, alice, bob, other };
}

describe("ThreatFaucet", function () {
    it("gives each wallet the drip amount", async function () {
        const { token, faucet, alice } = await loadFixture(faucetFixture);
        await expect((faucet.connect(alice) as Contract).claim())
            .to.emit(faucet, "Claimed")
            .withArgs(alice.address, ethers.parseEther("100"));
        expect(await token.balanceOf(alice.address)).to.equal(ethers.parseEther("100"));
    });

    it("makes a wallet wait out the cooldown before claiming again", async function () {
        const { faucet, alice } = await loadFixture(faucetFixture);
        expect(await faucet.nextClaimAt(alice.address)).to.equal(0n);
        await (faucet.connect(alice) as Contract).claim();
        const next = await faucet.nextClaimAt(alice.address);
        expect(next).to.be.greaterThan(0n);

        await expect((faucet.connect(alice) as Contract).claim()).to.be.revertedWith("Come back later");
        await advanceTime(DAY);
        await expect((faucet.connect(alice) as Contract).claim()).to.emit(faucet, "Claimed");
    });

    it("says when it's empty instead of giving part of a drip", async function () {
        const { faucet, alice, bob, other } = await loadFixture(faucetFixture);
        await (faucet.connect(alice) as Contract).claim();
        await (faucet.connect(bob) as Contract).claim();
        // 50 left, less than a drip.
        await expect((faucet.connect(other) as Contract).claim()).to.be.revertedWith("Faucet is empty");
        expect(await faucet.nextClaimAt(other.address)).to.equal(0n);
    });

    it("lets only the owner change the drip, within limits", async function () {
        const { faucet, owner, alice } = await loadFixture(faucetFixture);
        await expect((faucet.connect(alice) as Contract).setDrip(1n, DAY)).to.be.revertedWithCustomError(
            faucet,
            "OwnableUnauthorizedAccount"
        );
        await expect((faucet.connect(owner) as Contract).setDrip(0n, DAY)).to.be.revertedWith("Invalid drip");
        await expect((faucet.connect(owner) as Contract).setDrip(ethers.parseEther("10"), 60)).to.be.revertedWith("Invalid drip");
        await expect((faucet.connect(owner) as Contract).setDrip(ethers.parseEther("10"), 3600))
            .to.emit(faucet, "DripChanged")
            .withArgs(ethers.parseEther("10"), 3600);
        expect(await faucet.dripAmount()).to.equal(ethers.parseEther("10"));
    });

    it("lets only the owner take tokens back out", async function () {
        const { token, faucet, owner, alice } = await loadFixture(faucetFixture);
        await expect((faucet.connect(alice) as Contract).reclaim(1n)).to.be.revertedWithCustomError(
            faucet,
            "OwnableUnauthorizedAccount"
        );
        const before = await token.balanceOf(owner.address);
        await (faucet.connect(owner) as Contract).reclaim(ethers.parseEther("250"));
        expect((await token.balanceOf(owner.address)) - before).to.equal(ethers.parseEther("250"));
    });

    it("refuses a zero token address or a bad drip at deployment", async function () {
        const F = await ethers.getContractFactory("ThreatFaucet");
        await expect(F.deploy(ethers.ZeroAddress, 1n, DAY)).to.be.revertedWith("Invalid token");
        const { token } = await loadFixture(faucetFixture);
        await expect(F.deploy(await token.getAddress(), 0n, DAY)).to.be.revertedWith("Invalid drip");
    });
});
