import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import hre from "hardhat";
import { fhe, Encryptable, FheTypes } from "@luxfhe/sdk/node";

describe("ShadowGovernance", function () {
  async function deployFixture() {
    const [admin, alice, bob, charlie, dave] = await hre.ethers.getSigners();
    const Factory = await hre.ethers.getContractFactory("ShadowGovernance");
    const gov = await Factory.connect(admin).deploy();

    // Setup: create a ministry and set participants
    const ministryId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("shadow-education"));
    const ministryName = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Education"));
    const ministryDesc = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Shadow Ministry of Education"));

    await gov.connect(admin).createMinistry(ministryId, ministryName, ministryDesc);
    await gov.connect(admin).setParticipantCount(100);

    return { gov, admin, alice, bob, charlie, dave, ministryId };
  }

  beforeEach(function () {
    if (!hre.fhe.isPermittedEnvironment("MOCK")) this.skip();
  });

  describe("Ministry Management", function () {
    it("should create a ministry", async function () {
      const { gov, ministryId } = await loadFixture(deployFixture);
      const ministry = await gov.ministries(ministryId);
      expect(ministry.active).to.be.true;
    });

    it("should reject duplicate ministry", async function () {
      const { gov, admin, ministryId } = await loadFixture(deployFixture);
      await expect(
        gov.connect(admin).createMinistry(
          ministryId,
          hre.ethers.keccak256(hre.ethers.toUtf8Bytes("dup")),
          hre.ethers.keccak256(hre.ethers.toUtf8Bytes("dup"))
        )
      ).to.be.revertedWith("Ministry exists");
    });

    it("should track ministry count", async function () {
      const { gov, admin } = await loadFixture(deployFixture);

      const id2 = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("shadow-health"));
      await gov.connect(admin).createMinistry(
        id2,
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Health")),
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Health Ministry"))
      );

      expect(await gov.getMinistryCount()).to.equal(2);
    });
  });

  describe("Proposal Creation", function () {
    it("should create a proposal", async function () {
      const { gov, alice, ministryId } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Reform proposal"));

      await gov.connect(alice).createProposal(contentHash, ministryId, 100);

      const proposal = await gov.getProposal(0);
      expect(proposal.contentHash).to.equal(contentHash);
      expect(proposal.ministryId).to.equal(ministryId);
      expect(proposal.voterCount).to.equal(0);
      expect(proposal.status).to.equal(0); // Active
    });
  });

  describe("Anonymous Voting", function () {
    it("should cast encrypted votes", async function () {
      const { gov, alice, bob, charlie, ministryId } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Vote test"));

      await gov.connect(alice).createProposal(contentHash, ministryId, 1000);

      // Alice votes yes (1)
      const nullifier1 = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("alice-secret-0"));
      const [encYes] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await gov.connect(alice).castVote(0, encYes, nullifier1);

      // Bob votes no (0)
      const nullifier2 = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("bob-secret-0"));
      const [encNo] = await fhe.encrypt([Encryptable.uint32(0n)]);
      await gov.connect(bob).castVote(0, encNo, nullifier2);

      // Charlie votes yes (1)
      const nullifier3 = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("charlie-secret-0"));
      const [encYes2] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await gov.connect(charlie).castVote(0, encYes2, nullifier3);

      const proposal = await gov.getProposal(0);
      expect(proposal.voterCount).to.equal(3);
    });

    it("should prevent double-voting with same nullifier", async function () {
      const { gov, alice, ministryId } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Double vote test"));

      await gov.connect(alice).createProposal(contentHash, ministryId, 1000);

      const nullifier = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("alice-secret"));
      const [enc] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await gov.connect(alice).castVote(0, enc, nullifier);

      // Same nullifier = rejected
      const [enc2] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await expect(gov.connect(alice).castVote(0, enc2, nullifier))
        .to.be.revertedWith("Already voted");
    });
  });

  describe("Tally and Finalization", function () {
    it("should tally votes and finalize (pass scenario)", async function () {
      const { gov, admin, alice, bob, charlie, dave, ministryId } = await loadFixture(deployFixture);

      // Set low quorum for test
      await gov.connect(admin).setQuorum(100); // 1%

      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Tally test"));
      await gov.connect(alice).createProposal(contentHash, ministryId, 5);

      // 3 yes, 1 no
      const [ey1] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await gov.connect(alice).castVote(0, ey1, hre.ethers.keccak256(hre.ethers.toUtf8Bytes("n1")));

      const [ey2] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await gov.connect(bob).castVote(0, ey2, hre.ethers.keccak256(hre.ethers.toUtf8Bytes("n2")));

      const [ey3] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await gov.connect(charlie).castVote(0, ey3, hre.ethers.keccak256(hre.ethers.toUtf8Bytes("n3")));

      const [en1] = await fhe.encrypt([Encryptable.uint32(0n)]);
      await gov.connect(dave).castVote(0, en1, hre.ethers.keccak256(hre.ethers.toUtf8Bytes("n4")));

      // Mine blocks past deadline
      await hre.network.provider.send("hardhat_mine", ["0x10"]);

      // Start tally
      await gov.startTally(0);

      // Finalize
      await gov.finalize(0);

      const proposal = await gov.getProposal(0);
      expect(proposal.status).to.equal(2); // Passed

      const tally = await gov.getTally(0);
      expect(tally.yesVotes).to.equal(3);
      expect(tally.noVotes).to.equal(1);
    });
  });

  describe("Access Control", function () {
    it("should reject non-admin ministry creation", async function () {
      const { gov, alice } = await loadFixture(deployFixture);
      await expect(
        gov.connect(alice).createMinistry(
          hre.ethers.keccak256(hre.ethers.toUtf8Bytes("rogue")),
          hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Rogue")),
          hre.ethers.keccak256(hre.ethers.toUtf8Bytes("Rogue Ministry"))
        )
      ).to.be.revertedWith("Not admin");
    });
  });
});
