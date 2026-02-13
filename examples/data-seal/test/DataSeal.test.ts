import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import hre from "hardhat";
import { fhe, Encryptable, FheTypes } from "@luxfhe/sdk/node";

describe("DataSeal", function () {
  async function deployFixture() {
    const [owner, alice, bob] = await hre.ethers.getSigners();
    const DataSeal = await hre.ethers.getContractFactory("DataSeal");
    const dataSeal = await DataSeal.deploy();
    return { dataSeal, owner, alice, bob };
  }

  beforeEach(function () {
    if (!hre.fhe.isPermittedEnvironment("MOCK")) this.skip();
  });

  describe("Seal Creation", function () {
    it("should create a Public seal", async function () {
      const { dataSeal, alice } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("document content"));

      const [encTag] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 0); // Public mode

      const seal = await dataSeal.getSeal(0);
      expect(seal.contentHash).to.equal(contentHash);
      expect(seal.creator).to.equal(alice.address);
      expect(seal.mode).to.equal(0);
      expect(seal.revoked).to.be.false;
    });

    it("should create a ZK seal", async function () {
      const { dataSeal, alice } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("secret document"));

      const [encTag] = await fhe.encrypt([Encryptable.uint32(99n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 1); // ZK mode

      const seal = await dataSeal.getSeal(0);
      expect(seal.mode).to.equal(1);
    });

    it("should create a Private (FHE) seal", async function () {
      const { dataSeal, alice } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("encrypted evidence"));

      const [encTag] = await fhe.encrypt([Encryptable.uint32(777n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 2); // Private mode

      const seal = await dataSeal.getSeal(0);
      expect(seal.mode).to.equal(2);
    });

    it("should increment seal count", async function () {
      const { dataSeal, alice } = await loadFixture(deployFixture);
      const hash1 = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc1"));
      const hash2 = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc2"));

      const [enc1] = await fhe.encrypt([Encryptable.uint32(1n)]);
      const [enc2] = await fhe.encrypt([Encryptable.uint32(2n)]);

      await dataSeal.connect(alice).createSeal(hash1, enc1, 0);
      await dataSeal.connect(alice).createSeal(hash2, enc2, 0);

      expect(await dataSeal.sealCount()).to.equal(2);
    });
  });

  describe("Seal Verification", function () {
    it("should verify matching seal (encrypted comparison)", async function () {
      const { dataSeal, alice, bob } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("test document"));

      // Alice creates seal with tag=42
      const [encTag] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 0);

      // Bob verifies with same tag=42 (should match)
      const [challenge] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await dataSeal.connect(bob).verifySeal(0, challenge);

      // In mock mode, check result
      const result = await dataSeal.getVerificationResult(0);
      // Result depends on FHE mock implementation
      expect(result.ready).to.be.true;
      expect(result.matched).to.be.true;
    });

    it("should reject mismatched seal", async function () {
      const { dataSeal, alice, bob } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("test document"));

      // Alice creates seal with tag=42
      const [encTag] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 0);

      // Bob verifies with wrong tag=99 (should not match)
      const [challenge] = await fhe.encrypt([Encryptable.uint32(99n)]);
      await dataSeal.connect(bob).verifySeal(0, challenge);

      const result = await dataSeal.getVerificationResult(0);
      expect(result.ready).to.be.true;
      expect(result.matched).to.be.false;
    });

    it("should reject verification of revoked seal", async function () {
      const { dataSeal, alice, bob } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("revoked doc"));

      const [encTag] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 0);
      await dataSeal.connect(alice).revokeSeal(0);

      const [challenge] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await expect(dataSeal.connect(bob).verifySeal(0, challenge))
        .to.be.revertedWith("Seal revoked");
    });
  });

  describe("Batch Sealing", function () {
    it("should create batch of seals", async function () {
      const { dataSeal, alice } = await loadFixture(deployFixture);

      const hashes = [
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc1")),
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc2")),
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc3")),
      ];

      const tags = await Promise.all([
        fhe.encrypt([Encryptable.uint32(1n)]),
        fhe.encrypt([Encryptable.uint32(2n)]),
        fhe.encrypt([Encryptable.uint32(3n)]),
      ]);

      const tx = await dataSeal.connect(alice).batchSeal(
        hashes,
        tags.map((t) => t[0]),
        0
      );

      const receipt = await tx.wait();
      expect(await dataSeal.sealCount()).to.equal(3);
    });
  });

  describe("Seal Revocation", function () {
    it("should allow creator to revoke", async function () {
      const { dataSeal, alice } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc"));

      const [encTag] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 0);
      await dataSeal.connect(alice).revokeSeal(0);

      const seal = await dataSeal.getSeal(0);
      expect(seal.revoked).to.be.true;
    });

    it("should reject non-creator revocation", async function () {
      const { dataSeal, alice, bob } = await loadFixture(deployFixture);
      const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc"));

      const [encTag] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await dataSeal.connect(alice).createSeal(contentHash, encTag, 0);

      await expect(dataSeal.connect(bob).revokeSeal(0))
        .to.be.revertedWith("Not seal creator");
    });
  });
});
