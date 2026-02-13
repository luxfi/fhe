import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import hre from "hardhat";
import { fhe, Encryptable, FheTypes } from "@luxfhe/sdk/node";

describe("EncryptedCRDT", function () {
  async function deployFixture() {
    const [owner, alice, bob, charlie] = await hre.ethers.getSigners();
    const Factory = await hre.ethers.getContractFactory("EncryptedCRDT");
    const crdt = await Factory.deploy();
    return { crdt, owner, alice, bob, charlie };
  }

  beforeEach(function () {
    if (!hre.fhe.isPermittedEnvironment("MOCK")) this.skip();
  });

  function registerId(docId: string, field: string): string {
    return hre.ethers.keccak256(
      hre.ethers.solidityPacked(["string", "string"], [docId, field])
    );
  }

  describe("LWW-Register", function () {
    it("should set and read an encrypted register", async function () {
      const { crdt, alice } = await loadFixture(deployFixture);
      const regId = registerId("doc1", "title");
      const docId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc1"));

      const [encVal] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await crdt.connect(alice).setRegister(regId, encVal, 1, docId);

      const info = await crdt.getRegisterInfo(regId);
      expect(info.exists).to.be.true;
      expect(info.timestamp).to.equal(1);
      expect(info.lastWriter).to.equal(alice.address);
    });

    it("should accept higher timestamp (LWW semantics)", async function () {
      const { crdt, alice, bob } = await loadFixture(deployFixture);
      const regId = registerId("doc1", "title");
      const docId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc1"));

      // Alice writes at t=1
      const [enc1] = await fhe.encrypt([Encryptable.uint32(10n)]);
      await crdt.connect(alice).setRegister(regId, enc1, 1, docId);

      // Bob writes at t=2 (wins)
      const [enc2] = await fhe.encrypt([Encryptable.uint32(20n)]);
      await crdt.connect(bob).setRegister(regId, enc2, 2, docId);

      const info = await crdt.getRegisterInfo(regId);
      expect(info.timestamp).to.equal(2);
      expect(info.lastWriter).to.equal(bob.address);
    });

    it("should reject stale updates (lower timestamp)", async function () {
      const { crdt, alice, bob } = await loadFixture(deployFixture);
      const regId = registerId("doc1", "title");
      const docId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc1"));

      // Alice writes at t=5
      const [enc1] = await fhe.encrypt([Encryptable.uint32(10n)]);
      await crdt.connect(alice).setRegister(regId, enc1, 5, docId);

      // Bob tries to write at t=3 (rejected)
      const [enc2] = await fhe.encrypt([Encryptable.uint32(20n)]);
      await expect(crdt.connect(bob).setRegister(regId, enc2, 3, docId))
        .to.be.revertedWith("Stale update: lower timestamp");
    });

    it("should decrypt register value", async function () {
      const { crdt, alice } = await loadFixture(deployFixture);
      const regId = registerId("doc1", "title");
      const docId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc1"));

      const [encVal] = await fhe.encrypt([Encryptable.uint32(99n)]);
      await crdt.connect(alice).setRegister(regId, encVal, 1, docId);
      await crdt.connect(alice).decryptRegister(regId);

      const result = await crdt.getDecryptedRegister(regId);
      expect(result.ready).to.be.true;
      expect(result.value).to.equal(99);
    });
  });

  describe("Register Merge", function () {
    it("should merge two registers (higher timestamp wins)", async function () {
      const { crdt, alice, bob } = await loadFixture(deployFixture);
      const docId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("doc1"));

      const regA = registerId("doc1", "title-alice");
      const regB = registerId("doc1", "title-bob");
      const regMerged = registerId("doc1", "title-merged");

      // Alice's version at t=3
      const [enc1] = await fhe.encrypt([Encryptable.uint32(100n)]);
      await crdt.connect(alice).setRegister(regA, enc1, 3, docId);

      // Bob's version at t=5 (wins)
      const [enc2] = await fhe.encrypt([Encryptable.uint32(200n)]);
      await crdt.connect(bob).setRegister(regB, enc2, 5, docId);

      // Merge
      await crdt.connect(alice).mergeRegisters(regA, regB, regMerged);

      const info = await crdt.getRegisterInfo(regMerged);
      expect(info.timestamp).to.equal(5);
      expect(info.lastWriter).to.equal(bob.address);
    });
  });

  describe("OR-Set", function () {
    it("should add elements to a set", async function () {
      const { crdt, alice } = await loadFixture(deployFixture);
      const setId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("members"));

      const [enc1] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await crdt.connect(alice).addToSet(setId, enc1);

      const [enc2] = await fhe.encrypt([Encryptable.uint32(2n)]);
      await crdt.connect(alice).addToSet(setId, enc2);

      const size = await crdt.getSetSize(setId);
      expect(size).to.equal(2);
    });

    it("should remove elements by tag", async function () {
      const { crdt, alice } = await loadFixture(deployFixture);
      const setId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("members"));

      const [enc1] = await fhe.encrypt([Encryptable.uint32(1n)]);
      const tx = await crdt.connect(alice).addToSet(setId, enc1);
      const receipt = await tx.wait();

      // Get the tag from the event
      const event = receipt?.logs.find((l: any) => l.fragment?.name === "SetElementAdded");
      const tag = (event as any)?.args?.uniqueTag;

      if (tag) {
        await crdt.connect(alice).removeFromSet(setId, tag);
        const size = await crdt.getSetSize(setId);
        expect(size).to.equal(0);
      }
    });

    it("should track operation count", async function () {
      const { crdt, alice } = await loadFixture(deployFixture);
      const setId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("ops"));

      const [enc1] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await crdt.connect(alice).addToSet(setId, enc1);

      const [enc2] = await fhe.encrypt([Encryptable.uint32(2n)]);
      await crdt.connect(alice).addToSet(setId, enc2);

      expect(await crdt.operationCount()).to.equal(2);
    });
  });
});
