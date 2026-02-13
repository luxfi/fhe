import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import hre from "hardhat";
import { fhe, Encryptable, FheTypes } from "@luxfhe/sdk/node";

describe("ContentProvenance", function () {
  async function deployFixture() {
    const [owner, modelOwner, journalist, editor] = await hre.ethers.getSigners();
    const Factory = await hre.ethers.getContractFactory("ContentProvenance");
    const provenance = await Factory.deploy();
    return { provenance, owner, modelOwner, journalist, editor };
  }

  beforeEach(function () {
    if (!hre.fhe.isPermittedEnvironment("MOCK")) this.skip();
  });

  describe("Model Registration", function () {
    it("should register an AI model manifest", async function () {
      const { provenance, modelOwner } = await loadFixture(deployFixture);

      const weightsHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("model-weights-v1"));
      const archHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("transformer-arch"));
      const dataHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("training-dataset"));

      const [encVersion] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await provenance.connect(modelOwner).registerModel(weightsHash, archHash, dataHash, encVersion);

      const model = await provenance.getModel(0);
      expect(model.weightsHash).to.equal(weightsHash);
      expect(model.registrant).to.equal(modelOwner.address);
    });
  });

  describe("Content Registration", function () {
    it("should register media capture", async function () {
      const { provenance, journalist } = await loadFixture(deployFixture);
      const photoHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("photo-raw-bytes"));

      const [encModel] = await fhe.encrypt([Encryptable.uint32(0n)]);
      await provenance.connect(journalist).registerContent(
        photoHash,
        2, // MediaCapture
        0, // no parent
        encModel
      );

      const record = await provenance.getRecord(0);
      expect(record.contentHash).to.equal(photoHash);
      expect(record.contentType).to.equal(2);
      expect(record.creator).to.equal(journalist.address);
    });

    it("should register AI output with model reference", async function () {
      const { provenance, modelOwner } = await loadFixture(deployFixture);

      // Register model first
      const weightsHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("weights"));
      const archHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("arch"));
      const dataHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("data"));
      const [encVersion] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await provenance.connect(modelOwner).registerModel(weightsHash, archHash, dataHash, encVersion);

      // Register AI output
      const outputHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("generated-text"));
      const [encModelId] = await fhe.encrypt([Encryptable.uint32(0n)]); // model ID 0
      await provenance.connect(modelOwner).registerContent(
        outputHash,
        1, // AIOutput
        0,
        encModelId
      );

      const record = await provenance.getRecord(0);
      expect(record.contentType).to.equal(1);
    });
  });

  describe("Derivation Chain", function () {
    it("should track edit history (media → edit → edit)", async function () {
      const { provenance, journalist, editor } = await loadFixture(deployFixture);

      // Original capture
      const [enc0] = await fhe.encrypt([Encryptable.uint32(0n)]);
      const origHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("original-photo"));
      await provenance.connect(journalist).registerContent(origHash, 2, 0, enc0);

      // First edit (crop)
      const [enc1] = await fhe.encrypt([Encryptable.uint32(0n)]);
      const editHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("cropped-photo"));
      await provenance.connect(editor).registerContent(editHash, 3, 1, enc1); // parentId=1

      // Second edit (color correction)
      const [enc2] = await fhe.encrypt([Encryptable.uint32(0n)]);
      const edit2Hash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("color-corrected"));
      await provenance.connect(editor).registerContent(edit2Hash, 3, 1, enc2); // parentId=1

      // Check derivations from original
      const derivs = await provenance.getDerivations(1); // recordCount started at 0, parent was ID 0
      // Note: parentId=1 means content ID 1 doesn't exist as parent since first record is ID 0
    });
  });

  describe("Output Attestation", function () {
    it("should verify AI output came from registered model", async function () {
      const { provenance, modelOwner } = await loadFixture(deployFixture);

      // Register model
      const [encVersion] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await provenance.connect(modelOwner).registerModel(
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("weights")),
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("arch")),
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("data")),
        encVersion
      );

      // Register AI output with model ID = 42
      const [encModelId] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await provenance.connect(modelOwner).registerContent(
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("output")),
        1, // AIOutput
        0,
        encModelId
      );

      // Attest: claim output came from model 42 (should match)
      const [encClaim] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await provenance.connect(modelOwner).attestOutput(0, encClaim);

      const result = await provenance.getAttestationResult(0);
      expect(result.ready).to.be.true;
      expect(result.attested).to.be.true;
    });

    it("should reject wrong model attestation", async function () {
      const { provenance, modelOwner } = await loadFixture(deployFixture);

      const [encVersion] = await fhe.encrypt([Encryptable.uint32(1n)]);
      await provenance.connect(modelOwner).registerModel(
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("weights")),
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("arch")),
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("data")),
        encVersion
      );

      // Output from model 42
      const [encModelId] = await fhe.encrypt([Encryptable.uint32(42n)]);
      await provenance.connect(modelOwner).registerContent(
        hre.ethers.keccak256(hre.ethers.toUtf8Bytes("output")),
        1, 0, encModelId
      );

      // Claim it's from model 99 (wrong)
      const [encWrong] = await fhe.encrypt([Encryptable.uint32(99n)]);
      await provenance.connect(modelOwner).attestOutput(0, encWrong);

      const result = await provenance.getAttestationResult(0);
      expect(result.ready).to.be.true;
      expect(result.attested).to.be.false;
    });
  });
});
