import { task } from "hardhat/config";

task("task:get-register", "Get register info and request decryption")
  .addParam("contract", "EncryptedCRDT contract address")
  .addParam("doc", "Document ID")
  .addParam("field", "Field name")
  .setAction(async ({ contract, doc, field }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const crdt = await hre.ethers.getContractAt("EncryptedCRDT", contract);

    const regId = hre.ethers.keccak256(
      hre.ethers.solidityPacked(["string", "string"], [doc, field])
    );

    const info = await crdt.getRegisterInfo(regId);
    if (!info.exists) {
      console.log("Register not found.");
      return;
    }

    console.log("Register:", {
      timestamp: info.timestamp.toString(),
      lastWriter: info.lastWriter,
      documentId: info.documentId,
    });

    // Request decryption
    await crdt.connect(signer).decryptRegister(regId);

    // Poll for result
    let attempts = 0;
    while (attempts < 10) {
      const result = await crdt.getDecryptedRegister(regId);
      if (result.ready) {
        console.log("Decrypted value:", result.value.toString());
        return;
      }
      await new Promise((r) => setTimeout(r, 2000));
      attempts++;
    }
    console.log("Decryption pending.");
  });
