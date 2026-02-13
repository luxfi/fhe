import { task } from "hardhat/config";
import { fhe, Encryptable } from "@luxfhe/sdk/node";

task("task:verify-seal", "Verify a data integrity seal")
  .addParam("contract", "DataSeal contract address")
  .addParam("id", "Seal ID to verify")
  .addParam("tag", "Integrity tag (the secret used at seal creation)")
  .setAction(async ({ contract, id, tag }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const dataSeal = await hre.ethers.getContractAt("DataSeal", contract);

    const seal = await dataSeal.getSeal(parseInt(id));
    console.log("Seal:", {
      contentHash: seal.contentHash,
      creator: seal.creator,
      timestamp: seal.timestamp.toString(),
      mode: ["Public", "ZK", "Private"][Number(seal.mode)],
      revoked: seal.revoked,
    });

    const [encChallenge] = await fhe.encrypt([Encryptable.uint32(BigInt(tag))]);
    const tx = await dataSeal.connect(signer).verifySeal(parseInt(id), encChallenge);
    await tx.wait();

    // Poll for decryption result
    let attempts = 0;
    while (attempts < 10) {
      const result = await dataSeal.getVerificationResult(parseInt(id));
      if (result.ready) {
        console.log(result.matched ? "PASS: Seal verified." : "FAIL: Seal mismatch.");
        return;
      }
      await new Promise((r) => setTimeout(r, 2000));
      attempts++;
    }
    console.log("Decryption pending. Check later.");
  });
