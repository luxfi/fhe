import { task } from "hardhat/config";
import { fhe, Encryptable } from "@luxfhe/sdk/node";

task("task:attest-output", "Attest that AI output came from a specific model")
  .addParam("contract", "ContentProvenance contract address")
  .addParam("output", "Output content ID")
  .addParam("model", "Claimed model ID")
  .setAction(async ({ contract, output, model }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const provenance = await hre.ethers.getContractAt("ContentProvenance", contract);

    const [encClaim] = await fhe.encrypt([Encryptable.uint32(BigInt(model))]);
    const tx = await provenance.connect(signer).attestOutput(parseInt(output), encClaim);
    await tx.wait();

    console.log(`Attestation submitted for output ${output} against model ${model}`);

    // Wait for result
    let attempts = 0;
    while (attempts < 10) {
      const result = await provenance.getAttestationResult(parseInt(output));
      if (result.ready) {
        console.log(result.attested
          ? "ATTESTED: Output confirmed from claimed model."
          : "REJECTED: Output does NOT match claimed model.");
        return;
      }
      await new Promise((r) => setTimeout(r, 2000));
      attempts++;
    }
    console.log("Decryption pending.");
  });
