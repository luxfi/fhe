import { task } from "hardhat/config";
import { fhe, Encryptable } from "@luxfhe/sdk/node";

task("task:register-content", "Register content for provenance tracking")
  .addParam("contract", "ContentProvenance contract address")
  .addParam("hash", "Content hash (hex)")
  .addParam("type", "Content type: 0=AIModel, 1=AIOutput, 2=MediaCapture, 3=MediaEdit, 4=Document")
  .addOptionalParam("parent", "Parent content ID for derivations", "0")
  .addOptionalParam("model", "Model ID (for AI outputs)", "0")
  .setAction(async ({ contract, hash, type, parent, model }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const provenance = await hre.ethers.getContractAt("ContentProvenance", contract);

    const [encModelId] = await fhe.encrypt([Encryptable.uint32(BigInt(model))]);
    const tx = await provenance.connect(signer).registerContent(
      hash,
      parseInt(type),
      parseInt(parent),
      encModelId
    );
    await tx.wait();

    const count = await provenance.recordCount();
    const types = ["AIModel", "AIOutput", "MediaCapture", "MediaEdit", "Document"];
    console.log(`Registered ${types[parseInt(type)]} content. ID: ${(count - 1n).toString()}`);
  });
