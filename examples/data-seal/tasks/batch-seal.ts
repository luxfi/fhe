import { task } from "hardhat/config";
import { fhe, Encryptable } from "@luxfhe/sdk/node";

task("task:batch-seal", "Create a batch of data integrity seals")
  .addParam("contract", "DataSeal contract address")
  .addParam("count", "Number of seals to create")
  .addOptionalParam("mode", "Seal mode: 0=Public, 1=ZK, 2=Private", "0")
  .setAction(async ({ contract, count, mode }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const dataSeal = await hre.ethers.getContractAt("DataSeal", contract);

    const n = parseInt(count);
    const hashes: string[] = [];
    const tags: bigint[] = [];
    const encTags: any[] = [];

    for (let i = 0; i < n; i++) {
      const content = `batch-document-${i}-${Date.now()}`;
      hashes.push(hre.ethers.keccak256(hre.ethers.toUtf8Bytes(content)));
      const tag = BigInt(Math.floor(Math.random() * 1000000));
      tags.push(tag);
      const [enc] = await fhe.encrypt([Encryptable.uint32(tag)]);
      encTags.push(enc);
    }

    console.log(`Creating batch of ${n} seals...`);
    const tx = await dataSeal.connect(signer).batchSeal(hashes, encTags, parseInt(mode));
    const receipt = await tx.wait();

    console.log(`Batch sealed: ${n} documents`);
    console.log("Tags (save for verification):", tags.map(String));
  });
