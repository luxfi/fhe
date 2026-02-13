import { task } from "hardhat/config";
import { fhe, Encryptable } from "@luxfhe/sdk/node";

task("task:seal", "Create a data integrity seal")
  .addParam("contract", "DataSeal contract address")
  .addParam("hash", "Content hash (hex string)")
  .addOptionalParam("mode", "Seal mode: 0=Public, 1=ZK, 2=Private", "0")
  .setAction(async ({ contract, hash, mode }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const dataSeal = await hre.ethers.getContractAt("DataSeal", contract);

    // Generate a random integrity tag
    const tag = BigInt(Math.floor(Math.random() * 1000000));
    console.log("Integrity tag (save this for verification):", tag.toString());

    const [encTag] = await fhe.encrypt([Encryptable.uint32(tag)]);
    const tx = await dataSeal.connect(signer).createSeal(hash, encTag, parseInt(mode));
    const receipt = await tx.wait();

    const sealCount = await dataSeal.sealCount();
    console.log("Seal created. ID:", (sealCount - 1n).toString());
    console.log("Mode:", ["Public", "ZK", "Private"][parseInt(mode)]);
  });
