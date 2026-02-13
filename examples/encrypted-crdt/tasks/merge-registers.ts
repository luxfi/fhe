import { task } from "hardhat/config";

task("task:merge-registers", "Merge two registers (LWW conflict resolution)")
  .addParam("contract", "EncryptedCRDT contract address")
  .addParam("doc", "Document ID")
  .addParam("field1", "First field name")
  .addParam("field2", "Second field name")
  .addParam("result", "Result field name")
  .setAction(async ({ contract, doc, field1, field2, result }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const crdt = await hre.ethers.getContractAt("EncryptedCRDT", contract);

    const regId1 = hre.ethers.keccak256(
      hre.ethers.solidityPacked(["string", "string"], [doc, field1])
    );
    const regId2 = hre.ethers.keccak256(
      hre.ethers.solidityPacked(["string", "string"], [doc, field2])
    );
    const resultId = hre.ethers.keccak256(
      hre.ethers.solidityPacked(["string", "string"], [doc, result])
    );

    const tx = await crdt.connect(signer).mergeRegisters(regId1, regId2, resultId);
    await tx.wait();

    const info = await crdt.getRegisterInfo(resultId);
    console.log("Merged register:", {
      timestamp: info.timestamp.toString(),
      lastWriter: info.lastWriter,
    });
  });
