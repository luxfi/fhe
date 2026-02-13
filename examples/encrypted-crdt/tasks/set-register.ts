import { task } from "hardhat/config";
import { fhe, Encryptable } from "@luxfhe/sdk/node";

task("task:set-register", "Set an encrypted LWW-Register value")
  .addParam("contract", "EncryptedCRDT contract address")
  .addParam("doc", "Document ID")
  .addParam("field", "Field name")
  .addParam("value", "Value to set (integer)")
  .addParam("timestamp", "Lamport timestamp")
  .setAction(async ({ contract, doc, field, value, timestamp }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const crdt = await hre.ethers.getContractAt("EncryptedCRDT", contract);

    const regId = hre.ethers.keccak256(
      hre.ethers.solidityPacked(["string", "string"], [doc, field])
    );
    const docId = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(doc));

    const [encVal] = await fhe.encrypt([Encryptable.uint32(BigInt(value))]);
    const tx = await crdt.connect(signer).setRegister(regId, encVal, parseInt(timestamp), docId);
    await tx.wait();

    console.log(`Register set: ${doc}.${field} = [encrypted] @ t=${timestamp}`);
  });
