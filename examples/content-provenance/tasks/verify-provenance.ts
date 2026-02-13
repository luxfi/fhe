import { task } from "hardhat/config";

task("task:verify-provenance", "View the provenance chain for content")
  .addParam("contract", "ContentProvenance contract address")
  .addParam("id", "Content ID to trace")
  .setAction(async ({ contract, id }, hre) => {
    const provenance = await hre.ethers.getContractAt("ContentProvenance", contract);
    const types = ["AIModel", "AIOutput", "MediaCapture", "MediaEdit", "Document"];

    const record = await provenance.getRecord(parseInt(id));
    console.log("Content Record:");
    console.log("  Hash:", record.contentHash);
    console.log("  Type:", types[Number(record.contentType)]);
    console.log("  Creator:", record.creator);
    console.log("  Timestamp:", new Date(Number(record.timestamp) * 1000).toISOString());
    console.log("  Parent ID:", record.parentId.toString());

    // Show derivations
    const derivations = await provenance.getDerivations(parseInt(id));
    if (derivations.length > 0) {
      console.log("\nDerivations:", derivations.map(String).join(", "));
    } else {
      console.log("\nNo derivations (leaf content).");
    }
  });
