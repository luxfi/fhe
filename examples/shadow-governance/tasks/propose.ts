import { task } from "hardhat/config";

task("task:propose", "Create a governance proposal")
  .addParam("contract", "ShadowGovernance contract address")
  .addParam("content", "Proposal content text")
  .addParam("ministry", "Ministry ID (hex)")
  .addOptionalParam("blocks", "Voting period in blocks", "100")
  .setAction(async ({ contract, content, ministry, blocks }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const gov = await hre.ethers.getContractAt("ShadowGovernance", contract);

    const contentHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(content));
    const tx = await gov.connect(signer).createProposal(contentHash, ministry, parseInt(blocks));
    await tx.wait();

    const count = await gov.proposalCount();
    console.log(`Proposal created. ID: ${(count - 1n).toString()}`);
    console.log(`Content hash: ${contentHash}`);
    console.log(`Voting period: ${blocks} blocks`);
  });
