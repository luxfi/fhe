import { task } from "hardhat/config";

task("task:tally", "Start tally and finalize a proposal")
  .addParam("contract", "ShadowGovernance contract address")
  .addParam("proposal", "Proposal ID")
  .setAction(async ({ contract, proposal }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const gov = await hre.ethers.getContractAt("ShadowGovernance", contract);

    const p = await gov.getProposal(parseInt(proposal));
    const statusNames = ["Active", "Tallying", "Passed", "Rejected", "Cancelled"];

    if (Number(p.status) === 0) {
      console.log("Starting tally...");
      const tx = await gov.startTally(parseInt(proposal));
      await tx.wait();
    }

    // Try to finalize
    try {
      const tx = await gov.finalize(parseInt(proposal));
      await tx.wait();

      const tally = await gov.getTally(parseInt(proposal));
      const result = await gov.getProposal(parseInt(proposal));

      console.log(`\nResult: ${statusNames[Number(result.status)]}`);
      console.log(`  Yes: ${tally.yesVotes.toString()}`);
      console.log(`  No:  ${tally.noVotes.toString()}`);
      console.log(`  Voters: ${result.voterCount.toString()}`);
    } catch (e: any) {
      console.log("Decryption still pending. Try again later.");
    }
  });
