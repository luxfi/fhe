import { task } from "hardhat/config";
import { fhe, Encryptable } from "@luxfhe/sdk/node";

task("task:vote", "Cast an anonymous encrypted vote")
  .addParam("contract", "ShadowGovernance contract address")
  .addParam("proposal", "Proposal ID")
  .addParam("choice", "Vote: yes or no")
  .addParam("secret", "Your secret for nullifier generation")
  .setAction(async ({ contract, proposal, choice, secret }, hre) => {
    const [signer] = await hre.ethers.getSigners();
    const gov = await hre.ethers.getContractAt("ShadowGovernance", contract);

    const voteValue = choice.toLowerCase() === "yes" ? 1n : 0n;
    const nullifier = hre.ethers.keccak256(
      hre.ethers.solidityPacked(["string", "uint256"], [secret, parseInt(proposal)])
    );

    const [encVote] = await fhe.encrypt([Encryptable.uint32(voteValue)]);
    const tx = await gov.connect(signer).castVote(parseInt(proposal), encVote, nullifier);
    await tx.wait();

    console.log(`Vote cast: ${choice.toUpperCase()} on proposal ${proposal}`);
    console.log("Nullifier:", nullifier);
    console.log("(Your vote is encrypted — no one can see how you voted)");
  });
