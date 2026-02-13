import { task } from "hardhat/config";

task("task:list-ministries", "List all shadow ministries")
  .addParam("contract", "ShadowGovernance contract address")
  .setAction(async ({ contract }, hre) => {
    const gov = await hre.ethers.getContractAt("ShadowGovernance", contract);

    const count = await gov.getMinistryCount();
    console.log(`Shadow Ministries: ${count.toString()}`);

    for (let i = 0; i < Number(count); i++) {
      const id = await gov.ministryIds(i);
      const ministry = await gov.ministries(id);
      console.log(`  [${i}] ${id}`);
      console.log(`      Name hash: ${ministry.name}`);
      console.log(`      Active: ${ministry.active}`);
      console.log(`      Members: ${ministry.memberCount.toString()}`);
    }
  });
