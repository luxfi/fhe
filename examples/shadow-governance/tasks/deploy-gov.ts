import { task } from "hardhat/config";

task("task:deploy-gov", "Deploy the ShadowGovernance contract").setAction(
  async (_, hre) => {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying ShadowGovernance with:", deployer.address);

    const Factory = await hre.ethers.getContractFactory("ShadowGovernance");
    const gov = await Factory.deploy();
    await gov.waitForDeployment();

    const address = await gov.getAddress();
    console.log("ShadowGovernance deployed to:", address);
    return address;
  }
);
