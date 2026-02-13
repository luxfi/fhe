import { task } from "hardhat/config";

task("task:deploy", "Deploy the ContentProvenance contract").setAction(
  async (_, hre) => {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying ContentProvenance with:", deployer.address);

    const Factory = await hre.ethers.getContractFactory("ContentProvenance");
    const contract = await Factory.deploy();
    await contract.waitForDeployment();

    const address = await contract.getAddress();
    console.log("ContentProvenance deployed to:", address);
    return address;
  }
);
