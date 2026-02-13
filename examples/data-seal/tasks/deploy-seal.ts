import { task } from "hardhat/config";

task("task:deploy-seal", "Deploy the DataSeal contract").setAction(
  async (_, hre) => {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying DataSeal with:", deployer.address);

    const DataSeal = await hre.ethers.getContractFactory("DataSeal");
    const dataSeal = await DataSeal.deploy();
    await dataSeal.waitForDeployment();

    const address = await dataSeal.getAddress();
    console.log("DataSeal deployed to:", address);
    return address;
  }
);
