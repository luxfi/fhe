import { task } from "hardhat/config";

task("task:deploy-crdt", "Deploy the EncryptedCRDT contract").setAction(
  async (_, hre) => {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying EncryptedCRDT with:", deployer.address);

    const Factory = await hre.ethers.getContractFactory("EncryptedCRDT");
    const crdt = await Factory.deploy();
    await crdt.waitForDeployment();

    const address = await crdt.getAddress();
    console.log("EncryptedCRDT deployed to:", address);
    return address;
  }
);
