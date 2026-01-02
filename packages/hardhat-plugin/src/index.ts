import { extendConfig, extendEnvironment, task } from "hardhat/config";
import { HardhatConfig, HardhatUserConfig, HardhatRuntimeEnvironment } from "hardhat/types";
import axios from "axios";
import chalk from "chalk";

// Extend Hardhat config with LuxFHE plugin options
declare module "hardhat/types/config" {
  interface HardhatUserConfig {
    luxfhePlugin?: {
      fheServerUrl?: string;
      autoFaucet?: boolean;
      faucetUrl?: string;
    };
  }

  interface HardhatConfig {
    luxfhePlugin: {
      fheServerUrl: string;
      autoFaucet: boolean;
      faucetUrl: string;
    };
  }
}

declare module "hardhat/types/runtime" {
  interface HardhatRuntimeEnvironment {
    luxfhePlugin: {
      encrypt: (value: number | bigint, type?: string) => Promise<Uint8Array>;
      decrypt: (ciphertext: Uint8Array) => Promise<bigint>;
      getPublicKey: () => Promise<Uint8Array>;
      requestFaucet: (address: string) => Promise<boolean>;
    };
  }
}

const DEFAULT_CONFIG = {
  fheServerUrl: "http://localhost:8448",
  autoFaucet: true,
  faucetUrl: "http://localhost:42069/faucet",
};

extendConfig(
  (config: HardhatConfig, userConfig: Readonly<HardhatUserConfig>) => {
    const userPlugin = userConfig.luxfhePlugin ?? {};
    config.luxfhePlugin = {
      fheServerUrl: userPlugin.fheServerUrl ?? DEFAULT_CONFIG.fheServerUrl,
      autoFaucet: userPlugin.autoFaucet ?? DEFAULT_CONFIG.autoFaucet,
      faucetUrl: userPlugin.faucetUrl ?? DEFAULT_CONFIG.faucetUrl,
    };
  }
);

extendEnvironment((hre: HardhatRuntimeEnvironment) => {
  const config = hre.config.luxfhePlugin;

  hre.luxfhePlugin = {
    async encrypt(value: number | bigint, type: string = "uint32"): Promise<Uint8Array> {
      try {
        const response = await axios.post(`${config.fheServerUrl}/encrypt`, {
          value: value.toString(),
          type,
        });
        return new Uint8Array(response.data.ciphertext);
      } catch (error: any) {
        throw new Error(`FHE encryption failed: ${error.message}`);
      }
    },

    async decrypt(ciphertext: Uint8Array): Promise<bigint> {
      try {
        const response = await axios.post(`${config.fheServerUrl}/decrypt`, {
          ciphertext: Array.from(ciphertext),
        });
        return BigInt(response.data.value);
      } catch (error: any) {
        throw new Error(`FHE decryption failed: ${error.message}`);
      }
    },

    async getPublicKey(): Promise<Uint8Array> {
      try {
        const response = await axios.get(`${config.fheServerUrl}/publickey`);
        return new Uint8Array(response.data.publicKey);
      } catch (error: any) {
        throw new Error(`Failed to get FHE public key: ${error.message}`);
      }
    },

    async requestFaucet(address: string): Promise<boolean> {
      try {
        await axios.post(config.faucetUrl, { address });
        console.log(chalk.green(`Faucet tokens sent to ${address}`));
        return true;
      } catch (error: any) {
        console.error(chalk.red(`Faucet request failed: ${error.message}`));
        return false;
      }
    },
  };
});

// Task to use faucet
task("task:luxfhe:usefaucet", "Request tokens from the LuxFHE faucet")
  .addParam("address", "The address to send tokens to", undefined, undefined, true)
  .setAction(async (taskArgs, hre) => {
    let address = taskArgs.address;

    if (!address) {
      // Try to get address from ethers if available
      try {
        const signers = await (hre as any).ethers?.getSigners();
        address = signers?.[0]?.address;
      } catch {
        // ethers not available
      }
    }

    if (!address) {
      console.error(chalk.red("No address provided. Use --address <address>"));
      return;
    }

    await hre.luxfhePlugin.requestFaucet(address);
  });

// Task to check FHE server status
task("task:luxfhe:status", "Check FHE server status")
  .setAction(async (_, hre) => {
    const config = hre.config.luxfhePlugin;
    try {
      const response = await axios.get(`${config.fheServerUrl}/health`);
      console.log(chalk.green("FHE Server Status: Online"));
      console.log(chalk.gray(`  URL: ${config.fheServerUrl}`));
      console.log(chalk.gray(`  Response: ${JSON.stringify(response.data)}`));
    } catch (error: any) {
      console.log(chalk.red("FHE Server Status: Offline"));
      console.log(chalk.gray(`  URL: ${config.fheServerUrl}`));
      console.log(chalk.gray(`  Error: ${error.message}`));
    }
  });

export { DEFAULT_CONFIG };
