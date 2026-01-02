import { extendConfig, extendEnvironment } from "hardhat/config";
import { HardhatConfig, HardhatUserConfig, HardhatRuntimeEnvironment, HttpNetworkConfig } from "hardhat/types";
import chalk from "chalk";

// Extend Hardhat config with LuxFHE network options
declare module "hardhat/types/config" {
  interface HardhatUserConfig {
    luxfheNetwork?: {
      enabled?: boolean;
      mockFhe?: boolean;
      fheServerUrl?: string;
      rpcUrl?: string;
      chainId?: number;
    };
  }

  interface HardhatConfig {
    luxfheNetwork: {
      enabled: boolean;
      mockFhe: boolean;
      fheServerUrl: string;
      rpcUrl: string;
      chainId: number;
    };
  }
}

declare module "hardhat/types/runtime" {
  interface HardhatRuntimeEnvironment {
    luxfhe: {
      isFheEnabled: boolean;
      fheServerUrl: string;
      mockMode: boolean;
      rpcUrl: string;
      chainId: number;
    };
  }
}

// Default configuration for lux dev
const DEFAULT_FHE_SERVER_URL = "http://localhost:8448";
const DEFAULT_RPC_URL = "http://localhost:8545/ext/bc/C/rpc";
const DEFAULT_CHAIN_ID = 1337;

// Default test mnemonic (same as Hardhat default)
const DEFAULT_MNEMONIC = "test test test test test test test test test test test junk";

extendConfig(
  (config: HardhatConfig, userConfig: Readonly<HardhatUserConfig>) => {
    const userNetwork = userConfig.luxfheNetwork ?? {};

    // Store LuxFHE network config
    config.luxfheNetwork = {
      enabled: userNetwork.enabled ?? true,
      mockFhe: userNetwork.mockFhe ?? false,
      fheServerUrl: userNetwork.fheServerUrl ?? DEFAULT_FHE_SERVER_URL,
      rpcUrl: userNetwork.rpcUrl ?? DEFAULT_RPC_URL,
      chainId: userNetwork.chainId ?? DEFAULT_CHAIN_ID,
    };

    // Add localluxfhe network if not already defined
    if (!config.networks.localluxfhe) {
      config.networks.localluxfhe = {
        url: config.luxfheNetwork.rpcUrl,
        chainId: config.luxfheNetwork.chainId,
        accounts: {
          mnemonic: DEFAULT_MNEMONIC,
          path: "m/44'/60'/0'/0",
          initialIndex: 0,
          count: 20,
        },
        gas: "auto",
        gasPrice: "auto",
        gasMultiplier: 1,
        timeout: 40000,
        httpHeaders: {},
      } as HttpNetworkConfig;
    }
  }
);

extendEnvironment((hre: HardhatRuntimeEnvironment) => {
  const config = hre.config.luxfheNetwork;

  hre.luxfhe = {
    isFheEnabled: config.enabled,
    fheServerUrl: config.fheServerUrl,
    mockMode: config.mockFhe,
    rpcUrl: config.rpcUrl,
    chainId: config.chainId,
  };

  if (config.enabled && hre.network.name === "localluxfhe") {
    console.log(chalk.blue("LuxFHE Local Development Network"));
    console.log(chalk.gray(`  RPC URL: ${config.rpcUrl}`));
    console.log(chalk.gray(`  Chain ID: ${config.chainId}`));
    if (config.mockFhe) {
      console.log(chalk.yellow("  FHE Mode: Mock (for testing)"));
    } else {
      console.log(chalk.gray(`  FHE Server: ${config.fheServerUrl}`));
    }
  }
});

export { DEFAULT_FHE_SERVER_URL, DEFAULT_RPC_URL, DEFAULT_CHAIN_ID };
