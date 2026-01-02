import { extendConfig, task } from "hardhat/config";
import { HardhatConfig, HardhatUserConfig } from "hardhat/types";
import { spawn, ChildProcess, execSync } from "child_process";
import chalk from "chalk";

// Extend Hardhat config with LuxFHE options
declare module "hardhat/types/config" {
  interface HardhatUserConfig {
    luxfhe?: {
      dockerImage?: string;
      containerName?: string;
      rpcPort?: number;
      wsPort?: number;
      fheServerPort?: number;
    };
  }

  interface HardhatConfig {
    luxfhe: {
      dockerImage: string;
      containerName: string;
      rpcPort: number;
      wsPort: number;
      fheServerPort: number;
    };
  }
}

// Default configuration
const DEFAULT_CONFIG = {
  dockerImage: "luxfi/fhe:latest",
  containerName: "luxfhe-local",
  rpcPort: 42069,
  wsPort: 42070,
  fheServerPort: 8448,
};

// Extend config with defaults
extendConfig(
  (config: HardhatConfig, userConfig: Readonly<HardhatUserConfig>) => {
    const userLuxFhe = userConfig.luxfhe ?? {};
    config.luxfhe = {
      dockerImage: userLuxFhe.dockerImage ?? DEFAULT_CONFIG.dockerImage,
      containerName: userLuxFhe.containerName ?? DEFAULT_CONFIG.containerName,
      rpcPort: userLuxFhe.rpcPort ?? DEFAULT_CONFIG.rpcPort,
      wsPort: userLuxFhe.wsPort ?? DEFAULT_CONFIG.wsPort,
      fheServerPort: userLuxFhe.fheServerPort ?? DEFAULT_CONFIG.fheServerPort,
    };
  }
);

let dockerProcess: ChildProcess | null = null;

function isDockerRunning(): boolean {
  try {
    execSync("docker info", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function isContainerRunning(containerName: string): boolean {
  try {
    const result = execSync(
      `docker ps --filter "name=${containerName}" --format "{{.Names}}"`,
      { encoding: "utf-8" }
    );
    return result.trim() === containerName;
  } catch {
    return false;
  }
}

function stopContainer(containerName: string): void {
  try {
    execSync(`docker stop ${containerName}`, { stdio: "ignore" });
    execSync(`docker rm ${containerName}`, { stdio: "ignore" });
  } catch {
    // Container might not exist
  }
}

// Task to start LuxFHE local node
task("luxfhe:start", "Start a local LuxFHE node using Docker")
  .addFlag("detach", "Run in detached mode")
  .addFlag("fresh", "Remove existing container and start fresh")
  .setAction(async (taskArgs, hre) => {
    const config = hre.config.luxfhe;

    if (!isDockerRunning()) {
      console.error(chalk.red("Docker is not running. Please start Docker first."));
      process.exit(1);
    }

    if (taskArgs.fresh) {
      console.log(chalk.yellow(`Stopping existing container ${config.containerName}...`));
      stopContainer(config.containerName);
    }

    if (isContainerRunning(config.containerName)) {
      console.log(chalk.green(`Container ${config.containerName} is already running.`));
      return;
    }

    console.log(chalk.blue(`Starting LuxFHE local node...`));
    console.log(chalk.gray(`  Image: ${config.dockerImage}`));
    console.log(chalk.gray(`  RPC Port: ${config.rpcPort}`));
    console.log(chalk.gray(`  FHE Server Port: ${config.fheServerPort}`));

    const args = [
      "run",
      "--name", config.containerName,
      "-p", `${config.rpcPort}:8545`,
      "-p", `${config.wsPort}:8546`,
      "-p", `${config.fheServerPort}:8448`,
    ];

    if (taskArgs.detach) {
      args.push("-d");
    }

    args.push(config.dockerImage);

    dockerProcess = spawn("docker", args, {
      stdio: taskArgs.detach ? "ignore" : "inherit",
    });

    if (taskArgs.detach) {
      console.log(chalk.green(`LuxFHE node started in detached mode.`));
      console.log(chalk.gray(`  RPC URL: http://localhost:${config.rpcPort}`));
      console.log(chalk.gray(`  FHE Server: http://localhost:${config.fheServerPort}`));
    } else {
      dockerProcess.on("close", (code) => {
        console.log(chalk.yellow(`LuxFHE node exited with code ${code}`));
      });
    }
  });

// Task to stop LuxFHE local node
task("luxfhe:stop", "Stop the local LuxFHE node")
  .setAction(async (_, hre) => {
    const config = hre.config.luxfhe;

    if (!isContainerRunning(config.containerName)) {
      console.log(chalk.yellow(`Container ${config.containerName} is not running.`));
      return;
    }

    console.log(chalk.blue(`Stopping LuxFHE node...`));
    stopContainer(config.containerName);
    console.log(chalk.green(`LuxFHE node stopped.`));
  });

// Task to check status
task("luxfhe:status", "Check the status of the local LuxFHE node")
  .setAction(async (_, hre) => {
    const config = hre.config.luxfhe;

    if (!isDockerRunning()) {
      console.log(chalk.red("Docker is not running."));
      return;
    }

    if (isContainerRunning(config.containerName)) {
      console.log(chalk.green(`LuxFHE node is running.`));
      console.log(chalk.gray(`  Container: ${config.containerName}`));
      console.log(chalk.gray(`  RPC URL: http://localhost:${config.rpcPort}`));
      console.log(chalk.gray(`  FHE Server: http://localhost:${config.fheServerPort}`));
    } else {
      console.log(chalk.yellow(`LuxFHE node is not running.`));
    }
  });

export { DEFAULT_CONFIG };
