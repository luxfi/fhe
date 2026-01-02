import { spawn, ChildProcess } from 'child_process';
import { Page } from '@playwright/test';

export interface FrontendConfig {
  name: string;
  path: string;
  command: string;
  port: number;
  waitForText?: string;
  env?: Record<string, string>;
}

export const frontends: Record<string, FrontendConfig> = {
  'blind-auction-v2': {
    name: 'Blind Auction V2',
    path: '/Users/z/work/luxfhe/examples/blind-auction-v2/frontend',
    command: 'pnpm dev',
    port: 3000,
    waitForText: 'Nuxt',
  },
  'blind-auction': {
    name: 'Blind Auction',
    path: '/Users/z/work/luxfhe/examples/blind-auction/frontend',
    command: 'pnpm dev',
    port: 3001,
    waitForText: 'Nuxt',
  },
  'playground': {
    name: 'Playground',
    path: '/Users/z/work/luxfhe/examples/playground/frontend',
    command: 'npm start',
    port: 3002,
    waitForText: 'react',
    env: { PORT: '3002' },
  },
  'erc20-tutorial': {
    name: 'ERC20 Tutorial',
    path: '/Users/z/work/luxfhe/examples/erc20-tutorial/frontend',
    command: 'npm start',
    port: 3003,
    waitForText: 'react',
    env: { PORT: '3003' },
  },
  'poker': {
    name: 'Poker',
    path: '/Users/z/work/luxfhe/examples/poker/packages/frontend',
    command: 'pnpm dev',
    port: 3004,
    waitForText: 'Next',
    env: { PORT: '3004' },
  },
  'kuhn-poker': {
    name: 'Kuhn Poker',
    path: '/Users/z/work/luxfhe/examples/kuhn-poker/packages/frontend',
    command: 'pnpm dev',
    port: 3005,
    waitForText: 'Next',
    env: { PORT: '3005' },
  },
};

let runningProcesses: Map<string, ChildProcess> = new Map();

export async function startFrontend(config: FrontendConfig): Promise<void> {
  return new Promise((resolve, reject) => {
    const [cmd, ...args] = config.command.split(' ');
    const env = { ...process.env, ...config.env };
    
    console.log(`Starting ${config.name} on port ${config.port}...`);
    
    const proc = spawn(cmd, args, {
      cwd: config.path,
      env,
      stdio: 'pipe',
      shell: true,
    });

    runningProcesses.set(config.name, proc);

    let started = false;
    const timeout = setTimeout(() => {
      if (!started) {
        console.log(`${config.name} started (timeout reached)`);
        started = true;
        resolve();
      }
    }, 30000);

    proc.stdout?.on('data', (data) => {
      const output = data.toString();
      if (!started && (output.includes('localhost') || output.includes('ready') || output.includes('started'))) {
        console.log(`${config.name} ready on port ${config.port}`);
        started = true;
        clearTimeout(timeout);
        setTimeout(resolve, 2000); // Wait 2s for server to stabilize
      }
    });

    proc.stderr?.on('data', (data) => {
      const output = data.toString();
      // Many frameworks output to stderr for status
      if (!started && (output.includes('localhost') || output.includes('ready'))) {
        console.log(`${config.name} ready on port ${config.port}`);
        started = true;
        clearTimeout(timeout);
        setTimeout(resolve, 2000);
      }
    });

    proc.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    proc.on('exit', (code) => {
      if (!started && code !== 0) {
        clearTimeout(timeout);
        reject(new Error(`${config.name} exited with code ${code}`));
      }
    });
  });
}

export function stopFrontend(name: string): void {
  const proc = runningProcesses.get(name);
  if (proc) {
    console.log(`Stopping ${name}...`);
    proc.kill('SIGTERM');
    runningProcesses.delete(name);
  }
}

export function stopAllFrontends(): void {
  for (const [name, proc] of runningProcesses) {
    console.log(`Stopping ${name}...`);
    proc.kill('SIGTERM');
  }
  runningProcesses.clear();
}

// Wait for page to be interactive
export async function waitForApp(page: Page, timeout = 30000): Promise<void> {
  await page.waitForLoadState('domcontentloaded', { timeout });
  await page.waitForLoadState('networkidle', { timeout }).catch(() => {
    // Network idle may not happen with web3 apps
  });
}

// Check if MetaMask or wallet connection is required
export async function hasWalletPrompt(page: Page): Promise<boolean> {
  const walletPrompts = [
    'Connect Wallet',
    'Connect wallet',
    'connect wallet',
    'MetaMask',
    'metamask',
    'WalletConnect',
    'Connect to',
  ];
  
  const content = await page.content();
  return walletPrompts.some(prompt => content.includes(prompt));
}

// Check FHE server health
export async function checkFHEServer(): Promise<boolean> {
  try {
    const response = await fetch('http://localhost:8448/health');
    const data = await response.json();
    return data.status === 'ok';
  } catch {
    return false;
  }
}
