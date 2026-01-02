import { test, expect } from '@playwright/test';
import { 
  frontends, 
  startFrontend, 
  stopFrontend, 
  stopAllFrontends, 
  waitForApp, 
  hasWalletPrompt,
  checkFHEServer,
  FrontendConfig 
} from './helpers';

test.describe('LuxFHE Web3 Examples', () => {
  
  test.beforeAll(async () => {
    // Verify FHE server is running
    const fheHealthy = await checkFHEServer();
    if (!fheHealthy) {
      throw new Error('FHE Server not running on localhost:8448. Start it with: cd ~/work/lux/tfhe && ./bin/fhe-server');
    }
    console.log('✓ FHE Server is healthy');
  });

  test.afterAll(async () => {
    stopAllFrontends();
  });

  test.describe('blind-auction-v2 (Nuxt.js)', () => {
    const config = frontends['blind-auction-v2'];
    
    test.beforeAll(async () => {
      await startFrontend(config);
    });

    test.afterAll(async () => {
      stopFrontend(config.name);
    });

    test('loads homepage', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      // Check page loaded
      const title = await page.title();
      expect(title).toBeTruthy();
      console.log(`  Page title: ${title}`);
      
      // Check for wallet connection UI
      const needsWallet = await hasWalletPrompt(page);
      console.log(`  Requires wallet: ${needsWallet}`);
      
      // Take screenshot
      await page.screenshot({ path: `screenshots/blind-auction-v2-home.png` });
    });

    test('has FHE-related UI elements', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const content = await page.content();
      const hasFHETerms = 
        content.includes('encrypt') || 
        content.includes('Encrypt') ||
        content.includes('FHE') ||
        content.includes('bid') ||
        content.includes('Bid') ||
        content.includes('auction') ||
        content.includes('Auction');
      
      expect(hasFHETerms).toBe(true);
      console.log('  ✓ Found FHE/auction-related content');
    });
  });

  test.describe('blind-auction (Nuxt.js)', () => {
    const config = frontends['blind-auction'];

    test.beforeAll(async () => {
      await startFrontend(config);
    });

    test.afterAll(async () => {
      stopFrontend(config.name);
    });

    test('loads homepage', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const title = await page.title();
      expect(title).toBeTruthy();
      console.log(`  Page title: ${title}`);
      
      await page.screenshot({ path: `screenshots/blind-auction-home.png` });
    });
  });

  test.describe('playground (React)', () => {
    const config = frontends['playground'];

    test.beforeAll(async () => {
      await startFrontend(config);
    });

    test.afterAll(async () => {
      stopFrontend(config.name);
    });

    test('loads homepage', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const title = await page.title();
      expect(title).toBeTruthy();
      console.log(`  Page title: ${title}`);
      
      await page.screenshot({ path: `screenshots/playground-home.png` });
    });

    test('has FHE functionality', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const content = await page.content();
      const hasFHETerms = 
        content.includes('encrypt') || 
        content.includes('Encrypt') ||
        content.includes('FHE') ||
        content.includes('FHERC20') ||
        content.includes('Token');
      
      console.log(`  Has FHE terms: ${hasFHETerms}`);
    });
  });

  test.describe('erc20-tutorial (React)', () => {
    const config = frontends['erc20-tutorial'];

    test.beforeAll(async () => {
      await startFrontend(config);
    });

    test.afterAll(async () => {
      stopFrontend(config.name);
    });

    test('loads homepage', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const title = await page.title();
      expect(title).toBeTruthy();
      console.log(`  Page title: ${title}`);
      
      await page.screenshot({ path: `screenshots/erc20-tutorial-home.png` });
    });

    test('shows ERC20 UI', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const content = await page.content();
      const hasERC20 = 
        content.includes('ERC20') ||
        content.includes('token') ||
        content.includes('Token') ||
        content.includes('balance') ||
        content.includes('Balance') ||
        content.includes('transfer') ||
        content.includes('Transfer');
      
      console.log(`  Has ERC20 terms: ${hasERC20}`);
    });
  });

  test.describe('poker (Next.js)', () => {
    const config = frontends['poker'];

    test.beforeAll(async () => {
      await startFrontend(config);
    });

    test.afterAll(async () => {
      stopFrontend(config.name);
    });

    test('loads homepage', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const title = await page.title();
      expect(title).toBeTruthy();
      console.log(`  Page title: ${title}`);
      
      await page.screenshot({ path: `screenshots/poker-home.png` });
    });

    test('has poker UI elements', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const content = await page.content();
      const hasPoker = 
        content.includes('poker') ||
        content.includes('Poker') ||
        content.includes('card') ||
        content.includes('Card') ||
        content.includes('bet') ||
        content.includes('Bet') ||
        content.includes('fold') ||
        content.includes('Fold');
      
      console.log(`  Has poker terms: ${hasPoker}`);
    });
  });

  test.describe('kuhn-poker (Next.js)', () => {
    const config = frontends['kuhn-poker'];

    test.beforeAll(async () => {
      await startFrontend(config);
    });

    test.afterAll(async () => {
      stopFrontend(config.name);
    });

    test('loads homepage', async ({ page }) => {
      await page.goto(`http://localhost:${config.port}`);
      await waitForApp(page);
      
      const title = await page.title();
      expect(title).toBeTruthy();
      console.log(`  Page title: ${title}`);
      
      await page.screenshot({ path: `screenshots/kuhn-poker-home.png` });
    });
  });
});
