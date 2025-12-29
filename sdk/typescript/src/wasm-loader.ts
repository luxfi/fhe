/**
 * WASM Loader - handles loading Go WASM in Node.js and browser environments
 */

import type { LuxFHEWasm, InitOptions } from './types';

// Detect environment
const isNode = typeof process !== 'undefined' && process.versions?.node;
const isBrowser = typeof window !== 'undefined';

// Global for Go runtime
declare global {
  var Go: any;
  var luxfhe: LuxFHEWasm | undefined;
}

let wasmInitialized = false;
let initPromise: Promise<LuxFHEWasm> | null = null;

/**
 * Load the Go WASM runtime (wasm_exec.js)
 */
async function loadGoRuntime(execPath?: string): Promise<void> {
  if (typeof Go !== 'undefined') {
    return; // Already loaded
  }

  if (isNode) {
    // Node.js: use require or dynamic import
    if (execPath) {
      await import(execPath);
    } else {
      // Default path relative to package
      const path = await import('path');
      const defaultPath = path.join(__dirname, '..', 'wasm', 'wasm_exec.js');
      await import(defaultPath);
    }
  } else if (isBrowser) {
    // Browser: load via script tag
    const scriptPath = execPath || './wasm/wasm_exec.js';
    await new Promise<void>((resolve, reject) => {
      const script = document.createElement('script');
      script.src = scriptPath;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`Failed to load ${scriptPath}`));
      document.head.appendChild(script);
    });
  }
}

/**
 * Load and instantiate the WASM module
 */
async function loadWasm(wasmPath?: string): Promise<void> {
  const go = new Go();
  
  let wasmBytes: BufferSource;

  if (isNode) {
    // Node.js: read file
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const defaultPath = path.join(__dirname, '..', 'wasm', 'luxfhe.wasm');
    const wasmFile = wasmPath || defaultPath;
    wasmBytes = await fs.readFile(wasmFile);
  } else if (isBrowser) {
    // Browser: fetch
    const wasmUrl = wasmPath || './wasm/luxfhe.wasm';
    const response = await fetch(wasmUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${wasmUrl}: ${response.statusText}`);
    }
    wasmBytes = await response.arrayBuffer();
  } else {
    throw new Error('Unsupported environment');
  }

  // Instantiate and run
  const result = await WebAssembly.instantiate(wasmBytes, go.importObject);
  go.run(result.instance);
}

/**
 * Initialize the LuxFHE WASM module
 * 
 * @param options - Optional configuration
 * @returns The initialized LuxFHE interface
 * 
 * @example
 * ```typescript
 * const fhe = await loadLuxFHE();
 * const keys = fhe.generateKeys();
 * ```
 */
export async function loadLuxFHE(options: InitOptions = {}): Promise<LuxFHEWasm> {
  // Return existing promise if initialization in progress
  if (initPromise) {
    return initPromise;
  }

  // Return cached if already initialized
  if (wasmInitialized && globalThis.luxfhe) {
    return globalThis.luxfhe;
  }

  initPromise = (async () => {
    try {
      // Load Go runtime
      await loadGoRuntime(options.execPath);
      
      // Load WASM
      await loadWasm(options.wasmPath);
      
      // Wait for luxfhe to be available
      let attempts = 0;
      while (!globalThis.luxfhe && attempts < 100) {
        await new Promise(resolve => setTimeout(resolve, 10));
        attempts++;
      }

      if (!globalThis.luxfhe) {
        throw new Error('LuxFHE WASM failed to initialize');
      }

      wasmInitialized = true;
      return globalThis.luxfhe;
    } catch (error) {
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

/**
 * Check if WASM is initialized
 */
export function isInitialized(): boolean {
  return wasmInitialized && !!globalThis.luxfhe;
}

/**
 * Get the raw WASM interface (throws if not initialized)
 */
export function getWasm(): LuxFHEWasm {
  if (!wasmInitialized || !globalThis.luxfhe) {
    throw new Error('LuxFHE not initialized. Call loadLuxFHE() first.');
  }
  return globalThis.luxfhe;
}
