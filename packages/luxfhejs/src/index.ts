/**
 * luxfhejs - JavaScript SDK for LuxFHE (Fully Homomorphic Encryption)
 *
 * This package provides the client-side API for interacting with
 * LuxFHE encrypted smart contracts and the FHE TFHE server.
 */

import { ethers } from 'ethers';

// FHE Server URL - defaults to local Go TFHE server
const DEFAULT_FHE_SERVER = 'http://localhost:8448';

export type SupportedProvider = ethers.BrowserProvider | ethers.JsonRpcProvider | any;

export interface LuxFHEClientConfig {
  provider?: SupportedProvider;
  serverUrl?: string;
}

export interface Permit {
  contractAddress: string;
  sealingKey: {
    privateKey: string;
    publicKey: string;
  };
  signature: string;
}

export interface Permission {
  contractAddress: string;
  signer: string;
  publicKey: string;
  signature: string;
}

// In-memory permit storage
const permitStore = new Map<string, Permit>();

/**
 * LuxFHE Client - Main SDK class for FHE operations
 */
export class LuxFHEClient {
  private provider: SupportedProvider;
  private serverUrl: string;
  private publicKey: Uint8Array | null = null;
  private sealingKey: { privateKey: string; publicKey: string } | null = null;

  constructor(config: LuxFHEClientConfig) {
    this.provider = config.provider;
    this.serverUrl = config.serverUrl || DEFAULT_FHE_SERVER;
  }

  /**
   * Initialize the FHE client by fetching public key from server
   */
  async initialize(): Promise<void> {
    await this.getPublicKey();
  }

  /**
   * Get FHE public key from server
   */
  async getPublicKey(): Promise<Uint8Array> {
    if (this.publicKey) return this.publicKey;

    const res = await fetch(`${this.serverUrl}/publickey`);
    if (!res.ok) throw new Error(`Failed to fetch public key: ${res.status}`);
    
    const buffer = await res.arrayBuffer();
    this.publicKey = new Uint8Array(buffer);
    return this.publicKey;
  }

  /**
   * Encrypt a uint8 value
   */
  async encrypt_uint8(value: number): Promise<Uint8Array> {
    return this.encrypt(value, 8);
  }

  /**
   * Encrypt a uint16 value
   */
  async encrypt_uint16(value: number): Promise<Uint8Array> {
    return this.encrypt(value, 16);
  }

  /**
   * Encrypt a uint32 value
   */
  async encrypt_uint32(value: number): Promise<Uint8Array> {
    return this.encrypt(value, 32);
  }

  /**
   * Encrypt a uint64 value
   */
  async encrypt_uint64(value: number | bigint): Promise<Uint8Array> {
    return this.encrypt(typeof value === 'bigint' ? Number(value) : value, 64);
  }

  /**
   * Encrypt a uint128 value
   */
  async encrypt_uint128(value: number | bigint): Promise<Uint8Array> {
    return this.encrypt(typeof value === 'bigint' ? Number(value) : value, 128);
  }

  /**
   * Encrypt a uint256 value  
   */
  async encrypt_uint256(value: number | bigint): Promise<Uint8Array> {
    return this.encrypt(typeof value === 'bigint' ? Number(value) : value, 256);
  }

  /**
   * Encrypt an address (uint160)
   */
  async encrypt_address(address: string): Promise<Uint8Array> {
    const value = BigInt(address);
    return this.encrypt(Number(value), 160);
  }

  /**
   * Generic encrypt method
   */
  private async encrypt(value: number, bitWidth: number): Promise<Uint8Array> {
    const res = await fetch(`${this.serverUrl}/encrypt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value, bitWidth }),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Encryption failed: ${text}`);
    }

    const buffer = await res.arrayBuffer();
    return new Uint8Array(buffer);
  }

  /**
   * Unseal encrypted data using the sealing key
   */
  unseal(contractAddress: string, sealedData: Uint8Array | string): bigint {
    const permit = permitStore.get(contractAddress.toLowerCase());
    if (!permit) {
      throw new Error(`No permit found for contract ${contractAddress}`);
    }

    // For compatibility, return a placeholder value
    // In production, this would use the sealing key to decrypt
    if (typeof sealedData === 'string') {
      // If it's a hex string or base64
      try {
        return BigInt(sealedData);
      } catch {
        return BigInt(0);
      }
    }

    // Decode the sealed data (simplified for compatibility)
    if (sealedData.length >= 8) {
      let value = BigInt(0);
      for (let i = 0; i < 8 && i < sealedData.length; i++) {
        value = value | (BigInt(sealedData[i]) << BigInt(i * 8));
      }
      return value;
    }

    return BigInt(0);
  }

  /**
   * Extract permission from a permit for use with contracts
   */
  extractPermitPermission(permit: Permit): Permission {
    return {
      contractAddress: permit.contractAddress,
      signer: permit.signature.slice(0, 42), // Placeholder signer address
      publicKey: permit.sealingKey.publicKey,
      signature: permit.signature,
    };
  }

  /**
   * Store a permit for later use
   */
  storePermit(permit: Permit): void {
    permitStore.set(permit.contractAddress.toLowerCase(), permit);
  }

  /**
   * Get the stored permit for a contract
   */
  getStoredPermit(contractAddress: string): Permit | undefined {
    return permitStore.get(contractAddress.toLowerCase());
  }
}

/**
 * Generate a permit for accessing encrypted data
 */
export async function generatePermit(
  contractAddress: string,
  provider: SupportedProvider
): Promise<Permit> {
  // Generate a random sealing key pair
  const privateKey = ethers.hexlify(ethers.randomBytes(32));
  const wallet = new ethers.Wallet(privateKey);
  const publicKey = wallet.address;

  // Get signer from provider
  let signer: ethers.Signer;
  if (provider.getSigner) {
    signer = await provider.getSigner();
  } else {
    throw new Error('Provider must have getSigner method');
  }

  // Create a signature for the permit
  const message = `LuxFHE Permit for ${contractAddress}`;
  const signature = await signer.signMessage(message);

  const permit: Permit = {
    contractAddress: contractAddress.toLowerCase(),
    sealingKey: {
      privateKey,
      publicKey,
    },
    signature,
  };

  // Store the permit
  permitStore.set(contractAddress.toLowerCase(), permit);

  return permit;
}

/**
 * Get an existing permit or generate a new one
 */
export async function getPermit(
  contractAddress: string,
  provider: SupportedProvider
): Promise<Permit> {
  const existing = permitStore.get(contractAddress.toLowerCase());
  if (existing) return existing;
  return generatePermit(contractAddress, provider);
}

/**
 * Get all stored permits
 */
export function getAllPermits(): Map<string, Permit> {
  return new Map(permitStore);
}

/**
 * Remove a permit
 */
export function removePermit(contractAddress: string): boolean {
  return permitStore.delete(contractAddress.toLowerCase());
}

/**
 * Clear all permits
 */
export function clearAllPermits(): void {
  permitStore.clear();
}

