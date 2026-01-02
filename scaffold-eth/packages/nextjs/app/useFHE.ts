"use client";

import { useCallback, useEffect, useMemo, useSyncExternalStore } from "react";
import { arbSepolia, hardhat, sepolia } from "@fhe/sdk/chains";
import {
  CreateSelfPermitOptions,
  CreateSharingPermitOptions,
  Permit,
  PermitUtils,
  permitStore,
} from "@fhe/sdk/permits";
import { createFHEsdkClient, createFHEsdkConfig } from "@fhe/sdk/web";
import * as chains from "viem/chains";
import { useAccount, usePublicClient, useWalletClient } from "wagmi";
import { create } from "zustand";
import scaffoldConfig from "~~/scaffold.config";
import { logBlockMessage, logBlockMessageAndEnd, logBlockStart } from "~~/utils/fhe/logging";
import { notification } from "~~/utils/scaffold-eth";

const config = createFHEsdkConfig({
  // mirrors scaffoldConfig.targetNetworks
  supportedChains: [hardhat, sepolia, arbSepolia],
  mocks: {
    sealOutputDelay: 1000,
  },
});
export const fhesdkClient = createFHEsdkClient(config);

// sync core store
const subscribeToConnection = (onStoreChange: () => void) => {
  return fhesdkClient.subscribe(() => {
    onStoreChange();
  });
};
const getConnectionSnapshot = () => fhesdkClient.getSnapshot();

const useFHEConnectionSnapshot = () =>
  useSyncExternalStore(subscribeToConnection, getConnectionSnapshot, getConnectionSnapshot);
// sync permits store
type PermitsSnapshot = ReturnType<(typeof fhesdkClient.permits)["getSnapshot"]>;
const subscribeToPermits = (onStoreChange: () => void) => {
  return fhesdkClient.permits.subscribe(() => {
    onStoreChange();
  });
};

const getPermitsSnapshot = () => fhesdkClient.permits.getSnapshot();

const useFHEPermitsSnapshot = (): PermitsSnapshot =>
  useSyncExternalStore(subscribeToPermits, getPermitsSnapshot, getPermitsSnapshot);

/**
 * Hook to check if the currently connected chain is supported by the application
 * @returns boolean indicating if the current chain is in the target networks list
 * Refreshes when chainId changes
 */
export const useIsConnectedChainSupported = () => {
  const { chainId } = useAccount();
  return useMemo(
    () => scaffoldConfig.targetNetworks.some((network: chains.Chain) => network.id === chainId),
    [chainId],
  );
};

/**
 * Hook to track the connected wallet and chain and make sure fhe is connected to the correct ones
 * Handles connection errors and displays toast notifications on success or error
 * Refreshes when connected wallet or chain changes
 */
export function useConnectFHEClient() {
  const publicClient = usePublicClient();
  const { data: walletClient } = useWalletClient();
  const isChainSupported = useIsConnectedChainSupported();

  const handleError = (error: string) => {
    console.error("fhe connection error:", error);
    notification.error(`fhe connection error: ${error}`);
  };

  useEffect(() => {
    const connectFHE = async () => {
      // Early exit if any of the required dependencies are missing
      if (!publicClient || !walletClient || !isChainSupported) return;

      logBlockStart("useConnectFHEClient");
      logBlockMessage("CONNECTING     | Setting up CoFHE");

      try {
        const connectionResult = await fhesdkClient.connect(publicClient, walletClient);
        if (connectionResult.success) {
          logBlockMessageAndEnd(`[connectionResult] SUCCESS          | CoFHE environment initialization`);
          notification.success("FHE connected successfully");
        } else {
          logBlockMessageAndEnd(
            `FAILED           | ${connectionResult.error.message ?? String(connectionResult.error)}`,
          );
          handleError(connectionResult.error.message ?? String(connectionResult.error));
        }
      } catch (err) {
        logBlockMessageAndEnd(`FAILED           | ${err instanceof Error ? err.message : "Unknown error"}`);
        handleError(err instanceof Error ? err.message : "Unknown error initializing fhe");
      }
    };

    connectFHE();
  }, [walletClient, publicClient, isChainSupported]);
}

/**
 * Hook to get the current account connected to fhe
 * @returns The current account address or undefined
 */
export const useFHEAccount = () => {
  return useFHEConnectionSnapshot().account;
};

/**
 * Hook to check if fhe is connected (provider, and signer)
 * This is used to determine if the user is ready to use the FHE library
 * FHE based interactions (encrypt / decrypt) should be disabled until this is true
 * @returns boolean indicating if provider, and signer are all connected
 */
export const useFHEConnected = () => {
  const { connected } = useFHEConnectionSnapshot();
  return connected;
};

/**
 * Hook to get the complete status of fhe
 * @returns Object containing chainId, account, and initialization status
 * Refreshes when any of the underlying values change
 */
export const useFHEStatus = () => {
  const { chainId, account, connected } = useFHEConnectionSnapshot();
  return useMemo(() => ({ chainId, account, connected }), [chainId, account, connected]);
};

// Permit Modal

interface FHEPermitModalStore {
  generatePermitModalOpen: boolean;
  generatePermitModalCallback?: () => void;
  setGeneratePermitModalOpen: (open: boolean, callback?: () => void) => void;
}

/**
 * Hook to access the permit modal store
 * @returns Object containing modal state and control functions
 */
export const useFHEModalStore = create<FHEPermitModalStore>(set => ({
  generatePermitModalOpen: false,
  setGeneratePermitModalOpen: (open, callback) =>
    set({ generatePermitModalOpen: open, generatePermitModalCallback: callback }),
}));

// Permits

/**
 * Hook to get the active permit hash for the current chain and account
 * @returns The active permit hash or undefined if not set
 * Refreshes when chainId, account, or initialization status changes
 */
export const useFHEActivePermitHash = () => {
  const { chainId, account, connected } = useFHEStatus();
  const permitsSnapshot = useFHEPermitsSnapshot();
  if (!connected || !chainId || !account) return undefined;
  return permitsSnapshot.activePermitHash?.[chainId]?.[account];
};

/**
 * Hook to get the active permit object
 * @returns The active permit object or null if not found/valid
 * Refreshes when active permit hash changes
 */
export const useFHEActivePermit = (): Permit | null => {
  const { chainId, account, connected } = useFHEStatus();
  const activePermitHash = useFHEActivePermitHash();
  const permitsSnapshot = useFHEPermitsSnapshot();
  return useMemo(() => {
    if (!connected || !chainId || !account || !activePermitHash) return null;
    const serializedPermit = permitsSnapshot.permits?.[chainId]?.[account]?.[activePermitHash] ?? null;
    const permit = serializedPermit ? PermitUtils.deserialize(serializedPermit) : null;
    return permit;
  }, [activePermitHash, chainId, account, connected, permitsSnapshot]);
};

/**
 * Hook to check if the active permit is valid
 * @returns boolean indicating if the active permit is valid
 * Refreshes when permit changes
 */
export const useFHEIsActivePermitValid = () => {
  const permit = useFHEActivePermit();
  return useMemo(() => {
    if (!permit) return false;
    return PermitUtils.isValid(permit);
  }, [permit]);
};

/**
 * Hook to get all permit hashes for the current chain and account
 * @returns Array of permit hashes
 * Refreshes when chainId, account, or initialization status changes
 */
export const useFHEAllPermitHashes = () => {
  const { chainId, account, connected } = useFHEStatus();
  const permitsSnapshot = useFHEPermitsSnapshot();
  return useMemo(() => {
    if (!connected || !chainId || !account) return [];
    const permitsForAccount = permitsSnapshot.permits?.[chainId]?.[account];
    if (!permitsForAccount) return [];
    return Object.keys(permitsForAccount);
  }, [chainId, account, connected, permitsSnapshot]);
};

/**
 * Hook to get all permit objects for the current chain and account
 * @returns Array of permit objects
 * Refreshes when permit hashes change
 */
export const useFHEAllPermits = (): Permit[] => {
  const { chainId, account, connected } = useFHEStatus();
  const permitsSnapshot = useFHEPermitsSnapshot();
  if (!connected || !chainId || !account) return [];
  return Object.values(permitsSnapshot.permits?.[chainId]?.[account] || {})
    .map(serializedPermit => (serializedPermit ? PermitUtils.deserialize(serializedPermit) : null))
    .filter((permit): permit is Permit => permit !== null);
};

/**
 * Hook to create a new permit
 * @returns Async function to create a permit with optional options
 * Refreshes when chainId, account, or initialization status changes
 */
export const useFHECreatePermit = () => {
  const { chainId, account, connected } = useFHEStatus();
  return useCallback(
    async (opts: CreateSelfPermitOptions | CreateSharingPermitOptions) => {
      if (!connected || !chainId || !account) return;

      async function getPermitResult() {
        if (opts.type === "self") return fhesdkClient.permits.createSelf(opts);
        if (opts.type === "sharing") return fhesdkClient.permits.createSharing(opts);
        throw new Error("Invalid permit type");
      }
      const permitResult = await getPermitResult();
      if (permitResult.success) {
        notification.success("Permit created");
      } else {
        notification.error(permitResult.error.message ?? String(permitResult.error));
      }
      return permitResult;
    },
    [chainId, account, connected],
  );
};

/**
 * Hook to remove a permit
 * @returns Async function to remove a permit by its hash
 * Refreshes when chainId, account, or initialization status changes
 */
export const useFHERemovePermit = () => {
  const { chainId, account, connected } = useFHEStatus();
  return useCallback(
    async (permitHash: string) => {
      if (!connected || !chainId || !account) return;
      permitStore.removePermit(chainId, account, permitHash);
      notification.success("Permit removed");
    },
    [chainId, account, connected],
  );
};

/**
 * Hook to select the active permit
 * @returns Async function to set the active permit by its hash
 * Refreshes when chainId, account, or initialization status changes
 */
export const useFHESetActivePermit = () => {
  const { chainId, account, connected } = useFHEStatus();
  return useCallback(
    async (permitHash: string) => {
      if (!connected || !chainId || !account) return;
      permitStore.setActivePermitHash(chainId, account, permitHash);
      notification.success("Active permit updated");
    },
    [chainId, account, connected],
  );
};

/**
 * Hook to get the issuer of the active permit
 * @returns The permit issuer address or null if no active permit
 * Refreshes when active permit changes
 */
export const useFHEPermitIssuer = () => {
  const permit = useFHEActivePermit();
  return useMemo(() => {
    if (!permit) return null;
    return permit.issuer;
  }, [permit]);
};
