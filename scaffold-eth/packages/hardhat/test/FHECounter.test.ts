/* eslint-disable @typescript-eslint/no-unused-vars */
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import hre from "hardhat";
import { Encryptable, FheTypes } from "@fhe/sdk";

/**
 * @file FHECounter.test.ts
 * @description Test suite for the FHECounter contract demonstrating FHE operations and testing utilities
 *
 * This test suite showcases the use of FHE testing tools and utilities:
 * - hre.fhesdk: Internal FHE testing utilities
 * - fhe client: FHE operations interface
 * - Mock environment testing for FHE operations
 */

describe("Counter", function () {
  /**
   * @dev Deploys a fresh instance of the FHECounter contract for each test
   * Uses the third signer (bob) as the deployer
   */
  async function deployCounterFixture() {
    // Contracts are deployed using the first signer/account by default
    const [signer, signer2, bob, alice] = await hre.ethers.getSigners();

    const Counter = await hre.ethers.getContractFactory("FHECounter");
    const counter = await Counter.connect(bob).deploy();

    return { counter, signer, bob, alice };
  }

  describe("Functionality", function () {
    /**
     * @dev Setup and teardown for FHE testing
     * - Checks if we're in a MOCK environment (required for FHE testing)
     * - Provides options for enabling/disabling FHE operation logging
     */
    beforeEach(function () {
      // NOTE: Uncomment for global logging
      // hre.fhesdk.mocks.enableLogs();
    });

    afterEach(function () {
      // NOTE: Uncomment for global logging
      // hre.fhesdk.mocks.disableLogs()
    });

    /**
     * @dev Tests the basic increment functionality
     * Demonstrates:
     * - Reading encrypted values using hre.fhesdk.mocks.expectPlaintext
     * - Logging FHE operations using hre.fhesdk.mocks.withLogs
     */
    it("Should increment the counter", async function () {
      const { counter, bob } = await loadFixture(deployCounterFixture);
      const count = await counter.count();

      // `hre.fhesdk.mocks.expectPlaintext` is used to verify that the encrypted value is 0
      // This uses the encrypted variable `count` and retrieves the plaintext value from the on-chain mock contracts
      // This kind of test can only be done in a mock environment where the plaintext value is known
      await hre.fhesdk.mocks.expectPlaintext(count, 0n);

      // `hre.fhesdk.mocks.withLogs` is used to log the FHE operations
      // This is useful for debugging and understanding the FHE operations
      // It will log the FHE operations to the console
      await hre.fhesdk.mocks.withLogs("counter.increment()", async () => {
        await counter.connect(bob).increment();
      });

      const count2 = await counter.count();
      await hre.fhesdk.mocks.expectPlaintext(count2, 1n);
    });

    /**
     * @dev Tests the fhesdk unseal functionality in mock environment
     * Demonstrates:
     * - Initializing FHE with a Hardhat signer
     * - Reading with transparently unsealing encrypted values
     * - Verifying unsealed values match expectations
     */
    it("fhesdk decrypt (mocks)", async function () {
      await hre.fhesdk.mocks.enableLogs("fhesdk decrypt (mocks)");
      const { counter, bob } = await loadFixture(deployCounterFixture);

      // `hre.fhesdk.createBatteriesIncludedFHEsdkClient` is used to initialize FHE with a Hardhat signer
      // Initialization is required before any `encrypt` or `decrypt` operations can be performed
      // `createBatteriesIncludedFHEsdkClient` is a helper function that initializes FHE with a Hardhat signer
      // Returns a `Promise<FHEsdkClient>` type.

      const client = await hre.fhesdk.createBatteriesIncludedFHEsdkClient(bob);

      const count = await counter.count();

      // `decryptHandle` is used to unseal the encrypted value
      // the client must be initialized and connected before `unseal` can be called
      // `decrypt` returns a `Promise<Result<T>>` type.
      const unsealedResult = await client.decryptHandle(count, FheTypes.Uint32).decrypt();
      // The `Result<T>` type looks like this:
      // {
      //   success: boolean,
      //   data: T (Permit | undefined in the case of initializeWithHardhatSigner),
      //   error: FHEsdkError | null,
      // }

      // `hre.fhesdk.expectResultValue` is used to verify that the `Result.data` is the expected value
      // If the `Result.data` is not the expected value, the test will fail
      await hre.fhesdk.expectResultValue(unsealedResult, 0n);

      await counter.connect(bob).increment();

      const count2 = await counter.count();
      const unsealedResult2 = await client.decryptHandle(count2, FheTypes.Uint32).decrypt();
      await hre.fhesdk.expectResultValue(unsealedResult2, 1n);

      await hre.fhesdk.mocks.disableLogs();
    });

    /**
     * @dev Tests the fhesdk encryption and value setting functionality
     * Demonstrates:
     * - Encrypting values using fhesdk
     * - Setting encrypted values in the contract
     * - Verifying encrypted values using both mocks and unsealing
     */
    it("fhesdk encrypt (mocks)", async function () {
      const { counter, bob } = await loadFixture(deployCounterFixture);

      const client = await hre.fhesdk.createBatteriesIncludedFHEsdkClient(bob);

      // `encryptInputs` is used to encrypt the value
      // the client must be initialized and connected before `encryptInputs` can be called
      // `encrypt` returns a `Promise<Result<T>>` type.

      const encryptResult = await client.encryptInputs([Encryptable.uint32(5n)]).encrypt();
      // The `Result<T>` type looks like this:
      // {
      //   success: boolean,
      //   data: T (Permit | undefined in the case of initializeWithHardhatSigner),
      //   error: FHEsdkError | null,
      // }

      const [encryptedInput] = await hre.fhesdk.expectResultSuccess(encryptResult);
      await hre.fhesdk.mocks.expectPlaintext(encryptedInput.ctHash, 5n);

      await counter.connect(bob).set(encryptedInput);

      const count = await counter.count();
      await hre.fhesdk.mocks.expectPlaintext(count, 5n);

      const unsealedResult = await client.decryptHandle(count, FheTypes.Uint32).decrypt();

      await hre.fhesdk.expectResultValue(unsealedResult, 5n);
    });
  });
});
