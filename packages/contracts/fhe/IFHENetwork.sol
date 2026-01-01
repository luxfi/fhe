// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <0.9.0;

import {FunctionId, EncryptedInput} from "./IFHE.sol";

/// @title IFHENetwork
/// @notice Interface for the FHE Network contract on the Lux T-Chain
/// @dev Extends ITaskManager with additional access control and utility methods
interface IFHENetwork {
    // Task Management
    function createTask(
        uint8 returnType,
        FunctionId funcId,
        uint256[] memory encryptedInputs,
        uint256[] memory extraInputs
    ) external returns (uint256);

    function createDecryptTask(uint256 ctHash, address requestor) external;

    function verifyInput(
        EncryptedInput memory input,
        address sender
    ) external returns (uint256);

    // Decryption Results
    function getDecryptResult(uint256 ctHash) external view returns (uint256);

    function getDecryptResultSafe(
        uint256 ctHash
    ) external view returns (uint256 result, bool decrypted);

    // Access Control
    function allow(uint256 ctHash, address account) external;

    function allowGlobal(uint256 ctHash) external;

    function allowTransient(uint256 ctHash, address account) external;

    function allowForDecryption(uint256 ctHash) external;

    function isAllowed(
        uint256 ctHash,
        address account
    ) external view returns (bool);

    // Note: isAllowedWithPermission is implementation-specific due to Permission struct variations
    // Implementations should define this function with their own Permission type

    // Utility
    function exists() external view returns (bool);
}
