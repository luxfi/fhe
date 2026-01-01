// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <0.9.0;

// Extension library for FHE operations with InEuint* typed inputs
// These provide convenience overloads for the typed input structs

import "@luxfi/contracts/fhe/FHE.sol";
import {InEbool, InEuint8, InEuint16, InEuint32, InEuint64, InEuint128, InEuint256, InEaddress} from "./InTypes.sol";
import {Ebool, Euint8, Euint16, Euint32, Euint64, Euint128, Euint256, Eaddress, EncryptedInput, Utils} from "@luxfi/contracts/fhe/IFHE.sol";
import {FHENetwork} from "@luxfi/contracts/fhe/FHENetwork.sol";

/// @title FHEIn
/// @notice Extension library providing asEuint* functions for typed input structs
library FHEIn {
    // ===== Convert InEuint* structs to euint* types =====

    function asEbool(InEbool memory value) internal returns (ebool) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return ebool.wrap(FHENetwork.verifyInput(input));
    }

    function asEuint8(InEuint8 memory value) internal returns (euint8) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return euint8.wrap(FHENetwork.verifyInput(input));
    }

    function asEuint16(InEuint16 memory value) internal returns (euint16) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return euint16.wrap(FHENetwork.verifyInput(input));
    }

    function asEuint32(InEuint32 memory value) internal returns (euint32) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return euint32.wrap(FHENetwork.verifyInput(input));
    }

    function asEuint64(InEuint64 memory value) internal returns (euint64) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return euint64.wrap(FHENetwork.verifyInput(input));
    }

    function asEuint128(InEuint128 memory value) internal returns (euint128) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return euint128.wrap(FHENetwork.verifyInput(input));
    }

    function asEuint256(InEuint256 memory value) internal returns (euint256) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return euint256.wrap(FHENetwork.verifyInput(input));
    }

    function asEaddress(InEaddress memory value) internal returns (eaddress) {
        EncryptedInput memory input = EncryptedInput({
            ctHash: value.ctHash,
            securityZone: value.securityZone,
            utype: value.utype,
            signature: value.signature
        });
        return eaddress.wrap(FHENetwork.verifyInput(input));
    }
}
