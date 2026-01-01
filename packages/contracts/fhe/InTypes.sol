// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <0.9.0;

// Typed encrypted input structs for the FHE API
// These have the same memory layout as EncryptedInput for ABI compatibility
// Format: { ctHash, securityZone, utype, signature }

struct InEbool {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint8 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint16 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint32 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint64 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint128 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint256 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEaddress {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}
