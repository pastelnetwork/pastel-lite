#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <cstdint>
#include <map>
#include "vector_types.h"
#include "enum_util.h"

enum NetworkMode {
    MAINNET = 0,
    TESTNET = 1,
    REGTEST = 2,
    UNKNOWN = 6
};

class CChainParams{
public:
    enum struct Base58Type : uint32_t
    {
        PUBKEY_ADDRESS = 0,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        ZCPAYMENT_ADDRESS,
        ZCSPENDING_KEY,
        ZCVIEWING_KEY,

        MAX_BASE58_TYPES
    };
    v_uint8 m_base58Prefixes[to_integral_type(Base58Type::MAX_BASE58_TYPES)];

    [[nodiscard]] const v_uint8& Base58Prefix(const Base58Type type) const noexcept
    {
        return m_base58Prefixes[to_integral_type(type)];
    }
};

class CMainnetParams : public CChainParams {
public:
    CMainnetParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x0c, 0xe3};
    }
};

class CTestnetParams : public CChainParams {
public:
    CTestnetParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x1C, 0xEF};
    }
};

class CRegtestParams : public CChainParams {
public:
    CRegtestParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x1C, 0xEF};
    }
};
