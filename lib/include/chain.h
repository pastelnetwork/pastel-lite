#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <cstdint>
#include <map>
#include "vector_types.h"
#include "enum_util.h"

enum class NetworkMode {
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

    uint32_t bip44CoinType = 0;
    uint32_t walletIDIndex = 0xA0000001;

    [[nodiscard]] uint32_t BIP44CoinType() const noexcept { return bip44CoinType; }
};

class CMainnetParams : public CChainParams {
public:
    CMainnetParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x0c, 0xe3};
        m_base58Prefixes[to_integral_type(Base58Type::EXT_PUBLIC_KEY)] = {0x04, 0x88, 0xB2, 0x1E};
        bip44CoinType = 4826951;    //0x0049A747; bip44CoinTypeHard => 0x8049A747
    }
};

class CTestnetParams : public CChainParams {
public:
    CTestnetParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x1C, 0xEF};
        m_base58Prefixes[to_integral_type(Base58Type::EXT_PUBLIC_KEY)] = {0x04, 0x35, 0x87, 0xCF};
    }
};

class CRegtestParams : public CChainParams {
public:
    CRegtestParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x1C, 0xEF};
        m_base58Prefixes[to_integral_type(Base58Type::EXT_PUBLIC_KEY)] = {0x04, 0x35, 0x87, 0xCF};
    }
};
