#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <cstdint>
#include <map>
#include <memory>
#include <cassert>

#include "key_constants.h"
#include "vector_types.h"
#include "enum_util.h"

enum class NetworkMode {
    MAINNET = 0,
    TESTNET = 1,
    DEVNET = 2,
    UNKNOWN = 6
};

enum class PastelIDType {
    PASTELID = 0,
    LEGROAST = 1
};

class CBaseKeyConstants : public KeyConstants
{
public:
    const v_uint8& Base58Prefix(const Base58Type type) const noexcept override
    {
        return m_base58Prefixes[to_integral_type(type)];
    }
    const std::string& Bech32HRP(const Bech32Type type) const noexcept override
    {
        return m_bech32HRPs[to_integral_type(type)];
    }

protected:
    v_uint8 m_base58Prefixes[to_integral_type(Base58Type::MAX_BASE58_TYPES)];
    std::string m_bech32HRPs[to_integral_type(Bech32Type::MAX_BECH32_TYPES)];
};

class CChainParams : public CBaseKeyConstants{
public:
    std::string m_sPastelBurnAddress;

    //these are same for all networks
    uint32_t bip44CoinType = 4826951;    //0x0049A747; bip44CoinTypeHard => 0x8049A747
    uint32_t walletIDIndex = 0xA0000001;

    [[nodiscard]] uint32_t BIP44CoinType() const noexcept { return bip44CoinType; }
    [[nodiscard]] uint32_t WalletIDIndex() const noexcept { return walletIDIndex; }
};

class CMainnetParams : public CChainParams {
public:
    CMainnetParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x0c, 0xe3};
        m_base58Prefixes[to_integral_type(Base58Type::EXT_PUBLIC_KEY)] = {0x04, 0x88, 0xB2, 0x1E};
        m_base58Prefixes[to_integral_type(Base58Type::SECRET_KEY)] = {0x80};
        m_sPastelBurnAddress = "PtpasteLBurnAddressXXXXXXXXXXbJ5ndd";
    }
};

class CTestnetParams : public CChainParams {
public:
    CTestnetParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x1C, 0xEF};
        m_base58Prefixes[to_integral_type(Base58Type::EXT_PUBLIC_KEY)] = {0x04, 0x35, 0x87, 0xCF};
        m_base58Prefixes[to_integral_type(Base58Type::SECRET_KEY)] = {0xEF};
        m_sPastelBurnAddress = "tPpasteLBurnAddressXXXXXXXXXXX3wy7u";
    }
};

class CDevnetParams : public CChainParams {
public:
    CDevnetParams(){
        m_base58Prefixes[to_integral_type(Base58Type::PUBKEY_ADDRESS)] = {0x64, 0x1C};
        m_base58Prefixes[to_integral_type(Base58Type::EXT_PUBLIC_KEY)] = {0x04, 0x35, 0x87, 0xCF};
        m_base58Prefixes[to_integral_type(Base58Type::SECRET_KEY)] = {0xEF};
        m_sPastelBurnAddress = "44oUgmZSL997veFEQDq569wv5tsT6KXf9QY7";
    }
};

const CChainParams& GetChainParams(const NetworkMode mode);

