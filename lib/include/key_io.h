#pragma once
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2018 The Zcash developers
// Copyright (c) 2018-2021 Pastel Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <variant>

#include "key_constants.h"
#include "key.h"
#include "pubkey.h"
#include "standard.h"
#include "transaction/script.h"

class KeyIO
{
private:
    const KeyConstants& m_KeyConstants;

public:
    KeyIO(const KeyConstants& keyConstants) : m_KeyConstants(keyConstants) {}

    CKey DecodeSecret(const std::string& str, std::string& error); // Changed to return CKey
    std::string EncodeSecret(const CKey& key);

    CExtKey DecodeExtKey(const std::string& str);
    std::string EncodeExtKey(const CExtKey& extkey);
    CExtPubKey DecodeExtPubKey(const std::string& str);
    std::string EncodeExtPubKey(const CExtPubKey& extpubkey);

    std::string EncodeDestination(const CTxDestination& dest);
    CTxDestination DecodeDestination(const std::string& str);

    bool IsValidDestinationString(const std::string& str);
};