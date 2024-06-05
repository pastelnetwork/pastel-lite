// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2016-2018 The Zcash developers
// Copyright (c) 2018-2023 Pastel Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <cassert>
#include <string.h>
#include <variant>

#include <fmt/core.h>

#include "vector_types.h"
#include "base58.h"
#include "transaction/script.h"
#include "key_io.h"

using namespace std;

namespace
{
class DestinationEncoder
{
private:
	const KeyConstants& m_KeyConstants;

public:
	DestinationEncoder(const KeyConstants& keyConstants) : 
		m_KeyConstants(keyConstants)
	{}

    string operator()(const CKeyID& id) const
    {
        v_uint8 data = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    string operator()(const CScriptID& id) const
    {
        v_uint8 data = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    string operator()(const CNoDestination& no) const { return {}; }
};
} // namespace

CTxDestination KeyIO::DecodeDestination(const string& str)
{
    v_uint8 data;
    uint160 hash;
    if (DecodeBase58Check(str, data))
    {
        // base58-encoded Bitcoin addresses.
        // Public-key-hash-addresses have version 0 (or 111 testnet).
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const auto& pubkey_prefix = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin()))
        {
            copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return CKeyID(hash);
        }
        // Script-hash-addresses have version 5 (or 196 testnet).
        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const auto& script_prefix = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && equal(script_prefix.begin(), script_prefix.end(), data.begin()))
        {
            copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return CScriptID(hash);
        }
    }
    return CNoDestination();
}

/**
 * Decodes private key string (base58 encoded) to CKey object.
 * 
 * \param str - private key string
 * \return CKey object that encapsulates private key
 */
CKey KeyIO::DecodeSecret(const string& str, string& error)
{
    CKey key;
    v_uint8 data;
    do
    {
        if (!DecodeBase58Check(str, data))
        {
            error = "failed to decode base58-encoded string";
            break;
        }
        // secret key prefix
        const auto& privkey_prefix = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::SECRET_KEY);
        // check that:
        //   - key string is exactly 32 bytes or 32 bytes with trailing compression flag
        //   - key string starts with secret key prefix
        const auto nKeySize = privkey_prefix.size() + CKey::KEY_SIZE;
        if  ((data.size() == nKeySize ||
            ((data.size() == nKeySize + 1) && data.back() == 1)) &&
            equal(privkey_prefix.cbegin(), privkey_prefix.cend(), data.cbegin()))
        {
            const bool bCompressed = data.size() == nKeySize + 1;
            key.Set(data.cbegin() + privkey_prefix.size(), data.cbegin() + nKeySize, bCompressed);
        }
        else
        {
            if (data.size() < nKeySize)
            {
                error = fmt::format("length is less than {} bytes", CKey::KEY_SIZE);
                break;
            }
            error = "invalid prefix";
            break;
        }
    } while (false);
    // wipe out memory
    memory_cleanse(data.data(), data.size());
    return key;
}

/**
 * Encodes CKey private key object to string.
 * This function expects that key is valid
 * 
 * \param key - CKey object that encapsulates private key
 * \return string representation of private key
 */
string KeyIO::EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    v_uint8 data = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::SECRET_KEY);
    data.insert(data.end(), key.cbegin(), key.cend());
    // add "compressed" flag = 1
    if (key.IsCompressed())
        data.push_back(1);
    // base58 encoding
    string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey KeyIO::DecodeExtPubKey(const string& str)
{
    CExtPubKey key;
    v_uint8 data;
    if (DecodeBase58Check(str, data))
    {
        const auto& prefix = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && equal(prefix.begin(), prefix.end(), data.begin()))
            key.Decode(data.data() + prefix.size());
    }
    return key;
}

string KeyIO::EncodeExtPubKey(const CExtPubKey& key)
{
    v_uint8 data = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::EXT_PUBLIC_KEY);
    const size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey KeyIO::DecodeExtKey(const string& str)
{
    CExtKey key;
    v_uint8 data;
    if (DecodeBase58Check(str, data))
    {
        const auto& prefix = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::EXT_SECRET_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && equal(prefix.cbegin(), prefix.cend(), data.cbegin()))
            key.Decode(data.data() + prefix.size());
    }
    return key;
}

string KeyIO::EncodeExtKey(const CExtKey& key)
{
    v_uint8 data = m_KeyConstants.Base58Prefix(KeyConstants::Base58Type::EXT_SECRET_KEY);
    const size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

string KeyIO::EncodeDestination(const CTxDestination& dest)
{
    return visit(DestinationEncoder(m_KeyConstants), dest);
}

bool KeyIO::IsValidDestinationString(const string& str)
{
    return IsValidDestination(DecodeDestination(str));
}
