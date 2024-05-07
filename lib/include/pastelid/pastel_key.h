#pragma once
// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <unordered_map>

#include "types.h"
#include "serialize.h"
#include "vector_types.h"
#include "map_types.h"
#include "pastelid/legroast.h"
#include "uint256.h"
#include "pastelid/secure_container.h"

using namespace std;

// storage type for pastel ids and associated keys
using pastelid_store_t = mu_strings;

constexpr auto SIGN_ALG_ED448 = "ed448";
constexpr auto SIGN_ALG_LEGROAST = "legroast";

class CPastelIDPkg {
    string m_sPastelID;
    string m_sLegRoastPubKey;
    pair<uint256, v_uint8> m_encryptedPastelIDPrivateKey; // [fingerprint, seed encrypted with m_vMasterKey]
    pair<uint256, v_uint8> m_encryptedLegRoastPrivateKey; // [fingerprint, seed encrypted with m_vMasterKey]
public:
    CPastelIDPkg() = default;

    CPastelIDPkg(const string& sPastelID, const string& sLegRoastPubKey)
        : m_sPastelID(sPastelID), m_sLegRoastPubKey(sLegRoastPubKey) {}

    bool SetSecureData(const pair<uint256, v_uint8>& pastelID, const pair<uint256, v_uint8>& legRoast) {
        m_encryptedPastelIDPrivateKey = pastelID;
        m_encryptedLegRoastPrivateKey = legRoast;
        return true;
    }

    const string& GetPastelID() const { return m_sPastelID; }
    const string& GetLegRoastPubKey() const { return m_sLegRoastPubKey; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_sPastelID);
        READWRITE(m_sLegRoastPubKey);
        READWRITE(m_encryptedPastelIDPrivateKey);
        READWRITE(m_encryptedLegRoastPrivateKey);
    }
};

class CPastelID
{
    static constexpr size_t  PASTELID_PUBKEY_SIZE = 57;
    static constexpr uint8_t PASTELID_PREFIX[] = {0xA1, 0xDE};

    static constexpr size_t  LEGROAST_PUBKEY_SIZE = legroast::PK_BYTES;
    static constexpr uint8_t LEGROAST_PREFIX[] = {0x51, 0xDE};

public:
    enum class SIGN_ALGORITHM : int
    {
        not_defined = 0,
        ed448 = 1,
        legroast = 2
    };

    // Generate new Pastel ID(EdDSA448) and LegRoast public / private key pairs.
    static pastelid_store_t CreateNewPastelKeys(SecureString&& passPhrase, secure_container::CSecureContainer& container);

    // Get signing algorithm enum by name.
    static SIGN_ALGORITHM GetAlgorithmByName(const string& s);
    // Sign text with the private key associated with PastelID.
    static string Sign(const string& sText, const string& sPastelID, SecureString&& sPassPhrase,
        const SIGN_ALGORITHM alg = SIGN_ALGORITHM::ed448, const bool fBase64 = false);
    // Verify signature with the public key associated with PastelID.
    static bool Verify(const string& sText, const string& sSignature, const string& sPastelID,
        const SIGN_ALGORITHM alg = SIGN_ALGORITHM::ed448, const bool fBase64 = false);
    // Validate passphrase via secure container or pkcs8 format
    static bool isValidPassphrase(const string& sPastelId, const SecureString& strKeyPass) noexcept;
    // Change passphrase used to encrypt the secure container
    static bool ChangePassphrase(string &error, const string& sPastelId, SecureString&& sOldPassphrase, SecureString&& sNewPassphrase);

    static string EncodePastelID(const v_uint8& key);
    static string EncodeLegRoastPubKey(const string& sPubKey);
protected:
    // encode/decode PastelID
    static bool DecodePastelID(const string& sPastelID, v_uint8& vData);
    // encode/decode LegRoast public key
    static bool DecodeLegRoastPubKey(const string& sLRKey, v_uint8& vData);

private:
};
