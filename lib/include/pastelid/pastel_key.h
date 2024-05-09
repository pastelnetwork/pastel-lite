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
    static pastelid_store_t CreateNewPastelKeysFile(const string& sDirPath, SecureString&& passPhrase);
    static void CreatePastelKeysFile(const string& sDirPath, SecureString&& passPhrase,
                                     const string& paslteID, const string& legRoastPubKey,
                                     const v_uint8& pastelIDPrivKey, const v_uint8& legRoastPrivKey);

    // Get signing algorithm enum by name.
    static SIGN_ALGORITHM GetAlgorithmByName(const string& s);

    // encode/decode PastelID
    static string EncodePastelID(const v_uint8& key);
    static bool DecodePastelID(const string& sPastelID, v_uint8& vData);
    // encode/decode LegRoast public key
    static string EncodeLegRoastPubKey(const string& sPubKey);
    static bool DecodeLegRoastPubKey(const string& sLRKey, v_uint8& vData);

    static uint256 PastelIDFingerprint(const v_uint8& vData);
    static uint256 LegRoastFingerprint(const v_uint8& vData);

protected:

private:
};
