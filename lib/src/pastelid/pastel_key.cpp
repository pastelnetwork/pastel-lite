// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <filesystem>
#include <fmt/core.h>
#include "support/cleanse.h"
#include "base58.h"
#include "hash.h"
#include "pastelid/common.h"
#include "pastelid/pastel_key.h"

using namespace std;
using namespace legroast;
using namespace crypto_helpers;
using namespace secure_container;

constexpr size_t SEEDBYTES = 16;
constexpr unsigned char PASTEL_ID_FP[SEEDBYTES] =
        {'P', 'a', 's', 't', 'e', 'l', 'I', 'D', '_', 'e', 'd', '4', '4', '8', 'F', 'P'};
constexpr unsigned char PASTEL_LR_FP[SEEDBYTES] =
        {'P', 'a', 's', 't', 'e', 'l', 'I', 'D', '_', 'l', 'e', 'g', 'R', '_', 'F', 'P'};

/**
* Generate new Pastel ID (EdDSA448) and LegRoast public/private key pairs.
* Create new secure container to store all items associated with Pastel ID.
* \param sDirPath - secure container file path
* \param passPhrase - secure passphrase that will be used to encrypt secure container.
* \return pastelid_store_t map [encoded Pastel ID] -> [encoded LegRoast public key]
*/
pastelid_store_t CPastelID::CreateNewPastelKeysFile(const string &sDirPath, SecureString &&passPhrase) {
    pastelid_store_t resultMap;
    try {
        // Pastel ID private/public keys (EdDSA448)
        Botan::AutoSeeded_RNG rng;
        v_uint8 seed;
        seed.resize(ED448_LEN);
        rng.randomize(seed);
        auto key = Botan::Ed448_PrivateKey(std::span(seed));

        // encode public key with Pastel ID prefix (A1DE), base58 encode + checksum
        string sPastelID = EncodePastelID(key.public_key_bits());
        // LegRoast signing keys
        CLegRoast<algorithm::Legendre_Middle> LegRoastKey;
        // generate LegRoast private/public key pair
        LegRoastKey.keygen();
        string sEncodedLegRoastPubKey = EncodeLegRoastPubKey(LegRoastKey.get_public_key());

        auto privKey = key.private_key_bits();
        // write secure container with both private keys
        CreatePastelKeysFile(sDirPath, std::move(passPhrase), sPastelID, sEncodedLegRoastPubKey,
                             {privKey.begin(), privKey.end()}, LegRoastKey.get_private_key());

        // populate storage object with encoded PastelID and LegRoast public keys
        resultMap.emplace(std::move(sPastelID), std::move(sEncodedLegRoastPubKey));
    } catch (const crypto_exception &ex) {
        throw runtime_error(ex.what());
    }
    return resultMap;
}

void CPastelID::CreatePastelKeysFile(const string &sDirPath, SecureString &&passPhrase,
                                     const string &pastelID, const string &legRoastPubKey,
                                     const v_uint8 &pastelIDPrivKey, const v_uint8 &legRoastPrivKey) {
    std::filesystem::path dir(sDirPath);
    std::filesystem::path file(pastelID);
    std::filesystem::path full_path = dir / file;

    CSecureContainer cont;
    cont.add_public_item(PUBLIC_ITEM_TYPE::pubkey_legroast, legRoastPubKey);
    cont.add_secure_item_vector(SECURE_ITEM_TYPE::pkey_ed448, pastelIDPrivKey);
    cont.add_secure_item_vector(SECURE_ITEM_TYPE::pkey_legroast, legRoastPrivKey);
    cont.write_to_file(full_path, std::move(passPhrase));
}

/**
* Get signing algorithm enum by name.
* 
* \param s - algorithm (empty string, ed448 or legroast)
* \return enum item
*/
CPastelID::SIGN_ALGORITHM CPastelID::GetAlgorithmByName(const string &s) {
    SIGN_ALGORITHM alg = SIGN_ALGORITHM::not_defined;
    if (s.empty() || s == SIGN_ALG_ED448)
        alg = SIGN_ALGORITHM::ed448;
    else if (s == SIGN_ALG_LEGROAST)
        alg = SIGN_ALGORITHM::legroast;
    return alg;
}

string CPastelID::EncodePastelID(const v_uint8 &key) {
    v_uint8 vData;
    vData.reserve(key.size() + sizeof(PASTELID_PREFIX));
    vData.assign(cbegin(PASTELID_PREFIX), cend(PASTELID_PREFIX));
    vData.insert(vData.end(), key.cbegin(), key.cend());
    string sRet = EncodeBase58Check(vData);
    memory_cleanse(vData.data(), vData.size());
    return sRet;
}

bool CPastelID::DecodePastelID(const string &sPastelID, v_uint8 &vData) {
    if (!DecodeBase58Check(sPastelID, vData))
        return false;
    if (vData.size() != PASTELID_PUBKEY_SIZE + sizeof(PASTELID_PREFIX) ||
        !equal(cbegin(PASTELID_PREFIX), cend(PASTELID_PREFIX), vData.cbegin()))
        return false;
    vData.erase(vData.cbegin(), vData.cbegin() + sizeof(PASTELID_PREFIX));
    return true;
}

string CPastelID::EncodeLegRoastPubKey(const string &sPubKey) {
    v_uint8 vData;
    vData.reserve(sPubKey.size() + sizeof(LEGROAST_PREFIX));
    vData.assign(cbegin(LEGROAST_PREFIX), cend(LEGROAST_PREFIX));
    append_string_to_vector(sPubKey, vData);
    string sRet = EncodeBase58Check(vData);
    memory_cleanse(vData.data(), vData.size());
    return sRet;
}

bool CPastelID::DecodeLegRoastPubKey(const string &sLRKey, v_uint8 &vData) {
    if (!DecodeBase58Check(sLRKey, vData))
        return false;
    if (vData.size() != LEGROAST_PUBKEY_SIZE + sizeof(LEGROAST_PREFIX) ||
        !equal(cbegin(LEGROAST_PREFIX), cend(LEGROAST_PREFIX), vData.cbegin()))
        return false;
    vData.erase(vData.cbegin(), vData.cbegin() + sizeof(LEGROAST_PREFIX));
    return true;
}

uint256 CPastelID::PastelIDFingerprint(const v_uint8 &vData) {
    CBLAKE2bWriter h(SER_GETHASH, 0, PASTEL_ID_FP);
    h << vData;
    return h.GetHash();
}

uint256 CPastelID::LegRoastFingerprint(const v_uint8 &vData) {
    CBLAKE2bWriter h(SER_GETHASH, 0, PASTEL_LR_FP);
    h << vData;
    return h.GetHash();
}
