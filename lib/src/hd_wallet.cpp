// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <sodium.h>
#include <botan/hash.h>

#include "hd_wallet.h"
#include "utiltime.h"
#include "base58.h"
#include "pubkey.h"
#include "key.h"
#include "crypto/aes.h"
#include "crypto/hmac_sha512.h"
#include "hash.h"
#include "pastelid/pastel_key.h"
#include "pastelid/legroast.h"
#include "pastelid/ed.h"

using namespace legroast;
using namespace ed_crypto;

string CHDWallet::SetupNewWallet(NetworkMode mode, const SecureString &password) {
    m_NetworkMode = mode;
    setNetworkParams(mode);

    // Generate new random master key and encrypt it using key derived from password
    string error;
    if (!setMasterKey(password, error)) {
        stringstream ss;
        ss << "Failed to set master key: " << error.c_str();
        throw runtime_error(ss.str());
    }

    // Generate new random mnemonic seed and encrypt it using master key
    auto bip44CoinType = m_NetworkParams->BIP44CoinType();
    MnemonicSeed seed = MnemonicSeed::Random(bip44CoinType, Language::English);
    if (!setEncryptedMnemonicSeed(seed, error)) {
        stringstream ss;
        ss << "Failed to set encrypted mnemonic seed: " << error.c_str();
        throw runtime_error(ss.str());
    }

    // verify that the seed can be decrypted
    auto decSeed = getDecryptedMnemonicSeed();
    if (!decSeed.has_value()) {
        throw runtime_error("Failed to get decrypted mnemonic seed");
    }
    return seed.GetMnemonic();
}

bool CHDWallet::setMasterKey(const SecureString &strPassphrase, string &error) noexcept {
    try {
        if (strPassphrase.empty()) {
            error = "Passphrase is empty";
            return false;
        }
        if (m_encryptedMasterKey.vchCryptedKey.size() == WALLET_CRYPTO_KEY_SIZE + AES_BLOCKSIZE) {// already set
            error = "Master key already set";
            return false;
        }
        if (m_vMasterKey.size() == WALLET_CRYPTO_KEY_SIZE) { // already set
            error = "Master key already set";
            return false;
        }
        m_vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
        randombytes_buf(&m_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

        CMasterKey kMasterKey;
        kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
        randombytes_buf(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

        CCrypter crypter;
        int64_t nStartTime = GetTimeMillis();
        if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod)) {
            error = "Failed to set key from passphrase";
            return false;
        }
        kMasterKey.nDeriveIterations = 2500000 / ((double) (GetTimeMillis() - nStartTime));

        nStartTime = GetTimeMillis();
        if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                          kMasterKey.nDerivationMethod)) {
            error = "Failed to set key from passphrase";
            return false;
        }
        kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 /
                                                                       ((double) (GetTimeMillis() - nStartTime))) / 2;
        if (kMasterKey.nDeriveIterations < 25000)
            kMasterKey.nDeriveIterations = 25000;

        if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                          kMasterKey.nDerivationMethod)) {
            error = "Failed to set key from passphrase";
            return false;
        }
        if (!crypter.Encrypt(m_vMasterKey, kMasterKey.vchCryptedKey)) {
            error = "Failed to encrypt master key";
            return false;
        }
        m_encryptedMasterKey = kMasterKey;
    } catch (const exception &e) {
        error = e.what();
        return false;
    }
    return true;
}

bool CHDWallet::setEncryptedMnemonicSeed(const MnemonicSeed &seed, string &error) noexcept {
    try {
        // Use seed's fingerprint as IV
        auto seedFp = seed.Fingerprint();

        auto vchSeed = MnemonicSeed::Write(seed);

        vector<unsigned char> vchCryptedSecret;
        if (!CCrypter::EncryptSecret(m_vMasterKey, vchSeed, seedFp, vchCryptedSecret)) {
            error = "Failed to encrypt mnemonic seed";
            return false;
        }
        m_encryptedMnemonicSeed = make_pair(seedFp, vchCryptedSecret);
    } catch (const exception &e) {
        error = e.what();
        return false;
    }
    return true;
}

void CHDWallet::Lock() {
    memory_cleanse(&m_vMasterKey[0], m_vMasterKey.size());
    m_vMasterKey.clear();
}


void CHDWallet::Unlock(const SecureString &strPassphrase) {
    if (strPassphrase.empty())
        throw runtime_error("Passphrase is empty");
    if (m_encryptedMasterKey.vchCryptedKey.size() != WALLET_CRYPTO_KEY_SIZE + AES_BLOCKSIZE) // doesn't exist
        throw runtime_error("Master key doesn't exist");
    if (m_vMasterKey.size() == WALLET_CRYPTO_KEY_SIZE)  // already unlocked
        return;

    CCrypter crypter;
    if (!crypter.SetKeyFromPassphrase(strPassphrase, m_encryptedMasterKey.vchSalt,
                                      m_encryptedMasterKey.nDeriveIterations, m_encryptedMasterKey.nDerivationMethod))
        throw runtime_error("Failed to set key from passphrase");
    if (!crypter.Decrypt(m_encryptedMasterKey.vchCryptedKey, m_vMasterKey))
        throw runtime_error("Failed to decrypt master key");
}

[[nodiscard]] optional<MnemonicSeed> CHDWallet::getDecryptedMnemonicSeed() const noexcept {
    if (m_encryptedMnemonicSeed.second.empty()) {
        return nullopt;
    }

    CKeyingMaterial vchSecret;

    // Use seed's fingerprint as IV
    if (CCrypter::DecryptSecret(m_vMasterKey, m_encryptedMnemonicSeed.second, m_encryptedMnemonicSeed.first,
                                vchSecret)) {
        auto seed = MnemonicSeed::Read(vchSecret);
        if (seed.Fingerprint() == m_encryptedMnemonicSeed.first) {
            return seed;
        }
    }
    return nullopt;
}

[[nodiscard]] string CHDWallet::MakeNewAddress() {
    auto size = m_addressIndexMap.size();
    return getAddressByIndex(size, true);
}

[[nodiscard]] string CHDWallet::GetAddress(uint32_t addrIndex) {
    return getAddressByIndex(addrIndex, false);
}

[[nodiscard]] string CHDWallet::getAddressByIndex(uint32_t addrIndex, bool bCreateNew) {
    if (m_indexAddressMap.contains(addrIndex)) {
        return m_indexAddressMap[addrIndex];
    }

    if (!bCreateNew) {
        throw runtime_error("Address not found");
    }

    auto key = GetAddressKey(addrIndex);

    // Get and encode public key
    const auto pubKey = key->GetPubKey();
    const auto keyID = pubKey.GetID();
    auto strPubKey = encodeAddress(keyID, m_NetworkParams);
    m_addressIndexMap[strPubKey] = addrIndex;
    m_indexAddressMap[addrIndex] = strPubKey;
    return strPubKey;
}


[[nodiscard]] string CHDWallet::GetNewLegacyAddress() {
    CKey secret;
    secret.MakeNewKey(true);

    const CPubKey newKey = secret.GetPubKey();
    if (!secret.VerifyPubKey(newKey)) {
        throw runtime_error("Failed to verify public key");
    }

    // Get and encode public key
    const CKeyID keyID = newKey.GetID();
    auto strPubKey = encodeAddress(keyID, m_NetworkParams);
    m_addressMapNonHD[strPubKey] = secret;
    return strPubKey;
}

[[nodiscard]] optional<CKey> CHDWallet::GetAddressKey(const string &address) {
    auto addrIndex = m_addressIndexMap[address];
    return GetAddressKey(addrIndex);
}

[[nodiscard]] optional<CKey> CHDWallet::GetAddressKey(uint32_t addrIndex) const {
    auto extKey = getExtKey(addrIndex);
    auto key = extKey.value().key;
    return key;
}

[[nodiscard]] vector<string> CHDWallet::GetAddresses() const {
    vector<string> addresses;
    addresses.reserve(m_addressIndexMap.size());
    for (const auto &pair: m_addressIndexMap) {
        addresses.push_back(pair.first);
    }
    return addresses;
}

[[nodiscard]] string CHDWallet::SignWithAddressKey(const string& address, const string& message, bool fBase64){
    if (!m_addressIndexMap.contains(address)) {
        throw runtime_error("Address not found");
    }
    //if (!m_addressMapNonHD.contains(address)) // TODO: support non-HD addresses

    auto key = GetAddressKey(m_addressIndexMap[address]);
    if (!key.has_value()) {
        throw runtime_error("Failed to get account key");
    }

    uint256 hash;
    CHash256().Write((unsigned char *) message.data(), message.size()).Finalize(hash.begin());
    v_uint8 vchSig;
    if (key.value().Sign(hash, vchSig)) {
        if (fBase64) {
            return Botan::base64_encode(vchSig);
        } else {
            return string(vchSig.begin(), vchSig.end());
        }
    }
    return "";
}

[[nodiscard]] optional<CExtKey> CHDWallet::getExtKey(uint32_t addrIndex) const {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }

    auto accountKey = getAccountKey();
    if (!accountKey.has_value()) {
        throw runtime_error("Failed to get account key");
    }
    auto extKey = accountKey.value().Derive(addrIndex);
    accountKey.value().Clear();
    if (!extKey.has_value()) {
        throw runtime_error("Failed to get new address");
    }
    return extKey;
}

[[nodiscard]] optional<AccountKey> CHDWallet::getAccountKey() const noexcept {
    auto seed = getDecryptedMnemonicSeed();
    if (!seed.has_value()) {
        return nullopt;
    }
    return AccountKey::MakeAccount(seed.value(), m_NetworkParams->bip44CoinType, 0);
}

void CHDWallet::setNetworkParams(NetworkMode mode) {
    switch (mode) {
        case NetworkMode::MAINNET:
            m_NetworkParams = new CMainnetParams();
            break;
        case NetworkMode::TESTNET:
            m_NetworkParams = new CTestnetParams();
            break;
        case NetworkMode::REGTEST:
            m_NetworkParams = new CRegtestParams();
            break;
        default:
            throw runtime_error("Invalid network mode");
    }
}

string CHDWallet::encodeAddress(const CKeyID &id, const CChainParams *network) noexcept {
    v_uint8 pubKey = network->Base58Prefix(CChainParams::Base58Type::PUBKEY_ADDRESS);
    pubKey.insert(pubKey.end(), id.begin(), id.end());
    return EncodeBase58Check(pubKey);
}

string CHDWallet::encodeExtPubKey(const CExtPubKey &key, const CChainParams *network) noexcept {
    v_uint8 data = network->Base58Prefix(CChainParams::Base58Type::EXT_PUBLIC_KEY);
    const size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    string ret = EncodeBase58Check(data);
    return ret;
}

CExtPubKey CHDWallet::decodeExtPubKey(const string &str, const CChainParams *network) noexcept {
    CExtPubKey key;
    v_uint8 data;
    if (DecodeBase58Check(str, data)) {
        const auto &prefix = network->Base58Prefix(CChainParams::Base58Type::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && equal(prefix.begin(), prefix.end(), data.begin()))
            key.Decode(data.data() + prefix.size());
    }
    return key;
}

v_uint8 CHDWallet::makePastelIDSeed(uint32_t addrIndex, PastelIDType type) {
    try {
        auto addressKey1 = GetAddressKey(addrIndex);
        if (!addressKey1.has_value()) {
            throw runtime_error(fmt::format("Failed to get key at index {}", addrIndex));
        }
        auto privateKey1 = addressKey1.value().GetPrivKey();
        auto addrIndex2 = HARDENED_KEY_LIMIT + addrIndex;
        auto addressKey2 = GetAddressKey(addrIndex2);
        if (!addressKey2.has_value()) {
            throw runtime_error(fmt::format("Failed to get key at index {}", addrIndex2));
        }
        auto privateKey2 = addressKey2.value().GetPrivKey();

        auto hmacKey = (type == PastelIDType::PASTELID) ? privateKey1 : privateKey2;
        auto hmacMsg = (type == PastelIDType::PASTELID) ? privateKey2 : privateKey1;

        std::vector<unsigned char> hmac_result(CHMAC_SHA512::OUTPUT_SIZE);
        CHMAC_SHA512(hmacKey.data(), hmacKey.size())
                .Write(hmacMsg.data(), hmacMsg.size())
                .Finalize(hmac_result.data());

        std::string shake_name = fmt::format("SHAKE-128({})", ED448_LEN * 8);
        std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(shake_name));
        if (!hash) {
            throw runtime_error(fmt::format("Failed to hash keys for indexes {0}:{1}", addrIndex, addrIndex2));
        }
        hash->update(hmac_result);
        Botan::secure_vector<uint8_t> output_data = hash->final();
        if (output_data.size() != ED448_LEN) {
            output_data.resize(ED448_LEN);
        }
        return {output_data.begin(), output_data.end()};
    } catch (const exception &e) {
        throw runtime_error(e.what());
    }
}

[[nodiscard]] string CHDWallet::MakeNewPastelID() {
    try {
        auto newIndex = m_pastelIDIndexMap.size();
        const key_dsa448 key = key_dsa448::generate_key(makePastelIDSeed(newIndex, PastelIDType::PASTELID));
        auto pastelID = CPastelID::EncodePastelID(key.public_key_raw());

        CLegRoast<algorithm::Legendre_Middle> legRoastKey;
        legRoastKey.keygen(makePastelIDSeed(newIndex, PastelIDType::LEGROAST));
        auto legRoastPubKey = CPastelID::EncodeLegRoastPubKey(legRoastKey.get_public_key());

        m_pastelIDIndexMap[pastelID] = newIndex;
        m_indexPastelIDMap[newIndex] = pastelID;
        m_pastelIDLegRoastMap[pastelID] = legRoastPubKey;

        return pastelID;

    } catch (const crypto_exception &ex) {
        throw runtime_error(ex.what());
    }
}

string CHDWallet::GetPastelID(uint32_t addrIndex, PastelIDType type) {
    if (m_indexPastelIDMap.contains(addrIndex)) {
        auto pastelID = m_indexPastelIDMap[addrIndex];
        if (type == PastelIDType::PASTELID) {
            return pastelID;
        } else if (type == PastelIDType::LEGROAST) {
            return m_pastelIDLegRoastMap[pastelID];
        } else {
            throw runtime_error("Invalid PastelID type");
        }
    }
    throw runtime_error("PastelID not found");
}

string CHDWallet::GetPastelID(const string &pastelID, PastelIDType type) {
    if (m_pastelIDIndexMap.contains(pastelID)) {
        if (type == PastelIDType::PASTELID) {
            return pastelID;
        } else if (type == PastelIDType::LEGROAST) {
            return m_pastelIDLegRoastMap[pastelID];
        } else {
            throw runtime_error("Invalid PastelID type");
        }
    }
    throw runtime_error("PastelID not found");
}

[[nodiscard]] v_uint8 CHDWallet::GetPastelIDKey(uint32_t addrIndex, PastelIDType type) {
    if (m_indexPastelIDMap.contains(addrIndex)) {
        if (type == PastelIDType::PASTELID) {
            const key_dsa448 key = key_dsa448::generate_key(makePastelIDSeed(addrIndex, PastelIDType::PASTELID));
            return key.private_key_raw();
        } else if (type == PastelIDType::LEGROAST) {
            CLegRoast<algorithm::Legendre_Middle> LegRoastKey;
            LegRoastKey.keygen(makePastelIDSeed(addrIndex, PastelIDType::LEGROAST));
            return LegRoastKey.get_private_key();
        } else {
            throw runtime_error("Invalid PastelID type");
        }
    }
    throw runtime_error("PastelID not found");
}

[[nodiscard]] v_uint8 CHDWallet::GetPastelIDKey(const string &pastelID, PastelIDType type) {
    if (m_pastelIDIndexMap.contains(pastelID)) {
        return GetPastelIDKey(m_pastelIDIndexMap[pastelID], type);
    }
    if (m_externalPastelIDs.contains(pastelID)) {
        auto externalPastelID = m_externalPastelIDs[pastelID];
        v_uint8 key;
        if (type == PastelIDType::PASTELID) {
            DecryptWithMasterKey(externalPastelID.m_encryptedPastelIDKey.second,
                                 externalPastelID.m_encryptedPastelIDKey.first, key);
        } else if (type == PastelIDType::LEGROAST) {
            DecryptWithMasterKey(externalPastelID.m_encryptedLegRoastKey.second,
                                 externalPastelID.m_encryptedLegRoastKey.first, key);
        }
        return key;
    }
    throw runtime_error("PastelID key not found");
}

[[nodiscard]] vector<string> CHDWallet::GetPastelIDs() const {
    vector<string> pastelIDs;
    pastelIDs.reserve(m_pastelIDIndexMap.size() + m_externalPastelIDs.size());
    for (const auto &pair: m_pastelIDIndexMap) {
        pastelIDs.push_back(pair.first);
    }
    for (const auto &pair: m_externalPastelIDs) {
        pastelIDs.push_back(pair.first);
    }
    return pastelIDs;
}

[[nodiscard]] string CHDWallet::SignWithPastelID(const string& pastelID, const string& message, PastelIDType type, bool fBase64){
    if (!m_pastelIDIndexMap.contains(pastelID))
        throw runtime_error("PastelID not found");
    auto addrIndex = m_pastelIDIndexMap[pastelID];

    if (type == PastelIDType::PASTELID) {
        const auto key = key_dsa448::generate_key(makePastelIDSeed(addrIndex, PastelIDType::PASTELID));
        auto sigBuf = ed_crypto::crypto_sign::sign(message, key);
        if (fBase64) {
            return Botan::base64_encode(sigBuf);
        } else {
            return {sigBuf.begin(), sigBuf.end()};
        }
    } else if (type == PastelIDType::LEGROAST) {
        CLegRoast<algorithm::Legendre_Middle> LegRoastKey;
        LegRoastKey.keygen(makePastelIDSeed(addrIndex, PastelIDType::LEGROAST));
        string error;
        if (!LegRoastKey.sign(error, reinterpret_cast<const unsigned char*>(message.data()), message.length()))
            throw runtime_error(fmt::format("Failed to sign text message with the LegRoast private key. {}", error));
        auto sigBuf = LegRoastKey.get_signature();
        if (fBase64)
            return Botan::base64_encode(reinterpret_cast<const unsigned char*>(sigBuf.data()), sigBuf.length());
        return {sigBuf.begin(), sigBuf.end()};
    } else {
        throw runtime_error("Invalid PastelID type");
    }

}
[[nodiscard]] bool CHDWallet::VerifyWithPastelID(const string& pastelID, const string& message, const string& signature, bool fBase64){
    v_uint8 vRawPubKey;
    if (!CPastelID::DecodePastelID(pastelID, vRawPubKey))
        throw runtime_error("Invalid PastelID");

    auto key = ed_crypto::key_dsa448::create_from_raw_public(vRawPubKey);
    if (fBase64)
        return ed_crypto::crypto_sign::verify_base64(message, signature, key);
    else
        return ed_crypto::crypto_sign::verify(message, signature, key);

}
[[nodiscard]] bool CHDWallet::VerifyWithLegRoast(const string& lrPubKey, const string& message, const string& signature, bool fBase64){
    v_uint8 vLRPubKey;
    if (!CPastelID::DecodeLegRoastPubKey(lrPubKey, vLRPubKey))
        throw runtime_error("Invalid LegRoast Public key");

    string error;
    CLegRoast<algorithm::Legendre_Middle> LegRoast;
    if (!LegRoast.set_public_key(error, vLRPubKey.data(), vLRPubKey.size()))
        throw runtime_error(error);

    if (fBase64) {
        auto b64Sign = Botan::base64_decode(signature);
        if (!LegRoast.set_signature(error, {b64Sign.begin(), b64Sign.end()}))
            throw runtime_error(error);
    } else {
        if (!LegRoast.set_signature(error, reinterpret_cast<const unsigned char*>(signature.data()), signature.size()))
            throw runtime_error(error);
    }
    return LegRoast.verify(error, reinterpret_cast<const unsigned char*>(message.data()), message.size());
}

[[nodiscard]] bool CHDWallet::AddExternalPastelID() {
//    auto pKey = LegRoastKey.get_private_key();
//    auto fingerprint = CPastelID::LegRoastFingerprint(pKey);
//    EncryptWithMasterKey(pKey, uint256(), legroast);
    return true;
}

void CHDWallet::ExportPastelIDKeys(const string& pastelID, SecureString&& passPhrase, const string& sDirPath){
    auto keyBufPastelID = GetPastelIDKey(pastelID, PastelIDType::PASTELID);
    auto keyBufLegRoast = GetPastelIDKey(pastelID, PastelIDType::LEGROAST);
    auto legRoastPubKey = GetPastelID(pastelID, PastelIDType::LEGROAST);
    CPastelID::CreatePastelKeysFile(sDirPath, std::move(passPhrase),
                                    pastelID, legRoastPubKey, keyBufPastelID, keyBufLegRoast);
}

bool CHDWallet::EncryptWithMasterKey(const v_uint8 &data, const uint256 &nIV, v_uint8 &encryptedData) const {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }
    if (!CCrypter::EncryptSecret(m_vMasterKey, data, nIV, encryptedData)) {
        throw runtime_error("Failed to encrypt data with master key");
    }
    return true;
}

bool CHDWallet::DecryptWithMasterKey(const v_uint8 &encryptedData, const uint256 &nIV, v_uint8 &data) const {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }
    if (!CCrypter::DecryptSecret(m_vMasterKey, encryptedData, nIV, data)) {
        throw runtime_error("Failed to decrypt data with master key");
    }
    return true;
}

[[nodiscard]] string CHDWallet::GetWalletPubKey() {
    return GetPubKeyAt(m_NetworkParams->walletIDIndex);
}

[[nodiscard]] string CHDWallet::SignWithWalletKey(string message) {
    return SignWithKeyAt(m_NetworkParams->walletIDIndex, std::move(message));
}

[[nodiscard]] string CHDWallet::GetPubKeyAt(uint32_t addrIndex) const {
    auto key = GetAddressKey(addrIndex);
    if (!key.has_value()) {
        throw runtime_error("Failed to get key");
    }
    auto pubKey = key->GetPubKey();
    return EncodeBase58(pubKey.begin(), pubKey.end());
}

[[nodiscard]] string CHDWallet::SignWithKeyAt(uint32_t addrIndex, string message) {
    auto key = GetAddressKey(addrIndex);
    if (!key.has_value()) {
        throw runtime_error("Failed to get account key");
    }

    uint256 hash;
    CHash256().Write((unsigned char *) message.data(), message.size()).Finalize(hash.begin());
    v_uint8 vchSig;
    if (key.value().Sign(hash, vchSig)) {
        return EncodeBase58(vchSig);
    }
    return "";
}

