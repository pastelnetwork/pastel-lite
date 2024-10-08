// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <sodium.h>
#include <botan/hash.h>

#include "key_io.h"
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
#include "pastelid/common.h"
#include "pastelid/secure_container.h"

using namespace legroast;
using namespace crypto_helpers;
using namespace secure_container;

// Wallet functions
string CHDWallet::SetupNewWallet(const SecureString &password) {
    return setupNewWalletImpl(password, []() -> std::optional<MnemonicSeed> {
        return MnemonicSeed::Random(CChainParams().BIP44CoinType(), Language::English);
    });
}
[[nodiscard]] string CHDWallet::SetupNewWalletFromMnemonic(const SecureString& password, const SecureString& mnemonic) {
    if (mnemonic.empty()) {
        throw runtime_error("Mnemonic is empty");
    }
    return setupNewWalletImpl(password, [&mnemonic]() -> std::optional<MnemonicSeed> {
        return MnemonicSeed::FromPhrase(Language::English, mnemonic).value();
    });
}

string CHDWallet::setupNewWalletImpl(const SecureString &password, const std::function<std::optional<MnemonicSeed>()>& getSeed) {
    // Generate a new random master key and encrypt it using a key derived from password
    string error;
    if (!setMasterKey(password, error)) {
        stringstream ss;
        ss << "Failed to set master key: " << error.c_str();
        throw runtime_error(ss.str());
    }

    MnemonicSeed seed = getSeed().value();
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

[[nodiscard]] optional<MnemonicSeed> CHDWallet::getDecryptedMnemonicSeed() noexcept {
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

// Address-specific functions
[[nodiscard]] string CHDWallet::MakeNewAddress(NetworkMode mode) {
    auto addrIndex = m_keyIdIndexMap.size();
    if (m_indexKeyIdMap.contains(addrIndex)) {
        return encodeAddress(m_indexKeyIdMap[addrIndex], mode);
    }
    auto key = _getDerivedKeyAt(addrIndex);

    // Get and encode public key
    const auto pubKey = key->GetPubKey();
    const auto keyID = pubKey.GetID();

    m_keyIdIndexMap[keyID] = addrIndex;
    m_indexKeyIdMap[addrIndex] = keyID;

    return encodeAddress(keyID, mode);
}

[[nodiscard]] string CHDWallet::GetAddress(uint32_t addrIndex, NetworkMode mode) {
    if (m_indexKeyIdMap.contains(addrIndex)) {
        return encodeAddress(m_indexKeyIdMap[addrIndex], mode);
    }
    throw runtime_error("Address not found");
}

[[nodiscard]] uint32_t CHDWallet::GetAddressesCount() {
    return m_keyIdIndexMap.size();
}

[[nodiscard]] vector<string> CHDWallet::GetAddresses(NetworkMode mode) {
    vector<string> addresses;
    addresses.reserve(m_keyIdIndexMap.size());
    for (const auto& key : m_keyIdIndexMap | views::keys) {
        addresses.push_back(encodeAddress(key, mode));
    }
    for (const auto& key : m_addressMapLegacy | views::keys) {
        addresses.push_back(key);
    }
    return addresses;
}

[[nodiscard]] string CHDWallet::MakeNewLegacyAddress(NetworkMode mode) {
    CKey secret;
    secret.MakeNewKey(true);

    const CPubKey newKey = secret.GetPubKey();
    if (!secret.VerifyPubKey(newKey)) {
        throw runtime_error("Failed to verify public key");
    }

    // Get and encode public key
    const CKeyID keyID = newKey.GetID();
    auto strAddress = encodeAddress(keyID, mode);
    m_addressMapLegacy[strAddress] = secret;
    return strAddress;
}

[[nodiscard]] string CHDWallet::ImportLegacyPrivateKey(const string& encoded_key, NetworkMode mode) {
    string error;
    KeyIO keyIO(GetChainParams(mode));
    const auto secret = keyIO.DecodeSecret(encoded_key, error);
    if (!secret.IsValid()) {
        throw runtime_error(fmt::format("Failed to decode secret {}", error));
    }

    const CPubKey newKey = secret.GetPubKey();
    if (!secret.VerifyPubKey(newKey)) {
        throw runtime_error("Failed to verify public key");
    }

    // Get and encode public key
    const CKeyID keyID = newKey.GetID();
    auto strAddress = encodeAddress(keyID, mode);
    m_addressMapLegacy[strAddress] = secret;
    return strAddress;
}

// PastelID specific functions
[[nodiscard]] string CHDWallet::MakeNewPastelID(bool makeLegRoast) {
    try {
        auto newIndex = m_pastelIDIndexMap.size();
        auto pastelID = ed448_pubkey_encoded(makePastelIDSeed(newIndex, PastelIDType::PASTELID));
        m_pastelIDIndexMap[pastelID] = newIndex;
        m_indexPastelIDMap[newIndex] = pastelID;

        if (makeLegRoast) {
            auto legRoastPubKey = legroast_pubkey_encoded(makePastelIDSeed(newIndex, PastelIDType::LEGROAST));
            m_pastelIDLegRoastMap[pastelID] = legRoastPubKey;
        }

        return pastelID;

    } catch (const crypto_exception &ex) {
        throw runtime_error(ex.what());
    }
}

string CHDWallet::GetPastelID(uint32_t pastelIDIndex, PastelIDType type) {
    if (m_indexPastelIDMap.contains(pastelIDIndex)) {
        auto pastelID = m_indexPastelIDMap[pastelIDIndex];
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
        }
        if (type == PastelIDType::LEGROAST) {
            return m_pastelIDLegRoastMap[pastelID];
        }
        throw runtime_error("Invalid PastelID type");
    }
    if (m_externalPastelIDs.contains(pastelID)) {
        if (type == PastelIDType::PASTELID) {
            return pastelID;
        }
        if (type == PastelIDType::LEGROAST) {
            return m_externalPastelIDs[pastelID].m_legRoastPubKey;
        }
        throw runtime_error("Invalid PastelID type");
    }
    throw runtime_error("PastelID not found");
}

[[nodiscard]] vector<string> CHDWallet::GetPastelIDs() {
    vector<string> pastelIDs;
    pastelIDs.reserve(m_pastelIDIndexMap.size() + m_externalPastelIDs.size());
    for (const auto& key : m_pastelIDIndexMap | views::keys) {
        pastelIDs.push_back(key);
    }
    for (const auto& key : m_externalPastelIDs | views::keys) {
        pastelIDs.push_back(key);
    }
    return pastelIDs;
}

[[nodiscard]] string CHDWallet::SignWithPastelID(const string& pastelID, const string& message, PastelIDType type, bool fBase64){
    if (m_pastelIDIndexMap.contains(pastelID))
    {
        const auto pastelIDIndex = m_pastelIDIndexMap[pastelID];
        if (type == PastelIDType::PASTELID) {
            return ed448_sign(makePastelIDSeed(pastelIDIndex, PastelIDType::PASTELID), message, fBase64? encoding::base64 : encoding::none);
        }
        if (type == PastelIDType::LEGROAST) {
            return legroast_sign(makePastelIDSeed(pastelIDIndex, PastelIDType::LEGROAST), message, fBase64? encoding::base64 : encoding::none);
        }
        throw runtime_error("Invalid PastelID type");
    }
    if (m_externalPastelIDs.contains(pastelID)) {
        auto key = _getPastelIDKey(pastelID, type);
        if (type == PastelIDType::PASTELID) {
            return ed448_sign(std::move(key), message, fBase64? encoding::base64 : encoding::none);
        }
        if (type == PastelIDType::LEGROAST) {
            return legroast_sign(std::move(key), message, fBase64? encoding::base64 : encoding::none);
        }
        throw runtime_error("Invalid PastelID type");
    }
    throw runtime_error("PastelID not found");
}

[[nodiscard]] bool CHDWallet::VerifyWithPastelID(const string& pastelID, const string& message, const string& signature, bool fBase64){
    return ed448_verify(pastelID, message, signature, fBase64? encoding::base64 : encoding::hex);
}

[[nodiscard]] bool CHDWallet::VerifyWithLegRoast(const string& lrPubKey, const string& message, const string& signature, bool fBase64){
    return legroast_verify(lrPubKey, message, signature, fBase64? encoding::base64 : encoding::hex);
}

[[nodiscard]] bool CHDWallet::ImportPastelIDKeys(const string& pastelID, SecureString&& password, const string& pastelIDDir) {
    const std::filesystem::path dir(pastelIDDir);
    const std::filesystem::path file(pastelID);
    const std::filesystem::path full_path = dir / file;

    CSecureContainer cont;
    cont.read_from_file(full_path.string(), password);
    auto pk_legroast = cont.extract_secure_data(SECURE_ITEM_TYPE::pkey_legroast);
    auto pk_ed448 = cont.extract_secure_data(SECURE_ITEM_TYPE::pkey_ed448);
    string pub_legroast;
    cont.get_public_data(PUBLIC_ITEM_TYPE::pubkey_legroast, pub_legroast);

    auto fp_legroast = CPastelID::LegRoastFingerprint(pk_legroast);
    auto fp_ed448 = CPastelID::PastelIDFingerprint(pk_ed448);

    v_uint8 enc_pk_legroast, enc_pk_ed448;
    encryptWithMasterKey(pk_legroast, fp_legroast, enc_pk_legroast);
    encryptWithMasterKey(pk_ed448, fp_ed448, enc_pk_ed448);

    m_externalPastelIDs[pastelID] = external_pastel_id{
        {fp_ed448, enc_pk_ed448},
        {fp_legroast, enc_pk_legroast},
        pub_legroast
    };

    return true;
}

void CHDWallet::ExportPastelIDKeys(const string& pastelID, SecureString&& passPhrase, const string& sDirPath){
    auto keyBufPastelID = _getPastelIDKey(pastelID, PastelIDType::PASTELID);
    auto keyBufLegRoast = _getPastelIDKey(pastelID, PastelIDType::LEGROAST);
    auto legRoastPubKey = GetPastelID(pastelID, PastelIDType::LEGROAST);
    CPastelID::CreatePastelKeysFile(sDirPath, std::move(passPhrase),
                                    pastelID, legRoastPubKey, keyBufPastelID, keyBufLegRoast);
}

// Account-specific functions
[[nodiscard]] string CHDWallet::GetWalletPubKey() {
    return GetPubKeyAt(m_walletIDIndex);
}

[[nodiscard]] string CHDWallet::SignWithWalletKey(string message) {
    return SignWithKeyAt(m_walletIDIndex, std::move(message));
}

[[nodiscard]] string CHDWallet::GetPubKeyAt(uint32_t addrIndex) {
    auto key = _getDerivedKeyAt(addrIndex);
    if (!key.has_value()) {
        throw runtime_error("Failed to get key");
    }
    auto pubKey = key->GetPubKey();
    return EncodeBase58(pubKey.begin(), pubKey.end());
}

[[nodiscard]] string CHDWallet::SignWithKeyAt(uint32_t addrIndex, string message) {
    auto key = _getDerivedKeyAt(addrIndex);
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

// Key functions
[[nodiscard]] string CHDWallet::GetSecret(uint32_t addrIndex, NetworkMode mode){
    auto key = _getDerivedKeyAt(addrIndex);
    if (key.has_value()) {
        KeyIO keyIO(GetChainParams(mode));
        return keyIO.EncodeSecret(key.value());
    }
    return "";
}

[[nodiscard]] string CHDWallet::GetSecret(const string& address, NetworkMode mode) {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }

    auto keyID = decodeAddress(address, mode);
    if (keyID.has_value()) {
        KeyIO keyIO(GetChainParams(mode));
        if (auto key = _getDerivedKey(keyID.value()); key.has_value()) {
            return keyIO.EncodeSecret(key.value());
        }
        if (m_addressMapLegacy.contains(address)) {
            return keyIO.EncodeSecret(m_addressMapLegacy[address]);
        }
    }
    throw runtime_error("Address not found");
}

[[nodiscard]] optional<CKey> CHDWallet::_getDerivedKeyAt(uint32_t addrIndex) {
    auto extKey = getExtKey(addrIndex);
    auto key = extKey.value().key;
    return key;
}

[[nodiscard]] optional<CKey> CHDWallet::_getDerivedKey(const CKeyID& keyID) {
    if (m_keyIdIndexMap.contains(keyID)) {
        return _getDerivedKeyAt(m_keyIdIndexMap[keyID]);
    }
    return nullopt;
}

[[nodiscard]] std::optional<CKey> CHDWallet::_getLegacyKey(const CKeyID& keyID) {
    auto address = encodeAddress(keyID, NetworkMode::MAINNET);
    if (m_addressMapLegacy.contains(address)) {
        return m_addressMapLegacy[address];
    }
    return nullopt;
}

[[nodiscard]] optional<CPubKey> CHDWallet::_getPubKey(const CKeyID& keyID) {
    if (m_keyIdIndexMap.contains(keyID)) {
        auto key = _getDerivedKeyAt(m_keyIdIndexMap[keyID]);
        if (key.has_value())
            return key->GetPubKey();
    }
    return nullopt;
}

[[nodiscard]] optional<CExtKey> CHDWallet::getExtKey(uint32_t addrIndex) {
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

[[nodiscard]] optional<AccountKey> CHDWallet::getAccountKey() noexcept {
    auto seed = getDecryptedMnemonicSeed();
    if (!seed.has_value()) {
        return nullopt;
    }
    return AccountKey::MakeAccount(seed.value(), m_bip44CoinType, 0);
}

[[nodiscard]] const v_uint8& CHDWallet::getNetworkPrefix(NetworkMode mode, const CChainParams::Base58Type type) {
    switch (mode) {
        case NetworkMode::MAINNET:
            return m_mainnetParams.Base58Prefix(type);
        case NetworkMode::TESTNET:
            return m_testnetParams.Base58Prefix(type);
        case NetworkMode::DEVNET:
            return m_devnetParams.Base58Prefix(type);
        default:
            throw runtime_error("Invalid network mode");
    }
}

string CHDWallet::encodeAddress(const CKeyID &id, NetworkMode mode) noexcept {
    v_uint8 pubKey = getNetworkPrefix(mode, CChainParams::Base58Type::PUBKEY_ADDRESS);
    pubKey.insert(pubKey.end(), id.begin(), id.end());
    return EncodeBase58Check(pubKey);
}

optional<CKeyID> CHDWallet::decodeAddress(const string& address, NetworkMode mode) noexcept {
    KeyIO keyIO(GetChainParams(mode));
    if (auto destination = keyIO.DecodeDestination(address); IsKeyDestination(destination)){
        return std::get<CKeyID>(destination);
    }
    return nullopt;
}

string CHDWallet::encodeExtPubKey(const CExtPubKey &key, NetworkMode mode) noexcept {
    v_uint8 data = getNetworkPrefix(mode, CChainParams::Base58Type::EXT_PUBLIC_KEY);
    const size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    string ret = EncodeBase58Check(data);
    return ret;
}

CExtPubKey CHDWallet::decodeExtPubKey(const string &str, NetworkMode mode) noexcept {
    CExtPubKey key;
    v_uint8 data;
    if (DecodeBase58Check(str, data)) {
        const auto &prefix = getNetworkPrefix(mode, CChainParams::Base58Type::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && equal(prefix.begin(), prefix.end(), data.begin()))
            key.Decode(data.data() + prefix.size());
    }
    return key;
}

v_uint8 CHDWallet::makePastelIDSeed(uint32_t addrIndex, PastelIDType type) {
    try {
        auto addressKey1 = _getDerivedKeyAt(addrIndex);
        if (!addressKey1.has_value()) {
            throw runtime_error(fmt::format("Failed to get key at index {}", addrIndex));
        }
        auto privateKey1 = addressKey1.value().GetPrivKey();
        auto addrIndex2 = HARDENED_KEY_LIMIT + addrIndex;
        auto addressKey2 = _getDerivedKeyAt(addrIndex2);
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
[[nodiscard]] v_uint8 CHDWallet::_getPastelIDKey(uint32_t pastelIDIndex, PastelIDType type) {
    if (m_indexPastelIDMap.contains(pastelIDIndex)) {
        if (type == PastelIDType::PASTELID) {
            return ed448_privkey(makePastelIDSeed(pastelIDIndex, PastelIDType::PASTELID));
        }
        if (type == PastelIDType::LEGROAST) {
            return legroast_privkey(makePastelIDSeed(pastelIDIndex, PastelIDType::LEGROAST));
        }
        throw runtime_error("Invalid PastelID type");
    }
    throw runtime_error("PastelID not found");
}

[[nodiscard]] v_uint8 CHDWallet::_getPastelIDKey(const string &pastelID, PastelIDType type) {
    if (m_pastelIDIndexMap.contains(pastelID)) {
        return _getPastelIDKey(m_pastelIDIndexMap[pastelID], type);
    }
    if (m_externalPastelIDs.contains(pastelID)) {
        auto externalPastelID = m_externalPastelIDs[pastelID];
        v_uint8 key;
        if (type == PastelIDType::PASTELID) {
            decryptWithMasterKey(externalPastelID.m_encryptedPastelIDKey.second,
                                 externalPastelID.m_encryptedPastelIDKey.first, key);
        } else if (type == PastelIDType::LEGROAST) {
            decryptWithMasterKey(externalPastelID.m_encryptedLegRoastKey.second,
                                 externalPastelID.m_encryptedLegRoastKey.first, key);
        } else {
            throw runtime_error("Invalid PastelID type");
        }
        return key;
    }
    throw runtime_error("PastelID key not found");
}

bool CHDWallet::encryptWithMasterKey(const v_uint8 &data, const uint256 &nIV, v_uint8 &encryptedData) {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }
    if (!CCrypter::EncryptSecret(m_vMasterKey, data, nIV, encryptedData)) {
        throw runtime_error("Failed to encrypt data with master key");
    }
    return true;
}

bool CHDWallet::decryptWithMasterKey(const v_uint8 &encryptedData, const uint256 &nIV, v_uint8 &data) {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }
    if (!CCrypter::DecryptSecret(m_vMasterKey, encryptedData, nIV, data)) {
        throw runtime_error("Failed to decrypt data with master key");
    }
    return true;
}

