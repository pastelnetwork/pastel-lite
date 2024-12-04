// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <sodium.h>
#include <botan/hash.h>
#include <cstdio> 
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
    
    // Initialize state for unified address tracking
    m_lastHDIndex = 0;
    m_indexIsLegacy.clear();
    
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
    uint32_t addrIndex = getNextHDIndex();
    
    // Ensure this is marked as an HD address
    m_indexIsLegacy[addrIndex] = false;
    
    auto key = _getDerivedKeyAt(addrIndex);
    if (!key.has_value()) {
        throw runtime_error("Failed to derive key");
    }

    const auto pubKey = key->GetPubKey();
    const auto keyID = pubKey.GetID();
    
    m_keyIdIndexMap[keyID] = addrIndex;
    m_indexKeyIdMap[addrIndex] = keyID;
    
    return encodeAddress(keyID, mode);
}

[[nodiscard]] string CHDWallet::GetAddress(uint32_t addrIndex, NetworkMode mode) {
    if (!m_indexKeyIdMap.contains(addrIndex)) {
        throw runtime_error("Address index not found");
    }
    return encodeAddress(m_indexKeyIdMap[addrIndex], mode);
}

[[nodiscard]] uint32_t CHDWallet::GetAddressesCount() {
    return m_indexKeyIdMap.size();  // This now includes both HD and legacy
}

[[nodiscard]] vector<string> CHDWallet::GetAddresses(NetworkMode mode) {
    printf("Getting addresses for mode: %d\n", static_cast<int>(mode));
    vector<string> addresses;
    addresses.reserve(m_indexKeyIdMap.size());
    
    // Process all addresses in index order
    for (const auto& [index, keyID] : m_indexKeyIdMap) {
        auto address = encodeAddress(keyID, mode);
        printf("Adding address: %s (index: %u, legacy: %s)\n", 
               address.c_str(), 
               index, 
               m_indexIsLegacy.contains(index) ? "yes" : "no");
        addresses.push_back(address);
    }
    
    printf("Total addresses found: %zu\n", addresses.size());
    return addresses;
}

[[nodiscard]] string CHDWallet::MakeNewLegacyAddress(NetworkMode mode) {
    CKey secret;
    secret.MakeNewKey(true);

    // Verify key validity
    if (!secret.IsValid()) {
        throw runtime_error("Failed to generate valid key");
    }

    const CPubKey newKey = secret.GetPubKey();
    if (!secret.VerifyPubKey(newKey)) {
        throw runtime_error("Failed to verify public key");
    }

    // Get and encode public key
    const CKeyID keyID = newKey.GetID();
    auto strAddress = encodeAddress(keyID, mode);
    
    // Add to unified tracking system with verified key
    addImportedKeyToMaps(secret, strAddress);
    
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

    printf("Importing key for mode %d\n", static_cast<int>(mode));

    // Get and encode public key
    const CKeyID keyID = newKey.GetID();
    
    // Check if key already exists in HD wallet
    if (m_keyIdIndexMap.contains(keyID)) {
        printf("Key already exists in wallet\n");
        return encodeAddress(keyID, mode);
    }

    auto strAddress = encodeAddress(keyID, mode);
    printf("Generated address: %s\n", strAddress.c_str());
    
    // Add to unified tracking system
    addImportedKeyToMaps(secret, strAddress);
    
    return strAddress;
}

// Key management and derivation functions

std::optional<CKey> CHDWallet::getKeyFromLegacyOrHD(const CKeyID& keyID) {
    // First check legacy addresses
    for (const auto& [addr, serialKey] : m_addressMapLegacy) {
        CKey key = serialKey.GetKey();
        if (!key.IsValid()) {
            printf("Warning: Found invalid key in legacy map\n");
            continue;
        }
        if (key.GetPubKey().GetID() == keyID) {
            printf("Found key in legacy map\n");
            return key;
        }
    }
    
    // If not found in legacy, try HD derivation
    if (m_keyIdIndexMap.contains(keyID)) {
        const uint32_t index = m_keyIdIndexMap[keyID];
        // Skip HD derivation if this is a legacy key
        if (m_indexIsLegacy.contains(index) && m_indexIsLegacy[index]) {
            printf("ERROR: Legacy key not found in address map but marked as legacy\n");
            return std::nullopt;
        }
        // Only try HD derivation for non-legacy keys
        printf("Attempting HD key derivation for index %u\n", index);
        return _getDerivedKeyAt(index);
    }

    printf("Failed to find key for keyID\n");
    return std::nullopt;
}

[[nodiscard]] std::optional<CKey> CHDWallet::_getDerivedKeyAt(uint32_t addrIndex) {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }

    // First check if this is a legacy key index
    if (m_indexIsLegacy.contains(addrIndex) && m_indexIsLegacy[addrIndex]) {
        printf("Index %u is marked as legacy - searching in legacy map\n", addrIndex);
        // Need to find the corresponding legacy key
        for (const auto& [addr, serialKey] : m_addressMapLegacy) {
            CKey key = serialKey.GetKey();
            if (!key.IsValid()) continue;
            const auto keyID = key.GetPubKey().GetID();
            if (m_keyIdIndexMap.contains(keyID) && m_keyIdIndexMap[keyID] == addrIndex) {
                printf("Found legacy key for index %u\n", addrIndex);
                return key;
            }
        }
        printf("ERROR: No legacy key found for index %u\n", addrIndex);
        return std::nullopt;
    }

    // Only do HD derivation for non-legacy keys
    auto extKey = getExtKey(addrIndex);
    if (!extKey.has_value()) {
        return std::nullopt;
    }
    return extKey.value().key;
}

bool CHDWallet::initializeUnifiedAddressInfo(const CKeyID& keyID, const string& address) {
    printf("Initializing unified address info for: %s\n", address.c_str());
    
    // Look for key in legacy addresses first
    for (const auto& [addr, serialKey] : m_addressMapLegacy) {
        CKey key = serialKey.GetKey();
        if (!key.IsValid()) continue;
        
        if (key.GetPubKey().GetID() == keyID) {
            // Found in legacy map
            const auto it = m_keyIdIndexMap.find(keyID);
            if (it == m_keyIdIndexMap.end()) {
                printf("Error: Legacy key found but no index mapping\n");
                return false;
            }
            
            m_unifiedAddressMap[keyID] = {
                it->second,
                true,
                key
            };
            return true;
        }
    }

    // Try HD derivation if not found in legacy
    if (m_keyIdIndexMap.contains(keyID)) {
        const uint32_t index = m_keyIdIndexMap[keyID];
        if (!m_indexIsLegacy[index]) {
            auto derivedKey = _getDerivedKeyAt(index);
            if (derivedKey.has_value()) {
                m_unifiedAddressMap[keyID] = {
                    index,
                    false,
                    derivedKey.value()
                };
                return true;
            }
        }
    }

    printf("Failed to initialize unified address info\n");
    return false;
}

optional<CKey> CHDWallet::getKeyForAddress(const CKeyID& keyID, const string& address) {
    printf("getKeyForAddress called with keyID: %s and address: %s\n", keyID.ToString().c_str(), address.c_str());

    // First check unified map even if no address provided
    auto unifiedIt = m_unifiedAddressMap.find(keyID);
    if (unifiedIt != m_unifiedAddressMap.end()) {
        printf("Found key in unified address map\n");
        return unifiedIt->second.key;
    }

    // Always check legacy map regardless of address
    for (const auto& [addr, serialKey] : m_addressMapLegacy) {
        CKey key = serialKey.GetKey();
        if (!key.IsValid()) {
            printf("Warning: Found invalid key in legacy map for address: %s\n", addr.c_str());
            continue;
        }
        if (key.GetPubKey().GetID() == keyID) {
            printf("Found key in legacy map for address: %s\n", addr.c_str());
            return key;
        }
    }

    // Only try initialize if we have an address
    if (!address.empty()) {
        printf("Address provided, attempting to initialize unified address info\n");
        if (initializeUnifiedAddressInfo(keyID, address)) {
            unifiedIt = m_unifiedAddressMap.find(keyID);
            if (unifiedIt != m_unifiedAddressMap.end()) {
                printf("Successfully initialized and retrieved unified key\n"); 
                return unifiedIt->second.key;
            }
        }
    }

    printf("No key found for keyID: %s\n", keyID.ToString().c_str());
    return std::nullopt;
}

bool CHDWallet::validateKeyAccess(const CKeyID& keyID, const string& address) {
    auto key = getKeyForAddress(keyID, address);
    if (!key.has_value() || !key->IsValid()) {
        return false;
    }
    
    // Verify the key matches the address
    CPubKey pubKey = key->GetPubKey();
    return pubKey.GetID() == keyID;
}

[[nodiscard]] std::optional<CKey> CHDWallet::_getDerivedKey(const CKeyID& keyID) {
    printf("Getting key for keyID: %s\n", keyID.ToString().c_str());
    
    // First check if this key corresponds to a legacy imported address
    for (const auto& [addr, serialKey] : m_addressMapLegacy) {
        CKey key = serialKey.GetKey();
        if (!key.IsValid()) {
            printf("Warning: Found invalid key in legacy map\n");
            continue;
        }
        if (key.GetPubKey().GetID() == keyID) {
            printf("Successfully retrieved legacy key from address map\n");
            return key;
        }
    }
    
    // If no legacy key found and we have an index, try HD derivation
    if (m_keyIdIndexMap.contains(keyID)) {
        const uint32_t index = m_keyIdIndexMap[keyID];
        // Skip HD derivation if this is a legacy key
        if (m_indexIsLegacy.contains(index) && m_indexIsLegacy[index]) {
            printf("ERROR: Legacy key not found in address map but marked as legacy\n");
            return std::nullopt;
        }
        // Only try HD derivation for non-legacy keys
        printf("Attempting HD key derivation for index %u\n", index);
        return _getDerivedKeyAt(index);
    }

    printf("Failed to find key for keyID\n");
    return std::nullopt;
}

[[nodiscard]] optional<CPubKey> CHDWallet::_getPubKey(const CKeyID& keyID) {
    if (m_keyIdIndexMap.contains(keyID)) {
        auto key = _getDerivedKey(keyID);
        if (key.has_value() && key->IsValid()) {
            auto pubKey = key->GetPubKey();
            printf("Retrieved derived pubKey for keyID: %s\n", keyID.ToString().c_str());
            return pubKey;
        }
    }

    // Check legacy keys if not found in HD
    for (const auto& [address, serialKey] : m_addressMapLegacy) {
        CKey key = serialKey.GetKey();
        if (!key.IsValid()) {
            printf("Warning: Invalid legacy key found for address %s\n", address.c_str());
            continue;
        }
        if (key.GetPubKey().GetID() == keyID) {
            auto pubKey = key.GetPubKey();
            printf("Retrieved legacy pubKey for keyID: %s from address: %s\n", 
                   keyID.ToString().c_str(), address.c_str());
            return pubKey;
        }
    }

    printf("Failed to retrieve pubKey for keyID: %s\n", keyID.ToString().c_str());
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

[[nodiscard]] const v_uint8& CHDWallet::getNetworkPrefix(NetworkMode mode, CChainParams::Base58Type type) {
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
    printf("Getting all PastelIDs...\n");
    vector<string> pastelIDs;
    pastelIDs.reserve(m_pastelIDIndexMap.size() + m_externalPastelIDs.size());
    
    // Internal PastelIDs
    printf("Adding internal PastelIDs...\n");
    for (const auto& [id, _] : m_pastelIDIndexMap) {
        printf("Adding internal PastelID: %s\n", id.c_str());
        pastelIDs.push_back(id);
    }
    
    // External PastelIDs
    printf("Adding external PastelIDs...\n");
    for (const auto& [id, _] : m_externalPastelIDs) {
        printf("Adding external PastelID: %s\n", id.c_str());
        pastelIDs.push_back(id);
    }
    
    printf("Total PastelIDs found: %zu\n", pastelIDs.size());
    return pastelIDs;
}

[[nodiscard]] string CHDWallet::SignWithPastelID(const string& pastelID, const string& message, PastelIDType type, bool fBase64) {
    printf("SignWithPastelID called with pastelID: %s, type: %d, fBase64: %d\n", 
           pastelID.c_str(), static_cast<int>(type), fBase64);
    
    if (IsLocked()) {
        printf("ERROR: Wallet is locked, cannot sign\n");
        throw runtime_error("Wallet is locked");
    }

    if (m_pastelIDIndexMap.contains(pastelID)) {
        printf("Found pastelID in m_pastelIDIndexMap\n");
        const auto pastelIDIndex = m_pastelIDIndexMap[pastelID];
        printf("PastelID index: %u\n", pastelIDIndex);
        
        if (type == PastelIDType::PASTELID) {
            printf("Attempting ed448_sign with PASTELID type\n");
            try {
                auto seed = makePastelIDSeed(pastelIDIndex, PastelIDType::PASTELID);
                printf("Successfully generated seed for ed448_sign\n");
                auto signature = ed448_sign(std::move(seed), message, fBase64 ? encoding::base64 : encoding::none);
                printf("Successfully created signature: %s\n", signature.c_str());
                return signature;
            } catch (const exception& e) {
                printf("ERROR in ed448_sign: %s\n", e.what());
                throw;
            }
        }
        if (type == PastelIDType::LEGROAST) {
            printf("Attempting legroast_sign with LEGROAST type\n");
            try {
                auto seed = makePastelIDSeed(pastelIDIndex, PastelIDType::LEGROAST);
                printf("Successfully generated seed for legroast_sign\n");
                auto signature = legroast_sign(std::move(seed), message, fBase64 ? encoding::base64 : encoding::none);
                printf("Successfully created signature: %s\n", signature.c_str());
                return signature;
            } catch (const exception& e) {
                printf("ERROR in legroast_sign: %s\n", e.what());
                throw;
            }
        }
        printf("ERROR: Invalid PastelID type: %d\n", static_cast<int>(type));
        throw runtime_error("Invalid PastelID type");
    }

    if (m_externalPastelIDs.contains(pastelID)) {
        printf("Found pastelID in m_externalPastelIDs\n");
        try {
            auto key = _getPastelIDKey(pastelID, type);
            printf("Successfully retrieved key for external PastelID\n");
            
            if (type == PastelIDType::PASTELID) {
                printf("Attempting ed448_sign with external PASTELID\n");
                auto signature = ed448_sign(std::move(key), message, fBase64 ? encoding::base64 : encoding::none);
                printf("Successfully created signature for external PastelID: %s\n", signature.c_str());
                return signature;
            }
            if (type == PastelIDType::LEGROAST) {
                printf("Attempting legroast_sign with external LEGROAST\n");
                auto signature = legroast_sign(std::move(key), message, fBase64 ? encoding::base64 : encoding::none);
                printf("Successfully created signature for external LegRoast: %s\n", signature.c_str());
                return signature;
            }
            printf("ERROR: Invalid PastelID type for external PastelID: %d\n", static_cast<int>(type));
            throw runtime_error("Invalid PastelID type");
        } catch (const exception& e) {
            printf("ERROR processing external PastelID: %s\n", e.what());
            throw;
        }
    }

    printf("ERROR: PastelID not found in either internal or external storage: %s\n", pastelID.c_str());
    throw runtime_error(fmt::format("PastelID not found: {}", pastelID));
}

[[nodiscard]] bool CHDWallet::VerifyWithPastelID(const string& pastelID, const string& message, 
                                                const string& signature, bool fBase64) {
    return ed448_verify(pastelID, message, signature, fBase64 ? encoding::base64 : encoding::hex);
}

[[nodiscard]] bool CHDWallet::VerifyWithLegRoast(const string& lrPubKey, const string& message, 
                                                const string& signature, bool fBase64) {
    return legroast_verify(lrPubKey, message, signature, fBase64 ? encoding::base64 : encoding::hex);
}

// Account specific functions
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
    if (!key.has_value() || !key->IsValid()) {
        throw runtime_error("Failed to get valid account key");
    }

    uint256 hash;
    CHash256().Write((unsigned char*)message.data(), message.size()).Finalize(hash.begin());
    v_uint8 vchSig;
    if (key.value().Sign(hash, vchSig)) {
        return EncodeBase58(vchSig);
    }
    return "";
}

// Key functions
[[nodiscard]] string CHDWallet::GetSecret(uint32_t addrIndex, NetworkMode mode) {
    auto key = _getDerivedKeyAt(addrIndex);
    if (key.has_value() && key->IsValid()) {
        KeyIO keyIO(GetChainParams(mode));
        return keyIO.EncodeSecret(key.value());
    }
    return "";
}

[[nodiscard]] string CHDWallet::GetSecret(const string& address, NetworkMode mode) {
    printf("GetSecret called for address: %s, mode: %d\n", address.c_str(), static_cast<int>(mode));
    auto keyID = decodeAddress(address, mode);
    if (keyID.has_value()) {
        KeyIO keyIO(GetChainParams(mode));
        auto key = _getDerivedKey(keyID.value());
        if (key.has_value() && key->IsValid()) {
            string secret = keyIO.EncodeSecret(key.value());
            printf("GetSecret: Key found. Secret: %s\n", secret.c_str());
            return secret;
        }
    }
    printf("GetSecret failed: Address not found or invalid key.\n");
    throw runtime_error("Address not found or invalid key");
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

void CHDWallet::ExportPastelIDKeys(const string& pastelID, SecureString&& passPhrase, const string& sDirPath) {
    auto keyBufPastelID = _getPastelIDKey(pastelID, PastelIDType::PASTELID);
    auto keyBufLegRoast = _getPastelIDKey(pastelID, PastelIDType::LEGROAST);
    auto legRoastPubKey = GetPastelID(pastelID, PastelIDType::LEGROAST);
    CPastelID::CreatePastelKeysFile(sDirPath, std::move(passPhrase),
                                    pastelID, legRoastPubKey, keyBufPastelID, keyBufLegRoast);
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

[[nodiscard]] v_uint8 CHDWallet::_getPastelIDKey(const string& pastelID, PastelIDType type) {
    printf("_getPastelIDKey called with pastelID: %s, type: %d\n", pastelID.c_str(), static_cast<int>(type));
    
    if (m_pastelIDIndexMap.contains(pastelID)) {
        printf("Found pastelID in m_pastelIDIndexMap\n");
        return _getPastelIDKey(m_pastelIDIndexMap[pastelID], type);
    }
    
    if (m_externalPastelIDs.contains(pastelID)) {
        printf("Found pastelID in m_externalPastelIDs\n");
        auto externalPastelID = m_externalPastelIDs[pastelID];
        v_uint8 key;
        
        if (type == PastelIDType::PASTELID) {
            printf("Attempting to decrypt PASTELID key\n");
            if (!decryptWithMasterKey(externalPastelID.m_encryptedPastelIDKey.second,
                                    externalPastelID.m_encryptedPastelIDKey.first, key)) {
                printf("ERROR: Failed to decrypt PASTELID key\n");
                throw runtime_error("Failed to decrypt PASTELID key");
            }
            printf("Successfully decrypted PASTELID key\n");
        } else if (type == PastelIDType::LEGROAST) {
            printf("Attempting to decrypt LEGROAST key\n");
            if (!decryptWithMasterKey(externalPastelID.m_encryptedLegRoastKey.second,
                                    externalPastelID.m_encryptedLegRoastKey.first, key)) {
                printf("ERROR: Failed to decrypt LEGROAST key\n");
                throw runtime_error("Failed to decrypt LEGROAST key");
            }
            printf("Successfully decrypted LEGROAST key\n");
        } else {
            printf("ERROR: Invalid PastelID type: %d\n", static_cast<int>(type));
            throw runtime_error("Invalid PastelID type");
        }
        
        printf("Returning key of size: %zu\n", key.size());
        return key;
    }
    
    printf("ERROR: PastelID not found in either internal or external storage: %s\n", pastelID.c_str());
    throw runtime_error(fmt::format("PastelID key not found: {}", pastelID));
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