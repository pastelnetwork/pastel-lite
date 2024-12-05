#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <functional>

#include "crypter.h"
#include "hd_mnemonic.h"
#include "hd_keys.h"
#include "types.h"
#include "chain.h"

using namespace std;

struct external_pastel_id {
    pair<uint256, v_uint8> m_encryptedPastelIDKey;   // [fingerprint, encrypted Key]
    pair<uint256, v_uint8> m_encryptedLegRoastKey;   // [fingerprint, encrypted Key]
    string m_legRoastPubKey;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_encryptedPastelIDKey);
        READWRITE(m_encryptedLegRoastKey);
        READWRITE(m_legRoastPubKey);
    }
};

struct SerializableKey {
    v_uint8 keyData;
    bool fCompressed;

    SerializableKey() : fCompressed(true) {
        keyData.resize(CKey::KEY_SIZE);  // Ensure proper size
    }
    
    explicit SerializableKey(const CKey& key) {
        if (!key.IsValid()) {
            printf("WARNING: Attempting to serialize invalid key\n");
            keyData.resize(CKey::KEY_SIZE);
            fCompressed = true;
            return;
        }
        keyData = key.GetKeyData();
        fCompressed = key.IsCompressed();
    }

    CKey GetKey() const {
        CKey key;
        if (keyData.size() != CKey::KEY_SIZE) {
            printf("WARNING: Invalid key data size: %zu\n", keyData.size());
            return key;
        }
        key.SetKeyData(keyData, fCompressed);
        if (!key.IsValid()) {
            printf("WARNING: Failed to create valid key from serialized data\n");
        }
        return key;
    }

    bool IsValid() const {
        return keyData.size() == CKey::KEY_SIZE;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream>
    inline void SerializationOp(Stream& s, const SERIALIZE_ACTION ser_action)
    {
        READWRITE(keyData);
        READWRITE(fCompressed);
        
        if (ser_action == SERIALIZE_ACTION::Read) {
            if (keyData.size() != CKey::KEY_SIZE) {
                printf("WARNING: Deserialized invalid key data size: %zu\n", 
                       keyData.size());
                keyData.resize(CKey::KEY_SIZE);
            }
        }
    }
};

class Signer;

class CHDWallet
{
    friend class Signer;

    pair<uint256, v_uint8> m_encryptedMnemonicSeed; // [fingerprint, seed encrypted with m_vMasterKey]
    CMasterKey m_encryptedMasterKey;    // m_vMasterKey encrypted with a key derived from passphrase, also keeps salt and derivation method inside

    map<CKeyID, uint32_t> m_keyIdIndexMap;          // to access address index by address (non encoded)
    map<string, SerializableKey> m_addressMapLegacy;   // to access exported NON HD private keys by address
    
    map<string, uint32_t> m_pastelIDIndexMap;               // only ed448 public part
    map<string, string> m_pastelIDLegRoastMap;
    map<string, external_pastel_id> m_externalPastelIDs;    // secure part is encrypted

    // Do not serialize
    CKeyingMaterial m_vMasterKey;   // random key

    map<uint32_t, CKeyID> m_indexKeyIdMap;     // to access (non-encoded) address index by address
    map<uint32_t, string> m_indexPastelIDMap;   // only ed448 public part

    // New tracking members for unified address handling
    uint32_t m_lastHDIndex = 0;                 // Track last used HD index
    map<uint32_t, bool> m_indexIsLegacy;        // Track which indexes are legacy imports

    uint32_t m_bip44CoinType = CChainParams().BIP44CoinType();
    uint32_t m_walletIDIndex = CChainParams().WalletIDIndex();
    CMainnetParams m_mainnetParams;
    CTestnetParams m_testnetParams;
    CDevnetParams m_devnetParams;

    // New helper methods for index management
    uint32_t getNextHDIndex() {
        while (m_indexKeyIdMap.contains(m_lastHDIndex)) {
            m_lastHDIndex++;
        }
        return m_lastHDIndex++;
    }

    void addImportedKeyToMaps(const CKey& key, const string& address) {
        if (!key.IsValid()) {
            printf("Attempting to import invalid key\n");
            return;
        }

        const auto pubKey = key.GetPubKey();
        const auto keyID = pubKey.GetID();
        
        // Check if this key is already imported
        for (const auto& [addr, existingKey] : m_addressMapLegacy) {
            CKey existing = existingKey.GetKey();
            if (!existing.IsValid()) {
                printf("Warning: Found invalid key in legacy map\n");
                continue;
            }
            if (existing.GetPubKey().GetID() == keyID) {
                printf("Key already imported for address: %s\n", addr.c_str());
                return;
            }
        }
        
        uint32_t importIndex = getNextHDIndex();
        printf("Adding imported key to maps with index: %u\n", importIndex);
        
        m_keyIdIndexMap[keyID] = importIndex;
        m_indexKeyIdMap[importIndex] = keyID;
        m_addressMapLegacy[address] = SerializableKey(key);
        m_indexIsLegacy[importIndex] = true;
    }

public:
    // Wallet functions
    [[nodiscard]] string SetupNewWallet(const SecureString& password);
    [[nodiscard]] string SetupNewWalletFromMnemonic(const SecureString& password, const SecureString& mnemonic);
    void Lock();
    void Unlock(const SecureString& strPassphrase);
    [[nodiscard]] bool IsLocked() const {return m_vMasterKey.empty();}

    // Address-specific functions
    [[nodiscard]] string MakeNewAddress(NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string GetAddress(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] uint32_t GetAddressesCount();
    [[nodiscard]] vector<string> GetAddresses(NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string MakeNewLegacyAddress(NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string ImportLegacyPrivateKey(const string& encoded_key, NetworkMode mode = NetworkMode::MAINNET);

    // PastelID specific functions
    [[nodiscard]] string MakeNewPastelID(bool makeLegRoast = true);
    [[nodiscard]] string GetPastelID(uint32_t pastelIDIndex, PastelIDType type = PastelIDType::PASTELID);
    [[nodiscard]] string GetPastelID(const string& pastelID, PastelIDType type = PastelIDType::PASTELID);
    [[nodiscard]] uint32_t GetPastelIDsCount() const { return m_pastelIDIndexMap.size(); }
    [[nodiscard]] vector<string> GetPastelIDs();
    [[nodiscard]] string SignWithPastelID(const string& pastelID, const string& message, PastelIDType type = PastelIDType::PASTELID, bool fBase64 = false);
    [[nodiscard]] bool VerifyWithPastelID(const string& pastelID, const string& message, const string& signature, bool fBase64 = false);
    [[nodiscard]] bool VerifyWithLegRoast(const string& lrPubKey, const string& message, const string& signature, bool fBase64 = false);
    [[nodiscard]] bool ImportPastelIDKeys(const string& pastelID, SecureString&& password, const string& pastelIDDir);
    void ExportPastelIDKeys(const string& pastelID, SecureString&& passPhrase, const string& sDirPath);

    // Account specific functions
    [[nodiscard]] string GetWalletPubKey();
    [[nodiscard]] string SignWithWalletKey(string message);
    [[nodiscard]] string GetPubKeyAt(uint32_t addrIndex);
    [[nodiscard]] string SignWithKeyAt(uint32_t addrIndex, string message);

    // Key functions
    [[nodiscard]] string GetSecret(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string GetSecret(const string& address, NetworkMode mode = NetworkMode::MAINNET);

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_encryptedMnemonicSeed);
        READWRITE(m_encryptedMasterKey);
        READWRITE(m_keyIdIndexMap);
        READWRITE(m_addressMapLegacy);
        READWRITE(m_pastelIDLegRoastMap);
        READWRITE(m_pastelIDIndexMap);
        READWRITE(m_lastHDIndex);      // Add serialization for last used index
        READWRITE(m_indexIsLegacy);    // Add serialization for legacy flag map
        READWRITE(m_externalPastelIDs);
        
        if (ser_action == SERIALIZE_ACTION::Read) {
            // Rebuild index maps on load
            m_indexKeyIdMap.clear();
            for (const auto& pair : m_keyIdIndexMap) {
                m_indexKeyIdMap[pair.second] = pair.first;
            }
            
            m_indexPastelIDMap.clear();
            for (const auto& pair : m_pastelIDIndexMap) {
                m_indexPastelIDMap[pair.second] = pair.first;
            }
            
            // Ensure m_lastHDIndex is beyond all used indexes
            for (const auto& [index, _] : m_indexKeyIdMap) {
                if (index >= m_lastHDIndex) {
                    m_lastHDIndex = index + 1;
                }
            }
        }
    }

protected:
    [[nodiscard]] std::optional<CKey> _getDerivedKeyAt(uint32_t addrIndex);
    [[nodiscard]] std::optional<CKey> _getDerivedKey(const CKeyID& keyID);
    [[nodiscard]] std::optional<CPubKey> _getPubKey(const CKeyID& keyID);
    [[nodiscard]] std::optional<CKey> getKeyForAddress(const CKeyID& keyID, const string& address);
    [[nodiscard]] bool validateKeyAccess(const CKeyID& keyID, const string& address);
    [[nodiscard]] std::optional<CKey> getKeyFromLegacyOrHD(const CKeyID& keyID);

    [[nodiscard]] v_uint8 _getPastelIDKey(uint32_t pastelIDIndex, PastelIDType type = PastelIDType::PASTELID);
    [[nodiscard]] v_uint8 _getPastelIDKey(const string& pastelID, PastelIDType type = PastelIDType::PASTELID);

private:
    string setupNewWalletImpl(const SecureString &password, const std::function<std::optional<MnemonicSeed>()>& getSeed);

    bool setMasterKey(const SecureString& strPassphrase, string& error = (string &) "") noexcept;
    bool setEncryptedMnemonicSeed(const MnemonicSeed& seed, string& error = (string &) "") noexcept;
    [[nodiscard]] std::optional<MnemonicSeed> getDecryptedMnemonicSeed() noexcept;
    bool encryptWithMasterKey(const v_uint8& data, const uint256& nIV, v_uint8& encryptedData);
    bool decryptWithMasterKey(const v_uint8& encryptedData, const uint256& nIV, v_uint8& data);

    [[nodiscard]] std::optional<CExtKey> getExtKey(uint32_t addrIndex);
    [[nodiscard]] std::optional<AccountKey> getAccountKey() noexcept;

    [[nodiscard]] const v_uint8& getNetworkPrefix(NetworkMode mode, CChainParams::Base58Type type);
    string encodeAddress(const CKeyID& id, NetworkMode mode) noexcept;
    std::optional<CKeyID> decodeAddress(const string& address, NetworkMode mode) noexcept;
    string encodeExtPubKey(const CExtPubKey& key, NetworkMode mode) noexcept;
    CExtPubKey decodeExtPubKey(const string& str, NetworkMode mode) noexcept;

    v_uint8 makePastelIDSeed(uint32_t addrIndex, PastelIDType type);
    
    // New validation helper
    bool validateIndexContinuity() const {
        uint32_t lastIndex = 0;
        for (const auto& [index, _] : m_indexKeyIdMap) {
            if (index > lastIndex + 1) {
                printf("Warning: Index gap detected between %u and %u\n", lastIndex, index);
                return false;
            }
            lastIndex = index;
        }
        return true;
    }

    // New helper to track unified address info    
    struct UnifiedAddressInfo {
        uint32_t index;
        bool isLegacy;
        CKey key;
    };
    mutable std::map<CKeyID, UnifiedAddressInfo> m_unifiedAddressMap;
    
    bool initializeUnifiedAddressInfo(const CKeyID& keyID, const string& address);
};
