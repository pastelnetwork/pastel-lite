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

class Signer;

class CHDWallet
{
    friend class Signer;

    pair<uint256, v_uint8> m_encryptedMnemonicSeed; // [fingerprint, seed encrypted with m_vMasterKey]
    CMasterKey m_encryptedMasterKey;    // m_vMasterKey encrypted with a key derived from passphrase, also keeps salt and derivation method inside

    map<CKeyID, uint32_t> m_keyIdIndexMap;          // to access address index by address (non encoded)
    map<string, CKey> m_addressMapLegacy;           // to access exported NON HD private keys by address. TODO: encryption/decryption for serialization/deserialization

    map<string, uint32_t> m_pastelIDIndexMap;               // only ed448 public part
    map<string, string> m_pastelIDLegRoastMap;
    map<string, external_pastel_id> m_externalPastelIDs;    // secure part is encrypted

    // Do not serialize
    CKeyingMaterial m_vMasterKey;   // random key

    map<uint32_t, CKeyID> m_indexKeyIdMap;     // to access (non-encoded) address index by address
    map<uint32_t, string> m_indexPastelIDMap;   // only ed448 public part

    uint32_t m_bip44CoinType = CChainParams().BIP44CoinType();
    uint32_t m_walletIDIndex = CChainParams().WalletIDIndex();
    CMainnetParams m_mainnetParams;
    CTestnetParams m_testnetParams;
    CDevnetParams m_devnetParams;

public:
    // Wallet functions
    [[nodiscard]] string SetupNewWallet(const SecureString& password);
    [[nodiscard]] string SetupNewWalletFromMnemonic(const SecureString& password, const SecureString& mnemonic);
    void Lock();
    void Unlock(const SecureString& strPassphrase);
    [[nodiscard]] bool IsLocked() const {return m_vMasterKey.empty();}

    // Address-specific functions
    // If address is not created by MakeNewAddress function:
    //      it cannot be used for signing/verification;
    //      won't be returned by GetAddress and GetAddresses function;
    //      won't be counted by GetAddressesCount function;
    //      and won't be serialized
    [[nodiscard]] string MakeNewAddress(NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string GetAddress(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);
    // GetAddressesCount - returns the number of addresses created by MakeNewAddress function
    [[nodiscard]] uint32_t GetAddressesCount();
    // GetAddresses - returns addresses created by the MakeNewAddress AND MakeNewLegacyAddress AND imported by ImportLegacyPrivateKey
    [[nodiscard]] vector<string> GetAddresses(NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string MakeNewLegacyAddress(NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string ImportLegacyPrivateKey(const string& encoded_key, NetworkMode mode = NetworkMode::MAINNET);

    // PastelID specific functions
    // If PastelID is not created by MakeNewPastelID function:
    //      it cannot be used for signing/verification;
    //      won't be returned by GetPastelID and GetPastelIDs function;
    //      won't be counted by GetPastelIDsCount function;
    //      and won't be serialized
    [[nodiscard]] string MakeNewPastelID(bool makeLegRoast = true);
    [[nodiscard]] string GetPastelID(uint32_t pastelIDIndex, PastelIDType type = PastelIDType::PASTELID);
    [[nodiscard]] string GetPastelID(const string& pastelID, PastelIDType type = PastelIDType::PASTELID);
    [[nodiscard]] uint32_t GetPastelIDsCount() const { return m_pastelIDIndexMap.size(); }
    [[nodiscard]] vector<string> GetPastelIDs();
    // SignWithPastelID will use both: HD and external PastelIDs for signing/verification
    [[nodiscard]] string SignWithPastelID(const string& pastelID, const string& message, PastelIDType type = PastelIDType::PASTELID, bool fBase64 = false);
    [[nodiscard]] bool VerifyWithPastelID(const string& pastelID, const string& message, const string& signature, bool fBase64 = false);
    [[nodiscard]] bool VerifyWithLegRoast(const string& lrPubKey, const string& message, const string& signature, bool fBase64 = false);
    [[nodiscard]] bool ImportPastelIDKeys(const string& pastelID, SecureString&& password, const string& pastelIDDir);
    void ExportPastelIDKeys(const string& pastelID, SecureString&& passPhrase, const string& sDirPath);

    // Account specific functions
    // All functions return base58 encoded strings w/o prefix and checksum
    [[nodiscard]] string GetWalletPubKey();
    [[nodiscard]] string SignWithWalletKey(string message);
    [[nodiscard]] string GetPubKeyAt(uint32_t addrIndex);
    // Function will use any key for signing/verification, not only if it was created by MakeNewAddress function
    [[nodiscard]] string SignWithKeyAt(uint32_t addrIndex, string message);

    // Key functions - functions return base58 encoded strings WITH prefix and checksum
    [[nodiscard]] string GetSecret(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);
    [[nodiscard]] string GetSecret(const string& address, NetworkMode mode = NetworkMode::MAINNET);

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_encryptedMnemonicSeed);
        READWRITE(m_encryptedMasterKey);
        READWRITE(m_keyIdIndexMap);
        if (ser_action == SERIALIZE_ACTION::Read) {
            for (const auto& pair : m_keyIdIndexMap) {
                m_indexKeyIdMap[pair.second] = pair.first;
            }
        }
        READWRITE(m_pastelIDLegRoastMap);
        READWRITE(m_pastelIDIndexMap);
        if (ser_action == SERIALIZE_ACTION::Read) {
            for (const auto& pair : m_pastelIDIndexMap) {
                m_indexPastelIDMap[pair.second] = pair.first;
            }
        }
        READWRITE(m_externalPastelIDs);
    }
protected:
    [[nodiscard]] std::optional<CKey> _getDerivedKeyAt(uint32_t addrIndex);
    [[nodiscard]] std::optional<CKey> _getDerivedKey(const CKeyID& keyID);
    [[nodiscard]] std::optional<CKey> _getLegacyKey(const CKeyID& keyID);
    [[nodiscard]] std::optional<CPubKey> _getPubKey(const CKeyID& keyID);

    [[nodiscard]] v_uint8 _getPastelIDKey(uint32_t pastelIDIndex, PastelIDType type = PastelIDType::PASTELID);
    [[nodiscard]] v_uint8 _getPastelIDKey(const string& pastelID, PastelIDType type = PastelIDType::PASTELID);

private:
    // function accepts lambda to get seed
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
};
