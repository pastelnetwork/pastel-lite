#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "crypter.h"
#include "hd_mnemonic.h"
#include "hd_keys.h"
#include "types.h"
#include "chain.h"

using namespace std;

class CHDWallet
{
    // Can serialize
    NetworkMode m_NetworkMode;

    pair<uint256, vector<unsigned char>> m_encryptedMnemonicSeed; // [fingerprint, seed encrypted with m_vMasterKey]
    CMasterKey m_encryptedMasterKey;    // m_vMasterKey encrypted with key derived from passphrase, also keeps salt and derivation method inside

    map<string, uint32_t> m_addressIndexMap;  // to access address index by address
    map<string, CKey> m_addressMapNonHD;      // to access exported NON HD private keys by address. TODO: encryption/decryption for serialization/deserialization

    // Do not serialize
    CKeyingMaterial m_vMasterKey;   // random key

    map<uint32_t, string> m_indexAddressMap;  // to access address by index
    CChainParams* m_NetworkParams;

public:
    [[nodiscard]] string SetupNewWallet(NetworkMode mode, const SecureString& password);
    void Lock();
    void Unlock(const SecureString& strPassphrase);
    bool IsLocked() const {return m_vMasterKey.empty();}

    [[nodiscard]] string ExportWallet();

    [[nodiscard]] string MakeNewAddress();
    [[nodiscard]] string GetAddress(uint32_t addrIndex);
    [[nodiscard]] optional<CKey> GetAddressKey(const string& address);
    [[nodiscard]] optional<CKey> GetAddressKey(uint32_t addrIndex) const;
    [[nodiscard]] string GetNewLegacyAddress();

    [[nodiscard]] uint32_t GetAddressesCount() const { return m_indexAddressMap.size(); }
    [[nodiscard]] vector<string> GetAddresses() const {
        vector<string> addresses;
        addresses.reserve(m_indexAddressMap.size());
        for(const auto& pair : m_indexAddressMap) {
            addresses.push_back(pair.second);
        }
        return addresses;
    }

    [[nodiscard]] string GetWalletPubKey();    // returns base58 encoded Public Key, w/o prefix and checksum
    [[nodiscard]] string SignWithWalletKey(string message);
    [[nodiscard]] string GetPubKeyAt(uint32_t addrIndex);   // returns base58 encoded Public Key, w/o prefix and checksum
    [[nodiscard]] string SignWithKeyAt(uint32_t addrIndex, string message);

    [[nodiscard]] NetworkMode GetNetworkMode() const { return m_NetworkMode; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (ser_action == SERIALIZE_ACTION::Read) {
            uint32_t mode;
            READWRITE(mode);
            m_NetworkMode = static_cast<NetworkMode>(mode);
            setNetworkParams(m_NetworkMode);
        } else {
            auto mode = static_cast<uint32_t>(m_NetworkMode);
            READWRITE(mode);
        }
        READWRITE(m_encryptedMnemonicSeed);
        READWRITE(m_encryptedMasterKey);
        READWRITE(m_addressIndexMap);
        if (ser_action == SERIALIZE_ACTION::Read) {
            for (const auto& pair : m_addressIndexMap) {
                m_indexAddressMap[pair.second] = pair.first;
            }
        }
    }

private:
    bool setMasterKey(const SecureString& strPassphrase, string& error = (string &) "") noexcept;
    bool setEncryptedMnemonicSeed(const MnemonicSeed& seed, string& error = (string &) "") noexcept;
    [[nodiscard]] optional<MnemonicSeed> getDecryptedMnemonicSeed() const noexcept;
    [[nodiscard]] optional<CExtKey> getExtKey(uint32_t addrIndex) const;

    [[nodiscard]] string getAddressByIndex(uint32_t addrIndex, bool bCreateNew = false);
    [[nodiscard]] optional<AccountKey> getAccountKey() const noexcept;

    void setNetworkParams(NetworkMode mode);

    static string encodeAddress(const CKeyID& id, const CChainParams* network) noexcept;
    static string encodeExtPubKey(const CExtPubKey& key, const CChainParams* network) noexcept;
    static CExtPubKey decodeExtPubKey(const string& str, const CChainParams* network) noexcept;
};
