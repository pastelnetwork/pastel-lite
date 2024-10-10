#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <types.h>

#include "chain.h"
#include "transaction/amount.h"
#include "rawtransaction.h"
#include "hd_wallet.h"

using namespace std;

class Pastel {
    CHDWallet m_HDWallet;

public:
    Pastel();

    // Wallet functions
    string CreateNewWallet(const string& password);
    string CreateWalletFromMnemonic(const string& password, const string& mnemonic);
    string ExportWallet();
    string ImportWallet(const string& data);
    string UnlockWallet(const string& password);
    string LockWallet();

    // Address functions
    string MakeNewAddress(NetworkMode mode = NetworkMode::MAINNET);
    string GetAddress(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);
    string GetAddressesCount();
    string GetAddresses(NetworkMode mode = NetworkMode::MAINNET);
    string MakeNewLegacyAddress(NetworkMode mode = NetworkMode::MAINNET);
    string ImportLegacyPrivateKey(const string& encoded_key, NetworkMode mode = NetworkMode::MAINNET);

    // PastelID functions
    string MakeNewPastelID(bool makeLegRoast = true);
    string GetPastelIDByIndex(uint32_t addrIndex, PastelIDType type = PastelIDType::PASTELID);
    string GetPastelID(const string& pastelID, PastelIDType type = PastelIDType::PASTELID);
    string GetPastelIDsCount();
    string GetPastelIDs();
    string SignWithPastelID(const string& pastelID, const string& message, PastelIDType type = PastelIDType::PASTELID, bool fBase64 = false);
    string VerifyWithPastelID(const string& pastelID, const string& message, const string& signature, bool fBase64 = false);
    string VerifyWithLegRoast(const string& lrPubKey, const string& message, const string& signature, bool fBase64 = false);
    string ExportPastelIDKeys(const string& pastelID, string passPhrase, const string& sDirPath);
    string ImportPastelIDKeys(const string& pastelID, string passPhrase, const string& sDirPath);

    // Account specific functions
    // All functions returns base58 encoded strings w/o prefix and checksum
    string GetWalletPubKey();                   // returns base58 encoded Public Key, w/o prefix and checksum
    string SignWithWalletKey(string message);
    string GetPubKeyAt(uint32_t addrIndex);     // returns base58 encoded Public Key, w/o prefix and checksum
    string SignWithKeyAt(uint32_t addrIndex, string message);

    // Key functions
    string GetSecret(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);
    string GetAddressSecret(const string& address, NetworkMode mode = NetworkMode::MAINNET);

    // Transaction functions
    string CreateSendToTransaction(NetworkMode mode,
                                   const vector<pair<string, CAmount>>& sendTo, const string& sendFrom,
                                   v_utxos& utxosJson, uint32_t nHeight, int nExpiryHeight = 0);

    // JSON version
    string CreateSendToTransactionJson(NetworkMode mode, const string& sendToJson, const string& sendFrom,
                                       const string& utxosJson, uint32_t nHeight, int nExpiryHeight = 0);

    string CreateRegisterPastelIdTransaction(NetworkMode mode,
                                             const string& pastelID, const string& fundingAddress,
                                             v_utxos& utxos, uint32_t nHeight, int nExpiryHeight = 0);

    // JSON version
    string CreateRegisterPastelIdTransactionJson(NetworkMode mode,
                                                 const string& pastelID, const string& fundingAddress,
                                                 const string& utxosJson, uint32_t nHeight, int nExpiryHeight = 0);

private:
    static bool utxosJsonToVector(const string& utxosJson, v_utxos& utxos);
};

class PastelID {
    friend class PastelSigner;

    PastelID(const string& pastelIDDir, const string& pastelID, v_uint8 key) :
        m_path(pastelIDDir), m_pastelID(pastelID), m_key(std::move(key)) {}

    static auto getPastelIDKey(const string& pastelIDDir, const string& pastelID, const SecureString& password);
    static PastelID Load(const string& pastelIDDir, const string& pastelID, const string& password);

public:
    [[nodiscard]] string Sign(const string& message);
    [[nodiscard]] string SignBase64(const string& messageBase64);
    bool Verify(const string& message, const string& signature);
    bool VerifyBase64(const string& messageBase64, const string& signature);

    [[nodiscard]] string GetPath() const { return m_path; }
    [[nodiscard]] string GetID() const { return m_pastelID; }

private:
    string m_path;
    string m_pastelID;
    v_uint8 m_key;
};

class PastelSigner {
    string m_pastelIDDir;

public:
    explicit PastelSigner(const string& pastelID_dir);
    [[nodiscard]] string SignWithPastelID(const string& message, const string& pastelID, const string& password);
    [[nodiscard]] string SignWithPastelIDBase64(const string& messageBase64, const string& pastelID, const string& password);
    bool VerifyWithPastelID(const string& message, const string& signature, const string& pastelID);
    bool VerifyWithPastelIDBase64(const string& messageBase64, const string& signature, const string& pastelID);

    auto GetPastelID(const string& pastelID, const SecureString& password) {
        return PastelID::Load(m_pastelIDDir, pastelID, password);
    }
};
