#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <optional>
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
    string CreateWalletFromMnemonic(const string& mnemonic, const string& password);
    string ExportWallet();
    string ImportWallet(const string& data);
    string UnlockWallet(const string& password);
    string LockWallet();

    // Address functions
    string MakeNewAddress(NetworkMode mode = NetworkMode::MAINNET);
    string GetAddress(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);
    string GetAddressesCount();
    string GetAddresses(NetworkMode mode = NetworkMode::MAINNET);

    // PastelID functions
    string MakeNewPastelID();
    string GetPastelIDByIndex(uint32_t addrIndex, PastelIDType type = PastelIDType::PASTELID);
    string GetPastelID(const string& pastelID, PastelIDType type = PastelIDType::PASTELID);
    string GetPastelIDsCount();
    string GetPastelIDs();
    string SignWithPastelID(const string& pastelID, const string& message, PastelIDType type = PastelIDType::PASTELID, bool fBase64 = false);
    string VerifyWithPastelID(const string& pastelID, const string& message, const string& signature, bool fBase64 = false);
    string VerifyWithLegRoast(const string& lrPubKey, const string& message, const string& signature, bool fBase64 = false);
    string ExportPastelIDKeys(const string& pastelID, string passPhrase, const string& sDirPath);

    // Key functions
    string GetWalletPubKey();                   // returns base58 encoded Public Key, w/o prefix and checksum
    string SignWithWalletKey(string message);
    string GetPubKeyAt(uint32_t addrIndex);     // returns base58 encoded Public Key, w/o prefix and checksum
    string SignWithKeyAt(uint32_t addrIndex, string message);
    string GetSecret(uint32_t addrIndex, NetworkMode mode = NetworkMode::MAINNET);

    // Transaction functions
    string CreateSendToTransaction(NetworkMode mode,
                                   const vector<pair<string, CAmount>>& sendTo, const string& sendFrom,
                                   v_utxos& utxos, const uint32_t nHeight, int nExpiryHeight = 0);

    string CreateRegisterPastelIdTransaction(NetworkMode mode,
                                             string&& pastelID, const string& fundingAddress,
                                             v_utxos& utxos, const uint32_t nHeight, int nExpiryHeight = 0);
};

class PastelSigner {

    string m_pastelIDDir;

public:
    PastelSigner(const string& pastelID_dir);

    [[nodiscard]] string SignWithPastelID(const string& pastelID, const string& message, const SecureString& password);
    [[nodiscard]] string SignWithPastelIDBase64(const string& pastelID, const string& messageBase64, const SecureString& password);
    bool VerifyWithPastelID(const string& pastelID, const string& message, const string& signature);
    bool VerifyWithPastelIDBase64(const string& pastelID, const string& messageBase64, const string& signature);

private:
    string getPastelIDKey(const string& pastelID, const SecureString& password);
};
