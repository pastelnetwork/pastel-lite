#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <optional>
#include <types.h>

#include "chain.h"
#include "hd_wallet.h"

using namespace std;

class Pastel {
    map<NetworkMode, CChainParams*> m_Networks;
    CHDWallet m_HDWallet;

public:
    Pastel();

    // Wallet functions
    string CreateNewWallet(NetworkMode mode, const string& password);
    string CreateWalletFromMnemonic(const string& mnemonic, NetworkMode mode, const string& password);
    string ExportWallet();
    string ImportWallet(const string& data);
    string UnlockWallet(const string& password);
    string LockWallet();

    // Address functions
    string MakeNewAddress();
    string GetAddress(uint32_t addrIndex);
    string GetAddressesCount();
    string GetAddresses();
    string SignWithAddressKey(const string& address, const string& message, bool fBase64 = false);

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
};
