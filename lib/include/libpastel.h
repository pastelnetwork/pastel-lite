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
    string CreateNewWallet(NetworkMode mode, const SecureString& password);
    string CreateWalletFromMnemonic(const string& mnemonic, NetworkMode mode, const SecureString& password);
    string ExportWallet();
    string ImportWallet(const string& data);
    string UnlockWallet(const SecureString& password);
    string LockWallet();
    string MakeNewAddress();
    string GetAddress(uint32_t addrIndex);
    string GetAddressesCount();
    string GetAddresses();
    string GetWalletPubKey();    // returns base58 encoded Public Key, w/o prefix and checksum
    string SignWithWalletKey(string message);
    string GetPubKeyAt(uint32_t addrIndex);   // returns base58 encoded Public Key, w/o prefix and checksum
    string SignWithKeyAt(uint32_t addrIndex, string message);
};
