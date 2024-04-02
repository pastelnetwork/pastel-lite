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

    string CreateNewWallet(NetworkMode mode, const SecureString& password);
    void CreateWalletFromMnemonic(const string& mnemonic, NetworkMode mode, const SecureString& password);

    string ExportWallet();
    void ImportWallet(const string& data, const SecureString& password);

    string GetNewAddress();
    string GetNewAddressByIndex(uint32_t addrIndex);

    vector<string> GetAddresses() { return m_HDWallet.GetAddresses(); }
};
