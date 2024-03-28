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
    std::map<NetworkMode, CChainParams*> m_Networks;
    CHDWallet m_HDWallet;

public:
    Pastel();
    std::string GetNewAddress(NetworkMode mode);

    std::string CreateNewWallet(NetworkMode mode, const SecureString& password);
//    void ImportWalletFromMnemonic(const std::string& mnemonic, NetworkMode mode, SecureString password);
//
//    void ImportWallet(const std::vector<unsigned char>& data, SecureString password);
//    std::vector<unsigned char> ExportWallet();
};
