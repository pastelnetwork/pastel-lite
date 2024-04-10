// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "libpastel.h"
#include "support/response.hpp"
#include "base58.h"
#include "crypto/common.h"
#include "hd_wallet.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#endif

using namespace std;

Pastel::Pastel() {
    init_and_check_sodium();
}

string Pastel::CreateNewWallet(NetworkMode mode, const SecureString &password) {
    return wrapResponse([&]() {
        return m_HDWallet.SetupNewWallet(mode, password);
    });
}

string Pastel::CreateWalletFromMnemonic(const string &mnemonic, NetworkMode mode, const SecureString &password) {
    return wrapResponse([&]() {
        return false;
    });
}

string Pastel::ExportWallet() {
    return wrapResponse([&]() {
        CSecureDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << m_HDWallet;
        vector<unsigned char> vchWallet(ss.begin(), ss.end());
        auto strWallet = EncodeBase58(vchWallet);
        return strWallet;
    });
}

string Pastel::ImportWallet(const string &data) {
    return wrapResponse([&]() {
        vector<unsigned char> vchWallet;
        if (!DecodeBase58(data, vchWallet)) {
            throw runtime_error("Failed to decode base58 wallet data");
        }
        CSecureDataStream ss(vchWallet, SER_NETWORK, PROTOCOL_VERSION);
        ss >> m_HDWallet;
    });
}

string Pastel::UnlockWallet(const SecureString &password) {
    return wrapResponse([&]() {
        m_HDWallet.Unlock(password);
    });
}

string Pastel::LockWallet() {
    return wrapResponse([&]() {
        m_HDWallet.Lock();
    });
}

string Pastel::MakeNewAddress() {
    return wrapResponse([&]() {
        return m_HDWallet.MakeNewAddress();
    });
}

string Pastel::GetAddress(uint32_t addrIndex) {
    return wrapResponse([&]() {
        return m_HDWallet.GetAddress(addrIndex);
    });
}

string Pastel::GetAddressesCount() {
    return wrapResponse([&]() {
        return m_HDWallet.GetAddressesCount();
    });
}

string Pastel::GetAddresses() {
    return wrapResponse([&]() {
        return m_HDWallet.GetAddresses();
    });
}


#ifdef __EMSCRIPTEN__
EMSCRIPTEN_BINDINGS(PastelModule) {
    emscripten::enum_<NetworkMode>("NetworkMode")
        .value("Mainnet", NetworkMode::MAINNET)
        .value("Testnet", NetworkMode::TESTNET)
        .value("Regtest", NetworkMode::REGTEST)
        ;
    emscripten::class_<Pastel>("Pastel")
        .constructor<>()
        .function("CreateNewWallet", &Pastel::CreateNewWallet)
        .function("CreateWalletFromMnemonic", &Pastel::CreateWalletFromMnemonic)
        .function("ExportWallet", &Pastel::ExportWallet)
        .function("ImportWallet", &Pastel::ImportWallet)
        .function("UnlockWallet", &Pastel::UnlockWallet)
        .function("LockWallet", &Pastel::LockWallet)
        .function("MakeNewAddress", &Pastel::MakeNewAddress)
        .function("GetAddress", &Pastel::GetAddress)
        .function("GetAddresses", &Pastel::GetAddresses)
        .function("GetAddressesCount", &Pastel::GetAddressesCount)
        ;
    // Add more bindings as needed
}
#endif
