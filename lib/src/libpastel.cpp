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

string Pastel::CreateNewWallet(const string &password) {
    return wrapResponse([&]() {
        return m_HDWallet.SetupNewWallet(password);
    });
}

string Pastel::CreateWalletFromMnemonic(const string &mnemonic, const string &password) {
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

string Pastel::UnlockWallet(const string &password) {
    return wrapResponse([&]() {
        m_HDWallet.Unlock(password);
    });
}

string Pastel::LockWallet() {
    return wrapResponse([&]() {
        m_HDWallet.Lock();
    });
}

string Pastel::MakeNewAddress(NetworkMode mode) {
    return wrapResponse([&]() {
        return m_HDWallet.MakeNewAddress(mode);
    });
}

string Pastel::GetAddress(uint32_t addrIndex, NetworkMode mode) {
    return wrapResponse([&]() {
        return m_HDWallet.GetAddress(addrIndex, mode);
    });
}

string Pastel::GetAddressesCount() {
    return wrapResponse([&]() {
        return m_HDWallet.GetAddressesCount();
    });
}

string Pastel::GetAddresses(NetworkMode mode) {
    return wrapResponse([&]() {
        return m_HDWallet.GetAddresses(mode);
    });
}

string Pastel::GetWalletPubKey() {
    return wrapResponse([&]() {
        return m_HDWallet.GetWalletPubKey();
    });
}

string Pastel::SignWithWalletKey(string message) {
    return wrapResponse([&]() {
        return m_HDWallet.SignWithWalletKey(message);
    });
}

string Pastel::GetPubKeyAt(uint32_t addrIndex) {
    return wrapResponse([&]() {
        return m_HDWallet.GetPubKeyAt(addrIndex);
    });
}

string Pastel::SignWithKeyAt(uint32_t addrIndex, string message) {
    return wrapResponse([&]() {
        return m_HDWallet.SignWithKeyAt(addrIndex, message);
    });
}

string Pastel::MakeNewPastelID()
{
    return wrapResponse([&]() {
        return m_HDWallet.MakeNewPastelID();
    });
}

string Pastel::GetPastelIDByIndex(uint32_t addrIndex, PastelIDType type)
{
    return wrapResponse([&]() {
        return m_HDWallet.GetPastelID(addrIndex, type);
    });
}

string Pastel::GetPastelID(const string& pastelID, PastelIDType type)
{
    return wrapResponse([&]() {
        return m_HDWallet.GetPastelID(pastelID, type);
    });
}

string Pastel::GetPastelIDsCount() {
    return wrapResponse([&]() {
        return m_HDWallet.GetPastelIDsCount();
    });
}

string Pastel::GetPastelIDs()
{
    return wrapResponse([&]() {
        return m_HDWallet.GetPastelIDs();
    });
}

string Pastel::SignWithPastelID(const string& pastelID, const string& message, PastelIDType type, bool fBase64) {
    return wrapResponse([&]() {
        return m_HDWallet.SignWithPastelID(pastelID, message, type, fBase64);
    });
}

string Pastel::VerifyWithPastelID(const string& pastelID, const string& message, const string& signature, bool fBase64){
    return wrapResponse([&]() {
        return m_HDWallet.VerifyWithPastelID(pastelID, message, signature, fBase64);
    });
}

string Pastel::VerifyWithLegRoast(const string& lrPubKey, const string& message, const string& signature, bool fBase64){
    return wrapResponse([&]() {
        return m_HDWallet.VerifyWithLegRoast(lrPubKey, message, signature, fBase64);
    });
}

string Pastel::ExportPastelIDKeys(const string& pastelID, string passPhrase, const string& sDirPath) {
    return wrapResponse([&]() {
        return m_HDWallet.ExportPastelIDKeys(pastelID, std::move(passPhrase), sDirPath);
    });
}

string Pastel::GetSecret(uint32_t addrIndex, NetworkMode mode) {
    return wrapResponse([&]() {
        return m_HDWallet.GetSecret(addrIndex, mode);
    });
}

// Transaction functions
string Pastel::CreateSendToTransaction(NetworkMode mode,
                                       const vector<pair<string, CAmount>>& sendTo, const string& sendFrom,
                                       v_utxos& utxos, const uint32_t nHeight, int nExpiryHeight) {

    SendToTransactionBuilder sendToTransactionBuilder(mode, nHeight);
    if (nExpiryHeight > 0)
        sendToTransactionBuilder.SetExpiration(nExpiryHeight);

    return wrapResponse([&]() {
        return sendToTransactionBuilder.Create(sendTo, sendFrom, utxos, m_HDWallet);
    });
}


#ifdef __EMSCRIPTEN__
EMSCRIPTEN_BINDINGS(PastelModule) {
    emscripten::enum_<NetworkMode>("NetworkMode")
        .value("Mainnet", NetworkMode::MAINNET)
        .value("Testnet", NetworkMode::TESTNET)
        .value("Devnet", NetworkMode::DEVNET)
        ;
    emscripten::enum_<PastelIDType>("PastelIDType")
        .value("PastelID", PastelIDType::PASTELID)
        .value("LegRoast", PastelIDType::LEGROAST)
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
        .function("GetAddressesCount", &Pastel::GetAddressesCount)
        .function("GetAddresses", &Pastel::GetAddresses)

        .function("MakeNewPastelID", &Pastel::MakeNewPastelID)
        .function("GetPastelIDByIndex", &Pastel::GetPastelIDByIndex)
        .function("GetPastelID", &Pastel::GetPastelID)
        .function("GetPastelIDsCount", &Pastel::GetPastelIDsCount)
        .function("GetPastelIDs", &Pastel::GetPastelIDs)
        .function("SignWithPastelID", &Pastel::SignWithPastelID)
        .function("VerifyWithPastelID", &Pastel::VerifyWithPastelID)
        .function("VerifyWithLegRoast", &Pastel::VerifyWithLegRoast)
        .function("ExportPastelIDKeys", &Pastel::ExportPastelIDKeys)

        .function("GetWalletPubKey", &Pastel::GetWalletPubKey)
        .function("SignWithWalletKey", &Pastel::SignWithWalletKey)
        .function("GetPubKeyAt", &Pastel::GetPubKeyAt)
        .function("SignWithKeyAt", &Pastel::SignWithKeyAt)
        ;
    // Add more bindings as needed
}
#endif
