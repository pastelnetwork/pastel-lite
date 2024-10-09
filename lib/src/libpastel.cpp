// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "libpastel.h"
#include "support/response.hpp"
#include "base58.h"
#include "crypto/common.h"
#include "hd_wallet.h"
#include <json/json.hpp>

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#endif

using namespace std;
using json = nlohmann::json;

Pastel::Pastel() {
    init_and_check_sodium();
}

string Pastel::CreateNewWallet(const string &password) {
    return wrapResponse([&]() {
        return m_HDWallet.SetupNewWallet(password);
    });
}

string Pastel::CreateWalletFromMnemonic(const string &password, const string &mnemonic) {
    return wrapResponse([&]() {
        return m_HDWallet.SetupNewWalletFromMnemonic(password, mnemonic);
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

string Pastel::MakeNewPastelID(bool makeLegRoast)
{
    return wrapResponse([&]() {
        return m_HDWallet.MakeNewPastelID(makeLegRoast);
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

string Pastel::ImportPastelIDKeys(const string& pastelID, string passPhrase, const string& sDirPath) {
    return wrapResponse([&]() {
        return m_HDWallet.ImportPastelIDKeys(pastelID, std::move(passPhrase), sDirPath);
    });
}

string Pastel::GetSecret(uint32_t addrIndex, NetworkMode mode) {
    return wrapResponse([&]() {
        return m_HDWallet.GetSecret(addrIndex, mode);
    });
}

string Pastel::GetSecret(const string& address, NetworkMode mode) {
    return wrapResponse([&]() {
        return m_HDWallet.GetSecret(address, mode);
    });
}

// Transaction functions
string Pastel::CreateSendToTransaction(NetworkMode mode,
                                       const vector<pair<string, CAmount>>& sendTo, const string& sendFrom,
                                       v_utxos& utxos, uint32_t nHeight, int nExpiryHeight) {

    SendToTransactionBuilder sendToTransactionBuilder(mode, nHeight);
    if (nExpiryHeight > 0)
        sendToTransactionBuilder.SetExpiration(nExpiryHeight);

    return wrapResponse([&]() {
        return sendToTransactionBuilder.Create(sendTo, sendFrom, utxos, m_HDWallet);
    });
}

/*
sendToJson:
 [
     {
        "address": "44oVSAF5rocpsXzCXbJsF4NTPCPGEZMWKWMo",
        "amount": 501, // in PSL not patoshis!!!
     },
     ...
 ]

 utxosJson:
 [
     {
        "address": "44oVSAF5rocpsXzCXbJsF4NTPCPGEZMWKWMo",
        "txid": "35f467563ca38c74a9f9ee17291d042b72b0a766793ebe9153a408e72284e1a0",
        "outputIndex": 1,
        "script": "76a914cb4469283743420302d9ccddf5d0e10c68eae09c88ac",
        "patoshis": 50100000,
        "height": 78920
     },
     ...
 ]
 */
string Pastel::CreateSendToTransactionJson(NetworkMode mode, const string& sendToJson, const string& sendFrom,
                                           const string& utxosJson, uint32_t nHeight, int nExpiryHeight) {
    if (sendToJson.empty())
        return wrapResponse([&]() {
            throw runtime_error("Empty sendTo JSON");
        });
    if (utxosJson.empty())
        return wrapResponse([&]() {
            throw runtime_error("Empty UTXOs JSON");
        });
    v_utxos utxos;
    if (!utxosJsonToVector(utxosJson, utxos))
        return wrapResponse([&]() {
            throw runtime_error("Invalid UTXOs JSON");
        });

    vector<pair<string, CAmount>> sendTo;
    nlohmann::json j = nlohmann::json::parse(sendToJson);
    for (const auto& item : j)
    {
        string address = item["address"].get<string>();
        CAmount amount = item["amount"].get<double>();
        sendTo.emplace_back(address, amount);
    }
    return CreateSendToTransaction(mode, sendTo, sendFrom, utxos, nHeight, nExpiryHeight);
}

string Pastel::CreateRegisterPastelIdTransaction(const NetworkMode mode,
                                                 const string& pastelID, const string& fundingAddress,
                                                 v_utxos& utxos, const uint32_t nHeight, const int nExpiryHeight) {

    RegisterPastelIDTransactionBuilder pastelIdTransactionBuilder(mode, nHeight);
    if (nExpiryHeight > 0)
        pastelIdTransactionBuilder.SetExpiration(nExpiryHeight);

    return wrapResponse([&]() {
        return pastelIdTransactionBuilder.Create(pastelID, fundingAddress, utxos, m_HDWallet);
    });
}

/*
utxosJson:
 [
     {
        "address": "44oVSAF5rocpsXzCXbJsF4NTPCPGEZMWKWMo",
        "txid": "35f467563ca38c74a9f9ee17291d042b72b0a766793ebe9153a408e72284e1a0",
        "outputIndex": 1,
        "script": "76a914cb4469283743420302d9ccddf5d0e10c68eae09c88ac",
        "patoshis": 50100000,
        "height": 78920
     },
     ...
 ]
*/
string Pastel::CreateRegisterPastelIdTransactionJson(const NetworkMode mode, const  string& pastelID, const string& fundingAddress,
                                                     const string& utxosJson, const uint32_t nHeight, const int nExpiryHeight) {
    if (utxosJson.empty())
        return wrapResponse([&]() {
            throw runtime_error("Empty UTXOs");
        });
    if (pastelID.empty())
        return wrapResponse([&]() {
            throw runtime_error("Empty PastelID");
        });
    if (fundingAddress.empty())
        return wrapResponse([&]() {
            throw runtime_error("Empty funding address");
        });

    v_utxos utxos;
    if (!utxosJsonToVector(utxosJson, utxos))
        return wrapResponse([&]() {
            throw runtime_error("Invalid UTXOs JSON");
        });
    return CreateRegisterPastelIdTransaction(mode, pastelID, fundingAddress, utxos, nHeight, nExpiryHeight);
}

bool Pastel::utxosJsonToVector(const string& utxosJson, v_utxos& utxos) {
    nlohmann::json j = nlohmann::json::parse(utxosJson);
    for (const auto& item : j)
    {
        utxo u;
        u.address = item["address"].get<string>();
        u.txid = item["txid"].get<string>();
        u.n = item["outputIndex"].get<int>();
        u.value = item["patoshis"].get<int64_t>();
        utxos.push_back(u);
    }
    return !utxos.empty();
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
        .function("ImportPastelIDKeys", &Pastel::ImportPastelIDKeys)

        .function("GetWalletPubKey", &Pastel::GetWalletPubKey)
        .function("SignWithWalletKey", &Pastel::SignWithWalletKey)
        .function("GetPubKeyAt", &Pastel::GetPubKeyAt)
        .function("SignWithKeyAt", &Pastel::SignWithKeyAt)

        .function("CreateSendToTransaction", &Pastel::CreateSendToTransactionJson)
        .function("CreateRegisterPastelIdTransaction", &Pastel::CreateRegisterPastelIdTransactionJson)
        ;
    // Add more bindings as needed
}
#endif
