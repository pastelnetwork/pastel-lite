// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "libpastel.h"
#include "support/response.hpp"
#include "base58.h"
#include "crypto/common.h"
#include "hd_wallet.h"
#include <json/json.hpp>
#include <cmath>

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#endif

using namespace std;
using json = nlohmann::json;

Pastel::Pastel() {
    init_and_check_sodium();
}

// Wallet functions
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

// Address functions
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
        auto count = m_HDWallet.GetAddressesCount();
        printf("Total addresses (HD + imported): %u\n", count);
        return count;
    });
}

string Pastel::GetAddresses(NetworkMode mode) {
    return wrapResponse([&]() {
        printf("Getting all addresses (HD and imported) for mode %d\n", static_cast<int>(mode));
        auto addresses = m_HDWallet.GetAddresses(mode);
        printf("Retrieved %zu total addresses\n", addresses.size());
        return addresses;
    });
}

string Pastel::MakeNewLegacyAddress(NetworkMode mode) {
    return wrapResponse([&]() {
        return m_HDWallet.MakeNewLegacyAddress(mode);
    });
}

string Pastel::ImportLegacyPrivateKey(const string& encoded_key, NetworkMode mode) {
    return wrapResponse([&]() {
        printf("Importing legacy private key and integrating with HD wallet tracking...\n");
        auto address = m_HDWallet.ImportLegacyPrivateKey(encoded_key, mode);
        printf("Successfully imported key for address: %s\n", address.c_str());
        return address;
    });
}

// PastelID functions
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

// Account specific functions
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

string Pastel::GetSecret(uint32_t addrIndex, NetworkMode mode) {
    return wrapResponse([&]() {
        printf("Getting secret for address index %u (mode: %d)\n", addrIndex, static_cast<int>(mode));
        auto secret = m_HDWallet.GetSecret(addrIndex, mode);
        if (secret.empty()) {
            throw runtime_error("Failed to get secret for address index");
        }
        return secret;
    });
}

string Pastel::GetAddressSecret(const string& address, NetworkMode mode) {
    return wrapResponse([&]() {
        printf("Getting secret for address: %s (mode: %d)\n", address.c_str(), static_cast<int>(mode));
        auto secret = m_HDWallet.GetSecret(address, mode);
        if (secret.empty()) {
            throw runtime_error("Failed to get secret for address");
        }
        return secret;
    });
}

// Transaction functions
string Pastel::CreateSendToTransaction(NetworkMode mode,
                                   const vector<pair<string, CAmount>>& sendTo, 
                                   const string& sendFrom,
                                   v_utxos& utxosJson, 
                                   uint32_t nHeight,
                                   int nExpiryHeight,
                                   const string& walletPassword) { // Add password parameter
    return wrapResponse([&]() {
        stringstream debug;
        debug << "Starting CreateSendToTransaction\n";
        debug << "From address: " << sendFrom << "\n";
        debug << "Total UTXOs: " << utxosJson.size() << "\n";
        
        // Log send to details 
        for (const auto& [addr, amount] : sendTo) {
            debug << "Sending " << amount << " patoshis to " << addr << "\n";
        }
        
        // Log UTXO details
        for (const auto& utxo : utxosJson) {
            debug << "Available UTXO: "
                 << "Address=" << utxo.address 
                 << ", TxId=" << utxo.txid
                 << ", Index=" << utxo.n 
                 << ", Amount=" << utxo.value << "\n";
        }

        // First check if wallet is locked and unlock it with provided password
        if (m_HDWallet.IsLocked()) {
            try {
                m_HDWallet.Unlock(walletPassword);
                if (m_HDWallet.IsLocked()) {
                    debug << "ERROR: Failed to unlock wallet with provided password\n";
                    throw runtime_error(debug.str());
                }
            } catch (const exception& e) {
                debug << "ERROR: Failed to unlock wallet: " << e.what() << "\n";
                throw runtime_error(debug.str());
            }
        }

        SendToTransactionBuilder sendToTransactionBuilder(mode, nHeight);
        if (nExpiryHeight > 0) {
            debug << "Setting expiry height to: " << nExpiryHeight << "\n";
            sendToTransactionBuilder.SetExpiration(nExpiryHeight);
        }

        try {
            debug << "Attempting to create transaction...\n";
            auto result = sendToTransactionBuilder.Create(sendTo, sendFrom, utxosJson, m_HDWallet);
            debug << "Transaction created successfully\n"; 
            return result;
        } catch (const exception& e) {
            debug << "Failed to create transaction: " << e.what() << "\n";
            throw runtime_error(debug.str());
        }
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
                                           const string& utxosJson, uint32_t nHeight, int nExpiryHeight,
                                           const string& walletPassword) {
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
        CAmount amount = 0;
        if (item["amount"].is_string()) {
            // Parse the string to a double, then convert to CAmount
            try {
                string amountStr = item["amount"].get<string>();
                double amountDouble = std::stod(amountStr);
                amount = static_cast<CAmount>(round(amountDouble * COIN));
            } catch (const std::exception& e) {
                throw runtime_error("Invalid amount format in JSON: " + string(e.what()));
            }
        } else if (item["amount"].is_number_float()) {
            double amountDouble = item["amount"].get<double>();
            amount = static_cast<CAmount>(round(amountDouble * COIN));
        } else if (item["amount"].is_number_integer()) {
            // If amount is provided in patoshis as integer
            amount = item["amount"].get<int64_t>();
        } else {
            throw runtime_error("Invalid amount type in JSON");
        }
        sendTo.emplace_back(address, amount);
    }
    return CreateSendToTransaction(mode, sendTo, sendFrom, utxos, nHeight, nExpiryHeight, walletPassword);
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
        u.value = 0;
        if (item["patoshis"].is_string()) {
            try {
                string valueStr = item["patoshis"].get<string>();
                u.value = std::stoll(valueStr);
            } catch (const std::exception& e) {
                throw runtime_error("Invalid patoshis format in UTXO JSON: " + string(e.what()));
            }
        } else if (item["patoshis"].is_number_integer()) {
            u.value = item["patoshis"].get<int64_t>();
        } else {
            throw runtime_error("Invalid patoshis type in UTXO JSON");
        }
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
        .function("ImportLegacyPrivateKey", &Pastel::ImportLegacyPrivateKey)

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
        .function("GetAddressSecret", &Pastel::GetAddressSecret)

        .function("CreateSendToTransaction", &Pastel::CreateSendToTransactionJson)
        .function("CreateRegisterPastelIdTransaction", &Pastel::CreateRegisterPastelIdTransactionJson)
        ;
    // Add more bindings as needed
}
#endif
