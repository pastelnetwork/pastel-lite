// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "libpastel.h"
#include "base58.h"
#include "crypto/common.h"
#include "hd_wallet.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#endif

using namespace std;

Pastel::Pastel(){
    init_and_check_sodium();
}
string Pastel::CreateNewWallet(NetworkMode mode, const SecureString& password)
{
    return m_HDWallet.SetupNewWallet(mode, password);
}

void Pastel::CreateWalletFromMnemonic(const string& mnemonic, NetworkMode mode, const SecureString& password)
{

}
string Pastel::ExportWallet()
{
    CSecureDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << m_HDWallet;
    vector<unsigned char> vchWallet(ss.begin(), ss.end());
    auto strWallet = EncodeBase58(vchWallet);
    return strWallet;
}
void Pastel::ImportWallet(const string& data, const SecureString& password)
{
    vector<unsigned char> vchWallet;
    if (!DecodeBase58(data, vchWallet)) {
        throw runtime_error("Failed to decode base58 wallet data");
    }
    CSecureDataStream ss(vchWallet, SER_NETWORK, PROTOCOL_VERSION);
    ss >> m_HDWallet;
    m_HDWallet.Unlock(password);
}

string Pastel::GetNewAddress()
{
    return m_HDWallet.GetNewAddress();
}
string Pastel::GetNewAddressByIndex(uint32_t addrIndex)
{
    return m_HDWallet.GetAddress(addrIndex);
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
        .function("CreateNewWallet", &Pastel::CreateNewWallet)
        .function("ImportWallet", &Pastel::ImportWallet)
        .function("GetNewAddress", &Pastel::GetNewAddress)
        .function("GetNewAddressByIndex", &Pastel::GetNewAddressByIndex)
        ;
    // Add more bindings as needed
}
#endif
