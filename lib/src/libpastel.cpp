// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "libpastel.h"
#include "base58.h"
#include "pubkey.h"
#include "key.h"
#include "crypto/common.h"
#include "hd_wallet.h"
#include "streams.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#endif

using namespace std;

Pastel::Pastel(){
    m_Networks[NetworkMode::MAINNET] = new CMainnetParams();
    m_Networks[NetworkMode::TESTNET] = new CTestnetParams();
    m_Networks[NetworkMode::REGTEST] = new CRegtestParams();
    init_and_check_sodium();
}

static string encodePublicKey(const CKeyID& id, const CChainParams* network)
{
    v_uint8 pubKey = network->Base58Prefix(CChainParams::Base58Type::PUBKEY_ADDRESS);
    pubKey.insert(pubKey.end(), id.begin(), id.end());
    return EncodeBase58Check(pubKey);
}

string Pastel::GetNewAddress(const NetworkMode mode)
{
    CKey secret;
    secret.MakeNewKey(true);

    const CPubKey newKey = secret.GetPubKey();
    if (!secret.VerifyPubKey(newKey)) {
        throw std::runtime_error("Failed to verify public key");
    }

    // Get private key
    const CPrivKey privkey = secret.GetPrivKey();

    // Get and encode public key
    const CKeyID keyID = newKey.GetID();
    const CChainParams *network = m_Networks[mode];
    return encodePublicKey(keyID, network);
}
void Pastel::CreateNewWallet(NetworkMode mode, const SecureString& password)
{
    // Generate new random master key and encrypt it using key derived from password
    if (!m_HDWallet.SetMasterKey(password)) {
        throw std::runtime_error("Failed to set master key");
    }
    // Generate new random mnemonic seed and encrypt it using master key
//    auto bip44CoinType = m_Networks[mode]->BIP44CoinType();
//    MnemonicSeed seed = MnemonicSeed::Random(bip44CoinType, Language::English);
//    m_HDWallet.SetEncryptedMnemonicSeed(seed);
}
//void Pastel::ImportWalletFromMnemonic(const std::string& mnemonic, NetworkMode mode, SecureString password)
//{
//
//}
//void Pastel::ImportWallet(const std::vector<unsigned char>& data, SecureString password)
//{
//
//}
//std::vector<unsigned char> Pastel::ExportWallet()
//{
//    return std::vector<unsigned char>();
//}


#ifdef __EMSCRIPTEN__
EMSCRIPTEN_BINDINGS(PastelModule) {
    emscripten::enum_<NetworkMode>("NetworkMode")
        .value("Mainnet", NetworkMode::MAINNET)
        .value("Testnet", NetworkMode::TESTNET)
        .value("Regtest", NetworkMode::REGTEST)
        ;
    emscripten::class_<Pastel>("Pastel")
        .constructor<>()
        .function("GetNewAddress", &Pastel::GetNewAddress);
    // Add more bindings as needed
}
#endif
