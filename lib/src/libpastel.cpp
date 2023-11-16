//
// Created by Pastel Developers on 11/9/23.
//
#include <iostream>
#include "libpastel.h"
#include "base58.h"
#include "pubkey.h"
#include "key.h"
#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#endif

using namespace std;

Pastel::Pastel(){
    m_Networks[MAINNET] = new CMainnetParams();
    m_Networks[TESTNET] = new CTestnetParams();
    m_Networks[REGTEST] = new CRegtestParams();
}

static string encodePublicKey(const CKeyID& id, CChainParams* network)
{
    v_uint8 pubKey = network->Base58Prefix(CChainParams::Base58Type::PUBKEY_ADDRESS);
    pubKey.insert(pubKey.end(), id.begin(), id.end());
    return EncodeBase58Check(pubKey);
}

string Pastel::GetNewAddress(NetworkMode mode)
{
    CKey secret;
    secret.MakeNewKey(true);

    CPubKey newKey = secret.GetPubKey();
    assert(secret.VerifyPubKey(newKey));

    // Get private key
    secret.GetPrivKey();

    // Get and encode public key
    CKeyID keyID = newKey.GetID();
    CChainParams *network = m_Networks[mode];
    return encodePublicKey(keyID, network);
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_BINDINGS(PastelModule) {
    emscripten::class_<Pastel>("Pastel")
        .constructor<>()
        .function("GetNewAddress", &Pastel::GetNewAddress);
    // Add more bindings as needed
}
#endif
