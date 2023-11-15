//
// Created by Pastel Developers on 11/9/23.
//
#include <iostream>
#include "libpastel.h"
#include "base58.h"
#include "pubkey.h"

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
    // Generate a new key that is added to wallet
    CPubKey newKey;
//    if (!pwalletMain->GetKeyFromPool(newKey))
//        throw;
    CKeyID keyID = newKey.GetID();

    CChainParams *network = m_Networks[mode];
    return encodePublicKey(keyID, network);
}
