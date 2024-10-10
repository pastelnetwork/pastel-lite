// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <vector>

#include "transaction/signer.h"

using namespace std;

bool Signer::CreateSig(v_uint8& vchSig, const CKeyID& keyId, const CScript& scriptCode, const TransactionData& txData)
{
    auto key = m_hdWallet._getDerivedKey(keyId);
    if (!key.has_value())
    {
        key = m_hdWallet._getLegacyKey(keyId);
        if (!key.has_value())
            return false;
    }

    uint256 hash;
    try {
        hash = SignatureHash(scriptCode, txData.tx, txData.index, txData.nHashType, txData.amount);
    } catch (logic_error ex) {
        return false;
    }

    if (!key.value().Sign(hash, vchSig))
        return false;
    vchSig.push_back(txData.nHashType);
    return true;
}

bool Signer::Sign1(const CKeyID& address, const CScript& scriptCode, vector<v_uint8>& retSignature, const TransactionData& txData)
{
    v_uint8 vchSig;
    if (!CreateSig(vchSig, address, scriptCode, txData))
        return false;
    retSignature.push_back(vchSig);
    return true;
}

bool Signer::SignN(const vector<v_uint8>& multisigdata, const CScript& scriptCode, vector<v_uint8>& retSignature, const TransactionData& txData)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const v_uint8& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, scriptCode, retSignature, txData))
            ++nSigned;
    }
    return nSigned==nRequired;
}

bool Signer::SignStep(const CScript& scriptPubKey, vector<v_uint8>& ret, const TransactionData& txData)
{
    CScript scriptRet;
    uint160 h160;
    ret.clear();

    txnouttype whichTypeRet;
    vector<v_uint8> vSolutions;
    // get public keys or their hashes from scriptPubKey
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    switch (whichTypeRet)
    {
        case TX_NONSTANDARD:
        case TX_NULL_DATA:
        case TX_SCRIPTHASH:
            // light wallet doesn't support pay-to-script
            return false;
        case TX_PUBKEY:
            // scriptSig is just `<signature>`
            keyID = CPubKey(vSolutions[0]).GetID(); // get keyID from pub key
            return Sign1(keyID, scriptPubKey, ret, txData);
        case TX_PUBKEYHASH:
        {
            // scriptSig is `<signature> <pubKey>`
            keyID = CKeyID(uint160(vSolutions[0])); // get keyID from pub key hash
            if (!Sign1(keyID, scriptPubKey, ret, txData))
                return false;
            auto pubKey = m_hdWallet._getPubKey(keyID);    // Find PubKey by keyID
            if (pubKey.has_value()) {
                ret.push_back(ToByteVector(pubKey.value()));
                return true;
            }
            return false;
        }
        case TX_MULTISIG:
            // scriptSig is `OP_0 <signature1> <signature2> ... <signatureM>`
            ret.emplace_back(); // work around CHECKMULTISIG bug
            return (SignN(vSolutions, scriptPubKey, ret, txData));
        default:
            return false;
    }
}

CScript Signer::MakeScriptSig(const vector<v_uint8>& values)
{
    CScript result;
    for (const auto &v : values)
    {
        if (v.empty())
            result << OP_0;
        else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16)
            result << CScript::EncodeOP_N(v[0]);
        else
            result << v;
    }
    return result;
}

bool Signer::ProduceSignature(const CScript& fromPubKey, CMutableTransaction& txToIn,
                              unsigned int nIn, CAmount amountIn, const uint8_t nHashTypeIn)
{
    vector<v_uint8> result;
    if (SignStep(fromPubKey, result, {nIn, amountIn, nHashTypeIn, txToIn})){
        auto scriptSig = MakeScriptSig(result);
        // Test solution
        MutableTransactionSignatureChecker checker(txToIn, nIn, amountIn);
        if (VerifyScript(scriptSig, fromPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, checker)) {
            txToIn.vin[nIn].scriptSig = scriptSig;
            return true;
        }
    }
    return false;
}
