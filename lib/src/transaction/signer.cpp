// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <vector>

#include "transaction/signer.h"
#include "standard.h"
#include <stdexcept>

using namespace std;


bool Signer::CreateSig(v_uint8& vchSig, const CKeyID& keyId, 
                       const CScript& scriptCode, const TransactionData& txData) {
    printf("CreateSig for keyID: %s\n", keyId.ToString().c_str());
    
    // Retrieve the key directly
    auto key = m_hdWallet.getKeyForAddress(keyId, "");
    if (!key.has_value() || !key->IsValid()) {
        printf("Failed to get valid key\n");
        return false;
    }

    uint256 hash = SignatureHash(scriptCode, txData.tx, txData.index, 
                                txData.nHashType, txData.amount);
                                
    if (!key->Sign(hash, vchSig)) {
        printf("Signing failed\n");
        return false;
    }
    
    vchSig.push_back(static_cast<unsigned char>(txData.nHashType));
    return true;
}


bool Signer::Sign1(const CKeyID& address, const CScript& scriptCode, 
                  vector<v_uint8>& retSignature, const TransactionData& txData) {
    printf("Sign1 called for address: %s\n", address.ToString().c_str());
    v_uint8 vchSig;
    if (!CreateSig(vchSig, address, scriptCode, txData)) {
        printf("CreateSig failed\n");
        return false;
    }
    printf("CreateSig succeeded\n");
    retSignature.push_back(vchSig);
    return true;
}

bool Signer::SignN(const vector<v_uint8>& multisigdata, const CScript& scriptCode, 
                  vector<v_uint8>& retSignature, const TransactionData& txData) {
    printf("SignN called for multisig data\n");
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    printf("Required signatures: %d\n", nRequired);

    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++) {
        const v_uint8& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        printf("Attempting to sign with key %s\n", keyID.ToString().c_str());
        
        if (Sign1(keyID, scriptCode, retSignature, txData)) {
            printf("Successfully signed with key %s\n", keyID.ToString().c_str());
            ++nSigned;
        } else {
            printf("Failed to sign with key %s\n", keyID.ToString().c_str());
        }
    }
    
    printf("Signed %d out of %d required signatures\n", nSigned, nRequired);
    return nSigned==nRequired;
}

CTxDestination Signer::ExtractDestination(const CScript& scriptPubKey) {
    CTxDestination dest;
    if (!::ExtractDestination(scriptPubKey, dest)) {
        printf("Failed to extract destination from scriptPubKey\n");
        throw std::runtime_error("Failed to extract destination");
    }
    return dest;
}

// signer.cpp

bool Signer::SignStep(const CScript& scriptPubKey, vector<v_uint8>& ret,
                      const TransactionData& txData) {
    CScript scriptRet;
    uint160 h160;
    ret.clear();

    txnouttype whichTypeRet;
    vector<v_uint8> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions)) {
        printf("Script solver failed\n");
        return false;
    }
    printf("Script type: %d\n", whichTypeRet);

    switch (whichTypeRet) {
        case TX_PUBKEY:
            printf("Processing TX_PUBKEY\n");
            {
                CKeyID keyID = CPubKey(vSolutions[0]).GetID();
                return Sign1(keyID, scriptPubKey, ret, txData);
            }

        case TX_PUBKEYHASH:
            printf("Processing TX_PUBKEYHASH\n");
            {
                CKeyID keyID = CKeyID(uint160(vSolutions[0]));
                if (!Sign1(keyID, scriptPubKey, ret, txData))
                    return false;
                    
                auto key = m_hdWallet.getKeyForAddress(keyID, "");
                if (!key.has_value() || !key->IsValid()) {
                    printf("No key found for keyID after signing\n");
                    return false;
                }
                
                // Push the public key into the signature script
                ret.push_back(ToByteVector(key->GetPubKey()));
                return true;
            }

        case TX_MULTISIG:
            printf("Processing TX_MULTISIG\n");
            ret.push_back(v_uint8()); // workaround CHECKMULTISIG bug
            return (SignN(vSolutions, scriptPubKey, ret, txData));

        default:
            printf("Unsupported transaction type: %d\n", whichTypeRet);
            return false;
    }
}


CScript Signer::MakeScriptSig(const vector<v_uint8>& values) {
    CScript result;
    for (const auto &v : values) {
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
                             unsigned int nIn, CAmount amountIn, uint8_t nHashTypeIn) {
    TransactionData txData = { nIn, amountIn, nHashTypeIn, txToIn };
    
    vector<v_uint8> sig;
    if (!SignStep(fromPubKey, sig, txData))
        return false;

    txToIn.vin[nIn].scriptSig = MakeScriptSig(sig);

    return VerifyScript(txToIn.vin[nIn].scriptSig, fromPubKey, 
                       STANDARD_SCRIPT_VERIFY_FLAGS,
                       MutableTransactionSignatureChecker(txToIn, nIn, amountIn));
}