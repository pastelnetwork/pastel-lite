// signer.h
#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <utility>

#include "transaction/script.h"
#include "hd_wallet.h"
#include "standard.h"

constexpr size_t TX_SIGNATURE_SCRIPT_SIZE = 139;

struct TransactionData {
    unsigned int index;
    CAmount amount;
    uint8_t nHashType;
    const CMutableTransaction& tx;
};

class Signer {
    CHDWallet &m_hdWallet;

    bool CreateSig(v_uint8& vchSig, const CKeyID& keyId, const CScript& scriptCode, const TransactionData& txData);
    bool Sign1(const CKeyID& address, const CScript& scriptCode, vector<v_uint8>& retSignature, const TransactionData& txData);
    bool SignN(const vector<v_uint8>& multisigdata, const CScript& scriptCode, vector<v_uint8>& retSignature, const TransactionData& txData);
    bool SignStep(const CScript& scriptPubKey, vector<v_uint8>& ret, const TransactionData& txData);
    static CScript MakeScriptSig(const vector<v_uint8>& values);
    CTxDestination ExtractDestination(const CScript& scriptPubKey);

public:
    Signer() = delete;
    explicit Signer(CHDWallet &hdWallet) : m_hdWallet(hdWallet) {
        if (hdWallet.IsLocked()) {
            throw runtime_error("Cannot create signer - wallet is locked");
        }
    }

    bool ProduceSignature(const CScript& fromPubKey, CMutableTransaction& txToIn,
                          unsigned int nIn, CAmount amountIn, uint8_t nHashTypeIn);
};