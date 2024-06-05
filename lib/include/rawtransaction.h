#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>

#include "chain.h"
#include "standard.h"
#include "transaction/amount.h"
#include "transaction/transaction.h"

using namespace std;

struct COutput
{
    string address;
    string txid;
    int n;
    CAmount value;
};

typedef vector<COutput> tnx_outputs;
typedef vector<pair<string, CAmount>> sendto_addresses;

class TransactionBuilder{
    TransactionBuilder() = delete;

public:
    TransactionBuilder(NetworkMode mode, const uint32_t nHeight);
    void SetExpiration(int nExpiryHeight);
    string Create(const sendto_addresses& sendTo, const string& sendFrom, tnx_outputs& utxos);

protected:
    virtual void setOutputs(const sendto_addresses& sendTo) = 0;
    virtual void setInputs(tnx_outputs& utxos);

    CMutableTransaction m_mtx;
    const CChainParams& m_Params;
    string m_sFromAddress;
    optional<CTxDestination> m_fromAddress;
    CAmount m_nAllSpentAmountInPat = 0;

    std::vector<CScript> m_vOutScripts;
    tnx_outputs m_vSelectedOutputs;

    size_t m_numOutputs = 0;

    void signTransaction();
    string encodeHexTx();

    void setChangeOutput(const CAmount nChange);
};

class SendToTransactionBuilder : public TransactionBuilder {
public:
    SendToTransactionBuilder(NetworkMode mode, const uint32_t nHeight) : TransactionBuilder(mode, nHeight) {}

protected:
    void setOutputs(const sendto_addresses& sendTo) override;
};
