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
#include "hd_wallet.h"

using namespace std;

struct utxo
{
    string address;
    string txid;
    int n;
    CAmount value;
};

typedef vector<utxo> v_utxos;
typedef vector<pair<string, CAmount>> sendto_addresses;
typedef map<string, CScript> addr_pubkeys;


class TransactionBuilder{
public:
    TransactionBuilder() = delete;
    TransactionBuilder(NetworkMode mode, uint32_t nHeight);

    void SetExpiration(int nExpiryHeight);
    string Create(const sendto_addresses& sendTo, const string& sendFrom, v_utxos& utxos, CHDWallet& hdWallet);

protected:
    virtual void setOutputs(const sendto_addresses& sendTo) = 0;
    virtual void setInputs(v_utxos& utxos);

    CMutableTransaction m_mtx;
    const CChainParams& m_Params;
    optional<string> m_sFromAddress;
    CAmount m_nAllSpentAmountInPat = 0;

    v_utxos m_vSelectedUTXOs;
    addr_pubkeys m_mInputPubKeys;
    size_t m_numOutputs = 0;

    void signTransaction(CHDWallet& hdWallet);
    string encodeHexTx();

    void setChangeOutput(CAmount nChange);
    void validateAddress(const string& address);
};

class SendToTransactionBuilder : public TransactionBuilder {
public:
    SendToTransactionBuilder(NetworkMode mode, const uint32_t nHeight) : TransactionBuilder(mode, nHeight) {}

protected:
    void setOutputs(const sendto_addresses& sendTo) override;

private:
    std::vector<CScript> m_vOutScripts;
};
