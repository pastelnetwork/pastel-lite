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
#include "tickets/ticket.h"
#include "support/datacompressor.h"

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

protected:
    virtual void setOutputs() = 0;
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
    string Create(const sendto_addresses& sendTo, const string& sendFrom, v_utxos& utxos, CHDWallet& hdWallet);

protected:
    void setOutputs() override;

private:
    sendto_addresses m_sendTo;
};

class TicketTransactionBuilder : public TransactionBuilder {
public:
    TicketTransactionBuilder(NetworkMode mode, const uint32_t nHeight, CAmount extraPayment)
        : TransactionBuilder(mode, nHeight), m_nExtraAmountInPat(extraPayment) {}

protected:
    void processTicket(CPastelTicket& ticket);

    void setOutputs() override;

    CAmount m_nTicketPriceInPat;
    // Any extra payments to send with ticket
    CAmount m_nExtraAmountInPat;
    vector<CTxOut> m_vExtraOutputs;

private:
    std::vector<CScript> m_vOutScripts;
    size_t createP2FMSScripts(CCompressedDataStream& data_stream);
};

class RegisterPastelIDTransactionBuilder : public TicketTransactionBuilder {
public:
    RegisterPastelIDTransactionBuilder(NetworkMode mode, const uint32_t nHeight)
        : TicketTransactionBuilder(mode, nHeight, 0) {}

    string Create(string&& sPastelID, const string& sFundingAddress, v_utxos& utxos, CHDWallet& hdWallet);

protected:

private:
};
