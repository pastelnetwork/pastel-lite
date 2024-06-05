// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <fmt/core.h>

//#include "transaction/sign.h"
constexpr size_t TX_SIGNATURE_SCRIPT_SIZE = 139;


#include "chain.h"
#include "utils.h"
#include "key_io.h"
#include "version.h"
#include "serialize.h"
#include "rawtransaction.h"

static constexpr uint32_t DEFAULT_TX_EXPIRY_DELTA = 20;
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE = 30;
static constexpr uint32_t TX_EXPIRING_SOON_THRESHOLD = 3;
static constexpr CAmount DEFAULT_TRANSACTION_FEE = 0;
static constexpr CAmount DEFAULT_TRANSACTION_MAXFEE = static_cast<CAmount>(0.1 * COIN);

CAmount GetMinimumFee(const size_t nTxBytes)
{
    CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
    CFeeRate minTxFee(1000);
    CFeeRate minRelayTxFee(DEFAULT_MIN_RELAY_TX_FEE);

    CAmount nFeeNeeded = payTxFee.GetFee(nTxBytes);
    if (nFeeNeeded == 0) {
        nFeeNeeded = minTxFee.GetFee(nTxBytes);
    }
    if (nFeeNeeded < minRelayTxFee.GetFee(nTxBytes)) {
        nFeeNeeded = minRelayTxFee.GetFee(nTxBytes);
    }
    if (nFeeNeeded > DEFAULT_TRANSACTION_MAXFEE) {
        nFeeNeeded = DEFAULT_TRANSACTION_MAXFEE;
    }
    return nFeeNeeded;
}

TransactionBuilder::TransactionBuilder(NetworkMode mode, const uint32_t nHeight) : m_Params(GetChainParams(mode)) {
    m_mtx.fOverwintered = true;
    m_mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    m_mtx.nVersion = SAPLING_TX_VERSION;
    m_mtx.nExpiryHeight = nHeight + DEFAULT_TX_EXPIRY_DELTA;
}

void TransactionBuilder::SetExpiration(int nExpiryHeight) {
    if (nExpiryHeight > 0)
    {
        if (nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD)
            throw runtime_error(fmt::format("Invalid parameter, expiryHeight must be less than {}.", TX_EXPIRY_HEIGHT_THRESHOLD));
        if (m_mtx.nExpiryHeight - DEFAULT_TX_EXPIRY_DELTA + TX_EXPIRING_SOON_THRESHOLD > nExpiryHeight)
        {
            throw runtime_error(fmt::format("Invalid parameter, expiryHeight should be at least {} to avoid transaction expiring soon",
                                            m_mtx.nExpiryHeight - DEFAULT_TX_EXPIRY_DELTA + TX_EXPIRING_SOON_THRESHOLD));
        }
        m_mtx.nExpiryHeight = static_cast<uint32_t>(nExpiryHeight);
    }
}

string TransactionBuilder::Create(const sendto_addresses& sendTo, const string& sendFrom, tnx_outputs& utxos)
{
    if (!sendFrom.empty()) {
        m_sFromAddress = sendFrom;
        KeyIO keyIO(m_Params);
        m_fromAddress = keyIO.DecodeDestination(sendFrom);
        if (!IsValidDestination(m_fromAddress.value())) {
            throw runtime_error(
                    fmt::format("Not a valid transparent address [{}] used for funding the transaction", sendFrom));
        }
    }

    setOutputs(sendTo);
    setInputs(utxos);
    signTransaction();
    return encodeHexTx();
}

void TransactionBuilder::setInputs(tnx_outputs& utxos)
{
    // Sort the utxos by their values, ascending
    sort(utxos.begin(), utxos.end(), [](const COutput& a, const COutput& b)
    {
        return a.value < b.value;
    });

    // make few passes:
    //  1) without tx fee, calculate exact required transaction fee at the end
    //  2) with tx fee included, add inputs if required
    //  3) if tx fee changes after adding inputs (tx size increased), repeat 2) again

    CAmount nTotalValueInPat = 0;   // total value of all selected outputs in patoshis
    CAmount nTxFeeInPat = 0;        // transaction fee in patoshis
    uint32_t nPass = 0;
    constexpr uint32_t MAX_TXFEE_PASSES = 4;
    while (nPass < MAX_TXFEE_PASSES)
    {
        if (nPass != 0) // Not the first pass
        {
            // calculate correct transaction fee based on the transaction size
            size_t nTxSize = GetSerializeSize(m_mtx, SER_NETWORK, PROTOCOL_VERSION);
            // add signature size for each input
            nTxSize += m_mtx.vin.size() * TX_SIGNATURE_SCRIPT_SIZE;
            CAmount nNewTxFeeInPat = GetMinimumFee(nTxSize);

            // if the new fee is within 1% of the previous fee, then we are done
            // but still will try to apply the new tx fee if it fits into the current inputs
            const bool bTxFeeApplied = abs(nNewTxFeeInPat - nTxFeeInPat) < nNewTxFeeInPat / 100;

            // tx fee has changed, add more inputs to cover the new fee if required
            m_nAllSpentAmountInPat += (nNewTxFeeInPat - nTxFeeInPat);
            nTxFeeInPat = nNewTxFeeInPat;

            if (nTotalValueInPat >= m_nAllSpentAmountInPat)
            {
                // we have enough coins to cover the new fee, no need to add more inputs
                // just need to update the change output, send change (in patoshis) output back to the last input address
                setChangeOutput(nTotalValueInPat - m_nAllSpentAmountInPat);
                break;
            }
            // we don't want more iterations to adjust the tx fee - it's already close enough
            if (bTxFeeApplied)
                break;
        }
        // Find funding (unspent) transactions with enough coins to cover all outputs
        int64_t nLastUsedOutputNo = -1;
        for (const auto& txOut: utxos)
        {
            ++nLastUsedOutputNo;

            if (m_fromAddress.has_value()) // use utxo only from the specified funding address
            {
                if (txOut.address != m_sFromAddress)
                    continue;
            }

            CTxIn input;
            input.prevout.n = txOut.n;
            input.prevout.hash = uint256S(txOut.txid);
            m_mtx.vin.emplace_back(std::move(input));
            m_vSelectedOutputs.push_back(txOut);

            nTotalValueInPat += txOut.value*COIN;

            if (nTotalValueInPat >= m_nAllSpentAmountInPat)
                break; // found enough coins
        }
        // return an error if we don't have enough coins to cover all outputs
        if (nTotalValueInPat < m_nAllSpentAmountInPat)
        {
            if (m_vSelectedOutputs.empty())
                throw runtime_error(fmt::format("No unspent transaction found {} - cannot send data to the blockchain!",
                                                m_fromAddress.has_value() ?
                                                fmt::format("for address [{}]", m_sFromAddress) :
                                                ""));
            else
                throw runtime_error(
                        fmt::format("Not enough coins in the unspent transactions {} to cover the spending of {} PSL. Cannot send data to the blockchain!",
                                    m_fromAddress.has_value() ? fmt::format(" for address [{}]", m_sFromAddress) : "", m_nAllSpentAmountInPat/COIN));
        }
        // remove from vOutputs all selected outputs
        if (!utxos.empty() && (nLastUsedOutputNo >= 0))
            utxos.erase(utxos.cbegin(), utxos.cbegin() + nLastUsedOutputNo + 1);

        // Send change (in patoshis) output back to the last input address
        setChangeOutput(nTotalValueInPat - m_nAllSpentAmountInPat);

        ++nPass;
    }
    if (nPass >= MAX_TXFEE_PASSES)
    {
        throw runtime_error(
                fmt::format("Could not calculate transaction fee. Cannot send data to the blockchain!"));
    }
}

void TransactionBuilder::setChangeOutput(const CAmount nChange)
{
    KeyIO keyIO(m_Params);

    const auto& lastTxOut = m_vSelectedOutputs.back();
    CTxDestination destination = keyIO.DecodeDestination(lastTxOut.address);
    if (!IsValidDestination(destination))
        throw runtime_error(string("Invalid Pastel address: ") + lastTxOut.address);

    if (m_mtx.vout.size() == m_numOutputs)
        m_mtx.vout.resize(m_numOutputs+1);

    m_mtx.vout[m_numOutputs].nValue = nChange;
    m_mtx.vout[m_numOutputs].scriptPubKey = GetScriptForDestination(destination);
}

void TransactionBuilder::signTransaction()
{
/*
    vector<future<void>> futures;
    futures.reserve(tx_out.vin.size());
    mutex m;
    atomic_bool bSignError(false);

    for (uint32_t i = 0; i < tx_out.vin.size(); i++)
    {
        futures.emplace_back(async(launch::async, [&](uint32_t i)
        {
            try
            {
                const auto& output = m_vSelectedOutputs[i];
                const auto& txOut = output.tx->vout[output.i];
                const CScript& prevPubKey = txOut.scriptPubKey;
                const CAmount prevAmount = txOut.nValue;
                SignatureData sigdata;
                if (!ProduceSignature(
                        MutableTransactionSignatureCreator(pwalletMain, &tx_out, i, prevAmount, to_integral_type(SIGHASH::ALL)),
                        prevPubKey, sigdata, m_consensusBranchId))
                    throw runtime_error("Failed to produce a signature script");
                UpdateTransaction(tx_out, i, sigdata);
            } catch (const exception& e)
            {
                lock_guard<mutex> lock(m);
                bSignError = true;
                m_error = strprintf("Error signing transaction input #%u. %s", i, e.what());
            }
        }, i));
    }
    for (auto &f: futures)
        f.get();
    return !bSignError;
*/
}

string TransactionBuilder::encodeHexTx()
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << m_mtx;
    return HexStr(ssTx.begin(), ssTx.end());
}

void SendToTransactionBuilder::setOutputs(const sendto_addresses& sendTo)
{
    KeyIO keyIO(m_Params);
    set<CTxDestination> destinations;
    for (const auto& sendToItem : sendTo)
    {
        CTxDestination destination = keyIO.DecodeDestination(sendToItem.first);
        if (!IsValidDestination(destination))
            throw runtime_error(string("Invalid Pastel address: ") + sendToItem.first);

        if (!destinations.insert(destination).second)
            throw runtime_error(string("Invalid parameter, duplicated address: ") + sendToItem.first);

        CScript scriptPubKey = GetScriptForDestination(destination);
        CAmount nAmount = sendToItem.second * COIN;
        CTxOut out(nAmount, scriptPubKey);

        m_mtx.vout.push_back(out);
        m_nAllSpentAmountInPat += nAmount;
    }
    m_numOutputs = m_mtx.vout.size();

    /* FOR TICKETS - TODO: move to child class
        m_numOutputs = m_vOutScripts.size();
        if (nPass == 0)
        {
            // Add fake output scripts only on first pass
            m_mtx.vout.resize(m_numOutputs + 1); // +1 for change output
            for (size_t i = 0; i < m_numOutputs; ++i)
            {
                m_mtx.vout[i].nValue = nPerOutputAmountInPat;
                m_mtx.vout[i].scriptPubKey = m_vOutScripts[i];
            }
            // MUST be precise!!!
            m_mtx.vout[0].nValue = nPerOutputAmountInPat + nLostAmountInPat;
            // Add extra outputs if required
            if (m_nExtraAmountInPat != 0)
            {
                for (const auto& extra : m_vExtraOutputs)
                    tx_out.vout.emplace_back(extra);
            }
        }
     */
}
