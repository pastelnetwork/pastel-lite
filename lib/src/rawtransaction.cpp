// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <fmt/core.h>
#include <future>

#include "transaction/signer.h"
#include "tickets/pastelid.h"
#include "chain.h"
#include "utils.h"
#include "key_io.h"
#include "version.h"
#include "serialize.h"
#include "hash.h"
#include "standard.h"
#include "rawtransaction.h"

static constexpr uint32_t DEFAULT_TX_EXPIRY_DELTA = 20;
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE = 30;
static constexpr uint32_t TX_EXPIRING_SOON_THRESHOLD = 3;
static constexpr CAmount DEFAULT_TRANSACTION_FEE = 0;
static constexpr CAmount DEFAULT_TRANSACTION_MAX_FEE = static_cast<CAmount>(0.1 * COIN);

static constexpr int DATASTREAM_VERSION = 1;

CAmount GetMinimumFee(const size_t nTxBytes) {
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
    if (nFeeNeeded > DEFAULT_TRANSACTION_MAX_FEE) {
        nFeeNeeded = DEFAULT_TRANSACTION_MAX_FEE;
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
    if (nExpiryHeight > 0) {
        if (nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD)
            throw runtime_error(
                    fmt::format("Invalid parameter, expiryHeight must be less than {}.", TX_EXPIRY_HEIGHT_THRESHOLD));
        if (m_mtx.nExpiryHeight - DEFAULT_TX_EXPIRY_DELTA + TX_EXPIRING_SOON_THRESHOLD > nExpiryHeight) {
            throw runtime_error(fmt::format(
                    "Invalid parameter, expiryHeight should be at least {} to avoid transaction expiring soon",
                    m_mtx.nExpiryHeight - DEFAULT_TX_EXPIRY_DELTA + TX_EXPIRING_SOON_THRESHOLD));
        }
        m_mtx.nExpiryHeight = static_cast<uint32_t>(nExpiryHeight);
    }
}

void TransactionBuilder::validateAddress(const string &address) {
    KeyIO keyIO(m_Params);
    auto destination = keyIO.DecodeDestination(address);
    if (!IsValidDestination(destination))
        throw runtime_error(
                fmt::format("Not a valid transparent address {} used for funding the transaction", address));
}

void TransactionBuilder::setInputs(v_utxos &utxos) {
    // Sort the utxos by their values, ascending
    sort(utxos.begin(), utxos.end(), [](const utxo &a, const utxo &b) {
        return a.value < b.value;
    });

    // make few passes:
    //  1) without tx fee, calculate exact required transaction fee at the end
    //  2) with tx fee included, add inputs if required
    //  3) if tx fee changes after adding inputs (tx size increased), repeat 2) again

    KeyIO keyIO(m_Params);
    CAmount nTotalValueInPat = 0;   // total value of all selected outputs in patoshis
    CAmount nTxFeeInPat = 0;        // transaction fee in patoshis
    uint32_t nPass = 0;
    constexpr uint32_t MAX_TXFEE_PASSES = 4;
    while (nPass < MAX_TXFEE_PASSES) {
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

            if (nTotalValueInPat >= m_nAllSpentAmountInPat) {
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
        for (const auto &utxo: utxos) {
            ++nLastUsedOutputNo;

            if (m_sFromAddress.has_value()) // use utxo only from the specified funding address
            {
                if (utxo.address != m_sFromAddress)
                    continue;
            }

            CTxDestination destination = keyIO.DecodeDestination(utxo.address);
            if (!IsValidDestination(destination))
                throw runtime_error(string("Invalid Pastel address: ") + utxo.address);
            m_mInputPubKeys[utxo.address] = GetScriptForDestination(destination);

            CTxIn input;
            input.prevout.n = utxo.n;
            input.prevout.hash = uint256S(utxo.txid);
            m_mtx.vin.emplace_back(std::move(input));
            m_vSelectedUTXOs.push_back(utxo);

            nTotalValueInPat += utxo.value;

            if (nTotalValueInPat >= m_nAllSpentAmountInPat)
                break; // found enough coins
        }
        // return an error if we don't have enough coins to cover all outputs
        if (nTotalValueInPat < m_nAllSpentAmountInPat) {
            if (m_vSelectedUTXOs.empty())
                throw runtime_error(fmt::format("No unspent transaction found {} - cannot send data to the blockchain!",
                                                m_sFromAddress.has_value() ?
                                                fmt::format("for address {}", m_sFromAddress.value()) :
                                                ""));
            else
                throw runtime_error(
                        fmt::format(
                                "Not enough coins in the unspent transactions {} to cover the spending of {} PSL. Cannot send data to the blockchain!",
                                m_sFromAddress.has_value() ? fmt::format(" for address {}", m_sFromAddress.value()) : "",
                                m_nAllSpentAmountInPat / COIN));
        }
        // remove from vOutputs all selected outputs
        if (!utxos.empty() && (nLastUsedOutputNo >= 0))
            utxos.erase(utxos.cbegin(), utxos.cbegin() + nLastUsedOutputNo + 1);

        // Send change (in patoshis) output back to the last input address
        setChangeOutput(nTotalValueInPat - m_nAllSpentAmountInPat);

        ++nPass;
    }
    if (nPass >= MAX_TXFEE_PASSES)
        throw runtime_error(fmt::format("Could not calculate transaction fee. Cannot send data to the blockchain!"));
}

// add change at the END of vOut list - this is important for ticket transactions!!!
void TransactionBuilder::setChangeOutput(const CAmount nChange) {
    if (m_mtx.vout.size() == m_numOutputs)
        m_mtx.vout.resize(m_numOutputs + 1);

    const auto &lastTxOut = m_vSelectedUTXOs.back();
    m_mtx.vout[m_numOutputs].scriptPubKey = m_mInputPubKeys[lastTxOut.address];
    m_mtx.vout[m_numOutputs].nValue = nChange;
}

//void TransactionBuilder::setChangeOutput(const CAmount nChange) {
//    const auto &lastTxOut = m_vSelectedUTXOs.back();
//    if (m_mtx.vout.size() == m_numOutputs) {
//        m_mtx.vout.insert(m_mtx.vout.begin(), CTxOut(nChange, m_mInputPubKeys[lastTxOut.address]));
//    } else {
//        m_mtx.vout[0].scriptPubKey = m_mInputPubKeys[lastTxOut.address];
//        m_mtx.vout[0].nValue = nChange;
//    }
//}

void TransactionBuilder::signTransaction(CHDWallet& hdWallet) {
    Signer signer(hdWallet);
    for (uint32_t i = 0; i < m_mtx.vin.size(); i++) {
        try {
            const auto &utxo = m_vSelectedUTXOs[i];
            const CScript &prevPubKey = m_mInputPubKeys[utxo.address];
            const CAmount prevAmount = utxo.value;
            if (!signer.ProduceSignature(prevPubKey, m_mtx, i, prevAmount, to_integral_type(SIGHASH::ALL)))
                throw runtime_error("Failed to produce a signature script");
        } catch (const exception &e) {
            throw runtime_error(fmt::format("Error signing transaction input {}. {}", i, e.what()));
        }
    }
}

string TransactionBuilder::encodeHexTx() {
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << m_mtx;
    return HexStr(ssTx.begin(), ssTx.end());
}

string ScriptToAsmStr(const CScript& script)
{
    string str;
    opcodetype opcode;
    v_uint8 vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<v_uint8::size_type>(4)) {
                str += fmt::format("{}", CScriptNum(vch, false).getint());
            } else {
                    str += HexStr(vch);
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}
std::string ValueFromAmount(const CAmount& amount)
{
    const bool bSign = amount < 0;
    const int64_t n_abs = (bSign ? -amount : amount);
    const int64_t quotient = n_abs / COIN;
    const int64_t remainder = n_abs % COIN;
    return fmt::format("{}{}.{:05}", bSign ? "-" : "", quotient, remainder);
}

void TransactionBuilder::ScriptPubKeyToJSON(const CScript& scriptPubKey, nlohmann::json& out)
{
    txnouttype type;
    txdest_vector_t addresses;
    int nRequired;

    out["asm"] = ScriptToAsmStr(scriptPubKey);
    out["hex"] = HexStr(scriptPubKey.begin(), scriptPubKey.end());

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out["type"] = GetTxnOutputType(type);
        return;
    }

    out["reqSigs"] = nRequired;
    out["type"] = GetTxnOutputType(type);

    KeyIO keyIO(m_Params);
    nlohmann::json a = nlohmann::json::array();
    for (const auto& addr : addresses)
        a.push_back(keyIO.EncodeDestination(addr));
    out["addresses"] = a;
}

std::string TransactionBuilder::TxToJSON()
{
    nlohmann::json entry;

    const uint256 &txid = m_mtx.GetHash();
    entry["txid"] = txid.GetHex();
    entry["size"] = ::GetSerializeSize(m_mtx, SER_NETWORK, PROTOCOL_VERSION);
    entry["overwintered"] = m_mtx.fOverwintered;
    entry["version"] = m_mtx.nVersion;
    if (m_mtx.fOverwintered)
        entry["versiongroupid"] = HexInt(m_mtx.nVersionGroupId);
    entry["locktime"] = m_mtx.nLockTime;
    if (m_mtx.fOverwintered)
        entry["expiryheight"] = m_mtx.nExpiryHeight;
    entry["hex"] = encodeHexTx();

    KeyIO keyIO(m_Params);
    nlohmann::json vin = nlohmann::json::array();
    for (const auto& txin : m_mtx.vin)
    {
        nlohmann::json in;
        in["txid"] = txin.prevout.hash.GetHex();
        in["vout"] = txin.prevout.n;
        nlohmann::json o;
        o["hex"] = HexStr(txin.scriptSig.begin(), txin.scriptSig.end());
        in["scriptSig"] = o;
        in["sequence"] = txin.nSequence;
        vin.push_back(in);
    }
    entry["vin"] = vin;

    nlohmann::json vout = nlohmann::json::array();
    for (unsigned int i = 0; i < m_mtx.vout.size(); i++)
    {
        const CTxOut& txout = m_mtx.vout[i];
        nlohmann::json out;
        out["value"] = ValueFromAmount(txout.nValue);
        out["valuePat"] = txout.nValue;
        out["n"] = i;

        nlohmann::json o;
        ScriptPubKeyToJSON(txout.scriptPubKey, o);
        out["scriptPubKey"] = o;
        vout.push_back(out);
    }
    entry["vout"] = vout;
    return entry.dump();
}

string SendToTransactionBuilder::Create(const sendto_addresses &sendTo, const string &sendFrom, v_utxos &utxos, CHDWallet& hdWallet) {
    if (!sendFrom.empty()) {
        validateAddress(sendFrom);
        m_sFromAddress = sendFrom;
    }
    m_sendTo = sendTo;

    setOutputs();
    setInputs(utxos);
    signTransaction(hdWallet);
    return TxToJSON();
}

void SendToTransactionBuilder::setOutputs() {
    KeyIO keyIO(m_Params);
    set<CTxDestination> destinations;
    for (const auto &sendToItem: m_sendTo) {
        CTxDestination destination = keyIO.DecodeDestination(sendToItem.first);
        if (!IsValidDestination(destination))
            throw runtime_error(string("Invalid Pastel address: ") + sendToItem.first);

        if (!destinations.insert(destination).second)
            throw runtime_error(string("Invalid parameter, duplicated address: ") + sendToItem.first);

        CScript scriptPubKey = GetScriptForDestination(destination);
        CAmount nAmount = sendToItem.second * COIN;
        CTxOut out(nAmount, scriptPubKey);

        m_mtx.vout.push_back(out);
        // total amount to spend in patoshis - sum of all outputs
        m_nAllSpentAmountInPat += nAmount;
    }
    m_numOutputs = m_mtx.vout.size();
}

void TicketTransactionBuilder::setOutputs() {

    // ticket price in patoshis
    const CAmount nPriceInPat = m_nTicketPriceInPat;
    // total amount to spend in patoshis - sum of all fake outputs + extra if any
    m_nAllSpentAmountInPat = nPriceInPat + m_nExtraAmountInPat;

    const size_t nFakeTxCount = m_vOutScripts.size();
    // Amount in patoshis per output
    const CAmount nPerOutputAmountInPat = nPriceInPat / nFakeTxCount;

    // Add fake output scripts
    m_mtx.vout.resize(nFakeTxCount);
    for (size_t i = 0; i < nFakeTxCount; ++i)
    {
        m_mtx.vout[i].nValue = nPerOutputAmountInPat;
        m_mtx.vout[i].scriptPubKey = m_vOutScripts[i];
    }
    // MUST be precise!!! adding leftover amount to first fake output in patoshis
    const CAmount nLostAmountInPat = nPriceInPat - nPerOutputAmountInPat * nFakeTxCount;
    m_mtx.vout[0].nValue = nPerOutputAmountInPat + nLostAmountInPat;
    // Add extra outputs if required
    if (m_nExtraAmountInPat != 0)
    {
        for (const auto& extra : m_vExtraOutputs)
            m_mtx.vout.emplace_back(extra);
    }
    m_numOutputs = m_mtx.vout.size();
}

void TicketTransactionBuilder::processTicket(CPastelTicket& ticket) {
    CCompressedDataStream data_stream(SER_NETWORK, DATASTREAM_VERSION);
    auto nTicketID = ticket.TicketID();
    // compressed flag is saved in highest bit of the ticket id
    nTicketID |= TICKET_COMPRESS_ENABLE_MASK;
    data_stream << nTicketID;
    data_stream << ticket;

    // compress ticket data
    std::string error;
    if (!data_stream.CompressData(error, sizeof(nTicketID),
        [&](CSerializeData::iterator start, CSerializeData::iterator end)
        {
            if (start != end)
                *start = nTicketID & TICKET_COMPRESS_DISABLE_MASK;
        }))
        throw runtime_error(fmt::format("Failed to compress ticket ({}) data. {}", ticket.TicketName(), error));

    const size_t nInputDataSize = createP2FMSScripts(data_stream);
    if (!nInputDataSize || m_vOutScripts.empty())
        throw runtime_error(fmt::format("Failed to create P2FMS from data provided. {}", error));

}

size_t TicketTransactionBuilder::createP2FMSScripts(CCompressedDataStream& input_stream){
    m_vOutScripts.clear();
    // fake key size - transaction data should be aligned to this size
    constexpr size_t FAKE_KEY_SIZE = 33;
    // position of the input stream data in vInputData vector
    constexpr size_t STREAM_DATA_POS = uint256::SIZE + sizeof(uint64_t);

    // +--------------  vInputData ---------------------------+
    // |     8 bytes     |    32 bytes     |  nDataStreamSize |
    // +-----------------+-----------------+------------------+
    // | nDataStreamSize | input data hash |    input data    |
    // +-----------------+-----------------+------------------+
    v_uint8 vInputData;
    const uint64_t nDataStreamSize = input_stream.size();
    // input data size without padding
    const size_t nDataSizeNotPadded = STREAM_DATA_POS + nDataStreamSize;
    const size_t nInputDataSize = nDataSizeNotPadded + (FAKE_KEY_SIZE - (nDataSizeNotPadded % FAKE_KEY_SIZE));
    vInputData.resize(nInputDataSize, 0);
    input_stream.read_buf(vInputData.data() + STREAM_DATA_POS, input_stream.size());

    auto p = vInputData.data();
    // set size of the original data upfront
    auto* input_len_bytes = reinterpret_cast<const unsigned char*>(&nDataStreamSize);
    memcpy(p, input_len_bytes, sizeof(uint64_t)); // sizeof(uint64_t) == 8
    p += sizeof(uint64_t);

    // Calculate sha256 hash of the input data (without padding) and set it at offset 8
    const uint256 input_hash = Hash(vInputData.cbegin() + STREAM_DATA_POS, vInputData.cbegin() + nDataSizeNotPadded);
    memcpy(p, input_hash.begin(), input_hash.size());

    // Create output P2FMS scripts
    //    each CScript can hold up to 3 chunks (fake keys)
    v_uint8 vChunk;
    vChunk.resize(FAKE_KEY_SIZE);
    for (size_t nChunkPos = 0; nChunkPos < nInputDataSize;)
    {
        CScript script;
        script << CScript::EncodeOP_N(1);
        int m = 0;
        for (; m < 3 && nChunkPos < nInputDataSize; ++m, nChunkPos += FAKE_KEY_SIZE)
        {
            memcpy(vChunk.data(), vInputData.data() + nChunkPos, FAKE_KEY_SIZE);
            script << vChunk;
        }
        // add chunks count (up to 3)
        script << CScript::EncodeOP_N(m) << OP_CHECKMULTISIG;
        m_vOutScripts.emplace_back(std::move(script));
    }
    return nInputDataSize;
}

string RegisterPastelIDTransactionBuilder::Create(const string& sPastelID, const string& sFundingAddress, v_utxos& utxos, CHDWallet& hdWallet) {
    validateAddress(sFundingAddress);
    m_sFromAddress = sFundingAddress;

    auto ticket = CPastelIDRegTicket::Create(sPastelID, sFundingAddress, hdWallet);

    m_nExtraAmountInPat = ticket.GetExtraOutputs(m_vExtraOutputs);
    m_nTicketPriceInPat = ticket.TicketPrice() * COIN;
    m_sFromAddress = sFundingAddress;

    processTicket(ticket);
    setOutputs();

    setInputs(utxos);
    signTransaction(hdWallet);
    return TxToJSON();
}
