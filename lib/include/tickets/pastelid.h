#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>

#include "serialize.h"
#include "vector_types.h"
#include "transaction/transaction.h"
#include "tickets/ticket.h"
#include "hd_wallet.h"

class CPastelIDRegTicket : public CPastelTicket {
public:
    CPastelIDRegTicket() noexcept = default;

    explicit CPastelIDRegTicket(const std::string& _pastelID) : m_sPastelID(_pastelID) {}

    uint8_t TicketID() override {return 0;} //TicketID::PastelID
    std::string TicketName() override {return "Pastel ID";}
    CAmount TicketPrice() override {return 1000;}

    void SerializationOp(CDataStream& s, const SERIALIZE_ACTION ser_action) override
    {
        handle_stream_read_mode(s, ser_action);
        READWRITE(m_sPastelID);
        READWRITE(m_sFundingAddress);
        READWRITE(m_outpoint);
        READWRITE(m_nTimestamp);
        READWRITE(m_mn_signature);
        READWRITE(m_pslid_signature);
        READWRITE(m_txid);
        READWRITE(m_nBlock);
        READWRITE(m_nVersion);
        READWRITE(m_LegRoastKey);
    }

    static CPastelIDRegTicket Create(const std::string& sPastelID, const std::string& sFundingAddress, CHDWallet& hdWallet);

protected:
    void ToStrStream(stringstream& ss) const noexcept;

    std::string m_sPastelID;       // Pastel ID - base58-encoded public key (EdDSA448)
    std::string m_sFundingAddress; // funding address associated with Pastel ID
    COutPoint m_outpoint{};
    std::string m_LegRoastKey; // Legendre Post-Quantum LegRoast public key (base58-encoded with prefix)
    v_uint8 m_mn_signature;
    v_uint8 m_pslid_signature;
};