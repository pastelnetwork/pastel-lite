#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>

#include "transaction/amount.h"
#include "transaction/transaction.h"

constexpr uint8_t TICKET_COMPRESS_ENABLE_MASK  = (1<<7); // using bit 7 to mark a ticket is compressed
constexpr uint8_t TICKET_COMPRESS_DISABLE_MASK = 0x7F;

class CPastelTicket {
public:
    // abstract classes should have virtual destructor
    virtual ~CPastelTicket() = default;

    virtual int TicketID() = 0;
    virtual std::string TicketName() = 0;
    virtual CAmount TicketPrice() = 0;

    virtual CAmount GetExtraOutputs(v_txouts& outputs) const { return 0; }

    virtual bool handle_stream_read_mode(const CDataStream& s, const SERIALIZE_ACTION ser_action) noexcept
    {
        const bool bRead = ser_action == SERIALIZE_ACTION::Read;
        if (bRead)
            m_nSerializedSize = static_cast<uint32_t>(s.size());
        return bRead;
    }
    const size_t GetSerializedSize() const noexcept { return m_nSerializedSize; }
    const size_t GetCompressedSize() const noexcept { return m_nCompressedSize; }

    void SetSerializedSize(const size_t nSize) noexcept { m_nSerializedSize = static_cast<uint32_t>(nSize); }
    void SetCompressedSize(const size_t nSize) noexcept { m_nCompressedSize = static_cast<uint32_t>(nSize); }

    virtual void SerializationOp(CDataStream& s, const SERIALIZE_ACTION ser_action) = 0;
    void Serialize(CDataStream& s) const
    {
        NCONST_PTR(this)->SerializationOp(s, SERIALIZE_ACTION::Write);
    }
    void Unserialize(CDataStream& s)
    {
        SerializationOp(s, SERIALIZE_ACTION::Read);
    }

protected:
    std::string m_txid;          // ticket transaction id
    uint32_t m_nBlock{0};        // ticket block
    std::int64_t m_nTimestamp{}; // create timestamp
    short m_nVersion{ -1 };      // stored ticket version

    // memory only fields
    uint32_t m_nSerializedSize{0}; // ticket data serialized size in bytes
    uint32_t m_nCompressedSize{0}; // ticket data serialized size in bytes after compression

    std::int64_t GenerateTimestamp() noexcept
    {
        m_nTimestamp = time(nullptr);
        return m_nTimestamp;
    }
};