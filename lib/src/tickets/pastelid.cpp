// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "tickets/pastelid.h"
#include "hd_wallet.h"

CPastelIDRegTicket CPastelIDRegTicket::Create(const std::string& sPastelID, const std::string& sFundingAddress, CHDWallet& hdWallet)
{
    // this method will throw exception if PastelID was not created in Wallet
    auto legRoast = hdWallet.GetPastelID(sPastelID, PastelIDType::LEGROAST);

    CPastelIDRegTicket ticket(std::move(sPastelID));
    ticket.m_sFundingAddress = sFundingAddress;

    ticket.m_LegRoastKey = legRoast; // encoded LegRoast public key
    ticket.GenerateTimestamp();

    stringstream ss;
    // serialize all ticket fields except mn signature
    ticket.ToStrStream(ss);

    const auto sFullTicket = ss.str();
    // sign full ticket using ed448 private key and store it in pslid_signature vector
    auto signature = hdWallet.SignWithPastelID(ticket.m_sPastelID , sFullTicket, PastelIDType::PASTELID, false); //non base64 -> as is
    string_to_vector(signature, ticket.m_pslid_signature);
    return ticket;
}

void CPastelIDRegTicket::ToStrStream(stringstream& ss) const noexcept
{
    ss << m_sPastelID; // base58-encoded ed448 public key (with prefix)
    ss << m_LegRoastKey;   // base58-encoded legroast public key (with prefix)
    ss << m_sFundingAddress;
    ss << m_outpoint.ToStringShort();
    ss << m_nTimestamp;
}