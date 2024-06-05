#pragma once
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2024 Pastel Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <cstdint>
#include <variant>
#include <vector>

#include "uint256.h"
#include "pubkey.h"

class CKeyID;
class CScript;

enum txnouttype
{
    TX_NONSTANDARD = 0,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    explicit CScriptID(const CScript& in);
    CScriptID(const uint160& in) : uint160(in) {}
};

static const unsigned int MAX_OP_RETURN_RELAY = 80;      //! bytes
extern unsigned nMaxDatacarrierBytes;

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator!=(const CNoDestination &a, const CNoDestination &b) { return false; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * CScriptID: TX_SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in a Pastel address
 */
typedef std::variant<CNoDestination, CKeyID, CScriptID> CTxDestination;

/** Check whether a CTxDestination is a CNoDestination. */
bool IsValidDestination(const CTxDestination& dest) noexcept;

/** Check whether a CTxDestination is a CKeyID. */
bool IsKeyDestination(const CTxDestination& dest) noexcept;

/** Check whether a CTxDestination is a CScriptID. */
bool IsScriptDestination(const CTxDestination& dest) noexcept;

using txdest_vector_t = std::vector<CTxDestination>;

/**
 * Parse a standard scriptPubKey for the destination address. Assigns result to
 * the addressRet parameter and returns true if successful. For multisig
 * scripts (that can have multiple destination addresses), instead use ExtractDestinations.
 * Currently only works for P2PK, P2PKH, and P2SH scripts.
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet, txnouttype* pScriptType = nullptr);

/**
 * Parse a standard scriptPubKey with one or more destination addresses. For
 * multisig scripts, this populates the addressRet vector with the pubkey IDs
 * and nRequiredRet with the n required to spend. For other destinations,
 * addressRet is populated with a single value and nRequiredRet is set to 1.
 * Returns true if successful.
 */
bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, txdest_vector_t& addressRet, int& nRequiredRet);

CScript GetScriptForDestination(const CTxDestination& dest);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);
