// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2024 The Pastel Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <vector>

#include "standard.h"
#include "transaction/script.h"
#include "hash.h"

using namespace std;

unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

/**
 * Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
 */
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, vector<v_uint8>& vSolutionsRet)
{
    // Templates
    static multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // Empty, provably prunable, data-carrying output
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_RETURN << OP_SMALLDATA));
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_RETURN));
    }

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        v_uint8 hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    v_uint8 vch1, vch2;
    // Scan templates
    const CScript& script1 = scriptPubKey;
    for(const auto &[txOut, script2] : mTemplates)
    {
        vSolutionsRet.clear();
        vch1.clear();
        vch2.clear();

        opcodetype opcode1, opcode2;

        // Compare
        auto pc1 = script1.begin();
        auto pc2 = script2.begin();
        while (true)
        {
            if (pc1 == script1.end() && pc2 == script2.end())
            {
                // Found a match
                typeRet = txOut;
                if (typeRet == TX_MULTISIG)
                {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        return false;
                }
                return true;
            }
            if (!script1.GetOp(pc1, opcode1, vch1))
                break;
            if (!script2.GetOp(pc2, opcode2, vch2))
                break;

            // Template matching opcodes:
            if (opcode2 == OP_PUBKEYS)
            {
                while (vch1.size() >= 33 && vch1.size() <= 65)
                {
                    vSolutionsRet.push_back(vch1);
                    if (!script1.GetOp(pc1, opcode1, vch1))
                        break;
                }
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;
                // Normal situation is to fall through
                // to other if/else statements
            }

            if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() < 33 || vch1.size() > 65)
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_SMALLINTEGER)
            {   // Single-byte small integer pushed onto vSolutions
                if (opcode1 == OP_0 ||
                    (opcode1 >= OP_1 && opcode1 <= OP_16))
                {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(v_uint8(1, n));
                }
                else
                    break;
            }
            else if (opcode2 == OP_SMALLDATA)
            {
                // small pushdata, <= nMaxDatacarrierBytes
                if (vch1.size() > nMaxDatacarrierBytes)
                    break;
            }
            else if (opcode1 != opcode2 || vch1 != vch2)
            {
                // Others must match exactly
                break;
            }
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

namespace
{
    class CScriptVisitor
    {
    private:
        CScript *script;
    public:
        CScriptVisitor(CScript *scriptin) { script = scriptin; }

        bool operator()(const CNoDestination &dest) const {
            script->clear();
            return false;
        }

        bool operator()(const CKeyID &keyID) const {
            script->clear();
            *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
            return true;
        }

        bool operator()(const CScriptID &scriptID) const {
            script->clear();
            *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
            return true;
        }
    };
}

bool IsValidDestination(const CTxDestination& dest) noexcept
{
    return !holds_alternative<CNoDestination>(dest);
}

bool IsKeyDestination(const CTxDestination& dest) noexcept
{
    return holds_alternative<CKeyID>(dest);
}

bool IsScriptDestination(const CTxDestination& dest) noexcept
{
    return holds_alternative<CScriptID>(dest);
}

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;

    visit(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForMultisig(int nRequired, const vector<CPubKey>& keys)
{
    CScript script;

    script << CScript::EncodeOP_N(nRequired);
    for (const auto& key : keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(static_cast<int>(keys.size())) << OP_CHECKMULTISIG;
    return script;
}

/**
 * Extract destination address from a standard scriptPubKey.
 *
 * \param scriptPubKey - script to parse
 * \param addressRet - (return) destination address
 * \param pScriptType - (return, optional) script type
 * \return true if address was successfully extracted, false otherwise
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet, txnouttype* pScriptType)
{
    vector<v_uint8> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions))
    {
        if (pScriptType)
            *pScriptType = whichType;
        return false;
    }

    bool bRet = false;
    switch (whichType)
    {
        case TX_PUBKEY: {
            CPubKey pubKey(vSolutions[0]);
            if (pubKey.IsValid())
            {
                addressRet = pubKey.GetID();
                bRet = true;
            }
        } break;

        case TX_PUBKEYHASH: {
            addressRet = CKeyID(uint160(vSolutions[0]));
            bRet = true;
        } break;

        case TX_SCRIPTHASH: {
            addressRet = CScriptID(uint160(vSolutions[0]));
            bRet = true;
        } break;

        default:
            break;
    }

    if (pScriptType)
        *pScriptType = whichType;
    // Multisig txns have more than one address...
    return bRet;
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, txdest_vector_t& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    vector<v_uint8> vSolutions;
    if (!Solver(scriptPubKey, typeRet, vSolutions))
        return false;
    if (typeRet == TX_NULL_DATA)
        return false; // This is data, not addresses

    if (typeRet == TX_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid())
                continue;

            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }

        if (addressRet.empty())
            return false;
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address))
            return false;
        addressRet.push_back(address);
    }

    return true;
}
