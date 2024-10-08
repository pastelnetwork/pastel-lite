#pragma once
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Zcash developers
// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <stdexcept>
#include <vector>

#include "pubkey.h"
#include "serialize.h"
#include "uint256.h"
#include "support/cleanse.h"

/**
 * secure_allocator is defined in allocators.h
 * CPrivKey is a serialized private key, with all parameters included
 * (PRIVATE_KEY_SIZE bytes)
 */
typedef std::vector<unsigned char> CPrivKey;

/** An encapsulated private key. */
class CKey
{
public:
    /**
     * secp256k1:
     */
    constexpr static unsigned int PRIVATE_KEY_SIZE            = 279;
    constexpr static unsigned int COMPRESSED_PRIVATE_KEY_SIZE = 214;
    constexpr static unsigned int KEY_SIZE = 32; // key size in bytes
    /**
     * see www.keylength.com
     * script supports up to 75 for single byte push
     */
    static_assert(
        PRIVATE_KEY_SIZE >= COMPRESSED_PRIVATE_KEY_SIZE,
        "COMPRESSED_PRIVATE_KEY_SIZE is larger than PRIVATE_KEY_SIZE");

private:
    //! Whether this private key is valid. We check for correctness when modifying the key
    //! data, so fValid should always correspond to the actual state.
    bool fValid;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed;

    //! The actual byte data
    std::vector<unsigned char> keydata;

    //! Check whether the 32-byte array pointed to be vch is valid keydata.
    bool static Check(const unsigned char* vch);

public:
    //! Construct an invalid private key.
    CKey() : 
        fValid(false), 
        fCompressed(false)
    {
        // Important: vch must be 32 bytes in length to not break serialization
        keydata.resize(KEY_SIZE);
    }

    //! Destructor (again necessary because of memlocking).
    ~CKey() = default;

    CKey& operator=(const CKey& other)
    {
        if (this == &other)
			return *this;
        fValid = other.fValid;
		fCompressed = other.fCompressed;
		keydata = other.keydata;
		return *this;
    }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return a.fCompressed == b.fCompressed &&
		a.size() == b.size() &&
            	memcmp(a.keydata.data(), b.keydata.data(), a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, const bool fCompressedIn)
    {
        do
        {
            fValid = false;
            if (pend - pbegin != KEY_SIZE)
                break;
            if (!Check(&pbegin[0]))
                break;
            memcpy(keydata.data(), (unsigned char*)&pbegin[0], keydata.size());
            fValid = true;
            fCompressed = fCompressedIn;
        } while (false);
    }

    void Clear()
    {
        fValid = false;
        fCompressed = false;
        memory_cleanse(keydata.data(), keydata.size());
        keydata.clear();
    }

    //! Simple read-only vector-like interface.
    [[nodiscard]] unsigned int size() const noexcept { return (fValid ? static_cast<unsigned int>(keydata.size()) : 0); }
    [[nodiscard]] const unsigned char* begin() const noexcept { return keydata.data(); }
    [[nodiscard]] const unsigned char* end() const noexcept { return keydata.data() + size(); }
    [[nodiscard]] const unsigned char* cbegin() const noexcept { return keydata.data(); }
    [[nodiscard]] const unsigned char* cend() const noexcept { return keydata.data() + size(); }

    //! Check whether this private key is valid.
    [[nodiscard]] bool IsValid() const noexcept { return fValid; }

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    [[nodiscard]] bool IsCompressed() const noexcept { return fCompressed; }

    //! Initialize from a CPrivKey (serialized OpenSSL private key data).
    bool SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed);

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressed);

    /**
     * Convert the private key to a CPrivKey (serialized OpenSSL private key data).
     * This is expensive. 
     */
    [[nodiscard]] CPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * This is expensive.
     */
    [[nodiscard]] CPubKey GetPubKey() const;

    /**
     * Create a DER-serialized signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool Sign(const uint256& hash, v_uint8& vchSig, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */
    bool SignCompact(const uint256& hash, v_uint8& vchSig) const;

    //! Derive BIP32 child key.
    bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */
    [[nodiscard]] bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(CPrivKey& privkey, CPubKey& vchPubKey, bool fSkipCheck = false);

//    //! Check whether an element of a signature (r or s) is valid.
//    static bool CheckSignatureElement(const unsigned char* vch, const int len, const bool half);
};

struct CExtKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CKey key;

    static std::optional<CExtKey> Master(const unsigned char* seed, unsigned int nSeedLen);

    friend bool operator==(const CExtKey& a, const CExtKey& b)
    {
        return a.nDepth == b.nDepth &&
		memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
		a.nChild == b.nChild &&
            	a.chaincode == b.chaincode &&
		a.key == b.key;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);

    [[nodiscard]] std::optional<CExtKey> Derive(unsigned int numChild) const;
    [[nodiscard]] CExtPubKey Neuter() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = BIP32_EXTKEY_SIZE;
        ::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        Encode(code);
        s.write((const char *)&code[0], len);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        size_t len = ::ReadCompactSize(s); //not using BIP32_EXTKEY_SIZE as max size here -> want to throw my own exception
        if (len != BIP32_EXTKEY_SIZE) {
            throw std::runtime_error("Invalid extended key size\n");
        }
        unsigned char code[BIP32_EXTKEY_SIZE];
        s.read((char *)&code[0], len);
        Decode(code);
    }
};

/** Check that required EC support is available at runtime. */
bool ECC_InitSanityCheck();
