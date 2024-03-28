#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "types.h"
#include "vector_types.h"
#include "uint256.h"
#include "support/cleanse.h"
#include "serialize.h"

constexpr unsigned int WALLET_CRYPTO_KEY_SIZE = 32;
constexpr unsigned int WALLET_CRYPTO_SALT_SIZE = 8;
constexpr unsigned int WALLET_CRYPTO_IV_SIZE = 32; // AES IV's are 16bytes, not 32 -> use 16?

/** Encryption/decryption context with key information */
class CCrypter
{
private:
    CKeyingMaterial vchKey;
    CKeyingMaterial vchIV;
    bool fKeySet;

    int BytesToKeySHA512AES(const std::vector<unsigned char>& chSalt, const SecureString& strKeyData, int count, unsigned char *key,unsigned char *iv) const;

public:
    bool SetKeyFromPassphrase(const SecureString &strKeyData, const v_uint8& chSalt, unsigned int nRounds, unsigned int nDerivationMethod);
    bool Encrypt(const CKeyingMaterial& vchPlaintext, v_uint8& vchCiphertext) const;
    bool Decrypt(const v_uint8& vchCiphertext, CKeyingMaterial& vchPlaintext) const;
    bool SetKey(const CKeyingMaterial& chNewKey, const v_uint8& chNewIV);

    void CleanKey()
    {
        memory_cleanse(vchKey.data(), vchKey.size());
        memory_cleanse(vchIV.data(), vchIV.size());
        fKeySet = false;
    }

    CCrypter()
    {
        fKeySet = false;
        vchKey.resize(WALLET_CRYPTO_KEY_SIZE);
        vchIV.resize(WALLET_CRYPTO_IV_SIZE);
    }

    ~CCrypter()
    {
        CleanKey();
    }

    static bool EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial& vchPlaintext, const uint256& nIV, v_uint8& vchCiphertext);
    static bool DecryptSecret(const CKeyingMaterial& vMasterKey, const v_uint8& vchCiphertext, const uint256& nIV, CKeyingMaterial& vchPlaintext);
};

class CMasterKey
{
public:
    std::vector<unsigned char> vchCryptedKey;
    std::vector<unsigned char> vchSalt;
    //! 0 = EVP_sha512()
    //! 1 = scrypt()
    unsigned int nDerivationMethod;
    unsigned int nDeriveIterations;
    //! Use this for more parameters to key derivation,
    //! such as the various parameters to scrypt
    std::vector<unsigned char> vchOtherDerivationParameters;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchCryptedKey);
        READWRITE(vchSalt);
        READWRITE(nDerivationMethod);
        READWRITE(nDeriveIterations);
        READWRITE(vchOtherDerivationParameters);
    }

    CMasterKey()
    {
        // 25000 rounds is just under 0.1 seconds on a 1.86 GHz Pentium M
        // ie slightly lower than the lowest hardware we need bother supporting
        nDeriveIterations = 25000;
        nDerivationMethod = 0;
        vchOtherDerivationParameters = std::vector<unsigned char>(0);
    }

    // Copy constructor
    CMasterKey(const CMasterKey& other) = default;

    // Copy assignment operator
    CMasterKey& operator=(const CMasterKey& other) = default;
};