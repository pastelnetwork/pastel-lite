// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <iostream>

#include "crypter.h"
#include "types.h"
#include "support/cleanse.h"
#include "support/scope_guard.hpp"
#include "vector_types.h"
#include "uint256.h"
#include "key.h"

bool CCrypter::SetKeyFromPassphrase(const SecureString& strKeyData, const v_uint8& chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
    if (nDerivationMethod == 0)
        i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &chSalt[0],
                          (unsigned char *)&strKeyData[0], static_cast<int>(strKeyData.size()), nRounds, vchKey.data(), vchIV.data());

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(vchKey.data(), vchKey.size());
        memory_cleanse(vchIV.data(), vchIV.size());
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial& chNewKey, const v_uint8& chNewIV)
{
    if (chNewKey.size() != WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != WALLET_CRYPTO_IV_SIZE)
        return false;

    memcpy(vchKey.data(), chNewKey.data(), chNewKey.size());
    memcpy(vchIV.data(), chNewIV.data(), chNewIV.size());

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, v_uint8& vchCiphertext) const
{
    if (!fKeySet)
        return false;

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    const int nLen = static_cast<int>(vchPlaintext.size());
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = v_uint8(nCLen);

    bool fOk = false;
    do
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        assert(ctx);
        const auto guard = sg::make_scope_guard([&]() noexcept
            {
                if (ctx)
                    EVP_CIPHER_CTX_free(ctx);
            });
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, vchKey.data(), vchIV.data()) != 1)
            break;
        if (EVP_EncryptUpdate(ctx, &vchCiphertext[0], &nCLen, &vchPlaintext[0], nLen) != 1)
            break;
        if (EVP_EncryptFinal_ex(ctx, (&vchCiphertext[0]) + nCLen, &nFLen) != 1)
            break;
        fOk = true;
    } while (false);

    if (!fOk)
        return false;

    vchCiphertext.resize(nCLen + nFLen);
    return true;
}

bool CCrypter::Decrypt(const v_uint8& vchCiphertext, CKeyingMaterial& vchPlaintext) const
{
    if (!fKeySet)
        return false;

    // plaintext will always be equal to or lesser than length of ciphertext
    const int nLen = static_cast<int>(vchCiphertext.size());
    int nPLen = nLen, nFLen = 0;

    vchPlaintext = CKeyingMaterial(nPLen);

    bool fOk = false;
    do
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        assert(ctx);
        const auto guard = sg::make_scope_guard([&]() noexcept
            {
                if (ctx)
                    EVP_CIPHER_CTX_free(ctx);
            });
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, vchKey.data(), vchIV.data()) != 1)
            break;
        if (EVP_DecryptUpdate(ctx, &vchPlaintext[0], &nPLen, &vchCiphertext[0], nLen) != 1)
            break;
        if (EVP_DecryptFinal_ex(ctx, (&vchPlaintext[0]) + nPLen, &nFLen) != 1)
            break;
        fOk = true;
    } while (false);

    if (!fOk)
        return false;

    vchPlaintext.resize(nPLen + nFLen);
    return true;
}


bool CCrypter::EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial& vchPlaintext, const uint256& nIV, v_uint8& vchCiphertext)
{
    CCrypter cKeyCrypter;
    v_uint8 chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_IV_SIZE);
    if (!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt(*((const CKeyingMaterial*)&vchPlaintext), vchCiphertext);
}

bool CCrypter::DecryptSecret(const CKeyingMaterial& vMasterKey, const v_uint8& vchCiphertext, const uint256& nIV, CKeyingMaterial& vchPlaintext)
{
    CCrypter cKeyCrypter;
    v_uint8 chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_IV_SIZE);
    if (!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}

