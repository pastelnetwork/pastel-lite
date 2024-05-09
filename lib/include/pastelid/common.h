#pragma once
// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <iomanip>
#include <sstream>
#include <cmath>

#include <botan/pk_keys.h>
#include "botan/auto_rng.h"
#include <botan/rng.h>
#include <botan/ed448.h>
#include <botan/x448.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/base64.h>
#include <botan/exceptn.h>

#include "pastelid/legroast.h"
#include "pastelid/pastel_key.h"

using namespace std;
using namespace legroast;

namespace crypto_helpers {
    static constexpr size_t  ED448_LEN = 57;    // bytes

    enum class encoding : uint32_t {
        none = 0,
        base58 = 1,
        base64 = 2,
        hex = 3,
    };

    inline string encode(const v_uint8& in, encoding enc)
    {
        switch (enc) {
            case encoding::base58:
                throw std::runtime_error("Base58 encoding is not supported for Ed448 signatures");
//                return Botan::base58_encode(in);
            case encoding::base64:
                return Botan::base64_encode(in);
            case encoding::hex:
                return Botan::hex_encode(in);
            case encoding::none:
            default:
                return {in.begin(), in.end()};
        }
    }
    inline v_uint8 decode(const string& in, encoding enc)
    {
        switch (enc) {
            case encoding::base58:
                throw std::runtime_error("Base58 encoding is not supported for Ed448 signatures");
//                return Botan::base58_decode(in);
            case encoding::base64: {
                auto out = Botan::base64_decode(in);
                return {out.begin(), out.end()};
            }
            case encoding::hex: {
                return Botan::hex_decode(in);
            }
            case encoding::none:
            default:
                return {in.begin(), in.end()};
        }
    }

    inline string ed448_pubkey_encoded(v_uint8&& seed)
    {
        auto key = Botan::Ed448_PrivateKey(std::span(seed));
        auto pubKey = key.public_key_bits();
        return CPastelID::EncodePastelID(pubKey);
    }
    inline v_uint8 ed448_privkey(v_uint8&& seed) {
        auto key = Botan::Ed448_PrivateKey(std::span(seed));
        auto privKey = key.private_key_bits();
        return {privKey.begin(), privKey.end()};
    }
    inline string ed448_sign(v_uint8&& seed, const string& message, encoding enc)
    {
        Botan::AutoSeeded_RNG rng;
        auto key = Botan::Ed448_PrivateKey(std::span(seed));
        Botan::PK_Signer signer(key, rng, "Pure"); //"Ed448" - default - in OpenSSL
        signer.update(message);
        auto signature = signer.signature(rng);
        return encode(signature, enc);
    }
    inline bool ed448_verify(const string& pubkey, const string& message, const string& signature, encoding enc)
    {
        v_uint8 vRawPubKey;
        if (!CPastelID::DecodePastelID(pubkey, vRawPubKey))
            throw std::runtime_error("Failed to decode Ed448 public key");
        auto public_key = Botan::Ed448_PublicKey(vRawPubKey);
        Botan::PK_Verifier verifier(public_key, "Pure"); //"Ed448" - default - in OpenSSL
        verifier.update(message);
        auto sig = decode(signature, enc);
        return verifier.check_signature(sig);
    }

    inline string legroast_pubkey_encoded(v_uint8&& seed)
    {
        CLegRoast<algorithm::Legendre_Middle> legRoastKey;
        legRoastKey.keygen(std::move(seed));
        return CPastelID::EncodeLegRoastPubKey(legRoastKey.get_public_key());
    }
    inline v_uint8 legroast_privkey(v_uint8&& seed)
    {
        CLegRoast<algorithm::Legendre_Middle> legRoastKey;
        legRoastKey.keygen(std::move(seed));
        return legRoastKey.get_private_key();
    }
    inline string legroast_sign(v_uint8&& seed, const string& message, encoding enc)
    {
        CLegRoast<algorithm::Legendre_Middle> LegRoast;
        LegRoast.keygen(std::move(seed));
        string error;
        if (!LegRoast.sign(error, reinterpret_cast<const unsigned char*>(message.data()), message.length()))
            throw runtime_error(fmt::format("Failed to sign text message with the LegRoast private key. {}", error));
        auto signature = LegRoast.get_signature();
        return encode({signature.begin(), signature.end()}, enc);
    }
    inline bool legroast_verify(const string& pubkey, const string& message, const string& signature, encoding enc)
    {
        v_uint8 vRawPubKey;
        if (!CPastelID::DecodeLegRoastPubKey(pubkey, vRawPubKey))
            throw std::runtime_error("Failed to decode LegRoast public key");

        string error;
        CLegRoast<algorithm::Legendre_Middle> LegRoast;
        if (!LegRoast.set_public_key(error, vRawPubKey.data(), vRawPubKey.size()))
            throw runtime_error(error);
        auto sig = decode(signature, enc);
        if (!LegRoast.set_signature(error, sig))
            throw runtime_error(error);
        if (!LegRoast.verify(error, reinterpret_cast<const unsigned char*>(message.data()), message.size()))
            throw runtime_error(error);
        return true;
    }


    class crypto_exception : public std::exception
    {
        std::string message;
    public:
        crypto_exception(const std::string &error, const std::string &details, const std::string &func_name)
        {
            std::ostringstream str_str;
            str_str << func_name << " - " << error << ": " << details << std::endl;
            message = str_str.str();
        }

        [[nodiscard]] const char *what() const noexcept override
        {
            return message.c_str();
        }
    };
}