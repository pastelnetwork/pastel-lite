#pragma once

#include <memory>
#include <sstream>
#include <iostream>
#include <fstream>
#include <memory>
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

#include "vector_types.h"
#include "pastelid/common.h"
#include "pastelid/secure_container.h"

// EdDSA uses small public keys ED25519 - 32 bytes; ED448 - 57 bytes
// and signatures ED25519 - 64 bytes; Ed448 - 114 bytes

namespace ed_crypto {

    static constexpr size_t  ED448_LEN = 57;    // bytes

    enum {
        ED448 = 1,
        X448 = 2,
        ED25519 = 3,
        X25519 = 3,
    };

    template<int type>
    class key
    {
    public:
        using unique_key_ptr = std::unique_ptr<Botan::Private_Key>;

        explicit key(unique_key_ptr key) : key_(std::move(key)) {}

        [[nodiscard]] const Botan::Private_Key* get() const noexcept { return key_.get(); }

        static key generate_key(v_uint8&& seed = v_uint8())
        {
            Botan::AutoSeeded_RNG rng;
            if (seed.empty()) {
                seed.resize(ED448_LEN);
                rng.randomize(seed);
            } else {
                if (seed.size() != ED448_LEN) {
                    seed.resize(ED448_LEN);
                }
            }
            return create_from_raw_private(seed);
        }

        static key create_from_raw_private(const v_uint8 seed)
        {
            std::unique_ptr<Botan::Private_Key> pkey;
            if (type == ED448) {
                pkey = std::make_unique<Botan::Ed448_PrivateKey>(std::span(seed));
            } else if (type == X448) {
                pkey = std::make_unique<Botan::X448_PrivateKey>(std::span(seed));
//            } else if (type == ED25519) {
//                pkey.reset(new Botan::Ed25519_PrivateKey(std::span(seed));
//            } else if (type == X25519) {
//                pkey.reset(new Botan::X25519_PrivateKey(std::span(seed));
            } else {
                throw crypto_exception("Unsupported key type", std::string(), "create_from_raw_private");
            }

            unique_key_ptr uniqueKeyPtr(pkey.release());
            key k(std::move(uniqueKeyPtr));
            return k;
        }

        static key create_public_key_from_raw(const v_uint8 rawpubkey)
        {
            std::unique_ptr<Botan::Public_Key> pkey;

            if (type == ED448) {
                pkey = std::make_unique<Botan::Ed448_PublicKey>(std::span(rawpubkey));
            } else if (type == X448) {
                pkey = std::make_unique<Botan::X448_PublicKey>(std::span(rawpubkey));
//            } else if (type == ED25519) {
//                pkey.reset(new Botan::Ed25519_PublicKey(std::span(rawpubkey));
//            } else if (type == X25519) {
//                pkey.reset(new Botan::X25519_PublicKey(std::span(rawpubkey));
            } else {
                throw crypto_exception("Unsupported key type", std::string(), "create_from_raw_public");
            }

            unique_key_ptr uniqueKeyPtr(dynamic_cast<Botan::Private_Key*>(pkey.release()));
            key k(std::move(uniqueKeyPtr));
            return k;
        }

        static key create_public_key_from_hex(const std::string& rawPublicKey)
        {
            v_uint8 vec = Botan::hex_decode(rawPublicKey);
            return create_public_key_from_raw(vec);
        }

        static key create_public_key_from_base64(const std::string& rawPublicKey)
        {
            v_uint8 vec = Botan::hex_decode(rawPublicKey);
            return create_public_key_from_raw(vec);
        }

        [[nodiscard]] std::string public_key() const
        {
            if (type == ED448) {
                const auto* pk = dynamic_cast<const Botan::Ed448_PublicKey*>(key_.get());
                return Botan::hex_encode(pk->public_key_bits());
            } else if (type == X448) {
                const auto* pk = dynamic_cast<const Botan::X448_PublicKey*>(key_.get());
                return Botan::hex_encode(pk->public_key_bits());
//            } else if (type == ED25519) {
//                const auto* pk = dynamic_cast<const Botan::Ed25519_PublicKey*>(key_.get());
//                return Botan::hex_encode(pk->public_key_bits());
//            } else if (type == X25519) {
//                const auto* pk = dynamic_cast<const Botan::X25519_PublicKey*>(key_.get());
//                return Botan::hex_encode(pk->public_key_bits());
            } else {
                throw crypto_exception("Unsupported key type", std::string(), "public_key");
            }
        }

        [[nodiscard]] std::string private_key() const
        {
            if (type == ED448) {
                const auto* pk = dynamic_cast<const Botan::Ed448_PrivateKey*>(key_.get());
                return Botan::hex_encode(pk->private_key_bits());
            } else if (type == X448) {
                const auto* pk = dynamic_cast<const Botan::X448_PrivateKey*>(key_.get());
                return Botan::hex_encode(pk->private_key_bits());
//            } else if (type == ED25519) {
//                const auto* pk = dynamic_cast<const Botan::Ed25519_PrivateKey*>(key_.get());
//                return Botan::hex_encode(pk->private_key_bits());
//            } else if (type == X25519) {
//                const auto* pk = dynamic_cast<const Botan::X25519_PrivateKey*>(key_.get());
//                return Botan::hex_encode(pk->private_key_bits());
            } else {
                throw crypto_exception("Unsupported key type", std::string(), "private_key");
            }
        }

        [[nodiscard]] v_uint8 public_key_raw() const
        {
            if (type == ED448) {
                const auto* pk = dynamic_cast<const Botan::Ed448_PublicKey*>(key_.get());
                return pk->public_key_bits();
            } else if (type == X448) {
                const auto* pk = dynamic_cast<const Botan::X448_PublicKey*>(key_.get());
                return pk->public_key_bits();
//            } else if (type == ED25519) {
//                const auto* pk = dynamic_cast<const Botan::Ed25519_PublicKey*>(key_.get());
//                return pk->public_key_bits();
//            } else if (type == X25519) {
//                const auto* pk = dynamic_cast<const Botan::X25519_PublicKey*>(key_.get());
//                return pk->public_key_bits();
            } else {
                throw crypto_exception("Unsupported key type", std::string(), "public_key_raw");
            }
        }

        [[nodiscard]] std::string public_key_raw_hex() const
        {
            return Botan::hex_encode(public_key_raw().data(), public_key_raw().size());
        }

        [[nodiscard]] std::string public_key_raw_base64() const
        {
            return Botan::base64_encode(public_key_raw().data(), public_key_raw().size());
        }

        [[nodiscard]] v_uint8 private_key_raw() const
        {
            if (type == ED448) {
                const auto* pk = dynamic_cast<const Botan::Ed448_PrivateKey*>(key_.get());
                return {pk->private_key_bits().begin(), pk->private_key_bits().end()};
            } else if (type == X448) {
                const auto* pk = dynamic_cast<const Botan::X448_PrivateKey*>(key_.get());
                return {pk->private_key_bits().begin(), pk->private_key_bits().end()};
//            } else if (type == ED25519) {
//                const auto* pk = dynamic_cast<const Botan::Ed25519_PrivateKey*>(key_.get());
//                return v_uint8(pk->private_key_bits().begin(), pk->private_key_bits().end());
//            } else if (type == X25519) {
//                const auto* pk = dynamic_cast<const Botan::X25519_PrivateKey*>(key_.get());
//                return v_uint8(pk->private_key_bits().begin(), pk->private_key_bits().end());
            } else {
                throw crypto_exception("Unsupported key type", std::string(), "private_key_raw");
            }
        }

        [[nodiscard]] std::string private_key_raw_hex() const
        {
            return Botan::hex_encode(private_key_raw().data(), private_key_raw().size());
        }

        [[nodiscard]] std::string private_key_raw_base64() const
        {
            return Botan::base64_encode(private_key_raw().data(), private_key_raw().size());
        }

    private:
        unique_key_ptr key_;
    };

    //ed DSA
    class crypto_sign {
    public:

        crypto_sign() = default;

        template<int type>
        static v_uint8 sign(const unsigned char* message, std::size_t length, const key<type>& secret_key)
        {
            Botan::AutoSeeded_RNG rng;
            Botan::PK_Signer signer(*(secret_key.get()), rng, "Ed448ph");
            signer.update(message, length);
            return signer.signature(rng);
        }

        template<int type>
        static v_uint8 sign_base64(const std::string& messageBase64, const key<type>& secret_key)
        {
            Botan::secure_vector<uint8_t> vec = Botan::base64_decode(messageBase64);
            return sign(vec.data(), vec.size(), secret_key);
        }

        template<int type>
        static v_uint8 sign_hex(const std::string& messageHex, const key<type>& secret_key)
        {
            v_uint8 vec = Botan::hex_decode(messageHex);
            return sign(vec.data(), vec.size(), secret_key);
        }

        template<int type>
        static v_uint8 sign(const std::string& message, const key<type>& secret_key)
        {
            return sign(reinterpret_cast <const unsigned char*>(message.c_str()), message.length(), secret_key);
        }

        template<int type>
        static bool verify(const unsigned char* message, std::size_t msglen, const unsigned char* signature, std::size_t siglen, const key<type>& public_key)
        {
            Botan::PK_Verifier verifier(*(public_key.get()), "Ed448ph");
            verifier.update(message, msglen);
            return verifier.check_signature(signature, siglen);
        }

        template<int type>
        static bool verify(const std::string& message, const unsigned char* signature, std::size_t siglen, const key<type>& public_key)
        {
            return verify(reinterpret_cast <const unsigned char*>(message.c_str()), message.length(), signature, siglen, public_key);
        }

        template<int type>
        static bool verify(const std::string& message, const std::string& signature, const key<type>& public_key)
        {
            return verify(reinterpret_cast <const unsigned char*>(message.c_str()), message.length(),
                          reinterpret_cast <const unsigned char*>(signature.c_str()), signature.length(), public_key);
        }

        template<int type>
        static bool verify_base64(const std::string& message, const std::string& signatureBase64, const key<type>& public_key)
        {
            Botan::secure_vector<uint8_t> vec = Botan::base64_decode(signatureBase64);
            return verify(message, vec.data(), vec.size(), public_key);
        }

        template<int type>
        static bool verify_hex(const std::string& message, const std::string& signatureHex, const key<type>& public_key)
        {
            v_uint8 vec = Botan::hex_decode(signatureHex);
            return verify(message, vec.data(), vec.size(), public_key);
        }
    };

    //ed DH
    class crypto_box {
        static std::string encrypt()
        {
            return {};
        }

        static std::string decrypt()
        {
            return {};
        }
    };

    using key_dsa448 = key<ED448>;
    using key_dh448 = key<X448>;
    using key_dsa25519 = key<ED25519>;
    using key_hd25519 = key<X25519>;
}