// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <filesystem>
#include <botan/base64.h>

#include "crypto/common.h"
#include "pastelid/secure_container.h"
#include "pastelid/common.h"

#include "libpastel.h"

using namespace std;
namespace fs = std::filesystem;
using namespace secure_container;
using namespace crypto_helpers;

auto PastelID::getPastelIDKey(const string& pastelIDDir, const string& pastelID, const SecureString& password) {
    std::filesystem::path dir(pastelIDDir);
    std::filesystem::path file(pastelID);
    std::filesystem::path full_path = dir / file;

    CSecureContainer cont;
    cont.read_from_file(full_path.string(), password);
    return cont.extract_secure_data(SECURE_ITEM_TYPE::pkey_ed448);
}

PastelID PastelID::Load(const string& pastelIDDir, const string& pastelID, const string& password) {
    auto key = getPastelIDKey(pastelIDDir, pastelID, password);
    return PastelID(pastelIDDir, pastelID, key);
}

[[nodiscard]] string PastelID::Sign(const string& message) {
    auto key = m_key;
    return ed448_sign(std::move(key), message, encoding::base64);   // return signature as base64
}

[[nodiscard]] string PastelID::SignBase64(const string& messageBase64) {
    auto message = Botan::base64_decode(messageBase64);
    auto key = m_key;
    return ed448_sign(std::move(key), string(message.begin(), message.end()), encoding::base64);   // return signature as base64
}

bool PastelID::Verify(const string& message, const string& signature) {
    auto sig = Botan::base64_decode(signature);
    return ed448_verify(m_pastelID, message, signature, encoding::base64);   // accept signature as base64
}

bool PastelID::VerifyBase64(const string& messageBase64, const string& signature){
    auto message = Botan::base64_decode(messageBase64);
    return ed448_verify(m_pastelID, string(message.begin(), message.end()), signature, encoding::base64);   // accept signature as base64
}

PastelSigner::PastelSigner(const string& pastelID_dir){
    init_and_check_sodium();

    if (!fs::exists(pastelID_dir)) {
        throw runtime_error("PastelID directory does not exist");
    }
    if (fs::is_empty(pastelID_dir)) {
        throw runtime_error("PastelID directory is empty");
    }
    m_pastelIDDir = pastelID_dir;
}

string PastelSigner::SignWithPastelID(const string& message, const string& pastelID, const string& password) {
    auto key = PastelID::getPastelIDKey(m_pastelIDDir, pastelID, password);
    return ed448_sign(std::move(key), message, encoding::base64);   // return signature as base64
}

string PastelSigner::SignWithPastelIDBase64(const string& messageBase64, const string& pastelID, const string& password) {
    auto message = Botan::base64_decode(messageBase64);
    auto key = PastelID::getPastelIDKey(m_pastelIDDir, pastelID, password);
    return ed448_sign(std::move(key), string(message.begin(), message.end()), encoding::base64);   // return signature as base64
}

bool PastelSigner::VerifyWithPastelID(const string& message, const string& signature, const string& pastelID) {
    auto sig = Botan::base64_decode(signature);
    return ed448_verify(pastelID, message, signature, encoding::base64);   // accept signature as base64
}

bool PastelSigner::VerifyWithPastelIDBase64(const string& messageBase64, const string& signature, const string& pastelID) {
    auto message = Botan::base64_decode(messageBase64);
    return ed448_verify(pastelID, string(message.begin(), message.end()), signature, encoding::base64);   // accept signature as base64
}
