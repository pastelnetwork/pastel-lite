// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <filesystem>
#include <botan/base64.h>

#include "pastelid/secure_container.h"
#include "pastelid/common.h"

#include "libpastel.h"

using namespace std;
namespace fs = std::filesystem;
using namespace secure_container;
using namespace crypto_helpers;

PastelSigner::PastelSigner(const string& pastelID_dir){
    if (!fs::exists(pastelID_dir)) {
        throw runtime_error("PastelID directory does not exist");
    }
    if (fs::is_empty(pastelID_dir)) {
        throw runtime_error("PastelID directory is empty");
    }
    m_pastelIDDir = pastelID_dir;
}

string PastelSigner::getPastelIDKey(const string& pastelID, const SecureString& password) {
    std::filesystem::path dir(m_pastelIDDir);
    std::filesystem::path file(pastelID);
    std::filesystem::path full_path = dir / file;

    CSecureContainer cont;
    cont.read_from_file(full_path.string(), password);

    return "";
}

string PastelSigner::SignWithPastelID(const string& pastelID, const string& message, const SecureString& password) {



    return "";
}

string PastelSigner::SignWithPastelIDBase64(const string& pastelID, const string& messageBase64, const SecureString& password) {
    auto message = Botan::base64_decode(messageBase64);
    return SignWithPastelID(pastelID, string(message.begin(), message.end()), password);
}

bool PastelSigner::VerifyWithPastelID(const string& pastelID, const string& message, const string& signature) {
    return ed448_verify(pastelID, message, signature, encoding::base64);
}

bool PastelSigner::VerifyWithPastelIDBase64(const string& pastelID, const string& messageBase64, const string& signature) {
    auto message = Botan::base64_decode(messageBase64);
    return VerifyWithPastelID(pastelID, string(message.begin(), message.end()), signature);
}