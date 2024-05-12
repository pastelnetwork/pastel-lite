// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <algorithm>
#include <filesystem>
#include <fmt/core.h>

#include "vector_types.h"
#include "pastelid/pastel_key.h"
#include "pastelid/secure_container.h"
#include "compat/endian.h"
#include "hash.h"

using namespace std;
using namespace secure_container;

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
void initFS() {
    EM_ASM(
        FS.mkdir('/wallet_data');
        FS.mount(IDBFS, {}, '/wallet_data');
        FS.syncfs(true, function(err) {
            if (err) {
                console.error('Error syncing file system:', err);
            } else {
                console.log('File system synced successfully.');
            }
        });
    );
}

// Function to sync the file system
void syncFS() {
    EM_ASM(
        FS.syncfs(function(err) {
            if (err) {
                console.error('Error syncing file system:', err);
            } else {
                console.log('File system synced successfully.');
            }
        });
    );
}
#endif

/**
 * Add secure item to the container (data in a byte vector).
 * 
 * \param type - item type
 * \param vData - data in a byte vector to encrypt
 */
void CSecureContainer::add_secure_item_vector(const SECURE_ITEM_TYPE type, const v_uint8& vData) noexcept
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(vData), nullptr);
}

void CSecureContainer::add_secure_item_vector(const SECURE_ITEM_TYPE type, v_uint8&& vData) noexcept
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(std::move(vData)), nullptr);
}

/**
 * Add public item to the secure container.
 * 
 * \param type - public item type
 * \param sData - public item data
 */
void CSecureContainer::add_public_item(const PUBLIC_ITEM_TYPE type, const std::string& sData) noexcept
{
     m_vPublicItems.emplace_back(type, std::move(string_to_vector(sData)));
}

/**
 * Write secure container to the file.
 *
 * \param sPassphrase - passphrase in clear text to use for encryption
 */
void CSecureContainer::write_to_file(const string& sFilePath, SecureString&& sPassphrase) {

        using json = nlohmann::ordered_json;
#ifdef __EMSCRIPTEN__
        initFS();
        FILE* fs = fopen(sFilePath.c_str(), "wb");
        if (!fs)
            throw runtime_error(fmt::format("Cannot open file [{}] to write the secure container", sFilePath.c_str()));
#else
        ofstream fs(sFilePath, ios::out | ios::binary);
        if (!fs)
            throw runtime_error(fmt::format("Cannot open file [{}] to write the secure container", sFilePath.c_str()));
#endif

    try {

        json jItems;
        // generate json for the public items
        json jPublic =
                {
                        {"version", SECURE_CONTAINER_VERSION}
                };
        size_t nJsonPublicSize = 20; // used to estimate size of the json with public items

            for (const auto &item: m_vPublicItems) {
                const auto szTypeName = GetPublicItemTypeName(item.type);
                jItems.push_back(
                        {
                                {"type", szTypeName},
                                {"data", item.data}
                        });
                nJsonPublicSize += 25 + strlen(szTypeName) + item.data.size();
            }
            jPublic.emplace("public_items", std::move(jItems));
            jItems.clear();

            // generate a json header for the secure items
            m_nTimestamp = time(nullptr);
            json jSecure =
                    {
                            {"version",    SECURE_CONTAINER_VERSION},
                            {"timestamp",  m_nTimestamp},
                            {"encryption", SECURE_CONTAINER_ENCRYPTION}
                    };
            size_t nJsonSecureSize = 200; // used to estimate size of the json with secure items
            CSodiumAutoBuf pw;
        // allocate secure memory for the key, buffer is reused for all secure items
        if (!pw.allocate(PWKEY_BUFSUZE))
            throw runtime_error(fmt::format("Failed to allocate memory ({} bytes)", PWKEY_BUFSUZE));
        // encryption buffer is reused for all messages
        json::binary_t encrypted_data;
        for (auto &item: m_vSecureItems) {
            // generate nonce
            item.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            randombytes_buf(item.nonce.data(), item.nonce.size());
            // derive key from the passphrase
            if (crypto_pwhash(pw.p, crypto_box_SEEDBYTES,
                              sPassphrase.c_str(), sPassphrase.length(), item.nonce.data(),
                              crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                              crypto_pwhash_ALG_DEFAULT) != 0) {
                throw runtime_error(
                        fmt::format("Failed to generate encryption key for '{}'", GetSecureItemTypeName(item.type)));
            }
            // if data handler is defined -> use it to get secure data
            if (item.pHandler) {
                if (!item.pHandler->GetSecureData(item.data))
                    throw runtime_error(fmt::format("Failed to get '{}' data", GetSecureItemTypeName(item.type)));
                // possibility for caller to cleanup data
                item.pHandler->CleanupSecureData();
            }
            // encrypt data using XChaCha20-Poly1305 construction
            unsigned long long nEncSize = 0;
            encrypted_data.resize(item.data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
            if (crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted_data.data(), &nEncSize,
                                                           item.data.data(), item.data.size(), nullptr, 0, nullptr,
                                                           item.nonce.data(), pw.p) != 0)
                throw runtime_error(fmt::format("Failed to encrypt '{}' data", GetSecureItemTypeName(item.type)));
            const auto szTypeName = GetSecureItemTypeName(item.type);
            const size_t nEncryptedDataSize = encrypted_data.size();
            const size_t nItemNonceSize = item.nonce.size();
            jItems.push_back({
                                     {"type",  szTypeName},
                                     {"nonce", std::move(item.nonce)},
                                     {"data",  std::move(encrypted_data)}
                             });
            nJsonSecureSize += 50 + strlen(szTypeName) + nItemNonceSize + nEncryptedDataSize;
        }
        jSecure.emplace("secure_items", std::move(jItems));

        // serialize as a msgpack to file

#ifdef __EMSCRIPTEN__
        fwrite(SECURE_CONTAINER_PREFIX, 1, std::char_traits<char>::length(SECURE_CONTAINER_PREFIX), fs);
#else
        fs.write(SECURE_CONTAINER_PREFIX, std::char_traits<char>::length(SECURE_CONTAINER_PREFIX));
#endif

        v_uint8 vOut;
        const auto nMsgPackReserve = std::max(nJsonPublicSize, nJsonSecureSize);
        vOut.reserve(nMsgPackReserve);
        // write json for public items to the file serialized into msgpack format
        json::to_msgpack(jPublic, vOut);
        jPublic.clear();
        // write msgpack size in network byte order (big endian)
        const uint64_t nMsgPackSize = htobe64(vOut.size());

#ifdef __EMSCRIPTEN__
        fwrite(&nMsgPackSize, sizeof(nMsgPackSize), 1, fs);
#else
        fs.write(reinterpret_cast<const char *>(&nMsgPackSize), sizeof(nMsgPackSize));
#endif

        // calculate and write hash of the msgpack
        const auto hash = Hash(vOut.cbegin(), vOut.cend());

#ifdef __EMSCRIPTEN__
        fwrite(hash.begin(), 1, hash.size(), fs);
#else
        hash.Serialize(fs);
#endif

        // write public items in msgpack format
#ifdef __EMSCRIPTEN__
        fwrite(vOut.data(), 1, vOut.size(), fs);
#else
        fs.write(reinterpret_cast<const char *>(vOut.data()), vOut.size());
#endif

        vOut.clear();

        // write json for secure items to the file serialized into msgpack format
        json::to_msgpack(jSecure, vOut);
        jSecure.clear();

#ifdef __EMSCRIPTEN__
        fwrite(vOut.data(), 1, vOut.size(), fs);
        fclose(fs);
        syncFS();
#else
        fs.write(reinterpret_cast<const char*>(vOut.data()), vOut.size());
#endif
    } catch(const std::exception &ex){
#ifdef __EMSCRIPTEN__
        fclose(fs);
        syncFS();
#endif
        throw runtime_error(fmt::format("Failed to write secure container to file [{}]. {}", sFilePath.c_str(), ex.what()));
    }
}

/**
 * Clear the container.
 *
 */
void CSecureContainer::clear() noexcept
{
    m_nVersion = 0; // version not defined
    m_nTimestamp = -1;
    m_sEncryptionAlgorithm.clear();
    for (auto& item : m_vSecureItems)
        item.cleanup();
    m_vSecureItems.clear();
    m_vPublicItems.clear();
}

/**
 * Read from secure container header and public items.
 *
 * \param fs - input file stream
 * \param nDataSize - returns
 * \return true - if public items were successfully read. In this case current position is fs
 *                will be set to the beginning of the secure items msgpack.
 *         false - if secure container prefix does not match
 *                throws runtime_error if any error occurred while reading secure container public data
 */
bool CSecureContainer::read_public_items_ex(
#ifdef __EMSCRIPTEN__
        FILE* fs,
#else
        std::ifstream& fs,
#endif
        uint64_t& nDataSize)
{
    using json = nlohmann::json;
    bool bRet = false;
    do
    {
        // get file size
#ifdef __EMSCRIPTEN__
        fseek(fs, 0, SEEK_END);
        auto nFileSize = ftell(fs);
        fseek(fs, 0, SEEK_SET);
#else
        const auto nFileSize = fs.tellg();
        fs.seekg(0);
#endif
        if (nFileSize < 0)
            break;
        nDataSize = static_cast<uint64_t>(nFileSize);
        // read prefix from the file and compare with SECURE_CONTAINER_PREFIX
        constexpr auto nPrefixLength = std::char_traits<char>::length(SECURE_CONTAINER_PREFIX);
        if (nDataSize < nPrefixLength)
            break;
        char szPrefix[nPrefixLength + 1];

#ifdef __EMSCRIPTEN__
        if (fread(szPrefix, 1, nPrefixLength, fs) != nPrefixLength)
            break;
#else
        fs.read(szPrefix, nPrefixLength);
        if (fs.gcount() != nPrefixLength)
            break;
#endif
        szPrefix[nPrefixLength] = 0;
        // check if prefix matches
        if (strcmp(szPrefix, SECURE_CONTAINER_PREFIX) != 0)
            break;
        nDataSize -= nPrefixLength;
        // here we should have two fields:
        // [ size of the public items msgpack in network bytes order - uint64_t, 8-bytes] [ hash of the public items msgpack, uint256, 32-bytes ]
        if (nDataSize < sizeof(uint64_t) + uint256::SIZE)
            throw runtime_error("No public data found in the secure container");
        uint64_t nMsgPackSize = 0;
        v_uint8 vHash;
        vHash.resize(uint256::SIZE);

#ifdef __EMSCRIPTEN__
        fread(&nMsgPackSize, sizeof(uint64_t), 1, fs);
        fread(vHash.data(), 1, vHash.size(), fs);
#else
        fs.read(reinterpret_cast<char*>(&nMsgPackSize), sizeof(uint64_t))
          .read(reinterpret_cast<char*>(vHash.data()), vHash.size());
#endif
        nDataSize -= sizeof(uint64_t) + uint256::SIZE;
        // convert size to host order
        nMsgPackSize = be64toh(nMsgPackSize);
        if (nMsgPackSize > nDataSize)
            throw runtime_error(fmt::format("Invalid size [{}] for the public data in the secure container", nMsgPackSize));
        // read public data from the secure container as msgpack
        v_uint8 v;
        v.resize(nMsgPackSize);

#ifdef __EMSCRIPTEN__
        fread(v.data(), 1, v.size(), fs);
#else
        fs.read(reinterpret_cast<char*>(v.data()), v.size());
#endif

        // verify hash
        const auto MsgPackHash = Hash(v.cbegin(), v.cend());
        if (memcmp(&MsgPackHash, vHash.data(), uint256::SIZE) != 0)
            throw runtime_error("Failed to verify public data integrity in the secure container");
        nDataSize -= nMsgPackSize;
        json j = json::from_msgpack(v);
        v.clear();
        // process public items
        string sType;
        for (auto& jItem : j.at("public_items"))
        {
            jItem["type"].get_to(sType);
            public_item_t item;
            item.type = GetPublicItemTypeByName(sType);
            if (item.type == PUBLIC_ITEM_TYPE::not_defined)
                throw runtime_error(fmt::format("Public item type '{}' is not supported in the secure container", sType));
            item.data = std::move(jItem["data"].get_binary());
            m_vPublicItems.push_back(std::move(item));
        }

        bRet = true;
    } while (false);
    return bRet;
}

/**
 * Read from secure container file public and secure data encoded as a msgpack.
 * Decrypt secure data. Throws std::runtime_error exception in case of failure.
 *
 * \param sFilePath - container file path
 * \param sPassphrase - passphrase in clear text to use for data decryption
 * \return true if file was successfully read and decrypted
 *         false if file does not contain Pastel secure container
 *         if container data cannot be read or decrypted - throws std::runtime_error
 */
void CSecureContainer::read_from_file(const string& sFilePath, const SecureString& sPassphrase)
{
    using json = nlohmann::json;
    bool bOk = false;
    string error;

#ifdef __EMSCRIPTEN__
    initFS();
            FILE* fs = fopen(sFilePath.c_str(), "rb");
            if (!fs)
                throw runtime_error(fmt::format("File [{}] does not exist", sFilePath.c_str()));
#endif

    try
    {
        do
        {
            clear();
#ifndef __EMSCRIPTEN__
            if (!std::filesystem::exists(sFilePath))
                throw runtime_error(fmt::format("File [{}] does not exist", sFilePath.c_str()));
            ifstream fs(sFilePath, ios::in | ios::ate | ios::binary);
            fs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
#endif
            v_uint8 v;
            uint64_t nDataSize = 0;
            if (!read_public_items_ex(fs, nDataSize))
                break;
            // read secure container data as json msgpack
            v.resize(nDataSize);

#ifdef __EMSCRIPTEN__
            fread(v.data(), 1, v.size(), fs);
#else
            fs.read(reinterpret_cast<char*>(v.data()), v.size());
#endif
            json j = json::from_msgpack(v);
            v.clear();

            // read header
            j.at("version").get_to(m_nVersion);
            j.at("timestamp").get_to(m_nTimestamp);
            j.at("encryption").get_to(m_sEncryptionAlgorithm);
            if (m_sEncryptionAlgorithm != SECURE_CONTAINER_ENCRYPTION)
                throw runtime_error(fmt::format(
                        "Encryption algorithm '{}' is not supported",
                        m_sEncryptionAlgorithm.c_str()));

            CSodiumAutoBuf pw;
            // allocate secure memory for the key, buffer is reused for all secure items
            if (!pw.allocate(PWKEY_BUFSUZE))
                throw runtime_error(fmt::format(
                        "Failed to allocate memory ({} bytes)",
                        PWKEY_BUFSUZE));

            // process encrypted items
            // read nonce for each item and use it to derive password key from passphrase and
            // to decrypt data
            string sType;
            for (auto &jItem : j.at("secure_items"))
            {
                jItem["type"].get_to(sType);
                secure_item_t item;
                item.type = GetSecureItemTypeByName(sType);
                if (item.type == SECURE_ITEM_TYPE::not_defined)
                    throw runtime_error(fmt::format("Secure item type '{}' is not supported", sType));
                jItem["nonce"].get_to(item.nonce);
                // encrypted data
                auto& encrypted_data = jItem["data"].get_binary();

                // derive key from the passphrase
                if (crypto_pwhash(pw.p, crypto_box_SEEDBYTES,
                                  sPassphrase.c_str(), sPassphrase.length(), item.nonce.data(),
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
                {
                    throw runtime_error(fmt::format("Failed to generate encryption key for the secure item '{}'", GetSecureItemTypeName(item.type)));
                }
                item.data.resize(encrypted_data.size());
                unsigned long long nDecryptedLength = 0;
                if (crypto_aead_xchacha20poly1305_ietf_decrypt(item.data.data(), &nDecryptedLength, nullptr,
                                                               encrypted_data.data(), encrypted_data.size(), nullptr, 0, item.nonce.data(), pw.p) != 0)
                {
                    throw secure_container_exception(fmt::format(
                            "Passphrase is invalid. Failed to decrypt secure item '{}' data",
                            sType));
                }
                item.data.resize(nDecryptedLength);
                m_vSecureItems.push_back(std::move(item));
            }
            bOk = true;
        } while (false);
    }
    catch (const std::out_of_range &ex)
    {
        error = fmt::format("Pastel secure container file format error. {}", ex.what());
    }
    catch (const secure_container_exception &ex)
    {
        error = fmt::format("{}", ex.what());
    }
    catch (const std::exception &ex)
    {
        error = fmt::format("Failed to read Pastel secure container file [{0}]. {1}", sFilePath.c_str(), ex.what());
    }

#ifdef __EMSCRIPTEN__
    fclose(fs);
    syncFS();
#endif

    if (!bOk)
        throw runtime_error(error);
}
