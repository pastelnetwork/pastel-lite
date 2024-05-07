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

/**
 * Add secure item to the container (data in a string).
 * 
 * \param type - item type
 * \param sData - data string to encrypt
 */
void CSecureContainer::add_secure_item_string(const SECURE_ITEM_TYPE type, const std::string& sData) noexcept
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(std::move(string_to_vector(sData))), nullptr);
}

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
 * Add secure item to the container (handler interface to get data).
 * 
 * \param type - item type
 * \param sData - data string to encrypt
 * \param pHandler - interface to set/get secure data for the item
 */
void CSecureContainer::add_secure_item_handler(const SECURE_ITEM_TYPE type, ISecureDataHandler* pHandler) noexcept 
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(), pHandler);
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
 * Find secure item in the container by type.
 * 
 * \param type - secure item type to find
 * \return 
 */
auto CSecureContainer::find_secure_item(const SECURE_ITEM_TYPE type) noexcept
{
    return find_if(m_vSecureItems.begin(), m_vSecureItems.end(), [=](const auto& Item) { return Item.type == type; });
}

/**
 * Find public item in the container by type.
 * 
 * \param type - secure item type to find
 * \return 
 */
auto CSecureContainer::find_public_item(const PUBLIC_ITEM_TYPE type) const noexcept
{
    return find_if(m_vPublicItems.cbegin(), m_vPublicItems.cend(), [=](const auto& Item) { return Item.type == type; });
}

/**
 * Get public data (byte vector) from the container by type.
 * 
 * \param type - public item type
 * \param data - public binary data
 * \return true if public item was found in the secure container
 */
bool CSecureContainer::get_public_data_vector(const PUBLIC_ITEM_TYPE type, v_uint8& data) const noexcept
{
    const auto it = find_public_item(type);
    if (it != m_vPublicItems.cend())
    {
        data = it->data;
        return true;
    }
    return false;
}

/**
 * Get public data (string) from the container by type.
 * 
 * \param type - public item type
 * \param sData - public string data
 * \return true if public item was found in the secure container
 */
bool CSecureContainer::get_public_data(const PUBLIC_ITEM_TYPE type, std::string& sData) const noexcept
{
    const auto it = find_public_item(type);
    if (it != m_vPublicItems.cend())
    {
        sData.assign(it->data.cbegin(), it->data.cend());
        return true;
    }
    return false;
}

/**
 * Extract secure data from the container by type (byte vector).
 * 
 * \param type - secure item type
 * \return - secure data in byte vector (moved from storage)
 */
v_uint8 CSecureContainer::extract_secure_data(const SECURE_ITEM_TYPE type)
{
    auto it = find_secure_item(type);
    if (it != m_vSecureItems.end())
        return std::move(it->data);
    return {};
}

/**
 * Extract secure data from the container by type (string).
 * 
 * \param type - secure item type
 * \return - secure data (moved from storage)
 */
string CSecureContainer::extract_secure_data_string(const SECURE_ITEM_TYPE type)
{
    auto it = find_secure_item(type);
    string sData;
    if (it != m_vSecureItems.end())
    {
        sData.assign(reinterpret_cast<const char *>(it->data.data()), it->data.size());
        memory_cleanse(it->data.data(), it->data.size());
        it->data.clear();
    }
    return sData;
}

////////////////////////// Serialize/DeSerialize //////////////////////////
/**
 * Serialize secure container to a Base58 encoded string.
 *
 * \param sPassphrase - passphrase in clear text to use for encryption
 * \return - Base58 encoded string
 */
bool CSecureContainer::serialize(SecureString&& sPassphrase, v_uint8 &vOut)
{
    using json = nlohmann::ordered_json;

    json jItems;
    // generate json for the public items
    json jPublic =
    {
        { "version", SECURE_CONTAINER_VERSION }
    };
    size_t nJsonPublicSize = 20; // used to estimate size of the json with public items

    for (const auto& item: m_vPublicItems)
    {
        const auto szTypeName = GetPublicItemTypeName(item.type);
        jItems.push_back(
            {
                { "type", szTypeName },
                { "data", item.data }
            });
        nJsonPublicSize += 25 + strlen(szTypeName) + item.data.size();
    }
    jPublic.emplace("public_items", std::move(jItems));
    jItems.clear();

    // generate a json header for the secure items
    m_nTimestamp = time(nullptr);
    json jSecure =
    {
        { "version", SECURE_CONTAINER_VERSION },
        { "timestamp", m_nTimestamp },
        { "encryption", SECURE_CONTAINER_ENCRYPTION }
    };
    size_t nJsonSecureSize = 200; // used to estimate size of the json with secure items
    CSodiumAutoBuf pw;
    // allocate secure memory for the key, buffer is reused for all secure items
    if (!pw.allocate(PWKEY_BUFSUZE))
        throw runtime_error(fmt::format("Failed to allocate memory ({} bytes)", PWKEY_BUFSUZE));
    // encryption buffer is reused for all messages
    json::binary_t encrypted_data;
    for (auto& item : m_vSecureItems)
    {
        // generate nonce
        item.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(item.nonce.data(), item.nonce.size());
        // derive key from the passphrase
        if (crypto_pwhash(pw.p, crypto_box_SEEDBYTES,
            sPassphrase.c_str(), sPassphrase.length(), item.nonce.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
        {
            throw runtime_error(fmt::format("Failed to generate encryption key for '{}'", GetSecureItemTypeName(item.type)));
        }
        // if data handler is defined -> use it to get secure data
        if (item.pHandler)
        {
            if (!item.pHandler->GetSecureData(item.data))
                throw runtime_error(fmt::format("Failed to get '{}' data", GetSecureItemTypeName(item.type)));
            // possibility for caller to cleanup data
            item.pHandler->CleanupSecureData();
        }
        // encrypt data using XChaCha20-Poly1305 construction
        unsigned long long nEncSize = 0;
        encrypted_data.resize(item.data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted_data.data(), &nEncSize,
                                                       item.data.data(), item.data.size(), nullptr, 0, nullptr, item.nonce.data(), pw.p) != 0)
            throw runtime_error(fmt::format("Failed to encrypt '{}' data", GetSecureItemTypeName(item.type)));
        const auto szTypeName = GetSecureItemTypeName(item.type);
        const size_t nEncryptedDataSize = encrypted_data.size();
        const size_t nItemNonceSize = item.nonce.size();
        jItems.push_back({
            {"type", szTypeName},
            {"nonce", std::move(item.nonce)},
            {"data", std::move(encrypted_data)}
        });
        nJsonSecureSize += 50 + strlen(szTypeName) + nItemNonceSize + nEncryptedDataSize;
    }
    jSecure.emplace("secure_items", std::move(jItems));

    // write prefix to the vector
    vOut.insert(vOut.end(), SECURE_CONTAINER_PREFIX, SECURE_CONTAINER_PREFIX + std::char_traits<char>::length(SECURE_CONTAINER_PREFIX));

    const auto nMsgPackReserve = std::max(nJsonPublicSize, nJsonSecureSize);
    vOut.reserve(vOut.size() + nMsgPackReserve);

    // write json for public items to the vector serialized into msgpack format
    json::to_msgpack(jPublic, vOut);
    jPublic.clear();

    // write msgpack size in network byte order (big endian)
    const uint64_t nMsgPackSize = htobe64(vOut.size());
    vOut.insert(vOut.end(), reinterpret_cast<const uint8_t*>(&nMsgPackSize), reinterpret_cast<const uint8_t*>(&nMsgPackSize) + sizeof(nMsgPackSize));

    // calculate and write hash of the msgpack
    const auto hash = Hash(vOut.cbegin(), vOut.cend());
    vOut.insert(vOut.end(), hash.begin(), hash.end());

    // write json for secure items to the vector serialized into msgpack format
    json::to_msgpack(jSecure, vOut);
    jSecure.clear();

    return true;
}

////////////////////////// FS based functions //////////////////////////
#ifndef __EMSCRIPTEN__
/**
 * Encrypt and save secure container to the file.
 * Throws std::runtime_error exception in case of failure.
 *
 * \param sFilePath - secure container absolute file path
 * \param vIn - secure container data to write
 * \return true if file was successfully written
 */
bool CSecureContainer::write_to_file(const string& sFilePath, const v_uint8 &vIn)
{
    ofstream outputFile(sFilePath, ios::out | ios::binary);
    if (!outputFile)
        throw runtime_error(fmt::format("Cannot open file [{}] to write the secure container", sFilePath.c_str()));

    // write the decoded data to the file
    outputFile.write(reinterpret_cast<const char*>(vIn.data()), vIn.size());

    // close the file
    outputFile.close();

    return true;
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
bool CSecureContainer::read_from_file(const string& sFilePath, const SecureString& sPassphrase)
{
    using json = nlohmann::json;
    bool bRet = false;
    try
    {
        do
        {
            clear();

            if (!std::filesystem::exists(sFilePath))
                throw runtime_error(fmt::format("File [{}] does not exist", sFilePath.c_str()));
            ifstream fs(sFilePath, ios::in | ios::ate | ios::binary);
            fs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
            v_uint8 v;
            uint64_t nDataSize = 0;
            if (!read_public_items_ex(fs, nDataSize))
                break;
            // read secure container data as json msgpack
            v.resize(nDataSize);
            fs.read(reinterpret_cast<char*>(v.data()), v.size());
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
            bRet = true;
        } while (false);
    }
    catch (const std::out_of_range &ex)
    {
        throw runtime_error(fmt::format("Pastel secure container file format error. {}", ex.what()));
    }
    catch (const secure_container_exception &ex)
    {
        throw runtime_error(fmt::format("{}", ex.what()));
    }
    catch (const std::exception &ex)
    {
        throw runtime_error(fmt::format("Failed to read Pastel secure container file [{0}]. {1}", sFilePath.c_str(), ex.what()));
    }
    return bRet;
}

/**
 * Read from secure container file public data as a msgpack.
 *
 * \param error - error message
 * \param sFilePath - container file path
 * \return true if public items were successfully read from the container
 */
bool CSecureContainer::read_public_from_file(string &error, const string& sFilePath)
{
    clear();

    bool bRet = false;
    try
    {
    	ifstream fs(sFilePath, ios::in | ios::ate | ios::binary);
	    fs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
	    uint64_t nDataSize = 0;
    	bRet = read_public_items_ex(fs, nDataSize);
    }
    catch (const system_error &ex)
    {
        error = fmt::format("Failed to read public items from secure container [{0}]. {1}", sFilePath, ex.code().message());
    }
    return bRet;
}

/**
 * Change passphrase that was used to encrypt the secure container.
 *
 * \param sFilePath - secure container absolute file path
 * \param sOldPassphrase - old passphrase used to encrypt the secure container
 * \param sNewPassphrase - new passphrase (should not be empty)
 * \return true if successfully changed passphrase and encrypted secure container
 *         throws std::runtime_error in case of any error
 */
bool CSecureContainer::change_passphrase(const std::string& sFilePath, SecureString&& sOldPassphrase, SecureString&& sNewPassphrase)
{
    if (sNewPassphrase.empty())
        return false;
    if (!read_from_file(sFilePath, sOldPassphrase))
    {
        throw runtime_error(fmt::format("Failed to read secure container file [{}]", sFilePath));
    }
    v_uint8 v;
    serialize(std::move(sNewPassphrase), v);
    return write_to_file(sFilePath, v);
}

/**
 * Validate passphrase via SECURE_ITEM_TYPE::pkey_ed448.
 * Decrypt secure data. Does not throws exceptions
 *
 * \param sFilePath - container file path
 * \param sPassphrase - passphrase in clear text to use for data decryption
 * \return true if password was succesfully validated
 *         false if file does not contain Pastel secure container
 *         if container data cannot be read or decrypted - throws std::runtime_error
 */
bool CSecureContainer::is_valid_passphrase(const string& sFilePath, const SecureString& sPassphrase)
{
    using json = nlohmann::json;
    bool bRet = false;
    string error;
    try
    {
        do
        {
            clear();

            ifstream fs(sFilePath, ios::in | ios::ate | ios::binary);
            fs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
            v_uint8 v;
            uint64_t nDataSize = 0;
            if (!read_public_items_ex(fs, nDataSize))
            {
                error = "Failed to read public items";
                break;
            }
            // read secure container data as json msgpack
            v.resize(nDataSize);
            fs.read(reinterpret_cast<char*>(v.data()), v.size());
            json j = json::from_msgpack(v);
            v.clear();

            // read header
            j.at("version").get_to(m_nVersion);
            j.at("timestamp").get_to(m_nTimestamp);
            j.at("encryption").get_to(m_sEncryptionAlgorithm);
            if (m_sEncryptionAlgorithm != SECURE_CONTAINER_ENCRYPTION)
            {
                error = fmt::format("Encryption algorithm '{}' is not supported", m_sEncryptionAlgorithm.c_str());
                break;
            }

            CSodiumAutoBuf pw;
            // allocate secure memory for the key, buffer is reused for all secure items
            if (!pw.allocate(PWKEY_BUFSUZE))
            {
                error = fmt::format("Failed to allocate memory ({} bytes)", PWKEY_BUFSUZE);
                break;
            }

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
                {
                    error = fmt::format("Secure item type '{}' is not supported", sType);
                    break;
                }
                jItem["nonce"].get_to(item.nonce);
                // encrypted data
                auto& encrypted_data = jItem["data"].get_binary();

                // derive key from the passphrase
                if (crypto_pwhash(pw.p, crypto_box_SEEDBYTES,
                                  sPassphrase.c_str(), sPassphrase.length(), item.nonce.data(),
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
                {
                    error = fmt::format("Failed to generate encryption key for the secure item '{}'", GetSecureItemTypeName(item.type));
                    break;
                }
                item.data.resize(encrypted_data.size());
                unsigned long long nDecryptedLength = 0;
                if (crypto_aead_xchacha20poly1305_ietf_decrypt(item.data.data(), &nDecryptedLength, nullptr,
                        encrypted_data.data(), encrypted_data.size(), nullptr, 0, item.nonce.data(), pw.p) != 0)
                {
                    error = fmt::format("Failed to decrypt secure item '{}' data", sType);
                    break;
                }
                // Only need to read first secure item which has pkey_ed448 type
                if (item.type == SECURE_ITEM_TYPE::pkey_ed448)
                    break;
            }
            if (!error.empty())
                break;
            bRet = true;
        } while (false);
    }
    catch (const std::out_of_range &ex)
    {
        error = fmt::format("File format error. {}", ex.what());
    }
    catch (const std::exception &ex)
    {
        error = fmt::format("{}", sFilePath.c_str(), ex.what());
    }
    if (!error.empty())
        throw runtime_error(fmt::format("Passphrase is invalid. Failed to read the Pastel secure container file [{0}]. {1}\n", sFilePath, error));
    return bRet;
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
bool CSecureContainer::read_public_items_ex(ifstream& fs, uint64_t& nDataSize)
{
    using json = nlohmann::json;
    bool bRet = false;
    do
    {
        // get file size
        const auto nFileSize = fs.tellg();
        if (nFileSize < 0)
            break;
        nDataSize = static_cast<uint64_t>(nFileSize);
        // read prefix from the file and compare with SECURE_CONTAINER_PREFIX
        constexpr auto nPrefixLength = std::char_traits<char>::length(SECURE_CONTAINER_PREFIX);
        if (nDataSize < nPrefixLength)
            break;
        char szPrefix[nPrefixLength + 1];
        fs.seekg(0);
        fs.read(szPrefix, nPrefixLength);
        if (fs.gcount() != nPrefixLength)
            break;
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
        fs.read(reinterpret_cast<char*>(&nMsgPackSize), sizeof(uint64_t))
          .read(reinterpret_cast<char*>(vHash.data()), vHash.size());
        nDataSize -= sizeof(uint64_t) + uint256::SIZE;
        // convert size to host order
        nMsgPackSize = be64toh(nMsgPackSize);
        if (nMsgPackSize > nDataSize)
            throw runtime_error(fmt::format("Invalid size [{}] for the public data in the secure container", nMsgPackSize));
        // read public data from the secure container as msgpack
        v_uint8 v;
        v.resize(nMsgPackSize);
        fs.read(reinterpret_cast<char*>(v.data()), v.size());
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
#endif
