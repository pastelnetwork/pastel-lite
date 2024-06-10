#include <iostream>
#include <json/json.hpp>

#include "libpastel.h"
#include "support/decoder.hpp"

#include <iostream>
#include <string>

void testCreateWallet(Pastel &lib, const std::string &password) {
    auto mnemonic= decodeStringResponse(lib.CreateNewWallet(password));
    std::cout << "==== Create wallet ====" << std::endl;
    std::cout << "Mnemonic: " << mnemonic << std::endl;
}
void testNewAddresses(Pastel &lib, uint32_t count, uint32_t startIndex = 0, NetworkMode mode = NetworkMode::MAINNET) {
    std::vector<std::string> newAddresses;
    std::vector<std::string> retrievedAddresses;

    std::cout << "==== Addresses ====" << std::endl;
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        auto address = decodeStringResponse(lib.MakeNewAddress(mode));
        newAddresses.push_back(address);
        std::cout << "Create new Address " << i << ": " << address << std::endl;
    }
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        auto address = decodeStringResponse(lib.GetAddress(i, mode));
        retrievedAddresses.push_back(address);
        std::cout << "Get existing Address " << i << ": " << address << std::endl;
    }
    auto addressCount = decodeUint32Response(lib.GetAddressesCount());
    std::cout << "Addresses count: " << addressCount << std::endl;

    // Compare tests
    for (uint32_t i = 0; i < count; ++i) {
        assert(newAddresses[i] == retrievedAddresses[i]);
    }
    assert(addressCount == count + startIndex);
}
void testNewPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
    std::vector<std::string> newPastelIDs;
    std::vector<std::string> retrievedPastelIDs;

    std::cout << "==== PastelIDs ====" << std::endl;
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        auto pastelID = decodeStringResponse(lib.MakeNewPastelID());
        newPastelIDs.push_back(pastelID);
        std::cout << "Create new PastelID " << i << ": " << pastelID << std::endl;
    }
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        auto pastelID = decodeStringResponse(lib.GetPastelIDByIndex(i));
        retrievedPastelIDs.push_back(pastelID);
        std::cout << "Get existing PastelID " << i << ": " << pastelID << std::endl;
    }
    auto pastelIDCount = decodeUint32Response(lib.GetPastelIDsCount());
    std::cout << "PastelIDs count: " << pastelIDCount << std::endl;

    // Compare tests
    for (uint32_t i = 0; i < count; ++i) {
        assert(newPastelIDs[i] == retrievedPastelIDs[i]);
    }
    assert(pastelIDCount == count + startIndex);
}
void testSignVerify(Pastel &lib) {
    auto pastelID = nlohmann::json::parse(lib.GetPastelIDByIndex(1)).at("data").get<std::string>();

    std::cout << "==== Sign/Verify ====" << std::endl;
    auto signature1 = decodeStringResponse(lib.SignWithPastelID(pastelID, "message", PastelIDType::PASTELID, true));
    std::cout << "PastelID signature: " << signature1 << std::endl;
    auto signature1result =  decodeBoolResponse(lib.VerifyWithPastelID(pastelID, "message", signature1, true));
    std::cout << "Verify with PastelID: " << (signature1result ? "OK": "Failed") << std::endl;
    assert(signature1result);

    auto signature2 = decodeStringResponse(lib.SignWithPastelID(pastelID, "message", PastelIDType::LEGROAST, true));
    std::cout << "LegRoast signature: " << signature2 << std::endl;
    auto legRoast = decodeStringResponse(lib.GetPastelID(pastelID, PastelIDType::LEGROAST));
    auto signature2result =  decodeBoolResponse(lib.VerifyWithLegRoast(legRoast, "message", signature2, true));
    std::cout << "Verify with LegRoast: " << (signature2result ? "OK": "Failed") << std::endl;
    assert(signature2result);
}
void testExternalPastelIDs(Pastel &lib) {
    std::cout << "==== Use External PastelID ====" << std::endl;
    auto sigVer = lib.VerifyWithPastelID("jXXQ5MdtkCMjftmgmHC2nXGwqiqh2m14kbnVdwcjaeKD7nmE3tFiNnHrwEkV2ZPKejUmvkQzfMFwizkjKVy9nG", "message",
                                         "3LdXRMIHJ3t9n3Fkv6Wlnq3+fK0HcNJXJnWYgWsGjoHGT1nGGfEnhiUnrOkLOko2WkZVuFEBIt8ASApzI92ThOdJEgGivBnEpXZGTJZj8thKwcqxvaH5A3Pjow+z96YNl/WeUTYxAYqVEzgeDBT+EQsA",
                                         true);
    std::cout << "Verify with External PastelID: " << (decodeBoolResponse(sigVer) ? "OK": "Failed") << std::endl;
}
void testExportPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
    std::cout << "==== Export PastelID to file ====" << std::endl;
    for (uint32_t i = 0; i < count; ++i) {
        auto pastelID = decodeStringResponse(lib.GetPastelIDByIndex(i));
        std::cout << "Export PastelID " << i << ": "
            << (checkSuccessResponse(lib.ExportPastelIDKeys(pastelID, "password", "."))? "OK": "Failed") << std::endl;
        std::filesystem::path p = std::filesystem::current_path() / pastelID;
        std::cout << p << std::endl;
        assert(std::filesystem::exists(pastelID));
    }
}
Pastel testExportImportWallet(Pastel &lib) {
    std::cout << "==== Export wallet ====" << std::endl;
    auto wallet = decodeStringResponse(lib.ExportWallet());
    std::cout << wallet << std::endl;

    std::cout << "==== Import wallet (wallet locked) ====" << std::endl;
    Pastel lib2;
    std::cout << (checkSuccessResponse(lib2.ImportWallet(wallet))? "OK": "Failed") << std::endl;

    // Compare tests
    std::cout << "Check addresses are matching" << std::endl;
    assert(lib.GetAddresses() == lib2.GetAddresses());
    std::cout << "Check PastelIDs are matching" << std::endl;
    assert(lib.GetPastelIDs() == lib2.GetPastelIDs());

    std::cout << "Check LegRoast are matching" << std::endl;
    auto count = decodeUint32Response(lib.GetPastelIDsCount());
    for (uint32_t i = 0; i < count; ++i) {
        assert(lib.GetPastelIDByIndex(i, PastelIDType::LEGROAST) ==
               lib2.GetPastelIDByIndex(i, PastelIDType::LEGROAST));
        assert(lib.GetPastelID(lib.GetPastelIDByIndex(i), PastelIDType::LEGROAST) ==
               lib2.GetPastelID(lib.GetPastelIDByIndex(i), PastelIDType::LEGROAST));
    }

    return lib2;
}
void testCreateInLockedWallet(Pastel &lib, uint32_t count, NetworkMode mode = NetworkMode::MAINNET) {
    std::cout << "==== Create in Locked Wallet ====" << std::endl;
    for (uint32_t i = 0; i < count; ++i) {
        auto newAddressResponse = lib.MakeNewAddress(mode);
        bool failedCheck = checkErrorResponse(newAddressResponse);
        assert(failedCheck);
        std::cout << "Failed to create new address " << i << " in locked wallet - that's correct" << std::endl;
    }

    for (uint32_t i = 0; i < count; ++i) {
        auto newPastelIDResponse = lib.MakeNewPastelID();
        bool failedCheck = checkErrorResponse(newPastelIDResponse);
        assert(failedCheck);
        std::cout << "Failed to create new PastelID " << i << " in locked wallet - that's correct" << std::endl;
    }
    std::cout << std::endl;
}
void testUnlockWallet(Pastel &lib, const std::string &password) {
    std::cout << "==== Unlock Wallet ====" << std::endl;
    auto unlockResponse = lib.UnlockWallet(password);
    auto okCheck = checkSuccessResponse(unlockResponse);
    assert(okCheck);
    std::cout << "Unlock wallet: OK" << std::endl;
}
void testUnlockWalletWrongPassword(Pastel &lib) {
    std::cout << "==== Unlock Wallet with Wrong Password ====" << std::endl;
    auto unlockResponse = lib.UnlockWallet("wrong");
    auto errorCheck = checkErrorResponse(unlockResponse);
    assert(errorCheck);
    std::cout << "Unlock wallet: Error (OK)" << std::endl;
}
void testLockWallet(Pastel &lib) {
    std::cout << "==== Lock Wallet ====" << std::endl;
    auto lockResponse = lib.LockWallet();
    auto okCheck = checkSuccessResponse(lockResponse);
    assert(okCheck);
    std::cout << "Lock wallet: OK" << std::endl;
}
void testGetExistingAddresses(Pastel &lib, uint32_t count, uint32_t startIndex = 0, NetworkMode mode = NetworkMode::MAINNET) {
    std::vector<std::string> retrievedAddresses;
    std::cout << "==== Get existing Addresses ====" << std::endl;
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        auto address = decodeStringResponse(lib.GetAddress(i, mode));
        retrievedAddresses.push_back(address);
        std::cout << "Get existing Address " << i << ": " << address << std::endl;
    }
}
void testGetNonExistingAddresses(Pastel &lib, uint32_t count, uint32_t startIndex = 0, NetworkMode mode = NetworkMode::MAINNET) {
    std::cout << "==== Get non-exising Addresses ====" << std::endl;
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        bool failedCheck = checkErrorResponse(lib.GetAddress(i, mode));
        assert(failedCheck);
        std::cout << "Get non-existing Address " << i << ": ""Failed (OK)" << std::endl;
    }
}
void testGetExistingPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
    std::cout << "==== PastelIDs ====" << std::endl;
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        auto pastelID = decodeStringResponse(lib.GetPastelIDByIndex(i));
        std::cout << "Get existing PastelID " << i << ": " << pastelID << std::endl;
        auto ok = checkSuccessResponse(lib.GetPastelIDByIndex(i, PastelIDType::LEGROAST));
        assert(ok);
        std::cout << "Get existing LegRoast " << i << " OK" << std::endl;
    }
}
void testGetNonExistingPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
    std::cout << "==== Get non-exising PastelIDs ====" << std::endl;
    for (uint32_t i = startIndex; i < startIndex+count; ++i) {
        bool failedCheck = checkErrorResponse(lib.GetPastelIDByIndex(i));
        assert(failedCheck);
        std::cout << "Get non-existing PastelID " << i << ": ""Failed (OK)" << std::endl;
    }
}
void testAccountManagement(Pastel &lib) {
    std::cout << "==== Account Management ====" << std::endl;

    auto wPubKey = decodeStringResponse(lib.GetWalletPubKey());
    std::cout << "WalletPubKey: " << wPubKey << std::endl;

    auto signWalletKeyResponse = decodeStringResponse(lib.SignWithWalletKey("message"));
    std::cout << "Sign with Wallet Key: " << signWalletKeyResponse << std::endl;

    auto pubKeyAt3 = decodeStringResponse(lib.GetPubKeyAt(3));
    std::cout << "PubKey at index 3: " << pubKeyAt3 << std::endl;
    auto signKeyAt3 = decodeStringResponse(lib.SignWithKeyAt(3, "message"));
    std::cout << "Sign with Key at index 3: " << signKeyAt3 << std::endl;

    auto pubKeyAt0x80000003 = decodeStringResponse(lib.GetPubKeyAt(0x80000003));
    std::cout << "PubKey at index 0x80000003: " << pubKeyAt0x80000003 << std::endl;
    auto signKeyAt0x80000003 = decodeStringResponse(lib.SignWithKeyAt(0x80000003, "message"));
    std::cout << "Sign with Key at index 0x80000003: " << signKeyAt0x80000003 << std::endl;

    auto pubKeyAt0x9A551AB3 = decodeStringResponse(lib.GetPubKeyAt(0x9A551AB3));
    std::cout << "PubKey at index 0x9A551AB3: " << pubKeyAt0x9A551AB3 << std::endl;
    auto signKeyAt0x9A551AB3 = decodeStringResponse(lib.SignWithKeyAt(0x9A551AB3, "message"));
    std::cout << "Sign with Key at index 0x9A551AB3: " << signKeyAt0x9A551AB3 << std::endl;
}

void testOne() {
    auto password = "password";
    auto mode = NetworkMode::MAINNET;
    Pastel lib;
    testCreateWallet(lib, password);
    testNewAddresses(lib, 2, 0, mode);
    testNewPastelIDs(lib, 2);
    testSignVerify(lib);
    testExternalPastelIDs(lib);
    testExportPastelIDs(lib, 1);
    auto lib2 = testExportImportWallet(lib);
    testCreateInLockedWallet(lib2, 2, mode);
    testUnlockWallet(lib2, password);
    testNewAddresses(lib2, 2, 2, mode);
    testNewPastelIDs(lib2, 2, 2);
    testLockWallet(lib2);
    testUnlockWalletWrongPassword(lib2);
    testGetExistingAddresses(lib2, 2, 2, mode);
    testGetNonExistingAddresses(lib2, 2, 4, mode);
    testGetExistingPastelIDs(lib2, 2, 2);
    testGetNonExistingPastelIDs(lib2, 2, 4);
    testUnlockWallet(lib2, password);
    testAccountManagement(lib2);
}

int main() {
//    testOne();

    {
        Pastel lib;
//        auto mnemonic= decodeStringResponse(lib.CreateNewWallet("password"));
//        auto wallet = decodeStringResponse(lib.ExportWallet());
//        std::cout << wallet << std::endl;
//        std::cout << decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET)) << std::endl;

        auto walletStr = "7KBHjKqLzc7QnRM44n8UrhUyxQ6W2ApLYpbwoRvUnzgQjd2XcyxwrWgDivanUv6QernA3prjECBVFUtTQRTqGDbnjxD5UvrZMKG616JLtdBgZjd4cKGx1hopaaRBzsUXmhr7WnsNSi6D6SteF26zDqvkuPooSkDUUrcBNiaJuEs3wuqGneySGxq5aX56AEb9ye544Wd5QJ8cDEz4eEzxx9r2zWHTAogw2r7JKtVf13T3Lm82jHYwfNjRfUsqGsyWu6onatf1eCpwd8ZK9z4d41ByvPtgyFUqFUtpXbivKz6gHrabyF3jBf4fd2bbW7cA4kanxDW2pbmUovMqm6QpfJwcshzdpk9nQ4XagmGgX";
        std::cout << (checkSuccessResponse(lib.ImportWallet(walletStr))? "OK": "Failed") << std::endl;
        auto unlockResponse = lib.UnlockWallet("password");
        auto okCheck = checkSuccessResponse(unlockResponse);
        assert(okCheck);
        auto address = decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET));
        assert(address == "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo");
        // 4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc
//        "vout": [
//        {
//            "value": 1000.00000,
//                    "valuePat": 100000000,
//                    "n": 0,
//                    "scriptPubKey": {
//                "asm": "OP_DUP OP_HASH160 25ca0dc39e74770fa739e9ced36912f0251842b4 OP_EQUALVERIFY OP_CHECKSIG",
//                        "hex": "76a91425ca0dc39e74770fa739e9ced36912f0251842b488ac",
//                        "reqSigs": 1,
//                        "type": "pubkeyhash",
//                        "addresses": [
//                "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo"
//                ]
//            }
//        },

        std::cout << "Private key" << lib.GetSecret(0, NetworkMode::DEVNET) << std::endl;

        auto send_to = sendto_addresses{
                {"44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg", 100},
//                {"PtWW6LP6dLLgi5WqTYi6C7NwiesVgeRRV18", 500}
        };
        auto utxos = v_utxos{
                {"44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo", "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc", 0, 1000},
//                {"PtnsSy2e2AQM1ZBM8fxpSXPrUQGFfkiYzyJ", "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac", 0, 410},
        };
        cout << lib.CreateSendToTransaction(NetworkMode::DEVNET, send_to, "", utxos, 76270);
    }

    return 0;
}

