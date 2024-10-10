#include <iostream>
#include <json/json.hpp>
#include <chrono>
#include <string>

#include "libpastel.h"
#include "support/decoder.hpp"

#define PASTEL_ID_PATH "/home/alexey/work/Pastel/pastel-lite/python_bindings"

namespace testWallet {
    string testCreateWallet(Pastel &lib, const std::string &password) {
        auto mnemonic = decodeStringResponse(lib.CreateNewWallet(password));
        std::cout << "==== Create wallet ====" << std::endl;
        std::cout << "Mnemonic: " << mnemonic << std::endl;
        return mnemonic;
    }

    string testRestoreWallet(Pastel &lib, const std::string &password, const std::string &mnemonic) {
        auto mnemonicToo = decodeStringResponse(lib.CreateWalletFromMnemonic(password, mnemonic));
        assert(mnemonic == mnemonicToo);
        std::cout << "==== Create wallet From Mnemonic ====" << std::endl;
        std::cout << "Mnemonic In: " << mnemonic << std::endl;
        std::cout << "Mnemonic Out: " << mnemonicToo << std::endl;
        return mnemonicToo;
    }

    std::vector<std::string>
    testNewAddresses(Pastel &lib, uint32_t count, uint32_t startIndex = 0, NetworkMode mode = NetworkMode::MAINNET) {
        std::vector<std::string> newAddresses;
        std::vector<std::string> retrievedAddresses;

        std::cout << "==== Addresses ====" << std::endl;
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
            auto address = decodeStringResponse(lib.MakeNewAddress(mode));
            newAddresses.push_back(address);
            std::cout << "Create new Address " << i << ": " << address << std::endl;
        }
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
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
        return newAddresses;
    }

    std::vector<std::string> testNewPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
        std::vector<std::string> newPastelIDs;
        std::vector<std::string> retrievedPastelIDs;

        std::cout << "==== PastelIDs ====" << std::endl;
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
            auto pastelID = decodeStringResponse(lib.MakeNewPastelID());
            newPastelIDs.push_back(pastelID);
            std::cout << "Create new PastelID " << i << ": " << pastelID << std::endl;
        }
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
            auto pastelID = decodeStringResponse(lib.GetPastelIDByIndex(i));
//            auto pastelIDLR = decodeStringResponse(lib.GetPastelIDByIndex(i, PastelIDType::LEGROAST));
            retrievedPastelIDs.push_back(pastelID);
//            std::cout << "Get existing PastelID " << i << ": " << pastelID << "; " << pastelIDLR << std::endl;
        }
        auto pastelIDCount = decodeUint32Response(lib.GetPastelIDsCount());
        std::cout << "PastelIDs count: " << pastelIDCount << std::endl;

        // Compare tests
        for (uint32_t i = 0; i < count; ++i) {
            assert(newPastelIDs[i] == retrievedPastelIDs[i]);
        }
        assert(pastelIDCount == count + startIndex);
        return newPastelIDs;
    }

    void testSignVerify(Pastel &lib) {
        auto pastelID = nlohmann::json::parse(lib.GetPastelIDByIndex(1)).at("data").get<std::string>();

        std::cout << "==== Sign/Verify ====" << std::endl;
        auto signature1 = decodeStringResponse(lib.SignWithPastelID(pastelID, "message", PastelIDType::PASTELID, true));
        std::cout << "PastelID signature: " << signature1 << std::endl;
        auto signature1result = decodeBoolResponse(lib.VerifyWithPastelID(pastelID, "message", signature1, true));
        std::cout << "Verify with PastelID: " << (signature1result ? "OK" : "Failed") << std::endl;
        assert(signature1result);

        auto signature2 = decodeStringResponse(lib.SignWithPastelID(pastelID, "message", PastelIDType::LEGROAST, true));
        std::cout << "LegRoast signature: " << signature2 << std::endl;
        auto legRoast = decodeStringResponse(lib.GetPastelID(pastelID, PastelIDType::LEGROAST));
        auto signature2result = decodeBoolResponse(lib.VerifyWithLegRoast(legRoast, "message", signature2, true));
        std::cout << "Verify with LegRoast: " << (signature2result ? "OK" : "Failed") << std::endl;
        assert(signature2result);
    }

    void testExternalPastelIDs(Pastel &lib) {
        std::cout << "==== Use External PastelID ====" << std::endl;
        auto sigVer = lib.VerifyWithPastelID(
                "jXXQ5MdtkCMjftmgmHC2nXGwqiqh2m14kbnVdwcjaeKD7nmE3tFiNnHrwEkV2ZPKejUmvkQzfMFwizkjKVy9nG", "message",
                "3LdXRMIHJ3t9n3Fkv6Wlnq3+fK0HcNJXJnWYgWsGjoHGT1nGGfEnhiUnrOkLOko2WkZVuFEBIt8ASApzI92ThOdJEgGivBnEpXZGTJZj8thKwcqxvaH5A3Pjow+z96YNl/WeUTYxAYqVEzgeDBT+EQsA",
                true);
        std::cout << "Verify with External PastelID: " << (decodeBoolResponse(sigVer) ? "OK" : "Failed") << std::endl;
    }

    void testExportPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
        std::cout << "==== Export PastelID to file ====" << std::endl;
        for (uint32_t i = 0; i < count; ++i) {
            auto pastelID = decodeStringResponse(lib.GetPastelIDByIndex(i));
            std::cout << "Export PastelID " << i << ": "
                      << (checkSuccessResponse(lib.ExportPastelIDKeys(pastelID, "password", ".")) ? "OK" : "Failed")
                      << std::endl;
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
        std::cout << (checkSuccessResponse(lib2.ImportWallet(wallet)) ? "OK" : "Failed") << std::endl;

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

    void testGetExistingAddresses(Pastel &lib, uint32_t count, uint32_t startIndex = 0,
                                  NetworkMode mode = NetworkMode::MAINNET) {
        std::vector<std::string> retrievedAddresses;
        std::cout << "==== Get existing Addresses ====" << std::endl;
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
            auto address = decodeStringResponse(lib.GetAddress(i, mode));
            retrievedAddresses.push_back(address);
            std::cout << "Get existing Address " << i << ": " << address << std::endl;
        }
    }

    void testGetNonExistingAddresses(Pastel &lib, uint32_t count, uint32_t startIndex = 0,
                                     NetworkMode mode = NetworkMode::MAINNET) {
        std::cout << "==== Get non-exising Addresses ====" << std::endl;
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
            bool failedCheck = checkErrorResponse(lib.GetAddress(i, mode));
            assert(failedCheck);
            std::cout << "Get non-existing Address " << i << ": ""Failed (OK)" << std::endl;
        }
    }

    void testGetExistingPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
        std::cout << "==== PastelIDs ====" << std::endl;
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
            auto pastelID = decodeStringResponse(lib.GetPastelIDByIndex(i));
            std::cout << "Get existing PastelID " << i << ": " << pastelID << std::endl;
            auto ok = checkSuccessResponse(lib.GetPastelIDByIndex(i, PastelIDType::LEGROAST));
            assert(ok);
            std::cout << "Get existing LegRoast " << i << " OK" << std::endl;
        }
    }

    void testGetNonExistingPastelIDs(Pastel &lib, uint32_t count, uint32_t startIndex = 0) {
        std::cout << "==== Get non-exising PastelIDs ====" << std::endl;
        for (uint32_t i = startIndex; i < startIndex + count; ++i) {
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

    void run() {
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

    void run2() {
        auto password = "password";
        auto mode = NetworkMode::MAINNET;
        Pastel lib1;
        auto mnemonic = testCreateWallet(lib1, password);
        auto addresses1 = testNewAddresses(lib1, 2, 0, mode);
        auto pastelIDs1 = testNewPastelIDs(lib1, 2);
        Pastel lib2;
        testRestoreWallet(lib2, password, mnemonic);
        auto addresses2 = testNewAddresses(lib2, 2, 0, mode);
        auto pastelIDs2 = testNewPastelIDs(lib2, 2);
        assert(addresses1 == addresses2);
        assert(pastelIDs1 == pastelIDs2);
    }
}

namespace testSendTo {
    void run() {
        Pastel lib;
//        auto mnemonic= decodeStringResponse(lib.CreateNewWallet("password"));
//        auto wallet = decodeStringResponse(lib.ExportWallet());
//        std::cout << wallet << std::endl;
//        std::cout << decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET)) << std::endl;

        auto walletStr = "7KBHjKqLzc7QnRM44n8UrhUyxQ6W2ApLYpbwoRvUnzgQjd2XcyxwrWgDivanUv6QernA3prjECBVFUtTQRTqGDbnjxD5UvrZMKG616JLtdBgZjd4cKGx1hopaaRBzsUXmhr7WnsNSi6D6SteF26zDqvkuPooSkDUUrcBNiaJuEs3wuqGneySGxq5aX56AEb9ye544Wd5QJ8cDEz4eEzxx9r2zWHTAogw2r7JKtVf13T3Lm82jHYwfNjRfUsqGsyWu6onatf1eCpwd8ZK9z4d41ByvPtgyFUqFUtpXbivKz6gHrabyF3jBf4fd2bbW7cA4kanxDW2pbmUovMqm6QpfJwcshzdpk9nQ4XagmGgX";
        std::cout << (checkSuccessResponse(lib.ImportWallet(walletStr)) ? "OK" : "Failed") << std::endl;
        auto unlockResponse = lib.UnlockWallet("password");
        auto okCheck = checkSuccessResponse(unlockResponse);
        assert(okCheck);
        auto address = decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET));
        assert(address == "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo");
        auto pastelID = decodeStringResponse(lib.MakeNewPastelID());

        std::cout << "Private key" << lib.GetSecret(0, NetworkMode::DEVNET) << std::endl;

        auto send_to = sendto_addresses{
                {"44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg", 100},
//                {"PtWW6LP6dLLgi5WqTYi6C7NwiesVgeRRV18", 500}
        };
        auto utxos = v_utxos{
                {"44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
                 "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc", 0, 2000 * 100000},
//                {"PtnsSy2e2AQM1ZBM8fxpSXPrUQGFfkiYzyJ", "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac", 0, 410*100000},
        };
//        cout << lib.CreateSendToTransaction(NetworkMode::DEVNET, send_to, "", utxos, 76270);
        cout << lib.CreateRegisterPastelIdTransaction(NetworkMode::DEVNET, pastelID,
                                                      "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo", utxos, 76270);
    }
}

namespace testSendToJSON {
    void run() {
        Pastel lib;
//        auto mnemonic= decodeStringResponse(lib.CreateNewWallet("password"));
//        auto wallet = decodeStringResponse(lib.ExportWallet());
//        std::cout << wallet << std::endl;
//        std::cout << decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET)) << std::endl;

        auto walletStr = "7KBHjKqLzc7QnRM44n8UrhUyxQ6W2ApLYpbwoRvUnzgQjd2XcyxwrWgDivanUv6QernA3prjECBVFUtTQRTqGDbnjxD5UvrZMKG616JLtdBgZjd4cKGx1hopaaRBzsUXmhr7WnsNSi6D6SteF26zDqvkuPooSkDUUrcBNiaJuEs3wuqGneySGxq5aX56AEb9ye544Wd5QJ8cDEz4eEzxx9r2zWHTAogw2r7JKtVf13T3Lm82jHYwfNjRfUsqGsyWu6onatf1eCpwd8ZK9z4d41ByvPtgyFUqFUtpXbivKz6gHrabyF3jBf4fd2bbW7cA4kanxDW2pbmUovMqm6QpfJwcshzdpk9nQ4XagmGgX";
        std::cout << (checkSuccessResponse(lib.ImportWallet(walletStr)) ? "OK" : "Failed") << std::endl;
        auto unlockResponse = lib.UnlockWallet("password");
        auto okCheck = checkSuccessResponse(unlockResponse);
        assert(okCheck);
        auto address = decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET));
        assert(address == "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo");
        auto pastelID = decodeStringResponse(lib.MakeNewPastelID());
        std::cout << "PastelID: " << pastelID << std::endl;

        std::cout << "Private key" << lib.GetSecret(0, NetworkMode::DEVNET) << std::endl;

        auto send_to_json = R"(
        [
             {
                "address": "44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg",
                "amount": 100
             }
        ])";
        auto utxo_json = R"(
        [
  {
    "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
    "txid": "3e8b383ac68d9ecb51606f4b7589b8f2c0c22ed7701f73ad00452228ceb4304a",
    "outputIndex": 0,
    "script": "76a91425ca0dc39e74770fa739e9ced36912f0251842b488ac",
    "patoshis": 89999661,
    "height": 76263
  },
  {
    "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
    "txid": "8323a1928d697908e6fbb790db1c497abb69b395c83c2acf0c0bd5f49ebeac29",
    "outputIndex": 1,
    "script": "76a91425ca0dc39e74770fa739e9ced36912f0251842b488ac",
    "patoshis": 100000000,
    "height": 83647
  },
  {
    "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
    "txid": "16d18d8ed3d74699d2582d16b310333b8b13a5525b04b70f6ba0d302bc1ceffa",
    "outputIndex": 0,
    "script": "76a91425ca0dc39e74770fa739e9ced36912f0251842b488ac",
    "patoshis": 100000000,
    "height": 83647
  }
        ])";

        cout << lib.CreateSendToTransactionJson(NetworkMode::DEVNET, send_to_json, "", utxo_json, 76270);
//        cout << decodeStringResponse(lib.CreateRegisterPastelIdTransactionJson(NetworkMode::DEVNET, pastelID,
//                                                                               "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
//                                                                               utxo_json, 84001));
    }
}

namespace testSigner1 {
    void run() {
        PastelSigner lib(PASTEL_ID_PATH);
        auto start1 = std::chrono::high_resolution_clock::now();
        auto signature1 = lib.SignWithPastelID(
                "test message",
                "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw",
                "passphrase");
        auto end1 = std::chrono::high_resolution_clock::now();
        auto duration1 = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1);
        cout << "Sign with PastelSigner: " << signature1 << " (" << duration1.count() << ")" << endl;
        auto ok1 = lib.VerifyWithPastelID(
                "test message",
                signature1,
                "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw");
        cout << "Singed and verified: " << (ok1 ? "true" : "false") << endl;

        auto signature2 = "0P6EeisbiWzmNab5HC0xeLAjLr/tW5zBLvFXE81yNciLtmUg8fXuvaZFrbsFT54fagznt4TNxK0ACYgQJ/3pVqmj0T5Al/BvetwqFg2VSjWP/ss6wCzYz83Uj94eoei7lrK7Iq55QMKghBmLRhtIjhIA";
        auto ok2 = lib.VerifyWithPastelID(
                "test",
                signature2,
                "jXaczRW4MgeiioV1DAte38aj6FK2dwL7ykEajmm6K7J1XQc5qcJfkJYD24pSt1MUAbPjfhDv1iSYrSsxAqp1Mb");
        cout << signature2 << endl;
        cout << "Verified signed message: " << (ok2 ? "true" : "false") << endl;
    }
}

namespace testSigner2 {
    void run() {
        PastelSigner lib(PASTEL_ID_PATH);
        auto pastelID = lib.GetPastelID(
                "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw", "passphrase");
        auto start2 = std::chrono::high_resolution_clock::now();
        auto signature3 = pastelID.Sign("test message");
        auto end2 = std::chrono::high_resolution_clock::now();
        auto duration2 = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2);
        cout << "Sign with PastelSigner::GetPastelID: " << signature3 << " (" << duration2.count() << ")" << endl;
        auto ok3 = pastelID.Verify("test message", signature3);
        cout << "Singed and verified: " << (ok3 ? "true" : "false") << endl;
        auto ok4 = lib.VerifyWithPastelID(
                "test message",
                signature3,
                "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw");
        cout << "Verified with PastelSigner: " << (ok4 ? "true" : "false") << endl;
    }
}

namespace testExternalWallet {
    void run() {
        std::cout << "==== External Wallet ====" << std::endl;
        Pastel lib;
        auto walletStr = "54E4KZKgzqgBeWpdKPX5kz7ECfcXwS7xQkXgHbRvkCd5ehSwZwMgR4dXt5Zbxj2DegbB5MKpVHH19SgH4UH9PA4iUpCqmr75aH54oKkjpDi8JfvE1drd3PhM9hK1Dd29deebKjkuEP72KM7Rc4udJcuiAUQiqhmdh7Y8Pzrx7qsh2Hbkcnb8VpLZgUNGG6sMWzewZQ4HNHcG3XorG2RAGKMhWiHkdUv1KJtSoUGMGHSv4GdoJgG4s64ojcKsg4iVRZJfzFqsRwxiPDHGutXbxKaDSzNhsyx68ZujQUqVYhDSx3AyERRmoiJ95HYXE1WEUrf2NNCnHkJGRnPSvjAzJVgxd3FAQWtX1ZPGKLFA2WvDXgNTAx7RQf6nKEfDpjWwb32A6bhk3MCgEaVgRtUBZFvFzsuGtz3twMA6V8g98ZNLN37F8wvVDVi7";
        std::cout << (checkSuccessResponse(lib.ImportWallet(walletStr)) ? "OK" : "Failed") << std::endl;
        auto unlockResponse = lib.UnlockWallet("12341234");
        auto okCheck = checkSuccessResponse(unlockResponse);
        assert(okCheck);
    }
}

namespace testExternalPastelID
{
    void testSignVerify(Pastel &lib, const std::string &pastel_id, const std::string &pub_legroast, const string &message)
    {
        std::cout << "=== Check Sign ===" << std::endl;
        auto ed_sig = decodeStringResponse(lib.SignWithPastelID(pastel_id, message, PastelIDType::PASTELID, true));
        auto lr_sig = decodeStringResponse(lib.SignWithPastelID(pastel_id, message, PastelIDType::LEGROAST, true));
        std::cout << "ED448 Signature: " << ed_sig << std::endl;
        std::cout << "LegRoast Signature: " << lr_sig << std::endl;

        std::cout << "=== Check Verify ===" << std::endl;
        std::cout << "ED448 Verification: " << (checkSuccessResponse(lib.VerifyWithPastelID(pastel_id, message, ed_sig, true)) ? "OK" : "Failed") << std::endl;
        std::cout << "LegRoast Verification: " << (checkSuccessResponse(lib.VerifyWithLegRoast(pub_legroast, message, lr_sig, true)) ? "OK" : "Failed") << std::endl;
    }

    void testVerifyExternal(Pastel &lib, const std::string &pastel_id, const std::string &pub_legroast, const string &message)
    {
        std::cout << "=== Check Verify External signatures ===" << std::endl;
        auto ed_signature = "gH+KRIkxlDkpb9KMvRQztuK1OAWrE+wnCpFPN3NNahvMqAV7hQcnjJD6KaVY5C2jOE1lPl/fdT2AVzETsih0f4QS61+MZPnOki6G+gMPb1hT2HFg/XCoNwmIu9IUQDY6TWh7KorLR4ChtRH735gVRBsA";
        auto lr_signature = "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";
        std::cout << "ED448 Verification external: " << (checkSuccessResponse(lib.VerifyWithPastelID(pastel_id, message, ed_signature, true)) ? "OK" : "Failed") << std::endl;
        std::cout << "LegRoast Verification external: " << (checkSuccessResponse(lib.VerifyWithLegRoast(pub_legroast, message, lr_signature, true)) ? "OK" : "Failed") << std::endl;
    }

    Pastel testExportImportWallet(Pastel &lib, const std::string &pastel_id) {
        std::cout << "==== Export wallet ====" << std::endl;
        auto wallet = decodeStringResponse(lib.ExportWallet());
        std::cout << wallet << std::endl;

        std::cout << "==== Import wallet (wallet locked) ====" << std::endl;
        Pastel lib2;
        std::cout << (checkSuccessResponse(lib2.ImportWallet(wallet)) ? "OK" : "Failed") << std::endl;

        auto pub_ed4481 = decodeStringResponse(lib.GetPastelID(pastel_id, PastelIDType::PASTELID));
        auto pub_legroast1 = decodeStringResponse(lib.GetPastelID(pastel_id, PastelIDType::LEGROAST));
        std::cout << "PastelID pub key: " << pub_ed4481 << std::endl;
        std::cout << "LegRoast pub key: " << pub_legroast1 << std::endl;

        auto pub_ed4482 = decodeStringResponse(lib2.GetPastelID(pastel_id, PastelIDType::PASTELID));
        auto pub_legroast2 = decodeStringResponse(lib2.GetPastelID(pastel_id, PastelIDType::LEGROAST));
        std::cout << "PastelID pub key: " << pub_ed4482 << std::endl;
        std::cout << "LegRoast pub key: " << pub_legroast2 << std::endl;

        // Compare tests
        std::cout << "=== Check PastelID is matching ===" << std::endl;
        assert(pub_ed4481 == pub_ed4482);
        std::cout << "OK" << std::endl;

        std::cout << "=== Check LegRoast is matching ===" << std::endl;
        assert(pub_legroast1 == pub_legroast2);
        std::cout << "OK" << std::endl;

        return lib2;
    }

    void run()
    {
        Pastel lib;
        const auto walletPassword = "password";
        testWallet::testCreateWallet(lib, walletPassword);

        const auto pastel_id = "jXXmQdZPF5mT6kxPr2Z3HNWsNKoZedC2gFdmwoAQr1e4kD5Jtw6BryZD8fJzZAgc2iAdMsUZ3aGfzE4ccrKkEo";
        const auto password = "passphrase";
        const auto message = "test";

        std::cout << lib.ImportPastelIDKeys(pastel_id, password, PASTEL_ID_PATH) << std::endl;

        auto pub_ed448 = decodeStringResponse(lib.GetPastelID(pastel_id, PastelIDType::PASTELID));
        std::cout << "PastelID pub key: " << pub_ed448 << std::endl;
        auto pub_legroast = decodeStringResponse(lib.GetPastelID(pastel_id, PastelIDType::LEGROAST));
        std::cout << "LegRoast pub key: " << pub_legroast << std::endl;

        testSignVerify(lib, pastel_id, pub_legroast, message);
        testVerifyExternal(lib, pastel_id, pub_legroast, message);

        auto lib2 = testExportImportWallet(lib, pastel_id);
        lib2.UnlockWallet(walletPassword);

        testSignVerify(lib2, pastel_id, pub_legroast, message);
        testVerifyExternal(lib2, pastel_id, pub_legroast, message);
    }
}

int main() {
    // testWallet::run();
    // testWallet::run2();
    // testSendTo::run();
    // testSendToJSON::run();
    // testExternalWallet::run();
    // testExternalPastelID::run();

    Pastel lib;
    testWallet::testCreateWallet(lib, "password");
    for (const auto addresses = testWallet::testNewAddresses(lib, 2, 0, NetworkMode::MAINNET);
        const auto& address : addresses) {
        auto secret = lib.GetAddressSecret(address, NetworkMode::MAINNET);
        std::cout << "Address: " << address << "; Private key: " << secret << std::endl;
    }
    const auto orig_address = "PtiMyKSofCEt9X9FuaXDzjhyvZ27uadqXsa";
    const auto orig_privKey = "Kxb6W74ZrtRTZX7viSUtWeJxvSaxxfcQpCCpSuore2VR8vv9kM37";
    const auto imp_address = decodeStringResponse(lib.ImportLegacyPrivateKey(orig_privKey, NetworkMode::MAINNET));
    const auto imp_privKey = decodeStringResponse(lib.GetAddressSecret(orig_address, NetworkMode::MAINNET));
    std::cout << imp_address << std::endl;
    std::cout << imp_privKey << std::endl;
    assert(imp_address == orig_address);
    assert(imp_privKey == orig_privKey);

    for (const auto addresses = decodeVectorStringResponse(lib.GetAddresses(NetworkMode::MAINNET));
        const auto& address : addresses) {
        auto secret = lib.GetAddressSecret(address, NetworkMode::MAINNET);
        std::cout << "Address: " << address << "; Private key: " << secret << std::endl;
    }

    // testSigner1::run();
    // testSigner1::run();
    // testSigner1::run();
    // testSigner1::run();
    // testSigner1::run();
    // testSigner2::run();
    // testSigner2::run();
    // testSigner2::run();
    // testSigner2::run();
    // testSigner2::run();
#if 0
//    auto walletStr = "L9we22TUta29d4255xWN5u6z8xyqV8VDygDPCCe6o2S6A6LR2FD6PN2tA4rFxeVtcJ2ugjHEBsB52GRVWes4kna4D3Y1n2xeWC9RJf4gtdor76LiNBuDBMBRyh6jXs3HsetM1vf1yGSiZj7UJP5nbzsDCNXWxDWoexGhbmQYVgtorTeriat9G9RiHcnFBGepnZx7va6WfFFe44TV56aue6tcLZKgNzJVRY146JcKZ5tEN8SF3SJqHzdHe3SvkRGKsEmoQDgtw2ZQYS8KDnPcP2LAXRcRT7TjJzo7pp21fq5cx4Yc42XnNU9zVrjPF8FxSSUojonn1kXKCKi6BHDJy5NAujGsLyt2wfHpy1L6iYPkEmdbRFGXQyzGqEAxtsXhMCUtgg8hNkDBZNJexY6WAe9mjXP9X9R";
//    Pastel lib2;
//    std::cout << lib2.ImportWallet(walletStr) << std::endl;
//    std::cout << lib2.UnlockWallet("12341234") << std::endl;

//    Pastel lib;
//    auto walletStr = "L9we22TUta29d4255xWN5u6z8xyqV8VDygDPCCe6o2S6Abs5wTTyS3bdkTd9DUbGTXqMABvf5hqD2k1Fh6DVAbk9nHr3nTFxfhyTCZasWYpBPNjDFtxMAqeEX79MFMnNy3592VUKZt6uzFaGF2NqosUYMvfxArPUYkB93W7WVesswzJiD3yXnZh5Ficp5HMkeiJiFm5xvp3WhtJmhdMBqdXy2JqakVzLNrA4s1aH7UKk986KYcWLnW8mzoDL3V8ScKed3yghQfCWGJmmi6be5TVfSUodNs4zXz9rGbyHwa99vx8vHkmwfNbUb85fFTGYmD2xinPBQDUguVZU9As28bsCYubg5bPGkUynjZCLnYh3yfNinTnSCKRyMGm7A1exJF4HugnLRs1zCcMVf6PXV8Ups3rjEdd";
//    std::cout << (checkSuccessResponse(lib.ImportWallet(walletStr)) ? "OK" : "Failed") << std::endl;
//    auto unlockResponse = lib.UnlockWallet("12341234");
//    auto okCheck = checkSuccessResponse(unlockResponse);
//    assert(okCheck);
//    auto address1 = decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET));
//    auto address2 = decodeStringResponse(lib.MakeNewAddress(NetworkMode::DEVNET));
//    assert(address2 == "44oZadG1Ns1qL1DGwuPswWR9sF6xtET86x92");
//    auto send_to_json = R"([{"address":"44oHrTBfhAg7vxvFdMwABJWRjxCmEwkFr3fo","amount":1000}])";
//    auto utxo_json = R"([{"address":"44oZadG1Ns1qL1DGwuPswWR9sF6xtET86x92","txid":"532d47232ca7b35907b2b85cf5cf06c6ce3321cd511439c733a38cbe07a8804a","outputIndex":0,"patoshis":200000000},{"address":"44oZadG1Ns1qL1DGwuPswWR9sF6xtET86x92","txid":"2d4c1985b5778de58c6850fd6a96b5d6f1b76f79b9e4fd4ea916529025914688","outputIndex":1,"patoshis":400000000},{"address":"44oZadG1Ns1qL1DGwuPswWR9sF6xtET86x92","txid":"1becee0d977da16cfd03a03f9fc4d42dddf2b56c6d6f1fc83f82df1085801a8b","outputIndex":0,"patoshis":100000000},{"address":"44oZadG1Ns1qL1DGwuPswWR9sF6xtET86x92","txid":"a805caa0692a84c4621ead16b0cd51aaa761e3f9eb2db9f48bbf7a559cc07ddd","outputIndex":1,"patoshis":300000000}])";
//    cout << lib.CreateSendToTransactionJson(NetworkMode::DEVNET, send_to_json, "44oZadG1Ns1qL1DGwuPswWR9sF6xtET86x92", utxo_json, 76270);
#endif

    return 0;
}

