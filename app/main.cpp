#include <iostream>
#include <json/json.hpp>

#include "libpastel.h"
#include "support/decoder.hpp"

#include <iostream>
#include <string>

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

    std::vector<std::string> testNewAddresses(Pastel &lib, uint32_t count, uint32_t startIndex = 0, NetworkMode mode = NetworkMode::MAINNET) {
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
//        cout << lib.CreateSendToTransactionJson(NetworkMode::DEVNET, send_to_json, "", utxo_json, 76270);
        cout << decodeStringResponse(lib.CreateRegisterPastelIdTransactionJson(NetworkMode::DEVNET, pastelID,
                                                                               "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
                                                                               utxo_json, 84001));
    }
}

namespace testSigner {
    void run() {
        PastelSigner lib("/home/alexey/.pastel/devnet/pastelkeys/");
        auto signature1 = lib.SignWithPastelID("jXZ2tqWy4nMp3wTRJtwPYhcf57j2FequbHoi6wciVzDgDr2dwbqgoS33BD64GVZN7i9ZCdHU7GUeWbpp82Ro46", "test message", "password");
        cout << signature1 << endl;
        auto ok1 = lib.VerifyWithPastelID("jXZ2tqWy4nMp3wTRJtwPYhcf57j2FequbHoi6wciVzDgDr2dwbqgoS33BD64GVZN7i9ZCdHU7GUeWbpp82Ro46", "test message", signature1);
        cout << (ok1?"true":"false") << endl;

        auto signature2 = "0P6EeisbiWzmNab5HC0xeLAjLr/tW5zBLvFXE81yNciLtmUg8fXuvaZFrbsFT54fagznt4TNxK0ACYgQJ/3pVqmj0T5Al/BvetwqFg2VSjWP/ss6wCzYz83Uj94eoei7lrK7Iq55QMKghBmLRhtIjhIA";
        auto ok2 = lib.VerifyWithPastelID(
                "jXaczRW4MgeiioV1DAte38aj6FK2dwL7ykEajmm6K7J1XQc5qcJfkJYD24pSt1MUAbPjfhDv1iSYrSsxAqp1Mb", "test", signature2);
        cout << (ok2 ? "true" : "false") << endl;
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

int main() {
    testWallet::run();
    testWallet::run2();
    testSendTo::run();
    testSendToJSON::run();
//    testSigner::run();
    testExternalWallet::run();

    return 0;
}

