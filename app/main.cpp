#include <iostream>
#include <json/json.hpp>

#include "libpastel.h"

void test1() {
    Pastel lib;
    auto mnem = lib.CreateNewWallet("password");
    std::cout << "==== Create wallet ====" << std::endl;
    std::cout << "Mnemonic: " << mnem << std::endl;

    std::cout << "==== Addresses ====" << std::endl;
    std::cout << "Create new Address 0: " << lib.MakeNewAddress() << std::endl;
    std::cout << "Create new Devnet Address 0: " << lib.MakeNewAddress(NetworkMode::DEVNET) << std::endl;
    std::cout << "Create new Address 1: " << lib.MakeNewAddress() << std::endl;
    std::cout << "Get existing Address 0: " << lib.GetAddress(0) << std::endl;
    std::cout << "Get existing Address 1: " << lib.GetAddress(1) << std::endl;
    std::cout << "Get non-created Address 2: " << lib.GetAddress(2) << std::endl;
    std::cout << "Addresses count: " << lib.GetAddressesCount() << std::endl;
//    std::cout << "==== PastelIDs ====" << std::endl;
//    std::cout << "Create new PastelID 0: " << lib.MakeNewPastelID() << std::endl;
//    std::cout << "Create new PastelID 1: " << lib.MakeNewPastelID() << std::endl;
//    std::cout << "Get existing PastelID 0: " << lib.GetPastelIDByIndex(0) << std::endl;
//    std::cout << "Get existing LegRoast 0: " << lib.GetPastelIDByIndex(0, PastelIDType::LEGROAST) << std::endl;
//    std::cout << "Get existing PastelID 1: " << lib.GetPastelIDByIndex(1) << std::endl;
//    std::cout << "Get existing LegRoast 1: " << lib.GetPastelIDByIndex(1, PastelIDType::LEGROAST) << std::endl;
//    std::cout << "Get non-created PastelID 2: " << lib.GetPastelIDByIndex(2) << std::endl;
//    std::cout << "Get non-created LegRoast 2: " << lib.GetPastelIDByIndex(2, PastelIDType::LEGROAST) << std::endl;
//    std::cout << "All PastelIDs: " << lib.GetPastelIDs() << std::endl;
//    std::cout << "PastelIDs count: " << lib.GetPastelIDsCount() << std::endl;
//
//    std::cout << "==== Sign/Verify ====" << std::endl;
//    auto pastelID = nlohmann::json::parse(lib.GetPastelIDByIndex(1)).at("data").get<std::string>();
//    std::cout << "Sign with PastelID 1: " << pastelID << std::endl;
//
//    auto sigRes1 = lib.SignWithPastelID(pastelID, "message", PastelIDType::PASTELID, true);
//    auto signature1 = nlohmann::json::parse(sigRes1).at("data").get<std::string>();
//    std::cout << "PastelID signature: " << signature1 << std::endl;
//
//    auto sigRes2 = lib.SignWithPastelID(pastelID, "message", PastelIDType::LEGROAST, true);
//    auto signature2 = nlohmann::json::parse(sigRes2).at("data").get<std::string>();
//    std::cout << "LegRoast signature: " << signature2 << std::endl;
//
//    std::cout << "Verify with PastelID: " << lib.VerifyWithPastelID(pastelID, "message", signature1, true) << std::endl;
//
//    auto legRoast = nlohmann::json::parse(lib.GetPastelID(pastelID, PastelIDType::LEGROAST)).at("data").get<std::string>();
//    std::cout << "Get LegRoast 1: " << legRoast << std::endl;
//    std::cout << "Verify with LegRoast: " << lib.VerifyWithLegRoast(legRoast, "message", signature2, true) << std::endl;
//
//    std::cout << "Verify with External PastelID: " << lib.VerifyWithPastelID("jXXQ5MdtkCMjftmgmHC2nXGwqiqh2m14kbnVdwcjaeKD7nmE3tFiNnHrwEkV2ZPKejUmvkQzfMFwizkjKVy9nG", "message",
//                                                                             "3LdXRMIHJ3t9n3Fkv6Wlnq3+fK0HcNJXJnWYgWsGjoHGT1nGGfEnhiUnrOkLOko2WkZVuFEBIt8ASApzI92ThOdJEgGivBnEpXZGTJZj8thKwcqxvaH5A3Pjow+z96YNl/WeUTYxAYqVEzgeDBT+EQsA",
//                                                                             true) << std::endl;
//
//
//    std::cout << "==== Export PastelID 1 ====" << std::endl;
//    std::cout << lib.ExportPastelIDKeys(pastelID, "password", ".") << std::endl;

    std::cout << "==== Export wallet ====" << std::endl;
    auto wallet= lib.ExportWallet();
    nlohmann::json jsonObj = nlohmann::json::parse(wallet);
    std::cout << jsonObj.at("result") << std::endl;
    std::cout << "=======================" << std::endl;
    std::cout << std::endl;
    std::cout << "==== Import wallet (wallet locked) ====" << std::endl;
    Pastel lib2;
    std::cout << lib2.ImportWallet(jsonObj.at("data")) << std::endl;
    std::cout << "== All Addresses in imported wallet ==" << std::endl;
    std::cout << lib2.GetAddresses() << std::endl;
//    std::cout << "== All PastelIDs in imported wallet ==" << std::endl;
//    std::cout << lib2.GetPastelIDs() << std::endl;
//    std::cout << "Get existing LegRoast 0: " << lib.GetPastelIDByIndex(0, PastelIDType::LEGROAST) << std::endl;
//    std::cout << "Get existing LegRoast 1: " << lib.GetPastelIDByIndex(1, PastelIDType::LEGROAST) << std::endl;
    std::cout << "== Create new address in locked wallet ==" << std::endl;
    std::cout << "New Address  2: " << lib2.MakeNewAddress() << std::endl;
    std::cout << std::endl;
//    std::cout << "== Create new PastelID in locked wallet ==" << std::endl;
//    std::cout << "New PastelID  2: " << lib2.MakeNewPastelID() << std::endl;
//    std::cout << std::endl;
    std::cout << "==== Unlock wallet ====" << std::endl;
    std::cout << lib2.UnlockWallet("password") << std::endl;
    std::cout << "== Create new address ==" << std::endl;
    std::cout << "New Address 2: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "New Address 3: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "New Address 4: " << lib2.MakeNewAddress() << std::endl;
//    std::cout << "== Create new PastelID ==" << std::endl;
//    std::cout << "New PastelID 2: " << lib2.MakeNewPastelID() << std::endl;
//    std::cout << "New PastelID 3: " << lib2.MakeNewPastelID() << std::endl;
//    std::cout << "New PastelID 4: " << lib2.MakeNewPastelID() << std::endl;
//    std::cout << std::endl;
    std::cout << "==== Lock wallet ====" << std::endl;
    std::cout << lib2.LockWallet() << std::endl;
    std::cout << "==== Addresses ====" << std::endl;
    std::cout << "Get existing Address 2: " << lib2.GetAddress(2) << std::endl;
    std::cout << "Get existing Address 3: " << lib2.GetAddress(3) << std::endl;
    std::cout << "Get existing Address 4: " << lib2.GetAddress(4) << std::endl;
    std::cout << "Addresses count: " << lib2.GetAddressesCount() << std::endl;
    std::cout << "New Address 5: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "Get non-existing Address 5: " << lib2.GetAddress(5) << std::endl;
//    std::cout << "==== PastelIDs ====" << std::endl;
//    std::cout << "Get existing PastelID 2: " << lib2.GetPastelIDByIndex(2) << std::endl;
//    std::cout << "Get existing LegRoast 2: " << lib2.GetPastelIDByIndex(2, PastelIDType::LEGROAST) << std::endl;
//    std::cout << "Get existing PastelID 3: " << lib2.GetPastelIDByIndex(3) << std::endl;
//    std::cout << "Get existing LegRoast 3: " << lib2.GetPastelIDByIndex(3, PastelIDType::LEGROAST) << std::endl;
//    std::cout << "Get existing PastelID 4: " << lib2.GetPastelIDByIndex(4) << std::endl;
//    std::cout << "Get existing LegRoast 4: " << lib2.GetPastelIDByIndex(4, PastelIDType::LEGROAST) << std::endl;
//    std::cout << "PastelIDes count: " << lib2.GetPastelIDsCount() << std::endl;
//    std::cout << "New PastelID 5: " << lib2.MakeNewPastelID() << std::endl;
//    std::cout << "Get non-existing PastelID 5: " << lib2.GetPastelIDByIndex(5) << std::endl;
//    std::cout << "Get non-existing LegRoast 5: " << lib2.GetPastelIDByIndex(5, PastelIDType::LEGROAST) << std::endl;
//    std::cout << std::endl;
    std::cout << "==== Unlock wallet with wrong password ====" << std::endl;
    std::cout << "wrong password " << lib2.UnlockWallet("wrong password") << std::endl;
    std::cout << std::endl;
    std::cout << "==== Unlock wallet ====" << std::endl;
    lib2.UnlockWallet("password");
    std::cout << "==== Account management ====" << std::endl;
    std::cout << lib2.GetWalletPubKey() << std::endl;
    std::cout << lib2.SignWithWalletKey("message") << std::endl;
    std::cout << lib2.GetPubKeyAt(3) << std::endl;
    std::cout << lib2.SignWithKeyAt(3, "message") << std::endl;
    std::cout << lib2.GetPubKeyAt(0x80000003) << std::endl;
    std::cout << lib2.SignWithKeyAt(0x80000003, "message") << std::endl;
    std::cout << std::endl;
    std::cout << lib2.GetPubKeyAt(0x9A551AB3) << std::endl;
    std::cout << lib2.SignWithKeyAt(0x9A551AB3, "message") << std::endl;
}

void test2(){
    Pastel lib;
    auto wallet = "1111Ysq69vYFqPRfbMRZ3kQETyAyr9qiEZZrwEzTbxAuTBTWu9cicawR2MTK22vXdnsDP4m2Y7zFYKZU24ywJvVgcyajGTnh77osz1dMvqdmd1S72KGZ7V6sRytjAW3vSWXLYqdDHpYA3tisnBRsTM8yYYBRcFN5mVA7hnFypvkpRGwmsvpJAqBotx3VqD9asVqvrMFuMWAxCbhgcWNwgbSoYVrFesB6sgeR5WfY5gj4kWEtmy2T8hU68qmgxYUs1ViEt9xuoAiz1AbSYtMwFaUhXRcafKnG3s4xiFPNEV1XFXZUg4Kc5TutYx4Sn4pcKREtvuBJxgM6nyXtDqPDmQmEJgBC7AAPRvgncJGtdpAJAsMiwKAtWzcSspFoRtfo9g1eqLqEtReDbCQ6e18tUnbLm3sCMD124CSozUrbjz6nnADE5ePQB";
    std::cout << lib.ImportWallet(wallet) << std::endl;

}

int main() {

//    test1();
//    test2();

    auto send_to = sendto_addresses{
        {"PtWJRAAQAfezCiSnYNsF3szBc7U9X4nqgQb", 100},
        {"PtWW6LP6dLLgi5WqTYi6C7NwiesVgeRRV18", 500}
    };

    auto utxos = tnx_outputs{
        {"PtTDUHythfRfXHh63yzyiGDid4TZj2P76Zd", "76a91402301e7752a9d3170dbecefd72010e9f3f9707a388ac", 0, 200},
        {"PtnsSy2e2AQM1ZBM8fxpSXPrUQGFfkiYzyJ", "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac", 0, 410},
    };

    Pastel lib;
    cout << lib.CreateSendToTransaction(NetworkMode::MAINNET, send_to, "", utxos, 1000);


    return 0;
}

