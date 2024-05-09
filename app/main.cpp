#include <iostream>
#include <json/json.hpp>

#include "libpastel.h"

int main() {
    Pastel lib;
    std::cout << "==== Create wallet ====" << std::endl;
    auto mnem = lib.CreateNewWallet(NetworkMode::MAINNET, "password");
    std::cout << "Mnemonic: " << mnem << std::endl;
//    std::cout << "==== Addresses ====" << std::endl;
//    std::cout << "Create new Address 0: " << lib.MakeNewAddress() << std::endl;
//    std::cout << "Create new Address 1: " << lib.MakeNewAddress() << std::endl;
//    std::cout << "Get existing Address 0: " << lib.GetAddress(0) << std::endl;
//    std::cout << "Get existing Address 1: " << lib.GetAddress(1) << std::endl;
//    std::cout << "Get non-created Address 2: " << lib.GetAddress(2) << std::endl;
    std::cout << "==== PastelIDs ====" << std::endl;
    std::cout << "Create new PastelID 0: " << lib.MakeNewPastelID() << std::endl;
    std::cout << "Create new PastelID 1: " << lib.MakeNewPastelID() << std::endl;
    std::cout << "Get existing PastelID 0: " << lib.GetPastelID(0) << std::endl;
    std::cout << "Get existing LegRoast 0: " << lib.GetPastelID(0, PastelIDType::LEGROAST) << std::endl;
    std::cout << "Get existing PastelID 1: " << lib.GetPastelID(1) << std::endl;
    std::cout << "Get existing LegRoast 1: " << lib.GetPastelID(1, PastelIDType::LEGROAST) << std::endl;
    std::cout << "Get non-created PastelID 2: " << lib.GetPastelID(2) << std::endl;
    std::cout << "Get non-created LegRoast 2: " << lib.GetPastelID(2, PastelIDType::LEGROAST) << std::endl;
    std::cout << "All PastelIDs: " << lib.GetPastelIDs() << std::endl;

    std::cout << "==== Sign/Verify ====" << std::endl;
    auto pastelID = nlohmann::json::parse(lib.GetPastelID(1)).at("data").get<std::string>();
    std::cout << "Sign with PastelID 1: " << pastelID << std::endl;
    auto sigRes1 = lib.SignWithPastelID(pastelID, "message", PastelIDType::PASTELID, true);
    auto signature1 = nlohmann::json::parse(sigRes1).at("data").get<std::string>();
    std::cout << "PastelID signature" << signature1 << std::endl;
    auto sigRes2 = lib.SignWithPastelID(pastelID, "message", PastelIDType::LEGROAST, true);
    auto signature2 = nlohmann::json::parse(sigRes2).at("data").get<std::string>();
    std::cout << "LegRoast signature" << signature2 << std::endl;
    std::cout << "Verify with PastelID: " << lib.VerifyWithPastelID(pastelID, "message", signature1, true) << std::endl;
    std::cout << "Verify with LegRoast: " << lib.VerifyWithLegRoast(pastelID, "message", signature2, true) << std::endl;

    std::cout << "==== Export PastelID 1 ====" << std::endl;
    std::cout << lib.ExportPastelIDKeys(pastelID, "password", ".") << std::endl;

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
    std::cout << "== All PastelIDs in imported wallet ==" << std::endl;
    std::cout << lib2.GetPastelIDs() << std::endl;
    std::cout << "Get existing LegRoast 0: " << lib.GetPastelID(0, PastelIDType::LEGROAST) << std::endl;
    std::cout << "Get existing LegRoast 1: " << lib.GetPastelID(1, PastelIDType::LEGROAST) << std::endl;
    std::cout << "== Create new address in locked wallet ==" << std::endl;
    std::cout << "New Address  2: " << lib2.MakeNewAddress() << std::endl;
    std::cout << std::endl;
    std::cout << "== Create new PastelID in locked wallet ==" << std::endl;
    std::cout << "New PastelID  2: " << lib2.MakeNewPastelID() << std::endl;
    std::cout << std::endl;
    std::cout << "==== Unlock wallet ====" << std::endl;
    std::cout << lib2.UnlockWallet("password") << std::endl;
    std::cout << "== Create new address ==" << std::endl;
    std::cout << "New Address 2: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "New Address 3: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "New Address 4: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "== Create new PastelID ==" << std::endl;
    std::cout << "New PastelID 2: " << lib2.MakeNewPastelID() << std::endl;
    std::cout << "New PastelID 3: " << lib2.MakeNewPastelID() << std::endl;
    std::cout << "New PastelID 4: " << lib2.MakeNewPastelID() << std::endl;
    std::cout << std::endl;
    std::cout << "==== Lock wallet ====" << std::endl;
    std::cout << lib2.LockWallet() << std::endl;
    std::cout << "==== Addresses ====" << std::endl;
    std::cout << "Get existing Address 2: " << lib2.GetAddress(2) << std::endl;
    std::cout << "Get existing Address 3: " << lib2.GetAddress(3) << std::endl;
    std::cout << "Get existing Address 4: " << lib2.GetAddress(4) << std::endl;
    std::cout << "Addresses count: " << lib2.GetAddressesCount() << std::endl;
    std::cout << "New Address 5: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "Get non-existing Address 5: " << lib2.GetAddress(5) << std::endl;
    std::cout << "==== PastelIDs ====" << std::endl;
    std::cout << "Get existing PastelID 2: " << lib2.GetPastelID(2) << std::endl;
    std::cout << "Get existing LegRoast 2: " << lib2.GetPastelID(2, PastelIDType::LEGROAST) << std::endl;
    std::cout << "Get existing PastelID 3: " << lib2.GetPastelID(3) << std::endl;
    std::cout << "Get existing LegRoast 3: " << lib2.GetPastelID(3, PastelIDType::LEGROAST) << std::endl;
    std::cout << "Get existing PastelID 4: " << lib2.GetPastelID(4) << std::endl;
    std::cout << "Get existing LegRoast 4: " << lib2.GetPastelID(4, PastelIDType::LEGROAST) << std::endl;
    std::cout << "PastelIDes count: " << lib2.GetPastelIDsCount() << std::endl;
    std::cout << "New PastelID 5: " << lib2.MakeNewPastelID() << std::endl;
    std::cout << "Get non-existing PastelID 5: " << lib2.GetPastelID(5) << std::endl;
    std::cout << "Get non-existing LegRoast 5: " << lib2.GetPastelID(5, PastelIDType::LEGROAST) << std::endl;
    std::cout << std::endl;
    std::cout << "==== Unlock wallet with wrong password ====" << std::endl;
//    std::cout << "wrong password " << lib2.UnlockWallet("wrong password") << std::endl;
//    std::cout << std::endl;
//    std::cout << "==== Unlock wallet ====" << std::endl;
//    lib2.UnlockWallet("password");
//    std::cout << "==== Account management ====" << std::endl;
//    std::cout << lib2.GetWalletPubKey() << std::endl;
//    std::cout << lib2.SignWithWalletKey("message") << std::endl;
//    std::cout << lib2.GetPubKeyAt(3) << std::endl;
//    std::cout << lib2.SignWithKeyAt(3, "message") << std::endl;
//    std::cout << lib2.GetPubKeyAt(0x80000003) << std::endl;
//    std::cout << lib2.SignWithKeyAt(0x80000003, "message") << std::endl;
//    std::cout << std::endl;
//    std::cout << lib2.GetPubKeyAt(0x9A551AB3) << std::endl;
//    std::cout << lib2.SignWithKeyAt(0x9A551AB3, "message") << std::endl;
    return 0;
}

