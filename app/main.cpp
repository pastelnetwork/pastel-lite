#include <iostream>

#include "libpastel.h"

int main() {
    Pastel lib;
    auto mnem = lib.CreateNewWallet(NetworkMode::MAINNET, "password");
    std::cout << "Mnemonic: " << mnem << std::endl;

    std::cout << "New Address  0: " << lib.MakeNewAddress() << std::endl;
    std::cout << "New Address  1: " << lib.MakeNewAddress() << std::endl;
    std::cout << "New Address  2: " << lib.MakeNewAddress() << std::endl;
    std::cout << std::endl;
    std::cout << "Same Address 0: " << lib.GetAddress(0) << std::endl;
    std::cout << "Same Address 1: " << lib.GetAddress(1) << std::endl;
    std::cout << "Same Address 2: " << lib.GetAddress(2) << std::endl;

    auto wallet= lib.ExportWallet();
    std::cout << wallet << std::endl;

    auto wallet2 = "11114YN6Aey8kUNoL8jjfkTx2iWPshvbNST5sjt5czmyxCNBMRYYgsm6SjCyanjH7Fkod7XCvYLnTn4Y1CKy1ZpDWS1bfbtxpQvMT9nWSGuuBjn1tYvvpeQqbWYwhd8HTNdAHZXGwQTP4TwQwKLWi2ATb2khvBwREqu2RQ355NaZZoJrKQuZFdvxKyrZT3baZFmZvvEhzthXy4FVX1CDQAH2b85UmJyokicxPbwnrjusfjQwB8jGvKnfuWeQBBLyW4zAnhUgXj1sRwE4MUGgrGaFgiR5VfALUbshQfQ9j7eycLS1Cgs3C1zP4y2wa9hmQmRDENtYCqUzqLcQ3FfGxf5Mo6q38u5R7cjfw944P1Qa7DrBfSbYiF6kTsrueoFaf89fGmbwSyq6mXB9NXXDmeQc6gfYpYJDwpkPvL8U1pCTzSCE2nN8Sz1zY99pDEayt8ayHfyBzzCbXBiFizEtthx1KwJZQAmP6DgQJS6An3SVSP5cWE5nbWmnzeYzCg36kQE2GsKxFBYL7";
    Pastel lib2;
    std::cout << lib2.ImportWallet(wallet2) << std::endl;
    auto list = lib2.GetAddresses();
    std::cout << "Imported Addresses: " << std::endl;
    std::cout << list << std::endl;
//    for (const auto& addr : list) {
//        std::cout << addr << std::endl;
//    }

    std::cout << "New Address  3: " << lib2.MakeNewAddress() << std::endl;

    std::cout << lib2.UnlockWallet("password") << std::endl;
    std::cout << "New Address  3: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "New Address  4: " << lib2.MakeNewAddress() << std::endl;
    std::cout << "New Address  5: " << lib2.MakeNewAddress() << std::endl;
    std::cout << std::endl;
    std::cout << lib2.LockWallet() << std::endl;
    std::cout << "Same Address 3: " << lib2.GetAddress(3) << std::endl;
    std::cout << "Same Address 4: " << lib2.GetAddress(4) << std::endl;
    std::cout << "Same Address 5: " << lib2.GetAddress(5) << std::endl;
    std::cout << lib2.GetAddressesCount() << std::endl;
    try {
        std::cout << "New Address  6: " << lib2.MakeNewAddress() << std::endl;
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
    }

    std::cout << "wrong password " << lib2.UnlockWallet("wrong password") << std::endl;

    lib2.UnlockWallet("password");
    std::cout << lib2.GetWalletPubKey() << std::endl;
    std::cout << lib2.SignWithWalletKey("message") << std::endl;
    std::cout << lib2.GetPubKeyAt(3) << std::endl;
    std::cout << lib2.SignWithKeyAt(3, "message") << std::endl;
    std::cout << lib2.GetPubKeyAt(0x80000003) << std::endl;
    std::cout << lib2.SignWithKeyAt(0x80000003, "message") << std::endl;

    std::cout << lib2.GetPubKeyAt(0x9A551AB3) << std::endl;
    std::cout << lib2.SignWithKeyAt(0x9A551AB3, "message") << std::endl;

    return 0;
}

