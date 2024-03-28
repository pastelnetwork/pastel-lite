#include "libpastel.h"
#include <iostream>

int main() {
    Pastel lib;
    string address = lib.GetNewAddress(NetworkMode::MAINNET);
    std::cout << "New Address: " << address << std::endl;

    auto mnem = lib.CreateNewWallet(NetworkMode::MAINNET, "password");
    std::cout << "Mnemonic: " << mnem << std::endl;
    return 0;
}

