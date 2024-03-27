#include "libpastel.h"
#include <iostream>

int main() {
    Pastel lib;
    string address = lib.GetNewAddress(NetworkMode::MAINNET);
    std::cout << "New Address: " << address << std::endl;

    lib.CreateNewWallet(NetworkMode::MAINNET, "password");
    return 0;
}

