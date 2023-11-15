#include "libpastel.h"
#include <iostream>

int main() {
    Pastel lib;
    string address = lib.GetNewAddress(MAINNET);
    std::cout << "New Address: " << address << std::endl;
    return 0;
}

