#include <iostream>

#include "libpastel.h"

int main() {
    Pastel lib;
    auto mnem = lib.CreateNewWallet(NetworkMode::MAINNET, "password");
    std::cout << "Mnemonic: " << mnem << std::endl;

    std::cout << "New Address  0: " << lib.GetNewAddress() << std::endl;
    std::cout << "New Address  1: " << lib.GetNewAddress() << std::endl;
    std::cout << "New Address  2: " << lib.GetNewAddress() << std::endl;
    std::cout << std::endl;
    std::cout << "Same Address 0: " << lib.GetNewAddressByIndex(0) << std::endl;
    std::cout << "Same Address 1: " << lib.GetNewAddressByIndex(1) << std::endl;
    std::cout << "Same Address 2: " << lib.GetNewAddressByIndex(2) << std::endl;

    auto wallet= lib.ExportWallet();

    auto wallet2 = "w5dddcKJHcKcwqJrwqgWwoJCHcK4wobCvMORAC/CmRHCsWVGw7FvcQdVw7vCr1jDoTNfFsKCwrXDvcOjHUfDmsOOwrXCjMK8QsOGJMOLNcK0fcO3w4Eow4DDtEDDqhkzPzHDlEgww7MweMONWQwGPsOjw4TCusOqL8Oiw7gPNMOycMOIw4TClAp5w5ZRw7XCnsOFw41PwoDCvsK3S1zCuj3DpsKiwq9vGBjDgXvCghgQw5vCvCdfwpFWMgzCmsKbHwHCuQLCjWfCscK8eMKdwonCosOxw6fDjnFNwqnDkSfCoMKgw5hKAy/CvUvDg8OMZFwNCcOxZsO7wrbCiTDCqcOnOywOw7bDsRbDlxVzccO2EQjDql9iw7vDl8Khw4LDssO7w590UcOqw4vCncKHe8OWSXFBJmTDhgoywq3Dl8K5wr7CtQXDq3jCk8K2w5kLwqU4E8OIIMKGJcOzw6cnw6jDoHQfwrFFUgVdZxcAQB1zBi7CoMO1fMKww5ISw6zDs1jCvMOKJjTDt1zDsMKPwoAcwrbCrXFsw5zCkC1ZK8Ozwo0gwo3DjAp4wpEBZ8KuKMO3Cno8wr3CqhVDecKiw60nw7bDp2DDmEjDnMOxw6x2w6cUw5dhw4XCiMO6wqRswqkTa8K7wo7CucKBw6o4wpNxJ8KKJWkoY23ClWkKKcOqwrjDknLDrMOwT3YyF2vCmWDCuhxmw7oMw4oqwqDDnTTDlcO1TsKzAhLDvELDg0VJFjHDmsKYc8KcwrZ4w5bCsMOhwpnDksKhwpgQwqvCoxbDnsOxEcONSsKKDx3DrWrDg8Kgw7PCmcKDJ0o=";
    Pastel lib2;
    lib2.ImportWallet(wallet, "password");
    auto list = lib2.GetAddresses();
    std::cout << "Imported Addresses: " << std::endl;
    for (const auto& addr : list) {
        std::cout << addr << std::endl;
    }
    std::cout << "New Address  3: " << lib2.GetNewAddress() << std::endl;
    std::cout << "New Address  4: " << lib2.GetNewAddress() << std::endl;
    std::cout << "New Address  5: " << lib2.GetNewAddress() << std::endl;
    std::cout << std::endl;
    std::cout << "Same Address 3: " << lib2.GetNewAddressByIndex(3) << std::endl;
    std::cout << "Same Address 4: " << lib2.GetNewAddressByIndex(4) << std::endl;
    std::cout << "Same Address 5: " << lib2.GetNewAddressByIndex(5) << std::endl;

    return 0;
}

