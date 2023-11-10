//
// Created by Pastel Developers on 11/9/23.
//
#include "libpastel.h"
#include <iostream>

#include <pubkey.h>
#include <key_io.h>

void Pastel::doSomething() {
    std::cout << "Doing something inside mylib!" << std::endl;
}

void getnewaddress()
{
    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw;
    CKeyID keyID = newKey.GetID();

    KeyIO keyIO(Params());
    keyIO.EncodeDestination(keyID);
}