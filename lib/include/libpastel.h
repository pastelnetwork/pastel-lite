#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include "chain.h"

using namespace std;

class Pastel {
    std::map<NetworkMode, CChainParams*> m_Networks;

public:
    Pastel();
    std::string GetNewAddress(NetworkMode mode);
};
