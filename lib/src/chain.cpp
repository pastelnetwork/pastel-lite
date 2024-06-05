// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include "chain.h"

const CChainParams& GetChainParams(const NetworkMode mode)
{
    static std::unique_ptr<CChainParams> ChainParams;

    switch (mode)
    {
        case NetworkMode::MAINNET:
            ChainParams = std::make_unique<CMainnetParams>();
            break;

        case NetworkMode::TESTNET:
            ChainParams = std::make_unique<CTestnetParams>();
            break;

        case NetworkMode::DEVNET:
            ChainParams = std::make_unique<CDevnetParams>();
            break;

        default:
            assert(false && "Unimplemented network");
            ChainParams = std::make_unique<CMainnetParams>();
            break;
    }

    return *ChainParams;
}
