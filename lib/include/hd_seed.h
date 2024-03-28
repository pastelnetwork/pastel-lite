#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "types.h"
#include "uint256.h"

typedef CKeyingMaterial RawHDSeed;

class HDSeed {
protected:
    RawHDSeed seed;

    HDSeed() = default;
public:
    explicit HDSeed(RawHDSeed seedIn) : seed(std::move(seedIn)) {}

    [[nodiscard]] uint256 Fingerprint() const;
    [[nodiscard]] RawHDSeed RawSeed() const { return seed; }

    friend bool operator==(const HDSeed& a, const HDSeed& b)
    {
        return a.seed == b.seed;
    }

    friend bool operator!=(const HDSeed& a, const HDSeed& b)
    {
        return !(a == b);
    }
};
