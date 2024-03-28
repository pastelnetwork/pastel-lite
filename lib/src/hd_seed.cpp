// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "hd_seed.h"
#include "uint256.h"
#include <hash.h>
#include "crypter.h"

constexpr size_t PERSONALBYTES = 16;
constexpr unsigned char PASTEL_HD_SEED_FP_PERSONAL[PERSONALBYTES] =
    {'P', 'a', 's', 't', 'e', 'l', 'H', 'D', '_', 'S', 'e', 'e', 'd', '_', 'F', 'P'};

uint256 HDSeed::Fingerprint() const
{
    CBLAKE2bWriter h(SER_GETHASH, 0, PASTEL_HD_SEED_FP_PERSONAL);
    h << seed;
    return h.GetHash();
}
