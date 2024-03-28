#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "crypter.h"
#include "hd_mnemonic.h"
#include "types.h"

class CHDWallet
{
    std::pair<uint256, std::vector<unsigned char>> m_encryptedMnemonicSeed;
    CMasterKey m_encryptedMasterKey;
    CKeyingMaterial m_vMasterKey;

public:
    bool SetMasterKey(const SecureString& strPassphrase);
    bool SetEncryptedMnemonicSeed(const MnemonicSeed& seed);
    [[nodiscard]] std::optional<MnemonicSeed> GetDecryptedMnemonicSeed() const;
};
