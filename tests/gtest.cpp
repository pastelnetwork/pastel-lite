// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "libpastel.h"
#include "support/decoder.hpp"

// Test fixture for the Pastel class
class PastelTest : public ::testing::Test {
protected:
    static Pastel pastel;
};

Pastel PastelTest::pastel;

// Wallet function tests
TEST_F(PastelTest, CreateNewWallet) {
    std::string password = "password";
    std::string result = pastel.CreateNewWallet(password);
    cout << result << endl;
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, CreateWalletFromMnemonic) {
    std::string mnemonic = "test mnemonic";
    std::string password = "password";
    std::string result = pastel.CreateWalletFromMnemonic(mnemonic, password);
    cout << result << endl;
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, ExportWallet) {
    std::string result = pastel.ExportWallet();
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, ImportWallet) {
    std::string data = decodeStringResponse(pastel.ExportWallet());
    std::string result = pastel.ImportWallet(data);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, UnlockWallet) {
    std::string password = "password";
    pastel.CreateNewWallet(password);
    std::string result = pastel.UnlockWallet(password);
    EXPECT_FALSE(result.empty());
}

//TEST_F(PastelTest, LockWallet) {
//    std::string result = pastel.LockWallet();
//    EXPECT_FALSE(result.empty());
//}

// Address function tests
TEST_F(PastelTest, MakeNewAddress) {
    std::string result = pastel.MakeNewAddress();
    cout << result << endl;
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, GetAddress) {
    pastel.MakeNewAddress();
    std::string result = pastel.GetAddress(0);
    cout << result << endl;
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, GetAddressesCount) {
    pastel.MakeNewAddress();
    auto result = decodeUint32Response(pastel.GetAddressesCount());
    cout << result << endl;
    EXPECT_EQ(result, 3);
}

TEST_F(PastelTest, GetAddresses) {
    pastel.MakeNewAddress();
    std::string result = pastel.GetAddresses();
    EXPECT_FALSE(result.empty());
}

// PastelID function tests
TEST_F(PastelTest, MakeNewPastelID) {
    std::string result = pastel.MakeNewPastelID();
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, GetPastelIDByIndex) {
    pastel.MakeNewPastelID();
    std::string result = pastel.GetPastelIDByIndex(0);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, GetPastelID) {
    std::string pastelID = pastel.MakeNewPastelID();
    std::string result = pastel.GetPastelID(pastelID);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, GetPastelIDsCount) {
    pastel.MakeNewPastelID();
    std::string result = pastel.GetPastelIDsCount();
    EXPECT_EQ(result, "1");
}

TEST_F(PastelTest, GetPastelIDs) {
    pastel.MakeNewPastelID();
    std::string result = pastel.GetPastelIDs();
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, SignWithPastelID) {
    std::string pastelID = pastel.MakeNewPastelID();
    std::string message = "message";
    std::string result = pastel.SignWithPastelID(pastelID, message);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, VerifyWithPastelID) {
    std::string pastelID = pastel.MakeNewPastelID();
    std::string message = "message";
    std::string signature = pastel.SignWithPastelID(pastelID, message);
    std::string result = pastel.VerifyWithPastelID(pastelID, message, signature);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, VerifyWithLegRoast) {
    std::string pastelID = pastel.MakeNewPastelID();
    std::string message = "message";
    std::string signature = pastel.SignWithPastelID(pastelID, message, PastelIDType::LEGROAST);
    std::string legRoast = pastel.GetPastelID(pastelID, PastelIDType::LEGROAST);
    std::string result = pastel.VerifyWithLegRoast(legRoast, message, signature);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, ExportPastelIDKeys) {
    std::string pastelID = pastel.MakeNewPastelID();
    std::string passPhrase = "password";
    std::string dirPath = ".";
    std::string result = pastel.ExportPastelIDKeys(pastelID, passPhrase, dirPath);
    EXPECT_FALSE(result.empty());
}

// Key function tests
TEST_F(PastelTest, GetWalletPubKey) {
    std::string result = pastel.GetWalletPubKey();
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, SignWithWalletKey) {
    std::string message = "message";
    std::string result = pastel.SignWithWalletKey(message);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, GetPubKeyAt) {
    pastel.MakeNewAddress();
    std::string result = pastel.GetPubKeyAt(0);
    EXPECT_FALSE(result.empty());
}

TEST_F(PastelTest, SignWithKeyAt) {
    pastel.MakeNewAddress();
    std::string message = "message";
    std::string result = pastel.SignWithKeyAt(0, message);
    EXPECT_FALSE(result.empty());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
