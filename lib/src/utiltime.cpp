// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chrono>
#include <thread>

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <utiltime.h>

using namespace std;

static int64_t nMockTime = 0;  //! For unit testing

int64_t GetTime() noexcept
{
    if (nMockTime)
        return nMockTime;
    return time(nullptr);
}

void SetMockTime(const int64_t nMockTimeIn) noexcept
{
    nMockTime = nMockTimeIn;
}

int64_t GetTimeMillis() noexcept
{
    return chrono::duration_cast<chrono::milliseconds>(
            chrono::system_clock::now().time_since_epoch()).count();
}

int64_t GetTimeMicros() noexcept
{
    return chrono::duration_cast<chrono::microseconds>(
            chrono::system_clock::now().time_since_epoch()).count();
}

void MilliSleep(int64_t n)
{
    this_thread::sleep_for(chrono::milliseconds(n));
}
