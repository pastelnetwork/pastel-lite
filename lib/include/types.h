#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <vector>
#include <string>

// It is not clear how to port secure_allocator to WASM ready code.
// The secure_allocator is a custom allocator that zeroes out memory before freeing it and locks the memory in RAM.

// typedef std::basic_string<char, std::char_traits<char>, secure_allocator<char> > SecureString;
typedef std::string SecureString;

// typedef std::vector<unsigned char, secure_allocator<unsigned char>> SecureVector;
typedef std::vector<unsigned char> SecureVector;

// typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
typedef std::vector<unsigned char> CKeyingMaterial;
