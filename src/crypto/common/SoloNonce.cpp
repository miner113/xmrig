/* XMRig
 * Copyright (c) 2018-2025 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2025 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include "crypto/common/SoloNonce.h"


#include <cstring>
#include <random>


#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
#   include <bcrypt.h>
#else
#   include <fstream>
#endif


namespace xmrig {


void SoloNonce::initialize(uint8_t* nonce32)
{
    // Fill with cryptographically secure random bytes
    if (!getRandomBytes(nonce32, 32)) {
        // Fallback to std::random_device if secure random fails
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist;

        for (int i = 0; i < 4; i++) {
            uint64_t val = dist(gen);
            std::memcpy(nonce32 + i * 8, &val, 8);
        }
    }

    // Clear bytes 0-1 (bottom 16 bits) for increment space
    nonce32[0] = 0;
    nonce32[1] = 0;

    // Clear bytes 30-31 (top 16 bits) for safety margin
    nonce32[30] = 0;
    nonce32[31] = 0;
}


void SoloNonce::increment(uint8_t* nonce32)
{
    // Full 256-bit little-endian increment with carry
    for (int i = 0; i < 32; ++i) {
        if (++nonce32[i] != 0) {
            break;
        }
    }
}


void SoloNonce::copyToBlob(uint8_t* blob, size_t offset, const uint8_t* nonce32)
{
    std::memcpy(blob + offset, nonce32, 32);
}


bool SoloNonce::getRandomBytes(uint8_t* buffer, size_t size)
{
#ifdef _WIN32
    // Windows: use BCryptGenRandom
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }
    status = BCryptGenRandom(hAlgorithm, buffer, static_cast<ULONG>(size), 0);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return BCRYPT_SUCCESS(status);
#else
    // Linux/macOS: use /dev/urandom
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom) {
        urandom.read(reinterpret_cast<char*>(buffer), size);
        return urandom.good();
    }
    return false;
#endif
}


} // namespace xmrig
