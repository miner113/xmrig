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

#ifndef XMRIG_SOLONONCE_H
#define XMRIG_SOLONONCE_H


#include <cstdint>
#include <cstddef>


namespace xmrig {


/**
 * Solo mining nonce utilities for 256-bit (32-byte) nonces.
 *
 * Collision avoidance strategy:
 * 1. Generate cryptographically random 256-bit nonce
 * 2. Clear bytes 0-1 (bits 0-15) - reserved for increment space
 * 3. Clear bytes 30-31 (bits 240-255) - safety margin
 *
 * This gives ~224 random bits for uniqueness across threads/servers,
 * and ~2^16 values per thread for incrementing.
 * Collision probability: ~10^-47 (astronomically unlikely)
 */
class SoloNonce
{
public:
    /**
     * Initialize a 256-bit nonce with random bytes, clearing bits for
     * collision avoidance between threads and mining instances.
     *
     * @param nonce32 Pointer to 32-byte buffer to initialize
     */
    static void initialize(uint8_t* nonce32);

    /**
     * Increment a full 256-bit nonce in little-endian byte order.
     *
     * @param nonce32 Pointer to 32-byte buffer to increment
     */
    static void increment(uint8_t* nonce32);

    /**
     * Copy a 256-bit nonce to a blob at the specified offset.
     *
     * @param blob     Destination blob
     * @param offset   Offset within blob where nonce should be written
     * @param nonce32  Source 32-byte nonce
     */
    static void copyToBlob(uint8_t* blob, size_t offset, const uint8_t* nonce32);

private:
    /**
     * Fill buffer with cryptographically secure random bytes.
     * Uses platform-specific secure random:
     * - Windows: BCryptGenRandom
     * - Linux/macOS: /dev/urandom
     *
     * @param buffer  Buffer to fill
     * @param size    Number of bytes to fill
     * @return true on success, false on failure
     */
    static bool getRandomBytes(uint8_t* buffer, size_t size);
};


} // namespace xmrig


#endif /* XMRIG_SOLONONCE_H */
