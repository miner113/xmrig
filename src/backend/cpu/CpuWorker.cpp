/* XMRig
 * Copyright (c) 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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

#include <cassert>
#include <thread>
#include <mutex>


#include "backend/cpu/Cpu.h"
#include "backend/cpu/CpuWorker.h"
#include "base/tools/Alignment.h"
#include "base/tools/Chrono.h"
#include "core/config/Config.h"
#include "core/Miner.h"
#include "crypto/cn/CnCtx.h"
#include "crypto/cn/CryptoNight_test.h"
#include "crypto/cn/CryptoNight.h"
#include "crypto/common/Nonce.h"
#include "crypto/common/VirtualMemory.h"
#include "crypto/rx/Rx.h"
#include "crypto/rx/RxCache.h"
#include "crypto/rx/RxDataset.h"
#include "crypto/rx/RxVm.h"
#include "crypto/ghostrider/ghostrider.h"
#include "net/JobResults.h"
#ifdef XMRIG_FEATURE_TLS
#   include <openssl/sha.h>
#else
// Standalone SHA-256 for non-TLS builds
#   ifdef _WIN32
#       include <windows.h>
#       include <bcrypt.h>
static void SHA256(const uint8_t* data, size_t len, uint8_t* out) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
    BCryptFinishHash(hHash, out, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}
#   else
#       include "crypto/ghostrider/sph_sha2.h"
static void SHA256(const uint8_t* data, size_t len, uint8_t* out) {
    sph_sha256_context ctx;
    sph_sha256_init(&ctx);
    sph_sha256(&ctx, data, len);
    sph_sha256_close(&ctx, out);
}
#   endif
#endif


#ifdef XMRIG_ALGO_RANDOMX
#   include "crypto/randomx/randomx.h"
#endif


#ifdef XMRIG_FEATURE_BENCHMARK
#   include "backend/common/benchmark/BenchState.h"
#endif


namespace xmrig {

static constexpr uint32_t kReserveCount = 32768;


// ── DRAGONX Cash PoW hash ────────────────────────────────────────────────────────
//
// DRAGONX block difficulty is checked against double_sha256(173-byte header),
// NOT the RandomX hash directly (unlike Monero).
//
// Full 173-byte header structure (from DRAGONX miner.cpp / miner.h):
//   [0:108]   header_base  = version(4) + prevhash(32) + merkle(32)
//                          + commitments(32) + time(4) + bits(4)
//   [108:140] nonce        = 32-byte miner nonce
//   [140]     0x20         = compact_size for 32-byte solution
//   [141:173] rx_solution  = RandomX hash result (32 bytes)
//
// This matches CBlockHeader::GetHash() in the DRAGONX daemon source.
//
// @param blob      140-byte header WITH nonce already at bytes [108:140]
// @param rx_hash   32-byte RandomX hash result
// @param out       32-byte output buffer for double_sha256
//



static inline void dragonx_pow_hash(const uint8_t* blob, const uint8_t* rx_hash, uint8_t* out)
{
    uint8_t full_header[173];
    memcpy(full_header,        blob,    140);   // header (108 bytes) + nonce (32 bytes)
    full_header[140] = 0x20;                    // compact_size = 32 (solution length)
    memcpy(full_header + 141,  rx_hash, 32);    // RandomX hash = the PoW solution

    // double SHA256 = SHA256(SHA256(full_header))
    uint8_t tmp[32];
    SHA256(full_header, 173, tmp);
    SHA256(tmp,          32, out);
}
// ─────────────────────────────────────────────────────────────────────────────


#ifdef XMRIG_ALGO_CN_HEAVY
static std::mutex cn_heavyZen3MemoryMutex;
VirtualMemory* cn_heavyZen3Memory = nullptr;
#endif

} // namespace xmrig



template<size_t N>
xmrig::CpuWorker<N>::CpuWorker(size_t id, const CpuLaunchData &data) :
    Worker(id, data.affinity, data.priority),
    m_algorithm(data.algorithm),
    m_assembly(data.assembly),
    m_hwAES(data.hwAES),
    m_yield(data.yield),
    m_av(data.av()),
    m_miner(data.miner),
    m_threads(data.threads),
    m_ctx()
{
#   ifdef XMRIG_ALGO_CN_HEAVY
    // cn-heavy optimization for Zen3 CPUs
    const auto arch = Cpu::info()->arch();
    const uint32_t model = Cpu::info()->model();
    const bool is_vermeer = (arch == ICpuInfo::ARCH_ZEN3) && (model == 0x21);
    const bool is_raphael = (arch == ICpuInfo::ARCH_ZEN4) && (model == 0x61);
    if ((N == 1) && (m_av == CnHash::AV_SINGLE) && (m_algorithm.family() == Algorithm::CN_HEAVY) && (m_assembly != Assembly::NONE) && (is_vermeer || is_raphael)) {
        std::lock_guard<std::mutex> lock(cn_heavyZen3MemoryMutex);
        if (!cn_heavyZen3Memory) {
            // Round up number of threads to the multiple of 8
            const size_t num_threads = ((m_threads + 7) / 8) * 8;
            cn_heavyZen3Memory = new VirtualMemory(m_algorithm.l3() * num_threads, data.hugePages, false, false, node(), VirtualMemory::kDefaultHugePageSize);
        }
        m_memory = cn_heavyZen3Memory;
    }
    else
#   endif
    {
        m_memory = new VirtualMemory(m_algorithm.l3() * N, data.hugePages, false, true, node(), VirtualMemory::kDefaultHugePageSize);
    }

#   ifdef XMRIG_ALGO_GHOSTRIDER
    m_ghHelper = ghostrider::create_helper_thread(affinity(), data.priority, data.affinities);
#   endif
}


template<size_t N>
xmrig::CpuWorker<N>::~CpuWorker()
{
#   ifdef XMRIG_ALGO_RANDOMX
    RxVm::destroy(m_vm);
#   endif

    CnCtx::release(m_ctx, N);

#   ifdef XMRIG_ALGO_CN_HEAVY
    if (m_memory != cn_heavyZen3Memory)
#   endif
    {
        delete m_memory;
    }

#   ifdef XMRIG_ALGO_GHOSTRIDER
    ghostrider::destroy_helper_thread(m_ghHelper);
#   endif
}


#ifdef XMRIG_ALGO_RANDOMX
template<size_t N>
void xmrig::CpuWorker<N>::allocateRandomX_VM()
{
    RxDataset *dataset = Rx::dataset(m_job.currentJob(), node());

    while (dataset == nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        if (Nonce::sequence(Nonce::CPU) == 0) {
            return;
        }

        dataset = Rx::dataset(m_job.currentJob(), node());
    }

    if (!m_vm) {
        // Try to allocate scratchpad from dataset's 1 GB huge pages, if normal huge pages are not available
        uint8_t* scratchpad = m_memory->isHugePages() ? m_memory->scratchpad() : dataset->tryAllocateScrathpad();
        m_vm = RxVm::create(dataset, scratchpad ? scratchpad : m_memory->scratchpad(), !m_hwAES, m_assembly, node());
    }
    else if (!dataset->get() && (m_job.currentJob().seed() != m_seed)) {
        // Update RandomX light VM with the new seed
        randomx_vm_set_cache(m_vm, dataset->cache()->get());
    }
    m_seed = m_job.currentJob().seed();
}
#endif


template<size_t N>
bool xmrig::CpuWorker<N>::selfTest()
{
#   ifdef XMRIG_ALGO_RANDOMX
    if (m_algorithm.family() == Algorithm::RANDOM_X) {
        return N == 1;
    }
#   endif

    allocateCnCtx();

#   ifdef XMRIG_ALGO_GHOSTRIDER
    if (m_algorithm.family() == Algorithm::GHOSTRIDER) {
        return (N == 8) && verify(Algorithm::GHOSTRIDER_RTM, test_output_gr);
    }
#   endif

    if (m_algorithm.family() == Algorithm::CN) {
        const bool rc = verify(Algorithm::CN_0,      test_output_v0)   &&
                        verify(Algorithm::CN_1,      test_output_v1)   &&
                        verify(Algorithm::CN_2,      test_output_v2)   &&
                        verify(Algorithm::CN_FAST,   test_output_msr)  &&
                        verify(Algorithm::CN_XAO,    test_output_xao)  &&
                        verify(Algorithm::CN_RTO,    test_output_rto)  &&
                        verify(Algorithm::CN_HALF,   test_output_half) &&
                        verify2(Algorithm::CN_R,     test_output_r)    &&
                        verify(Algorithm::CN_RWZ,    test_output_rwz)  &&
                        verify(Algorithm::CN_ZLS,    test_output_zls)  &&
                        verify(Algorithm::CN_CCX,    test_output_ccx)  &&
                        verify(Algorithm::CN_DOUBLE, test_output_double);

        return rc;
    }

#   ifdef XMRIG_ALGO_CN_LITE
    if (m_algorithm.family() == Algorithm::CN_LITE) {
        return verify(Algorithm::CN_LITE_0,    test_output_v0_lite) &&
               verify(Algorithm::CN_LITE_1,    test_output_v1_lite);
    }
#   endif

#   ifdef XMRIG_ALGO_CN_HEAVY
    if (m_algorithm.family() == Algorithm::CN_HEAVY) {
        return verify(Algorithm::CN_HEAVY_0,    test_output_v0_heavy)  &&
               verify(Algorithm::CN_HEAVY_XHV,  test_output_xhv_heavy) &&
               verify(Algorithm::CN_HEAVY_TUBE, test_output_tube_heavy);
    }
#   endif

#   ifdef XMRIG_ALGO_CN_PICO
    if (m_algorithm.family() == Algorithm::CN_PICO) {
        return verify(Algorithm::CN_PICO_0, test_output_pico_trtl) &&
               verify(Algorithm::CN_PICO_TLO, test_output_pico_tlo);
    }
#   endif

#   ifdef XMRIG_ALGO_CN_FEMTO
    if (m_algorithm.family() == Algorithm::CN_FEMTO) {
        return verify(Algorithm::CN_UPX2, test_output_femto_upx2);
    }
#   endif

#   ifdef XMRIG_ALGO_ARGON2
    if (m_algorithm.family() == Algorithm::ARGON2) {
        return verify(Algorithm::AR2_CHUKWA, argon2_chukwa_test_out) &&
               verify(Algorithm::AR2_CHUKWA_V2, argon2_chukwa_v2_test_out) &&
               verify(Algorithm::AR2_WRKZ, argon2_wrkz_test_out);
    }
#   endif

    return false;
}


template<size_t N>
void xmrig::CpuWorker<N>::hashrateData(uint64_t &hashCount, uint64_t &, uint64_t &rawHashes) const
{
    hashCount = m_count;
    rawHashes = m_count;
}


template<size_t N>
void xmrig::CpuWorker<N>::start()
{
    while (Nonce::sequence(Nonce::CPU) > 0) {
        if (Nonce::isPaused()) {
            do {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            while (Nonce::isPaused() && Nonce::sequence(Nonce::CPU) > 0);

            if (Nonce::sequence(Nonce::CPU) == 0) {
                break;
            }

            consumeJob();
        }

#       ifdef XMRIG_ALGO_RANDOMX
        bool first = true;
        alignas(16) uint64_t tempHash[8] = {};
#       endif

        while (!Nonce::isOutdated(Nonce::CPU, m_job.sequence())) {
            const Job &job = m_job.currentJob();

            if (job.algorithm().l3() != m_algorithm.l3()) {
                break;
            }

            uint32_t current_job_nonces[N];
            alignas(8) uint8_t current_solo_nonces[N * 32];
            for (size_t i = 0; i < N; ++i) {
                current_job_nonces[i] = readUnaligned(m_job.nonce(i));
                // Save solo nonces BEFORE they get incremented by nextRound()
                if (m_job.isSoloMining()) {
                    memcpy(current_solo_nonces + i * 32, m_job.soloNonce(i), 32);
                }
                // For RX_DRAGONX stratum, also save full 32-byte nonce from blob
                // (proxy may have set fixed byte that we need to preserve)
                else if (job.algorithm() == Algorithm::RX_DRAGONX) {
                    memcpy(current_solo_nonces + i * 32, m_job.blob() + m_job.nonceOffset() + i * job.size(), 32);
                }
            }

#           ifdef XMRIG_FEATURE_BENCHMARK
            if (m_benchSize) {
                if (current_job_nonces[0] >= m_benchSize) {
                    return BenchState::done();
                }

                // Make each hash dependent on the previous one in single thread benchmark to prevent cheating with multiple threads
                if (m_threads == 1) {
                    *(uint64_t*)(m_job.blob()) ^= BenchState::data();
                }
            }
#           endif

            bool valid = true;

            uint8_t miner_signature_saved[64];

#           ifdef XMRIG_ALGO_RANDOMX
            uint8_t* miner_signature_ptr = m_job.blob() + m_job.nonceOffset() + m_job.nonceSize();
            if (job.algorithm().family() == Algorithm::RANDOM_X) {
                if (first) {
                    first = false;
                    if (job.hasMinerSignature()) {
                        job.generateMinerSignature(m_job.blob(), job.size(), miner_signature_ptr);
                    }
                    randomx_calculate_hash_first(m_vm, tempHash, m_job.blob(), job.size());
                }

                if (!nextRound()) {
                    break;
                }

                if (job.hasMinerSignature()) {
                    memcpy(miner_signature_saved, miner_signature_ptr, sizeof(miner_signature_saved));
                    job.generateMinerSignature(m_job.blob(), job.size(), miner_signature_ptr);
                }
                randomx_calculate_hash_next(m_vm, tempHash, m_job.blob(), job.size(), m_hash);
            }
            else
#           endif
            {
                switch (job.algorithm().family()) {

#               ifdef XMRIG_ALGO_GHOSTRIDER
                case Algorithm::GHOSTRIDER:
                    if (N == 8) {
                        ghostrider::hash_octa(m_job.blob(), job.size(), m_hash, m_ctx, m_ghHelper);
                    }
                    else {
                        valid = false;
                    }
                    break;
#               endif

                default:
                    fn(job.algorithm())(m_job.blob(), job.size(), m_hash, m_ctx, job.height());
                    break;
                }

                if (!nextRound()) {
                    break;
                };
            }

            if (valid) {
                for (size_t i = 0; i < N; ++i) {
                    const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24);
					
#                   ifdef XMRIG_FEATURE_BENCHMARK
                    if (m_benchSize) {
						
                        if (current_job_nonces[i] < m_benchSize) {
                            BenchState::add(value);
                        }
                        continue;
                    }
#                   endif

                    if (job.algorithm() == Algorithm::RX_DRAGONX) {
                        // ── DRAGONX: use double_sha256(173-byte header) for difficulty ──
                        //
                        // The DRAGONX daemon checks GetHash() = double_sha256(173 bytes) < target,
                        // NOT the RandomX hash directly. We must filter shares the same way
                        // so that every submitted share is a genuine block candidate.
                        //
                        // Reconstruct the 140-byte blob that was ACTUALLY hashed this round:
                        //   - bytes  [0:108] are unchanged by nextRound() (only nonce changes)
                        //   - bytes [108:140] = saved nonce (current_solo_nonces, before nextRound)
                        uint8_t blob_for_header[140];
                        memcpy(blob_for_header,       m_job.blob(),                    108); // header base (unchanged)
                        memcpy(blob_for_header + 108, current_solo_nonces + i * 32,    32);  // saved 32-byte nonce

                        // Compute DRAGONX PoW hash: double_sha256(blob[140] + 0x20 + rx_hash[32])
                        alignas(8) uint8_t pow_hash[32];
                        dragonx_pow_hash(blob_for_header, m_hash + (i * 32), pow_hash);

                        // Compare last 8 bytes of pow_hash (same field as XMRig's standard check)
                        const uint64_t pow_value = *reinterpret_cast<uint64_t*>(pow_hash + 24);
                        if (pow_value < job.target()) {
                            // Submit full 32-byte nonce + rx_hash as result
                            // Pool validates: randomx(blob, seed) == rx_hash (PoW authenticity)
                            // Pool also checks: double_sha256(173 bytes) < networkTarget (block detection)
                            JobResults::submit(JobResult(job, current_solo_nonces + i * 32, m_hash + (i * 32)));
                        }
                    } else {
                        // ── Standard XMRig path (Monero, CryptoNight, etc.) ──
                        const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24);
                        if (value < job.target()) {
                            if (m_job.isSoloMining()) {
                                // Solo mining: submit with full 256-bit nonce
                                JobResults::submit(JobResult(job, current_solo_nonces + i * 32, m_hash + (i * 32)));
                            } else {
                                JobResults::submit(job, current_job_nonces[i], m_hash + (i * 32), job.hasMinerSignature() ? miner_signature_saved : nullptr);
                            }
                        }
                    }
                }
                m_count += N;
            }

            if (m_yield) {
                std::this_thread::yield();
            }
        }

        if (!Nonce::isPaused()) {
            consumeJob();
        }
    }
}


template<size_t N>
bool xmrig::CpuWorker<N>::nextRound()
{
    // Solo mining uses its own 256-bit nonce management
    if (m_job.isSoloMining()) {
        return m_job.nextRoundSolo();
    }

#   ifdef XMRIG_FEATURE_BENCHMARK
    const uint32_t count = m_benchSize ? 1U : kReserveCount;
#   else
    constexpr uint32_t count = kReserveCount;
#   endif

    if (!m_job.nextRound(count, 1)) {
        JobResults::done(m_job.currentJob());

        return false;
    }

    return true;
}


template<size_t N>
bool xmrig::CpuWorker<N>::verify(const Algorithm &algorithm, const uint8_t *referenceValue)
{
#   ifdef XMRIG_ALGO_GHOSTRIDER
    if (algorithm == Algorithm::GHOSTRIDER_RTM) {
        uint8_t blob[N * 80] = {};
        for (size_t i = 0; i < N; ++i) {
            blob[i * 80 + 0] = static_cast<uint8_t>(i);
            blob[i * 80 + 4] = 0x10;
            blob[i * 80 + 5] = 0x02;
        }

        uint8_t hash1[N * 32] = {};
        ghostrider::hash_octa(blob, 80, hash1, m_ctx, 0, false);

        for (size_t i = 0; i < N; ++i) {
            blob[i * 80 + 0] = static_cast<uint8_t>(i);
            blob[i * 80 + 4] = 0x43;
            blob[i * 80 + 5] = 0x05;
        }

        uint8_t hash2[N * 32] = {};
        ghostrider::hash_octa(blob, 80, hash2, m_ctx, 0, false);

        for (size_t i = 0; i < N * 32; ++i) {
            if ((hash1[i] ^ hash2[i]) != referenceValue[i]) {
                return false;
            }
        }

        return true;
    }
#   endif

    cn_hash_fun func = fn(algorithm);
    if (!func) {
        return false;
    }

    func(test_input, 76, m_hash, m_ctx, 0);
    return memcmp(m_hash, referenceValue, sizeof m_hash) == 0;
}


template<size_t N>
bool xmrig::CpuWorker<N>::verify2(const Algorithm &algorithm, const uint8_t *referenceValue)
{
    cn_hash_fun func = fn(algorithm);
    if (!func) {
        return false;
    }

    for (size_t i = 0; i < (sizeof(cn_r_test_input) / sizeof(cn_r_test_input[0])); ++i) {
        const size_t size = cn_r_test_input[i].size;
        for (size_t k = 0; k < N; ++k) {
            memcpy(m_job.blob() + (k * size), cn_r_test_input[i].data, size);
        }

        func(m_job.blob(), size, m_hash, m_ctx, cn_r_test_input[i].height);

        for (size_t k = 0; k < N; ++k) {
            if (memcmp(m_hash + k * 32, referenceValue + i * 32, sizeof m_hash / N) != 0) {
                return false;
            }
        }
    }

    return true;
}


namespace xmrig {

template<>
bool CpuWorker<1>::verify2(const Algorithm &algorithm, const uint8_t *referenceValue)
{
    cn_hash_fun func = fn(algorithm);
    if (!func) {
        return false;
    }

    for (size_t i = 0; i < (sizeof(cn_r_test_input) / sizeof(cn_r_test_input[0])); ++i) {
        func(cn_r_test_input[i].data, cn_r_test_input[i].size, m_hash, m_ctx, cn_r_test_input[i].height);

        if (memcmp(m_hash, referenceValue + i * 32, sizeof m_hash) != 0) {
            return false;
        }
    }

    return true;
}

} // namespace xmrig


template<size_t N>
void xmrig::CpuWorker<N>::allocateCnCtx()
{
    if (m_ctx[0] == nullptr) {
        int shift = 0;

#       ifdef XMRIG_ALGO_CN_HEAVY
        // cn-heavy optimization for Zen3 CPUs
        if (m_memory == cn_heavyZen3Memory) {
            shift = (id() / 8) * m_algorithm.l3() * 8 + (id() % 8) * 64;
        }
#       endif

        CnCtx::create(m_ctx, m_memory->scratchpad() + shift, m_algorithm.l3(), N);
    }
}


template<size_t N>
void xmrig::CpuWorker<N>::consumeJob()
{
    if (Nonce::sequence(Nonce::CPU) == 0) {
        return;
    }

    auto job = m_miner->job();

#   ifdef XMRIG_FEATURE_BENCHMARK
    m_benchSize          = job.benchSize();
    const uint32_t count = m_benchSize ? 1U : kReserveCount;
#   else
    constexpr uint32_t count = kReserveCount;
#   endif

    m_job.add(job, count, Nonce::CPU);

    // Handle solo mining nonce initialization
    if (job.isSoloMining()) {
        m_job.setSoloMining(true);
        m_job.initSoloNonces();
    } else {
        m_job.setSoloMining(false);
    }

#   ifdef XMRIG_ALGO_RANDOMX
    if (m_job.currentJob().algorithm().family() == Algorithm::RANDOM_X) {
        allocateRandomX_VM();
    }
    else
#   endif
    {
        allocateCnCtx();
    }
}


namespace xmrig {

template class CpuWorker<1>;
template class CpuWorker<2>;
template class CpuWorker<3>;
template class CpuWorker<4>;
template class CpuWorker<5>;
template class CpuWorker<8>;

} // namespace xmrig

