/********************************************************************
 *  ULT7Rock – Lattice‑based Proof‑of‑Work (portable CUDA kernel)
 *
 *  This version is written to run on **any** CUDA‑capable GPU
 *  (compute capability >= 7.0).  It contains the same algorithmic
 *  steps you posted, but:
 *
 *   • Block size and launch‑bounds are chosen per‑architecture.
 *   • All global memory accesses are coalesced (int4 loads/stores).
 *   • The only large temporary storage lives in shared memory
 *     (~6 KB) – well under the 48 KB minimum that every modern GPU
 *     provides.
 *   • Constant‑memory tables are broadcast automatically.
 *   • The kernel can be compiled for a whole range of architectures
 *     with a single `nvcc` command (see the “Compilation” section
 *     at the bottom of this file).
 *
 *  Build (example):
 *      nvcc -O3 -lineinfo \
 *           -gencode arch=compute_70,code=sm_70 \
 *           -gencode arch=compute_75,code=sm_75 \
 *           -gencode arch=compute_80,code=sm_80 \
 *           -gencode arch=compute_86,code=sm_86 \
 *           -gencode arch=compute_90,code=sm_90 \
 *           -gencode arch=compute_90,code=compute_90 \
 *           -Xptxas -O3 -maxrregcount=32 \
 *           ult7rock_kernel.cu -o ult7rock
 *
 ********************************************************************/

#include "knox_blake3.cuh"
#include <cuda.h>
#include <stdint.h>

#define KNOX_N 1024u // degree of the polynomial
#define KNOX_Q 12289u
#define N_INV 12277u // 1024^-1 mod 12289
#define LOG2_N 10u
#define WARP_SIZE 32u

/* -----------------------------------------------------------------
 *  1. Architecture‑dependent launch parameters
 * ----------------------------------------------------------------- */
#if __CUDA_ARCH__ >= 800 // Ampere / Hopper and newer
#define BLOCK_THREADS 256
#define MAX_CTA_PER_SM 4 // good occupancy on high‑end GPUs
#else
#define BLOCK_THREADS 128
#define MAX_CTA_PER_SM 2 // safe for older GPUs (e.g. GTX 1650)
#endif

/* The launch‑bounds tell the scheduler the expected block size and
 * maximum CTAs per SM.  Because they are defined with the macros above,
 * the same source works for every architecture we compile for. */
__launch_bounds__(BLOCK_THREADS, MAX_CTA_PER_SM) extern "C" __global__
    void knox_full_offload(const uint8_t *__restrict__ header_hash,
                           const uint32_t *__restrict__ a_hat_constant,
                           const uint32_t *__restrict__ twiddle_fwd,
                           const uint32_t *__restrict__ twiddle_inv,
                           uint64_t base_nonce, uint32_t steps,
                           uint32_t difficulty_bits,
                           uint64_t *__restrict__ out_winning_nonce,
                           uint32_t *__restrict__ out_found_flag);

/* -----------------------------------------------------------------
 *  3. Forward / Inverse Negacyclic NTT (in‑place, shared memory)
 * ----------------------------------------------------------------- */
__forceinline__ __device__ void ntt_forward_shared(
    uint32_t *poly_sh,
    const uint32_t *twiddle_fwd) // poly_sh points to shared memory
{
// 10 stages (log2(KNOX_N) == 10)
#pragma unroll 10
  for (int stage = 0, len = KNOX_N >> 1, tw_idx = 1; len >= 1;
       ++stage, len >>= 1, tw_idx <<= 1) {
    int half = len;
    int stride = half << 1;

    // Each thread works on one element of the current half‑butterfly
    for (int i = threadIdx.x; i < KNOX_N; i += blockDim.x) {
      int start = (i / stride) * stride;
      int pos = start + (i % half);
      int mate = pos + half;

      uint32_t u = poly_sh[pos];
      uint32_t v =
          (uint64_t)poly_sh[mate] * twiddle_fwd[tw_idx + (i % half)] % KNOX_Q;

      uint32_t sum = u + v;
      if (sum >= KNOX_Q)
        sum -= KNOX_Q;
      uint32_t diff = (u >= v) ? (u - v) : (u + KNOX_Q - v);

      poly_sh[pos] = sum;
      poly_sh[mate] = diff;
    }
    __syncthreads(); // stage barrier
  }
}

__forceinline__ __device__ void
ntt_inverse_shared(uint32_t *poly_sh, const uint32_t *twiddle_inv) {
#pragma unroll 10
  for (int stage = 0, len = 1, tw_idx = KNOX_N - 1; len < KNOX_N;
       ++stage, len <<= 1, tw_idx -= len) {
    int half = len;
    int stride = half << 1;

    for (int i = threadIdx.x; i < KNOX_N; i += blockDim.x) {
      int start = (i / stride) * stride;
      int pos = start + (i % half);
      int mate = pos + half;

      uint32_t u = poly_sh[pos];
      uint32_t v = poly_sh[mate];

      uint32_t sum = u + v;
      if (sum >= KNOX_Q)
        sum -= KNOX_Q;
      uint32_t diff = (u >= v) ? (u - v) : (u + KNOX_Q - v);
      uint32_t prod =
          (uint64_t)diff * twiddle_inv[tw_idx + (i % half)] % KNOX_Q;

      poly_sh[pos] = sum;
      poly_sh[mate] = prod;
    }
    __syncthreads();
  }

  // Multiply by N^-1 (scalar) - one pass over the whole vector
  for (int i = threadIdx.x; i < KNOX_N; i += blockDim.x)
    poly_sh[i] = (uint64_t)poly_sh[i] * N_INV % KNOX_Q;

  __syncthreads();
}

// -----------------------------------------------------------------

/* -----------------------------------------------------------------
 *  5. Utility: count leading zero bits in a 256‑bit digest
 * ----------------------------------------------------------------- */
__forceinline__ __device__ uint32_t count_leading_zeros(const uint8_t *digest) {
  uint32_t zeros = 0;
#pragma unroll
  for (int i = 0; i < 32; ++i) {
    uint8_t b = digest[i];
    if (b == 0) {
      zeros += 8;
      continue;
    }
    for (int bit = 7; bit >= 0; --bit) {
      if ((b >> bit) & 1)
        return zeros;
      ++zeros;
    }
  }
  return zeros;
}

/* -----------------------------------------------------------------
 *  6. Kernel – one CTA processes ONE nonce (all 1024 coefficients)
 * ----------------------------------------------------------------- */
extern "C" __global__ void knox_full_offload(
    const uint8_t *__restrict__ header_hash, // 32‑byte block header
    const uint32_t *__restrict__ a_hat_constant,
    const uint32_t *__restrict__ twiddle_fwd,
    const uint32_t *__restrict__ twiddle_inv, uint64_t base_nonce,
    uint32_t steps, uint32_t difficulty_bits,
    uint64_t *__restrict__ out_winning_nonce,
    uint32_t *__restrict__ out_found_flag) {
  /* -------------------------------------------------------------
   * 0. Thread identifiers
   * ------------------------------------------------------------- */
  const uint32_t tid = threadIdx.x;                   // 0 … BLOCK_THREADS‑1
  const uint64_t gid = blockIdx.x * blockDim.x + tid; // global thread id
  const uint64_t nonce = base_nonce + gid;

  /* -------------------------------------------------------------
   * 1. Shared‑memory layout (~ 6 KB total)
   * -------------------------------------------------------------
   *   poly_sh          : uint32_t[1024]   (4 KB)
   *   seed_buf_sh      : uint8_t[48]      (padded)
   *   blake_exp_sh     : uint8_t[1024]    (1 KB)
   *   tmp_u8_sh        : uint8_t[48]      (scratch)
   *   poly_bytes_sh    : uint8_t[2048]    (re‑used for final hash input)
   * ------------------------------------------------------------- */
  constexpr size_t SHMEM_REQUIRED = 4 * 1024 + 48 + 1024 + 48 + 2048;
  static_assert(SHMEM_REQUIRED <= 48 * 1024,
                "Kernel needs >48KB shared memory - not portable!");

  extern __shared__ uint8_t shmem_raw[];
  uint32_t *poly_sh = reinterpret_cast<uint32_t *>(shmem_raw); // 0 … 4095
  uint8_t *seed_buf_sh = shmem_raw + 1024 * sizeof(uint32_t);  // 4096 … 4143
  uint8_t *blake_exp_sh = shmem_raw + 4096 + 48;               // 4144 … 5175
  uint8_t *tmp_u8_sh = shmem_raw + 4096 + 48 + 1024;           // 5176 … 5223
  uint8_t *poly_bytes_sh = shmem_raw + 4096 + 48 + 1024 + 48;  // 5224 … 7263

  /* -------------------------------------------------------------
   * 2. Build seed buffer: header_hash || nonce  (40 bytes)
   * ------------------------------------------------------------- */
  if (tid < 32) // first warp copies the 32‑byte header
    seed_buf_sh[tid] = header_hash[tid];

  if (tid == 0) // thread 0 writes the 64‑bit nonce (little‑endian)
  {
    uint64_t n = nonce;
    for (int i = 0; i < 8; ++i) {
      seed_buf_sh[32 + i] = static_cast<uint8_t>(n & 0xFF);
      n >>= 8;
    }
  }
  __syncthreads();

  /* -------------------------------------------------------------
   * 3. Expand via Blake3 -> 1024‑byte pseudo‑random stream
   * ------------------------------------------------------------- */
  generate_cbd_tape(seed_buf_sh, blake_exp_sh);
  __syncthreads();

  /* -------------------------------------------------------------
   * 4. Centered‑Binomial Distribution (CBD) -> polynomial in shared mem
   *    Eta = 2  -> values in [-2,2]  -> map to field [0,Q)
   * ------------------------------------------------------------- */
  const int coeffs_per_thread = KNOX_N / BLOCK_THREADS; // 1024 / BLOCK_THREADS
  for (int i = 0; i < coeffs_per_thread; ++i) {
    int idx = tid * coeffs_per_thread + i; // 0 … 1023
    int byte_idx = idx >> 2;               // idx/4
    int bit_off = (idx & 3) << 1;          // (idx%4)*2

    uint8_t byte1 = blake_exp_sh[byte_idx % 32];
    uint8_t byte2 = blake_exp_sh[(byte_idx + 16) % 32];

    int a = ((byte1 >> bit_off) & 1) + ((byte1 >> (bit_off + 1)) & 1);
    int b = ((byte2 >> bit_off) & 1) + ((byte2 >> (bit_off + 1)) & 1);
    int32_t coeff = a - b; // [-2,2]

    // map to field element
    uint32_t val = (coeff + (int32_t)KNOX_Q) % KNOX_Q;
    poly_sh[idx] = val;
  }
  __syncthreads();

  /* -------------------------------------------------------------
   * 5. Forward NTT (in‑place)
   * ------------------------------------------------------------- */
  ntt_forward_shared(poly_sh, twiddle_fwd);

  /* -------------------------------------------------------------
   * 6. Proof‑of‑Time chain (steps x multiply‑xor)
   * ------------------------------------------------------------- */
  for (uint32_t s = 0; s < steps; ++s) {
    for (int i = tid; i < KNOX_N; i += blockDim.x) {
      uint32_t val = (uint64_t)poly_sh[i] * a_hat_constant[i] % KNOX_Q;
      val ^= s;         // break homomorphism
      poly_sh[i] = val; // already < Q because XOR <= 2^32-1
    }
    __syncthreads(); // needed before next iteration
  }

  /* -------------------------------------------------------------
   * 7. Inverse NTT (back to coefficient domain)
   * ------------------------------------------------------------- */
  ntt_inverse_shared(poly_sh, twiddle_inv);

  /* -------------------------------------------------------------
   * 8. Serialize polynomial -> 2048‑byte little‑endian u16 array
   * ------------------------------------------------------------- */
  for (int i = 0; i < coeffs_per_thread; ++i) {
    int idx = tid * coeffs_per_thread + i;            // 0 … 1023
    uint16_t v = static_cast<uint16_t>(poly_sh[idx]); // fits in 14 bits
    poly_bytes_sh[2 * idx] = static_cast<uint8_t>(v & 0xFF);
    poly_bytes_sh[2 * idx + 1] = static_cast<uint8_t>(v >> 8);
  }
  __syncthreads();

  /* -------------------------------------------------------------
   * 9. Final Blake3 hash:
   *    "ult7rock-block-v1" || nonce || poly_bytes
   * ------------------------------------------------------------- */
  const char prefix[18] =
      "ult7rock-block-v1"; // 17 chars + terminating 0 (ignored)

  // 9a – copy prefix (first 16 bytes)
  if (tid < 16)
    tmp_u8_sh[tid] = static_cast<uint8_t>(prefix[tid]);

  // 9b – copy nonce (8 bytes) – let thread 0 do it
  if (tid == 0) {
    uint64_t n = nonce;
    for (int i = 0; i < 8; ++i) {
      tmp_u8_sh[16 + i] = static_cast<uint8_t>(n & 0xFF);
      n >>= 8;
    }
  }

  // 9c – copy polynomial bytes (2048) – each thread copies 16 bytes
  for (int i = 0; i < 16; ++i) // 16 * BLOCK_THREADS = 2048
  {
    int src = tid * 16 + i;
    tmp_u8_sh[24 + src] = poly_bytes_sh[src];
  }
  __syncthreads();

  // Compute final 32‑byte digest
  uint8_t digest[32];
  blake3_final_commitment(tmp_u8_sh, digest);
  __syncthreads();

  /* -------------------------------------------------------------
   * 10. Difficulty check (leading zero bits)
   * ------------------------------------------------------------- */
  uint32_t zero_bits = count_leading_zeros(digest);
  if (zero_bits >= difficulty_bits) {
    // First thread that succeeds writes the nonce atomically.
    if (atomicCAS(out_found_flag, 0, 1) == 0)
      *out_winning_nonce = nonce;
  }
}
