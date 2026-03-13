/********************************************************************
 *  ULT7Rock – Lattice‑based PoW (CUDA)
 *
 ********************************************************************/

#include <cuda_runtime.h>
#include <cuda.h>
#include <stdint.h>
#include "blake3.cu"                     

#define KNOX_N          1024u
#define KNOX_Q          12289u
#define N_INV           12277u               
#define PAD_IDX(i)      ((i) + ((i) >> 5))   

/* -----------------------------------------------------------------
 *  Fast Barrett reduction (Q = 12289)
 * ----------------------------------------------------------------- */
static __forceinline__ __device__ uint32_t barrett_reduce(uint32_t a) {
    const uint64_t mu = 349496ULL;               
    uint64_t t = ((uint64_t)a * mu) >> 32;       
    uint32_t r = a - (uint32_t)(t * KNOX_Q);
    if (r >= KNOX_Q) r -= KNOX_Q;
    return r;
}
static __forceinline__ __device__ uint32_t mul_mod(uint32_t a, uint32_t b) {
    return barrett_reduce((uint32_t)((uint64_t)a * b));
}

/* -----------------------------------------------------------------
 * Forward Negacyclic NTT (Warp-Synchronous: 32 Threads)
 * ----------------------------------------------------------------- */
static __device__ void ntt_forward_shared(uint32_t *poly,
                                          const uint32_t *twiddle,
                                          int lane_id)
{
    const int total_butterflies = KNOX_N / 2;   // 512
    int len = KNOX_N / 2;                       // 512, 256, ..., 1
    int twiddle_base = 1;

    while (len >= 1) {
        // 32 threads in the warp, each computing 16 butterflies per stage.
        for (int idx = lane_id; idx < total_butterflies; idx += 32) {
            int group = idx / len;
            int j     = idx % len;
            int start = group * 2 * len;

            int tw_idx = twiddle_base + group;
            uint32_t w = twiddle[PAD_IDX(tw_idx)];

            uint32_t u = poly[PAD_IDX(start + j)];
            uint32_t v = mul_mod(poly[PAD_IDX(start + j + len)], w);

            uint32_t sum = u + v;
            if (sum >= KNOX_Q) sum -= KNOX_Q;
            uint32_t diff = (u >= v) ? (u - v) : (u + KNOX_Q - v);

            poly[PAD_IDX(start + j)]       = sum;
            poly[PAD_IDX(start + j + len)] = diff;
        }
        __syncwarp(); // Hardware-level sync, zero block stalling.
        len >>= 1;
        twiddle_base <<= 1;
    }
}

/* -----------------------------------------------------------------
 * Inverse Negacyclic NTT (Warp-Synchronous: 32 Threads)
 * ----------------------------------------------------------------- */
static __device__ void ntt_inverse_shared(uint32_t *poly,
                                          const uint32_t *twiddle,
                                          int lane_id)
{
    int len = 1;

    while (len < KNOX_N) {
        // 32 threads, 16 butterflies each per stage.
        for (int idx = lane_id; idx < KNOX_N / 2; idx += 32) {
            int group = idx / len;
            int j     = idx % len;
            int start = KNOX_N - 2 * len * (group + 1);

            // Deterministic twiddle index in the same order as sequential k--.
            int stage_base = (KNOX_N / len) - 1;
            int k = stage_base - group;
            uint32_t w = twiddle[PAD_IDX(k)];

            uint32_t u = poly[PAD_IDX(start + j)];
            uint32_t v = poly[PAD_IDX(start + j + len)];

            uint32_t sum = u + v;
            if (sum >= KNOX_Q) sum -= KNOX_Q;
            uint32_t diff = (u >= v) ? (u - v) : (u + KNOX_Q - v);

            poly[PAD_IDX(start + j)]       = sum;
            poly[PAD_IDX(start + j + len)] = mul_mod(diff, w);
        }
        __syncwarp();
        len <<= 1;
    }

    // Scale by N^-1 (mod Q) cooperatively across the warp.
    for (int i = lane_id; i < KNOX_N; i += 32) {
        poly[PAD_IDX(i)] = mul_mod(poly[PAD_IDX(i)], N_INV);
    }
    __syncwarp();
}


/* -----------------------------------------------------------------
 *  Main PoW kernel – one CTA == one nonce
 * ----------------------------------------------------------------- */
extern "C"
__global__ void knox_full_offload(
    const uint8_t  *header_hash,      
    const uint32_t *a_hat_constant,   
    const uint32_t *twiddle_fwd,      
    const uint32_t *twiddle_inv,      
    uint64_t        base_nonce,
    uint32_t        steps,            
    uint32_t        difficulty_bits,
    uint64_t       *out_winning_nonce,
    uint32_t       *out_found_flag)
{
    /* -------------------------------------------------------------
     *  Shared memory (padded)
     * ------------------------------------------------------------- */
    __shared__ uint32_t poly_sh[KNOX_N + 32];         
    __shared__ uint32_t tw_fwd_sh[KNOX_N + 32];
    __shared__ uint32_t tw_inv_sh[KNOX_N + 32];
    __shared__ uint32_t a_hat_sh[KNOX_N + 32];
    __shared__ uint8_t  blake_xof_sh[KNOX_N];        
    __shared__ uint8_t  final_buf_sh[17 + 8 + 2*KNOX_N];
    __shared__ uint8_t  digest_sh[32];

    /* -------------------------------------------------------------
     *  0. Load constant tables into shared memory (coalesced)
     * ------------------------------------------------------------- */
    for (int i = threadIdx.x; i < KNOX_N; i += blockDim.x) {
        tw_fwd_sh[PAD_IDX(i)] = twiddle_fwd[i];
        tw_inv_sh[PAD_IDX(i)] = twiddle_inv[i];
        a_hat_sh[PAD_IDX(i)]  = a_hat_constant[i];
    }
    __syncthreads();

    /* -------------------------------------------------------------
     *  1. CTA‑wide nonce
     * ------------------------------------------------------------- */
    const uint64_t nonce = base_nonce + (uint64_t)blockIdx.x;

    /* -------------------------------------------------------------
     *  2. Blake‑3 XOF (seed = header_hash || nonce) – only thread 0
     * ------------------------------------------------------------- */
    if (threadIdx.x == 0) {
        uint8_t seed[40];
        #pragma unroll
        for (int i = 0; i < 32; ++i) seed[i] = header_hash[i];
        #pragma unroll
        for (int i = 0; i < 8; ++i) seed[32 + i] = (uint8_t)(nonce >> (8*i));

        device_blake3_hash(seed, 40, blake_xof_sh, KNOX_N);  
    }
    __syncthreads();   

    /* -------------------------------------------------------------
     *  3. Centered‑Binomial Distribution (CBD) – 
     * ------------------------------------------------------------- */
    const int warps_per_cta   = blockDim.x / 32;        
    const int lane_id        = threadIdx.x & 31;          
    const int warp_id        = threadIdx.x >> 5;          
    const int coeffs_per_warp = KNOX_N / warps_per_cta;   
    for (int idx = warp_id * coeffs_per_warp + lane_id;
         idx < (warp_id + 1) * coeffs_per_warp;
         idx += 32) {

        int byte_idx = idx >> 2;                
        int bit_off  = (idx & 3) << 1;          

        uint8_t byte1 = blake_xof_sh[byte_idx];          
        uint8_t byte2 = blake_xof_sh[512 + byte_idx];    

        
        int a = ((byte1 >> bit_off) & 1) + ((byte1 >> (bit_off + 1)) & 1);
        int b = ((byte2 >> bit_off) & 1) + ((byte2 >> (bit_off + 1)) & 1);
        int32_t coeff = a - b;                 // range [-2, 2]

        
        int32_t tmp = coeff + (int32_t)KNOX_Q;
        if (tmp >= (int32_t)KNOX_Q) {
            tmp -= (int32_t)KNOX_Q;
        }
        poly_sh[PAD_IDX(idx)] = (uint32_t)tmp;
    }
    __syncthreads();   

    /* -------------------------------------------------------------
     *  4. Forward NTT (already warp‑distributed)
     * ------------------------------------------------------------- */
    if (threadIdx.x < 32) {
        ntt_forward_shared(poly_sh, tw_fwd_sh, threadIdx.x);
    }
    __syncthreads();

    /* -------------------------------------------------------------
     *  5. Proof‑of‑Time loop – **warp‑distributed**
     * ------------------------------------------------------------- */
    for (uint32_t s = 0; s < steps; ++s) {
        
        for (int i = warp_id * coeffs_per_warp + lane_id;
             i < (warp_id + 1) * coeffs_per_warp;
             i += 32) {

            uint32_t val = mul_mod(poly_sh[PAD_IDX(i)], a_hat_sh[PAD_IDX(i)]);
            val ^= s;                                 
            poly_sh[PAD_IDX(i)] = barrett_reduce(val);
        }
        __syncthreads();   
    }

    /* -------------------------------------------------------------
     *  6. Inverse NTT (already warp‑distributed)
     * ------------------------------------------------------------- */
    if (threadIdx.x < 32) {
        ntt_inverse_shared(poly_sh, tw_inv_sh, threadIdx.x);
    }
    __syncthreads();

    /* -------------------------------------------------------------
     *  7. Serialize polynomial to little‑endian u16 array (2048 bytes)
     * ------------------------------------------------------------- */
    for (int i = threadIdx.x; i < KNOX_N; i += blockDim.x) {
        uint16_t coeff = (uint16_t)poly_sh[PAD_IDX(i)];
        final_buf_sh[17 + 8 + i*2]     = (uint8_t)(coeff & 0xFF);
        final_buf_sh[17 + 8 + i*2 + 1] = (uint8_t)(coeff >> 8);
    }

    /* -------------------------------------------------------------
     *  8. Build final hash input: "ult7rock-block-v1" || nonce || poly
     * ------------------------------------------------------------- */
    if (threadIdx.x == 0) {
        const char prefix[] = "ult7rock-block-v1";   
        #pragma unroll
        for (int i = 0; i < 17; ++i) final_buf_sh[i] = (uint8_t)prefix[i];
        #pragma unroll
        for (int i = 0; i < 8; ++i) final_buf_sh[17 + i] = (uint8_t)(nonce >> (8*i));
    }
    __syncthreads();

    /* -------------------------------------------------------------
     *  9. Blake‑3 hash of the whole payload → 32‑byte digest
     * ------------------------------------------------------------- */
    if (threadIdx.x == 0) {
        device_blake3_hash(final_buf_sh,
                           17 + 8 + 2*KNOX_N,  
                           digest_sh,
                           32);
    }
    __syncthreads();

    /* -------------------------------------------------------------
     * 10. Leading‑zero test & atomic win handling (only thread 0)
     * ------------------------------------------------------------- */
    if (threadIdx.x == 0) {
        uint32_t zero_bits = ::count_leading_zeros(digest_sh);
        if (zero_bits >= difficulty_bits) {
            if (atomicCAS(out_found_flag, 0, 1) == 0) {
                *out_winning_nonce = nonce;
            }
        }
    }
}

/* -----------------------------------------------------------------
 *  Host‑side wrapper – rebinding the CUDA context before launch.
 * ----------------------------------------------------------------- */
extern "C"
cudaError_t offload_mine(CUcontext cu_ctx,
                         const uint8_t *d_header_hash,
                         const uint32_t *d_a_hat_constant,
                         const uint32_t *d_twiddle_fwd,
                         const uint32_t *d_twiddle_inv,
                         uint64_t base_nonce,
                         uint32_t steps,
                         uint32_t difficulty_bits,
                         uint64_t *d_out_winning_nonce,
                         uint32_t *d_out_found_flag,
                         dim3 gridDim,
                         dim3 blockDim)
{
    CUresult rc = cuCtxSetCurrent(cu_ctx);
    if (rc != CUDA_SUCCESS) return cudaErrorUnknown;

    knox_full_offload<<<gridDim, blockDim>>>(
        d_header_hash,
        d_a_hat_constant,
        d_twiddle_fwd,
        d_twiddle_inv,
        base_nonce,
        steps,
        difficulty_bits,
        d_out_winning_nonce,
        d_out_found_flag);

    return cudaGetLastError();
}
