#pragma once
#include <stdint.h>
#include <string.h>

#define IV0 0x6A09E667
#define IV1 0xBB67AE85
#define IV2 0x3C6EF372
#define IV3 0xA54FF53A
#define IV4 0x510E527F
#define IV5 0x9B05688C
#define IV6 0x1F83D9AB
#define IV7 0x5BE0CD19

#define CHUNK_START (1 << 0)
#define CHUNK_END (1 << 1)
#define PARENT (1 << 2)
#define ROOT (1 << 3)

__constant__ uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 11, 5, 0, 9, 15, 8, 1},
    {10, 7, 12, 5, 14, 3, 13, 15, 4, 11, 0, 2, 9, 8, 1, 6},
    {12, 13, 5, 0, 15, 10, 14, 8, 7, 11, 2, 3, 9, 1, 6, 4},
    {5, 14, 0, 2, 8, 12, 15, 1, 13, 11, 3, 10, 9, 6, 4, 7},
    {0, 15, 2, 3, 1, 5, 8, 6, 14, 11, 10, 12, 9, 4, 7, 13}};

__device__ __forceinline__ uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ void g(uint32_t *state, int a, int b, int c, int d,
                                  uint32_t mx, uint32_t my) {
  state[a] = state[a] + state[b] + mx;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + my;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 7);
}

__device__ __forceinline__ void round_fn(uint32_t *state, const uint32_t *msg,
                                         int round_idx) {
  g(state, 0, 4, 8, 12, msg[MSG_SCHEDULE[round_idx][0]],
    msg[MSG_SCHEDULE[round_idx][1]]);
  g(state, 1, 5, 9, 13, msg[MSG_SCHEDULE[round_idx][2]],
    msg[MSG_SCHEDULE[round_idx][3]]);
  g(state, 2, 6, 10, 14, msg[MSG_SCHEDULE[round_idx][4]],
    msg[MSG_SCHEDULE[round_idx][5]]);
  g(state, 3, 7, 11, 15, msg[MSG_SCHEDULE[round_idx][6]],
    msg[MSG_SCHEDULE[round_idx][7]]);
  g(state, 0, 5, 10, 15, msg[MSG_SCHEDULE[round_idx][8]],
    msg[MSG_SCHEDULE[round_idx][9]]);
  g(state, 1, 6, 11, 12, msg[MSG_SCHEDULE[round_idx][10]],
    msg[MSG_SCHEDULE[round_idx][11]]);
  g(state, 2, 7, 8, 13, msg[MSG_SCHEDULE[round_idx][12]],
    msg[MSG_SCHEDULE[round_idx][13]]);
  g(state, 3, 4, 9, 14, msg[MSG_SCHEDULE[round_idx][14]],
    msg[MSG_SCHEDULE[round_idx][15]]);
}

__device__ void blake3_compress(const uint32_t *cv, const uint8_t *block,
                                uint32_t block_len, uint64_t counter,
                                uint32_t flags, uint32_t *out) {
  uint32_t msg[16];
  for (int i = 0; i < 16; i++) {
    msg[i] =
        ((uint32_t)block[i * 4 + 0] << 0) | ((uint32_t)block[i * 4 + 1] << 8) |
        ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
  }

  uint32_t state[16] = {cv[0],
                        cv[1],
                        cv[2],
                        cv[3],
                        cv[4],
                        cv[5],
                        cv[6],
                        cv[7],
                        IV0,
                        IV1,
                        IV2,
                        IV3,
                        (uint32_t)counter,
                        (uint32_t)(counter >> 32),
                        block_len,
                        flags};

#pragma unroll
  for (int i = 0; i < 7; i++) {
    round_fn(state, msg, i);
  }

#pragma unroll
  for (int i = 0; i < 8; i++) {
    out[i] = state[i] ^ state[i + 8] ^ cv[i];
  }
}

// Parent node hashing (combines two 32-byte CVs)
__device__ void blake3_parent(const uint32_t *left_cv, const uint32_t *right_cv,
                              const uint32_t *key, uint32_t flags,
                              uint32_t *out_cv) {
  uint8_t block[64];
  for (int i = 0; i < 8; i++) {
    uint32_t l = left_cv[i];
    block[i * 4 + 0] = l & 0xFF;
    block[i * 4 + 1] = (l >> 8) & 0xFF;
    block[i * 4 + 2] = (l >> 16) & 0xFF;
    block[i * 4 + 3] = (l >> 24) & 0xFF;
    uint32_t r = right_cv[i];
    block[32 + i * 4 + 0] = r & 0xFF;
    block[32 + i * 4 + 1] = (r >> 8) & 0xFF;
    block[32 + i * 4 + 2] = (r >> 16) & 0xFF;
    block[32 + i * 4 + 3] = (r >> 24) & 0xFF;
  }
  blake3_compress(key, block, 64, 0, PARENT | flags, out_cv);
}

// ---------------------------------------------------------------------------------
// 1. CBD Tape Generation
// 16 calls of 64 byte blocks.
// Rust: counter_expand(b"knox-lattice-cbd", seed, N/2=512)
// block = "knox-lattice-cbd" (16 bytes) || ctr (8 bytes LE) || seed (40 bytes)
// ---------------------------------------------------------------------------------
__device__ void generate_cbd_tape(const uint8_t *seed_40, uint8_t *out_512) {
  uint32_t key[8] = {IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7};
  uint8_t block[64];

  // Prefix
  const char *prefix = "knox-lattice-cbd";
  for (int i = 0; i < 16; i++)
    block[i] = prefix[i];

  // Seed
  for (int i = 0; i < 40; i++)
    block[24 + i] = seed_40[i];

#pragma unroll
  for (uint64_t ctr = 0; ctr < 16; ctr++) {
    block[16] = (uint8_t)(ctr & 0xFF);
    block[17] = 0;
    block[18] = 0;
    block[19] = 0;
    block[20] = 0;
    block[21] = 0;
    block[22] = 0;
    block[23] = 0;

    uint32_t out_cv[8];
    blake3_compress(key, block, 64, 0, CHUNK_START | CHUNK_END | ROOT, out_cv);

    // Copy out
    for (int i = 0; i < 8; i++) {
      uint32_t v = out_cv[i];
      out_512[ctr * 32 + i * 4 + 0] = v & 0xFF;
      out_512[ctr * 32 + i * 4 + 1] = (v >> 8) & 0xFF;
      out_512[ctr * 32 + i * 4 + 2] = (v >> 16) & 0xFF;
      out_512[ctr * 32 + i * 4 + 3] = (v >> 24) & 0xFF;
    }
  }
}

// ---------------------------------------------------------------------------------
// 2. Final 2073 Byte Commitment Hash
// "ult7rock-block-v1" (17) || nonce (8) || poly_bytes (2048) = 2073 bytes
// Chunk 0: 1024 bytes (Blocks 0-15) -> CV0
// Chunk 1: 1024 bytes (Blocks 16-31) -> CV1
// Chunk 2: 25 bytes (Block 32) -> CV2
// Tree: CV_p1 = Parent(CV0, CV1), Root = Parent(CV_p1, CV2)
// ---------------------------------------------------------------------------------
__device__ void blake3_final_commitment(const uint8_t *payload_2073,
                                        uint8_t *out_32) {
  uint32_t init_key[8] = {IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7};
  uint32_t cv0[8], cv1[8], cv2[8];
  uint32_t cur_cv[8];

  // Chunk 0 (1024 Bytes)
  for (int i = 0; i < 8; i++)
    cur_cv[i] = init_key[i];
  for (int b = 0; b < 16; b++) {
    uint32_t flags = (b == 0) ? CHUNK_START : 0;
    if (b == 15)
      flags |= CHUNK_END;
    blake3_compress(cur_cv, payload_2073 + b * 64, 64, 0, flags, cur_cv);
  }
  for (int i = 0; i < 8; i++)
    cv0[i] = cur_cv[i];

  // Chunk 1 (1024 Bytes)
  for (int i = 0; i < 8; i++)
    cur_cv[i] = init_key[i];
  for (int b = 0; b < 16; b++) {
    uint32_t flags = (b == 0) ? CHUNK_START : 0;
    if (b == 15)
      flags |= CHUNK_END;
    blake3_compress(cur_cv, payload_2073 + 1024 + b * 64, 64, 1, flags, cur_cv);
  }
  for (int i = 0; i < 8; i++)
    cv1[i] = cur_cv[i];

  // Chunk 2 (25 Bytes)
  for (int i = 0; i < 8; i++)
    cur_cv[i] = init_key[i];
  uint8_t last_block[64];
  for (int i = 0; i < 25; i++)
    last_block[i] = payload_2073[2048 + i];
  for (int i = 25; i < 64; i++)
    last_block[i] = 0;
  blake3_compress(cur_cv, last_block, 25, 2, CHUNK_START | CHUNK_END, cur_cv);
  for (int i = 0; i < 8; i++)
    cv2[i] = cur_cv[i];

  // Merkle Tree
  uint32_t cv_p1[8];
  blake3_parent(cv0, cv1, init_key, 0, cv_p1);

  uint32_t final_cv[8];
  blake3_parent(cv_p1, cv2, init_key, ROOT, final_cv);

  for (int i = 0; i < 8; i++) {
    uint32_t v = final_cv[i];
    out_32[i * 4 + 0] = v & 0xFF;
    out_32[i * 4 + 1] = (v >> 8) & 0xFF;
    out_32[i * 4 + 2] = (v >> 16) & 0xFF;
    out_32[i * 4 + 3] = (v >> 24) & 0xFF;
  }
}
