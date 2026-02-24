KNOX: A Post-Quantum, Self-Hardening Privacy Protocol

Lead Architect: ULT7RA

Technical Legacy: Dedicated to Rockasaurus Rex

URK  = ULT7Rock KNOX
URKL = ULT7Rock KNOX Lattice

Status: Mainnet-Ready | Version: 1.1.9 – ULT7Rock

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ORIGIN STATEMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KNOX is an original protocol. It was designed and built from the ground up, in a clean room,
with zero code copied, forked, or derived from any existing cryptocurrency, blockchain project,
or open-source library beyond standard cryptographic primitives (Argon2, BLAKE3,
ChaCha20-Poly1305). KNOX is not a fork of Bitcoin, Monero, Ethereum, or any other chain.
Every cryptographic construction — the ring signature scheme, the commitment scheme, the
range proofs, the stealth address system, the P2P handshake, the consensus engine, and the
mining kernel — was designed and implemented specifically for KNOX.

KNOX is the first Layer-1 blockchain in existence to run fully end-to-end lattice cryptography
across every protocol layer: transaction signing, output commitments, range proofs, stealth
addresses, block proof-of-work, consensus rule enforcement, and the peer-to-peer session key
exchange. There is no other chain like it.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Executive Summary

KNOX is a sovereign Layer-1 decentralized ledger designed as a permanent, quantum-resistant
vault. It utilizes ULT7Rock Lattice-PoW to secure the chain, deterministic validity rules for
block admission/finality, and Lattice-LSAG for zero-knowledge privacy. KNOX is built on the principle of
Forward-Immunity, where the ledger's security debt increases over time, making historical
blocks exponentially harder to attack as the universe ages.

No other protocol combines post-quantum ring signatures, confidential lattice transactions,
lattice stealth addresses, forward-immunity hardening, and a fully lattice-encrypted P2P layer
into a single cohesive Layer-1. KNOX is not inspired by prior art — it is prior art.

2. The ULT7Rock Cryptographic Core

KNOX moves beyond Elliptic Curve Cryptography (ECC), which is vulnerable to Shor's Algorithm. Instead, it is built on the Shortest Vector Problem (SVP).

2.1 Ring-LWE Parameters

The protocol operates in the cyclotomic ring Rq=Zq[x]/(x^1024+1).

    Dimension (N): 1024

    Modulus (q): 12289 (Chosen for optimal NTT-friendly primes)

    Error Distribution: Centered-Binomial Distribution (CBD) with η=2.

2.2 Forward-Immunity Hardening

KNOX implements a Computational Security Debt. Every 10,000 blocks, the CLH_DIMENSION_GROWTH constant triggers a hardware-hardening event.

    The Logic: As global compute power increases, KNOX increases the mathematical complexity of its lattice problems.

    The Result: Attacking a block from 5 years ago requires solving a problem that is significantly "taller" in the lattice than it was at the time of minting.

    Verification Cost: Forward-Immunity only hardens the mining layer. Transaction verification remains constant-time regardless of chain age. A light client in year 20 verifies a transaction identically to year 1.

3. High-Performance GPU Mining (ULT7Rock Kernel)

The KNOX miner is not a generic hashing tool; it is a specialized CUDA-accelerated lattice solver.

    Shared Memory NTT: Operates using a Radix-2 Cooley-Tukey forward transform and a Gentleman-Sande inverse transform.

    Occupancy: The kernel is capped at 32 registers to ensure maximum thread occupancy on the Streaming Multiprocessor (SM).

    Memory Bottlenecking: By keeping the 1024-coefficient polynomial in L1/Shared SRAM (~6KB per CTA), KNOX bypasses the slow GDDR6X global memory latency that plagues other PoW coins.

    Portability: The kernel runs on any CUDA-capable GPU with compute capability >= 7.0, from consumer GTX 1650s to datacenter H100s.

    Proof Pipeline: Seed → BLAKE3 expand → CBD sampling → Forward NTT → Proof-of-Time chain → Inverse NTT → Serialize → Final BLAKE3 commitment → Difficulty check.

4. Privacy and Metadata Immunity

KNOX assumes that the network layer is under constant surveillance.

4.1 URKL-LSAG (Ring Signatures)

Anonymity is achieved via Linkable Spontaneous Anonymous Group signatures built entirely on lattice primitives.

    Key Images: Derived via tag = H(pk) · sk. This is a deterministic, one-way function in the lattice—the same private key always produces the same Key Image regardless of ring composition.

    Double-Spend Prevention: The KeyImageSet maintains a global set of all spent Key Image hashes. Any duplicate Key Image is rejected at the consensus layer, preventing double-spending without revealing the sender's identity.

    Privacy: The sender remains hidden within a "Ring" of up to 64 decoy outputs. The lattice-based math ensures this anonymity holds even against a quantum computer.

    Ring Size: Configurable from 16 to 65 members (MIN_DECOY_COUNT=15 + the real input), with a default of 32 members.

4.2 Confidential Transactions (ULT7Rock KNOX (URKL) Lattice Commitments)

All transaction amounts are hidden using homomorphic lattice-based Pedersen commitments.

    Amount Hiding: Each output carries a URKL Commitment that binds to the amount without revealing it. Only the sender and recipient know the true value.

    Balance Verification: The protocol verifies that inputs equal outputs + fees using polynomial arithmetic: Σ(input commitments) - Σ(output commitments) - fee_commitment = 0 (the zero polynomial). No amounts are ever exposed publicly.

    URKL Range Proofs: Every output includes a URKL LatticeRangeProof that proves the hidden amount is non-negative and within bounds, preventing inflation attacks.

    Progressive Encryption: Output amounts are encrypted with a hardening level that grows by 1 bit per block (TX_SECURITY_GROWTH_PER_BLOCK). The KDF iterates more rounds over time, increasing computational cost to brute-force historical outputs.

4.3 URKL Stealth Addresses

KNOX implements a full dual-key stealth address system for unlinkable, one-time payment addresses.

    Dual Keys: Every wallet has a View Key (for scanning) and a Spend Key (for spending). A recipient can share their View Key with an auditor without exposing spend authority.

    One-Time Addresses: When sending, the sender computes a shared secret with the recipient's View Public Key using an ephemeral polynomial, derives a one-time stealth address, and attaches the ephemeral public key to the output.

    Scanning: The recipient scans the blockchain with their View Key via scan_with_view_key(). If the derived one-time address matches the output, the payment belongs to them.

    Spending: The recipient recovers the one-time private key via recover_one_time_secret(), combining their Spend Key with the ephemeral public attached to the output.

    Quantum Resistance: Unlike Monero's ECC-based stealth addresses, KNOX stealth addresses operate entirely in the lattice domain, providing post-quantum security.

4.4 Metadata Jitter & Cover Traffic

    Dandelion++ Relay: Transactions do not broadcast instantly. They follow a "Stem" phase with a randomized 120ms – 900ms jitter before "Fluffing" out to the network.

    Constant-Bandwidth Noise: Nodes emit 1KB padded packets at fixed intervals. To an ISP or outside observer, the network looks like constant, rhythmic noise, hiding the exact timing of real transactions.

5. P2P URK Architecture (The Rust Stack)

Built using the Tokio runtime for non-blocking, asynchronous performance.

    Async Fan-Out: Each peer connection is handled by a separate green thread.

    MPSC Backpressure: Each peer has a 1,024-slot queue. If a peer cannot keep up, the node drops the oldest messages specifically for that peer, preventing a single slow connection from slowing down the local miner.

    Sybil Protection: Establishing a P2P handshake requires a 16-bit Proof-of-Work, making it computationally expensive to "flood" the network with fake nodes.

    Per-IP Rate Limiting: Max 200 inbound messages per second per IP. Max 8 simultaneous connections from the same IP. State eviction after 5 minutes of inactivity.

    Replay Protection: Every message carries a session_id and monotonic sequence number. The ReplayProtector tracks seen (session, sequence) pairs with a 24-hour TTL, preventing message replay attacks.

5.1 URKL Two-Round Lattice Key Exchange (Per-Session Encryption)

KNOX does not use a static Pre-Shared Key or any classical Diffie-Hellman for P2P encryption.
Every connection is secured by a two-round lattice key exchange built on the URKL Stealth KEM.

Round 1 — Public Key Advertisement:
    The initiating node opens a TCP connection and sends a plaintext Handshake frame containing
    its peer ID, a 16-bit proof-of-work nonce, and its lattice public key. The receiving node
    responds with its own lattice public key. At this point both sides have each other's public
    keys but no shared secret has been established.

Round 2 — Ephemeral Session Key Derivation:
    The initiator generates a fresh ephemeral short polynomial and computes a one-time stealth
    output addressed to the responder's lattice public key using the URKL Stealth KEM:

        shared = send_to_stealth_with_ephemeral(peer_pub, peer_pub, eph_secret)
        session_key = BLAKE3(shared.one_time_public)

    The initiator sends the ephemeral public key to the responder in a second Handshake frame.
    The responder independently recovers the same session key:

        one_time_secret = recover_one_time_secret(local_secret, local_secret, eph_public)
        one_time_public = public_from_secret(one_time_secret)
        session_key = BLAKE3(one_time_public)

    Both sides now hold an identical 32-byte session key that was never transmitted on the wire.

Post-Handshake Encryption:
    All subsequent traffic is encrypted with XChaCha20-Poly1305 using the derived session key.
    Each connection derives its own independent key — compromising one session reveals nothing
    about any other past or future connection. No static secrets exist anywhere in the codebase.

    This construction is fully post-quantum: an adversary with a quantum computer cannot
    recover the session key because the hardness of the key exchange rests on the lattice
    Shortest Vector Problem, not on discrete logarithm or elliptic curve assumptions.

6. Open Mining Consensus (Lattice-PoW)

KNOX runs open mining: any node can propose a block by solving ULT7Rock Lattice-PoW.

    Open Participation: There is no fixed validator committee, no leader election, and no BFT voting rounds.

    Deterministic Admission Rules: A candidate block must pass the same checks on every node:
    valid parent linkage, valid timestamp spacing, valid lattice proof-of-work target, and valid
    transaction/coinbase accounting.

    Finality Model: Practical finality is chainwork-based. Nodes converge on the heaviest valid
    chain under identical rule enforcement.

    Fork Safety: Conflicting blocks are resolved by deterministic chainwork selection plus strict
    parent/timestamp/proof validation. Invalid branches are rejected network-wide.

7. URK Ledger Model (Confidential UTXO)

KNOX uses a Confidential UTXO model built entirely and exclusively on ULT7Rock lattice primitives.
No classical curve cryptography underlies any UTXO operation.

    Inputs: Each references a ring of possible source UTXOs, a lattice ring signature proving ownership, a Key Image for double-spend detection, and a pseudo-commitment for balance verification.

    Outputs: Each contains a stealth address, an ephemeral public key, a lattice commitment hiding the amount, a range proof, and encrypted amount/blinding factor fields.

    No Scripting: KNOX is deliberately not a smart-contract platform. The "smart" part is in the cryptography: confidential amounts, ring signatures, stealth addresses, and range proofs. This minimizes attack surface while maximizing privacy.

8. Incentive URK Game Theory (ϕ-Logic)

Everything in KNOX is tied to the Golden Ratio (ϕ ≈ 1.618034).

8.1 The Streak

Miners earn a 1.618% bonus for every consecutive block they mine.

    Max Streak: 34 blocks (Fibonacci).

    Max Reward: 1.618x (ϕ) of the base coinbase.

    Reset Mechanic: If another miner produces a block, the streak resets to 1. This creates a natural competitive tension—breaking a rival's streak resets their bonus.

8.2 The Monthly Surge

A monthly event window lasting ~16 hours 18 minutes, starting at an unpredictable time seeded by BLAKE3(month_start || month_duration || first_block_hash). During the Surge, difficulty scales upward:

    Surge Difficulty = BaseBits + round(block_index / 1000 × log₂(ϕ))

    Escalating Challenge: Difficulty increases progressively with each Surge block mined. Early blocks are near-normal difficulty; late blocks are significantly harder. This prevents any single miner from dominating the window.

    Block Cap: Maximum 16,180 blocks per Surge (a Fibonacci number).

    Cooldown: After the Surge ends (or the cap is reached), a 161.8-minute cooldown phase begins before normal mining resumes.

    The Fibonacci Wall: The winner of block 16,180 is etched onto the Fibonacci Wall—a permanent on-chain hall of fame.

9. Tokenomics

    Genesis Address: 2,696,969 KNOX (One-time mint for the Founder/Son legacy).

    Public Supply: 67,000,000 KNOX (distributed to miners over the emission window).

    Hard Cap: 69,696,969 KNOX (immutable, enforced in code).

    Emission Window: 21 Years (linear distribution).

    Dev Fund: 0 KNOX (no team allocation, no investor tokens).

    Treasury: 1% of each block's public reward, allocated to the protocol treasury.

    Post-Emission: After 21 years, miners are sustained by transaction fees only. The hard cap is absolute.

10. KNOX Desktop Wallet

Most post-quantum research ends at the protocol layer. KNOX ships a complete, production-ready
desktop wallet alongside the node — because a protocol that cannot be used by real people is
not a finished protocol.

The KNOX Desktop Wallet is a native Windows application distributed as a single MSI installer
with no external dependencies. It bundles the full KNOX node, the wallet daemon, and a polished
React-based UI into one cohesive package. A user can go from a blank machine to a live,
mining, privacy-preserving KNOX node in under two minutes.

10.1 Architecture

The desktop wallet is composed of three integrated layers:

    knox-node: The full Layer-1 node — mempool, block production, P2P networking,
    open mining participation — running locally on the user's machine.

    knox-walletd: A wallet daemon exposing a JSON API over local TLS. All wallet operations
    (UTXO scanning, transaction building, address derivation) happen here, isolated from
    the UI layer and accessible only over localhost with TLS certificate enforcement.

    Electron UI: A desktop shell built with React, TanStack Query, and Zustand.
    Communicates with walletd exclusively through the secure local API.

This separation means the cryptographic core and key material never touch the UI process.
The wallet daemon is a trust boundary — the UI layer is treated as untrusted by design.

10.2 Key Management and Encryption

Wallet files are encrypted with Argon2id key derivation and XChaCha20-Poly1305 authenticated
encryption — the same cryptographic discipline applied to the chain itself. View keys and
spend keys are separated: a recipient can share their view key for auditing without exposing
any spend authority. Multiple stealth addresses can be derived from a single wallet file,
each producing a fresh unlinkable one-time address for every transaction received.

10.3 What Ships in the Box

    One-click Quick Start: Starts the node, wallet daemon, and mining in a single action.

    Live Mining Dashboard: Real-time hash rate, difficulty, streak bonus, surge phase,
    and block count — all visible at a glance.

    Multi-Address Wallet: Generate as many stealth addresses as needed from a single
    wallet file. Each address is independently unlinkable on-chain.

    Full Send UI: Ring size selection, fee control, recipient address, and confirmation
    dialog — everything needed to send a private lattice transaction from a desktop.

    TLS Certificate Generation: First-run generates a self-signed TLS certificate for
    the local wallet daemon. This is a one-click operation. The wallet will not start
    without it, enforcing encrypted local communication by default.

    Sync Control: Manual sync triggers a full UTXO rescan so balance always reflects
    the true chain state.

10.4 Why This Matters

Shipping a full desktop wallet is not a cosmetic feature. It is a statement about what
KNOX is. Privacy cryptography that lives only in academic papers or CLI tools reaches
almost no one. The KNOX desktop wallet makes post-quantum, ring-signature, stealth-address
privacy accessible to any user on a standard Windows machine — no Rust toolchain, no
command line, no configuration files required.

The wallet exists because KNOX was built to be used, not just theorized.

11. Conclusion

KNOX is a mathematical fortress. It is the first protocol to combine Post-Quantum Ring Signatures, Confidential Transactions, Lattice Stealth Addresses, and Forward-Immunity Hardening into a single, cohesive Layer-1. The "Unpredictable Excitement" of the Surge, the "Loyalty Incentive" of the Streak, and the "Total Privacy" of Lattice-LSAG create a protocol designed to be a permanent digital asset that survives the quantum age.
