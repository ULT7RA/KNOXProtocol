# KNOX Threat Model & Security Posture

Version: 1.1.9 | Status: Mainnet

---

## Executive Statement

KNOX is a new cryptographic system — an original composition of lattice primitives designed
specifically for this protocol, not derived from any prior codebase or specification.

Because the design is novel in composition, the complete real-world threat model is not fully
exhausted by internal analysis alone. That uncertainty is stated explicitly here.

At the same time, KNOX is intentionally engineered toward post-quantum resistance and rising
attacker cost over time. The architecture is not conservative — it is aggressive in its use of
lattice hardness as the sole security foundation across all protocol layers.

Both statements are true:
- KNOX is the most complete end-to-end lattice privacy protocol in existence,
- continued external cryptanalysis and operational maturity will deepen the security evidence.

---

## Security Claims: What Is and Is Not Claimed

**Claimed:**
- Deterministic validation and fail-closed behavior for invalid proofs and signatures
- Resistance targets aligned with modern lattice hardness assumptions (N=1024, Q=12289)
- Anti-double-spend and canonical serialization protections enforced at consensus
- Per-connection post-quantum session encryption via URKL two-round Stealth KEM
- Compounding forward-immunity hardening that raises attack cost with every block

**Not claimed at this time:**
- Complete formal compositional proof for every protocol subsystem
- Immunity to implementation bugs, side channels, or endpoint compromise
- Exhaustive quantum security margin against all future quantum algorithms

---

## Assets Protected

- Wallet private spend and view keys
- Validator signing keys and consensus authority
- Transaction correctness and non-inflation ledger invariants
- User privacy: sender ambiguity, receiver unlinkability, amount hiding
- Network liveness and deterministic finality
- Software distribution and update channel integrity

---

## Trust Boundaries

- On-chain consensus verification boundary
- Node-to-node network boundary (URKL KEM encrypted)
- Walletd local API boundary (TLS)
- Desktop wallet runtime boundary
- Build, signing, and distribution pipeline boundary

Compromise at any boundary can bypass cryptographic assurances in higher layers.

---

## Adversary Classes

1. **Passive chain observer** — analyzes transaction graph, timing, and metadata
2. **Active network adversary** — delays, drops, reorders, or partitions traffic
3. **Byzantine validator subset** — attempts censorship, equivocation, or liveness degradation
4. **Endpoint attacker** — malware or local compromise targeting user systems and keys
5. **Supply-chain attacker** — targets build artifacts, dependency chain, or installer path
6. **Cryptanalytic adversary** — attempts to break lattice assumptions or exploit parameterization

---

## Time-Gated Adversary Model

KNOX hardening (sequential Argon2id PoW + memory escalation + cumulative hardening updates)
means an attacker is not attacking a static target. They face a time-gated target:

- Each block can increase effective attack cost
- Historical attack precomputation loses relative value over time
- Useful attack windows narrow rather than widen as the chain ages

The correct attacker model is not "crack one transaction whenever."
It is "race a moving target that trends harder with every block."

---

## Quantum Threat Posture

**Threat assumption:**
- Practical quantum capability is approaching
- Migration urgency from classical cryptography is real
- Classical-only security horizons are shrinking

**KNOX response:**
- Post-quantum lattice primitives across every protocol layer
- No elliptic curve or discrete logarithm assumptions in any critical path
- Hardening mechanisms designed to increase work factors over time

**Residual uncertainty:**
- Exact long-run quantum security margin requires continued external cryptanalysis
  and operational history

---

## Attack Scenarios

### A. Transaction Forgery / Amount Inflation
- **Attack:** Forge commitments, range proofs, or spend authorization
- **Mitigations:** Strict consensus verification, commitment and range checks,
  canonical transaction structure, key image spend tracking
- **Residual risk:** Medium — dominated by implementation correctness and cryptographic review depth

### B. Ring Deanonymization and Linkage
- **Attack:** Infer true spender via ring mismatch, decoy weakness, or metadata correlation
- **Mitigations:** Canonical ring-member equality checks, configurable ring size (up to 64 members),
  network padding, Dandelion++ relay jitter (120ms–900ms stem phase)
- **Residual risk:** Medium against global passive observers with poor decoy hygiene

### C. Quantum-Assisted Cryptanalysis
- **Attack:** Exploit unforeseen weaknesses in parameterization or lattice constructions
- **Mitigations:** Conservative lattice parameters, hardening updates, governance flexibility
- **Residual risk:** Unknown — new composed system requires continued external review

### D. Validator Collusion and Censorship
- **Attack:** Censor transactions or stall liveness through coordinated behavior
- **Mitigations:** PulsarBFT quorum rules (2/3+1), deterministic leader rotation,
  timeout progression, slashing on equivocation
- **Residual risk:** Low below Byzantine threshold, high above it

### E. Endpoint Compromise
- **Attack:** Steal wallet keys, inject destination addresses, tamper with UI or runtime
- **Mitigations:** Key isolation, encrypted wallet files (Argon2 + XChaCha20-Poly1305),
  hardened host baseline
- **Residual risk:** High at endpoint layer — cryptography does not protect compromised hosts

### F. Build and Installer Supply-Chain Attack
- **Attack:** Replace binaries or installer, malicious update path, dependency poisoning
- **Mitigations:** Deterministic build discipline, release audits, artifact provenance
- **Residual risk:** Medium — requires strict release governance

---

## Assumptions Register

KNOX relies on:
- Hardness of RLWE / SVP under chosen parameters (N=1024, Q=12289)
- Correct implementation of polynomial arithmetic, CBD sampling, and proof verification
- Deterministic consensus without divergence bugs
- Sound operational key management and node hardening
- Prompt upgrade response if cryptographic assumptions weaken

If any assumption fails, effective security can degrade quickly.

---

## Open Questions

1. Full compositional security proof across all lattice subsystems and their interfaces
2. Long-horizon behavior of hardening parameters under adversarial economics
3. Real-world metadata leakage under sustained global passive observation
4. Quantum capability timelines vs. assumed security margins at current parameters
5. Emergent behavior under extreme validator or network stress

---

## Control Plan

**Short-term:**
- External cryptography review
- Differential and property-based fuzzing
- Strict canonicalization tests
- Operational runbooks for incident response

**Medium-term:**
- Formal methods on critical proof/verification paths
- Adversarial testnet exercises
- Parameter-governance process with transparent rationale

**Long-term:**
- Periodic parameter re-evaluation
- Migration pathways for future primitives
- Independent red-team exercises and public security reporting

---

## Final Security Posture

KNOX is designed so attacker cost increases over time. It is the first protocol to place
post-quantum lattice cryptography at every layer simultaneously. The honest and accurate
public statement is:

> KNOX is quantum-resistant in intent, architecture, and implementation. It is continuously
> hardening. Complete threat certainty requires continued cryptanalysis, operational maturity,
> and independent audit evidence — which this protocol actively invites.
