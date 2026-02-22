use knox_lattice::{
    consensus_public_key_id, sign_consensus, verify_block_proof, verify_consensus, ImmunityState,
    LatticePublicKey, LatticeSecretKey,
};
use knox_types::{
    hash_header_for_signing, hash_timeout_vote_for_signing, hash_vote_for_signing, Block,
    Hash32, SlashEvidence, TimeoutCertificate, TimeoutVote, Vote,
};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub epoch_length: u64,
    pub committee_size: usize,
    pub max_round_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatorSet {
    pub validators: Vec<LatticePublicKey>,
}

impl ValidatorSet {
    pub fn quorum(&self) -> usize {
        (self.validators.len() * 2 / 3) + 1
    }

    pub fn index_of(&self, pk: &LatticePublicKey) -> Option<u16> {
        self.validators
            .iter()
            .position(|v| v == pk)
            .map(|i| i as u16)
    }

    pub fn index_of_id(&self, id: &[u8; 32]) -> Option<u16> {
        self.validators
            .iter()
            .position(|v| consensus_public_key_id(v) == *id)
            .map(|i| i as u16)
    }
}

#[derive(Clone, Debug)]
pub enum ConsensusMessage {
    Proposal(Block),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    TimeoutCertificate(TimeoutCertificate),
    Slash(SlashEvidence),
}

#[derive(Clone, Debug)]
pub struct ConsensusOutput {
    pub messages: Vec<ConsensusMessage>,
    pub finalized: Vec<Block>,
}

const MAX_TRACKED_VOTES: usize = 131_072;
const MAX_TRACKED_CONTRIBUTIONS: usize = 262_144;

pub struct Ult7RockLattice {
    _cfg: ConsensusConfig,
    validators: ValidatorSet,
    secret: LatticeSecretKey,
    public: LatticePublicKey,
    height: u64,
    round: u32,
    banned: HashSet<u16>,
    seen_contributions: HashSet<[u8; 32]>,
    proposals: HashMap<(u64, u32, Hash32), Block>,
    seen_votes: HashMap<(u64, u32, u16), Vote>,
    seen_vote_order: VecDeque<(u64, u32, u16)>,
    seen_timeout_votes: HashMap<(u64, u32, u16), TimeoutVote>,
    seen_timeout_vote_order: VecDeque<(u64, u32, u16)>,
    immunity: ImmunityState,
}

impl Ult7RockLattice {
    pub fn new(
        cfg: ConsensusConfig,
        validators: ValidatorSet,
        secret: LatticeSecretKey,
        public: LatticePublicKey,
    ) -> Self {
        Self {
            _cfg: cfg,
            validators,
            secret,
            public,
            height: 0,
            round: 0,
            banned: HashSet::new(),
            seen_contributions: HashSet::new(),
            proposals: HashMap::new(),
            seen_votes: HashMap::new(),
            seen_vote_order: VecDeque::new(),
            seen_timeout_votes: HashMap::new(),
            seen_timeout_vote_order: VecDeque::new(),
            immunity: ImmunityState::genesis(),
        }
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn round(&self) -> u32 {
        self.round
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.round = 0;
        self.proposals.retain(|(h, _, _), _| *h >= height);
    }

    pub fn leader_index(&self, height: u64, round: u32) -> u16 {
        if self.validators.validators.is_empty() {
            return 0;
        }
        let idx = (height as usize + round as usize) % self.validators.validators.len();
        idx as u16
    }

    pub fn is_leader(&self, height: u64, round: u32) -> bool {
        if self.validators.validators.is_empty() {
            return false;
        }
        if let Some(idx) = self.validators.index_of(&self.public) {
            idx == self.leader_index(height, round)
        } else {
            false
        }
    }

    pub fn on_message(&mut self, msg: ConsensusMessage) -> ConsensusOutput {
        match msg {
            ConsensusMessage::Proposal(block) => self.on_proposal(block),
            ConsensusMessage::Vote(vote) => self.on_vote(vote),
            ConsensusMessage::TimeoutVote(vote) => self.on_timeout_vote(vote),
            ConsensusMessage::TimeoutCertificate(tc) => self.on_timeout_certificate(tc),
            ConsensusMessage::Slash(ev) => self.on_slash(ev),
        }
    }

    pub fn on_tick(&mut self, _now_ms: u64) -> ConsensusOutput {
        Self::empty_output()
    }

    pub fn try_propose(&mut self, block: Block) -> ConsensusOutput {
        let mut out = Self::empty_output();
        if self.is_leader(block.header.height, block.header.round) {
            out.messages.push(ConsensusMessage::Proposal(block));
        }
        out
    }

    pub fn verify_slash_evidence(&self, _ev: &SlashEvidence) -> bool {
        let ev = _ev;
        let a = &ev.vote_a;
        let b = &ev.vote_b;
        if a.voter != b.voter {
            return false;
        }
        if a.height != b.height || a.round != b.round {
            return false;
        }
        if a.block_hash == b.block_hash {
            return false;
        }
        let Some(pk) = self.validators.validators.get(a.voter as usize) else {
            return false;
        };
        let ha = hash_vote_for_signing(a);
        let hb = hash_vote_for_signing(b);
        verify_consensus(pk, &ha.0, &a.sig) && verify_consensus(pk, &hb.0, &b.sig)
    }

    pub fn apply_slashed(&mut self, validators: &[u16]) {
        for v in validators {
            self.banned.insert(*v);
        }
    }

    pub fn immunity_state(&self) -> &ImmunityState {
        &self.immunity
    }

    fn on_proposal(&mut self, block: Block) -> ConsensusOutput {
        let mut out = Self::empty_output();

        if block.header.height != self.height {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: expected height {}",
                block.header.height, block.header.round, self.height
            );
            return out;
        }
        if block.header.round != self.round {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: expected round {}",
                block.header.height, block.header.round, self.round
            );
            return out;
        }
        if self.validators.validators.is_empty() {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: validator set is empty",
                block.header.height, block.header.round
            );
            return out;
        }

        let Some(proposer_idx) = self.validators.index_of_id(&block.header.proposer) else {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: proposer id not in validator set",
                block.header.height, block.header.round
            );
            return out;
        };
        let Some(proposer_pk) = self.validators.validators.get(proposer_idx as usize) else {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: proposer index missing",
                block.header.height, block.header.round
            );
            return out;
        };
        let signer_msg = hash_header_for_signing(&block.header);
        if !verify_consensus(proposer_pk, &signer_msg.0, &block.proposer_sig) {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: invalid proposer signature",
                block.header.height, block.header.round
            );
            return out;
        }

        let leader = self.leader_index(block.header.height, self.round);
        if proposer_idx != leader {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: proposer mismatch",
                block.header.height, block.header.round
            );
            return out;
        }
        if self.banned.contains(&leader) {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: block proposer is slashed",
                block.header.height, block.header.round
            );
            return out;
        }

        if !verify_block_proof(&block.header, &block.lattice_proof) {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: invalid lattice proof",
                block.header.height, block.header.round
            );
            return out;
        }

        if self
            .seen_contributions
            .contains(&block.lattice_proof.clh_contribution)
        {
            eprintln!(
                "[knox-node] reject proposal h={} r={}: duplicate lattice contribution",
                block.header.height, block.header.round
            );
            return out;
        }

        let block_hash = hash_header_for_signing(&block.header);
        self.proposals
            .entry((block.header.height, block.header.round, block_hash))
            .or_insert(block.clone());

        if let Some(voter) = self.validators.index_of(&self.public) {
            if !self.banned.contains(&voter) {
                let vote_key = (block.header.height, block.header.round, voter);
                if !self.seen_votes.contains_key(&vote_key) {
                    let unsigned = Vote {
                        height: block.header.height,
                        round: block.header.round,
                        block_hash,
                        voter,
                        sig: Vec::new(),
                    };
                    let sig_hash = hash_vote_for_signing(&unsigned);
                    if let Ok(sig) = sign_consensus(&self.secret, &sig_hash.0) {
                        let vote = Vote { sig, ..unsigned };
                        self.insert_vote(vote.clone());
                        out.messages.push(ConsensusMessage::Vote(vote));
                    }
                }
            }
        }

        if let Some(finalized) =
            self.try_finalize_block(block.header.height, block.header.round, block_hash)
        {
            out.finalized.push(finalized);
        }
        out
    }

    fn on_slash(&mut self, ev: SlashEvidence) -> ConsensusOutput {
        if !self.verify_slash_evidence(&ev) {
            return Self::empty_output();
        }
        self.apply_slashed(&[ev.vote_a.voter]);
        Self::empty_output()
    }

    fn on_vote(&mut self, vote: Vote) -> ConsensusOutput {
        if !self.verify_vote(&vote) {
            return Self::empty_output();
        }
        if vote.height != self.height || vote.round < self.round {
            return Self::empty_output();
        }
        let key = (vote.height, vote.round, vote.voter);
        if let Some(prev) = self.seen_votes.get(&key) {
            if prev.block_hash != vote.block_hash {
                return ConsensusOutput {
                    messages: vec![ConsensusMessage::Slash(SlashEvidence {
                        vote_a: prev.clone(),
                        vote_b: vote,
                    })],
                    finalized: Vec::new(),
                };
            }
            return Self::empty_output();
        }
        self.insert_vote(vote.clone());

        let mut out = Self::empty_output();
        if let Some(finalized) = self.try_finalize_block(vote.height, vote.round, vote.block_hash) {
            out.finalized.push(finalized);
        }
        out
    }

    fn on_timeout_vote(&mut self, vote: TimeoutVote) -> ConsensusOutput {
        if !self.verify_timeout_vote(&vote) {
            return Self::empty_output();
        }
        let key = (vote.height, vote.round, vote.voter);
        if !self.seen_timeout_votes.contains_key(&key) {
            self.seen_timeout_votes.insert(key, vote);
            self.seen_timeout_vote_order.push_back(key);
            while self.seen_timeout_votes.len() > MAX_TRACKED_VOTES {
                if let Some(oldest) = self.seen_timeout_vote_order.pop_front() {
                    self.seen_timeout_votes.remove(&oldest);
                } else {
                    break;
                }
            }
        }
        Self::empty_output()
    }

    fn on_timeout_certificate(&mut self, tc: TimeoutCertificate) -> ConsensusOutput {
        if tc.height != self.height || tc.round != self.round {
            return Self::empty_output();
        }
        let mut valid = 0usize;
        let mut seen_validators = HashSet::new();
        for sig in &tc.sigs {
            if !seen_validators.insert(sig.validator) {
                continue;
            }
            let Some(pk) = self.validators.validators.get(sig.validator as usize) else {
                continue;
            };
            let vote = TimeoutVote {
                height: tc.height,
                round: tc.round,
                voter: sig.validator,
                sig: sig.sig.clone(),
            };
            if self.verify_timeout_vote_with_pk(&vote, pk) {
                valid += 1;
            }
        }
        if valid >= self.validators.quorum() {
            self.round = self.round.saturating_add(1);
        }
        Self::empty_output()
    }

    fn verify_vote(&self, vote: &Vote) -> bool {
        let Some(pk) = self.validators.validators.get(vote.voter as usize) else {
            return false;
        };
        if self.banned.contains(&vote.voter) {
            return false;
        }
        let hash = hash_vote_for_signing(vote);
        verify_consensus(pk, &hash.0, &vote.sig)
    }

    fn verify_timeout_vote(&self, vote: &TimeoutVote) -> bool {
        let Some(pk) = self.validators.validators.get(vote.voter as usize) else {
            return false;
        };
        self.verify_timeout_vote_with_pk(vote, pk)
    }

    fn verify_timeout_vote_with_pk(&self, vote: &TimeoutVote, pk: &LatticePublicKey) -> bool {
        if self.banned.contains(&vote.voter) {
            return false;
        }
        let hash = hash_timeout_vote_for_signing(vote);
        verify_consensus(pk, &hash.0, &vote.sig)
    }

    fn insert_vote(&mut self, vote: Vote) {
        let key = (vote.height, vote.round, vote.voter);
        if self.seen_votes.contains_key(&key) {
            return;
        }
        self.seen_votes.insert(key, vote);
        self.seen_vote_order.push_back(key);
        while self.seen_votes.len() > MAX_TRACKED_VOTES {
            if let Some(oldest) = self.seen_vote_order.pop_front() {
                self.seen_votes.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn vote_count_for_block(&self, height: u64, round: u32, block_hash: Hash32) -> usize {
        self.seen_votes
            .values()
            .filter(|v| v.height == height && v.round == round && v.block_hash == block_hash)
            .count()
    }

    fn try_finalize_block(&mut self, height: u64, round: u32, block_hash: Hash32) -> Option<Block> {
        if height != self.height || round != self.round {
            return None;
        }
        if self.vote_count_for_block(height, round, block_hash) < self.validators.quorum() {
            return None;
        }

        let block = self.proposals.remove(&(height, round, block_hash))?;
        if !self
            .seen_contributions
            .insert(block.lattice_proof.clh_contribution)
        {
            return None;
        }

        self.immunity
            .absorb_contribution(&block.lattice_proof.clh_contribution, block.header.height);
        if self.seen_contributions.len() > MAX_TRACKED_CONTRIBUTIONS {
            self.seen_contributions.clear();
            self.seen_contributions
                .insert(block.lattice_proof.clh_contribution);
        }

        self.height = self.height.saturating_add(1);
        self.round = 0;
        let new_height = self.height;
        self.proposals.retain(|(h, _, _), _| *h >= new_height);
        Some(block)
    }

    fn empty_output() -> ConsensusOutput {
        ConsensusOutput {
            messages: Vec::new(),
            finalized: Vec::new(),
        }
    }
}

pub type PulsarBft = Ult7RockLattice;

#[cfg(test)]
mod tests {
    use super::*;
    use knox_lattice::{consensus_public_from_secret, consensus_secret_from_seed, sign_consensus};
    use knox_types::{Hash32, VoteSignature};

    fn make_vote(
        sk: &LatticeSecretKey,
        voter: u16,
        height: u64,
        round: u32,
        block_hash: Hash32,
    ) -> Vote {
        let unsigned = Vote {
            height,
            round,
            block_hash,
            voter,
            sig: Vec::new(),
        };
        let sig_hash = hash_vote_for_signing(&unsigned);
        let sig = sign_consensus(sk, &sig_hash.0).expect("vote sign");
        Vote { sig, ..unsigned }
    }

    fn make_timeout_sig(
        sk: &LatticeSecretKey,
        voter: u16,
        height: u64,
        round: u32,
    ) -> VoteSignature {
        let tv = TimeoutVote {
            height,
            round,
            voter,
            sig: Vec::new(),
        };
        let sig_hash = hash_timeout_vote_for_signing(&tv);
        let sig = sign_consensus(sk, &sig_hash.0).expect("timeout sign");
        VoteSignature {
            validator: voter,
            sig,
        }
    }

    #[test]
    fn conflicting_votes_emit_slash_message() {
        let sk0 = consensus_secret_from_seed(&[0x11; 32]);
        let pk0 = consensus_public_from_secret(&sk0);
        let sk1 = consensus_secret_from_seed(&[0x22; 32]);
        let pk1 = consensus_public_from_secret(&sk1);
        let cfg = ConsensusConfig {
            epoch_length: 100,
            committee_size: 2,
            max_round_ms: 5000,
        };
        let validators = ValidatorSet {
            validators: vec![pk0.clone(), pk1],
        };
        let mut c = Ult7RockLattice::new(cfg, validators, sk0.clone(), pk0);
        c.set_height(7);

        let v1 = make_vote(&sk0, 0, 7, 0, Hash32([0x11; 32]));
        let out1 = c.on_message(ConsensusMessage::Vote(v1.clone()));
        assert!(out1.messages.is_empty());

        let v2 = make_vote(&sk0, 0, 7, 0, Hash32([0x22; 32]));
        let out2 = c.on_message(ConsensusMessage::Vote(v2.clone()));
        assert_eq!(out2.messages.len(), 1);
        match &out2.messages[0] {
            ConsensusMessage::Slash(ev) => {
                assert_eq!(ev.vote_a.block_hash, v1.block_hash);
                assert_eq!(ev.vote_b.block_hash, v2.block_hash);
            }
            other => panic!("expected slash evidence, got {other:?}"),
        }
    }

    #[test]
    fn timeout_certificate_quorum_advances_round() {
        let sk0 = consensus_secret_from_seed(&[0x31; 32]);
        let pk0 = consensus_public_from_secret(&sk0);
        let sk1 = consensus_secret_from_seed(&[0x32; 32]);
        let pk1 = consensus_public_from_secret(&sk1);
        let sk2 = consensus_secret_from_seed(&[0x33; 32]);
        let pk2 = consensus_public_from_secret(&sk2);
        let cfg = ConsensusConfig {
            epoch_length: 100,
            committee_size: 3,
            max_round_ms: 5000,
        };
        let validators = ValidatorSet {
            validators: vec![pk0.clone(), pk1, pk2],
        };
        let mut c = Ult7RockLattice::new(cfg, validators, sk0.clone(), pk0);
        c.set_height(10);
        assert_eq!(c.round(), 0);

        let tc = TimeoutCertificate {
            height: 10,
            round: 0,
            sigs: vec![
                make_timeout_sig(&sk0, 0, 10, 0),
                make_timeout_sig(&sk1, 1, 10, 0),
                make_timeout_sig(&sk2, 2, 10, 0),
            ],
        };
        let out = c.on_message(ConsensusMessage::TimeoutCertificate(tc));
        assert!(out.messages.is_empty());
        assert_eq!(c.round(), 1);
    }

    #[test]
    fn timeout_certificate_duplicate_signatures_do_not_count_toward_quorum() {
        let sk0 = consensus_secret_from_seed(&[0x41; 32]);
        let pk0 = consensus_public_from_secret(&sk0);
        let sk1 = consensus_secret_from_seed(&[0x42; 32]);
        let pk1 = consensus_public_from_secret(&sk1);
        let sk2 = consensus_secret_from_seed(&[0x43; 32]);
        let pk2 = consensus_public_from_secret(&sk2);
        let cfg = ConsensusConfig {
            epoch_length: 100,
            committee_size: 3,
            max_round_ms: 5000,
        };
        let validators = ValidatorSet {
            validators: vec![pk0.clone(), pk1, pk2],
        };
        let mut c = Ult7RockLattice::new(cfg, validators, sk0.clone(), pk0);
        c.set_height(10);
        assert_eq!(c.round(), 0);

        let dup = make_timeout_sig(&sk0, 0, 10, 0);
        let tc = TimeoutCertificate {
            height: 10,
            round: 0,
            sigs: vec![dup.clone(), dup.clone(), dup],
        };
        let out = c.on_message(ConsensusMessage::TimeoutCertificate(tc));
        assert!(out.messages.is_empty());
        assert_eq!(c.round(), 0);
    }
}
