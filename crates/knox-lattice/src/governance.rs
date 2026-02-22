use std::collections::{HashMap, HashSet};

use crate::params::BLOCKS_PER_YEAR;
use crate::{consensus_public_key_id, verify_consensus, LatticePublicKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamChange {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceProposal {
    pub id: u64,
    pub activation_height: u64,
    pub changes: Vec<ParamChange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceVote {
    pub proposal_id: u64,
    pub voter: [u8; 32],
    pub approve: bool,
    pub sig: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernancePhase {
    Developer,
    Community,
}

#[derive(Default, Clone, Debug)]
pub struct GovernanceState {
    proposals: HashMap<u64, GovernanceProposal>,
    approvals: HashMap<u64, HashSet<[u8; 32]>>,
    rejections: HashMap<u64, HashSet<[u8; 32]>>,
}

impl GovernanceState {
    pub fn insert_proposal(&mut self, proposal: GovernanceProposal) -> Result<(), String> {
        if proposal.changes.is_empty() {
            return Err("proposal must contain at least one change".to_string());
        }
        if self.proposals.contains_key(&proposal.id) {
            return Err("proposal already exists".to_string());
        }
        self.proposals.insert(proposal.id, proposal);
        Ok(())
    }

    pub fn cast_vote(
        &mut self,
        vote: GovernanceVote,
        validator_keys: &[LatticePublicKey],
    ) -> Result<(), String> {
        if !self.proposals.contains_key(&vote.proposal_id) {
            return Err("proposal not found".to_string());
        }
        let Some(pk) = validator_keys
            .iter()
            .find(|pk| consensus_public_key_id(pk) == vote.voter)
        else {
            return Err("voter is not in validator set".to_string());
        };
        let msg = governance_vote_signing_hash(vote.proposal_id, vote.approve);
        if !verify_consensus(pk, &msg, &vote.sig) {
            return Err("invalid governance vote signature".to_string());
        }
        let yes = self.approvals.entry(vote.proposal_id).or_default();
        let no = self.rejections.entry(vote.proposal_id).or_default();
        yes.remove(&vote.voter);
        no.remove(&vote.voter);
        if vote.approve {
            yes.insert(vote.voter);
        } else {
            no.insert(vote.voter);
        }
        Ok(())
    }

    pub fn approved(
        &self,
        proposal_id: u64,
        validator_count: usize,
        quorum_ratio_num: usize,
        quorum_ratio_den: usize,
    ) -> bool {
        let yes = self
            .approvals
            .get(&proposal_id)
            .map(|s| s.len())
            .unwrap_or_default();
        let needed = quorum(validator_count, quorum_ratio_num, quorum_ratio_den);
        yes >= needed
    }

    pub fn active_changes(
        &self,
        height: u64,
        validator_count: usize,
        quorum_ratio_num: usize,
        quorum_ratio_den: usize,
    ) -> Vec<ParamChange> {
        let mut out = Vec::new();
        for proposal in self.proposals.values() {
            if height < proposal.activation_height {
                continue;
            }
            if self.approved(
                proposal.id,
                validator_count,
                quorum_ratio_num,
                quorum_ratio_den,
            ) {
                out.extend(proposal.changes.clone());
            }
        }
        out
    }
}

pub fn governance_phase(height: u64) -> GovernancePhase {
    let developer_window = BLOCKS_PER_YEAR.saturating_mul(3);
    if height < developer_window {
        GovernancePhase::Developer
    } else {
        GovernancePhase::Community
    }
}

pub fn proposal_active_at(proposal: &GovernanceProposal, height: u64) -> bool {
    height >= proposal.activation_height
}

fn quorum(total: usize, n: usize, d: usize) -> usize {
    if total == 0 || d == 0 {
        return usize::MAX;
    }
    (total.saturating_mul(n).saturating_add(d - 1)) / d
}

fn governance_vote_signing_hash(proposal_id: u64, approve: bool) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-governance-vote-v1");
    h.update(&proposal_id.to_le_bytes());
    h.update(&[approve as u8]);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus_public_from_secret, consensus_secret_from_seed, sign_consensus};

    #[test]
    fn phase_switches_after_three_years() {
        assert_eq!(governance_phase(0), GovernancePhase::Developer);
        assert_eq!(
            governance_phase(BLOCKS_PER_YEAR.saturating_mul(3)),
            GovernancePhase::Community
        );
    }

    #[test]
    fn proposal_quorum_and_activation() {
        let sk1 = consensus_secret_from_seed(&[0x11; 32]);
        let pk1 = consensus_public_from_secret(&sk1);
        let sk2 = consensus_secret_from_seed(&[0x22; 32]);
        let pk2 = consensus_public_from_secret(&sk2);
        let validators = vec![pk1.clone(), pk2.clone()];

        let mut state = GovernanceState::default();
        state
            .insert_proposal(GovernanceProposal {
                id: 7,
                activation_height: 100,
                changes: vec![ParamChange {
                    key: "RING_SIZE".to_string(),
                    value: "48".to_string(),
                }],
            })
            .expect("proposal");
        state
            .cast_vote(
                GovernanceVote {
                    proposal_id: 7,
                    voter: consensus_public_key_id(&pk1),
                    approve: true,
                    sig: sign_consensus(&sk1, &governance_vote_signing_hash(7, true))
                        .expect("sign vote 1"),
                },
                &validators,
            )
            .expect("vote");
        state
            .cast_vote(
                GovernanceVote {
                    proposal_id: 7,
                    voter: consensus_public_key_id(&pk2),
                    approve: true,
                    sig: sign_consensus(&sk2, &governance_vote_signing_hash(7, true))
                        .expect("sign vote 2"),
                },
                &validators,
            )
            .expect("vote");
        assert!(state.approved(7, 3, 2, 3));
        let active = state.active_changes(150, 3, 2, 3);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].key, "RING_SIZE");
    }
}
