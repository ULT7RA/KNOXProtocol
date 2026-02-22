use knox_lattice::params::{CLH_DIMENSION_GROWTH, CLH_UPDATE_INTERVAL, N};
use knox_lattice::ImmunityState;

#[test]
fn immunity_hardens_at_update_interval() {
    let mut state = ImmunityState::genesis();
    let update_height = CLH_UPDATE_INTERVAL;
    state.absorb_contribution(&[3u8; 32], update_height);
    assert_eq!(state.effective_n, N + CLH_DIMENSION_GROWTH);
    assert_eq!(state.last_update_height, update_height);
}
