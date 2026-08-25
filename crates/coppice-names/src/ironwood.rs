use zcash_primitives::transaction::Transaction;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IronwoodEffects {
    pub commitments: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
}

/// Extracts the wire-canonical fields from actual Ironwood Action objects.
pub fn extract_ironwood_effects(tx: &Transaction) -> IronwoodEffects {
    let Some(bundle) = tx.ironwood_bundle() else {
        return IronwoodEffects::default();
    };
    let mut effects = IronwoodEffects::default();
    for action in bundle.actions() {
        effects.commitments.push(action.cmx().to_bytes());
        effects.nullifiers.push(action.nullifier().to_bytes());
    }
    effects
}
