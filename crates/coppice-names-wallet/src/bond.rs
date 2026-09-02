//! Application request for an exact wallet-controlled bond denomination.

/// Current deployment bond denomination: exactly one ZEC.
pub const REQUIRED_BOND_ZATOSHIS: u64 = coppice_names::protocol::BOND_ZATOSHIS;

/// What the wallet must do before it can construct a Names COMMIT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondInventoryDecision {
    /// An exact, spendable, unreserved one-ZEC Ironwood note is available.
    Ready,
    /// Sufficient Ironwood value exists but the wallet must create the exact
    /// denomination with an ordinary self-transfer and wait for confirmation.
    PrepareExactNote,
    /// The wallet lacks enough spendable Ironwood value even before fees.
    InsufficientFunds,
}

/// Classifies values supplied by the wallet. Names never selects or spends a
/// wallet note here; it only states its exact denomination requirement.
pub fn classify_bond_inventory<I>(spendable_unreserved_values: I) -> BondInventoryDecision
where
    I: IntoIterator<Item = u64>,
{
    let mut total = 0u64;
    for value in spendable_unreserved_values {
        if value == REQUIRED_BOND_ZATOSHIS {
            return BondInventoryDecision::Ready;
        }
        total = total.saturating_add(value);
    }
    if total >= REQUIRED_BOND_ZATOSHIS {
        BondInventoryDecision::PrepareExactNote
    } else {
        BondInventoryDecision::InsufficientFunds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_note_is_ready_even_with_other_values() {
        assert_eq!(
            classify_bond_inventory([20_000, REQUIRED_BOND_ZATOSHIS, 500_000_000]),
            BondInventoryDecision::Ready
        );
    }

    #[test]
    fn enough_value_without_exact_note_requests_wallet_split() {
        assert_eq!(
            classify_bond_inventory([60_000_000, 50_000_000]),
            BondInventoryDecision::PrepareExactNote
        );
    }

    #[test]
    fn insufficient_value_is_explicit() {
        assert_eq!(
            classify_bond_inventory([99_999_999]),
            BondInventoryDecision::InsufficientFunds
        );
    }
}
