use super::*;
use orchard::circuit::state_note_binding::spend_auth_owner_key_bytes;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};

#[test]
fn owner_field_requires_a_real_non_identity_ak() {
    let spending_key = SpendingKey::from_bytes([7; 32]).unwrap();
    let ask = SpendAuthorizingKey::from(&spending_key);
    assert!(owner_key_field(spend_auth_owner_key_bytes(&ask)).is_ok());
    assert_eq!(owner_key_field([0; 32]), Err(StateError::InvalidOwner));
    let invalid_curve_encoding = (1..10_000u64)
        .map(|value| pallas::Base::from(value).to_repr())
        .find(|bytes| VerificationKey::<SpendAuth>::try_from(*bytes).is_err())
        .expect("a small canonical field search finds a non-key encoding");
    assert_eq!(
        owner_key_field(invalid_curve_encoding),
        Err(StateError::InvalidOwner)
    );
}
