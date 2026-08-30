use super::super::payment::{
    PAYMENT_RECORD_HEADER_LEN, PAYMENT_RECORD_MAGIC, PaymentNetwork, PaymentRecord,
    PaymentRecordError,
};
const MAINNET_UA: &str = "u1pg2aaph7jp8rpf6yhsza25722sg5fcn3vaca6ze27hqjw7jvvhhuxkpcg0ge9xh6drsgdkda8qjq5chpehkcpxf87rnjryjqwymdheptpvnljqqrjqzjwkc2ma6hcq666kgwfytxwac8eyex6ndgr6ezte66706e3vaqrd25dzvzkc69kw0jgywtd0cmq52q5lkw6uh7hyvzjse8ksx";

fn mainnet_ua() -> String {
    MAINNET_UA.to_owned()
}

#[test]
fn payment_record_round_trips_canonical_mainnet_ua() {
    let address = mainnet_ua();
    let record = PaymentRecord::new(PaymentNetwork::Main, &address).unwrap();
    let bytes = record.encode();
    assert_eq!(&bytes[..4], &PAYMENT_RECORD_MAGIC);
    assert_eq!(bytes.len(), PAYMENT_RECORD_HEADER_LEN + address.len());
    let decoded = PaymentRecord::decode(&bytes, PaymentNetwork::Main).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.address(), address);
}

#[test]
fn payment_record_rejects_wrong_network_and_noncanonical_bytes() {
    let address = mainnet_ua();
    assert_eq!(
        PaymentRecord::new(PaymentNetwork::Test, &address),
        Err(PaymentRecordError::WrongNetwork)
    );
    let mut bytes = PaymentRecord::new(PaymentNetwork::Main, &address)
        .unwrap()
        .encode();
    bytes[7] = bytes[7].saturating_add(1);
    assert_eq!(
        PaymentRecord::decode(&bytes, PaymentNetwork::Main),
        Err(PaymentRecordError::InvalidFraming)
    );
}

#[test]
fn payment_record_requires_a_shielded_unified_receiver() {
    let transparent = "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs";
    assert!(matches!(
        PaymentRecord::new(PaymentNetwork::Main, transparent),
        Err(PaymentRecordError::InvalidEncoding)
            | Err(PaymentRecordError::NotUnified)
            | Err(PaymentRecordError::WrongNetwork)
    ));
}
