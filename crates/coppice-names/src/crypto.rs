use blake2b_simd::Params;

const PERSONALIZATION_LEN: usize = 16;
const HASH_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    LabelTooLong,
    LabelNotAscii,
}

pub fn personalization(label: &str) -> Result<[u8; PERSONALIZATION_LEN], Error> {
    let bytes = label.as_bytes();
    if bytes.len() > PERSONALIZATION_LEN {
        return Err(Error::LabelTooLong);
    }
    if !bytes.is_ascii() {
        return Err(Error::LabelNotAscii);
    }

    let mut output = [0; PERSONALIZATION_LEN];
    output[..bytes.len()].copy_from_slice(bytes);
    Ok(output)
}

pub fn hash(label: &str, message: &[u8]) -> Result<[u8; HASH_LEN], Error> {
    let personalization = personalization(label)?;
    let digest = Params::new()
        .hash_length(HASH_LEN)
        .personal(&personalization)
        .hash(message);
    Ok(digest
        .as_bytes()
        .try_into()
        .expect("fixed BLAKE2b digest length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_json_vectors_match() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/hashes.json")).unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 28);

        for vector in vectors {
            let label = vector["label"].as_str().unwrap();
            let message = hex::decode(vector["message_hex"].as_str().unwrap()).unwrap();
            let expected_personalization: [u8; PERSONALIZATION_LEN] =
                hex::decode(vector["personalization_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
            let expected_hash: [u8; HASH_LEN] =
                hex::decode(vector["expected_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();

            assert_eq!(personalization(label).unwrap(), expected_personalization);
            assert_eq!(hash(label, &message).unwrap(), expected_hash);
        }
    }

    #[test]
    fn labels_longer_than_sixteen_bytes_are_rejected() {
        assert_eq!(
            personalization("CoppiceLabelTooLong"),
            Err(Error::LabelTooLong)
        );
        assert_eq!(
            hash("CoppiceLabelTooLong", b"message"),
            Err(Error::LabelTooLong)
        );
    }
}
