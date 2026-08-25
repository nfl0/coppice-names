use ::coppice as coppice_core;
use coppice_core::{carrier, transport};

const RUNTIME_ID: [u8; 32] = [0x11; 32];

fn expected_frames(vector: &serde_json::Value) -> Vec<[u8; 512]> {
    vector["frame_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|frame| {
            hex::decode(frame.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect()
}

fn payload_from_frames(frames: &[[u8; 512]], payload_length: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(payload_length);
    let start_len = payload_length.min(carrier::CPV1_START_CHUNK_CAPACITY);
    payload.extend_from_slice(
        &frames[0][carrier::CPV1_START_FRAME_HEADER_LEN
            ..carrier::CPV1_START_FRAME_HEADER_LEN + start_len],
    );
    let mut offset = start_len;
    for frame in frames.iter().skip(1) {
        let len = (payload_length - offset).min(carrier::CPV1_CONTINUATION_CHUNK_CAPACITY);
        payload.extend_from_slice(
            &frame[carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN
                ..carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN + len],
        );
        offset += len;
    }
    payload
}

#[test]
fn frozen_names_cpv1_vectors_preserve_core_framing() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/carrier.json")).unwrap();
    let binding: [u8; 32] = hex::decode(fixture["deployment_id_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        fixture["start_header"],
        carrier::CPV1_START_FRAME_HEADER_LEN
    );
    assert_eq!(
        fixture["start_chunk_cap"],
        carrier::CPV1_START_CHUNK_CAPACITY
    );
    assert_eq!(
        fixture["cont_header"],
        carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN
    );
    assert_eq!(
        fixture["cont_chunk_cap"],
        carrier::CPV1_CONTINUATION_CHUNK_CAPACITY
    );
    assert_eq!(fixture["max_frames"], carrier::CPV1_MAX_FRAMES);
    assert_eq!(fixture["max_payload_len"], carrier::MAX_CPV1_PAYLOAD_LEN);

    for vector in fixture["vectors"].as_array().unwrap() {
        let payload_length = vector["payload_length"].as_u64().unwrap() as usize;
        let expected = expected_frames(vector);
        let payload = vector["payload_hex"]
            .as_str()
            .map(|value| hex::decode(value).unwrap())
            .unwrap_or_else(|| payload_from_frames(&expected, payload_length));
        assert_eq!(
            transport::required_frames(payload_length),
            Ok(expected.len())
        );
        assert_eq!(
            hex::encode(transport::payload_digest(&payload)),
            vector["payload_digest_hex"].as_str().unwrap()
        );
        assert_eq!(
            transport::encode_frames(binding, &payload),
            Ok(expected.clone())
        );
        assert_eq!(
            transport::reconstruct_frames(&expected, binding),
            Ok(payload)
        );
    }
}

#[test]
fn frozen_permutation_and_negative_classes_remain_strict() {
    let payload = (0..944)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let frames = transport::encode_frames(RUNTIME_ID, &payload).unwrap();
    let shuffled = vec![frames[2], frames[0], frames[1]];
    assert_eq!(
        transport::reconstruct_frames(&shuffled, RUNTIME_ID),
        Ok(payload)
    );

    let mut duplicate = frames.clone();
    duplicate[2][6] = 1;
    assert_eq!(
        transport::reconstruct_frames(&duplicate, RUNTIME_ID),
        Err(transport::Error::DuplicateIndex)
    );
    assert_eq!(
        transport::reconstruct_frames(&frames[..2], RUNTIME_ID),
        Err(transport::Error::MissingIndex)
    );
    let mut out_of_range = frames;
    out_of_range[1][6] = 32;
    assert_eq!(
        transport::reconstruct_frames(&out_of_range, RUNTIME_ID),
        Err(transport::Error::IndexOutOfRange)
    );
}
