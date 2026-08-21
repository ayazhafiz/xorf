//! Compatibility fixtures for persisted filter representations.

use xorf::{BinaryFuse16, Descriptor, DmaSerializable};

fn fixture() -> BinaryFuse16 {
    BinaryFuse16 {
        descriptor: Descriptor {
            seed: 1,
            segment_length: 2,
            segment_length_mask: 3,
            segment_count_length: 4,
        },
        fingerprints: vec![5, 6, 7].into_boxed_slice(),
    }
}

fn assert_fixture(filter: &BinaryFuse16) {
    assert_eq!(filter.descriptor.seed, 1);
    assert_eq!(filter.descriptor.segment_length, 2);
    assert_eq!(filter.descriptor.segment_length_mask, 3);
    assert_eq!(filter.descriptor.segment_count_length, 4);
    assert_eq!(filter.fingerprints.as_ref(), [5, 6, 7]);
}

#[test]
fn serde_json_shape_is_stable() {
    const JSON: &str = concat!(
        r#"{"seed":1,"segment_length":2,"segment_length_mask":3,"#,
        r#""segment_count_length":4,"fingerprints":[5,6,7]}"#,
    );

    let encoded = serde_json::to_string(&fixture()).unwrap();
    assert_eq!(encoded, JSON);

    let decoded: BinaryFuse16 = serde_json::from_str(JSON).unwrap();
    assert_fixture(&decoded);
}

#[test]
fn dma_layout_is_stable() {
    let filter = fixture();
    let mut descriptor = [0u8; BinaryFuse16::DESCRIPTOR_LEN];
    filter.dma_copy_descriptor_to(&mut descriptor);

    assert_eq!(
        descriptor,
        [
            1, 0, 0, 0, 0, 0, 0, 0, // seed
            2, 0, 0, 0, // segment_length
            3, 0, 0, 0, // segment_length_mask
            4, 0, 0, 0, // segment_count_length
        ]
    );

    let expected_fingerprints: Vec<u8> = [5u16, 6, 7]
        .into_iter()
        .flat_map(u16::to_ne_bytes)
        .collect();
    assert_eq!(filter.dma_fingerprints(), expected_fingerprints);
}
