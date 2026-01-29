//! Tests for hex string validation.

use agent_pack::{parse_hex_32, validate_hex_32, HexError};

#[test]
fn test_valid_hex_32_bytes() {
    let valid = "0x0000000000000000000000000000000000000000000000000000000000000001";
    assert!(validate_hex_32(valid).is_ok());

    let parsed = parse_hex_32(valid).unwrap();
    assert_eq!(parsed[31], 1);
    assert_eq!(parsed[0], 0);
}

#[test]
fn test_valid_hex_all_fs() {
    let valid = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert!(validate_hex_32(valid).is_ok());

    let parsed = parse_hex_32(valid).unwrap();
    assert!(parsed.iter().all(|&b| b == 0xff));
}

#[test]
fn test_invalid_hex_wrong_length_too_short() {
    let too_short = "0x0001";
    let result = validate_hex_32(too_short);
    assert!(matches!(
        result,
        Err(HexError::InvalidLength {
            expected: 64,
            actual: 4
        })
    ));
}

#[test]
fn test_invalid_hex_wrong_length_too_long() {
    let too_long = "0x00000000000000000000000000000000000000000000000000000000000000010000";
    let result = validate_hex_32(too_long);
    assert!(matches!(result, Err(HexError::InvalidLength { .. })));
}

#[test]
fn test_invalid_hex_no_prefix() {
    let no_prefix = "0000000000000000000000000000000000000000000000000000000000000001";
    let result = validate_hex_32(no_prefix);
    assert_eq!(result, Err(HexError::MissingPrefix));
}

#[test]
fn test_invalid_hex_bad_chars() {
    let bad_chars = "0xGGGG000000000000000000000000000000000000000000000000000000000001";
    let result = validate_hex_32(bad_chars);
    assert!(matches!(result, Err(HexError::InvalidHex(_))));
}

#[test]
fn test_invalid_hex_uppercase_valid() {
    // Uppercase hex should be valid
    let uppercase = "0xABCDEF0000000000000000000000000000000000000000000000000000000001";
    assert!(validate_hex_32(uppercase).is_ok());
}

#[test]
fn test_invalid_hex_mixed_case_valid() {
    let mixed = "0xAbCdEf0000000000000000000000000000000000000000000000000000000001";
    assert!(validate_hex_32(mixed).is_ok());
}

#[test]
fn test_parse_hex_without_prefix() {
    // parse_hex_32 accepts without prefix
    let no_prefix = "0000000000000000000000000000000000000000000000000000000000000001";
    let result = parse_hex_32(no_prefix);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()[31], 1);
}

#[test]
fn test_image_id_format() {
    // Known IMAGE_ID from yield agent
    let image_id = "0x5f42241afd61bf9e341442c8baffa9c544cf20253720f2540cf6705f27bae2c4";
    assert!(validate_hex_32(image_id).is_ok());
}

#[test]
fn test_agent_code_hash_format() {
    // Known agent code hash from yield agent
    let code_hash = "0x5aac6b1fedf1b0c0ccc037c3223b7b5c8b679f48b9c599336c0dc777be88924b";
    assert!(validate_hex_32(code_hash).is_ok());
}
