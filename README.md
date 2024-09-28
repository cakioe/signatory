# Signatory

`Signatory` is a lightweight Rust library for generating and validating signatures, encoding/decoding to and from Base64, and handling timestamp insertion for secure data transmission. It leverages MD5 hashing and allows for URL parameter construction with signed values.

## Features

- Generate signatures by hashing URL-like query strings.
- Base64 encode and decode JSON objects.
- Automatically adds a timestamp if none is provided.
- Validates signatures for incoming requests.

## Installation

Add `Signatory` to your `Cargo.toml` dependencies:

```toml
[dependencies]
signatory = { git = "https://github.com/cakioe/signatory.git" }
```

## Usage

```rust
use signatory_kit::Signatory;
use serde_json::Value;
use std::collections::HashMap;

fn main() {
let key = "your_secret_key".to_string();
let signatory = Signatory::new(key);

    let mut params = HashMap::new();
    params.insert("client_id".to_string(), Value::String("16327128".to_string()));
    params.insert("method".to_string(), Value::String("android.shutdown".to_string()));
    params.insert("timestamp".to_string(), Value::String("1727494645".to_string()));

    // Generate a signature
    let sign = signatory.gen_signature(params.clone()).unwrap();
    println!("Generated signature: {}", sign);

    // Add signature to the params and encode to Base64
    let base64_str = signatory.to_base64_str(params.clone()).unwrap();
    println!("Base64 Encoded: {}", base64_str);

    // Decode the Base64 string back to HashMap
    let decoded_params = signatory.decrypt_base64_str(base64_str).unwrap();
    println!("Decoded params: {:?}", decoded_params);

    // Validate the signature
    let is_valid = signatory.check_signature(decoded_params.clone(), sign.clone());
    assert!(is_valid, "Signature is valid");
}

```