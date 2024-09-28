use std::collections::HashMap;
use std::error::Error;
use base64::Engine;
use serde_json::Value;
use base64::engine::general_purpose; // Using the general-purpose base64 encoding engine
use md5;
use chrono::Utc;

/// Struct responsible for signing operations.
pub struct Signatory {
    key: String, // Secret key used for generating signatures
}

impl Signatory {
    /// Creates a new instance of the Signatory struct with the provided secret key.
    ///
    /// # Arguments
    ///
    /// * `key` - A `String` representing the secret key to be used in signing.
    pub fn new(key: String) -> Signatory {
        Signatory { key }
    }

    /// Generates a signature from a given `HashMap<String, Value>`.
    ///
    /// Steps:
    /// 1. Removes the `sign` field from `params` if it exists.
    /// 2. Sorts the remaining keys in ascending order.
    /// 3. Builds a query string from key-value pairs.
    /// 4. Appends the secret key to the query string.
    /// 5. Computes the MD5 hash of the string.
    /// 6. Converts the hash to an uppercase hexadecimal string and returns it.
    ///
    /// # Arguments
    ///
    /// * `params` - A mutable `HashMap<String, Value>` containing the parameters to sign.
    ///
    /// # Returns
    ///
    /// Returns the generated signature as a `Result<String, Box<dyn Error>>`.
    pub fn gen_signature(
        &self,
        mut params: HashMap<String, Value>,
    ) -> Result<String, Box<dyn Error>> {
        // Ensure `params` is not empty
        if params.is_empty() {
            return Err("Params is empty".into());
        }

        // Remove the "sign" field if it exists
        params.remove("sign");

        // Collect and sort the keys of the HashMap
        let mut keys: Vec<String> = params.keys().cloned().collect();
        keys.sort();

        // Build the query string by iterating over sorted keys and values
        let payload: String = keys
            .iter()
            .filter_map(|key| {
                // Convert each value to a string, skipping keys with non-string values
                match params.get(key) {
                    Some(value) => value.as_str().map(|v| format!("{}={}", key, v)),
                    None => None,
                }
            })
            .collect::<Vec<String>>()
            .join("&");

        // Append the secret key to the query string
        let payload_with_key = format!("{}&key={}", payload, self.key);

        // Compute the MD5 hash of the final payload
        let digest = md5::compute(payload_with_key);

        // Convert the hash to uppercase hexadecimal and return the result
        Ok(format!("{:x}", digest).to_ascii_uppercase())
    }

    /// Converts a `HashMap<String, Value>` into a Base64-encoded string.
    ///
    /// This function:
    /// 1. Adds the current timestamp if the `timestamp` key does not exist.
    /// 2. Adds the generated signature to `params` if the `sign` key does not exist.
    /// 3. Serializes the `params` to a JSON string.
    /// 4. Base64 encodes the JSON string and returns it.
    ///
    /// # Arguments
    ///
    /// * `params` - A mutable `HashMap<String, Value>` containing the parameters to encode.
    ///
    /// # Returns
    ///
    /// Returns the Base64 encoded string as `Result<String, Box<dyn Error>>`.
    pub fn to_base64_str(
        &self,
        mut params: HashMap<String, Value>,
    ) -> Result<String, Box<dyn Error>> {
        // Check if `params` is empty
        if params.is_empty() {
            return Err("Params is empty".into());
        }

        // Insert current timestamp if it doesn't exist
        if !params.contains_key("timestamp") {
            let now = Utc::now().timestamp().to_string(); // Get current Unix timestamp as string
            params.insert("timestamp".to_string(), Value::String(now));
        }

        // Insert signature if it doesn't exist
        if !params.contains_key("sign") {
            let sign = self.gen_signature(params.clone()).unwrap(); // Generate signature
            params.insert("sign".to_string(), Value::String(sign));
        }

        // Serialize `HashMap` to a JSON string
        let body = serde_json::to_string(&params)
            .map_err(|e| format!("Failed to serialize params to JSON: {}", e))?;

        // Encode the JSON string to Base64
        let encoded = general_purpose::STANDARD.encode(body);

        Ok(encoded)
    }

    /// Decodes a Base64-encoded string into a `HashMap<String, Value>`.
    ///
    /// This function:
    /// 1. Base64 decodes the input string.
    /// 2. Converts the resulting bytes into a UTF-8 string.
    /// 3. Deserializes the string into a `HashMap`.
    ///
    /// # Arguments
    ///
    /// * `params` - A Base64-encoded string representing serialized `HashMap<String, Value>`.
    ///
    /// # Returns
    ///
    /// Returns the decoded `HashMap<String, Value>` as `Result<HashMap<String, Value>, Box<dyn Error>>`.
    pub fn decrypt_base64_str(
        &self,
        params: String,
    ) -> Result<HashMap<String, Value>, Box<dyn Error>> {
        // Base64 decode the input string
        let bytes = general_purpose::STANDARD.decode(&params).unwrap();

        // Convert the decoded bytes into a UTF-8 string
        let body = String::from_utf8(bytes).unwrap();

        // Deserialize the string into a HashMap
        let result = serde_json::from_str(&body).unwrap();
        Ok(result)
    }

    /// Verifies the integrity of the provided signature.
    ///
    /// This function:
    /// 1. Regenerates the signature based on the `params`.
    /// 2. Compares the regenerated signature with the provided `sign`.
    ///
    /// # Arguments
    ///
    /// * `params` - A `HashMap<String, Value>` representing the parameters to verify.
    /// * `sign` - A `String` representing the signature to verify.
    ///
    /// # Returns
    ///
    /// Returns `true` if the signature matches, otherwise `false`.
    pub fn check_signature(&self, params: HashMap<String, Value>, sign: String) -> bool {
        let value = self.gen_signature(params);
        if value.is_err() {
            return false;
        }

        value.unwrap() == sign
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;

    #[test]
    fn test_signature_generation_and_validation() {
        // Create the signatory instance with a sample key
        let key = "ds069ed4223ac1660f".to_string();
        let signatory = Signatory::new(key);

        // Prepare a sample HashMap
        let mut params = HashMap::new();
        params.insert("client_id".to_string(), Value::String("16327128".to_string()));
        params.insert("method".to_string(), Value::String("android.shutdown".to_string()));
        params.insert("timestamp".to_string(), Value::String("1727494645".to_string()));

        // Generate signature
        let sign = signatory.gen_signature(params.clone()).unwrap();
        println!("Generated sign: {}", sign);

        // Manually provided expected signature (from the decoded JSON)
        let expected_sign = "4D49FFFDE0DA4537160CFC258356277B";

        // Assert that the generated signature matches the expected one
        assert_eq!(sign, expected_sign, "The generated signature should match the expected signature");

        // Insert the expected sign back into the params
        params.insert("sign".to_string(), Value::String(sign.clone()));

        // Now encode the parameters as base64
        let base64_str = signatory.to_base64_str(params.clone()).unwrap();
        println!("Base64 encoded: {}", base64_str);

        // Decode back to HashMap
        let decoded_params = signatory.decrypt_base64_str(base64_str).unwrap();
        assert_eq!(params, decoded_params, "Decoded params should match the original params");

        // Check if signature is valid
        let is_valid = signatory.check_signature(decoded_params.clone(), sign.clone());
        assert!(is_valid, "Signature should be valid");
    }
}
