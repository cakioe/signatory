use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose;
use md5;
use serde_json::Value;
use std::collections::HashMap;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct Signatory(String);

pub trait SignerTrait {
    fn new(secret: impl Into<String>) -> Self
    where
        Self: Sized;

    fn current_timestamp() -> i64;

    fn to_string(&self, params: HashMap<String, Value>) -> Result<String, anyhow::Error>;
    fn to_json(&self, params: HashMap<String, Value>) -> Result<String, anyhow::Error>;
    fn decrypt(&self, params: impl Into<String>) -> Result<HashMap<String, Value>, anyhow::Error>;

    #[deprecated(since = "1.2.0", note = "please use `sign` instead")]
    fn generate_sign(&self, params: HashMap<String, Value>) -> Result<String, anyhow::Error>;
    fn sign(&self, params: HashMap<String, Value>) -> Result<String, anyhow::Error>;

    #[deprecated(since = "1.2.0", note = "please use `verify` instead")]
    fn check_sign(&self, params: HashMap<String, Value>, sign: String) -> bool;
    fn verify(&self, params: HashMap<String, Value>, sign: impl Into<String>) -> bool;
}

impl SignerTrait for Signatory {
    fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    fn current_timestamp() -> i64 {
        #[cfg(feature = "wasm")]
        {
            (js_sys::Date::now() / 1000.0) as i64
        }

        #[cfg(not(feature = "wasm"))]
        {
            chrono::Utc::now().timestamp()
        }
    }

    fn generate_sign(&self, params: HashMap<String, Value>) -> Result<String, anyhow::Error> {
        self.sign(params)
    }

    fn sign(&self, mut params: HashMap<String, Value>) -> Result<String, anyhow::Error> {
        if params.is_empty() {
            return Err(anyhow!("params is empty"));
        }

        params.remove("sign");

        let canonical = serde_json_canonicalizer::to_string(&params)?;

        let payload = format!("{}&key={}", canonical, self.0);
        let digest = md5::compute(payload);

        Ok(format!("{:X}", digest))
    }

    fn to_string(&self, params: HashMap<String, Value>) -> Result<String, anyhow::Error> {
        let body = match self.to_json(params) {
            Ok(json) => json,
            Err(e) => {
                return Err(e);
            }
        };

        Ok(general_purpose::STANDARD.encode(body))
    }

    fn to_json(&self, mut params: HashMap<String, Value>) -> Result<String, anyhow::Error> {
        if params.is_empty() {
            return Err(anyhow!("params is empty"));
        }

        if !params.contains_key("timestamp") {
            let now = Self::current_timestamp().to_string();
            params.insert("timestamp".to_string(), Value::String(now));
        }

        if !params.contains_key("sign") {
            let sign = self.sign(params.clone())?; // Generate signature
            params.insert("sign".to_string(), Value::String(sign));
        }

        let value = serde_json::to_value(&params)?;

        let body = serde_json_canonicalizer::to_string(&value)
            .map_err(|e| anyhow!("Failed to canonicalize JSON: {}", e))?;

        Ok(body)
    }

    fn decrypt(&self, params: impl Into<String>) -> Result<HashMap<String, Value>, anyhow::Error> {
        let bytes = general_purpose::STANDARD.decode(&params.into())?;

        let body = String::from_utf8(bytes)?;

        let result = serde_json::from_str::<HashMap<String, Value>>(&body)?;
        Ok(result)
    }

    fn check_sign(&self, params: HashMap<String, Value>, sign: String) -> bool {
        self.verify(params, sign)
    }

    fn verify(&self, params: HashMap<String, Value>, sign: impl Into<String>) -> bool {
        match self.sign(params) {
            Err(e) => {
                println!("Error generating signature: {:#?}", e);
                return false;
            }
            Ok(generated_sign) => sign.into() == generated_sign,
        }
    }
}

#[cfg(feature = "wasm")]
fn parse_params(params: JsValue) -> Result<HashMap<String, Value>, JsValue> {
    serde_wasm_bindgen::from_value(params).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl Signatory {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: String) -> Signatory {
        Signatory(secret)
    }

    /// Get current Unix timestamp in seconds.
    #[wasm_bindgen(js_name = currentTimestamp)]
    pub fn wasm_current_timestamp() -> i64 {
        <Self as SignerTrait>::current_timestamp()
    }

    /// Generate signature.
    #[wasm_bindgen(js_name = sign)]
    pub fn wasm_sign(&self, params: JsValue) -> Result<String, JsValue> {
        let params = parse_params(params)?;

        <Self as SignerTrait>::sign(self, params).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verify signature.
    #[wasm_bindgen(js_name = verify)]
    pub fn wasm_verify(&self, params: JsValue, sign: String) -> Result<bool, JsValue> {
        let params = parse_params(params)?;

        Ok(<Self as SignerTrait>::verify(self, params, sign))
    }

    /// Convert parameters to canonical JSON.
    #[wasm_bindgen(js_name = toJson)]
    pub fn wasm_to_json(&self, params: JsValue) -> Result<String, JsValue> {
        let params = parse_params(params)?;

        <Self as SignerTrait>::to_json(self, params).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Convert parameters to Base64 encoded JSON.
    #[wasm_bindgen(js_name = toString)]
    pub fn wasm_to_string(&self, params: JsValue) -> Result<String, JsValue> {
        let params = parse_params(params)?;

        <Self as SignerTrait>::to_string(self, params)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Decode Base64 JSON.
    #[wasm_bindgen(js_name = decrypt)]
    pub fn wasm_decrypt(&self, params: String) -> Result<JsValue, JsValue> {
        let result = <Self as SignerTrait>::decrypt(self, params)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// @deprecated Use sign() instead.
    #[deprecated(since = "1.2.0", note = "Use sign() instead.")]
    #[wasm_bindgen(js_name = generateSign)]
    pub fn wasm_generate_sign(&self, params: JsValue) -> Result<String, JsValue> {
        let params = parse_params(params)?;

        <Self as SignerTrait>::sign(self, params).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// @deprecated Use verify() instead.
    #[deprecated(since = "1.2.0", note = "Use verify() instead.")]
    #[wasm_bindgen(js_name = checkSign)]
    pub fn wasm_check_sign(&self, params: JsValue, sign: String) -> Result<bool, JsValue> {
        let params = parse_params(params)?;

        Ok(<Self as SignerTrait>::verify(self, params, sign))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;

    #[test]
    fn test_signature_generation_and_validation() {
        let signatory = Signatory::new("ds069ed4223ac1660f");

        let mut params = HashMap::new();
        params.insert(
            "client_id".to_string(),
            Value::String("16327128".to_string()),
        );
        params.insert(
            "method".to_string(),
            Value::String("android.shutdown".to_string()),
        );
        params.insert(
            "timestamp".to_string(),
            Value::String("1727494645".to_string()),
        );

        let sign = signatory.sign(params.clone()).unwrap();
        println!("Generated sign: {}", sign);

        let expected_sign = "F8834B3D1BE660D268DFF7278D16F848";

        assert_eq!(
            sign, expected_sign,
            "The generated signature should match the expected signature"
        );

        params.insert("sign".to_string(), Value::String(sign.clone()));

        let base64_str = signatory.to_string(params.clone()).unwrap();
        println!("Base64 encoded: {}", base64_str);

        let decoded_params = signatory.decrypt(base64_str).unwrap();
        assert_eq!(
            params, decoded_params,
            "Decoded params should match the original params"
        );

        let is_valid = signatory.verify(decoded_params.clone(), sign.clone());
        assert!(is_valid, "Signature should be valid");
    }
}
