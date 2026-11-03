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
        SignerTrait::sign(self, params)
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
            let sign = SignerTrait::sign(self, params.clone())?; // Generate signature
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

        let value: Value = serde_json::from_str(&body)?;

        // RFC 8785 JSON Canonicalization
        let canonical = serde_json_canonicalizer::to_string(&value)?;

        let result = serde_json::from_str::<HashMap<String, Value>>(&canonical)?;

        Ok(result)
    }

    fn check_sign(&self, params: HashMap<String, Value>, sign: String) -> bool {
        SignerTrait::verify(self, params, sign)
    }

    fn verify(&self, params: HashMap<String, Value>, sign: impl Into<String>) -> bool {
        match SignerTrait::sign(self, params) {
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

    pub fn to_string(&self, params: JsValue) -> Result<String, JsValue> {
        let params: HashMap<String, Value> = parse_params(params)?;

        SignerTrait::to_string(self, params).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn verify(&self, params: JsValue, sign: String) -> Result<bool, JsValue> {
        let params: HashMap<String, Value> = parse_params(params)?;

        Ok(SignerTrait::verify(self, params, sign))
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

        let base64_str = signatory.to_string(params.clone()).unwrap();
        println!("Base64 encoded: {}", base64_str);

        let decoded_params = signatory.decrypt(base64_str).unwrap();
        println!("decoded_params: {:#?}", &decoded_params);

        let sign = "F8834B3D1BE660D268DFF7278D16F848";
        let is_valid = signatory.verify(decoded_params.clone(), sign);

        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_parse_value() {
        let signatory = Signatory::new("ds069ed4223ac1660f");

        let input = "eyJjbGllbnRfaWQiOiIxNjMyNzEyOCIsIm1ldGhvZCI6ImFuZHJvaWQuc2h1dGRvd24iLCJzaWduIjoiRjg4MzRCM0QxQkU2NjBEMjY4REZGNzI3OEQxNkY4NDgiLCJ0aW1lc3RhbXAiOiIxNzI3NDk0NjQ1In0=";

        let value = signatory
            .decrypt(input)
            .unwrap_or_else(|err| panic!("decrypt error: {:#?}", err));

        assert_eq!(
            value.get("client_id").and_then(|v| v.as_str()),
            Some("16327128")
        );
    }
}
