use crate::constants::ALGORITHM;
use crate::errors::SecureError;
use crate::id_token::IdToken;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
#[cfg(feature = "tool-signing")]
use {
  crate::jwt,
  crate::stores::key_store::KeyStore,
  base64::{engine::general_purpose, Engine},
  openssl::pkey::Private,
  openssl::rsa::Rsa,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Jwk {
  pub kid: String,
  pub kty: String,
  pub n: String,
  pub e: String,
  pub r#use: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Jwks {
  pub keys: Vec<Jwk>,
}

// Decode a json web token (JWT) using a JwkSet
// Generate a JwkSet from a JSON string:
// let jwks: JwkSet = serde_json::from_str(&jwks_json).expect("Failed to parse jwks json");
pub fn decode_w_aud(token: &str, jwks: &JwkSet, aud: &[&str]) -> Result<IdToken, SecureError> {
  let header =
    decode_header(token).map_err(|e| SecureError::CannotDecodeJwtToken(e.to_string()))?;
  let kid = header.kid.ok_or_else(|| {
    SecureError::CannotDecodeJwtToken("Token doesn't have a `kid` header field".into())
  })?;

  let jwk = jwks.find(&kid).ok_or_else(|| {
    SecureError::CannotDecodeJwtToken("No matching JWK found for the given kid".into())
  })?;

  match jwk.algorithm {
    AlgorithmParameters::RSA(ref rsa) => {
      let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
        .map_err(|e| SecureError::CannotDecodeJwtToken(e.to_string()))?;
      let mut validation = Validation::new(ALGORITHM);
      validation.set_audience(aud);
      jsonwebtoken::decode::<IdToken>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| SecureError::CannotDecodeJwtToken(e.to_string()))
    }
    _ => Err(SecureError::InvalidEncoding),
  }
}

// Decode a json web token (JWT) using a JwkSet
// Generate a JwkSet from a JSON string:
// let jwks: JwkSet = serde_json::from_str(&jwks_json).expect("Failed to parse jwks json");
pub fn decode(token: &str, jwks: &JwkSet) -> Result<IdToken, SecureError> {
  // Decode the JWT header to extract the `kid`
  let header =
    decode_header(token).map_err(|e| SecureError::CannotDecodeJwtToken(e.to_string()))?;
  let kid = header.kid.ok_or_else(|| {
    SecureError::CannotDecodeJwtToken("Token doesn't have a `kid` header field".into())
  })?;

  // Find the JWK corresponding to the `kid`
  let jwk = jwks.find(&kid).ok_or_else(|| {
    SecureError::CannotDecodeJwtToken("No matching JWK found for the given kid".into())
  })?;

  match jwk.algorithm {
    AlgorithmParameters::RSA(ref rsa) => {
      // let decoding_key =
      //   DecodingKey::from_jwk(jwk).map_err(|e| SecureError::CannotDecodeJwtToken(e.to_string()))?;
      let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
        .map_err(|e| SecureError::CannotDecodeJwtToken(e.to_string()))?;

      let mut validation = Validation::new(ALGORITHM);
      validation.validate_aud = false;
      jsonwebtoken::decode::<IdToken>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| SecureError::CannotDecodeJwtToken(e.to_string()))
    }
    _ => Err(SecureError::InvalidEncoding),
  }
}

// Encode a json web token (JWT) using a Jwk
#[cfg(feature = "tool-signing")]
pub fn encode(
  id_token: &IdToken,
  kid: &str,
  rsa_key_pair: Rsa<Private>,
) -> Result<String, SecureError> {
  jwt::encode(id_token, kid, rsa_key_pair)
}

// Generate a JWK from a private key
// Generate a new RSA key
// let rsa_key_pair = Rsa::generate(2048).expect("Failed to generate RSA key");
#[cfg(feature = "tool-signing")]
pub fn generate_jwk(id: &str, rsa_key_pair: &Rsa<Private>) -> Result<Jwk, SecureError> {
  let jwk = Jwk {
    kty: "RSA".to_string(),
    kid: id.to_string(),
    n: general_purpose::URL_SAFE_NO_PAD.encode(rsa_key_pair.n().to_vec()),
    e: general_purpose::URL_SAFE_NO_PAD.encode(rsa_key_pair.e().to_vec()),
    r#use: "sig".to_string(),
  };

  Ok(jwk)
}

// Get a JwkSet using the current keys in the provided KeyStore
#[cfg(feature = "tool-signing")]
pub async fn get_current_jwks(key_store: &dyn KeyStore) -> Result<Jwks, SecureError> {
  let keys = key_store.get_current_keys(3).await?;
  let jwks = Jwks {
    keys: keys
      .iter()
      .map(|(key, value)| generate_jwk(key, value))
      .collect::<Result<Vec<Jwk>, SecureError>>()?,
  };
  Ok(jwks)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_schoology() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjlkNDM0OWM5NGYwOTg5YzQifQ.eyJpc3MiOiJodHRwczovL3NjaG9vbG9neS5zY2hvb2xvZ3kuY29tIiwiYXVkIjpbIjc0ODUzOTM4MTUiXSwic3ViIjoiNjM3Nzg3MjU6OjkyY2U5NzM3N2M1OGVlZWVkY2E2NjcyM2M0YjY5NDk2IiwiZXhwIjoxNzI2MjQyMDI4LCJpYXQiOjE3MjYyNDE0MjgsIm5vbmNlIjoibWlXc2JmM1oyNHZDMjVOYmNpNlNpT3BDV3dyTjE0UkEiLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS9tZXNzYWdlX3R5cGUiOiJMdGlSZXNvdXJjZUxpbmtSZXF1ZXN0IiwiaHR0cHM6Ly9wdXJsLmltc2dsb2JhbC5vcmcvc3BlYy9sdGkvY2xhaW0vdmVyc2lvbiI6IjEuMy4wIiwiaHR0cHM6Ly9wdXJsLmltc2dsb2JhbC5vcmcvc3BlYy9sdGkvY2xhaW0vZGVwbG95bWVudF9pZCI6Ijc0ODUzOTM4MTUtMTM4MDQyNjY3OSIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL3RhcmdldF9saW5rX3VyaSI6Imh0dHBzOi8vYXRvbWljLW94aWRlLmF0b21pY2pvbHQud2luL2x0aS9sYXVuY2giLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS9yb2xlcyI6WyJodHRwOi8vcHVybC5pbXNnbG9iYWwub3JnL3ZvY2FiL2xpcy92Mi9tZW1iZXJzaGlwI0FkbWluaXN0cmF0b3IiLCJodHRwOi8vcHVybC5pbXNnbG9iYWwub3JnL3ZvY2FiL2xpcy92Mi9tZW1iZXJzaGlwI0luc3RydWN0b3IiXX0.Lo8Ywk3YduGNgstvqgIthSjW2OS76jTDp0B5BqhO6olZP_CpbyiSR0sydZTzSroFCNAOzKUfxJ9W_KHbFhv07KpiWWkSkjjLwcuAp2dt811u87G3okfxWmSEQrRLlxjdIS-ZugV7GPtAz1gY3iC20ah60KpQ_JomrHoXylUa1IKQYSm-V076sJ6IzR7Hf33mZILCLjF_2Nfv1Km8I6eWot-r5rAiB7183UGbasXZ0nQFan4RMUdd2aX8f82kP4biNV9Wf8Jll5tFHV4L0gw-DjXShT4Pkql7AanRdLbv6Axtac-SiI2DbvxMwuITSwN9cmjZEz8Sh7Yc-LZRNUbm2g";

    // Decode header and payload without signature verification for testing
    // This is appropriate for testing since we don't have the actual Schoology private key

    // Use the recommended dangerous::insecure_decode function
    let decoded = jsonwebtoken::dangerous::insecure_decode::<IdToken>(token)
      .expect("Failed to decode token payload");

    let decoded_claims = decoded.claims;

    // Verify the claims from the Schoology token
    assert_eq!(decoded_claims.iss, "https://schoology.schoology.com");
    assert_eq!(decoded_claims.aud, "7485393815"); // Fixed the aud value
    assert_eq!(
      decoded_claims.sub,
      "63778725::92ce97377c58eeeedca66723c4b69496"
    );

    // Verify LTI-specific claims
    assert_eq!(decoded_claims.message_type, "LtiResourceLinkRequest");
    assert_eq!(decoded_claims.lti_version, "1.3.0");
    assert_eq!(decoded_claims.deployment_id, "7485393815-1380426679"); // Fixed the deployment_id value
    assert_eq!(
      decoded_claims.target_link_uri,
      "https://atomic-oxide.atomicjolt.win/lti/launch"
    );

    // Verify roles
    assert!(!decoded_claims.roles.is_empty());
    assert!(decoded_claims
      .roles
      .contains(&"http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator".to_string()));
    assert!(decoded_claims
      .roles
      .contains(&"http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor".to_string()));
  }

  // Signature verification against a pre-signed fixture.
  //
  // These are deliberately *not* gated on `tool-signing`: `decode` and
  // `decode_w_aud` verify the Platform's ID token and stay available when the
  // feature is off, so they need coverage in that configuration too. Every other
  // test of these functions mints a signing key first, which requires the
  // feature. Using a checked-in token and JWK set keeps them key-generation free.
  //
  // Regenerate by signing `FIXTURE_TOKEN`'s claims with a fresh 2048-bit RSA key
  // and rebuilding the JWK set from its public parts.
  const FIXTURE_KID: &str = "2025-09-fixture-key";
  const FIXTURE_AUD: &str = "10000000000004";
  const FIXTURE_JWKS: &str = r#"{"keys":[{"kid":"2025-09-fixture-key","kty":"RSA","n":"z2uV8fFSD3veXHl9M74UsaUTxlVkqpW0Od24P2O3ZDP8UT5iB4kXH9TLxxocu35dqbpufQ6vms5efNl6NpMMqFd7Y_QQ8JD6-X_MERkKIvJyDcH7PY_Si56zMW6iUV-IItvnz6UQtmbY_zK8uzJsD_mYv5KNwWGy8hk_lSL4q-PUP_INpS7kK1McBvsIdrZe3YK7O_B2rllRoHZJrMcFHkSfTcQ48RRKzNhYcsdqAbcx3YdqfBnfZ6AKsZgAmMC1LVh-AznCc8x13J2gcagzIp_Gz7HBWchj8Ce8K0Ix_CUqy87q98HGvzcENQ6rehNetLtqq1lfzzg3qGFDUvJQhw","e":"AQAB","use":"sig"}]}"#;
  // Expires 2100-01-01.
  const FIXTURE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjUtMDktZml4dHVyZS1rZXkifQ.eyJhdWQiOiIxMDAwMDAwMDAwMDAwNCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NhbnZhcy5pbnN0cnVjdHVyZS5jb20iLCJub25jZSI6ImZjNWZkYzZkLTVkZDYtNDdmNC1iMmM5LTVkMTIxNmU5Yjc3MSIsInN1YiI6ImE2ZDVjNDQzLTFmNTEtNDc4My1iYTFhLTc2ODZmZmUzYjU0YSIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL21lc3NhZ2VfdHlwZSI6Ikx0aVJlc291cmNlTGlua1JlcXVlc3QiLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS92ZXJzaW9uIjoiMS4zLjAiLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS9yZXNvdXJjZV9saW5rIjp7ImlkIjoiNGRkZTA1ZThjYTE5NzNiY2NhOWJmZmMxM2UxNTQ4ODIwZWVlOTNhMyIsInRpdGxlIjoiRXhhbXBsZSBBc3NpZ25tZW50In0sImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL2RlcGxveW1lbnRfaWQiOiIxOjg4NjVhYTA1YjRiNzliNjRhOTFhODYwNDJlNDNhZjVlYThhZTc5ZWIiLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS90YXJnZXRfbGlua191cmkiOiJodHRwczovL3Rvb2wuZXhhbXBsZS5jb20vbHRpL2xhdW5jaCIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL3JvbGVzIjpbImh0dHA6Ly9wdXJsLmltc2dsb2JhbC5vcmcvdm9jYWIvbGlzL3YyL21lbWJlcnNoaXAjSW5zdHJ1Y3RvciJdLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS9yb2xlX3Njb3BlX21lbnRvciI6W10sImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL2NvbnRleHQiOnsiaWQiOiJjMjhhY2IyZTAyZTJkMWM2YTJhM2IwYTc2YjVkMGExYjdlMGM5YjRmIiwibGFiZWwiOiJDUzEwMSIsInRpdGxlIjoiSW50cm8gdG8gQ29tcHV0ZXIgU2NpZW5jZSJ9fQ.V7V1lpA6Lryvn_5oP9ER5vbtUWCD4UWeM1cGM9_dsuUW61hXIvdRnHhMJbuSSdUxz1u0Dj1qFt0p0W8iZaH8yrL5G5A4g_p79G98Vg8RGWICwW1wa8djeHvtQgfkutk2kiMzYxlx9gMwaRd8xikLbMxQBneM92XdOFUrYYK27IQZCd5txh0c-r6p2Q0Vwo1sAxhcEfoADZhet3R14N7HCK0_8JY0f8328EB80viQzhGWXbXg4g2zzVf7H-mU5RVtfejOJuBofsCWZlNoqbpfvCJ-vvId8zAXWfES_OxHVfFDSFwY1IHu1MMgfqSd6VPtVTaskxUSmXY-hMhToGYQSw";
  // Same key and claims, but expired.
  const FIXTURE_TOKEN_EXPIRED: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjUtMDktZml4dHVyZS1rZXkifQ.eyJhdWQiOiIxMDAwMDAwMDAwMDAwNCIsImV4cCI6MTcwMDAwMzYwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NhbnZhcy5pbnN0cnVjdHVyZS5jb20iLCJub25jZSI6ImZjNWZkYzZkLTVkZDYtNDdmNC1iMmM5LTVkMTIxNmU5Yjc3MSIsInN1YiI6ImE2ZDVjNDQzLTFmNTEtNDc4My1iYTFhLTc2ODZmZmUzYjU0YSIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL21lc3NhZ2VfdHlwZSI6Ikx0aVJlc291cmNlTGlua1JlcXVlc3QiLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS92ZXJzaW9uIjoiMS4zLjAiLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS9yZXNvdXJjZV9saW5rIjp7ImlkIjoiNGRkZTA1ZThjYTE5NzNiY2NhOWJmZmMxM2UxNTQ4ODIwZWVlOTNhMyIsInRpdGxlIjoiRXhhbXBsZSBBc3NpZ25tZW50In0sImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL2RlcGxveW1lbnRfaWQiOiIxOjg4NjVhYTA1YjRiNzliNjRhOTFhODYwNDJlNDNhZjVlYThhZTc5ZWIiLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS90YXJnZXRfbGlua191cmkiOiJodHRwczovL3Rvb2wuZXhhbXBsZS5jb20vbHRpL2xhdW5jaCIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL3JvbGVzIjpbImh0dHA6Ly9wdXJsLmltc2dsb2JhbC5vcmcvdm9jYWIvbGlzL3YyL21lbWJlcnNoaXAjSW5zdHJ1Y3RvciJdLCJodHRwczovL3B1cmwuaW1zZ2xvYmFsLm9yZy9zcGVjL2x0aS9jbGFpbS9yb2xlX3Njb3BlX21lbnRvciI6W10sImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvbHRpL2NsYWltL2NvbnRleHQiOnsiaWQiOiJjMjhhY2IyZTAyZTJkMWM2YTJhM2IwYTc2YjVkMGExYjdlMGM5YjRmIiwibGFiZWwiOiJDUzEwMSIsInRpdGxlIjoiSW50cm8gdG8gQ29tcHV0ZXIgU2NpZW5jZSJ9fQ.IyhYubWBe-fvU1a1iJ3Jw9YtBUuo4sG4mKgssBlwWtE3jAnjFc3OydbH3KC8BERz6Ya4hLJhu0XbB3xUPyPlqMBBPMVyF8NTVX9jxKbsqIuyK1DICZ9uBn8pdUrqogw_ynXfnTWzVzcqlvQppDKP0hMqxoak1O9G1U_3B8Waae8c9w3927cWrzEmlo5AC8Ymogk3KkzljfgOTa_pepC-nPVtp267l5mnRc5GIvkzvSEEnyaGm6rvMn8H_14_ZI0jEnY7iP9LULkrJzQvBx85umZnPcedUViij2hSMSyMLf4vXHf_hRN7IIxw6KNEL3zvRzYE0JXqqQBSDMVSpcWqJQ";

  fn fixture_jwks() -> JwkSet {
    serde_json::from_str(FIXTURE_JWKS).expect("Failed to parse fixture JWK set")
  }

  #[test]
  fn test_decode_fixture_verifies_signature() {
    let claims = decode(FIXTURE_TOKEN, &fixture_jwks()).expect("Failed to decode fixture token");

    assert_eq!(claims.iss, "https://canvas.instructure.com");
    assert_eq!(claims.sub, "a6d5c443-1f51-4783-ba1a-7686ffe3b54a");
    assert_eq!(claims.aud, FIXTURE_AUD);
    assert_eq!(claims.message_type, "LtiResourceLinkRequest");
    assert_eq!(claims.lti_version, "1.3.0");
    assert_eq!(
      claims.deployment_id,
      "1:8865aa05b4b79b64a91a86042e43af5ea8ae79eb"
    );
    assert_eq!(
      claims.target_link_uri,
      "https://tool.example.com/lti/launch"
    );
    assert!(claims
      .roles
      .contains(&"http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor".to_string()));
    assert_eq!(
      claims
        .resource_link
        .as_ref()
        .expect("Missing resource link")
        .title
        .as_deref(),
      Some("Example Assignment")
    );
    assert_eq!(
      claims
        .context
        .as_ref()
        .expect("Missing context")
        .label
        .as_deref(),
      Some("CS101")
    );
    assert!(!claims.is_deep_link_launch());
  }

  #[test]
  fn test_decode_w_aud_fixture_accepts_matching_audience() {
    let claims = decode_w_aud(FIXTURE_TOKEN, &fixture_jwks(), &[FIXTURE_AUD])
      .expect("Failed to decode fixture token");

    assert_eq!(claims.aud, FIXTURE_AUD);
  }

  #[test]
  fn test_decode_w_aud_fixture_rejects_wrong_audience() {
    let result = decode_w_aud(FIXTURE_TOKEN, &fixture_jwks(), &["a-different-client-id"]);

    assert!(matches!(result, Err(SecureError::CannotDecodeJwtToken(_))));
  }

  #[test]
  fn test_decode_fixture_rejects_expired_token() {
    let result = decode(FIXTURE_TOKEN_EXPIRED, &fixture_jwks());

    assert!(matches!(result, Err(SecureError::CannotDecodeJwtToken(_))));
  }

  #[test]
  fn test_decode_fixture_rejects_unknown_kid() {
    // The token's kid is absent from the JWK set, so no key can be selected.
    let jwks: JwkSet = serde_json::from_str(&FIXTURE_JWKS.replace(FIXTURE_KID, "another-kid"))
      .expect("Failed to parse fixture JWK set");

    let result = decode(FIXTURE_TOKEN, &jwks);

    assert!(matches!(result, Err(SecureError::CannotDecodeJwtToken(_))));
  }

  #[test]
  fn test_decode_fixture_rejects_tampered_signature() {
    let (signed_part, signature) = FIXTURE_TOKEN
      .rsplit_once('.')
      .expect("Fixture token is not a JWT");
    let replacement = if signature.starts_with('A') { "B" } else { "A" };
    let tampered = format!("{}.{}{}", signed_part, replacement, &signature[1..]);

    let result = decode(&tampered, &fixture_jwks());

    assert!(matches!(result, Err(SecureError::CannotDecodeJwtToken(_))));
  }

  // Tests that mint a signing key, and so need the Tool's own RSA private key.
  #[cfg(feature = "tool-signing")]
  mod signing {
    use super::*;
    use crate::{
      id_token::{AcceptTypes, DeepLinkingClaim, DocumentTargets},
      lti_definitions::LTI_DEEP_LINKING_REQUEST,
    };
    use chrono::{Duration, Utc};

    #[test]
    fn test_encode_decode() {
      let iss = "https://lms.example.com";
      let aud = "https://www.example.com/lti/auth/token".to_string();
      let user_id = "12";
      let rsa_key_pair = Rsa::generate(2048).expect("Failed to generate RSA key");
      let id = "1234567890";
      let jwk = generate_jwk(id, &rsa_key_pair).expect("Failed to generate JWK");

      // Set the expiration time to 15 minutes from now
      let expiration = Utc::now() + Duration::minutes(15);

      let id_token = IdToken {
        iss: iss.to_string(),
        sub: user_id.to_string(),
        aud: aud.clone(),
        exp: expiration.timestamp(),
        message_type: LTI_DEEP_LINKING_REQUEST.to_string(),
        deep_linking: Some(DeepLinkingClaim {
          deep_link_return_url: "example.com".to_string(),
          accept_types: vec![AcceptTypes::Link],
          accept_presentation_document_targets: vec![DocumentTargets::Iframe],
          accept_media_types: None,
          accept_multiple: None,
          accept_lineitem: None,
          auto_create: None,
          title: None,
          text: None,
          data: None,
        }),
        launch_presentation: None,
        ..Default::default()
      };

      // Encode the ID Token using the private key
      let token = encode(&id_token, &jwk.kid, rsa_key_pair).expect("Failed to encode token");

      // Turn the JWK into JSON and then read it back into a JWK set compatible with jsonwebtoken
      let jwks = Jwks { keys: vec![jwk] };
      let jwks_json = serde_json::to_string(&jwks).expect("Serialization failed");
      let jwks: JwkSet = serde_json::from_str(&jwks_json).expect("Failed to parse jwks");

      // Decode the JWT using the JWK set
      let result = decode(&token, &jwks);
      let decoded_claims = result.expect("Failed to decode token");

      assert_eq!(decoded_claims.iss, iss);
      assert_eq!(decoded_claims.aud, aud);
      assert_eq!(decoded_claims.sub, user_id);
      assert!(decoded_claims.is_deep_link_launch());
    }

    #[test]
    fn test_encode_decode_auds() {
      let iss = "https://lms.example.com";
      let aud = "https://www.example.com/lti/auth/token".to_string();
      let user_id = "12";
      let rsa_key_pair = Rsa::generate(2048).expect("Failed to generate RSA key");
      let id = "1234567890";
      let jwk = generate_jwk(id, &rsa_key_pair).expect("Failed to generate JWK");

      // Set the expiration time to 15 minutes from now
      let expiration = Utc::now() + Duration::minutes(15);

      let id_token = IdToken {
        iss: iss.to_string(),
        sub: user_id.to_string(),
        aud: aud.clone(),
        exp: expiration.timestamp(),
        message_type: LTI_DEEP_LINKING_REQUEST.to_string(),
        deep_linking: Some(DeepLinkingClaim {
          deep_link_return_url: "example.com".to_string(),
          accept_types: vec![AcceptTypes::Link],
          accept_presentation_document_targets: vec![DocumentTargets::Iframe],
          accept_media_types: None,
          accept_multiple: None,
          accept_lineitem: None,
          auto_create: None,
          title: None,
          text: None,
          data: None,
        }),
        launch_presentation: None,
        ..Default::default()
      };

      // Encode the ID Token using the private key
      let token = encode(&id_token, &jwk.kid, rsa_key_pair).expect("Failed to encode token");

      // Turn the JWK into JSON and then read it back into a JWK set compatible with jsonwebtoken
      let jwks = Jwks { keys: vec![jwk] };
      let jwks_json = serde_json::to_string(&jwks).expect("Serialization failed");
      let jwks: JwkSet = serde_json::from_str(&jwks_json).expect("Failed to parse jwks");

      // Decode the JWT using the JWK set and aud
      let auds = vec![aud.as_str()];
      let result = decode_w_aud(&token, &jwks, &auds);
      let decoded_claims = result.expect("Failed to decode token");

      assert_eq!(decoded_claims.iss, iss);
      assert_eq!(decoded_claims.aud, aud);
      assert_eq!(decoded_claims.sub, user_id);
      assert!(decoded_claims.is_deep_link_launch());
    }

    #[test]
    fn test_encode_decode_bad_auds() {
      let iss = "https://lms.example.com";
      let aud = "https://www.example.com/lti/auth/token".to_string();
      let user_id = "12";
      let rsa_key_pair = Rsa::generate(2048).expect("Failed to generate RSA key");
      let id = "1234567890";
      let jwk = generate_jwk(id, &rsa_key_pair).expect("Failed to generate JWK");

      // Set the expiration time to 15 minutes from now
      let expiration = Utc::now() + Duration::minutes(15);

      let id_token = IdToken {
        iss: iss.to_string(),
        sub: user_id.to_string(),
        aud: aud.clone(),
        exp: expiration.timestamp(),
        message_type: LTI_DEEP_LINKING_REQUEST.to_string(),
        deep_linking: Some(DeepLinkingClaim {
          deep_link_return_url: "example.com".to_string(),
          accept_types: vec![AcceptTypes::Link],
          accept_presentation_document_targets: vec![DocumentTargets::Iframe],
          accept_media_types: None,
          accept_multiple: None,
          accept_lineitem: None,
          auto_create: None,
          title: None,
          text: None,
          data: None,
        }),
        launch_presentation: None,
        ..Default::default()
      };

      // Encode the ID Token using the private key
      let token = encode(&id_token, &jwk.kid, rsa_key_pair).expect("Failed to encode token");

      // Turn the JWK into JSON and then read it back into a JWK set compatible with jsonwebtoken
      let jwks = Jwks { keys: vec![jwk] };
      let jwks_json = serde_json::to_string(&jwks).expect("Serialization failed");
      let jwks: JwkSet = serde_json::from_str(&jwks_json).expect("Failed to parse jwks");

      // Decode the JWT using the JWK set and aud
      let auds = vec!["bad_aud"];
      let result = decode_w_aud(&token, &jwks, &auds);
      assert!(result.is_err());
    }
  }
}
