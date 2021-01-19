use rustica::rustica_client::{RusticaClient};
use rustica::{CertificateRequest, ChallengeRequest};

use rustica_keys::ssh::{PrivateKey, PublicKeyKind, PrivateKeyKind};
use rustica_keys::ssh::{CertType, CurveKind};
use rustica_keys::yubikey::{sign_data, ssh::{ssh_cert_fetch_pubkey, get_ssh_key_type}};

use std::collections::HashMap;
use tokio::runtime::Runtime;
use yubikey_piv::key::SlotId;

pub mod rustica {
    tonic::include_proto!("rustica");
}

pub struct RusticaCert {
    pub cert: String,
    pub comment: String,
}

pub enum Signatory {
    Yubikey(SlotId),
    Direct(PrivateKey),
}

pub async fn refresh_certificate_async(signatory: &Signatory, kind: CertType, principals: Vec<String>, requested_expiration: u64) -> Option<RusticaCert> {
    let ssh_pubkey = match signatory {
        Signatory::Yubikey(user_key_slot) => ssh_cert_fetch_pubkey(*user_key_slot).unwrap(),
        Signatory::Direct(ref privkey) => privkey.pubkey.clone(),
    };
    
    let encoded_key = format!("{}", ssh_pubkey);
    debug!("Requesting cert for key with fingerprint: {}", ssh_pubkey.fingerprint());
    let request = tonic::Request::new(ChallengeRequest {
        pubkey: encoded_key.to_string(),
    });

    let mut client = match RusticaClient::connect("http://[::1]:50051").await {
        Ok(client) => client,
        Err(_e) => return None,
    };

    let response = match client.challenge(request).await {
        Ok(response) => response,
        Err(_e) => return None,
    };

    let mut extensions = HashMap::new();
    extensions.insert(String::from("permit-X11-forwarding"), String::from(""));
    extensions.insert(String::from("permit-agent-forwarding"), String::from(""));
    extensions.insert(String::from("permit-port-forwarding"), String::from(""));
    extensions.insert(String::from("permit-pty"), String::from(""));
    extensions.insert(String::from("permit-user-rc"), String::from(""));

    let response = response.into_inner();
    let decoded_challenge = match hex::decode(&response.challenge) {
        Ok(dc) => dc,
        Err(_) => {
            error!("Server returned a bad challenge");
            return None;
        }
    };

    let challenge_signature = match signatory {
        Signatory::Yubikey(user_key_slot) => {
            let alg = get_ssh_key_type(*user_key_slot)?;

            match sign_data(&decoded_challenge, alg, *user_key_slot) {
                Ok(v) => hex::encode(v),
                Err(_) => {
                    error!("Couldn't sign challenge with YubiKey. Is it connected and configured?");
                    return None;
                }
            }
        },
        Signatory::Direct(privkey) => {
            use ring::{rand, signature};
            let rng = rand::SystemRandom::new();

            match &privkey.kind {
                PrivateKeyKind::Rsa(_) => return None,
                PrivateKeyKind::Ecdsa(key) => {
                    let alg = match key.curve.kind {
                        CurveKind::Nistp256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                        CurveKind::Nistp384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                        CurveKind::Nistp521 => return None,
                    };

                    let pubkey = match &privkey.pubkey.kind {
                        PublicKeyKind::Ecdsa(key) => &key.key,
                        _ => return None,
                    };

                    let key = if key.key[0] == 0x0_u8 {&key.key[1..]} else {&key.key};
                    let key_pair = signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &key, &pubkey).unwrap();
                    //from_private_key_and_public_key
                    //let key_pair = signature::EcdsaKeyPair::from_pkcs8(alg, &key.key).unwrap();
                    hex::encode(key_pair.sign(&rng, &decoded_challenge).unwrap())
                },
                PrivateKeyKind::Ed25519(_) => return None,
            }
        },
    };

    // We don't request any servers because Rustica will give us a cert good for all
    // certs we have access to. For that reason we also don't have to request any principals
    // as our allowed principals are tied to the fingerprint of our public key. The fields
    // are part of the API for future expansion to allow requesting of restricted certs
    let request = tonic::Request::new(CertificateRequest {
        pubkey: encoded_key.to_string(),
        cert_type: kind as u32,
        key_id: String::from(""),           // Rustica Server ignores this field
        challenge_time: response.time,
        critical_options: HashMap::new(),
        extensions,
        servers: vec![],
        principals,
        valid_before: requested_expiration,
        valid_after: 0x0,
        challenge: response.challenge,
        challenge_signature,
    });

    let mut client = match RusticaClient::connect("http://[::1]:50051").await {
        Ok(c) => c,
        Err(_e) => return None,
    };

    let response = match client.certificate(request).await {
        Ok(r) => r.into_inner(),
        Err(_e) => return None,
    };

    match &response {
        response if (response.error_code == 0) => (),
        e_response => {
            error!("Rustica returned error code: {} - {}", e_response.error_code, e_response.error);
            return None
        }
    };

    Some(RusticaCert {
        cert: response.certificate,
        comment: "JITC".to_string(),
    })
}

pub fn refresh_certificate(signatory: &Signatory) -> Option<RusticaCert> {
    Runtime::new().unwrap().block_on(async {
        refresh_certificate_async(signatory, CertType::User, vec![], 0xFFFFFFFFFFFFFFFF).await
    })
}

pub fn get_custom_certificate(signatory: &Signatory, kind: CertType, principals: Vec<String>, expiration_time: u64) -> Option<RusticaCert> {
    Runtime::new().unwrap().block_on(async {
        refresh_certificate_async(signatory, kind, principals, expiration_time).await
    })
}