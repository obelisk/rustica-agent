use rustica::rustica_client::{RusticaClient};
use rustica::{CertificateRequest, ChallengeRequest};

use rustica_keys::yubikey::{AlgorithmId, sign_data, ssh::ssh_cert_fetch_pubkey};

use std::collections::HashMap;
use tokio::runtime::Runtime;
use yubikey_piv::key::SlotId;

pub mod rustica {
    tonic::include_proto!("rustica");
}

pub struct RusticaCert {
    pub cert: Vec<u8>,
    pub comment: String,
}

pub async fn refresh_certificate_async(user_key_slot: SlotId) -> Option<RusticaCert> {
    let ssh_pubkey = ssh_cert_fetch_pubkey(user_key_slot).unwrap();
    
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

    let challenge_signature = match sign_data(&decoded_challenge, AlgorithmId::EccP384, user_key_slot) {
        Ok(v) => hex::encode(v),
        Err(_) => {
            error!("Couldn't sign challenge with YubiKey. Is it connected and configured?");
            return None;
        }
    };

    // We don't request any servers because Rustica will give us a cert good for all
    // certs we have access to. For that reason we also don't have to request any principals
    // as our allowed principals are tied to the fingerprint of our public key. The fields
    // are part of the API for future expansion to allow requesting of restricted certs
    let request = tonic::Request::new(CertificateRequest {
        pubkey: encoded_key.to_string(),
        cert_type: 1,
        key_id: String::from("JITC-Rustica-Agent"),
        challenge_time: response.time,
        critical_options: HashMap::new(),
        extensions,
        servers: vec![],
        principals: vec![],
        valid_before: 0xFFFFFFFFFFFFFFFF,
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

    let cert: Vec<&str> = response.certificate.split(' ').collect();
    let parsed_cert = rustica_keys::Certificate::from_string(&response.certificate).unwrap();
    debug!("{:#}", parsed_cert);
    debug!("{}", parsed_cert);
    Some(RusticaCert {
        cert: base64::decode(cert[1]).unwrap(),
        comment: "JITC".to_string(),
    })
}

pub fn refresh_certificate(slot: SlotId) -> Option<RusticaCert> {
    Runtime::new().unwrap().block_on(async {
        refresh_certificate_async(slot).await
    })
}