use rustica::rustica_client::{RusticaClient};
use rustica::{CertificateRequest, ChallengeRequest};

use rustica_sshkey::yubikey::{asn_cert_signer, ssh_cert_fetch_pubkey};

use std::collections::HashMap;
use tokio::runtime::Runtime;
use yubikey_piv::key::{RetiredSlotId, SlotId};

pub mod rustica {
    tonic::include_proto!("rustica");
}

pub struct RusticaCert {
    pub cert: Vec<u8>,
    pub comment: String,
}

pub async fn refresh_certificate_async() -> Option<RusticaCert> {
    let user_key_slot = SlotId::Retired(RetiredSlotId::R13);
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
    let challenge_signature = hex::encode(asn_cert_signer(&hex::decode(&response.challenge).unwrap(), user_key_slot).unwrap());
    let request = tonic::Request::new(CertificateRequest {
        pubkey: encoded_key.to_string(),
        cert_type: 1,
        key_id: String::from("JITC-Rustica-Agent"),
        challenge_time: response.time,
        critical_options: HashMap::new(),
        extensions: extensions,
        servers: vec!["atheris".to_string()],
        principals: vec!["obelisk".to_string()],
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
        Ok(r) => r,
        Err(_e) => return None,
    };

    let response = response.into_inner();
    let cert: Vec<&str> = response.certificate.split(' ').collect();

    Some(RusticaCert {
        cert: base64::decode(cert[1]).unwrap(),
        comment: "JITC".to_string(),
    })
}

pub fn refresh_certificate() -> Option<RusticaCert> {
    Runtime::new().unwrap().block_on(async {
        refresh_certificate_async().await
    })
}