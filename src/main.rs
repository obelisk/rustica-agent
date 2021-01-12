#[macro_use] extern crate log;

mod agent;

use agent::Agent;
use std::os::unix::net::{UnixListener};

use rustica::rustica_client::{RusticaClient};
use rustica::{CertificateRequest, ChallengeRequest};

use rustica_sshkey::yubikey::{asn_cert_signer, ssh_cert_signer, ssh_cert_fetch_pubkey};

use std::collections::HashMap;
use yubikey_piv::key::{RetiredSlotId, SlotId};

pub mod rustica {
    tonic::include_proto!("rustica");
}

struct Handler {
    identities: Vec<agent::Identity>
}

impl agent::SSHAgentHandler for Handler {
    fn new() -> Self {
        Handler {
            identities: vec![]
        }
    }

    fn identities(&mut self) -> Result<agent::Response, agent::error::Error> {
        println!("Refreshing certificate from authority");
        let our_identity = agent::Identity {
            key_blob: self.identities[0].key_blob.clone(),
            key_comment: "Test".to_string()
        };
        Ok(agent::Response::Identities(vec![our_identity]))
    }

    fn sign_request(&mut self, pubkey: Vec<u8>, data: Vec<u8>, flags: u32) -> Result<agent::Response, agent::error::Error> {
        let signature = ssh_cert_signer(&data, SlotId::Retired(RetiredSlotId::R13)).unwrap();
        let signature = (&signature[27..]).to_vec();

        let response = agent::Response::SignResponse {
            algo_name: String::from("ecdsa-sha2-nistp256"),
            signature,
        };

        return Ok(response);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {    
    println!("Starting Rustica Agent");
    let user_key_slot = SlotId::Retired(RetiredSlotId::R13);
    let ssh_pubkey = ssh_cert_fetch_pubkey(user_key_slot).unwrap();
    
    let encoded_key = format!("{}", ssh_pubkey);
    println!("Requesting cert for key with fingerprint: {}", ssh_pubkey.fingerprint());
    let request = tonic::Request::new(ChallengeRequest {
        pubkey: encoded_key.to_string(),
    });

    let mut client = RusticaClient::connect("http://[::1]:50051").await?;
    let response = client.challenge(request).await?;

    let response = response.into_inner();
    let challenge_signature = hex::encode(asn_cert_signer(&hex::decode(&response.challenge).unwrap(), user_key_slot).unwrap());
    let request = tonic::Request::new(CertificateRequest {
        pubkey: encoded_key.to_string(),
        cert_type: 1,
        key_id: String::from("JITC:obelisk@exclave"),
        challenge_time: response.time,
        critical_options: HashMap::new(),
        extensions: HashMap::new(),
        servers: vec!["atheris".to_string()],
        principals: vec!["obelisk".to_string()],
        valid_before: 0xFFFFFFFFFFFFFFFF,
        valid_after: 0x0,
        challenge: response.challenge,
        challenge_signature,
    });

    let mut client = RusticaClient::connect("http://[::1]:50051").await?;
    let response = client.certificate(request).await?;
    let response = response.into_inner();
    
    let cert: Vec<&str> = response.certificate.split(" ").collect();
    let cert = agent::Identity {
        key_blob: base64::decode(cert[1]).unwrap(),
        key_comment: "JIT Cert".to_string(),
    };

    let socket_path = "rustica.sock";
    let handler = Handler {
        identities: vec![cert],
    };
    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    Ok(())
}