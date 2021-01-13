#[macro_use] extern crate log;

mod agent;

use agent::{Agent, error::Error as AgentError, Identity, Response};
use std::os::unix::net::{UnixListener};

use rustica::rustica_client::{RusticaClient};
use rustica::{CertificateRequest, ChallengeRequest};

use rustica_sshkey::yubikey::{asn_cert_signer, ssh_cert_signer, ssh_cert_fetch_pubkey};

use std::collections::HashMap;
use std::time::SystemTime;
use tokio::runtime::Runtime;
use yubikey_piv::key::{RetiredSlotId, SlotId};

pub mod rustica {
    tonic::include_proto!("rustica");
}

struct Handler {
    cert: Option<Identity>,
    stale_at: u64,
}

async fn refresh_certificate() -> Option<Identity> {
    let user_key_slot = SlotId::Retired(RetiredSlotId::R13);
    let ssh_pubkey = ssh_cert_fetch_pubkey(user_key_slot).unwrap();
    
    let encoded_key = format!("{}", ssh_pubkey);
    println!("Requesting cert for key with fingerprint: {}", ssh_pubkey.fingerprint());
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

    let mut client = match RusticaClient::connect("http://[::1]:50051").await {
        Ok(c) => c,
        Err(_e) => return None,
    };

    let response = match client.certificate(request).await {
        Ok(r) => r,
        Err(_e) => return None,
    };

    let response = response.into_inner();
    
    let cert: Vec<&str> = response.certificate.split(" ").collect();

    Some(agent::Identity {
        key_blob: base64::decode(cert[1]).unwrap(),
        key_comment: "JIT Cert".to_string(),
    })
}

impl agent::SSHAgentHandler for Handler {
    fn new() -> Self {
        Handler {
            cert: None,
            stale_at: 0,
        }
    }

    fn identities(&mut self) -> Result<Response, AgentError> {
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if let Some(cert) = &self.cert {
            if timestamp < self.stale_at {
                debug!("Certificate has not expired, not refreshing");
                return Ok(Response::Identities(vec![cert.clone()]));
            }
        }
        Runtime::new().unwrap().block_on(async {
            match refresh_certificate().await {
                Some(identity) => {
                    self.cert = Some(identity.clone());
                    Ok(Response::Identities(vec![identity]))
                },
                None => Err(agent::error::Error::from("Could not refresh certificate")),
            }
        })
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

impl Handler {
    fn new() -> Self {
        Handler {
            cert: None,
            stale_at: 0,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {    
    println!("Starting Rustica Agent");

    let socket_path = "rustica.sock";
    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(Handler::new(), socket);

    Ok(())
}