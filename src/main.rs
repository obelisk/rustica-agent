#[macro_use] extern crate log;

mod sshagent;
mod rustica;

use sshagent::{Agent, error::Error as AgentError, Identity, SSHAgentHandler, Response};
use std::os::unix::net::{UnixListener};

use rustica::refresh_certificate;
use rustica_keys::yubikey::{
    provision,
    ssh::{
        convert_to_ssh_pubkey,
        ssh_cert_signer,
        ssh_cert_fetch_pubkey,
    }
};

use std::time::SystemTime;
use yubikey_piv::key::{AlgorithmId, RetiredSlotId, SlotId};


struct Handler {
    cert: Option<Identity>,
    stale_at: u64,
}

impl SSHAgentHandler for Handler {
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
        match refresh_certificate(SlotId::Retired(RetiredSlotId::R17)) {
            Some(cert) => {
                let ident = Identity {
                    key_blob: cert.cert,
                    key_comment: cert.comment,
                };
                self.cert = Some(ident.clone());
                Ok(Response::Identities(vec![ident]))
            },
            None => Err(AgentError::from("Could not refresh certificate")),
        }
    }

    /// Pubkey is currently unused because the idea is to only ever have a single cert which itself is only
    /// active for a very small window of time
    fn sign_request(&mut self, _pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> Result<Response, AgentError> {
        let signature = ssh_cert_signer(&data, SlotId::Retired(RetiredSlotId::R17)).unwrap();
        let signature = (&signature[27..]).to_vec();

        let pubkey = ssh_cert_fetch_pubkey(SlotId::Retired(RetiredSlotId::R17)).unwrap();

        let response = Response::SignResponse {
            algo_name: String::from(pubkey.key_type.name),
            signature,
        };

        Ok(response)
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

fn provision_new_key(slot: SlotId) {
    println!("Provisioning new key in slot: {:?}", slot);
    match provision(b"123456", slot, AlgorithmId::EccP384) {
        Ok(pk) => {
            let pk = convert_to_ssh_pubkey(&pk).unwrap();
            println!("Access Fingerprint: {}", pk.fingerprint().hash);
        },
        Err(_) => panic!("Could not provision device with new key"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {  
    env_logger::init();  
    println!("Starting Rustica Agent");
    let slot = SlotId::Retired(RetiredSlotId::R17);

    match ssh_cert_fetch_pubkey(slot) {
        Some(x) => println!("Access Fingerprint: {}", x.fingerprint().hash),
        None => provision_new_key(slot),
    };

    let socket_path = "rustica.sock";
    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(Handler::new(), socket);

    Ok(())
}