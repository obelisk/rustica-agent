#[macro_use] extern crate log;

mod agent;
mod rustica;

use agent::{Agent, error::Error as AgentError, Identity, SSHAgentHandler, Response};
use std::os::unix::net::{UnixListener};

use rustica::refresh_certificate;
use rustica_sshkey::yubikey::ssh_cert_signer;

use std::time::SystemTime;
use yubikey_piv::key::{RetiredSlotId, SlotId};


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
        match refresh_certificate() {
            Some(cert) => {
                let ident = Identity {
                    key_blob: cert.cert,
                    key_comment: cert.comment,
                };
                self.cert = Some(ident.clone());
                Ok(Response::Identities(vec![ident]))
            },
            None => Err(agent::error::Error::from("Could not refresh certificate")),
        }
    }

    fn sign_request(&mut self, pubkey: Vec<u8>, data: Vec<u8>, flags: u32) -> Result<agent::Response, agent::error::Error> {
        let signature = ssh_cert_signer(&data, SlotId::Retired(RetiredSlotId::R13)).unwrap();
        let signature = (&signature[27..]).to_vec();

        let response = agent::Response::SignResponse {
            algo_name: String::from("ecdsa-sha2-nistp256"),
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

fn main() -> Result<(), Box<dyn std::error::Error>> {    
    println!("Starting Rustica Agent");

    let socket_path = "rustica.sock";
    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(Handler::new(), socket);

    Ok(())
}