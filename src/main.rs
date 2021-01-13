#[macro_use] extern crate log;

mod sshagent;
mod rustica;

use sshagent::{Agent, error::Error as AgentError, Identity, SSHAgentHandler, Response};
use std::os::unix::net::{UnixListener};

use rustica::refresh_certificate;
use rustica_keys::yubikey::ssh_cert_signer;

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
            None => Err(AgentError::from("Could not refresh certificate")),
        }
    }

    /// Pubkey is currently unused because the idea is to only ever have a single cert which itself is only
    /// active for a very small window of time
    fn sign_request(&mut self, _pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> Result<Response, AgentError> {
        let signature = ssh_cert_signer(&data, SlotId::Retired(RetiredSlotId::R13)).unwrap();
        let signature = (&signature[27..]).to_vec();

        let response = Response::SignResponse {
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
    env_logger::init();  
    println!("Starting Rustica Agent");

    let socket_path = "rustica.sock";
    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(Handler::new(), socket);

    Ok(())
}