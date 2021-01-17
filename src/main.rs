#[macro_use] extern crate log;

mod sshagent;
mod rustica;

use clap::{App, Arg};

use sshagent::{Agent, error::Error as AgentError, Identity, SSHAgentHandler, Response};
use std::env;
use std::os::unix::net::{UnixListener};
use std::process;

use rustica::refresh_certificate;
use rustica_keys::yubikey::{
    provision,
    ssh::{
        convert_to_ssh_pubkey,
        ssh_cert_signer,
        ssh_cert_fetch_pubkey,
    }
};

use std::convert::TryFrom;
use std::time::SystemTime;
use yubikey_piv::key::{AlgorithmId, RetiredSlotId, SlotId};
use yubikey_piv::policy::TouchPolicy;


struct Handler {
    cert: Option<Identity>,
    slot: SlotId,
    stale_at: u64,
}

impl SSHAgentHandler for Handler {
    fn new() -> Self {
        Handler {
            cert: None,
            slot: SlotId::Retired(RetiredSlotId::R17),
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
        match refresh_certificate(self.slot) {
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
        let signature = ssh_cert_signer(&data, self.slot).unwrap();
        let signature = (&signature[27..]).to_vec();

        let pubkey = ssh_cert_fetch_pubkey(self.slot).unwrap();

        let response = Response::SignResponse {
            algo_name: String::from(pubkey.key_type.name),
            signature,
        };

        Ok(response)
    }
}

fn provision_new_key(slot: SlotId, pin: &str, alg: &str, secure: bool) {
    let alg = match alg {
        "eccp256" => AlgorithmId::EccP256,
        _ => AlgorithmId::EccP384,
    };

    println!("Provisioning new {:?} key in slot: {:?}", alg, slot);

    let policy = if secure {
        println!("You're creating a secure key that will require touch to use.");
        TouchPolicy::Cached
    } else {
        TouchPolicy::Never
    };

    match provision(pin.as_bytes(), slot, alg, policy) {
        Ok(pk) => {
            convert_to_ssh_pubkey(&pk).unwrap();
        },
        Err(_) => panic!("Could not provision device with new key"),
    }
}

fn slot_parser(slot: &str) -> Option<SlotId> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.chars().nth(0).unwrap() == 'R' {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Some(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => None,
        }
    } else {
        if let Ok(s) = SlotId::try_from(slot.to_owned()) {
            Some(s)
        } else {
            None
        }
    }
}

fn slot_validator(slot: &str) -> Result<(), String> {
    match slot_parser(slot) {
        Some(_) => Ok(()),
        None => Err(String::from("Provided slot was not valid. Should be R1 - R20 or a raw hex identifier")),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {  
    env_logger::init();
    let matches = App::new("rustica-agent")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("The SSH Agent component of Rustica")
        .arg(
            Arg::new("slot")
                .about("Numerical value for the slot on the yubikey to use for your private key")
                .long("slot")
                .short('s')
                .validator(slot_validator)
                .takes_value(true),
        )
        .arg(
            Arg::new("provision")
                .about("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .long("provision")
                .short('p')
                .requires("slot")
                .takes_value(true),
        )
        .arg(
            Arg::new("type")
                .about("Specify the type of key you want to provision (eccp256, eccp384)")
                .long("type")
                .short('t')
                .possible_value("eccp256")
                .possible_value("eccp384")
                .requires("provision")
                .takes_value(true),
        )
        .arg(
            Arg::new("require-touch")
                .about("Newly provisioned key requires touch for signing operations (touch cached for 15 seconds)")
                .long("require-touch")
                .short('r')
                .requires("provision")
        )
        .get_matches();

    let slot = match matches.value_of("slot") {
        // We unwrap here because we have already run the validator above
        Some(x) => slot_parser(x).unwrap(),
        None => SlotId::Retired(RetiredSlotId::R17),
    };

    let secure = if matches.is_present("require-touch") {
        true
    } else {
        false
    };

    if let Some(pin) = matches.value_of("provision") {
        provision_new_key(slot, pin, matches.value_of("type").unwrap_or("eccp384"), secure);
    }

    println!("Starting Rustica Agent");
    match ssh_cert_fetch_pubkey(slot) {
        Some(x) => println!("Access Fingerprint: {}", x.fingerprint().hash),
        None => {
            println!("There was no configured key in slot {:?}", slot);
            return Ok(());
        },
    };

    let mut socket_path = env::temp_dir();
    socket_path.push(format!("rustica.{}", process::id()));
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path.to_string_lossy());

    let handler = Handler {
        cert: None,
        slot,
        stale_at: 0,
    };

    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    Ok(())
}