#[macro_use] extern crate log;

mod sshagent;
mod rustica;

use clap::{App, Arg};

use sshagent::{Agent, error::Error as AgentError, Identity, SSHAgentHandler, Response};
use std::env;
use std::os::unix::net::{UnixListener};
use std::process;

use rustica::{cert, RusticaServer, Signatory};
use rustica_keys::ssh::{PrivateKey, Certificate, CertType};
use rustica_keys::yubikey::{
    provision,
    ssh::{
        convert_to_ssh_pubkey,
        ssh_cert_signer,
        ssh_cert_fetch_pubkey,
    }
};

use std::convert::TryFrom;
use std::fs::File;
use std::io::{Read};
use std::time::SystemTime;
use yubikey_piv::key::{AlgorithmId, SlotId};
use yubikey_piv::policy::TouchPolicy;


struct Handler {
    server: RusticaServer,
    cert: Option<Identity>,
    signatory: Signatory,
    stale_at: u64,
}

impl SSHAgentHandler for Handler {
    fn identities(&mut self) -> Result<Response, AgentError> {
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if let Some(cert) = &self.cert {
            if timestamp < self.stale_at {
                debug!("Certificate has not expired, not refreshing");
                return Ok(Response::Identities(vec![cert.clone()]));
            }
        }
        match cert::refresh_certificate(&self.server, &self.signatory) {
            Ok(response) => {
                info!("{:#}", Certificate::from_string(&response.cert).unwrap());
                let cert: Vec<&str> = response.cert.split(' ').collect();
                let raw_cert = base64::decode(cert[1]).unwrap_or(vec![]);
                let ident = Identity {
                    key_blob: raw_cert,
                    key_comment: response.comment,
                };
                self.cert = Some(ident.clone());
                Ok(Response::Identities(vec![ident]))
            },
            Err(e) => {
                error!("Refresh certificate error: {:?}", e);
                Err(AgentError::from("Could not refresh certificate"))
            },
        }
    }

    /// Pubkey is currently unused because the idea is to only ever have a single cert which itself is only
    /// active for a very small window of time
    fn sign_request(&mut self, _pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> Result<Response, AgentError> {
        match self.signatory {
            Signatory::Yubikey(slot) => {
                let signature = ssh_cert_signer(&data, slot).unwrap();
                let signature = (&signature[27..]).to_vec();

                let pubkey = ssh_cert_fetch_pubkey(slot).unwrap();

                Ok(Response::SignResponse {
                    algo_name: String::from(pubkey.key_type.name),
                    signature,
                })
            },
            Signatory::Direct(_) => Err(AgentError::from("unimplemented"))
        }
    }
}

fn provision_new_key(slot: SlotId, pin: &str, mgm_key: &[u8], alg: &str, secure: bool) {
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

    match provision(pin.as_bytes(), mgm_key, slot, alg, policy) {
        Ok(pk) => {
            convert_to_ssh_pubkey(&pk).unwrap();
        },
        Err(_) => panic!("Could not provision device with new key"),
    }
}

fn slot_parser(slot: &str) -> Option<SlotId> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Some(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => None,
        }
    } else if let Ok(s) = SlotId::try_from(slot.to_owned()) {
        Some(s)
    } else {
        None
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
            Arg::new("server")
                .about("Full address of Rustica server to use as CA")
                .default_value("http://[::1]:50051")
                .long("server")
                .short('r')
                .takes_value(true),
        )
        .arg(
            Arg::new("serverpem")
                .about("Path to PEM that contains server public key")
                .long("serverpem")
                .short('c')
                .takes_value(true),
        )
        .arg(
            Arg::new("slot")
                .about("Numerical value for the slot on the yubikey to use for your private key")
                .default_value("R3")
                .long("slot")
                .short('s')
                .validator(slot_validator)
                .takes_value(true),
        )
        .arg(
            Arg::new("file")
                .about("Used instead of a slot to provide a private key via file")
                .long("file")
                .short('f')
                .takes_value(true),
        )
        .subcommand(
            App::new("manual")
                .about("Manually request a certificate from a Rustica server")
                .arg(
                    Arg::new("kind")
                        .about("The type of certificate you want to request")
                        .default_value("user")
                        .long("kind")
                        .short('k')
                        .possible_value("user")
                        .possible_value("host")
                        .takes_value(true),
                )
                .arg(
                    Arg::new("duration")
                        .about("Your request for certificate duration in seconds")
                        .default_value("10")
                        .long("duration")
                        .short('d')
                        .takes_value(true),
                )
                .arg(
                    Arg::new("principals")
                        .about("A comma separated list of values you are requesting as principals")
                        .default_value("root")
                        .short('p')
                        .takes_value(true),
                )
        )
        .subcommand(
            App::new("provision")
                .about("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .arg(
                    Arg::new("management-key")
                        .about("Specify the management key")
                        .default_value("010203040506070801020304050607080102030405060708")
                        .long("mgmkey")
                        .short('m')
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("pin")
                        .about("Specify the pin")
                        .default_value("123456")
                        .long("pin")
                        .short('p')
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("type")
                        .about("Specify the type of key you want to provision")
                        .default_value("eccp256")
                        .long("type")
                        .short('t')
                        .possible_value("eccp256")
                        .possible_value("eccp384")
                        .takes_value(true),
                )
                .arg(
                    Arg::new("require-touch")
                        .about("Newly provisioned key requires touch for signing operations (touch cached for 15 seconds)")
                        .long("require-touch")
                        .short('r')
                )
        )
        .get_matches();
    
    let address = matches.value_of("server").unwrap().to_owned();

    let ca = if address.starts_with("https") {
        let path = match matches.value_of("serverpem") {
            Some(v) => v,
            None => {
                error!("You requested an HTTPS server address but no server pem for identification");
                return Ok(());
            }
        };
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;
        contents
    } else {
        String::new()
    };

    let server = RusticaServer {
        address,
        ca,
    };

    let signatory = match matches.value_of("file") {
        Some(file) => Signatory::Direct(PrivateKey::from_path(file)?),
        None => Signatory::Yubikey(slot_parser(matches.value_of("slot").unwrap()).unwrap()),
    };

    if let Some(ref matches) = matches.subcommand_matches("provision") {
        let slot = match signatory {
            Signatory::Yubikey(slot) => slot,
            Signatory::Direct(_) => {
                println!("Cannot provision a file, requires a Yubikey slot");
                return Ok(());
            }
        };

        let secure = matches.is_present("require-touch");
        let mgm_key = match matches.value_of("management-key") {
            Some(mgm) => hex::decode(mgm).unwrap(),
            None => {
                println!("Management key error");
                return Ok(());
            }
        };

        let pin = matches.value_of("pin").unwrap_or("123456");
        provision_new_key(slot, pin, &mgm_key, matches.value_of("type").unwrap_or("eccp384"), secure);
        return Ok(());
    }

    if let Some(ref matches) = matches.subcommand_matches("manual") {
        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        let principals = matches.value_of("principals").unwrap_or("").split(',').map(|s| s.to_string()).collect();
        let ct = CertType::try_from(matches.value_of("kind").unwrap()).unwrap();
        let expiration_time = current_timestamp + matches.value_of("duration").unwrap().parse::<u64>().unwrap_or(0xFFFFFFFFFFFFFFFF);

        match cert::get_custom_certificate(&server, &signatory, ct, principals, expiration_time) {
            Ok(x) => {
                let cert = rustica_keys::Certificate::from_string(&x.cert).unwrap();
                println!("Certificate Details!");
                println!("{:#}", &cert);
                println!();
                println!("Raw Certificate: ");
                println!("{}", &cert);
            }
            Err(e) => println!("Error: {:?}", e),
        }
        return Ok(());
    }    

    println!("Starting Rustica Agent");
    let pubkey = match signatory {
        Signatory::Yubikey(slot) => ssh_cert_fetch_pubkey(slot).unwrap(),
        Signatory::Direct(ref privkey) => privkey.pubkey.clone()
    };

    println!("Access Fingerprint: {}", pubkey.fingerprint().hash);

    let mut socket_path = env::temp_dir();
    socket_path.push(format!("rustica.{}", process::id()));
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path.to_string_lossy());

    let handler = Handler {
        server,
        cert: None,
        signatory,
        stale_at: 0,
    };

    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    Ok(())
}