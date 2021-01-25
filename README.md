# Rustica Agent

Rustica Agent the agent portion of the Rustica SSHCA. It is designed to be an SSH-Agent that uses keys loaded on a Yubikey though also supports a file, generally for requesting host certs which are not stored on Yubikeys. See command help for more complete documentation on use.

Rustica-Agent does not support the normal array of SSH-Agent calls, instead only supporting `Identities` and `Sign`. The reason for this is the call for identities initiates a request to a Rustica SSHCA server. Rustica is then expected to return a cert that contains all permissions your key is allowed, including all principals, and hosts. This SSH certificate is generated containing the public portion of the key present on your Yubikey (which may contain up to 24 keys, the key used is chosen at agent start either by command line flag or configuration file).

It is possible to generate keys that require touch (and Rustica Agent allows you to create such keys) though SSH in unaware this is happening so you must notice your key is blinking and act accordingly. Pin is not supported.

## Features
- Yubikey backed private keys
- Just In Time Certificate Generation
- gRPC over TLS

### JITC
The default for RusticaAgent is to use Just In Time Certificate Generation meaning certificates are generated with a TTL of 10s. Using manual mode you may request a certificate of longer duration however, the server will only take this as a request and will return you a cert that expires when it chooses.

### Host Restriction
Rustica may return a cert that is only valid for certain hostnames. When this happens, the certificate generated will have the `force-command` CriticalOption enabled. This forces the running of a bash script loaded inside the cert that contains all hostnames you are allowed to log in to. If the hostname name of the remote host does not match any in the list, your connection will be closed.

### gRPC over TLS
Rustica-Agent is intended to be used with server side TLS. mTLS could be support in future but currently is not.

## Key Support
Rustica Agent supports ECDSA keys fully:
- ECDSA 256
- ECDSA 384

RSA and Ed25519 keys are not officially supported at this time though there is some support for both of them throughout the codebase. Using them is not recommended and will likely fail in strange ways (Ed25519 keys for example cannot be stored on Yubikeys).
  
  
## Security Warning

No review has been done. I built it because I thought people could find it useful. Be wary about using this in production without doing a thorough code review. If you find mistakes, please open a pull request or if it's a security bug, email me.

  
## Licence

This software is provided under the MIT licence so you may use it basically however you wish so long as all distributions and derivatives (source and binary) include the copyright from the `LICENSE`.
