# simple-pgp
`simple-pgp` is an implementation of the [OpenPGP RFC: 9580](https://www.rfc-editor.org/rfc/rfc9580.html) and the [LibrePGP](https://www.ietf.org/archive/id/draft-koch-librepgp-03.html) standards.

## Usage

To sign files

```sh
# Sign a file
spgp --sign --local-user <KEY> <FILE...> # Long arguments
spgp -su <KEY> <FILE...> # Short arguments

# Detach sign
spgp --detach-sign --local-user <KEY> <FILE...> # Long arguments
spgp -bu <KEY> <FILE...> # Short arguments

# Cleartext sign
spgp --clear-sign --local-user <KEY> <FILE...> # Long arguments
```

To verify signatures
```sh
# Verify a signed message or a cleartext signature
spgp --verify <FILE...> # Long arguments
spgp -v <FILE...> # Short arguments

# Verify a detached signatue
spgp -v <SIGNATURE> <FILE> # Signature file followed by data file
```

To encrypt files
```sh
# Encrypt a file for recipients
spgp --encrypt --recipient <KEY> <FILE...> # Long arguments
spgp -er <KEY> <FILE...> # Short arguments

# Encrypt a file using a passphrase
spgp --symmetric <FILE...> --passphrase <PASSPHRASE> # Long arguments (Explicit passphrase)
spgp -c <FILE...> # Short arguments (Passphrase will be prompted)

# Encrypt a file for recipients also using a passphrase
spgp --encrypt --symmetric --recipient <KEY> <FILE...> # Long arguments
spgp -ecr <KEY> <FILE...> # Short arguments
```

To decrypt files
```sh
# Decrypt a file
spgp --decrypt <FILE...> # Long arguments
spgp -d <FILE...> # Short arguments
```

Output customization
```sh
# Armor output
spgp --sign --armor --local-user <KEY> <FILE...> # Long arguments
spgp -sau <KEY> <FILE...> # Short arguments

# Specify output (Only one input file allowed)
spgp --encrypt --recipient <KEY> <FILE> --output <OUT> # Long arguments
spgp -er <KEY> <FILE> -o <OUT> # Short arguments
```

To generate keys
```sh
# Generate a key
spgp --generate <USER> <ALGORITHM:CAPABILITIES:EXPIRY/...> # Long arguments
spgp -g <USER> <ALGORITHM:CAPABILITIES:EXPIRY/...> # Short arguments

# Generate RSA-4096 signing key with encryption subkey expiring in two years
spgp -g "Alice" rsa4096:CS:2y/rsa4096:E:2y

# Generate ECDSA primary key using NIST-P256 and ECDH subkey using NIST-P384
spgp -g "Bob" nistp256:CS/nistp384:E

# Generate EDDSA primary key expiring in one years
spgp -g "Darth" ed25519:CS:1y
```

To import keys
```sh
spgp --import <FILE...> # Long arguments
spgp -i <FILE...> # Short arguments
```

To export keys
```sh
# Public keys
spgp --export <KEY...> # Long arguments
spgp -x <FILE...> # Short arguments

# Secret keys
spgp --export-secret-keys <KEY...> # Long arguments
spgp -X <FILE...> # Short arguments
```

## Features
### Supported Alogrithms
* Hash: MD5, RIPEMD160, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-256, SHA3-512
* Ciphers: IDEA, TDES, CAST-5, BLOWFISH, AES, CAMELLIA, TWOFISH
* Public Key: RSA, DSA, ECDH, ECDSA, EDDSA, ED25519, ED448, X25519, X448

## Build

### Prerequisites 
* CMake 3.15 or newer
* C23 Compatible compiler

### Instructions

```sh
cmake .
```
