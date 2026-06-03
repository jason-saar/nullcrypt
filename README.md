# nullcrypt

A concurrent TCP server implementing the Vigenère cipher, supporting both encryption and decryption via a client-server architecture in C.

## Usage

Start the server:
    nullcrypt_server <port>

Encrypt a file:
    nullcrypt_client -e textfile keyfile <port>

Generate a key:
    keygen <length> > keyfile

## Details

 - Vigenère cipher over 26-character alphabet (A-Z)
 - Key repeats via modulo indexing for arbitrary length plaintext
 - Concurrent server using fork(), supports multiple simultaneous connections
 - Length-prefixed protocol with guaranteed complete send/recv via looped I/O wrappers
