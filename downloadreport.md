# Secure Note Sharing Application - Project Report

## 1. Introduction
This project implements a secure client-server note-sharing system where the server is treated as "honest-but-curious" (or potentially untrusted regarding data confidentiality). All note content is encrypted on the client side before transmission, ensuring that the server never sees the plaintext.

## 2. System Architecture

### 2.1 Technologies
- **Language**: Go (Golang) 1.25+
- **Cryptography**:
    - **AES-256-GCM**: For symmetric encryption of note content.
    - **RSA-2048**: For asymmetric encryption of keys (User Identity & Key Sharing).
    - **SHA-256**: For password hashing (basic implementation).
- **Protocol**: RESTful HTTP API.
- **Data Format**: JSON.

### 2.2 Components
1.  **Server (`cmd/server`)**:
    - Manage User Registry (Username, Public Key).
    - Store Encrypted Notes (Blob storage).
    - Enforce Access Control (Check ownership/sharing list).
2.  **Client (`cmd/client`)**:
    - CLI Interface for user interaction.
    - **Key Management**: Generates RSA KeyPair on registration, stores Private Key locally (PEM).
    - **Encryption**: Encrypts notes with a unique random AES key.
    - **Key Encapsulation**: Encrypts the AES key with the owner's RSA Public Key and attached to the note.

## 3. Security Design

### 3.1 Encryption Flow (Create Note)
1.  User enters content $M$.
2.  Client generates random AES key $K_{AES}$.
3.  Client encrypts content: $C = AES\_GCM(M, K_{AES})$.
4.  Client fetches own Public Key $PK_{User}$.
5.  Client encrypts key: $K_{Enc} = RSA\_OAEP(K_{AES}, PK_{User})$.
6.  Client sends $\{C, K_{Enc}\}$ to server.

### 3.2 Decryption Flow (Read Note)
1.  Client fetches note $\{C, K_{Enc}\}$ from server.
2.  Client decrypts key: $K_{AES} = RSA\_OAEP^{-1}(K_{Enc}, SK_{User})$.
3.  Client decrypts content: $M = AES\_GCM^{-1}(C, K_{AES})$.

### 3.3 Secure Sharing Flow
To share a note with User B:
1.  Client A fetches $PK_B$ from server.
2.  Client A decrypts $K_{AES}$ using $SK_A$.
3.  Client A encrypts $K_{AES}$ using $PK_B$ -> $K_{EncB}$.
4.  Client A sends $K_{EncB}$ to server to append to the note's access list.
5.  Now User B can fetch the note and decrypt $K_{AES}$ using $SK_B$.

## 4. Challenges & Solutions

### Challenge 1: Key Management
**Problem**: How to store user keys securely without forcing them to re-enter credentials or complex commands?
**Solution**: The client generates the RSA key pair upon registration and saves the Private Key to a local PEM file (`username.pem`). The Public Key is sent to the server.

### Challenge 2: Sharing Access
**Problem**: How to allow another user to read a note without re-encrypting the whole content?
**Solution**: We use Hybrid Encryption. The content is encrypted once with a symmetric key (AES). Only the small AES key is re-encrypted with the recipient's Public Key. This is efficient and standard practice (similar to PGP).

## 5. Future Improvements
1.  **Secure Password Storage**: Upgrade from simple SHA-256 to Argon2 or bcrypt.
2.  **Transport Security**: Enable HTTPS/TLS for the server to prevent MITM attacks on the network layer (protecting metadata and auth tokens).
3.  **Local Key Encryption**: Encrypt the local PEM file with a passphrase so the private key isn't stored in plaintext on disk.
4.  **Database**: Replace the in-memory JSON store with a real database (Postgres/SQLite) for scalability.
