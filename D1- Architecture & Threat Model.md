# D1: Architecture & Threat Model

### Secure File Exchange Platform (Secure Digital Document Vault)

**Universidad Nacional Autónoma de México · Facultad de Ingeniería**

Criptografía · Semester 2027-1 · Group 04

Teacher: Dra. Rocío Alejandra Aldeco Pérez · Delivery date: 26/09/2026

**Team 05:** 
· Arroyo Ramírez Carlos Alberto 
· Escudero Bohórquez Julio 
· Martínez Miranda Juan Carlos 
· Pérez Avin Paola Celina de Jesús 
· Salgado Miranda Jorge

---
## 1. System Overview

**The problem:** Two people who do not share a trusted network need to exchange a file. The file travels through, and may sit in, places neither of them controls: a network path, a shared folder, a remote storage service. 
The platform (the Vault, from here on) exists to make that not matter: Bob should be able to read what Alice sent, notice if anything was changed along the way, and be sure it actually came from her. All three guarantees have to hold no matter how the channel or the storage in between behaves.

**Core features**

1. Protect a file for one named recipient: the content is encrypted, and the key that protects it is packaged so that only that recipient can recover it.
2. Sign the result so that sender, recipient, metadata and payload are bound together in a single Secure Package (the encrypted file container).
3. Keep each user's private keys in a Key Store inside their trusted environment and never leaves it.
4. Resolve identities to public keys through a Secure Address Book, both when choosing a recipient and when checking who sent a package.
5. Treat every incoming package as untrusted: check freshness, verify the signature, and only then recover the key and decrypt. Any failed check ends in a refusal with no output.

**Explicitly out of scope.**

- *Availability.* An attacker who controls the channel can delete or block a package. Nothing here guarantees delivery.
- *Compromised endpoints.* If Alice's or Bob's device already has malware on it, or is stolen while unlocked, none of this helps. Trusted environments are assumed to stay trustworthy while in use.
- *Content safety.* The platform can tell Bob that a file really came from Alice and wasn't altered. It cannot tell if the file is harmless.
- *What happens after decryption.* Once Bob has the plaintext, he could copy it, forward it, or leak it, and the architecture has no say in that.
- *Traffic analysis.* Who talks to whom, how often, and roughly how much isn't hidden beyond the minimum that the visible metadata already allows.
- *Key lifecycle.* Revocation, rotation, recovery, and how public keys get enrolled in the first place along with what happens to old packages if a long-term key is later exposed are left as open questions.

--- 
## 2. Architecture Diagram
![Architecture diagram showing explicitly trusted and untrusted components, trust boundaries and data flows](architecture_diagram.png)

The diagram follows the package from left to right. On Alice's side, the vault picks up the chosen file, looks up for Bob's public key, encrypts the content (**E**) and signs the package (**S**) using the private key stored in the Key Store.
The Secure Package then crosses into the untrusted zone, where we assume the attacker can act on it.
On Bob's side, the package arrives and is treated as an untrusted input, once the vault checks freshness and verifies the signature (**V**) against Alice's public key from the Address Book, it recovers the key and decrypts (**D**) with Bob's private key. 
Only then is the file released to Bob. 


### How the required elements map to this platform

| Required element | In this platform | Trust | What the design assumes by trusting or distrusting it |
| --- | --- | --- | --- |
| User | Alice (sender), Bob (recipient) | Trusted | They act in good faith with their files and keep their secret and their devices are not compromised. |
| Application (Vault) | Sender side: file selection, encryption, signing.<br> Recipient side: freshness check, signature verification, key recovery, decryption. | Trusted | It runs as designed and has not been modified. It is the only place where plaintext and clear keys exist. |
| Encrypted File Container | The Secure Package | Untrusted | Anyone can read, copy, alter or replace it outside a trusted environment, so it must protect itself. It stays untrusted on arrival until every check passes. |
| Key Store | One per user, inside their trusted environment | Trusted | It keeps private keys protected at rest and gives them to the Vault only after the user unlocks it. |
| Public Keys / Recipients | The Secure Address Book | Trusted | Its entries are authentic and cannot be changed by untrusted parties. |
| transit channel | The transit channel and any place where a package rests | Untrusted | Nothing depends on it. No confidentiality, integrity, ordering or delivery is expected from it. |
| Attacker | Acts on the untrusted zone | Untrusted | Assumed to have malicious intent and the capabilities. |


### Trust boundaries

| ID | Boundary | Why it matters |
| --- | --- | --- |
| TB1 | Alice's trusted environment → untrusted zone | Once the package crosses, the attacker can read, copy, modify, delete or replay it. |
| TB2 | Untrusted zone → Bob's trusted environment | Everything arriving is attacker-controlled input until verified. |
| TB3 | User ↔ Vault | File input and command-line arguments cross here. |
| TB4 | Vault ↔ Key Store and Address Book | Key import, export and lookup cross here. Wrong keys here defeat every later check. |

### Data flows

| ID | Flow | Carries | Boundary |
| --- | --- | --- | --- |
| F1 | Alice → Vault (sender) | The chosen file | TB3 |
| F2 | Key Store → Vault (sender) | Signing private key, used inside the Vault and never exported | TB4 |
| F3 | Address Book → Vault (sender) | The recipient's public key | TB4 |
| F4 | Vault (sender) → untrusted zone | The Secure Package | TB1 |
| F5 | Untrusted zone → Vault (recipient) | The received package, still untrusted | TB2 |
| F6 | Bob → Vault (recipient) | command-line arguments | TB3 |
| F7 | Address Book → Vault (recipient) | The sender's public key, to verify the signature | TB4 |
| F8 | Key Store → Vault (recipient) | Decryption private key, used inside the Vault | TB4 |
| F9 | Vault (recipient) → Bob | The original file | TB3 |
| F10 | Attacker ↔ untrusted zone | Read, copy, modify, delete, replay | None |

### Where encryption, signing and keys sit

Encryption and signing happen only in the sender's Vault. Signature verification and decryption happen only in the recipient's Vault. None of these operations takes place in the untrusted environment. Private keys are stored only in the Key Stores. Public keys are stored in the Address Books.

## 3. Security Requirements
| ID | Requirement | Property |
| --- | --- | --- |
| SR-01 | An attacker who obtains a Secure Package, by reading it in transit, copying it from storage or capturing it in flight, must not be able to learn anything about the file's content without the intended recipient's private key. | Confidentiality of file contents |
| SR-02 | If any part of the file content is changed after the sender has packaged it, the recipient's Vault must detect the change and refuse to output a file. | Integrity of file contents |
| SR-03 | Any change to any part of a Secure Package (visible metadata, recipient information, protected key, encrypted payload or signature), including removal, substitution or reordering of parts, must be detected before the content is processed. A one-byte change must be enough to trigger detection. | Protection against tampering |
| SR-04 | The recipient's Vault must accept a package as coming from Alice only if its signature verifies against the public key the Secure Address Book holds for Alice. An attacker without Alice's private key must not be able to produce a package that Bob accepts as coming from her. | Authenticity of the sender |
| SR-05 | A valid package that an attacker captured and sends again, once or many times, must not be accepted as a new package. | Freshness |
| SR-06 | The recipient's Vault must finish every check (freshness, signature) before it decrypts or releases anything. Any failure must stop processing without leaving partial plaintext or other usable output, and a malformed package must be rejected without unsafe behavior. | Safe failure and ordered processing |
| | |
---

## 4. Threat Model

The threat model defines the assets that need protection and the capabilities of the attackers considered by the Secure File Exchange Platform.

### 4.1 Assets

The following assets were identified as relevant to the security of the platform:

| Asset | Why it must be protected | What must hold |
| --- | --- | --- |
| File contents | The original information sent by Alice must remain confidential and must not be modified during transmission. | Confidentiality and integrity |
| Metadata | Information associated with the Secure Package must not be modified without detection. | Confidentiality and integrity |
| Private keys | Private keys must remain protected inside the trusted environment and must not be available to attackers. | Confidentiality |
| Protected file key | The key used to protect the file must only be recoverable by the intended recipient. | Confidentiality |
| User credentials | Credentials used to access the system must not be obtained by an attacker and used to impersonate a legitimate user. | Confidentiality |
| Sender information | Bob must be able to determine whether the package actually originated from Alice. | Authenticity |
| Recipient information | An attacker must not be able to replace or modify the intended recipient without detection. | Integrity and authenticity |
| Digital signatures | The signature must remain valid for the original package and must allow the recipient to verify its origin and integrity. | Confidentiality |
| Secure Address Book | The mapping between identities and public keys must remain trustworthy. | Authenticity and integrity |
| Transmission package | The package may be copied, modified, replayed or deleted while passing through the untrusted transmission channel. | Confidentiality and integrity |

### 4.2 Adversaries

The main adversary considered by the system is an attacker that is assumed to know exactly how the platformn works and can operate in the untrusted environment, especially the transmission channel between Alice and Bob.

The attacker may act actively by modifying or replacing information, or  by observing and copying information traveling through the channel.

### External / Network Attacker

An attacker with access to the untrusted transmission channel.

The attacker can:

- Intercept a Secure Package traveling from Alice to Bob.
- Copy an encrypted package.
- Read visible or plaintext information contained in the package headers.
- Modify the contents of a package before it reaches Bob.
- Modify metadata contained in the package.
- Remove the sender's signature and attempt to attach another signature.
- Generate a malicious package and send it to Bob while impersonating Alice.
- Attempt to impersonate Bob's public key to Alice.
- Capture a legitimate package and replay it to Bob multiple times.
- Attempt to recover the protected key from an intercepted encrypted payload.
- Delete a package before it reaches its intended recipient.

Under the assumptions of this architecture, the attacker cannot:

- Directly access private keys that remain protected inside the trusted environment.
- Recover the protected file key without the corresponding recipient's private key.
- Legitimately prove Alice's identity without the cryptographic material associated with Alice.
- Modify authenticated file contents or metadata without the receiving system being expected to detect the modification.
- Control the Secure Address Book, since it is considered a trusted component.
- Directly compromise the encryption, signing, verification and decryption processes, because these processes only operate inside the trusted environment.

### 4.3 Relevant Attack Scenarios

### Scenario 1 — Sender Identity: Spoofing

An attacker attempts to impersonate Alice and send a malicious or unauthorized package to Bob.

This may happen through stolen user credentials or by generating a package that falsely claims to have been sent by Alice.

The security risk is that Bob could trust a package that did not actually originate from Alice.

---

### Scenario 2 — File Contents: Tampering in Transit

An attacker positioned in the untrusted transmission channel intercepts a Secure Package before it reaches Bob.

The attacker modifies the file contents, metadata, recipient information or other information contained in the package and then forwards the modified package to Bob.

The receiving system must detect the modification before processing the file and reject it.

---

### Scenario 3 — Protected Key: Unauthorized Recovery

Alice creates a Secure Package and sends it to Bob through the untrusted transmission environment.

An attacker intercepts and copies the encrypted package. The attacker isolates the protected key or encrypted payload and attempts to recover the key necessary to access the original file.

The system must ensure that recovery of the protected key depends on possession of the intended recipient's private key.

---

### Scenario 4 — Replay

An attacker captures a legitimate Secure Package sent by Alice and stores it.

At a later time, the attacker sends the same package to Bob multiple times in an attempt to make the system process an old transmission as if it were new.

The receiving system must be able to distinguish a new package from a replayed package by validating the timestamp on the package.

---

### Scenario 5 — Recipient Information Modification

An attacker intercepts a Secure Package and modifies the recipient information or attempts to replace Bob's information.

The receiving system must detect unauthorized modification of recipient information before accepting the package.

## 5. Trust Assumptions

1. Users act without malicios intent: It is assumed that both Alice and Bob have good intentions and do not seek to harme the system, as they are vital for initiating and completing the exchange.
2. The original file is safe: It is assumed that the file the sender selects to transmit is trusted from ist origin and does not contain inherent malicious payloads.
3. Local cryptographic processes operate flawlessly: It is assumed that processes occurring in trusted enviroments, such as encryption, signature generation and verification, timestamp validation and decryption work securely and flawlessly.
4. Public keys are authentic: It is assumed that the secure address book functions properly as an infallible means to map and validate identities with their respective public keys.
5. The transmission channel is an untrusted enviroment: The system assumes it has not control over the transit network or channel, treating it as an enviroment with unceirtain security where packages can be intercepted and altered.
6. The integrity of a received package is uncertain: It is assumed that any newrly arrived package from the transit channel is untrusted until it passes through the local verification and decryption.
7. Attackers have malicious intentions: It is assumed that any external actor in the transit channel has the sole objective of harming system components and violating the data carried by the package.
