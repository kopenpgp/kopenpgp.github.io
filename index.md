---
layout: page
title: Key Overwriting (KO) Attacks against OpenPGP
---


Key Overwriting (KO) attacks exploit the fact that **an encrypted private key or its metadata can be corrupted in such a way that secret data might be leaked when the key is used.**

### Background
<img src="/assets/logo.png" id="logo" alt="logo" />

OpenPGP stores private keys in Secret Key (or Subkey) packets. These packets are composed of public, non-encrypted fields (e.g. the public key parameters) and private, encrypted fields (e.g. the actual private key material). While the encrypted fields are integrity protected to some extent, OpenPGP has no mechanism to programmatically detect corruption of the public fields. The result is that, in a KO attack scenario, the correct private key material can end up being used in conjunction with corrupted public key parameters. This can lead to leakage of the private key. 

Because of the inability to verify the authenticity of the public fields, a private key cannot be fully trusted even if it decrypts successfully with the expected passphrase (unless further key validation steps are carried out by the OpenPGP client, see [Countermeasures]($#countermeasures) below). It follows that, as a user, to confirm the integrity and authenticity of personal keys, it is necessary to check the fingerprint of those keys, just as is required with third-party keys.

### Attack Vectors
In the KO **threat model**, the attacker needs write access to the encrypted private key of the victim. This may arise when the encrypted private key is stored in **insecure storage** (e.g. USB drive, cloud server, or in transit). Given this setting, we have identified two classes of attacks:

**1) Secret key extraction attacks**. In this case, the attacker aims to overwrite the public key parameters in the victim’s encrypted private key, so that when the victim uses it e.g. to sign something, the resulting faulty signature will leak at least partial information about the original secret key parameters.

We have found that **all key types are potentially vulnerable to secret key extraction**: in RSA and DSA, a single faulty signature is sufficient to reconstruct the secret exponent, while EdDSA requires two signatures. Finally, ECDSA, EdDSA, ECDH and ElGamal keys can be broken by placing the corresponding encrypted private keys inside a DSA key entity, and targeting the latter.

Here is a visual example of how an ECDSA encrypted key packet can be converted into a DSA key packet, where the attacker has arbitrary control over the group parameters. Notice how the encryption settings and encrypted secret data (in gray) are left untouched:
![Schematics of overwritten ECDSA key](/assets/key_schematics.jpg)

**2) Encrypt-to-self compromise (MITM attack)**. This second attack vector can be carried out against email clients and applications, by taking advantage of the fact that emails are usually also encrypted to the sender's personal key, so that they can be stored in encrypted form and still be readable by the sender. The attack consists of replacing the public encryption key of the victim with one for which the adversary knows the private counterpart: any sent message will then be encrypted to the malicious key, and the adversary will be able to decrypt it, after intercepting the message.
Ideally, this type of attack should be prevented by the email client, e.g. by checking that the key is not corrupted when the user imports it.

## Countermeasures
For existing standard keys (namely CFB-encrypted keys), the integrity of the public parameters of private keys needs to be confirmed by OpenPGP libraries through careful **key validation**, hence we recommend developers implement it. The comprehensive key validation steps required to prevent all of our attacks are detailed in Appendix D of the [paper](#paper). 

<p class="message">
Implementing incomplete or improper key checks can open up further attack possibilities that exploit key validation itself (see KOKV attacks in Appendix C of the <a href='#paper'>paper</a>).
</p>

As a long-term solution, in the recently released draft `ietf-draft-crypto-refresh-04`,[^2] OpenPGP has updated the proposed AEAD key encryption mechanism (S2K specifier 253). The new specification prevents all the attacks we reported by properly authenticating the public key material stored in an encrypted private key.
Still, **existing keys will remain vulnerable to the attacks**, until they are re-encrypted using the revised AEAD format. Note that before such re-encryption, the integrity of the keys should be confirmed using key validation.


If you are a user, see also [What can I do to protect against the attacks?](#what-can-i-do-to-protect-against-the-attacks).


## <a name="paper"></a> Paper with Full Technical Details


**_Victory by KO: Attacking OpenPGP Using Key Overwriting_**<br>
_Lara Bruseghini, Kenneth G. Paterson, and Daniel Huigens._<br>
To appear in: _Proceedings of ACM Conference
on Computer and Communications Security, Los Angeles, November
2022._

A pre-print version is available [here](/assets/paper.pdf){:target="_blank"}.


## Vulnerability Disclosures

We reviewed the following libraries and applications and found them vulnerable to KO attacks, to different degree (see [paper](#paper) for more details). We got in touch with the developers to disclose our findings between July 2020 to January 2021.

| Library    | Fixed in version |
|------------|------------------|
| [GnuPG](https://gnupg.org/)      | still vulnerable (won't fix)        |
| [RNP](https://www.rnpgp.org/software/rnp/)        | v0.16            |
| [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) | v4.10.5 |
| [gopenpgp](https://github.com/ProtonMail/gopenpgp)   | v2.1             |
| [Sequoia](https://sequoia-pgp.org/)    | still vulnerable (won't fix)        |

GnuPG and Sequoia do not plan to address the attacks: Sequoia maintainers consider key storage attacks as out of scope for their threat model. For more info about GnuPG, see [Is my installation of GnuPG affected?](#is-my-installation-of-gnupg-affected) .

##### OpenPGP-based applications
[ProtonMail](https://protonmail.com) and [FlowCrypt](https://flowcrypt.com/) were found vulnerable to the attacks, because based on their threat models, malicious servers could potentially compromise user keys. Both applications have been patched by upgrading to secure versions of OpenPGP.js and are no longer vulnerable.


## Q&A


<!-- @import "[TOC]" {cmd="toc" depthFrom=4 depthTo=4 orderedList=false} -->

<!-- code_chunk_output -->

- [Who is affected by KO attacks?](#who-is-affected-by-ko-attacks)
- [What types of keys are impacted?](#what-types-of-keys-are-impacted)
- [What can an attacker do if they overwrote/corrupted my key?](#what-can-an-attacker-do-if-they-overwrotecorrupted-my-key)
- [If my key decrypts correctly, am I safe?](#if-my-key-decrypts-correctly-am-i-safe)
- [If I sign a message with my key, and check that the signature verifies, does it confirm that the key was not corrupted?](#if-i-sign-a-message-with-my-key-and-check-that-the-signature-verifies-does-it-confirm-that-the-key-was-not-corrupted)
- [If I encrypt a message with my key, and check that it decrypts, does it confirm that the key was not corrupted?](#if-i-encrypt-a-message-with-my-key-and-check-that-it-decrypts-does-it-confirm-that-the-key-was-not-corrupted)
- [If I store my key stripped of the primary key secret data (i.e. "gnu-dummy" primary key) that includes only encryption subkeys, am I safe against signing attacks?](#if-i-store-my-key-stripped-of-the-primary-key-secret-data-ie-gnu-dummy-primary-key-that-includes-only-encryption-subkeys-am-i-safe-against-signing-attacks)
- [What can I do to protect against the attacks?](#what-can-i-do-to-protect-against-the-attacks)
- [I am worried one of my keys was corrupted. How can I check?](#i-am-worried-one-of-my-keys-was-corrupted-how-can-i-check)
- [Is my installation of GnuPG affected?](#is-my-installation-of-gnupg-affected)
- [Will the OpenPGP standard be updated to address these attacks?](#will-the-openpgp-standard-be-updated-to-address-these-attacks)
- [How are these attack different from the one published by Klíma-Rosa in 2001?](#how-are-these-attack-different-from-the-one-published-by-klíma-rosa-in-2001)
- [Do random corruptions also pose a risk?](#do-random-corruptions-also-pose-a-risk)

<!-- /code_chunk_output -->



#### Who is affected by KO attacks?
Users/apps that store their encrypted private key in insecure storage (namely where an attacker has write access to).<br>
Example scenarios:
  - sharing the key via (unencrypted) email;
  - backing up the key in cloud storage (non end-to-end encrypted) or on a USB stick that an attacker gets hold of.


#### What types of keys are impacted?
In principle, all of them. However, ECDSA, EdDSA, ECDH, DSA and ElGamal keys are generally easier to target than RSA ones (because fewer libraries are vulnerable to the attacks against RSA keys).


#### What can an attacker do if they overwrote/corrupted my key?
New emails that are encrypted with it (e.g. for storage in the Sent folder) could be decrypted by the attacker, if they can access them.
In addition, if the key is used for signing (or automated decryption), the attacker could recover your private key, allowing them to decrypt your old messages or sign new messages in your name.


#### If my key decrypts correctly, am I safe?
No, corrupted keys will also decrypt correctly.
#### If I sign a message with my key, and check that the signature verifies, does it confirm that the key was not corrupted?
No, because corrupted RSA and DSA keys could still successfully sign-verify a message. In principle, corrupted ECDSA or EdDSA keys will fail to verify the signature, but the attacker might have converted them to DSA keys without you noticing, thus escaping detection through this method.
#### If I encrypt a message with my key, and check that it decrypts, does it confirm that the key was not corrupted?
No, because corrupted RSA and ElGamal keys could still successfully encrypt-decrypt a message. In principle, corrupted ECDH keys will fail to decrypt the message, but the attacker might have converted them to ElGamal keys without you noticing, thus escaping detection through this method.
#### If I store my key stripped of the primary key secret data (i.e. "gnu-dummy" primary key) that includes only encryption subkeys, am I safe against signing attacks?
No, because encryption subkeys can be converted into signing subkeys by an attacker.


#### What can I do to protect against the attacks?
If you are a user:
  - Check the fingerprint of your personal keys before using them.
  - Do not solely rely on private key encryption for protection: consider storing an encrypted OpenPGP message (encrypted with a passphrase) containing the key.
  
If you are a library developer: see [Countermeasures](#countermeasures).

If you are an application developer: see [list of OpenPGP libraries](#vulnerability-disclosures) that have been patched against the attacks.

#### I am worried one of my keys was corrupted. How can I check?
Here are two simple scripts you can use to locally check your keys:

<details markdown="1">
<summary>In Node.js</summary>

Install [OpenPGP.js v5](https://github.com/openpgpjs/openpgpjs):

```sh
npm install openpgp
```
Then run the following script (e.g. with `node ./script.js`):
```js
const openpgp = require('openpgp');

// Your encrypted private key
const armoredPrivateKey = ```-----BEGIN PGP PRIVATE KEY BLOCK-----

...
-----END PGP PRIVATE KEY BLOCK-----
```;
// your key passphrase
const passphrase = '...';

async function main() {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey });
  // the following line will throw in case of wrong passphrase, or invalid key
  const decryptedKey = await openpgp.decryptKey({ privateKey, passphrase });

  console.log('Key is valid');
  decryptedKey.clearPrivateParams();
}

main();
```
</details>

<details markdown="1">
<summary>In Golang</summary>

```go
package main

import (
  "fmt"
  "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// your encrypted private key
const armoredKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

...
-----END PGP PRIVATE KEY BLOCK-----
`
// your key passphrase
const passphrase = "..."

func main() {
  privateKey, err := crypto.NewKeyFromArmored(armoredKey)
  if err != nil {
    fmt.Println("Error reading key")
    return
  }

  if _, err = privateKey.Unlock([]byte(passphrase)); err != nil {
    // the unlock operations will fail if the passphrase is wrong, or if the key material is invalid
    fmt.Print("Error decrypting private key: ", err)
    return
  }

  fmt.Println("Key is valid")
}
```
</details>

#### Is my installation of GnuPG affected?
GPG might fail to detect that a private key being imported is corrupted, opening up some attack possibilities if the key is used.
However, from GPG v2.2.22 (don't use - use 2.2.23), keys cannot be corrupted as described in our paper _after_ they have been imported and stored encrypted inside a GnuPG keyring (unless they were imported using a `gpg-agent` with the option `--disable-extended-key-format`). In fact, keys stored using the GPG extended key format do not rely on OpenPGP encryption for protection, making our attacks not viable. However, note that we haven't analysed this GPG's custom key protection in depth.<br><br>
  If you are using GPG v2.2.22 (or later) but imported some keys before updating to it, you can have them automatically converted to the new format by changing the key passphrase.<br>
If you are using GPG v2.2.12-21, you can manually convert the keys to the extended format by setting the `enable-extended-key-format` option for `gpg-agent` (see `man` entry), and then change the key passphrase.

#### Will the OpenPGP standard be updated to address these attacks?
Discussions about a new version of the standard are ongoing.[^2] We have brought our findings to the attention of the OpenPGP Working Group and proposed changes that would prevent all the attacks on newly-encrypted keys. The countermeasures have been incorporated into the draft revision of the specification (`draft-ietf-openpgp-crypto-refresh-04`[^2]). However, existing keys will remain vulnerable to the attacks, until they are re-encrypted using the revised (AEAD) format.

#### How are these attack different from the one published by Klíma-Rosa[^1] in 2001?
The fundamental attack vector behind secret key extraction attacks is the same. But we target all key types and exploit message decryption as well as signing. We also show how to exploit/bypass the key checks implemented by popular libraries.

#### Do random corruptions also pose a risk?
We haven't looked into this in depth. Our current attacks depend on having fine control over public parameters/public key material. In principle, random key corruptions (such as bit-flips) could result in e.g. faulty signatures being generated. However, this should not cause issues in the libraries we have reviewed, as they all require that keys have verifiable certification signatures (otherwise the key is considered invalid).

## References
[^1]: Klíma V, Rosa T. "Attack on private signature keys of the OpenPGP format [...]": <https://eprint.iacr.org/2002/076>{:target="_blank"}
[^2]: Draft for OpenPGP crypto-refresh: <https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh>{:target="_blank"} ([see diff of Section 5.5.3](https://www.ietf.org/rfcdiff?difftype=--hwdiff&url2=draft-ietf-openpgp-crypto-refresh-04.txt){:target="_blank"})
