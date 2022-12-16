# micro-aes-gcm-siv

AES-GCM-SIV: classic AES-GCM with nonce-misuse resistance. Implements [RFC 8452](https://datatracker.ietf.org/doc/html/rfc8452).

## What?

> <https://en.wikipedia.org/wiki/AES-GCM-SIV>
> AES-GCM-SIV is designed to preserve both privacy and integrity even if nonces are repeated. To accomplish this, encryption is a function of a nonce, the plaintext message, and optional additional associated data (AAD). In the event a nonce is misused (i.e. used more than once), nothing is revealed except in the case that same message is encrypted multiple times with the same nonce. When that happens, an attacker is able to observe repeat encryptions, since encryption is a deterministic function of the nonce and message. However, beyond that, no additional information is revealed to the attacker. For this reason, AES-GCM-SIV is an ideal choice in cases that unique nonces cannot be guaranteed, such as multiple servers or network devices encrypting messages under the same key without coordination.

> <https://www.imperialviolet.org/2017/05/14/aesgcmsiv.html>
> AEADs that can withstand nonce duplication are called “nonce-misuse resistant” and that name appears to have caused some people to believe that they are infinitely resistant. I.e. that an unlimited number of messages can be encrypted with a fixed nonce with no loss in security. That is not the case, and the term wasn't defined that way originally by Rogaway and Shrimpton (nor does their SIV mode have that property). So it's important to emphasise that AES-GCM-SIV (and nonce-misuse resistant modes in general) are not a magic invulnerability shield. Figure four and section five of the the paper give precise bounds but, if in doubt, consider AES-GCM-SIV to be a safety net for accidental nonce duplication and otherwise treat it like a traditional AEAD.


