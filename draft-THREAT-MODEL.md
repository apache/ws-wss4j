<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# Apache WSS4J Security Threat Model (draft)

## §1 Header

- **Project**: Apache WSS4J — a Java implementation of the OASIS WS-Security
  specifications (SOAP Message Security 1.1, UsernameToken Profile 1.1,
  X.509 Certificate Token Profile 1.1, SAML Token Profile 1.1, Kerberos
  Token Profile 1.1, SwA Profile 1.1, Basic Security Profile 1.1)
  *(documented: `README.md`, `src/site/asciidoc/what.adoc`)*.
- **Repository**: `apache/ws-wss4j`.
- **Version / commit**: this model is drafted against the default branch
  (`master`) at clone time. A report against project release *N* should be
  triaged against the model as it stood at *N*, not at HEAD.
- **Supported branches** (per `SECURITY.md`): 4.0.x, 3.0.x, 2.4.x. Earlier
  branches are explicitly out of support.
- **Date**: 2026-05-30.
- **Authors**: ASF Security team draft, awaiting WSS4J / Webservices PMC
  review.
- **Status**: draft — under maintainer review.
- **Reporting**: vulnerabilities that fall under §8 (claimed properties)
  should be reported per the Apache Security Team disclosure channel
  (linked from `SECURITY.md` → <https://www.apache.org/security/>); reports
  that fall under §3 (out of scope) or §9 (properties not provided) will
  be closed by WSS4J triagers citing this document. Existing project
  advisories are published at
  <http://ws.apache.org/wss4j/security_advisories.html> *(documented:
  `src/site/xdoc/security_advisories.xml`)*.
- **Provenance legend** —
  *(documented)* = drawn from in-repo docs / project website / source-tree
  source comments, with citation;
  *(maintainer)* = stated by a WSS4J maintainer in response to this draft;
  *(inferred)* = synthesized by the producer from code structure or
  domain knowledge, awaiting PMC ratification (every *(inferred)* tag has
  a matching §14 question).
- **Draft confidence**: 39 documented / 0 maintainer / 28 inferred.

WSS4J is a library — not a service, not a daemon, not a SOAP stack of
its own. It is designed to be embedded by a Web Services stack such as
Apache CXF or Apache Axis to apply and validate the WS-Security message
header on SOAP envelopes: signature, encryption, timestamps, replay
caches, and security tokens (UsernameToken, X.509, SAML, Kerberos,
SecurityContextToken, IssuedToken, DerivedKey). Cryptographic primitives
are delegated to Apache Santuario (XML Signature / XML Encryption), the
JDK's JCE provider (TLS, MessageDigest, KeyStore), Bouncy Castle (optional
BC provider, OpenSAML's BC use), and OpenSAML (SAML assertion
construction and processing). WSS4J ships two distinct processing
engines: a DOM-based engine (`ws-security-dom`) and a streaming StAX-based
engine (`ws-security-stax`) introduced in 2.0.0.

## §2 Scope and intended use

### Intended use

- In-process production of and verification of WS-Security message headers
  on SOAP 1.1 / 1.2 envelopes, invoked by a Web Services stack
  (Apache CXF, Apache Axis) on the host application's behalf
  *(documented: `README.md`, `src/site/asciidoc/what.adoc`,
  `src/site/asciidoc/using.adoc`)*.
- Two API styles are documented as supported: the "actions" approach
  (`WSHandlerConstants.ACTION`-driven handlers) and the
  WS-SecurityPolicy-driven approach (PolicyEnforcer in
  `ws-security-policy-stax`). The best-practice guide
  *strongly favors* WS-SecurityPolicy because it provides automatic
  protection against XML signature wrapping
  *(documented: `src/site/asciidoc/best_practice.adoc` §"Use
  WS-SecurityPolicy to enforce security requirements")*.

### Deployment shape

WSS4J is **not** a network service, **not** a daemon, **not** a SOAP
stack. It is an in-process Java library whose callers are SOAP stacks
that own the network surface. The threat model is therefore that of a
security-rich library *(documented: `README.md`,
`src/site/asciidoc/what.adoc`)*.

### Caller roles (library model)

| Role | Trust level | Notes |
| --- | --- | --- |
| **Embedding SOAP stack** (CXF / Axis / Spring-WS) | trusted | Calls WSS4J entry points, supplies `RequestData` / `WSSSecurityProperties`, supplies the SOAP envelope as a `Document` (DOM) or `XMLStreamReader` (StAX), holds keystores, supplies `CallbackHandler`. WSS4J does no peer authentication of the embedding stack. |
| **CallbackHandler implementation** | trusted | Provides passwords, decryption keys, attachments. WSS4J does not validate that the CallbackHandler is well-behaved; a hostile CallbackHandler can read arbitrary plaintext or leak any key WSS4J asks for *(inferred — §14 Q1)*. |
| **Validator implementation** | trusted | Plugs into the inbound chain via `WSSConfig` to validate UsernameToken, SAML assertion, Timestamp, signature, etc. WSS4J ships a default set; replacing them is a documented extension point *(documented: `src/site/asciidoc/topics.adoc` §"Introducing Validators")*. |
| **Wire-side peer of the SOAP message** | **untrusted** | The producer of the bytes WSS4J actually parses. This is the only untrusted role. The peer is the adversary in §7. |
| **Keystore / TrustStore on disk** | trusted | Supplies signing keys and the set of CAs WSS4J will accept *(documented: `src/site/asciidoc/topics.adoc` §"Crypto Interface", `src/site/asciidoc/config.adoc` §"Crypto properties")*. |
| **Apache Santuario, OpenSAML, Bouncy Castle, JCE provider** | trusted upstream | WSS4J vendors none of these; vulnerabilities intrinsic to these upstreams are reported there *(inferred — §14 Q2)*. |

### Component-family table

| Family | Representative entry point | Touches outside the process? | In-model? |
| --- | --- | --- | --- |
| `ws-security-common` — Crypto interface (`Merlin`, `CertificateStore`, `MerlinDevice`), `ReplayCache` (`EHCacheReplayCache`, `MemoryReplayCache`), `ConfigurationConstants`, BSP rule enforcement, derived-key util, SAML assertion wrapper, SPNEGO util, JAAS callback wrapper | static config / file-backed keystore / file-backed EHCache | **yes** (file-backed surfaces noted as caller-trusted) |
| `ws-security-dom` — DOM-based inbound `WSSecurityEngine`, processors per element (Signature, Encryption, Timestamp, UsernameToken, SAML, Kerberos, SCT, …), `WSHandler` action-based driver | invoked from CXF / Axis interceptor with a parsed `org.w3c.dom.Document` *(documented: `src/site/asciidoc/topics.adoc` §"Specifying elements to sign or encrypt")* | **yes** — primary attacker-controlled surface |
| `ws-security-stax` — streaming StAX-based inbound/outbound (`InboundWSSec`, `OutboundWSSec`, `WSSec`); installs a security-specific `XMLStreamReader` wrapper | invoked from CXF Stax interceptor with caller-supplied `XMLStreamReader` *(documented: `src/site/asciidoc/streaming.adoc`)* | **yes** — primary attacker-controlled surface |
| `ws-security-policy-stax` — WS-SecurityPolicy enforcement layered on the StAX engine (`PolicyEnforcer`, `PolicyInputProcessor`) | n/a (operates on the StAX event stream) | **yes** |
| `ws-security-web` — servlet `Filter` and utility for receiving WS-Security messages via plain HTTP, used in some legacy deployments | network listener via the embedding container | in-model **insofar as WSS4J ships it**; the surrounding servlet container is out *(inferred — §14 Q3)* |
| `bindings/` — JAXB-generated XML bindings for WS-Trust, WS-SecureConversation, WS-Policy schema, `wsu`, `wsse10`/`wsse11`, `xenc`, `xmldsig` | n/a (DTOs only) | **yes** — used by both engines |
| `integration/` (test-only, Kerberos integration tests against Apache Directory) | n/a in production | **out of model** *(§3)* |
| Sample/test resources (`*/src/test/`, `policy/src/test/...`) — test JKS keystores with publicly-documented passwords | n/a | **out of model** *(§3)* |

A finding is in-model only if it reaches a row marked **yes**.

## §3 Out of scope (explicit non-goals)

1. **The SOAP stack itself.** WSS4J is invoked by Apache CXF / Apache Axis;
   the parsing of the HTTP request, the routing of the SOAP body to a
   service implementation, SOAPAction enforcement, and authentication
   of the transport layer are all the stack's job. Findings that
   require the SOAP stack to misbehave (e.g. WSS-456's "SOAPAction
   spoofing should be left to the SOAP stack" — *(documented:
   `ws-security-policy-stax/src/test/java/org/apache/wss4j/policy/stax/test/VulnerabliltyVectorsTest.java`*)
   are out of model. → `OUT-OF-MODEL: adversary-not-in-scope`.
2. **A SOAP parser.** WSS4J does not parse SOAP from bytes — it receives a
   `Document` (DOM engine) or `XMLStreamReader` (StAX engine) from the
   caller. XXE / DTD / billion-laughs defenses on the *XML-bytes-to-DOM*
   parsing step belong to the caller's parser configuration. WSS4J's
   `InboundWSSec` javadoc warns this explicitly: *"configure your
   xmlStreamReader correctly. Otherwise you can create a security
   hole."* *(documented:
   `ws-security-stax/src/main/java/org/apache/wss4j/stax/setup/InboundWSSec.java` line 94-99)*. →
   `OUT-OF-MODEL: trusted-input`.
3. **Cryptographic primitives.** WSS4J does not implement RSA, AES, SHA,
   PKCS#1v1.5, OAEP, GCM, ECDSA, or any other primitive. It composes the
   JDK's JCE provider, Bouncy Castle (when registered), and Apache
   Santuario. Defects in the primitives themselves are out of model and
   reported to the JDK / BC / Santuario projects *(inferred — §14 Q2)*. →
   `OUT-OF-MODEL: unsupported-component`.
4. **XML Signature / XML Encryption canonical processing.** Delegated to
   Apache Santuario; WSS4J does the WS-Security framing
   *(documented: `README.md` Crypto Notice; `src/site/asciidoc/topics.adoc`
   §"JSR-105 support")*. → `OUT-OF-MODEL: unsupported-component` for
   Santuario-internal defects. Where WSS4J *configures* Santuario (e.g.
   `setSecureValidation`, `setCanonicalizationMethod`,
   `setEncryptionSerializer`), that configuration is in-model.
5. **The OpenSAML library.** Used for SAML 1.1 / SAML 2.0 assertion
   construction and parsing in `ws-security-common/.../saml/`. Defects
   intrinsic to OpenSAML (XML processing, schema handling) are out of
   model *(inferred — §14 Q2)*. → `OUT-OF-MODEL: unsupported-component`.
6. **The Kerberos KDC and SASL/JAAS infrastructure.** WSS4J's Kerberos
   token support assumes a working JAAS-configured Kerberos environment
   *(documented: `src/site/asciidoc/wss4j22.adoc` §"Kerberos changes")*. →
   `OUT-OF-MODEL: trusted-input` for KDC misbehavior.
7. **EHCache as a Java component.** Default `ReplayCache` implementation
   is `EHCacheReplayCache`; defects in the EHCache jar itself are
   out of model *(inferred — §14 Q4)*. → `OUT-OF-MODEL: unsupported-component`.
8. **Pre-2.4.x branches.** Per `SECURITY.md`, only 4.0.x, 3.0.x, 2.4.x
   are supported. Reports against 1.x / 2.0.x / 2.1.x / 2.2.x / 2.3.x
   that are not also reproducible on a supported branch are out of model
   *(documented: `SECURITY.md`)*.
9. **The embedding application's password / private-key storage.**
   WSS4J reads passwords through `WSPasswordCallback` from a caller-supplied
   `CallbackHandler`. How those passwords are stored, rotated, or audited
   is the caller's concern *(documented:
   `src/site/asciidoc/topics.adoc` §"WSPasswordCallback identifiers")*. →
   `OUT-OF-MODEL: trusted-input`.
10. **Code shipped in `*/src/test/` and `policy/src/test/`.** Test JKS
    keystores with documented passwords (e.g. `"security"`, `"changeit"`,
    `"default"`, `"transmitter.jks"`, `"receiver.jks"`) are sample
    data, not production keys. Reports that the test keystores have
    weak passwords or self-signed certs are `OUT-OF-MODEL: unsupported-component`.

## §4 Trust boundaries and data flow

WSS4J has a small number of well-defined trust transitions; a finding
is in-model only if it maps to one of them.

| # | Transition | Authentication | Authorization |
| --- | --- | --- | --- |
| B1 | Wire peer → SOAP stack → WSS4J `WSSecurityEngine` / `InboundWSSec` (the bytes of the incoming SOAP envelope's `wsse:Security` header and any signed/encrypted parts of the body) | the security tokens *inside* the envelope (UsernameToken, X.509 sig, SAML assertion, Kerberos token) are the authentication; that is what WSS4J validates | application-layer; not WSS4J's concern |
| B2 | Embedding stack → `CallbackHandler` → WSS4J | the embedding stack is trusted by construction; WSS4J reads passwords and keys via callback | none |
| B3 | WSS4J → JCE / Santuario / OpenSAML / Bouncy Castle | trusted upstream | none |
| B4 | WSS4J → file-backed keystore / truststore / `ReplayCache` directory | filesystem permissions, owned by the embedding application | OS-level |
| B5 | WSS4J → SAML token issuer's signing key (for inbound) — trust chain rooted in the configured TrustStore | X.509 trust chain validation + optional `SIG_SUBJECT_CERT_CONSTRAINTS` regex | configured per `Merlin` truststore |
| B6 | WSS4J → KDC (Kerberos token validation) | Kerberos / SPNEGO; relies on JAAS config | out of WSS4J's hands |

### Reachability preconditions per component

- **DOM engine (`WSSecurityEngine`)**: a finding is in-model only if it
  is reachable from the bytes of the `wsse:Security` header (or any
  body part referenced by signature / encryption) supplied by a wire
  peer. Bytes that arrive through a `CallbackHandler` (passwords, keys)
  are out-of-model — that's a trusted channel.
- **Streaming engine (`InboundWSSec`)**: same reachability as above,
  *plus* the caller is expected to have set
  `XMLInputFactory.SUPPORT_DTD=false` and
  `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES=false` on the
  `XMLStreamReader` they hand in. WSS4J's *internal*
  `XML_INPUT_FACTORY` (used for the security-header reparse) sets both
  to `false` *(documented:
  `ws-security-stax/src/main/java/org/apache/wss4j/stax/setup/InboundWSSec.java` lines 63-67)*.
- **WS-SecurityPolicy enforcement (`ws-security-policy-stax`)**: in-model
  only when the embedding stack has wired in a `PolicyEnforcer` for the
  inbound message. Without WS-SecurityPolicy, signature-wrapping
  defenses described in §11a depend on the caller setting
  `SIGNATURE_PARTS` / `ENCRYPTION_PARTS` / `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS`
  *(documented: `src/site/asciidoc/best_practice.adoc`,
  `src/site/asciidoc/config.adoc`)*.
- **`ws-security-web`**: in-model insofar as the servlet entry point
  reaches WSS4J; the surrounding servlet container is out.
- **JAXB bindings**: pure DTO objects, in-model only insofar as the
  engines call them.
- **Code in `*/src/test/`**: out of model (§3 item 10).

## §5 Assumptions about the environment

- **JDK**: minimum JDK8 for WSS4J 2.2.x, JDK11 for 3.0.x, JDK17 for 4.0.x
  *(documented: `src/site/asciidoc/wss4j22.adoc` §"JDK8 minimum
  requirement"; inferred from `README.md` build link "JDK17"
  *(inferred — §14 Q5)*)*.
- **JCE Unlimited Strength**: required for the unit tests; *"if you get
  errors about invalid key lengths, the Unlimited Strength files are
  not installed"* *(documented: `README.md` Test Requirements)*. As of
  Java 8u151 / 9+ this is the default, but on older JDKs WSS4J would
  use weaker algorithms silently *(inferred — §14 Q6)*.
- **Apache Santuario** on the classpath, version matching the WSS4J
  branch *(documented: `README.md` Crypto Notice)*.
- **OpenSAML 4.x** for WSS4J 3.x+, OpenSAML 3.x for 2.x
  *(documented: `ChangeLog.txt` WSS-687, WSS-694)*.
- **Bouncy Castle (optional)** as a JCE provider; WSS4J 2.3.x changed
  *how* BC is registered *(documented: `ChangeLog.txt` WSS-661)*.
- **Filesystem**: keystores and truststores are file-backed (via
  `Merlin`) or `null`-stream-backed (via `MerlinDevice` for HSMs)
  *(documented: `src/site/asciidoc/config.adoc` §"Merlin Keystore
  Properties")*. WSS4J does **not** create or rotate these files; the
  caller does.
- **Clock**: WSS4J uses the host wall-clock to evaluate
  `wsu:Timestamp` `Created` / `Expires` semantics. Bounded clock skew
  is honored via `TTL_TIMESTAMP` (default 300 s) and
  `TTL_FUTURE_TIMESTAMP` (default 60 s) *(documented:
  `src/site/asciidoc/config.adoc`)*. If the host clock is wrong, valid
  signatures may be rejected and replayed messages may be accepted
  inside the wider window *(inferred — §14 Q7)*.
- **Memory**: DOM engine holds the entire SOAP envelope in memory;
  StAX engine streams *(documented: `src/site/asciidoc/streaming.adoc`)*.

### What WSS4J does *not* do to its host (negative claims, awaiting maintainer ratification)

- Opens **no** listening sockets *(inferred — §14 Q8)*.
- Spawns **no** child processes *(inferred — §14 Q8)*.
- Installs **no** signal handlers *(inferred — §14 Q8)*.
- Reads a small documented set of system properties for extension
  registry / provider selection (e.g. `org.apache.wss4j.crypto.provider`,
  the SAMLIssuer system property in 1.6.x); does **not** consume
  `LD_*`-style envvars for security-sensitive choices *(inferred —
  §14 Q8)*.
- Writes log lines via SLF4J at the level the embedder configures;
  ReplayCache writes EHCache spool files at the documented location
  *(inferred — §14 Q9)*.
- Touches the file system only via the JDK `KeyStore`/`Properties`/
  EHCache APIs at paths the caller supplied
  *(inferred — §14 Q8)*.

## §5a Build-time and configuration variants

WSS4J ships as a single Maven artifact set (one per module); there are
no compile-time defines. The runtime configuration knobs in
`ConfigurationConstants` materially change the security envelope. The
maintainer-confirmed list is at
`ws-security-common/src/main/java/org/apache/wss4j/common/ConfigurationConstants.java`
and `ws-security-dom/.../handler/RequestData.java`; the security-relevant
subset:

| Flag | Default | Maintainer stance | Effect |
| --- | --- | --- | --- |
| `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM` *("allowRSA15KeyTransportAlgorithm")* | `false` since 2.0.0 *(documented: `src/site/asciidoc/best_practice.adoc`)* | hardened default; flipping voids Bleichenbacher defense | enables RSA v1.5 key-transport algorithm |
| `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS` | `false` *(documented: `ws-security-dom/.../RequestData.java` line 74)* | **maintainer ruling required** — CVE-2015-0227 was about this flag's enforcement *(inferred — §14 Q10)* | requires `EncryptedData` to live in a signed subtree |
| `IS_BSP_COMPLIANT` *("isBSPCompliant")* | `true` since 1.6 *(documented: `src/site/asciidoc/topics.adoc` §"Basic Security Profile 1.1 compliance")* | hardened; disabling weakens inbound checks | enforce BSP 1.1 inbound shape |
| `TIMESTAMP_STRICT` | `true` *(documented: `src/site/asciidoc/config.adoc`)* | hardened | rejects past-expiry timestamps; if `false`, expired timestamps are accepted |
| `REQUIRE_TIMESTAMP_EXPIRES` | `false` *(documented: `src/site/asciidoc/config.adoc`)* | optional hardening; flipping forces explicit expiry | requires `wsu:Timestamp` to carry `Expires` |
| `TTL_TIMESTAMP` | `300` (s) *(documented)* | tunable; smaller = stricter | message-validity window |
| `TTL_FUTURE_TIMESTAMP` | `60` (s) *(documented)* | tunable; smaller = stricter clock-skew tolerance | how far in the future a `Created` may be |
| `TTL_USERNAMETOKEN` / `TTL_FUTURE_USERNAMETOKEN` | `300` / `60` *(documented)* | tunable | analog for UsernameToken `wsu:Created` |
| `HANDLE_CUSTOM_PASSWORD_TYPES` | `false` *(documented)* | hardened; flipping accepts non-standard password types | inbound UsernameToken policy |
| `ALLOW_USERNAMETOKEN_NOPASSWORD` | `false` *(documented)* | hardened; flipping accepts UT-no-password as deriving primitive | inbound UsernameToken policy |
| `PASSWORD_TYPE` (outbound) | `PW_DIGEST` *(documented: `ws-security-dom/.../RequestData.java`)* | discouraged for plaintext-over-cleartext; **digest is still relatively weak** | outbound UsernameToken password encoding |
| `ENC_KEY_TRANSPORT` *("encryptionKeyTransportAlgorithm")* | RSA-OAEP since 2.0.0 *(documented: `src/site/asciidoc/best_practice.adoc`)* | hardened default; flipping to RSA15 *requires* setting `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=true` | choice of key-transport algorithm |
| `ENC_SYM_ALGO` *("encryptionSymAlgorithm")* | AES-128 (CBC by default) *(documented: `src/site/asciidoc/config.adoc`)* | **maintainer ruling required** — best-practice doc says "avoid using a cbc Symmetric Encryption Algorithm" *(inferred — §14 Q11)* | symmetric encryption algorithm |
| `ENC_MGF_ALGO` | `mgfsha1` *(documented)* | tunable; SHA-1 is fine in MGF1 context but raises scanner noise | MGF for RSA-OAEP |
| `SIG_DIGEST_ALGO` (default) | `SHA-1` *(documented: `src/site/asciidoc/config.adoc`)* | **maintainer ruling required** — SHA-1 signatures are below modern guidance *(inferred — §14 Q11)* | default signature digest |
| `SIG_ALGO` | per certificate *(documented)* | best-practice doc recommends explicit `SIG_ALGO` on inbound to bind algorithm | inbound algorithm enforcement |
| `SIG_SUBJECT_CERT_CONSTRAINTS` / `SIG_ISSUER_CERT_CONSTRAINTS` | unset *(documented: `src/site/asciidoc/best_practice.adoc` §"Use Subject DN regular expressions with chain trust")* | strongly recommended when using chain trust | regex constraints over signing-cert DNs |
| `SIG_CERT_CONSTRAINTS_SEPARATOR` | `,` *(documented since 2.2.3)* | tunable | separator in the constraint string |
| `ENABLE_REVOCATION` | `false` *(documented)* | optional CRL checking | inbound certificate revocation |
| `ENABLE_SIGNATURE_CONFIRMATION` | `false` *(documented)* | tunable | enables WS-Security SignatureConfirmation flow |
| `VALIDATE_SAML_SUBJECT_CONFIRMATION` | `true` *(documented)* | hardened | inbound SAML SubjectConfirmation validation |
| `NONCE_CACHE_INSTANCE` / `TIMESTAMP_CACHE_INSTANCE` / `SAML_ONE_TIME_USE_CACHE_INSTANCE` | `EHCacheReplayCache` *(documented)* | replay protection on by default | replay cache for UsernameToken nonces, Timestamps, SAML OneTimeUse |
| `PASSWORD_ENCRYPTOR_INSTANCE` | `JasyptPasswordEncryptor` *(documented)* | tunable | decryption of encrypted passwords in Crypto properties files |
| `merlin.keystore.password` | `"security"` *(documented: `src/site/asciidoc/config.adoc`)* | **maintainer ruling required** — this is a *default for the property file*; production deployments override *(inferred — §14 Q12)* | Merlin keystore password |
| `merlin.truststore.password` | `"changeit"` *(documented)* | dev default | Merlin truststore password |
| `merlin.load.cacerts` | `false` *(documented)* | hardened-by-default; flipping admits the JDK cacerts roots | whether the JDK cacerts are accepted as trust anchors |

### The insecure-default case

Several knobs above ship with defaults that are *correct for a secure
production deployment* (`ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=false`,
`IS_BSP_COMPLIANT=true`, `TIMESTAMP_STRICT=true`,
`VALIDATE_SAML_SUBJECT_CONFIRMATION=true`,
`HANDLE_CUSTOM_PASSWORD_TYPES=false`,
`ALLOW_USERNAMETOKEN_NOPASSWORD=false`,
`merlin.load.cacerts=false`). A small number ship in a posture that
the best-practice document *itself flags as deprecated or weak*:
default `SIG_DIGEST_ALGO=SHA-1`, default `ENC_SYM_ALGO=AES-128-CBC`,
`REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS=false`. The maintainer ruling
on each is captured in §14 Q10–Q11.

## §6 Assumptions about inputs

### Per-entry-point trust table

| Entry point | Parameter | Attacker-controllable? | Caller must enforce |
| --- | --- | --- | --- |
| `WSSecurityEngine.processSecurityHeader(Document doc, ...)` (DOM) | `doc` bytes (the entire SOAP envelope as a parsed DOM) | **yes** — wire-supplied | parse with a DOM parser that has DTD / XXE disabled (WSS4J does not re-parse) |
| `WSSecurityEngine.processSecurityHeader(...)` (DOM) | `WSSConfig` / `RequestData` | **no** — caller-supplied | none |
| `WSSecurityEngine.processSecurityHeader(...)` (DOM) | `Crypto` (signature verification trust source) | **no** — caller-supplied | caller controls the TrustStore contents |
| `WSSecurityEngine.processSecurityHeader(...)` (DOM) | `CallbackHandler` (passwords / decryption keys) | **no** — caller-supplied | none |
| `InboundWSSec.processInMessage(XMLStreamReader xmlStreamReader, ...)` (StAX) | `xmlStreamReader` | **yes** — wraps wire input | `SUPPORT_DTD=false`, `IS_SUPPORTING_EXTERNAL_ENTITIES=false`, `IS_COALESCING=false`, and `WstxInputProperties.P_MIN_TEXT_SEGMENT` per the documented warning *(documented: `ws-security-stax/.../InboundWSSec.java` line 94-99)* |
| `InboundWSSec.processInMessage(...)` (StAX) | `WSSSecurityProperties`, `SecurityEventListener` | **no** — caller-supplied | none |
| `WSHandler.doSenderAction / doReceiverAction` (action-based) | `WSHandlerConstants.ACTION` properties | **no** — caller-supplied | must specify `SIGNATURE_PARTS`, `ENCRYPTION_PARTS`, `OPTIONAL_SIGNATURE_PARTS`, `SIG_ALGO`, `ENC_SYM_ALGO` per `best_practice.adoc` |
| `WSSec.loadWSSecuritySchemas` (internal) | XML Schema XSDs / DTDs | **no** — bundled in jar | n/a; resolver returns bundled `schemas/*.xsd` only *(documented: `ws-security-stax/.../setup/WSSec.java` lines 463-490)* |
| Inbound `wsse:UsernameToken` | UT bytes (Username, Password, Nonce, Created, …) | **yes** | UsernameTokenValidator checks `PASSWORD_TYPE`, nonce replay, `Created` window per `TTL_USERNAMETOKEN` |
| Inbound `wsu:Timestamp` | Timestamp bytes (`Created`, `Expires`) | **yes** | TimestampValidator checks `TIMESTAMP_STRICT`, replay cache, `TTL_FUTURE_TIMESTAMP` |
| Inbound `ds:Signature` over message parts | Signature element + the parts it references | **yes** | Caller must set `SIGNATURE_PARTS` / `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS` or use WS-SecurityPolicy to defend against signature-wrapping |
| Inbound `xenc:EncryptedData` / `xenc:EncryptedKey` | encrypted payload + algorithm declarations | **yes** | `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=false`, an `AlgorithmSuite` constrained policy, Bleichenbacher defense in WSS4J |
| Inbound `saml:Assertion` / `saml2:Assertion` | SAML assertion bytes | **yes** | Caller-supplied truststore; `VALIDATE_SAML_SUBJECT_CONFIRMATION=true`; OpenSAML schema processing |
| Inbound `wsse:BinarySecurityToken` (X.509, Kerberos) | base64 token bytes | **yes** | Trust chain in `Merlin` truststore; Kerberos validated against KDC |
| `Crypto` properties file (`org.apache.wss4j.crypto.merlin.*`) | file path, keystore type, passwords | **no** — caller-supplied | filesystem permissions |
| SAML `CallbackHandler` (outbound assertion construction) | populated `SAMLCallback` | **no** — caller-supplied | caller is responsible for the contents of the assertion |
| Attachment via `AttachmentRequestCallback` (SwA Profile 1.1, 2.0.0+) | attachment bytes + headers | **yes** — wire-supplied | `STORE_BYTES_IN_ATTACHMENT` + signature/encryption parts; *(documented: `src/site/asciidoc/attachments.adoc`)* |
| `EXPAND_XOP_INCLUDE` | configuration | **no** | per `src/site/asciidoc/config.adoc`; inbound expansion default is `true` so signed bytes (not just XOP refs) are what gets verified |

### Size / shape / rate

- WSS4J accepts arbitrarily large SOAP envelopes through the DOM engine,
  bounded only by host memory. The streaming engine is bounded by the
  caller's `XMLInputFactory` limits (e.g. Woodstox `P_MAX_*`)
  *(documented: `src/site/asciidoc/streaming.adoc`)*.
- The streaming engine *does* enforce a maximum-decompressed-bytes
  bound on signed-data compression
  *(documented: `ws-security-stax/.../wss-config-compression.xml`,
  exercised by `VulnerabliltyVectorsDecompressedBytesTest`)*.
- WSS4J has **no rate limiter** of its own — concurrent inbound
  message rate is whatever the SOAP stack admits.

## §7 Adversary model

### Actors

| Actor | In scope? | Capabilities |
| --- | --- | --- |
| **Unauthenticated wire peer** sending a crafted SOAP envelope to the SOAP stack | **yes** | bytes of the SOAP envelope, including the `wsse:Security` header and any signed/encrypted body parts |
| **Authenticated wire peer with valid UsernameToken / X.509 / SAML / Kerberos credential** | **yes** | as above, plus credentials that pass §8 P1; relevant for replay / token-reuse / sender-vouches escalation |
| **Local code in the embedding JVM** | **out of scope** | already in the process; can read keys directly |
| **Owner of the keystore / truststore / passwords file** | **out of scope** | by construction (§3 item 9) |
| **Author of a hostile `CallbackHandler` / `Validator` plugged into `WSSConfig`** | **out of scope** | the embedding stack chose to plug it in; trusted by §2 |
| **Author of a hostile SAML `CallbackHandler` (outbound) populating arbitrary claims** | **out of scope** | caller's choice; WSS4J just signs what the callback returns |
| **Co-tenant on the same JVM** (e.g. multi-app servlet container) | **out of scope** *(inferred — §14 Q13)* — Java's `SecurityManager` is the boundary if any; WSS4J does not claim cross-tenant isolation |
| **Side-channel observer** (cache timing, branch prediction, EM) | **out of scope** *(inferred — §14 Q14)* — but constant-time comparison is used for password / signature-value equality (WSS-677) *(documented: `ChangeLog.txt` 2.3.1)* |
| **Quantum adversary** | **out of scope** |
| **Hostile peer impersonating a trusted CA** | covered iff `SIG_SUBJECT_CERT_CONSTRAINTS` / `SIG_ISSUER_CERT_CONSTRAINTS` are set per `best_practice.adoc` |
| **Operator who fails to set the `best_practice.adoc` knobs** | **out of scope** — operator misconfiguration is documented as such |

## §8 Security properties the project provides

### P1 — Authentication of an inbound SOAP message via the configured WS-Security tokens

- **Condition**: at least one inbound action is configured; the
  corresponding `Validator` is registered (default validator set, or
  caller-supplied); the `Crypto`/TrustStore is configured; the
  `CallbackHandler` returns the right passwords / keys.
- **Violation symptom**: an inbound SOAP envelope is accepted as
  authenticated even though the embedded UsernameToken / X.509
  signature / SAML assertion / Kerberos token is invalid (wrong
  signature, unknown CA, untrusted issuer, expired, mis-bound subject).
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented: `src/site/asciidoc/what.adoc` §"Message Authentication";
  `src/site/asciidoc/topics.adoc` §"Introducing Validators")*

### P2 — Integrity of signed message parts (XML Signature)

- **Condition**: outbound side specified `SIGNATURE_PARTS`; inbound
  side either uses WS-SecurityPolicy to enforce which parts must be
  signed, or sets `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS=true` and
  specifies `SIGNATURE_PARTS` *(documented:
  `src/site/asciidoc/best_practice.adoc`)*.
- **Violation symptom**: an inbound envelope is accepted as integrity-
  protected even though a referenced part was relocated, swapped, or
  unsigned (classic XML signature wrapping). This is the precise threat
  the `VulnerabliltyVectorsTest` regression suite exercises
  *(documented:
  `ws-security-policy-stax/src/test/java/.../VulnerabliltyVectorsTest.java`)*.
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented)*

### P3 — Confidentiality of encrypted message parts (XML Encryption)

- **Condition**: caller specified `ENCRYPTION_PARTS`, key-transport
  algorithm not RSA v1.5 (per default), symmetric algorithm an
  AEAD or operator-accepted CBC, `EncryptedKey` references a key the
  recipient holds in their decryption keystore.
- **Violation symptom**: an attacker recovers plaintext of an
  `EncryptedData` block without the corresponding private key, or
  bypasses confidentiality by swapping/wrapping `EncryptedData`
  references.
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented)*

### P4 — Defense against Bleichenbacher-style oracle attacks on RSA key transport

- **Condition**: WSS4J 2.0.0+ with `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=false`
  (the default); upstream Santuario / JCE provider not contributing an
  oracle.
- **Violation symptom**: the recipient produces a distinguishable error
  / timing signal between "padding malformed" and "padding well-formed
  but plaintext rejected" that lets the attacker iteratively recover the
  symmetric key.
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented: CVE-2015-0226 advisory; `best_practice.adoc`
  §"Use RSA-OAEP for the Key Transport Algorithm")*

### P5 — Replay protection on inbound UsernameToken nonces, Timestamps, and SAML2 OneTimeUse assertions

- **Condition**: replay-cache is enabled (default `EHCacheReplayCache`);
  inbound message carries the required `wsu:Created` / `Nonce` /
  SAML2 `OneTimeUse` condition.
- **Violation symptom**: an inbound envelope identical to one already
  accepted within the TTL window is accepted again.
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented: `src/site/asciidoc/config.adoc` §"Non-boolean configuration
  tags" — `NONCE_CACHE_INSTANCE`, `TIMESTAMP_CACHE_INSTANCE`,
  `SAML_ONE_TIME_USE_CACHE_INSTANCE`)*

### P6 — Strict Timestamp expiry enforcement

- **Condition**: `TIMESTAMP_STRICT=true` (default); host clock within
  `TTL_FUTURE_TIMESTAMP` of the sender.
- **Violation symptom**: an inbound envelope with an `Expires` in the
  past is accepted.
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented: `src/site/asciidoc/config.adoc`)*

### P7 — Basic Security Profile 1.1 compliance on inbound envelopes

- **Condition**: `IS_BSP_COMPLIANT=true` (default since 1.6).
- **Violation symptom**: an inbound envelope that violates a BSP rule
  not on the caller's `ignoredBSPRules` list is accepted.
- **Severity**: **security-critical** when the rule defended a known
  interop / attack class; **correctness-only** for purely stylistic
  rules — case-by-case in `BSPRule`.
- *(documented: `src/site/asciidoc/topics.adoc` §"Basic Security Profile
  1.1 compliance")*

### P8 — Constant-time comparison of password / signature secrets

- **Condition**: WSS4J 2.3.1+ for the comparator fix
  *(documented: `ChangeLog.txt` WSS-677, 2.3.1)*.
- **Violation symptom**: an attacker recovers a password / signature
  value via a timing side-channel measured against WSS4J's comparator.
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented)*

### P9 — Strict SAML SubjectConfirmation validation

- **Condition**: `VALIDATE_SAML_SUBJECT_CONFIRMATION=true` (default).
- **Violation symptom**: an inbound SAML assertion with mis-bound
  Subject / HolderOfKey / Bearer / SenderVouches is accepted as
  authenticating a different principal.
- **Severity**: **security-critical**, `VALID` per §13.
- *(documented: `src/site/asciidoc/config.adoc`)*

### P10 — Decompression-bound enforcement on signed compressed payloads (StAX)

- **Condition**: streaming engine, `wss-config-compression.xml` configures
  a maximum byte count.
- **Violation symptom**: an inbound signed compressed payload expands
  beyond the configured threshold and the engine still accepts it.
- **Severity**: **security-critical** for DoS resistance,
  `VALID-HARDENING` boundary case in DOM mode
  *(inferred — §14 Q15)*.
- *(documented:
  `ws-security-stax/src/test/java/.../VulnerabliltyVectorsDecompressedBytesTest.java`)*

## §9 Security properties the project does *not* provide

State each plainly so a triager can route an inbound report to the
matching disclaimer.

- **No XXE / DTD defense on the bytes-to-DOM step.** WSS4J accepts a
  pre-parsed `Document` (DOM engine) or `XMLStreamReader` (StAX engine).
  If the caller hands in a reader / document built with DTD or external
  entity expansion enabled, WSS4J does not retroactively re-secure it.
  The streaming engine warns about this in javadoc and configures *its
  internal* `XML_INPUT_FACTORY` securely *(documented:
  `ws-security-stax/.../InboundWSSec.java` lines 63-67, 94-99)*.
- **No transport-layer security.** WSS4J operates on already-received
  bytes; TLS is the SOAP stack's / container's responsibility
  *(documented: not the topic of WSS4J — message-level only)*.
- **No defender against the SOAP stack.** If the SOAP stack routes a
  body to a service implementation regardless of WSS4J's verdict, that
  is the stack's bug, not WSS4J's.
- **No automatic signature-wrapping defense without WS-SecurityPolicy or
  explicit `SIGNATURE_PARTS`.** *(documented:
  `src/site/asciidoc/best_practice.adoc` §"Use WS-SecurityPolicy to
  enforce security requirements")*. The action-based API requires the
  caller to specify which parts must be signed; failing to specify them
  produces a working but insecure deployment.
- **No defense against an authenticated peer who is *also* authorized
  to do the operation.** WSS4J authenticates the peer and validates the
  signature; whether the peer is allowed to do what the SOAP body says
  is the embedding application's authorization decision.
- **No bound on the size of an inbound SOAP envelope in DOM mode.**
  DoS via a 10 GB signed envelope is a deployment-side concern; the
  StAX engine streams, but the DOM engine reads the whole envelope into
  memory.
- **No defense against decompression bombs in DOM mode.** Only the
  streaming engine wires up `MaximumAllowedDecompressedBytes` *(documented:
  `VulnerabliltyVectorsDecompressedBytesTest`)*.
- **No data-at-rest protection.** Keystores, truststores, and the
  EHCache replay-cache spool are read and written through standard JDK /
  EHCache APIs; encryption of these files at rest is the operator's
  job.
- **No constant-time guarantees beyond `MessageDigest.isEqual` since
  2.3.1.** Other comparators may still be early-exit; only
  `UsernameTokenValidator`'s password compare was hardened
  *(documented: `ChangeLog.txt` WSS-677; *(inferred — §14 Q16)* for
  the rest)*.
- **No defense against side-channel observation** of cryptographic
  operations (cache, branch prediction, EM) beyond what the underlying
  JCE / Santuario / BC provider provides *(inferred — §14 Q14)*.
- **No defense against a hostile `CallbackHandler`, `Validator`,
  `Crypto`, or `Processor` registered through `WSSConfig`.**
- **No quantum-resistance.**

### False-friend properties (call out separately)

- **`PASSWORD_DIGEST` looks like password hashing, but it is **not**.**
  The wire-format is `SHA-1(nonce || created || password)`; a peer with
  the digest and the cleartext nonce + created can mount an offline
  dictionary attack against the password. *(documented:
  `src/site/asciidoc/config.adoc` §"PASSWORD_TYPE"; OASIS UsernameToken
  Profile 1.1)*. Use TLS *and* a strong password policy regardless.
- **CRC / checksum-like elements in BSP / WS-Security profile are not
  MACs.** A `wsse:Nonce` is for replay defense, not message integrity.
- **The Web UI `wsse:Username` / `wsse:Password` text are not
  authorization tokens.** Any caller-supplied content; authorization is
  layered on by the embedding stack.
- **`enableSignatureConfirmation` does not authenticate the *responder*
  to the original requester** beyond the signature it confirms. It is
  a replay-style defense, not an extra factor.
- **A successful X.509 trust chain validation does not authenticate the
  *holder of the private key* to be the *expected* principal unless
  `SIG_SUBJECT_CERT_CONSTRAINTS` (or equivalent) is set.** Any cert from
  any CA in the truststore would otherwise pass *(documented:
  `src/site/asciidoc/best_practice.adoc` §"Use Subject DN regular
  expressions with chain trust")*.
- **`merlin.keystore.password` default of `"security"` and
  `merlin.truststore.password` default of `"changeit"` are *property-file
  defaults for documentation*, not WSS4J runtime defaults for production
  keystores** — the actual keystore on disk has whatever password the
  operator gave it *(documented: `src/site/asciidoc/config.adoc`)*.
- **The `ws-security-web` servlet filter is not a SOAP stack.** It does
  not parse the SOAP envelope or route bodies; it is a thin entrypoint
  *(inferred — §14 Q3)*.
- **Apache Santuario's `setSecureValidation` setting does not subsume
  WSS4J's `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS`.** They cover
  different attack classes *(inferred — §14 Q10)*.

### Well-known attack classes the project does not single-handedly defend against

- **XML Signature wrapping** — defended only with WS-SecurityPolicy or
  explicit `SIGNATURE_PARTS` + `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS`.
- **XXE / billion laughs** — relies on caller's parser configuration.
- **Compression bomb in `EncryptedData`** — only the streaming engine
  enforces a bound by default.
- **Bleichenbacher / oracle on RSA v1.5 key transport** — defended only
  with the default `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=false`.
- **CBC padding oracle on symmetric encryption** — `best_practice.adoc`
  advises switching to AES-GCM; default of AES-CBC is still in use
  *(inferred — §14 Q11)*.
- **Timing side-channel on token comparators** — `MessageDigest.isEqual`
  is used since 2.3.1 in `UsernameTokenValidator`; comprehensive sweep
  is *(inferred — §14 Q16)*.
- **SAML assertion forgery via signature wrapping or sender-vouches
  misuse** — defended via OpenSAML + `VALIDATE_SAML_SUBJECT_CONFIRMATION`.
- **Token replay** — defended via the three replay caches.

## §10 Downstream responsibilities

The embedding SOAP stack / application **must**:

1. Parse the inbound SOAP bytes with a DOM parser or `XMLStreamReader`
   configured with DTDs disabled and external entities disabled. The
   streaming engine's javadoc spells out the minimum:
   `SUPPORT_DTD=false`, `IS_SUPPORTING_EXTERNAL_ENTITIES=false`,
   `IS_COALESCING=false`, and (for Woodstox) `P_MIN_TEXT_SEGMENT=8192`
   *(documented: `ws-security-stax/.../InboundWSSec.java` lines 94-99)*.
2. Use WS-SecurityPolicy when at all possible, in preference to the
   action-based approach *(documented:
   `src/site/asciidoc/best_practice.adoc` §"Use WS-SecurityPolicy")*.
3. When using the action-based approach, set `SIGNATURE_PARTS` and
   `ENCRYPTION_PARTS` for outbound, and `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS=true`
   for inbound; specify `SIG_ALGO` and `ENC_KEY_TRANSPORT` on inbound to
   enforce algorithm choice *(documented:
   `src/site/asciidoc/best_practice.adoc`)*.
4. Never set `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=true` for new
   deployments *(documented: `src/site/asciidoc/best_practice.adoc`,
   CVE-2015-0226)*.
5. Prefer AES-GCM symmetric algorithms over CBC by explicitly setting
   `ENC_SYM_ALGO` to a `xmlenc11#aes*-gcm` identifier *(documented:
   `src/site/asciidoc/best_practice.adoc` §"Avoid using a cbc Symmetric
   Encryption Algorithm")*.
6. When relying on chain trust, set `SIG_SUBJECT_CERT_CONSTRAINTS` (or
   `SIG_ISSUER_CERT_CONSTRAINTS`) to bound the acceptable signer
   identities *(documented:
   `src/site/asciidoc/best_practice.adoc` §"Use Subject DN regular
   expressions with chain trust")*.
7. Restrict OS-level permissions on keystore / truststore / Crypto
   `.properties` files to the running process owner.
8. Configure the EHCache replay-cache to a writable, persistent location
   sized for the expected token-per-TTL volume; verify that the cache
   is durable across host restart if the deployment relies on cross-
   restart replay defense *(inferred — §14 Q17)*.
9. Run on a supported WSS4J branch (4.0.x / 3.0.x / 2.4.x) *(documented:
   `SECURITY.md`)*.
10. Use TLS for the transport — WSS4J is message-level security, not
    a substitute for transport security.
11. Treat the `CallbackHandler` and any custom `Validator` as part of
    the security TCB.
12. Set `ENABLE_REVOCATION=true` and supply a current `merlin.x509crl.file`
    when revocation matters *(documented: `src/site/asciidoc/config.adoc`)*.
13. Override `merlin.keystore.password` / `merlin.truststore.password`
    away from the documented `"security"` / `"changeit"` defaults
    *(documented)*.
14. Never enable `merlin.load.cacerts=true` unless the embedding
    application is willing to trust the system-wide CA bundle for
    WS-Security purposes *(documented)*.
15. Apply security advisories listed at
    `http://ws.apache.org/wss4j/security_advisories.html` and at
    Apache CXF's advisory page (many WS-Security CVEs land there
    rather than on WSS4J) *(documented:
    `src/site/xdoc/security_advisories.xml`)*.

## §11 Known misuse patterns

- **Using WSS4J with the action-based approach and forgetting to set
  `SIGNATURE_PARTS` on the receiving side.** Inbound signature is
  validated, but the validated set may be empty or only the SOAP body,
  letting a signature-wrapping attacker move signed content into a
  header *(documented: `src/site/asciidoc/best_practice.adoc`)*.
- **Plumbing a wire-supplied `XMLStreamReader` into `InboundWSSec`
  without disabling DTD / external entities** — the engine itself only
  configures its *internal* factory *(documented:
  `ws-security-stax/.../InboundWSSec.java` warning)*.
- **Trusting an X.509 chain-validated certificate without
  `SIG_SUBJECT_CERT_CONSTRAINTS`.** Any cert any CA in the truststore
  issued is admitted *(documented:
  `src/site/asciidoc/best_practice.adoc`)*.
- **Re-enabling RSA v1.5 (`ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=true`)
  for interop with a legacy peer.** Re-introduces the Bleichenbacher
  oracle path even though WSS4J's own defense exists.
- **Reusing the same `merlin.keystore.password` (`"security"` from the
  documented example) in production deployments.**
- **Disabling BSP compliance via `IS_BSP_COMPLIANT=false` to "make
  interop work" with a non-conformant stack.**
- **Treating `PASSWORD_DIGEST` as offline-attack-resistant.** Combined
  with a weak password, the digest can be brute-forced offline
  *(documented: `src/site/asciidoc/config.adoc` and OASIS UT 1.1)*.
- **Building a custom `Validator` that returns success on the wrong
  branch** — e.g. validating the literal text of a SAML assertion
  without checking enveloped signature on the OpenSAML 1.x → 2.x
  upgrade boundary *(documented: `src/site/asciidoc/topics.adoc`
  §"Support for SAML2 assertions" — WSS-146)*.
- **Setting `ENABLE_REVOCATION=true` without supplying a CRL file** —
  validation silently degrades when the CRL is missing
  *(inferred — §14 Q18)*.
- **Using the same `nonceCacheInstance` across deployments at different
  trust levels** — a leak in deployment A becomes a forgery primitive
  in deployment B *(inferred — §14 Q17)*.
- **Mixing the action-based and WS-SecurityPolicy approaches in the
  same handler chain.** The behavior across both is documented but
  rarely tested.

## §11a Known non-findings (recurring false positives)

This section is the highest-leverage input for automated agentic
security scans. Each entry: tool symptom, why it is safe under the
model, the section that licenses the call.

- **"`MessageDigest.MD5` / `MessageDigest.SHA1` instantiated in
  `Merlin`-related code."** `SHA1` is used for legacy
  digestMethod identifiers and OASIS-specified token digests; MD5 is
  used for OASIS-specified `XKMS` legacy identifiers. WSS4J's
  algorithm choice for *production signature/encryption* is controlled
  by `SIG_DIGEST_ALGO` / `SIG_ALGO` / `ENC_SYM_ALGO`. → `BY-DESIGN:
  property-disclaimed` per §9 *(inferred — §14 Q11)*.
- **"Hardcoded `'security'` / `'changeit'` / `'default'` keystore
  password in test resources."** `ws-security-dom/src/test/resources/*.properties`
  and `ws-security-stax/src/test/resources/*.jks` are test data;
  documented passwords. → `OUT-OF-MODEL: unsupported-component` per §3
  item 10.
- **"Hardcoded `'security'` default in
  `src/site/asciidoc/config.adoc`."** Documentation default for the
  `merlin.keystore.password` property file format; not a runtime
  default. → `KNOWN-NON-FINDING`.
- **"`XMLInputFactory.newInstance()` in
  `ws-security-stax` does not call `setProperty(SUPPORT_DTD, false)`."**
  Check `InboundWSSec`'s static initializer: it does
  *(documented: `InboundWSSec.java` lines 63-67)*. The instances *callers
  supply* are the caller's concern per the documented warning.
- **"`DocumentBuilderFactory` not hardened in `ws-security-dom`."** The
  DOM engine does not parse XML bytes; it receives a `Document` from
  the SOAP stack. → `OUT-OF-MODEL: trusted-input` per §3 item 2.
- **"Path traversal via `merlin.keystore.file`."** Caller-supplied
  property. → `OUT-OF-MODEL: trusted-input`.
- **"Plaintext password in `Crypto` properties file."** A
  `PasswordEncryptor` (default `Jasypt`) is documented; passwords *can*
  be encrypted in the properties file *(documented:
  `src/site/asciidoc/config.adoc` `PASSWORD_ENCRYPTOR_INSTANCE`)*. A
  literal plaintext password is a deployment choice. → `OUT-OF-MODEL:
  trusted-input`.
- **"`Arrays.equals` early-exit in
  `org.apache.wss4j.dom.transform.STRTransform` / signature value
  compare."** WSS-677 hardened `UsernameTokenValidator`; if a scanner
  flags a different comparator, treat as `MODEL-GAP` and trigger §12
  *(inferred — §14 Q16)*.
- **"`AccessController.doPrivileged` block."** The legacy SecurityManager
  bracket is a JDK requirement on JDK pre-17. Reports against this
  pattern are `OUT-OF-MODEL: non-default-build` *(inferred — §14 Q5)*.
- **"`RuntimeException` thrown from `Crypto` property loader on bad
  password."** The exception is the documented failure mode; not a
  crash leak. → `BY-DESIGN: property-disclaimed`.
- **"Open `KeyStore` and silently fall back to default on missing
  file."** Reproducible only under operator misconfiguration. →
  `OUT-OF-MODEL: trusted-input`.
- **"`opensaml-*.jar` has CVE-X."** Report upstream to the OpenSAML
  project; WSS4J picks up via dependency bump
  *(documented: `ChangeLog.txt` WSS-687 et al)*. → `OUT-OF-MODEL:
  unsupported-component`.
- **"DTD / billion-laughs against WSS4J DOM engine via crafted
  `<soap:Envelope>`."** WSS4J does not parse bytes-to-DOM; the SOAP
  stack does. → `OUT-OF-MODEL: trusted-input` per §3 item 2.
- **"`InputStream.close()` not in finally."** Code-quality finding,
  not a security one. → `OUT-OF-MODEL: out-of-layer`.

## §12 Conditions that would change this model

Revise this document when any of the following lands:

- A new WS-Security profile or token type (e.g. a new bearer-token
  profile).
- A new processing engine beyond the DOM and StAX implementations.
- A change in the default value of any §5a knob — especially
  `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM`, `IS_BSP_COMPLIANT`,
  `ENC_KEY_TRANSPORT`, `ENC_SYM_ALGO`, `SIG_DIGEST_ALGO`,
  `VALIDATE_SAML_SUBJECT_CONFIRMATION`.
- An upgrade of the bundled OpenSAML / Apache Santuario / Bouncy Castle
  / EHCache that materially changes default behavior.
- A new public extension point (`Validator`, `Processor`,
  `CallbackHandler` subclass) that materially expands the trusted-by-
  construction set.
- A new bound-violation surface, e.g. shipping a built-in maximum
  envelope size on the DOM engine.
- A vulnerability report that cannot be cleanly routed to one of the
  §13 dispositions: that is evidence the model has a gap.

## §13 Triage dispositions

A report against WSS4J receives exactly one of the following:

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a §8 property via an in-scope §7 adversary using an in-scope §6 input on a supported branch per `SECURITY.md`. | §8, §6, §7 |
| `VALID-HARDENING` | No §8 property violated, but a §11 misuse pattern can be made harder to fall into by code change. Typically no CVE. | §11 |
| `OUT-OF-MODEL: trusted-input` | Requires attacker control of a §6 parameter the model marks trusted (caller-supplied `XMLStreamReader` not hardened against XXE, caller-supplied `Crypto` properties file path, hostile `CallbackHandler`, …). | §6 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires a §7 actor the model excludes (in-process attacker, owner of the keystore, hostile SOAP stack). | §7 |
| `OUT-OF-MODEL: unsupported-component` | Lands in `*/src/test/`, `integration/`, vendored sample data, or in upstream code (OpenSAML, Santuario, EHCache, BC, JCE). | §3 items 3–7, §3 item 10 |
| `OUT-OF-MODEL: non-default-build` | Only manifests when a §5a knob the maintainer rules dev/test has been flipped (e.g. `ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM=true`, `IS_BSP_COMPLIANT=false`, `TIMESTAMP_STRICT=false`). | §5a |
| `BY-DESIGN: property-disclaimed` | Concerns a §9 property the project explicitly does not provide (no XXE defense on caller-parsed XML, no automatic signature-wrapping defense without WS-SecurityPolicy or `SIGNATURE_PARTS`, no rate limiting, no data-at-rest encryption). | §9 |
| `KNOWN-NON-FINDING` | Matches a §11a recurring false positive. | §11a |
| `MODEL-GAP` | Cannot be cleanly routed to any of the above — triggers §12 model revision. | §12 |

## §14 Open questions for the maintainers

Every *(inferred)* tag in the body maps to one of these. Proposed
answers are inline; please confirm, correct, or strike.

### Wave 1 — scope, trust boundaries

**Q1.** Confirm that a `CallbackHandler` and a `Validator` plugged into
`WSSConfig` are treated as part of WSS4J's trusted computing base — i.e.
a hostile callback / validator is out of model (proposed: **yes**, §2
caller-roles, §3 item 9). *(maps to §2, §3, §7)*

**Q2.** Defects intrinsic to Apache Santuario, OpenSAML, Bouncy Castle,
EHCache, and the JDK JCE provider — confirm policy is "report upstream;
WSS4J picks up via dependency bump" (proposed: **yes**). *(maps to §3
items 3–7, §11a)*

**Q3.** `ws-security-web` ships a servlet `Filter` and helper utility.
Is it (a) a first-class supported entry point, (b) a legacy artifact,
or (c) sample code best removed? The draft assumes (a) with the caveat
that the surrounding container is out of model. *(maps to §2, §3 item 1)*

**Q4.** EHCache default replay-cache backing: proposed treatment is
"EHCache the library is upstream; WSS4J's wiring of it is in-model"
(WSS-643 NullPointerException example). Confirm? *(maps to §3 item 7)*

**Q5.** Supported JDK matrix per branch: proposed 2.4.x = JDK8+, 3.0.x
= JDK11+ (Jakarta namespace migration WSS-694), 4.0.x = JDK17+ (per
`README.md` JDK17 badge). Confirm exact minima. *(maps to §5)*

**Q6.** JCE Unlimited Strength: now default on Java 8u151+, so the
README requirement is effectively a no-op on supported JDKs. Confirm
WSS4J makes no claim about behavior on pre-8u151 JDKs (proposed: out
of model). *(maps to §5)*

**Q7.** Clock-skew assumption: WSS4J's `TTL_FUTURE_TIMESTAMP=60` and
`TTL_TIMESTAMP=300` are documented defaults; do you make any Impala-
level claim about host-clock accuracy, or is that entirely operator
responsibility (proposed: operator)? *(maps to §5, §10)*

**Q8.** Confirm the negative-side inventory in §5: WSS4J opens **no**
sockets, spawns **no** processes, installs **no** signal handlers, and
reads only the documented system properties. Anything else? *(maps to §5)*

**Q9.** Confirm WSS4J writes only via SLF4J + the EHCache spool (when
configured) + the keystore/truststore files (when callers ask
`Merlin` to write). *(maps to §5)*

### Wave 2 — insecure defaults & enforcement gaps

**Q10.** `REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS` defaults to `false`.
CVE-2015-0227 was about enforcing this property. Is the production
guidance "set to `true` per §10" (proposed) or "set explicitly via
WS-SecurityPolicy so it is policy-enforced"? Is a report against an
unset deployment `VALID` (operator-error) or `OUT-OF-MODEL: non-default-build`?
*(maps to §5a, §8 P2, §10, §13)*

**Q11.** **Default SHA-1 signature digest and AES-128-CBC symmetric
algorithm.** The best-practice document explicitly recommends moving
off CBC and is silent on the SHA-1 default. Are these defaults
"supported production posture" (so a report against them is `VALID`),
"dev-default; operators must flip per §10" (so reports are
`OUT-OF-MODEL: non-default-build`), or "deprecated but kept for legacy
interop, will be flipped in a future release" (so reports are
`VALID-HARDENING`)? Proposed answer for both: **legacy interop default
— `VALID-HARDENING` with a §10 note**. *(maps to §5a, §10, §11a)*

**Q12.** `merlin.keystore.password=security` and
`merlin.truststore.password=changeit` are documented as defaults in
`config.adoc`. Confirm these are *documentation defaults for the
property-file format*, not runtime defaults applied by WSS4J when the
property is absent (proposed: documentation only). *(maps to §5a, §9
false-friend)*

**Q13.** Co-tenant attackers (multiple webapps in one JVM): does WSS4J
make any claim about cross-classloader / cross-tenant isolation
(proposed: **no**, §7 out-of-scope)? *(maps to §7, §9)*

**Q14.** Side-channel observers (cache, branch prediction, EM): out of
scope (proposed)? *(maps to §7, §9)*

**Q15.** §8 P10 (decompression bound) is enforced by the StAX engine
when wired via `wss-config-compression.xml`. Is the analog in the DOM
engine an out-of-model concern (proposed: `VALID-HARDENING`), or does
the DOM engine carry an equivalent? *(maps to §8 P10, §9)*

**Q16.** WSS-677 hardened `UsernameTokenValidator` to use
`MessageDigest.isEqual`. Has the rest of the comparator surface
(signature values, SAML attribute matches, BSP rule compares) been
swept? Proposed §11a treatment is "specific WSS-677 surface is
hardened; other comparator reports are `MODEL-GAP` until ruled". *(maps
to §8 P8, §9, §11a)*

**Q17.** Replay-cache durability: do you make a claim that an
`EHCacheReplayCache` configured with a persistent spool defends
across-restart (proposed: **yes, when persistent spool is configured**),
or is replay defense documented as best-effort? *(maps to §5a, §10)*

**Q18.** `ENABLE_REVOCATION=true` without a CRL file: does WSS4J fail
loudly or silently degrade? Proposed treatment in §11 is "silent
degrade is a `VALID-HARDENING` for a clearer log line / startup
exception". *(maps to §11)*

### Wave 3 — meta & coexistence

**Q19.** This document should be hosted in-repo at
`docs/security/threat-model.md` (proposed) or on
`ws.apache.org/wss4j/`? *(meta)*

**Q20.** `SECURITY.md` is currently disclosure-only. Should this
threat model (a) replace its in-the-spirit-of-threat-model content,
(b) become canonical and `SECURITY.md` link to it, or (c) sit
alongside as an expansion (proposed: (b))? *(meta — §3.1a)*

**Q21.** `best_practice.adoc` already does much of the §10 work for
us. Should the threat model link to it as the canonical operator
guidance, or maintain a separate §10 list (proposed: link + a §10
table that *references* the best-practice entries)? *(meta)*

**Q22.** §11a known-non-findings is thin (~13 patterns). Could the
WSS4J / Webservices PMC populate from the JIRA "not a bug" / "wontfix"
closures (`WSS-*` tickets)? Concrete asks: 3–5 patterns the PMC sees
recur in inbound reports against WSS4J. *(meta — §11a)*

**Q23.** What kind of change to WSS4J should trigger a revision
(proposed list in §12 — confirm or correct)? *(meta — §12)*

---

## Appendix: SECURITY.md / website → §x back-map

WSS4J's `SECURITY.md` is disclosure-only — it does not embed
threat-model content beyond the supported-branch matrix. The other
documented sources are the AsciiDoc pages under `src/site/asciidoc/`
(published at `https://ws.apache.org/wss4j/`).

| Source | Claim | Lands in |
| --- | --- | --- |
| `SECURITY.md` | Supported branches: 4.0.x, 3.0.x, 2.4.x | §1 supported branches, §3 item 8, §13 `VALID` precondition |
| `SECURITY.md` | Reporting via `https://www.apache.org/security/` | §1 reporting |
| `SECURITY.md` | Advisories at `http://ws.apache.org/wss4j/security_advisories.html` | §1 reporting, §10 item 15 |
| `README.md` | WS-Security profiles supported | §1 description, §2 intended use |
| `README.md` | Apache Santuario / OpenSAML / BC cryptographic dependencies | §3 item 3, §3 item 5, §5 environment |
| `README.md` Test Requirements | JCE Unlimited Strength | §5 environment |
| `src/site/asciidoc/what.adoc` | Message Confidentiality / Integrity / Authentication / Authorization | §8 P1–P3 |
| `src/site/asciidoc/using.adoc` | "Apache WSS4J is designed to be used with a Web Services stack such as Apache CXF or Apache Axis" | §2 deployment shape, §3 item 1 |
| `src/site/asciidoc/best_practice.adoc` §"Use WS-SecurityPolicy" | "gives you more *automatic* protection against various attacks" + link to signature-wrapping post | §3.1 mining; §8 P2 violation symptom; §9 first/disclaim entry; §10 item 2 |
| `src/site/asciidoc/best_practice.adoc` §"Use RSA-OAEP" | CVE-2015-0226 / Bleichenbacher | §8 P4, §10 item 4, §11 |
| `src/site/asciidoc/best_practice.adoc` §"Avoid using a cbc Symmetric Encryption Algorithm" | recommend GCM | §5a `ENC_SYM_ALGO` insecure-default, §10 item 5, §14 Q11 |
| `src/site/asciidoc/best_practice.adoc` §"Use Subject DN regular expressions" | recommended with chain trust | §5a `SIG_SUBJECT_CERT_CONSTRAINTS`, §10 item 6, §11 |
| `src/site/asciidoc/best_practice.adoc` §"Specify signature algorithm on receiving side" | bind algorithm via `SIG_ALGO` | §6 trust table, §10 item 3 |
| `src/site/asciidoc/config.adoc` | full configuration-tag inventory | §5a |
| `src/site/asciidoc/topics.adoc` §"Introducing Validators" | Validator concept; default validators; signature-wrapping defense | §2 caller-roles, §8 P1, §11a `Validator` non-finding |
| `src/site/asciidoc/topics.adoc` §"Basic Security Profile 1.1 compliance" | BSP default is `true` since 1.6 | §8 P7, §5a `IS_BSP_COMPLIANT` |
| `src/site/asciidoc/topics.adoc` §"WSPasswordCallback identifiers" | CallbackHandler is the password / key channel | §2 caller-roles, §3 item 9, §6 entry-point table |
| `src/site/asciidoc/streaming.adoc` | StAX engine introduced in 2.0.0; limitations vs DOM | §2 component-family table, §4 reachability, §9 (limitations) |
| `src/site/asciidoc/attachments.adoc` | SwA Profile 1.1 sign/encrypt support | §6 attachment row |
| `src/site/asciidoc/wss4j22.adoc` | JDK8 minimum, Kerberos changes | §5 |
| `src/site/xdoc/security_advisories.xml` | CVE-2015-0226, CVE-2015-0227; pointer to CXF advisories | §1 reporting, §10 item 15 |
| `ws-security-stax/src/main/java/org/apache/wss4j/stax/setup/InboundWSSec.java` (javadoc + static init) | "configure your xmlStreamReader correctly. Otherwise you can create a security hole" — internal factory sets DTD/external-entity to false | §3 item 2, §6 trust table, §10 item 1, §11a `XMLInputFactory` non-finding |
| `ws-security-stax/src/main/java/org/apache/wss4j/stax/setup/WSSec.java` | `SchemaFactory.setFeature(FEATURE_SECURE_PROCESSING, true)` for bundled schema load | §5 environment |
| `ws-security-common/src/main/java/org/apache/wss4j/common/cache/EHCacheReplayCache.java` | EHCache-backed replay defense | §5a, §8 P5, §10 item 8 |
| `ws-security-common/src/main/java/org/apache/wss4j/common/ConfigurationConstants.java` + `ws-security-dom/.../RequestData.java` | configuration-tag definitions and defaults | §5a |
| `ws-security-policy-stax/src/test/java/.../VulnerabliltyVectorsTest.java` | SOAPAction spoofing is out of scope; signed-body-relocation is a `VALID` regression test | §3 item 1, §8 P2 |
| `ws-security-stax/src/test/java/.../VulnerabliltyVectorsDecompressedBytesTest.java` | "Maximum byte count … reached" enforced on signed compressed payloads | §8 P10, §10 item 8 |
| `ChangeLog.txt` WSS-677 (2.3.1) | "Comparison in validate class is vulnerable to timing side channels" | §8 P8 |
| `ChangeLog.txt` WSS-694 (3.0.0) | Move wss4j to native jakarta namespace | §5 environment |
| `ChangeLog.txt` WSS-684/WSS-687 (3.0.0) | OpenSAML 4 upgrade | §3 item 5, §5 |
| `Performance-Tips.txt` | engineering guidance only, not security; called out so triagers do not mine it | n/a |
