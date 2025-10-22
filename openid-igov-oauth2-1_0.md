---
title: "International Government Assurance Profile (iGov) for OAuth 2.0 – draft 08"
abbrev: "iGov OAuth 2.0"
docName: "openid-igov-oauth2-1_08"
category: std
ipr: none
consensus: true
date: "15 September 2025"
authors:
  - name: "Kelley Burgin"
    initials: "K."
    surname: "Burgin"
    role: editor
    organization: "The MITRE Corporation"
    email: "kburgin@mitre.org"
  - name: "Tom Clancy"
    initials: "T."
    surname: "Clancy"
    role: editor
    organization: "The MITRE Corporation"
    email: "tclancy@mitre.org"
workgroup: "OpenID iGov Working Group"
abstract: |
  The OAuth 2.0 protocol framework defines a mechanism to allow a
  resource owner to delegate access to a protected resource for a
  client application.

  This specification profiles the OAuth 2.0 protocol framework to
  increase baseline security, provide greater interoperability, and
  structure deployments in a manner specifically applicable, but not
  limited to consumer‑to‑government deployments.
---

# Introduction {#introduction}

This document profiles the OAuth 2.0 web authorization framework for
use in the context of securing web‑facing application programming
interfaces (APIs), particularly Representational State Transfer (RESTful)
APIs. The OAuth 2.0 specifications accommodate a wide range of
implementations with varying security and usability considerations,
across different types of software clients. The OAuth 2.0 client,
protected resource, and authorization server profiles defined in this
document serve two purposes:

1. Define a mandatory baseline set of security controls suitable for a
   wide range of government use cases, while maintaining reasonable ease
   of implementation and functionality.  
2. Identify optional, advanced security controls for sensitive use
   cases where increased risk justifies more stringent controls.

## Requirements Notation and Conventions {#rnc}

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**,
and **OPTIONAL** in this document are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

All uses of [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515) and
[JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516) data
structures in this specification utilize the JWS Compact Serialization
or the JWE Compact Serialization; the JWS JSON Serialization and the
JWE JSON Serialization are not used.

## Terminology {#terminology}

This specification uses the terms *Access Token*, *Authorization Code*,
*Authorization Endpoint*, *Authorization Grant*, *Authorization Server*,
*Client*, *Client Authentication*, *Client Identifier*, *Client Secret*,
*Grant Type*, *Protected Resource*, *Redirection URI*, *Refresh Token*,
*Resource Owner*, *Resource Server*, *Response Type*, and *Token Endpoint*
defined by [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), the terms
*Claim Name*, *Claim Value*, and *JSON Web Token (JWT)* defined by
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), and the terms
defined by [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

## Conformance

This specification defines requirements for the following components:

* OAuth 2.0 **clients**.  
* OAuth 2.0 **authorization servers**.  
* OAuth 2.0 **protected resources**.

The specification also defines features for interaction between these
components:

* Client ↔ authorization server.  
* Protected resource ↔ authorization server.

When an iGov‑compliant component is interacting with other iGov‑compliant
components, in any valid combination, **all components MUST fully
conform** to the features and requirements of this specification.
All interaction with non‑iGov components is outside the scope of this
specification.

An iGov‑compliant OAuth 2.0 authorization server **MUST** support all
features described in this specification. A general‑purpose authorization
server **MAY** support additional features for use with non‑iGov clients
and protected resources.

An iGov‑compliant OAuth 2.0 client **MUST** use all functions described
in this specification. A general‑purpose client library **MAY** support
additional features for use with non‑iGov authorization servers and
protected resources.

An iGov‑compliant OAuth 2.0 protected resource **MUST** use all
functions described in this specification. A general‑purpose protected
resource library **MAY** support additional features for use with
non‑iGov authorization servers and clients.

## Global Requirements

All network connections **MUST** be made using TLS 1.3 or above. Each
originator of a TLS connection **MUST** verify the destination’s
certificate. Additionally, the following four TLS 1.2 cipher suites **MAY**
be used:

* `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`  
* `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`  
* `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`  
* `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`

Implementers of this profile **SHOULD** monitor the progress of
specifications of post‑quantum cryptography for TLS implementations.
Implementers **MAY** adopt a cipher suite not included in
[BCP 195](#bcp195) when post‑quantum safety is required, provided the
suite is supported in the implementation environment.

An example of an emerging PQ cipher suite that is broadly supported at
the time of writing is **X25519MLKEM768**, specified by
[Post‑quantum Hybrid Key Exchange with ML‑KEM in IKEv2](https://datatracker.ietf.org/doc/draft-kampanakis-ml-kem-ikev2/).

For the `authorization_endpoint`, the authorization server **MAY** allow
additional cipher suites that are permitted by the latest version of
[BCP 195](#bcp195), if necessary to allow sufficient interoperability
with users’ web browsers or as required by local regulations.

**NOTE:** Permitted cipher suites are those listed in BCP 195 that do not
explicitly say “MUST NOT” use.

Endpoints for use by web browsers **MUST** use mechanisms to ensure that
connections cannot be downgraded using TLS‑Stripping attacks. Protected
resources **MAY** implement an HTTP Strict Transport Security (HSTS)
policy as defined in [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) to
mitigate these attacks. Protected resources **SHOULD** consider registering
web domain names with browsers that offer browser‑side (“preload”) HSTS
policy enforcement to further mitigate TLS downgrade attacks.

# Client Profiles {#clientprofiles}

## Client Types {#clienttypes}

OAuth defines two client types, based on their ability to authenticate
securely with the authorization server:

* **confidential clients:** Clients that have credentials with the
  authorization server.  
* **public clients:** Clients without credentials. Public‑client use cases
  are out of scope for this profile.

## Client Type Use Cases {#usecases}

This specification has been designed around the following client use
cases:

* **web application:** A web application is a client running on a web
  server. Resource owners access the client via an HTML user interface
  rendered in a user agent on the device used by the resource owner. The
  client credentials as well as any access tokens issued to the client
  are stored on the web server and are not exposed to or accessible by
  the resource owner. In this use case, web applications are **confidential
  clients** and in‑scope for this profile.

* **native application:** A native application is a client installed and
  executed on the device used by the resource owner. Protocol data and
  credentials are accessible to the resource owner; it is assumed that
  any client authentication credentials included in the application can
  be extracted. Dynamically issued access tokens and refresh tokens can
  receive an acceptable level of protection. On some platforms, these
  credentials are protected from other applications residing on the same
  device. In this use case, native applications are **public clients**
  and out of scope for this profile. Best current practices for native
  applications are detailed in
  [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252).

* **browser‑based application:** A browser‑based application is a client
  in which the client code is downloaded from a web server and executes
  within a user agent (e.g., web browser) on the device used by the
  resource owner. Protocol data and credentials are easily accessible
  (and often visible) to the resource owner. If such applications wish
  to use client credentials, it is recommended to utilize the
  *backend‑for‑frontend* pattern. Since these applications reside within
  the user agent, they can make seamless use of the user agent’s
  capabilities when requesting authorization. In this use case,
  browser‑based applications are **public clients** and out of scope for
  this profile. Best current practices are detailed in
  [OAuth 2.0 for Browser‑Based Applications](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps).

This profile establishes requirements that can only be met by
**confidential clients**. Government implementers with public‑client use
cases are encouraged to consult the best‑practice guidance identified
above.

## Client Registration

All clients **MUST** register with the authorization server. For client
software that may be installed on multiple client instances, each client
instance **MAY** receive a unique client identifier from the authorization
server.

Client registration **MAY** be completed by either out‑of‑band
configuration or using the
[Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591).

If a client uses
[OAuth 2.0 Mutual‑TLS Client Authentication and Certificate‑Bound Access
Tokens (mTLS)](https://www.rfc-editor.org/rfc/rfc8705) for client
authentication or to sender‑constrain tokens, the client **MUST** include
the `tls_client_certificate_bound_access_tokens` parameter in its
registration metadata.

If a client uses
[OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
to sender‑constrain tokens, the client **MUST** include the
`dpop_bound_access_tokens` parameter in its registration metadata.

Clients using mTLS for client authentication or to sender‑constrain tokens
**MUST** register their TLS certificate’s subject DN with the authorization
server. Clients using the self‑signed certificate option are not guaranteed
uniqueness of their certificate fingerprint.

### Redirect URI {#redirecturi}

* Clients using the authorization code grant type **MUST** register their
  full redirect URIs.  
* Clients **MUST** protect the values passed back to their redirect URI
  by ensuring that the redirect URI is one of the following:  

  * Hosted on a website with Transport Layer Security (TLS) protection
    (an HTTPS URI).  
  * Hosted on a client‑specific non‑remote‑protocol URI scheme
    (e.g., `myapp://`).  

* Clients **MUST** use a unique redirect URI for each logical
  authorization server.  
* Clients **MUST NOT** forward values passed back to their redirect URIs
  to other arbitrary or user‑provided URIs (a practice known as an
  “open redirector”).

Refer to [BCP 240, § 2.4.1](#bcp240) for additional guidance on
implementation of edge cases.

## Sender‑Constrained Tokens

While a bearer token can be used by anyone in possession of the token,
a sender‑constrained token is bound to a particular symmetric or
asymmetric key issued to, or already possessed by, the client. The
association of the key to the token is also communicated to the protected
resource. When the client presents the token to the protected resource,
it is also required to demonstrate possession of the corresponding key.

As described in [BCP 240](#bcp240), sender‑constrained tokens could
prevent a number of attacks on OAuth that entail the misuse of stolen
and leaked access tokens by unauthorized parties. The attacker would
need to obtain the legitimate client’s cryptographic key **and** the
access token to gain access to protected resources.

All clients **MUST** use proof‑of‑possession to sender‑constrain access
tokens using either **OAuth 2.0 Mutual‑TLS Client Authentication and
Certificate‑Bound Access Tokens** ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705))
or **OAuth 2.0 Demonstrating Proof of Possession (DPoP)**
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)).

## Authentication Context and Step‑Up Authentication Challenge Protocol Support

Clients **SHOULD** support the mechanism specified in
[OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470)
to communicate authentication context and implement interoperable step‑up
authentication.

This profile acknowledges that government use cases will likely operate
within an ecosystem of authentication methods of highly variable security
value for the foreseeable future. It therefore imposes requirements to
enable protected resources with basic capabilities to communicate
requirements for authentication strength and recency to supporting
authorization clients and servers, as well as the capability to enforce
access policies using access tokens augmented with the strength and
recency of the authentication event that led to the issuance of each
specific access token.

The profile leverages the supporting server metadata, request, token
claims and values, and error messages from the **Step Up Authentication
Challenge Protocol** and **OpenID Connect Core 1.0**.

OAuth 2.0 **MUST NOT** be used as an authentication protocol. Use of the
**International Government Assurance Profile (iGov) for OpenID Connect 1.0**
is **RECOMMENDED** to provide the identity authentication layer for iGov
OAuth 2.0 delegated‑access use cases.

## Connection to the Authorization Server

### Requests to the Authorization Endpoint {#requests-to-authorization-endpoint}

All clients **MUST** use the PKCE `S256` code‑challenge method as
described in [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) and
include the `code_challenge` parameter and `code_challenge_method=S256`
in the authorization request.

Clients making a request to the authorization endpoint **MUST** use an
unpredictable value for the `state` parameter with at least 128 bits of
entropy. Clients **MUST** validate the value of the `state` parameter
upon return to the redirect URI and **MUST** ensure that the state value
is securely tied to the user’s current session (e.g., by relating the
state value to a session identifier issued by the client software to the
browser).

Clients that have multiple client types **MUST** have a separate client
ID for each client type.

Clients **MUST** include their full redirect URI in the authorization
request.

The client **MAY** specify a strength of authentication and maximum age
to the authorization server that should be met when issuing an access
token for the requesting client by including parameters in the
authorization request:

* `acr_values` – a space‑separated string listing the authentication‑
  context class reference values in order of preference. The protected
  resource requires one of these values for the authentication event
  associated with the access token. (See § 1.2 of **OpenID Connect Core 1.0**.)  
* `max_age` – a non‑negative integer value that indicates the allowable
  elapsed time in seconds since the last active authentication event
  associated with the access token.

If the authorization request is a follow‑up to a prior request that did
not meet the resource server’s initial or subsequent authentication
strength or recency requirements, the client should include the
`acr_values` and/or `max_age` values sent by the resource server with the
`insufficient_user_authentication` error code that specify expected
strength and recency requirements to be provided to the authentication
provider (e.g., the OpenID Provider) in a new authentication request.

The following is a sample **HTTP 302** response that a client would send
to the end‑user’s browser to redirect the user to the authorization
server’s authorization endpoint.

**Figure 1 – Sample redirect response**

CODEMARKINGSTART
HTTP/1.2 302 Found
Cache-Control: no-cache
Connection: close
Content-Type: text/plain; charset=UTF-8
Date: Wed, 07 Jan 2015 20:24:15 GMT
Location: \
  https://idp-p.example.com/authorize?client_id=55f9f559-2496-49d4-b6c3-351a586b7484&response_type=code&scope=openid+email&redirect_uri=\
https%3A%2F%2Fclient.example.org%2Fcb&acr_values=myACR&max_age=1800\
Status: 302 Found
CODEMARKINGSTOP

This causes the browser to send the following (non‑normative) request to
the authorization endpoint (inline wraps for display purposes only).

**Figure 2 – Sample request to the authorization endpoint**

CODEMARKINGSTART
GET /authorize?
   client_id=55f9f559-2496-49d4-b6c3-351a586b7484
  &nonce=cd567ed4d958042f721a7cdca557c30d
  &response_type=code
  &scope=openid+email
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb HTTP/1.1
Host: idp-p.example.com
CODEMARKINGSTOP

### Requests to the Token Endpoint {#requests-to-token-endpoint}

Clients **MUST** authenticate to the authorization server’s token endpoint
using either the `private_key_jwt` method as defined in **OpenID Connect Core**
or the mutually‑authenticated transport‑layer security (mTLS) request
method defined in **RFC 8705**.

If using the `private_key_jwt` method, the request **MUST** be a JWT
assertion as defined by [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523). The
JWT assertion **MUST** be signed by the client using the client’s private
key.

If using **RFC 8705** (mTLS), the request **MUST** be made over a
mutually authenticated TLS channel.

### Client Keys

Confidential clients **MUST** have a public/private key pair for use in
authentication to the token endpoint. These clients **MUST** either send
the public key directly in the `jwks` field or register a `jwks_uri`
that is reachable by the authorization server. It is **RECOMMENDED**
that clients use a `jwks_uri` if possible, as this allows for key rotation
more easily. This applies to both dynamic and out‑of‑band client
registration.

The `jwks` field or the content available from the `jwks_uri` of a
client **MUST** contain a public key in **JSON Web Key Set (JWK Set)**
format ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)). The
authorization server **MUST** validate the content of the client’s
registered `jwks_uri` document and verify that it contains a JWK Set.
The following example is a 2048‑bit RSA key.

**Figure 3 – Example public JWK Set**

CODEMARKINGSTART
{
   "keys": [
     {
       "alg": "RS256",
       "e": "AQAB",
       "n": "kAMYD62n_f2rUcR4awJX4uccDt0zcXRssq_mDch5-ifcShx9aTtTVza23PTn3KaKrsBXwWcfioXR6zQn5eYdZQVGNBfOR4rxF5i7t3hfb4WkS50EK1gBYk2lO9NSrQ-xG9QsUsAnN6RHksXqsdOqv-nxjLexDfIJlgbcCN9h6TB-C66ZXv7PVhl19gIYVifSU7liHkLe0l0fw7jUI6rHLHf4d96_neR1HrNIK_xssr99Xpv1EM_ubxpktX0T925-qej9fMEpzzQ5HLmcNt1H2_VQ_Ww1JOLn9vRn-H48FDj7TxlIT74XdTZgTv31wGRPAOfyxEw_ZUmxhz5Z-gTlQ",
       "kty": "RSA",
       "kid": "oauth-client"
     }
   ]
}
CODEMARKINGSTOP

For reference, the corresponding public/private key pair (in JWK format) is:

**Figure 4 – Example RSA private JWK**

CODEMARKINGSTART
{
  "alg": "RS256",
  "d": "PjIX4i2NsBQuOVIw74ZDjqthYsoFvaoah9GP-cPrai5s5VUIlLoadEAdGbBrss_6dR58x_pRlPHWh04vLQsFBuwQNc9SN3O6TAaai9Jg5TlCi6V0d4O6lUoTYpMR0cxFIU-xFMwII--_OZRgmAxiYiAXQj7TKMKvgSvVO7-9-YdhMwHoD-UrJkfnZckMKSs0BoAbjReTski3IV9f1wVJ53_pmr9NBpiZeHYmmG_1QDSbBuY35Zummut4QShF-fey2gSALdp9h9hRk1p1fsTZtH2lwpvmOcjwDkSDv-zO-4Pt8NuOyqNVPFahROBPlsMVxc_zjPck8ltblalBHPo6AQ",
  "e": "AQAB",
  "n": "kAMYD62n_f2rUcR4awJX4uccDt0zcXRssq_mDch5-ifcShx9aTtTVza23PTn3KaKrsBXwWcfioXR6zQn5eYdZQVGNBfOR4rxF5i7t3hfb4WkS50EK1gBYk2lO9NSrQ-xG9QsUsAnN6RHksXqsdOqv-nxjLexDfIJlgbcCN9h6TB-C66ZXv7PVhl19gIYVifSU7liHkLe0l0fw7jUI6rHLHf4d96_neR1HrNIK_xssr99Xpv1EM_ubxpktX0T925-qej9fMEpzzQ5HLmcNt1H2_VQ_Ww1JOLn9vRn-H48FDj7TxlIT74XdTZgTv31wGRPAOfyxEw_ZUmxhz5Z-gTlQ",
  "kty": "RSA",
  "kid": "oauth-client"
}
CODEMARKINGSTOP

Note that the first example contains **only** the public key; the second
example contains both the public and private keys.

# Authorization Server Profile {#serverprofile}

All servers **MUST** conform to applicable recommendations found in the
Security Considerations sections of **RFC 6749** and the
**OAuth Threat Model Document** ([RFC 6819](https://www.rfc-editor.org/rfc/rfc6819)).

The authorization server **MUST** protect all communications to and from its
OAuth endpoints using TLS as described in Section 1.4.

## Connections with Clients

### Grant Types

Authorization servers **MUST** support the `authorization_code` grant
type and **MAY** support the `client_credentials` grant type. The
implicit grant type **MUST NOT** be used.

Authorization servers **MUST** limit each registered client (identified
by a client ID) to a single client type only, since a single piece of
software will be functioning at runtime as only one client type.

### Client Authentication

Authorization servers **MUST** enforce client authentication for
confidential clients. Public clients cannot authenticate to the
authorization server. Authorization servers **MUST** support the RS256
signature method (RSA with SHA‑256) and **MAY** use other asymmetric
signature methods listed in **RFC 7518**.

The authorization server **MUST** validate all redirect URIs for
authorization‑code grant types and **MUST** confirm thumbprints of client
keys.

Authorization servers **MUST** only grant access to higher‑level‑scope
resources to clients that have permission to request those scope levels.
Authorization servers **MUST** reject client authorization requests
containing scopes that are outside their permission.

Authorization servers **MAY** set the expiry time (`exp`) of access tokens
associated with higher‑level resources to be shorter than access tokens
for less‑sensitive resources.

Authorization servers **MAY** allow a `refresh_token` issued at a higher
level to be used to obtain an access token for a lower‑level resource
scope with an extended expiry time. The client **MUST** request both the
higher‑level scope and lower‑level scope in the original authorization
request. This allows clients to continue accessing lower‑level resources
after the higher‑level resource access has expired – without requiring an
additional user authentication/authorization.

### Dynamic Registration {#dynamic-registration}

Dynamic Registration allows authorized clients to on‑board
programmatically without administrative intervention. This is particularly
important in ecosystems with many potential clients, including mobile
apps acting as independent clients.

Authorization servers **MUST** support dynamic client registration, and
clients **MAY** register using the
[Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591) for
authorization‑code grant types. Clients **MUST NOT** dynamically register
for the client‑credentials grant type. Authorization servers **MAY** limit
the scopes available to dynamically registered clients.

Authorization servers **MAY** protect their Dynamic Registration
endpoints by requiring clients to present credentials that the server
recognises as authorized participants. Authorization servers **MAY**
accept signed software statements as described in **RFC 7591** issued to
client software developers from a trusted registration entity. The
software statement **MUST** include the following client metadata
parameters:

* `redirect_uris` – array of redirect URIs used by the client (subject to the
  requirements listed in **Redirect URI**).  
* `grant_types` – grant type used by the client; must be `"authorization_code"`
  or `"client_credentials"`.  
* `client_name` – human‑readable name of the client.  
* `client_uri` – URL of a web page containing further information about the
  client.  
* `tls_client_certificate_bound_access_tokens` – **REQUIRED**. Boolean indicating
  server support for mutual‑TLS client‑certificate‑bound access tokens.  
* `acr_values_supported` – **OPTIONAL**. Indicates the client will include the
  `acr_values` and `max_age` parameters in authorization requests, and send
  `insufficient_user_authentication` error messages in conformance with
  **RFC 9470**.  
* `dpop_signing_alg_values_supported` – **REQUIRED**. JSON array containing the
  JWS `alg` values supported by the client for DPoP proof JWTs.  
* `jwks_uri` *or* `jwks` – client’s public key in a JWK Set
  ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)); if `jwks_uri` is used it
  **MUST** be reachable by the authorization server.  

When using the `tls_client_auth` authentication method, the client **MUST**
indicate exactly one of the following metadata parameters to specify the
expected certificate subject:

* `tls_client_auth_subject_dn` – expected subject DN of the client certificate.  
* `tls_client_auth_san_dns` – expected `dNSName` SAN entry in the client
  certificate.  
* `tls_client_auth_san_uri` – expected `uniformResourceIdentifier` SAN entry
  in the client certificate.  

It is **NOT RECOMMENDED** that authorization servers use IP addresses or
email addresses to identify authenticating clients, nor that they use
`tls_client_auth_san_ip` or `tls_client_auth_san_email`.

### Client Approval

When presenting an interactive approval page to the end‑user, the
authorization server **MUST** indicate to the user:

* Whether the client was dynamically registered, or else statically
  registered by a trusted administrator.  
* Whether the client is associated with a software statement, and if so,
  provide information about the trusted issuer of the software statement.  
* What kind of access the client is requesting, including scope, protected
  resources (if applicable beyond scopes), and access duration.

### Sender‑Constrained Tokens

The authorization server **MUST** support and verify sender‑constrained
tokens.

The Authorization Server **MUST NOT** issue the client an access token if
the client included the `tls_client_certificate_bound_access_tokens`
parameter in its registration metadata and makes a request to the token
endpoint over a connection not secured by TLS.

### Discovery

The authorization server **MUST** provide an **OpenID Connect** service
discovery endpoint listing the components relevant to the OAuth 2.0
protocol. The discovery document **MUST** contain (among others) the
following fields:

* `issuer` – **REQUIRED**. Fully qualified issuer URL of the server.  
* `authorization_endpoint` – **REQUIRED**. Fully qualified URL of the server’s
  authorization endpoint.  
* `token_endpoint` – **REQUIRED**. Fully qualified URL of the server’s token
  endpoint.  
* `token_endpoint_auth_method` – **REQUIRED**. String of values corresponding
  to permitted methods for client authentication (e.g., `"private_key_jwt"`,
  `"tls_client_auth"`, `"self_signed_tls_auth"`).  
* `introspection_endpoint` – **OPTIONAL**. URL of the server’s introspection
  endpoint.  
* `revocation_endpoint` – **OPTIONAL**. URL of the server’s revocation
  endpoint.  
* `mtls_endpoint_aliases` – **OPTIONAL**. JSON object containing alternative
  authorization server endpoints for mutual TLS.  
* `jwks_uri` – **REQUIRED**. URL of the server’s JWK Set.  

If a client uses **OAuth 2.0 Mutual‑TLS Client Authentication** for
authentication, exactly one authentication method metadata value **MUST**
be included:

* `tls_client_auth` – mutual TLS using a PKI‑issued certificate.  
* `self_signed_tls_client_auth` – mutual TLS using a self‑signed certificate.  

If the authorization server is also an OpenID Connect Provider, it **MUST**
provide a discovery endpoint meeting the requirements listed in Section 3.6
of **OpenID Connect Core 1.0**.

**Figure 5 – Example discovery document**

CODEMARKINGSTART
{
  "request_parameter_supported": true,
  "registration_endpoint": "https://idp-p.example.com/register",
  "userinfo_signing_alg_values_supported": [
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512"
  ],
  "token_endpoint": "https://idp-p.example.com/token",
  "request_uri_parameter_supported": false,
  "request_object_encryption_enc_values_supported": [
    "A192CBC-HS384", "A192GCM", "A256CBC+HS512",
    "A128CBC+HS256", "A256CBC-HS512",
    "A128CBC+HS256", "A128GCM", "A256GCM"
  ],
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt"
  ],
  "jwks_uri": "https://idp-p.example.com/jwk",
  "authorization_endpoint": "https://idp-p.example.com/authorize",
  "require_request_uri_registration": false,
  "introspection_endpoint": "https://idp-p.example.com/introspect",
  "revocation_endpoint": "https://idp-p.example.com/revoke",
  "service_documentation": "https://idp-p.example.com/about",
  "response_types_supported": [
    "code", "token"
  ],
  "token_endpoint_auth_signing_alg_values_supported": [
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512"
  ],
  "request_object_signing_alg_values_supported": [
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512"
  ],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials"
  ],
  "scopes_supported": [
    "profile", "openid", "email", "address", "phone", "offline_access"
  ],
  "op_tos_uri": "https://idp-p.example.com/about",
  "issuer": "https://idp-p.example.com/",
  "op_policy_uri": "https://idp-p.example.com/about",
  "tls_client_certificate_bound_access_tokens": "true",
  "dpop_signing_alg_values_supported": ["PS256", "ES256"]
}
CODEMARKINGSTOP

The authorization server **MUST** provide cache information through HTTP
headers and make the cache valid for at least one week. This allows
clients and protected resources to cache the discovery information.

The authorization server **MUST** support the RS256 signature method and
**MAY** use other asymmetric signature methods listed in the **JSON
Web Algorithms (JWA)** registry
([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)).  

The authorization server **MUST** provide its public key in JWK Set format.
The key **MUST** contain the following fields:

* `kid` – key identifier.  
* `kty` – key type.  
* `alg` – default algorithm used for this key.

**Figure 6 – Example public RSA JWK**

CODEMARKINGSTART
{
  "keys": [
    {
      "alg": "RS256",
      "e": "AQAB",
      "n": "o80vbR0ZfMhjZWfqwPUGNkcIeUcweFyzB2S2T-hje83IOVct8gVg9FxvHPK1ReEW3-p7-A8GNcLAuFP_8jPhiL6LyJC3F10aV9KPQFF-w6Eq6VtpEgYSfzvFegNiPt pMWd7C43EDwjQ-GrXMVCLrBYxZC-P1ShyxVBOzeR_5MTC0JGiDTecr_2YT6o_3aE2SIJu4iNPgGh9MnyxdBo0Uf0TmrqEIabquXA1-V8iUihwfI8qjf3EujkYi7gXXelIo4_gipQYNjr4DBNlE0__RI0kDU-27mb6esswnP2WgHZQPsk779fTcNDBIcYgyLujlcUATEqfCaPDNp00J6AbY6w"
      ,
      "kty": "RSA",
      "kid": "rsa1"
    }
  ]
}
CODEMARKINGSTOP

# Protected Resource Profile

## Connections with Clients

Protected resources **MUST** interpret access tokens using either JWT,
token introspection, or a combination of the two.

Protected resources **MUST** check the `aud` claim in tokens to ensure that
it includes the protected resource’s identifier.

Protected resources **MUST** accept tokens passed in the `Authorization`
header as described in [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750). A
protected resource **MUST NOT** accept tokens passed in the form
parameter or query‑parameter methods.

Protected resources **MUST** define and document which scopes are
required for access to the resource and any authentication strength or
recency requirements for each scope.

If a client uses **mTLS** to sender‑constrain tokens, the protected
resource **MUST** verify that the certificate matches the certificate
associated with the access token. If they do not match, the resource
access attempt **MUST** be denied.

Protected resources **MAY** use authentication context or step‑up
authentication to implement access controls.

If the authentication event associated with the access token does not
satisfy the requirements of the resource server for the given request,
the protected resource **MUST** return a `401 Unauthorized` status code
along with a `WWW-Authenticate` header as defined in
[OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470). The header **MUST** include the
`insufficient_user_authentication` error code to indicate that the
presented access token is inadequate. This header **MUST** also include
the `acr_values` and/or `max_age` auth‑params to communicate the required
authentication context class reference values and the allowable elapsed
time since the last active authentication event.

The mechanisms by which the protected resource determines whether the
authentication requirements are met are outside the scope of this
profile. Protected resources **MAY** include both `acr_values` and
`max_age` if both are relevant. They **MAY** include the `scope`
parameter if additional scopes are required to access the resource, as
per Section 3.1 of
[OAuth 2.0 Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750).

## Protecting Resources

### Trust Levels and Scopes

Protected Resources grant access to clients if they present a valid
sender‑constrained `access_token` with the appropriate scopes. Resource
servers trust the authorization server to authenticate the end user and
client appropriately for the importance, risk, and value level of the
protected resource scope.

Protected resources **MAY** use
[OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470) to implement access controls.

If a protected resource requires a higher end‑user authentication trust
level to access certain resources, the protected resource **MUST** associate
those resources with a unique scope and **MUST** associate acceptable `acr`
values for each scope as described in the Step‑Up protocol. Protected
resources may also specify a `max_age` for each scope.

### Trust Levels Example

For example, a resource server associates scopes with data classified as
“public” and “sensitive”. Access to data with scope “sensitive” requires
the user to perform a two‑factor authentication and limits those access
grants to only 15 minutes. The resource server associates scope
“sensitive” with `acr="MFA"`.

* A client that wishes to obtain access to both “public” and “sensitive”
  data makes an authorization request with `scope=public+sensitive`,
  `acr_values="MFA"`, and `max_age=900`. The authorization server
  authenticates the end‑user as required to meet the trust level (two‑factor
  authentication or equivalent) and issues an `access_token` for the two
  scopes with a 15‑minute expiry and a `refresh_token` for the “public”
  scope with a 24‑hour expiry.  

* The client can access both “public” and “sensitive” data for 15 minutes
  with the access token. When the token expires, the client must obtain a
  new access token.  

* The client makes a refresh‑token request (as described in
  [RFC 6749 § 6](https://www.rfc-editor.org/rfc/rfc6749)) with the
  refresh token and the reduced scope of just “public”. The token endpoint
  validates the refresh token and issues a new access token for the “public”
  scope with a 24‑hour expiry. A request for a new access token with the
  “sensitive” scope would be rejected, requiring the client to re‑authenticate
  the end‑user.

In this manner, protected resources and authorization servers work
together to meet risk‑tolerance levels for sensitive resources and end‑user
authentication.

## Connections with Authorization Servers

Protected resources **MUST** provide a `jwks_uri` endpoint to distribute
public keys to support signing, encryption, and authentication to the
authorization server’s revocation and introspection endpoints. **OAuth 2.0
Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728))
defines a metadata format that a client or authorization server can use to
obtain the information needed to interact with a protected resource.

Protected resources calling the introspection endpoint **MUST** use
credentials distinct from any other OAuth client registered at the
authorization server.

Protected resources **MAY** cache the response from the introspection
endpoint for a period of time no greater than half the lifetime of the
token. A protected resource **MUST NOT** accept a token that is not
active according to the introspection response.

Protected resources **MUST** ensure that the rights associated with the
token are sufficient to grant access to the resource (e.g., by checking
scopes and `acr` values returned by introspection).

Protected resources **MUST** limit which authorization servers they will
accept valid tokens from. A resource server **MAY** accomplish this using
a whitelist of trusted servers, a dynamic policy engine, or other means.

# Security Considerations

## DNSSEC Considerations

For comprehensive protection against network attackers, all endpoints
should additionally use
[DNSSEC](https://www.rfc-editor.org/rfc/rfc9364) to protect against DNS
spoofing attacks that can lead to the issuance of rogue
domain‑validated TLS certificates.

## Best Practices

Authorization server, client, and protected resource implementations
**SHOULD** consider including requirements from
[BCP 240](#bcp240), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) and
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) that are not
explicitly mentioned in this profile.

## Other Considerations

* Authorization Servers **SHOULD** take device posture into account when
  possible. Examples of device posture include:  

  * the user’s lock‑screen setting,  
  * the client’s level of privilege over the device OS (e.g., root
    access), and  
  * the availability of a device attestation to validate the client.  

* Specific policies or capabilities are outside the scope of this
  specification.  

* This profile does **not** protect against the attacks described in
  [_The Stronger Attacker Model_](https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/)
  (PKCE vs. nonce). Although request‑object signatures would provide
  mitigation, this profile does not require request‑object signatures
  because of limited implementation availability.

# Privacy Considerations

This profile addresses the privacy threats identified in
[Privacy Considerations for Internet Protocols (RFC 6973)](https://www.rfc-editor.org/rfc/rfc6973) with
normative language throughout the document. In particular, this profile
requires the use of TLS for all network connections, PKCE, and
sender‑constrained tokens to mitigate the threats in RFC 6973.

In OpenID Connect implementations, clients and servers **SHOULD**
implement the privacy threat mitigations in Section 17 of
[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

# Normative References {#normative-references}

* [RFC 2119 – Key words for use in RFCs to Indicate Requirement Levels](https://www.rfc-editor.org/rfc/rfc2119)  
* [RFC 6749 – The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)  
* [RFC 6750 – OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)  
* [RFC 6797 – HTTP Strict Transport Security (HSTS)](https://www.rfc-editor.org/rfc/rfc6797)  
* [RFC 6819 – OAuth 2.0 Threat Model and Security Considerations](https://www.rfc-editor.org/rfc/rfc6819)  
* [RFC 6973 – Privacy Considerations for Internet Protocols](https://www.rfc-editor.org/rfc/rfc6973)  
* [RFC 7009 – OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)  
* [RFC 7515 – JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515)  
* [RFC 7516 – JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516)  
* [RFC 7517 – JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)  
* [RFC 7519 – JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)  
* [RFC 7523 – JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7523)  
* [RFC 7591 – OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)  
* [RFC 7636 – Proof Key for Code Exchange by OAuth Public Clients (PKCE)](https://www.rfc-editor.org/rfc/rfc7636)  
* [RFC 7662 – OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)  
* [RFC 7518 – JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518)  
* [RFC 7638 – JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)  
* [RFC 7800 – Proof‑of‑Possession Key Semantics for JWTs](https://www.rfc-editor.org/rfc/rfc7800)  
* [RFC 8414 – OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)  
* [RFC 8252 – OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)  
* [RFC 8705 – OAuth 2.0 Mutual‑TLS Client Authentication and Certificate‑Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)  
* [RFC 8725 – JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)  
* [RFC 9068 – JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)  
* [RFC 9364 – DNSSEC Operational Practices](https://www.rfc-editor.org/rfc/rfc9364)  
* [RFC 9449 – OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)  
* [RFC 9470 – OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470)  
* [RFC 9728 – OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)  

### Internet-Drafts and Other References

* **BCP 195** – Recommendations for Secure Use of TLS and DTLS  
  <https://www.rfc-editor.org/info/bcp195>  

* **BCP 240** – Best Current Practice for OAuth 2.0 Security  
  <https://www.rfc-editor.org/info/bcp240>  

* **OpenID Connect Core 1.0** – <https://openid.net/specs/openid-connect-core-1_0.html>  

* **OpenID Connect Discovery 1.0** – <https://openid.net/specs/openid-connect-discovery-1_0.html>  

* **International Government Assurance Profile (iGov) for OpenID Connect 1.0** –  
  <https://openid.net/specs/openid-igov-openid-connect-1_0.html>  

* **JSON Web Signature and Encryption Algorithms Registry** – <https://www.rfc-editor.org/rfc/rfc7518#section-4>  

* **Post‑quantum Hybrid Key Exchange with ML‑KEM in IKEv2** –  
  <https://datatracker.ietf.org/doc/draft-kampanakis-ml-kem-ikev2/>  

* **PKCE vs. Nonce: Equivalent or Not?** –  
  <https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/>

# Acknowledgements {#acknowledgements}

The OpenID Community would like to thank the following people for
their contributions to this specification: Mark Russel, Mary
Pulvermacher, David Hill, Dale Moberg, Adrian Gropper, Eve Maler,
Danny van Leeuwen, John Moehrke, Aaron Seib, John Bradley, Debbie
Bucci, Josh Mandel, Sarah Cecchetti, Giuseppe De Marco, Joseph Heenan,
Jim Fenton, Ryan Galluzzo, Bjorn Hjelm, Aaron Parecki, Michael B. Jones,
and Stas Mironov.

Special thank you to the original iGov Profile editors: Paul Grassi,
Justin Richer, and Michael Varley.

The original version of this specification was part of the Secure
RESTful Interfaces project from The MITRE Corporation, available
online at http://secure-restful-interface-profile.github.io/pages/

# Notices {#notices}

Copyright (c) 2025 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer,
implementer, or other interested party a non‑exclusive, royalty free,
worldwide copyright license to reproduce, prepare derivative works
from, distribute, perform and display, this Implementers Draft, Final
Specification, or Final Specification Incorporating Errata Corrections
solely for the purposes of (i) developing specifications, and (ii)
implementing Implementers Drafts, Final Specifications, and Final
Specification Incorporating Errata Corrections based on such documents,
provided that attribution be made to the OIDF as the source of the
material, but that such attribution does not indicate an endorsement by
the OIDF.

The technology described in this specification was made available from
contributions from various sources, including members of the OpenID
Foundation and others. Although the OpenID Foundation has taken steps
to help ensure that the technology is available for distribution, it
takes no position regarding the validity or scope of any intellectual
property or other rights that might be claimed to pertain to the
implementation or use of the technology described in this specification
or the extent to which any license under such rights might or might not
be available; neither does it represent that it has made any independent
effort to identify any such rights. The OpenID Foundation and the
contributors to this specification make no (and hereby expressly
disclaim any) warranties (express, implied, or otherwise), including
implied warranties of merchantability, non‑infringement, fitness for a
particular purpose, or title, related to this specification, and the
entire risk as to implementing this specification is assumed by the
implementer. The OpenID Intellectual Property Rights policy (found at
openid.net) requires contributors to offer a patent promise not to assert
certain patent claims against other contributors and against
implementers. OpenID invites any interested party to bring to its
attention any copyrights, patents, patent applications, or other
proprietary rights that may cover technology that may be required to
practice this specification.

# Document History {#history}

[[ To be removed from the final specification ]]

-08
* Added description of resource server requirements for authentication
  context and step‑up.  
* Restructured the document so the text flows better.  
* Added a method to securely discover or declare JWKS‑URI for PR/RS.  
* Removed public clients to align with FAPI.  
* Moved requirements to correct section.  
* Realigned requirements among AS, client, and PR/RS.  
* Changed date, version, and document history.

-06‑07
* Addressed comments from WGLC request Jan 31 2025.

-05
* Updated BCP mitigations, aligned with FAPI.  
* Harmonized cryptography, sender‑constrained tokens with FAPI.  
* Added requirement and optionality for authentication context and support
  for Step‑up (RFC 9470).  
* Added Privacy Considerations (RFC 6973).  
* Added optionality to support enterprise tailoring, especially RFC 8705
  mTLS with PKI.

-04
* Enable building with https://author-tools.ietf.org/.  
* Applied OpenID specification conventions.

-03
* First Implementer’s Draft.

-2017‑06‑01
* Aligned with prior version of iGov.  
* Added guidance text around using scopes and refresh_tokens to protect
  sensitive resources.  
* Removed ACR reference.

-2018‑05‑07
* Imported content from HEART OAuth profile.
