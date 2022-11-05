# Certhunt

Match Sigma rules against TLS certificates, in real-time as they are issued, in order to quickly spot malicious domains.

Certhunt uses [Certstream](https://certstream.calidog.io) to retrieve certificates from [Certificate Transparency logs](https://certificate.transparency.dev/) in close-to real-time. The certificate JSON is enriched and evaluated against Sigma rules with the help of [go-sigma-rule-engine](https://github.com/markuskont/go-sigma-rule-engine), a Sigma rule evaluator. A certificate that matches a Sigma rule will lead to a MISP attribute in JSON format being appended to `attributes.jsonl`, for consumption into MISP.

## Certificate format

Sigma rules are evaluated against the JSON certificate format used by Certstream. See example below:

```json
{
  "cert_index": 284386337,
  "cert_link": "https://ct.googleapis.com/logs/xenon2023/ct/v1/get-entries?start=284386337&end=284386337",
  "leaf_cert": {
    "all_domains": [
      "api.github.leroymerlln.com",
      "github.github.leroymerlln.com",
      "github.leroymerlln.com"
    ],
    "extensions": {
      "authorityInfoAccess": "CA Issuers - URI:http://r3.i.lencr.org/\nOCSP - URI:http://r3.o.lencr.org\n",
      "authorityKeyIdentifier": "keyid:14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6\n",
      "basicConstraints": "CA:FALSE",
      "certificatePolicies": "Policy: 1.3.6.1.4.1.44947.1.1.1\n  CPS: http://cps.letsencrypt.org",
      "ctlSignedCertificateTimestamp": "BIHxAO8AdgB6MoxU2LcttiDqOOBSHumEFnAyE4VNO9IrwTpXo1LrUgAAAYQ0r9meAAAEAwBHMEUCIHqCZ0tKIq3wZg6qdJPgsqAyH91tBp-ieeutblDdsz1bAiEApj-YyRJxwTBmjXvwQquXEYm53YcG6s-jFRcHVc9sxwsAdQCt9776fP8QyIudPZwePhhqtGcpXc-xDCTKhYY069yCigAAAYQ0r9m4AAAEAwBGMEQCIB0TDPf7UMbvrwDm3ERTuNyWws7sjkmJjuafEdKOdlNFAiAc6LufRLlM24E7gL-l5F1gHPn1KpLiu53XkjRu6RDOgQ==",
      "extendedKeyUsage": "TLS Web server authentication, TLS Web client authentication",
      "keyUsage": "Digital Signature, Key Encipherment",
      "subjectAltName": "DNS:github.leroymerlln.com, DNS:github.github.leroymerlln.com, DNS:api.github.leroymerlln.com",
      "subjectKeyIdentifier": "89:97:70:51:80:F7:AD:06:C7:FF:3D:A8:7A:A9:12:B1:65:46:CE:2B"
    },
    "fingerprint": "B4:53:20:21:1A:47:80:8E:2D:C8:89:71:DC:B0:6E:3E:DB:D2:14:D7",
    "issuer": {
      "C": "US",
      "CN": "R3",
      "L": null,
      "O": "Let's Encrypt",
      "OU": null,
      "ST": null,
      "aggregated": "/C=US/CN=R3/O=Let's Encrypt",
      "emailAddress": null
    },
    "not_after": 1675103649,
    "not_before": 1667327650,
    "registered_domains": [
      "leroymerlln.com"
    ],
    "serial_number": "3DF149200267A66A3D18B019E6DF1203C75",
    "signature_algorithm": "sha256, rsa",
    "subject": {
      "C": null,
      "CN": "github.leroymerlln.com",
      "L": null,
      "O": null,
      "OU": null,
      "ST": null,
      "aggregated": "/CN=github.leroymerlln.com",
      "emailAddress": null
    }
  },
  "seen": 1667331321.648794,
  "source": {
    "name": "Google 'Xenon2023' log",
    "url": "https://ct.googleapis.com/logs/xenon2023/"
  },
  "update_type": "X509LogEntry"
}
```

**Enrichment fields:**

* `leaf_cert.registered_domains` is an enrichment field. It's calculated by mapping each domain in `leaf_cert.all_domains` to the "registered" domain with the help of the [Public Suffix List](https://publicsuffix.org/).

## Writing rules

Rules should follow the [Sigma 1.0 specification](https://github.com/SigmaHQ/sigma-specification/blob/3d7aa6365eb061b75285dd9efc6c08c20b8fecd6/Sigma_1_0_1.md).

### Special handling of lists

Due to Sigma [treating all values as strings](https://github.com/SigmaHQ/sigma-specification/blob/3d7aa6365eb061b75285dd9efc6c08c20b8fecd6/Sigma_1_0_1.md#general), I've made a few workarounds to support conditions against lists of strings (such as `leaf_cert.all_domains`).

* If you write a condition against a list, it is considered a match if ANY element matches the condition
* A specific element can be retrieved by appending `.<zero-based-index>` to the key, for example: `leaf_cert.all_domains.0`
* The length of a list can be retrieved by appending `.length` to the key, for example: `leaf_cert.all_domains.length`

### Example rule

This is what a rule may look like:

```yaml
title: Outlook Phishlet
description: Subdomains used by Evilginx2 phishlet
status: experimental
author: DenizenB
date: 2022-10-05
references:
  - https://github.com/kgretzky/evilginx2/blob/master/phishlets/outlook.yaml
tags:
  - Phishing
detection:
  selection:
    leaf_cert.issuer.O: "Let's Encrypt"
    leaf_cert.all_domains.length: 3
    leaf_cert.all_domains|startswith|all:
      - outlook.
      - login.
      - account.
  condition: selection
falsepositives:
  - Unknown
```

**Notes:**

* `tags` should contain valid MISP tags, as these will be added to the MISP event
