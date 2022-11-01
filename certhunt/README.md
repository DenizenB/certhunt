# Certhunt

Match Sigma rules against TLS certificates, in real-time as they are issued, in order to quickly spot malicious domains.

Certhunt uses [Certstream](https://certstream.calidog.io) to retrieve certificates from [Certificate Transparency logs](https://certificate.transparency.dev/) in close-to real-time. The certificate JSON is enriched and evaluated against Sigma rules with the help of [go-sigma-rule-engine](https://github.com/markuskont/go-sigma-rule-engine), a Sigma rule evaluator. A certificate that matches one or several Sigma rules will lead to a MISP attribute in JSON format being appended to `attributes.jsonl`, for consumption into MISP.

## Rules


