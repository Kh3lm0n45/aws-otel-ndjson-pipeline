# Certificate-authenticated log delivery with IAM Roles Anywhere

How an off-AWS collector (for example, an OpenTelemetry Collector running on a
third-party host) can write logs to S3 **without long-lived access keys**.

All identifiers are placeholders. Run it in your own sandbox account.

## Pattern

```
Collector host (outside AWS)
  holds: leaf cert + private key (CN=example-collector-01)
  |
  | aws_signing_helper credential-process  (signs request with the key)
  v
IAM Roles Anywhere
  trust anchor = your CA certificate (you register the CA, not the leaf)
  profile      = which role(s) may be assumed
  |
  | short-lived STS credentials (default 1h)
  v
IAM role: write-only to one S3 prefix  ->  S3 raw bucket
```

Why this over IAM user access keys: nothing long-lived sits on a host you do not
control; access is revocable centrally; every session appears in CloudTrail.

## 1. Lab CA and leaf certificate (ECDSA P-256)

A local CA is for **labs only**: the CA key sits on disk, with no revocation
service. For production use a managed CA (e.g. AWS Private CA or your PKI) and
publish a CRL.

```bash
# CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 365 -subj "/CN=example-lab-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.pem

# Leaf (client authentication)
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -subj "/CN=example-collector-01" -out leaf.csr
printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 90 -sha256 -extfile leaf.ext -out leaf.pem
```

## 2. Register the trust anchor, create the role and profile

```bash
jq -n --rawfile ca ca.pem \
  '{sourceType:"CERTIFICATE_BUNDLE",sourceData:{x509CertificateData:$ca}}' > source.json
aws rolesanywhere create-trust-anchor --name example-ca --enabled --source file://source.json

aws iam create-role --role-name example-collector-writer \
  --assume-role-policy-document file://../iam/vendor-writer-role-trust-policy.json
aws iam put-role-policy --role-name example-collector-writer --policy-name write-own-prefix \
  --policy-document file://../iam/vendor-writer-role-policy.json

aws rolesanywhere create-profile --name example-profile --enabled \
  --role-arns arn:aws:iam::123456789012:role/example-collector-writer
```

## 3. Obtain credentials on the collector host

```bash
aws_signing_helper credential-process \
  --certificate leaf.pem --private-key leaf.key \
  --trust-anchor-arn <trust-anchor-arn> --profile-arn <profile-arn> \
  --role-arn arn:aws:iam::123456789012:role/example-collector-writer
```

Wire the same command into `credential_process` in the AWS config profile the
exporter uses. If the output contains `AccessKeyId`, `SecretAccessKey` and
`SessionToken`, the chain works.

## 4. Security tests to run (and what each proved in the lab)

| Test | Expected | Why it matters |
|---|---|---|
| Write to own prefix | Allowed | Positive control |
| Write to another prefix | Denied | Role is scoped to one prefix |
| List bucket / read / delete | Denied | Write-only means a compromised host cannot read or tamper with history |
| Valid cert from the same CA, different CN | Refused at session creation | CN condition in the trust policy binds a role to one identity |
| Disable the Roles Anywhere profile | New sessions blocked; **already-issued sessions keep working until expiry** | Disabling is not instant revocation |
| Apply `iam/revoke-live-sessions.json` (deny on `aws:TokenIssueTime`) | Live sessions denied | This is how you actually cut off an issued session |
| Turn on bucket default SSE-KMS | Writes fail until the role has `kms:GenerateDataKey` | KMS permissions are a separate, easily-missed dependency |
| CloudTrail lookup | `CreateSession` and `GenerateDataKey` events, including refused attempts | Gives independent evidence of who authenticated and when |

## Known limitations to design around

- A trust policy that pins only on certificate CN trusts whatever CN the CA
  issues. If the CA copies the subject verbatim from a CSR, control of issuance
  *is* control of access. Consider a dedicated CA or trust anchor per supplier,
  additional conditions, and a review step on certificate issuance.
- Certificate expiry silently stops delivery. Automate rotation and track
  expiry in a shared, team-owned register, not an individual's calendar.
- Static keys remain a fallback if a supplier cannot support certificates, but
  then scope tightly and rotate.
