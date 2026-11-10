# scep

`scep` is a Golang implementation of the Simple Certificate Enrollment Protocol (SCEP).

This is OmniTrust Security LLC's fork of
[Smallstep SCEP](https://github.com/smallstep/scep). The package originated in
[micromdm/scep](https://github.com/micromdm/scep), from which Smallstep extracted
the core protocol implementation. The module path remains
`github.com/smallstep/scep`.

This fork adds certificate polling and pending responses, transaction-ID
customization, per-response digest selection, response encryption matching the
request, nonce fixes, and exported SCEP attribute OIDs.

## Installation

The fork retains upstream module paths and imports. Each consuming application
must replace both upstream SCEP and PKCS7 with the OTPKI forks in its own
`go.mod`. Replacements in library dependencies do not propagate to consumers.

Replace `SCEP_COMMIT_HASH` with a published migration commit (or tag) and
`PKCS7_COMMIT_HASH` with a compatible PKCS7 migration commit (currently
`45c33a79b5c329cd270847682543462666ed1fb3`):

```sh
go mod edit -replace=github.com/smallstep/scep=github.com/otpki/scep@SCEP_COMMIT_HASH
go mod edit -replace=github.com/smallstep/pkcs7=github.com/otpki/pkcs7@PKCS7_COMMIT_HASH
go mod tidy
```

Continue importing `github.com/smallstep/scep` and `github.com/smallstep/pkcs7`.
Libraries using fork-specific APIs also need the replacements for their own
builds and tests. Consumers of the earlier OTPKI module-path migration must
return imports to the Smallstep paths before adopting these forks.

## Usage

The package can be used for both client and server operations.

For detailed usage, see the [Go Reference](https://pkg.go.dev/github.com/smallstep/scep).

Example server:

```go
// read a request body containing SCEP message
body, err := io.ReadAll(r.Body)
if err != nil {
    // handle err
}

// parse the SCEP message
msg, err := scep.ParsePKIMessage(body)
if err != nil {
    // handle err
}

// do something with msg
fmt.Println(msg.MessageType)

// extract encrypted pkiEnvelope
err = msg.DecryptPKIEnvelope(CAcert, CAkey)
if err != nil {
    // handle err
}

// use the CSR from decrypted PKCS request and sign
// MyCSRSigner returns an *x509.Certificate here
crt, err := MyCSRSigner(msg.CSRReqMessage.CSR)
if err != nil {
    // handle err
}

// create a CertRep message from the original
certRep, err := msg.Success(CAcert, CAkey, crt)
if err != nil {
    // handle err
}

// send response back
// w is a http.ResponseWriter
w.Write(certRep.Raw)
```


## License

Original SCEP code remains licensed under the MIT terms in [LICENSE](LICENSE).
Original additions and modifications copyright (c) 2026 OmniTrust Security LLC
are licensed under the [Apache License, Version 2.0](LICENSE-APACHE).

Existing upstream and third-party attribution and terms remain applicable,
including the full Go BSD notice embedded in [x509util/x509util.go](x509util/x509util.go).
