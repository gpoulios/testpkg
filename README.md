# testpkg

## Github Artifact Attestations (l2)

It is implemented with `cosign`, which attaches a [Sigstore bundle](https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md) to the image. It uses keyless signatures of [in-toto statements](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md). Github OIDC identity is used to issue short-lived certificates via [Fulcio](https://github.com/sigstore/fulcio). For public repos the Sigstore Public Good Instance is used, whereas for private repos (Organization plan only) Github's sigstore instance is used.

- https://docs.github.com/en/enterprise-cloud@latest/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- https://github.com/actions/attest-build-provenance
- https://github.blog/news-insights/product-news/introducing-artifact-attestations-now-in-public-beta/
- https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md
- https://github.com/sigstore/architecture-docs/blob/main/client-spec.md

### Usage

```yaml
      - name: Build and push Docker images
        id: push
        uses: docker/build-push-action@v5
[...]
      - name: Generate artifact attestation
        uses: actions/attest-build-provenance@v2
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true
```

### Inspection

See also: https://search.sigstore.dev/?hash=sha256:05211794607b1d7f8d72c3cd75d6168f209680d8cbefe23d2d2cf1291b22140f

```bash
$ export IMAGE=ghcr.io/gpoulios/testpkg

$ oras discover $IMAGE:sha-5b07e3b
ghcr.io/gpoulios/testpkg@sha256:9c24ac7eca13411bee8f335f96442c0b5ef8de65ff1f85da6f16fcb0c046bd78
└── application/vnd.dev.sigstore.bundle.v0.3+json
    └── sha256:ac86426c102983ecd8036b7ae6d6ba9aabfdba1b1672cebcf481373863f0d08b
    
$ oras manifest fetch --pretty $IMAGE@sha256:ac86426c102983ecd8036b7ae6d6ba9aabfdba1b1672cebcf481373863f0d08b
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "digest": "sha256:42f04b717a13e740a8a5b80798a4bbf256bb2334aab7a110d3d4c8b10f9ed395",
      "size": 10204
    }
  ],
  "subject": {
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "digest": "sha256:9c24ac7eca13411bee8f335f96442c0b5ef8de65ff1f85da6f16fcb0c046bd78",
    "size": 1575
  },
  "annotations": {
    "org.opencontainers.image.created": "2025-04-07T14:08:20.999Z",
    "dev.sigstore.bundle.content": "dsse-envelope",
    "dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1"
  }
}
```

```bash
# fetch config (should be empty according to docs)
$ oras blob fetch --output - $IMAGE@sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
{}
```

```bash
# fetch sigstore bundle
$ export BUNDLE_BLOB=$IMAGE@sha256:42f04b717a13e740a8a5b80798a4bbf256bb2334aab7a110d3d4c8b10f9ed395

$ oras blob fetch --output - $BUNDLE_BLOB | jq .
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {
      "rawBytes": "MIIG5[...]23g=="
    },
    "tlogEntries": [
      {
        "logIndex": "193309908",
        "logId": {
          "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
        },
        "kindVersion": {
          "kind": "dsse",
          "version": "0.0.1"
        },
        "integratedTime": "1744034900",
        "inclusionPromise": {
          "signedEntryTimestamp": "MEYCIQD8z87SQxky9Y7Jf6tFoDy2ODnTOKN0UhiDIIXiL7IpgQIhAIYX3K3gvN/c5jVXNWwkAQCPyx/TV6ImOnkRPPCOYRn9"
        },
        "inclusionProof": {
          "logIndex": "71405646",
          "rootHash": "jwMQYpmhU5+mbAeaB0yVuQhQHFkaeWhCYU42jnHmFR4=",
          "treeSize": "71405647",
          "hashes": [
            "BhvGTITc6Typ7og9sHExoibiSQGp5vcGyyCxHaWRoLY=",
            "uDMdJS5sJaR5Jl8nRmQnPwSqv71mGmG/ChUmq1WQPYA=",
            "MV0m2tcTL27GzR5URej2vRXJu17zNFvNFVYcprUSfwg=",
            "7+cd/T7/MjQPioKlluPTwQfwBKsVeA5S9OJKFQRL1WU=",
            "TU1yMZdKk3kwkkEcdTP+TZDedez3c1V3Pb0ddxVp4fA=",
            "O/GbrV/EyjMT3G39TVcls6Kk/zSqFF91cwEazQ/1z3w=",
            "8p/j8sus1mXXJ6kDz8G2pymKt8PZJXwKgHJbowUqJ+w=",
            "WEm5OgPzJpYROv+4CcrieexCYyQKrLUH3hbxmcQQ+DM=",
            "7v8qPHNDLerpduaMx06eb/MwgoQwczTn/cYGKX/9wZ4="
          ],
          "checkpoint": {
            "envelope": "rekor.sigstore.dev - 1193050959916656506\n71405647\njwMQYpmhU5+mbAeaB0yVuQhQHFkaeWhCYU42jnHmFR4=\n\n— rekor.sigstore.dev wNI9ajBEAiBCCYVFyRZ69qtPv/89MC+XfjWrkIJMwyIQSna3Q0AkIQIgGkdu1OAq7DwQpwHkKjvyNFZnWBAewMerU2o78pt5ehE=\n"
          }
        },
        "canonicalizedBody": "eyJhcGlWZ[...]9fQ=="
      }
    ],
    "timestampVerificationData": {
      "rfc3161Timestamps": []
    }
  },
  "dsseEnvelope": {
    "payload": "eyJfdHlw[...]X19",
    "payloadType": "application/vnd.in-toto+json",
    "signatures": [
      {
        "sig": "MEYCIQDUuiLRXfB2KLhLG57TrLdBP9DkBkkS1ywzk1Pwfoq3OAIhALhm6WyBCLZ6Vrsgxct0Yjv2RLCau9neKZcPKIO1SHB7",
        "keyid": ""
      }
    ]
  }
}
```

`dsseEnvelope.payload` contains the provenance data signed at `dsseEnvelope.sig`:

```json
$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -r .dsseEnvelope.payload | base64 -d | jq .
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "ghcr.io/gpoulios/testpkg",
      "digest": {
        "sha256": "9c24ac7eca13411bee8f335f96442c0b5ef8de65ff1f85da6f16fcb0c046bd78"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://actions.github.io/buildtypes/workflow/v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/heads/main",
          "repository": "https://github.com/gpoulios/testpkg",
          "path": ".github/workflows/build-docker-image.yaml"
        }
      },
      "internalParameters": {
        "github": {
          "event_name": "workflow_dispatch",
          "repository_id": "961832747",
          "repository_owner_id": "14057280",
          "runner_environment": "github-hosted"
        }
      },
      "resolvedDependencies": [
        {
          "uri": "git+https://github.com/gpoulios/testpkg@refs/heads/main",
          "digest": {
            "gitCommit": "5b07e3bac70089fa60a35f72f3771a709b2aa173"
          }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/gpoulios/testpkg/.github/workflows/build-docker-image.yaml@refs/heads/main"
      },
      "metadata": {
        "invocationId": "https://github.com/gpoulios/testpkg/actions/runs/14311391069/attempts/1"
      }
    }
  }
}
```

`.verificationMaterial.tlogEntries[0].canonicalizedBody` contains the same signature in `signature` and a certificate in `verifier`:

```json
$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -r '.verificationMaterial.tlogEntries[0].canonicalizedBody' | base64 -d | jq .
{
  "apiVersion": "0.0.1",
  "kind": "dsse",
  "spec": {
    "envelopeHash": {
      "algorithm": "sha256",
      "value": "fd50612485cd2c1652a0d52e4bfdb4e1f224c88c2e36f3d277968915480e4f00"
    },
    "payloadHash": {
      "algorithm": "sha256",
      "value": "05211794607b1d7f8d72c3cd75d6168f209680d8cbefe23d2d2cf1291b22140f"
    },
    "signatures": [
      {
        "signature": "MEYCIQDUuiLRXfB2KLhLG57TrLdBP9DkBkkS1ywzk1Pwfoq3OAIhALhm6WyBCLZ6Vrsgxct0Yjv2RLCau9neKZcPKIO1SHB7",
        "verifier": "LS0tLS1CRU[...]0tLS0tCg=="
      }
    ]
  }
}
```

where:

- `.[...].canonicalizedBody.spec.payloadHash` is the SHA256 of the base64 decoded value of `.dsseEnvelope.payload`:

  - ```bash
    $ oras blob fetch --output - $BUNDLE_BLOB | \
            jq -r .dsseEnvelope.payload | base64 -d | sha256sum
    05211794607b1d7f8d72c3cd75d6168f209680d8cbefe23d2d2cf1291b22140f
    ```

- `.[...].canonicalizedBody.spec.envelopeHash` ?

See also: https://search.sigstore.dev/?hash=sha256:05211794607b1d7f8d72c3cd75d6168f209680d8cbefe23d2d2cf1291b22140f

### Certificates

The certificate in `verificationMaterial.certificate.rawBytes` is a short-lived (10 minute') "sigstore-intermediate": 

```bash
$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -r '.verificationMaterial.certificate.rawBytes' | base64 -d | \
  openssl x509 -text -noout -inform DER -in -
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            52:cf:34:90:45:31:ca:a7:ad:bb:6d:4c:ca:85:7e:38:86:3b:3f:b8
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O = sigstore.dev, CN = sigstore-intermediate
        Validity
            Not Before: Apr  7 14:08:20 2025 GMT
            Not After : Apr  7 14:18:20 2025 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:[...]:b4
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing
            X509v3 Subject Key Identifier: 
                2D:56:5A:C4:CF:BD:91:FE:34:D3:FD:24:8E:3E:02:65:DA:02:12:84
            X509v3 Authority Key Identifier: 
                keyid:DF:D3:E9:CF:56:24:11:96:F9:A8:D8:E9:28:55:A2:C6:2E:18:64:3F

            X509v3 Subject Alternative Name: critical
                URI:https://github.com/gpoulios/testpkg/.github/workflows/build-docker-image.yaml@refs/heads/main
[...]
```

The certificate under `verificationMaterial.tlogEntries[0].canonicalizedBody.signatures.verifier` is the same in PEM format.

### Verification

```bash
$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -rj '.dsseEnvelope.payloadType' \
  > payload.type

$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -r '.dsseEnvelope.payload' | \
  base64 -d \
  > payload.json

$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -r '.dsseEnvelope.signatures[0].sig' | \
  base64 -d \
  > payload.sig

$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -r '.verificationMaterial.certificate.rawBytes' | \
  base64 -d \
  > cert.der
  
$ openssl x509 -pubkey -noout -in cert.der -inform DER > pubkey.pem

$ echo -n "DSSEv1 $(wc -c payload.type | awk '{print $1}') $(cat payload.type) $(wc -c payload.json | awk '{print $1}') $(cat payload.json)" \
  > payload.pae

$ openssl sha256 -verify pubkey.pem -signature payload.sig payload.pae
Verified OK
```

See also:

- https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- https://jfrog.com/help/r/jfrog-artifactory-documentation/verify-release-bundles-v2 (with PGP signature but shows PAE encoding)

### Concerns

- Privacy: https://blog.sigstore.dev/privacy-in-sigstore-57cac15af0d0/

- SLSA L2 (see Limits section): https://www.ianlewis.org/en/understanding-github-artifact-attestations

  

## SLSA Github generators (L3)

https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/container/README.md

...but also uses cosign, the public Rekor API server and the public transparency log (perhaps even less privacy than private repos under the Github enterprise plan using Github Artifact Attestations). Doesn't seem to be configurable either (?). See also concerns for "enterprise needs" in: https://www.legitsecurity.com/blog/slsa-provenance-blog-series-part3-challenges-of-adopting-slsa-provenance.

And some things to keep in mind (including comments therein): https://blog.richardfan.xyz/2024/08/02/reusable-workflow-is-good-until-you-realize-your-identity-is-also-reusable-by-anyone.html.

