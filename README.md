# testpkg

## Github Artifact Attestations (L2)

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

```bash
$ export IMAGE=ghcr.io/gpoulios/testpkg

$ oras discover ${IMAGE}:sha-5b07e3b
ghcr.io/gpoulios/testpkg@sha256:9c24ac7eca13411bee8f335f96442c0b5ef8de65ff1f85da6f16fcb0c046bd78
└── application/vnd.dev.sigstore.bundle.v0.3+json
    └── sha256:ac86426c102983ecd8036b7ae6d6ba9aabfdba1b1672cebcf481373863f0d08b
    
$ oras manifest fetch --pretty ${IMAGE}@sha256:ac86426c102983ecd8036b7ae6d6ba9aabfdba1b1672cebcf481373863f0d08b
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
$ oras blob fetch --output - ${IMAGE}@sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
{}
```

```bash
# fetch sigstore bundle
$ export BUNDLE_BLOB="${IMAGE}@sha256:42f04b717a13e740a8a5b80798a4bbf256bb2334aab7a110d3d4c8b10f9ed395"

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

> [!WARNING]
> Obviously, the recommended way of verifying is through `gh attestation verify`. The following is just an exercise for better undertanding. DO NOT use in production.

```bash
$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -j '.dsseEnvelope.payloadType' \
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

## Notary V2 - Notation

Github actions and plugins:

- https://github.com/marketplace/actions/notation-actions

Plan for Support for Cryptographic Tokens dropped:

- https://github.com/notaryproject/notation/issues/20

but supports [plugins](https://github.com/notaryproject/specifications/blob/main/specs/plugin-extensibility.md):

- [AWS signer](https://github.com/aws/aws-signer-notation-plugin)
- [Azure Key Vault](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-sign-build-push): https://github.com/Azure/notation-azure-kv
- [HashiCorp Vault](https://github.com/notaryproject/notation-hashicorp-vault)
- or custom, eg: https://docs.securosys.com/docker_signing/Concepts/DockerSigningConcept/

### Usage

```yaml
      # Buildx is required for docker build attestations
      # Otherwise we can still sign the image without it.
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push Docker images
        id: push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          annotations: ${{ steps.meta.outputs.annotations }}
[...]

      - name: Setup Notation CLI
        uses: notaryproject/notation-action/setup@v1
        with:
          version: "1.3.1"

      - name: Sign using notation
        run: |
          set -eu

          notation cert generate-test --default testkey.io

          # can also use --signature-format=cose here
          # but we want to inspect it later using cmd line tools
          notation sign \
            --force-referrers-tag=false \
            ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}
```

### Inspection - docker buildx attestation

```bash
$ export IMAGE=ghcr.io/gpoulios/testpkg
$ export IMAGE_DGST=138fc25e9aaf93251609d23a8a50e91d50462f5dccb53cffde8db7a46385cfec

$ oras manifest fetch --pretty ${IMAGE}@sha256:${IMAGE_DGST}
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:0e026e48c72f503a89f1299d8d6a768f1e516740017b8dd29d290c234ec889b4",
      "size": 1960,
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:0b99212f395833227bbb3fdf0e821efd8ce8af3cca65ce9e00fc96c683af7076",
      "size": 566,
      "annotations": {
        "vnd.docker.reference.digest": "sha256:0e026e48c72f503a89f1299d8d6a768f1e516740017b8dd29d290c234ec889b4",
        "vnd.docker.reference.type": "attestation-manifest"
      },
      "platform": {
        "architecture": "unknown",
        "os": "unknown"
      }
    }
  ]
}

$ oras manifest fetch ${IMAGE}@sha256:${IMAGE_DGST} | sha256
138fc25e9aaf93251609d23a8a50e91d50462f5dccb53cffde8db7a46385cfec
# matches IMAGE_DGST, which is what gets signed by tools like notation
```

The 1st manifest is the image manifest (containing config, layers and annotations):

```json
$ oras manifest fetch --pretty ${IMAGE}@sha256:0e026e48c72f503a89f1299d8d6a768f1e516740017b8dd29d290c234ec889b4
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:be655f7112c64381b439d1ec749c5bfc90b238fdfd2d9144dd6f51fdb866b9d2",
    "size": 6447
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:8663204ce13b2961da55026a2034abb9e5afaaccf6a9cfb44ad71406dcd07c7b",
      "size": 2818370
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:e6202aa870befe19a5b6da7484e3ac1b39b0762008cbc7ed14e11815e9ac4668",
      "size": 666689
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:a88bc25b90f3caced3e4722e35e5135cd8baf7e88ecba1a0ab8cb25ef38f9813",
      "size": 12276368
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:27cc90149e46b2c2d78df4b7995c16fc46f0dae17249cb9376af954923c430e6",
      "size": 232
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:59657a21942375d7527fd74698336299373dafc8b302ae2613749049e0b0d409",
      "size": 2871684
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:2dfb43191caac1183ebd2f283eeeb04722bd6999816cd0fb5fe05b3ecdc12bc1",
      "size": 4704
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2025-04-09T16:52:51.101Z",
    "org.opencontainers.image.description": "",
    "org.opencontainers.image.licenses": "",
    "org.opencontainers.image.revision": "a5973387abf03990dd3b8247b7c59f4ef9bb7c3b",
    "org.opencontainers.image.source": "https://github.com/gpoulios/testpkg",
    "org.opencontainers.image.title": "testpkg",
    "org.opencontainers.image.url": "https://github.com/gpoulios/testpkg",
    "org.opencontainers.image.version": "sha-a597338"
  }
}
```

The 2nd manifest is the attestation manifest, which references the in-toto layer:

```json
$ oras manifest fetch --pretty ${IMAGE}@sha256:0b99212f395833227bbb3fdf0e821efd8ce8af3cca65ce9e00fc96c683af7076
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:3cba032129a6997082edcc529756dc27194b9f16ca7695c67fb00991aae5e9bd",
    "size": 167
  },
  "layers": [
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:63f574b1d103c131d7e8f18b3c78df741e07a22ed9f2adfdc1303763f69a4305",
      "size": 5572,
      "annotations": {
        "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"
      }
    }
  ]
}
```

Dump the in-toto statement using its sha256:

```json
$ oras blob fetch --output - ${IMAGE}@sha256:63f574b1d103c131d7e8f18b3c78df741e07a22ed9f2adfdc1303763f69a4305 | jq .
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "pkg:docker/ghcr.io/gpoulios/testpkg@sha-a597338?platform=linux%2Famd64",
      "digest": {
        "sha256": "0e026e48c72f503a89f1299d8d6a768f1e516740017b8dd29d290c234ec889b4"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/gpoulios/testpkg/actions/runs/14362696875"
    },
    "buildType": "https://mobyproject.org/buildkit@v1",
    "materials": [
      {
        "uri": "pkg:docker/python@alpine3.14?platform=linux%2Famd64",
        "digest": {
          "sha256": "fb93ca595ad82020cc52ff60604cddc1a6d393229ef5ecc8f6ac7c7fb52bacda"
        }
      }
    ],
    "invocation": {
      "configSource": {
        "entryPoint": "Dockerfile"
      },
      "parameters": {
        "frontend": "dockerfile.v0",
        "args": {
          "label:org.opencontainers.image.created": "2025-04-09T16:52:51.101Z",
          "label:org.opencontainers.image.description": "",
          "label:org.opencontainers.image.licenses": "",
          "label:org.opencontainers.image.revision": "a5973387abf03990dd3b8247b7c59f4ef9bb7c3b",
          "label:org.opencontainers.image.source": "https://github.com/gpoulios/testpkg",
          "label:org.opencontainers.image.title": "testpkg",
          "label:org.opencontainers.image.url": "https://github.com/gpoulios/testpkg",
          "label:org.opencontainers.image.version": "sha-a597338"
        },
        "locals": [
          {
            "name": "context"
          },
          {
            "name": "dockerfile"
          }
        ]
      },
      "environment": {
        "platform": "linux/amd64"
      }
    },
    "buildConfig": {
      "llbDefinition": [
        {
          "id": "step0",
          "op": {
            "Op": {
              "source": {
                "identifier": "docker-image://docker.io/library/python:alpine3.14@sha256:fb93ca595ad82020cc52ff60604cddc1a6d393229ef5ecc8f6ac7c7fb52bacda"
              }
            },
            "platform": {
              "Architecture": "amd64",
              "OS": "linux"
            },
            "constraints": {}
          }
        },
        {
          "id": "step1",
          "op": {
            "Op": {
              "source": {
                "identifier": "local://context",
                "attrs": {
                  "local.followpaths": "[\"README.md\"]",
                  "local.sharedkeyhint": "context"
                }
              }
            },
            "constraints": {}
          }
        },
        {
          "id": "step2",
          "op": {
            "Op": {
              "file": {
                "actions": [
                  {
                    "input": 0,
                    "secondaryInput": 1,
                    "output": 0,
                    "Action": {
                      "copy": {
                        "src": "/README.md",
                        "dest": "/README.md",
                        "mode": -1,
                        "followSymlink": true,
                        "dirCopyContents": true,
                        "createDestPath": true,
                        "allowWildcard": true,
                        "allowEmptyWildcard": true,
                        "timestamp": -1
                      }
                    }
                  }
                ]
              }
            },
            "constraints": {}
          },
          "inputs": [
            "step0:0",
            "step1:0"
          ]
        },
        {
          "id": "step3",
          "op": {
            "Op": {}
          },
          "inputs": [
            "step2:0"
          ]
        }
      ],
      "digestMapping": {
        "sha256:0dc4de8261b5f57fb8841320b739fcfab7aa37bad994059fa7e656b1a8613b25": "step2",
        "sha256:89e2f16e1b3612bab3c8c7f6a58b6e59b72b4453381874fed3c7827ef1b95894": "step1",
        "sha256:d177efd10a9c6867868470b75a11251105d3a3ecc44b233623a35f31a6bb6aae": "step3",
        "sha256:de26ac856cfa3a78d41f9afc56cbf99148b029f067c24adfc65a4635fc06f5fa": "step0"
      }
    },
    "metadata": {
      "buildInvocationID": "kzmxe5iwuyoc0sa6jmz28mpuc",
      "buildStartedOn": "2025-04-09T16:52:55.674772811Z",
      "buildFinishedOn": "2025-04-09T16:52:57.076365945Z",
      "completeness": {
        "parameters": true,
        "environment": true,
        "materials": false
      },
      "reproducible": false,
      "https://mobyproject.org/buildkit@v1#metadata": {
        "vcs": {
          "localdir:context": ".",
          "localdir:dockerfile": ".",
          "revision": "a5973387abf03990dd3b8247b7c59f4ef9bb7c3b",
          "source": "https://github.com/gpoulios/testpkg"
        },
        "source": {
          [...]
          },
          "infos": [
            {
              "filename": "Dockerfile",
              "language": "Dockerfile",
              "data": "RlJPTSBweXRob246YWxwaW5lMy4xNAoKQ09QWSBSRUFETUUubWQgL1JFQURNRS5tZA==",
              "llbDefinition": [
                {
                  [...]
                },
                {
                  [...]
                }
              ],
              "digestMapping": {
                "sha256:8b17f348481d74e162a5e8d3a451a8fa311d134a6d322de5c9e16dca92bd2c2f": "step0",
                "sha256:d132751cb927fea092c24a73a178c0b44530f946ee5d78242618e02d9162835b": "step1"
              }
            }
          ]
        },
        "layers": {
          "step0:0": [
            [
              {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:8663204ce13b2961da55026a2034abb9e5afaaccf6a9cfb44ad71406dcd07c7b",
                "size": 2818370
              },
[...]
              {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:59657a21942375d7527fd74698336299373dafc8b302ae2613749049e0b0d409",
                "size": 2871684
              }
            ]
          ],
          "step2:0": [
            [
              {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:8663204ce13b2961da55026a2034abb9e5afaaccf6a9cfb44ad71406dcd07c7b",
                "size": 2818370
              },
[...]
              {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:2dfb43191caac1183ebd2f283eeeb04722bd6999816cd0fb5fe05b3ecdc12bc1",
                "size": 4704
              }
            ]
          ]
        }
      }
    }
  }
}
```

### Inspection - notary V2 signature

Image -> JOSE object's manifest -> JOSE object -> {payload, signer cert, signature}

Get the digest of the JOSE object's manifest (in this case `sha256:879fb0d930[...]`):

```bash
$ export IMAGE=ghcr.io/gpoulios/testpkg
$ export IMAGE_DGST=138fc25e9aaf93251609d23a8a50e91d50462f5dccb53cffde8db7a46385cfec

$ oras discover ${IMAGE}:sha-a597338
ghcr.io/gpoulios/testpkg@sha256:138fc25e9aaf93251609d23a8a50e91d50462f5dccb53cffde8db7a46385cfec
└── application/vnd.cncf.notary.signature
    └── sha256:879fb0d9305cb86cd90433d0a6547a2c721786a597d4c01d006cf0dc423af4a3

# equivalent to
$ oras discover ${IMAGE}@sha256:${IMAGE_DGST}
ghcr.io/gpoulios/testpkg@sha256:138fc25e9aaf93251609d23a8a50e91d50462f5dccb53cffde8db7a46385cfec
└── application/vnd.cncf.notary.signature
    └── sha256:879fb0d9305cb86cd90433d0a6547a2c721786a597d4c01d006cf0dc423af4a3

# can be also retrieved directly through the OCI image index
$ oras manifest fetch --pretty ${IMAGE}:sha256-${IMAGE_DGST}
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:879fb0d9305cb86cd90433d0a6547a2c721786a597d4c01d006cf0dc423af4a3",
      "size": 725,
      "annotations": {
        "io.cncf.notary.x509chain.thumbprint#S256": "[\"c1597ea37ee855f7b4ba42ef844869a462626b19b054ee22190a6a6fab3cc2ca\"]",
        "org.opencontainers.image.created": "2025-04-09T16:53:00Z"
      },
      "artifactType": "application/vnd.cncf.notary.signature"
    }
  ]
}

# NOTE: this is different from the image manifest retrievable through:
# $ oras manifest fetch --pretty ${IMAGE}@sha256:${IMAGE_DGST}
# (see above: Inspection - docker buildx attestation)
```

Dump the JOSE object's manifest:

```json
$ oras manifest fetch --pretty ${IMAGE}@sha256:879fb0d9305cb86cd90433d0a6547a2c721786a597d4c01d006cf0dc423af4a3
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.cncf.notary.signature",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/jose+json",
      "digest": "sha256:3fbd0b22f97543ad66ff7d86058e3237ed101a97dfd67943098d7926ddc8e9cf",
      "size": 2078
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": "sha256:138fc25e9aaf93251609d23a8a50e91d50462f5dccb53cffde8db7a46385cfec",
    "size": 856
  },
  "annotations": {
    "io.cncf.notary.x509chain.thumbprint#S256": "[\"c1597ea37ee855f7b4ba42ef844869a462626b19b054ee22190a6a6fab3cc2ca\"]",
    "org.opencontainers.image.created": "2025-04-09T16:53:00Z"
  }
}
```

Get the JOSE object:

```json
$ export JOSE_BLOB="${IMAGE}@sha256:3fbd0b22f97543ad66ff7d86058e3237ed101a97dfd67943098d7926ddc8e9cf"

$ oras blob fetch --output - $JOSE_BLOB | jq .
{
  "payload": "eyJ0Y[...]Nn19",
  "protected": "eyJh[...]WiJ9",
  "header": {
    "x5c": [
      "MIIDR[...]w/YHqc="
    ],
    "io.cncf.notary.signingAgent": "notation-go/1.3.1"
  },
  "signature": "sw4zJv[...]sujflDg"
}
```

JOSE object payload, and other protected properties:

```json
$ oras blob fetch --output - $JOSE_BLOB | jq -r .payload | \
  basenc --base64url -d 2>/dev/null | jq .
{
  "targetArtifact": {
    "digest": "sha256:138fc25e9aaf93251609d23a8a50e91d50462f5dccb53cffde8db7a46385cfec",
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "size": 856
  }
}

$ oras blob fetch --output - $JOSE_BLOB | jq -r .protected | \
  basenc --base64url -d 2>/dev/null | jq .
{
  "alg": "PS256",
  "crit": [
    "io.cncf.notary.signingScheme"
  ],
  "cty": "application/vnd.cncf.notary.payload.v1+json",
  "io.cncf.notary.signingScheme": "notary.x509",
  "io.cncf.notary.signingTime": "2025-04-09T16:53:00Z"
}
```

### Certificate

```bash
$ oras blob fetch --output - $JOSE_BLOB | jq -r '.header.x5c[0]' | \
  base64 -d | openssl x509 -text -noout -inform DER
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 105 (0x69)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = WA, L = Seattle, O = Notary, CN = testkey.io
        Validity
            Not Before: Apr  9 16:52:59 2025 GMT
            Not After : Apr 10 16:52:59 2025 GMT
        Subject: C = US, ST = WA, L = Seattle, O = Notary, CN = testkey.io
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:c0:9a:5f:dd:89:87:8a:e7:f8:a9:a2:df:ce:b2:
[...]
                    56:87
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing
    Signature Algorithm: sha256WithRSAEncryption
         3f:be:60:49:52:8e:ef:40:77:ef:9e:56:da:4f:69:2b:7f:48:
[...]
```

### Verification

> [!WARNING]
> Obviously, the recommended way of verifying is through `notation verify`. The following is just an exercise for better undertanding. DO NOT use in production.

```bash
$ oras blob fetch --output - $JOSE_BLOB | jq -j .protected > jwt.input
$ echo -n '.' >> jwt.input
$ oras blob fetch --output - $JOSE_BLOB | jq -j .payload >> jwt.input

$ oras blob fetch --output - $JOSE_BLOB | jq -r .signature | basenc --base64url -d 2>/dev/null > jwt.sig

$ oras blob fetch --output - $JOSE_BLOB | jq -r '.header.x5c[0]' | base64 -d | openssl x509 -noout -inform DER -pubkey > pubkey.pem

$ openssl dgst -sigopt rsa_padding_mode:pss -verify pubkey.pem -sha256 -signature jwt.sig jwt.input
Verified OK
```

## Sigstore - Cosign

### Usage

```yaml
      # Buildx is required for docker build attestations
      # Otherwise we can still sign the image without it.
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push Docker images
        id: push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          annotations: ${{ steps.meta.outputs.annotations }}
[...]

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3.8.1
        with:
          cosign-release: 'v2.5.0'

      - name: Sign using cosign
        run: |
          set -eu

          image=ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}

          docker buildx imagetools inspect $image \
            --format "{{json .Provenance.SLSA}}" > provenance.json

          # generate a dummy key pair and a self-signed CA
          openssl ecparam -out ecparam.pem -name prime256v1
          openssl genpkey -paramfile ecparam.pem -out openssl.key
          openssl req -rand /dev/random -new -days 365 -nodes -x509 \
            -subj "/C=CC/ST=ST/L=l/O=o/CN=www.example.com" \
            -key openssl.key -out cosign.cert

          cosign import-key-pair --key openssl.key --output-key-prefix=cosign

          cosign attest \
            --tlog-upload=false --new-bundle-format=true \
            --predicate provenance.json --type slsaprovenance02 \
            --key cosign.key --certificate cosign.cert \
            $image

          # cosign sign -y --key cosign.key $image
          # ..is pretty much equivalent except it doesn't upload as OCI artifact
          #   but rather as a new tag attachment with ".sig" extension. The same
          #   provenance data is included in the signed digest but need to be
          #   fetched through the image index instead the referrers API.
        env:
          COSIGN_PASSWORD: insecure
```

### Inspection - docker buildx attestation

> This part should be identical to notation; put it here for completeness anyway.

```bash
$ export IMAGE=ghcr.io/gpoulios/testpkg
$ export IMAGE_DGST=7fe4940f551b5c1c58e815b882024e2eed6b60d2380a3134aa3bcf603f2dc350

$ oras manifest fetch --pretty ${IMAGE}@sha256:${IMAGE_DGST}
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:898aa9e520bd7011f9c3b0063693d39915859b3a40dde035753651313a258891",
      "size": 1960,
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:5cc9b1839fe53fc7dad25d6f2d638abaf70729359bb48d0fb9dd0f7a78e9409f",
      "size": 566,
      "annotations": {
        "vnd.docker.reference.digest": "sha256:898aa9e520bd7011f9c3b0063693d39915859b3a40dde035753651313a258891",
        "vnd.docker.reference.type": "attestation-manifest"
      },
      "platform": {
        "architecture": "unknown",
        "os": "unknown"
      }
    }
  ]
}

$ oras manifest fetch ${IMAGE}@sha256:${IMAGE_DGST} | sha256
7fe4940f551b5c1c58e815b882024e2eed6b60d2380a3134aa3bcf603f2dc350
# matches IMAGE_DGST, which is what gets signed by tools like notation
```

The 1st manifest is the image manifest (containing config, layers and annotations):

```json
$ oras manifest fetch --pretty ${IMAGE}@sha256:898aa9e520bd7011f9c3b0063693d39915859b3a40dde035753651313a258891
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:3d9417294bde277f4acc3d02e0ddeb34a021cd813dae38f371d3fcd4f12aea6b",
    "size": 6447
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:8663204ce13b2961da55026a2034abb9e5afaaccf6a9cfb44ad71406dcd07c7b",
      "size": 2818370
    },
[...]
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:329af3d6b5976031130ffb3742b14bd26cdeb52608555fd5de46e77bd28d6eb1",
      "size": 9092
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2025-04-10T14:18:50.649Z",
    "org.opencontainers.image.description": "",
    "org.opencontainers.image.licenses": "",
    "org.opencontainers.image.revision": "e938cc9053a8d2d893abb2ac8cdc49cf92dbc75d",
    "org.opencontainers.image.source": "https://github.com/gpoulios/testpkg",
    "org.opencontainers.image.title": "testpkg",
    "org.opencontainers.image.url": "https://github.com/gpoulios/testpkg",
    "org.opencontainers.image.version": "sha-e938cc9"
  }
}
```

The 2nd manifest is the attestation manifest, which references the in-toto layer:

```json
$ oras manifest fetch --pretty ${IMAGE}@sha256:5cc9b1839fe53fc7dad25d6f2d638abaf70729359bb48d0fb9dd0f7a78e9409f
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:34125b0257bbdf32a5746ceca2b6de32451df38c2bc201641732d8862c0a6992",
    "size": 167
  },
  "layers": [
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:4f9a327ff766e5c8a1f192a671ce1269cf78d498c73dc8e11369ee4b7ecbc48f",
      "size": 5572,
      "annotations": {
        "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"
      }
    }
  ]
}
```

Dump the in-toto statement using its sha256:

```json
$ oras blob fetch --output - ${IMAGE}@sha256:4f9a327ff766e5c8a1f192a671ce1269cf78d498c73dc8e11369ee4b7ecbc48f | jq .
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "pkg:docker/ghcr.io/gpoulios/testpkg@sha-e938cc9?platform=linux%2Famd64",
      "digest": {
        "sha256": "898aa9e520bd7011f9c3b0063693d39915859b3a40dde035753651313a258891"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/gpoulios/testpkg/actions/runs/14382811836"
    },
    "buildType": "https://mobyproject.org/buildkit@v1",
    "materials": [
      {
        "uri": "pkg:docker/python@alpine3.14?platform=linux%2Famd64",
        "digest": {
          "sha256": "fb93ca595ad82020cc52ff60604cddc1a6d393229ef5ecc8f6ac7c7fb52bacda"
        }
      }
    ],
    "invocation": {
      "configSource": {
        "entryPoint": "Dockerfile"
      },
      "parameters": {
        "frontend": "dockerfile.v0",
        "args": {
          "label:org.opencontainers.image.created": "2025-04-10T14:18:50.649Z",
          "label:org.opencontainers.image.description": "",
          "label:org.opencontainers.image.licenses": "",
          "label:org.opencontainers.image.revision": "e938cc9053a8d2d893abb2ac8cdc49cf92dbc75d",
          "label:org.opencontainers.image.source": "https://github.com/gpoulios/testpkg",
          "label:org.opencontainers.image.title": "testpkg",
          "label:org.opencontainers.image.url": "https://github.com/gpoulios/testpkg",
          "label:org.opencontainers.image.version": "sha-e938cc9"
        },
        "locals": [
          {
            "name": "context"
          },
          {
            "name": "dockerfile"
          }
        ]
      },
      "environment": {
        "platform": "linux/amd64"
      }
    },
    "buildConfig": {
      "llbDefinition": [
        {
          "id": "step0",
          "op": {
            "Op": {
              "source": {
                "identifier": "docker-image://docker.io/library/python:alpine3.14@sha256:fb93ca595ad82020cc52ff60604cddc1a6d393229ef5ecc8f6ac7c7fb52bacda"
              }
            },
            "platform": {
              "Architecture": "amd64",
              "OS": "linux"
            },
            "constraints": {}
          }
        },
        {
          "id": "step1",
          "op": {
            "Op": {
              "source": {
                "identifier": "local://context",
                "attrs": {
                  "local.followpaths": "[\"README.md\"]",
                  "local.sharedkeyhint": "context"
                }
              }
            },
            "constraints": {}
          }
        },
        {
          "id": "step2",
          "op": {
            "Op": {
              "file": {
                "actions": [
                  {
                    "input": 0,
                    "secondaryInput": 1,
                    "output": 0,
                    "Action": {
                      "copy": {
                        "src": "/README.md",
                        "dest": "/README.md",
                        "mode": -1,
                        "followSymlink": true,
                        "dirCopyContents": true,
                        "createDestPath": true,
                        "allowWildcard": true,
                        "allowEmptyWildcard": true,
                        "timestamp": -1
                      }
                    }
                  }
                ]
              }
            },
            "constraints": {}
          },
          "inputs": [
            "step0:0",
            "step1:0"
          ]
        },
        {
          "id": "step3",
          "op": {
            "Op": {}
          },
          "inputs": [
            "step2:0"
          ]
        }
      ],
      "digestMapping": {
        "sha256:04791fa18032d49f58bede05a8ca61aea762887a5c4d2536d2e3b9e74ba061cf": "step2",
        "sha256:34510348aeb0e52c6e2ad801dfa721a6070de58fb1958c99ccfacb6e876e4079": "step3",
        "sha256:4a83b20505b1605345549177e2fdab92d54cf1198aea85c82be235590b6451a5": "step1",
        "sha256:de26ac856cfa3a78d41f9afc56cbf99148b029f067c24adfc65a4635fc06f5fa": "step0"
      }
    },
    "metadata": {
      "buildInvocationID": "q0memssqoxky1qpkko3tt9k0m",
      "buildStartedOn": "2025-04-10T14:18:58.343923031Z",
      "buildFinishedOn": "2025-04-10T14:19:00.144312805Z",
      "completeness": {
        "parameters": true,
        "environment": true,
        "materials": false
      },
      "reproducible": false,
      "https://mobyproject.org/buildkit@v1#metadata": {
        "vcs": {
          "localdir:context": ".",
          "localdir:dockerfile": ".",
          "revision": "e938cc9053a8d2d893abb2ac8cdc49cf92dbc75d",
          "source": "https://github.com/gpoulios/testpkg"
        },
        "source": {
          "locations": {
            "step0": {
              "locations": [
                {
                  "ranges": [
                    {
                      "start": {
                        "line": 1
                      },
                      "end": {
                        "line": 1
                      }
                    }
                  ]
                }
              ]
            },
            "step1": {},
            "step2": {
              "locations": [
                {
                  "ranges": [
                    {
                      "start": {
                        "line": 3
                      },
                      "end": {
                        "line": 3
                      }
                    }
                  ]
                }
              ]
            }
          },
          "infos": [
            {
              "filename": "Dockerfile",
              "language": "Dockerfile",
              "data": "RlJPTSBweXRob246YWxwaW5lMy4xNAoKQ09QWSBSRUFETUUubWQgL1JFQURNRS5tZA==",
              "llbDefinition": [
                {
                  "id": "step0",
                  "op": {
                    "Op": {
                      "source": {
                        "identifier": "local://dockerfile",
                        "attrs": {
                          "local.differ": "none",
                          "local.followpaths": "[\"Dockerfile\",\"Dockerfile.dockerignore\",\"dockerfile\"]",
                          "local.sharedkeyhint": "dockerfile"
                        }
                      }
                    },
                    "constraints": {}
                  }
                },
                {
                  "id": "step1",
                  "op": {
                    "Op": {}
                  },
                  "inputs": [
                    "step0:0"
                  ]
                }
              ],
              "digestMapping": {
                "sha256:26270324bccf3e6bd92b2b19258f233aece87d9b702e9a4b8c6ee88772442f77": "step1",
                "sha256:92120a28d91c0518bc8f4128594a044ad350fe5e92d4b5c245e4d20c74cf8ef5": "step0"
              }
            }
          ]
        },
        "layers": {
          "step0:0": [
            [
              {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:8663204ce13b2961da55026a2034abb9e5afaaccf6a9cfb44ad71406dcd07c7b",
                "size": 2818370
              },
[...]
              {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:59657a21942375d7527fd74698336299373dafc8b302ae2613749049e0b0d409",
                "size": 2871684
              }
            ]
          ],
          "step2:0": [
            [
              {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:8663204ce13b2961da55026a2034abb9e5afaaccf6a9cfb44ad71406dcd07c7b",
                "size": 2818370
              },
[...]
              {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:329af3d6b5976031130ffb3742b14bd26cdeb52608555fd5de46e77bd28d6eb1",
                "size": 9092
              }
            ]
          ]
        }
      }
    }
  }
}
```

### Inspection - cosign attestation

Image -> Sigstore bundle's manifest -> Sigstore bundle -> {payload, signer cert, signature}

Get the digest of the Sigstore bundle's manifest (in this case `sha256:95c0a84b61[...]`):

```bash
$ export IMAGE=ghcr.io/gpoulios/testpkg
$ export IMAGE_DGST=7fe4940f551b5c1c58e815b882024e2eed6b60d2380a3134aa3bcf603f2dc350

$ oras discover ${IMAGE}:sha-e938cc9
ghcr.io/gpoulios/testpkg@sha256:7fe4940f551b5c1c58e815b882024e2eed6b60d2380a3134aa3bcf603f2dc350
└── application/vnd.oci.empty.v1+json
    └── sha256:9524b2c35a48c5c077949425f6a3330fad01863d5d658f351b013888184ed1cc

# equivalent to
$ oras discover ${IMAGE}@sha256:${IMAGE_DGST}
ghcr.io/gpoulios/testpkg@sha256:7fe4940f551b5c1c58e815b882024e2eed6b60d2380a3134aa3bcf603f2dc350
└── application/vnd.oci.empty.v1+json
    └── sha256:9524b2c35a48c5c077949425f6a3330fad01863d5d658f351b013888184ed1cc

# can be also retrieved directly through the OCI image index
$ oras manifest fetch --pretty ${IMAGE}:sha256-${IMAGE_DGST}
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "size": 872,
      "digest": "sha256:9524b2c35a48c5c077949425f6a3330fad01863d5d658f351b013888184ed1cc",
      "artifactType": "application/vnd.oci.empty.v1+json"
    }
  ]
}

# NOTE: this is different from the image manifest retrievable through:
# $ oras manifest fetch --pretty ${IMAGE}@sha256:${IMAGE_DGST}
# (see above: Inspection - docker buildx attestation)
```

Dump the Sigstore bundle's manifest:

```json
$ oras manifest fetch --pretty ${IMAGE}@sha256:95c0a84b615b98ed01cb61348889e73a06b28ee54949389bdd6a6144055d9bc6
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "size": 2,
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"
  },
  "layers": [
    {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "size": 4553,
      "digest": "sha256:855097fd1ae34ad3e4101218738589ab56fbf41e455c34fc7f13229bdf470f64"
    }
  ],
  "annotations": {
    "dev.sigstore.bundle.content": "dsse-envelope",
    "dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v0.2",
    "org.opencontainers.image.created": "2025-04-10T14:19:09Z"
  },
  "subject": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "size": 856,
    "digest": "sha256:7fe4940f551b5c1c58e815b882024e2eed6b60d2380a3134aa3bcf603f2dc350"
  },
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"
}
```

Get the Sigstore bundle:

```json
$ export BUNDLE_BLOB="${IMAGE}@sha256:855097fd1ae34ad3e4101218738589ab56fbf41e455c34fc7f13229bdf470f64"

$ oras blob fetch --output - $BUNDLE_BLOB | jq .
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {
      "rawBytes": "MIIB7TCCAZ[...]Nb1by3V8dfg3WQ="
    }
  },
  "dsseEnvelope": {
    "payload": "eyJfdHlwZSI6Im[...]1dfX0=",
    "payloadType": "application/vnd.in-toto+json",
    "signatures": [
      {
        "sig": "MEUCIQDdNnoWlqZGM0VReIbwNj/167V4kJjoiOKpj3vncE0MqQIgPmQCD+F6Claj5h6HxWxiZ8va/GKxwaRsqlrja9PQnKA="
      }
    ]
  }
}
```

Sigstore bundle payload:

```json
$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -r '.dsseEnvelope.payload' | base64 -d | jq .
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "ghcr.io/gpoulios/testpkg",
      "digest": {
        "sha256": "7fe4940f551b5c1c58e815b882024e2eed6b60d2380a3134aa3bcf603f2dc350"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/gpoulios/testpkg/actions/runs/14382811836"
    },
    "buildType": "https://mobyproject.org/buildkit@v1",
    "invocation": {
      "configSource": {
        "entryPoint": "Dockerfile"
      },
      "parameters": {
        "args": {
          "label:org.opencontainers.image.created": "2025-04-10T14:18:50.649Z",
          "label:org.opencontainers.image.description": "",
          "label:org.opencontainers.image.licenses": "",
          "label:org.opencontainers.image.revision": "e938cc9053a8d2d893abb2ac8cdc49cf92dbc75d",
          "label:org.opencontainers.image.source": "https://github.com/gpoulios/testpkg",
          "label:org.opencontainers.image.title": "testpkg",
          "label:org.opencontainers.image.url": "https://github.com/gpoulios/testpkg",
          "label:org.opencontainers.image.version": "sha-e938cc9"
        },
        "frontend": "dockerfile.v0",
        "locals": [
          {
            "name": "context"
          },
          {
            "name": "dockerfile"
          }
        ]
      },
      "environment": {
        "platform": "linux/amd64"
      }
    },
    "buildConfig": {
      "digestMapping": {
        "sha256:04791fa18032d49f58bede05a8ca61aea762887a5c4d2536d2e3b9e74ba061cf": "step2",
        "sha256:34510348aeb0e52c6e2ad801dfa721a6070de58fb1958c99ccfacb6e876e4079": "step3",
        "sha256:4a83b20505b1605345549177e2fdab92d54cf1198aea85c82be235590b6451a5": "step1",
        "sha256:de26ac856cfa3a78d41f9afc56cbf99148b029f067c24adfc65a4635fc06f5fa": "step0"
      },
      "llbDefinition": [
        {
          "id": "step0",
          "op": {
            "Op": {
              "source": {
                "identifier": "docker-image://docker.io/library/python:alpine3.14@sha256:fb93ca595ad82020cc52ff60604cddc1a6d393229ef5ecc8f6ac7c7fb52bacda"
              }
            },
            "constraints": {},
            "platform": {
              "Architecture": "amd64",
              "OS": "linux"
            }
          }
        },
        {
          "id": "step1",
          "op": {
            "Op": {
              "source": {
                "attrs": {
                  "local.followpaths": "[\"README.md\"]",
                  "local.sharedkeyhint": "context"
                },
                "identifier": "local://context"
              }
            },
            "constraints": {}
          }
        },
        {
          "id": "step2",
          "inputs": [
            "step0:0",
            "step1:0"
          ],
          "op": {
            "Op": {
              "file": {
                "actions": [
                  {
                    "Action": {
                      "copy": {
                        "allowEmptyWildcard": true,
                        "allowWildcard": true,
                        "createDestPath": true,
                        "dest": "/README.md",
                        "dirCopyContents": true,
                        "followSymlink": true,
                        "mode": -1,
                        "src": "/README.md",
                        "timestamp": -1
                      }
                    },
                    "input": 0,
                    "output": 0,
                    "secondaryInput": 1
                  }
                ]
              }
            },
            "constraints": {}
          }
        },
        {
          "id": "step3",
          "inputs": [
            "step2:0"
          ],
          "op": {
            "Op": {}
          }
        }
      ]
    },
    "metadata": {
      "buildInvocationID": "q0memssqoxky1qpkko3tt9k0m",
      "buildStartedOn": "2025-04-10T14:18:58.343923031Z",
      "buildFinishedOn": "2025-04-10T14:19:00.144312805Z",
      "completeness": {
        "parameters": true,
        "environment": true,
        "materials": false
      },
      "reproducible": false
    },
    "materials": [
      {
        "uri": "pkg:docker/python@alpine3.14?platform=linux%2Famd64",
        "digest": {
          "sha256": "fb93ca595ad82020cc52ff60604cddc1a6d393229ef5ecc8f6ac7c7fb52bacda"
        }
      }
    ]
  }
}
```

### Verification

> [!WARNING]
> Obviously, the recommended way of verifying is through `cosign verify[-attestation]`. The following is just an exercise for better undertanding. DO NOT use in production.

```bash
$ oras blob fetch --output - $BUNDLE_BLOB | \
  jq -j '.dsseEnvelope.payloadType' \
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

