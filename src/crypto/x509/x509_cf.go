package x509

import (
	"crypto"
	"encoding/asn1"

	circlPki "cloudflare/circl/pki"
	circlSign "cloudflare/circl/sign"
	"cloudflare/circl/sign/eddilithium2"
	"cloudflare/circl/sign/eddilithium3"
	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
)

// To add a signature scheme from Circl
//
//   1. make sure it implements CertificateScheme,
//	 2. add SignatureAlgorithm and PublicKeyAlgorithm constants in x509.go
//   3. add row in circlSchemes below
//   4. update publicKeyAlgoName in x509.go

var circlSchemes = [...]struct {
	sga    SignatureAlgorithm
	alg    PublicKeyAlgorithm
	scheme circlSign.Scheme
}{
	{PureEdDilithium2, EdDilithium2, eddilithium2.Scheme()},
	{PureEdDilithium3, EdDilithium3, eddilithium3.Scheme()},
	{PureMLDSA44, MLDSA44, mldsa44.Scheme()},
	{PureMLDSA65, MLDSA65, mldsa65.Scheme()},
	{PureMLDSA87, MLDSA87, mldsa87.Scheme()},
}

func CirclSchemeByPublicKeyAlgorithm(alg PublicKeyAlgorithm) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.alg == alg {
			return cs.scheme
		}
	}
	return nil
}

func SignatureAlgorithmByCirclScheme(scheme circlSign.Scheme) SignatureAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.sga
		}
	}
	return UnknownSignatureAlgorithm
}

func PublicKeyAlgorithmByCirclScheme(scheme circlSign.Scheme) PublicKeyAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.alg
		}
	}
	return UnknownPublicKeyAlgorithm
}

func init() {
	for _, cs := range circlSchemes {
		signatureAlgorithmDetails = append(signatureAlgorithmDetails,
			struct {
				algo       SignatureAlgorithm
				name       string
				oid        asn1.ObjectIdentifier
				pubKeyAlgo PublicKeyAlgorithm
				hash       crypto.Hash
			}{
				cs.sga,
				cs.scheme.Name(),
				cs.scheme.(circlPki.CertificateScheme).Oid(),
				cs.alg,
				crypto.Hash(0),
			},
		)
	}
}
