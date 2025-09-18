package x509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

type deltaCertificateDescriptor struct {
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	Issuer             asn1.RawValue            `asn1:"optional,explicit,tag:1"`
	Validity           validity                 `asn1:"optional,explicit,tag:2"`
	Subject            asn1.RawValue            `asn1:"optional,explicit,tag:3"`
	PublicKey          publicKeyInfo
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:4"`
	SignatureValue     asn1.BitString
}

func parseDeltaExtension(deltaDer []byte) (*deltaCertificateDescriptor, error) {
	// Attempt to parse the delta extension
	deltaExtension := deltaCertificateDescriptor{}
	_, err := asn1.Unmarshal(deltaDer, &deltaExtension)
	if err != nil {
		return nil, err
	}

	// Return the result
	return &deltaExtension, nil
}

// TODO -> Revise and modify value if the Draft is approved and IANA assigns an OID for
//
//	the extension.
var deltaExtensionOid = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 6, 1}

// CreateChameleonCertificate creates a new x509 chameleon certificate as per
// `draft-bonnell-lamps-chameleon-certs-06`.
func CreateChameleonCertificate(randSource io.Reader, template, deltaParent, baseParent *Certificate, deltaPubKey, basePubKey, deltaPrivKey, basePrivKey any) ([]byte, error) {
	// Generate a secure serial number for the delta certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	deltaSerialNumber, err := rand.Int(randSource, serialNumberLimit)
	if err != nil {
		return nil, errors.New("x509: could not generate delta certificate serial number")
	}
	template.SerialNumber = deltaSerialNumber

	// Type cast the delta private key
	deltaKey, ok := deltaPrivKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	// Generate the delta certificate
	deltaDer, err := CreateCertificate(randSource, template, deltaParent, deltaPubKey, deltaPrivKey)
	if err != nil {
		return nil, err
	}
	deltaCert, err := ParseCertificate(deltaDer)
	if err != nil {
		return nil, err
	}

	// Get the raw values for the necessary fields
	_, signatureAlgorithm, _ := signingParamsForPublicKey(deltaKey.Public(), template.SignatureAlgorithm)
	pubKeyBytes, pubKeyAlgorithm, _ := marshalPublicKey(deltaKey.Public())

	// Add the delta extension to the template
	deltaExt := deltaCertificateDescriptor{
		SerialNumber:       deltaCert.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer: asn1.RawValue{
			Class:      2,
			Tag:        1,
			IsCompound: true,
			Bytes:      deltaCert.RawIssuer,
		},
		Validity: validity{
			NotBefore: deltaCert.NotBefore,
			NotAfter:  deltaCert.NotAfter,
		},
		Subject: asn1.RawValue{
			Class:      2,
			Tag:        3,
			IsCompound: true,
			Bytes:      deltaCert.RawSubject,
		},
		PublicKey: publicKeyInfo{
			Raw:       nil,
			Algorithm: pubKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     pubKeyBytes,
				BitLength: len(pubKeyBytes) * 8,
			},
		},
		Extensions: deltaCert.Extensions,
		SignatureValue: asn1.BitString{
			Bytes:     deltaCert.Signature,
			BitLength: len(deltaCert.Signature) * 8,
		},
	}
	rawDeltaExt, err := asn1.MarshalWithParams(deltaExt, `asn1:"optional"`)

	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:    deltaExtensionOid,
			Value: rawDeltaExt,
		},
	}

	// Change the serial number to generate the base/outer certificate
	baseSerialNumber, err := rand.Int(randSource, serialNumberLimit)
	if err != nil {
		return nil, errors.New("x509: could not generate base certificate serial number")
	}
	template.SerialNumber = baseSerialNumber

	// Generate the base/outer certificate
	return CreateCertificate(randSource, template, baseParent, basePubKey, basePrivKey)
}

func ReconstructDeltaCertificate(base *Certificate) (*Certificate, error) {
	// Build a map with all base certificate extensions and their index
	baseExtensions := make(map[string]int)
	for index, ext := range base.Extensions {
		baseExtensions[ext.Id.String()] = index
	}

	// Check if the base certificate contains a DCD extension
	dcdIndex, ok := baseExtensions[deltaExtensionOid.String()]
	if !ok {
		return nil, errors.New("Error: the certificate does not contain a Delta Certificate Descriptor extension")
	}

	// Parse the Delta Certificate Descriptor extension
	dcd, err := parseDeltaExtension(base.Extensions[dcdIndex].Value)
	if err != nil {
		//return nil, errors.New("Error parsing the Delta Certificate Descriptor")
		return nil, err
	}

	// 1. Clone the base certificate and remove the DCD extension
	// In order to do this, the base certificate is encoded and decoded to create
	// a new object.
	deltaCert, err := ParseCertificate(base.Raw)
	if err != nil {
		return nil, err
	}
	deltaCert.Extensions = append(deltaCert.Extensions[:dcdIndex], deltaCert.Extensions[dcdIndex+1:]...)

	// 2. Replace the Serial Number
	deltaCert.SerialNumber = dcd.SerialNumber

	// 3. Replace the Signature Algorithm (if required)
	// TODO -> Make this optional, as per Page 9 of the draft
	deltaCert.SignatureAlgorithm = getSignatureAlgorithmFromAI(dcd.SignatureAlgorithm)

	// 4. Replace the Issuer field (if required)
	if len(dcd.Issuer.Bytes) > 0 {
		deltaCert.RawIssuer = dcd.Subject.Bytes
		issuerRDNs, err := parseName(dcd.Issuer.Bytes)
		deltaCert.Issuer.FillFromRDNSequence(issuerRDNs)

		if err != nil {
			return nil, err
		}
	}

	// 6. Replace the Subject Public Key information
	deltaCert.RawSubjectPublicKeyInfo = dcd.PublicKey.Raw
	deltaCert.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(dcd.PublicKey.Algorithm.Algorithm)
	deltaCert.PublicKey, err = parsePublicKey(&dcd.PublicKey)
	if err != nil {
		return nil, err
	}

	// 7. Replace the subject field (if required)
	if len(dcd.Subject.Bytes) > 0 {
		deltaCert.RawSubject = dcd.Subject.Bytes
		subjectRDNs, err := parseName(dcd.Subject.Bytes)
		deltaCert.Subject.FillFromRDNSequence(subjectRDNs)

		if err != nil {
			return nil, err
		}
	}

	// 8. Parse extensions and see if any modifications are required
	for _, ext := range dcd.Extensions {
		// If the extension does not exist in the base certificate, return an error
		index, ok := baseExtensions[ext.Id.String()]
		if !ok {
			return nil, errors.New("Error: The deltaCertificateExtension contains extensions not present in the base certificate")
		}

		// Update the extension in the template
		deltaCert.Extensions[index] = ext
	}

	// 9. Replace the value of the Signature field
	deltaCert.Signature = dcd.SignatureValue.RightAlign()

	// 10. Recompute the ASN.1 encoded value of the certificate by replacing the Raw
	//     and RawTBSCertificate fields with the delta values
	err = deltaCert.deriveRawCertificate()
	if err != nil {
		return nil, err
	}

	// Return the reconstructed certificate
	return deltaCert, nil
}

func (c *Certificate) deriveRawCertificate() error {
	// Get the raw values of the appropriate fields
	_, signatureAlgorithm, err := signingParamsForPublicKey(c.PublicKey, c.SignatureAlgorithm)
	if err != nil {
		return err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(c.PublicKey)
	if err != nil {
		return err
	}
	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}

	// Create the TBSCertificate struct and encode it
	certTBSCertificate := tbsCertificate{
		Version:            2,
		SerialNumber:       c.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: c.RawIssuer},
		Validity:           validity{c.NotBefore.UTC(), c.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: c.RawSubject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         c.Extensions,
	}

	c.RawTBSCertificate, err = asn1.Marshal(certTBSCertificate)
	if err != nil {
		return err
	}

	// Rebuild the Certificate struct and encode it
	signed := certificate{
		TBSCertificate:     certTBSCertificate,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue: asn1.BitString{
			Bytes:     c.Signature,
			BitLength: len(c.Signature) * 8,
		},
	}
	c.Raw, err = asn1.Marshal(signed)
	if err != nil {
		return err
	} else {
		return nil
	}
}
