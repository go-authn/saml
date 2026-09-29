// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// The content encryption algorithms (XML Encryption 1.1, 5.2). A Shibboleth
// IdP uses AES-128-GCM on a fresh install and AES-CBC on an older one, so
// both are read. Triple DES is not.
var contentAlgorithms = map[string]struct {
	key int
	gcm bool
}{
	"http://www.w3.org/2001/04/xmlenc#aes128-cbc": {16, false},
	"http://www.w3.org/2001/04/xmlenc#aes192-cbc": {24, false},
	"http://www.w3.org/2001/04/xmlenc#aes256-cbc": {32, false},
	"http://www.w3.org/2009/xmlenc11#aes128-gcm":  {16, true},
	"http://www.w3.org/2009/xmlenc11#aes192-gcm":  {24, true},
	"http://www.w3.org/2009/xmlenc11#aes256-gcm":  {32, true},
}

const (
	oaepMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	oaep11    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

var oaepDigests = map[string]crypto.Hash{
	"http://www.w3.org/2000/09/xmldsig#sha1":        crypto.SHA1,
	"http://www.w3.org/2001/04/xmlenc#sha256":       crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmlenc#sha512":       crypto.SHA512,
}

var mgfDigests = map[string]crypto.Hash{
	"http://www.w3.org/2009/xmlenc11#mgf1sha1":   crypto.SHA1,
	"http://www.w3.org/2009/xmlenc11#mgf1sha256": crypto.SHA256,
	"http://www.w3.org/2009/xmlenc11#mgf1sha384": crypto.SHA384,
	"http://www.w3.org/2009/xmlenc11#mgf1sha512": crypto.SHA512,
}

// The hashes are linked in by name, not only through crypto.Hash.
var _ = []any{sha1.New, sha256.New, sha512.New}

// decrypt opens an EncryptedAssertion and returns the Assertion inside.
//
// ⛔ CBC ciphertext is only decrypted when a verified signature covered it.
// Unauthenticated CBC is a padding oracle: "XML Encryption is broken"
// (Jager and Somorovsky, 2011) recovers a plaintext by sending a server
// variations of the ciphertext and watching which ones it rejects, and an SP
// that decrypts an unsigned response and then complains about the XML is
// exactly that server. GCM authenticates itself, so it is read either way.
//
// RSA PKCS#1 v1.5 key transport is not accepted at all: it is the
// Bleichenbacher oracle, and XML Encryption 1.1 (5.5.1) calls it NOT
// RECOMMENDED.
func (sp *SP) decrypt(ea *etree.Element, authenticated bool) (*etree.Element, error) {
	if sp.Key == nil {
		return nil, errors.New("the assertion is encrypted and this SP has no key")
	}
	ed, err := child(ea, nsXEnc, "EncryptedData")
	if err != nil {
		return nil, err
	}
	em, err := child(ed, nsXEnc, "EncryptionMethod")
	if err != nil {
		return nil, err
	}
	alg, ok := contentAlgorithms[em.SelectAttrValue("Algorithm", "")]
	if !ok {
		return nil, fmt.Errorf("content encryption %q is not accepted", em.SelectAttrValue("Algorithm", ""))
	}
	if !alg.gcm && !authenticated {
		return nil, errors.New("an AES-CBC assertion in an unsigned response is refused before decryption")
	}
	ct, err := cipherValue(ed)
	if err != nil {
		return nil, err
	}

	// The key may be inside EncryptedData's KeyInfo or beside it in the
	// EncryptedAssertion; both are in use.
	var eks []*etree.Element
	if ki, _ := optional(ed, nsDSig, "KeyInfo"); ki != nil {
		eks = append(eks, children(ki, nsXEnc, "EncryptedKey")...)
	}
	eks = append(eks, children(ea, nsXEnc, "EncryptedKey")...)
	if len(eks) == 0 {
		return nil, errors.New("the encrypted assertion carries no key")
	}
	var key []byte
	for _, ek := range eks {
		if r := ek.SelectAttrValue("Recipient", ""); r != "" && r != sp.EntityID {
			continue
		}
		if k, err := sp.unwrap(ek); err == nil && len(k) == alg.key {
			key = k
			break
		}
	}
	if key == nil {
		return nil, errors.New("no key in the encrypted assertion opens with this SP's key")
	}

	block, _ := aes.NewCipher(key)
	var pt []byte
	if alg.gcm {
		// 96-bit IV first, 128-bit tag last (XML Encryption 1.1, 5.2.4).
		g, _ := cipher.NewGCM(block)
		if len(ct) < g.NonceSize()+g.Overhead() {
			return nil, errors.New("the ciphertext is too short")
		}
		if pt, err = g.Open(nil, ct[:g.NonceSize()], ct[g.NonceSize():], nil); err != nil {
			return nil, errors.New("the ciphertext does not authenticate")
		}
	} else {
		bs := block.BlockSize()
		if len(ct) < 2*bs || len(ct)%bs != 0 {
			return nil, errors.New("the ciphertext is not whole blocks")
		}
		pt = make([]byte, len(ct)-bs)
		cipher.NewCBCDecrypter(block, ct[:bs]).CryptBlocks(pt, ct[bs:])
		// XML Encryption padding (5.2.1): N-1 arbitrary bytes, then N.
		// Unlike PKCS#7 the filler is not checked, because it is arbitrary.
		n := int(pt[len(pt)-1])
		if n == 0 || n > bs {
			return nil, errors.New("the plaintext padding is not valid")
		}
		pt = pt[:len(pt)-n]
	}
	root, err := parse(pt)
	if err != nil {
		return nil, fmt.Errorf("decrypted assertion: %w", err)
	}
	return root, nil
}

// unwrap decrypts one EncryptedKey with RSA-OAEP.
func (sp *SP) unwrap(ek *etree.Element) ([]byte, error) {
	em, err := child(ek, nsXEnc, "EncryptionMethod")
	if err != nil {
		return nil, err
	}
	opts := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
	switch a := em.SelectAttrValue("Algorithm", ""); a {
	case oaepMGF1P:
		// MGF1 with SHA-1, fixed; an MGF element MUST NOT be given (5.5.2).
		if len(children(em, nsXEnc11, "MGF")) > 0 {
			return nil, errors.New("rsa-oaep-mgf1p with an MGF element")
		}
	case oaep11:
		if m, _ := optional(em, nsXEnc11, "MGF"); m != nil {
			h, ok := mgfDigests[m.SelectAttrValue("Algorithm", "")]
			if !ok {
				return nil, fmt.Errorf("mask generation %q is not accepted", m.SelectAttrValue("Algorithm", ""))
			}
			opts.MGFHash = h
		}
	default:
		return nil, fmt.Errorf("key transport %q is not accepted", a)
	}
	if dm, _ := optional(em, nsDSig, "DigestMethod"); dm != nil {
		h, ok := oaepDigests[dm.SelectAttrValue("Algorithm", "")]
		if !ok {
			return nil, fmt.Errorf("OAEP digest %q is not accepted", dm.SelectAttrValue("Algorithm", ""))
		}
		opts.Hash = h
	}
	if p, _ := optional(em, nsXEnc, "OAEPparams"); p != nil {
		if opts.Label, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(p.Text()), "")); err != nil {
			return nil, err
		}
	}
	ct, err := cipherValue(ek)
	if err != nil {
		return nil, err
	}
	return sp.Key.Decrypt(nil, ct, opts)
}

func cipherValue(el *etree.Element) ([]byte, error) {
	cd, err := child(el, nsXEnc, "CipherData")
	if err != nil {
		return nil, err
	}
	cv, err := child(cd, nsXEnc, "CipherValue")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(cv.Text()), ""))
}
