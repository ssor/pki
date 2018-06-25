// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package easypki provides helpers to manage a Public Key Infrastructure.
package easypki

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "errors"
    "fmt"
    "time"
    "github.com/ssor/pki/easypki/pkg/certificate"
    "github.com/ssor/zlog"
)

const (
    defaultPrivateKeySize = 2048
)

// Signing errors.
var (
    ErrCannotSelfSignNonCA = errors.New("cannot self sign non CA request")
    ErrMaxPathLenReached   = errors.New("max path len reached")
)

// Request is a struct for providing configuration to
// GenerateCertificate when actioning a certification generation request.
type Request struct {
    Name                string
    IsClientCertificate bool
    PrivateKeySize      int
    Template            *x509.Certificate
}

// EasyPKI wraps helpers to handle a Public Key Infrastructure.
type EasyPKI struct {
    Store *Local
}

// GetCA fetches and returns the named Certificate Authrority bundle
// from the store.
func (e *EasyPKI) GetCA(name string) (*certificate.Bundle, error) {
    zlog.Info("Get CA name = ", name)
    return e.GetBundle(name, name)
}

// GetBundle fetches and returns a certificate bundle from the store.
func (e *EasyPKI) GetBundle(caName, name string) (*certificate.Bundle, error) {
    k, c, err := e.Store.Fetch(caName, name)
    if err != nil {
        return nil, fmt.Errorf("failed fetching bundle %v within CA %v: %v", name, caName, err)
    }

    return certificate.RawToBundle(name, k, c)
}

// Sign signs a generated certificate bundle based on the given request with
// the given signer.
func (e *EasyPKI) Sign(signer *certificate.Bundle, req *Request) error {
    if !req.Template.IsCA && signer == nil {
        zlog.AddFields("isCA", req.Template.IsCA, "signer_is_nil", signer == nil).Info("pki sign <-")
        return ErrCannotSelfSignNonCA
    }
    if req.Template.IsCA && signer != nil && signer.Cert.MaxPathLen == 0 {
        zlog.AddFields("isCA", req.Template.IsCA, "signer_is_nil", signer == nil, "maxPathLen", signer.Cert.MaxPathLen).Info(" pki sign <-")
        return ErrMaxPathLenReached
    }
    zlog.Debug("pki sign -> ")

    if req.PrivateKeySize == 0 {
        req.PrivateKeySize = defaultPrivateKeySize
    }
    privateKey, err := rsa.GenerateKey(rand.Reader, req.PrivateKeySize)
    if err != nil {
        return fmt.Errorf("failed generating private key: %v", err)
    }
    publicKey := privateKey.Public()

    if err := defaultTemplate(req, publicKey); err != nil {
        return fmt.Errorf("failed updating generation request: %v", err)
    }

    if req.Template.IsCA {
        zlog.Info("CA -> ")
        var intermediateCA bool
        if signer != nil {
            intermediateCA = true
            if signer.Cert.MaxPathLen > 0 {
                req.Template.MaxPathLen = signer.Cert.MaxPathLen - 1
            }
        }
        if err := caTemplate(req, intermediateCA); err != nil {
            return fmt.Errorf("failed updating generation request for CA: %v", err)
        }
        zlog.AddFields("name", req.Name, "intermediateCA", intermediateCA).Info("use caTemplate -> ")

        if !intermediateCA {
            // Use the generated certificate template and private key (self-signing).
            signer = &certificate.Bundle{Name: req.Name, Cert: req.Template, Key: privateKey}
            zlog.AddFields("intermediateCA", intermediateCA, "name", req.Name).Info("init signer ")
        }

    } else {
        zlog.Info("Not CA -> ")
        nonCATemplate(req)
        zlog.AddFields("name", req.Name).Info("nonCATemplate -> ")
    }

    rawCert, err := x509.CreateCertificate(rand.Reader, req.Template, signer.Cert, publicKey, signer.Key)
    if err != nil {
        return fmt.Errorf("failed creating and signing certificate: %v", err)
    }

    zlog.AddFields("signer", signer.Name, "signee", req.Name).Info("CreateCertificate OK")

    if err := e.Store.Add(signer.Name, req.Name, req.Template.IsCA, x509.MarshalPKCS1PrivateKey(privateKey), rawCert); err != nil {
        return fmt.Errorf("failed saving generated bundle: %v", err)
    }
    return nil
}

// Revoke revokes the given certificate from the store.
func (e *EasyPKI) Revoke(caName string, cert *x509.Certificate) error {
    if err := e.Store.Update(caName, cert.SerialNumber, certificate.Revoked); err != nil {
        return fmt.Errorf("failed revoking certificate: %v", err)
    }
    return nil
}

// CRL builds a CRL for a given CA based on the revoked certs.
func (e *EasyPKI) CRL(caName string, expire time.Time) ([]byte, error) {
    revoked, err := e.Store.Revoked(caName)
    if err != nil {
        return nil, fmt.Errorf("failed retrieving revoked certificates for %v: %v", caName, err)
    }
    ca, err := e.GetCA(caName)
    if err != nil {
        return nil, fmt.Errorf("failed retrieving CA bundle %v: %v", caName, err)
    }

    crl, err := ca.Cert.CreateCRL(rand.Reader, ca.Key, revoked, time.Now(), expire)
    if err != nil {
        return nil, fmt.Errorf("failed creating crl for %v: %v", caName, err)
    }
    return crl, nil
}
