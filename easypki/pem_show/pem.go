package pem_show

import (
    "io/ioutil"
    "github.com/ssor/zlog"
    "encoding/pem"
    "github.com/pkg/errors"
    "crypto/x509"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "path/filepath"
    "strings"
    "encoding/json"
    "os"
    "time"
    "fmt"
)

const (
    PUBLIC_KEY      = "PUBLIC KEY"
    CERTIFICATE     = "CERTIFICATE"
    RSA_PRIVATE_KEY = "RSA PRIVATE KEY"
)

func ShowPem(pemFilePath string) error {
    raw, err := ioutil.ReadFile(pemFilePath)
    if err != nil {
        return err
    }
    zlog.Debug("pem_show raw content: \n", string(raw))
    result, err := parsePem(raw)
    if err != nil {
        return err
    }
    summary := extractPemSummaryInfo(result)

    filePath, fileName := filepath.Split(pemFilePath)
    ext := filepath.Ext(fileName)
    newFilePath := filepath.Join(filePath, strings.TrimSuffix(fileName, ext)+"_detail.txt")
    zlog.AddFields("dir", filePath, "ext", ext, "new", newFilePath).Debug("generate new file path:")
    err = createPemDetailFile(result, summary, newFilePath)
    if err != nil {
        return err
    }
    return nil
}

func parsePem(pemData []byte) (interface{}, error) {
    block, _ := pem.Decode(pemData)

    if block == nil {
        zlog.Error("pem decode result is empty")
        return nil, errors.New("pem_show data format error")
    }

    switch block.Type {
    case PUBLIC_KEY:
        pub, err := x509.ParsePKIXPublicKey(block.Bytes)
        if err != nil {
            return nil, err
        }
        return pub, nil
    case CERTIFICATE:
        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            return nil, err
        }
        return cert, nil
    case RSA_PRIVATE_KEY:
        private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
        if err != nil {
            return nil, err
        }
        return private, nil
    default:
        zlog.Error("no support for " + block.Type)
        return nil, errors.New("no support for " + block.Type)
    }
}

func extractPemSummaryInfo(pemResult interface{}) map[string]interface{} {
    switch pub := pemResult.(type) {
    case *rsa.PublicKey:
        zlog.Info("pem is of type Public RSA:", pub)
    case *dsa.PublicKey:
        zlog.Info("pem is of type Public DSA:", pub)
    case *ecdsa.PublicKey:
        zlog.Info("pem is of type Public ECDSA:", pub)
    case *x509.Certificate:
        zlog.Info("pem is a Certificate")
        return summaryCertificat(pemResult.(*x509.Certificate))
    case *rsa.PrivateKey:
        return nil
    default:
        zlog.Error("unknown type of key")
        return nil
    }
    return nil
}

func createPemDetailFile(pemResult interface{}, summary map[string]interface{}, newFilePath string) error {
    result := struct {
        Summary map[string]interface{}
        Detail  interface{}
    }{
        Summary: summary,
        Detail:  pemResult,
    }
    raw, err := json.MarshalIndent(result, "", "    ")
    if err != nil {
        zlog.Error("marshal json failed: ", err)
        return err
    }
    err = ioutil.WriteFile(newFilePath, raw, os.ModePerm)
    if err != nil {
        zlog.Error("write to file failed: ", err)
        return err
    }
    zlog.Info("create file ", newFilePath, " OK")
    return nil
}

func summaryCertificat(cert *x509.Certificate) map[string]interface{} {
    fields := map[string]interface{}{
        "subject":        cert.Subject.String(),
        "Issuer":         cert.Issuer.String(),
        "NotBefore":      cert.NotBefore.Format(time.RFC3339),
        "NotAfter":       cert.NotAfter.Format(time.RFC3339),
        "KeyUsage":       cert.KeyUsage,
        "IsCA":           cert.IsCA,
        "URIs":           fmt.Sprintf("%s", cert.URIs),
        "IPAddresses":    fmt.Sprintf("%s", cert.IPAddresses),
        "EmailAddresses": fmt.Sprintf("%s", cert.EmailAddresses),
        "DNSNames":       fmt.Sprintf("%s", cert.DNSNames),
    }
    zlog.WithFields(fields).Info("certificate summary: ")
    return fields
}
