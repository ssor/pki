package main

import (
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "io/ioutil"
    "log"
    "os"
    "time"

    "gopkg.in/yaml.v2"
    "github.com/ssor/pki/easypki/pkg/certificate"
    "github.com/ssor/pki/easypki/pkg/easypki"
    "github.com/ssor/zlog"
    "github.com/alexflint/go-arg"
    "github.com/ssor/pki/easypki/pem_show"
    "path/filepath"
)

const (
    PKI   = "pki"
    PEM   = "pem"
    CHAIN = "chain"
)

type InputArgs struct {
    // pki or pem_show or chain
    Cmd        string `arg:"required" help:"Use pki or pem or chain"`
    CaName     string `help:"CA Name"` // args for build PKI chain files
    BundleName string                  // args for build PKI chain files
    DbPath     string                  // args for build PKI chain files
    ConfigPath string                  // args for build PKI chain files
    PemFileDir string `help:"Dir of crt or key file with pem format"`
    PemFile    string `help:"Specified pem file"`
}

func (InputArgs) Version() string {
    return "version 0.1.0"
}
func (InputArgs) Description() string {
    return `This program is used as PKI tool.
    Use pki, generate a PKI example through config file
        dbPath, bundleName, configPath, CaName is needed
    Use pem, generate human readable details of certificate file
        PemFile or PemFileDir is needed
    Use chain, show how the PKI system working (developing)`
}

func main() {
    zlog.SetLevel(zlog.DebugLevel)

    var args InputArgs
    args.DbPath = "ca_files"
    args.ConfigPath = "pki.yaml"
    arg.MustParse(&args)

    switch args.Cmd {
    case PKI:
        buildPKI(args.DbPath, args.BundleName, args.ConfigPath, args.CaName)
    case PEM:
        showPemContent(args.PemFile, args.PemFileDir)
    case CHAIN:
    default:
        zlog.Error("cmd name not supported now")
        return
    }
}

func showPemContent(pemPath, pemDir string) {
    if len(pemPath) <= 0 && len(pemDir) <= 0 {
        zlog.Error("no pem_show file or dir set")
        return
    }
    err := pem_show.ShowPem(pemPath)
    if err != nil {
        zlog.WithError(err).Error("show pem failed")
    }
    showPemFileDir(pemDir)
}

func showPemFileDir(pemDir string) {
    if len(pemDir)<=0{
        return
    }

    err := filepath.Walk(pemDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            zlog.WithError(err).WithField("path", path).Error("error occored alreay")
            return err
        }
        if info.IsDir() {
            return nil
        }
        ext := filepath.Ext(info.Name())
        switch ext {
        case ".crt", ".key":
            zlog.Info("visited file: ", path)
            err = pem_show.ShowPem(path)
            if err != nil {
                return err
            }
        default:
            zlog.Warn("skip file: ", path)
        }
        return nil
    })

    if err != nil {
        zlog.WithError(err).Error("error walking the path ", pemDir)
    }
}

func buildPKI(dbPath, bundleName, configPath, caName string) {

    err := os.MkdirAll(dbPath, os.ModePerm)
    if err != nil {
        log.Fatal("create output dir failed: ", err)
    }

    pki := &easypki.EasyPKI{Store: &easypki.Local{Root: dbPath}}
    if bundleName != "" {
        get(pki, caName, bundleName, true)
        return
    }
    build(pki, configPath)
}

type configCerts struct {
    Name           string        `yaml:"name"`
    CommonName     string        `yaml:"commonName"`
    DNSNames       []string      `yaml:"dnsNames"`
    EmailAddresses []string      `yaml:"emailAddresses"`
    IsCA           bool          `yaml:"isCA"`
    IsClient       bool          `yaml:"isClient"`
    Signer         string        `yaml:"signer"`
    Expire         time.Duration `yaml:"expire"`
}

type config struct {
    Subject pkix.Name      `yaml:"subject"`
    Certs   []*configCerts `yaml:"certs"`
}

// build create a full PKI based on a yaml configuration.
func build(pki *easypki.EasyPKI, configPath string) {
    b, err := ioutil.ReadFile(configPath)
    if err != nil {
        log.Fatalf("Failed reading configuration file %v: %v", configPath, err)
    }
    conf := &config{}
    if err := yaml.Unmarshal(b, conf); err != nil {
        log.Fatalf("Failed umarshaling yaml config (%v) %v: %v", configPath, string(b), err)
    }

    for _, cert := range conf.Certs {
        sign(pki, cert, conf.Subject)
    }
}

func sign(pki *easypki.EasyPKI, cert *configCerts, subject pkix.Name) {
    req := &easypki.Request{
        Name: cert.Name,
        Template: &x509.Certificate{
            Subject:        subject,
            NotAfter:       time.Now().Add(cert.Expire),
            IsCA:           cert.IsCA,
            DNSNames:       cert.DNSNames,
            EmailAddresses: cert.EmailAddresses,
        },
        IsClientCertificate: cert.IsClient,
    }
    if cert.IsCA {
        req.Template.MaxPathLen = -1
    }
    req.Template.Subject.CommonName = cert.CommonName

    var signer *certificate.Bundle
    var err error
    if cert.Signer != "" { // root ca not need
        signer, err = pki.GetCA(cert.Signer)
        if err != nil {
            log.Fatalf("Cannot sign %v because cannot get CA %v: %v", cert.Name, cert.Signer, err)
        }
    }
    if err := pki.Sign(signer, req); err != nil {
        log.Fatalf("Cannot create bundle for %v: %v", cert.Name, err)
    }
}

// get retrieves a bundle from the bolt database. If fullChain is true, the
// certificate will be the chain of trust from the primary tup to root CA.
func get(pki *easypki.EasyPKI, caName, bundleName string, fullChain bool) {
    var bundle *certificate.Bundle
    if caName == "" {
        caName = bundleName
    }
    bundle, err := pki.GetBundle(caName, bundleName)
    if err != nil {
        log.Fatalf("Failed getting bundle %v within CA %v: %v", bundleName, caName, err)
    }
    leaf := bundle
    chain := []*certificate.Bundle{bundle}
    if fullChain {
        for {
            if leaf.Cert.Issuer.CommonName == leaf.Cert.Subject.CommonName {
                break
            }
            ca, err := pki.GetCA(leaf.Cert.Issuer.CommonName)
            if err != nil {
                log.Fatalf("Failed getting signing CA %v: %v", leaf.Cert.Issuer.CommonName, err)
            }
            chain = append(chain, ca)
            leaf = ca
        }
    }
    key, err := os.Create(bundleName + ".key")
    if err != nil {
        log.Fatalf("Failed creating key output file: %v", err)
    }
    if err := pem.Encode(key, &pem.Block{
        Bytes: x509.MarshalPKCS1PrivateKey(bundle.Key),
        Type:  "RSA PRIVATE KEY",
    }); err != nil {
        log.Fatalf("Failed ecoding private key: %v", err)
    }
    crtName := bundleName + ".crt"
    if fullChain {
        crtName = bundleName + "+chain.crt"
    }
    cert, err := os.Create(crtName)
    if err != nil {
        log.Fatalf("Failed creating chain output file: %v", err)
    }
    for _, c := range chain {
        if err := pem.Encode(cert, &pem.Block{
            Bytes: c.Cert.Raw,
            Type:  "CERTIFICATE",
        }); err != nil {
            log.Fatalf("Failed ecoding %v certificate: %v", c.Name, err)
        }
    }
}
