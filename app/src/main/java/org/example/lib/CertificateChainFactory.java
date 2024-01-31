package org.example.lib;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateChainFactory {

    public static KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance("JKS");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void load(KeyStore jks, String path, String password) {
        try {
            jks.load(new FileInputStream(path), password.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate generateCertificate(String cn, KeyPair keyPair, String issuerCN, KeyPair issuerKeyPair, boolean isCaCertificate,
                                                      int validityYears, Extension... extensions) {
        try {
            if (issuerCN == null) {
                issuerCN = cn;
            }
            if (issuerKeyPair == null) {
                issuerKeyPair = keyPair;
            }
            return issueCertificate(issuerCN, cn, issuerKeyPair, keyPair, isCaCertificate, validityYears, extensions);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate issueCertificate(String issuerCN, String cn, KeyPair issuerKeyPair, KeyPair issuedKeyPair, boolean isCACertificate,
                                                   int validityYears, Extension... extensions)
            throws NoSuchAlgorithmException, OperatorCreationException, CertIOException, CertificateException {

        BigInteger serialNumber = new BigInteger(512, new Random()); //
        X500Name issuerDN = new X500Name(issuerCN);
        X500Name subjectDN = new X500Name(cn);
        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.YEAR, validityYears);
        Date notAfter = cal.getTime();
        // Subject public key
        byte[] publicKey;
        KeyPair keyPair;
        if (issuedKeyPair == null) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096);
            keyPair = keyGen.generateKeyPair();
            publicKey = keyPair.getPublic().getEncoded();
        } else {
            keyPair = issuedKeyPair;
            publicKey = issuedKeyPair.getPublic().getEncoded();
        }
        SubjectPublicKeyInfo subjectPublicKey = SubjectPublicKeyInfo.getInstance(publicKey);

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN,
                subjectPublicKey);

        // Authority Key Identifier
        AuthorityKeyIdentifier authorityKeyIdentifier = createAuthorityKeyIdentifier(issuerKeyPair.getPublic());
        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);

        // Subject Key Identifier
        SubjectKeyIdentifier subjectKeyIdentifier = createSubjectKeyIdentifier(keyPair.getPublic());
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        // Basic Constraints
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCACertificate)); // last value corresponds to
        // whether this is a CA certificate or not

        if (extensions != null) {
            for (Extension extension : extensions) {
                certificateGenerator.addExtension(extension);
            }
        }

        X509CertificateHolder certHolder = certificateGenerator
                .build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(issuerKeyPair.getPrivate()));

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public static AuthorityKeyIdentifier createAuthorityKeyIdentifier(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

    // Copied from CertificateFactory class
    public static SubjectKeyIdentifier createSubjectKeyIdentifier(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }

    public static Extension createExtendedKeyUsage() throws IOException {
        // Create an ExtendedKeyUsage extension for Server and Client Authentication
        KeyPurposeId serverAuthPurpose = KeyPurposeId.id_kp_serverAuth;
        KeyPurposeId clientAuthPurpose = KeyPurposeId.id_kp_clientAuth;
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[] { serverAuthPurpose, clientAuthPurpose });
        ASN1Sequence seq = ASN1Sequence.getInstance(extendedKeyUsage.toASN1Primitive());
        return new Extension(Extension.extendedKeyUsage, false, seq.getEncoded());
    }

    public static Extension createSubjectAlternativeNames() throws IOException {
        GeneralName[] sanEntries = new GeneralName[] { new GeneralName(GeneralName.dNSName, "localhost")
                // new GeneralName(GeneralName.iPAddress, "192.168.1.1"),
                // Add more SAN entries as needed
        };

        GeneralNames subjectAltNames = new GeneralNames(sanEntries);
        return new Extension(Extension.subjectAlternativeName, false, subjectAltNames.getEncoded());
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyGen = getKeyPairGenerator();
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance("RSA");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyStore generateKeyStore(Key privateKey, X509Certificate certificate, String password) {
        java.security.KeyStore jks = getKeyStore();
        load(jks);
        setKeyEntry(privateKey, certificate, password.toCharArray(), jks);
        return jks;
    }

    public static void load(KeyStore jks) {
        try {
            jks.load(null, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void setKeyEntry(
            Key privateKey,
            X509Certificate certificate,
            char[] password,
            KeyStore jks) {
        try {
            jks.setKeyEntry("key", privateKey, password, new Certificate[]{ certificate });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getCrl(X509Certificate rootCert, PrivateKey rootKey, X509Certificate cert) throws Exception
    {
        Date date = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));

        var generator = new JcaX509v2CRLBuilder(cert.getIssuerX500Principal(), date);
        generator.addCRLEntry(cert.getSerialNumber(), date, CRLReason.keyCompromise);
        generator.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(rootCert));
        generator.addExtension(Extension.cRLNumber, false, new CRLNumber(new BigInteger("1000")));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(rootKey);

        X509CRL crl = new JcaX509CRLConverter().getCRL(generator.build(signer));
        return crl.getEncoded();
    }

    public static X509Certificate getCert(KeyStore keyStore) throws Exception {
        return (X509Certificate) keyStore.getCertificate(keyStore.aliases().nextElement());
    }

    public static PrivateKey getKey(KeyStore keyStore, String password) throws Exception {
        return (PrivateKey) keyStore.getKey(keyStore.aliases().nextElement(), password.toCharArray());
    }

    public static byte[] getOcspResponse(byte[] req, X509Certificate ocspResponder, PrivateKey privateKey, boolean includeResponderCertificateInResponse) throws Exception
    {
        OCSPReq ocspRequest = new OCSPReq(req);
        Req[] requestList = ocspRequest.getRequestList();

        X509CertificateHolder holder = new X509CertificateHolder(org.bouncycastle.asn1.x509.Certificate.getInstance(ocspResponder));
        var builder = new BasicOCSPRespBuilder(new RespID(holder.getSubject()));

        Calendar thisUpdate = new GregorianCalendar();
        Date now = thisUpdate.getTime();
        thisUpdate.add(Calendar.DAY_OF_MONTH, -2);
        Date before = thisUpdate.getTime();
        thisUpdate.add(Calendar.DAY_OF_MONTH, 7);
        Date nexUpdate = thisUpdate.getTime();

        CertificateStatus certificateStatus = Files.exists(Path.of("revoked"))
                ? new RevokedStatus(before, 16)
                : Files.exists(Path.of("unknown"))
                ? new UnknownStatus()
                : CertificateStatus.GOOD;

        for (Req request: requestList) {
            builder.addResponse(request.getCertID(), certificateStatus, now, nexUpdate, null);
        }

        Extension extNonce = ocspRequest.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));
        if (extNonce != null) {
            builder.setResponseExtensions(new Extensions(extNonce));
        }

        X509CertificateHolder[] chain = includeResponderCertificateInResponse
                ? new X509CertificateHolder[]{ holder }
                : new X509CertificateHolder[0];

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
        BasicOCSPResp ocspResponse = builder.build(signer, chain, Calendar.getInstance().getTime());
        OCSPRespBuilder ocspResponseBuilder = new OCSPRespBuilder();
        return ocspResponseBuilder.build(OCSPRespBuilder.SUCCESSFUL, ocspResponse).getEncoded();
    }
}
