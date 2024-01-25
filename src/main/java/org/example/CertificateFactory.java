package org.example;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class CertificateFactory {

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyGen = getKeyPairGenerator();
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static KeyStore generateKeyStore(Key privateKey, X509Certificate certificate, String password) {
        java.security.KeyStore jks = getKeyStore();
        load(jks);
        setKeyEntry(privateKey, certificate, password.toCharArray(), jks);
        return jks;
    }

    public static X509Certificate generateCertificate(KeyPair keyPair) {
        Instant now = Instant.now().minus(1, ChronoUnit.DAYS);
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        X500Name x500Name = new X500Name("CN=localhost");
        BigInteger serial = BigInteger.valueOf(now.toEpochMilli());

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        DigestCalculator digestCalculator = getDigestCalculator(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        SubjectKeyIdentifier subjectKeyId = new X509ExtensionUtils(digestCalculator).createSubjectKeyIdentifier(publicKeyInfo);
        AuthorityKeyIdentifier authorityKeyId = new X509ExtensionUtils(digestCalculator).createAuthorityKeyIdentifier(publicKeyInfo);

        var builder = new JcaX509v3CertificateBuilder(x500Name, serial, notBefore, notAfter, x500Name, keyPair.getPublic());
        addExtension(builder, Extension.subjectKeyIdentifier, false, subjectKeyId);
        addExtension(builder, Extension.authorityKeyIdentifier, false, authorityKeyId);
        addExtension(builder, Extension.basicConstraints, true, new BasicConstraints(true));

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        ContentSigner contentSigner = build(keyPair, contentSignerBuilder);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());
        return getCertificate(builder, contentSigner, converter);
    }

    public static KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance("RSA");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance("JKS");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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

    public static DigestCalculator getDigestCalculator(AlgorithmIdentifier algorithmIdentifier) {
        try {
            return new BcDigestCalculatorProvider().get(algorithmIdentifier);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void addExtension(
            X509v3CertificateBuilder builder,
            ASN1ObjectIdentifier oid,
            boolean isCritical,
            ASN1Encodable value) {
        try {
            builder.addExtension(oid, isCritical, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ContentSigner build(KeyPair keyPair, JcaContentSignerBuilder contentSignerBuilder) {
        try {
            return contentSignerBuilder.build(keyPair.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate getCertificate(
            JcaX509v3CertificateBuilder builder,
            ContentSigner contentSigner,
            JcaX509CertificateConverter converter) {
        try {
            return converter.getCertificate(builder.build(contentSigner));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}