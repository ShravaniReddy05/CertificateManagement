package com.certificate.learning.digitalcertificate.certManagement;


import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.certificate.learning.digitalcertificate.CertificateUtils;
import com.certificate.learning.digitalcertificate.EncryptionDecryptionAES;
import com.certificate.learning.digitalcertificate.bean.Certificates;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SelfSignedCertificateGenerator {



    public Certificates certificates1 = new Certificates();

    private static final String CERTIFICATE_ALGORITHM = CertificateUtils.CERTIFICATE_ALGORITHM;
    private static final int IssueYears= CertificateUtils.Issue_Years;
    private static final int CERTIFICATE_BITS = CertificateUtils.CERTIFICATE_BITS;

    static {

        // adds the Bouncy castle provider to java security
        //BouncyCastle acts similar to keytool to generate certificate
        Security.addProvider(new BouncyCastleProvider());
    }


    public X509Certificate createCertificate(String CERTIFICATE_ALIAS,String CERTIFICATE_DN) throws Exception{
        X509Certificate cert = null;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CERTIFICATE_ALGORITHM);
        //key is generated with the number of bits specified...SecureRandom() is PRNG
        keyPairGenerator.initialize(CERTIFICATE_BITS, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        // GENERATE THE X509 CERTIFICATE
        X509V3CertificateGenerator v3CertGen =  new X509V3CertificateGenerator();
        v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        v3CertGen.setIssuerDN(new X509Principal(CERTIFICATE_DN));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24*2));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24*365*IssueYears)));
        v3CertGen.setSubjectDN(new X509Principal(CERTIFICATE_DN));
        v3CertGen.setPublicKey(keyPair.getPublic());
        v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        //for self signed cert
        v3CertGen.addExtension(X509Extensions.BasicConstraints.getId(),true,new BasicConstraints(false));
        cert = v3CertGen.generateX509Certificate(keyPair.getPrivate());
        saveCert(cert,keyPair.getPrivate(),CERTIFICATE_ALIAS);
        return cert;
    }


    public Certificates saveFile(X509Certificate cert,String Filename) throws Exception {
        final FileOutputStream os = new FileOutputStream(Filename);
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.write(Base64.encode(cert.getEncoded()));
        os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        //certificateRepository.save(certificates1);
        os.close();
        System.out.println();
        return certificates1;
    }
    String projectRoot = System.getProperty("user.dir");
    String privateKeyPath = projectRoot + "/private.key";
    String publicKeyPath = projectRoot + "/public.key";
    String certificatePath = projectRoot + "/certificate.crt";
    String csrPath = projectRoot + "/csr.csr";
    
    public void saveCert(X509Certificate cert, PrivateKey key,String CERTIFICATE_ALIAS) throws Exception {
        String s = new String(Base64.encode(cert.getEncoded()));
        String enc = EncryptionDecryptionAES.encrypt(s,cert.getPublicKey());
        certificates1.setCertificatetest(enc);
        certificates1.setCaflag("F");
        certificates1.setAliasname(CERTIFICATE_ALIAS);
        certificates1.setId(CERTIFICATE_ALIAS);
        certificates1.setPrivatekey(new String(Base64.encode(key.getEncoded())));
        certificates1.setPublickey(new String(Base64.encode(cert.getPublicKey().getEncoded())));

     // Save the private key to a file
        try (FileOutputStream privateKeyFile = new FileOutputStream(privateKeyPath)) {
            privateKeyFile.write(Base64.encode(key.getEncoded()));
        }

        // Save the public key to a file
        try (FileOutputStream publicKeyFile = new FileOutputStream(publicKeyPath)) {
            publicKeyFile.write(Base64.encode(cert.getPublicKey().getEncoded()));
        }

        // Save the certificate to a file
        try (FileOutputStream certificateFile = new FileOutputStream(certificatePath)) {
            certificateFile.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
            certificateFile.write(Base64.encode(cert.getEncoded()));
            certificateFile.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        }
        
        System.out.println("Private Key Path: " + privateKeyPath);
        System.out.println("Public Key Path: " + publicKeyPath);
        System.out.println("Certificate Path: " + certificatePath);
        System.out.println("CSR Path: " + csrPath);
    }
}
 



