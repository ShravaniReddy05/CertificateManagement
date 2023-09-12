package com.certificate.learning.digitalcertificate.certManagement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import com.certificate.learning.digitalcertificate.CertificateUtils;
import com.certificate.learning.digitalcertificate.EncryptionDecryptionAES;
import com.certificate.learning.digitalcertificate.bean.Certificates;

import javax.security.auth.x500.X500Principal;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;

public class unsignedCertificate {
    static {

        // adds the Bouncy castle provider to java security
        //BouncyCastle acts similar to keytool to generate certificate
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int CERTIFICATE_BITS = CertificateUtils.CERTIFICATE_BITS;
    public Certificates certificates1 = new Certificates();


    public Certificates create(String CERTIFICATE_ALIAS,String subject) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(CERTIFICATE_BITS, new SecureRandom());
        KeyPair pair = gen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        ContentSigner signGen = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
        X500Principal subj = new X500Principal(subject);
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subj, publicKey);
        PKCS10CertificationRequest csr = builder.build(signGen);
        System.out.println(builder);

        final FileOutputStream os = new FileOutputStream("src\\main\\java/" + CERTIFICATE_ALIAS + ".cer");
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.write(Base64.encode(csr.getEncoded()));
        os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.close();

        certificates1.setCertificatetest(new String(Base64.encode(csr.getEncoded())));
        certificates1.setCaflag("F");
        certificates1.setAliasname(CERTIFICATE_ALIAS);
        certificates1.setPrivatekey(new String(Base64.encode(privateKey.getEncoded())));
        certificates1.setPublickey(new String(Base64.encode(publicKey.getEncoded())));
        System.out.println(csr);
        return certificates1;
    }

    String projectRoot = System.getProperty("user.dir");
    String privateKeyPath = projectRoot + "/private.key";
    String publicKeyPath = projectRoot + "/public.key";
    String certificatePath = projectRoot + "/certificate.crt";
    String csrPath = projectRoot + "/csr.csr";
    
    
    public void saveCert(X509Certificate cert, PrivateKey key,String CERTIFICATE_ALIAS) throws Exception {
        String s = new String(Base64.encode(cert.getEncoded()));
        String enc =EncryptionDecryptionAES.encrypt(s,cert.getPublicKey());
        certificates1.setCertificatetest(enc);
        certificates1.setCaflag("T");
        certificates1.setAliasname(CERTIFICATE_ALIAS);
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
    public unsignedCertificate() throws Exception {
    }
}