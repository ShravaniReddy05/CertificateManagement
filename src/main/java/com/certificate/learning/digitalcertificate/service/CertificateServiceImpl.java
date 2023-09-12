package com.certificate.learning.digitalcertificate.service;


import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.certificate.learning.digitalcertificate.EncryptionDecryptionAES;
import com.certificate.learning.digitalcertificate.Exception.CertificatesNotFoundException;
import com.certificate.learning.digitalcertificate.bean.Certificates;
import com.certificate.learning.digitalcertificate.bean.RenewForm;
import com.certificate.learning.digitalcertificate.bean.UserForm;
import com.certificate.learning.digitalcertificate.certManagement.CaSignedCertificateGenerator;
import com.certificate.learning.digitalcertificate.certManagement.RenewCertificate;
import com.certificate.learning.digitalcertificate.certManagement.SelfSignedCertificateGenerator;
import com.certificate.learning.digitalcertificate.certManagement.SignedCertificateGenerator;
import com.certificate.learning.digitalcertificate.certManagement.unsignedCertificate;
import com.certificate.learning.digitalcertificate.repository.CertificatesRepository;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;


@EnableScheduling
@Service
public class CertificateServiceImpl implements CertificateService{

    @Autowired
    private CertificatesRepository certificatesRepository;

    @Override
    @Transactional
    public String generateSelfSignedCertificate(UserForm userForm) throws Exception {
        try {
            SelfSignedCertificateGenerator c = new SelfSignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L=" + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E=" + userForm.getEmail();
            X509Certificate cer = c.createCertificate(userForm.getAlias(), CERTIFICATE_DN);
            Certificates s = c.saveFile(cer, "src\\main\\java/" + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
            
            return new String(Base64.encode(cer.getEncoded()));
        }
        catch(Exception e) {
        	e.printStackTrace();
            throw new CertificatesNotFoundException("");
        }

    }


    @Override
    public String generateCaSignedCertificate(UserForm userForm)  {
        try {
            CaSignedCertificateGenerator c = new CaSignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L=" + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E=" + userForm.getEmail();
            X509Certificate cert = c.createCertificate(userForm.getAlias(), CERTIFICATE_DN);
            Certificates s = c.saveFile(cert, "src\\main\\java/" + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
           
            return new String(Base64.encode(cert.getEncoded()));
        }
        catch(Exception e) {
            throw new CertificatesNotFoundException("Service: Issue while generating CA Signed cetificate: "+e.getMessage());
        }
    }


    @Override
    public String generateUnsignedCertificate(UserForm userForm) throws Exception {
        try {
            unsignedCertificate c = new unsignedCertificate();
            String CERTIFICATE_DN = "C= " + userForm.getCountry() + ", ST=" + userForm.getState() +", L=" + userForm.getLocality() +", O=" + userForm.getOrganization() +  ", OU=Telstra India, CN=" + userForm.getCn()+  ", EMAILADDRESS=" + userForm.getEmail();
            Certificates cert = c.create(userForm.getAlias(), CERTIFICATE_DN);
            
            cert.setMail(userForm.getEmail());
            cert.setUsername(userForm.getName());
            
            return cert.getCertificatetest();
        }
        catch(Exception e) {
            throw new CertificatesNotFoundException("Service: Issue while generating CA Signed cetificate: "+e.getMessage());
        }
    }

    @Override
    public String generateSignedCertificate(UserForm userForm) {
        try {
            Certificates certificates = certificatesRepository.findById(1).get();
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));
            String dec= EncryptionDecryptionAES.decrypt(certificates.getCertificatetest(),pk);
            X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);


            SignedCertificateGenerator c = new SignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L=" + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E=" + userForm.getEmail();
            X509Certificate certi = c.createSignedCertificate(certificate, pk, CERTIFICATE_DN, userForm.getAlias());
            Certificates s = c.saveFile(certi, "src\\main\\java/" + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
           
            return new String(Base64.encode(certi.getEncoded()));
        } catch (Exception e) {
            throw new CertificatesNotFoundException("Service: Certificate Not Found: calocal.test is not found in db to generate a your signed certificate");
        }

    }
    
    
    
    
    @Override
    public String renewCertificate(RenewForm userForm) {
        String res = "";
        FileInputStream is = null;
        try {
            Certificates certificates = certificatesRepository.findById(1).get();
        	//Certificates certificates = certificatesRepository.findByAlias(userForm.getAlias());
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));

            Certificates m = certificatesRepository.getcertest(userForm.getAlias());
            PrivateKey pkm = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String dec= EncryptionDecryptionAES.decrypt(m.getCertificatetest(),pkm);
            X509Certificate certi = EncryptionDecryptionAES.convertToX509Cert(dec);

            RenewCertificate renewedCertificate = new RenewCertificate();
            long l = ((certi.getNotAfter().getTime() - (new Date(System.currentTimeMillis()).getTime())) / ((1000 * 60 * 60 * 24)));
            System.out.println("certificate will expire in: "+l+" days");
            if (l <= 0) {
                return "certificate expired, request for new one";
            } else if (l > 0 && l < 10) {
                X509Certificate c = renewedCertificate.renewCertificate(certi, pk, userForm.getRenewYears(), userForm.getAlias());
                Certificates s = renewedCertificate.saveFile(c, "src\\main\\java/" + userForm.getAlias() + ".cer");
                certificatesRepository.updateByAlias(userForm.getAlias(), s.getCertificatetest());
        
                return "Certificate renewed successfully";
            } else {
                return "There is still time for renewal";
            }

        } catch (Exception e) {
            throw new CertificatesNotFoundException("----Service: Certificate Not Found: The certificate you are tyring to renew is not found in db");
//            e.printStackTrace();
        } finally {
            if (null != is) {
                try {
                    is.close();
                } catch (IOException e) {
                    throw new CertificatesNotFoundException("Service: Certificate Not Found: The certificate you are tyring to renew is not found in db");
//                    e.printStackTrace();
                }
            }
        }
//        return res;
    }

   /* @Override
    public String renewCertificate(RenewForm userForm) {
        String res = "";
        FileInputStream is = null;
        try {
            // Retrieve the certificate with the specified alias name
            Certificates certificates = certificatesRepository.findByAlias(userForm.getAlias());

            if (certificates == null) {
                return "Certificate not found for alias: " + userForm.getAlias();
            }

            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));

            // Decrypt the certificate's content and convert it to X509Certificate
            String dec = EncryptionDecryptionAES.decrypt(certificates.getCertificatetest(), pk);
            X509Certificate certi = EncryptionDecryptionAES.convertToX509Cert(dec);

            RenewCertificate renewedCertificate = new RenewCertificate();
            long l = ((certi.getNotAfter().getTime() - (new Date(System.currentTimeMillis()).getTime())) / ((1000 * 60 * 60 * 24)));
            System.out.println("Certificate will expire in: " + l + " days");

            if (l <= 0) {
                return "Certificate expired, request for a new one";
            } else if (l > 0 && l < 10) {
                X509Certificate c = renewedCertificate.renewCertificate(certi, pk, userForm.getRenewYears(), userForm.getAlias());
                Certificates s = renewedCertificate.saveFile(c, "src\\main\\java/" + userForm.getAlias() + ".cer");
                certificatesRepository.updateByAlias(userForm.getAlias(), s.getCertificatetest());

                return "Certificate renewed successfully";
            } else {
                return "There is still time for renewal";
            }
        } catch (CertificatesNotFoundException e) {
            // Handle specific CertificatesNotFoundException
            return e.getMessage();
        } catch (Exception e) {
            // Handle other exceptions
            e.printStackTrace();
            return "An error occurred during certificate renewal.";
        } finally {
            if (null != is) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
*/
    
    @Override
    public String usercerts(String username) throws Exception {
        String res="";
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        List<Certificates> list = certificatesRepository.getCertByUser(username);
        if(list.size()==0)
            return "no certificates yet";
        for(Certificates m : list){
            ArrayList<String> temp = new ArrayList<>();
            PrivateKey pkm = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String dec= EncryptionDecryptionAES.decrypt(m.getCertificatetest(),pkm);
            X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);
            res += m.getAliasname()+","+certificate.getNotBefore().toGMTString()+","+certificate.getNotAfter().toGMTString()+"\n";

        }
        return res.substring(0,res.length()-1);

    }



   
	}