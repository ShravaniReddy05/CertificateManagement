package com.certificate.learning.digitalcertificate.service;



import com.certificate.learning.digitalcertificate.bean.RenewForm;
import com.certificate.learning.digitalcertificate.bean.UserForm;



public interface CertificateService {
    public String generateSelfSignedCertificate(UserForm userForm) throws Exception;
    
    public String generateCaSignedCertificate(UserForm userForm) throws Exception;
    public String generateSignedCertificate(UserForm userForm);
    public String generateUnsignedCertificate(UserForm userForm) throws Exception;
    
    public String renewCertificate(RenewForm userForm);
    public String usercerts(String username) throws Exception;
}