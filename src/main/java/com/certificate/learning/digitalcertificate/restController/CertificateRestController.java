package com.certificate.learning.digitalcertificate.restController;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.certificate.learning.digitalcertificate.Exception.CertificatesNotFoundException;
import com.certificate.learning.digitalcertificate.bean.RenewForm;
import com.certificate.learning.digitalcertificate.bean.UserForm;
import com.certificate.learning.digitalcertificate.service.CertificateService;

@RestController
public class CertificateRestController {
    @Autowired
    private CertificateService certificateService;




    @PostMapping("/ss")
    public ResponseEntity<String> ssCertificate(@RequestBody UserForm userForm) throws Exception {
        try {
            String res=certificateService.generateSelfSignedCertificate(userForm);
            System.out.println(res);
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        catch(Exception e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }
    
    @PostMapping("/ca")
    public ResponseEntity<String> caSignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
        try {
            String res=certificateService.generateCaSignedCertificate(userForm);
            System.out.println(res);
            return new ResponseEntity<>(res, HttpStatus.OK);

        }
        catch(Exception e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }
    
    @PostMapping("/signed")
    public ResponseEntity<String> SignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
        try {
            String res =certificateService.generateSignedCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
        
        
        

    }
    
    
    @PostMapping("/unsigned")
    public ResponseEntity<String> UnsignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
        try {
            String res =certificateService.generateUnsignedCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }

    }
    
    
    @PutMapping("/renew")
    public ResponseEntity<String> CertificateRenewal(@RequestBody RenewForm userForm) throws Exception {
        try {
            String res =certificateService.renewCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        catch (CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }
    @GetMapping("/certs/{name}")
    public ResponseEntity<String> usercerts(@PathVariable("name") String name) throws Exception {
        return new ResponseEntity<>(certificateService.usercerts(name),HttpStatus.OK);
    }
}
