package com.certificate.learning.digitalcertificate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
public class DigitalcertificateApplication {

	public static void main(String[] args) {
		SpringApplication.run(DigitalcertificateApplication.class, args);
	}

}
