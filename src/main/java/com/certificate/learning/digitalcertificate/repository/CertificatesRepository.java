package com.certificate.learning.digitalcertificate.repository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.certificate.learning.digitalcertificate.bean.Certificates;

import javax.transaction.Transactional;
import java.util.List;

@Repository
public interface CertificatesRepository extends CrudRepository<Certificates,Integer> {
	
	 @Query("select p from Certificates p where p.aliasname like :alias ")
	    public Certificates getcertest(@Param("alias") String aliasname);

	    @Transactional
	    @Modifying
	    @Query("update Certificates p set p.certificatetest =?2 where p.aliasname =?1")
	    public void updateByAlias(String alias, String certificatetest);

	    @Transactional
	    @Modifying
	    public void deleteById(Integer id);

	    @Query("select p from Certificates p  where p.username like :name")
	    public List<Certificates> getCertByUser(@Param("name") String username);

	    @Transactional
	    @Modifying
		public Certificates findByAlias(String alias);

}