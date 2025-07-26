package com.eazybytes.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;

import com.eazybytes.model.Loans;

@Repository
public interface LoanRepository extends CrudRepository<Loans, Long> {

	/**
	 * @PreAuthorize: 메소드 호출 전에 security가 권한 부여 검사를 수행함
	 *
	 * 메소드 호출이 시작되기 전에 권한 부여 검사를 수행하고, 권한이 없으면 메소드가 호출되지 않음
	 */
	// @PreAuthorize("hasRole('USER')")
	List<Loans> findByCustomerIdOrderByStartDtDesc(long customerId);

}
