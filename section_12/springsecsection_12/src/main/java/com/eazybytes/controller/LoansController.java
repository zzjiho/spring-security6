package com.eazybytes.controller;

import com.eazybytes.model.Loans;
import com.eazybytes.repository.LoanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class LoansController {

    private final LoanRepository loanRepository;

    /**
     * @PostAuthorize: PreAuthorize와 정확히 반대로 작동한다.
     *
     * 메소두 호출 중 security가 권한 부여 검사를 수행하지 않음
     * 메소드 호출이 완료되고 출력 반환시 security가 권한 부여 검사를 강제함
     *
     * 그럼 언제 이걸 사용할까?
     * 떄떄로 메소드 호출시 권한 강제할 충분한 정보가 없을 수 있음.
     */
    @GetMapping("/myLoans")
    @PostAuthorize("hasRole('USER')")
    public List<Loans> getLoanDetails(@RequestParam long id) {
        List<Loans> loans = loanRepository.findByCustomerIdOrderByStartDtDesc(id);
        if (loans != null) {
            return loans;
        } else {
            return null;
        }
    }

}
