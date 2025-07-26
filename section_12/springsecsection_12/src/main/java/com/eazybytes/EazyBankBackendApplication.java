package com.eazybytes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
// 특정 URL에 대한 접근 제어뿐만 아니라, 특정 기능을 수행하는 자바 메소드 자체를 누가 실행할 수 있는지 통제 가능
@EnableMethodSecurity(jsr250Enabled = true,securedEnabled = true)
public class EazyBankBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(EazyBankBackendApplication.class, args);
    }

}
