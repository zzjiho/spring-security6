package com.eazybytes.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SecureController {

    @GetMapping("/secure")
    public String securePage(Authentication authentication) {
        // authentication 객체가 OAuth2AuthenticationToken 인지 UsernamePasswordAuthenticationToken인지 확인
        // id/pwd 기반이냐 oauth 냐 확인
        if(authentication instanceof UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken){
            System.out.println(usernamePasswordAuthenticationToken);
        } else if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
            System.out.println(oAuth2AuthenticationToken);
        }
        return "secure.html";
    }

}
