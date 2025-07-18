package com.eazybytes.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * AuthenticationProvider는
 * 사용자가 제시한 인증 정보(예: 아이디/비밀번호)가 유효한지 실제로 "검증"하는 책임을 가진 컴포넌트
 *
 * 어떤 AuthenticationProvider는 아이디/비밀번호 방식만 처리하고,
 * 다른 AuthenticationProvider는 LDAP 인증이나 OAuth 토큰을 처리할 수 있다.
 *
 */

@Component
@Profile("prod")
@RequiredArgsConstructor
public class EazyBankProdUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     * authenticate 메서드는 인증 로직의 실질적인 구현이 이루어짐
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (passwordEncoder.matches(pwd, userDetails.getPassword())) {
            // Fetch Age details and perform validation to check if age >18
            return new UsernamePasswordAuthenticationToken(username,pwd,userDetails.getAuthorities());
        }else {
            throw new BadCredentialsException("Invalid password!");
        }
    }

    /**
     * 사용자 인증 요청이 들어왔을 때, AuthenticationManager는 이 요청을 어떤 Provider에게 맡겨야 할지 결정해야 함
     * 이때 supports 메소드가 사용
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
