package com.eazybytes.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Spring Authorization Server와 관련된 모든 보안 설정을 담당하는 클래스.
 * 이 클래스는 두 개의 주요 SecurityFilterChain을 설정합니다:
 * 1. 인증 서버 자체의 엔드포인트(/oauth2/authorize, /oauth2/token 등)를 위한 필터 체인.
 * 2. 사용자가 로그인하는 일반적인 웹 페이지를 위한 필터 체인.
 */
@Configuration
@EnableWebSecurity
public class ProjectSecurityConfig {

    /**
     * Spring Authorization Server의 프로토콜 엔드포인트를 위한 SecurityFilterChain을 설정합니다.
     * @Order(1)을 통해 이 필터 체인이 다른 필터 체인보다 먼저 실행되도록 우선순위를 부여합니다.
     * 인증 서버의 핵심 기능(인가, 토큰 발급 등)을 처리하므로 가장 먼저 처리되어야 합니다.
     */
    @Bean @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // Spring Authorization Server의 기본 설정을 적용
        // 이 한 줄이 /oauth2/authorize, /oauth2/token, /oauth2/jwks, /.well-known/openid-configuration 등의
        // 표준 엔드포인트들을 자동으로 구성
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // OIDC(OpenID Connect 1.0) 기능을 활성화
        // 이를 통해 /userinfo 엔드포인트와 ID Token 발급이 가능
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0
        http
                // 인증되지 않은 사용자가 인증 서버의 보호된 엔드포인트에 접근할 때의 처리를 설정
                .exceptionHandling((exceptions) -> exceptions
                        // 브라우저(HTML)를 통해 접근한 경우, Spring Security의 기본 로그인 페이지 대신
                        // 우리가 정의한 '/login' 경로로 리디렉션
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // 사용자 정보(/userinfo)나 클라이언트 등록 정보를 가져오기 위한 access token을 처리하는
                // 리소스 서버 설정을 추가. 인증 서버 자신이 리소스 서버 역할을 겸하는 것.
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    /**
     * 일반적인 애플리케이션의 인증(로그인 등)을 위한 SecurityFilterChain을 설정합니다.
     * @Order(2)를 통해 authorizationServerSecurityFilterChain 다음에 실행되도록 합니다.
     *
     * @param http HttpSecurity 객체
     * @return SecurityFilterChain 빈
     * @throws Exception 설정 중 발생할 수 있는 예외
     */
    @Bean @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                // 모든 HTTP 요청은 반드시 인증된 사용자만 접근 가능하도록 설정합니다.
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // 폼 기반 로그인을 활성화합니다.
                // 위 authorizationServerSecurityFilterChain에서 '/login'으로 리디렉션 시,
                // 이 필터 체인의 폼 로그인이 해당 요청을 받아 로그인 페이지를 보여주고 인증을 처리합니다.
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * 이 인증 서버에 등록된 클라이언트(애플리케이션)들의 정보를 관리하는 저장소를 설정.
     * 실무에서는 DB와 연동되는 JdbcRegisteredClientRepository를 사용해야 하지만,
     * 여기서는 데모를 위해 메모리 기반의 InMemoryRegisteredClientRepository를 사용.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Client Credentials Grant Type을 사용하는 클라이언트 (Machine-to-Machine 통신용)
        // 발급되는 토큰은 Self-Contained JWT.
        RegisteredClient clientCredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("eazybankapi")
                .clientSecret("{noop}VxubZgAXyyTq9lGjj3qGvWNsHtE4SqTq") // {noop}은 비밀번호를 암호화하지 않겠다는 의미(데모용)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Basic 인증 헤더로 클라이언트 인증
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // 허용된 인가 타입
                .scopes(scopeConfig -> scopeConfig.addAll(List.of(OidcScopes.OPENID, "ADMIN", "USER"))) // 요청 가능한 스코프
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10)) // 토큰 유효기간
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()).build(); // JWT 형식으로 전달

        // Token Introspection을 위한 클라이언트.
        // 발급되는 토큰은 Reference(Opaque) Token임. 이 토큰은 내용을 알 수 없으며,
        // 리소스 서버는 이 토큰을 받으면 인증 서버의 Introspection 엔드포인트에 유효성을 문의해야 한다.
        RegisteredClient introspectClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("eazybankintrospect")
                .clientSecret("{noop}c1BK9Bg2REeydBbvUoUeKCbD2bvJzXGj")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(scopeConfig -> scopeConfig.addAll(List.of(OidcScopes.OPENID)))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE).build()).build();

        // Authorization Code Grant Type을 사용하는 클라이언트 (전통적인 웹 애플리케이션용)
        RegisteredClient authCodeClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("eazybankclient")
                .clientSecret("{noop}Qw3rTy6UjMnB9zXcV2pL0sKjHn5TxQqB")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // 폼 파라미터로 클라이언트 인증
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Basic 인증 헤더로도 인증 가능
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // 인가 코드 그랜트
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 리프레시 토큰 사용 가능
                .redirectUri("https://oauth.pstmn.io/v1/callback") // 인가 코드 전달 후 리디렉션될 URI
                .scope(OidcScopes.OPENID).scope(OidcScopes.EMAIL) // OIDC 스코프 요청 가능
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofHours(8)).reuseRefreshTokens(false) // false 로 하면 리프레시 토큰은 한번만 사용 (보안상)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()).build();

        // PKCE(Proof Key for Code Exchange)를 사용하는 Public 클라이언트 (SPA, 모바일 앱용)
        RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("eazypublicclient")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public 클라이언트는 Secret을 안전하게 저장할 수 없으므로 사용 안함
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope(OidcScopes.OPENID).scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder().requireProofKey(true).build()) // PKCE 사용을 강제함
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofHours(8)).reuseRefreshTokens(false)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()).build();

        return new InMemoryRegisteredClientRepository(clientCredClient, introspectClient, authCodeClient, pkceClient);
    }

    /**
     * JWT(JSON Web Token)를 서명하고 검증하는 데 사용될 암호화 키(JWK)를 제공
     * JWK는 JSON Web Key의 약자이다.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // 생성된 키를 nimbus-jose 라이브러리의 RSAKey 객체로 래핑
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString()) // 키에 대한 고유 ID 부여
                .build();
        // JWKSet은 여러 개의 JWK를 담는 컨테이너이다
        JWKSet jwkSet = new JWKSet(rsaKey);
        // ImmutableJWKSet을 사용하여 불변의 JWK 소스를 생성
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 2048비트 RSA 키 쌍을 생성하는 헬퍼 메서드.
     * 실무에서는 이렇게 매번 키를 생성하면 서버 재시작 시 기존 토큰이 모두 무효화되므로,
     * KeyStore 파일(.jks)에서 키를 읽어오거나 외부 Vault에서 가져와야 합니다.
     *
     * @return 생성된 KeyPair 객체
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 리소스 서버가 Access Token(JWT)을 디코딩하고 검증하는 데 사용할 JwtDecoder를 설정합니다.
     * 이 디코더는 jwkSource()에서 제공된 공개키를 사용하여 토큰의 서명을 검증합니다.
     *
     * @param jwkSource JWT 서명 키를 제공하는 JWKSource
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 인증 서버의 전반적인 설정을 정의합니다.
     * 예를 들어, issuer URL이나 각 엔드포인트의 경로를 커스터마이징할 수 있습니다.
     * .builder().build()는 모든 기본 설정을 그대로 사용하겠다는 의미입니다.
     *
     * @return AuthorizationServerSettings 빈
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    /**
     * 토큰 생성 작업 후 사용자 정의를 위한 로직, OAuth2TokenCustomizer 인터페이스를 구현한 클래스의 bean을 생성해야함
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            // Access Token에 대해서만 클레임을 추가하도록 제한
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                context.getClaims().claims((claims) -> {
                    // 어떤 Grant Type으로 토큰이 발급되었는지에 따라 다른 로직을 적용
                    if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
                        // Client Credentials Grant의 경우, 요청된 scope를 그대로 'roles' 클레임에 복사
                        Set<String> roles = context.getClaims().build().getClaim("scope");
                        claims.put("roles", roles);
                    } else if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                        // Authorization Code Grant의 경우, 인증된 사용자의 권한(Authorities) 목록을 가져옴
                        Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                                .stream()
                                .map(c -> c.replaceFirst("^ROLE_", "")) // "ROLE_" 접두사 제거
                                .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                        // 정리된 권한 목록을 'roles' 클레임에 추가
                        claims.put("roles", roles);
                    }
                });
            }
        };
    }

    /**
     * 사용자의 비밀번호를 안전하게 해싱하기 위한 PasswordEncoder를 설정
     * DelegatingPasswordEncoder는 여러 해싱 알고리즘을 지원하며,
     * 암호화된 비밀번호 앞에 {bcrypt}, {scrypt} 같은 ID를 붙여 어떤 알고리즘이 사용되었는지 식별함
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 등록 과정에서 인증서버가 간단한 비밀번호는 허용하지 않도록 체크
     */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

}