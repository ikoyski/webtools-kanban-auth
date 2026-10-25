package com.ikoyski.webtools.authserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Protocol endpoints: /oauth2/authorize, /oauth2/token, /oauth2/jwks,
     * /.well-known/oauth-authorization-server, etc. Browsers that are not signed in are sent
     * to /login. OIDC and dynamic client registration are deliberately NOT enabled, so there is
     * no open registration endpoint; clients are pre-registered (see ClientSeeder).
     * CORS is enabled so a browser app can call the token endpoint (see CorsConfig).
     */
    @Bean
    @Order(1)
    @SuppressWarnings("deprecation") // applyDefaultSecurity is deprecated since 1.4 but still supported
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.cors(Customizer.withDefaults());
        http.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    /**
     * Everything else: sign-in with the configured identity providers (Google today) and health.
     * With oauth2Login and no form login, Spring generates the /login page listing each provider.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          FederatedLoginSuccessHandler successHandler) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(login -> login.successHandler(successHandler));
        return http.build();
    }
}
