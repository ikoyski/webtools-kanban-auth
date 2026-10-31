package com.ikoyski.webtools.authserver.security;

import java.util.List;
import java.util.function.Consumer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.ikoyski.webtools.authserver.config.ClientSeeder;
import com.ikoyski.webtools.authserver.config.GeminiRedirectUriValidator;

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
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http, GeminiRedirectUriValidator geminiRedirectUriValidator) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
        authorizationServerConfigurer.authorizationEndpoint(endpoint ->
                endpoint.authenticationProviders(configureAuthorizationCodeValidator(geminiRedirectUriValidator)));

        http.cors(Customizer.withDefaults());
        http.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    private Consumer<List<AuthenticationProvider>> configureAuthorizationCodeValidator(
            GeminiRedirectUriValidator geminiRedirectUriValidator) {
        return providers -> providers.forEach(provider -> {
            if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider authorizationCodeProvider) {
                Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> redirectValidator = context -> {
                    Object isGeminiDynamic = context.getRegisteredClient().getClientSettings()
                            .getSetting(ClientSeeder.GEMINI_DYNAMIC_REDIRECT_SETTING);
                    if (Boolean.TRUE.equals(isGeminiDynamic)) {
                        geminiRedirectUriValidator.accept(context);
                    } else {
                        OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                                .accept(context);
                    }
                };
                authorizationCodeProvider.setAuthenticationValidator(
                        redirectValidator.andThen(
                                OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR));
            }
        });
    }

    /**
     * Everything else: sign-in with the configured identity providers (Google today) and health.
     * With oauth2Login and no form login, Spring generates the /login page listing each provider.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          FederatedLoginSuccessHandler successHandler,
                                                          LogoutRedirectHandler logoutHandler) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(login -> login.successHandler(successHandler))
                // GET /logout?redirect=<allow-listed url> ends this server's sign-in session, so "sign out" in an
                // app really signs the person out instead of silently signing them back in.
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessHandler(logoutHandler)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
        return http.build();
    }
}