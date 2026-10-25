package com.ikoyski.webtools.authserver.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * RSA signing key for the access tokens. The gateway will verify tokens with the public key
 * published at /oauth2/jwks, so the signing secret never leaves this service (unlike the shared
 * HMAC secret used for the login tokens).
 */
@Configuration
public class JwkConfig {

    private static final Logger log = LoggerFactory.getLogger(JwkConfig.class);

    @Bean
    public JWKSource<SecurityContext> jwkSource(
            @Value("${auth.jwk.key-id}") String keyId,
            @Value("${auth.jwk.private-key-file}") String privateKeyFile,
            @Value("${auth.jwk.public-key-file}") String publicKeyFile) throws Exception {

        RSAKey rsaKey;
        if (privateKeyFile.isBlank() || publicKeyFile.isBlank()) {
            log.warn("No signing key configured: generating an EPHEMERAL RSA key. "
                    + "Tokens stop validating after a restart. Set auth.jwk.* before real use.");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            rsaKey = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey((RSAPrivateKey) pair.getPrivate())
                    .keyID(keyId)
                    .build();
        } else {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(readPem(privateKeyFile)));
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new X509EncodedKeySpec(readPem(publicKeyFile)));
            rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId).build();
        }
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private static byte[] readPem(String path) throws IOException {
        String pem = Files.readString(Path.of(path))
                .replaceAll("-----(BEGIN|END) [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(pem);
    }
}
