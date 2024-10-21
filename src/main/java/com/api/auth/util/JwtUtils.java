package com.api.auth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@AllArgsConstructor
@NoArgsConstructor
@Component
public class JwtUtils {

    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    // Método para cargar la clave privada desde la variable de entorno
    private RSAPrivateKey getPrivateKey() throws Exception {
        String privateKeyPEM = System.getenv("JWT_PRIVATE_KEY");

        // Eliminar los encabezados y espacios en blanco
        privateKeyPEM = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // Decodificar la clave y construir el PrivateKey
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

    // Método para cargar la clave pública desde la variable de entorno
    private PublicKey getPublicKey() throws Exception {
        String publicKeyPEM = System.getenv("JWT_PUBLIC_KEY");

        // Eliminar los encabezados y espacios en blanco
        publicKeyPEM = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // Decodificar la clave y construir el PublicKey
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // Método para crear el token JWT firmado con RSA256
    public String createToken(Authentication authentication) {
        try {
            // Obtener la clave privada
            RSAPrivateKey privateKey = getPrivateKey();

            // Crear el algoritmo RSA256 con la clave privada
            Algorithm algorithm = Algorithm.RSA256(null, privateKey);

            // Extraer la información del usuario
            String username = authentication.getPrincipal().toString();
            String authorities = authentication.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

            // Crear el token JWT
            return JWT.create()
                    .withIssuer(userGenerator)
                    .withSubject(username)
                    .withClaim("authorities", authorities)
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + 3600000)) // Token válido por 1 hora
                    .withJWTId(UUID.randomUUID().toString())
                    .withNotBefore(new Date(System.currentTimeMillis()))
                    .sign(algorithm);

        } catch (Exception e) {
            throw new RuntimeException("Error al generar el token JWT", e);
        }
    }

    // Método para validar el token utilizando la clave pública (RSA256)
    public DecodedJWT validateToken(String token) {
        try {
            // Obtener la clave pública
            PublicKey publicKey = getPublicKey();

            // Crear el algoritmo RSA256 con la clave pública
            Algorithm algorithm = Algorithm.RSA256((java.security.interfaces.RSAPublicKey) publicKey, null);

            // Verificador del token JWT
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build();

            // Verificar el token
            return verifier.verify(token);
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException("El token " + token + " es inválido");
        } catch (Exception e) {
            throw new RuntimeException("Error al validar el token JWT", e);
        }
    }

    // Método para exponer la clave pública en formato JWK
    public Map<String, Object> getJwkSet() throws Exception {
        // Obtener la clave pública
        PublicKey publicKey = getPublicKey();

        // Convertir la clave pública en un JWK
        RSAKey jwk = new RSAKey.Builder((java.security.interfaces.RSAPublicKey) publicKey)
                .keyID("my-key-id") // Identificador único de la clave
                .build();

        // Devolver el JWK como un mapa JSON
        return Collections.singletonMap("keys", Collections.singletonList(jwk.toJSONObject()));
    }

    // Métodos auxiliares para extraer información de JWT
    public String extractUsername(DecodedJWT decodedJWT) {
        return decodedJWT.getSubject();
    }

    public Claim getSpecificClaim(DecodedJWT decodedJWT, String claimName) {
        return decodedJWT.getClaim(claimName);
    }

    public Map<String, Claim> returnAllClaims(DecodedJWT decodedJWT) {
        return decodedJWT.getClaims();
    }
}