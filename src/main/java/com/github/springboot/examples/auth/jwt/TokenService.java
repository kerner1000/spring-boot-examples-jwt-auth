package com.github.springboot.examples.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenService {

   @Value("${app.jwt.secret}")
    private String jwtSecret;

    /**
     * Checks if the provided token is not expired and contains an expected username.
     * Extend this method to do more checks if provided token is valid.
     *
     * @param token Token string
     * @param passwordExpected expected password
     * @return {@code true} if the provided token is valid; {@code false} otherwise
     */
    public boolean validateJwtToken(String token, String passwordExpected) {
        String password = getPasswordFromToken(token);
        SecretKey secretKey = new SecretKeySpec(jwtSecret.getBytes(), SignatureAlgorithm.HS256.getJcaName());
        Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        if(password == null || claims == null)
            return false;
        // Allow no expiration date
        boolean isTokenExpired = claims.getExpiration() != null && claims.getExpiration().before(new Date());
        return (password.equals(passwordExpected)) && !isTokenExpired;
    }
    public String getUsernameFromToken(String token) {
        SecretKey secretKey = new SecretKeySpec(jwtSecret.getBytes(), SignatureAlgorithm.HS256.getJcaName());
        final Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    public String getPasswordFromToken(String token) {
        SecretKey secretKey = new SecretKeySpec(jwtSecret.getBytes(), SignatureAlgorithm.HS256.getJcaName());
        final Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        Object password = claims.get("myCustomPasswordClaim");
        if(password != null){
            return password.toString();
        }
        return null;
    }
}
