package com.github.springboot.examples.auth.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    private final UserService userService;

    private final static Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);

    public JwtTokenFilter(TokenService tokenService, UserService userService) {
        this.tokenService = tokenService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String token;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                // remove 'Bearer ' substring
                token = authHeader.substring(7);
                /**
                 * Get username and password from token. This is just one way to do it.
                 * In principle, any information can be used to check if the token is valid,
                 * in the most simple case just an arbitrary string such as a username, password
                 * or API key.
                 * Primary idea of authentication is signing the token using a private secret
                 * or a public key/private key pair.
                 * If the sent token can be decoded successfully, the request can be considered
                 * trustworthy.
                 */
                String username = tokenService.getUsernameFromToken(token);
                String password = userService.getPasswordForUser(username);
                if (tokenService.validateJwtToken(token, password)) {
                    grantAccess(username);
                    filterChain.doFilter(request, response);
                    return;
                } else {
                    logger.info("Denied access for {} with token {}", username, token);
                }
            } catch (IllegalArgumentException e) {
                logger.error("Unable to get JWT Token", e);
            } catch (ExpiredJwtException e) {
                logger.error("JWT Token has expired", e);
            } catch (Exception e) {
                logger.error(e.getLocalizedMessage(), e);
            }
        } else {
            logger.error("Bearer String not found in token");
        }
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }

    private void grantAccess(String username) {
        AuthenticationToken<String> token = new AuthenticationToken<>(username, Collections.emptyList());
        token.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(token);
    }
}
