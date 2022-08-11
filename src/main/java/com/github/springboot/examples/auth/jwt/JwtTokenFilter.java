package com.github.springboot.examples.auth.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String token = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {

            try {
            token = authHeader.substring(7);
            String username = tokenService.getUsernameFromToken(token);;
            String password = userService.getPasswordForUser(username);
                if(tokenService.validateJwtToken(token, password)){
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
            } catch (Exception e){
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
