package com.github.springboot.examples.auth.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AuthenticationToken<P> extends AbstractAuthenticationToken {

    private final P principal;

    private Object credentials;

    public AuthenticationToken(P principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public P getPrincipal() {
        return principal;
    }
}
