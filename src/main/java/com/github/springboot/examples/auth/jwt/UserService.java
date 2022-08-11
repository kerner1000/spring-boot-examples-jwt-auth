package com.github.springboot.examples.auth.jwt;

import org.springframework.stereotype.Component;

@Component
public class UserService {
    public String getPasswordForUser(String username) {
        /**
         * Should check in a DB or similar if user exists and query for and return his password.
         */
        return "dummy-password";
    }
}
