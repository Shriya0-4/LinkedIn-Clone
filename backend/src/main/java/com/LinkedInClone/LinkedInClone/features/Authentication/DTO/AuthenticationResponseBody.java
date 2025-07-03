package com.LinkedInClone.LinkedInClone.features.Authentication.DTO;

public class AuthenticationResponseBody {
    private final String token;
    private final String message;

    public String getToken() {
        return token;
    }

    public String getMessage() {
        return message;
    }

    public AuthenticationResponseBody(String token, String message) {
        this.token = token;
        this.message = message;
    }
}
