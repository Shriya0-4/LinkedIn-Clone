package com.LinkedInClone.LinkedInClone.features.Authentication.Utils;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Component
public class Encoder {
    public String encode(String password)
    {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("ERROR encoding password");
        }
    }

    public boolean matches(String password,String encodedPassword)
    {
        return encode(password).equals(encodedPassword);
    }
}
