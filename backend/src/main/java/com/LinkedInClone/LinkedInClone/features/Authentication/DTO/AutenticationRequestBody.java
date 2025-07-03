package com.LinkedInClone.LinkedInClone.features.Authentication.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class AutenticationRequestBody {
    @NotBlank(message = "email is mandatory")
    @Email
    private  String Email;
    @NotBlank(message = "password is mandatory")
    private  String password;

    public AutenticationRequestBody(String email, String password) {
        this.Email = email;
        this.password = password;
    }

    public void setEmail(String email) {
        this.Email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return Email;
    }

    public String getPassword() {
        return password;
    }
}
