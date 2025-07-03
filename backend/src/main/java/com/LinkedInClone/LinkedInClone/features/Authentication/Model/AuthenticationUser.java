package com.LinkedInClone.LinkedInClone.features.Authentication.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDateTime;

@Entity(name = "Users")
public class AuthenticationUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @NotNull
    @Email
    @Column(unique = true)
    private String email;
    private Boolean emailVerified = false;
    private String EmailVerificationToken=null;
    private LocalDateTime emailVerificationTokenExpireDate = null;
    @JsonIgnore
    private String password;
    private String passwordResetToken=null;
    private LocalDateTime passwordResetTokenExpiryDate = null;

    public AuthenticationUser( String email, String password) {
        this.email = email;
        this.password = password;
    }

    public AuthenticationUser() {

    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public LocalDateTime getEmailVerificationTokenExpireDate() {
        return emailVerificationTokenExpireDate;
    }

    public void setEmailVerificationTokenExpireDate(LocalDateTime emailVerificationTokenExpireDate) {
        this.emailVerificationTokenExpireDate = emailVerificationTokenExpireDate;
    }

    public String getEmailVerificationToken() {
        return EmailVerificationToken;
    }

    public void setEmailVerificationToken(String emailVerificationToken) {
        EmailVerificationToken = emailVerificationToken;
    }

    public String getPasswordResetToken() {
        return passwordResetToken;
    }

    public void setPasswordResetToken(String passwordResetToken) {
        this.passwordResetToken = passwordResetToken;
    }

    public LocalDateTime getPasswordResetTokenExpiryDate() {
        return passwordResetTokenExpiryDate;
    }

    public void setPasswordResetTokenExpiryDate(LocalDateTime passwordResetTokenExpiryDate) {
        this.passwordResetTokenExpiryDate = passwordResetTokenExpiryDate;
    }
}
