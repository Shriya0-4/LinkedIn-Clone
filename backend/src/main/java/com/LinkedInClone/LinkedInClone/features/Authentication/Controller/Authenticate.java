package com.LinkedInClone.LinkedInClone.features.Authentication.Controller;

import com.LinkedInClone.LinkedInClone.features.Authentication.DTO.AutenticationRequestBody;
import com.LinkedInClone.LinkedInClone.features.Authentication.DTO.AuthenticationResponseBody;
import com.LinkedInClone.LinkedInClone.features.Authentication.Model.AuthenticationUser;
import com.LinkedInClone.LinkedInClone.features.Authentication.Service.AuthenticationService;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;

@RestController
@RequestMapping("/api/v1/auth")
public class Authenticate {
    private final AuthenticationService authenticationService;

    public Authenticate(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping("/user")
    public AuthenticationUser getUser(@RequestAttribute("authenticatedUser") AuthenticationUser authenticationUser)
    {

        return authenticationService.getUser(authenticationUser.getEmail());
    }

    @PostMapping("/login")
    public AuthenticationResponseBody loginPage(@Valid @RequestBody AutenticationRequestBody autenticationRequestBody)
    {
        return authenticationService.login(autenticationRequestBody);
    }

    @PostMapping("/register")
    public AuthenticationResponseBody registerPage(@Valid @RequestBody AutenticationRequestBody autenticationRequestBody) throws MessagingException, UnsupportedEncodingException {
        return authenticationService.register(autenticationRequestBody);
    }

    @PutMapping("/validate-email-verification-token")
    public String verifyEmail(@RequestParam String token, @RequestAttribute("authenticatedUser") AuthenticationUser user) {
        authenticationService.validateEmailVerificationToken(token, user.getEmail());
        return "Email verified successfully";
    }

    @GetMapping("/send-email-verification-token")
    public String sendEmailVerificationToken(@RequestAttribute("authenticatedUser") AuthenticationUser user) {
        authenticationService.sendEmailVerificationToken(user.getEmail());
        return "Email verification Code sent";
    }

    @PutMapping("/send-password-reset-token")
    public String sendPasswordResetToken(@RequestParam String email) {
        authenticationService.sendPasswordResetToken(email);
        return "Password reset token sent";
    }

    @PutMapping("/reset-password")
    public String resetPassword(@RequestParam String newPassword, @RequestParam String token,
                                  @RequestParam String email) {
        authenticationService.resetPassword(email, newPassword, token);
        return "Password Reset Successfully";
    }
}
