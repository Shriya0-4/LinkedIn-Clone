package com.LinkedInClone.LinkedInClone.features.Authentication.Service;

import com.LinkedInClone.LinkedInClone.features.Authentication.DTO.AutenticationRequestBody;
import com.LinkedInClone.LinkedInClone.features.Authentication.DTO.AuthenticationResponseBody;
import com.LinkedInClone.LinkedInClone.features.Authentication.Model.AuthenticationUser;
import com.LinkedInClone.LinkedInClone.features.Authentication.Repository.AuthenticationUserRepository;
import com.LinkedInClone.LinkedInClone.features.Authentication.Utils.EmailService;
import com.LinkedInClone.LinkedInClone.features.Authentication.Utils.Encoder;
import com.LinkedInClone.LinkedInClone.features.Authentication.Utils.JsonWebToken;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;


@Service
public class AuthenticationService {
    private static final Logger logger = (Logger) LoggerFactory.getLogger(AuthenticationService.class);
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(AuthenticationService.class);
    private final JsonWebToken jsonWebToken;
    private final int durationInMinitues=1;
    private final Encoder encoder;
    private final AuthenticationUserRepository authenticationUserRepository;
    private final EmailService emailService;

    public AuthenticationService(JsonWebToken jsonWebToken, Encoder encoder, AuthenticationUserRepository authenticationUserRepository, EmailService emailService) {
        this.jsonWebToken = jsonWebToken;
        this.encoder = encoder;
        this.authenticationUserRepository = authenticationUserRepository;
        this.emailService = emailService;
    }

    public static String generateEmailVerificationToken(){
        SecureRandom random = new SecureRandom();
        StringBuilder token = new StringBuilder();
        for(int i =0; i<5;i++)
        {
            token.append(random.nextInt(10));
        }
        return token.toString();
    }

    public void sendEmailVerificationToken(String email)
    {
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent() && !user.get().getEmailVerified()) {
            String emailVerificationToken = generateEmailVerificationToken();
            String hashedToken = encoder.encode(emailVerificationToken);
            user.get().setEmailVerificationToken(hashedToken);
            user.get().setEmailVerificationTokenExpireDate(LocalDateTime.now().plusMinutes(durationInMinitues));
            authenticationUserRepository.save(user.get());
            String subject = "Email Verification";
            String body = String.format("Only one step to take full advantage of LinkedIn.\n\n"
                            + "Enter this code to verify your email: " + "%s\n\n" + "The code will expire in " + "%s"
                            + " minutes.",
                    emailVerificationToken, durationInMinitues);
            try {
                emailService.sendEmail(email, subject, body);
            } catch (Exception e) {
                logger.info("Error while sending email: {}");
            }
        } else {
            throw new IllegalArgumentException("Email verification token failed, or email is already verified.");
        }
    }

    public void validateEmailVerificationToken(String token, String email) {
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent() && encoder.matches(token, user.get().getEmailVerificationToken())
                && !user.get().getEmailVerificationTokenExpireDate().isBefore(LocalDateTime.now())) {
            user.get().setEmailVerified(true);
            user.get().setEmailVerificationToken(null);
            user.get().setEmailVerificationTokenExpireDate(null);
            authenticationUserRepository.save(user.get());
        } else if (user.isPresent() && encoder.matches(token, user.get().getEmailVerificationToken())
                && user.get().getEmailVerificationTokenExpireDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Email verification token expired.");
        } else {
            throw new IllegalArgumentException("Email verification token failed.");
        }
    }

    public AuthenticationUser getUser(String email)
    {
        return authenticationUserRepository.findByEmail(email).orElseThrow(()-> new IllegalArgumentException("User not found"));
    }

    public AuthenticationResponseBody register(AutenticationRequestBody autenticationRequestBody) throws MessagingException, UnsupportedEncodingException {
         AuthenticationUser user = authenticationUserRepository.save(new AuthenticationUser(autenticationRequestBody.getEmail(),encoder.encode(autenticationRequestBody.getPassword())));
         String EmailVerification = generateEmailVerificationToken();
         String HashedToken = encoder.encode(EmailVerification);
         user.setEmailVerificationToken(HashedToken);
         user.setEmailVerificationTokenExpireDate(LocalDateTime.now().plusMinutes(durationInMinitues));
         authenticationUserRepository.save(user);
         String Subject = "Email verification";
         String Body = String.format("Only one step to take full advantage of LinkedIn.\n Enter this code to verify your email. %s. the code will expire in %s minutes",EmailVerification,durationInMinitues);
         try{
             emailService.sendEmail(autenticationRequestBody.getEmail(),Subject,Body);
         }
             catch (Exception e)
             {
                 logger.info("error while sending the email: {}");
             }
         String token = jsonWebToken.generateToken(autenticationRequestBody.getEmail());
         emailService.sendEmail(autenticationRequestBody.getEmail(),"subject","body");
         return new AuthenticationResponseBody(token,"user registered successfully");
    }

    public AuthenticationResponseBody login( AutenticationRequestBody autenticationRequestBody) {
        AuthenticationUser user = authenticationUserRepository.findByEmail(autenticationRequestBody.getEmail()).orElseThrow(()-> new IllegalArgumentException("user not found!"));
        if(!encoder.matches( autenticationRequestBody.getPassword(),user.getPassword()))
        {
            throw new IllegalArgumentException("password incorrect!");
        }
        String Token = jsonWebToken.generateToken(autenticationRequestBody.getEmail());
        return new AuthenticationResponseBody(Token,"Authentication succeeded");
    }

    public void sendPasswordResetToken(String email) {
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent()) {
            String passwordResetToken = generateEmailVerificationToken();
            String hashedToken = encoder.encode(passwordResetToken);
            user.get().setPasswordResetToken(hashedToken);
            user.get().setPasswordResetTokenExpiryDate(LocalDateTime.now().plusMinutes(durationInMinitues));
            authenticationUserRepository.save(user.get());
            String subject = "Password Reset";
            String body = String.format("""
                    You requested a password reset.

                    Enter this code to reset your password: %s. The code will expire in %s minutes.""",
                    passwordResetToken,durationInMinitues);
            try {
                emailService.sendEmail(email, subject, body);
            } catch (Exception e) {
                logger.info("Error while sending email: {}");
            }
        } else {
            throw new IllegalArgumentException("User not found.");
        }
    }

    public void resetPassword(String email, String newPassword, String token) {
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent() && encoder.matches(token, user.get().getPasswordResetToken())
                && !user.get().getPasswordResetTokenExpiryDate().isBefore(LocalDateTime.now())) {
            user.get().setPasswordResetToken(null);
            user.get().setPasswordResetTokenExpiryDate(null);
            user.get().setPassword(encoder.encode(newPassword));
            authenticationUserRepository.save(user.get());
        } else if (user.isPresent() && encoder.matches(token, user.get().getPasswordResetToken())
                && user.get().getPasswordResetTokenExpiryDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Password reset token expired.");
        } else {
            throw new IllegalArgumentException("Password reset token failed.");
        }
    }
}
