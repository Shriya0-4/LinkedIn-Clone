package com.LinkedInClone.LinkedInClone.features.Authentication.Configuration;

import com.LinkedInClone.LinkedInClone.features.Authentication.Model.AuthenticationUser;
import com.LinkedInClone.LinkedInClone.features.Authentication.Repository.AuthenticationUserRepository;
import com.LinkedInClone.LinkedInClone.features.Authentication.Utils.Encoder;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoadDatabaseConfiguration {
    private final Encoder encoder;

    public LoadDatabaseConfiguration(Encoder encoder) {
        this.encoder = encoder;
    }

    @Bean
    public CommandLineRunner initDatabase(AuthenticationUserRepository authenticationUserRepository)
    {
        return args -> {
            AuthenticationUser authenticationUser = new AuthenticationUser("shriyakulkarni04@gmail.com", encoder.encode("shriya2601"));
            authenticationUserRepository.save(authenticationUser);
        };
    }
}
