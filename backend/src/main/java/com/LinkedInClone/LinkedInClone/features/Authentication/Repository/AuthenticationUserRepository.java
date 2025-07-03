package com.LinkedInClone.LinkedInClone.features.Authentication.Repository;

import com.LinkedInClone.LinkedInClone.features.Authentication.Model.AuthenticationUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthenticationUserRepository extends JpaRepository<AuthenticationUser,Long> {
    Optional<AuthenticationUser> findByEmail(String email);
}
