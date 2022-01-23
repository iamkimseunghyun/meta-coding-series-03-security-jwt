package io.laaf.securityjwt.repository;

import io.laaf.securityjwt.model.UserJWT;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserJWT, Long> {
    public UserJWT findByUsername(String username);
}
