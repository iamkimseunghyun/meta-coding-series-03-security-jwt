package io.laaf.securityjwt.auth;

import io.laaf.securityjwt.model.UserJWT;
import io.laaf.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:5556/login

@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("PrincipalDetailsService의 loadUserByUsername()");
        UserJWT userEntity = userRepository.findByUsername(username);
        log.info("프린시펄디테일 서비스까지 왔냐구? 유저엔티티가 뭐야? -> {}", userEntity);
        return new PrincipalDetails(userEntity);
    }
}
