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
        log.info("유저리포지토리에서 유저네임으로 가입명부 찾음");
        UserJWT userEntity = userRepository.findByUsername(username);
        log.info("유저리포지토리에서 찾아온 거 -> {}", userEntity);
        if (userEntity != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
