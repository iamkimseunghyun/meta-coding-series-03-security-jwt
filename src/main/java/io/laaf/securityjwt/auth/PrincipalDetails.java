package io.laaf.securityjwt.auth;

import io.laaf.securityjwt.model.UserJWT;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@Data
@Slf4j
public class PrincipalDetails implements UserDetails {

    private UserJWT user;

    public PrincipalDetails(UserJWT user) {
        this.user = user;
    }

    public UserJWT getUser() {
        return user;
    }


    @Override
    public String getPassword() {
        return user.getPassword();
    } // 여기서 찐빠가 나서 오랜 시간 삽질했다. 피곤할 때 놓친다.

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        user.getRoleList().forEach(r -> {
            authorities.add(() -> r);
        });
        return authorities;
    }
}
