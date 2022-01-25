package io.laaf.securityjwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.laaf.securityjwt.auth.PrincipalDetails;
import io.laaf.securityjwt.model.UserJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면 (post)
// Username
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        log.info("JwtAuthenticationFilter: 로그인 시도 중");
        try {
            ObjectMapper om = new ObjectMapper();
            UserJWT user = om.readValue(request.getInputStream(), UserJWT.class);
            log.info("유저: {} ", user);

            // 여기서 부터 작동을 안해서 삽집을 오래 했는데 세션 객체 생성할 때 패스워드 접근 메서드를 설정하지 않해서 일어났던 오류였다.
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            log.info("유저겟네임이랑 유저 겟페스워드 {} {}", user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴 됨
            // DB에 있는 username과 password가 일치한다는 뜻
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            log.info("어덴티케이션이 뭐지? {}", authentication.getName());
            log.info("토큰 좀 보자 {}", authenticationManager.authenticate(authenticationToken));

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            log.info("로그인이 정상이면 이게 나와야 한다는데? {} ", principalDetails.getUser().getUsername()); // 로그인이 정상이라는 뜻
            // authentication 객체가 session 영역에 저장을 해야 하고 그 방법이 return 해주면 됨
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것임.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 session 넣어 줍니다.

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
            throws IOException, ServletException {
        log.info("successfulAuthentication 실행됨: 인증이 완료 되었다는 뜻임.");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니구 해쉬 암호 방식
        String jwtToken = JWT.create()
                .withSubject("kaka토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("kaka"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
