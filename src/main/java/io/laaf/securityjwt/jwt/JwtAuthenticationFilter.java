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
        return super.attemptAuthentication(request, response);
    }

    //    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request,
//                                                HttpServletResponse response)
//            throws AuthenticationException {
//        log.info("JwtAuthenticationFilter: 로그인 시도 중");
//
//        // 1. username, password 받아서
//        try {
//            ObjectMapper om = new ObjectMapper();
//            UserJWT user = om.readValue(request.getInputStream(), UserJWT.class);
//            log.info("user:{}", user);
//
//            log.info("매니저 떳냐?");
//            UsernamePasswordAuthenticationToken authenticationToken
//                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
//            log.info("getUsername(), getPassword()", user.getUsername(), user.getPassword());
//            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행되고 정상이면 authentication이 리턴됨
//            // DB에 있는 username과 password가 일치한다
//
//            Authentication authentication = authenticationManager.authenticate(authenticationToken);
//
//            log.info("매니저 떳냐?");
//
//            // authentication 객체가 session 영역에 저장됨 => 로그인이 되었다는 뜻
//            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
//            System.out.println("Authentication : "+ principalDetails.getUser().getUsername());
//            log.info("로그인 완료됨: ", principalDetails.getUser().getUsername());
//            log.info("1=========================");
//
//            // authentication 객체가 session 영역에 저장을 해야 하고 그 방법이 return 해주면 됨
//            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것임
//            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 단지 권한 처리 때문에 session 넣어줌
//            return authentication;
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        log.info("2=====================================\n");
//
//
//        // 2. 정상인지 로그인 시도를 함 authenticationManager로 로그인 시도를 하면!
//        // PrincipalDetailsService 호출! loadUserByUsername() 함수 실행됨
//
//        // 3. PrincipalDetails를 세션에 담고(권한 관리를 위해서)
//
//        // 4. JWT 토큰을 만들어서 응답해주면 됨
//        return null;
//    }
//
//    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfullAuthentication 함수가 실행 됨
//    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request,
//                                            HttpServletResponse response,
//                                            FilterChain chain,
//                                            Authentication authResult) throws IOException, ServletException {
//
//        log.info("successfulAuthentication 실행됨: 인증이 완료 되었다는 뜻임");
//        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
//
//        String jwtToken = JWT.create()
//                .withSubject("katakana")
//                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
//                .withClaim("id", principalDetails.getUser().getId())
//                .withClaim("username", principalDetails.getUser().getUsername())
//                .sign(Algorithm.HMAC512("kaka"));
//
//        response.addHeader("Authorization", "Bearer " + jwtToken);
//
//    }

}
