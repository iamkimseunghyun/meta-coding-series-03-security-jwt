package io.laaf.securityjwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        // 토큰: cos 이걸 만들어줘야 함. id. pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어 주고 그걸 응답해준다
        // 요청할 때 마다 header에 Authorization에 value 값으로 토큰을 가지고 와야 함
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 됨(RSA, HS256)

        if (req.getMethod().equals("POST")) {
            log.info("Post 요청됨");
            String headerAuth = req.getHeader("Authorization");
            log.info("headerAuth: {}", headerAuth);
            log.info("필터1");

            if (headerAuth.equals("kaka")) {
                chain.doFilter(req, res);
                log.info("인증됨");
            } else {
                log.info("인증안됨");
            }
        }

    }
}
