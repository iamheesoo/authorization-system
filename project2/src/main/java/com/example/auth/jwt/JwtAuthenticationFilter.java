package com.example.auth.jwt;

import com.example.auth.UserController;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.logging.Logger;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);
//        System.out.println("doFilter: "+token);
        logger.info(token);

        if (token != null && jwtTokenProvider.validateToken(token)) { // 토큰이 유효하다면
            Authentication auth = jwtTokenProvider.getAuthentication(token);
            // SecurityContext에 authentication 저장
            SecurityContextHolder.getContext().setAuthentication(auth);
            logger.info(auth.getAuthorities()+" "+auth.getCredentials()+" "+auth.getPrincipal()+" "+auth.getDetails());

        }
        chain.doFilter(request, response);
    }

}