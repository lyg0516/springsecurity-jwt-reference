package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청에서 username, password 전송하면 (post)
// 필터가 동작함
// 현재 .formLogin().disabled() 이므로 동작하지 않
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도");
        User user = null;
        // 1. username, password 받아서
        ObjectMapper om = new ObjectMapper();
        try {
            user = om.readValue(request.getInputStream(), User.class);
            UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            Authentication authentication =
                    authenticationManager.authenticate(token);
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인: " +principalDetails.getUsername());
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // 2. 정상인지 로그인 시도 authenticationManager로 로그인을 실행하면
        // PrincipalDetailsService.loadUserByUsername() 호출

        // 3. PrincipalDetails를 세션에 달고 (세션에 달지않으면 권한관리가 되지 않는다.)

        // 4. JWT토큰을 만들어서 응답해주면 됨
    }

    // attemptAuthentication 실행 후 인증이 정장적으로 되었으면 호출
    // JWT 토큰을 만들어서 사용자에서 JWT토큰반환
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("username", principalDetails.getUsername())
                .sign(Algorithm.HMAC512("cos"));
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
