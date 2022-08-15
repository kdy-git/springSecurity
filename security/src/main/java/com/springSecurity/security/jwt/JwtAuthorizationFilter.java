package com.springSecurity.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.springSecurity.security.config.auth.PrincipalDetails;
import com.springSecurity.security.model.User;
import com.springSecurity.security.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//시큐리티가 filter를 가지고있는데. 그중에 BasicAuthenticationFilter 라는것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청 했을떄 위 필터를 무조건 타게 되어있음
// 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 url이 있을떄 해당 필터를 타게될 것.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 URL 요청이 들어옴");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("Authorization " + jwtHeader);

        //http header가 있는지 확인
        if (jwtHeader == null || jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        //jwt 토큰을 검증하여 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        // cos라는 암호키로 암호화한 JWT토큰을 빌드. -> 만들어진 토큰을 이용해 verify(서명). username을 받아와서 String화 해줌줌
        String username = JWT.require(Algorithm.HMAC512("cos")).build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();
        System.out.println(username);
        // 서명이 정상적으로 진행됐다면?
        if (username != null) {

            User user = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(user);

            // Jwt 토큰 서명이 정상이면 Authentication 객체를 강제로 만들어준다. (로그인진행없이)
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 authentication 객체를 저장시킴
            SecurityContextHolder.getContext().setAuthentication(authentication);


        }
        chain.doFilter(request, response);
    }
}
