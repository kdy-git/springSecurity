package com.springSecurity.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.springSecurity.security.config.auth.PrincipalDetails;
import com.springSecurity.security.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;


//스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음
// /login 으로 (post) username, password 전송하면 UsernamePasswordAuthenticationFilter 발동됨
// 하지만 현재 formLogin.disable 해둔상황. loginProcessUrl 사용 불가하여 /login으로 요청해도 404 not found 발생
// 그럼 어떻게 해야ㅐ하는가? JwtAuthenticationFilter 필터를 security 필터에 등록하면됨.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter 실행됨. 로그인 시도중");

        try {
//           BufferedReader br = request.getReader();       <-- 이렇게 하면 id:zinee2001&password:1234 이런식으로 응답이 찍힘. json으로 request받을경우 제대로 처리하지못함. parsing해줘야함
//           String input = null;
//           while ((input = br.readLine()) != null) {
//               System.out.println(input);
//           }
            ObjectMapper objectMapper = new ObjectMapper(); // json parsing 해주는 객체
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println("json으로 들어온 데이터를 parsing해서 user에 담아줌 // " + user);

            //id, pw로 토큰생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            System.out.println("유저 정보가 담긴 토큰이 만들어짐 " + authenticationToken);
            System.out.println("로그인 정보가 틀리면 여기서 멈춤 맞다면 계속 진행");

            //principalDetailsService의 로드바이유저네임 함수 실행됨. 로그인이 정상일 경우 return authentication; authentication에 로그인정보가 담김
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            System.out.println("로그인이 정상일 경우 토큰을 authenticationManager에 넣어서 authentication에 담음");

            //authenticatio 객체가 세션영역에 저장됨 => 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 / username : " + principalDetails.getUser().getUsername()); // 로그인이되면 여기서 정보가 찍힘
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;

        // username, password 받아서 정상인지 로그인 시도를 해봄
        // 즉, authenticationManager로 로그인시도를 하면 PrincipalDetailsService가 호출됨
        // 그러면 loadUserByUsername 함수 실행됨.
        // loadUserByUsername 함수 리턴되면 principalDetails를 세션에 담고 (권한 관리를 위해서)
        // jwt토큰을 만들어서 응답해주면됨
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨. 인증이 완료됐다는 뜻임");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //RSA방식은 아니고 Hash 암호방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername()) // 토큰이름. 큰 의미없음
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 60 * 10))) //토큰 유효기간 설정 (10분)
                .withClaim("id", principalDetails.getUser().getId()) // token에 들어갈 정보. 아무거나 넣고싶은거 넣어도됨
                .withClaim("username", principalDetails.getUser().getUsername()) // token에 들어갈 정보. 아무거나 넣고싶은거 넣어도됨
                .sign(Algorithm.HMAC512("cos")); // 안에 들어가는게 시크릿키임

        //http header에 Authorization 이름으로 토큰 담아줌
        response.addHeader("Authorization", "Bearer " + jwtToken);
        System.out.println("HTTP HEADER. Authorization : " + response.getHeader("Authorization"));

        super.successfulAuthentication(request, response, chain, authResult);
    }
}
