package com.springSecurity.security.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        req.setCharacterEncoding("UTF-8");

        // Authorization 객체에 담긴 값이 cos인 경우에만 인증됨. 즉 cos는 우리가 말하는 token임.
        // token 은 id, pw가 정상적으로 입력됐을떄 해당 id정보를 가지는 토큰을 만들어주고 그걸 응답을 해준다.
        // 그러면 요청할때마다 header - Authorization value값으로 토큰을 가지고 옴
        // 그때 토큰이 넘어오면 이 토큰이 내가만든 토큰이 맞는지만 검증하면됨

       if(req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터3");
            chain.doFilter(req, res);
//            if(headerAuth.equals("cos")) {
//                chain.doFilter(req, res);
//            }else {
//                PrintWriter out =res.getWriter();
//                out.println("can not access");
//            }
        }
    }

}
