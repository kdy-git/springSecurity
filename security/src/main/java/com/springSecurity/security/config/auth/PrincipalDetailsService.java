package com.springSecurity.security.config.auth;

import com.springSecurity.security.model.User;
import com.springSecurity.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessUrl("login") 요청이 오면 자동으로 PrincipalDetailsService 타입으로 IoC 되어있는
// loadUserByUsername 함수가 실행된다.
// 이건 시큐리티 실행 규칙임. 외워야함
//loadUserByUsername 파라미터로 들어가는 String username 값은 반드시 form문에서 전달하는 name값과 똑같아야함.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    //시큐리티 session(Authentication(userdetails))
    //아래 함수 발동되면 user 데이터를 담은 객체가 userDetails 타입으로 리턴 -> Authentication 내부의 userDetails 객체로 들어감
    //이것은 다시 시큐리티 세션 내부의 Authentication 객체 안으로 들어감. 즉 세션에 유저객체가 담기게 되는것임
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username);
        if(user != null) {
            return new PrincipalDetails(user);
        }
        return null;
    }
}
