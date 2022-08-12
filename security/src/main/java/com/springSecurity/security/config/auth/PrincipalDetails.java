package com.springSecurity.security.config.auth;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인 완료시 시큐리티 session을 만들어준다. (Security ContextHolder 에 저장)
// 세션에 들어갈 수 있는 타입의 오브젝트 => Authentication 타입의 객체만 가능
// Authentication 안에 User 정보가 있어야함
// User 정보 -> UserDetails 타입의 객체이다.

// 즉 Security Session => Authentication => UserDetails.
// 유저 정보를 얻기 위해 Session에 있는 정보를 get 하면 Authentication 정보가 나옴. 여기서 user 객체 꺼낼 수 있음
//어떻게?

import com.springSecurity.security.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    //해당 유저의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

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

        // 우리 사이트에서 1년동안 회원이 로그인을 안한다? 휴면계정으로 하기로 함. 그런경우 false

        return true;
    }
}
