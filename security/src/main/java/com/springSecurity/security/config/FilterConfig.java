package com.springSecurity.security.config;

import com.springSecurity.security.filter.MyFilter1;
import com.springSecurity.security.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(1); // 낮은 번호가 필터중 가장 먼저 실행됨
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(0); // 낮은 번호가 필터중 가장 먼저 실행됨
        return bean;
    }
}

// filter2 에 걸린 setOrder가 더 낮기때문에 2번 필터가 1번필터보다 먼저 실행됨.
// 이렇게 걸어주는 필터들은 항상 security filter 보다 늦게 실행됨
// security filter보다 먼저 실행시켜야한다면 securityConfig에서 http.addFilterBefore() 메서드 사용하여 출력해야함 (ex filter3)
