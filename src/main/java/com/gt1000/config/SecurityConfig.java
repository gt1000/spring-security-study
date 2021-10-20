package com.gt1000.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@AllArgsConstructor
// @PreAuthorize, @PostAuthorize 애노테이션을 사용하여 인가 처리를 하고 싶을때 사용하는 옵션이다. 특정 메소드 호출 전, 후 권한 확인
// @Secured 애노테이션을 사용하여 인가 처리를 하고 싶을때 사용하는 옵션이다.
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .formLogin()
//                .loginPage("/login")       // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/main")     // 로그인 성공 후 이동 페이지
                .failureUrl("/fail.html")       // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")    // 아이디 파라미터명 설정
                .passwordParameter("password")  // 비밀번호 파라미터명 설정
                .loginProcessingUrl("/login")   // 로그인 Form Action url
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication = " + authentication.getName());
//                        response.sendRedirect("/main-test");
//                    }
//                })      // 로그인 성공 후 핸들러
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception = " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
                .permitAll();
    }
}
