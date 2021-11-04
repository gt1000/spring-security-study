package com.gt1000.config;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        String password = passwordEncoder().encode("1111");

        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER", "USER");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN", "USER", "MANAGER");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // js, css, image 같은 정적 파일은 보안 필터를 적용할 필요가 없는 리소스를 설정
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/user").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

        .and()
                .formLogin();

//
//        http
//                .authorizeRequests()
//                .antMatchers("/login").permitAll();
//
//        http
//                .csrf().disable();
//
//        http
//                .formLogin()
////                .loginPage("/login")        // 사용자 정의 로그인 페이지
//                .defaultSuccessUrl("/main")     // 로그인 성공 후 이동 페이지
//                .failureUrl("/login?error=true")        // 로그인 실패 후 이동 페이지
//                .usernameParameter("userId")            // 로그인 페이지에 label for 와 input type의 id 는 username으로 세팅되고, username 만 userId로 세팅 됨
//                .passwordParameter("password")          // 로그인 페이지 비밀번호 입력값 설정
//                .loginProcessingUrl("/login-process")   // 로그인 처리 url
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        // 로그인 성공 후 핸들러, 람다 처리 해도 될듯
//                        log.info("------------------------------ userId = {}", authentication.getName());
//
//                        // 세션에 저장된 이전 요청 정보를 꺼내와서 이동 하게 함
//                        RequestCache requestCache = new HttpSessionRequestCache();
//                        SavedRequest savedRequest = requestCache.getRequest(request, response);
//                        String redirectUrl = savedRequest.getRedirectUrl();
//
//                        response.sendRedirect(redirectUrl);
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        // 로그인 실패 후 뭔가 처리가 필요한 경우 핸들러 사용. 람다 처리 해도 될듯
//                        log.info("----------------------------- exception = {}", exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll();
//
////        http
////                .rememberMe()
////                        .rememberMeParameter("remember")                    // 기본 패러미터명은 remember-me
////                .tokenValiditySeconds(3600)                         // 초단위. 1시간, 기본값은 14일
////                //.alwaysRemember(true)                               // 리멤버 미 기능이 활성화 되지 않아도 항상 실행, false가 맞을거 같음
////                .userDetailsService(userDetailsService);            // 실행할때, 시스템 사용자 계정을 조회할때 사용하는 클래스. 꼭 필요한 설정
//
//        http
//                .logout()
//                .logoutUrl("/logout")                           // 로그 아웃 처리 url
//                .logoutSuccessUrl("/login")                             // 로그 아웃 성공 후 이동 페이지
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        // 로그 아웃 핸들러, 기본 security 처리 하는 외 비지니스 로직을 하고 싶은 경우
//                        log.info("---------- 세션 무효화");
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        // 로그 아웃 성공 후 핸들러.... 후속 처리를 위한 핸들러~ 위에꺼와 뭐가 다른거임? 업무적인 분리?
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("JSESSIONID", "remember-me");     // 로그 아웃 쿠키 삭제
//
//        http.sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)             // jwt, 세션 생성하지도, 존재 해도 사용하지 않음
//                .sessionFixation().changeSessionId()        // 세션 공유 공격 차단. 매번 새로운 새센 아이디를 생성하는 옵션
//                .maximumSessions(1)               // 최대 허용 개수, -1: 무제한 로그인 세션 허용
//                .maxSessionsPreventsLogin(true)     // 최대 허용 개수 초대 했을때,  true : 로그인을 못하게 함. false : 기존 세션 만료
//                .expiredUrl("/expired");
//
//        http
//                .
//                exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        // 스프링 시큐리티가 아닌 우리가 만든 url
//                        response.sendRedirect("/login");
//                    }
//                })
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                        // 스프링 시큐리티가 아닌 우리가 만든 url
//                        response.sendRedirect("/denied");
//                    }
//                });
    }
}
