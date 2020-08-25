package com.springsecurity.weblogin.config;

import com.springsecurity.weblogin.exceptions.CustomAuthenticationFailureHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder)
                .withUser("user").password(passwordEncoder.encode("user123")).roles("USER")
                .and()
                .withUser("admin").password(passwordEncoder.encode("admin123")).roles("USER", "ADMIN");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationFailureHandler customAuthFailureHandler(){
        return new CustomAuthenticationFailureHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //see 'Pro Spring Security' for HTTP header based req-res authentication (formLogin uses body based req-res)

        http.authorizeRequests()
                //set pages which do not require authentication
                .antMatchers("/", "/welcome", "/login").permitAll()
                //set pages which require authentication
                .antMatchers("/authenticated/**").hasAnyRole("ADMIN", "USER")
                .antMatchers("/userPage").hasAnyRole("ADMIN", "USER")
                .antMatchers("/adminPage").hasAnyRole("ADMIN")
                //override the default login page (see controller)
                .and().formLogin()
                    // swap failureUrl with .failureHandler(new CustomAuthenticationFailureHandler()) to trigger 500 error response instead
                    .loginPage("/login").permitAll().failureUrl("/login-error")
                .and().logout().logoutSuccessUrl("/welcome").permitAll()
                .and().csrf().disable()
                .rememberMe().key("remember-me").rememberMeParameter("remember_me")
                .rememberMeCookieName("WebDemoLoginRememberMe").tokenValiditySeconds(3600)
                //maximum of one session per user
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS).maximumSessions(1);

        // needed to access H2-console with Spring Security (use /console instead of /h2-console)
        // can be commented out without affecting above requests
        // thanks, John Thompson (https://springframework.guru/using-the-h2-database-console-in-spring-boot-with-spring-security/)
        http.csrf().disable();
        http.headers().frameOptions().disable();

        //ensures all data streams are HTTPS based (will require certification on deployment)
//        http.requiresChannel().anyRequest().requiresSecure();
    }
}