package com.springsecurity.weblogin.config;

import com.springsecurity.weblogin.exceptions.CustomAuthenticationFailureHandler;
import com.springsecurity.weblogin.services.springDataJPA.security.UserSDjpaService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;


//use @Secured annotation to enable authorisation
//@EnableGlobalMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    //commenting configure() and PasswordEncoder would direct Spring to load JPAUserDetailsService (required at production) ===
//    @Autowired
//    PasswordEncoder passwordEncoder;
//
//    @Override
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        //inMemoryAuthentication can be substituted with SDjpa + bootstrap initialisation
//        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder)
//                .withUser("user").password(passwordEncoder.encode("user123")).roles("USER")
//                .and()
//                .withUser("admin").password(passwordEncoder.encode("admin123")).roles("USER", "ADMIN");
//    }

    // ===================================================================================================================

    //must inject UserDetailsService (Spring Core interface) to enable remember-me (H2 in-memory or persistent DB)
    private final UserDetailsService userDetailsService;

    //inject when using persistent DB
    private final PersistentTokenRepository persistentTokenRepository;

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

        //the order of the antMatchers is important
        //note that any Spring Boot /webjars or CSS stylesheets from the project's /resources directory may need to be
        //to the antMatchers() list (in addition to "/", "/welcome" etc.) as "/webjars/**" and "/resources/**"

        // The difference between "/api/v1/user/*" and "/api/v1/user/**"
        // The former allows for any characters up to the first instance of a boundary character (&, =, / and ?) at which point,
        // matching is terminated. The latter ignores boundary characters and allows for any character sequence.

        //note, the ROLE_ is automatically prepended to Role here, under SDjpa
        http.authorizeRequests()
                //set pages which do not require authentication
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers("/", "/welcome").permitAll()
                //override the default login page (see controller)
                .and().formLogin()
                    // swap failureUrl with .failureHandler(new CustomAuthenticationFailureHandler()) to trigger 500 error response instead
                    .loginPage("/login").permitAll().failureUrl("/login-error")
                .and().httpBasic()
                .and().logout()
                    .logoutSuccessUrl("/welcome").permitAll()
                //enable CSRF protection for all except h2-console (should also be ignored for RESTful APIs, if applicable)
                //see POST Spring MVC mock tests for use of with(csrf())
                .and().csrf().ignoringAntMatchers("/h2-console/**")
                .and()
                .rememberMe()

                //database-persistent remember-me
                    .tokenRepository(persistentTokenRepository)
                    .userDetailsService(userDetailsService)

                //cookie-based (local) rememeber-me
//                    .key("web-login").rememberMeParameter("remember_me")
//                    .userDetailsService(userDetailsService)
//                    .rememberMeCookieName("WebDemoLoginRememberMe")
                    .tokenValiditySeconds(3600)

                //maximum of one session per user
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS).maximumSessions(1);

        // needed to access H2-console with Spring Security (use /console instead of /h2-console)
        // can be commented out without affecting above requests
        // see also (https://springframework.guru/using-the-h2-database-console-in-spring-boot-with-spring-security/)
        http.headers().frameOptions().sameOrigin();

        //ensures all data streams are HTTPS based (will require certification on deployment)
//        http.requiresChannel().anyRequest().requiresSecure();
    }
}
