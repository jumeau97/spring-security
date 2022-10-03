package com.example.springsecutityservice.sec;

import com.example.springsecutityservice.sec.service.UserDetailsServiceImpl;
import com.example.springsecutityservice.sec.service.filters.JwtAuthenticationFilter;
import com.example.springsecutityservice.sec.service.filters.JwtAuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);


    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); // utiliser pour le stateLess authentication

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //auth stateLess

        http.headers().frameOptions().disable(); //desactiver l'utilisation pour le frames uniquement pour h2

        //Autoriser les ressources specifique
        //http.authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAuthority("ADMIN");
        //http.authorizeRequests().antMatchers(HttpMethod.GET, "/users/**").hasAuthority("USER");

        http.authorizeRequests().antMatchers("/h2-console/**", "/refreshToken/**", "/login/**", "/profile/**").permitAll();

        //http.formLogin(); //affiche le formulaire d'auth à l'utilisateur "utile pour auth stateFull"
        //http.authorizeRequests().anyRequest().permitAll(); //autorizer toutes les demandes

        http.authorizeRequests().anyRequest().authenticated(); // authentification obligatoire pour accéder aux ressources
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);


    }

    @Bean //vous pouvez l'injecter ou vous voulez
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
