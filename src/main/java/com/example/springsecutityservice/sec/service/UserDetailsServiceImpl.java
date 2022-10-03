package com.example.springsecutityservice.sec.service;

import com.example.springsecutityservice.sec.entities.AppUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private AccountService accountService;

    public UserDetailsServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = accountService.looadUserByUserName(username);
        //créer une collection de type GrantAuthority
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        appUser.getAppRoles().forEach(r->{
            authorities.add(new SimpleGrantedAuthority(r.getRoleName()));
        });
        //objet user de spring
        return new User(appUser.getUserName(), appUser.getPassword(), authorities);
    }
}
