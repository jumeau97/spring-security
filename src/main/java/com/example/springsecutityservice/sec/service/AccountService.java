package com.example.springsecutityservice.sec.service;

import com.example.springsecutityservice.sec.entities.AppRole;
import com.example.springsecutityservice.sec.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addROleToUser(String userName, String roleName );
    AppUser looadUserByUserName(String userName);
    List <AppUser> listeUsers();
}
