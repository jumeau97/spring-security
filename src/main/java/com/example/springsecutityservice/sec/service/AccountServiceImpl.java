package com.example.springsecutityservice.sec.service;

import com.example.springsecutityservice.sec.entities.AppRole;
import com.example.springsecutityservice.sec.entities.AppUser;
import com.example.springsecutityservice.sec.repository.AppRoleRepository;
import com.example.springsecutityservice.sec.repository.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {
    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;

    private PasswordEncoder passwordEncoder;

    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public AppUser addNewUser(AppUser appUser) {
        String pw = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pw));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addROleToUser(String userName, String roleName) {
        AppUser appUser = appUserRepository.findByUserName(userName);
        AppRole appRole = appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);

    }

    @Override
    public AppUser looadUserByUserName(String username) {
        return appUserRepository.findByUserName(username);
    }

    @Override
    public List<AppUser> listeUsers() {
        return appUserRepository.findAll();
    }
}
