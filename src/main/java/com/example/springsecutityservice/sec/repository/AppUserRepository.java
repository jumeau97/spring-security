package com.example.springsecutityservice.sec.repository;

import com.example.springsecutityservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUserName(String userName);
}
