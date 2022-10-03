package com.example.springsecutityservice;

import com.example.springsecutityservice.sec.entities.AppRole;
import com.example.springsecutityservice.sec.entities.AppUser;
import com.example.springsecutityservice.sec.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
//pour autoriser les ressources
@EnableGlobalMethodSecurity(prePostEnabled =  true, securedEnabled = true)
public class SpringSecutityServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecutityServiceApplication.class, args);
	}

	@Bean
    PasswordEncoder passwordEncoder(){
	    return new BCryptPasswordEncoder();
    }

	@Bean
	CommandLineRunner start(AccountService accountService){
		return args -> {
			accountService.addNewRole(new AppRole(null, "USER"));
			accountService.addNewRole(new AppRole(null, "ADMIN"));
			accountService.addNewRole(new AppRole(null, "CUSTOMER_MANAGER"));
			accountService.addNewRole(new AppRole(null, "PRODUCT_MANAGER"));
			accountService.addNewRole(new AppRole(null, "BILLS_MANAGER"));

			accountService.addNewUser(new AppUser(null, "user1", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "admin", "1234",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user2", "1234",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user3", "1234",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user4", "1234",new ArrayList<>()));

			accountService.addROleToUser("user1", "USER");
			accountService.addROleToUser("admin", "USER");
			accountService.addROleToUser("admin", "ADMIN");
			accountService.addROleToUser("user2", "USER");
			accountService.addROleToUser("user2", "CUSTOMER_MANAGER");
			accountService.addROleToUser("user3", "USER");
			accountService.addROleToUser("user3", "PRODUCT_MANAGER");
			accountService.addROleToUser("user4", "USER");
			accountService.addROleToUser("user4", "BILLS_MANAGER");
		};
	}

}
