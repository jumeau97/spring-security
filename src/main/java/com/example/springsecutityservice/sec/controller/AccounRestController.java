package com.example.springsecutityservice.sec.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.springsecutityservice.sec.entities.AppRole;
import com.example.springsecutityservice.sec.entities.AppUser;
import com.example.springsecutityservice.sec.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccounRestController {

    private AccountService accountService;

    public AccounRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listeUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('USER')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){

         accountService.addROleToUser(roleUserForm.getUserName(), roleUserForm.getRoleName());
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws  Exception{
        String authToken = request.getHeader("Authorization");
        if(authToken!=null && authToken.startsWith("Bearer")){
            try {
                String jwt = authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("mySecret1234");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String username = decodedJWT.getSubject();
                //verifiez la black liste
                AppUser appUser = accountService.looadUserByUserName(username);

                String jwtAccessToken = JWT.create().
                        withSubject(appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis()+1*60*1000))
                        //Recuperer les role et convertir en une liste de strind
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String, String> idToken = new HashMap<>();
                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", jwt);
                //montrer au client que l'object contient du json
                response.setContentType("application/json");
                //serializer en objet en Json
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            }catch (Exception e){
                //response.setHeader("error-message", e.toString());
                //response.sendError(HttpServletResponse.SC_FORBIDDEN);
                throw e;

            }
        }else{
            throw new RuntimeException("Refresh token required !!!");
        }
    }

    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
        return accountService.looadUserByUserName(principal.getName());
    }
}

@Data
 class RoleUserForm{
    private String userName;
    private String roleName;
 }

