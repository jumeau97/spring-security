package com.example.springsecutityservice.sec.service.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    //chaque fois qu'il ya une requête c'est la methode qui s'execute.
    @Override
    //chaque
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request, response);
        }else {

            String authorizationToken = request.getHeader(JwtUtil.AUTH_HEADER);
            if(authorizationToken!=null && authorizationToken.startsWith(JwtUtil.PREFIX)){
                try {
                    String jwt = authorizationToken.substring(JwtUtil.PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String r :roles){
                        authorities.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    //Authentification de l'utilisateur
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    //passage au filtre suivant
                    filterChain.doFilter(request, response);

                }catch (Exception e){
                    response.setHeader("error-message", e.toString());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);

                }
            }else{
                filterChain.doFilter(request, response);
            }

        }

    }
}
