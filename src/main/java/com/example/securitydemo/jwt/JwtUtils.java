package com.example.securitydemo.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
@Component
public class JwtUtils {
    private static final Logger logger= LoggerFactory.getLogger(JwtUtils.class);
    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;
    //getting jwt from headers
    public String getJwtFromHeader(HttpServletRequest request){
       String bearerToken=request.getHeader("Authorization");
       logger.debug("Authorization Header: {}",bearerToken);
       if(bearerToken!=null && bearerToken.startsWith("Bearer")){
           return bearerToken.substring(7);//remove the prefix
       }
       return null;
    }
    //generating username from token
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date().getTime() + jwtExpirationMs)))
                .signWith(key())
                .compact();
    }
    //generating username from jwt token
    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key()) // new API (not notify)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    //generate signing key
    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
    //validate jwt token
    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("Validate");
            Jwts.parser()
                    .verifyWith((SecretKey) key()) // new API (not notify)
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        }
        catch (MalformedJwtException exception){
            logger.error("Invalid JWT token : {}"+ exception.getMessage());
        }
        catch (ExpiredJwtException exception){
            logger.error("JWT token is expired: {}" +exception.getMessage());
        }
        catch (UnsupportedJwtException e){
            logger.error("JWT token is unsupported: {}"+e.getMessage());
        }
        catch (IllegalArgumentException e){
            logger.error("JWT claims String is empty: {}"+e.getMessage());
        }
        return false;
    }

}
