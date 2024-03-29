package com.project.securebackend.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    // SECRET KEY
    private static final String SECRET_KEY = "294A404E635166546A576E5A7234753778214125442A472D4B6150645367556B";

    // EXTRACT USERNAME FROM JWT TOKEN
    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    // EXTRACT CLAIM FROM JWT TOKEN
    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
      }
    
    private Claims extractAllClaims(String jwtToken) {
        return Jwts.parserBuilder()
        .setSigningKey(getSigninKey())
        .build()
        .parseClaimsJws(jwtToken)
        .getBody();
    }

    private Key getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // GENERATE A JWT TOKEN
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
      }

    public String generateToken(
        Map<String, Object> extraClaims,
        UserDetails userDetails
    ) {
      return Jwts
          .builder()
          .setClaims(extraClaims)
          .setSubject(userDetails.getUsername())
          .setIssuedAt(new Date(System.currentTimeMillis()))
          .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
          .signWith(getSigninKey(), SignatureAlgorithm.HS256)
          .compact();
    }

    // VALIDATE A JWT TOKEN
    public boolean isTokenValid(String jwtToken, UserDetails userDetails) {
        final String username = extractUsername(jwtToken);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwtToken);
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }
    
}
