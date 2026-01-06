package com.harusari.chainware.auth.jwt;

import com.harusari.chainware.exception.auth.ExpiredJwtTokenException;
import com.harusari.chainware.exception.auth.EmptyJwtClaimsException;
import com.harusari.chainware.exception.auth.InvalidJwtTokenException;
import com.harusari.chainware.exception.auth.JwtTokenEmptyException;
import com.harusari.chainware.exception.auth.UnsupportedJwtTokenException;
import com.harusari.chainware.member.command.domain.aggregate.MemberAuthorityType;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static com.harusari.chainware.exception.auth.AuthErrorCode.*;

@Component
public class JwtTokenProvider {

    private static final String CLAIM_AUTHORITY = "authority";

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private long jwtRefreshExpiration;

    private SecretKey secretKey;

    @PostConstruct
    public void initSecretKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createToken(String email, MemberAuthorityType memberAuthorityType) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .subject(email)
                .claim(CLAIM_AUTHORITY, memberAuthorityType)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    public String createRefreshToken(String email, MemberAuthorityType memberAuthorityType) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtRefreshExpiration);

        return Jwts.builder()
                .subject(email)
                .claim(CLAIM_AUTHORITY, memberAuthorityType)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    public long getRefreshExpiration() {
        return jwtRefreshExpiration;
    }

    /**
     * Refresh Token의 유효 기간을 "초(seconds)" 단위로 반환한다.
     *
     * JWT Refresh Token의 만료 시간은 내부적으로 밀리초(ms) 단위로 관리되지만,
     * HTTP 쿠키의 Max-Age 속성은 초 단위를 사용하므로 변환이 필요하다.
     *
     * 이 메서드는 컨트롤러 계층에서 쿠키 생성 시 사용된다.
     *
     * @return refresh token 쿠키의 maxAge 값 (seconds)
     */
    public long getRefreshTokenMaxAgeSeconds() {
        return TimeUnit.MILLISECONDS.toSeconds(jwtRefreshExpiration);
    }

    public boolean validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new JwtTokenEmptyException(JWT_TOKEN_EMPTY_EXCEPTION);
        }

        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            throw new InvalidJwtTokenException(INVALID_JWT_TOKEN_EXCEPTION);
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtTokenException(EXPIRED_JWT_TOKEN_EXCEPTION);
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtTokenException(UNSUPPORTED_JWT_TOKEN_EXCEPTION);
        } catch (IllegalArgumentException e) {
            throw new EmptyJwtClaimsException(EMPTY_JWT_CLAIMS_EXCEPTION);
        }
    }

    public String getEmailFromJWT(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

}