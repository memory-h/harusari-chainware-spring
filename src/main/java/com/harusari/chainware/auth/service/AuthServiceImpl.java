package com.harusari.chainware.auth.service;

import com.harusari.chainware.auth.dto.request.LoginRequest;
import com.harusari.chainware.auth.dto.response.TokenResponse;
import com.harusari.chainware.auth.jwt.JwtTokenProvider;
import com.harusari.chainware.exception.auth.*;
import com.harusari.chainware.member.command.domain.aggregate.Authority;
import com.harusari.chainware.member.command.domain.aggregate.LoginHistory;
import com.harusari.chainware.member.command.domain.aggregate.Member;
import com.harusari.chainware.member.command.domain.repository.AuthorityCommandRepository;
import com.harusari.chainware.member.command.domain.repository.LoginHistoryCommandRepository;
import com.harusari.chainware.member.common.utils.UserAgentUtils;
import com.harusari.chainware.member.query.repository.MemberQueryRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

import static com.harusari.chainware.exception.auth.AuthErrorCode.*;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String HEADER_USER_AGENT = "User-Agent";
    private static final String IP_DELIMITER = ",";

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final MemberQueryRepository memberQueryRepository;
    private final AuthorityCommandRepository authorityCommandRepository;
    private final LoginHistoryCommandRepository loginHistoryCommandRepository;
    private final RedisTemplate<String, String> redisTemplate;

    @Transactional
    @Override
    public TokenResponse login(LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
        Member member = findAndValidateMember(loginRequest);
        Authority authority = loadAuthority(member.getAuthorityId());

        TokenResponse tokenResponse = generateTokens(member, authority);
        saveLoginHistory(member, httpServletRequest);

        return tokenResponse;
    }

    @Override
    public void logout(String providedRefreshToken) {
        String email = validateAndGetEmailFromRefreshToken(providedRefreshToken);
        redisTemplate.delete(email);
    }

    @Override
    public TokenResponse refreshToken(String providedRefreshToken) {
        String email = validateAndGetEmailFromRefreshToken(providedRefreshToken);

        Member member = findMemberByEmail(email);
        Authority authority = loadAuthority(member.getAuthorityId());

        return generateTokens(member, authority);
    }

    private Member findAndValidateMember(LoginRequest loginRequest) {
        Member member = findMemberByEmail(loginRequest.email());
        if (!passwordEncoder.matches(loginRequest.password(), member.getPassword())) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_EXCEPTION);
        }
        return member;
    }

    private Member findMemberByEmail(String email) {
        return memberQueryRepository.findActiveMemberByEmail(email)
                .orElseThrow(() -> new MemberNotFoundException(MEMBER_NOT_FOUND_EXCEPTION));
    }

    private Authority loadAuthority(Integer authorityId) {
        return authorityCommandRepository.findByAuthorityId(authorityId);
    }

    private TokenResponse generateTokens(Member member, Authority authority) {
        String accessToken = jwtTokenProvider.createToken(member.getEmail(), authority.getAuthorityName());
        String refreshToken = jwtTokenProvider.createRefreshToken(member.getEmail(), authority.getAuthorityName());

        storeRefreshToken(member.getEmail(), refreshToken);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void storeRefreshToken(String email, String refreshToken) {
        redisTemplate.opsForValue().set(
                email, refreshToken, Duration.ofMillis(jwtTokenProvider.getRefreshExpiration())
        );
    }

    private String validateAndGetEmailFromRefreshToken(String providedRefreshToken) {
        jwtTokenProvider.validateToken(providedRefreshToken); // RefreshToken 유효성 검사
        String email = jwtTokenProvider.getEmailFromJWT(providedRefreshToken);

        String storedRefreshToken = getStoredRefreshToken(email); // Redis에 저장된 RefreshToken 조회
        validateRefreshToken(providedRefreshToken, storedRefreshToken); // 넘어온 리프레시 토큰과 Redis에서 조회한 리프레시 토큰 일치 확인

        return email;
    }

    private String getStoredRefreshToken(String email) {
        return redisTemplate.opsForValue().get(email);
    }

    private void validateRefreshToken(String providedRefreshToken, String storedRefreshToken) {
        if (storedRefreshToken == null) {
            throw new RefreshTokenNotFoundException(REFRESH_TOKEN_NOT_FOUND_EXCEPTION);
        }

        if (!storedRefreshToken.equals(providedRefreshToken)) {
            throw new RefreshTokenMismatchException(REFRESH_TOKEN_MISMATCH_EXCEPTION);
        }
    }

    private void saveLoginHistory(Member member, HttpServletRequest request) {
        String ipAddress = extractClientIp(request);
        String userAgent = request.getHeader(HEADER_USER_AGENT);
        String browser = UserAgentUtils.parseBrowser(userAgent);

        LoginHistory loginHistory = LoginHistory.builder()
                .memberId(member.getMemberId())
                .ipAddress(ipAddress)
                .browser(browser)
                .build();

        loginHistoryCommandRepository.save(loginHistory);
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader(HEADER_X_FORWARDED_FOR);
        return forwarded != null ? forwarded.split(IP_DELIMITER)[0].trim() : request.getRemoteAddr();
    }

}