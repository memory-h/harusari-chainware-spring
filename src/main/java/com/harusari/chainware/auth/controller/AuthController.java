package com.harusari.chainware.auth.controller;

import com.harusari.chainware.auth.dto.request.LoginRequest;
import com.harusari.chainware.auth.dto.response.AccessTokenResponse;
import com.harusari.chainware.auth.dto.response.TokenResponse;
import com.harusari.chainware.auth.jwt.JwtTokenProvider;
import com.harusari.chainware.auth.service.AuthService;
import com.harusari.chainware.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "인증 API", description = "로그인, 로그아웃, 토큰 재발급 API")
public class AuthController {

    private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    private static final String COOKIE_PATH = "/api/v1/auth";
    private static final int COOKIE_DELETE_MAX_AGE = 0;
    private static final boolean HTTP_ONLY = true;

    @Value("${app.cookie.secure:true}")
    private boolean secure;

    @Value("${app.cookie.same-site:none}")
    private String sameSite;

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @Operation(summary = "로그인", description = "아이디와 비밀번호를 이용해 로그인을 수행하고 JWT 토큰을 발급합니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "로그인 성공")
    })
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AccessTokenResponse>> login(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "로그인 요청", required = true)
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest httpServletRequest
    ) {
        TokenResponse token = authService.login(loginRequest, httpServletRequest);

        return buildTokenResponse(token);
    }

    @Operation(summary = "로그아웃", description = "리프레시 토큰을 사용하여 로그아웃을 수행합니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "로그아웃 성공")
    })
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @Parameter(description = "리프레시 토큰 요청", required = true)
            @CookieValue(name = REFRESH_TOKEN_COOKIE_NAME) String refreshToken
    ) {
        authService.logout(refreshToken);
        ResponseCookie deleteCookie = createDeleteRefreshTokenCookie();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
                .body(ApiResponse.success(null));
    }

    @Operation(summary = "토큰 재발급", description = "리프레시 토큰을 이용해 새로운 JWT 토큰을 발급합니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "토큰 재발급 성공")
    })
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AccessTokenResponse>> refresh(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "리프레시 토큰 요청", required = true)
            @CookieValue(name = REFRESH_TOKEN_COOKIE_NAME) String refreshToken
    ) {
        TokenResponse tokenResponse = authService.refreshToken(refreshToken);

        return buildTokenResponse(tokenResponse);
    }

    /* accessToken 과 refreshToken을 body와 쿠키에 담아 반환 */
    private ResponseEntity<ApiResponse<AccessTokenResponse>> buildTokenResponse(TokenResponse tokenResponse) {
        ResponseCookie cookie = createRefreshTokenCookie(tokenResponse.refreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(ApiResponse.success(
                                AccessTokenResponse.builder()
                                        .accessToken(tokenResponse.accessToken())
                                        .build()
                        )
                );
    }

    /* refreshToken 쿠키 생성 */
    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                .httpOnly(HTTP_ONLY)
                .secure(secure)
                .path(COOKIE_PATH)
                .maxAge(Duration.ofSeconds(jwtTokenProvider.getRefreshTokenMaxAgeSeconds()))
                .sameSite(sameSite)
                .build();
    }

    /* 쿠키 삭제용 설정 */
    private ResponseCookie createDeleteRefreshTokenCookie() {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .httpOnly(HTTP_ONLY)
                .secure(secure)
                .path(COOKIE_PATH)
                .maxAge(COOKIE_DELETE_MAX_AGE)
                .sameSite(sameSite)
                .build();
    }

}