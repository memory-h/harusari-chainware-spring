package com.harusari.chainware.exception.auth.jwt.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum SecurityError {

    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Unauthorized", "인증이 필요합니다."),
    FORBIDDEN(HttpStatus.FORBIDDEN, "Forbidden", "해당 계정의 권한으로는 접근할 수 없습니다.");

    private final HttpStatus status;
    private final String error;
    private final String defaultMessage;

}