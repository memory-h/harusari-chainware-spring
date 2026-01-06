package com.harusari.chainware.auth.service;

import com.harusari.chainware.auth.model.CustomUserDetails;
import com.harusari.chainware.exception.auth.MemberNotFoundException;
import com.harusari.chainware.member.query.dto.MemberDetailDTO;
import com.harusari.chainware.member.query.repository.MemberQueryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static com.harusari.chainware.exception.auth.AuthErrorCode.MEMBER_NOT_FOUND_EXCEPTION;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberQueryRepository memberQueryRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        MemberDetailDTO memberDetailDto = memberQueryRepository.findMemberDetailDtoByEmail(email)
                .orElseThrow(() -> new MemberNotFoundException(MEMBER_NOT_FOUND_EXCEPTION));

        return new CustomUserDetails(memberDetailDto.memberId(), memberDetailDto.email(), memberDetailDto.authorityName());
    }

}