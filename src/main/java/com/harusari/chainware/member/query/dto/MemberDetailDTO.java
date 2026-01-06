package com.harusari.chainware.member.query.dto;

import com.harusari.chainware.member.command.domain.aggregate.MemberAuthorityType;
import lombok.Builder;

@Builder
public record MemberDetailDTO(
        Long memberId, String email, String name, String phoneNumber,
        String position, MemberAuthorityType authorityName, String authorityLabelKr
) {
}