package com.harusari.chainware.member.query.repository;

import com.harusari.chainware.member.query.dto.MemberDetailDTO;
import com.harusari.chainware.member.command.domain.aggregate.Member;
import com.harusari.chainware.member.query.dto.request.MemberSearchRequest;
import com.harusari.chainware.member.query.dto.response.LoginHistoryResponse;
import com.harusari.chainware.member.query.dto.response.MemberSearchDetailResponse;
import com.harusari.chainware.member.query.dto.response.MemberSearchResponse;
import com.harusari.chainware.member.query.dto.response.MyMemberDetailResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

public interface MemberQueryRepositoryCustom {

    boolean existsByEmail(String email);

    Optional<Member> findActiveMemberByEmail(String email);

    Page<MemberSearchResponse> findMembers(MemberSearchRequest condition, Pageable pageable);

    Optional<MemberSearchDetailResponse> findMemberSearchDetailById(Long memberId);

    Optional<MyMemberDetailResponse> findMyMemberDetailById(Long memberId);

    Page<LoginHistoryResponse> findLoginHistoryByMemberId(Long memberId, Pageable pageable);

    Optional<MemberDetailDTO> findMemberDetailDtoByEmail(String email);

}