package com.harusari.chainware.member.command.domain.repository;

import com.harusari.chainware.member.command.domain.aggregate.Member;

import java.util.Optional;

public interface MemberCommandRepositoryCustom {

    Member findActiveMemberByEmail(String email);

    boolean existsByEmail(String email);

    Optional<Member> findByMemberId(Long memberId);

}