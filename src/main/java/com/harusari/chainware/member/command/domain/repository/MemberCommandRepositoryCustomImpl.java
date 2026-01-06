package com.harusari.chainware.member.command.domain.repository;

import com.harusari.chainware.member.command.domain.aggregate.Member;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

import static com.harusari.chainware.member.command.domain.aggregate.QMember.member;

@Repository
@RequiredArgsConstructor
public class MemberCommandRepositoryCustomImpl implements MemberCommandRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Member findActiveMemberByEmail(String email) {
        return queryFactory
                .selectFrom(member)
                .where(
                        member.email.eq(email),
                        member.isDeleted.eq(false)
                )
                .fetchOne();
    }

    @Override
    public boolean existsByEmail(String email) {
        return queryFactory
                .selectOne()
                .from(member)
                .where(member.email.eq(email))
                .fetchFirst() != null;
    }

    @Override
    public Optional<Member> findByMemberId(Long memberId) {
        return Optional.ofNullable(
                queryFactory
                        .selectFrom(member)
                        .where(member.memberId.eq(memberId))
                        .fetchOne()
        );
    }

}