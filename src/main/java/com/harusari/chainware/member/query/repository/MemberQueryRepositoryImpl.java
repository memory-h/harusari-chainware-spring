package com.harusari.chainware.member.query.repository;

import com.harusari.chainware.member.command.domain.aggregate.Member;
import com.harusari.chainware.member.command.domain.aggregate.MemberAuthorityType;
import com.harusari.chainware.member.query.dto.MemberDetailDTO;
import com.harusari.chainware.member.query.dto.request.MemberSearchRequest;
import com.harusari.chainware.member.query.dto.response.LoginHistoryResponse;
import com.harusari.chainware.member.query.dto.response.MemberSearchDetailResponse;
import com.harusari.chainware.member.query.dto.response.MemberSearchResponse;
import com.harusari.chainware.member.query.dto.response.MyMemberDetailResponse;
import com.querydsl.core.types.Projections;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

import static com.harusari.chainware.member.command.domain.aggregate.QAuthority.authority;
import static com.harusari.chainware.member.command.domain.aggregate.QMember.member;
import static com.harusari.chainware.member.command.domain.aggregate.QLoginHistory.loginHistory;

@Repository
@RequiredArgsConstructor
public class MemberQueryRepositoryImpl implements MemberQueryRepositoryCustom {

    private static final long TOTAL_DEFAULT_VALUE = 0L;

    private final JPAQueryFactory queryFactory;

    @Override
    public boolean existsByEmail(String email) {
        return queryFactory
                .selectOne()
                .from(member)
                .where(member.email.eq(email))
                .fetchFirst() != null;
    }

    @Override
    public Optional<Member> findActiveMemberByEmail(String email) {
        return Optional.ofNullable(
                queryFactory
                        .selectFrom(member)
                        .where(
                                member.email.eq(email),
                                member.isDeleted.eq(false)
                        )
                        .fetchOne()
        );
    }

    @Override
    public Page<MemberSearchResponse> findMembers(MemberSearchRequest memberSearchRequest, Pageable pageable) {
        List<MemberSearchResponse> contents = queryFactory
                .select(Projections.constructor(MemberSearchResponse.class,
                        member.memberId, member.email, member.name,
                        authority.authorityLabelKr, member.phoneNumber,
                        member.birthDate, member.position, member.joinAt, member.isDeleted
                ))
                .from(member)
                .leftJoin(authority).on(member.authorityId.eq(authority.authorityId))
                .where(
                        emailEq(memberSearchRequest.email()),
                        authorityEq(memberSearchRequest.authorityName()),
                        positionEq(memberSearchRequest.position()),
                        joinDateBetween(memberSearchRequest.joinDateFrom(), memberSearchRequest.joinDateTo()),
                        isDeletedFalse(memberSearchRequest.isDeleted())
                )
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .orderBy(member.memberId.asc())
                .fetch();

        Long result = queryFactory
                .select(member.count())
                .from(member)
                .leftJoin(authority).on(member.authorityId.eq(authority.authorityId))
                .where(
                        emailEq(memberSearchRequest.email()),
                        authorityEq(memberSearchRequest.authorityName()),
                        positionEq(memberSearchRequest.position()),
                        joinDateBetween(memberSearchRequest.joinDateFrom(), memberSearchRequest.joinDateTo()),
                        isDeletedFalse(memberSearchRequest.isDeleted())
                )
                .fetchOne();

        long total = Optional.ofNullable(result).orElse(TOTAL_DEFAULT_VALUE);

        return new PageImpl<>(contents, pageable, total);
    }

    @Override
    public Optional<MemberSearchDetailResponse> findMemberSearchDetailById(Long memberId) {
        return Optional.ofNullable(queryFactory
                .select(Projections.constructor(MemberSearchDetailResponse.class,
                        member.memberId, member.email, member.name,
                        authority.authorityLabelKr, member.phoneNumber,
                        member.birthDate, member.position, member.joinAt,
                        member.modifiedAt, member.isDeleted
                ))
                .from(member)
                .leftJoin(authority).on(member.authorityId.eq(authority.authorityId))
                .where(member.memberId.eq(memberId))
                .fetchOne()
        );
    }

    @Override
    public Optional<MyMemberDetailResponse> findMyMemberDetailById(Long memberId) {
        return Optional.ofNullable(queryFactory
                .select(Projections.constructor(MyMemberDetailResponse.class,
                        member.memberId, member.email, member.name,
                        authority.authorityLabelKr, member.phoneNumber,
                        member.birthDate, member.position
                ))
                .from(member)
                .leftJoin(authority).on(member.authorityId.eq(authority.authorityId))
                .where(member.memberId.eq(memberId))
                .fetchOne()
        );
    }

    @Override
    public Page<LoginHistoryResponse> findLoginHistoryByMemberId(Long memberId, Pageable pageable) {
        List<LoginHistoryResponse> contents = queryFactory
                .select(Projections.constructor(LoginHistoryResponse.class,
                        loginHistory.memberId, loginHistory.loginAt,
                        loginHistory.ipAddress, loginHistory.browser
                ))
                .from(loginHistory)
                .where(loginHistory.memberId.eq(memberId))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .orderBy(loginHistory.loginAt.desc())
                .fetch();

        Long result = queryFactory
                .select(loginHistory.count())
                .from(loginHistory)
                .where(loginHistory.memberId.eq(memberId))
                .fetchOne();

        long total = Optional.ofNullable(result).orElse(TOTAL_DEFAULT_VALUE);

        return new PageImpl<>(contents, pageable, total);
    }

    @Override
    public Optional<MemberDetailDTO> findMemberDetailDtoByEmail(String email) {
        return Optional.ofNullable(
                queryFactory
                        .select(Projections.constructor(MemberDetailDTO.class,
                                member.memberId, member.email, member.name, member.phoneNumber,
                                member.position, authority.authorityName, authority.authorityLabelKr
                        ))
                        .from(member)
                        .join(authority).on(member.authorityId.eq(authority.authorityId))
                        .where(member.isDeleted.eq(false))
                        .fetchOne()
        );
    }

    private BooleanExpression emailEq(String email) {
        return email != null ? member.email.eq(email) : null;
    }

    private BooleanExpression authorityEq(MemberAuthorityType authorityName) {
        return authorityName != null ? authority.authorityName.eq(authorityName) : null;
    }

    private BooleanExpression positionEq(String position) {
        return position != null ? member.position.eq(position) : null;
    }

    private BooleanExpression joinDateBetween(LocalDate from, LocalDate to) {
        if (from != null && to != null) {
            return member.joinAt.between(from.atStartOfDay(), to.atTime(LocalTime.MAX));
        } else if (from != null) {
            return member.joinAt.goe(from.atStartOfDay());
        } else if (to != null) {
            return member.joinAt.loe(to.atTime(LocalTime.MAX));
        } else {
            return null;
        }
    }

    private BooleanExpression isDeletedFalse(Boolean isDeleted) {
        if (isDeleted == null) {
            return null;
        }
        return member.isDeleted.eq(isDeleted);
    }

}