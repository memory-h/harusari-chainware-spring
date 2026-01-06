package com.harusari.chainware.member.command.domain.repository;

import com.harusari.chainware.member.command.domain.aggregate.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberCommandRepository extends MemberCommandRepositoryCustom, JpaRepository<Member, Long> {

}