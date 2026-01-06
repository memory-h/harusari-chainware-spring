package com.harusari.chainware.member.command.application.service;

import com.harusari.chainware.exception.auth.MemberNotFoundException;
import com.harusari.chainware.exception.member.*;
import com.harusari.chainware.franchise.command.application.service.FranchiseCommandService;
import com.harusari.chainware.member.command.application.dto.request.MemberCreateRequest;
import com.harusari.chainware.member.command.application.dto.request.PasswordChangeRequest;
import com.harusari.chainware.member.command.application.dto.request.UpdateMemberRequest;
import com.harusari.chainware.member.command.application.dto.request.UpdateMyInfoRequest;
import com.harusari.chainware.member.command.application.dto.request.franchise.MemberWithFranchiseRequest;
import com.harusari.chainware.member.command.application.dto.request.vendor.MemberWithVendorRequest;
import com.harusari.chainware.member.command.application.dto.request.warehouse.MemberWithWarehouseRequest;
import com.harusari.chainware.member.command.domain.aggregate.Authority;
import com.harusari.chainware.member.command.domain.aggregate.Member;
import com.harusari.chainware.member.command.domain.aggregate.MemberAuthorityType;
import com.harusari.chainware.member.command.domain.repository.AuthorityCommandRepository;
import com.harusari.chainware.member.command.domain.repository.MemberCommandRepository;
import com.harusari.chainware.member.common.mapstruct.MemberMapStruct;
import com.harusari.chainware.vendor.command.application.service.VendorCommandService;
import com.harusari.chainware.warehouse.command.domain.aggregate.Warehouse;
import com.harusari.chainware.warehouse.command.domain.repository.WarehouseRepository;
import com.harusari.chainware.warehouse.common.mapstruct.WarehouseMapStruct;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import static com.harusari.chainware.exception.auth.AuthErrorCode.MEMBER_NOT_FOUND_EXCEPTION;
import static com.harusari.chainware.exception.member.MemberErrorCode.*;
import static com.harusari.chainware.member.common.constants.EmailValidationConstant.EMAIL_VALIDATION_PREFIX;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberCommandServiceImpl implements MemberCommandService {

    private final MemberMapStruct memberMapStruct;
    private final WarehouseMapStruct warehouseMapStruct;
    private final PasswordEncoder passwordEncoder;

    private final FranchiseCommandService franchiseCommandService;
    private final VendorCommandService vendorCommandService;

    private final MemberCommandRepository memberCommandRepository;
    private final AuthorityCommandRepository authorityCommandRepository;
    private final WarehouseRepository warehouseRepository;

    private final RedisTemplate<String, String> redisTemplate;

    @Override
    public void registerHeadquartersMember(MemberCreateRequest memberCreateRequest) {
        if (
                memberCreateRequest.authorityName() == MemberAuthorityType.MASTER ||
                        memberCreateRequest.authorityName() == MemberAuthorityType.GENERAL_MANAGER ||
                        memberCreateRequest.authorityName() == MemberAuthorityType.SENIOR_MANAGER
        ) {
            registerMember(memberCreateRequest);
            deleteEmailVerificationToken(memberCreateRequest.validationToken());
        } else {
            throw new InvalidMemberAuthorityException(INVALID_MEMBER_AUTHORITY);
        }
    }

    @Override
    public void registerFranchise(MemberWithFranchiseRequest memberWithFranchiseRequest, MultipartFile agreementFile) {
        MemberCreateRequest memberCreateRequest = memberWithFranchiseRequest.memberCreateRequest();

        if (memberCreateRequest.authorityName() == MemberAuthorityType.FRANCHISE_MANAGER) {
            Member member = registerMember(memberCreateRequest);
            franchiseCommandService.createFranchiseWithAgreement(member.getMemberId(), memberWithFranchiseRequest, agreementFile);
            deleteEmailVerificationToken(memberCreateRequest.validationToken());
        } else {
            throw new InvalidMemberAuthorityException(INVALID_MEMBER_AUTHORITY);
        }
    }

    @Override
    public void registerVendor(MemberWithVendorRequest memberWithVendorRequest, MultipartFile agreementFile) {
        MemberCreateRequest memberCreateRequest = memberWithVendorRequest.memberCreateRequest();

        if (memberCreateRequest.authorityName() == MemberAuthorityType.VENDOR_MANAGER) {
            Member member = registerMember(memberCreateRequest);
            vendorCommandService.createVendorWithAgreement(member.getMemberId(), memberWithVendorRequest, agreementFile);
            deleteEmailVerificationToken(memberCreateRequest.validationToken());
        } else {
            throw new InvalidMemberAuthorityException(INVALID_MEMBER_AUTHORITY);
        }
    }

    @Override
    public void registerWarehouse(MemberWithWarehouseRequest memberWithWarehouseRequest) {
        MemberCreateRequest memberCreateRequest = memberWithWarehouseRequest.memberCreateRequest();

        if (memberCreateRequest.authorityName() == MemberAuthorityType.WAREHOUSE_MANAGER) {
            Member member = registerMember(memberCreateRequest);
            Warehouse warehouse = warehouseMapStruct.toWarehouse(memberWithWarehouseRequest.warehouseCreateRequest(), member.getMemberId());
            warehouseRepository.save(warehouse);
            deleteEmailVerificationToken(memberCreateRequest.validationToken());
        } else {
            throw new InvalidMemberAuthorityException(INVALID_MEMBER_AUTHORITY);
        }
    }

    @Override
    public void changePassword(PasswordChangeRequest passwordChangeRequest, String email) {
        Member member = memberCommandRepository.findActiveMemberByEmail(email);

        validateCurrentPassword(passwordChangeRequest.currentPassword(), member.getPassword());
        validateNewPassword(passwordChangeRequest, member.getPassword());

        String encodedPassword = passwordEncoder.encode(passwordChangeRequest.newPassword());
        member.updateEncodedPassword(encodedPassword);
    }

    @Override
    public void updateMemberInfo(Long memberId, UpdateMemberRequest updateMemberRequest) {
        Member member = memberCommandRepository.findByMemberId(memberId)
                .orElseThrow(() -> new MemberNotFoundException(MEMBER_NOT_FOUND_EXCEPTION));

        Authority authority = authorityCommandRepository.findByAuthorityName(updateMemberRequest.authorityName());

        member.updateMember(authority.getAuthorityId(), updateMemberRequest);
    }

    @Override
    public void updateMyInfo(Long memberId, UpdateMyInfoRequest updateMyInfoRequest) {
        Member member = memberCommandRepository.findByMemberId(memberId)
                .orElseThrow(() -> new MemberNotFoundException(MEMBER_NOT_FOUND_EXCEPTION));

        member.updateMyInfo(updateMyInfoRequest);
    }

    @Override
    public void deleteMemberRequest(Long memberId) {
        Member member = memberCommandRepository.findByMemberId(memberId)
                .orElseThrow(() -> new MemberNotFoundException(MEMBER_NOT_FOUND_EXCEPTION));

        member.softDelete();
    }

    private Member registerMember(MemberCreateRequest memberCreateRequest) {
        validateEmailVerification(memberCreateRequest.email(), memberCreateRequest.validationToken());

        if (memberCommandRepository.existsByEmail(memberCreateRequest.email())) {
            throw new EmailAlreadyExistsException(EMAIL_ALREADY_EXISTS);
        }

        Member member = memberMapStruct.toMember(memberCreateRequest);
        member.updateEncodedPassword(passwordEncoder.encode(memberCreateRequest.password()));

        Authority authority = authorityCommandRepository.findByAuthorityName(memberCreateRequest.authorityName());
        member.updateAuthorityId(authority.getAuthorityId());

        memberCommandRepository.save(member);

        return member;
    }

    private void validateEmailVerification(String email, String token) {
        String redisKey = EMAIL_VALIDATION_PREFIX + token;
        String emailInRedis = redisTemplate.opsForValue().get(redisKey);

        if (emailInRedis == null || !emailInRedis.equals(email)) {
            throw new EmailVerificationRequiredException(EMAIL_VERIFICATION_REQUIRED);
        }
    }

    private void deleteEmailVerificationToken(String token) {
        String redisKey = EMAIL_VALIDATION_PREFIX + token;
        redisTemplate.delete(redisKey);
    }

    private void validateCurrentPassword(String currentPassword, String storedPassword) {
        if (!passwordEncoder.matches(currentPassword, storedPassword)) {
            throw new InvalidCurrentPasswordException(INVALID_CURRENT_PASSWORD_EXCEPTION);
        }
    }

    private void validateNewPassword(PasswordChangeRequest request, String currentPassword) {
        final int PASSWORD_MINIMUM_LENGTH = 8;
        String newPassword = request.newPassword();
        String confirmPassword = request.confirmPassword();

        if (newPassword.length() < PASSWORD_MINIMUM_LENGTH) {
            throw new InvalidPasswordChangeException(INVALID_PASSWORD_CHANGE_EXCEPTION);
        }

        if (!newPassword.equals(confirmPassword)) {
            throw new PasswordConfirmationMismatchException(PASSWORD_CONFIRMATION_MISMATCH_EXCEPTION);
        }

        if (passwordEncoder.matches(newPassword, currentPassword)) {
            throw new PasswordSameAsCurrentException(PASSWORD_SAME_AS_CURRENT_EXCEPTION);
        }
    }

}