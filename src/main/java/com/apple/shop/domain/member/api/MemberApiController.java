package com.apple.shop.domain.member.api;

import com.apple.shop.domain.member.entity.Member;
import com.apple.shop.domain.member.repo.MemberRepo;
import io.swagger.v3.oas.annotations.Operation;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/members")
public class MemberApiController {

    private final MemberRepo memberRepo;

    @GetMapping("/{id}")
    @Operation(summary = "회원 단건 조회", description = "ID로 회원 정보를 조회합니다.")
    public ResponseEntity<MemberDTO> get(@PathVariable Long id){
        Member m = memberRepo.findById(id).orElseThrow();
        return ResponseEntity.ok(new MemberDTO(m.getId(), m.getLoginId(), m.getUsrName()));
    }

    @GetMapping("/me")
    @Operation(summary = "내 인증 정보", description = "JWT 인증 주체 문자열을 반환합니다.")
    public ResponseEntity<String> me(Authentication auth){
        return ResponseEntity.ok(auth == null ? "(Error) auth is null" : auth.getPrincipal().toString());
    }

    public record MemberDTO(@NonNull Long id, @NonNull String loginId, @NonNull String usrName) {}
}
