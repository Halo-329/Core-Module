package com.apple.shop.domain.member.entity;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public long id;

    @Column
    private String loginId;
    private String loginPw;
    private String UsrName;
    private String Email;
    private String profileImageUrl; // 이미지 파일 경로나 S3, 서버 저장 경로




}
