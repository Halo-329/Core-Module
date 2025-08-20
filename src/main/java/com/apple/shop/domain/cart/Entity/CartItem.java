package com.apple.shop.domain.cart.Entity;

import com.apple.shop.domain.item.entity.Item;
import com.apple.shop.domain.member.entity.Member;
import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@NoArgsConstructor      // 가독성의 이유로 맨 위로 이동
@Getter
@Setter
@Entity
@Table(
        name="cart_item",
        uniqueConstraints = @UniqueConstraint(columnNames = {"member_id", "item_id"})
)
@AllArgsConstructor
@Builder
public class CartItem {

    //1. ID
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    // 2. 사용자
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "member_id",
            foreignKey = @ForeignKey(ConstraintMode.CONSTRAINT) //member_id를 외래키로 설정
    )
    private Member member;

    //3. 아이템
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "item_id",
            foreignKey = @ForeignKey(ConstraintMode.CONSTRAINT)
    )
    private Item item;


    //4. 상품 개수
    @Column(nullable = false)
    private int quantity;

    //5. 장바구니 담은 날짜
    @Column
    @CreationTimestamp
    private LocalDateTime createdAt;    //  카멜케이스 코드 컨벤션 따르기

    //6. 해당 상품 업데이트 날짜
    @Column
    @UpdateTimestamp
    private LocalDateTime updated_at;
}
