package com.apple.shop.domain.cart.Entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@NoArgsConstructor      // 가독성의 이유로 맨 위로 이동
@Entity
public class Cart {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private int member_id;
    private int status;
    private BigDecimal total_amount;
    private LocalDateTime created_at;
    private LocalDateTime updated_at;

}
