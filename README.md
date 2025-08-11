
# 🛒 쇼핑몰 프로젝트

## 📖 프로젝트 문서 허브

본 프로젝트의 모든 문서는 아래 노션 페이지에서 확인 가능합니다.
[📄 프로젝트 문서 허브](https://shopping-mall.notion.site/21a25e3f71a4809e982ecae26ba6cb96)

* **요구사항 정의서** – 서비스의 기능 요구사항과 비기능 요구사항 정리
* **유저 플로우** – 사용자의 서비스 이용 흐름 시각화
* **API 명세서** – REST API 설계 및 요청/응답 구조 정의
* **DB 명세서** – 데이터베이스 테이블 구조, 관계, 제약 조건 정의

---

## 📦 프로젝트 소개

사용자 인증, 마이페이지, 상품 목록 및 상세 조회, 장바구니, 주문 결제 등
전자상거래 서비스의 핵심 기능을 구현한 Spring Boot 기반 쇼핑몰입니다.

---

## 🛠️ 사용 기술

| 분류         | 기술 스택                                 |
| ---------- | ------------------------------------- |
| Language   | Java 17                               |
| Framework  | Spring Boot 3.4.5                     |
| Template   | Thymeleaf                             |
| Database   | MySQL                                 |
| ORM        | Spring Data JPA                       |

| Build Tool | Gradle                                |
| 기타         | Lombok, Spring Boot DevTools, JUnit 5 |

---

## 📂 프로젝트 구조

```plaintext
src
 └── main
     ├── java
     │    └── com.apple.shop
     │         ├── controller    # HTTP 요청 처리 및 응답 반환
     │         ├── service       # 비즈니스 로직 계층
     │         ├── repository    # 데이터 접근 계층(JPA)
     │         └── domain        # 엔티티 및 도메인 클래스
     └── resources
          ├── static             # 정적 자원 (CSS, JS, 이미지)
          ├── templates          # Thymeleaf 템플릿 뷰
          └── application.properties # 환경 설정
```

---

원하시면 이 README에 **각 문서 항목별로 노션 하위 링크**까지 바로 연결되게 만들어 드릴 수도 있습니다.
그렇게 하면 팀원들이 바로 특정 문서로 이동할 수 있습니다. 그렇게 해드릴까요?
