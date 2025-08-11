


# ⚙️ Codebase Extraction
기존 쇼핑몰 프로젝트를 모듈 추출(Module Extraction) 과정을 거쳐 범용 코어 모듈로 전환

## 📦 모듈 소개

사용자 인증, 프로필 관리, 콘텐츠(아이템) 조회 등
여러 서비스에서 공통적으로 필요한 핵심 기능을 제공하는 기반 모듈입니다.
새로운 프로젝트의 빠른 개발을 위해 재사용할 수 있도록 설계되었습니다.

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

## 📂 프로젝트 구조

```plaintext
src
 └── main
     ├── java
     │    └── com.apple.core
     │         ├── controller    # HTTP 요청 처리 및 응답 반환
     │         ├── service       # 비즈니스 로직 계층
     │         ├── repository    # 데이터 접근 계층(JPA)
     │         └── domain        # 엔티티 및 도메인 클래스
     └── resources
          ├── static             # 정적 자원 (CSS, JS, 이미지)
          ├── templates          # Thymeleaf 템플릿 뷰
          └── application.properties # 환경 설정
```


