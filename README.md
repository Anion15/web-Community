# 🛜 web-Community

웹 브라우저에서 실행되는 실시간 커뮤니티입니다.  
Tailwind CSS, Flask, Sqlite 기반으로 구축되었습니다.



---
&nbsp;
&nbsp;
## 🌍 적용 기술

&nbsp;
&nbsp;
&nbsp;
&nbsp;

| 분류               | 기술 요소                                   | 설명                                                                                 |
| ---------------- | --------------------------------------- | ---------------------------------------------------------------------------------- |
| **웹 프레임워크**      | `Flask`                                 | Python 기반 경량 웹 프레임워크로 REST API 및 웹 페이지 렌더링을 담당.                                    |
| **데이터베이스**       | `SQLAlchemy`                            | ORM(Object Relational Mapper) 라이브러리로, SQLite와 연동해 데이터 모델(User, Post, Comment)을 관리. |
| **사용자 인증 및 세션**  | `flask_login`, Flask 세션                 | 로그인 관리 및 세션 유지, 클라이언트별 UUID 기반 client\_id를 세션에 저장하여 식별 및 추적에 사용.                   |
| **보안**           | 세션 쿠키 설정 (Secure, HttpOnly, SameSite)   | 세션 쿠키의 보안 강화 설정 적용.                                                                |
| **IP 추적 및 제한**   | IP 변경 추적, IP 변경 횟수 제한, 레이트 리미팅          | IP 변경 기록을 세션에 저장, 5분 내 IP 변경 횟수 제한, 요청 빈도에 따른 포스트 및 댓글 레이트 리미팅 구현.                 |
| **스팸 방지**        | 게시물 및 댓글 중복 검사, 유사도 검사                  | 최근 게시글 5개와 비교해 제목/내용 유사도가 70% 이상이면 스팸으로 판단.                                        |
| **클라이언트 유효성 검사** | Origin, Referer, User-Agent 검사 (주석 처리됨) | 클라이언트 요청의 유효성 검증 로직 (현재는 주석 처리되어 있음).                                              |
| **시간 관리**        | 한국 시간대 적용 (`datetime` + `timezone`)     | UTC 기준에서 한국 시간(UTC+9)으로 변환하여 일관된 시간 저장 및 표시.                                       |
| **스레드 동기화**      | `threading.Lock()`                      | 서버에서 동시성 문제 방지를 위한 데이터 전송량 동기화 처리용 락 구현.                                           |
| **유효성 검사**       | UUID 형식 검증, 비정상 유니코드 문자 검사              | 클라이언트 ID 형식 검사 및 텍스트 내 비정상 Unicode 문자 필터링 기능 포함.                                   |



&nbsp;
&nbsp;

---
&nbsp;
&nbsp;
## 코드 활용시 필수 수정 사항

| 부분        | 수정사항 |
|--------------------|------|
| [main.py- is_valid_client](https://github.com/Anion15/web-Community/blob/9e5c6ed8148e9d8a6ad705aeab5a971f712d24a9/main.py#L128-L149), 128번줄~149번줄           | 주석 제거하여 코드 활성화하고, allowed_origin/referer_prefix 변수에 올바른 url 주소를 넣어주세요.|
| [.env- SECRET_KEY](https://github.com/Anion15/web-Community/blob/9e5c6ed8148e9d8a6ad705aeab5a971f712d24a9/.env#L2), 2번줄                                        | SECRET_KEY의 키를 변경하세요. |
| [loading.html- targetUrl](https://github.com/Anion15/web-Community/blob/9e5c6ed8148e9d8a6ad705aeab5a971f712d24a9/templates/loading.html#L50), 50번줄            | targetUrl에 올바른 url 주소를 넣어주세요. |

> 클라이언트 코드는 [JS 난독화](https://obfuscator.io/)를 하면 좋습니다.

---
&nbsp;
&nbsp;
## 📁 프로젝트 구조

```plaintext
├── templates/
│    └── admin_dashboard.html        #관리자 페이지
│    └── edit_post.html     # 관리자 페이지-게시물 수정 및 댓글 관리 페이
│    └── history.html     # 커뮤니티 역사 페이지
│    └── index.html     # 메인 페이지
│    └── info.html     # 커뮤니티 가이드 안내 페이지
│    └── loading.html     # 커뮤니티 이동 페이지
│    └── release-notes.html     # 릴리즈-노트 페이지
│    └── super.html
├── .env          # 시크릿 키 저장
├── LICENSE          # MIT License
└── main.py          # 메인 서버
```
&nbsp;
&nbsp;
&nbsp;

