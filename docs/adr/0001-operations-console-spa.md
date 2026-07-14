# ADR 0001: 운영 콘솔 CSR SPA

- 상태: 승인
- 날짜: 2026-07-14
- 요구사항: UI-001~UI-014, SEC-001~SEC-005, NFR-005

## 문맥

운영 콘솔은 loopback과 SSH tunnel로만 접근하며 검색 노출이 필요 없습니다. 반면 실시간 SSE, 다중 화면, URL 기반 필터, 10,000 client 목록, 권한별 명령, stale 상태와 사건 timeline을 일관되게 관리해야 합니다. 기존 DOM 직접 변경 방식은 이 계약을 검증 가능한 구조로 확장하기 어렵습니다.

## 결정

- React와 strict TypeScript 기반 CSR SPA를 사용합니다.
- Bun은 package manager와 script runner로 사용하고 `bun.lock`을 커밋합니다.
- Vite는 정적 JavaScript bundle을 만들고 Tailwind CSS CLI는 정적 CSS를 생성합니다.
- shadcn/ui는 Dialog, AlertDialog, Tooltip, Sheet, Tabs, Dropdown, Toast와 Table 기반 component만 source로 편입합니다.
- TanStack Router는 화면·검색 조건을 URL에 보존하고 TanStack Query는 REST snapshot과 mutation을 관리합니다.
- 실시간 갱신은 native `EventSource`로 받고 서버 event version gap에서 snapshot을 다시 조회합니다.
- build된 `web/dist`만 `guard-control`에 포함합니다. Bun과 Node runtime은 운영 VPS에 설치하지 않습니다.

## 제외

- SSR과 hydration server
- daisyUI와 shadcn/ui 혼용
- marketing card grid와 범용 admin panel 기능
- 원본 token, private key와 request body의 browser 저장

## 결과

프런트엔드 의존성과 build 단계가 늘어나므로 CI가 typecheck, unit, production build, Playwright와 embedded-asset 동일성을 필수로 검사합니다. UI 실패는 edge data plane에 영향을 주지 않습니다.
