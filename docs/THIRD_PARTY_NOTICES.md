# VPSGuard third-party notices

VPSGuard는 아래 제3자 구성요소를 사용합니다. 이 문서는 VPSGuard 자체 라이선스를 변경하지 않으며 각 구성요소에는 해당 원 라이선스가 적용됩니다. 전체 dependency inventory와 정확한 버전은 release bundle의 CycloneDX SBOM 또는 `cargo-metadata.json`이 정본입니다.

## pam-client 0.5.0

- 용도: Ubuntu Linux-PAM의 `pam_authenticate`와 `pam_acct_mgmt` safe Rust adapter
- 라이선스: Mozilla Public License 2.0 (`MPL-2.0`)
- 원본 source: <https://gitlab.com/cg909/rust-pam-client/>
- 배포 version: <https://crates.io/crates/pam-client/0.5.0>
- 라이선스 전문: <https://www.mozilla.org/MPL/2.0/>

VPSGuard는 해당 crate를 수정하지 않습니다. binary 배포 시 이 고지와 SBOM을 함께 제공하고 위 경로에서 MPL covered source를 받을 수 있도록 유지합니다. crate를 수정하거나 vendor하면 수정된 covered file의 source와 고지를 같은 release에서 제공해야 합니다.

## shadcn/ui source components

- 용도: VPSGuard 운영 SPA의 소스 소유형 공통 UI 컴포넌트와 Tailwind CSS 설계 토큰
- 라이선스: MIT
- 원본 source: <https://github.com/shadcn-ui/ui>

## Radix UI 1.6.4

- 용도: dialog, alert dialog, select, checkbox와 tooltip의 접근성 primitive
- 라이선스: MIT
- 원본 source: <https://github.com/radix-ui/primitives>
- 배포 package: <https://www.npmjs.com/package/radix-ui/v/1.6.4>

## tw-animate-css 1.4.0

- 용도: shadcn/ui 상태 전환 animation utility
- 라이선스: MIT
- 원본 source: <https://github.com/Wombosvideo/tw-animate-css>

## Geist Variable 5.3.0

- 용도: VPSGuard 운영 SPA의 Latin variable web font
- 라이선스: SIL Open Font License 1.1 (`OFL-1.1`)
- 원본 source: <https://github.com/vercel/geist-font>
- 배포 package: <https://www.npmjs.com/package/@fontsource-variable/geist/v/5.3.0>

## qrcode.react 4.2.0

- 용도: PAM·local 최초 TOTP 등록의 `otpauth` URI를 브라우저 내 SVG QR로 표시
- 라이선스: MIT
- 원본 source: <https://github.com/zpao/qrcode.react>
- 배포 package: <https://www.npmjs.com/package/qrcode.react/v/4.2.0>

QR은 embedded SPA에서 로컬 생성하며 secret 또는 `otpauth` URI를 외부 QR API로 전송하지 않습니다.
