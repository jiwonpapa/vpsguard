/** 브라우저 입력의 즉시 피드백 규칙이며 서버 검증을 대체하지 않습니다. */
export function validateAdminSetup(
  username: string,
  password: string,
  confirmation: string,
): string | null {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$/.test(username.trim())) {
    return "관리자 ID 형식을 확인하십시오.";
  }
  if ([...password].length < 12 || new TextEncoder().encode(password).length > 1024) {
    return "비밀번호는 12자 이상 1,024 byte 이하여야 합니다.";
  }
  if (password !== confirmation) return "비밀번호 확인이 일치하지 않습니다.";
  return null;
}

/** TOTP는 공백 없는 ASCII 숫자 6자리만 허용합니다. */
export function isTotpCode(value: string): boolean {
  return /^[0-9]{6}$/.test(value);
}
