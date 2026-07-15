# 핵심 서비스 관측 설정

VPSGuard는 서버의 모든 프로세스를 검색하지 않습니다. 관리자가 `collectors.services`에 명시한 최대 16개 systemd unit만 5초마다 읽고, cgroup v2 자원값과 서비스 자체 병목 지표를 함께 표시합니다. 수집기는 Edge 요청 경로와 분리되며 각 probe에는 독립 timeout이 적용됩니다.

## 수집 범위

| 종류 | cgroup 공통값 | 의미 지표 |
|---|---|---|
| Nginx | CPU, memory, I/O, process/task, OOM | active/read/write/wait connection, request 누계 |
| Apache | 동일 | busy/idle worker, access 누계 |
| PHP-FPM | 동일 | listen queue, active/idle child, max-children·slow 누계 |
| MySQL/MariaDB | 동일 | connected/running, max connection, slow query, InnoDB lock wait, aborted connect |
| Redis | 동일 | memory, connected/blocked client, hit/miss, eviction |

값은 진단 보조 자료입니다. `delayed`, `stale`, component 오류 코드가 표시된 값은 현재 정상값으로 해석하지 않습니다.

## 설정

[`configs/vps-guard.example.toml`](../configs/vps-guard.example.toml)의 예시처럼 `unit`, `kind`와 probe만 명시합니다. 기본 cgroup 경로는 `system.slice/<unit>`이며, template/slice 구성이 다른 서버만 실제 unit 이름으로 끝나는 상대 `cgroup_path`를 지정합니다. status URL과 Redis address는 loopback만 허용됩니다.

Nginx/Apache/PHP-FPM status endpoint도 반드시 별도 loopback listener와 웹서버 allow/deny로 제한합니다. public virtual host에 status location을 노출하지 않습니다.

## MySQL/MariaDB credential

collector는 `SHOW GLOBAL STATUS`와 `SHOW GLOBAL VARIABLES LIKE 'max_connections'`만 실행합니다. MySQL 공식 계약상 `SHOW STATUS`는 접속 권한 외 별도 권한을 요구하지 않으므로 `PROCESS`, 전체 DB `SELECT`, 관리자 role을 부여하지 않습니다.

- [MySQL 8.4 SHOW STATUS](https://dev.mysql.com/doc/refman/8.4/en/show-status.html)
- [MariaDB SHOW STATUS](https://mariadb.com/docs/server/reference/sql-statements/administrative-sql-statements/show/show-status)

```sql
CREATE USER 'vpsguard_monitor'@'127.0.0.1'
  IDENTIFIED BY '별도-긴-비밀번호'
  WITH MAX_USER_CONNECTIONS 2;
SHOW GRANTS FOR 'vpsguard_monitor'@'127.0.0.1';
```

`/etc/vps-guard/secrets/mysql-monitor-url`에는 URL 예약문자를 percent-encoding한 다음 아래 한 줄만 저장합니다.

```text
mysql://vpsguard_monitor:ENCODED_PASSWORD@127.0.0.1:3306/
```

## Redis credential

Redis 6 이상에서는 전용 ACL user에 `PING`, `INFO`만 허용합니다.

```text
ACL SETUSER vpsguard_monitor reset on >별도-긴-비밀번호 +ping +info
```

`/etc/vps-guard/secrets/redis-monitor-url`:

```text
redis://vpsguard_monitor:ENCODED_PASSWORD@127.0.0.1:6379/
```

## systemd 전달

원본 credential은 root 소유 regular file, mode `0600`으로 만들고 설정 TOML이나 환경변수에 값을 넣지 않습니다. [`vps-guard-control-service-credentials.conf.example`](../packaging/systemd/vps-guard-control-service-credentials.conf.example)을 `/etc/systemd/system/vps-guard-control.service.d/20-service-credentials.conf`로 설치한 뒤 daemon reload와 service restart를 수행합니다.

```bash
sudo install -d -o root -g root -m 0700 /etc/vps-guard/secrets
sudo chmod 0600 /etc/vps-guard/secrets/mysql-monitor-url /etc/vps-guard/secrets/redis-monitor-url
sudo systemctl daemon-reload
sudo systemctl restart vps-guard-control.service
```

URL과 비밀번호는 journal, UI, API 오류에 출력하지 않습니다. credential 오류는 안정된 오류 코드만 표시합니다.
