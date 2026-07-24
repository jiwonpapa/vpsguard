import { ConsoleSection } from "../components/console-section";
import { SectionHeading } from "../components/section-heading";

const TERMS = [
  {
    term: "RPS",
    meaning: "관측 시간창의 초당 평균 요청 수입니다.",
    formula: "requests × 1,000 ÷ window milliseconds",
    source: "Edge의 bounded traffic aggregate",
  },
  {
    term: "p95 지연",
    meaning: "요청 100개 중 약 95개가 이 시간 안에 끝났다는 뜻입니다.",
    formula: "현재 시간창에서 최대 2,048개 latency sample의 95번째 백분위",
    source: "Edge 요청 완료 telemetry",
  },
  {
    term: "경로 비용 점수",
    meaning: "정규화 route가 CPU·DB·업로드 자원을 소모할 가능성을 0~10으로 분류한 profile 값입니다.",
    formula: "application profile 기본값 + site override, 최대 10",
    source: "versioned Edge policy",
  },
  {
    term: "서비스 압력",
    meaning: "핵심 서비스의 CPU와 queue·worker·connection·lock 병목 중 큰 값을 비교용 백분율로 표시합니다.",
    formula: "max(cgroup CPU%, service semantic pressure%)",
    source: "allowlist systemd cgroup와 read-only semantic probe",
  },
  {
    term: "Load / core",
    meaning: "1분 load average를 logical CPU 수로 나눈 값입니다. 100%면 core 수만큼 실행 대기 작업이 있다는 뜻입니다.",
    formula: "load 1m × 100 ÷ logical CPU count",
    source: "Linux /proc/loadavg와 /proc/stat",
  },
  {
    term: "Storage queue 손실",
    meaning: "Control 저장소가 밀려 상세 표본을 받지 못한 수입니다. Edge의 요청 처리는 계속됩니다.",
    formula: "queue send failure + writer failure sample count",
    source: "bounded non-blocking telemetry writer",
  },
  {
    term: "Retention backlog",
    meaning: "설정 보존기간을 지난 row가 한 번의 bounded 삭제 뒤에도 남아 있음을 뜻합니다.",
    formula: "각 계층 cutoff 이전 row 존재 여부",
    source: "SQLite retention read-back",
  },
  {
    term: "Provider stage",
    meaning: "Cloudflare DNS proxy와 origin lock transaction에서 마지막으로 검증된 단계입니다.",
    formula: "원자 checkpoint와 외부 read-back이 모두 성공한 마지막 stage",
    source: "Cloudflare transaction ledger",
  },
] as const;

export function GlossaryPage() {
  return (
    <>
      <SectionHeading
        eyebrow="Metric definitions"
        title="운영 지표 용어집"
        description="화면 수치의 의미·산정 방식·실제 데이터 출처를 확인합니다. 추정값은 실제 read-back처럼 표시하지 않습니다."
      />
      <ConsoleSection label="운영 지표 용어집" title={`${TERMS.length}개 핵심 지표`} description="지표별 계산 경계와 수집 소유자를 함께 표시합니다." contentClassName="p-0 sm:p-0">
        <div className="divide-y">
          {TERMS.map((item) => (
            <article key={item.term} className="grid gap-3 px-5 py-5 md:grid-cols-[11rem_1fr] sm:px-6" aria-label={`${item.term} 정의`}>
              <h2 className="text-sm font-semibold">{item.term}</h2>
              <div>
                <p className="text-sm leading-6">{item.meaning}</p>
                <dl className="mt-3 grid gap-2 font-mono text-[10px] text-muted-foreground">
                  <div><dt className="inline font-semibold text-foreground">산정 </dt><dd className="inline">{item.formula}</dd></div>
                  <div><dt className="inline font-semibold text-foreground">출처 </dt><dd className="inline">{item.source}</dd></div>
                </dl>
              </div>
            </article>
          ))}
        </div>
      </ConsoleSection>
    </>
  );
}
