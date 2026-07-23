import type { ReactNode } from "react";

export function DataTable({
  headers,
  children,
  empty,
}: {
  headers: string[];
  children: ReactNode;
  empty?: boolean;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] border-collapse text-left text-xs">
        <thead className="bg-muted/45 text-[10px] uppercase tracking-wider text-muted-foreground">
          <tr>
            {headers.map((header) => (
              <th key={header} className="border-b px-4 py-3 font-semibold">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border/70">{children}</tbody>
      </table>
      {empty ? (
        <div className="py-14 text-center text-xs text-muted-foreground">아직 수집된 항목이 없습니다.</div>
      ) : null}
    </div>
  );
}
