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
    <div className="overflow-x-auto border-y border-zinc-800">
      <table className="w-full min-w-[680px] border-collapse text-left text-xs">
        <thead className="bg-zinc-950 text-[10px] uppercase tracking-wider text-zinc-500">
          <tr>
            {headers.map((header) => (
              <th key={header} className="border-b border-zinc-800 px-3 py-3 font-semibold">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">{children}</tbody>
      </table>
      {empty ? (
        <div className="py-14 text-center text-xs text-zinc-600">아직 수집된 항목이 없습니다.</div>
      ) : null}
    </div>
  );
}
