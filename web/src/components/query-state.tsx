import { AlertTriangle, LoaderCircle } from "lucide-react";

export function LoadingState({ label = "운영 데이터를 불러오는 중" }: { label?: string }) {
  return (
    <div className="flex min-h-48 items-center justify-center gap-2 border-y border-zinc-800 text-sm text-zinc-500">
      <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex min-h-48 items-center justify-center gap-2 border-y border-red-900 bg-red-950/30 px-6 text-sm text-red-300">
      <AlertTriangle className="size-4" aria-hidden="true" />
      {message}
    </div>
  );
}
