import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Skeleton } from "./ui/skeleton";

export function LoadingState({ label = "운영 데이터를 불러오는 중" }: { label?: string }) {
  return (
    <div className="grid min-h-56 content-center gap-3 rounded-xl border bg-card px-6 shadow-sm" aria-label={label} aria-busy="true">
      <Skeleton className="h-3 w-32" />
      <Skeleton className="h-8 w-full max-w-lg" />
      <Skeleton className="h-3 w-60 max-w-full" />
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <Alert variant="destructive" className="min-h-48 content-center border-red-900 bg-red-950/30 px-6">
      <AlertTriangle className="size-4" aria-hidden="true" />
      <AlertTitle>운영 데이터를 표시하지 못했습니다.</AlertTitle>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  );
}
