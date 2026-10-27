export function PageLoading({ label }: { label: string }) {
  return (
    <div className="app-canvas flex min-h-screen items-center justify-center px-5">
      <div className="flex items-center gap-3 rounded-lg border border-line bg-ink-900/80 px-4 py-3">
        <span className="status-dot status-dot-live" />
        <span className="font-mono text-[10px] tracking-[0.08em] text-mist">{label}</span>
      </div>
    </div>
  );
}
