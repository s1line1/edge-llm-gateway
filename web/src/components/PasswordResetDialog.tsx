// 管理面改密：普通 DOM Dialog，不依赖可能被浏览器/嵌入式 WebView 拦截的原生 prompt。

import { useEffect, useState, type FormEvent } from "react";

import { Button } from "./ui";

export interface PasswordResetDialogProps {
  username: string;
  pending: boolean;
  error: string | null;
  onCancel: () => void;
  onSubmit: (password: string) => void;
}

const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

export function PasswordResetDialog({
  username,
  pending,
  error,
  onCancel,
  onSubmit,
}: PasswordResetDialogProps) {
  const [password, setPassword] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !pending) onCancel();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onCancel, pending]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
      setValidationError("密码长度必须为 12–128 个字符");
      return;
    }
    setValidationError(null);
    onSubmit(password);
  };

  return (
    <div
      data-testid="password-reset-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      onClick={(event) => {
        if (event.target === event.currentTarget && !pending) onCancel();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-reset-title"
        className="panel w-full max-w-md p-5"
        onClick={(event) => event.stopPropagation()}
      >
        <h2
          id="password-reset-title"
          className="text-[0.86rem] font-semibold tracking-[-0.01em] text-paper"
        >
          修改密码：{username}
        </h2>
        <p className="mt-1 text-[11px] leading-relaxed text-mist">
          密码长度必须为 12–128 个字符。更新后该用户的现有 session 会被撤销。
        </p>

        <form className="mt-4 space-y-3" onSubmit={submit}>
          <label className="block">
            <span className="micro-label mb-1.5 block">新密码</span>
            <input
              autoFocus
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                setValidationError(null);
              }}
              autoComplete="new-password"
              className="input"
              disabled={pending}
            />
          </label>

          {validationError && (
            <p role="alert" className="font-mono text-[10px] text-coral">
              {validationError}
            </p>
          )}
          {error && (
            <p role="alert" className="font-mono text-[10px] text-coral">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={onCancel} disabled={pending}>
              取消
            </Button>
            <Button type="submit" disabled={pending || !password}>
              {pending ? "更新中…" : "更新密码"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
