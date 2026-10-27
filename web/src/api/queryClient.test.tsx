// 401 的全局接线：query/mutation 失败都派发 auth 失效事件，由 AuthProvider 清 session 查询。

import { QueryClientProvider, useMutation, useQuery } from "@tanstack/react-query";
import { fireEvent, render, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "./client";
import { createQueryClient } from "./queryClient";

function FailingQuery({ status }: { status: number }) {
  const query = useQuery({
    queryKey: ["probe", status],
    queryFn: async () => {
      throw new ApiError(status, `HTTP ${status}`);
    },
    retry: false,
  });
  return <div>{query.isError ? "加载失败" : "加载中"}</div>;
}

function FailingMutation({ status }: { status: number }) {
  const mutation = useMutation({
    mutationFn: async () => {
      throw new ApiError(status, `HTTP ${status}`);
    },
  });
  return <button onClick={() => mutation.mutate()}>写一次</button>;
}

function wrap(node: ReactNode) {
  return render(<QueryClientProvider client={createQueryClient()}>{node}</QueryClientProvider>);
}

describe("401 的全局处理", () => {
  it("query 401 派发 auth 失效事件", async () => {
    const listener = vi.fn();
    window.addEventListener("hlmg-auth-unauthorized", listener);
    wrap(<FailingQuery status={401} />);
    await waitFor(() => expect(listener).toHaveBeenCalled());
    window.removeEventListener("hlmg-auth-unauthorized", listener);
  });

  it("mutation 401 也派发", async () => {
    const listener = vi.fn();
    window.addEventListener("hlmg-auth-unauthorized", listener);
    const view = wrap(<FailingMutation status={401} />);
    fireEvent.click(view.getByRole("button", { name: "写一次" }));
    await waitFor(() => expect(listener).toHaveBeenCalled());
    window.removeEventListener("hlmg-auth-unauthorized", listener);
  });

  it("500 不派发（一次网关抖动不能丢登录态）", async () => {
    const listener = vi.fn();
    window.addEventListener("hlmg-auth-unauthorized", listener);
    const view = wrap(<FailingQuery status={500} />);
    await waitFor(() => expect(view.getByText("加载失败")).toBeDefined());
    expect(listener).not.toHaveBeenCalled();
    window.removeEventListener("hlmg-auth-unauthorized", listener);
  });
});
