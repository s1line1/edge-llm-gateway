import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { PkiPair } from "../api/types";
import { TestAuthProvider } from "../auth/TestAuthProvider";

const mocks = vi.hoisted(() => ({
  fetchPkiStatus: vi.fn(),
  listPkiPairs: vi.fn(),
  listTenants: vi.fn(),
  createPkiPair: vi.fn(),
  revokePkiPair: vi.fn(),
  downloadPkiPair: vi.fn(),
}));
vi.mock("../api/client", () => ({
  fetchPkiStatus: mocks.fetchPkiStatus,
  listPkiPairs: mocks.listPkiPairs,
  listTenants: mocks.listTenants,
  createPkiPair: mocks.createPkiPair,
  revokePkiPair: mocks.revokePkiPair,
  downloadPkiPair: mocks.downloadPkiPair,
}));

import Certificates from "./Certificates";

const pair: PkiPair = {
  id: "pair-1",
  name: "laptop-1",
  tenant_id: "tenant-a",
  server_name: "gateway.example.com",
  serial: "ABCD",
  ca_fingerprint_sha256: "ca",
  server_fingerprint_sha256: "srv",
  client_fingerprint_sha256: "cli",
  status: "waiting",
  created_at: 0,
  created_by: "admin",
  downloaded_at: null,
  last_connected_at: null,
  revoked_at: null,
  client_not_after: 2_000_000_000,
  download_url: "/admin/pki/pairs/pair-1/download",
};

function renderPage(role: "super_admin" | "tenant_admin") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TestAuthProvider role={role}>
        <Certificates />
      </TestAuthProvider>
    </QueryClientProvider>,
  );
}

describe("Certificates page", () => {
  it("shows the empty state and the enabled status", async () => {
    mocks.fetchPkiStatus.mockResolvedValue({
      enabled: true,
      credentials: 0,
      tunnel_ready: false,
      waiting_for_credentials: true,
    });
    mocks.listPkiPairs.mockResolvedValue([]);
    mocks.listTenants.mockResolvedValue([]);
    renderPage("super_admin");
    expect(await screen.findByText("还没有凭证")).toBeDefined();
    expect(screen.getByText("PKI ENABLED")).toBeDefined();
  });

  it("creates a pair and exposes only the one-time download panel", async () => {
    mocks.fetchPkiStatus.mockResolvedValue({
      enabled: true,
      credentials: 0,
      tunnel_ready: false,
      waiting_for_credentials: true,
    });
    mocks.listPkiPairs.mockResolvedValue([]);
    mocks.listTenants.mockResolvedValue([{ id: "tenant-a", name: "tenant-a" }]);
    mocks.createPkiPair.mockResolvedValue(pair);
    renderPage("super_admin");

    expect(await screen.findByText("PKI ENABLED")).toBeDefined();
    fireEvent.change(await screen.findByLabelText("名称"), { target: { value: "laptop-1" } });
    fireEvent.change(screen.getByLabelText("Server name (SNI)"), {
      target: { value: "gateway.example.com" },
    });
    fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "tenant-a" } });
    fireEvent.click(screen.getByRole("button", { name: /创建凭证对/ }));

    expect(await screen.findByText("凭证已创建")).toBeDefined();
    expect(screen.getByText(/client 私钥只下载一次/)).toBeDefined();
    expect(mocks.createPkiPair).toHaveBeenCalledWith({
      name: "laptop-1",
      tenant_id: "tenant-a",
      server_name: "gateway.example.com",
      server_sans: [],
    });
  });

  it("lists a pair and revokes it with confirmation", async () => {
    mocks.fetchPkiStatus.mockResolvedValue({
      enabled: true,
      credentials: 1,
      tunnel_ready: true,
      waiting_for_credentials: false,
    });
    mocks.listPkiPairs.mockResolvedValue([pair]);
    mocks.listTenants.mockResolvedValue([]);
    mocks.revokePkiPair.mockResolvedValue(undefined);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage("tenant_admin");

    expect(await screen.findByText("laptop-1")).toBeDefined();
    fireEvent.click(screen.getByRole("button", { name: "吊销" }));
    await waitFor(() => expect(mocks.revokePkiPair).toHaveBeenCalledWith("pair-1"));
  });

  it("does not render private key material", async () => {
    mocks.fetchPkiStatus.mockResolvedValue({
      enabled: true,
      credentials: 1,
      tunnel_ready: true,
      waiting_for_credentials: false,
    });
    mocks.listPkiPairs.mockResolvedValue([pair]);
    mocks.listTenants.mockResolvedValue([]);
    renderPage("tenant_admin");
    await screen.findByText("laptop-1");
    expect(document.body.textContent ?? "").not.toMatch(/BEGIN (RSA |EC )?PRIVATE KEY/);
  });
});
