import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("appearance boot", () => {
  it("applies the stored theme before the React module", () => {
    const html = readFileSync(resolve(process.cwd(), "index.html"), "utf8");
    const boot = html.indexOf("hlmg.ui.appearance.v1");
    const module = html.indexOf("/src/main.tsx");
    expect(boot).toBeGreaterThan(-1);
    expect(module).toBeGreaterThan(-1);
    expect(boot).toBeLessThan(module);
    expect(html).toContain('name="theme-color"');
    expect(html).not.toContain("hlmg_session");
  });
});
