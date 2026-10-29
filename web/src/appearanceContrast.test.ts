import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

function luminance(hex: string): number {
  const value = hex.replace("#", "");
  const channels = [0, 2, 4].map((offset) => {
    const channel = Number.parseInt(value.slice(offset, offset + 2), 16) / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(a: string, b: string): number {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

function tokens(block: string): Record<string, string> {
  return Object.fromEntries(
    [...block.matchAll(/--ui-([a-z-]+):\s*(#[0-9a-fA-F]{6})/g)].map((match) => [
      match[1],
      match[2],
    ]),
  );
}

describe("appearance palettes", () => {
  const css = readFileSync(resolve(process.cwd(), "src/styles/theme.css"), "utf8");
  const lightBlock = css.slice(
    css.indexOf('[data-theme="light"]'),
    css.indexOf("/* Accent presets"),
  );
  const rootBlock = css.slice(css.indexOf(":root {"), css.indexOf('[data-theme="light"]'));

  it.each([
    ["light", tokens(lightBlock)],
    ["dark", tokens(rootBlock)],
  ])("%s text and muted tokens meet WCAG AA", (_name, palette) => {
    for (const key of ["text", "muted", "dim"]) {
      expect(contrast(palette[key], palette.panel)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it.each([
    ["light", tokens(lightBlock)],
    ["dark", tokens(rootBlock)],
  ])("%s accent tokens meet WCAG AA on panels", (_name, palette) => {
    for (const key of ["accent", "cyan", "amber", "coral"]) {
      expect(contrast(palette[key], palette.panel)).toBeGreaterThanOrEqual(4.5);
    }
  });
});
