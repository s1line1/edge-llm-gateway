import type { AgentStatusTone } from "../orbitGeometry";

export function OrbitBeacon({ tone }: { tone: AgentStatusTone }) {
  return (
    <svg viewBox="0 0 8 8" className={`orbit-pixel orbit-pixel-${tone}`} aria-hidden="true">
      <rect x="1" y="1" width="2" height="2" />
      <rect x="5" y="1" width="2" height="2" opacity="0.55" />
      <rect x="1" y="5" width="2" height="2" opacity="0.55" />
      <rect x="5" y="5" width="2" height="2" />
      <rect x="3" y="3" width="2" height="2" opacity="0.9" />
    </svg>
  );
}
