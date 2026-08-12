const WIDTH = 720;
const HEIGHT = 360;

/** Enlem/boylamı SVG koordinatına çevirir (equirectangular projeksiyon). */
function project(lat, lon) {
  const x = ((lon + 180) / 360) * WIDTH;
  const y = ((90 - lat) / 180) * HEIGHT;
  return { x, y };
}

const MERIDIANS = [-180, -120, -60, 0, 60, 120, 180];
const PARALLELS = [-60, -30, 0, 30, 60];

// Kıtaların kaba konumunu belirten silüet blokları (kesin sınır değil, görsel referans).
const CONTINENT_BLOBS = [
  { cx: 150, cy: 95, rx: 115, ry: 58 }, // Kuzey Amerika
  { cx: 245, cy: 225, rx: 42, ry: 65 }, // Güney Amerika
  { cx: 390, cy: 75, rx: 48, ry: 33 }, // Avrupa
  { cx: 395, cy: 180, rx: 68, ry: 72 }, // Afrika
  { cx: 555, cy: 100, rx: 110, ry: 68 }, // Asya
  { cx: 627, cy: 234, rx: 40, ry: 32 }, // Avustralya
];

const SEVERITY_COLOR = {
  critical: "hsl(var(--critical))",
  high: "hsl(var(--high))",
  medium: "hsl(var(--medium))",
  low: "hsl(var(--low))",
};

/** IP göstergesinin coğrafi konumunu basit bir dünya haritası üzerinde işaretler. */
export function ThreatMap({ lat, lon, label, severity }) {
  const { x, y } = project(lat, lon);
  const color = SEVERITY_COLOR[severity] ?? "hsl(var(--primary))";

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full rounded-md border border-border bg-background">
      {CONTINENT_BLOBS.map((b, i) => (
        <ellipse
          key={i}
          cx={b.cx}
          cy={b.cy}
          rx={b.rx}
          ry={b.ry}
          fill="hsl(var(--muted-foreground))"
          opacity={0.12}
        />
      ))}

      {MERIDIANS.map((lonDeg) => {
        const gx = project(0, lonDeg).x;
        return (
          <line
            key={`v${lonDeg}`}
            x1={gx}
            y1={0}
            x2={gx}
            y2={HEIGHT}
            stroke="hsl(var(--border))"
            strokeWidth={lonDeg === 0 ? 1 : 0.5}
          />
        );
      })}
      {PARALLELS.map((latDeg) => {
        const gy = project(latDeg, 0).y;
        return (
          <line
            key={`h${latDeg}`}
            x1={0}
            y1={gy}
            x2={WIDTH}
            y2={gy}
            stroke="hsl(var(--border))"
            strokeWidth={latDeg === 0 ? 1 : 0.5}
          />
        );
      })}

      <circle cx={x} cy={y} r={10} fill={color} opacity={0.3}>
        <animate attributeName="r" values="6;16;6" dur="2s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="0.4;0.05;0.4" dur="2s" repeatCount="indefinite" />
      </circle>
      <circle cx={x} cy={y} r={4.5} fill={color} stroke="white" strokeWidth={1} />

      {label && (
        <text
          x={x}
          y={y - 14}
          textAnchor="middle"
          fontSize="11"
          fontWeight="600"
          fill="hsl(var(--foreground))"
        >
          {label}
        </text>
      )}
    </svg>
  );
}
