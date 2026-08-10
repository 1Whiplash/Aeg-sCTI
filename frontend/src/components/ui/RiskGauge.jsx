const SIZE = 140;
const STROKE = 10;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function colorForScore(score) {
  if (score >= 80) return "hsl(var(--critical))";
  if (score >= 50) return "hsl(var(--high))";
  if (score >= 20) return "hsl(var(--medium))";
  return "hsl(var(--low))";
}

/** 0-100 arası risk skorunu dairesel bir gösterge (gauge) olarak çizer. */
export function RiskGauge({ score }) {
  const clamped = Math.max(0, Math.min(100, score ?? 0));
  const offset = CIRCUMFERENCE * (1 - clamped / 100);
  const color = colorForScore(clamped);

  return (
    <div className="relative" style={{ width: SIZE, height: SIZE }}>
      <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`} className="-rotate-90">
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth={STROKE}
        />
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-foreground">{clamped}</span>
        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">risk skoru</span>
      </div>
    </div>
  );
}
