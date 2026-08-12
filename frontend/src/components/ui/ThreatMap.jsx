import { geoEquirectangular, geoPath } from "d3-geo";
import countries110m from "world-atlas/countries-110m.json";
import { feature } from "topojson-client";

const WIDTH = 720;
const HEIGHT = 380;

const countries = feature(countries110m, countries110m.objects.countries);
const projection = geoEquirectangular().fitSize([WIDTH, HEIGHT], countries);
const pathGenerator = geoPath(projection);
const COUNTRY_PATHS = countries.features.map((f) => pathGenerator(f));

const SEVERITY_COLOR = {
  critical: "hsl(var(--critical))",
  high: "hsl(var(--high))",
  medium: "hsl(var(--medium))",
  low: "hsl(var(--low))",
};

function Marker({ lat, lon, severity, label, showLabel }) {
  const [x, y] = projection([lon, lat]) ?? [WIDTH / 2, HEIGHT / 2];
  const color = SEVERITY_COLOR[severity] ?? "hsl(var(--primary))";
  const tooltip = `${label ? `${label} · ` : ""}${lat.toFixed(2)}, ${lon.toFixed(2)}`;

  return (
    <g className="cursor-pointer">
      <title>{tooltip}</title>
      <circle cx={x} cy={y} r={9} fill={color} opacity={0.3}>
        <animate attributeName="r" values="6;14;6" dur="2s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="0.4;0.05;0.4" dur="2s" repeatCount="indefinite" />
      </circle>
      <circle cx={x} cy={y} r={4} fill={color} stroke="white" strokeWidth={1} />
      {showLabel && label && (
        <text
          x={x}
          y={y - 12}
          textAnchor="middle"
          fontSize="11"
          fontWeight="600"
          fill="hsl(var(--foreground))"
        >
          {label}
        </text>
      )}
    </g>
  );
}

/**
 * IP göstergelerinin coğrafi konumunu gerçek ülke sınırlarına sahip bir dünya
 * haritası üzerinde işaretler (d3-geo + world-atlas, harici tile sunucusu yok).
 *
 * Tekli kullanım: `lat`/`lon`/`severity`/`label` ver.
 * Çoklu kullanım (örn. Dashboard): `points={[{lat, lon, severity, label}, ...]}` ver.
 */
export function ThreatMap({ lat, lon, label, severity, points }) {
  const markers = points ?? (lat !== undefined && lon !== undefined ? [{ lat, lon, label, severity }] : []);
  const showLabels = markers.length === 1;

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full rounded-md border border-border bg-background">
      {COUNTRY_PATHS.map((d, i) => (
        <path
          key={i}
          d={d}
          fill="hsl(var(--primary) / 0.16)"
          stroke="hsl(var(--border))"
          strokeWidth={0.5}
        />
      ))}

      {markers.map((m, i) => (
        <Marker key={i} {...m} showLabel={showLabels} />
      ))}
    </svg>
  );
}
