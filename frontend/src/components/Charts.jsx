import { useEffect, useRef, useState } from 'react'
import './Charts.css'

const MODULE_COLORS = {
  manifest:    'var(--sev-critical)',
  permissions: 'var(--sev-high)',
  secrets:     'var(--sev-critical)',
  firebase:    'var(--sev-high)',
  ssl:         'var(--sev-medium)',
  storage:     'var(--sev-medium)',
  yara:        'var(--sev-critical)',
  crypto:      'var(--sev-high)',
  webview:     'var(--sev-high)',
}

const MODULE_LABELS = {
  manifest:    'MANIFEST',
  permissions: 'PERMS',
  secrets:     'SECRETS',
  firebase:    'FIREBASE',
  ssl:         'SSL/TLS',
  storage:     'STORAGE',
  yara:        'YARA',
  crypto:      'CRYPTO',
  webview:     'WEBVIEW',
}

const SEV_COLORS = {
  CRITICAL: 'var(--sev-critical)',
  HIGH:     'var(--sev-high)',
  MEDIUM:   'var(--sev-medium)',
  LOW:      'var(--sev-low)',
}

const MODULE_ORDER = ['manifest','permissions','secrets','firebase','ssl','storage','yara','crypto','webview']

function countFindings(module) {
  return (module?.findings ?? []).length
}

export function BarChart({ scanData }) {
  const [animated, setAnimated] = useState(false)

  useEffect(() => {
    if (!scanData) return
    const t = setTimeout(() => setAnimated(true), 60)
    return () => clearTimeout(t)
  }, [scanData])

  if (!scanData?.findings) {
    return (
      <div className="chart-bar">
        <div className="chart-bar__header">
          <span className="chart-bar__label">FINDINGS BY MODULE</span>
        </div>
        <div className="chart-bar__empty">NO SCAN DATA</div>
      </div>
    )
  }

  const modules = MODULE_ORDER.map(k => ({
    key: k,
    label: MODULE_LABELS[k] || k.toUpperCase(),
    count: countFindings(scanData.findings[k]),
    color: MODULE_COLORS[k] || 'var(--sev-info)',
  }))

  const total = modules.reduce((s, m) => s + m.count, 0)
  const max   = Math.max(...modules.map(m => m.count), 1)

  return (
    <div className="chart-bar">
      <div className="chart-bar__header">
        <span className="chart-bar__label">FINDINGS BY MODULE</span>
        <span className="chart-bar__total">{total} TOTAL</span>
      </div>
      <div className="chart-bar__rows">
        {modules.map((m, i) => (
          <div key={m.key} className="chart-bar__row">
            <span className="chart-bar__name">{m.label}</span>
            <div className="chart-bar__track">
              <div
                className="chart-bar__fill"
                style={{
                  background: m.color,
                  width: animated ? `${(m.count / max) * 100}%` : '0%',
                  transitionDelay: `${i * 80}ms`,
                }}
              />
            </div>
            <span className="chart-bar__count">{m.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export function LineGraph({ scanData }) {
  const svgRef   = useRef(null)
  const [tooltip, setTooltip] = useState(null)
  const [animated, setAnimated] = useState(false)

  useEffect(() => {
    if (!scanData) return
    const t = setTimeout(() => setAnimated(true), 200)
    return () => clearTimeout(t)
  }, [scanData])

  if (!scanData?.findings) {
    return (
      <div className="chart-line">
        <div className="chart-line__header">
          <span className="chart-line__label">SEVERITY DISTRIBUTION</span>
        </div>
        <div className="chart-line__empty">AWAITING SCAN DATA</div>
      </div>
    )
  }

  const W = 270
  const H = 90
  const PAD = { top: 8, right: 8, bottom: 20, left: 24 }
  const innerW = W - PAD.left - PAD.right
  const innerH = H - PAD.top - PAD.bottom

  const sevs  = ['CRITICAL','HIGH','MEDIUM','LOW']
  const mods  = MODULE_ORDER

  const data = sevs.map(sev => ({
    sev,
    color: SEV_COLORS[sev],
    points: mods.map(mod => {
      const findings = scanData.findings[mod]?.findings ?? []
      return findings.filter(f => (f.severity ?? 'INFO') === sev).length
    }),
  }))

  const maxVal = Math.max(...data.flatMap(d => d.points), 1)

  function xPos(i) {
    return PAD.left + (i / (mods.length - 1)) * innerW
  }
  function yPos(v) {
    return PAD.top + innerH - (v / maxVal) * innerH
  }

  function buildPath(points) {
    return points
      .map((v, i) => `${i === 0 ? 'M' : 'L'}${xPos(i).toFixed(1)},${yPos(v).toFixed(1)}`)
      .join(' ')
  }

  const gridYVals = [0, Math.ceil(maxVal / 2), maxVal]

  return (
    <div className="chart-line">
      <div className="chart-line__header">
        <span className="chart-line__label">SEVERITY DISTRIBUTION</span>
        <div className="chart-line__legend">
          {sevs.map(s => (
            <span key={s} className="chart-line__legend-item">
              <span className="chart-line__legend-dot" style={{ background: SEV_COLORS[s] }} />
              {s.slice(0,4)}
            </span>
          ))}
        </div>
      </div>
      <svg
        ref={svgRef}
        className="chart-line__svg"
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        style={{ height: '90px' }}
      >
        {gridYVals.map((v, i) => (
          <line
            key={i}
            className="chart-line__grid"
            x1={PAD.left} y1={yPos(v).toFixed(1)}
            x2={W - PAD.right} y2={yPos(v).toFixed(1)}
          />
        ))}
        {mods.map((mod, i) => (
          <text
            key={mod}
            x={xPos(i)} y={H - 4}
            textAnchor="middle"
            fontSize="8"
            fill="var(--text-tertiary)"
            fontFamily="var(--font-mono)"
          >
            {MODULE_LABELS[mod]?.slice(0,4)}
          </text>
        ))}
        {data.map((d, di) => (
          <g key={d.sev} style={{ opacity: animated ? 1 : 0, transition: `opacity 500ms ${di * 150}ms` }}>
            <path
              d={buildPath(d.points)}
              stroke={d.color}
              strokeOpacity={0.85}
            />
            {d.points.map((v, i) => v > 0 && (
              <circle
                key={i}
                cx={xPos(i).toFixed(1)}
                cy={yPos(v).toFixed(1)}
                r="3.5"
                fill={d.color}
                style={{ transition: `r 150ms` }}
                onMouseEnter={e => setTooltip({
                  x: e.clientX + 8,
                  y: e.clientY - 28,
                  mod: MODULE_LABELS[mods[i]],
                  sev: d.sev,
                  count: v,
                  color: d.color,
                })}
                onMouseLeave={() => setTooltip(null)}
              />
            ))}
          </g>
        ))}
      </svg>
      {tooltip && (
        <div className="chart-line__tooltip" style={{ left: tooltip.x, top: tooltip.y }}>
          <div>{tooltip.mod}</div>
          <div className="chart-line__tooltip-sev" style={{ color: tooltip.color }}>
            {tooltip.sev}: {tooltip.count}
          </div>
        </div>
      )}
    </div>
  )
}
