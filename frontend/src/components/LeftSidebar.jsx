import { useEffect, useRef, useState } from 'react'
import './LeftSidebar.css'

const SEV_COLORS = {
  CRITICAL: 'var(--sev-critical)',
  HIGH:     'var(--sev-high)',
  MEDIUM:   'var(--sev-medium)',
  LOW:      'var(--sev-low)',
  INFO:     'var(--sev-info)',
}

const SEV_DIM = {
  CRITICAL: 'var(--sev-critical-dim)',
  HIGH:     'var(--sev-high-dim)',
  MEDIUM:   'var(--sev-medium-dim)',
  LOW:      'var(--sev-low-dim)',
  INFO:     'var(--sev-info-dim)',
}

const MODULES = [
  { key: 'manifest',    label: 'MANIFEST' },
  { key: 'permissions', label: 'PERMISSIONS' },
  { key: 'secrets',     label: 'SECRETS' },
  { key: 'firebase',    label: 'FIREBASE' },
  { key: 'ssl',         label: 'SSL / TLS' },
  { key: 'storage',     label: 'STORAGE' },
  { key: 'yara',        label: 'YARA SCAN' },
  { key: 'crypto',      label: 'CRYPTOGRAPHY' },
  { key: 'webview',     label: 'WEBVIEW' },
]

function useCountUp(target, duration = 1000) {
  const [value, setValue] = useState(0)
  useEffect(() => {
    if (target == null) return
    setValue(0)
    const start  = performance.now()
    function step(now) {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(Math.round(eased * target))
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [target, duration])
  return value
}

function formatRelTime(ts) {
  const diff = Date.now() - ts
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function moduleSeverity(module) {
  if (!module?.findings?.length) return 'INFO'
  const order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
  for (const s of order) {
    if (module.findings.some(f => (f.severity ?? 'INFO') === s)) return s
  }
  return 'INFO'
}

function countBySeverity(findings) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  if (!findings) return c
  for (const mod of Object.values(findings)) {
    for (const f of (mod?.findings ?? [])) {
      const s = f.severity ?? 'INFO'
      if (s in c) c[s]++
    }
  }
  return c
}

export default function LeftSidebar({
  uploadFlow, appState, scanData, activeModule, setActiveModule,
  scanHistory, onLoadHistory,
}) {
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef(null)
  const countedScore = useCountUp(
    appState === 'complete' ? (scanData?.risk_score ?? 0) : null,
    1200
  )

  const sevCounts = countBySeverity(scanData?.findings)
  const level     = scanData?.risk_level ?? 'INFO'

  const activeIdx = MODULES.findIndex(m => m.key === activeModule)

  function onDrop(e) {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file && file.name.endsWith('.apk')) uploadFlow(file)
  }

  function onDragOver(e) {
    e.preventDefault()
    setDragOver(true)
  }

  return (
    <div className="leftsidebar">
      <span className="leftsidebar__section-label">// TARGET INPUT</span>

      <div
        className={`leftsidebar__dropzone${dragOver ? ' drag-over' : ''}`}
        onClick={() => fileRef.current?.click()}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={() => setDragOver(false)}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".apk"
          style={{ display: 'none' }}
          onChange={e => {
            const file = e.target.files?.[0]
            if (file) uploadFlow(file)
            e.target.value = ''
          }}
        />

        {appState === 'uploading' ? (
          <>
            <span className="leftsidebar__uploading-text">UPLOADING...</span>
            <div className="leftsidebar__upload-progress running" />
          </>
        ) : (
          <>
            <svg className="leftsidebar__drop-icon" viewBox="0 0 16 16" fill="none">
              <path d="M8 2v8M5 7l3 3 3-3M2 11v2a1 1 0 001 1h10a1 1 0 001-1v-2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span className="leftsidebar__drop-text">DROP APK FILE</span>
            <span className="leftsidebar__drop-sub">or click to browse</span>
          </>
        )}
      </div>

      {appState === 'complete' && scanData && (
        <>
          <div className="leftsidebar__divider" />
          <span className="leftsidebar__section-label">// TARGET</span>

          <div className="leftsidebar__target">
            <div className="leftsidebar__target-name" title={scanData.app_name}>
              {scanData.app_name}
            </div>
            {scanData.package_name && (
              <div className="leftsidebar__target-pkg">{scanData.package_name}</div>
            )}
            {scanData.scan_duration != null && (
              <div className="leftsidebar__target-duration">
                ANALYZED IN {Number(scanData.scan_duration).toFixed(1)}s
              </div>
            )}
          </div>

          <div
            className="leftsidebar__risk"
            style={{
              background: SEV_DIM[level],
              border: `1px solid ${SEV_COLORS[level]}33`,
            }}
          >
            <div className="leftsidebar__risk-number-row">
              <span className="leftsidebar__risk-number" style={{ color: SEV_COLORS[level] }}>
                {countedScore}
              </span>
              <span className="leftsidebar__risk-denom">/ 100</span>
            </div>
            <span className="leftsidebar__risk-level" style={{ color: SEV_COLORS[level] }}>
              {level}
            </span>
            <div className="leftsidebar__risk-stats">
              {[['C', 'CRITICAL'], ['H', 'HIGH'], ['M', 'MEDIUM'], ['L', 'LOW']].map(([abbr, sev], i) => (
                <span key={sev} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  {i > 0 && <span className="leftsidebar__risk-stat-sep" />}
                  <span className="leftsidebar__risk-stat" style={{ color: SEV_COLORS[sev] }}>
                    {abbr}:{sevCounts[sev]}
                  </span>
                </span>
              ))}
            </div>
          </div>
        </>
      )}

      <div className="leftsidebar__divider" />
      <span className="leftsidebar__section-label">// MODULES</span>

      <div className="leftsidebar__modules">
        {activeIdx >= 0 && (
          <div
            className="leftsidebar__active-indicator"
            style={{ transform: `translateY(${activeIdx * 31 + 5}px)` }}
          />
        )}
        {MODULES.map(mod => {
          const moduleData = scanData?.findings?.[mod.key]
          const sev        = moduleSeverity(moduleData)
          const count      = moduleData?.findings?.length ?? 0
          const isActive   = activeModule === mod.key

          return (
            <button
              key={mod.key}
              className={`leftsidebar__module-item${isActive ? ' active' : ''}`}
              onClick={() => setActiveModule(mod.key)}
            >
              <span
                className="leftsidebar__module-dot"
                style={{ background: appState === 'complete' ? SEV_COLORS[sev] : 'var(--text-disabled)' }}
              />
              <span className="leftsidebar__module-name">{mod.label}</span>
              {appState === 'complete' && (
                <span
                  className="leftsidebar__module-badge"
                  style={{
                    background: SEV_DIM[sev],
                    color: SEV_COLORS[sev],
                  }}
                >
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {scanHistory.length > 0 && (
        <>
          <div className="leftsidebar__divider" />
          <span className="leftsidebar__section-label">// RECENT SCANS</span>
          <div className="leftsidebar__history">
            {scanHistory.map(h => (
              <button
                key={h.scan_id}
                className="leftsidebar__history-item"
                onClick={() => onLoadHistory(h.scan_id)}
              >
                <span className="leftsidebar__history-name">{h.app_name}</span>
                <span
                  className="leftsidebar__history-badge"
                  style={{
                    background: SEV_DIM[h.risk_level] ?? 'var(--sev-info-dim)',
                    color: SEV_COLORS[h.risk_level] ?? 'var(--sev-info)',
                  }}
                >
                  {h.risk_score}
                </span>
                <span className="leftsidebar__history-time">
                  {formatRelTime(h.timestamp)}
                </span>
              </button>
            ))}
          </div>
        </>
      )}

      <div className="leftsidebar__system">
        <div className="leftsidebar__divider" style={{ margin: '8px 0' }} />
        <span className="leftsidebar__section-label" style={{ padding: '0 0 6px' }}>// SYSTEM</span>
        <div className="leftsidebar__system-row">ENGINE: STATIC ANALYSIS</div>
        <div className="leftsidebar__system-row">MODULES: 9 ACTIVE</div>
        <div className="leftsidebar__system-row">AI: GROQ LLAMA-3.3-70B</div>
      </div>
    </div>
  )
}
