import { useState, useEffect } from 'react'
import './ScanProgress.css'

const MODULES = [
  { key: 'unpacking',   label: 'UNPACK / DECOMPILE' },
  { key: 'manifest',    label: 'MANIFEST ANALYSIS' },
  { key: 'permissions', label: 'PERMISSION AUDIT' },
  { key: 'secrets',     label: 'SECRET DETECTION' },
  { key: 'firebase',    label: 'FIREBASE CHECK' },
  { key: 'ssl',         label: 'SSL / TLS AUDIT' },
  { key: 'storage',     label: 'STORAGE ANALYSIS' },
  { key: 'yara',        label: 'YARA RULE SCAN' },
  { key: 'crypto',      label: 'CRYPTO ANALYSIS' },
  { key: 'webview',     label: 'WEBVIEW AUDIT' },
  { key: 'ai',          label: 'AI RISK REPORT' },
]

function getModuleState(key, scanData) {
  if (!scanData) return 'queued'
  const findings = scanData.findings ?? {}
  const modMap = {
    unpacking:   'unpacked',
    manifest:    'manifest',
    permissions: 'permissions',
    secrets:     'secrets',
    firebase:    'firebase',
    ssl:         'ssl',
    storage:     'storage',
    yara:        'yara',
    crypto:      'crypto',
    webview:     'webview',
    ai:          'ai_summary',
  }
  const fkey = modMap[key]
  if (fkey === 'unpacked' && scanData.status !== 'queued') return 'done'
  if (fkey === 'ai_summary') {
    return scanData.ai_summary ? 'done' : (scanData.status === 'complete' ? 'done' : 'queued')
  }
  if (findings[fkey] !== undefined) return 'done'
  if (scanData.current_module === key) return 'running'
  return 'queued'
}

export default function ScanProgress({ scanData }) {
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    setElapsed(0)
    const id = setInterval(() => setElapsed(e => e + 1), 1000)
    return () => clearInterval(id)
  }, [])

  const doneCount = MODULES.filter(m => getModuleState(m.key, scanData) === 'done').length
  const progress  = (doneCount / MODULES.length) * 100
  const appName   = scanData?.app_name ?? 'TARGET'

  const pad = n => String(n).padStart(2, '0')
  const mm  = pad(Math.floor(elapsed / 60))
  const ss  = pad(elapsed % 60)

  return (
    <div className="scan-progress">
      <div className="scan-progress__heading">
        <span className="scan-progress__title">// SCANNING TARGET</span>
        <span className="scan-progress__app">{appName}</span>
      </div>

      <div className="scan-progress__modules">
        {MODULES.map((mod, i) => {
          const state = getModuleState(mod.key, scanData)
          return (
            <div
              key={mod.key}
              className={`scan-progress__row ${state}`}
            >
              <span className="scan-progress__index">{pad(i + 1)}</span>
              <span className="scan-progress__name">{mod.label}</span>
              <span className={`scan-progress__status ${state}`}>
                {state === 'queued'  && 'QUEUED'}
                {state === 'running' && <><span className="scan-progress__run-pulse">▶</span> RUNNING</>}
                {state === 'done'    && '✓ COMPLETE'}
              </span>
            </div>
          )
        })}
      </div>

      <div className="scan-progress__bar-wrap">
        <div className="scan-progress__bar-track">
          <div className="scan-progress__bar-fill" style={{ width: `${progress}%` }} />
        </div>
      </div>

      <span className="scan-progress__timer">T+{mm}:{ss}</span>
    </div>
  )
}
