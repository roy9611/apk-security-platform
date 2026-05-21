import { useState, useEffect, useRef } from 'react'
import ScanProgress from './ScanProgress.jsx'
import FindingCard from './FindingCard.jsx'
import PermissionMatrix from './PermissionMatrix.jsx'
import './MainContent.css'

const MODULE_ORDER = ['manifest','permissions','secrets','firebase','ssl','storage','yara','crypto','webview']

const MODULE_LABELS = {
  manifest:    'MANIFEST ANALYSIS',
  permissions: 'PERMISSION AUDIT',
  secrets:     'SECRET DETECTION',
  firebase:    'FIREBASE CHECK',
  ssl:         'SSL / TLS ANALYSIS',
  storage:     'STORAGE ANALYSIS',
  yara:        'YARA RULE SCAN',
  crypto:      'CRYPTOGRAPHY ANALYSIS',
  webview:     'WEBVIEW AUDIT',
}

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

function countAll(findings) {
  if (!findings) return 0
  return Object.values(findings).reduce((n, m) => n + (m?.findings?.length ?? 0), 0)
}

function countBySev(findings, sev) {
  if (!findings) return 0
  return Object.values(findings).reduce(
    (n, m) => n + (m?.findings ?? []).filter(f => (f.severity ?? 'INFO') === sev).length, 0
  )
}

function remediationPriority(item) {
  if (/^(Remove|Rotate)/i.test(item))  return 'CRITICAL'
  if (/^(Disable|Add)/i.test(item))    return 'HIGH'
  if (/^(Replace|Audit)/i.test(item))  return 'MEDIUM'
  return null
}

function StatCard({ label, value, color, sub, delay }) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay ?? 0)
    return () => clearTimeout(t)
  }, [delay])

  return (
    <div className={`stat-card${visible ? ' visible' : ''}`} style={{ animationDelay: `${delay ?? 0}ms` }}>
      <span className="stat-card__label">{label}</span>
      <span className="stat-card__value" style={color ? { color } : {}}>
        {value}
      </span>
      {sub && <span className="stat-card__sub">{sub}</span>}
    </div>
  )
}

function ModuleSection({ index, moduleKey, mod, activeFilter, sendToChat, scrollRef }) {
  const sev   = mod?.severity ?? 'INFO'
  const count = mod?.findings?.length ?? 0

  const autoOpen = sev === 'CRITICAL' || sev === 'HIGH'
  const [open, setOpen] = useState(autoOpen)

  const visibleFindings = activeFilter === 'ALL'
    ? (mod?.findings ?? [])
    : (mod?.findings ?? []).filter(f => (f.severity ?? 'INFO') === activeFilter)

  const pad = n => String(n).padStart(2, '0')

  return (
    <div
      id={`module-${moduleKey}`}
      className={`module-section${open ? ' open' : ''}`}
      ref={scrollRef}
    >
      <div
        className="module-section__header"
        onClick={() => setOpen(v => !v)}
        role="button"
        aria-expanded={open}
      >
        <span className="module-section__index">{pad(index + 1)}</span>
        <span className="module-section__name">{MODULE_LABELS[moduleKey] ?? moduleKey.toUpperCase()}</span>
        <span className="module-section__spacer" />
        <span
          className="module-section__count-badge"
          style={{ background: SEV_DIM[sev], color: SEV_COLORS[sev] }}
        >
          {count}
        </span>
        <span
          className="module-section__sev"
          style={{ background: SEV_DIM[sev], color: SEV_COLORS[sev] }}
        >
          {sev}
        </span>
        <span className="module-section__chevron">▶</span>
      </div>

      <div className={`module-section__body-wrap${open ? ' open' : ''}`}>
        <div className="module-section__body-inner">
          <div className="module-section__body">
            {mod?.errors?.length > 0 && (
              <div className="module-section__error">
                ANALYSIS ERRORS: {mod.errors.join(', ')}
              </div>
            )}
            {count === 0 ? (
              <p className="module-section__empty">NO ISSUES DETECTED</p>
            ) : moduleKey === 'permissions' ? (
              <PermissionMatrix permissionsModule={mod} />
            ) : (
              visibleFindings.length === 0
                ? <p className="module-section__empty">NO {activeFilter} FINDINGS</p>
                : visibleFindings.map((f, i) => (
                    <FindingCard key={i} finding={f} sendToChat={sendToChat} />
                  ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function MainContent({ appState, scanData, activeModule, scanId, sendToChat }) {
  const moduleRefs = useRef({})
  const [activeFilter, setActiveFilter] = useState('ALL')

  useEffect(() => {
    if (!activeModule || appState !== 'complete') return
    const el = moduleRefs.current[activeModule]
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [activeModule, appState])

  if (appState === 'empty') {
    return (
      <main className="main-content">
        <div className="main-content__empty">
          <div className="main-content__scanline" />
          <span className="main-content__empty-wordmark">AppEX</span>
          <span className="main-content__empty-sub">NO TARGET LOADED</span>
          <span className="main-content__empty-hint">
            Drop an APK file in the left panel to begin static analysis
          </span>
        </div>
      </main>
    )
  }

  if (appState === 'uploading' || appState === 'scanning') {
    return (
      <main className="main-content">
        <div className="main-content__scanning">
          <ScanProgress scanData={scanData} />
        </div>
      </main>
    )
  }

  if (appState !== 'complete' || !scanData) return null

  const findings   = scanData.findings ?? {}
  const totalCount = countAll(findings)
  const critCount  = countBySev(findings, 'CRITICAL')
  const highCount  = countBySev(findings, 'HIGH')
  const duration   = scanData.scan_duration != null
    ? `${Number(scanData.scan_duration).toFixed(1)}s`
    : '—'
  const pad = n => String(n).padStart(2, '0')
  const scanDate = scanData.timestamp
    ? new Date(scanData.timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ')
    : '—'

  const presentModules = MODULE_ORDER.filter(k => findings[k])

  return (
    <main className="main-content">
      <div className="main-content__report">

        {/* 01 · UPLOAD anchor */}
        <div id="upload" />

        {/* 02 · ANALYSIS */}
        <section id="analysis">
          <div className="section-label">// OVERVIEW</div>
          <div className="stat-cards-row">
            <StatCard
              label="RISK SCORE"
              value={scanData.risk_score}
              color={SEV_COLORS[scanData.risk_level]}
              sub={scanData.risk_level}
              delay={0}
            />
            <StatCard
              label="TOTAL FINDINGS"
              value={totalCount}
              sub="across 6 modules"
              delay={80}
            />
            <StatCard
              label="CRITICAL"
              value={critCount}
              color={critCount > 0 ? 'var(--sev-critical)' : undefined}
              sub={`${highCount} HIGH`}
              delay={160}
            />
            <StatCard
              label="SCAN TIME"
              value={duration}
              color="var(--cyan)"
              sub={scanDate}
              delay={240}
            />
          </div>
        </section>

        {scanData.ai_summary && (
          <section>
            <div className="section-label">// AI RISK ASSESSMENT</div>
            <div className="ai-panel">
              <div className="ai-panel__header">
                <span className="ai-panel__title">ANALYST ASSESSMENT</span>
                <span className="ai-panel__model">GROQ LLAMA-3.3-70B</span>
              </div>
              <p className="ai-panel__text">{scanData.ai_summary}</p>
            </div>
          </section>
        )}

        {scanData.remediation?.length > 0 && (
          <section>
            <div className="section-label">// REMEDIATION PRIORITY</div>
            <ol className="remediation-list">
              {scanData.remediation.map((item, i) => {
                const pri = remediationPriority(item)
                return (
                  <li key={i} className="remediation-row">
                    <span className="remediation-idx">[{pad(i + 1)}]</span>
                    {pri && (
                      <span
                        className="remediation-priority"
                        style={{ background: SEV_DIM[pri], color: SEV_COLORS[pri] }}
                      >
                        {pri}
                      </span>
                    )}
                    <span className="remediation-text">
                      {pri ? item.replace(/^(Remove|Rotate|Disable|Add|Replace|Audit)\s*/i, m => '') : item}
                    </span>
                  </li>
                )
              })}
            </ol>
          </section>
        )}

        {/* 03 · FINDINGS */}
        <section id="findings">
          <div className="section-label">// SECURITY FINDINGS</div>
          <div className="findings-subheader">
            <span className="findings-info">
              {presentModules.length} MODULES · {totalCount} TOTAL FINDINGS
            </span>
            <div className="findings-filters">
              {['ALL','CRITICAL','HIGH','MEDIUM'].map(f => (
                <button
                  key={f}
                  className={`filter-btn${activeFilter === f ? ' active' : ''}`}
                  onClick={() => setActiveFilter(f)}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <div className="module-accordion">
            {presentModules.map((key, i) => (
              <ModuleSection
                key={key}
                index={i}
                moduleKey={key}
                mod={findings[key]}
                activeFilter={activeFilter}
                sendToChat={sendToChat}
                scrollRef={el => { moduleRefs.current[key] = el }}
              />
            ))}
          </div>
        </section>

        {/* 04 · INTELLIGENCE */}
        <section id="intelligence">
          <div className="section-label">// INTELLIGENCE SUMMARY</div>
          <div className="intelligence-grid">
            <div>
              <div className="section-label">// PERMISSION RISK MATRIX</div>
              {findings.permissions
                ? <PermissionMatrix permissionsModule={findings.permissions} />
                : <p className="module-section__empty">NO PERMISSION DATA</p>
              }
            </div>
            <div>
              <div className="section-label">// APK METADATA</div>
              <div className="metadata-panel">
                {[
                  ['APP NAME',   scanData.app_name    ?? '—'],
                  ['PACKAGE',    scanData.package_name ?? '—'],
                  ['SCAN ID',    scanData.scan_id      ?? '—'],
                  ['DURATION',   duration],
                  ['MODULES',    '6 / 6 COMPLETE'],
                  ['ENGINE',     'AppEX v1.0.0'],
                  ['AI MODEL',   'GROQ LLAMA-3.3-70B'],
                  ['TIMESTAMP',  scanDate],
                ].map(([k, v]) => (
                  <div key={k} className="metadata-row">
                    <span className="metadata-key">{k}:</span>
                    <span className="metadata-val">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

      </div>
    </main>
  )
}
