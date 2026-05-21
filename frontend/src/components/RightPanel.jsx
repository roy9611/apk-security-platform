import { useState } from 'react'
import { BarChart, LineGraph } from './Charts.jsx'
import AIChat from './AIChat.jsx'
import './RightPanel.css'

function ChartSection({ label, children, defaultCollapsed = true }) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed)

  return (
    <div className={`rightpanel__chart${collapsed ? ' collapsed' : ''}`}>
      <div className="rightpanel__chart-header" onClick={() => setCollapsed(c => !c)}>
        <span className="rightpanel__chart-title">
          {collapsed ? '▶' : '▼'} {label}
        </span>
        <span className="rightpanel__chart-toggle">
          {collapsed ? 'expand' : 'collapse'}
        </span>
      </div>
      <div className="rightpanel__chart-body">
        {children}
      </div>
    </div>
  )
}

export default function RightPanel({
  scanData, appState, scanId,
  externalMessage, onExternalMessageHandled,
}) {
  return (
    <div className="rightpanel">
      <ChartSection label="FINDINGS BY MODULE" defaultCollapsed={false}>
        <BarChart scanData={appState === 'complete' ? scanData : null} />
      </ChartSection>

      <ChartSection label="SEVERITY DISTRIBUTION" defaultCollapsed={true}>
        <LineGraph scanData={appState === 'complete' ? scanData : null} />
      </ChartSection>

      <div className="rightpanel__chat">
        <AIChat
          scanId={scanId}
          scanData={scanData}
          appState={appState}
          externalMessage={externalMessage}
          onExternalMessageHandled={onExternalMessageHandled}
        />
      </div>
    </div>
  )
}
