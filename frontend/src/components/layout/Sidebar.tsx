import React from 'react';
import {
  Layers,
  Globe,
  Network,
  Cpu,
  AlertTriangle,
  Share2,
  ShieldAlert,
  History,
  Clock,
  Plus
} from 'lucide-react';
import { InvestigationResponse } from '../../types/api';

export interface SidebarCounts {
  assets?: number;
  dns?: number;
  services?: number;
  vulnerabilities?: number;
  graph?: number;
  findings?: number;
  monitoring?: number;
  scans?: number;
}

interface SidebarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  investigations: InvestigationResponse[];
  selectedInv: InvestigationResponse | null;
  onSelectInv: (inv: InvestigationResponse) => void;
  onOpenNewInvModal: () => void;
  counts: SidebarCounts;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  investigations,
  selectedInv,
  onSelectInv,
  onOpenNewInvModal,
  counts,
}) => {
  const navItems = [
    { id: 'overview', label: '1. Overview', icon: <Layers size={17} /> },
    { id: 'assets', label: '2. Discovered Assets', icon: <Globe size={17} />, count: counts.assets },
    { id: 'dns', label: '3. DNS / Infrastructure', icon: <Network size={17} />, count: counts.dns },
    { id: 'services', label: '4. Services & Tech', icon: <Cpu size={17} />, count: counts.services },
    { id: 'vulnerabilities', label: '5. Vulnerabilities', icon: <AlertTriangle size={17} />, count: counts.vulnerabilities },
    { id: 'graph', label: '6. Attack Surface Graph', icon: <Share2 size={17} />, count: counts.graph },
    { id: 'findings', label: '7. Findings & Risk', icon: <ShieldAlert size={17} />, count: counts.findings },
    { id: 'monitoring', label: '8. Monitoring & Changes', icon: <History size={17} />, count: counts.monitoring },
    { id: 'scans', label: '9. Scans & Details', icon: <Clock size={17} />, count: counts.scans },
  ];

  return (
    <aside className="sidebar">
      {/* Assessment Selector Station */}
      <div style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
            ACTIVE ASSESSMENTS
          </span>
          <button
            onClick={onOpenNewInvModal}
            className="btn btn-primary"
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
            title="Create New Assessment"
          >
            <Plus size={12} />
            <span>New</span>
          </button>
        </div>

        <select
          className="form-input"
          value={selectedInv?.id || ''}
          onChange={e => {
            const found = investigations.find(i => i.id === e.target.value);
            if (found) onSelectInv(found);
          }}
          style={{ width: '100%', padding: '0.45rem 0.65rem', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}
        >
          {investigations.map(inv => (
            <option key={inv.id} value={inv.id}>
              {inv.target_domain} ({inv.reference_code})
            </option>
          ))}
          {investigations.length === 0 && (
            <option value="" disabled>No assessments available</option>
          )}
        </select>
      </div>

      {/* Navigation Sections */}
      <nav style={{ flex: 1, padding: '0.75rem 0.5rem', display: 'flex', flexDirection: 'column', gap: '0.25rem', overflowY: 'auto' }}>
        <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', padding: '0.35rem 0.75rem', letterSpacing: '0.04em' }}>
          INVESTIGATION WORKSPACE
        </div>

        {navItems.map(item => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', minWidth: 0 }}>
                <span style={{ color: isActive ? 'var(--cyan-400)' : 'var(--text-muted)', display: 'flex' }}>
                  {item.icon}
                </span>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.label}
                </span>
              </div>

              {item.count !== undefined && item.count > 0 && (
                <span
                  className="badge badge-neutral"
                  style={{
                    fontSize: '0.68rem',
                    padding: '0.1rem 0.4rem',
                    fontFamily: 'var(--font-mono)',
                    background: isActive ? 'rgba(56, 189, 248, 0.2)' : 'rgba(15, 23, 42, 0.6)',
                    color: isActive ? 'var(--cyan-400)' : 'var(--text-secondary)',
                  }}
                >
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={{ padding: '0.85rem 1rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
        <div>Stages 0–10 Active</div>
        <div style={{ color: 'var(--cyan-400)', marginTop: '0.15rem' }}>OSINT Platform v0.10.0</div>
      </div>
    </aside>
  );
};

export default Sidebar;
