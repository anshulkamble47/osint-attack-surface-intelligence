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
  Plus,
  Target,
  Calendar
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
    { id: 'overview', label: '1. Overview', icon: <Layers size={16} /> },
    { id: 'assets', label: '2. Discovered Assets', icon: <Globe size={16} />, count: counts.assets },
    { id: 'dns', label: '3. DNS / Infrastructure', icon: <Network size={16} />, count: counts.dns },
    { id: 'services', label: '4. Services & Tech', icon: <Cpu size={16} />, count: counts.services },
    { id: 'vulnerabilities', label: '5. Vulnerabilities', icon: <AlertTriangle size={16} />, count: counts.vulnerabilities },
    { id: 'graph', label: '6. Attack Surface Graph', icon: <Share2 size={16} />, count: counts.graph },
    { id: 'findings', label: '7. Findings & Risk', icon: <ShieldAlert size={16} />, count: counts.findings },
    { id: 'monitoring', label: '8. Monitoring & Changes', icon: <History size={16} />, count: counts.monitoring },
    { id: 'scans', label: '9. Scans & Details', icon: <Clock size={16} />, count: counts.scans },
  ];

  return (
    <aside className="sidebar">
      {/* Active Assessments Section */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', paddingBottom: '0.65rem', borderBottom: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 0.25rem' }}>
          <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
            ACTIVE ASSESSMENTS ({investigations.length})
          </span>
          <button
            onClick={onOpenNewInvModal}
            className="btn btn-primary"
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: '0.25rem', height: '24px' }}
            title="Create New Investigation"
          >
            <Plus size={12} />
            <span>New</span>
          </button>
        </div>

        {/* Scrollable list of investigation cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', maxHeight: '150px', overflowY: 'auto', paddingRight: '2px' }}>
          {investigations.map(inv => {
            const isSelected = selectedInv?.id === inv.id;
            return (
              <div
                key={inv.id}
                onClick={() => onSelectInv(inv)}
                className={`investigation-card-compact ${isSelected ? 'selected' : ''}`}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', minWidth: 0 }}>
                    <Target size={13} color={isSelected ? 'var(--cyan-400)' : 'var(--text-muted)'} style={{ flexShrink: 0 }} />
                    <span
                      style={{
                        fontSize: '0.8rem',
                        fontWeight: isSelected ? 700 : 600,
                        color: isSelected ? 'var(--cyan-400)' : 'var(--text-primary)',
                        fontFamily: 'var(--font-mono)',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}
                      title={inv.target_domain}
                    >
                      {inv.target_domain}
                    </span>
                  </div>

                  <span
                    className={`badge ${inv.status === 'active' ? 'badge-success' : 'badge-neutral'}`}
                    style={{ fontSize: '0.62rem', padding: '0.1rem 0.35rem' }}
                  >
                    {inv.status}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                  <span className="font-mono" style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>
                    {inv.reference_code}
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                    <Calendar size={10} />
                    {new Date(inv.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                  </span>
                </div>
              </div>
            );
          })}

          {investigations.length === 0 && (
            <div style={{ padding: '0.75rem', textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              No active assessments. Click "+ New" to begin.
            </div>
          )}
        </div>
      </div>

      {/* Navigation Sections */}
      <nav style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.2rem', overflowY: 'auto' }}>
        <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', padding: '0.35rem 0.5rem', letterSpacing: '0.05em' }}>
          INVESTIGATION MODULES
        </div>

        {navItems.map(item => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', minWidth: 0 }}>
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
                    fontSize: '0.65rem',
                    padding: '0.1rem 0.35rem',
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
      <div style={{ padding: '0.65rem 0.75rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>OSINT Analyzer</span>
        <span style={{ color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)', fontSize: '0.65rem' }}>v0.10.0</span>
      </div>
    </aside>
  );
};

export default Sidebar;
