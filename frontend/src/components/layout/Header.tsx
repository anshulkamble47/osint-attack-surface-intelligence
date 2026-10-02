import React from 'react';
import { Shield, LogOut, User as UserIcon, Activity } from 'lucide-react';
import { UserResponse, InvestigationResponse, HealthResponse } from '../../types/api';

interface HeaderProps {
  selectedInv: InvestigationResponse | null;
  currentUser: UserResponse | null;
  healthData: HealthResponse | null;
  onLogout: () => void;
  investigations?: InvestigationResponse[];
  onSelectInv?: (inv: InvestigationResponse) => void;
  onOpenNewInvModal?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  selectedInv,
  currentUser,
  healthData,
  onLogout,
}) => {
  return (
    <header className="header-bar">
      {/* Brand & Target Identifier */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <div
            style={{
              background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
              padding: '0.45rem',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 2px 8px rgba(2, 132, 199, 0.3)',
            }}
          >
            <Shield size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              OSINT ATTACK SURFACE ANALYZER
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              Intelligence & Risk Analysis Platform
            </div>
          </div>
        </div>

        {/* Investigation Scope Breadcrumb */}
        {selectedInv && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginLeft: '1rem', paddingLeft: '1rem', borderLeft: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Target Scope:</span>
            <span className="badge badge-neutral font-mono" style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--cyan-400)' }}>
              {selectedInv.target_domain}
            </span>
            <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>
              {selectedInv.status}
            </span>
          </div>
        )}
      </div>

      {/* Right: Health Badge & User Profile */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        {/* Database Health Pill */}
        <div
          className={`badge ${healthData?.database?.connected ? 'badge-success' : 'badge-danger'}`}
          style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
          title={healthData?.database?.connected ? `Connected (${healthData.database.latency_ms}ms)` : 'Database disconnected'}
        >
          <Activity size={13} className={healthData?.database?.connected ? '' : 'animate-pulse'} />
          <span>{healthData?.database?.connected ? `DB Connected (${healthData.database.latency_ms}ms)` : 'DB Disconnected'}</span>
        </div>

        {/* User Details & Logout */}
        {currentUser && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              background: 'rgba(30, 41, 59, 0.5)',
              padding: '0.3rem 0.6rem 0.3rem 0.75rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <UserIcon size={14} color="var(--cyan-400)" />
              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                {currentUser.username}
              </span>
              <span
                className="badge badge-neutral"
                style={{ fontSize: '0.65rem', padding: '0.1rem 0.35rem', textTransform: 'uppercase' }}
              >
                {currentUser.role}
              </span>
            </div>

            <button
              onClick={onLogout}
              className="btn btn-secondary"
              style={{
                padding: '0.25rem 0.5rem',
                fontSize: '0.75rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
              }}
              title="Sign Out"
            >
              <LogOut size={13} />
              <span>Logout</span>
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

export default Header;
