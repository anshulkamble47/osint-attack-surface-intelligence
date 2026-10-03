import React from 'react';
import { LucideIcon } from 'lucide-react';

interface CompactStatCardProps {
  icon: LucideIcon;
  label: string;
  value: number | string;
  subtext?: string;
  color?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'purple' | 'neutral';
  onClick?: () => void;
}

export const CompactStatCard: React.FC<CompactStatCardProps> = ({
  icon: Icon,
  label,
  value,
  subtext,
  color = 'cyan',
  onClick,
}) => {
  const colorMap = {
    cyan: {
      bg: 'rgba(14, 165, 233, 0.12)',
      border: 'rgba(56, 189, 248, 0.25)',
      icon: 'var(--cyan-400)',
      val: 'var(--text-primary)',
    },
    emerald: {
      bg: 'rgba(52, 211, 153, 0.12)',
      border: 'rgba(52, 211, 153, 0.25)',
      icon: 'var(--emerald-400)',
      val: 'var(--emerald-400)',
    },
    amber: {
      bg: 'rgba(251, 191, 36, 0.12)',
      border: 'rgba(251, 191, 36, 0.25)',
      icon: 'var(--amber-400)',
      val: 'var(--amber-400)',
    },
    rose: {
      bg: 'rgba(244, 63, 94, 0.12)',
      border: 'rgba(244, 63, 94, 0.25)',
      icon: 'var(--rose-400)',
      val: 'var(--rose-400)',
    },
    purple: {
      bg: 'rgba(168, 85, 247, 0.12)',
      border: 'rgba(168, 85, 247, 0.25)',
      icon: 'var(--purple-400)',
      val: 'var(--purple-400)',
    },
    neutral: {
      bg: 'rgba(148, 163, 184, 0.1)',
      border: 'rgba(148, 163, 184, 0.2)',
      icon: 'var(--text-secondary)',
      val: 'var(--text-primary)',
    },
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div
      className="stat-card-compact"
      style={{
        borderColor: scheme.border,
        cursor: onClick ? 'pointer' : 'default',
      }}
      onClick={onClick}
    >
      <div
        className="stat-icon-wrapper"
        style={{
          background: scheme.bg,
          color: scheme.icon,
          border: `1px solid ${scheme.border}`,
        }}
      >
        <Icon size={18} />
      </div>

      <div className="stat-content">
        <span className="stat-label-compact">{label}</span>
        <span className="stat-value-compact" style={{ color: scheme.val }}>
          {value}
        </span>
        {subtext && <span className="stat-subtext-compact">{subtext}</span>}
      </div>
    </div>
  );
};
