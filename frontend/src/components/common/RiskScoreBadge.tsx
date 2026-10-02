import React from 'react';

interface RiskScoreBadgeProps {
  score: number;
  category?: string;
  showLabel?: boolean;
}

export const RiskScoreBadge: React.FC<RiskScoreBadgeProps> = ({ score, category, showLabel = false }) => {
  let bg = 'rgba(148, 163, 184, 0.15)';
  let border = 'rgba(148, 163, 184, 0.3)';
  let color = 'var(--text-secondary)';
  let label = category || 'Low Risk';

  if (score >= 75) {
    bg = 'rgba(225, 29, 72, 0.2)';
    border = 'rgba(225, 29, 72, 0.5)';
    color = '#fb7185';
    label = category || 'Critical Risk';
  } else if (score >= 50) {
    bg = 'rgba(234, 88, 12, 0.2)';
    border = 'rgba(234, 88, 12, 0.45)';
    color = '#fb923c';
    label = category || 'High Risk';
  } else if (score >= 25) {
    bg = 'rgba(234, 179, 8, 0.2)';
    border = 'rgba(234, 179, 8, 0.4)';
    color = '#facc15';
    label = category || 'Medium Risk';
  } else {
    bg = 'rgba(52, 211, 153, 0.15)';
    border = 'rgba(52, 211, 153, 0.35)';
    color = 'var(--emerald-400)';
    label = category || 'Low Risk';
  }

  return (
    <span
      className="badge font-mono"
      style={{
        background: bg,
        border: `1px solid ${border}`,
        color: color,
        fontWeight: 700,
      }}
      title={`Contextual Risk Score: ${score}/100 (${label})`}
    >
      {score}/100 {showLabel ? `(${label})` : ''}
    </span>
  );
};

export default RiskScoreBadge;
