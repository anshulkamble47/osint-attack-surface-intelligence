import React from 'react';

interface SeverityBadgeProps {
  severity?: string | null;
  cvssScore?: number | null;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, cvssScore, size = 'md' }) => {
  const norm = (severity || 'UNKNOWN').toUpperCase();

  let className = 'badge severity-info';
  if (norm === 'CRITICAL') className = 'badge severity-critical';
  else if (norm === 'HIGH') className = 'badge severity-high';
  else if (norm === 'MEDIUM') className = 'badge severity-medium';
  else if (norm === 'LOW') className = 'badge severity-low';

  const fontStyle = size === 'sm' ? { fontSize: '0.7rem', padding: '0.15rem 0.5rem' } : undefined;

  return (
    <span className={className} style={fontStyle}>
      {norm} {cvssScore !== undefined && cvssScore !== null ? `(${cvssScore})` : ''}
    </span>
  );
};

export default SeverityBadge;
