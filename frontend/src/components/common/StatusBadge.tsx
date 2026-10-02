import React from 'react';

interface StatusBadgeProps {
  status: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const s = (status || '').toLowerCase();

  if (s === 'completed' || s === 'active' || s === 'resolving' || s === 'reachable' || s === 'open') {
    return (
      <span className="badge badge-success">
        <span className="pulse-dot pulse-success" />
        {status}
      </span>
    );
  }

  if (s === 'running' || s === 'pending' || s === 'acknowledged' || s === 'potential') {
    return (
      <span className="badge badge-warning">
        <span className="pulse-dot pulse-warning" />
        {status}
      </span>
    );
  }

  if (s === 'failed' || s === 'error' || s === 'expired' || s === 'unreachable') {
    return (
      <span className="badge badge-danger">
        <span className="pulse-dot pulse-danger" />
        {status}
      </span>
    );
  }

  if (s === 'resolved' || s === 'suppressed') {
    return (
      <span className="badge badge-neutral">
        {status}
      </span>
    );
  }

  return (
    <span className="badge badge-info">
      {status}
    </span>
  );
};

export default StatusBadge;
