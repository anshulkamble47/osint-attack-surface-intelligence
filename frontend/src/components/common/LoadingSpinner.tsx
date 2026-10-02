import React from 'react';
import { Activity } from 'lucide-react';

interface LoadingSpinnerProps {
  message?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ message = 'Loading intelligence...' }) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '3rem 1.5rem',
        gap: '0.75rem',
        color: 'var(--cyan-400)',
      }}
    >
      <Activity size={28} className="animate-spin" />
      <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{message}</span>
    </div>
  );
};

export default LoadingSpinner;
