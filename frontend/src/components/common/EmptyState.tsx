import React from 'react';
import { LucideIcon, Layers } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description?: string;
  message?: string;
  icon?: LucideIcon | React.ComponentType<{ size?: number }> | React.ReactNode;
  actionLabel?: string;
  actionText?: string;
  onAction?: () => void;
  loading?: boolean;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  message,
  icon,
  actionLabel,
  actionText,
  onAction,
  loading = false,
}) => {
  const text = description || message || '';
  const btnLabel = actionLabel || actionText;

  const renderIcon = () => {
    if (!icon) return <Layers size={28} />;
    if (React.isValidElement(icon)) {
      return icon;
    }
    const IconComp = icon as React.ElementType;
    return <IconComp size={28} />;
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '3rem 1.5rem',
        textAlign: 'center',
        color: 'var(--text-muted)',
      }}
    >
      <div
        style={{
          background: 'rgba(15, 23, 42, 0.8)',
          border: '1px solid var(--border-subtle)',
          padding: '1rem',
          borderRadius: '50%',
          color: 'var(--cyan-400)',
          marginBottom: '1rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {renderIcon()}
      </div>
      <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
        {title}
      </h3>
      <p style={{ fontSize: '0.85rem', maxWidth: '440px', lineHeight: 1.5, marginBottom: btnLabel ? '1.25rem' : 0 }}>
        {text}
      </p>
      {btnLabel && onAction && (
        <button className="btn btn-primary" onClick={onAction} disabled={loading}>
          {loading ? 'Running...' : btnLabel}
        </button>
      )}
    </div>
  );
};

export default EmptyState;
