import React from 'react';

export class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error("ErrorBoundary caught:", error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div style={{ padding: 20, color: '#ff35d2', background: '#0a1530', height: '100%', overflow: 'auto', fontFamily: 'monospace' }}>
                    <h2>React Render Crash</h2>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: '#ff70e3' }}>
                        {String(this.state.error?.stack || this.state.error)}
                    </pre>
                    <button onClick={() => window.location.reload()} style={{ padding: '8px 16px', background: '#ff35d2', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer', marginTop: 10 }}>Reload</button>
                </div>
            );
        }
        return this.props.children;
    }
}
