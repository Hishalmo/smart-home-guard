import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/Button'

interface ErrorBoundaryProps {
  children: ReactNode
}

interface ErrorBoundaryState {
  error: Error | null
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary] caught:', error, info.componentStack)
  }

  handleReset = () => {
    this.setState({ error: null })
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    const isDev = import.meta.env.DEV

    return (
      <div className="flex min-h-screen items-center justify-center bg-surface-base p-6">
        <div className="w-full max-w-xl rounded-lg border border-severity-critical/40 bg-severity-critical/5 p-6">
          <div className="mb-3 flex items-center gap-2 text-severity-critical">
            <AlertTriangle className="h-5 w-5" />
            <h1 className="text-base font-semibold">Something went wrong</h1>
          </div>
          <p className="mb-4 text-sm text-content-secondary">
            The dashboard hit an unexpected error. You can try to recover without losing your
            session, or reload the whole page.
          </p>
          {isDev && (
            <pre className="mb-4 max-h-48 overflow-auto rounded-md bg-surface-raised p-3 font-mono text-xs text-content-primary">
              {error.message}
              {error.stack ? `\n\n${error.stack}` : ''}
            </pre>
          )}
          <div className="flex gap-2">
            <Button variant="primary" onClick={this.handleReset}>
              Try again
            </Button>
            <Button variant="outline" onClick={() => window.location.reload()}>
              Reload page
            </Button>
          </div>
        </div>
      </div>
    )
  }
}
