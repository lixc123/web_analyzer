export const getTerminalServiceUrl = (): string => {
  const envUrl = (import.meta.env.VITE_TERMINAL_URL || '').trim()
  if (envUrl) {
    return envUrl.replace(/\/+$/, '')
  }

  const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:'
  const hostname = window.location.hostname || 'localhost'
  return `${protocol}//${hostname}:3001`
}

export const getTerminalServiceLabel = (terminalServiceUrl: string): string => {
  try {
    return new URL(terminalServiceUrl).host
  } catch {
    return terminalServiceUrl
  }
}

export const getTerminalServiceHealthUrl = (terminalServiceUrl: string): string => {
  return `${terminalServiceUrl.replace(/\/+$/, '')}/health`
}
