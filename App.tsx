import React, { useState, useEffect, useRef } from 'react';
import { Shield, Lock, Terminal, AlertTriangle, CheckCircle, XCircle, User, Key, Eye, EyeOff } from 'lucide-react';
import { LogEntry, AuthStatus } from './types';

// EDUCATIONAL NOTE:
// This application demonstrates Client-Side Validation.
// In a real-world scenario, client-side checks are for User Experience (UX) only.
// NEVER rely on client-side code for actual security. An attacker can bypass
// this entire React application and send requests directly to a backend API.
// Real security requires Server-Side Validation and secure authentication protocols (OAuth, JWT, etc.).

const MAX_ATTEMPTS = 3;

const App: React.FC = () => {
  // State for form inputs
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // State for authentication logic
  const [attempts, setAttempts] = useState(0);
  const [status, setStatus] = useState<AuthStatus>(AuthStatus.IDLE);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  
  // Terminal logs state for visual feedback
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Initial boot sequence log
  useEffect(() => {
    addLog('System initialized...', 'info');
    addLog('Loading secure module v2.0...', 'info');
    addLog('Waiting for credentials...', 'warning');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const addLog = (message: string, type: LogEntry['type'] = 'info') => {
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setLogs(prev => [...prev, { id: crypto.randomUUID(), timestamp, message, type }]);
  };

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();

    // 1. Check if system is locked
    if (status === AuthStatus.LOCKED || attempts >= MAX_ATTEMPTS) {
      addLog('ACCESS DENIED: System is locked due to excessive failures.', 'error');
      return;
    }

    addLog(`Initiating authentication sequence for user: ${username || 'UNKNOWN'}`, 'info');
    setStatus(AuthStatus.AUTHENTICATING);
    setErrorMessage(null);

    // Simulate network delay for realism
    setTimeout(() => {
      validateCredentials();
    }, 800);
  };

  const validateCredentials = () => {
    // 2. Client-Side Validation: Empty Fields
    if (!username.trim() || !password.trim()) {
      const error = 'ERROR: Credentials cannot be empty.';
      setErrorMessage(error);
      addLog(error, 'error');
      setStatus(AuthStatus.IDLE);
      return;
    }

    // 3. Client-Side Validation: Password Strength
    // Educational: This prevents users from submitting obviously weak passwords before hitting the server.
    if (password.length < 6) {
      const error = 'SECURITY VIOLATION: Password must be at least 6 characters.';
      setErrorMessage(error);
      addLog(error, 'error');
      setStatus(AuthStatus.IDLE);
      return;
    }

    // 4. Authentication Check (Hardcoded Demo Credentials)
    // Educational: NEVER store credentials in frontend code in production.
    if (username === 'admin' && password === 'admin123') {
      setStatus(AuthStatus.SUCCESS);
      addLog('Authentication successful. Access granted.', 'success');
      addLog('Redirecting to secure dashboard...', 'success');
    } else {
      // Failed Attempt Logic
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);
      
      if (newAttempts >= MAX_ATTEMPTS) {
        setStatus(AuthStatus.LOCKED);
        const error = `CRITICAL FAILURE: Max attempts reached (${newAttempts}/${MAX_ATTEMPTS}). Account locked.`;
        setErrorMessage('Account Locked.');
        addLog(error, 'error');
        addLog('Session terminated.', 'error');
      } else {
        setStatus(AuthStatus.IDLE);
        const remaining = MAX_ATTEMPTS - newAttempts;
        const error = `ACCESS DENIED: Invalid credentials. ${remaining} attempt(s) remaining.`;
        setErrorMessage(`Invalid credentials. ${remaining} attempts left.`);
        addLog(error, 'warning');
      }
    }
  };

  const resetSystem = () => {
    setUsername('');
    setPassword('');
    setAttempts(0);
    setStatus(AuthStatus.IDLE);
    setErrorMessage(null);
    setLogs([]);
    addLog('System reset initiated by administrator.', 'info');
  };

  return (
    <div className="min-h-screen bg-black text-green-500 font-mono p-4 flex flex-col md:flex-row gap-6 items-center justify-center relative overflow-hidden">
      
      {/* Background Decor */}
      <div className="absolute inset-0 z-0 opacity-10 pointer-events-none">
         <div className="absolute top-10 left-10 text-9xl font-bold text-green-900 select-none">01</div>
         <div className="absolute bottom-10 right-10 text-9xl font-bold text-green-900 select-none">10</div>
      </div>

      {/* Main Login Panel */}
      <div className="w-full max-w-md bg-gray-900/80 border border-green-500/30 rounded-lg shadow-[0_0_20px_rgba(34,197,94,0.1)] p-8 z-10 backdrop-blur-sm relative">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-green-500 to-transparent opacity-50"></div>
        
        <div className="flex items-center justify-center mb-8">
          <Shield className="w-12 h-12 text-green-500 mr-3 animate-pulse" />
          <div>
            <h1 className="text-2xl font-bold tracking-wider text-green-400">SECURE_ACCESS</h1>
            <p className="text-xs text-green-600 tracking-widest">RESTRICTED AREA // AUTH REQUIRED</p>
          </div>
        </div>

        {status === AuthStatus.SUCCESS ? (
          <div className="text-center py-10 animate-fade-in">
            <CheckCircle className="w-20 h-20 text-green-500 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-white mb-2">ACCESS GRANTED</h2>
            <p className="text-green-400 mb-6">Welcome back, Administrator.</p>
            <button 
              onClick={resetSystem}
              className="px-6 py-2 border border-green-500 hover:bg-green-500 hover:text-black transition-colors rounded text-sm uppercase tracking-wider"
            >
              Log Out / Reset
            </button>
          </div>
        ) : (
          <form onSubmit={handleLogin} className="space-y-6">
            
            {/* Username Input */}
            <div className="relative group">
              <label className="block text-xs uppercase tracking-widest text-green-600 mb-2">Identity</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-green-700 group-focus-within:text-green-500 transition-colors" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={status === AuthStatus.LOCKED || status === AuthStatus.AUTHENTICATING}
                  className="w-full bg-black/50 border border-green-800 rounded px-10 py-3 text-green-400 focus:outline-none focus:border-green-500 focus:shadow-[0_0_10px_rgba(34,197,94,0.2)] transition-all placeholder-green-900"
                  placeholder="Enter Username"
                  autoComplete="off"
                />
              </div>
            </div>

            {/* Password Input */}
            <div className="relative group">
              <label className="block text-xs uppercase tracking-widest text-green-600 mb-2">Security Key</label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-green-700 group-focus-within:text-green-500 transition-colors" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={status === AuthStatus.LOCKED || status === AuthStatus.AUTHENTICATING}
                  className="w-full bg-black/50 border border-green-800 rounded px-10 py-3 text-green-400 focus:outline-none focus:border-green-500 focus:shadow-[0_0_10px_rgba(34,197,94,0.2)] transition-all placeholder-green-900"
                  placeholder="Enter Password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-green-800 hover:text-green-500 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Validation Feedback Area */}
            {errorMessage && (
              <div className={`flex items-start p-3 rounded border ${status === AuthStatus.LOCKED ? 'bg-red-900/20 border-red-500/50 text-red-400' : 'bg-yellow-900/20 border-yellow-500/50 text-yellow-400'}`}>
                {status === AuthStatus.LOCKED ? <Lock className="w-5 h-5 mr-2 shrink-0" /> : <AlertTriangle className="w-5 h-5 mr-2 shrink-0" />}
                <span className="text-sm font-semibold">{errorMessage}</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={status === AuthStatus.LOCKED || status === AuthStatus.AUTHENTICATING}
              className={`w-full py-3 px-4 rounded font-bold tracking-widest uppercase transition-all duration-300 flex items-center justify-center
                ${status === AuthStatus.LOCKED 
                  ? 'bg-red-900/50 text-red-500 cursor-not-allowed border border-red-900' 
                  : 'bg-green-600 hover:bg-green-500 text-black shadow-[0_0_15px_rgba(34,197,94,0.4)] hover:shadow-[0_0_25px_rgba(34,197,94,0.6)]'
                }
              `}
            >
              {status === AuthStatus.AUTHENTICATING ? (
                <span className="animate-pulse">Verifying...</span>
              ) : status === AuthStatus.LOCKED ? (
                <span className="flex items-center"><XCircle className="w-4 h-4 mr-2"/> LOCKED</span>
              ) : (
                "Authenticate"
              )}
            </button>
            
            {/* Demo Hints */}
            <div className="text-[10px] text-gray-500 text-center border-t border-gray-800 pt-4 mt-2">
               <p>DEMO CREDENTIALS:</p>
               <p>User: <span className="text-gray-400">admin</span> | Pass: <span className="text-gray-400">admin123</span></p>
            </div>
          </form>
        )}
      </div>

      {/* Terminal Output Panel - Visual Feedback */}
      <div className="w-full max-w-md h-[500px] bg-black border border-gray-800 rounded-lg p-4 font-mono text-xs z-10 shadow-2xl flex flex-col relative overflow-hidden">
        <div className="flex items-center justify-between border-b border-gray-800 pb-2 mb-2">
            <div className="flex items-center text-gray-400">
                <Terminal className="w-4 h-4 mr-2" />
                <span>SYS_LOG.TXT</span>
            </div>
            <div className="flex space-x-1">
                <div className="w-2 h-2 rounded-full bg-red-500/50"></div>
                <div className="w-2 h-2 rounded-full bg-yellow-500/50"></div>
                <div className="w-2 h-2 rounded-full bg-green-500/50"></div>
            </div>
        </div>
        
        <div className="flex-1 overflow-y-auto space-y-1 pr-2 font-mono">
            {logs.map((log) => (
                <div key={log.id} className="flex gap-2 animate-in fade-in slide-in-from-left-2 duration-300">
                    <span className="text-gray-600 shrink-0">[{log.timestamp}]</span>
                    <span className={`${
                        log.type === 'error' ? 'text-red-500' : 
                        log.type === 'success' ? 'text-green-400' : 
                        log.type === 'warning' ? 'text-yellow-500' : 'text-gray-300'
                    }`}>
                        {log.type === 'error' && '>> ERR: '}
                        {log.type === 'success' && '>> OK: '}
                        {log.type === 'warning' && '>> WARN: '}
                        {log.message}
                    </span>
                </div>
            ))}
            <div ref={logsEndRef} />
        </div>
        
        {/* Blinking Cursor at bottom of terminal */}
        <div className="mt-2 text-green-500 animate-pulse">
            _
        </div>
      </div>

    </div>
  );
};

export default App;