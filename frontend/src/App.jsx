import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { parseAssistantMarkdown } from './assistantMarkdown.js';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BarChart3,
  Bell,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  Code2,
  FileCode2,
  FileJson,
  FileText,
  Filter,
  FolderClock,
  History,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  Menu,
  MessageCircle,
  Send,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  UploadCloud,
  X,
} from 'lucide-react';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const MAX_PY_FILE_SIZE = 1_000_000;
const MAX_ZIP_FILE_SIZE = 10_000_000;


const AI_SECTION_LABELS = {
  'WHAT IT MEANS': 'What it means',
  'WHY IT MATTERS': 'Why it matters',
  'SAFER APPROACH': 'Safer approach',
  'SAFE EXAMPLE': 'Safe example',
};

function parseAiExplanation(text) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  const sections = [];
  let current = null;
  let matchedHeading = false;
  const headingPattern = /^\s*(?:#{1,3}\s*)?(?:\*\*)?(WHAT IT MEANS|WHY IT MATTERS|SAFER APPROACH|SAFE EXAMPLE)(?:\*\*)?\s*:?\s*(.*)$/i;

  for (const line of lines) {
    const match = line.match(headingPattern);
    if (match) {
      matchedHeading = true;
      if (current) sections.push(current);
      const key = match[1].toUpperCase();
      current = { key, title: AI_SECTION_LABELS[key], lines: match[2] ? [match[2]] : [] };
    } else if (current) {
      current.lines.push(line);
    } else if (line.trim()) {
      current = { key: 'EXPLANATION', title: 'Explanation', lines: [line] };
    }
  }

  if (current) sections.push(current);
  if (!matchedHeading) {
    return [{ key: 'EXPLANATION', title: 'Explanation', content: String(text || '').trim() }];
  }

  return sections
    .map((section) => ({ ...section, content: section.lines.join('\n').trim() }))
    .filter((section) => section.content);
}

function AiExplanationContent({ explanation, saferApproach }) {
  const sections = parseAiExplanation(explanation);
  const hasStructuredSections = sections.some((section) => section.key !== 'EXPLANATION');

  if (!hasStructuredSections) {
    return (
      <div className="ai-explanation-sections">
        <section className="ai-explanation-section">
          <h5>What it means</h5>
          <p>{explanation}</p>
        </section>
        {saferApproach && (
          <section className="ai-explanation-section">
            <h5>Safer approach</h5>
            <p>{saferApproach}</p>
          </section>
        )}
      </div>
    );
  }

  return (
    <div className="ai-explanation-sections">
      {sections.map((section, index) => {
        const isExample = section.key === 'SAFE EXAMPLE';
        const code = section.content
          .replace(/^```(?:python)?\s*$/gim, '')
          .replace(/^```\s*$/gm, '')
          .trim();
        return (
          <section className={`ai-explanation-section ${isExample ? 'ai-explanation-example' : ''}`} key={`${section.key}-${index}`}>
            <h5>{section.title}</h5>
            {isExample ? <pre><code>{code}</code></pre> : <p>{section.content}</p>}
          </section>
        );
      })}
    </div>
  );
}

const SENSITIVE_NAME_PATTERN =
  /(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|authorization|auth[_-]?token|refresh[_-]?token)/i;

function maskQuotedLiteral(literal) {
  // Preserve delimiters and source line numbers.
  const quote = literal.startsWith('"""') ? '"""'
    : literal.startsWith("'''") ? "'''"
    : literal[0];
  const lineBreaks = (literal.match(/\r\n|\n|\r/g) || []).join('');
  return `${quote}[REDACTED]${lineBreaks}${quote}`;
}

function redactSensitiveText(value) {
  let safeText = String(value ?? '');

  // Capture the quoted literal separately from its Python string prefix.
  safeText = safeText.replace(
    /(\b([A-Za-z_][A-Za-z0-9_]*)(?:[ \t]*:[ \t]*[^=,\r\n]+)?[ \t]*=[ \t]*)([rubfRUBF]{0,2})("""(?:\\[\s\S]|(?!""")[^\\])*"""|'''(?:\\[\s\S]|(?!''')[^\\])*'''|"(?:\\[\s\S]|[^"\\\r\n])*"|'(?:\\[\s\S]|[^'\\\r\n])*'|`(?:\\[\s\S]|[^`\\\r\n])*`)/g,
    (match, prefix, variableName, stringPrefix, literal) => {
      if (!SENSITIVE_NAME_PATTERN.test(variableName)) return match;
      return `${prefix}${stringPrefix}${maskQuotedLiteral(literal)}`;
    }
  );

  // Mask quoted dictionary values, including escaped quotes.
  safeText = safeText.replace(
    /(["'])([^"'\\\r\n]+)\1([ \t]*:[ \t]*)([rubfRUBF]{0,2})("""(?:\\[\s\S]|(?!""")[^\\])*"""|'''(?:\\[\s\S]|(?!''')[^\\])*'''|"(?:\\[\s\S]|[^"\\\r\n])*"|'(?:\\[\s\S]|[^'\\\r\n])*')/g,
    (match, keyQuote, key, separator, stringPrefix, literal) => {
      if (!SENSITIVE_NAME_PATTERN.test(key)) return match;
      return `${keyQuote}${key}${keyQuote}${separator}${stringPrefix}${maskQuotedLiteral(literal)}`;
    }
  );

  // Mask bearer credentials.
  safeText = safeText.replace(
    /(\bBearer\s+)[A-Za-z0-9._~+/-]+=*/gi,
    '$1[REDACTED]'
  );

  // Mask common provider token formats.
  safeText = safeText.replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED]');
  safeText = safeText.replace(
    /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    '[REDACTED]'
  );
  safeText = safeText.replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, '[REDACTED]');
  safeText = safeText.replace(/\b(?:xox[baprs]-)[A-Za-z0-9-]{10,}\b/g, '[REDACTED]');
  safeText = safeText.replace(
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    '[REDACTED]'
  );

  // Mask command-line style secret assignments.
  safeText = safeText.replace(
    /((?:--?)(?:password|passwd|token|secret|api[-_]?key|access[-_]?key)\s*=\s*)[^\s"'`]+/gi,
    '$1[REDACTED]'
  );

  return safeText;
}

function formatDate(value) {
  if (!value) return 'Unknown date';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function getScanResult(scan) {
  if (!scan) return null;
  const result = scan.result || scan;
  return {
    filePath: result.file_path || scan.file_name || scan.file_path || 'unknown.py',
    findings: result.findings || scan.findings || [],
    total: result.total_findings ?? scan.total_findings ?? (result.findings || scan.findings || []).length,
    counts: result.severity_counts || scan.severity_counts || {},
    syntaxError: result.syntax_error || scan.syntax_error || null,
    warnings: result.scanner_warnings || scan.scanner_warnings || [],
    typeCheck: result.type_check || scan.type_check || { status: 'not_requested', issues: [] },
    fileCount: result.file_count ?? scan.file_count ?? 1,
    filesScanned: result.files_scanned || scan.files_scanned || [],
    fileErrors: result.file_errors || scan.file_errors || [],
    deduplicatedFindings: result.deduplicated_findings ?? scan.deduplicated_findings ?? 0,
  };
}

function SeverityBadge({ severity }) {
  const value = (severity || 'INFO').toLowerCase();
  return <span className={`severity-badge severity-${value}`}>{severity || 'INFO'}</span>;
}

function EmptyState({ icon: Icon = ShieldCheck, title, description, action }) {
  return (
    <div className="empty-state">
      <div className="empty-icon"><Icon size={25} /></div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}

function App() {
  const [activeView, setActiveView] = useState('overview');
  const [backendStatus, setBackendStatus] = useState('checking');
  const [aiMode, setAiMode] = useState('local');
  const [aiExplanation, setAiExplanation] = useState(null);
  const [aiExplanationLoading, setAiExplanationLoading] = useState(false);
  const [aiExplanationError, setAiExplanationError] = useState('');
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [assistantMessages, setAssistantMessages] = useState([]);
  const [assistantDraft, setAssistantDraft] = useState('');
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [assistantError, setAssistantError] = useState('');
  const [consentRequest, setConsentRequest] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [activeScan, setActiveScan] = useState(null);
  const [activeSource, setActiveSource] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [file, setFile] = useState(null);
  const [source, setSource] = useState('');
  const [inputMode, setInputMode] = useState('file');
  const [includeBandit, setIncludeBandit] = useState(true);
  const [includeMypy, setIncludeMypy] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState('');
  const [toast, setToast] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [findingSearch, setFindingSearch] = useState('');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const fileInputRef = useRef(null);

  const currentResult = useMemo(() => getScanResult(activeScan), [activeScan]);
  const findings = currentResult?.findings || [];
  const visibleFindings = useMemo(() => {
    const query = findingSearch.trim().toLowerCase();
    return findings.filter((finding) => {
      const matchesSeverity = severityFilter === 'ALL' || finding.severity === severityFilter;
      const searchable = [
        finding.title,
        finding.rule_id,
        finding.description,
        finding.file_path,
        finding.evidence,
      ].join(' ').toLowerCase();
      return matchesSeverity && (!query || searchable.includes(query));
    });
  }, [findings, severityFilter, findingSearch]);

  const counts = currentResult?.counts || {};
  const totalFindings = currentResult?.total || 0;
  const highRisk = (counts.CRITICAL || 0) + (counts.HIGH || 0);

  const showToast = (message) => {
    setToast(message);
    window.setTimeout(() => setToast(''), 3200);
  };

  const checkBackend = useCallback(async () => {
    try {
      const response = await fetch('/api/health');
      if (!response.ok) throw new Error('Backend health check failed');
      const data = await response.json();
      setBackendStatus(data.status === 'ok' ? 'online' : 'offline');
      setAiMode(data.features?.ai_explanation_mode === 'nvidia' ? 'nvidia' : 'local');
    } catch {
      setBackendStatus('offline');
    }
  }, []);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const response = await fetch('/api/scans?limit=50');
      if (!response.ok) throw new Error('Could not load scan history');
      const data = await response.json();
      setHistory(data.scans || []);
    } catch (error) {
      setScanError(error.message || 'Could not load scan history');
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    checkBackend();
    loadHistory();
  }, [checkBackend, loadHistory]);

  useEffect(() => {
    setAssistantMessages([]);
    setAssistantOpen(false);
    setAssistantError('');
    setAssistantDraft('');
  }, [activeScan?.scan_id]);

  const assistantGreeting = {
    role: 'assistant',
    content: 'May I suggest a security improvement? I can review this scan, explain findings, and help prioritize safer fixes. I use limited masked finding metadata only; the original source files are not sent.'
  };

  const openAssistant = () => {
    setAssistantOpen(true);
    if (assistantMessages.length === 0) setAssistantMessages([assistantGreeting]);
  };

  const openAssistantAndReview = () => {
    setAssistantOpen(true);
    const baseMessages = assistantMessages.length ? assistantMessages : [assistantGreeting];
    if (assistantMessages.length === 0) setAssistantMessages(baseMessages);
    sendAssistantMessage('Review this scan and suggest the three highest-priority security improvements.', baseMessages);
  };

  const sendAssistantMessage = async (messageOverride = null, historyOverride = null, consentGranted = false) => {
    const message = String(messageOverride ?? assistantDraft).trim();
    if (!message || !activeScan?.scan_id || assistantLoading) return;
    if (message.length > 700) {
      setAssistantError('Keep each message under 700 characters.');
      return;
    }
    if (aiMode === 'nvidia' && !consentGranted) {
      setConsentRequest({
        type: 'chat',
        message,
        history: historyOverride ?? assistantMessages,
      });
      return;
    }

    const previousMessages = (historyOverride ?? assistantMessages).slice(-6);
    const nextMessages = [...(historyOverride ?? assistantMessages), { role: 'user', content: message }];
    setAssistantMessages(nextMessages);
    setAssistantDraft('');
    setAssistantError('');
    setAssistantLoading(true);
    try {
      const response = await fetch('/api/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: activeScan.scan_id,
          finding_id: selectedFinding?.finding_id || findings[0]?.finding_id || null,
          message,
          history: previousMessages,
          consent: aiMode === 'nvidia',
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Assistant request failed (${response.status})`);
      setAssistantMessages((items) => [...items, {
        role: 'assistant',
        content: data.reply,
        provider: data.provider,
        model: data.model,
      }]);
    } catch (error) {
      setAssistantMessages((items) => items.filter((item, index) => !(index === items.length - 1 && item.role === 'user' && item.content === message)));
      setAssistantError(error.message || 'Security Assistant could not answer.');
    } finally {
      setAssistantLoading(false);
    }
  };

  const explainFinding = async (finding, consentGranted = false) => {
    if (!activeScan?.scan_id || !finding?.finding_id) return;

    if (aiMode === 'nvidia' && !consentGranted) {
      setConsentRequest({ type: 'explain', finding });
      return;
    }

    setAiExplanationError('');
    setAiExplanationLoading(true);
    setAiExplanation(null);
    try {
      const response = await fetch(
        `/api/scans/${activeScan.scan_id}/findings/${encodeURIComponent(finding.finding_id)}/explain`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ consent: aiMode === 'nvidia' }),
        }
      );
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Explanation failed (${response.status})`);
      setAiExplanation({ findingId: finding.finding_id, ...data });
    } catch (error) {
      setAiExplanationError(error.message || 'Could not explain this finding.');
    } finally {
      setAiExplanationLoading(false);
    }
  };


  const confirmAssistantConsent = () => {
    const pending = consentRequest;
    setConsentRequest(null);
    if (!pending) return;
    if (pending.type === 'chat') {
      sendAssistantMessage(pending.message, pending.history, true);
    } else if (pending.type === 'explain') {
      explainFinding(pending.finding, true);
    }
  };

  const acceptFile = async (nextFile) => {
    if (!nextFile) return;
    const lowerName = nextFile.name.toLowerCase();
    const isPython = lowerName.endsWith('.py');
    const isZip = lowerName.endsWith('.zip');
    if (!isPython && !isZip) {
      setScanError('Only Python .py files or .zip archives are supported.');
      return;
    }
    const sizeLimit = isZip ? MAX_ZIP_FILE_SIZE : MAX_PY_FILE_SIZE;
    if (nextFile.size > sizeLimit) {
      setScanError(`The ${isZip ? 'ZIP archive' : 'Python file'} exceeds the ${(sizeLimit / 1_000_000).toFixed(0)} MB limit.`);
      return;
    }
    setScanError('');
    setFile(nextFile);
    setInputMode('file');
    if (isZip) {
      setSource('');
      return;
    }
    try {
      setSource(await nextFile.text());
    } catch {
      setSource('');
    }
  };

  const handleFileInput = (event) => {
    acceptFile(event.target.files?.[0]);
    event.target.value = '';
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  };

  const runScan = async (event) => {
    event?.preventDefault();
    setScanError('');
    setSelectedFinding(null);

    if (inputMode === 'file' && !file) {
      setScanError('Choose a Python file before starting the scan.');
      return;
    }
    if (inputMode === 'paste' && !source.trim()) {
      setScanError('Paste Python source code before starting the scan.');
      return;
    }

    setIsScanning(true);
    try {
      const isZipFile = inputMode === 'file' && file.name.toLowerCase().endsWith('.zip');
      const sourceForContext = inputMode === 'file'
        ? (isZipFile ? '' : await file.text())
        : source;
      let response;
      if (inputMode === 'file') {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('include_bandit', String(includeBandit));
        formData.append('include_mypy', String(includeMypy));
        response = await fetch('/api/scan', { method: 'POST', body: formData });
      } else {
        response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filename: 'pasted_code.py',
            source,
            include_bandit: includeBandit,
            include_mypy: includeMypy,
          }),
        });
      }

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Scan failed (${response.status})`);

      setActiveSource(redactSensitiveText(sourceForContext));
      setActiveScan(data);
      setActiveView('overview');
      setSeverityFilter('ALL');
      setFindingSearch('');
      await loadHistory();
      showToast(
        data.status === 'syntax_error'
          ? 'Scan completed with a syntax error.'
          : data.status === 'completed_with_errors'
            ? 'Analysis completed; some files had syntax errors.'
            : 'Analysis completed successfully.'
      );
    } catch (error) {
      setScanError(error.message || 'The scan could not be completed.');
    } finally {
      setIsScanning(false);
    }
  };

  const openHistoryItem = async (scanId) => {
    setScanError('');
    try {
      const response = await fetch(`/api/scans/${scanId}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not open scan');
      setActiveScan(data);
      setActiveSource('');
      setSelectedFinding(null);
      setActiveView('overview');
      setSeverityFilter('ALL');
      setFindingSearch('');
    } catch (error) {
      setScanError(error.message || 'Could not open scan');
    }
  };

  const startNewScan = () => {
    setActiveView('new-scan');
    setScanError('');
    setFile(null);
    setSource('');
    setActiveSource('');
    setInputMode('file');
  };

  const navigate = (view) => {
    setActiveView(view);
    setMobileNavOpen(false);
    setScanError('');
  };

  const currentScanId = activeScan?.scan_id;
  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'new-scan', label: 'New analysis', icon: ScanNavIcon },
    { id: 'history', label: 'Scan history', icon: FolderClock, count: history.length },
  ];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand-lockup">
          <div className="brand-mark"><Shield size={21} strokeWidth={2.4} /></div>
          <div>
            <div className="brand-name">sentinel<span>.</span></div>
            <div className="brand-caption">CODE SECURITY</div>
          </div>
          <button className="icon-button sidebar-close" onClick={() => setMobileNavOpen(false)} aria-label="Close menu"><X size={18} /></button>
        </div>

        <div className="workspace-switcher">
          <div className="workspace-avatar">PL</div>
          <div className="workspace-copy"><strong>Programming Languages</strong><span>Local workspace</span></div>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="main-nav">
          {navItems.map(({ id, label, icon: Icon, count }) => (
            <button key={id} className={`nav-item ${activeView === id ? 'active' : ''}`} onClick={() => navigate(id)}>
              <Icon size={18} strokeWidth={1.9} />
              <span>{label}</span>
              {id === 'history' && <span className="nav-count">{count}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-security-card">
            <div className="sidebar-security-icon"><LockKeyhole size={16} /></div>
            <strong>Private by design</strong>
            <p>Source files are analyzed, never executed or stored in scan history.</p>
          </div>
          <div className="sidebar-user">
            <div className="user-avatar">E</div>
            <div className="user-copy"><strong>Local analyst</strong><span>Developer workspace</span></div>
            <span className="online-dot" />
          </div>
        </div>
      </aside>

      {mobileNavOpen && <button className="mobile-scrim" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation" />}

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
            <div className="breadcrumb"><span>Workspace</span><ChevronRight size={14} /><strong>{navItems.find((item) => item.id === activeView)?.label || 'Overview'}</strong></div>
          </div>
          <div className="topbar-right">
            <div className={`backend-pill ${backendStatus}`}><span className="status-dot" />{backendStatus === 'checking' ? 'Checking API' : backendStatus === 'online' ? 'API connected' : 'API offline'}</div>
            <button className="icon-button notification-button" title="No new notifications"><Bell size={18} /><i /></button>
            <div className="topbar-avatar">E</div>
          </div>
        </header>

        <div className="page-content">
          {backendStatus === 'offline' && (
            <div className="connection-banner"><AlertCircle size={17} /><div><strong>Backend not reachable</strong><span>Start Flask on 127.0.0.1:5000, then refresh this page.</span></div><button onClick={checkBackend}><RefreshCw size={15} /> Retry</button></div>
          )}

          {scanError && <div className="error-banner"><AlertTriangle size={17} /><span>{scanError}</span><button onClick={() => setScanError('')} aria-label="Dismiss error"><X size={16} /></button></div>}

          {activeView === 'overview' && (
            <OverviewView
              activeScan={activeScan}
              activeSource={activeSource}
              currentResult={currentResult}
              counts={counts}
              totalFindings={totalFindings}
              highRisk={highRisk}
              history={history}
              historyLoading={historyLoading}
              selectedFinding={selectedFinding}
              setSelectedFinding={setSelectedFinding}
              visibleFindings={visibleFindings}
              severityFilter={severityFilter}
              setSeverityFilter={setSeverityFilter}
              findingSearch={findingSearch}
              setFindingSearch={setFindingSearch}
              onNewScan={startNewScan}
              onHistory={openHistoryItem}
              currentScanId={currentScanId}
              aiMode={aiMode}
              aiExplanation={aiExplanation}
              aiExplanationLoading={aiExplanationLoading}
              aiExplanationError={aiExplanationError}
              onExplainFinding={explainFinding}
            />
          )}

          {activeView === 'new-scan' && (
            <NewScanView
              file={file}
              source={source}
              setSource={setSource}
              inputMode={inputMode}
              setInputMode={setInputMode}
              includeBandit={includeBandit}
              setIncludeBandit={setIncludeBandit}
              includeMypy={includeMypy}
              setIncludeMypy={setIncludeMypy}
              isDragging={isDragging}
              setIsDragging={setIsDragging}
              isScanning={isScanning}
              fileInputRef={fileInputRef}
              onFileInput={handleFileInput}
              onDrop={handleDrop}
              onScan={runScan}
              onClearFile={() => { setFile(null); setSource(''); }}
            />
          )}

          {activeView === 'history' && (
            <HistoryView history={history} loading={historyLoading} onRefresh={loadHistory} onOpen={openHistoryItem} />
          )}

          <footer className="page-footer"><span>Sentinel Security Analyzer <b>v0.7.5</b></span><span><LockKeyhole size={12} /> Static analysis only · Source code is never executed</span></footer>
        </div>
      </main>

      {activeScan?.scan_id && (
        <SecurityAssistantWidget
          open={assistantOpen}
          onOpen={openAssistant}
          onOpenAndReview={openAssistantAndReview}
          onClose={() => setAssistantOpen(false)}
          messages={assistantMessages}
          draft={assistantDraft}
          setDraft={setAssistantDraft}
          loading={assistantLoading}
          error={assistantError}
          onSend={sendAssistantMessage}
          aiMode={aiMode}
        />
      )}
      {consentRequest && (
        <div className="assistant-consent-backdrop" role="presentation">
          <section className="assistant-consent-dialog" role="dialog" aria-modal="true" aria-labelledby="assistant-consent-title">
            <div className="assistant-consent-icon"><LockKeyhole size={20} /></div>
            <h2 id="assistant-consent-title">Allow NVIDIA AI request?</h2>
            <p>
              {consentRequest.type === 'explain'
                ? 'The selected finding details and best-effort-masked evidence will be sent to NVIDIA Nemotron to generate an explanation.'
                : 'Your short message and limited masked scan metadata will be sent to NVIDIA Nemotron to generate a response.'}
            </p>
            <p className="assistant-consent-warning">Original source files, full file contents, API keys, and environment variables are not intentionally included. Redaction is best-effort and may miss unusual secret formats. Do not send personal data or credentials.</p>
            <div className="assistant-consent-actions">
              <button type="button" className="secondary-button" onClick={() => setConsentRequest(null)}>Cancel</button>
              <button type="button" className="primary-button" onClick={confirmAssistantConsent}>Send to NVIDIA</button>
            </div>
          </section>
        </div>
      )}
      {toast && <div className="toast"><CheckCircle2 size={17} />{toast}</div>}
    </div>
  );
}


function AssistantRichContent({ content }) {
  const blocks = parseAssistantMarkdown(content);

  const renderInline = (value, prefix) => {
    const parts = String(value ?? '').split(/(\*\*[^*]+\*\*|__[^_]+__|`[^`\n]+`)/g);
    return parts.map((part, index) => {
      if ((part.startsWith('**') && part.endsWith('**')) || (part.startsWith('__') && part.endsWith('__'))) {
        return <strong key={`${prefix}-${index}`}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code className="assistant-inline-code" key={`${prefix}-${index}`}>{part.slice(1, -1)}</code>;
      }
      return <span key={`${prefix}-${index}`}>{part}</span>;
    });
  };

  return (
    <div className="assistant-rich-content">
      {blocks.map((block, index) => {
        if (block.type === 'heading') {
          return <h4 key={index}>{renderInline(block.text, `h-${index}`)}</h4>;
        }
        if (block.type === 'ordered-list' || block.type === 'unordered-list') {
          const ListTag = block.type === 'ordered-list' ? 'ol' : 'ul';
          return (
            <ListTag key={index}>
              {block.items.map((item, itemIndex) => (
                <li key={itemIndex}>{renderInline(item, `l-${index}-${itemIndex}`)}</li>
              ))}
            </ListTag>
          );
        }
        if (block.type === 'code') {
          return (
            <pre className="assistant-code-block" key={index}>
              {block.language && <span className="assistant-code-language">{block.language}</span>}
              <code>{block.text}</code>
            </pre>
          );
        }
        if (block.type === 'divider') return <hr key={index} />;
        return <p key={index}>{renderInline(block.text, `p-${index}`)}</p>;
      })}
    </div>
  );
}

function SecurityAssistantWidget({ open, onOpen, onOpenAndReview, onClose, messages, draft, setDraft, loading, error, onSend, aiMode }) {
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, loading, error]);

  const submit = (event) => {
    event.preventDefault();
    onSend();
  };

  return (
    <div className={`security-assistant ${open ? 'is-open' : ''}`}>
      {open ? (
        <section className="assistant-panel" aria-label="Sentinel Security Assistant">
          <header className="assistant-panel-header">
            <div className="assistant-avatar"><Sparkles size={17} /></div>
            <div className="assistant-panel-title">
              <strong>Sentinel Security Assistant</strong>
              <span>{aiMode === 'nvidia' ? 'NVIDIA Nemotron · Security mode' : 'Local guidance mode'}</span>
            </div>
            <button className="assistant-close" onClick={onClose} aria-label="Close assistant"><X size={17} /></button>
          </header>
          <div className="assistant-privacy-note">
            <LockKeyhole size={13} /> Only your short question and masked finding metadata are used. Source files are never sent.
          </div>
          <div className="assistant-messages" aria-live="polite">
            {messages.map((item, index) => (
              <div className={`assistant-message ${item.role === 'user' ? 'user-message' : 'bot-message'}`} key={`${item.role}-${index}`}>
                {item.role === 'assistant' ? <AssistantRichContent content={item.content} /> : <div className="assistant-user-content">{item.content}</div>}
                {item.model && <small>{item.provider === 'nvidia' ? `NVIDIA · ${item.model}` : 'Local guidance'}</small>}
                {index === 0 && item.role === 'assistant' && messages.length === 1 && (
                  <button className="assistant-suggestion" onClick={() => onSend('Review this scan and suggest the three highest-priority security improvements.')}>Review this scan <ArrowRight size={13} /></button>
                )}
              </div>
            ))}
            {loading && <div className="assistant-message bot-message assistant-typing"><LoaderCircle size={14} className="spin" /> Reviewing the security context...</div>}
            {error && <div className="assistant-inline-error">{error}</div>}
            <div ref={messagesEndRef} />
          </div>
          <form className="assistant-composer" onSubmit={submit}>
            <textarea
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); submit(event); } }}
              placeholder="Ask about this scan or a Python security issue..."
              maxLength={700}
              rows={2}
              disabled={loading}
            />
            <div className="assistant-composer-footer">
              <span>{draft.length}/700 · Security topics only</span>
              <button type="submit" disabled={loading || !draft.trim()} aria-label="Send message"><Send size={15} /></button>
            </div>
          </form>
        </section>
      ) : (
        <>
          <button className="assistant-teaser" onClick={onOpenAndReview}>May I suggest a security improvement?</button>
          <button className="assistant-launcher" onClick={onOpen} aria-label="Open Sentinel Security Assistant"><MessageCircle size={22} /><span className="assistant-launcher-dot" /></button>
        </>
      )}
    </div>
  );
}

function ScanNavIcon(props) {
  return <Code2 {...props} />;
}

function OverviewView({
  activeScan,
  activeSource,
  currentResult,
  counts,
  totalFindings,
  highRisk,
  history,
  historyLoading,
  selectedFinding,
  setSelectedFinding,
  visibleFindings,
  severityFilter,
  setSeverityFilter,
  findingSearch,
  setFindingSearch,
  onNewScan,
  onHistory,
  currentScanId,
  aiMode,
  aiExplanation,
  aiExplanationLoading,
  aiExplanationError,
  onExplainFinding,
}) {
  const hasScan = Boolean(activeScan && currentResult);
  const selected = selectedFinding || currentResult?.findings?.[0] || null;
  const distributionTotal = Math.max(totalFindings, 1);

  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS</div>
          <h1>{hasScan ? 'Analysis overview' : 'Good to see you.'}</h1>
          <p>{hasScan ? `Reviewing findings for ${currentResult.filePath}` : 'Find security issues in your Python code before they find their way into production.'}</p>
        </div>
        <button className="primary-button" onClick={onNewScan}><Plus size={17} /> New analysis</button>
      </div>

      {!hasScan ? (
        <>
          <section className="welcome-panel">
            <div className="welcome-copy">
              <div className="welcome-tag"><Sparkles size={13} /> STATIC ANALYSIS WORKSPACE</div>
              <h2>Make your code<br /><em>harder to break.</em></h2>
              <p>Run Python source through custom AST rules and Bandit. Get line-level findings, practical recommendations, and exportable reports.</p>
              <button className="welcome-button" onClick={onNewScan}>Start a code scan <ArrowRight size={16} /></button>
              <div className="welcome-footnote"><ShieldCheck size={14} /> Your source is analyzed, never executed.</div>
            </div>
            <div className="welcome-visual" aria-hidden="true">
              <div className="orbit orbit-one" /><div className="orbit orbit-two" />
              <div className="visual-shield"><ShieldCheck size={64} strokeWidth={1.25} /></div>
              <div className="floating-code code-one"><span>01</span> ast.parse(source)</div>
              <div className="floating-code code-two"><span>02</span> bandit -f json</div>
              <div className="floating-status"><span className="pulse-dot" /> ENGINE READY</div>
            </div>
          </section>

          <div className="section-heading-row"><div><h2>Workspace snapshot</h2><p>Your recent analysis activity at a glance.</p></div><button className="text-button" onClick={() => onHistory(history[0]?.scan_id)} disabled={!history.length}>View latest <ArrowRight size={14} /></button></div>
          <div className="metric-grid">
            <MetricCard icon={FolderClock} label="Total scans" value={history.length} note="Saved in local history" tone="blue" />
            <MetricCard icon={ShieldAlert} label="Latest findings" value={history[0]?.total_findings ?? '—'} note={history[0]?.file_name || 'No scans yet'} tone="amber" />
            <MetricCard icon={Activity} label="High risk findings" value={history[0]?.severity_counts ? (history[0].severity_counts.CRITICAL || 0) + (history[0].severity_counts.HIGH || 0) : '—'} note="From latest scan" tone="red" />
            <MetricCard icon={BadgeCheck} label="Analysis engine" value="Ready" note="AST rules + Bandit" tone="green" />
          </div>
          <div className="section-heading-row recent-heading"><div><h2>Recent scans</h2><p>Open a previous result to inspect its findings.</p></div><button className="text-button" onClick={() => window.location.reload()}><RefreshCw size={14} /> Refresh</button></div>
          <RecentScans history={history} loading={historyLoading} onOpen={onHistory} onNewScan={onNewScan} />
        </>
      ) : (
        <>
          <div className="scan-meta-strip">
            <div className="scan-file-icon"><FileCode2 size={20} /></div>
            <div className="scan-meta-copy"><strong>{currentResult.filePath}</strong><span>Scan ID: {currentScanId || activeScan.scan_id || '—'}{currentResult.fileCount > 1 ? ` · ${currentResult.fileCount} Python files` : ''}</span></div>
            <div className="scan-meta-date"><Clock3 size={14} /> {formatDate(activeScan.created_at)}</div>
            <span className={`scan-status ${['syntax_error', 'completed_with_errors'].includes(activeScan.status) ? 'status-warning' : ''}`}><span />{activeScan.status || 'completed'}</span>
            {currentScanId && <div className="report-actions"><a href={`/api/scans/${currentScanId}/report.json`}><FileJson size={14} /> JSON</a><a href={`/api/scans/${currentScanId}/report.html`}><FileText size={14} /> HTML</a></div>}
          </div>

          {currentResult.syntaxError && <div className="syntax-banner"><AlertTriangle size={17} /><div><strong>Syntax error detected</strong><span>Line {currentResult.syntaxError.line || '?'}: {currentResult.syntaxError.message || 'Unable to parse source.'}</span></div></div>}
          {currentResult.warnings?.length > 0 && <div className="warning-banner"><AlertCircle size={17} /><div><strong>Scanner warnings</strong><span>{currentResult.warnings.join(' · ')}</span></div></div>}

          <div className="metric-grid result-metrics">
            <MetricCard icon={ShieldAlert} label="Total findings" value={totalFindings} note="Across all scanners" tone="blue" />
            <MetricCard icon={AlertTriangle} label="High risk" value={highRisk} note="Critical + High severity" tone="red" />
            <MetricCard icon={Activity} label="Medium" value={counts.MEDIUM || 0} note="Review recommended" tone="amber" />
            <MetricCard icon={BadgeCheck} label="Low / Info" value={(counts.LOW || 0) + (counts.INFO || 0)} note="Best-practice warnings" tone="green" />
          </div>

          <div className="results-layout">
            <section className="panel findings-panel">
              <div className="panel-heading"><div><h2>Security findings</h2><p>Detected patterns and recommended actions.{currentResult.deduplicatedFindings > 0 ? ` ${currentResult.deduplicatedFindings} duplicate scanner detections merged.` : ""}</p></div><span className="result-count">{visibleFindings.length} of {totalFindings}</span></div>
              <div className="finding-toolbar">
                <div className="search-field"><Search size={15} /><input value={findingSearch} onChange={(event) => setFindingSearch(event.target.value)} placeholder="Search findings..." /></div>
                <div className="filter-select"><Filter size={14} /><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="ALL">All severity</option>{SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}</select><ChevronDown size={13} /></div>
              </div>
              <div className="findings-list">
                {visibleFindings.length ? visibleFindings.map((finding, index) => (
                  <button key={finding.finding_id || `${finding.rule_id}-${finding.line_number}-${index}`} className={`finding-row ${selected?.finding_id === finding.finding_id ? 'selected' : ''}`} onClick={() => setSelectedFinding(finding)}>
                    <div className="finding-severity-rail" />
                    <div className="finding-row-main"><div className="finding-title-line"><strong>{finding.title}</strong><SeverityBadge severity={finding.severity} /></div><div className="finding-subline"><span>{finding.rule_id}</span><span className="subline-dot">·</span><span>{finding.file_path || currentResult.filePath}</span><span className="subline-dot">·</span><span>Line {finding.line_number}</span><span className="subline-dot">·</span><span>{finding.source === 'bandit' ? 'Bandit' : 'Custom AST'}</span></div></div>
                    <ChevronRight size={16} className="finding-chevron" />
                  </button>
                )) : <div className="inline-empty">No findings match the current filters.</div>}
              </div>
            </section>

            <aside className="panel detail-panel">
              <div className="panel-heading detail-heading"><div><div className="eyebrow">FINDING DETAILS</div><h2>Selected issue</h2></div><div className="detail-icon"><SlidersHorizontal size={17} /></div></div>
              {selected ? (
                <>
                  <div className="detail-title-wrap"><SeverityBadge severity={selected.severity} /><h3>{selected.title}</h3><p>{selected.description}</p></div>
                  <div className="detail-facts"><div><span>RULE ID</span><strong>{selected.rule_id}</strong></div><div><span>LINE</span><strong>{selected.line_number}</strong></div><div><span>CONFIDENCE</span><strong>{selected.confidence || '—'}</strong></div><div><span>CWE</span><strong>{selected.cwe_id || '—'}</strong></div></div>
                  <div className="detail-section"><h4><Code2 size={14} /> Source context</h4><CodeContext source={activeSource} lineNumber={selected.line_number} evidence={selected.evidence} /></div>
                  <div className="recommendation-box"><div className="recommendation-heading"><ShieldCheck size={15} /> Recommended action</div><p>{selected.recommendation || 'Review this finding manually.'}</p></div>
                  <section className="ai-explanation-box">
                    <div className="ai-explanation-heading">
                      <div><Sparkles size={14} /><strong>Finding explanation</strong></div>
                      <span>{aiMode === 'nvidia' ? 'NVIDIA API ready' : 'Local guidance'}</span>
                    </div>
                    <button className="secondary-button ai-explain-button" onClick={() => onExplainFinding(selected)} disabled={aiExplanationLoading}>
                      {aiExplanationLoading ? <><LoaderCircle size={14} className="spin" /> Explaining...</> : <><Sparkles size={14} /> Explain this finding</>}
                    </button>
                    {aiExplanation?.findingId === selected.finding_id && (
                      <div className="ai-explanation-result">
                        <span>{aiExplanation.provider === 'nvidia' ? `Generated with ${aiExplanation.model}` : 'Built-in rule guidance'}</span>
                        <AiExplanationContent
                          explanation={aiExplanation.explanation}
                          saferApproach={aiExplanation.safer_approach}
                        />
                        <small>{aiExplanation.disclaimer}</small>
                      </div>
                    )}
                    {aiExplanationError && <div className="ai-explanation-error">{aiExplanationError}</div>}
                  </section>
                  <div className="detail-source"><span>DETECTED BY</span><strong>{selected.source === 'bandit' ? 'Bandit scanner' : 'Custom AST rule engine'}</strong></div>
                  {selected.related_findings?.length > 0 && (
                    <div className="related-detections">
                      <strong>Also detected by</strong>
                      {selected.related_findings.map((item) => (
                        <span key={item.finding_id}>{item.source} · {item.rule_id}</span>
                      ))}
                    </div>
                  )}
                </>
              ) : <EmptyState icon={CircleHelp} title="No finding selected" description="Choose a finding from the list to see its details." />}
            </aside>
          </div>

          <div className="distribution-panel panel">
            <div className="panel-heading"><div><h2>Severity distribution</h2><p>Breakdown of findings by risk level.</p></div><BarChart3 size={19} className="muted-icon" /></div>
            <div className="distribution-bars">
              {SEVERITIES.map((severity) => {
                const count = counts[severity] || 0;
                const width = totalFindings ? (count / distributionTotal) * 100 : 0;
                return <div className="distribution-item" key={severity}><div className="distribution-label"><span><i className={`legend-dot dot-${severity.toLowerCase()}`} />{severity}</span><strong>{count}</strong></div><div className="distribution-track"><div className={`distribution-fill fill-${severity.toLowerCase()}`} style={{ width: `${width}%` }} /></div></div>;
              })}
            </div>
          </div>
          <TypeCheckPanel typeCheck={currentResult.typeCheck} fileErrors={currentResult.fileErrors} />
        </>
      )}
    </>
  );
}


function TypeCheckPanel({ typeCheck = {}, fileErrors = [] }) {
  const status = typeCheck.status || 'not_requested';
  const issues = typeCheck.issues || [];
  const statusLabel = status.replaceAll('_', ' ');

  return (
    <section className="panel type-check-panel">
      <div className="panel-heading">
        <div>
          <h2>Type safety check</h2>
          <p>mypy diagnostics are kept separate from security vulnerabilities.</p>
        </div>
        <span className={`type-check-status type-check-${status}`}>{statusLabel}</span>
      </div>

      {status === 'not_requested' && (
        <div className="type-check-empty">Type checking was not selected for this scan.</div>
      )}
      {status === 'unavailable' && (
        <div className="type-check-empty">{typeCheck.message || 'mypy is not installed. Install the project requirements to enable this check.'}</div>
      )}
      {status === 'timed_out' && (
        <div className="type-check-empty">{typeCheck.message || 'mypy exceeded its time limit.'}</div>
      )}
      {status === 'failed' && (
        <div className="type-check-empty">{typeCheck.message || 'mypy could not complete this check.'}</div>
      )}
      {status === 'skipped' && (
        <div className="type-check-empty">{typeCheck.message || 'Type checking was skipped.'}</div>
      )}
      {(status === 'completed' || status === 'partial') && (
        <>
          <div className="type-check-summary">
            <span><strong>{typeCheck.error_count || 0}</strong> errors</span>
            <span><strong>{typeCheck.warning_count || 0}</strong> warnings</span>
            <span><strong>{typeCheck.files_checked || 0}</strong> files checked</span>
            {typeCheck.files_skipped > 0 && <span><strong>{typeCheck.files_skipped}</strong> files skipped</span>}
          </div>
          {issues.length ? (
            <div className="type-issues-wrap">
              <table className="type-issues-table">
                <thead>
                  <tr><th>FILE</th><th>LINE</th><th>LEVEL</th><th>CODE</th><th>MESSAGE</th></tr>
                </thead>
                <tbody>
                  {issues.map((issue, index) => (
                    <tr key={`${issue.file_path}-${issue.line_number}-${issue.code || index}`}>
                      <td>{issue.file_path}</td>
                      <td>{issue.line_number}{issue.column ? `:${issue.column}` : ''}</td>
                      <td><span className={`type-issue-level level-${issue.severity}`}>{issue.severity}</span></td>
                      <td>{issue.code || '—'}</td>
                      <td>{issue.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="type-check-empty">No type issues were reported.</div>
          )}
          {typeCheck.message && <p className="type-check-message">{typeCheck.message}</p>}
        </>
      )}

      {fileErrors.length > 0 && (
        <div className="type-file-errors">
          <strong>Files with Python syntax errors</strong>
          {fileErrors.map((item) => (
            <span key={`${item.file_path}-${item.syntax_error?.line || 0}`}>
              {item.file_path}: line {item.syntax_error?.line || '?'} · {item.syntax_error?.message || 'Syntax error'}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}


function CodeContext({ source, lineNumber, evidence }) {
  if (!source) {
    return (
      <div className="source-not-retained">
        <span>Source preview is unavailable. Masked finding evidence is shown below.</span>
        <pre className="evidence-block">
          <code>{redactSensitiveText(evidence || 'No evidence supplied.')}</code>
        </pre>
      </div>
    );
  }

  const lines = source.split(/\r?\n/);
  const start = Math.max(1, Number(lineNumber || 1) - 2);
  const end = Math.min(lines.length, Number(lineNumber || 1) + 2);
  const visible = lines.slice(start - 1, end);

  return (
    <div className="code-context">
      {visible.map((line, index) => {
        const number = start + index;
        const isActive = number === Number(lineNumber);

        return (
          <div
            className={`code-context-line ${isActive ? 'active' : ''}`}
            key={number}
          >
            <span>{number}</span>
            <code>{line || ' '}</code>
          </div>
        );
      })}
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, note, tone }) {
  return <div className="metric-card"><div className={`metric-icon metric-${tone}`}><Icon size={18} /></div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-note">{note}</div></div>;
}

function RecentScans({ history, loading, onOpen, onNewScan }) {
  if (loading) return <div className="panel recent-panel loading-row"><LoaderCircle className="spin" size={18} /> Loading recent scans...</div>;
  if (!history.length) return <div className="panel"><EmptyState icon={History} title="No scans yet" description="Your completed analyses will appear here." action={<button className="secondary-button" onClick={onNewScan}>Start your first scan</button>} /></div>;
  return <div className="panel recent-panel"><div className="recent-table-head"><span>FILE</span><span>DATE</span><span>FINDINGS</span><span>STATUS</span><span /></div>{history.slice(0, 5).map((item) => <button className="recent-row" key={item.scan_id} onClick={() => onOpen(item.scan_id)}><div className="recent-file"><div className="file-mini-icon"><FileCode2 size={16} /></div><div><strong>{item.file_name}</strong><span>{item.scan_id.slice(0, 13)}…</span></div></div><span className="recent-date">{formatDate(item.created_at)}</span><strong className="recent-findings">{item.total_findings}</strong><span className={`table-status ${['syntax_error', 'completed_with_errors'].includes(item.status) ? 'table-status-warning' : ''}`}><i />{item.status}</span><ChevronRight size={16} className="muted-icon" /></button>)}</div>;
}

function NewScanView({
  file,
  source,
  setSource,
  inputMode,
  setInputMode,
  includeBandit,
  setIncludeBandit,
  includeMypy,
  setIncludeMypy,
  isDragging,
  setIsDragging,
  isScanning,
  fileInputRef,
  onFileInput,
  onDrop,
  onScan,
  onClearFile,
}) {
  return (
    <>
      <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> ANALYSIS ENGINE</div><h1>New analysis</h1><p>Upload a Python file, ZIP project, or paste source code to inspect it.</p></div><div className="heading-note"><LockKeyhole size={14} /> Source code is never executed</div></div>
      <div className="scan-workspace">
        <section className="panel scan-form-panel">
          <div className="panel-heading"><div><h2>Source input</h2><p>Choose how you want to provide your Python code.</p></div><span className="step-indicator">STEP 01 <b>/ 02</b></span></div>
          <div className="input-tabs"><button className={inputMode === 'file' ? 'active' : ''} onClick={() => setInputMode('file')}><UploadCloud size={16} /> Upload file</button><button className={inputMode === 'paste' ? 'active' : ''} onClick={() => setInputMode('paste')}><Code2 size={16} /> Paste code</button></div>
          {inputMode === 'file' ? (
            <>
              <div className={`drop-zone ${isDragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`} onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }} onDragLeave={() => setIsDragging(false)} onDrop={onDrop} onClick={() => fileInputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') fileInputRef.current?.click(); }}>
                <input ref={fileInputRef} type="file" accept=".py,.zip,text/x-python,application/zip" hidden onChange={onFileInput} />
                {file ? <><div className="drop-icon file-ready"><FileCode2 size={25} /></div><strong>{file.name}</strong><span>{(file.size / 1024).toFixed(1)} KB · {file.name.toLowerCase().endsWith('.zip') ? 'Archive ready to analyze' : 'Ready to analyze'}</span><button className="remove-file" type="button" onClick={(event) => { event.stopPropagation(); onClearFile(); }}><X size={14} /> Remove file</button></> : <><div className="drop-icon"><UploadCloud size={26} /></div><strong>Drop a Python file or ZIP archive here</strong><span>or <b>browse files</b> from your computer</span><small>.PY · .ZIP UP TO 10 MB · MAX 25 PYTHON FILES</small></>}
              </div>
              <div className="upload-hint"><LockKeyhole size={14} /> Files are processed locally by your Flask backend and are not stored as source code.</div>
            </>
          ) : (
            <div className="code-input-wrap"><div className="code-input-top"><span><i /> <i /> <i /></span><span>pasted_code.py</span><span>PYTHON</span></div><textarea className="code-textarea" spellCheck="false" value={source} onChange={(event) => setSource(event.target.value)} placeholder={'# Paste Python code here\n\ndef example(user_input):\n    return eval(user_input)'} /></div>
          )}
          <div className="scan-options"><div className="option-copy"><strong>Additional security scanner</strong><span>Run Bandit alongside custom AST rules.</span></div><label className="toggle-switch"><input type="checkbox" checked={includeBandit} onChange={(event) => setIncludeBandit(event.target.checked)} /><span /></label></div>
          <div className="scan-options"><div className="option-copy"><strong>Type safety check</strong><span>Run mypy and report type issues separately.</span></div><label className="toggle-switch"><input type="checkbox" checked={includeMypy} onChange={(event) => setIncludeMypy(event.target.checked)} /><span /></label></div>
          <div className="scan-form-footer"><div className="scan-privacy"><ShieldCheck size={15} /> Static analysis · No code execution</div><button className="primary-button scan-submit" onClick={onScan} disabled={isScanning}>{isScanning ? <><LoaderCircle size={17} className="spin" /> Analyzing...</> : <><Play size={16} fill="currentColor" /> Run security analysis</>}</button></div>
        </section>
        <aside className="scan-side-column">
          <div className="panel scan-process-panel"><div className="panel-heading"><div><h2>Analysis pipeline</h2><p>What happens to your code.</p></div><Activity size={18} className="muted-icon" /></div><div className="pipeline-list"><PipelineStep number="01" title="Input validation" description="File type, size and encoding checks." /><PipelineStep number="02" title="Python AST parsing" description="Build syntax tree without execution." /><PipelineStep number="03" title="Security rules" description="Inspect risky calls and code patterns." /><PipelineStep number="04" title="Bandit and optional mypy" description="Security rules and separate type diagnostics." /><PipelineStep number="05" title="Report generation" description="Normalize and save findings." last /></div></div>
          <div className="info-card"><div className="info-card-icon"><ShieldCheck size={18} /></div><div><strong>Designed to be safe</strong><p>The analyzer never imports or executes the submitted Python source. Scan history stores findings and metadata, not the original code.</p></div></div>
        </aside>
      </div>
    </>
  );
}

function PipelineStep({ number, title, description, last }) {
  return <div className={`pipeline-step ${last ? 'last' : ''}`}><div className="pipeline-number">{number}</div><div><strong>{title}</strong><span>{description}</span></div><Check size={14} className="pipeline-check" /></div>;
}

function HistoryView({ history, loading, onRefresh, onOpen }) {
  return (
    <>
      <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> AUDIT TRAIL</div><h1>Scan history</h1><p>Review previous analyses and reopen their findings or reports.</p></div><button className="secondary-button" onClick={onRefresh} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh history</button></div>
      <div className="history-summary"><div><span className="history-summary-icon"><History size={18} /></span><div><strong>{history.length}</strong><span>Saved scans</span></div></div><div><span className="history-summary-icon"><ShieldCheck size={18} /></span><div><strong>{history.filter((item) => item.status === 'completed').length}</strong><span>Completed</span></div></div><div><span className="history-summary-icon"><AlertTriangle size={18} /></span><div><strong>{history.reduce((sum, item) => sum + (item.total_findings || 0), 0)}</strong><span>Total findings</span></div></div></div>
      <section className="panel history-panel"><div className="panel-heading"><div><h2>All analyses</h2><p>Newest scans appear first.</p></div><span className="result-count">{history.length} records</span></div>
        {loading ? <div className="loading-row"><LoaderCircle size={18} className="spin" /> Loading scan history...</div> : history.length ? <div className="history-table-wrap"><table className="history-table"><thead><tr><th>FILE NAME</th><th>DATE</th><th>FINDINGS</th><th>RISK SUMMARY</th><th>STATUS</th><th /></tr></thead><tbody>{history.map((item) => <tr key={item.scan_id}><td><div className="history-file"><span><FileCode2 size={16} /></span><div><strong>{item.file_name}</strong><small>{item.scan_id.slice(0, 18)}…</small></div></div></td><td>{formatDate(item.created_at)}</td><td><strong>{item.total_findings}</strong></td><td><div className="risk-pills"><span className="risk-high">H {item.severity_counts?.HIGH || 0}</span><span className="risk-medium">M {item.severity_counts?.MEDIUM || 0}</span><span className="risk-low">L {item.severity_counts?.LOW || 0}</span></div></td><td><span className={`table-status ${['syntax_error', 'completed_with_errors'].includes(item.status) ? 'table-status-warning' : ''}`}><i />{item.status}</span></td><td><button className="table-open-button" onClick={() => onOpen(item.scan_id)}>View <ArrowRight size={14} /></button></td></tr>)}</tbody></table></div> : <EmptyState icon={History} title="No scan history" description="Run your first analysis and the result will be saved here." />}
      </section>
      <div className="history-note"><LockKeyhole size={15} /><span>Only scan metadata and findings are stored. Submitted source files are not saved in the database.</span></div>
    </>
  );
}

export default App;
