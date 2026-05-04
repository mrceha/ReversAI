document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const browseTrigger = document.getElementById('browse-trigger');
    
    const sections = {
        upload: document.getElementById('upload-section'),
        progress: document.getElementById('progress-section'),
        report: document.getElementById('report-section')
    };

    const progress = {
        filename: document.getElementById('progress-filename'),
        bar: document.getElementById('progress-bar'),
        steps: document.getElementById('progress-steps')
    };

    const API_BASE = window.location.origin;

    // Track mouse for card glow effect
    document.querySelectorAll('.cap-card').forEach(card => {
        card.addEventListener('mousemove', e => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            card.style.setProperty('--mouse-x', `${x}px`);
            card.style.setProperty('--mouse-y', `${y}px`);
        });
    });

    // --- Drag and Drop Logic ---
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('drag-active');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('drag-active');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('drag-active');
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    browseTrigger.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });
    
    dropzone.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    // --- File Handling & API calls ---
    async function handleFile(file) {
        if (file.size > 100 * 1024 * 1024) {
            alert('File too large. Maximum size is 100MB.');
            return;
        }

        sections.upload.classList.remove('active');
        sections.progress.classList.add('active');
        progress.filename.textContent = file.name;
        progress.steps.innerHTML = '';
        updateProgress(0);

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`${API_BASE}/api/analyze`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Upload failed');
            }

            const data = await response.json();
            connectWebSocket(data.session_id);

        } catch (error) {
            alert(`Error: ${error.message}`);
            sections.progress.classList.remove('active');
            sections.upload.classList.add('active');
        }
    }

    // --- WebSocket ---
    function connectWebSocket(sessionId) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/progress/${sessionId}`;
        const ws = new WebSocket(wsUrl);

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.progress !== undefined) updateProgress(data.progress);
            if (data.detail) addProgressStep(data.detail);
            
            if (data.status === 'complete' || data.progress === 100) {
                ws.close();
                fetchReport(sessionId);
            } else if (data.status === 'error' || data.progress === -1) {
                ws.close();
                alert(`Analysis failed: ${data.detail}`);
                sections.progress.classList.remove('active');
                sections.upload.classList.add('active');
            }
        };

        ws.onerror = () => setTimeout(() => checkStatusPolling(sessionId), 2000);
    }
    
    async function checkStatusPolling(sessionId) {
        try {
            const res = await fetch(`${API_BASE}/api/report/${sessionId}`);
            const data = await res.json();
            if (data.status === 'complete') renderReport(data.report);
            else if (data.status === 'error') {
                alert(`Analysis failed: ${data.error}`);
                sections.progress.classList.remove('active');
                sections.upload.classList.add('active');
            } else {
                if (data.progress) {
                    updateProgress(data.progress.progress);
                    addProgressStep(data.progress.detail);
                }
                setTimeout(() => checkStatusPolling(sessionId), 2000);
            }
        } catch(e) {}
    }

    function updateProgress(percent) {
        progress.bar.style.width = `${percent}%`;
    }

    function addProgressStep(text) {
        const items = progress.steps.querySelectorAll('.log-line');
        items.forEach(item => item.classList.remove('active'));
        
        const div = document.createElement('div');
        div.className = 'log-line active';
        
        const now = new Date();
        const timeStr = `${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`;
        
        div.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="log-msg">${text}</span>`;
        progress.steps.appendChild(div);
        progress.steps.scrollTop = progress.steps.scrollHeight;
    }

    // --- Report Rendering ---
    async function fetchReport(sessionId) {
        try {
            const response = await fetch(`${API_BASE}/api/report/${sessionId}`);
            const data = await response.json();
            if (data.status === 'complete') renderReport(data.report);
        } catch (error) {
            alert(`Failed to fetch report: ${error.message}`);
        }
    }

    function renderReport(report) {
        sections.progress.classList.remove('active');
        sections.report.classList.add('active');
        
        const container = document.getElementById('report-container');
        
        let scoreClass = 'good';
        if (report.risk_score >= 70) scoreClass = 'critical';
        else if (report.risk_score >= 40) scoreClass = 'medium';
        else if (report.risk_score >= 20) scoreClass = 'high';
        
        let html = `
            <div class="report-layout">
                <div class="sidebar">
                    <div class="data-card risk-display">
                        <div class="data-card-header"><i>⚡</i> THREAT LEVEL</div>
                        <div class="risk-number ${scoreClass}">${report.risk_score}</div>
                        <div class="risk-label">Overall Risk Score</div>
                    </div>
                    
                    <div class="data-card">
                        <div class="data-card-header"><i>📄</i> FILE METADATA</div>
                        <div class="meta-grid">
                            <span class="meta-key">TYPE</span> <span class="meta-val">${report.file_info.file_type.toUpperCase()}</span>
                            <span class="meta-key">ARCH</span> <span class="meta-val">${report.file_info.architecture}</span>
                            <span class="meta-key">SIZE</span> <span class="meta-val">${formatBytes(report.file_info.file_size)}</span>
                            <span class="meta-key">ENTROPY</span> <span class="meta-val">${report.file_info.entropy}</span>
                            <span class="meta-key">MD5</span> <span class="meta-val">${report.file_info.md5}</span>
                            <span class="meta-key">SHA256</span> <span class="meta-val">${report.file_info.sha256}</span>
                        </div>
                    </div>
                    
                    ${report.security_checks.length > 0 ? `
                    <div class="data-card">
                        <div class="data-card-header"><i>🛡️</i> SECURITY MITIGATIONS</div>
                        <div class="mitigation-list">
                            ${report.security_checks.map(c => {
                                const isGood = c.status === 'enabled' || c.status === 'enforced';
                                return `
                                <div class="mitigation-item ${isGood ? 'pass' : 'fail'}">
                                    <span class="mitigation-name">${c.name}</span>
                                    <span class="mitigation-status ${isGood ? 'status-enabled' : 'status-disabled'}">${c.status}</span>
                                </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
                
                <div class="report-main">
                    <div class="report-header-main">
                        <div>
                            <h2 class="report-title-lg">${report.filename}</h2>
                            <p style="color: var(--text-muted); font-family: var(--font-mono); font-size: 0.85rem; margin-top: 0.5rem;">
                                Completed in ${report.analysis_duration}s • ${new Date(report.timestamp).toLocaleString()}
                            </p>
                        </div>
                        <div class="report-actions">
                            <button onclick="window.location.reload()">Scan Another Target</button>
                        </div>
                    </div>
                    
                    <div class="ai-briefing">
                        <div class="ai-content">${formatMarkdown(report.ai_summary || 'No AI summary available. Supply an API key in .env.')}</div>
                    </div>
                    
                    <div class="findings-container">
                        ${report.findings.length === 0 ? '<div class="empty-findings">Target appears clean. No significant vulnerabilities detected.</div>' : ''}
                        ${report.findings.map(f => renderFinding(f)).join('')}
                    </div>
                </div>
            </div>
        `;
        
        container.innerHTML = html;
        document.getElementById('header-status').innerHTML = '<div class="status-indicator" style="background:var(--accent-purple);box-shadow:0 0 10px var(--accent-purple);"></div><span id="status-text">REPORT GENERATED</span>';
    }

    function renderFinding(f) {
        return `
            <div class="finding-card ${f.severity}">
                <div class="finding-severity-bar"></div>
                <div class="finding-body">
                    <div class="finding-head">
                        <div class="finding-title">${f.title}</div>
                        <div class="badge-group">
                            ${f.cwe ? `<span class="badge-tag cat">${f.cwe}</span>` : ''}
                            <span class="badge-tag sev">${f.severity}</span>
                        </div>
                    </div>
                    <div class="finding-desc">${f.description}</div>
                    
                    ${f.location || f.evidence ? `
                    <div class="finding-details">
                        ${f.location ? `<div class="detail-row"><span class="detail-label">Location:</span> <span class="detail-val">${f.location}</span></div>` : ''}
                        ${f.evidence ? `<div class="detail-row"><span class="detail-label">Evidence:</span> <span class="detail-val"><code>${escapeHtml(f.evidence)}</code></span></div>` : ''}
                    </div>
                    ` : ''}
                    
                    ${f.recommendation ? `
                    <div class="finding-fix">
                        <span class="fix-icon">💡</span>
                        <span class="fix-text">${f.recommendation}</span>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    // Utils
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    function escapeHtml(unsafe) {
        return (unsafe||'').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }
    
    function formatMarkdown(text) {
        let html = escapeHtml(text);
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
        html = html.replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1);padding:0.1rem 0.3rem;border-radius:4px;color:var(--accent-cyan);font-family:var(--font-mono);">$1</code>');
        html = html.replace(/\n\n/g, '</p><p>');
        html = html.replace(/\n/g, '<br>');
        return `<p>${html}</p>`;
    }
});
