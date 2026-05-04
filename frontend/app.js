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
        bar: document.querySelector('.progress-glow'),
        percent: document.getElementById('progress-percent'),
        steps: document.getElementById('progress-steps')
    };

    const API_BASE = window.location.origin;

    // --- Drag and Drop Logic ---
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
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

        // Switch to progress UI
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

    // --- WebSocket for Progress ---
    function connectWebSocket(sessionId) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/progress/${sessionId}`;
        
        const ws = new WebSocket(wsUrl);

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.progress !== undefined) {
                updateProgress(data.progress);
            }
            if (data.detail) {
                addProgressStep(data.detail);
            }
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

        ws.onerror = (error) => {
            console.error('WebSocket Error:', error);
            // Polling fallback just in case
            setTimeout(() => checkStatusPolling(sessionId), 2000);
        };
    }
    
    async function checkStatusPolling(sessionId) {
        try {
            const res = await fetch(`${API_BASE}/api/report/${sessionId}`);
            const data = await res.json();
            if (data.status === 'complete') {
                renderReport(data.report);
            } else if (data.status === 'error') {
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
        progress.percent.textContent = `${percent}%`;
    }

    function addProgressStep(text) {
        const items = progress.steps.querySelectorAll('.step-item');
        items.forEach(item => item.classList.remove('active'));
        
        const div = document.createElement('div');
        div.className = 'step-item active';
        div.textContent = text;
        progress.steps.appendChild(div);
        progress.steps.scrollTop = progress.steps.scrollHeight;
    }

    // --- Report Rendering ---
    async function fetchReport(sessionId) {
        try {
            const response = await fetch(`${API_BASE}/api/report/${sessionId}`);
            const data = await response.json();
            
            if (data.status === 'complete') {
                renderReport(data.report);
            }
        } catch (error) {
            alert(`Failed to fetch report: ${error.message}`);
        }
    }

    function renderReport(report) {
        sections.progress.classList.remove('active');
        sections.report.classList.add('active');
        
        const container = document.getElementById('report-container');
        
        // Risk Score Category
        let scoreClass = 'good';
        if (report.risk_score >= 70) scoreClass = 'critical';
        else if (report.risk_score >= 40) scoreClass = 'medium';
        
        let html = `
            <div class="report-header">
                <div class="report-title">
                    <h2>Analysis Report: <span class="gradient-text">${report.filename}</span></h2>
                    <p>Analyzed in ${report.analysis_duration}s • ${new Date(report.timestamp).toLocaleString()}</p>
                </div>
                <div class="risk-score-badge">
                    <div class="score-value ${scoreClass}">${report.risk_score}/100</div>
                    <div class="score-label">Risk Score</div>
                </div>
            </div>
            
            <div class="report-grid">
                <div class="main-column">
                    <!-- AI Summary -->
                    <div class="report-card">
                        <h3><span class="feature-icon">🤖</span> AI Security Summary</h3>
                        <div class="ai-summary">${formatMarkdown(report.ai_summary || 'No AI summary available. (Check API keys)')}</div>
                    </div>
                    
                    <!-- Findings -->
                    <div class="report-card">
                        <h3><span class="feature-icon">⚠️</span> Security Findings (${report.findings.length})</h3>
                        <div class="findings-list">
                            ${report.findings.length === 0 ? '<p>No significant security findings detected.</p>' : ''}
                            ${report.findings.map(f => renderFinding(f)).join('')}
                        </div>
                    </div>
                </div>
                
                <div class="side-column">
                    <!-- File Info -->
                    <div class="report-card">
                        <h3><span class="feature-icon">📄</span> File Details</h3>
                        <div class="file-info-grid">
                            <span class="info-label">Type:</span> <span class="info-val">${report.file_info.file_type.toUpperCase()}</span>
                            <span class="info-label">Arch:</span> <span class="info-val">${report.file_info.architecture}</span>
                            <span class="info-label">Size:</span> <span class="info-val">${formatBytes(report.file_info.file_size)}</span>
                            <span class="info-label">Entropy:</span> <span class="info-val">${report.file_info.entropy}</span>
                            <span class="info-label">MD5:</span> <span class="info-val">${report.file_info.md5}</span>
                            <span class="info-label">SHA256:</span> <span class="info-val">${report.file_info.sha256}</span>
                        </div>
                    </div>
                    
                    <!-- Security Mitigations -->
                    ${report.security_checks.length > 0 ? `
                    <div class="report-card">
                        <h3><span class="feature-icon">🛡️</span> Mitigations</h3>
                        <div class="sec-checks-list">
                            ${report.security_checks.map(c => `
                                <div class="sec-check-item">
                                    <span class="sec-name">${c.name}</span>
                                    <span class="sec-status ${c.status}">${c.status}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- Actions -->
                    <div class="report-card" style="text-align: center;">
                        <button class="btn" onclick="window.location.reload()" style="width: 100%; margin-bottom: 1rem;">Analyze Another File</button>
                    </div>
                </div>
            </div>
        `;
        
        container.innerHTML = html;
        document.getElementById('header-status').innerHTML = '<span class="status-dot" style="background:#8b5cf6;box-shadow:0 0 10px #8b5cf6;"></span><span id="status-text">Report View</span>';
    }

    function renderFinding(f) {
        return `
            <div class="finding-item ${f.severity}">
                <div class="finding-header">
                    <div class="finding-title">${f.title}</div>
                    <div class="finding-badges">
                        ${f.cwe ? `<span class="badge category">${f.cwe}</span>` : ''}
                        <span class="badge ${f.severity}">${f.severity}</span>
                    </div>
                </div>
                <div class="finding-desc">${f.description}</div>
                ${f.location ? `<div class="finding-meta">Location: ${f.location}</div>` : ''}
                ${f.evidence ? `<div class="finding-meta" style="margin-top:0.5rem;background:rgba(0,0,0,0.2);padding:0.5rem;border-radius:4px;overflow-x:auto;"><code>${escapeHtml(f.evidence)}</code></div>` : ''}
                ${f.recommendation ? `<div class="finding-rec">💡 <strong>Fix:</strong> ${f.recommendation}</div>` : ''}
            </div>
        `;
    }

    // Utils
    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024, sizes = ['Bytes', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    function escapeHtml(unsafe) {
        return (unsafe||'').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }
    
    function formatMarkdown(text) {
        // Very basic markdown formatting for the summary
        let html = escapeHtml(text);
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
        html = html.replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1);padding:0.1rem 0.3rem;border-radius:3px;">$1</code>');
        html = html.replace(/\n\n/g, '</p><p>');
        html = html.replace(/\n/g, '<br>');
        return `<p>${html}</p>`;
    }
});
