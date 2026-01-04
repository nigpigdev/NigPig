/* NigPig Dashboard - JavaScript Application */

// State
let currentPage = 'dashboard';

// API Base URL
const API_BASE = '';

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initTabs();
    initForms();
    checkSystemStatus();
    loadResults();
});

// Navigation
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            showPage(page);
        });
    });
}

function showPage(page) {
    currentPage = page;
    
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === `page-${page}`);
    });
}

// Tabs
function initTabs() {
    document.querySelectorAll('.tabs').forEach(tabContainer => {
        tabContainer.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabId = tab.dataset.tab;
                const parent = tab.closest('.page');
                
                // Update tabs
                tabContainer.querySelectorAll('.tab').forEach(t => {
                    t.classList.toggle('active', t === tab);
                });
                
                // Update content
                parent.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.toggle('active', content.id === `tab-${tabId}`);
                });
            });
        });
    });
}

// Forms
function initForms() {
    // Quick Scan
    document.getElementById('scan-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = document.getElementById('scan-target').value;
        const modules = Array.from(document.querySelectorAll('input[name="modules"]:checked'))
            .map(cb => cb.value);
        await startScan(target, modules);
    });
    
    // Subdomain
    document.getElementById('subdomain-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('sub-domain').value;
        await runSubdomain(domain);
    });
    
    // Ports
    document.getElementById('ports-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const host = document.getElementById('port-host').value;
        await runPortScan(host);
    });
    
    // DNS
    document.getElementById('dns-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('dns-domain').value;
        await runDNS(domain);
    });
    
    // Fingerprint
    document.getElementById('fingerprint-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('fp-url').value;
        const tech = document.getElementById('fp-tech').checked;
        const waf = document.getElementById('fp-waf').checked;
        await runFingerprint(url, tech, waf);
    });
    
    // Templates
    document.getElementById('templates-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('tpl-url').value;
        const severity = Array.from(document.querySelectorAll('input[name="severity"]:checked'))
            .map(cb => cb.value);
        await runTemplates(url, severity);
    });
    
    // Secrets
    document.getElementById('secrets-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const content = document.getElementById('secret-content').value;
        await runSecrets(content);
    });
    
    // SSL
    document.getElementById('ssl-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('ssl-url').value;
        await runSSL(url);
    });
    
    // Dependencies
    document.getElementById('deps-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const path = document.getElementById('deps-path').value;
        await runDeps(path);
    });
}

// System Status
async function checkSystemStatus() {
    try {
        const res = await fetch(`${API_BASE}/api/status`);
        const data = await res.json();
        
        document.querySelector('#status-docker .status-dot')
            .classList.toggle('online', data.docker);
        document.querySelector('#status-zap .status-dot')
            .classList.toggle('online', data.zap);
    } catch (error) {
        console.error('Status check failed:', error);
    }
}

// Quick Scan
async function startScan(target, modules) {
    const progressCard = document.getElementById('scan-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressStatus = document.getElementById('progress-status');
    
    progressCard.style.display = 'block';
    progressFill.style.width = '0%';
    progressStatus.textContent = 'Starting scan...';
    
    try {
        const res = await fetch(`${API_BASE}/api/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, modules })
        });
        
        const data = await res.json();
        const scanId = data.scan_id;
        
        // Poll for updates
        const pollInterval = setInterval(async () => {
            const statusRes = await fetch(`${API_BASE}/api/scan/${scanId}`);
            const status = await statusRes.json();
            
            progressFill.style.width = `${status.progress}%`;
            progressStatus.textContent = status.current_module 
                ? `Running: ${status.current_module}...` 
                : 'Processing...';
            
            if (status.status === 'completed' || status.status === 'error') {
                clearInterval(pollInterval);
                progressFill.style.width = '100%';
                progressStatus.textContent = status.status === 'completed' 
                    ? '✅ Scan complete!' 
                    : `❌ ${status.error}`;
                
                loadResults();
                updateStats();
            }
        }, 1000);
        
    } catch (error) {
        progressStatus.textContent = `❌ Error: ${error.message}`;
    }
}

// Subdomain Enumeration
async function runSubdomain(domain) {
    const resultsDiv = document.getElementById('subdomain-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        const res = await fetch(`${API_BASE}/api/recon/subdomain`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        
        const data = await res.json();
        
        resultsDiv.innerHTML = `
            <h3>Found ${data.count} subdomains</h3>
            ${data.subdomains.map(s => `
                <div class="result-item info">
                    <div class="result-title">${s.subdomain}</div>
                    <div class="result-meta">Source: ${s.source} | Resolved: ${s.resolved ? '✓' : '✗'}</div>
                </div>
            `).join('')}
        `;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// Port Scan
async function runPortScan(host) {
    const resultsDiv = document.getElementById('ports-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        const res = await fetch(`${API_BASE}/api/recon/ports`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host })
        });
        
        const data = await res.json();
        
        resultsDiv.innerHTML = `
            <h3>Found ${data.count} open ports</h3>
            ${data.ports.map(p => `
                <div class="result-item info">
                    <div class="result-title">Port ${p.port} (${p.service})</div>
                    <div class="result-meta">${p.banner || 'No banner'}</div>
                </div>
            `).join('')}
        `;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// DNS Lookup
async function runDNS(domain) {
    const resultsDiv = document.getElementById('dns-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        const res = await fetch(`${API_BASE}/api/recon/dns`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        
        const data = await res.json();
        
        let html = '<h3>DNS Records</h3>';
        for (const [type, records] of Object.entries(data.records)) {
            if (records.length > 0) {
                html += `<h4>${type}</h4>`;
                records.forEach(r => {
                    html += `<div class="result-item info"><div class="result-title">${r.value}</div><div class="result-meta">TTL: ${r.ttl}</div></div>`;
                });
            }
        }
        resultsDiv.innerHTML = html;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// Fingerprint
async function runFingerprint(url, tech, waf) {
    const resultsDiv = document.getElementById('fingerprint-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    let html = '';
    
    try {
        if (tech) {
            const res = await fetch(`${API_BASE}/api/fingerprint/tech`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await res.json();
            
            html += `<h3>Technologies (${data.count})</h3><div class="tech-grid">`;
            data.technologies.forEach(t => {
                html += `<div class="tech-card"><div class="tech-name">${t.name}</div><div class="tech-category">${t.category}</div></div>`;
            });
            html += '</div>';
        }
        
        if (waf) {
            const res = await fetch(`${API_BASE}/api/fingerprint/waf`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await res.json();
            
            html += `<h3>WAF Detection</h3>`;
            if (data.detected) {
                data.wafs.forEach(w => {
                    html += `<div class="result-item medium"><div class="result-title">${w.name}</div><div class="result-meta">Confidence: ${w.confidence}%</div></div>`;
                });
            } else {
                html += '<div class="result-item info">No WAF detected</div>';
            }
        }
        
        resultsDiv.innerHTML = html;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// Templates
async function runTemplates(url, severity) {
    const resultsDiv = document.getElementById('templates-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        const res = await fetch(`${API_BASE}/api/templates/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, severity })
        });
        
        const data = await res.json();
        
        let html = `<h3>Findings (${data.findings_count})</h3>`;
        
        if (data.findings.length === 0) {
            html += '<div class="result-item info">No vulnerabilities found</div>';
        } else {
            data.findings.forEach(f => {
                html += `
                    <div class="result-item ${f.severity}">
                        <div class="result-title">
                            <span class="severity-badge ${f.severity}">${f.severity}</span>
                            ${f.name}
                        </div>
                        <div class="result-meta">${f.url}</div>
                    </div>
                `;
            });
        }
        
        resultsDiv.innerHTML = html;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// Secrets
async function runSecrets(content) {
    const resultsDiv = document.getElementById('secrets-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        const res = await fetch(`${API_BASE}/api/secrets/scan/content`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content, source: 'user-input' })
        });
        
        const data = await res.json();
        
        let html = `<h3>Found ${data.findings_count} secrets</h3>`;
        
        if (data.findings.length === 0) {
            html += '<div class="result-item info">No secrets detected</div>';
        } else {
            data.findings.forEach(f => {
                html += `
                    <div class="result-item ${f.severity}">
                        <div class="result-title">
                            <span class="severity-badge ${f.severity}">${f.severity}</span>
                            ${f.type}
                        </div>
                        <div class="result-meta">Line ${f.line}: ${f.context}</div>
                    </div>
                `;
            });
        }
        
        resultsDiv.innerHTML = html;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// SSL Analysis
async function runSSL(url) {
    const resultsDiv = document.getElementById('ssl-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        const res = await fetch(`${API_BASE}/api/audit/ssl`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        const data = await res.json();
        
        let html = `
            <div class="ssl-grade ${data.grade}">${data.grade}</div>
            <div class="result-item info">
                <div class="result-title">Protocol: ${data.protocol}</div>
                <div class="result-meta">Cipher: ${data.cipher} (${data.cipher_bits} bits)</div>
            </div>
        `;
        
        if (data.certificate) {
            html += `
                <div class="result-item ${data.certificate.is_expired ? 'critical' : 'info'}">
                    <div class="result-title">Certificate</div>
                    <div class="result-meta">
                        Expires: ${data.certificate.not_after}<br>
                        Days until expiry: ${data.certificate.days_until_expiry}
                    </div>
                </div>
            `;
        }
        
        html += '<h4>Protocol Support</h4>';
        html += `<div class="result-item ${data.supports.tls_1_0 ? 'high' : 'info'}">TLS 1.0: ${data.supports.tls_1_0 ? '⚠️ Enabled' : '✓ Disabled'}</div>`;
        html += `<div class="result-item ${data.supports.tls_1_1 ? 'medium' : 'info'}">TLS 1.1: ${data.supports.tls_1_1 ? '⚠️ Enabled' : '✓ Disabled'}</div>`;
        html += `<div class="result-item info">TLS 1.2: ${data.supports.tls_1_2 ? '✓ Enabled' : '✗ Disabled'}</div>`;
        html += `<div class="result-item info">TLS 1.3: ${data.supports.tls_1_3 ? '✓ Enabled' : '✗ Disabled'}</div>`;
        
        if (data.issues.length > 0) {
            html += '<h4>Issues</h4>';
            data.issues.forEach(issue => {
                html += `<div class="result-item medium">${issue}</div>`;
            });
        }
        
        resultsDiv.innerHTML = html;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// Dependency Scan
async function runDeps(path) {
    const resultsDiv = document.getElementById('deps-results');
    resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        const res = await fetch(`${API_BASE}/api/audit/deps`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        
        const data = await res.json();
        
        if (data.error) {
            resultsDiv.innerHTML = `<div class="result-item high">${data.error}</div>`;
            return;
        }
        
        let html = `<h3>Found ${data.total_vulnerabilities} vulnerabilities</h3>`;
        
        for (const [lang, vulns] of Object.entries(data.by_language)) {
            html += `<h4>${lang.toUpperCase()}</h4>`;
            vulns.forEach(v => {
                html += `
                    <div class="result-item ${v.severity}">
                        <div class="result-title">
                            <span class="severity-badge ${v.severity}">${v.severity}</span>
                            ${v.name} (${v.version})
                        </div>
                        <div class="result-meta">${v.description}</div>
                    </div>
                `;
            });
        }
        
        resultsDiv.innerHTML = html;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="result-item high">Error: ${error.message}</div>`;
    }
}

// Load Results
async function loadResults() {
    try {
        const res = await fetch(`${API_BASE}/api/results`);
        const data = await res.json();
        
        const resultsList = document.getElementById('results-list');
        
        if (data.length === 0) {
            resultsList.innerHTML = '<p class="no-results">No scan results yet. Start a scan to see results here.</p>';
            return;
        }
        
        let html = '';
        data.forEach(scan => {
            const vulnCount = (scan.results.vulnerabilities || []).length;
            html += `
                <div class="result-item ${vulnCount > 0 ? 'high' : 'info'}">
                    <div class="result-title">${scan.target}</div>
                    <div class="result-meta">
                        ID: ${scan.id} | 
                        Started: ${scan.started_at} | 
                        Status: ${scan.status} |
                        Vulnerabilities: ${vulnCount}
                    </div>
                </div>
            `;
        });
        
        resultsList.innerHTML = html;
    } catch (error) {
        console.error('Failed to load results:', error);
    }
}

// Update Stats
async function updateStats() {
    try {
        const res = await fetch(`${API_BASE}/api/results`);
        const data = await res.json();
        
        document.getElementById('stat-scans').textContent = data.length;
        
        let totalVulns = 0;
        let totalSubs = 0;
        let totalTechs = 0;
        
        data.forEach(scan => {
            totalVulns += (scan.results.vulnerabilities || []).length;
            totalSubs += (scan.results.subdomains || []).length;
            totalTechs += (scan.results.technologies || []).length;
        });
        
        document.getElementById('stat-vulns').textContent = totalVulns;
        document.getElementById('stat-subs').textContent = totalSubs;
        document.getElementById('stat-techs').textContent = totalTechs;
    } catch (error) {
        console.error('Failed to update stats:', error);
    }
}

// Make showPage globally accessible
window.showPage = showPage;
