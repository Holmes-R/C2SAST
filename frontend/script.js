const API_BASE = "/api";
let state = {
    username: '',
    token: localStorage.getItem('c2sast_token') || '',
    currentScan: null
};

// DOM Elements
const views = {
    auth: document.getElementById('auth-view'),
    scanner: document.getElementById('scanner-view'),
    report: document.getElementById('report-view')
};

const logoutBtn = document.getElementById('logout-btn');

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initDragAndDrop();
    
    if (state.token) {
        showView('scanner-view');
    }
});

// Navigation
function showView(viewId) {
    Object.values(views).forEach(v => {
        v.classList.add('hidden');
        v.classList.remove('active');
    });
    
    const target = document.getElementById(viewId);
    target.classList.remove('hidden');
    target.classList.add('active');
    
    if (viewId === 'auth-view') {
        logoutBtn.classList.add('hidden');
    } else {
        logoutBtn.classList.remove('hidden');
    }
}

// UI Tabs
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const formPanels = document.querySelectorAll('.form-panel');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            formPanels.forEach(f => f.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(btn.dataset.target).classList.add('active');
        });
    });
}

// Toasts
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'info';
    if (type === 'success') icon = 'check_circle';
    if (type === 'error') icon = 'error';
    
    toast.innerHTML = `<span class="material-icons-round">${icon}</span> ${message}`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Authentication
async function handleAuth(action) {
    const prefix = action === 'login' ? 'l' : 's';
    const username = document.getElementById(`${prefix}-user`).value.trim();
    const password = document.getElementById(`${prefix}-pass`).value.trim();
    
    if (!username || !password) {
        showToast('Please fill all fields', 'error');
        return;
    }
    
    try {
        // Since backend only has /api/register, we use it for both for demo purposes, 
        // or just mock login if user exists.
        if (action === 'login') {
            // Mock login since app.py lacks /api/login
            state.token = 'token-' + username;
            state.username = username;
            localStorage.setItem('c2sast_token', state.token);
            showToast('Login successful!', 'success');
            showView('scanner-view');
            return;
        }

        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok || response.status === 201) {
            state.token = data.token || 'token-' + username;
            state.username = username;
            localStorage.setItem('c2sast_token', state.token);
            showToast('Account created successfully!', 'success');
            showView('scanner-view');
        } else {
            showToast(data.message || data.error || 'Authentication failed', 'error');
        }
    } catch (err) {
        showToast('Could not connect to server', 'error');
        console.error(err);
    }
}

logoutBtn.addEventListener('click', () => {
    state.token = '';
    state.username = '';
    localStorage.removeItem('c2sast_token');
    showView('auth-view');
});

// Drag and Drop
function initDragAndDrop() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });
    
    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    }, false);
    
    fileInput.addEventListener('change', function() {
        handleFiles(this.files);
    });
}

async function handleFiles(files) {
    if (files.length === 0) return;
    const file = files[0];
    
    // Basic validation
    const validExts = ['.c', '.cpp', '.h', '.hpp', '.cc'];
    const isValid = validExts.some(ext => file.name.toLowerCase().endsWith(ext));
    if (!isValid) {
        showToast('Unsupported file type. Please upload C/C++ files.', 'error');
        return;
    }
    
    uploadFile(file);
}

async function uploadFile(file) {
    const dropZone = document.getElementById('drop-zone');
    const progress = document.getElementById('upload-progress');
    
    dropZone.classList.add('hidden');
    progress.classList.remove('hidden');
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${state.token}`
            },
            body: formData
        });
        
        if (response.ok) {
            const result = await response.json();
            state.currentScan = result;
            renderReport(result);
        } else {
            const error = await response.json();
            showToast(error.error || 'Analysis failed', 'error');
            resetScanner();
        }
    } catch (err) {
        showToast('Connection error during upload', 'error');
        resetScanner();
        console.error(err);
    }
}

function resetScanner() {
    document.getElementById('drop-zone').classList.remove('hidden');
    document.getElementById('upload-progress').classList.add('hidden');
    document.getElementById('file-input').value = '';
}

// Report Rendering
function renderReport(result) {
    resetScanner();
    showView('report-view');
    
    const vulns = result.vulnerabilities || [];
    document.getElementById('report-filename').textContent = result.filename || 'Unknown File';
    document.getElementById('report-count').textContent = `— ${vulns.length} vulnerabilities`;
    
    const noVulnState = document.getElementById('no-vuln-state');
    const statsGrid = document.getElementById('vuln-stats');
    const detailsContainer = document.getElementById('vuln-details-container');
    const vulnList = document.getElementById('vuln-list');
    
    if (vulns.length === 0) {
        noVulnState.classList.remove('hidden');
        statsGrid.classList.add('hidden');
        detailsContainer.classList.add('hidden');
        return;
    }
    
    noVulnState.classList.add('hidden');
    statsGrid.classList.remove('hidden');
    detailsContainer.classList.remove('hidden');
    
    // Calculate stats
    let h = 0, m = 0, l = 0;
    vulns.forEach(v => {
        if (v.severity === 'High') h++;
        else if (v.severity === 'Medium') m++;
        else l++;
    });
    
    document.getElementById('stat-high').textContent = h;
    document.getElementById('stat-medium').textContent = m;
    document.getElementById('stat-low').textContent = l;
    
    // Render list
    vulnList.innerHTML = '';
    vulns.forEach((v, index) => {
        const sevClass = v.severity === 'High' ? 'badge-high' : (v.severity === 'Medium' ? 'badge-medium' : 'badge-low');
        
        const card = document.createElement('div');
        card.className = 'glass-card vuln-card';
        
        card.innerHTML = `
            <div class="vuln-header" onclick="toggleVuln(${index})">
                <span class="badge ${sevClass}">${v.severity || 'Low'}</span>
                <span class="vuln-title">${v.name || 'Unknown Vulnerability'}</span>
                <span class="vuln-cwe">${v.cwe || ''}</span>
                <span class="vuln-line">Line ${v.line || '?'}</span>
                <span class="material-icons-round text-muted" id="icon-${index}">expand_more</span>
            </div>
            
            ${v.snippet ? `<div class="vuln-snippet">${escapeHtml(v.snippet)}</div>` : ''}
            
            <div class="vuln-expandable" id="details-${index}">
                <div class="vuln-section-title">Why dangerous?</div>
                <div class="vuln-text">${formatMarkdown(v.explanation || 'No explanation provided.')}</div>
                
                <div class="vuln-section-title mt-4">Mitigation</div>
                <div class="vuln-text text-mitigation">${formatMarkdown(v.mitigation || 'No mitigation provided.')}</div>
                
                ${v.secure_code ? `
                <div class="vuln-section-title mt-4">Secure Code Example</div>
                <div class="vuln-snippet secure-code-block">${escapeHtml(v.secure_code)}</div>
                ` : ''}
            </div>
        `;
        
        vulnList.appendChild(card);
    });
}

window.toggleVuln = function(index) {
    const details = document.getElementById(`details-${index}`);
    const icon = document.getElementById(`icon-${index}`);
    
    if (details.classList.contains('open')) {
        details.classList.remove('open');
        icon.textContent = 'expand_more';
    } else {
        details.classList.add('open');
        icon.textContent = 'expand_less';
    }
};

window.downloadPDF = function() {
    showToast('PDF Export started...', 'info');
    setTimeout(() => {
        showToast('PDF Export is mocked in this demo (Backend lacks /api/export-pdf).', 'success');
    }, 1500);
};

// Utilities
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function formatMarkdown(text) {
    // Very basic markdown parsing for bold and code
    if (!text) return '';
    let html = escapeHtml(text);
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1);padding:2px 4px;border-radius:4px;">$1</code>');
    return html;
}
