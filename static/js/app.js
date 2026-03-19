// ==================== AUTHENTICATION ====================
let sessionToken = localStorage.getItem('sessionToken');
let currentUsername = localStorage.getItem('username');

// Check authentication on page load
function checkAuth() {
    if (sessionToken && currentUsername) {
        // Show user greeting
        document.getElementById('userGreeting').classList.remove('hidden');
        document.getElementById('usernameDisplay').textContent = currentUsername;
        document.getElementById('logoutBtn').classList.remove('hidden');
        document.getElementById('loginBtn').classList.add('hidden');
    } else {
        // Redirect to login
        window.location.href = '/login';
    }
}

// Handle authentication errors
function handleAuthError() {
    localStorage.removeItem('sessionToken');
    localStorage.removeItem('username');
    window.location.href = '/login';
}

// Logout function
function logout() {
    fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
            'Authorization': sessionToken
        }
    }).finally(() => {
        localStorage.removeItem('sessionToken');
        localStorage.removeItem('username');
        window.location.href = '/login';
    });
}

// ==================== STATE MANAGEMENT ====================
let currentScanId = null;
let pollInterval = null;

// ==================== API BASE ====================
const API_BASE = window.location.origin;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication first
    checkAuth();
    
    // Set up logout button
    document.getElementById('logoutBtn')?.addEventListener('click', logout);
    
    // Set up login button
    document.getElementById('loginBtn')?.addEventListener('click', function() {
        window.location.href = '/login';
    });
    
    // Load recent scans
    loadRecentScans();
    
    // Set up form handler
    document.getElementById('scanForm').addEventListener('submit', handleScanSubmit);
    
    // Set up new scan button
    document.getElementById('newScanBtn')?.addEventListener('click', resetToNewScan);
    
    // Set up download report button
    document.getElementById('downloadReportBtn')?.addEventListener('click', downloadReport);
});

// ==================== SCAN SUBMISSION ====================
async function handleScanSubmit(event) {
    event.preventDefault();
    
    const urlInput = document.getElementById('targetUrl');
    let targetUrl = urlInput.value.trim();
    
    if (!targetUrl) {
        showError('Please enter a valid URL');
        return;
    }
    
    // Auto-prepend https:// if no protocol is specified
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = 'https://' + targetUrl;
        urlInput.value = targetUrl; // Update the input field to show the full URL
    }
    
    // Disable form
    const scanButton = document.getElementById('scanButton');
    scanButton.disabled = true;
    const btnText = document.querySelector('.btn-text');
    const btnLoader = document.querySelector('.btn-loader');
    btnText.style.display = 'none';
    btnLoader.classList.add('active');
    
    try {
        // Get max pages from input
        const maxPages = parseInt(document.getElementById('maxPages').value) || 10;
        
        // Start scan
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': sessionToken
            },
            body: JSON.stringify({ 
                url: targetUrl,
                max_pages: maxPages
            })
        });
        
        if (response.status === 401) {
            handleAuthError();
            return;
        }
        
        if (!response.ok) {
            throw new Error('Failed to start scan');
        }
        
        const data = await response.json();
        currentScanId = data.scan_id;
        
        // Show progress section
        const progressSection = document.getElementById('progressSection');
        const resultsSection = document.getElementById('resultsSection');
        progressSection.classList.add('active');
        resultsSection.classList.remove('active');
        document.getElementById('targetUrlDisplay').textContent = `Scanning: ${targetUrl}`;
        
        // Scroll to progress
        progressSection.scrollIntoView({ behavior: 'smooth' });
        
        // Start polling for status
        startStatusPolling();
        
    } catch (error) {
        console.error('Error starting scan:', error);
        showError('Failed to start scan. Please try again.');
        
        // Re-enable form
        scanButton.disabled = false;
        document.querySelector('.btn-text').style.display = 'inline';
        document.querySelector('.btn-loader').style.display = 'none';
    }
}

// ==================== STATUS POLLING ====================
function startStatusPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
    }
    
    pollInterval = setInterval(checkScanStatus, 1000);
    checkScanStatus();
}

async function checkScanStatus() {
    if (!currentScanId) return;
    
    try {
        const response = await fetch(`${API_BASE}/api/scan/${currentScanId}/status`, {
            headers: {
                'Authorization': sessionToken
            }
        });
        
        if (response.status === 401) {
            handleAuthError();
            return;
        }
        
        if (!response.ok) {
            throw new Error('Failed to check scan status');
        }
        
        const status = await response.json();
        
        // Update progress
        document.getElementById('progressMessage').textContent = status.message;
        document.getElementById('progressPercent').textContent = `${status.progress}%`;
        document.getElementById('progressFill').style.width = `${status.progress}%`;
        
        // Check if completed
        if (status.status === 'completed') {
            clearInterval(pollInterval);
            await loadScanResults();
        } else if (status.status === 'failed') {
            clearInterval(pollInterval);
            showError(status.message);
            resetForm();
        }
        
    } catch (error) {
        console.error('Error checking scan status:', error);
    }
}

// ==================== LOAD RESULTS ====================
async function loadScanResults() {
    if (!currentScanId) return;
    
    try {
        const response = await fetch(`${API_BASE}/api/scan/${currentScanId}/results`, {
            headers: {
                'Authorization': sessionToken
            }
        });
        
        if (response.status === 401) {
            handleAuthError();
            return;
        }
        
        if (!response.ok) {
            throw new Error('Failed to load scan results');
        }
        
        const results = await response.json();
        displayResults(results);
        
        // Hide progress, show results
        const progressSection = document.getElementById('progressSection');
        const resultsSection = document.getElementById('resultsSection');
        progressSection.classList.remove('active');
        resultsSection.classList.add('active');
        
        // Scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth' });
        
        // Reload recent scans
        loadRecentScans();
        
    } catch (error) {
        console.error('Error loading results:', error);
        showError('Failed to load scan results');
    }
}

// ==================== DISPLAY RESULTS ====================
function displayResults(results) {
    // Set results header info
    document.getElementById('resultsUrl').textContent = results.target_url;
    document.getElementById('scanTime').textContent = formatDateTime(results.scan_time);
    document.getElementById('pagesScanned').textContent = results.pages_scanned;
    document.getElementById('riskScore').textContent = results.risk_score;
    document.getElementById('riskLevel').textContent = results.risk_level;
    
    // Findings Summary
    document.getElementById('highCount').textContent = results.findings_summary.HIGH;
    document.getElementById('mediumCount').textContent = results.findings_summary.MEDIUM;
    document.getElementById('lowCount').textContent = results.findings_summary.LOW;
    document.getElementById('infoCount').textContent = results.findings_summary.INFO;
    
    // Category Grid
    const categoryGrid = document.getElementById('categoryGrid');
    categoryGrid.innerHTML = '';
    
    const categoryOrder = [
        'Transport Security',
        'Security Headers',
        'Session / Cookies',
        'Cryptography / TLS',
        'Input / Forms',
        'Resource Security',
        'Client-side Exposure',
        'Information Disclosure',
        'Availability / Performance',
        'Discovery / Hygiene'
    ];
    
    categoryOrder.forEach(category => {
        const count = results.category_summary[category] || 0;
        const categoryBox = document.createElement('div');
        categoryBox.className = 'category-box';
        categoryBox.innerHTML = `
            <h3>${escapeHtml(category)}</h3>
            <div class="count">${count}</div>
        `;
        categoryGrid.appendChild(categoryBox);
    });
    
    // Findings Table
    const tableBody = document.getElementById('findingsTableBody');
    tableBody.innerHTML = '';
    
    if (results.findings.length === 0) {
        tableBody.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted); grid-column: 1 / -1;">No security issues found.</div>';
    } else {
        results.findings.forEach(finding => {
            const row = document.createElement('div');
            row.className = 'finding-row';
            
            row.innerHTML = `
                <div class="severity ${finding.severity}">${finding.severity}</div>
                <div class="category">${escapeHtml(finding.category)}</div>
                <div class="description">${escapeHtml(finding.title)}</div>
                <div class="url">${escapeHtml(finding.url)}</div>
            `;
            
            tableBody.appendChild(row);
        });
    }
}

// ==================== RECENT SCANS ====================
async function loadRecentScans() {
    try {
        const response = await fetch(`${API_BASE}/api/scans`, {
            headers: {
                'Authorization': sessionToken
            }
        });
        
        if (response.status === 401) {
            handleAuthError();
            return;
        }
        
        if (!response.ok) {
            throw new Error('Failed to load recent scans');
        }
        
        const scans = await response.json();
        displayRecentScans(scans);
        
    } catch (error) {
        console.error('Error loading recent scans:', error);
    }
}

function displayRecentScans(scans) {
    const scansList = document.getElementById('recentScansList');
    scansList.innerHTML = '';
    
    if (scans.length === 0) {
        scansList.innerHTML = '<p class="empty-state">No recent scans. Start a scan to see results here.</p>';
        return;
    }
    
    scans.forEach(scan => {
        const scanCard = document.createElement('div');
        scanCard.className = 'scan-card';
        
        let metricsHtml = '';
        if (scan.status === 'completed') {
            metricsHtml = `
                <div class="scan-metrics">
                    <div class="scan-metric">
                        <span>Risk Score:</span>
                        <span class="metric-value">${scan.risk_score}</span>
                    </div>
                    <div class="scan-metric">
                        <span>Risk Level:</span>
                        <span class="metric-value">${scan.risk_level}</span>
                    </div>
                    <div class="scan-metric">
                        <span>Findings:</span>
                        <span class="metric-value">${scan.findings_count}</span>
                    </div>
                    <div class="scan-metric">
                        <span>Scanned:</span>
                        <span class="metric-value">${formatDate(scan.scan_time)}</span>
                    </div>
                </div>
            `;
        }
        
        scanCard.innerHTML = `
            <div class="scan-card-header">
                <div class="scan-url">${escapeHtml(scan.target_url || 'Scanning...')}</div>
                <span class="scan-status ${scan.status}">${scan.status}</span>
            </div>
            ${metricsHtml}
        `;
        
        if (scan.status === 'completed') {
            scanCard.addEventListener('click', () => {
                currentScanId = scan.scan_id;
                loadScanResults();
            });
        }
        
        scansList.appendChild(scanCard);
    });
}

// ==================== DOWNLOAD REPORT ====================
async function downloadReport() {
    if (!currentScanId) return;
    
    try {
        const response = await fetch(`${API_BASE}/api/scan/${currentScanId}/report`, {
            headers: {
                'Authorization': sessionToken
            }
        });
        
        if (response.status === 401) {
            handleAuthError();
            return;
        }
        
        if (!response.ok) {
            throw new Error('Failed to download report');
        }
        
        // Get the HTML content
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${currentScanId}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
    } catch (error) {
        console.error('Error downloading report:', error);
        showError('Failed to download report');
    }
}

// ==================== UTILITY FUNCTIONS ====================
function resetToNewScan() {
    resetForm();
    const resultsSection = document.getElementById('resultsSection');
    const progressSection = document.getElementById('progressSection');
    resultsSection.classList.remove('active');
    progressSection.classList.remove('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function resetForm() {
    const scanButton = document.getElementById('scanButton');
    scanButton.disabled = false;
    const btnText = document.querySelector('.btn-text');
    const btnLoader = document.querySelector('.btn-loader');
    btnText.style.display = 'inline';
    btnLoader.classList.remove('active');
    document.getElementById('targetUrl').value = '';
    currentScanId = null;
}

function showError(message) {
    alert(message); // Replace with better notification system
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (seconds < 60) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 30) return `${days}d ago`;
    
    return date.toLocaleDateString();
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    return `${year}-${month}-${day}-${hours}:${minutes}:${seconds}`;
}
