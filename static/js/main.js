// static/js/main.js
// Security Scanner - Main JavaScript
console.log('Security Scanner loaded');

let currentScanId = null;
let progressInterval = null;
// Track last-seen activity timestamp per scan to append only new log entries
let lastActivityTimestamps = {};
// Track seen log entries to prevent duplicates across updates
let seenLogEntries = {};
// Track if scan is paused
let isScanPaused = false;
let currentCategory = 'all';
let currentRisk = 'all';
// Track selected vulnerability severity filters
let selectedVulnFilters = new Set(['all']);
// Store latest risk breakdown data
let latestRiskBreakdown = {
    'Critical': 0,
    'High': 0,
    'Medium': 0,
    'Low': 0,
    'Info': 0
};

document.addEventListener('DOMContentLoaded', function() {
    initializeScanner();
});

function initializeScanner() {
    // Reset UI on page load
    resetScanUI();
    
    // Scan form submission
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            // If the user is not authenticated, show the login modal instead of submitting
            try {
                if (typeof window.IS_AUTHENTICATED === 'undefined' || window.IS_AUTHENTICATED !== true) {
                    const modalEl = document.getElementById('loginRequiredModal');
                    if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                        const modal = new bootstrap.Modal(modalEl);
                        modal.show();
                    } else {
                        // Fallback: alert and redirect to login page
                        alert('Please sign in to start a scan.');
                        window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
                    }
                    return;
                }
            } catch (err) {
                console.warn('Auth check failed, proceeding to attempt scan', err);
            }

            startScan(this);
        });
    }
    
    // Stop/Resume scan button
    const stopBtn = document.getElementById('stopScanButton');
    if (stopBtn) {
        stopBtn.addEventListener('click', function() {
            if (currentScanId) togglePauseResume(currentScanId);
        });
    }
    // Terminate and discard scan button
    const termBtn = document.getElementById('terminateScanButton');
    if (termBtn) {
        termBtn.addEventListener('click', function() {
            if (!currentScanId) return;
            if (!confirm('Stop this scan and permanently discard its results? This cannot be undone.')) return;
            terminateScan(currentScanId);
        });
    }

    // Export Report button (results page)
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        try { exportBtn.removeAttribute('onclick'); } catch (e) {}
        exportBtn.addEventListener('click', handleExportClick);
    }
    
    // Category and Risk filters for results page
    const categoryButtons = document.querySelectorAll('[data-category]');
    categoryButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            setCategory(this.getAttribute('data-category'));
        });
    });
    
    const riskButtons = document.querySelectorAll('[data-risk]');
    riskButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            setRisk(this.getAttribute('data-risk'));
        });
    });
    
    // Vulnerability filter checkboxes
    const vulnFilterCheckboxes = document.querySelectorAll('.vuln-filter-checkbox');
    vulnFilterCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', handleVulnFilterChange);
    });
    
    // Enhanced visibility change handling
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden && currentScanId) {
            // Tab became visible - force immediate progress check
            console.log('Tab visible - checking scan progress');
            if (progressInterval) {
                clearInterval(progressInterval);
                progressInterval = null;
            }
            // Restart monitoring with immediate check
            setTimeout(() => monitorProgress(currentScanId), 100);
            // Don't show confusing message - scan continues running in background
        }
    });
    
    // Also reset when page is shown (for browser navigation)
    // Always refresh the scan history on pageshow to handle bfcache/back-forward caching
    // which can restore an older DOM state. Refreshing will rebuild the table with
    // the current markup and ensure action buttons use the latest styles/markup.
    window.addEventListener('pageshow', function(event) {
        try {
            console.log('pageshow fired - refreshing scan history and localizing timestamps');
            // Rebuild the recent scans table (safe to call repeatedly)
            refreshScanHistory();

            // Re-localize any timestamps that might have been restored from cache
            if (typeof localizeExistingTimestamps === 'function') {
                localizeExistingTimestamps();
            }
        } catch (e) {
            console.warn('pageshow handler error:', e);
        }
    });

    // Fetch and replace the scan history table body with latest scans
    function refreshScanHistory() {
        const recentScansTable = document.getElementById('recentScansTable');
        if (!recentScansTable) return;

        fetch('/recent-scans', { credentials: 'same-origin' })
            .then(resp => {
                if (!resp.ok) throw new Error('Failed to fetch recent scans');
                return resp.json();
            })
            .then(data => {
                if (!data.scans) return;
                const tbody = recentScansTable.querySelector('tbody');
                if (!tbody) return;

                // Clear existing rows
                tbody.innerHTML = '';

                // Rebuild rows safely using textContent for user-controlled strings
                data.scans.forEach(scan => {
                    const tr = document.createElement('tr');
                    tr.setAttribute('data-scan-id', scan.id);
                    tr.setAttribute('data-created-at', scan.created_at);

                    // Target URL cell (user-controlled) - use textContent to avoid HTML injection
                    const tdTarget = document.createElement('td');
                    tdTarget.className = 'text-truncate';
                    tdTarget.style.maxWidth = '200px';
                    tdTarget.textContent = scan.target_url || '';

                    // Scan type cell
                    const tdType = document.createElement('td');
                    const spanType = document.createElement('span');
                    spanType.className = 'badge bg-secondary';
                    spanType.textContent = scan.scan_type || '';
                    tdType.appendChild(spanType);

                    // Status cell (rendered by helper - safe constant strings)
                    const tdStatus = document.createElement('td');
                    tdStatus.innerHTML = renderStatusBadge(scan.status);

                    // Vulnerabilities cell (safe helper)
                    const tdVulns = document.createElement('td');
                    tdVulns.innerHTML = renderVulns(scan);

                    // Score cell (safe helper)
                    const tdScore = document.createElement('td');
                    tdScore.innerHTML = renderScore(scan);

                    // Created at cell - localized
                    const tdCreated = document.createElement('td');
                    tdCreated.className = 'scan-created';
                    tdCreated.textContent = formatTimestampLocal(scan.created_at);

                    // Actions cell - already produces structured markup; keep as innerHTML but
                    // ensure scan.id is treated as string when passed into helper
                    const tdActions = document.createElement('td');
                    tdActions.innerHTML = renderActions(scan);

                    // Append cells in order
                    tr.appendChild(tdTarget);
                    tr.appendChild(tdType);
                    tr.appendChild(tdStatus);
                    tr.appendChild(tdVulns);
                    tr.appendChild(tdScore);
                    tr.appendChild(tdCreated);
                    tr.appendChild(tdActions);

                    tbody.appendChild(tr);
                });
            })
            .catch(err => console.error('Refresh scan history error:', err));
    }

    function renderStatusBadge(status) {
        if (status === 'completed') return '<span class="badge bg-success">Completed</span>';
        if (status === 'running') return '<span class="badge bg-warning">Running</span>';
        if (status === 'stopped') return '<span class="badge bg-secondary">Stopped</span>';
        return '<span class="badge bg-danger">Error</span>';
    }

    function renderVulns(scan) {
        if (scan.status === 'completed') {
            if (scan.vulnerabilities_count > 0) return `<span class="badge bg-danger">${scan.vulnerabilities_count} found</span>`;
            return `<span class="badge bg-success">${scan.vulnerabilities_count} found</span>`;
        }
        if (scan.status === 'running') return '<span class="badge bg-warning">Scanning...</span>';
        return '<span class="badge bg-secondary">N/A</span>';
    }

    function renderScore(scan) {
        if (scan.status === 'completed') {
            const cls = scan.security_score < 50 ? 'danger' : scan.security_score < 80 ? 'warning' : 'success';
            return `<span class="badge bg-${cls}">${scan.security_score}/100</span>`;
        }
        return '<span class="badge bg-secondary">N/A</span>';
    }

    function renderActions(scan) {
        // Match the server-rendered template markup so JS-rebuilt rows keep identical styles
        const viewBtn = scan.status === 'completed' ?
            `<a href="/results/${scan.id}" class="btn btn-sm btn-primary" title="View scan results">
                <i class="fas fa-chart-bar"></i>
                <span class="d-none d-md-inline"> View</span>
            </a>` : '';

        const deleteBtn = `
            <button onclick="deleteScan('${scan.id}')" class="btn btn-sm btn-outline-danger" title="Delete scan">
                <i class="fas fa-trash"></i>
                <span class="d-none d-md-inline"> Delete</span>
            </button>
        `;

        return `
            <div class="action-btns btn-group" role="group" aria-label="Scan actions">
                ${viewBtn}
                ${deleteBtn}
            </div>
        `;
    }

    // Convert ISO timestamp to user's local formatted string
    function formatTimestampLocal(isoTs) {
        try {
            const d = new Date(isoTs);
            if (isNaN(d)) return isoTs;
            return d.toLocaleString();
        } catch (e) {
            return isoTs;
        }
    }

    function localizeExistingTimestamps() {
        // Handle table rows with data-created-at (scan history table)
        const rows = document.querySelectorAll('tr[data-created-at]');
        rows.forEach(row => {
            const ts = row.getAttribute('data-created-at');
            const cell = row.querySelector('.scan-created');
            if (cell && ts) {
                cell.textContent = formatTimestampLocal(ts);
            }
        });
        
        // Handle elements with data-timestamp (results page and any other direct timestamps)
        const timestampElements = document.querySelectorAll('[data-timestamp]');
        timestampElements.forEach(element => {
            const ts = element.getAttribute('data-timestamp');
            if (ts && element.classList.contains('scan-created')) {
                element.textContent = formatTimestampLocal(ts);
            }
        });
    }

    // Localize timestamps once during initialization
    try {
        localizeExistingTimestamps();
    } catch (e) {
        console.warn('localizeExistingTimestamps not available during init:', e);
    }
}

// Enhanced function to reset scan UI when page loads
function resetScanUI() {
    const scanProgress = document.getElementById('scanProgress');
    const scanButton = document.getElementById('scanButton');
    const stopBtn = document.getElementById('stopScanButton');
    const progressBar = document.getElementById('scanProgressBar');
    const progressText = document.getElementById('progressText');
    
    // Always reset the UI when page loads
    if (scanProgress) {
        scanProgress.style.display = 'none';
    }
    
    if (scanButton) {
        scanButton.disabled = false;
        scanButton.innerHTML = '<i class="fas fa-search"></i> Start Scan';
    }
    
    if (stopBtn) {
        stopBtn.disabled = false;
        stopBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Stop Scan';
        stopBtn.className = 'btn btn-warning btn-sm';
    }
    
    if (progressBar) {
        progressBar.style.width = '0%';
        progressBar.setAttribute('aria-valuenow', '0');
    }
    
    if (progressText) {
        progressText.textContent = 'Ready to scan...';
    }
    
    // Clear any existing progress intervals
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
    
    currentScanId = null;
    isScanPaused = false;
    // Clear seen entries when resetting
    const scanKey = 'global';
    if (seenLogEntries[scanKey]) {
        delete seenLogEntries[scanKey];
    }
}

function startScan(form) {
    const formData = new FormData(form);
    const scanProgress = document.getElementById('scanProgress');
    const scanButton = document.getElementById('scanButton');
    
    // Show activity log panel
    if (scanProgress) {
        resetActivityLog();
        scanProgress.style.display = 'block';
        scanProgress.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Disable button
    if (scanButton) {
        scanButton.disabled = true;
        scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
    }
    
    // Start scan
    fetch(form.action, {
        method: 'POST',
        body: formData,
        // Ensure cookies (session / CSRF) are sent with the request
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            // Try to parse and surface a JSON error message from the server
            return response.json()
                .then(err => {
                    const msg = err.error || err.message || response.statusText || 'Request failed';
                    throw new Error(msg);
                })
                .catch(() => {
                    throw new Error('Network response was not ok');
                });
        }
        return response.json();
    })
    .then(data => {
        if (data.scan_id) {
            currentScanId = data.scan_id;
            isScanPaused = false;
            // initialize last-activity for this scan so we append new entries smoothly
            lastActivityTimestamps[data.scan_id] = null;
            
            // Reset vulnerability filters for new scan
            resetVulnerabilityFilters();
            
            addToActivityLog('🚀 Scan started successfully!', 'success');
            addToActivityLog(`🔍 Scan Type: ${form.scan_type.options[form.scan_type.selectedIndex].text}`, 'info');
            addToActivityLog(`🎯 Target: ${data.target_url}`, 'info');
            
            // Update stop button to show it's running
            const stopBtn = document.getElementById('stopScanButton');
            if (stopBtn) {
                stopBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Pause Scan';
                stopBtn.className = 'btn btn-warning btn-sm';
                stopBtn.disabled = false;
            }
            
            monitorProgress(data.scan_id);
        } else {
            throw new Error(data.error || 'Failed to start scan');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        addToActivityLog('❌ Error: ' + error.message, 'error');
        enableForm();
    });
}

function handleVulnFilterChange(event) {
    const checkbox = event.target;
    const value = checkbox.value;
    const allCheckbox = document.getElementById('filter-all');
    const otherCheckboxes = document.querySelectorAll('.vuln-filter-checkbox:not(#filter-all)');
    
    if (value === 'all') {
        // If "All" is checked, uncheck all others
        if (checkbox.checked) {
            selectedVulnFilters.clear();
            selectedVulnFilters.add('all');
            otherCheckboxes.forEach(cb => cb.checked = false);
        } else {
            // Don't allow unchecking "All" if nothing else is selected
            checkbox.checked = true;
        }
    } else {
        // If a specific filter is checked, uncheck "All"
        if (checkbox.checked) {
            selectedVulnFilters.delete('all');
            selectedVulnFilters.add(value);
            if (allCheckbox) allCheckbox.checked = false;
        } else {
            selectedVulnFilters.delete(value);
            // If no filters selected, revert to "All"
            if (selectedVulnFilters.size === 0) {
                selectedVulnFilters.add('all');
                if (allCheckbox) allCheckbox.checked = true;
            }
        }
    }
    
    // Update the vulnerability count display
    updateVulnerabilityCount();
}

function updateVulnerabilityCount() {
    const vulnerabilitiesCount = document.getElementById('vulnerabilitiesCount');
    if (!vulnerabilitiesCount) return;
    
    let count = 0;
    
    if (selectedVulnFilters.has('all')) {
        // Show all vulnerabilities
        count = Object.values(latestRiskBreakdown).reduce((sum, val) => sum + val, 0);
    } else {
        // Sum only selected severity levels
        selectedVulnFilters.forEach(severity => {
            count += latestRiskBreakdown[severity] || 0;
        });
    }
    
    vulnerabilitiesCount.textContent = count;
}

function resetVulnerabilityFilters() {
    // Reset vulnerability filters to "All"
    selectedVulnFilters.clear();
    selectedVulnFilters.add('all');
    const allCheckbox = document.getElementById('filter-all');
    if (allCheckbox) allCheckbox.checked = true;
    const otherCheckboxes = document.querySelectorAll('.vuln-filter-checkbox:not(#filter-all)');
    otherCheckboxes.forEach(cb => cb.checked = false);
    
    // Update display to show all vulnerabilities
    updateVulnerabilityCount();
}

function resetActivityLog() {
    const activityLog = document.getElementById('activityLog');
    if (activityLog) {
        activityLog.innerHTML = '';
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        const timeSpan = document.createElement('span');
        timeSpan.className = 'log-time';
        timeSpan.textContent = '[' + new Date().toLocaleTimeString() + ']';
        const msgSpan = document.createElement('span');
        msgSpan.className = 'log-message';
        msgSpan.textContent = '🔄 Scanner initialized and ready...';
        entry.appendChild(timeSpan);
        entry.appendChild(msgSpan);
        activityLog.appendChild(entry);
    }
    // reset last activity marker for current scan if any
    if (currentScanId) {
        lastActivityTimestamps[currentScanId] = null;
        seenLogEntries[currentScanId] = new Set(); // Reset seen entries for new scan
    }
    
    // Reset vulnerability filters
    selectedVulnFilters.clear();
    selectedVulnFilters.add('all');
    const allCheckbox = document.getElementById('filter-all');
    if (allCheckbox) allCheckbox.checked = true;
    const otherCheckboxes = document.querySelectorAll('.vuln-filter-checkbox:not(#filter-all)');
    otherCheckboxes.forEach(cb => cb.checked = false);
    
    // Reset risk breakdown
    latestRiskBreakdown = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Info': 0
    };
    
    // Reset counters
    const vulnerabilitiesCount = document.getElementById('vulnerabilitiesCount');
    const securityScore = document.getElementById('securityScore');
    const scanStatus = document.getElementById('scanStatus');
    const scanPhase = document.getElementById('scanPhase');
    
    if (vulnerabilitiesCount) vulnerabilitiesCount.textContent = '0';
    if (securityScore) {
        securityScore.textContent = '100';
        securityScore.className = 'text-success';
    }
    if (scanStatus) {
        scanStatus.textContent = 'Running';
        scanStatus.className = 'status-running';
    }
    if (scanPhase) scanPhase.textContent = 'Initializing...';
}

function addToActivityLog(message, type = 'info') {
    const activityLog = document.getElementById('activityLog');
    if (activityLog) {
        const timestamp = new Date().toLocaleTimeString();
        const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : '🔍';
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';

        const timeSpan = document.createElement('span');
        timeSpan.className = 'log-time';
        timeSpan.textContent = '[' + timestamp + ']';

        const msgSpan = document.createElement('span');
        msgSpan.className = 'log-message';
        // Use textContent to avoid interpreting message as HTML
        msgSpan.textContent = icon + ' ' + message;

        logEntry.appendChild(timeSpan);
        logEntry.appendChild(msgSpan);
        activityLog.appendChild(logEntry);
        activityLog.scrollTop = activityLog.scrollHeight;
    }
}

// Enhanced progress monitoring with detailed activity logging
function monitorProgress(scanId) {
    if (progressInterval) clearInterval(progressInterval);
    
    progressInterval = setInterval(() => {
        // Continue checking progress - scan runs on server and continues regardless of tab visibility
        // When tab is hidden, browser may throttle intervals, but we still check when possible
        
        fetch(`/scan-progress/${scanId}`, { credentials: 'same-origin' })
            .then(response => {
                if (!response.ok) {
                    // Surface server message (try JSON first, then text)
                    return response.json()
                        .then(err => { throw new Error(err.error || err.message || response.statusText); })
                        .catch(() => response.text().then(txt => { throw new Error(txt || 'Network response was not ok'); }));
                }
                return response.json();
            })
            .then(data => {
                // Check if scan is completing - reset filters BEFORE updating display
                const isCompleting = ['completed', 'stopped', 'error'].includes(data.status);
                if (isCompleting && data.status === 'completed') {
                    // Reset filters first so updateActivityDisplay shows all vulnerabilities
                    resetVulnerabilityFilters();
                }
                
                updateActivityDisplay(data);
                
                // Update button state based on scan status
                updateStopButtonState(data.status);
                
                if (isCompleting) {
                    clearInterval(progressInterval);
                    progressInterval = null;
                    
                    if (data.status === 'completed') {
                        addToActivityLog('✅ Scan completed! Redirecting to results...', 'success');
                        setTimeout(() => {
                            resetScanUI();
                            window.location.href = `/results/${scanId}`;
                        }, 2000);
                    } else {
                        setTimeout(resetScanUI, 1000);
                    }
                }
            })
            .catch(error => {
                console.error('Progress error:', error);
                // Don't stop on errors - retry on next interval
            });
    }, 1500); // Reduced interval for more real-time updates
}

// Adding timeout and retry logic to handle cases where the scan progress does not update within a reasonable timeframe.
function pollScanProgress(scanId) {
    const maxRetries = 10; // Maximum number of retries
    let retryCount = 0;

    function fetchProgress() {
        fetch(`/scan-progress/${scanId}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.status === 'completed' || data.status === 'error') {
                    updateUIWithProgress(data);
                } else if (retryCount < maxRetries) {
                    retryCount++;
                    setTimeout(fetchProgress, 3000); // Retry after 3 seconds
                } else {
                    alert('The scan is taking longer than expected. Please try again later.');
                }
            })
            .catch(error => {
                console.error('Error fetching scan progress:', error);
                alert('An error occurred while fetching scan progress. Please try again later.');
            });
    }

    fetchProgress();
}

function updateActivityDisplay(data) {
    // Always update risk breakdown if provided
    if (data.risk_breakdown) {
        latestRiskBreakdown = data.risk_breakdown;
    }
    
    // CRITICAL FIX: Always use vulnerabilities_found as the source of truth
    // The risk_breakdown might lag behind during rapid updates
    if (data.vulnerabilities_found !== undefined && data.vulnerabilities_found !== null) {
        const backendTotal = data.vulnerabilities_found;
        const breakdownTotal = Object.values(latestRiskBreakdown).reduce((sum, val) => sum + val, 0);
        
        // If backend reports more vulnerabilities than our breakdown shows,
        // put the difference in a placeholder category
        if (backendTotal > breakdownTotal) {
            const diff = backendTotal - breakdownTotal;
            latestRiskBreakdown = {
                ...latestRiskBreakdown,
                'Info': (latestRiskBreakdown['Info'] || 0) + diff
            };
        }
    }
    
    // Update vulnerabilities count based on selected filters
    updateVulnerabilityCount();
    
    // Update security score with color coding
    const securityScore = document.getElementById('securityScore');
    if (securityScore) {
        const score = data.security_score !== undefined && data.security_score !== null ? data.security_score : 100;
            securityScore.textContent = `${score}/100`;
        
        // Color coding based on score
            securityScore.classList.remove('text-success', 'text-warning', 'text-danger');
            if (score >= 80) {
                securityScore.classList.add('text-success');
            } else if (score >= 60) {
                securityScore.classList.add('text-warning');
            } else {
                securityScore.classList.add('text-danger');
            }
    }
    
    // Update status with color coding
    const scanStatus = document.getElementById('scanStatus');
    if (scanStatus) {
        scanStatus.textContent = data.status || 'Running';
        scanStatus.className = `status-${data.status || 'running'}`;
    }
    
    // Update scan phase with detailed information
    const scanPhase = document.getElementById('scanPhase');
    if (scanPhase && data.current_task) {
        scanPhase.textContent = data.current_task;
        
        // Removed vulnerability count display to keep phase name clean
    }
    
    // Update activity log with all entries
    updateActivityLog(data.activity_log || []);
}

function updateActivityLog(activityLog) {
    const activityLogContainer = document.getElementById('activityLog');
    if (!activityLogContainer) return;
    // Append only new entries to avoid blinking. Activity entries contain ISO timestamps.
    if (!Array.isArray(activityLog) || activityLog.length === 0) return;

    // Check if the user is already at the bottom before we append new entries
    const wasAtBottom = (function(el){
        try {
            const pos = el.scrollTop + el.clientHeight;
            return (el.scrollHeight - pos) <= 8; // within 8px is considered bottom
        } catch(e) { return true; }
    })(activityLogContainer);

    // Sort entries by timestamp to ensure chronological order
    activityLog.sort((a, b) => {
        const timeDiff = new Date(a.timestamp) - new Date(b.timestamp);
        // If timestamps are equal, compare messages to ensure consistent ordering
        if (timeDiff === 0) {
            return (a.message || '').localeCompare(b.message || '');
        }
        return timeDiff;
    });

    const scanKey = currentScanId || 'global';
    let lastTs = lastActivityTimestamps[scanKey] || null;
    
    // Initialize seen entries set for this scan if not exists
    if (!seenLogEntries[scanKey]) {
        seenLogEntries[scanKey] = new Set();
    }
    const seenEntries = seenLogEntries[scanKey];

    activityLog.forEach(logEntry => {
        const entryTs = logEntry.timestamp;
        const message = logEntry.message || '';
        // Create a more unique key that handles timestamp precision issues
        const entryKey = `${entryTs}|${message}`;
        
        // Skip if we've already seen this exact entry (across all updates)
        if (seenEntries.has(entryKey)) {
            return;
        }
        
        // Also check if message was seen recently (within 1 second) to catch duplicates with slightly different timestamps
        let isDuplicate = false;
        for (const seenKey of seenEntries) {
            const [seenTs, seenMsg] = seenKey.split('|', 2);
            if (seenMsg === message) {
                // If same message and timestamps are very close (within 1 second), treat as duplicate
                const tsDiff = Math.abs(new Date(entryTs) - new Date(seenTs));
                if (tsDiff < 1000) { // Within 1 second
                    isDuplicate = true;
                    break;
                }
            }
        }
        
        if (isDuplicate) {
            return;
        }
        
        // If we don't have a lastTs, or this entry is newer, append it
        if (!lastTs || entryTs >= lastTs) {
            addLogEntryToDisplay(logEntry);
            seenEntries.add(entryKey); // Mark as seen
            lastTs = entryTs;
        }
    });

    lastActivityTimestamps[scanKey] = lastTs;

    // Only auto-follow if user was already at (or near) the bottom
    if (wasAtBottom) {
        activityLogContainer.scrollTo({ top: activityLogContainer.scrollHeight, behavior: 'auto' });
    }
}

function addLogEntryToDisplay(logEntry) {
    const activityLog = document.getElementById('activityLog');
    if (!activityLog) return;
    
    const timestamp = new Date(logEntry.timestamp).toLocaleTimeString();
    const message = logEntry.message;
    const type = logEntry.type || 'info';
    
    // Check if message already starts with an emoji before choosing icon
    const messageText = message || '';
    const trimmedMessage = messageText.trim();
    
    // Check if first character is an emoji (common emoji ranges)
    const emojiPattern = /^[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}]/u;
    const alreadyHasIcon = emojiPattern.test(trimmedMessage);
    
    // Only choose icon if message doesn't already start with one
    let icon = '🔍'; // Default icon
    
    if (alreadyHasIcon) {
        // Don't add icon, message already has one
        icon = '';
    } else if (type === 'error') {
        icon = '❌';
    } else if (type === 'success') {
        icon = '✅';
    } else if (message.includes('🚀')) {
        icon = '🚀';
    } else if (message.includes('🦠')) {
        icon = '🦠';
    } else if (message.includes('💉')) {
        icon = '💉';
    } else if (message.includes('📋')) {
        icon = '📋';
    } else if (message.includes('📢')) {
        icon = '📢';
    } else if (message.includes('🛡️')) {
        icon = '🛡️';
    } else if (message.includes('⚠️')) {
        icon = '⚠️';
    } else if (message.includes('🔍')) {
        icon = '🔍';
    } else if (message.includes('📊')) {
        icon = '📊';
    } else if (message.includes('🎯')) {
        icon = '🎯';
    } else if (message.includes('🌐')) {
        icon = '🌐';
    } else if (message.includes('🧪')) {
        icon = '🧪';
    } else if (message.includes('🔬')) {
        icon = '🔬';
    } else if (message.includes('📝')) {
        icon = '📝';
    } else if (message.includes('🖥️')) {
        icon = '🖥️';
    } else if (message.includes('🔧')) {
        icon = '🔧';
    } else if (message.includes('🔄')) {
        icon = '🔄';
    } else if (message.includes('🛑')) {
        icon = '🛑';
    }
    
    const logElement = document.createElement('div');
    logElement.className = 'log-entry';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = '[' + timestamp + ']';

    const msgSpan = document.createElement('span');
    msgSpan.className = 'log-message';
    
    // Add icon if we have one, otherwise just use the message
    if (icon) {
        msgSpan.textContent = icon + ' ' + messageText;
    } else {
        msgSpan.textContent = messageText;
    }

    // Add animation for new entries
    logElement.style.opacity = '0';
    logElement.style.transform = 'translateY(-10px)';

    logElement.appendChild(timeSpan);
    logElement.appendChild(msgSpan);
    activityLog.appendChild(logElement);

    // Animate the new entry
    setTimeout(() => {
        logElement.style.transition = 'all 0.3s ease';
        logElement.style.opacity = '1';
        logElement.style.transform = 'translateY(0)';
    }, 10);
}

// Helper available to other modules if needed
function isNearBottom(el, threshold = 8) {
    try {
        const pos = el.scrollTop + el.clientHeight;
        return (el.scrollHeight - pos) <= threshold;
    } catch (e) { return true; }
}

function togglePauseResume(scanId) {
    const stopBtn = document.getElementById('stopScanButton');
    if (!stopBtn) return;
    
    // Disable button during request
    stopBtn.disabled = true;
    
    // Determine current action based on button state
    const isPausing = !isScanPaused;
    
    if (isPausing) {
        stopBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Pausing...';
        addToActivityLog('⏸️ Pausing scan...', 'info');
    } else {
        stopBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Resuming...';
        addToActivityLog('▶️ Resuming scan...', 'info');
    }
    
    fetch(`/stop-scan/${scanId}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error || err.message || response.statusText); }).catch(() => { throw new Error('Failed to pause/resume scan'); });
        }
        return response.json();
    })
    .then(data => {
        console.log('Pause/Resume response:', data); // Debug log
        if (data.action === 'pause') {
            isScanPaused = true;
            // Stop progress monitoring when paused
            if (progressInterval) {
                clearInterval(progressInterval);
                progressInterval = null;
            }
            if (stopBtn) {
                stopBtn.innerHTML = '<i class="fas fa-play me-1"></i> Resume Scan';
                stopBtn.className = 'btn btn-success btn-sm';
                stopBtn.disabled = false;
            }
            addToActivityLog('⏸️ Scan paused - Click Resume to continue', 'info');
        } else if (data.action === 'resume') {
            isScanPaused = false;
            // Restart progress monitoring when resumed
            if (currentScanId) {
                monitorProgress(currentScanId);
            }
            if (stopBtn) {
                stopBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Pause Scan';
                stopBtn.className = 'btn btn-warning btn-sm';
                stopBtn.disabled = false;
            }
            addToActivityLog('▶️ Scan resumed', 'success');
        } else {
            // If no action field, try to determine from status
            console.warn('No action field in response, using status:', data.status);
            if (data.status === 'paused') {
                isScanPaused = true;
                // Stop progress monitoring when paused
                if (progressInterval) {
                    clearInterval(progressInterval);
                    progressInterval = null;
                }
                if (stopBtn) {
                    stopBtn.innerHTML = '<i class="fas fa-play me-1"></i> Resume Scan';
                    stopBtn.className = 'btn btn-success btn-sm';
                    stopBtn.disabled = false;
                }
            } else if (data.status === 'running') {
                isScanPaused = false;
                // Restart progress monitoring when resumed
                if (currentScanId) {
                    monitorProgress(currentScanId);
                }
                if (stopBtn) {
                    stopBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Pause Scan';
                    stopBtn.className = 'btn btn-warning btn-sm';
                    stopBtn.disabled = false;
                }
            }
        }
    })
    .catch(error => {
        console.error('Pause/Resume error:', error);
        addToActivityLog('❌ Error: ' + error.message, 'error');
        if (stopBtn) {
            stopBtn.disabled = false;
            // Restore button state based on current pause state
            if (isScanPaused) {
                stopBtn.innerHTML = '<i class="fas fa-play me-1"></i> Resume Scan';
                stopBtn.className = 'btn btn-success btn-sm';
            } else {
                stopBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Pause Scan';
                stopBtn.className = 'btn btn-warning btn-sm';
            }
        }
    });
}

function updateStopButtonState(status) {
    const stopBtn = document.getElementById('stopScanButton');
    if (!stopBtn || !currentScanId) return;
    
    if (status === 'paused') {
        isScanPaused = true;
        // Stop progress monitoring when paused
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        if (stopBtn.innerHTML.includes('Pause')) {
            stopBtn.innerHTML = '<i class="fas fa-play me-1"></i> Resume Scan';
            stopBtn.className = 'btn btn-success btn-sm';
        }
    } else if (status === 'running') {
        isScanPaused = false;
        // Restart progress monitoring when resumed
        if (currentScanId && !progressInterval) {
            monitorProgress(currentScanId);
        }
        if (stopBtn.innerHTML.includes('Resume')) {
            stopBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Pause Scan';
            stopBtn.className = 'btn btn-warning btn-sm';
        }
    }
}

function enableForm() {
    const scanButton = document.getElementById('scanButton');
    const stopBtn = document.getElementById('stopScanButton');
    
    if (scanButton) {
        scanButton.disabled = false;
        scanButton.innerHTML = '<i class="fas fa-search"></i> Start Scan';
    }
    
    if (stopBtn) {
        stopBtn.disabled = false;
        stopBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Pause Scan';
        stopBtn.className = 'btn btn-warning btn-sm';
    }
}

// Stop a running scan and discard stored results
function terminateScan(scanId) {
    const termBtn = document.getElementById('terminateScanButton');
    if (termBtn) {
        termBtn.disabled = true;
        termBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Stopping...';
    }

    fetch(`/stop-and-discard/${scanId}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' }
    })
    .then(async response => {
        if (!response.ok) {
            // Try to parse JSON error, fallback to text
            try {
                const err = await response.json();
                throw new Error(err.error || err.message || response.statusText);
            } catch (e) {
                const txt = await response.text();
                throw new Error(txt || 'Failed to stop and discard scan');
            }
        }
        return response.json();
    })
    .then(data => {
        // Clean up UI: stop progress monitoring and reset UI
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        resetScanUI();

        // Remove row from recent scans table if present
        const row = document.querySelector(`tr[data-scan-id="${scanId}"]`);
        if (row && row.parentNode) row.parentNode.removeChild(row);

        addToActivityLog('🛑 Scan stopped and discarded', 'success');
    })
    .catch(error => {
        console.error('Terminate error:', error);
        addToActivityLog('❌ Error stopping scan: ' + error.message, 'error');
    })
    .finally(() => {
        if (termBtn) {
            termBtn.disabled = false;
            termBtn.innerHTML = '<i class="fas fa-times me-1"></i> Stop & Discard';
        }
    });
}

function setCategory(cat) {
    currentCategory = cat;
    updateActiveButtons();
    // Call filterVulnerabilities in a backward-compatible way.
    // Some pages (e.g. templates/results.html) override the global
    // filterVulnerabilities to accept a (value, type) signature. Passing
    // the category and explicit type ensures both implementations work.
    try {
        filterVulnerabilities(currentCategory, 'category');
    } catch (e) {
        // Fallback to legacy no-arg version
        try { filterVulnerabilities(); } catch (err) { console.warn('filterVulnerabilities failed', err); }
    }
}

function setRisk(risk) {
    currentRisk = risk;
    updateActiveButtons();
    // See setCategory: prefer calling with explicit args for compatibility
    try {
        filterVulnerabilities(currentRisk, 'risk');
    } catch (e) {
        try { filterVulnerabilities(); } catch (err) { console.warn('filterVulnerabilities failed', err); }
    }
}

function updateActiveButtons() {
    // Remove active from all category buttons
    document.querySelectorAll('[data-category]').forEach(btn => {
        btn.classList.remove('active', 'btn-primary');
        btn.classList.add('btn-outline-secondary');
    });
    // Add active to current category
    const catBtn = document.querySelector(`[data-category="${currentCategory}"]`);
    if (catBtn) {
        catBtn.classList.add('active', 'btn-primary');
        catBtn.classList.remove('btn-outline-secondary');
    }
    
    // Remove active from all risk buttons
    document.querySelectorAll('[data-risk]').forEach(btn => {
        btn.classList.remove('active', 'btn-primary');
        btn.classList.add('btn-outline-secondary');
    });
    // Add active to current risk
    const riskBtn = document.querySelector(`[data-risk="${currentRisk}"]`);
    if (riskBtn) {
        riskBtn.classList.add('active', 'btn-primary');
        riskBtn.classList.remove('btn-outline-secondary');
    }
}

function filterVulnerabilities() {
    const categories = document.querySelectorAll('.vulnerability-category');
    categories.forEach(cat => {
        const catName = cat.id.substring(9).replace(/-/g, ' '); // get category name from id
        const rows = cat.querySelectorAll('.vulnerability-row');
        let hasVisible = false;
        rows.forEach(row => {
            const rowRisk = row.dataset.risk;
            const categoryMatch = currentCategory === 'all' || catName.toLowerCase().replace(/\s+/g, '-') === currentCategory;
            const riskMatch = currentRisk === 'all' || rowRisk === currentRisk;
            if (categoryMatch && riskMatch) {
                row.style.display = 'table-row';
                hasVisible = true;
            } else {
                row.style.display = 'none';
            }
        });
        cat.style.display = hasVisible ? 'block' : 'none';
    });

    // Update counter on results page if helper is present
    if (typeof updateVulnCounter === 'function') {
        try {
            updateVulnCounter();
        } catch (err) {
            console.warn('updateVulnCounter failed', err);
        }
    }
}

function filterByCategory(category) {
    const categories = document.querySelectorAll('.vulnerability-category');
    categories.forEach(cat => {
        const catName = cat.id.substring(9).replace(/-/g, ' '); // get category name from id
        const categoryMatch = category === 'all' || catName.toLowerCase().replace(/\s+/g, '-') === category;
        const rows = cat.querySelectorAll('.vulnerability-row');
        let hasVisible = false;
        rows.forEach(row => {
            if (categoryMatch) {
                row.style.display = 'table-row';
                hasVisible = true;
            } else {
                row.style.display = 'none';
            }
        });
        cat.style.display = hasVisible ? 'block' : 'none';
    });
}

function filterByRiskLevel(riskLevel) {
    const categories = document.querySelectorAll('.vulnerability-category');
    categories.forEach(cat => {
        const rows = cat.querySelectorAll('.vulnerability-row');
        let hasVisible = false;
        rows.forEach(row => {
            const rowRisk = row.dataset.risk;
            const riskMatch = riskLevel === 'all' || rowRisk === riskLevel;
            if (riskMatch) {
                row.style.display = 'table-row';
                hasVisible = true;
            } else {
                row.style.display = 'none';
            }
        });
        cat.style.display = hasVisible ? 'block' : 'none';
    });
}

// PDF Export Function
function exportToPDF(scanId) {
    // Use the same fetch-as-blob approach as the results page so behavior is consistent
    const exportBtn = document.getElementById('exportBtn');
    const originalText = exportBtn ? exportBtn.innerHTML : null;

    if (exportBtn) {
        exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Generating PDF...';
        exportBtn.disabled = true;
    }

    // Build URL with optional timestamp metadata
    let requestUrl = `/export-pdf/${scanId}`;
    const params = new URLSearchParams();
    const scanTimeElement = document.getElementById('scanCompletedTime');
    if (scanTimeElement) {
        const isoTimestamp = scanTimeElement.getAttribute('data-timestamp');
        if (isoTimestamp) params.set('iso_time', isoTimestamp);

        let localizedDisplay = '';
        if (isoTimestamp) {
            const dateObj = new Date(isoTimestamp);
            if (!isNaN(dateObj.getTime())) {
                // Some JS engines/browsers (especially older ones) will throw
                // when given the modern `dateStyle` / `timeStyle` options.
                // Guard this call so it doesn't abort the export flow.
                try {
                    localizedDisplay = dateObj.toLocaleString(undefined, {
                        dateStyle: 'medium',
                        timeStyle: 'medium',
                        timeZoneName: 'short'
                    });
                } catch (e) {
                    // Fallback to a simpler locale representation when options
                    // are not supported or throw. We still try to avoid throwing
                    // an exception so the export flow can continue.
                    console.warn('toLocaleString with options not supported, falling back:', e);
                    try {
                        localizedDisplay = dateObj.toLocaleString();
                    } catch (e2) {
                        console.warn('toLocaleString fallback also failed:', e2);
                        localizedDisplay = isoTimestamp;
                    }
                }
            }
        }
        if (!localizedDisplay) {
            const match = scanTimeElement.textContent.match(/Scan completed on (.+)/);
            if (match && match[1]) localizedDisplay = match[1].trim();
        }
        if (localizedDisplay) params.set('local_time', localizedDisplay);
    }

    try {
        const tzOptions = Intl.DateTimeFormat().resolvedOptions();
        if (tzOptions && tzOptions.timeZone) params.set('timezone', tzOptions.timeZone);
    } catch (e) {}
    try { params.set('utc_offset', (-new Date().getTimezoneOffset()).toString()); } catch (e) {}

    const paramString = params.toString();
    if (paramString) requestUrl += `?${paramString}`;

    // Fetch the PDF and download as blob. Be tolerant when the server omits
    // or misreports the Content-Type by checking the PDF magic bytes.
    fetch(requestUrl, { credentials: 'same-origin', headers: { 'Accept': 'application/pdf' } })
        .then(async resp => {
            if (!resp.ok) {
                const text = await resp.text().catch(() => resp.statusText || 'Unknown error');
                throw new Error(text || resp.statusText || 'Request failed');
            }

            // Always read the response as a blob first. Some servers or proxies
            // may not set Content-Type correctly, so checking the blob's first
            // bytes (the PDF "magic") is the most reliable indicator.
            const rawBlob = await resp.blob();

            // Check header if available
            const contentType = (resp.headers && resp.headers.get) ? (resp.headers.get('content-type') || '') : '';
            const headerLooksLikePdf = contentType.toLowerCase().includes('application/pdf');

            // Check magic bytes for '%PDF-'
            let magicLooksLikePdf = false;
            try {
                const slice = rawBlob.slice(0, 5);
                const arr = new Uint8Array(await slice.arrayBuffer());
                let prefix = '';
                for (let i = 0; i < arr.length; i++) prefix += String.fromCharCode(arr[i]);
                magicLooksLikePdf = prefix.startsWith('%PDF-');
            } catch (e) {
                console.warn('Failed to inspect blob magic bytes:', e);
            }

            if (!headerLooksLikePdf && !magicLooksLikePdf) {
                // Not a PDF — attempt to surface a helpful snippet from the
                // server response (likely HTML login page or error trace).
                let text = '<non-text response>';
                try {
                    text = await new Response(rawBlob).text();
                } catch (e) {}
                const snippet = (typeof text === 'string') ? text.substring(0, 2000) : String(text);
                throw new Error('Expected PDF but server returned: ' + snippet);
            }

            // Looks like a PDF — proceed with downloading the blob
            return rawBlob;
        })
        .then(blob => {
            const blobUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = `security-scan-report-${scanId}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(blobUrl);
        })
        .catch(err => {
            // Suppress intrusive alert for the specific case where the
            // response was inspected and found not to be a PDF. In that
            // case we log a warning and append a lightweight activity
            // message so debugging info remains available without a
            // disruptive error popup.
            console.error('Export PDF failed:', err);
            const message = (err && err.message) ? err.message : 'Failed to generate PDF';

            const expectedPrefix = 'Expected PDF but server returned:';
            if (message && message.toLowerCase().includes('login')) {
                // Authentication issue - keep a visible alert so the user
                // knows they need to sign back in.
                showAlert('You may have been logged out. Please sign in and try again.', 'error');
            } else if (message && message.startsWith(expectedPrefix)) {
                // Non-PDF response detected. Don't show an alert; instead
                // add a short activity log entry and a console warning.
                console.warn(message);
                try { addToActivityLog('ℹ️ Export completed but server returned unexpected content-type; check server logs for details.', 'info'); } catch (e) { /* ignore */ }
            } else {
                // Generic error - show to user
                showAlert(message, 'error');
            }
        })
        .finally(() => {
            if (exportBtn && originalText !== null) {
                exportBtn.innerHTML = originalText;
                exportBtn.disabled = false;
            }
        });
}

// Wrapper used by results page click handler. Extracts scan id and delegates to exportToPDF.
function handleExportClick(event) {
    // Provide detailed logging and avoid swallowing errors silently.
    try {
        let button = null;

        if (event && typeof event === 'object' && typeof event.preventDefault === 'function') {
            try { event.preventDefault(); } catch (e) {}
            button = event.currentTarget || event.target || null;
        } else if (event && typeof event.nodeType === 'number') {
            // called with an element
            button = event;
        } else {
            // last-resort fallback
            console.warn('handleExportClick: called without an Event; falling back to #exportBtn', event);
            button = document.getElementById('exportBtn');
        }

        if (!button) {
            const msg = 'Export button element not found (no event target and #exportBtn missing)';
            console.error('handleExportClick:', msg, { event });
            showAlert(msg, 'error');
            return;
        }

        // Prefer explicit data attribute
        let scanId = null;
        try {
            if (button.dataset && button.dataset.scanId) scanId = button.dataset.scanId;
        } catch (e) {
            console.warn('handleExportClick: error reading dataset on button', e);
        }

        if (!scanId) {
            try {
                const href = (typeof button.getAttribute === 'function' && button.getAttribute('href')) || button.href || '';
                const parts = href.split('/').filter(Boolean);
                scanId = parts.length ? parts[parts.length - 1] : null;
            } catch (e) {
                console.warn('handleExportClick: error parsing href for scan id', e);
            }
        }

        if (!scanId) {
            const msg = 'Unable to determine scan id for export (no data-scan-id and href parse failed)';
            console.error('handleExportClick:', msg, { button });
            showAlert(msg, 'error');
            return;
        }

        try {
            exportToPDF(scanId);
        } catch (err) {
            console.error('handleExportClick -> exportToPDF threw:', err);
            showAlert('Failed to start PDF export: ' + (err && err.message ? err.message : String(err)), 'error');
        }
    } catch (err) {
        console.error('handleExportClick unexpected error:', err);
        showAlert('Failed to start PDF export: ' + (err && err.message ? err.message : String(err)), 'error');
    }
}

function showAlert(message, type) {
    // Remove existing alerts
    const existingAlerts = document.querySelectorAll('.custom-alert');
    existingAlerts.forEach(alert => alert.remove());
    
    // Create new alert
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : 'success'} alert-dismissible fade show custom-alert position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 1050; min-width: 300px;';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Risk level badge styling
function getRiskBadgeClass(riskLevel) {
    const riskClasses = {
        'High': 'badge-high',
        'Medium': 'badge-medium',
        'Low': 'badge-low',
        'Info': 'badge-info'
    };
    return riskClasses[riskLevel] || 'badge-secondary';
}


// Delete scan by id (called from UI)
function deleteScan(scanId) {
    if (!confirm('Are you sure you want to permanently delete this scan? This action cannot be undone.')) return;

    fetch(`/delete-scan/${scanId}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error || err.message || response.statusText); }).catch(() => { throw new Error('Failed to delete scan'); });
        }
        return response.json();
    })
    .then(data => {
        // Remove row from table if present
        const row = document.querySelector(`tr[data-scan-id="${scanId}"]`);
        if (row && row.parentNode) {
            row.parentNode.removeChild(row);
        }

        addToActivityLog('🗑️ Scan deleted successfully', 'success');
    })
    .catch(error => {
        console.error('Delete error:', error);
        addToActivityLog('❌ Error deleting scan: ' + error.message, 'error');
    });
}