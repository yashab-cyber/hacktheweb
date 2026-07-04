/**
 * HackTheWeb Simulation App Logic
 * Interactive CLI Simulator for scanning representation
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnRunScan = document.getElementById('btn-run-scan');
    const targetInput = document.getElementById('target-input');
    const terminalOutput = document.getElementById('terminal-output');
    const reportContainer = document.getElementById('report-view-container');
    
    if (!btnRunScan) return;
    
    let isRunning = false;
    
    btnRunScan.addEventListener('click', () => {
        if (isRunning) return;
        
        const targetUrl = targetInput.value.trim() || 'https://target-webapp.local';
        startSimulation(targetUrl);
    });
    
    function addLogLine(text, type = 'text', delay = 0) {
        return new Promise((resolve) => {
            setTimeout(() => {
                const line = document.createElement('div');
                line.className = `log-line log-${type}`;
                line.textContent = text;
                terminalOutput.appendChild(line);
                
                // Auto scroll to bottom
                const termBody = document.getElementById('scan-terminal');
                termBody.scrollTop = termBody.scrollHeight;
                
                resolve();
            }, delay);
        });
    }
    
    async function startSimulation(target) {
        isRunning = true;
        btnRunScan.disabled = true;
        btnRunScan.textContent = 'Scanning...';
        terminalOutput.innerHTML = '';
        reportContainer.classList.add('hidden');
        
        const timestamp = () => new Date().toISOString().replace('T', ' ').substring(0, 19);
        const formatJSON = (level, message, extra = null) => {
            const data = {
                timestamp: new Date().toISOString(),
                level: level.toUpperCase(),
                message: message
            };
            if (extra) Object.assign(data, extra);
            return JSON.stringify(data);
        };
        
        // Setup sequence of logs
        await addLogLine(`$ python3 hacktheweb.py scan ${target} --scan-mode smart`, 'text', 100);
        await addLogLine(formatJSON('info', `Starting scan on target: ${target}`), 'json', 300);
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'scan_start',
            target: target,
            status: 'initiated'
        }), 'json', 200);
        
        await addLogLine(formatJSON('info', 'Entering Phase 1: Reconnaissance'), 'json', 400);
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'reconnaissance_start',
            target: target,
            status: 'running'
        }), 'json', 150);
        
        await addLogLine(formatJSON('info', 'Executing DNS enumeration...'), 'json', 300);
        await addLogLine(formatJSON('info', 'Scanning common ports (21, 22, 80, 443, 3306, 8080)...'), 'json', 300);
        await addLogLine(formatJSON('info', 'Port 80 (HTTP) - OPEN'), 'json', 100);
        await addLogLine(formatJSON('info', 'Port 443 (HTTPS) - OPEN'), 'json', 50);
        
        await addLogLine(formatJSON('info', 'Gathering response headers and cookies...'), 'json', 400);
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'reconnaissance_complete',
            target: target,
            status: 'success',
            details: { domains_resolved: 1, open_ports: 2 }
        }), 'json', 200);
        
        await addLogLine(formatJSON('info', 'Entering Phase 2: AI Analysis'), 'json', 400);
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'ai_analysis_start',
            target: target,
            status: 'running'
        }), 'json', 150);
        
        await addLogLine(formatJSON('info', 'Running target signature detection rules...'), 'json', 300);
        await addLogLine(formatJSON('info', 'Server header signature match: Nginx detected (confidence 95%)'), 'json', 150);
        await addLogLine(formatJSON('info', 'Cookie signature match: PHPSESSID indicates PHP backend (confidence 85%)'), 'json', 200);
        await addLogLine(formatJSON('info', 'DOM signature match: data-reactroot indicates client-side React (confidence 80%)'), 'json', 250);
        
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'ai_analysis_complete',
            target: target,
            status: 'success',
            details: { priority_vulnerability_classes: ['xss', 'security_headers', 'csrf'] }
        }), 'json', 200);
        
        await addLogLine(formatJSON('info', 'Entering Phase 3: Vulnerability Scanning'), 'json', 400);
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'scanning_start',
            target: target,
            status: 'running'
        }), 'json', 150);
        
        // Scan strategy
        await addLogLine(formatJSON('info', 'AI Scan Strategy (smart): running 3 scanners: xss, csrf, security_headers'), 'json', 300);
        
        // XSS Scanner
        await addLogLine(formatJSON('info', 'Scanning for XSS...'), 'json', 400);
        await addLogLine(formatJSON('warning', 'Potential Reflected XSS detected in query parameter: "q"'), 'warning', 300);
        
        // CSRF Scanner
        await addLogLine(formatJSON('info', 'Scanning for CSRF...'), 'json', 400);
        await addLogLine(formatJSON('warning', 'Form action "/login" lacks anti-forgery token verification'), 'warning', 250);
        
        // Security Headers Scanner
        await addLogLine(formatJSON('info', 'Scanning for SECURITY_HEADERS...'), 'json', 300);
        await addLogLine(formatJSON('warning', 'Missing Content-Security-Policy (CSP) header (Severity: HIGH)'), 'warning', 100);
        await addLogLine(formatJSON('warning', 'Strict-Transport-Security missing (Severity: MEDIUM)'), 'warning', 100);
        await addLogLine(formatJSON('warning', 'Referrer-Policy header missing (Severity: LOW)'), 'warning', 100);
        
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'scanning_complete',
            target: target,
            status: 'success',
            details: { vulnerabilities_identified_count: 5 }
        }), 'json', 300);
        
        await addLogLine(formatJSON('info', 'Scan finished successfully'), 'json', 200);
        await addLogLine(JSON.stringify({
            timestamp: new Date().toISOString(),
            action: 'scan_end',
            target: target,
            status: 'completed'
        }), 'json', 100);
        
        // Show report details
        setTimeout(() => {
            reportContainer.classList.remove('hidden');
            
            // Auto scroll main document to report
            reportContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            
            isRunning = false;
            btnRunScan.disabled = false;
            btnRunScan.textContent = 'Launch Scanner';
        }, 500);
    }
});
