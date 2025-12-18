let systemInfo = null;

async function loadSystemInfo() {
    try {
        const response = await fetch('/api/local-ip');
        const data = await response.json();
        
        // Store globally
        systemInfo = data;
        
        // Update stats - pastikan element ada
        const hostnameEl = document.getElementById('statHostname');
        const ipEl = document.getElementById('statIP');
        const networkEl = document.getElementById('statNetwork');
        const networkInput = document.getElementById('networkTarget');
        
        if (hostnameEl) hostnameEl.textContent = data.hostname;
        if (ipEl) ipEl.textContent = data.local_ip;
        if (networkEl) networkEl.textContent = data.suggested_network;
        if (networkInput) networkInput.value = data.suggested_network;
        
        // Update navbar
        const navInfo = document.getElementById('navInfo');
        if (navInfo) {
            navInfo.innerHTML = `
                <div class="info-badge">
                    <i class="fas fa-circle" style="color: var(--success);"></i>
                    <span>System Ready</span>
                </div>
                <div class="info-badge">
                    <i class="fas fa-clock"></i>
                    <span>${new Date().toLocaleTimeString()}</span>
                </div>
            `;
        }
        
        console.log('[AUTO-DETECT] Stats updated successfully');
        
    } catch (error) {
        console.error('[AUTO-DETECT] Error:', error);
        
        // Fallback - set manual defaults
        const networkInput = document.getElementById('networkTarget');
        if (networkInput && !networkInput.value) {
            networkInput.value = '192.168.1.0/24';
        }
    }
}

// Initialize saat page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadSystemInfo);
} else {
    loadSystemInfo();
}
