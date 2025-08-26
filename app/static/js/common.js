// ReconForge Common JavaScript Functions

// Global variables
let alertTimeout;

/**
 * Show alert message to user
 * @param {string} type - Alert type (success, error, warning, info)
 * @param {string} message - Alert message
 * @param {number} duration - Auto-dismiss duration in ms (0 = no auto-dismiss)
 */
function showAlert(type, message, duration = 5000) {
    const alertContainer = document.getElementById('alertContainer');
    const alertId = 'alert-' + Date.now();
    
    // Map types to Bootstrap classes
    const typeMap = {
        'success': 'alert-success',
        'error': 'alert-danger',
        'warning': 'alert-warning',
        'info': 'alert-info'
    };
    
    const iconMap = {
        'success': 'bi-check-circle',
        'error': 'bi-exclamation-triangle',
        'warning': 'bi-exclamation-triangle',
        'info': 'bi-info-circle'
    };
    
    const alertClass = typeMap[type] || 'alert-info';
    const alertIcon = iconMap[type] || 'bi-info-circle';
    
    const alertHtml = `
        <div id="${alertId}" class="alert ${alertClass} alert-dismissible fade show" role="alert">
            <i class="bi ${alertIcon}"></i>
            <span class="ms-2">${message}</span>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    alertContainer.insertAdjacentHTML('beforeend', alertHtml);
    
    // Auto-dismiss after specified duration
    if (duration > 0) {
        setTimeout(() => {
            const alertElement = document.getElementById(alertId);
            if (alertElement) {
                const alert = new bootstrap.Alert(alertElement);
                alert.close();
            }
        }, duration);
    }
}

/**
 * Show loading spinner in element
 * @param {string|Element} element - Element ID or element object
 * @param {string} message - Loading message
 */
function showLoading(element, message = 'Loading...') {
    const el = typeof element === 'string' ? document.getElementById(element) : element;
    if (!el) return;
    
    el.innerHTML = `
        <div class="text-center p-4">
            <div class="loading-spinner"></div>
            <div class="mt-2">${message}</div>
        </div>
    `;
}

/**
 * Format timestamp for display
 * @param {string} timestamp - ISO timestamp string
 * @param {boolean} includeTime - Include time portion
 * @returns {string} Formatted timestamp
 */
function formatTimestamp(timestamp, includeTime = true) {
    if (!timestamp) return 'N/A';
    
    const date = new Date(timestamp);
    const options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    };
    
    if (includeTime) {
        options.hour = '2-digit';
        options.minute = '2-digit';
    }
    
    return date.toLocaleDateString('en-US', options);
}

/**
 * Format duration in seconds to human readable format
 * @param {number} seconds - Duration in seconds
 * @returns {string} Formatted duration
 */
function formatDuration(seconds) {
    if (!seconds || seconds < 1) return '0s';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    let result = '';
    if (hours > 0) result += `${hours}h `;
    if (minutes > 0) result += `${minutes}m `;
    if (secs > 0) result += `${secs}s`;
    
    return result.trim();
}

/**
 * Format file size to human readable format
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size
 */
function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    
    const units = ['B', 'KB', 'MB', 'GB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
}

/**
 * Validate domain name
 * @param {string} domain - Domain to validate
 * @returns {boolean} True if valid
 */
function validateDomain(domain) {
    if (!domain || domain.length === 0) return false;
    
    // Remove protocol if present
    domain = domain.replace(/^https?:\/\//, '');
    
    // Basic domain regex
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.([a-zA-Z]{2,}\.?)+$/;
    return domainRegex.test(domain);
}

/**
 * Validate URL
 * @param {string} url - URL to validate
 * @returns {boolean} True if valid
 */
function validateURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @param {string} successMessage - Success message to show
 */
async function copyToClipboard(text, successMessage = 'Copied to clipboard!') {
    try {
        await navigator.clipboard.writeText(text);
        showAlert('success', successMessage, 2000);
    } catch (error) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            showAlert('success', successMessage, 2000);
        } catch (fallbackError) {
            showAlert('error', 'Failed to copy to clipboard');
        }
        
        document.body.removeChild(textArea);
    }
}

/**
 * Download data as file
 * @param {string} data - Data to download
 * @param {string} filename - Filename
 * @param {string} mimeType - MIME type
 */
function downloadData(data, filename, mimeType = 'text/plain') {
    const blob = new Blob([data], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

/**
 * Debounce function execution
 * @param {Function} func - Function to debounce
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, delay) {
    let timeoutId;
    return function (...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
}

/**
 * Throttle function execution
 * @param {Function} func - Function to throttle
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, delay) {
    let lastCall = 0;
    return function (...args) {
        const now = Date.now();
        if (now - lastCall >= delay) {
            lastCall = now;
            return func.apply(this, args);
        }
    };
}

/**
 * Format vulnerability severity for display
 * @param {string} severity - Severity level
 * @returns {Object} Object with class and icon
 */
function formatSeverity(severity) {
    const severityMap = {
        'critical': { class: 'badge bg-danger', icon: 'bi-exclamation-triangle-fill' },
        'high': { class: 'badge bg-warning', icon: 'bi-exclamation-triangle' },
        'medium': { class: 'badge bg-info', icon: 'bi-info-circle' },
        'low': { class: 'badge bg-secondary', icon: 'bi-dash-circle' },
        'info': { class: 'badge bg-light text-dark', icon: 'bi-info-circle' }
    };
    
    return severityMap[severity.toLowerCase()] || severityMap['info'];
}

/**
 * Create progress bar HTML
 * @param {number} percentage - Progress percentage (0-100)
 * @param {string} type - Bootstrap progress type (primary, success, etc.)
 * @param {boolean} striped - Show striped animation
 * @returns {string} Progress bar HTML
 */
function createProgressBar(percentage, type = 'primary', striped = false) {
    const stripedClass = striped ? 'progress-bar-striped progress-bar-animated' : '';
    return `
        <div class="progress">
            <div class="progress-bar bg-${type} ${stripedClass}" 
                 role="progressbar" 
                 style="width: ${percentage}%"
                 aria-valuenow="${percentage}" 
                 aria-valuemin="0" 
                 aria-valuemax="100">
                ${percentage}%
            </div>
        </div>
    `;
}

/**
 * Create status badge HTML
 * @param {string} status - Status text
 * @param {string} type - Badge type (success, danger, warning, etc.)
 * @param {string} icon - Bootstrap icon class
 * @returns {string} Badge HTML
 */
function createStatusBadge(status, type, icon = null) {
    const iconHtml = icon ? `<i class="bi ${icon}"></i> ` : '';
    return `<span class="badge bg-${type}">${iconHtml}${status}</span>`;
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Parse query string parameters
 * @param {string} queryString - Query string to parse
 * @returns {Object} Parsed parameters
 */
function parseQueryString(queryString = window.location.search) {
    const params = {};
    const searchParams = new URLSearchParams(queryString);
    
    for (const [key, value] of searchParams) {
        params[key] = value;
    }
    
    return params;
}

/**
 * Build query string from object
 * @param {Object} params - Parameters object
 * @returns {string} Query string
 */
function buildQueryString(params) {
    const searchParams = new URLSearchParams();
    
    for (const [key, value] of Object.entries(params)) {
        if (value !== null && value !== undefined && value !== '') {
            searchParams.append(key, value);
        }
    }
    
    return searchParams.toString();
}

/**
 * Get CSRF token from meta tag
 * @returns {string|null} CSRF token
 */
function getCSRFToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    return metaTag ? metaTag.getAttribute('content') : null;
}

/**
 * Make authenticated API request
 * @param {string} url - Request URL
 * @param {Object} options - Fetch options
 * @returns {Promise} Fetch promise
 */
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    // Add CSRF token if available
    const csrfToken = getCSRFToken();
    if (csrfToken) {
        defaultOptions.headers['X-CSRF-Token'] = csrfToken;
    }
    
    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers,
        },
    };
    
    try {
        const response = await fetch(url, mergedOptions);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return response;
    } catch (error) {
        console.error('API request failed:', error);
        showAlert('error', `Request failed: ${error.message}`);
        throw error;
    }
}

/**
 * Initialize tooltips
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Initialize popovers
 */
function initPopovers() {
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

/**
 * Initialize common UI components
 */
function initializeUI() {
    initTooltips();
    initPopovers();
}

// Initialize UI components when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeUI();
});

// Export functions for module usage
window.ReconForge = {
    showAlert,
    showLoading,
    formatTimestamp,
    formatDuration,
    formatFileSize,
    validateDomain,
    validateURL,
    copyToClipboard,
    downloadData,
    debounce,
    throttle,
    formatSeverity,
    createProgressBar,
    createStatusBadge,
    escapeHtml,
    parseQueryString,
    buildQueryString,
    apiRequest,
    initializeUI
};