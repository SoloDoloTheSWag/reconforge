// ReconForge WebSocket Client

class ReconForgeWebSocket {
    constructor(url = null) {
        this.url = url || this.getWebSocketURL();
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectInterval = 5000;
        this.heartbeatInterval = 30000;
        this.heartbeatTimer = null;
        this.connected = false;
        this.subscribers = new Map();
        
        // Bind methods
        this.connect = this.connect.bind(this);
        this.disconnect = this.disconnect.bind(this);
        this.send = this.send.bind(this);
        this.onOpen = this.onOpen.bind(this);
        this.onMessage = this.onMessage.bind(this);
        this.onClose = this.onClose.bind(this);
        this.onError = this.onError.bind(this);
    }
    
    /**
     * Get WebSocket URL based on current location
     */
    getWebSocketURL() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        return `${protocol}//${host}/ws`;
    }
    
    /**
     * Connect to WebSocket server
     */
    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            console.log('WebSocket already connected');
            return;
        }
        
        console.log(`Connecting to WebSocket: ${this.url}`);
        
        try {
            this.ws = new WebSocket(this.url);
            this.ws.onopen = this.onOpen;
            this.ws.onmessage = this.onMessage;
            this.ws.onclose = this.onClose;
            this.ws.onerror = this.onError;
        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
            this.scheduleReconnect();
        }
    }
    
    /**
     * Disconnect from WebSocket server
     */
    disconnect() {
        this.connected = false;
        this.clearHeartbeat();
        
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        
        console.log('WebSocket disconnected');
        this.updateConnectionStatus(false);
    }
    
    /**
     * Send message to WebSocket server
     */
    send(message) {
        if (!this.connected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
            console.warn('WebSocket not connected, cannot send message:', message);
            return false;
        }
        
        try {
            const payload = typeof message === 'string' ? message : JSON.stringify(message);
            this.ws.send(payload);
            return true;
        } catch (error) {
            console.error('Failed to send WebSocket message:', error);
            return false;
        }
    }
    
    /**
     * Subscribe to specific message types
     */
    subscribe(messageType, callback) {
        if (!this.subscribers.has(messageType)) {
            this.subscribers.set(messageType, new Set());
        }
        
        this.subscribers.get(messageType).add(callback);
        
        // Return unsubscribe function
        return () => {
            const callbacks = this.subscribers.get(messageType);
            if (callbacks) {
                callbacks.delete(callback);
                if (callbacks.size === 0) {
                    this.subscribers.delete(messageType);
                }
            }
        };
    }
    
    /**
     * WebSocket open event handler
     */
    onOpen(event) {
        console.log('WebSocket connected successfully');
        this.connected = true;
        this.reconnectAttempts = 0;
        this.updateConnectionStatus(true);
        this.startHeartbeat();
        
        // Notify subscribers
        this.notifySubscribers('connection', {
            type: 'connected',
            event: event
        });
    }
    
    /**
     * WebSocket message event handler
     */
    onMessage(event) {
        try {
            const data = JSON.parse(event.data);
            console.log('WebSocket message received:', data);
            
            // Handle system messages
            if (data.type === 'pong') {
                // Heartbeat response
                return;
            }
            
            // Notify global message handlers
            this.notifySubscribers('message', data);
            
            // Notify specific message type handlers
            if (data.type) {
                this.notifySubscribers(data.type, data);
            }
            
            // Call global message handler if available
            if (window.handleWebSocketMessage && typeof window.handleWebSocketMessage === 'function') {
                window.handleWebSocketMessage(data);
            }
            
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    }
    
    /**
     * WebSocket close event handler
     */
    onClose(event) {
        console.log('WebSocket connection closed:', event.code, event.reason);
        this.connected = false;
        this.clearHeartbeat();
        this.updateConnectionStatus(false);
        
        // Notify subscribers
        this.notifySubscribers('connection', {
            type: 'disconnected',
            event: event
        });
        
        // Schedule reconnect if not intentional close
        if (event.code !== 1000) {
            this.scheduleReconnect();
        }
    }
    
    /**
     * WebSocket error event handler
     */
    onError(event) {
        console.error('WebSocket error:', event);
        
        // Notify subscribers
        this.notifySubscribers('connection', {
            type: 'error',
            event: event
        });
    }
    
    /**
     * Schedule reconnection attempt
     */
    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }
        
        this.reconnectAttempts++;
        const delay = this.reconnectInterval * Math.pow(2, this.reconnectAttempts - 1); // Exponential backoff
        
        console.log(`Scheduling reconnect attempt ${this.reconnectAttempts} in ${delay}ms`);
        
        setTimeout(() => {
            if (!this.connected) {
                this.connect();
            }
        }, delay);
    }
    
    /**
     * Start heartbeat to keep connection alive
     */
    startHeartbeat() {
        this.clearHeartbeat();
        
        this.heartbeatTimer = setInterval(() => {
            if (this.connected) {
                this.send({ type: 'ping' });
            }
        }, this.heartbeatInterval);
    }
    
    /**
     * Clear heartbeat timer
     */
    clearHeartbeat() {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
        }
    }
    
    /**
     * Notify subscribers of message
     */
    notifySubscribers(messageType, data) {
        const callbacks = this.subscribers.get(messageType);
        if (callbacks) {
            callbacks.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error('Error in WebSocket subscriber callback:', error);
                }
            });
        }
    }
    
    /**
     * Update connection status UI
     */
    updateConnectionStatus(connected) {
        // Update connection status indicator
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            if (connected) {
                statusElement.classList.add('d-none');
            } else {
                statusElement.classList.remove('d-none');
            }
        }
        
        // Update WebSocket status badge if available
        if (window.updateWebSocketStatus && typeof window.updateWebSocketStatus === 'function') {
            window.updateWebSocketStatus(connected);
        }
        
        // Update global connection state
        window.wsConnected = connected;
    }
    
    /**
     * Get connection status
     */
    isConnected() {
        return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN;
    }
    
    /**
     * Get ready state
     */
    getReadyState() {
        return this.ws ? this.ws.readyState : WebSocket.CLOSED;
    }
    
    /**
     * Subscribe to scan updates
     */
    subscribeScanUpdates(scanUuid, callback) {
        // Subscribe to all scan-related events
        const scanEvents = [
            'scan_update',
            'scan_complete',
            'scan_error',
            'subdomain_found',
            'vulnerability_found',
            'pentest_result'
        ];
        
        const unsubscribeFunctions = scanEvents.map(eventType => {
            return this.subscribe(eventType, (data) => {
                if (data.scan_uuid === scanUuid) {
                    callback(eventType, data);
                }
            });
        });
        
        // Send subscription message to server
        this.send({
            type: 'subscribe',
            scan_uuid: scanUuid
        });
        
        // Return function to unsubscribe from all events
        return () => {
            unsubscribeFunctions.forEach(unsub => unsub());
        };
    }
}

// Global WebSocket instance
let wsInstance = null;

/**
 * Initialize WebSocket connection
 */
function initWebSocket(url = null) {
    if (wsInstance) {
        wsInstance.disconnect();
    }
    
    wsInstance = new ReconForgeWebSocket(url);
    wsInstance.connect();
    
    // Make instance available globally
    window.ws = wsInstance;
    
    return wsInstance;
}

/**
 * Get WebSocket instance
 */
function getWebSocket() {
    return wsInstance;
}

/**
 * Send WebSocket message
 */
function sendMessage(message) {
    if (wsInstance) {
        return wsInstance.send(message);
    }
    return false;
}

/**
 * Subscribe to WebSocket messages
 */
function subscribeToMessages(messageType, callback) {
    if (wsInstance) {
        return wsInstance.subscribe(messageType, callback);
    }
    return () => {};
}

/**
 * Subscribe to scan updates
 */
function subscribeScanUpdates(scanUuid, callback) {
    if (wsInstance) {
        return wsInstance.subscribeScanUpdates(scanUuid, callback);
    }
    return () => {};
}

// Handle page visibility changes
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        // Page is hidden, reduce reconnection attempts
        if (wsInstance) {
            wsInstance.maxReconnectAttempts = 2;
        }
    } else {
        // Page is visible, restore normal reconnection behavior
        if (wsInstance) {
            wsInstance.maxReconnectAttempts = 5;
            
            // Reconnect if disconnected
            if (!wsInstance.isConnected()) {
                wsInstance.connect();
            }
        }
    }
});

// Handle page unload
window.addEventListener('beforeunload', function() {
    if (wsInstance) {
        wsInstance.disconnect();
    }
});

// Export for module usage
window.ReconForgeWS = {
    initWebSocket,
    getWebSocket,
    sendMessage,
    subscribeToMessages,
    subscribeScanUpdates,
    ReconForgeWebSocket
};