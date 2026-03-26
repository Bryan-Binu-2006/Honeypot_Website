/* CyberShield - Main JavaScript */

// API Helper
const api = {
    async get(url) {
        const response = await fetch(url);
        return response.json();
    },
    
    async post(url, data) {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        return response.json();
    },
    
    async postForm(url, formData) {
        const response = await fetch(url, {
            method: 'POST',
            body: formData
        });
        return response.json();
    }
};

// Notification system
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 2rem;
        border-radius: 5px;
        background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#00d4ff'};
        color: white;
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Terminal functionality
class Terminal {
    constructor(outputElement, inputElement) {
        this.output = outputElement;
        this.input = inputElement;
        this.history = [];
        this.historyIndex = -1;
        
        this.init();
    }
    
    init() {
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.execute();
            } else if (e.key === 'ArrowUp') {
                this.navigateHistory(-1);
            } else if (e.key === 'ArrowDown') {
                this.navigateHistory(1);
            }
        });
    }
    
    async execute() {
        const cmd = this.input.value.trim();
        if (!cmd) return;
        
        this.history.push(cmd);
        this.historyIndex = this.history.length;
        
        this.print(`$ ${cmd}`);
        this.input.value = '';
        
        try {
            const response = await api.post('/terminal/exec', { cmd });
            this.print(response.output);
        } catch (error) {
            this.print(`Error: ${error.message}`, 'error');
        }
        
        this.print('$ ', false);
    }
    
    print(text, newline = true) {
        this.output.innerHTML += text + (newline ? '\n' : '');
        this.output.scrollTop = this.output.scrollHeight;
    }
    
    navigateHistory(direction) {
        this.historyIndex += direction;
        this.historyIndex = Math.max(0, Math.min(this.history.length, this.historyIndex));
        this.input.value = this.history[this.historyIndex] || '';
    }
}

// File browser functionality
class FileBrowser {
    constructor(container) {
        this.container = container;
        this.currentPath = '/';
    }
    
    async browse(path) {
        try {
            const response = await api.get(`/files/browse?path=${encodeURIComponent(path)}`);
            this.currentPath = path;
            this.render(response);
        } catch (error) {
            showNotification('Error loading files', 'error');
        }
    }
    
    render(data) {
        let html = `<div class="file-browser">`;
        html += `<div class="path-bar">${this.currentPath}</div>`;
        html += `<ul class="file-list">`;
        
        if (this.currentPath !== '/') {
            html += `<li class="file-item folder" onclick="fileBrowser.browse('${this.getParentPath()}')">📁 ..</li>`;
        }
        
        for (const item of data.files) {
            const isDir = !item.includes('.');
            const icon = isDir ? '📁' : '📄';
            const newPath = this.currentPath === '/' ? `/${item}` : `${this.currentPath}/${item}`;
            
            if (isDir) {
                html += `<li class="file-item folder" onclick="fileBrowser.browse('${newPath}')">${icon} ${item}</li>`;
            } else {
                html += `<li class="file-item file" onclick="fileBrowser.viewFile('${newPath}')">${icon} ${item}</li>`;
            }
        }
        
        html += `</ul></div>`;
        this.container.innerHTML = html;
    }
    
    getParentPath() {
        const parts = this.currentPath.split('/').filter(p => p);
        parts.pop();
        return '/' + parts.join('/');
    }
    
    async viewFile(path) {
        try {
            const response = await api.get(`/files/read?path=${encodeURIComponent(path)}`);
            showFileModal(path, response.content);
        } catch (error) {
            showNotification('Error reading file', 'error');
        }
    }
}

function showFileModal(filename, content) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.8);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999;
    `;
    
    modal.innerHTML = `
        <div class="modal-content" style="background: #1a1a2e; padding: 2rem; border-radius: 10px; max-width: 800px; max-height: 80vh; overflow: auto;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <h3 style="color: #00d4ff;">${filename}</h3>
                <button onclick="this.closest('.modal').remove()" style="background: transparent; border: none; color: #fff; font-size: 1.5rem; cursor: pointer;">&times;</button>
            </div>
            <pre style="background: #0d0d0d; padding: 1rem; border-radius: 5px; overflow-x: auto; color: #00ff00;">${escapeHtml(content)}</pre>
        </div>
    `;
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
    
    document.body.appendChild(modal);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Initialize terminal if present
    const termOutput = document.getElementById('terminal-output');
    const termInput = document.getElementById('terminal-input');
    if (termOutput && termInput) {
        window.terminal = new Terminal(termOutput, termInput);
    }
    
    // Initialize file browser if present
    const fileBrowserEl = document.getElementById('file-browser');
    if (fileBrowserEl) {
        window.fileBrowser = new FileBrowser(fileBrowserEl);
        fileBrowser.browse('/');
    }
});
