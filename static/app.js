// Main JavaScript functionality for Secret Journal Manager

// Global variables
let calendar;
let toastTimeout;

// Document ready
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

// Initialize application
function initializeApp() {
    initializeTooltips();
    initializePopovers();
    setupPasswordToggles();
    setupFormValidation();
    setupAutoSave();
    setupCopyToClipboard();
    animateElements();
}

// Initialize Bootstrap tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Initialize Bootstrap popovers
function initializePopovers() {
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Setup password visibility toggles
function setupPasswordToggles() {
    document.querySelectorAll('.password-toggle').forEach(toggle => {
        toggle.addEventListener('click', function() {
            const input = this.previousElementSibling;
            const icon = this.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });
    });
}

// Setup form validation
function setupFormValidation() {
    // Password confirmation validation
    const passwordForms = document.querySelectorAll('form[id*="password"], form[id*="register"], form[id*="reset"]');
    passwordForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const password = this.querySelector('input[name="password"]');
            const confirmPassword = this.querySelector('input[name="confirm_password"]');
            
            if (password && confirmPassword && password.value !== confirmPassword.value) {
                e.preventDefault();
                showToast('Passwords do not match!', 'error');
                confirmPassword.focus();
                return false;
            }
        });
    });
    
    // Real-time password strength indicator
    const passwordInputs = document.querySelectorAll('input[type="password"][name="password"]');
    passwordInputs.forEach(input => {
        input.addEventListener('input', function() {
            updatePasswordStrength(this);
        });
    });
}

// Password strength indicator
function updatePasswordStrength(input) {
    const password = input.value;
    const strengthIndicator = input.parentElement.querySelector('.password-strength');
    
    if (!strengthIndicator) return;
    
    let strength = 0;
    let feedback = '';
    
    // Length check
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    
    // Character variety checks
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    // Update indicator
    strengthIndicator.className = 'password-strength';
    if (strength < 3) {
        strengthIndicator.classList.add('weak');
        feedback = 'Weak';
    } else if (strength < 5) {
        strengthIndicator.classList.add('medium');
        feedback = 'Medium';
    } else {
        strengthIndicator.classList.add('strong');
        feedback = 'Strong';
    }
    
    strengthIndicator.textContent = feedback;
}

// Setup auto-save functionality
function setupAutoSave() {
    const autosaveElements = document.querySelectorAll('[data-autosave]');
    autosaveElements.forEach(element => {
        let saveTimeout;
        
        element.addEventListener('input', function() {
            clearTimeout(saveTimeout);
            const indicator = document.getElementById('autosave-indicator');
            
            if (indicator) {
                indicator.textContent = 'Saving...';
                indicator.className = 'text-warning';
            }
            
            saveTimeout = setTimeout(() => {
                autoSaveContent(this);
            }, 2000);
        });
    });
}

// Auto-save content to localStorage
function autoSaveContent(element) {
    const key = element.getAttribute('data-autosave');
    const value = element.value;
    
    try {
        localStorage.setItem(`autosave_${key}`, value);
        
        const indicator = document.getElementById('autosave-indicator');
        if (indicator) {
            indicator.textContent = 'Saved';
            indicator.className = 'text-success';
            
            setTimeout(() => {
                indicator.textContent = '';
            }, 2000);
        }
    } catch (error) {
        console.error('Auto-save failed:', error);
    }
}

// Restore auto-saved content
function restoreAutoSavedContent() {
    const autosaveElements = document.querySelectorAll('[data-autosave]');
    autosaveElements.forEach(element => {
        const key = element.getAttribute('data-autosave');
        const saved = localStorage.getItem(`autosave_${key}`);
        
        if (saved && !element.value) {
            element.value = saved;
            showToast('Draft restored from auto-save', 'info');
        }
    });
}

// Copy to clipboard functionality
function setupCopyToClipboard() {
    document.addEventListener('click', function(e) {
        if (e.target.matches('[data-copy]') || e.target.closest('[data-copy]')) {
            const button = e.target.matches('[data-copy]') ? e.target : e.target.closest('[data-copy]');
            const text = button.getAttribute('data-copy');
            copyToClipboard(text);
        }
    });
}

// Copy text to clipboard
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Failed to copy:', err);
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

// Fallback copy method
function fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showToast('Copied to clipboard!', 'success');
    } catch (err) {
        console.error('Fallback copy failed:', err);
        showToast('Copy failed', 'error');
    }
    
    document.body.removeChild(textArea);
}

// Show toast notification
function showToast(message, type = 'info') {
    // Remove existing toast
    const existingToast = document.querySelector('.toast-notification');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create new toast
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    
    const icon = getToastIcon(type);
    toast.innerHTML = `${icon} ${message}`;
    
    document.body.appendChild(toast);
    
    // Auto-remove after 3 seconds
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 3000);
    
    // Click to dismiss
    toast.addEventListener('click', function() {
        this.remove();
    });
}

// Get icon for toast type
function getToastIcon(type) {
    const icons = {
        success: '<i class="fas fa-check-circle"></i>',
        error: '<i class="fas fa-exclamation-circle"></i>',
        warning: '<i class="fas fa-exclamation-triangle"></i>',
        info: '<i class="fas fa-info-circle"></i>'
    };
    return icons[type] || icons.info;
}

// Animate elements on scroll
function animateElements() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1
    });
    
    document.querySelectorAll('.card, .alert, .btn-group').forEach(el => {
        observer.observe(el);
    });
}

// Modal enhancements
function enhanceModals() {
    // Auto-focus first input in modals
    document.addEventListener('shown.bs.modal', function(e) {
        const firstInput = e.target.querySelector('input:not([type="hidden"]), textarea, select');
        if (firstInput) {
            firstInput.focus();
        }
    });
    
    // Clear form data when modal is hidden
    document.addEventListener('hidden.bs.modal', function(e) {
        const form = e.target.querySelector('form');
        if (form && form.hasAttribute('data-clear-on-hide')) {
            form.reset();
        }
    });
}

// Calendar functionality
function initializeCalendar() {
    const calendarEl = document.getElementById('calendar');
    if (!calendarEl) return;
    
    calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        height: 600,
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,listWeek'
        },
        dateClick: function(info) {
            window.location.href = `/journal/entry?date=${info.dateStr}`;
        },
        eventClick: function(info) {
            window.location.href = `/journal/entry?date=${info.event.startStr}`;
        },
        dayMaxEvents: 1,
        moreLinkClick: 'day',
        eventDisplay: 'block',
        loading: function(isLoading) {
            if (isLoading) {
                showToast('Loading calendar...', 'info');
            }
        }
    });
    
    calendar.render();
}

// Word count functionality
function setupWordCount() {
    const textareas = document.querySelectorAll('textarea[data-word-count]');
    textareas.forEach(textarea => {
        const updateWordCount = () => {
            const words = textarea.value.trim().split(/\s+/).filter(word => word.length > 0);
            const count = words.length;
            const target = document.getElementById(textarea.getAttribute('data-word-count'));
            if (target) {
                target.textContent = count;
            }
        };
        
        textarea.addEventListener('input', updateWordCount);
        updateWordCount(); // Initial count
    });
}

// Form submission with loading state
function setupFormSubmission() {
    document.addEventListener('submit', function(e) {
        const form = e.target;
        const submitButton = form.querySelector('button[type="submit"]');
        
        if (submitButton && !submitButton.hasAttribute('data-no-loading')) {
            const originalText = submitButton.innerHTML;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
            submitButton.disabled = true;
            submitButton.classList.add('btn-loading');
            
            // Re-enable after 10 seconds as fallback
            setTimeout(() => {
                submitButton.innerHTML = originalText;
                submitButton.disabled = false;
                submitButton.classList.remove('btn-loading');
            }, 10000);
        }
    });
}

// Search functionality
function setupSearch() {
    const searchInputs = document.querySelectorAll('[data-search]');
    searchInputs.forEach(input => {
        input.addEventListener('input', function() {
            const target = document.querySelector(this.getAttribute('data-search'));
            const query = this.value.toLowerCase();
            
            if (target) {
                const items = target.querySelectorAll('[data-searchable]');
                items.forEach(item => {
                    const text = item.textContent.toLowerCase();
                    if (text.includes(query)) {
                        item.style.display = '';
                    } else {
                        item.style.display = 'none';
                    }
                });
            }
        });
    });
}

// Keyboard shortcuts
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + S for save
        if ((e.ctrlKey || e.metaKey) && e.key === 's') {
            e.preventDefault();
            const saveButton = document.querySelector('button[type="submit"], .btn-save');
            if (saveButton) {
                saveButton.click();
            }
        }
        
        // Ctrl/Cmd + K for search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.querySelector('input[type="search"], [data-search]');
            if (searchInput) {
                searchInput.focus();
            }
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            const openModal = document.querySelector('.modal.show');
            if (openModal) {
                const modal = bootstrap.Modal.getInstance(openModal);
                if (modal) {
                    modal.hide();
                }
            }
        }
    });
}

// Utility functions
const Utils = {
    // Debounce function
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    // Format date
    formatDate: function(date) {
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        }).format(new Date(date));
    },
    
    // Format file size
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    // Generate random string
    generateRandomString: function(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }
};

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    enhanceModals();
    initializeCalendar();
    setupWordCount();
    setupFormSubmission();
    setupSearch();
    setupKeyboardShortcuts();
    restoreAutoSavedContent();
});

// Export for use in other scripts
window.SecretJournal = {
    showToast,
    copyToClipboard,
    Utils
};
