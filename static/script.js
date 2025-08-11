// Additional JavaScript functionality for Secret Journal Manager

// Global variables
let secretVisibility = {};
let autoSaveTimer = null;

// Initialize additional functionality
document.addEventListener('DOMContentLoaded', function() {
    initializeSecretToggles();
    initializePasswordStrength();
    initializeAutoComplete();
    initializeSecretManagement();
    initializeRecoveryHelpers();
    setupAdvancedSearch();
});

// Secret visibility toggles
function initializeSecretToggles() {
    document.querySelectorAll('.secret-toggle').forEach(button => {
        button.addEventListener('click', function() {
            const secretId = this.getAttribute('data-secret-id');
            toggleSecretVisibility(secretId);
        });
    });
}

function toggleSecretVisibility(secretId) {
    const input = document.getElementById(`secret-${secretId}`);
    const icon = document.getElementById(`eye-${secretId}`);
    
    if (!input || !icon) return;
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
        secretVisibility[secretId] = true;
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
        secretVisibility[secretId] = false;
    }
    
    // Auto-hide after 5 seconds for security
    if (secretVisibility[secretId]) {
        setTimeout(() => {
            if (secretVisibility[secretId]) {
                input.type = 'password';
                icon.className = 'fas fa-eye';
                secretVisibility[secretId] = false;
            }
        }, 5000);
    }
}

// Password strength indicator
function initializePasswordStrength() {
    const passwordInputs = document.querySelectorAll('input[type="password"][name="password"]');
    passwordInputs.forEach(input => {
        const strengthDiv = createPasswordStrengthIndicator(input);
        input.parentNode.insertBefore(strengthDiv, input.nextSibling);
        
        input.addEventListener('input', function() {
            updatePasswordStrengthIndicator(this, strengthDiv);
        });
    });
}

function createPasswordStrengthIndicator(input) {
    const div = document.createElement('div');
    div.className = 'password-strength-indicator mt-1';
    div.innerHTML = `
        <div class="strength-bar">
            <div class="strength-fill"></div>
        </div>
        <small class="strength-text text-muted"></small>
    `;
    return div;
}

function updatePasswordStrengthIndicator(input, indicator) {
    const password = input.value;
    const strengthBar = indicator.querySelector('.strength-fill');
    const strengthText = indicator.querySelector('.strength-text');
    
    let score = 0;
    let feedback = [];
    
    // Length checks
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    
    // Character variety
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    // Common password check
    const common = ['password', '123456', 'qwerty', 'abc123'];
    if (common.includes(password.toLowerCase())) score = Math.max(0, score - 2);
    
    // Update visual indicator
    const percentage = (score / 6) * 100;
    strengthBar.style.width = `${percentage}%`;
    
    let strengthLevel = 'Very Weak';
    let colorClass = 'bg-danger';
    
    if (score >= 5) {
        strengthLevel = 'Very Strong';
        colorClass = 'bg-success';
    } else if (score >= 4) {
        strengthLevel = 'Strong';
        colorClass = 'bg-info';
    } else if (score >= 3) {
        strengthLevel = 'Good';
        colorClass = 'bg-warning';
    } else if (score >= 2) {
        strengthLevel = 'Fair';
        colorClass = 'bg-warning';
    }
    
    strengthBar.className = `strength-fill ${colorClass}`;
    strengthText.textContent = strengthLevel;
}

// Auto-complete for common fields
function initializeAutoComplete() {
    // Common website URLs for password entries
    const commonSites = [
        'gmail.com', 'outlook.com', 'facebook.com', 'twitter.com',
        'linkedin.com', 'github.com', 'stackoverflow.com', 'amazon.com',
        'netflix.com', 'spotify.com', 'dropbox.com', 'google.com'
    ];
    
    const urlInputs = document.querySelectorAll('input[name="url"]');
    urlInputs.forEach(input => {
        input.addEventListener('input', function() {
            const value = this.value.toLowerCase();
            if (value.length > 2) {
                const matches = commonSites.filter(site => site.includes(value));
                if (matches.length > 0 && !value.includes('://')) {
                    // Show suggestion
                    showAutoCompleteSuggestion(this, `https://${matches[0]}`);
                }
            }
        });
    });
}

function showAutoCompleteSuggestion(input, suggestion) {
    // Remove existing suggestions
    const existingSuggestion = input.parentNode.querySelector('.autocomplete-suggestion');
    if (existingSuggestion) {
        existingSuggestion.remove();
    }
    
    const suggestionDiv = document.createElement('div');
    suggestionDiv.className = 'autocomplete-suggestion';
    suggestionDiv.innerHTML = `
        <small class="text-muted">
            Did you mean: <a href="#" class="text-decoration-none">${suggestion}</a>?
        </small>
    `;
    
    suggestionDiv.querySelector('a').addEventListener('click', function(e) {
        e.preventDefault();
        input.value = suggestion;
        suggestionDiv.remove();
    });
    
    input.parentNode.insertBefore(suggestionDiv, input.nextSibling);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (suggestionDiv.parentNode) {
            suggestionDiv.remove();
        }
    }, 5000);
}

// Enhanced secret management
function initializeSecretManagement() {
    // Secret type icons
    const secretTypeSelect = document.getElementById('secret_type');
    if (secretTypeSelect) {
        secretTypeSelect.addEventListener('change', function() {
            updateSecretTypeIcon(this.value);
            toggleFieldsBasedOnType(this.value);
        });
    }
    
    // Bulk operations
    setupBulkOperations();
    
    // Secret generation
    setupSecretGeneration();
}

function updateSecretTypeIcon(type) {
    const icons = {
        'password': 'fas fa-key',
        'api_key': 'fas fa-code',
        'note': 'fas fa-sticky-note',
        'card': 'fas fa-credit-card',
        'other': 'fas fa-file'
    };
    
    const icon = document.querySelector('.secret-type-icon');
    if (icon) {
        icon.className = `secret-type-icon ${icons[type] || icons.other}`;
    }
}

function toggleFieldsBasedOnType(type) {
    const urlField = document.getElementById('url')?.parentElement;
    const usernameField = document.getElementById('username')?.parentElement;
    
    if (urlField && usernameField) {
        if (type === 'password') {
            urlField.style.display = 'block';
            usernameField.style.display = 'block';
        } else if (type === 'api_key') {
            urlField.style.display = 'block';
            usernameField.style.display = 'none';
        } else {
            urlField.style.display = 'none';
            usernameField.style.display = 'none';
        }
    }
}

function setupBulkOperations() {
    const selectAllCheckbox = document.getElementById('select-all-secrets');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('.secret-checkbox');
            checkboxes.forEach(cb => cb.checked = this.checked);
            updateBulkActionButtons();
        });
    }
    
    // Individual checkboxes
    document.querySelectorAll('.secret-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', updateBulkActionButtons);
    });
}

function updateBulkActionButtons() {
    const selectedCount = document.querySelectorAll('.secret-checkbox:checked').length;
    const bulkActions = document.querySelector('.bulk-actions');
    
    if (bulkActions) {
        if (selectedCount > 0) {
            bulkActions.style.display = 'block';
            bulkActions.querySelector('.selected-count').textContent = selectedCount;
        } else {
            bulkActions.style.display = 'none';
        }
    }
}

function setupSecretGeneration() {
    const generateButton = document.getElementById('generate-password');
    if (generateButton) {
        generateButton.addEventListener('click', function() {
            const password = generateSecurePassword();
            const contentField = document.getElementById('content');
            if (contentField) {
                contentField.value = password;
                contentField.dispatchEvent(new Event('input')); // Trigger password strength check
            }
        });
    }
}

function generateSecurePassword(length = 16) {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const allChars = lowercase + uppercase + numbers + symbols;
    let password = '';
    
    // Ensure at least one character from each category
    password += getRandomChar(lowercase);
    password += getRandomChar(uppercase);
    password += getRandomChar(numbers);
    password += getRandomChar(symbols);
    
    // Fill the rest randomly
    for (let i = 4; i < length; i++) {
        password += getRandomChar(allChars);
    }
    
    // Shuffle the password
    return password.split('').sort(() => 0.5 - Math.random()).join('');
}

function getRandomChar(str) {
    return str.charAt(Math.floor(Math.random() * str.length));
}

// Recovery process helpers
function initializeRecoveryHelpers() {
    // Recovery phrase validation
    const recoveryPhraseInput = document.getElementById('recovery_phrase');
    if (recoveryPhraseInput) {
        recoveryPhraseInput.addEventListener('input', function() {
            validateRecoveryPhrase(this);
        });
    }
    
    // Security question helpers
    setupSecurityQuestionHelpers();
    
    // Recovery method selection
    setupRecoveryMethodSelection();
}

function validateRecoveryPhrase(input) {
    const words = input.value.trim().split(/\s+/).filter(word => word.length > 0);
    const feedback = document.getElementById('recovery-phrase-feedback');
    
    if (feedback) {
        if (words.length === 12) {
            feedback.innerHTML = '<small class="text-success"><i class="fas fa-check"></i> 12 words entered</small>';
        } else if (words.length > 12) {
            feedback.innerHTML = '<small class="text-warning"><i class="fas fa-exclamation-triangle"></i> Too many words (12 required)</small>';
        } else if (words.length > 0) {
            feedback.innerHTML = `<small class="text-info">${words.length}/12 words entered</small>`;
        } else {
            feedback.innerHTML = '';
        }
    }
}

function setupSecurityQuestionHelpers() {
    const answerInputs = document.querySelectorAll('input[name^="answer"]');
    answerInputs.forEach((input, index) => {
        input.addEventListener('input', function() {
            // Real-time feedback could be added here
            // For security, we don't show whether answers are correct until submission
        });
    });
}

function setupRecoveryMethodSelection() {
    const recoveryCards = document.querySelectorAll('.recovery-option');
    recoveryCards.forEach(card => {
        card.addEventListener('click', function() {
            const radio = this.querySelector('input[type="radio"]');
            if (radio && !radio.disabled) {
                radio.checked = true;
                
                // Visual feedback
                recoveryCards.forEach(c => c.classList.remove('selected'));
                this.classList.add('selected');
            }
        });
    });
}

// Advanced search functionality
function setupAdvancedSearch() {
    const searchInput = document.getElementById('secret-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(function() {
            performSecretSearch(this.value);
        }, 300));
    }
    
    // Filter by type
    const typeFilter = document.getElementById('type-filter');
    if (typeFilter) {
        typeFilter.addEventListener('change', function() {
            filterSecretsByType(this.value);
        });
    }
}

function performSecretSearch(query) {
    const secrets = document.querySelectorAll('.secret-card');
    const lowerQuery = query.toLowerCase();
    
    secrets.forEach(card => {
        const title = card.querySelector('.secret-title')?.textContent.toLowerCase() || '';
        const notes = card.querySelector('.secret-notes')?.textContent.toLowerCase() || '';
        const type = card.querySelector('.secret-type')?.textContent.toLowerCase() || '';
        
        if (title.includes(lowerQuery) || notes.includes(lowerQuery) || type.includes(lowerQuery)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
    
    updateSearchResults(query);
}

function filterSecretsByType(type) {
    const secrets = document.querySelectorAll('.secret-card');
    
    secrets.forEach(card => {
        const cardType = card.getAttribute('data-secret-type');
        if (!type || cardType === type) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

function updateSearchResults(query) {
    const visibleSecrets = document.querySelectorAll('.secret-card[style="display: block"], .secret-card:not([style])').length;
    const resultText = document.getElementById('search-results');
    
    if (resultText) {
        if (query) {
            resultText.textContent = `${visibleSecrets} results for "${query}"`;
        } else {
            resultText.textContent = '';
        }
    }
}

// Utility functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function showLoadingSpinner(button) {
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
    button.disabled = true;
    
    return function hideSpinner() {
        button.innerHTML = originalText;
        button.disabled = false;
    };
}

function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

// Export for global access
window.SecretJournalAdvanced = {
    toggleSecretVisibility,
    generateSecurePassword,
    performSecretSearch,
    showLoadingSpinner,
    confirmAction
};
