// FXロット数計算機 - 完全版 2025（手動レート特化）
// レート自動取得機能を完全に廃止し、手動レート設定のみに対応

'use strict';

// アプリケーション状態管理
const APP_STATE = {
    currentUser: null,
    isLoading: false,
    manualRates: {},
    lastCalculationResult: null,
    editHistory: [],
    historyIndex: -1
};

// 定数定義（完全版）
const CONSTANTS = {
    CURRENCIES: {
        JPY: { pip: 0.01, scale: 100, category: 'major', description: '日本円' },
        USD: { pip: 0.0001, scale: 10000, category: 'major', description: '米ドル' },
        EUR: { pip: 0.0001, scale: 10000, category: 'major', description: 'ユーロ' },
        GBP: { pip: 0.0001, scale: 10000, category: 'major', description: '英ポンド' },
        AUD: { pip: 0.0001, scale: 10000, category: 'major', description: '豪ドル' },
        NZD: { pip: 0.0001, scale: 10000, category: 'major', description: 'NZドル' },
        CAD: { pip: 0.0001, scale: 10000, category: 'major', description: 'カナダドル' },
        CHF: { pip: 0.0001, scale: 10000, category: 'major', description: 'スイスフラン' }
    },
    
    getCurrencyInfo(currency) {
        if (!currency || typeof currency !== 'string') {
            return { pip: 0.0001, scale: 10000, category: 'unknown', description: '不明' };
        }
        const currencyCode = currency.toUpperCase();
        const info = this.CURRENCIES[currencyCode];
        
        if (!info) {
            console.warn(`Unsupported currency: ${currencyCode}`);
            return { pip: 0.0001, scale: 10000, category: 'unknown', description: `未サポート通貨: ${currencyCode}` };
        }
        
        return { ...info, code: currencyCode };
    },
    
    getSupportedCurrencies(category = null) {
        if (!category) {
            return Object.keys(this.CURRENCIES);
        }
        return Object.keys(this.CURRENCIES).filter(code => 
            this.CURRENCIES[code].category === category
        );
    },
    
    isValidCurrencyPair(fromCurrency, toCurrency) {
        return this.getCurrencyInfo(fromCurrency) !== null && 
               this.getCurrencyInfo(toCurrency) !== null &&
               fromCurrency !== toCurrency;
    }
};

// 接続状態管理クラス（手動レート特化版）
class ConnectionManager {
    static isOfflineMode = true; // 常に手動レートモード
    
    static initialize() {
        this.updateConnectionStatus();
    }
    
    static updateConnectionStatus() {
        const statusElement = document.getElementById('connection-status');
        const iconElement = document.getElementById('status-icon');
        const textElement = document.getElementById('status-text');
        
        if (!statusElement) return;
        
        statusElement.style.display = 'flex';
        statusElement.className = 'connection-status offline';
        iconElement.textContent = '✏️';
        textElement.textContent = '手動レートモード';
    }
}

// セキュリティ管理クラス
class SecurityManager {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        return input
            .replace(/[<>&"']/g, (match) => {
                const escapeMap = {
                    '<': '&lt;',
                    '>': '&gt;',
                    '&': '&amp;',
                    '"': '&quot;',
                    "'": '&#x27;'
                };
                return escapeMap[match];
            })
            .trim();
    }

    static validateNumericInput(input, min = 0, max = Number.MAX_SAFE_INTEGER) {
        const num = parseFloat(input);
        if (Number.isNaN(num)) return null;
        if (num < min || num > max) return null;
        return num;
    }

    static setupCSPReporting() {
        document.addEventListener('securitypolicyviolation', (e) => {
            console.warn('CSP Violation:', e.violatedDirective, e.blockedURI);
        });
    }
}

// 認証セキュリティ管理クラス
class AuthSecurityManager {
    static async hashPassword(password) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            console.error('Password hashing failed:', error);
            throw new Error('パスワードの暗号化に失敗しました');
        }
    }

    static getAppropriateStorage() {
        const securityLevel = localStorage.getItem('securityLevel') || 'persistent';
        return securityLevel === 'session' ? sessionStorage : localStorage;
    }

    static logSecurityEvent(event, details = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            event: event,
            details: details,
            userAgent: navigator.userAgent.substring(0, 100)
        };
        
        try {
            const logs = JSON.parse(localStorage.getItem('securityLogs') || '[]');
            logs.push(logEntry);
            
            if (logs.length > 50) {
                logs.splice(0, logs.length - 50);
            }
            
            localStorage.setItem('securityLogs', JSON.stringify(logs));
        } catch (error) {
            console.warn('Security logging failed:', error);
        }
    }
}

// エラーハンドリングユーティリティ（完全版）
class ErrorHandler {
    static show(message, type = 'error') {
        console.error(`[${type.toUpperCase()}]`, message);
        const sanitizedMessage = SecurityManager.sanitizeInput(message);
        this.showErrorBanner(sanitizedMessage);
        this.showNotification(sanitizedMessage, type);
    }

    static showErrorBanner(message) {
        const banner = document.getElementById('error-banner');
        const messageElement = document.getElementById('error-message');
        
        if (banner && messageElement) {
            messageElement.textContent = message;
            banner.style.display = 'flex';
            banner.setAttribute('tabindex', '-1');
            banner.focus();
            
            setTimeout(() => {
                banner.style.display = 'none';
            }, 10000);
        }
    }

    static showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notification-container');
        if (!container) return;

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.setAttribute('role', 'alert');
        notification.setAttribute('aria-live', 'polite');
        
        const iconMap = {
            error: '⚠️ エラー',
            success: '✅ 成功',
            warning: '🟡 警告',
            info: 'ℹ️ 情報',
            offline: '📱 オフライン'
        };
        
        notification.innerHTML = `
            <div class="notification-content">
                <strong>${iconMap[type] || 'ℹ️ 情報'}</strong>
                <p>${message}</p>
                <button class="notification-close" aria-label="通知を閉じる">&times;</button>
            </div>
        `;

        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.remove();
        });

        container.appendChild(notification);

        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, duration);
    }

    static clearBanner() {
        const banner = document.getElementById('error-banner');
        if (banner) {
            banner.style.display = 'none';
        }
    }
}

// ローディング管理（完全版）
class LoadingManager {
    static show(message = 'アプリケーションを起動中...') {
        const screen = document.getElementById('loading-screen');
        if (screen) {
            const messageElement = screen.querySelector('p');
            if (messageElement) {
                messageElement.textContent = SecurityManager.sanitizeInput(message);
            }
            screen.style.display = 'flex';
            screen.setAttribute('aria-hidden', 'false');
        }
        APP_STATE.isLoading = true;
    }

    static hide() {
        const screen = document.getElementById('loading-screen');
        if (screen) {
            screen.style.display = 'none';
            screen.setAttribute('aria-hidden', 'true');
        }
        APP_STATE.isLoading = false;
    }
}

// モーダル管理クラス（完全版）
class ModalManager {
    static show(title, inputValue = '', onApply = null) {
        const modal = document.getElementById('rate-modal');
        const input = document.getElementById('manual-rate-input');
        
        if (!modal || !input) return;

        input.value = inputValue;
        modal.style.display = 'flex';
        modal.setAttribute('aria-hidden', 'false');
        setTimeout(() => modal.classList.add('show'), 10);
        
        input.focus();
        input.select();

        this.setupModalEvents(modal, input, onApply);
    }

    static setupModalEvents(modal, input, onApply) {
        const applyBtn = document.getElementById('apply-manual-rate');
        const cancelBtn = document.getElementById('cancel-manual-rate');

        const newApplyBtn = applyBtn.cloneNode(true);
        const newCancelBtn = cancelBtn.cloneNode(true);
        applyBtn.parentNode.replaceChild(newApplyBtn, applyBtn);
        cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);

        newApplyBtn.addEventListener('click', () => {
            const value = SecurityManager.validateNumericInput(input.value, 0.0001, 9999);
            if (value !== null) {
                if (onApply) onApply(value);
                this.hide();
            } else {
                ErrorHandler.show('有効な数値を入力してください（0.0001以上9999以下）', 'warning');
                input.focus();
            }
        });

        newCancelBtn.addEventListener('click', () => {
            this.hide();
        });

        const keyHandler = (e) => {
            switch (e.key) {
                case 'Enter':
                    e.preventDefault();
                    newApplyBtn.click();
                    break;
                case 'Escape':
                    e.preventDefault();
                    this.hide();
                    break;
            }
        };

        input.addEventListener('keydown', keyHandler);
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.hide();
            }
        });
    }

    static hide() {
        const modal = document.getElementById('rate-modal');
        if (!modal) return;

        modal.classList.remove('show');
        modal.setAttribute('aria-hidden', 'true');
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300);
    }
}

// バリデーション機能（完全版）
class Validator {
    static validateUser(username, password, isRegistration = false) {
        const errors = {};

        const sanitizedUsername = SecurityManager.sanitizeInput(username);
        if (!sanitizedUsername || sanitizedUsername.length < (isRegistration ? 4 : 1)) {
            errors.username = isRegistration ? 'ユーザー名は4文字以上で入力してください' : 'ユーザー名を入力してください';
        } else if (isRegistration && !/^[a-zA-Z0-9_-]+$/.test(sanitizedUsername)) {
            errors.username = 'ユーザー名は英数字、アンダースコア、ハイフンのみ使用可能です';
        }

        if (!password || password.length < (isRegistration ? 6 : 1)) {
            errors.password = isRegistration ? 'パスワードは6文字以上で入力してください' : 'パスワードを入力してください';
        } else if (isRegistration) {
            const passwordStrength = this.calculatePasswordStrength(password);
            if (passwordStrength.score < 3) {
                errors.password = `パスワードが弱すぎます。${passwordStrength.suggestions.join('、')}`;
            }
        }

        return errors;
    }

    static calculatePasswordStrength(password) {
        let score = 0;
        const suggestions = [];

        if (password.length >= 8) score++;
        else suggestions.push('8文字以上にしてください');

        if (/[A-Z]/.test(password)) score++;
        else suggestions.push('大文字を含めてください');

        if (/[a-z]/.test(password)) score++;
        else suggestions.push('小文字を含めてください');

        if (/\d/.test(password)) score++;
        else suggestions.push('数字を含めてください');

        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++;
        else suggestions.push('記号を含めてください');

        return { score, suggestions };
    }

    static validateCalculationInputs(inputs) {
        const errors = {};

        const validationRules = {
            balance: { min: 0.01, max: 100000000, message: '口座残高は0.01以上で入力してください' },
            riskPercent: { min: 0.1, max: 10, message: 'リスク許容度は0.1%から10%の間で入力してください' },
            entryPrice: { min: 0.0001, max: 9999, message: 'エントリー価格は正の値で入力してください' },
            stopLoss: { min: 0.0001, max: 9999, message: '損切り価格は正の値で入力してください' },
            takeProfit: { min: 0.0001, max: 9999, message: '目標価格は正の値で入力してください' }
        };

        Object.entries(validationRules).forEach(([field, rule]) => {
            const value = inputs[field];
            if (!value || value < rule.min || value > rule.max) {
                errors[field] = rule.message;
            }
        });

        if (inputs.entryPrice && inputs.stopLoss && inputs.toCurrency) {
            const currencyInfo = CONSTANTS.getCurrencyInfo(inputs.toCurrency);
            const minDifference = currencyInfo ? currencyInfo.pip : 0.0001;
            if (Math.abs(inputs.entryPrice - inputs.stopLoss) < minDifference) {
                errors.logic = 'エントリー価格と損切り価格は少なくとも1pip以上離してください';
            }
        }

        if (inputs.entryPrice && inputs.takeProfit && inputs.toCurrency) {
            const currencyInfo = CONSTANTS.getCurrencyInfo(inputs.toCurrency);
            const minDifference = currencyInfo ? currencyInfo.pip : 0.0001;
            if (Math.abs(inputs.entryPrice - inputs.takeProfit) < minDifference) {
                errors.logic = 'エントリー価格と目標価格は少なくとも1pip以上離してください';
            }
        }

        return errors;
    }

    static showValidationErrors(errors, formType = '') {
        document.querySelectorAll('.form-error').forEach(el => el.textContent = '');

        Object.entries(errors).forEach(([field, message]) => {
            const errorElement = document.getElementById(`${formType}${field}-error`);
            if (errorElement) {
                errorElement.textContent = message;
                errorElement.setAttribute('role', 'alert');
            } else {
                ErrorHandler.show(message, 'warning');
            }
        });

        return Object.keys(errors).length === 0;
    }
}

// 数値フォーマット機能（完全版）
class NumberFormatter {
    static formatWithCommas(num) {
        if (typeof num !== 'number' || !Number.isFinite(num)) return '0';
        return new Intl.NumberFormat('ja-JP').format(Math.round(num));
    }

    static parseFromCommas(str) {
        if (typeof str !== 'string') return 0;
        const cleaned = str.replace(/[,\s]/g, '');
        const num = parseFloat(cleaned);
        return Number.isNaN(num) ? 0 : num;
    }

    static formatCurrency(amount, currency = 'JPY') {
        if (typeof amount !== 'number' || !Number.isFinite(amount)) return '¥0';
        
        try {
            return new Intl.NumberFormat('ja-JP', {
                style: 'currency',
                currency: currency,
                maximumFractionDigits: 0
            }).format(amount);
        } catch (error) {
            console.warn('Currency formatting error:', error);
            return `${currency} ${this.formatWithCommas(Math.round(amount))}`;
        }
    }

    static formatPrice(price, currency) {
        const decimals = currency === 'JPY' ? 3 : 5;
        return parseFloat(price).toFixed(decimals);
    }

    static formatPriceForDisplay(price, currencyPair) {
        const toCurrency = currencyPair.slice(-3);
        const decimals = toCurrency === 'JPY' ? 3 : 4;
        return parseFloat(price).toFixed(decimals);
    }
}

// 手動レート管理クラス（完全版）
class ExchangeRateManager {
    static updateExchangeRate() {
        const fromCurrency = document.getElementById('from-currency')?.value;
        const toCurrency = document.getElementById('to-currency')?.value;
        const rateDisplay = document.getElementById('exchange-rate-display');
        const rateValue = document.getElementById('current-rate');
        const rateStatus = document.getElementById('rate-status');
        const rateTimestamp = document.getElementById('rate-timestamp');

        if (!fromCurrency || !toCurrency || !rateDisplay) return;

        if (fromCurrency === toCurrency) {
            rateDisplay.style.display = 'none';
            return;
        }

        rateDisplay.style.display = 'block';
        rateDisplay.classList.remove('rate-error', 'offline-mode');

        const manualRate = this.getManualRate(fromCurrency, toCurrency);
        if (manualRate) {
            this.displayManualRate(fromCurrency, toCurrency, manualRate, rateValue, rateStatus, rateTimestamp);
        } else {
            this.displayNoRate(rateValue, rateStatus, rateTimestamp);
        }
    }

    static displayManualRate(fromCurrency, toCurrency, manualRate, rateValue, rateStatus, rateTimestamp) {
        rateValue.textContent = `1 ${fromCurrency} = ${manualRate.rate.toFixed(4)} ${toCurrency}`;
        rateStatus.textContent = '🎯';
        rateStatus.setAttribute('title', '手動設定レート');
        rateTimestamp.textContent = new Date(manualRate.timestamp).toLocaleString('ja-JP') + ' (手動設定)';
    }

    static displayNoRate(rateValue, rateStatus, rateTimestamp) {
        rateValue.textContent = '未設定';
        rateStatus.textContent = '✏️';
        rateStatus.setAttribute('title', 'レート未設定');
        rateTimestamp.textContent = '-';
    }

    static setManualRate(fromCurrency, toCurrency, rate) {
        try {
            const manualRates = JSON.parse(localStorage.getItem('manualRates') || '{}');
            const key = `${fromCurrency}${toCurrency}`;
            manualRates[key] = {
                rate: rate,
                timestamp: Date.now(),
                expires: Date.now() + (24 * 60 * 60 * 1000) // 24時間有効
            };
            localStorage.setItem('manualRates', JSON.stringify(manualRates));
            console.log(`Manual rate set: ${key} = ${rate}`);
        } catch (error) {
            console.warn('Manual rate storage error:', error);
        }
    }

    static getManualRate(fromCurrency, toCurrency) {
        try {
            const manualRates = JSON.parse(localStorage.getItem('manualRates') || '{}');
            const key = `${fromCurrency}${toCurrency}`;
            const manual = manualRates[key];

            if (manual && manual.expires > Date.now()) {
                return manual;
            } else if (manual) {
                delete manualRates[key];
                localStorage.setItem('manualRates', JSON.stringify(manualRates));
            }
        } catch (error) {
            console.warn('Manual rate fetch error:', error);
        }
        return null;
    }

    static getCurrentRate(fromCurrency, toCurrency) {
        const manualRate = this.getManualRate(fromCurrency, toCurrency);
        return manualRate ? manualRate.rate : null;
    }

    static restoreAutoRate() {
        // 手動レート特化版では不要だが、互換性のため空実装
        console.log('手動レートモードでは自動復帰機能は無効です');
    }

    static saveToCache() {
        // 手動レート特化版では不要
    }

    static loadFromCache() {
        // 手動レート特化版では不要
        return false;
    }
}

// 認証管理クラス（完全版）
class AuthManager {
    static async checkAuthState() {
        const storage = AuthSecurityManager.getAppropriateStorage();
        const currentUser = storage.getItem('currentUser');
        
        const authContainer = document.getElementById('auth-container');
        const userInfoContainer = document.getElementById('user-info-container');
        const mainContainer = document.querySelector('.container');
        const recordsSection = document.querySelector('.records-section');

        if (currentUser) {
            APP_STATE.currentUser = currentUser;
            authContainer.style.display = 'none';
            userInfoContainer.style.display = 'block';
            mainContainer.style.display = 'block';
            recordsSection.style.display = 'block';
            
            const userElement = document.getElementById('current-user');
            if (userElement) {
                userElement.textContent = SecurityManager.sanitizeInput(currentUser);
            }
            
            AuthSecurityManager.logSecurityEvent('auth_check_success', { user: currentUser });
        } else {
            authContainer.style.display = 'block';
            userInfoContainer.style.display = 'none';
            mainContainer.style.display = 'none';
            recordsSection.style.display = 'none';
        }
    }

    static async login() {
        const username = document.getElementById('login-username')?.value?.trim();
        const password = document.getElementById('login-password')?.value;

        const errors = Validator.validateUser(username, password, false);
        if (!Validator.showValidationErrors(errors, 'login-')) {
            return;
        }

        try {
            const hashedPassword = await AuthSecurityManager.hashPassword(password);
            const users = JSON.parse(localStorage.getItem('users') || '{}');
            const sanitizedUsername = SecurityManager.sanitizeInput(username);
            
            if (users[sanitizedUsername] && users[sanitizedUsername] === hashedPassword) {
                const storage = AuthSecurityManager.getAppropriateStorage();
                storage.setItem('currentUser', sanitizedUsername);
                
                APP_STATE.currentUser = sanitizedUsername;
                this.checkAuthState();
                
                RecordManager.displayRecords('all');
                RecordManager.updateStats();
                
                ErrorHandler.showNotification('ログインしました', 'success');
                AuthSecurityManager.logSecurityEvent('login_success', { user: sanitizedUsername });
                
                document.getElementById('login-username').value = '';
                document.getElementById('login-password').value = '';
            } else {
                throw new Error('ユーザー名またはパスワードが間違っています');
            }
        } catch (error) {
            AuthSecurityManager.logSecurityEvent('login_failed', { error: error.message });
            ErrorHandler.show(error.message, 'error');
        }
    }

    static async register() {
        const username = document.getElementById('register-username')?.value?.trim();
        const password = document.getElementById('register-password')?.value;

        const errors = Validator.validateUser(username, password, true);
        if (!Validator.showValidationErrors(errors, 'register-')) {
            return;
        }

        try {
            const users = JSON.parse(localStorage.getItem('users') || '{}');
            const sanitizedUsername = SecurityManager.sanitizeInput(username);
            
            if (users[sanitizedUsername]) {
                throw new Error('このユーザー名は既に使用されています');
            }

            const hashedPassword = await AuthSecurityManager.hashPassword(password);
            users[sanitizedUsername] = hashedPassword;
            localStorage.setItem('users', JSON.stringify(users));
            
            const storage = AuthSecurityManager.getAppropriateStorage();
            storage.setItem('currentUser', sanitizedUsername);
            
            APP_STATE.currentUser = sanitizedUsername;
            
            this.checkAuthState();
            ErrorHandler.showNotification('アカウントが作成されました', 'success');
            AuthSecurityManager.logSecurityEvent('register_success', { user: sanitizedUsername });
            
            document.getElementById('register-username').value = '';
            document.getElementById('register-password').value = '';
        } catch (error) {
            AuthSecurityManager.logSecurityEvent('register_failed', { error: error.message });
            ErrorHandler.show(error.message, 'error');
        }
    }

    static logout() {
        if (confirm('ログアウトしますか？')) {
            try {
                localStorage.removeItem('currentUser');
                sessionStorage.removeItem('currentUser');
                
                AuthSecurityManager.logSecurityEvent('logout', { user: APP_STATE.currentUser });
                
                APP_STATE.currentUser = null;
                this.checkAuthState();
                ErrorHandler.showNotification('ログアウトしました', 'info');
            } catch (error) {
                console.warn('Logout error:', error);
                ErrorHandler.show('ログアウト処理でエラーが発生しました', 'error');
            }
        }
    }

    static runSecurityDiagnostic() {
        const results = {
            passwordHashingEnabled: true,
            secureStorageConfigured: !!localStorage.getItem('securityLevel'),
            httpsConnection: location.protocol === 'https:',
            browserSecurityFeatures: {
                cryptoSubtle: !!window.crypto?.subtle,
                secureContext: window.isSecureContext
            }
        };

        console.log('Security Diagnostic Results:', results);
        return results;
    }
}

// 計算エンジンクラス（完全版）
class CalculationEngine {
    static calculateLotSize() {
        try {
            const inputs = this.getInputs();
            const errors = Validator.validateCalculationInputs(inputs);
            
            if (!Validator.showValidationErrors(errors)) {
                return;
            }

            // 手動レートの確認
            const currentRate = ExchangeRateManager.getCurrentRate(inputs.fromCurrency, inputs.toCurrency);
            if (!currentRate) {
                ErrorHandler.show('先に通貨ペアのレートを手動で設定してください', 'warning');
                return;
            }

            const result = this.performCalculation(inputs, currentRate);
            this.displayResults(result);
            
            APP_STATE.lastCalculationResult = result;
            ErrorHandler.showNotification('計算が完了しました', 'success');

        } catch (error) {
            console.error('Calculation error:', error);
            ErrorHandler.show(`計算エラー: ${error.message}`, 'error');
        }
    }

    static getInputs() {
        const balanceStr = document.getElementById('balance')?.value;
        const riskPercent = document.getElementById('risk-percent')?.value;
        const entryPrice = document.getElementById('entry-price')?.value;
        const stopLoss = document.getElementById('stop-loss')?.value;
        const takeProfit = document.getElementById('take-profit')?.value;
        const leverage = document.getElementById('leverage')?.value;

        return {
            balance: NumberFormatter.parseFromCommas(balanceStr),
            riskPercent: SecurityManager.validateNumericInput(riskPercent, 0.1, 10),
            fromCurrency: document.getElementById('from-currency')?.value,
            toCurrency: document.getElementById('to-currency')?.value,
            entryPrice: SecurityManager.validateNumericInput(entryPrice, 0.0001, 9999),
            stopLoss: SecurityManager.validateNumericInput(stopLoss, 0.0001, 9999),
            takeProfit: SecurityManager.validateNumericInput(takeProfit, 0.0001, 9999),
            accountCurrency: document.getElementById('account-currency')?.value,
            leverage: SecurityManager.validateNumericInput(leverage, 1, 1000)
        };
    }

    static performCalculation(inputs, exchangeRate) {
        const currencyPair = inputs.fromCurrency + inputs.toCurrency;
        const riskAmount = inputs.balance * (inputs.riskPercent / 100);
        
        const currencyInfo = CONSTANTS.getCurrencyInfo(inputs.toCurrency);
        if (!currencyInfo) {
            throw new Error(`サポートされていない決済通貨です: ${inputs.toCurrency}`);
        }

        const pipsDifference = Math.abs(inputs.entryPrice - inputs.stopLoss) * currencyInfo.scale;
        const profitPips = Math.abs(inputs.takeProfit - inputs.entryPrice) * currencyInfo.scale;

        const pipValue = this.calculatePipValue(inputs.fromCurrency, inputs.toCurrency, inputs.accountCurrency, inputs.entryPrice, exchangeRate);
        if (pipValue === null) {
            throw new Error('この通貨ペアのpip値計算でエラーが発生しました');
        }

        const lotSize = riskAmount / (pipsDifference * pipValue);
        const expectedProfit = lotSize * profitPips * pipValue;
        const requiredMargin = (lotSize * 100000 * inputs.entryPrice) / inputs.leverage;
        const rrRatio = pipsDifference > 0 ? profitPips / pipsDifference : 0;

        if (!Number.isFinite(lotSize) || lotSize <= 0) {
            throw new Error('ロット数の計算結果が無効です。入力値を確認してください');
        }

        return {
            lotSize,
            riskAmount,
            expectedProfit,
            pipsDifference,
            profitPips,
            requiredMargin,
            rrRatio,
            currencyPair,
            entryPrice: inputs.entryPrice,
            stopLoss: inputs.stopLoss,
            takeProfit: inputs.takeProfit,
            leverage: inputs.leverage,
            pipValue,
            accountCurrency: inputs.accountCurrency,
            exchangeRate
        };
    }

    static calculatePipValue(fromCurrency, toCurrency, accountCurrency, entryPrice, exchangeRate) {
        try {
            const currencyInfo = CONSTANTS.getCurrencyInfo(toCurrency);
            if (!currencyInfo) {
                throw new Error(`サポートされていない決済通貨です: ${toCurrency}`);
            }

            let basePipValue = toCurrency === 'JPY' || toCurrency === 'KRW' ? 1000 : 10;

            if (toCurrency === accountCurrency) {
                return basePipValue;
            }
            
            if (fromCurrency === accountCurrency) {
                return basePipValue / entryPrice;
            }

            // クロス通貨の場合は手動レートを使用した概算計算
            const conversionRate = exchangeRate;
            if (!Number.isFinite(conversionRate) || conversionRate <= 0) {
                throw new Error('変換レートが無効です');
            }

            const result = basePipValue * conversionRate;
            
            if (!Number.isFinite(result) || result <= 0) {
                throw new Error('計算結果が無効です');
            }

            console.log(`PipValue calculation: ${toCurrency}→${accountCurrency}, basePip: ${basePipValue}, rate: ${conversionRate.toFixed(6)}, result: ${result.toFixed(4)}`);
            
            return result;
        } catch (error) {
            console.error('Pip value calculation error:', error);
            return null;
        }
    }

    static displayResults(results) {
        const resultContainer = document.querySelector('.result-container');
        if (!resultContainer) return;

        resultContainer.style.display = 'block';
        
        const valueElement = document.querySelector('.lot-result .value');
        if (valueElement) {
            valueElement.textContent = results.lotSize.toFixed(2);
        }

        resultContainer.querySelectorAll('.result-item').forEach(item => item.remove());

        const resultItems = {
            'リスクリワード比': `<span class="ratio-highlight">${results.rrRatio.toFixed(2)}</span>`,
            '想定利益金額': `<span class="profit-highlight">${NumberFormatter.formatCurrency(results.expectedProfit)}</span>`,
            'リスク金額': `<span class="risk-highlight">${NumberFormatter.formatCurrency(results.riskAmount)}</span>`,
            '価格差（損失まで）': `${results.pipsDifference.toFixed(1)} pips`,
            '価格差（利益まで）': `${results.profitPips.toFixed(1)} pips`,
            '1pip価値': `${NumberFormatter.formatCurrency(results.pipValue)}`,
            '必要証拠金（概算）': NumberFormatter.formatCurrency(results.requiredMargin)
        };

        Object.entries(resultItems).forEach(([label, value]) => {
            const itemDiv = document.createElement('div');
            itemDiv.className = 'result-item';
            itemDiv.innerHTML = `
                <span class="result-label">${SecurityManager.sanitizeInput(label)}</span>
                <span class="result-value">${value}</span>
            `;
            resultContainer.appendChild(itemDiv);
        });

        this.checkRiskWarning(results);
    }

    static checkRiskWarning(results) {
        const warningElement = document.querySelector('.warning');
        if (!warningElement) return;

        let warningMessage = '';

        if (results.lotSize > 10) {
            warningMessage = '⚠️ ロット数が大きすぎる可能性があります。リスク管理を確認してください。';
        } else if (results.requiredMargin > results.riskAmount * 10) {
            warningMessage = '⚠️ 必要証拠金が高額です。レバレッジの調整を検討してください。';
        } else if (results.rrRatio < 1) {
            warningMessage = '💡 リスクリワード比が1未満です。利益目標の見直しを検討してください。';
        }

        if (warningMessage) {
            warningElement.textContent = warningMessage;
            warningElement.style.display = 'block';
            warningElement.setAttribute('role', 'alert');
        } else {
            warningElement.style.display = 'none';
        }
    }
}

// レコード管理クラス（完全版）
class RecordManager {
    static saveTradeRecord() {
        if (!APP_STATE.lastCalculationResult) {
            ErrorHandler.show('まず計算を実行してください', 'warning');
            return;
        }

        if (!APP_STATE.currentUser) {
            ErrorHandler.show('ログインが必要です', 'error');
            return;
        }

        try {
            const result = APP_STATE.lastCalculationResult;
            const record = {
                id: Date.now(),
                timestamp: new Date().toLocaleString('ja-JP'),
                user: APP_STATE.currentUser,
                currencyPair: result.currencyPair,
                entryPrice: result.entryPrice,
                stopLoss: result.stopLoss,
                takeProfit: result.takeProfit,
                lotSize: result.lotSize,
                expectedProfit: result.expectedProfit,
                riskAmount: result.riskAmount,
                rrRatio: result.rrRatio,
                leverage: result.leverage,
                pipValue: result.pipValue || 0,
                accountCurrency: result.accountCurrency,
                exchangeRate: result.exchangeRate,
                result: 'pending'
            };

            const records = this.getRecords();
            records.push(record);
            localStorage.setItem(`tradeRecords_${APP_STATE.currentUser}`, JSON.stringify(records));

            this.displayRecords('all');
            this.updateStats();
            
            ErrorHandler.showNotification('トレード記録を保存しました', 'success');
        } catch (error) {
            console.error('Record save error:', error);
            ErrorHandler.show(`記録保存エラー: ${error.message}`, 'error');
        }
    }

    static getRecords() {
        if (!APP_STATE.currentUser) return [];
        
        try {
            const data = localStorage.getItem(`tradeRecords_${APP_STATE.currentUser}`);
            return JSON.parse(data || '[]');
        } catch (error) {
            console.error('Records parsing error:', error);
            return [];
        }
    }

    static displayRecords(filter = 'all') {
        const records = this.getRecords();
        const tbody = document.querySelector('.records-table tbody');
        
        if (!tbody) return;

        let filteredRecords = this.filterRecords(records, filter);
        filteredRecords.sort((a, b) => b.id - a.id);

        tbody.innerHTML = '';

        if (filteredRecords.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="11" style="text-align: center; padding: 40px; color: #666;">
                        ${filter === 'all' ? 'まだ記録がありません' : `${this.getFilterLabel(filter)}の記録がありません`}
                    </td>
                </tr>
            `;
            return;
        }

        filteredRecords.forEach(record => {
            const row = this.createRecordRow(record);
            tbody.appendChild(row);
        });

        this.makeEditable();
    }

    static filterRecords(records, filter) {
        switch (filter) {
            case 'win': return records.filter(r => r.result === 'win');
            case 'loss': return records.filter(r => r.result === 'loss');
            case 'pending': return records.filter(r => r.result === 'pending');
            default: return records;
        }
    }

    static getFilterLabel(filter) {
        const labels = { win: '勝ち', loss: '負け', pending: '未決済' };
        return labels[filter] || '';
    }

    static createRecordRow(record) {
        const row = document.createElement('tr');
        row.dataset.recordId = record.id;
        
        row.innerHTML = `
            <td style="text-align: center;">
                <button class="delete-record-btn" data-record-id="${record.id}" title="削除" aria-label="記録を削除">
                    ✕
                </button>
            </td>
            <td>${SecurityManager.sanitizeInput(record.timestamp)}</td>
            <td>${SecurityManager.sanitizeInput(record.currencyPair)}</td>
            <td data-field="entryPrice" tabindex="0">${NumberFormatter.formatPriceForDisplay(record.entryPrice, record.currencyPair)}</td>
            <td data-field="stopLoss" tabindex="0">${NumberFormatter.formatPriceForDisplay(record.stopLoss, record.currencyPair)}</td>
            <td data-field="takeProfit" tabindex="0">${NumberFormatter.formatPriceForDisplay(record.takeProfit, record.currencyPair)}</td>
            <td data-field="lotSize" tabindex="0">${record.lotSize.toFixed(2)}</td>
            <td data-field="expectedProfit">${NumberFormatter.formatCurrency(record.expectedProfit)}</td>
            <td data-field="riskAmount">${NumberFormatter.formatCurrency(record.riskAmount)}</td>
            <td data-field="rrRatio">${record.rrRatio.toFixed(2)}</td>
            <td>
                <select class="result-select" data-record-id="${record.id}" aria-label="トレード結果">
                    <option value="pending" ${record.result === 'pending' ? 'selected' : ''}>未決済</option>
                    <option value="win" ${record.result === 'win' ? 'selected' : ''}>勝ち</option>
                    <option value="loss" ${record.result === 'loss' ? 'selected' : ''}>負け</option>
                </select>
            </td>
        `;
        
        return row;
    }

    static makeEditable() {
        const editableFields = ['entryPrice', 'stopLoss', 'takeProfit', 'lotSize'];
        
        editableFields.forEach(field => {
            const cells = document.querySelectorAll(`td[data-field="${field}"]`);
            
            cells.forEach(cell => {
                cell.contentEditable = true;
                cell.setAttribute('role', 'textbox');
                cell.setAttribute('aria-label', `編集可能: ${field}`);
                
                cell.addEventListener('focus', function() {
                    this.originalValue = this.textContent;
                    this.style.backgroundColor = '#fff3cd';
                });
                
                cell.addEventListener('blur', function() {
                    this.style.backgroundColor = '';
                    if (this.textContent !== this.originalValue) {
                        RecordManager.recalculateRow(this);
                    }
                });
                
                cell.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        this.blur();
                    }
                    if (!/[\d\.\-\+e]/.test(e.key) && 
                        !['Backspace', 'Delete', 'Tab', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) {
                        e.preventDefault();
                    }
                });
            });
        });
    }

    static recalculateRow(cell) {
        try {
            const row = cell.closest('tr');
            const recordId = parseInt(row.dataset.recordId);
            
            const entryPrice = SecurityManager.validateNumericInput(
                row.querySelector('[data-field="entryPrice"]').textContent, 0.0001, 9999);
            const stopLoss = SecurityManager.validateNumericInput(
                row.querySelector('[data-field="stopLoss"]').textContent, 0.0001, 9999);
            const takeProfit = SecurityManager.validateNumericInput(
                row.querySelector('[data-field="takeProfit"]').textContent, 0.0001, 9999);
            const lotSize = SecurityManager.validateNumericInput(
                row.querySelector('[data-field="lotSize"]').textContent, 0.01, 100);
            
            if (entryPrice === null || stopLoss === null || takeProfit === null || lotSize === null) {
                ErrorHandler.show('有効な数値を入力してください', 'warning');
                this.restoreCellValue(cell);
                return;
            }
            
            const records = this.getRecords();
            const recordIndex = records.findIndex(r => r.id === recordId);
            
            if (recordIndex === -1) {
                ErrorHandler.show('該当する記録が見つかりません', 'error');
                this.restoreCellValue(cell);
                return;
            }
            
            const record = records[recordIndex];
            const fromCurrency = record.currencyPair.substring(0, 3);
            const toCurrency = record.currencyPair.substring(3, 6);
            
            let accountCurrency = record.accountCurrency;
            if (!accountCurrency) {
                accountCurrency = document.getElementById('account-currency')?.value || 'JPY';
                record.accountCurrency = accountCurrency;
            }
            
            // 手動レートを取得
            const exchangeRate = ExchangeRateManager.getCurrentRate(fromCurrency, toCurrency) || record.exchangeRate || 1.0;
            
            let pipValue;
            try {
                pipValue = CalculationEngine.calculatePipValue(fromCurrency, toCurrency, accountCurrency, entryPrice, exchangeRate);
                if (pipValue === null) {
                    throw new Error('pip値の計算に失敗しました');
                }
            } catch (pipError) {
                ErrorHandler.show(`pip値計算エラー: ${pipError.message}`, 'error');
                this.restoreCellValue(cell);
                return;
            }

            record.pipValue = pipValue;
            
            const currencyInfo = CONSTANTS.getCurrencyInfo(toCurrency);
            if (!currencyInfo) {
                ErrorHandler.show(`サポートされていない決済通貨です: ${toCurrency}`, 'error');
                this.restoreCellValue(cell);
                return;
            }
            
            const pipsDifference = Math.abs(entryPrice - stopLoss) * currencyInfo.scale;
            const profitPips = Math.abs(takeProfit - entryPrice) * currencyInfo.scale;
            const expectedProfit = lotSize * profitPips * pipValue;
            const riskAmount = lotSize * pipsDifference * pipValue;
            const rrRatio = pipsDifference > 0 ? profitPips / pipsDifference : 0;
            
            if (!Number.isFinite(expectedProfit) || !Number.isFinite(riskAmount) || !Number.isFinite(rrRatio)) {
                ErrorHandler.show('計算結果に無効な値が含まれています', 'error');
                this.restoreCellValue(cell);
                return;
            }
            
            record.entryPrice = entryPrice;
            record.stopLoss = stopLoss;
            record.takeProfit = takeProfit;
            record.lotSize = lotSize;
            record.expectedProfit = expectedProfit;
            record.riskAmount = riskAmount;
            record.rrRatio = rrRatio;
            
            localStorage.setItem(`tradeRecords_${APP_STATE.currentUser}`, JSON.stringify(records));
            
            row.querySelector('[data-field="expectedProfit"]').textContent = NumberFormatter.formatCurrency(expectedProfit);
            row.querySelector('[data-field="riskAmount"]').textContent = NumberFormatter.formatCurrency(riskAmount);
            row.querySelector('[data-field="rrRatio"]').textContent = rrRatio.toFixed(2);
            
            this.updateStats();
            
            console.log(`Row recalculated for record ${recordId}, pipValue: ${pipValue}, RR: ${rrRatio.toFixed(2)}`);
            
        } catch (error) {
            console.error('Row recalculation error:', error);
            ErrorHandler.show(`再計算エラー: ${error.message}`, 'error');
            this.restoreCellValue(cell);
        }
    }

    static restoreCellValue(cell) {
        if (cell && cell.originalValue !== undefined) {
            cell.textContent = cell.originalValue;
        }
    }

    static deleteRecord(recordId) {
        if (!confirm('この記録を削除しますか？この操作は取り消せません。')) return;

        try {
            const records = this.getRecords();
            const filteredRecords = records.filter(record => record.id !== recordId);

            localStorage.setItem(`tradeRecords_${APP_STATE.currentUser}`, JSON.stringify(filteredRecords));

            this.displayRecords(document.querySelector('.control-btn.active')?.dataset.filter || 'all');
            this.updateStats();
            
            ErrorHandler.showNotification('記録を削除しました', 'info');
        } catch (error) {
            console.error('Delete record error:', error);
            ErrorHandler.show(`削除エラー: ${error.message}`, 'error');
        }
    }

    static updateResult(recordId, result) {
        try {
            const records = this.getRecords();
            const recordIndex = records.findIndex(record => record.id === recordId);

            if (recordIndex !== -1) {
                records[recordIndex].result = result;
                localStorage.setItem(`tradeRecords_${APP_STATE.currentUser}`, JSON.stringify(records));
                this.updateStats();
                
                ErrorHandler.showNotification('結果を更新しました', 'success');
            }
        } catch (error) {
            console.error('Update result error:', error);
            ErrorHandler.show(`更新エラー: ${error.message}`, 'error');
        }
    }

    static updateStats() {
        const records = this.getRecords();
        
        const totalTrades = records.length;
        const wins = records.filter(r => r.result === 'win').length;
        const losses = records.filter(r => r.result === 'loss').length;
        const pending = records.filter(r => r.result === 'pending').length;
        const completedTrades = wins + losses;
        const winRate = completedTrades > 0 ? ((wins / completedTrades) * 100) : 0;

        const totalProfit = records
            .filter(r => r.result === 'win')
            .reduce((sum, r) => sum + (r.expectedProfit || 0), 0);

        const totalLoss = records
            .filter(r => r.result === 'loss')
            .reduce((sum, r) => sum + (r.riskAmount || 0), 0);

        const netProfit = totalProfit - totalLoss;

        const statCards = document.querySelectorAll('.stat-card');
        if (statCards.length >= 6) {
            statCards[0].querySelector('.stat-value').textContent = totalTrades;
            statCards[1].querySelector('.stat-value').textContent = wins;
            statCards[2].querySelector('.stat-value').textContent = losses;
            statCards[3].querySelector('.stat-value').textContent = winRate.toFixed(1) + '%';
            statCards[4].querySelector('.stat-value').textContent = NumberFormatter.formatCurrency(netProfit);
            statCards[5].querySelector('.stat-value').textContent = pending;
        }
    }

    static exportToCSV() {
        const records = this.getRecords();
        if (records.length === 0) {
            ErrorHandler.show('エクスポートするデータがありません', 'warning');
            return;
        }

        try {
            const headers = ['日時', '通貨ペア', 'エントリー', '損切り', '目標価格', 'ロット数', '想定利益', 'リスク金額', 'RR比', '結果'];
            const csvContent = [
                '\uFEFF' + headers.join(','),
                ...records.map(record => [
                    `"${record.timestamp}"`,
                    record.currencyPair,
                    NumberFormatter.formatPriceForDisplay(record.entryPrice, record.currencyPair),
                    NumberFormatter.formatPriceForDisplay(record.stopLoss, record.currencyPair),
                    NumberFormatter.formatPriceForDisplay(record.takeProfit, record.currencyPair),
                    record.lotSize.toFixed(2),
                    Math.round(record.expectedProfit || 0),
                    Math.round(record.riskAmount || 0),
                    (record.rrRatio || 0).toFixed(2),
                    record.result
                ].join(','))
            ].join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const fileName = `trade_records_${APP_STATE.currentUser}_${new Date().toISOString().split('T')[0]}.csv`;
            
            link.href = URL.createObjectURL(blob);
            link.download = fileName;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
            
            ErrorHandler.showNotification('CSVファイルをダウンロードしました', 'success');
        } catch (error) {
            console.error('Export error:', error);
            ErrorHandler.show(`エクスポートエラー: ${error.message}`, 'error');
        }
    }

    static async copyToClipboard() {
        const records = this.getRecords();
        if (records.length === 0) {
            ErrorHandler.show('コピーするデータがありません', 'warning');
            return;
        }

        try {
            const headers = ['日時', '通貨ペア', 'エントリー', '損切り', '目標価格', 'ロット数', '想定利益', 'リスク金額', 'RR比', '結果'];
            const content = [
                headers.join('\t'),
                ...records.map(record => [
                    record.timestamp,
                    record.currencyPair,
                    NumberFormatter.formatPriceForDisplay(record.entryPrice, record.currencyPair),
                    NumberFormatter.formatPriceForDisplay(record.stopLoss, record.currencyPair),
                    NumberFormatter.formatPriceForDisplay(record.takeProfit, record.currencyPair),
                    record.lotSize.toFixed(2),
                    Math.round(record.expectedProfit || 0),
                    Math.round(record.riskAmount || 0),
                    (record.rrRatio || 0).toFixed(2),
                    record.result
                ].join('\t'))
            ].join('\n');

            await navigator.clipboard.writeText(content);
            ErrorHandler.showNotification('データをクリップボードにコピーしました', 'success');
        } catch (error) {
            console.error('Clipboard copy error:', error);
            ErrorHandler.show('クリップボードへのコピーに失敗しました', 'error');
        }
    }

    static clearAllData() {
        if (!confirm('すべてのトレード記録を削除しますか？この操作は取り消せません。')) {
            return;
        }

        try {
            localStorage.removeItem(`tradeRecords_${APP_STATE.currentUser}`);
            
            this.displayRecords('all');
            this.updateStats();
            
            ErrorHandler.showNotification('すべてのデータを削除しました', 'info');
        } catch (error) {
            console.error('Clear data error:', error);
            ErrorHandler.show(`削除エラー: ${error.message}`, 'error');
        }
    }
}

// ユーティリティ関数（完全版）
class Utils {
    static setupNumberFormatting() {
        const balanceInput = document.getElementById('balance');
        if (!balanceInput) return;

        const formatInput = (e) => {
            let value = e.target.value.replace(/[,\s]/g, '');
            const numValue = SecurityManager.validateNumericInput(value, 0, 100000000);
            
            if (numValue !== null) {
                e.target.value = NumberFormatter.formatWithCommas(numValue);
            }
        };

        balanceInput.addEventListener('input', formatInput);
        balanceInput.addEventListener('blur', formatInput);

        if (balanceInput.value) {
            formatInput({ target: balanceInput });
        }
    }

    static setupEventListeners() {
        document.addEventListener('click', this.handleDocumentClick.bind(this));
        document.addEventListener('change', this.handleDocumentChange.bind(this));
        document.addEventListener('keypress', this.handleDocumentKeypress.bind(this));
        document.addEventListener('keydown', this.handleDocumentKeydown.bind(this));

        ['from-currency', 'to-currency', 'account-currency'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', () => {
                    ExchangeRateManager.updateExchangeRate();
                });
            }
        });

        this.setupRateSuggestions();
    }

    static setupRateSuggestions() {
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('rate-suggestion')) {
                const rate = parseFloat(e.target.dataset.rate);
                const input = document.getElementById('manual-rate-input');
                if (input && rate) {
                    input.value = rate.toFixed(4);
                    input.focus();
                }
            }
        });
    }

    static handleDocumentClick(e) {
        const { target } = e;
        
        switch (target.id) {
            case 'calculate-btn':
                CalculationEngine.calculateLotSize();
                break;
            case 'save-record-btn':
                RecordManager.saveTradeRecord();
                break;
            case 'export-csv-btn':
                RecordManager.exportToCSV();
                break;
            case 'export-copy-btn':
                RecordManager.copyToClipboard();
                break;
            case 'clear-data-btn':
                RecordManager.clearAllData();
                break;
            case 'login-btn':
                AuthManager.login();
                break;
            case 'register-btn':
                AuthManager.register();
                break;
            case 'logout-btn':
                AuthManager.logout();
                break;
            case 'manual-adjust-btn':
                this.showManualRateDialog();
                break;
            case 'auto-restore-btn':
                ExchangeRateManager.restoreAutoRate();
                break;
            case 'error-close':
                ErrorHandler.clearBanner();
                break;
            case 'debug-info-btn':
                this.showSystemDiagnostics();
                break;
        }

        if (target.classList.contains('delete-record-btn')) {
            const recordId = parseInt(target.dataset.recordId);
            if (recordId) RecordManager.deleteRecord(recordId);
        }

        if (target.classList.contains('control-btn')) {
            document.querySelectorAll('.control-btn').forEach(btn => btn.classList.remove('active'));
            target.classList.add('active');
            RecordManager.displayRecords(target.dataset.filter);
        }
    }

    static showManualRateDialog() {
        const fromCurrency = document.getElementById('from-currency').value;
        const toCurrency = document.getElementById('to-currency').value;
        const currentRate = ExchangeRateManager.getCurrentRate(fromCurrency, toCurrency) || 149.50;
        
        ModalManager.show(
            'レート手動設定',
            currentRate.toFixed(4),
            (newRate) => {
                ExchangeRateManager.setManualRate(fromCurrency, toCurrency, newRate);
                ExchangeRateManager.updateExchangeRate();
                ErrorHandler.showNotification(`レートを ${newRate.toFixed(4)} に設定しました`, 'success');
            }
        );
    }

    static showSystemDiagnostics() {
        const diagnostics = {
            'アプリバージョン': 'FX Calculator v2.2 (手動レート特化版)',
            'ブラウザ': navigator.userAgent.substring(0, 50) + '...',
            'オフラインモード': '常時有効（手動レート特化）',
            'サポート通貨数': Object.keys(CONSTANTS.CURRENCIES).length,
            'メジャー通貨': CONSTANTS.getSupportedCurrencies('major').join(', '),
            'ローカルストレージ': this.checkStorageAvailability(),
            'セキュリティ設定': localStorage.getItem('securityLevel') || 'デフォルト',
            '現在のユーザー': APP_STATE.currentUser || 'ログインなし'
        };
        
        const diagnosticsText = Object.entries(diagnostics)
            .map(([key, value]) => `${key}: ${value}`)
            .join('\n');
            
        alert(`🔍 システム診断情報:\n\n${diagnosticsText}\n\n※詳細はコンソールログをご確認ください`);
        console.table(diagnostics);
        
        console.group('サポート通貨詳細');
        Object.entries(CONSTANTS.CURRENCIES).forEach(([code, info]) => {
            console.log(`${code} (${info.description}): pip=${info.pip}, scale=${info.scale}, category=${info.category}`);
        });
        console.groupEnd();
    }

    static checkStorageAvailability() {
        try {
            const test = 'test';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return '利用可能';
        } catch (e) {
            return '制限あり';
        }
    }

    static handleDocumentChange(e) {
        const { target } = e;
        
        if (target.classList.contains('result-select')) {
            const recordId = parseInt(target.dataset.recordId);
            const result = target.value;
            if (recordId) RecordManager.updateResult(recordId, result);
        }
    }

    static handleDocumentKeypress(e) {
        const { target } = e;
        
        if (e.key === 'Enter') {
            if (target.id === 'login-password') {
                e.preventDefault();
                AuthManager.login();
            } else if (target.id === 'register-password') {
                e.preventDefault();
                AuthManager.register();
            }
        }
    }

    static handleDocumentKeydown(e) {
        if (e.key === 'Escape') {
            ModalManager.hide();
        }
        
        if (e.ctrlKey || e.metaKey) {
            switch (e.key) {
                case 'Enter':
                    e.preventDefault();
                    document.getElementById('calculate-btn')?.click();
                    break;
                case 's':
                    e.preventDefault();
                    document.getElementById('save-record-btn')?.click();
                    break;
            }
        }
    }
}

// アプリケーション初期化（完全版）
async function initializeApp() {
    try {
        LoadingManager.show('アプリケーションを初期化中...');

        // 接続状態管理の初期化
        ConnectionManager.initialize();

        // セキュリティ診断実行
        const securityResults = AuthManager.runSecurityDiagnostic();
        console.log('Security diagnostic completed:', securityResults);

        // セキュリティ設定
        SecurityManager.setupCSPReporting();
        
        // 認証状態チェック
        await AuthManager.checkAuthState();
        
        // イベントリスナー設定
        Utils.setupEventListeners();
        
        // 数値フォーマット設定
        Utils.setupNumberFormatting();
        
        // 初期レート表示
        ExchangeRateManager.updateExchangeRate();
        
        // 記録の初期表示
        if (APP_STATE.currentUser) {
            LoadingManager.show('データを読み込み中...');
            RecordManager.displayRecords('all');
            RecordManager.updateStats();
        }
        
        LoadingManager.hide();
        
        ErrorHandler.showNotification(
            '✅ アプリケーションの準備が完了しました（手動レートモード）', 
            'success'
        );
        
    } catch (error) {
        LoadingManager.hide();
        ErrorHandler.show(`初期化エラー: ${error.message}`, 'error');
        console.error('App initialization error:', error);
        
        // エラー時も基本機能は使用可能にする
        Utils.setupEventListeners();
        AuthManager.checkAuthState();
    }
}

// DOMContentLoaded時の初期化
document.addEventListener('DOMContentLoaded', initializeApp);

// 改良版エラーハンドリング
window.addEventListener('error', function(event) {
    console.error('Global error:', event.error);
    ErrorHandler.show('予期しないエラーが発生しました。ページを再読み込みしてください。', 'error');
});

window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    ErrorHandler.show('処理中にエラーが発生しました。', 'error');
    event.preventDefault();
});

// パフォーマンス監視
if ('performance' in window) {
    window.addEventListener('load', function() {
        setTimeout(() => {
            try {
                const perfData = performance.timing;
                const loadTime = perfData.loadEventEnd - perfData.navigationStart;
                console.log(`Page load time: ${loadTime}ms`);
                
                if (loadTime > 5000) {
                    console.warn('Page load time is slow:', loadTime);
                    ErrorHandler.showNotification(
                        '読み込みが遅いです。', 
                        'warning', 
                        5000
                    );
                }
            } catch (error) {
                console.warn('Performance monitoring error:', error);
            }
        }, 100);
    });
}