//======================================================================
// Firebase初期化 - あなたのプロジェクト設定
//======================================================================
const firebaseConfig = {
    apiKey: "AIzaSyBacHwNi61zQ9k1yaBczsyN2uvEJNekHoY",
    authDomain: "myfx-calculator.firebaseapp.com",
    projectId: "myfx-calculator",
    storageBucket: "myfx-calculator.firebasestorage.app",
    messagingSenderId: "1095991180111",
    appId: "1:1095991180111:web:afdbaeeba863bfc42c233a",
    measurementId: "G-9SJLXY7HDT"
};

// Firebase アプリケーションの初期化
const app = firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

console.log('Firebase初期化完了:', firebaseConfig.projectId);

//======================================================================
// グローバル変数
//======================================================================
let currentUser = null; // 現在のユーザー情報
let tradeRecords = []; // 現在表示しているトレード記録
let currentCalculation = null; // 最新の計算結果
let currentSort = 'date-desc';
let currentFilter = 'all';

//======================================================================
// HTML要素の取得
//======================================================================
const loginFormContainer = document.getElementById('login-form-container');
const userInfoContainer = document.getElementById('user-info-container');
const userEmailSpan = document.getElementById('user-email');
const currencyPair = document.getElementById('currencyPair');
const usdJpyGroup = document.getElementById('usdJpyGroup');
const results = document.getElementById('results');
const warning = document.getElementById('warning');

//======================================================================
// 認証機能（ログイン・ログアウトなど）
//======================================================================

// 認証状態の監視
auth.onAuthStateChanged(user => {
    const mainContent = document.querySelector('.container');
    if (user) {
        // ログインしている場合の処理
        currentUser = user;
        console.log('ログイン中:', currentUser.uid, currentUser.email);

        // UIの切り替え
        loginFormContainer.style.display = 'none';
        userInfoContainer.style.display = 'block';
        userEmailSpan.textContent = currentUser.email;
        mainContent.style.display = 'block';

        // ログインしたユーザーのデータを読み込む
        loadRecords();
        
    } else {
        // ログアウトしている場合の処理
        currentUser = null;
        console.log('ログアウト状態');

        // UIの切り替え
        loginFormContainer.style.display = 'flex';
        userInfoContainer.style.display = 'none';
        mainContent.style.display = 'none';

        // データをクリア
        tradeRecords = [];
        updateRecordsDisplay();
    }
});

// 新規登録
function signUp() {
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    
    if (!email || !password) {
        alert('メールアドレスとパスワードを入力してください');
        return;
    }
    
    if (password.length < 6) {
        alert('パスワードは6文字以上で入力してください');
        return;
    }
    
    console.log('新規登録を試行中:', email);
    
    auth.createUserWithEmailAndPassword(email, password)
        .then(userCredential => {
            console.log('新規登録成功:', userCredential.user.uid);
            alert('ユーザー登録が完了しました！');
            // フォームをクリア
            document.getElementById('signup-email').value = '';
            document.getElementById('signup-password').value = '';
        })
        .catch(error => {
            console.error('新規登録エラー:', error);
            alert('ユーザー登録エラー: ' + error.message);
        });
}

// ログイン
function logIn() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
        alert('メールアドレスとパスワードを入力してください');
        return;
    }
    
    console.log('ログインを試行中:', email);
    
    auth.signInWithEmailAndPassword(email, password)
        .then(userCredential => {
            console.log('ログイン成功:', userCredential.user.uid);
            alert('ログインしました！');
            // フォームをクリア
            document.getElementById('login-email').value = '';
            document.getElementById('login-password').value = '';
        })
        .catch(error => {
            console.error('ログインエラー:', error);
            alert('ログインエラー: ' + error.message);
        });
}

// ログアウト
function logOut() {
    if (confirm('ログアウトしますか？')) {
        console.log('ログアウト試行中');
        auth.signOut()
            .then(() => {
                console.log('ログアウト成功');
                alert('ログアウトしました。');
            })
            .catch((error) => {
                console.error('ログアウトエラー:', error);
                alert('ログアウトエラー: ' + error.message);
            });
    }
}

//======================================================================
// データベース機能 (Firestore) - ユーザーごとのデータ管理
//======================================================================

// 記録の読み込み（ユーザー専用パス使用）
async function loadRecords() {
    if (!currentUser) {
        console.log('ユーザーがログインしていないため、記録を読み込みません');
        return;
    }

    // ユーザー専用のデータパス: users/{ユーザーID}/records/{記録ID}
    const recordsRef = db.collection('users').doc(currentUser.uid).collection('records');
    
    try {
        console.log('Firestoreから記録を読み込み中...', currentUser.uid);
        const querySnapshot = await recordsRef.orderBy('timestamp', 'desc').get();
        tradeRecords = [];
        querySnapshot.forEach((doc) => {
            const data = doc.data();
            tradeRecords.push({
                id: doc.id,
                ...data,
                timestamp: data.timestamp.toDate().toISOString() // Firestoreの時間をJSの時間に変換
            });
        });
        console.log('記録を読み込みました:', tradeRecords.length + '件');
    } catch (error) {
        console.error('記録の読み込みエラー:', error);
        alert('記録の読み込みに失敗しました: ' + error.message);
        tradeRecords = [];
    }
    updateRecordsDisplay();
}

// 記録の保存（ユーザー専用パス使用）
async function saveRecordToDb(record) {
    if (!currentUser) {
        alert('ログインしてください');
        return;
    }

    // ユーザー専用のデータパス
    const recordsRef = db.collection('users').doc(currentUser.uid).collection('records');

    try {
        console.log('記録を保存中:', record.id, currentUser.uid);
        const recordToSave = {
            ...record,
            timestamp: firebase.firestore.Timestamp.fromDate(new Date(record.timestamp)),
            userId: currentUser.uid // セキュリティのためユーザーIDも保存
        };
        
        await recordsRef.doc(record.id.toString()).set(recordToSave);
        console.log('記録を保存しました:', record.id);
    } catch (error) {
        console.error('記録の保存エラー:', error);
        alert('記録の保存に失敗しました: ' + error.message);
        throw error;
    }
}

// 記録の削除（ユーザー専用パス使用）
async function deleteRecordFromDb(recordId) {
    if (!currentUser) {
        alert('ログインしてください');
        return;
    }
    
    const recordRef = db.collection('users').doc(currentUser.uid).collection('records').doc(recordId.toString());

    try {
        console.log('記録を削除中:', recordId, currentUser.uid);
        await recordRef.delete();
        console.log('記録を削除しました:', recordId);
    } catch (error) {
        console.error('記録の削除エラー:', error);
        alert('記録の削除に失敗しました: ' + error.message);
        throw error;
    }
}

//======================================================================
// FXトレード記録ツールのメインロジック
//======================================================================

console.log('FXトレード記録ツール開始');

// 数値フォーマット関数
function formatNumberInput(input) {
    const cursorPosition = input.selectionStart;
    const originalLength = input.value.length;
    
    let value = input.value.replace(/,/g, '');
    value = value.replace(/[^\d]/g, '');
    
    if (value) {
        const formattedValue = parseInt(value).toLocaleString();
        input.value = formattedValue;
        
        const newLength = formattedValue.length;
        const lengthDiff = newLength - originalLength;
        const newCursorPosition = cursorPosition + lengthDiff;
        
        setTimeout(() => {
            input.setSelectionRange(newCursorPosition, newCursorPosition);
        }, 0);
    } else {
        input.value = '';
    }
}

function validateNumberInput(input) {
    let value = input.value.replace(/,/g, '');
    if (value && !isNaN(value)) {
        input.value = parseInt(value).toLocaleString();
    } else if (!value) {
        input.value = '';
    }
}

function getNumericValue(input) {
    return parseFloat(input.value.replace(/,/g, '')) || 0;
}

// メイン計算関数
function calculateOptimalLots() {
    console.log('計算開始');
    
    try {
        const accountBalance = getNumericValue(document.getElementById('accountBalance'));
        const riskPercent = parseFloat(document.getElementById('riskPercent').value);
        const pair = document.getElementById('currencyPair').value;
        const entryPrice = parseFloat(document.getElementById('entryPrice').value);
        const stopLoss = parseFloat(document.getElementById('stopLoss').value);
        const targetPrice = parseFloat(document.getElementById('targetPrice').value);
        const usdJpyRate = parseFloat(document.getElementById('usdJpyRate').value) || 150.00;

        console.log('計算パラメータ:', {
            accountBalance, riskPercent, pair, entryPrice, stopLoss, targetPrice, usdJpyRate
        });

        // 入力値の検証
        if (!accountBalance || !riskPercent || !entryPrice || !stopLoss || !targetPrice) {
            alert('すべての必須項目を入力してください');
            return;
        }

        if (entryPrice === stopLoss) {
            alert('エントリー価格と損切り価格が同じです');
            return;
        }

        if (entryPrice === targetPrice) {
            alert('エントリー価格と目標価格が同じです');
            return;
        }

        const riskAmount = accountBalance * (riskPercent / 100);
        let pips, targetPips, optimalLots, lossPerLot, profitPerLot, requiredMargin;

        // JPY通貨ペアの場合
        if (['USDJPY', 'EURJPY', 'GBPJPY', 'AUDJPY'].includes(pair)) {
            pips = Math.abs(entryPrice - stopLoss) * 100;
            targetPips = Math.abs(entryPrice - targetPrice) * 100;
            
            lossPerLot = pips * 1000;
            profitPerLot = targetPips * 1000;
            
            optimalLots = riskAmount / lossPerLot;
            requiredMargin = (entryPrice * 100000 * optimalLots) / 1000;
        }
        // ドルストレート通貨ペアの場合
        else {
            pips = Math.abs(entryPrice - stopLoss) * 10000;
            targetPips = Math.abs(entryPrice - targetPrice) * 10000;
            
            const lossPerLotUSD = pips * 10;
            const profitPerLotUSD = targetPips * 10;
            
            lossPerLot = lossPerLotUSD * usdJpyRate;
            profitPerLot = profitPerLotUSD * usdJpyRate;
            
            optimalLots = riskAmount / lossPerLot;
            requiredMargin = (100000 * optimalLots * usdJpyRate) / 1000;
        }

        const expectedProfit = optimalLots * profitPerLot;
        const expectedLoss = optimalLots * lossPerLot;
        const riskRewardRatio = profitPerLot / lossPerLot;

        console.log('計算結果:', {
            optimalLots, expectedProfit, expectedLoss, riskRewardRatio, requiredMargin
        });

        // 現在の計算結果を保存
        currentCalculation = {
            accountBalance,
            riskPercent,
            pair,
            entryPrice,
            stopLoss,
            targetPrice,
            usdJpyRate,
            optimalLots,
            expectedProfit,
            expectedLoss,
            riskRewardRatio,
            riskAmount,
            pips,
            targetPips,
            lossPerLot,
            profitPerLot,
            requiredMargin
        };

        // 結果表示
        document.getElementById('optimalLots').textContent = optimalLots.toFixed(2);
        document.getElementById('riskRewardRatio').textContent = '1:' + riskRewardRatio.toFixed(2);
        document.getElementById('expectedProfit').textContent = Math.round(expectedProfit).toLocaleString() + '円';
        document.getElementById('riskAmount').textContent = Math.round(riskAmount).toLocaleString() + '円';
        document.getElementById('pipsDifference').textContent = pips.toFixed(1) + ' pips';
        document.getElementById('targetPipsDifference').textContent = targetPips.toFixed(1) + ' pips';
        document.getElementById('requiredMargin').textContent = Math.round(requiredMargin).toLocaleString() + '円';

        // 警告表示
        if (optimalLots > 100 || requiredMargin > accountBalance * 0.8) {
            warning.style.display = 'block';
            warning.innerHTML = '⚠️ 計算されたロット数が大きすぎる可能性があります。証拠金やレバレッジ制限をご確認ください。';
        } else if (riskRewardRatio < 1) {
            warning.style.display = 'block';
            warning.innerHTML = '⚠️ リスクリワード比が1未満です。リスクが利益を上回る可能性があります。';
        } else {
            warning.style.display = 'none';
        }

        results.style.display = 'block';
        console.log('計算完了');

    } catch (error) {
        console.error('計算エラー:', error);
        alert('計算エラーが発生しました: ' + error.message);
    }
}

// トレード記録保存
async function saveTradeRecord() {
    if (!currentCalculation) {
        alert('まず計算を実行してください');
        return;
    }
    if (!currentUser) {
        alert('ログインしてください');
        return;
    }

    try {
        const record = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            date: new Date().toLocaleDateString('ja-JP'),
            time: new Date().toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }),
            ...currentCalculation,
            result: 'pending'
        };

        console.log('トレード記録を保存中:', record);
        await saveRecordToDb(record);
        tradeRecords.unshift(record);
        updateRecordsDisplay();
        
        alert('トレード記録を保存しました！');
    } catch (error) {
        console.error('記録保存エラー:', error);
        alert('記録の保存に失敗しました: ' + error.message);
    }
}

// 結果更新
async function updateTradeResult(id, result) {
    if (!currentUser) {
        alert('ログインしてください');
        return;
    }
    
    try {
        console.log('トレード結果を更新中:', id, result);
        const record = tradeRecords.find(r => r.id.toString() === id.toString());
        if (record) {
            record.result = result;
            await saveRecordToDb(record);
            updateRecordsDisplay();
            console.log('トレード結果を更新しました:', id, result);
        }
    } catch (error) {
        console.error('結果更新エラー:', error);
        alert('結果の更新に失敗しました: ' + error.message);
    }
}

// 記録表示更新
function updateRecordsDisplay() {
    updateStatsSummary();
    displayRecords();
}

// 統計サマリー更新
function updateStatsSummary() {
    const total = tradeRecords.length;
    const wins = tradeRecords.filter(r => r.result === 'win').length;
    const losses = tradeRecords.filter(r => r.result === 'loss').length;
    const pending = tradeRecords.filter(r => r.result === 'pending').length;
    
    const winRate = total > 0 ? ((wins / (wins + losses)) * 100).toFixed(1) : '0.0';
    
    const expectedProfit = tradeRecords
        .filter(r => r.result === 'win')
        .reduce((sum, r) => sum + r.expectedProfit, 0);
        
    const expectedLoss = tradeRecords
        .filter(r => r.result === 'loss')
        .reduce((sum, r) => sum + r.expectedLoss, 0);
        
    const netProfit = expectedProfit - expectedLoss;

    const html = `
        <div class="stat-card">
            <div class="stat-value">${total}</div>
            <div class="stat-label">総記録数</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${wins}</div>
            <div class="stat-label">勝ち</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${losses}</div>
            <div class="stat-label">負け</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${winRate}%</div>
            <div class="stat-label">勝率</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: ${netProfit >= 0 ? '#27ae60' : '#e74c3c'}">${Math.round(netProfit).toLocaleString()}</div>
            <div class="stat-label">純損益（円）</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${pending}</div>
            <div class="stat-label">未決済</div>
        </div>
    `;
    
    const statsSummaryElement = document.getElementById('statsSummary');
    if (statsSummaryElement) {
        statsSummaryElement.innerHTML = html;
    }
}

// レコード表示
function displayRecords() {
    let filteredRecords = [...tradeRecords];
    
    if (currentFilter !== 'all') {
        filteredRecords = filteredRecords.filter(record => record.result === currentFilter);
    }
    
    filteredRecords.sort((a, b) => {
        switch (currentSort) {
            case 'date-desc':
                return new Date(b.timestamp) - new Date(a.timestamp);
            case 'date-asc':
                return new Date(a.timestamp) - new Date(b.timestamp);
            default:
                return 0;
        }
    });

    const tbody = document.getElementById('recordsTableBody');
    if (!tbody) return;
    
    if (filteredRecords.length === 0) {
        tbody.innerHTML = '<tr><td colspan="11" style="text-align: center; padding: 20px; color: #6c757d;">記録がありません</td></tr>';
        return;
    }

    tbody.innerHTML = filteredRecords.map(record => {
        const entryDisplay = record.entryPrice.toFixed(record.pair.includes('JPY') ? 2 : 5);
        const stopDisplay = record.stopLoss.toFixed(record.pair.includes('JPY') ? 2 : 5);
        const targetDisplay = record.targetPrice.toFixed(record.pair.includes('JPY') ? 2 : 5);
        
        const isBuy = record.entryPrice < record.targetPrice;
        const tradeDirection = isBuy ? 
            '<span style="color: #2196F3; font-weight: bold;">買い</span>' : 
            '<span style="color: #f44336; font-weight: bold;">売り</span>';
        
        return `
            <tr>
                <td>${record.date}<br><small>${record.time}</small></td>
                <td><strong>${record.pair}</strong><br><small>${tradeDirection}</small></td>
                <td>${entryDisplay}</td>
                <td>${stopDisplay}</td>
                <td>${targetDisplay}</td>
                <td>${record.optimalLots.toFixed(2)}</td>
                <td style="color: #27ae60;">¥${Math.round(record.expectedProfit).toLocaleString()}</td>
                <td style="color: #e74c3c;">¥${Math.round(record.expectedLoss).toLocaleString()}</td>
                <td>1:${record.riskRewardRatio.toFixed(2)}</td>
                <td>
                    <select class="result-select" onchange="updateTradeResult(${record.id}, this.value)">
                        <option value="pending" ${record.result === 'pending' ? 'selected' : ''}>未決済 −</option>
                        <option value="win" ${record.result === 'win' ? 'selected' : ''}>勝ち ◯</option>
                        <option value="loss" ${record.result === 'loss' ? 'selected' : ''}>負け ✗</option>
                    </select>
                </td>
                <td>
                    <button class="delete-record-btn" onclick="deleteRecord(${record.id})" title="この記録を削除">
                        ❌
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

// CSV出力機能
function exportToCSV() {
    if (tradeRecords.length === 0) {
        alert('出力するデータがありません');
        return;
    }

    const headers = [
        '日付', '時間', '通貨ペア', '売買', 'エントリー価格', '損切り価格', 
        '目標価格', 'ロット数', '想定利益', '想定損失', 'RR比', '結果'
    ];

    const csvData = tradeRecords.map(record => {
        const isBuy = record.entryPrice < record.targetPrice;
        const tradeDirection = isBuy ? '買い' : '売り';
        const resultText = record.result === 'win' ? '勝ち' : 
                         record.result === 'loss' ? '負け' : '未決済';
        
        return [
            record.date,
            record.time,
            record.pair,
            tradeDirection,
            record.entryPrice,
            record.stopLoss,
            record.targetPrice,
            record.optimalLots.toFixed(2),
            Math.round(record.expectedProfit),
            Math.round(record.expectedLoss),
            `1:${record.riskRewardRatio.toFixed(2)}`,
            resultText
        ];
    });

    const csvContent = [headers, ...csvData]
        .map(row => row.map(field => `"${field}"`).join(','))
        .join('\n');

    const bom = '\uFEFF';
    const blob = new Blob([bom + csvContent], { type: 'text/csv;charset=utf-8;' });
    
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `FXトレード記録_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    console.log('CSVファイルをダウンロードしました');
    alert('CSVファイルをダウンロードしました！');
}

// クリップボードコピー機能
function copyToClipboard() {
    if (tradeRecords.length === 0) {
        alert('コピーするデータがありません');
        return;
    }

    try {
        const headers = [
            '日付', '時間', '通貨ペア', '売買', 'エントリー', '損切り', 
            '目標', 'ロット', '想定利益', '想定損失', 'RR比', '結果'
        ];

        const tableData = tradeRecords.map(record => {
            const isBuy = record.entryPrice < record.targetPrice;
            const tradeDirection = isBuy ? '買い' : '売り';
            const resultText = record.result === 'win' ? '勝ち' : 
                             record.result === 'loss' ? '負け' : '未決済';
            
            return [
                record.date,
                record.time,
                record.pair,
                tradeDirection,
                record.entryPrice,
                record.stopLoss,
                record.targetPrice,
                record.optimalLots.toFixed(2),
                Math.round(record.expectedProfit),
                Math.round(record.expectedLoss),
                `1:${record.riskRewardRatio.toFixed(2)}`,
                resultText
            ];
        });

        const clipboardContent = [headers, ...tableData]
            .map(row => row.join('\t'))
            .join('\n');

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(clipboardContent).then(function() {
                console.log('クリップボードコピー成功');
                alert('データをクリップボードにコピーしました！\nGoogle スプレッドシートに直接貼り付けできます。');
            }, function(error) {
                console.error('クリップボードコピーエラー:', error);
                alert('コピーに失敗しました: ' + error.message);
            });
        } else {
            const textArea = document.createElement('textarea');
            textArea.value = clipboardContent;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                console.log('フォールバックコピー成功');
                alert('データをクリップボードにコピーしました！');
            } catch (error) {
                console.error('フォールバックコピーエラー:', error);
                alert('コピーに失敗しました。');
            }
            document.body.removeChild(textArea);
        }
    } catch (error) {
        console.error('コピー機能でエラー:', error);
        alert('コピー機能でエラーが発生しました: ' + error.message);
    }
}

// 個別記録削除
async function deleteRecord(id) {
    if (!currentUser) {
        alert('ログインしてください');
        return;
    }
    
    try {
        const record = tradeRecords.find(r => r.id.toString() === id.toString());
        if (!record) {
            alert('削除する記録が見つかりません');
            return;
        }

        const confirmed = window.confirm(
            `この記録を削除しますか？\n\n通貨ペア: ${record.pair}\n日時: ${record.date} ${record.time}\n\nこの操作は取り消せません。`
        );

        if (confirmed) {
            console.log('個別記録を削除中:', id);
            await deleteRecordFromDb(id);
            tradeRecords = tradeRecords.filter(r => r.id.toString() !== id.toString());
            updateRecordsDisplay();
            console.log('個別記録を削除しました:', id);
            alert('記録を削除しました。');
        }
    } catch (error) {
        console.error('削除処理でエラーが発生:', error);
        alert('削除処理でエラーが発生しました: ' + error.message);
    }
}

// 全記録削除
async function confirmClearAllRecords() {
    if (!currentUser) {
        alert('ログインしてください');
        return;
    }
    
    if (tradeRecords.length === 0) {
        alert('削除するデータがありません');
        return;
    }

    const confirmed = window.confirm(
        `本当に全ての記録を削除しますか？\n\n現在の記録数: ${tradeRecords.length}件\n\nこの操作は取り消せません。`
    );

    if (confirmed) {
        const doubleConfirm = window.confirm(
            '最終確認です。\n全てのトレード記録が完全に削除されます。\n\n本当に実行しますか？'
        );

        if (doubleConfirm) {
            try {
                console.log('全記録を削除中...', tradeRecords.length + '件');
                // Firestoreから全記録を削除
                const batch = db.batch();
                tradeRecords.forEach(record => {
                    const docRef = db.collection('users').doc(currentUser.uid).collection('records').doc(record.id.toString());
                    batch.delete(docRef);
                });
                await batch.commit();
                
                tradeRecords = [];
                updateRecordsDisplay();
                console.log('全記録を削除しました');
                alert('全ての記録を削除しました。');
            } catch (error) {
                console.error('全削除エラー:', error);
                alert('削除処理でエラーが発生しました: ' + error.message);
            }
        }
    }
}

//======================================================================
// 初期化処理
//======================================================================

console.log('初期化開始');

// DOMが読み込まれた後に初期化し、イベントリスナーを設定
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM読み込み完了');
    
    // --- イベントリスナー（ボタンと機能の紐付け） ---
    
    // 新規登録ボタン
    const signupBtn = document.getElementById('signup-button');
    if (signupBtn) {
        signupBtn.addEventListener('click', signUp);
        console.log('新規登録ボタンのイベントリスナー設定完了');
    }
    
    // ログインボタン
    const loginBtn = document.getElementById('login-button');
    if (loginBtn) {
        loginBtn.addEventListener('click', logIn);
        console.log('ログインボタンのイベントリスナー設定完了');
    }
    
    // ログアウトボタン（最初隠れているので存在確認してから紐付け）
    const logoutBtn = document.getElementById('logout-button');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logOut);
        console.log('ログアウトボタンのイベントリスナー設定完了');
    }
    
    // 計算ボタン
    const calculateBtn = document.getElementById('calculate-button');
    if (calculateBtn) {
        calculateBtn.addEventListener('click', calculateOptimalLots);
        console.log('計算ボタンのイベントリスナー設定完了');
    }
    
    // 記録保存ボタン
    const saveBtn = document.getElementById('save-record-button');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveTradeRecord);
        console.log('記録保存ボタンのイベントリスナー設定完了');
    }
    
    // エクスポートボタン
    const exportCsvBtn = document.getElementById('export-csv-button');
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', exportToCSV);
        console.log('CSV出力ボタンのイベントリスナー設定完了');
    }
    
    // クリップボードコピーボタン
    const copyBtn = document.getElementById('copy-clipboard-button');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyToClipboard);
        console.log('クリップボードコピーボタンのイベントリスナー設定完了');
    }
    
    // 全削除ボタン
    const clearAllBtn = document.getElementById('clear-all-button');
    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', confirmClearAllRecords);
        console.log('全削除ボタンのイベントリスナー設定完了');
    }
    
    // ソート・フィルタボタン
    document.querySelectorAll('.control-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // ソート機能
            if (this.dataset.sort) {
                currentSort = this.dataset.sort;
                document.querySelectorAll('.control-btn[data-sort]').forEach(sortBtn => {
                    sortBtn.classList.remove('active');
                });
                this.classList.add('active');
                displayRecords();
                console.log('ソート設定:', this.dataset.sort);
            }
            
            // フィルタ機能
            if (this.dataset.filter) {
                currentFilter = this.dataset.filter;
                document.querySelectorAll('.control-btn[data-filter]').forEach(filterBtn => {
                    filterBtn.classList.remove('active');
                });
                this.classList.add('active');
                displayRecords();
                console.log('フィルタ設定:', this.dataset.filter);
            }
        });
    });
    console.log('ソート・フィルタボタンのイベントリスナー設定完了');
    
    // 口座残高入力フィールドのフォーマット処理
    const accountBalanceInput = document.getElementById('accountBalance');
    if (accountBalanceInput) {
        accountBalanceInput.addEventListener('input', function() {
            formatNumberInput(this);
        });
        accountBalanceInput.addEventListener('blur', function() {
            validateNumberInput(this);
        });
        console.log('口座残高フィールドのイベントリスナー設定完了');
    }
    
    // 通貨ペア変更時の処理
    if (currencyPair) {
        currencyPair.addEventListener('change', function() {
            console.log('通貨ペア変更: ' + this.value);
            const pair = this.value;
            const isDollarStraight = ['EURUSD', 'GBPUSD', 'AUDUSD'].includes(pair);
            
            usdJpyGroup.style.display = isDollarStraight ? 'block' : 'none';
            
            const entryPrice = document.getElementById('entryPrice');
            const stopLoss = document.getElementById('stopLoss');
            const targetPrice = document.getElementById('targetPrice');
            
            switch(pair) {
                case 'USDJPY':
                    entryPrice.value = '150.00';
                    stopLoss.value = '150.20';
                    targetPrice.value = '149.70';
                    break;
                case 'EURJPY':
                    entryPrice.value = '165.00';
                    stopLoss.value = '165.30';
                    targetPrice.value = '164.70';
                    break;
                case 'GBPJPY':
                    entryPrice.value = '190.00';
                    stopLoss.value = '190.30';
                    targetPrice.value = '189.70';
                    break;
                case 'AUDJPY':
                    entryPrice.value = '100.00';
                    stopLoss.value = '100.30';
                    targetPrice.value = '99.70';
                    break;
                case 'EURUSD':
                    entryPrice.value = '1.1000';
                    stopLoss.value = '1.0970';
                    targetPrice.value = '1.1030';
                    break;
                case 'GBPUSD':
                    entryPrice.value = '1.2700';
                    stopLoss.value = '1.2670';
                    targetPrice.value = '1.2730';
                    break;
                case 'AUDUSD':
                    entryPrice.value = '0.6700';
                    stopLoss.value = '0.6670';
                    targetPrice.value = '0.6730';
                    break;
            }
        });
        
        // 初期設定を適用
        currencyPair.dispatchEvent(new Event('change'));
        console.log('通貨ペア初期化完了');
    }
    
    console.log('全てのイベントリスナー設定完了');
    console.log('アプリケーション初期化完了');
});

console.log('FXトレード記録ツール - 最終版script.js 読み込み完了');