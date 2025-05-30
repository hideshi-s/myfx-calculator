console.log('FXトレード記録ツール開始');

// グローバル変数
let tradeRecords = [];
let currentCalculation = null;
let currentSort = 'date-desc';
let currentFilter = 'all';

const currencyPair = document.getElementById('currencyPair');
const usdJpyGroup = document.getElementById('usdJpyGroup');
const results = document.getElementById('results');
const warning = document.getElementById('warning');

// localStorage関連の関数（実際のWebサイトでのみ動作）
function loadRecords() {
    try {
        // 注意: Claude.ai環境では動作しません。実際のWebサイトでは正常に動作します。
        const saved = localStorage.getItem('fxTradeRecords');
        if (saved) {
            tradeRecords = JSON.parse(saved);
            console.log('記録を読み込みました:', tradeRecords.length + '件');
        }
    } catch (error) {
        console.log('記録の読み込みに失敗しました（Claude.ai環境では正常）:', error.message);
        tradeRecords = []; // Claude.ai環境ではメモリ内のみで動作
    }
    updateRecordsDisplay();
}

function saveRecords() {
    try {
        // 注意: Claude.ai環境では動作しません。実際のWebサイトでは正常に動作します。
        localStorage.setItem('fxTradeRecords', JSON.stringify(tradeRecords));
        console.log('記録を保存しました:', tradeRecords.length + '件');
    } catch (error) {
        console.log('記録の保存に失敗しました（Claude.ai環境では正常）:', error.message);
        // Claude.ai環境ではメモリ内のみで動作継続
    }
}

// 通貨ペア変更時の処理
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

// 数値フォーマット関数
function formatNumberInput(input) {
    // カーソル位置を保存
    const cursorPosition = input.selectionStart;
    const originalLength = input.value.length;
    
    // 入力中はカンマを一時的に削除して数値のみにする
    let value = input.value.replace(/,/g, '');
    
    // 数値以外の文字を削除
    value = value.replace(/[^\d]/g, '');
    
    // 3桁区切りでカンマを追加
    if (value) {
        const formattedValue = parseInt(value).toLocaleString();
        input.value = formattedValue;
        
        // カーソル位置を調整
        const newLength = formattedValue.length;
        const lengthDiff = newLength - originalLength;
        const newCursorPosition = cursorPosition + lengthDiff;
        
        // カーソル位置を復元
        setTimeout(() => {
            input.setSelectionRange(newCursorPosition, newCursorPosition);
        }, 0);
    } else {
        input.value = '';
    }
}

function validateNumberInput(input) {
    // フォーカスが外れたときの最終チェック
    let value = input.value.replace(/,/g, '');
    if (value && !isNaN(value)) {
        input.value = parseInt(value).toLocaleString();
    } else if (!value) {
        input.value = '';
    }
}

function getNumericValue(input) {
    // カンマを削除して数値として取得
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

        // JPY通貨ペアの場合（1ロット = 100,000通貨、1pip = 1,000円）
        if (['USDJPY', 'EURJPY', 'GBPJPY', 'AUDJPY'].includes(pair)) {
            // JPYペアは小数点以下2桁で1pip = 0.01
            pips = Math.abs(entryPrice - stopLoss) * 100;
            targetPips = Math.abs(entryPrice - targetPrice) * 100;
            
            // 1ロット（100,000通貨）で1pip = 1,000円
            lossPerLot = pips * 1000;
            profitPerLot = targetPips * 1000;
            
            optimalLots = riskAmount / lossPerLot;
            
            // 証拠金計算（レバレッジ1000倍想定）
            requiredMargin = (entryPrice * 100000 * optimalLots) / 1000;
        }
        // ドルストレート通貨ペアの場合（1ロット = 100,000通貨、1pip = 10USD）
        else {
            // ドルストレートは小数点以下4桁で1pip = 0.0001
            pips = Math.abs(entryPrice - stopLoss) * 10000;
            targetPips = Math.abs(entryPrice - targetPrice) * 10000;
            
            // 1ロット（100,000通貨）で1pip = 10USD
            const lossPerLotUSD = pips * 10;
            const profitPerLotUSD = targetPips * 10;
            
            // USDをJPYに換算
            lossPerLot = lossPerLotUSD * usdJpyRate;
            profitPerLot = profitPerLotUSD * usdJpyRate;
            
            optimalLots = riskAmount / lossPerLot;
            
            // 証拠金計算（レバレッジ1000倍想定）
            requiredMargin = (100000 * optimalLots * usdJpyRate) / 1000;
        }

        const expectedProfit = optimalLots * profitPerLot;
        const expectedLoss = optimalLots * lossPerLot;
        const riskRewardRatio = profitPerLot / lossPerLot;

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

        // 結果表示（修正：小数点以下を削除）
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
function saveTradeRecord() {
    if (!currentCalculation) {
        alert('まず計算を実行してください');
        return;
    }

    const record = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        date: new Date().toLocaleDateString('ja-JP'),
        time: new Date().toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }),
        ...currentCalculation,
        result: 'pending' // pending, win, loss
    };

    tradeRecords.unshift(record); // 最新を先頭に追加
    saveRecords();
    updateRecordsDisplay();
    
    alert('トレード記録を保存しました！');
}

// 結果更新
function updateTradeResult(id, result) {
    const record = tradeRecords.find(r => r.id === id);
    if (record) {
        record.result = result;
        saveRecords();
        updateRecordsDisplay();
    }
}

// 記録表示更新
function updateRecordsDisplay() {
    updateStatsSummary();
    displayRecords();
}

// 統計サマリー更新（修正：小数点以下を削除）
function updateStatsSummary() {
    const total = tradeRecords.length;
    const wins = tradeRecords.filter(r => r.result === 'win').length;
    const losses = tradeRecords.filter(r => r.result === 'loss').length;
    const pending = tradeRecords.filter(r => r.result === 'pending').length;
    
    const winRate = total > 0 ? ((wins / (wins + losses)) * 100).toFixed(1) : '0.0';
    
    // 想定損益を計算
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
    
    document.getElementById('statsSummary').innerHTML = html;
}

// レコード表示（修正：小数点以下を削除）
function displayRecords() {
    let filteredRecords = [...tradeRecords];
    
    // フィルタリング
    if (currentFilter !== 'all') {
        filteredRecords = filteredRecords.filter(record => record.result === currentFilter);
    }
    
    // ソート
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
    
    if (filteredRecords.length === 0) {
        tbody.innerHTML = '<tr><td colspan="11" style="text-align: center; padding: 20px; color: #6c757d;">記録がありません</td></tr>';
        return;
    }

    tbody.innerHTML = filteredRecords.map(record => {
        const resultBadge = getResultBadge(record.result);
        
        // 小数点以下桁数を適切に設定
        const entryDisplay = record.entryPrice.toFixed(record.pair.includes('JPY') ? 2 : 5);
        const stopDisplay = record.stopLoss.toFixed(record.pair.includes('JPY') ? 2 : 5);
        const targetDisplay = record.targetPrice.toFixed(record.pair.includes('JPY') ? 2 : 5);
        
        // 買い/売り判定
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

// 結果バッジ
function getResultBadge(result) {
    const badges = {
        'win': '<span class="result-badge result-win">勝利 ◯</span>',
        'loss': '<span class="result-badge result-loss">敗北 ✗</span>',
        'pending': '<span class="result-badge result-pending">未決済 −</span>'
    };
    return badges[result] || badges['pending'];
}

// CSV出力機能（修正：小数点以下を削除）
function exportToCSV() {
    if (tradeRecords.length === 0) {
        alert('出力するデータがありません');
        return;
    }

    // CSVヘッダー
    const headers = [
        '日付', '時間', '通貨ペア', '売買', 'エントリー価格', '損切り価格', 
        '目標価格', 'ロット数', '想定利益', '想定損失', 'RR比', '結果'
    ];

    // データ変換
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

    // CSV文字列作成
    const csvContent = [headers, ...csvData]
        .map(row => row.map(field => `"${field}"`).join(','))
        .join('\n');

    // BOM付きUTF-8でエンコード（Excel対応）
    const bom = '\uFEFF';
    const blob = new Blob([bom + csvContent], { type: 'text/csv;charset=utf-8;' });
    
    // ダウンロード
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `FXトレード記録_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    alert('CSVファイルをダウンロードしました！\nGoogle スプレッドシートで開くことができます。');
}

// クリップボードコピー機能（修正：小数点以下を削除）
function copyToClipboard() {
    console.log('コピー機能が呼び出されました');
    
    if (tradeRecords.length === 0) {
        alert('コピーするデータがありません');
        return;
    }

    try {
        // ヘッダー
        const headers = [
            '日付', '時間', '通貨ペア', '売買', 'エントリー', '損切り', 
            '目標', 'ロット', '想定利益', '想定損失', 'RR比', '結果'
        ];

        // データ変換
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

        // タブ区切りテキスト作成（スプレッドシート用）
        const clipboardContent = [headers, ...tableData]
            .map(row => row.join('\t'))
            .join('\n');

        console.log('コピー内容:', clipboardContent);

        // クリップボードにコピー
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(clipboardContent).then(function() {
                alert('データをクリップボードにコピーしました！\nGoogle スプレッドシートに直接貼り付けできます。');
            }, function(error) {
                console.error('クリップボードコピーエラー:', error);
                alert('コピーに失敗しました: ' + error.message);
            });
        } else {
            // フォールバック: テキストエリアを使用
            const textArea = document.createElement('textarea');
            textArea.value = clipboardContent;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                alert('データをクリップボードにコピーしました！\nGoogle スプレッドシートに直接貼り付けできます。');
            } catch (error) {
                console.error('フォールバックコピーエラー:', error);
                alert('コピーに失敗しました。手動でデータを選択してコピーしてください。');
            }
            document.body.removeChild(textArea);
        }
    } catch (error) {
        console.error('コピー機能でエラー:', error);
        alert('コピー機能でエラーが発生しました: ' + error.message);
    }
}

// 個別記録削除
function deleteRecord(id) {
    console.log('削除機能が呼び出されました。ID:', id);
    
    try {
        const record = tradeRecords.find(r => r.id === id);
        if (!record) {
            console.log('記録が見つかりません。ID:', id);
            alert('削除する記録が見つかりません');
            return;
        }

        console.log('削除対象の記録:', record);

        const confirmed = window.confirm(
            `この記録を削除しますか？\n\n通貨ペア: ${record.pair}\n日時: ${record.date} ${record.time}\n\nこの操作は取り消せません。`
        );

        if (confirmed) {
            console.log('削除が確認されました');
            
            // 配列から削除
            const beforeLength = tradeRecords.length;
            tradeRecords = tradeRecords.filter(r => r.id !== id);
            const afterLength = tradeRecords.length;
            
            console.log(`削除前: ${beforeLength}件, 削除後: ${afterLength}件`);
            
            // 保存
            saveRecords();
            
            // 表示更新
            updateRecordsDisplay();
            
            alert('記録を削除しました。統計も更新されました。');
        } else {
            console.log('削除がキャンセルされました');
        }
    } catch (error) {
        console.error('削除処理でエラーが発生:', error);
        alert('削除処理でエラーが発生しました: ' + error.message);
    }
}

// 全記録削除（確認付き）
function confirmClearAllRecords() {
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
            tradeRecords = [];
            saveRecords();
            updateRecordsDisplay();
            updateStatsSummary();
            alert('全ての記録を削除しました。');
        }
    }
}

// ソート機能
function sortRecords(sortType) {
    currentSort = sortType;
    
    // ボタンのactive状態更新
    document.querySelectorAll('.control-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    displayRecords();
}

// フィルタ機能
function filterRecords(filterType) {
    currentFilter = filterType;
    
    // ボタンのactive状態更新
    document.querySelectorAll('.control-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    displayRecords();
}

// 全記録削除
function clearAllRecords() {
    if (confirm('本当に全ての記録を削除しますか？この操作は取り消せません。')) {
        tradeRecords = [];
        saveRecords();
        updateRecordsDisplay();
        alert('全ての記録を削除しました');
    }
}

// 初期化
console.log('初期化開始');
currencyPair.dispatchEvent(new Event('change'));
loadRecords(); // 保存された記録を読み込み
console.log('初期化完了');