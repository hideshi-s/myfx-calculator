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
            timestamp: new Date().toI