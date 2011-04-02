// SoftEther UT-VPN SourceCode
// 
// Copyright (C) 2004-2010 SoftEther Corporation.
// Copyright (C) 2004-2010 University of Tsukuba, Japan.
// Copyright (C) 2003-2010 Daiyuu Nobori.
// All Rights Reserved.
// 
// http://utvpn.tsukuba.ac.jp/
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// このファイルは GPL バージョン 2 ライセンスで公開されています。
// 誰でもこのファイルの内容を複製、改変したり、改変したバージョンを再配布
// することができます。ただし、原著作物を改変した場合は、原著作物の著作権表示
// を除去することはできません。改変した著作物を配布する場合は、改変実施者の
// 著作権表示を原著作物の著作権表示に付随して記載するようにしてください。
// 
// この SoftEther UT-VPN オープンソース・プロジェクトは、日本国の
// ソフトイーサ株式会社 (SoftEther Corporation, http://www.softether.co.jp/ )
// および筑波大学 (University of Tsukuba, http://www.tsukuba.ac.jp/ ) によって
// ホストされています。
// 本プログラムの配布者は、本プログラムを、業としての利用以外のため、
// および、試験または研究のために利用が行われることを想定して配布
// しています。
// SoftEther UT-VPN プロジェクトの Web サイトは http://utvpn.tsukuba.ac.jp/ に
// あります。
// 本ソフトウェアの不具合の修正、機能改良、セキュリティホールの修復などのコード
// の改変を行った場合で、その成果物を SoftEther UT-VPN プロジェクトに提出して
// いただける場合は、 http://utvpn.tsukuba.ac.jp/ までソースコードを送付して
// ください。SoftEther UT-VPN プロジェクトの本体リリースまたはブランチリリース
// に組み込みさせていただきます。
// 
// GPL に基づいて原著作物が提供される本ソフトウェアの改良版を配布、販売する
// 場合は、そのソースコードを GPL に基づいて誰にでも開示する義務が生じます。
// 
// 本ソフトウェアに関連する著作権、特許権、商標権はソフトイーサ株式会社
// (SoftEther Corporation) およびその他の著作権保持者が保有しています。
// ソフトイーサ株式会社等はこれらの権利を放棄していません。本ソフトウェアの
// 二次著作物を配布、販売する場合は、これらの権利を侵害しないようにご注意
// ください。
// 
// お願い: どのような通信ソフトウェアにも通常は必ず未発見の
// セキュリティホールが潜んでいます。本ソースコードをご覧いただいた結果、
// UT-VPN にセキュリティホールを発見された場合は、当該セキュリティホールの
// 情報を不特定多数に開示される前に、必ず、ソフトイーサ株式会社
// および脆弱性情報の届出を受け付ける公的機関まで通報いただき、
// 公益保護にご協力いただきますようお願い申し上げます。
// 
// ソフトイーサ株式会社は、当該セキュリティホールについて迅速に対処を
// 行い、UT-VPN および UT-VPN に関連するソフトウェアのユーザー・顧客
// を保護するための努力を行います。
// 
// ソフトイーサへの届出先: http://www.softether.co.jp/jp/contact/
// 日本国内の脆弱性情報届出受付公的機関:
//         独立行政法人 情報処理推進機構
//         http://www.ipa.go.jp/security/vuln/report/
// 
// 上記各事項について不明な点は、ソフトイーサ株式会社までご連絡ください。
// 連絡先: http://www.softether.co.jp/jp/contact/

// -----------------------------------------------
// [ChangeLog]
// 2010.05.20
//  新規リリース by SoftEther
// -----------------------------------------------

// CMInner.h
// CM.c の内部向けヘッダ

#define STARTUP_MUTEX_NAME	"utvpncmgr_startup_mutex"

void CmVoice(char *name);

typedef struct CM_UAC_HELPER
{
	THREAD *Thread;
	volatile bool Halt;
	EVENT *HaltEvent;
} CM_UAC_HELPER;

typedef struct CM_VOICE
{
	UINT voice_id;
	char *perfix;
} CM_VOICE;

static CM_VOICE cm_voice[] =
{
	{VOICE_SSK,		"ssk"		},
	{VOICE_AHO,		"aho"		},
};

typedef struct CM_ENUM_HUB
{
	HWND hWnd;
	THREAD *Thread;
	SESSION *Session;
	CLIENT_OPTION *ClientOption;
	TOKEN_LIST *Hub;
} CM_ENUM_HUB;

#define CM_SETTING_INIT_NONE		0
#define CM_SETTING_INIT_EASY		1	// 簡易モードへ遷移
#define CM_SETTING_INIT_NORMAL		2	// 通常モードへ遷移
#define CM_SETTING_INIT_SELECT		3	// 選択画面を表示

typedef struct CM
{
	HWND hMainWnd;
	HWND hStatusBar;
	REMOTE_CLIENT *Client;
	char *server_name;
	wchar_t *import_file_name;
	bool HideStatusBar;
	bool HideTrayIcon;
	bool ShowGrid;
	bool VistaStyle;
	bool ShowPort;
	wchar_t StatudBar1[MAX_SIZE];
	wchar_t StatudBar2[MAX_SIZE];
	wchar_t StatudBar3[MAX_SIZE];
	HICON Icon2, Icon3;
	bool IconView;
	THREAD *NotifyClientThread;
	NOTIFY_CLIENT *NotifyClient;
	volatile bool Halt;
	bool OnCloseDispatched;
	LIST *StatusWindowList;
	CEDAR *Cedar;
	LIST *EnumHubList;
	UINT WindowCount;
	bool DisableVoice;
	UINT VoiceId;
	UINT OldConnectedNum;
	bool UpdateConnectedNumFlag;
	UCHAR ShortcutKey[SHA1_SIZE];
	bool TrayInited;
	bool TrayAnimation;
	bool TraySpeedAnimation;
	UINT TrayAnimationCounter;
	bool StartupMode;
	THREAD *TryExecUiHelperThread;
	volatile bool TryExecUiHelperHalt;
	HANDLE TryExecUiHelperProcessHandle;
	EVENT *TryExecUiHelperHaltEvent;
	bool WindowsShutdowning;
	bool CmSettingSupported;
	bool CmEasyModeSupported;
	bool CmSettingInitialFlag;
	CM_SETTING CmSetting;
	HWND hEasyWnd;
	bool StartupFinished;
	bool ConnectStartedFlag;
	bool PositiveDisconnectFlag;
	wchar_t EasyLastSelectedAccountName[MAX_ACCOUNT_NAME_LEN + 1];
	WINDOWPLACEMENT FakeWindowPlacement;
	INSTANCE *StartupMutex;
	bool BadProcessChecked;
	bool MenuPopuping;
	bool SplashHasBeenShown;
} CM;

typedef struct CM_STATUS
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];		// アカウント名
	HWND hWndPolicy;					// ポリシーダイアログ
} CM_STATUS;

typedef struct CM_POLICY
{
	HWND hWnd;
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];		// アカウント名
	POLICY *Policy;						// ポリシーダイアログ
	CM_STATUS *CmStatus;				// CM_STATUS
	bool Extension;						// 拡張
} CM_POLICY;

typedef struct CM_ACCOUNT
{
	bool EditMode;						// 編集モード (false: 新規作成モード)
	bool LinkMode;						// リンクモード
	bool NatMode;						// NAT モード
	CLIENT_OPTION *ClientOption;		// クライアントオプション
	CLIENT_AUTH *ClientAuth;			// 認証データ
	bool Startup;						// スタートアップアカウント
	bool CheckServerCert;				// サーバー証明書のチェック
	X *ServerCert;						// サーバー証明書
	char old_server_name[MAX_HOST_NAME_LEN + 1];	// 古いサーバー名
	bool Inited;						// 初期化フラグ
	POLICY Policy;						// ポリシー (リンクモードのみ)
	struct SM_HUB *Hub;					// HUB
	RPC *Rpc;							// RPC
	bool OnlineFlag;					// オンライン フラグ
	bool Flag1;							// フラグ 1
	bool HideClientCertAuth;			// クライアント認証を隠す
	bool HideSecureAuth;				// スマートカード認証を隠す
	bool HideTrustCert;					// 信頼する証明機関ボタンを隠す
	UCHAR ShortcutKey[SHA1_SIZE];		// ショートカットキー
	bool LockMode;						// 設定ロックモード
	bool Link_ConnectNow;				// すぐに接続を開始する
	UINT PolicyVer;						// ポリシーバージョン
} CM_ACCOUNT;

typedef struct CM_CHANGE_PASSWORD
{
	CLIENT_OPTION *ClientOption;		// クライアントオプション
	char Username[MAX_USERNAME_LEN + 1];	// ユーザー名
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB 名
} CM_CHANGE_PASSWORD;

typedef struct CM_TRAFFIC
{
	bool ServerMode;		// サーバーモード
	bool Double;			// 2 倍モード
	bool Raw;				// 生データモード
	UINT Port;				// ポート番号
	char Host[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT NumTcp;			// TCP コネクション数
	UINT Type;				// 種類
	UINT Span;				// 期間
} CM_TRAFFIC;

typedef struct CM_TRAFFIC_DLG
{
	HWND hWnd;				// ウインドウハンドル
	CM_TRAFFIC *Setting;	// 設定
	TTS *Tts;				// 測定サーバー
	TTC *Ttc;				// 測定クライアント
	THREAD *HaltThread;		// 停止用スレッド
	THREAD *ClientEndWaitThread;	// クライアントが終了するのを待機するスレッド
	bool Started;			// 開始フラグ
	bool Stopping;			// 停止中
	UINT RetCode;			// 戻り値
	TT_RESULT Result;		// 結果
	EVENT *ResultShowEvent;	// 結果表示イベント
	bool CloseDialogAfter;	// ダイアログを閉じるかどうかのフラグ
} CM_TRAFFIC_DLG;

// インターネット接続設定
typedef struct CM_INTERNET_SETTING
{
	UINT ProxyType;								// プロキシサーバーの種類
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// プロキシサーバーホスト名
	UINT ProxyPort;								// プロキシサーバーポート番号
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// プロキシサーバーユーザー名
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// プロキシサーバーパスワード
} CM_INTERNET_SETTING;

static CM *cm = NULL;

void CmFreeTrayExternal(void *hWnd);

// 通常 RPC 呼び出しマクロ
__forceinline static bool CALL(HWND hWnd, UINT code)
{
	UINT ret = code;
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_DISCONNECTED)
		{
			if (cm != NULL)
			{
				Close(cm->hMainWnd);
			}
			else
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_DISCONNECTED"));
			}

			if (cm != NULL)
			{
				CmFreeTrayExternal((void *)cm->hMainWnd);
			}
			exit(0);
		}
		else
		{
			UINT flag = MB_ICONEXCLAMATION;
			if (ret == ERR_VLAN_IS_USED)
			{
				CmVoice("using_vlan");
			}
			if (hWnd != NULL && cm != NULL && cm->hEasyWnd != NULL)
			{
				hWnd = cm->hEasyWnd;
			}
			if (hWnd != NULL && cm != NULL && hWnd == cm->hEasyWnd)
			{
				flag |= MB_SETFOREGROUND | MB_TOPMOST;
			}
			MsgBox(hWnd, flag, _E(ret));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// 拡張 RPC 呼び出しマクロ (エラー値を取得する)
__forceinline static UINT CALLEX(HWND hWnd, UINT code)
{
	UINT ret = code;
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_DISCONNECTED)
		{
			if (cm != NULL)
			{
				Close(cm->hMainWnd);
			}
			else
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_DISCONNECTED"));
			}
			if (cm != NULL)
			{
				CmFreeTrayExternal((void *)cm->hMainWnd);
			}
			exit(0);
		}
	}

	return ret;
}

typedef struct CM_LOADX
{
	X *x;
} CM_LOADX;

typedef struct CM_SETTING_DLG
{
	bool CheckPassword;
	UCHAR HashedPassword[SHA1_SIZE];
} CM_SETTING_DLG;

typedef struct CM_EASY_DLG
{
	bool EndDialogCalled;
} CM_EASY_DLG;


// タスクトレイ関係
#define	WM_CM_TRAY_MESSAGE			(WM_APP + 44)
#define WM_CM_SETTING_CHANGED_MESSAGE	(WM_APP + 45)
#define WM_CM_EASY_REFRESH			(WM_APP + 46)
#define WM_CM_SHOW					(WM_APP + 47)
#define	CMD_EASY_DBLCLICK			40697
#define	CM_TRAY_ANIMATION_INTERVAL	3000
#define	CM_TRAY_MAX_ITEMS			4096
#define	CM_TRAY_MENU_ID_START		12000
#define	CM_TRAY_MENU_CONNECT_ID_START	(CM_TRAY_MENU_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_STATUS_ID_START	(CM_TRAY_MENU_CONNECT_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_DISCONNECT_ID_START	(CM_TRAY_MENU_STATUS_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_RECENT_ID_START	(CM_TRAY_MENU_DISCONNECT_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_IS_CONNECT_ID(id)	(((id) >= CM_TRAY_MENU_CONNECT_ID_START) && (id) < CM_TRAY_MENU_STATUS_ID_START)
#define	CM_TRAY_IS_STATUS_ID(id)	(((id) >= CM_TRAY_MENU_STATUS_ID_START) && (id) < CM_TRAY_MENU_DISCONNECT_ID_START)
#define	CM_TRAY_IS_DISCONNECT_ID(id)	(((id) >= CM_TRAY_MENU_DISCONNECT_ID_START) && (id) < (CM_TRAY_MENU_DISCONNECT_ID_START + CM_TRAY_MAX_ITEMS))
#define	CM_TRAY_IS_RECENT_ID(id)	(((id) >= CM_TRAY_MENU_RECENT_ID_START) && (id) < (CM_TRAY_MENU_RECENT_ID_START + CM_TRAY_MAX_ITEMS))

// スプラッシュスクリーンの枠線の色
#define	CM_SPLASH_BORDER_COLOR	(RGB(102, 0, 204))


// 関数プロトタイプ
void InitCM();
void FreeCM();
void MainCM();
bool LoginCM();
void LogoutCM();
UINT CmLoginDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void MainCMWindow();
void CmSendImportMessage(HWND hWnd, wchar_t *filename, UINT msg);
UINT CmMainWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmMainWindowOnSize(HWND hWnd);
void CmMainWindowOnInit(HWND hWnd);
void CmMainWindowOnQuit(HWND hWnd);
void CmSaveMainWindowPos(HWND hWnd);
void CmMainWindowOnCommand(HWND hWnd, WPARAM wParam, LPARAM lParam);
void CmMainWindowOnCommandEx(HWND hWnd, WPARAM wParam, LPARAM lParam, bool easy);
bool CmIsEnabled(HWND hWnd, UINT id);
bool CmIsChecked(UINT id);
bool CmIsBold(UINT id);
void CmMainWindowOnPopupMenu(HWND hWnd, HMENU hMenu, UINT pos);
void CmSaveMainWindowPos(HWND hWnd);
void CmRedrawStatusBar(HWND hWnd);
void CmRefresh(HWND hWnd);
void CmRefreshEx(HWND hWnd, bool style_changed);
void CmSetForegroundProcessToCnService();
void CmInitAccountList(HWND hWnd);
void CmInitAccountListEx(HWND hWnd, bool easy);
void CmInitVLanList(HWND hWnd);
void CmRefreshAccountList(HWND hWnd);
void CmRefreshAccountListEx(HWND hWnd, bool easy);
void CmRefreshAccountListEx2(HWND hWnd, bool easy, bool style_changed);
void CmRefreshVLanList(HWND hWnd);
void CmRefreshVLanListEx(HWND hWnd, bool style_changed);
void CmSaveAccountListPos(HWND hWnd);
void CmSaveVLanListPos(HWND hWnd);
wchar_t *CmGetProtocolName(UINT n);
void CmVLanNameToPrintName(char *str, UINT size, char *name);
bool CmPrintNameToVLanName(char *name, UINT size, char *str);
void CmMainWindowOnNotify(HWND hWnd, NMHDR *n);
void CmOnKey(HWND hWnd, bool ctrl, bool alt, UINT key);
void CmAccountListRightClick(HWND hWnd);
void CmVLanListRightClick(HWND hWnd);
void CmConnect(HWND hWnd, wchar_t *account_name);
void CmDisconnect(HWND hWnd, wchar_t *account_name);
void CmInitNotifyClientThread();
void CmFreeNotifyClientThread();
void CmNotifyClientThread(THREAD *thread, void *param);
void CmDeleteAccount(HWND hWnd, wchar_t *account_name);
void CmStatus(HWND hWnd, wchar_t *account_name);
void CmStatusDlg(HWND hWnd, wchar_t *account_name);
UINT CmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmStatusDlgPrint(HWND hWnd, CM_STATUS *cmst);
void CmPrintStatusToListView(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s);
void CmPrintStatusToListViewEx(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode);
void CmStatusDlgPrintCert(HWND hWnd, CM_STATUS *st, bool server);
void CmPolicyDlg(HWND hWnd, CM_STATUS *st);
UINT CmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmPolicyDlgPrint(HWND hWnd, CM_POLICY *p);
void CmPolicyDlgPrintEx(HWND hWnd, CM_POLICY *p, bool cascade_mode);
void CmPolicyDlgPrintEx2(HWND hWnd, CM_POLICY *p, bool cascade_mode, bool ver);
void CmNewAccount(HWND hWnd);
void CmEditAccount(HWND hWnd, wchar_t *account_name);
void CmGenerateNewAccountName(HWND hWnd, wchar_t *name, UINT size);
void CmGenerateCopyName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name);
void CmGenerateImportName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name);
CM_ACCOUNT *CmCreateNewAccountObject(HWND hWnd);
CM_ACCOUNT *CmGetExistAccountObject(HWND hWnd, wchar_t *account_name);
void CmEnumHubStart(HWND hWnd, CLIENT_OPTION *o);
void CmInitEnumHub();
void CmFreeEnumHub();
void CmFreeAccountObject(HWND hWnd, CM_ACCOUNT *a);
bool CmEditAccountDlg(HWND hWnd, CM_ACCOUNT *a);
UINT CmEditAccountDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmEditAccountDlgUpdate(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgInit(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgOnOk(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgStartEnumHub(HWND hWnd, CM_ACCOUNT *a);
bool CmLoadXAndK(HWND hWnd, X **x, K **k);
bool CmLoadK(HWND hWnd, K **k);
bool CmLoadKEx(HWND hWnd, K **k, char *filename, UINT size);
bool CmLoadKExW(HWND hWnd, K **k, wchar_t *filename, UINT size);
bool CmLoadXFromFileOrSecureCard(HWND hWnd, X **x);
void CmLoadXFromFileOrSecureCardDlgInit(HWND hWnd, CM_LOADX *p);
void CmLoadXFromFileOrSecureCardDlgUpdate(HWND hWnd, CM_LOADX *p);
UINT CmLoadXFromFileOrSecureCardDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CmLoadX(HWND hWnd, X **x);
bool CmLoadXEx(HWND hWnd, X **x, char *filename, UINT size);
bool CmLoadXExW(HWND hWnd, X **x, wchar_t *filename, UINT size);
X *CmGetIssuer(X *x);
bool CmProxyDlg(HWND hWnd, CLIENT_OPTION *a);
void CmProxyDlgUpdate(HWND hWnd, CLIENT_OPTION *a);
UINT CmProxyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CmDetailDlg(HWND hWnd, CM_ACCOUNT *a);
UINT CmDetailDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
char *CmNewVLanDlg(HWND hWnd);
UINT CmNewVLanDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmCopyAccount(HWND hWnd, wchar_t *account_name);
void CmExportAccount(HWND hWnd, wchar_t *account_name);
void CmSortcut(HWND hWnd, wchar_t *account_name);
void CmImportAccount(HWND hWnd);
void CmImportAccountMain(HWND hWnd, wchar_t *filename);
void CmImportAccountMainEx(HWND hWnd, wchar_t *filename, bool overwrite);
void CmTrustDlg(HWND hWnd);
UINT CmTrustDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrustDlgUpdate(HWND hWnd);
void CmTrustDlgRefresh(HWND hWnd);
void CmTrustImport(HWND hWnd);
void CmTrustExport(HWND hWnd);
void CmTrustView(HWND hWnd);
void CmPassword(HWND hWnd);
UINT CmPasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmPasswordRefresh(HWND hWnd);
void CmRefreshStatusBar(HWND hWnd);
UINT CmGetNumConnected(HWND hWnd);
void CmDisconnectAll(HWND hWnd);
wchar_t *CmGenerateMainWindowTitle();
void CmConfigDlg(HWND hWnd);
UINT CmConfigDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmConfigDlgInit(HWND hWnd);
void CmConfigDlgRefresh(HWND hWnd);
void CmConfigDlgOnOk(HWND hWnd);
bool CmWarningDesktop(HWND hWnd, wchar_t *account_name);
UINT CmDesktopDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmDesktopDlgInit(HWND hWnd, wchar_t *account_name);
void CmChangePassword(HWND hWnd, CLIENT_OPTION *o, char *hubname, char *username);
UINT CmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmChangePasswordUpdate(HWND hWnd, CM_CHANGE_PASSWORD *p);
void SmShowPublicVpnServerHtml(HWND hWnd);
void CmConnectShortcut(UCHAR *key);
UINT CmSelectSecure(HWND hWnd, UINT current_id);
void CmClientSecureManager(HWND hWnd);
UINT CmClientSelectSecure(HWND hWnd);
UINT CmSelectSecureDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSelectSecureDlgInit(HWND hWnd, UINT default_id);
void CmSelectSecureDlgUpdate(HWND hWnd);
void CmSecureManager(HWND hWnd, UINT id);
void CmSecureManagerEx(HWND hWnd, UINT id, bool no_new_cert);
UINT CmSecureManagerDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecureManagerDlgInit(HWND hWnd, UINT id);
void CmSecureManagerDlgUpdate(HWND hWnd, UINT id);
void CmSecureManagerDlgRefresh(HWND hWnd, UINT id);
void CmSecureManagerDlgPrintList(HWND hWnd, LIST *o);
void CmSecureManagerDlgPrintListEx(HWND hWnd, UINT id, LIST *o, UINT type);
wchar_t *CmSecureObjTypeToStr(UINT type);
UINT CmSecureType(HWND hWnd);
UINT CmSecureTypeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecureManagerDlgImport(HWND hWnd, UINT id);
void CmSecureManagerDlgDelete(HWND hWnd, UINT id);
void CmSecureManagerDlgExport(HWND hWnd, UINT id);
void CmSecureManagerDlgNewCert(HWND hWnd, UINT id);
void CmSecurePin(HWND hWnd, UINT id);
UINT CmSecurePinDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecurePinDlgUpdate(HWND hWnd);
void CmInitTray(HWND hWnd);
void CmPollingTray(HWND hWnd);
void CmFreeTray(HWND hWnd);
void CmChangeTrayString(HWND hWnd, wchar_t *str);
UINT CmGetTrayIconId(bool animation, UINT animation_counter);
void CmShowOrHideWindow(HWND hWnd);
void CmShowTrayMenu(HWND hWnd);
HMENU CmCreateTraySubMenu(HWND hWnd, bool flag, UINT start_id);
HMENU CmCreateRecentSubMenu(HWND hWnd, UINT start_id);
bool CmCheckPkcsEula(HWND hWnd, UINT id);
UINT CmPkcsEulaDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmDeleteOldStartupTrayFile();
UINT CmTrafficDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficDlgInit(HWND hWnd);
bool CmTrafficDlgUpdate(HWND hWnd);
void CmTrafficDlgOnOk(HWND hWnd);
bool CmTrafficLoadFromReg(CM_TRAFFIC *t);
void CmTrafficGetDefaultSetting(CM_TRAFFIC *t);
void CmTrafficSaveToReg(CM_TRAFFIC *t);
void CmTrafficDlgToStruct(HWND hWnd, CM_TRAFFIC *t);
void CmExecTraffic(HWND hWnd, CM_TRAFFIC *t);
UINT CmTrafficRunDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficRunDlgInit(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgStart(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgPrintProc(void *param, wchar_t *str);
void CmTrafficRunDlgAddStr(HWND hWnd, wchar_t *str);
void CmTrafficRunDlgHalt(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgHaltThread(THREAD *t, void *param);
void CmTrafficRunDlgClientWaitThread(THREAD *t, void *param);
void CmTrafficResult(HWND hWnd, TT_RESULT *r);
UINT CmTrafficResultDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficResultDlgInit(HWND hWnd, TT_RESULT *res);
void CmTryToExecUiHelper();
void CmInitTryToExecUiHelper();
void CmFreeTryToExecUiHelper();
void CmTryToExecUiHelperThread(THREAD *thread, void *param);
bool CmSetting(HWND hWnd);
UINT CmSettingDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSettingDlgInit(HWND hWnd, CM_SETTING_DLG *d);
void CmSettingDlgUpdate(HWND hWnd, CM_SETTING_DLG *d);
void CmSettingDlgOnOk(HWND hWnd, CM_SETTING_DLG *d);
void CmApplyCmSetting();
void CmMainWindowOnTrayClicked(HWND hWnd, WPARAM wParam, LPARAM lParam);
void CmShowEasy();
void CmCloseEasy();
void CmMainWindowOnShowEasy(HWND hWnd);
UINT CmEasyDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmEasyDlgInit(HWND hWnd, CM_EASY_DLG *d);
void CmEasyDlgUpdate(HWND hWnd, CM_EASY_DLG *d);
void CmEasyDlgRefresh(HWND hWnd, CM_EASY_DLG *d);
void CmRefreshEasy();
void CmEasyDlgOnNotify(HWND hWnd, CM_EASY_DLG *d, NMHDR *n);
void CmEasyDlgOnKey(HWND hWnd, CM_EASY_DLG *d, bool ctrl, bool alt, UINT key);
void CmEasyDlgOnCommand(HWND hWnd, CM_EASY_DLG *d, WPARAM wParam, LPARAM lParam);
bool CmStartStartupMutex();
void CmEndStartupMutex();
void CmSetUacWindowActive();
void CmUacHelperThread(THREAD *thread, void *param);
void CmProxyDlgUseForIE(HWND hWnd, CLIENT_OPTION *o);
void CmGetSystemInternetSetting(CM_INTERNET_SETTING *setting);
void CmProxyDlgSet(HWND hWnd, CLIENT_OPTION *o, CM_INTERNET_SETTING *setting);
bool CmGetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type);
void *CmUpdateJumpList(UINT start_id);



