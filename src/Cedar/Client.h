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

// Client.h
// Client.c のヘッダ

#ifndef	CLIENT_H
#define	CLIENT_H

#define	CLIENT_CONFIG_PORT					9930		// クライアントポート番号
#define	CLIENT_NOTIFY_PORT					9983		// クライアント通知ポート番号
#define CLIENT_WAIT_CN_READY_TIMEOUT		(10 * 1000)	// クライアント通知サービスが起動するまでの待機時間


// クライアントが指定された OS_TYPE で稼動するかどうかチェック
#define	IS_CLIENT_SUPPORTED_OS(t)			\
	((OS_IS_WINDOWS_NT(t) && GET_KETA(t, 100) >= 2) || (OS_IS_WINDOWS_9X(t)))


// 定数
#define	CLIENT_CONFIG_FILE_NAME				"@vpn_client.config"
#define	CLIENT_DEFAULT_KEEPALIVE_HOST		"keepalive.utvpn.tsukuba.ac.jp"
#define	CLIENT_DEFAULT_KEEPALIVE_PORT		80
#define	CLIENT_DEFAULT_KEEPALIVE_INTERVAL	KEEP_INTERVAL_DEFAULT

#define	CLIENT_RPC_MODE_NOTIFY				0
#define	CLIENT_RPC_MODE_MANAGEMENT			1
#define	CLIENT_RPC_MODE_SHORTCUT			2
#define	CLIENT_RPC_MODE_SHORTCUT_DISCONNECT	3

#define	CLIENT_MACOS_TAP_NAME				"tap0"

#define	CLIENT_SAVER_INTERVAL				(30 * 1000)

#define	CLIENT_NOTIFY_SERVICE_INSTANCENAME	"utvpnclient_uihelper"

#define	CLIENT_WIN32_EXE_FILENAME			"utvpnclient.exe"
#define	CLIENT_WIN32_EXE_FILENAME_X64		"utvpnclient_x64.exe"
#define	CLIENT_WIN32_EXE_FILENAME_IA64		"utvpnclient_ia64.exe"

#define CLIENT_CUSTOM_INI_FILENAME			"@custom.ini"


// UNIX における仮想 LAN カードの一覧
struct UNIX_VLAN
{
	bool Enabled;							// 有効フラグ
	char Name[MAX_SIZE];					// 名前
	UCHAR MacAddress[6];					// MAC アドレス
	UCHAR Padding[2];
};

// アカウント
struct ACCOUNT
{
	// 静的データ
	CLIENT_OPTION *ClientOption;			// クライアント オプション
	CLIENT_AUTH *ClientAuth;				// クライアント認証データ
	bool CheckServerCert;					// サーバー証明書をチェックする
	X *ServerCert;							// サーバー証明書
	bool StartupAccount;					// スタートアップアカウントにする
	UCHAR ShortcutKey[SHA1_SIZE];			// キー
	UINT64 CreateDateTime;					// 作成日時
	UINT64 UpdateDateTime;					// 更新日時
	UINT64 LastConnectDateTime;				// 最終接続日時

	// 動的データ
	LOCK *lock;								// ロック
	SESSION *ClientSession;					// クライアントセッション
	CLIENT_STATUS_PRINTER *StatusPrinter;	// ステータス表示器

	SOCK *StatusWindow;						// ステータスウインドウ
};

// クライアント設定
struct CLIENT_CONFIG
{
	bool AllowRemoteConfig;					// リモート設定を許可する
	bool UseKeepConnect;					// インターネットへの接続を維持
	char KeepConnectHost[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT KeepConnectPort;					// ポート番号
	UINT KeepConnectProtocol;				// プロトコル
	UINT KeepConnectInterval;				// 間隔
};

// バージョン取得
struct RPC_CLIENT_VERSION
{
	char ClientProductName[128];		// クライアント製品名
	char ClientVersionString[128];		// クライアントバージョン文字列
	char ClientBuildInfoString[128];	// クライアントビルド情報文字列
	UINT ClientVerInt;					// クライアントバージョン整数値
	UINT ClientBuildInt;				// クライアントビルド番号整数値
	UINT ProcessId;						// プロセス ID
	UINT OsType;						// OS の種類
};

// パスワード設定
struct RPC_CLIENT_PASSWORD
{
	char Password[MAX_PASSWORD_LEN + 1];	// パスワード
	bool PasswordRemoteOnly;				// パスワードはリモートのみ必要
};

// パスワード設定の取得
struct RPC_CLIENT_PASSWORD_SETTING
{
	bool IsPasswordPresented;				// パスワードが存在する
	bool PasswordRemoteOnly;				// パスワードはリモートのみ必要
};

// 証明書列挙項目
struct RPC_CLIENT_ENUM_CA_ITEM
{
	UINT Key;								// 証明書キー
	wchar_t SubjectName[MAX_SIZE];			// 発行先
	wchar_t IssuerName[MAX_SIZE];			// 発行者
	UINT64 Expires;							// 有効期限
};

// 証明書列挙
struct RPC_CLIENT_ENUM_CA
{
	UINT NumItem;							// 項目数
	RPC_CLIENT_ENUM_CA_ITEM **Items;		// 項目
};

// 証明書項目
struct RPC_CERT
{
	X *x;									// 証明書
};

// 証明書削除
struct RPC_CLIENT_DELETE_CA
{
	UINT Key;								// 証明書キー
};

// 証明書の取得
struct RPC_GET_CA
{
	UINT Key;								// 証明書キー
	X *x;									// 証明書
};

// 署名者の取得
struct RPC_GET_ISSUER
{
	X *x;									// 証明書
	X *issuer_x;							// 署名者
};

// セキュアデバイス列挙項目
struct RPC_CLIENT_ENUM_SECURE_ITEM
{
	UINT DeviceId;							// デバイス ID
	UINT Type;								// 種別
	char DeviceName[MAX_SIZE];				// デバイス名
	char Manufacturer[MAX_SIZE];			// 製造元
};

// セキュアデバイスの列挙
struct RPC_CLIENT_ENUM_SECURE
{
	UINT NumItem;							// 項目数
	RPC_CLIENT_ENUM_SECURE_ITEM **Items;	// 項目
};

// セキュアデバイス指定
struct RPC_USE_SECURE
{
	UINT DeviceId;							// デバイス ID
};

// セキュアデバイス内オブジェクト列挙
struct RPC_ENUM_OBJECT_IN_SECURE
{
	UINT hWnd;								// ウインドウハンドル
	UINT NumItem;							// 項目数
	char **ItemName;						// 項目名
	bool *ItemType;							// 種類 (true=秘密鍵, false=公開鍵)
};

// 仮想 LAN の作成
struct RPC_CLIENT_CREATE_VLAN
{
	char DeviceName[MAX_SIZE];				// デバイス名
};

// 仮想 LAN 情報の取得
struct RPC_CLIENT_GET_VLAN
{
	char DeviceName[MAX_SIZE];				// デバイス名
	bool Enabled;							// 動作しているかどうかのフラグ
	char MacAddress[MAX_SIZE];				// MAC アドレス
	char Version[MAX_SIZE];					// バージョン
	char FileName[MAX_SIZE];				// ドライバファイル名
	char Guid[MAX_SIZE];					// GUID
};

// 仮想 LAN 情報の設定
struct RPC_CLIENT_SET_VLAN
{
	char DeviceName[MAX_SIZE];				// デバイス名
	char MacAddress[MAX_SIZE];				// MAC アドレス
};

// 仮想 LAN 列挙アイテム
struct RPC_CLIENT_ENUM_VLAN_ITEM
{
	char DeviceName[MAX_SIZE];				// デバイス名
	bool Enabled;							// 動作フラグ
	char MacAddress[MAX_SIZE];				// MAC アドレス
	char Version[MAX_SIZE];					// バージョン
};

// 仮想 LAN の列挙
struct RPC_CLIENT_ENUM_VLAN
{
	UINT NumItem;							// アイテム数
	RPC_CLIENT_ENUM_VLAN_ITEM **Items;		// アイテム
};

// アカウントの作成
struct RPC_CLIENT_CREATE_ACCOUNT
{
	CLIENT_OPTION *ClientOption;			// クライアント オプション
	CLIENT_AUTH *ClientAuth;				// クライアント認証データ
	bool StartupAccount;					// スタートアップアカウント
	bool CheckServerCert;					// サーバー証明書をチェックする
	X *ServerCert;							// サーバー証明書
	UCHAR ShortcutKey[SHA1_SIZE];			// ショートカットキー
};

// アカウントの列挙アイテム
struct RPC_CLIENT_ENUM_ACCOUNT_ITEM
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
	char UserName[MAX_USERNAME_LEN + 1];	//  ユーザー名
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];	// デバイス名
	UINT ProxyType;							// プロキシ接続の種類
	char ProxyName[MAX_HOST_NAME_LEN + 1];	// ホスト名
	bool Active;							// 動作フラグ
	bool Connected;							// 接続完了フラグ
	bool StartupAccount;					// スタートアップアカウント
	UINT Port;								// ポート番号 (Ver 3.0 以降)
	char HubName[MAX_HUBNAME_LEN + 1];		// 仮想 HUB 名 (Ver 3.0 以降)
	UINT64 CreateDateTime;					// 作成日時 (Ver 3.0 以降)
	UINT64 UpdateDateTime;					// 更新日時 (Ver 3.0 以降)
	UINT64 LastConnectDateTime;				// 最終接続日時 (Ver 3.0 以降)
	UINT tmp1;								// 一時データ
};

// アカウントの列挙
struct RPC_CLIENT_ENUM_ACCOUNT
{
	UINT NumItem;							// アイテム数
	RPC_CLIENT_ENUM_ACCOUNT_ITEM **Items;	// アイテム
};

// アカウントの削除
struct RPC_CLIENT_DELETE_ACCOUNT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
};

// アカウント名の変更
struct RPC_RENAME_ACCOUNT
{
	wchar_t OldName[MAX_ACCOUNT_NAME_LEN + 1];		// 古い名前
	wchar_t NewName[MAX_ACCOUNT_NAME_LEN + 1];		// 新しい名前
};

// アカウントの取得
struct RPC_CLIENT_GET_ACCOUNT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
	CLIENT_OPTION *ClientOption;			// クライアント オプション
	CLIENT_AUTH *ClientAuth;				// クライアント認証データ
	bool StartupAccount;					// スタートアップアカウント
	bool CheckServerCert;					// サーバー証明書をチェックする
	X *ServerCert;							// サーバー証明書
	UCHAR ShortcutKey[SHA1_SIZE];			// ショートカットキー
	UINT64 CreateDateTime;					// 作成日時 (Ver 3.0 以降)
	UINT64 UpdateDateTime;					// 更新日時 (Ver 3.0 以降)
	UINT64 LastConnectDateTime;				// 最終接続日時 (Ver 3.0 以降)
};

// 接続
struct RPC_CLIENT_CONNECT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
};

// コネクション状況の取得
struct RPC_CLIENT_GET_CONNECTION_STATUS
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
	bool Active;							// 動作フラグ
	bool Connected;							// 接続済みフラグ
	UINT SessionStatus;						// セッションステータス
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	UINT ServerPort;						// サーバーのポート番号
	char ServerProductName[MAX_SIZE];		// サーバー製品名
	UINT ServerProductVer;					// サーバー製品バージョン
	UINT ServerProductBuild;				// サーバー製品ビルド番号
	X *ServerX;								// サーバーの証明書
	X *ClientX;								// クライアントの証明書
	UINT64 StartTime;						// 接続開始時刻
	UINT64 FirstConnectionEstablisiedTime;	// 最初のコネクションの接続完了時刻
	UINT64 CurrentConnectionEstablishTime;	// このコネクションの接続完了時刻
	UINT NumConnectionsEatablished;			// これまでに確立したコネクション数
	bool HalfConnection;					// ハーフコネクション
	bool QoS;								// VoIP / QoS
	UINT MaxTcpConnections;					// 最大の TCP コネクション数
	UINT NumTcpConnections;					// 現在の TCP コネクション数
	UINT NumTcpConnectionsUpload;			// 上りコネクション数
	UINT NumTcpConnectionsDownload;			// 下りコネクション数
	bool UseEncrypt;						// 暗号化の使用
	char CipherName[32];					// 暗号化アルゴリズム名
	bool UseCompress;						// 圧縮の使用
	char SessionName[MAX_SESSION_NAME_LEN + 1];	// セッション名
	char ConnectionName[MAX_CONNECTION_NAME_LEN + 1];	// コネクション名
	UCHAR SessionKey[SHA1_SIZE];			// セッションキー
	POLICY Policy;							// ポリシー
	UINT64 TotalSendSize;					// 合計送信データサイズ
	UINT64 TotalRecvSize;					// 合計受信データサイズ
	UINT64 TotalSendSizeReal;				// 合計送信データサイズ (無圧縮)
	UINT64 TotalRecvSizeReal;				// 合計受信データサイズ (無圧縮)
	TRAFFIC Traffic;						// トラフィックデータ
	bool IsBridgeMode;						// ブリッジモード
	bool IsMonitorMode;						// モニタモード
	UINT VLanId;							// VLAN ID
};


// RPC コネクション
struct CLIENT_RPC_CONNECTION
{
	struct CLIENT *Client;					// クライアント
	bool RpcMode;							// true: RPC モード, false: 通知モード
	THREAD *Thread;							// 処理スレッド
	SOCK *Sock;								// ソケット
};

// クライアント オブジェクト
struct CLIENT
{
	LOCK *lock;								// ロック
	LOCK *lockForConnect;					// CtConnect 内部で使用するロック
	REF *ref;								// 参照カウンタ
	CEDAR *Cedar;							// Cedar
	volatile bool Halt;						// 停止フラグ
	UINT Err;								// エラーコード
	CFG_RW *CfgRw;							// 設定ファイル R/W
	LIST *AccountList;						// アカウントリスト
	UCHAR EncryptedPassword[SHA1_SIZE];		// パスワード
	bool PasswordRemoteOnly;				// パスワードはリモート接続のみ必要とする
	UINT UseSecureDeviceId;					// 使用するセキュアデバイス ID
	CLIENT_CONFIG Config;					// クライアント設定
	LIST *RpcConnectionList;				// RPC コネクションリスト
	SOCK *RpcListener;						// RPC リスナ
	THREAD *RpcThread;						// RPC スレッド
	LOCK *HelperLock;						// 補助ロック
	THREAD *SaverThread;					// 設定データ自動保存スレッド
	EVENT *SaverHalter;						// 設定データ自動保存スレッド停止用イベント
	LIST *NotifyCancelList;					// 通知イベントリスト
	KEEP *Keep;								// Keep Connection
	LIST *UnixVLanList;						// UNIX における仮想 LAN カードのリスト
	LOG *Logger;							// ロガー
	bool DontSavePassword;					// パスワードを保存しないフラグ
	ERASER *Eraser;							// 自動ファイル削除器
	SOCKLIST *SockList;						// ソケットリスト
	CM_SETTING *CmSetting;					// CM 設定
	bool NoSaveLog;							// ログ保存をしない
	bool NoSaveConfig;						// 設定を保存しない
};

// リモートクライアントへの通知
struct RPC_CLIENT_NOTIFY
{
	UINT NotifyCode;						// コード
};

// 通知の種類
#define	CLIENT_NOTIFY_ACCOUNT_CHANGED	1	// アカウント変化通知
#define	CLIENT_NOTIFY_VLAN_CHANGED		2	// 仮想 LAN カード変化通知

// リモートクライアント
struct REMOTE_CLIENT
{
	RPC *Rpc;
	UINT OsType;
	bool Unix;
	bool Win9x;
	UINT ProcessId;
	UINT ClientBuildInt;
};

// 通知クライアント
struct NOTIFY_CLIENT
{
	SOCK *Sock;
};

// CM 設定
struct CM_SETTING
{
	bool EasyMode;							// 簡易モード
	bool LockMode;							// 設定ロックモード
	UCHAR HashedPassword[SHA1_SIZE];		// パスワード
};




// 関数プロトタイプ
REMOTE_CLIENT *CcConnectRpc(char *server_name, char *password, bool *bad_pass, bool *no_remote, UINT wait_retry);
REMOTE_CLIENT *CcConnectRpcEx(char *server_name, char *password, bool *bad_pass, bool *no_remote, UCHAR *key, UINT *key_error_code, bool shortcut_disconnect, UINT wait_retry);
UINT CcShortcut(UCHAR *key);
UINT CcShortcutDisconnect(UCHAR *key);
void CcDisconnectRpc(REMOTE_CLIENT *rc);
NOTIFY_CLIENT *CcConnectNotify(REMOTE_CLIENT *rc);
void CcDisconnectNotify(NOTIFY_CLIENT *n);
void CcStopNotify(NOTIFY_CLIENT *n);
bool CcWaitNotify(NOTIFY_CLIENT *n);
UINT CcGetClientVersion(REMOTE_CLIENT *r, RPC_CLIENT_VERSION *a);
UINT CcSetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a);
UINT CcGetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a);
UINT CcSetPassword(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD *pass);
UINT CcGetPasswordSetting(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD_SETTING *a);
UINT CcEnumCa(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_CA *e);
UINT CcAddCa(REMOTE_CLIENT *r, RPC_CERT *cert);
UINT CcDeleteCa(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_CA *p);
UINT CcGetCa(REMOTE_CLIENT *r, RPC_GET_CA *get);
UINT CcEnumSecure(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_SECURE *e);
UINT CcUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec);
UINT CcGetUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec);
UINT CcEnumObjectInSecure(REMOTE_CLIENT *r, RPC_ENUM_OBJECT_IN_SECURE *e);
UINT CcCreateVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create);
UINT CcUpgradeVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create);
UINT CcGetVLan(REMOTE_CLIENT *r, RPC_CLIENT_GET_VLAN *get);
UINT CcSetVLan(REMOTE_CLIENT *r, RPC_CLIENT_SET_VLAN *set);
UINT CcEnumVLan(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_VLAN *e);
UINT CcDeleteVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *d);
UINT CcEnableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan);
UINT CcDisableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan);
UINT CcCreateAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a);
UINT CcEnumAccount(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_ACCOUNT *e);
UINT CcDeleteAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcSetAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a);
UINT CcGetAccount(REMOTE_CLIENT *r, RPC_CLIENT_GET_ACCOUNT *a);
UINT CcRenameAccount(REMOTE_CLIENT *r, RPC_RENAME_ACCOUNT *rename);
UINT CcSetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o);
UINT CcGetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o);
UINT CcConnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect);
UINT CcDisconnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect);
UINT CcGetAccountStatus(REMOTE_CLIENT *r, RPC_CLIENT_GET_CONNECTION_STATUS *st);
UINT CcSetStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcRemoveStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcGetIssuer(REMOTE_CLIENT *r, RPC_GET_ISSUER *a);
void CcSetServiceToForegroundProcess(REMOTE_CLIENT *r);
char *CiGetFirstVLan(CLIENT *c);
void CiNormalizeAccountVLan(CLIENT *c);


void CnStart();
void CnListenerProc(THREAD *thread, void *param);

void CnReleaseSocket(SOCK *s, PACK *p);

void CnStatusPrinter(SOCK *s, PACK *p);
void Win32CnStatusPrinter(SOCK *s, PACK *p);

void CnConnectErrorDlg(SOCK *s, PACK *p);
void Win32CnConnectErrorDlg(SOCK *s, PACK *p);
void Win32CnConnectErrorDlgThreadProc(THREAD *thread, void *param);

void CnPasswordDlg(SOCK *s, PACK *p);
void Win32CnPasswordDlg(SOCK *s, PACK *p);
void Win32CnPasswordDlgThreadProc(THREAD *thread, void *param);

void CnMsgDlg(SOCK *s, PACK *p);
void Win32CnMsgDlg(SOCK *s, PACK *p);
void Win32CnMsgDlgThreadProc(THREAD *thread, void *param);

void CnNicInfo(SOCK *s, PACK *p);
void Win32CnNicInfo(SOCK *s, PACK *p);
void Win32CnNicInfoThreadProc(THREAD *thread, void *param);

void CnCheckCert(SOCK *s, PACK *p);
void Win32CnCheckCert(SOCK *s, PACK *p);
void Win32CnCheckCertThreadProc(THREAD *thread, void *param);

void CnExecDriverInstaller(SOCK *s, PACK *p);
void Win32CnExecDriverInstaller(SOCK *s, PACK *p);

bool CnCheckAlreadyExists(bool lock);
bool CnIsCnServiceReady();
void CnWaitForCnServiceReady();

void CnSecureSign(SOCK *s, PACK *p);

SOCK *CncConnect();
SOCK *CncConnectEx(UINT timeout);
void CncReleaseSocket();
void CncExit();
UINT CncGetSessionId();
bool CncExecDriverInstaller(char *arg);
SOCK *CncStatusPrinterWindowStart(SESSION *s);
void CncStatusPrinterWindowPrint(SOCK *s, wchar_t *str);
void CncStatusPrinterWindowStop(SOCK *s);
void CncStatusPrinterWindowThreadProc(THREAD *thread, void *param);
bool CncConnectErrorDlg(SESSION *session, UI_CONNECTERROR_DLG *dlg);
void CncConnectErrorDlgHaltThread(THREAD *thread, void *param);
bool CncPasswordDlg(SESSION *session, UI_PASSWORD_DLG *dlg);
void CncPasswordDlgHaltThread(THREAD *thread, void *param);
void CncCheckCert(SESSION *session, UI_CHECKCERT *dlg);
void CncCheckCertHaltThread(THREAD *thread, void *param);
bool CncSecureSignDlg(SECURE_SIGN *sign);
SOCK *CncMsgDlg(UI_MSG_DLG *dlg);
void CndMsgDlgFree(SOCK *s);
SOCK *CncNicInfo(UI_NICINFO *info);
void CncNicInfoFree(SOCK *s);

void CtStartClient();
void CtStopClient();
CLIENT *CtGetClient();
void CtReleaseClient(CLIENT *c);
bool CtGetClientVersion(CLIENT *c, RPC_CLIENT_VERSION *ver);
bool CtGetCmSetting(CLIENT *c, CM_SETTING *s);
bool CtSetCmSetting(CLIENT *c, CM_SETTING *s);
bool CtSetPassword(CLIENT *c, RPC_CLIENT_PASSWORD *pass);
bool CtGetPasswordSetting(CLIENT *c, RPC_CLIENT_PASSWORD_SETTING *a);
bool CtEnumCa(CLIENT *c, RPC_CLIENT_ENUM_CA *e);
bool CtAddCa(CLIENT *c, RPC_CERT *cert);
bool CtDeleteCa(CLIENT *c, RPC_CLIENT_DELETE_CA *p);
bool CtGetCa(CLIENT *c, RPC_GET_CA *get);
bool CtEnumSecure(CLIENT *c, RPC_CLIENT_ENUM_SECURE *e);
bool CtUseSecure(CLIENT *c, RPC_USE_SECURE *sec);
bool CtGetUseSecure(CLIENT *c, RPC_USE_SECURE *sec);
bool CtEnumObjectInSecure(CLIENT *c, RPC_ENUM_OBJECT_IN_SECURE *e);
bool CtCreateVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create);
bool CtUpgradeVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create);
bool CtGetVLan(CLIENT *c, RPC_CLIENT_GET_VLAN *get);
bool CtSetVLan(CLIENT *c, RPC_CLIENT_SET_VLAN *set);
bool CtEnumVLan(CLIENT *c, RPC_CLIENT_ENUM_VLAN *e);
bool CtDeleteVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *d);
bool CtEnableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan);
bool CtDisableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan);
bool CtCreateAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a);
bool CtEnumAccount(CLIENT *c, RPC_CLIENT_ENUM_ACCOUNT *e);
bool CtDeleteAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a);
bool CtSetAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a);
bool CtGetAccount(CLIENT *c, RPC_CLIENT_GET_ACCOUNT *a);
bool CtRenameAccount(CLIENT *c, RPC_RENAME_ACCOUNT *rename);
bool CtSetClientConfig(CLIENT *c, CLIENT_CONFIG *o);
bool CtGetClientConfig(CLIENT *c, CLIENT_CONFIG *o);
bool CtConnect(CLIENT *c, RPC_CLIENT_CONNECT *connect);
bool CtDisconnect(CLIENT *c, RPC_CLIENT_CONNECT *connect);
bool CtGetAccountStatus(CLIENT *c, RPC_CLIENT_GET_CONNECTION_STATUS *st);
bool CtSetStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a);
bool CtRemoveStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a);
bool CtGetIssuer(CLIENT *c, RPC_GET_ISSUER *a);





// 内部関数プロトタイプ
char *CiGetVpnClientExeFileName();
void CiServerThread(THREAD *t, void *param);
void CiInitSaver(CLIENT *c);
void CiFreeSaver(CLIENT *c);
void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s);
PACK *CiRpcDispatch(RPC *rpc, char *name, PACK *p);
void CiRpcAccepted(CLIENT *c, SOCK *s);
void CiNotifyMain(CLIENT *c, SOCK *s);
void CiRpcAcceptThread(THREAD *thread, void *param);
void CiRpcServerThread(THREAD *thread, void *param);
void CiStartRpcServer(CLIENT *c);
void CiStopRpcServer(CLIENT *c);
CLIENT_OPTION *CiLoadClientOption(FOLDER *f);
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f);
ACCOUNT *CiLoadClientAccount(FOLDER *f);
void CiLoadClientConfig(CLIENT_CONFIG *c, FOLDER *f);
void CiLoadAccountDatabase(CLIENT *c, FOLDER *f);
void CiLoadCAList(CLIENT *c, FOLDER *f);
void CiLoadCACert(CLIENT *c, FOLDER *f);
void CiLoadVLanList(CLIENT *c, FOLDER *f);
void CiLoadVLan(CLIENT *c, FOLDER *f);
bool CiReadSettingFromCfg(CLIENT *c, FOLDER *root);
void CiWriteAccountDatabase(CLIENT *c, FOLDER *f);
void CiWriteAccountData(FOLDER *f, ACCOUNT *a);
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o);
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a);
void CiWriteClientConfig(FOLDER *cc, CLIENT_CONFIG *config);
void CiWriteSettingToCfg(CLIENT *c, FOLDER *root);
void CiWriteCAList(CLIENT *c, FOLDER *f);
void CiWriteCACert(CLIENT *c, FOLDER *f, X *x);
void CiWriteVLanList(CLIENT *c, FOLDER *f);
void CiWriteVLan(CLIENT *c, FOLDER *f, UNIX_VLAN *v);
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st);
bool CiCheckCertProc(SESSION *s, CONNECTION *c, X *server_x, bool *expired);
bool CiSecureSignProc(SESSION *s, CONNECTION *c, SECURE_SIGN *sign);
bool Win32CiSecureSign(SECURE_SIGN *sign);
void CiFreeClientAuth(CLIENT_AUTH *auth);
void CiFreeClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *a);
void CiFreeClientGetAccount(RPC_CLIENT_GET_ACCOUNT *a);
void CiFreeClientEnumVLan(RPC_CLIENT_ENUM_VLAN *e);
void CiFreeClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e);
void CiFreeClientEnumCa(RPC_CLIENT_ENUM_CA *e);
void CiFreeEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *a);
void CiFreeGetCa(RPC_GET_CA *a);
void CiFreeGetIssuer(RPC_GET_ISSUER *a);
void CiFreeClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *a);
void CiSetError(CLIENT *c, UINT err);
void CiCheckOs();
CLIENT *CiNewClient();
void CiCleanupClient(CLIENT *c);
bool CiLoadConfigurationFile(CLIENT *c);
void CiSaveConfigurationFile(CLIENT *c);
void CiInitConfiguration(CLIENT *c);
void CiSetVLanToDefault(CLIENT *c);
bool CiIsVLan(CLIENT *c, char *name);
void CiFreeConfiguration(CLIENT *c);
int CiCompareAccount(void *p1, void *p2);
void CiFreeAccount(ACCOUNT *a);
void CiNotify(CLIENT *c);
void CiClientStatusPrinter(SESSION *s, wchar_t *status);
void CiInitKeep(CLIENT *c);
void CiFreeKeep(CLIENT *c);
int CiCompareUnixVLan(void *p1, void *p2);
BUF *CiAccountToCfg(RPC_CLIENT_CREATE_ACCOUNT *t);
RPC_CLIENT_CREATE_ACCOUNT *CiCfgToAccount(BUF *b);
void CiChangeAllVLanMacAddress(CLIENT *c);
void CiChangeAllVLanMacAddressIfMachineChanged(CLIENT *c);
bool CiReadLastMachineHash(void *data);
bool CiWriteLastMachineHash(void *data);
void CiGetCurrentMachineHash(void *data);
void CiGetCurrentMachineHashOld(void *data);
int CiCompareClientAccountEnumItemByLastConnectDateTime(void *p1, void *p2);

BUF *EncryptPassword(char *password);
char *DecryptPassword(BUF *b);

void InRpcGetIssuer(RPC_GET_ISSUER *c, PACK *p);
void OutRpcGetIssuer(PACK *p, RPC_GET_ISSUER *c);
void InRpcClientVersion(RPC_CLIENT_VERSION *ver, PACK *p);
void OutRpcClientVersion(PACK *p, RPC_CLIENT_VERSION *ver);
void InRpcClientPassword(RPC_CLIENT_PASSWORD *pw, PACK *p);
void OutRpcClientPassword(PACK *p, RPC_CLIENT_PASSWORD *pw);
void InRpcClientEnumCa(RPC_CLIENT_ENUM_CA *e, PACK *p);
void OutRpcClientEnumCa(PACK *p, RPC_CLIENT_ENUM_CA *e);
void InRpcCert(RPC_CERT *c, PACK *p);
void OutRpcCert(PACK *p, RPC_CERT *c);
void InRpcClientDeleteCa(RPC_CLIENT_DELETE_CA *c, PACK *p);
void OutRpcClientDeleteCa(PACK *p, RPC_CLIENT_DELETE_CA *c);
void InRpcGetCa(RPC_GET_CA *c, PACK *p);
void OutRpcGetCa(PACK *p, RPC_GET_CA *c);
void InRpcClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e, PACK *p);
void OutRpcClientEnumSecure(PACK *p, RPC_CLIENT_ENUM_SECURE *e);
void InRpcUseSecure(RPC_USE_SECURE *u, PACK *p);
void OutRpcUseSecure(PACK *p, RPC_USE_SECURE *u);
void InRpcEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *e, PACK *p);
void OutRpcEnumObjectInSecure(PACK *p, RPC_ENUM_OBJECT_IN_SECURE *e);
void InRpcCreateVLan(RPC_CLIENT_CREATE_VLAN *v, PACK *p);
void OutRpcCreateVLan(PACK *p, RPC_CLIENT_CREATE_VLAN *v);
void InRpcClientGetVLan(RPC_CLIENT_GET_VLAN *v, PACK *p);
void OutRpcClientGetVLan(PACK *p, RPC_CLIENT_GET_VLAN *v);
void InRpcClientSetVLan(RPC_CLIENT_SET_VLAN *v, PACK *p);
void OutRpcClientSetVLan(PACK *p, RPC_CLIENT_SET_VLAN *v);
void InRpcClientEnumVLan(RPC_CLIENT_ENUM_VLAN *v, PACK *p);
void OutRpcClientEnumVLan(PACK *p, RPC_CLIENT_ENUM_VLAN *v);
void InRpcClientOption(CLIENT_OPTION *c, PACK *p);
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c);
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p);
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c);
void InRpcClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *c, PACK *p);
void OutRpcClientCreateAccount(PACK *p, RPC_CLIENT_CREATE_ACCOUNT *c);
void InRpcClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *e, PACK *p);
void OutRpcClientEnumAccount(PACK *p, RPC_CLIENT_ENUM_ACCOUNT *e);
void InRpcClientDeleteAccount(RPC_CLIENT_DELETE_ACCOUNT *a, PACK *p);
void OutRpcClientDeleteAccount(PACK *p, RPC_CLIENT_DELETE_ACCOUNT *a);
void InRpcRenameAccount(RPC_RENAME_ACCOUNT *a, PACK *p);
void OutRpcRenameAccount(PACK *p, RPC_RENAME_ACCOUNT *a);
void InRpcClientGetAccount(RPC_CLIENT_GET_ACCOUNT *c, PACK *p);
void OutRpcClientGetAccount(PACK *p, RPC_CLIENT_GET_ACCOUNT *c);
void InRpcClientConnect(RPC_CLIENT_CONNECT *c, PACK *p);
void OutRpcClientConnect(PACK *p, RPC_CLIENT_CONNECT *c);
void InRpcPolicy(POLICY *o, PACK *p);
void OutRpcPolicy(PACK *p, POLICY *o);
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p);
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c);
void InRpcClientNotify(RPC_CLIENT_NOTIFY *n, PACK *p);
void OutRpcClientNotify(PACK *p, RPC_CLIENT_NOTIFY *n);
void InRpcClientConfig(CLIENT_CONFIG *c, PACK *p);
void OutRpcClientConfig(PACK *p, CLIENT_CONFIG *c);
void InRpcClientPasswordSetting(RPC_CLIENT_PASSWORD_SETTING *a, PACK *p);
void OutRpcClientPasswordSetting(PACK *p, RPC_CLIENT_PASSWORD_SETTING *a);
void InRpcTraffic(TRAFFIC *t, PACK *p);
void OutRpcTraffic(PACK *p, TRAFFIC *t);
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i);
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num);
void OutRpcCmSetting(PACK *p, CM_SETTING *c);
void InRpcCmSetting(CM_SETTING *c, PACK *p);


#endif	// CLIENT_H


