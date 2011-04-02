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

// SMInner.h
// SM.c の内部向けヘッダ

// 定数
#define	SM_REG_KEY			"Software\\SoftEther Corporation\\UT-VPN\\Server Manager"
#define	SM_CERT_REG_KEY		"Software\\SoftEther Corporation\\UT-VPN\\Server Manager\\Cert Tool"
#define	SM_SETTING_REG_KEY	"Software\\SoftEther Corporation\\UT-VPN\\Server Manager\\Settings"
#define	SM_LASTHUB_REG_KEY	"Software\\SoftEther Corporation\\UT-VPN\\Server Manager\\Last HUB Name"

// 定数 (古い値)
#define	SM_SETTING_REG_KEY_OLD	"Software\\SoftEther Corporation\\PacketiX VPN\\Server Manager\\Settings_Dummy"

// スプラッシュスクリーンの枠線の色
#define	SM_SPLASH_BORDER_COLOR	(RGB(72, 72, 72))

// 接続設定
typedef struct SETTING
{
	wchar_t Title[MAX_SIZE];	// 設定名
	bool ServerAdminMode;		// サーバー管理モード
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	UCHAR HashedPassword[SHA1_SIZE];	// パスワード
	CLIENT_OPTION ClientOption;	// クライアントオプション
	UCHAR Reserved[10240 - sizeof(bool) * 7];	// 予約領域
} SETTING;

// 構造体宣言
typedef struct SM
{
	CEDAR *Cedar;				// Cedar
	LIST *SettingList;			// 設定リスト
	SETTING *TempSetting;		// 仮設定
	HWND hParentWnd;			// 親ウインドウハンドル
} SM;

// 接続設定編集
typedef struct SM_EDIT_SETTING
{
	bool EditMode;				// 編集モード
	SETTING *OldSetting;		// 以前の設定へのポインタ
	SETTING *Setting;			// 設定へのポインタ
	bool Inited;				// 初期済みフラグ
} SM_EDIT_SETTING;

// サーバー管理ダイアログ
typedef struct SM_SERVER
{
	RPC *Rpc;					// RPC
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	wchar_t Title[MAX_SIZE];	// タイトル
	bool ServerAdminMode;		// サーバー管理モード
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	UINT ServerType;			// サーバーの種類
	bool Bridge;				// VPN Bridge 製品
	UINT PolicyVer;				// ポリシーバージョン
	RPC_SERVER_STATUS ServerStatus;	// サーバー状態
	RPC_SERVER_INFO ServerInfo;		// サーバー情報
	CAPSLIST *CapsList;			// Caps リスト
	bool EmptyPassword;			// 空のパスワード
	SETTING *CurrentSetting;	// 現在の接続設定
	wchar_t *AdminMsg;			// 管理者向けメッセージ
} SM_SERVER;

typedef void (SM_STATUS_INIT_PROC)(HWND hWnd, SM_SERVER *p, void *param);
typedef bool (SM_STATUS_REFRESH_PROC)(HWND hWnd, SM_SERVER *p, void *param);

// 情報表示ダイアログ
typedef struct SM_STATUS
{
	SM_SERVER *p;				// P へのポインタ
	void *Param;				// パラメータ
	UINT Icon;					// アイコン
	wchar_t *Caption;			// タイトル
	bool show_refresh_button;	// 更新ボタンの表示
	bool NoImage;				// イメージ無し
	SM_STATUS_INIT_PROC *InitProc;
	SM_STATUS_REFRESH_PROC *RefreshProc;
} SM_STATUS;

// 仮想 HUB 編集ダイアログ
typedef struct SM_EDIT_HUB
{
	SM_SERVER *p;				// P
	bool EditMode;				// 編集モード
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
} SM_EDIT_HUB;

// SSL 関係
typedef struct SM_SSL
{
	SM_SERVER *p;				// P
	X *Cert;					// 証明書
	K *Key;						// 秘密鍵
	bool SetCertAndKey;			// キーをセットする
} SM_SSL;

// 証明書保存
typedef struct SM_SAVE_KEY_PAIR
{
	X *Cert;					// 証明書
	K *Key;						// 秘密鍵
	char *Pass;					// パスフレーズ
} SM_SAVE_KEY_PAIR;

// コネクション情報
typedef struct SM_CONNECTION_INFO
{
	SM_SERVER *p;				// P
	char *ConnectionName;		// コネクション名
} SM_CONNECTION_INFO;

// HUB の管理
typedef struct SM_HUB
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	char *HubName;				// HUB 名
} SM_HUB;

// ユーザーリスト表示
typedef struct SM_USER
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	char *GroupName;			// グループ名でフィルタ
	bool SelectMode;			// 選択モード
	char *SelectedName;			// 選択されたユーザー名
	bool AllowGroup;			// グループの選択を許可
	bool CreateNow;				// すぐにユーザーを作成
} SM_USER;

// ユーザーの編集
typedef struct SM_EDIT_USER
{
	bool Inited;				// 初期化済みフラグ
	bool EditMode;				// 編集モード
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	RPC_SET_USER SetUser;		// ユーザー設定
} SM_EDIT_USER;

// ユーザー情報
typedef struct SM_USER_INFO
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	char *Username;				// Username
} SM_USER_INFO;

// ポリシー
typedef struct SM_POLICY
{
	bool Inited;				// 初期化
	POLICY *Policy;				// ポリシー
	wchar_t *Caption;			// タイトル
	bool CascadeMode;			// カスケードモード
	UINT Ver;					// バージョン
} SM_POLICY;

// グループリスト表示
typedef struct SM_GROUP
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	bool SelectMode;			// 選択モード
	char *SelectedGroupName;	// 選択されたグループ名
} SM_GROUP;

// グループの編集
typedef struct SM_EDIT_GROUP
{
	bool Inited;				// 初期化フラグ
	bool EditMode;				// 編集モード
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	RPC_SET_GROUP SetGroup;		// グループ設定
} SM_EDIT_GROUP;

// アクセスリスト一覧
typedef struct SM_ACCESS_LIST
{
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	LIST *AccessList;			// アクセスリスト
} SM_ACCESS_LIST;

// アクセスリストの編集
typedef struct SM_EDIT_ACCESS
{
	SM_HUB *Hub;				// HUB
	bool Inited;				// 初期化フラグ
	bool EditMode;				// 編集モード
	SM_ACCESS_LIST *AccessList;	// アクセスリスト
	ACCESS *Access;				// アクセスリスト項目
} SM_EDIT_ACCESS;

// アクセスリストの状態表示
typedef struct SM_LINK
{
	SM_HUB *Hub;				// HUB
	wchar_t *AccountName;		// アカウント名
} SM_LINK;

// セッション ステータス
typedef struct SM_SESSION_STATUS
{
	SM_HUB *Hub;				// HUB
	char *SessionName;			// セッション名
} SM_SESSION_STATUS;

// アドレステーブル
typedef struct SM_TABLE
{
	SM_HUB *Hub;				// HUB
	RPC *Rpc;					// RPC
	char *SessionName;			// セッション名
} SM_TABLE;

// 証明書ツール
typedef struct SM_CERT
{
	X *x;						// 生成された証明書
	K *k;						// 生成された秘密鍵
	X *root_x;					// ルート証明書
	K *root_k;					// ルート証明書の秘密鍵
	bool do_not_save;			// ファイルに保存しない
	char *default_cn;			// デフォルトの CN
} SM_CERT;

// config 編集
typedef struct SM_CONFIG
{
	SM_SERVER *s;				// SM_SERVER
	RPC_CONFIG Config;			// Config 本体
} SM_CONFIG;

// hub_admin_option 編集
typedef struct SM_EDIT_AO
{
	SM_EDIT_HUB *e;
	bool CanChange;
	RPC_ADMIN_OPTION CurrentOptions;
	RPC_ADMIN_OPTION DefaultOptions;
	bool NewMode;
	char Name[MAX_ADMIN_OPTION_NAME_LEN + 1];
	UINT Value;
	bool ExtOption;
} SM_EDIT_AO;

// スイッチ編集
typedef struct SM_L3SW
{
	SM_SERVER *s;
	char *SwitchName;
	bool Enable;
} SM_L3SW;

// スマートカードから証明書と秘密鍵の指定
typedef struct SM_SECURE_KEYPAIR
{
	UINT Id;
	bool UseCert;
	bool UseKey;
	char CertName[MAX_SIZE];
	char KeyName[MAX_SIZE];
	bool Flag;
	UINT BitmapId;
} SM_SECURE_KEYPAIR;

// CRL 編集
typedef struct SM_EDIT_CRL
{
	SM_HUB *s;
	bool NewCrl;
	UINT Key;
} SM_EDIT_CRL;

// AC リスト編集
typedef struct SM_EDIT_AC_LIST
{
	SM_EDIT_HUB *s;
	LIST *AcList;
} SM_EDIT_AC_LIST;

// AC 編集
typedef struct SM_EDIT_AC
{
	SM_EDIT_AC_LIST *e;
	UINT id;
} SM_EDIT_AC;

// ログファイルダウンロード
typedef struct SM_READ_LOG_FILE
{
	HWND hWnd;
	SM_SERVER *s;
	char *server_name;
	char *filepath;
	UINT totalsize;
	bool cancel_flag;
	BUF *Buffer;
} SM_READ_LOG_FILE;

// セットアップダイアログ
typedef struct SM_SETUP
{
	SM_SERVER *s;
	RPC *Rpc;
	bool IsBridge;
	bool UseRemote;			// リモートアクセス VPN
	bool UseSite;			// 拠点間接続 VPN
	bool UseSiteEdge;		// 各拠点に設置する VPN Server / Bridge
	char HubName[MAX_HUBNAME_LEN + 1];	// 仮想 HUB 名
	bool Flag1;
	bool Flag2;
} SM_SETUP;


// 関数プロトタイプ
void InitSM();
void SmParseCommandLine();
void MainSM();
void FreeSM();
void SmMainDlg();
UINT SmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmMainDlgInit(HWND hWnd);
void SmMainDlgUpdate(HWND hWnd);
void SmInitSettingList();
void SmFreeSettingList();
void SmWriteSettingList();
void SmLoadSettingList();
void SmInitDefaultSettingList();
int SmCompareSetting(void *p1, void *p2);
SETTING *SmGetSetting(wchar_t *title);
bool SmAddSetting(SETTING *s);
void SmDeleteSetting(wchar_t *title);
bool SmCheckNewName(SETTING *s, wchar_t *new_title);
void SmRefreshSetting(HWND hWnd);
void SmRefreshSettingEx(HWND hWnd, wchar_t *select_name);
bool SmAddSettingDlg(HWND hWnd, wchar_t *new_name, UINT new_name_size);
bool SmEditSettingDlg(HWND hWnd);
UINT SmEditSettingDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditSettingDlgInit(HWND hWnd, SM_EDIT_SETTING *p);
void SmEditSettingDlgUpdate(HWND hWnd, SM_EDIT_SETTING *p);
void SmEditSettingDlgOnOk(HWND hWnd, SM_EDIT_SETTING *p);
void SmConnect(HWND hWnd, SETTING *s);
char *SmPassword(HWND hWnd, char *server_name);
UINT SmServerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmServerDlgInit(HWND hWnd, SM_SERVER *p);
void SmServerDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmServerDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmStatusDlg(HWND hWnd, SM_SERVER *p, void *param, bool no_image, bool show_refresh_button, wchar_t *caption, UINT icon,
				 SM_STATUS_INIT_PROC *init, SM_STATUS_REFRESH_PROC *refresh);
UINT SmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool SmRefreshHubStatus(HWND hWnd, SM_SERVER *p, void *param);
void SmInsertTrafficInfo(LVB *b, TRAFFIC *t);
bool SmCreateHubDlg(HWND hWnd, SM_SERVER *p);
bool SmEditHubDlg(HWND hWnd, SM_SERVER *p, char *hubname);
UINT SmEditHubProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditHubInit(HWND hWnd, SM_EDIT_HUB *s);
void SmEditHubUpdate(HWND hWnd, SM_EDIT_HUB *s);
void SmEditHubOnOk(HWND hWnd, SM_EDIT_HUB *s);
bool SmCreateListenerDlg(HWND hWnd, SM_SERVER *p);
UINT SmCreateListenerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSslDlg(HWND hWnd, SM_SERVER *p);
UINT SmSslDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSslDlgInit(HWND hWnd, SM_SSL *s);
void SmSslDlgOnOk(HWND hWnd, SM_SSL *s);
void SmSslDlgUpdate(HWND hWnd, SM_SSL *s);
void SmGetCertInfoStr(wchar_t *str, UINT size, X *x);
bool SmSaveKeyPairDlg(HWND hWnd, X *x, K *k);
UINT SmSaveKeyPairDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSaveKeyPairDlgInit(HWND hWnd, SM_SAVE_KEY_PAIR *s);
void SmSaveKeyPairDlgUpdate(HWND hWnd, SM_SAVE_KEY_PAIR *s);
void SmSaveKeyPairDlgOnOk(HWND hWnd, SM_SAVE_KEY_PAIR *s);
bool SmRefreshServerStatus(HWND hWnd, SM_SERVER *p, void *param);
bool SmRefreshServerInfo(HWND hWnd, SM_SERVER *p, void *param);
void SmPrintNodeInfo(LVB *b, NODE_INFO *info);
wchar_t *SmGetConnectionTypeStr(UINT type);
void SmConnectionDlg(HWND hWnd, SM_SERVER *p);
UINT SmConnectionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmConnectionDlgInit(HWND hWnd, SM_SERVER *p);
void SmConnectionDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmConnectionDlgUpdate(HWND hWnd, SM_SERVER *p);
bool SmRefreshConnectionStatus(HWND hWnd, SM_SERVER *p, void *param);
bool SmFarmDlg(HWND hWnd, SM_SERVER *p);
UINT SmFarmDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmFarmDlgInit(HWND hWnd, SM_SERVER *p);
void SmFarmDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmFarmDlgOnOk(HWND hWnd, SM_SERVER *p);
LIST *SmStrToPortList(char *str);
UINT SmFarmMemberDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmFarmMemberDlgInit(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgOnOk(HWND hWnd, SM_SERVER *p);
void SmFarmMemberCert(HWND hWnd, SM_SERVER *p, UINT id);
bool SmRefreshFarmMemberInfo(HWND hWnd, SM_SERVER *p, void *param);
bool SmRefreshFarmConnectionInfo(HWND hWnd, SM_SERVER *p, void *param);
UINT SmChangeServerPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubDlg(HWND hWnd, SM_HUB *s);
UINT SmHubDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubDlgInit(HWND hWnd, SM_HUB *s);
void SmHubDlgUpdate(HWND hWnd, SM_HUB *s);
void SmHubDlgRefresh(HWND hWnd, SM_HUB *s);
void SmUserListDlg(HWND hWnd, SM_HUB *s);
UINT SmUserListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmUserListInit(HWND hWnd, SM_USER *s);
void SmUserListRefresh(HWND hWnd, SM_USER *s);
void SmUserListUpdate(HWND hWnd, SM_USER *s);
wchar_t *SmGetAuthTypeStr(UINT id);
bool SmCreateUserDlg(HWND hWnd, SM_HUB *s);
UINT SmEditUserDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditUserDlgInit(HWND hWnd, SM_EDIT_USER *s);
void SmEditUserDlgUpdate(HWND hWnd, SM_EDIT_USER *s);
void SmEditUserDlgOk(HWND hWnd, SM_EDIT_USER *s);
bool SmPolicyDlg(HWND hWnd, POLICY *p, wchar_t *caption);
bool SmPolicyDlgEx(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode);
bool SmPolicyDlgEx2(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode, UINT ver);
UINT SmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmPolicyDlgInit(HWND hWnd, SM_POLICY *s);
void SmPolicyDlgUpdate(HWND hWnd, SM_POLICY *s);
void SmPolicyDlgOk(HWND hWnd, SM_POLICY *s);
bool SmEditUserDlg(HWND hWnd, SM_HUB *s, char *username);
bool SmRefreshUserInfo(HWND hWnd, SM_SERVER *s, void *param);
void SmGroupListDlg(HWND hWnd, SM_HUB *s);
char *SmSelectGroupDlg(HWND hWnd, SM_HUB *s, char *default_name);
UINT SmGroupListDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmGroupListDlgInit(HWND hWnd, SM_GROUP *s);
void SmGroupListDlgUpdate(HWND hWnd, SM_GROUP *s);
void SmGroupListDlgRefresh(HWND hWnd, SM_GROUP *s);
bool SmCreateGroupDlg(HWND hWnd, SM_GROUP *s);
bool SmEditGroupDlg(HWND hWnd, SM_GROUP *s, char *name);
UINT SmEditGroupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditGroupDlgInit(HWND hWnd, SM_EDIT_GROUP *g);
void SmEditGroupDlgUpdate(HWND hWnd, SM_EDIT_GROUP *g);
void SmEditGroupDlgOnOk(HWND hWnd, SM_EDIT_GROUP *g);
void SmUserListDlgEx(HWND hWnd, SM_HUB *s, char *groupname, bool create);
void SmAccessListDlg(HWND hWnd, SM_HUB *s);
UINT SmAccessListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmAccessListInit(HWND hWnd, SM_ACCESS_LIST *s);
void SmAccessListUpdate(HWND hWnd, SM_ACCESS_LIST *s);
void SmAccessListRefresh(HWND hWnd, SM_ACCESS_LIST *s);
bool SmAddAccess(HWND hWnd, SM_ACCESS_LIST *s, bool ipv6);
bool SmEditAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *a);
UINT SmEditAccessDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditAccessInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmEditAccessUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
void SmEditAccessOnOk(HWND hWnd, SM_EDIT_ACCESS *s);
UINT SmSimulationDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSimulationUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
void SmSimulationInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmSimulationOnOk(HWND hWnd, SM_EDIT_ACCESS *s);
char *SmSelectUserDlg(HWND hWnd, SM_HUB *s, char *default_name);
char *SmSelectUserDlgEx(HWND hWnd, SM_HUB *s, char *default_name, bool allow_group);
void SmRadiusDlg(HWND hWnd, SM_HUB *s);
UINT SmRadiusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmRadiusDlgInit(HWND hWnd, SM_HUB *s);
void SmRadiusDlgUpdate(HWND hWnd, SM_HUB *s);
void SmRadiusDlgOnOk(HWND hWnd, SM_HUB *s);
void SmLinkDlg(HWND hWnd, SM_HUB *s);
void SmLinkDlgEx(HWND hWnd, SM_HUB *s, bool createNow);
UINT SmLinkDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLinkDlgInit(HWND hWnd, SM_HUB *s);
void SmLinkDlgUpdate(HWND hWnd, SM_HUB *s);
void SmLinkDlgRefresh(HWND hWnd, SM_HUB *s);
bool SmLinkCreate(HWND hWnd, SM_HUB *s);
bool SmLinkCreateEx(HWND hWnd, SM_HUB *s, bool connectNow);
bool SmLinkEdit(HWND hWnd, SM_HUB *s, wchar_t *name);
bool SmRefreshLinkStatus(HWND hWnd, SM_SERVER *s, void *param);
UINT SmLogDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLogDlgInit(HWND hWnd, SM_HUB *s);
void SmLogDlgUpdate(HWND hWnd, SM_HUB *s);
void SmLogDlgOnOk(HWND hWnd, SM_HUB *s);
void SmCaDlg(HWND hWnd, SM_HUB *s);
UINT SmCaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCaDlgInit(HWND hWnd, SM_HUB *s);
void SmCaDlgRefresh(HWND hWnd, SM_HUB *s);
void SmCaDlgUpdate(HWND hWnd, SM_HUB *s);
void SmCaDlgOnOk(HWND hWnd, SM_HUB *s);
bool SmCaDlgAdd(HWND hWnd, SM_HUB *s);
void SmSessionDlg(HWND hWnd, SM_HUB *s);
UINT SmSessionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSessionDlgInit(HWND hWnd, SM_HUB *s);
void SmSessionDlgUpdate(HWND hWnd, SM_HUB *s);
void SmSessionDlgRefresh(HWND hWnd, SM_HUB *s);
bool SmRefreshSessionStatus(HWND hWnd, SM_SERVER *s, void *param);
void SmMacTableDlg(HWND hWnd, SM_HUB *s, char *session_name);
UINT SmMacTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmMacTableDlgInit(HWND hWnd, SM_TABLE *s);
void SmMacTableDlgUpdate(HWND hWnd, SM_TABLE *s);
void SmMacTableDlgRefresh(HWND hWnd, SM_TABLE *s);
void SmIpTableDlg(HWND hWnd, SM_HUB *s, char *session_name);
UINT SmIpTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmIpTableDlgInit(HWND hWnd, SM_TABLE *s);
void SmIpTableDlgUpdate(HWND hWnd, SM_TABLE *s);
void SmIpTableDlgRefresh(HWND hWnd, SM_TABLE *s);
bool SmCreateCert(HWND hWnd, X **x, K **k, bool do_not_save, char *default_cn);
UINT SmCreateCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCreateCertDlgInit(HWND hWnd, SM_CERT *s);
void SmCreateCertDlgUpdate(HWND hWnd, SM_CERT *s);
void SmCreateCertDlgOnOk(HWND hWnd, SM_CERT *s);
UINT SmSNATDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSNATDlgUpdate(HWND hWnd, SM_HUB *s);
void SmBridgeDlg(HWND hWnd, SM_SERVER *s);
void SmInstallWinPcap(HWND hWnd, SM_SERVER *s);
UINT SmBridgeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmBridgeDlgInit(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgOnOk(HWND hWnd, SM_SERVER *s);
void SmAddServerCaps(LVB *b, CAPSLIST *t);
void SmConfig(HWND hWnd, SM_SERVER *s);
UINT SmConfigDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmConfigDlgInit(HWND hWnd, SM_CONFIG *c);
void SmHubAdminOption(HWND hWnd, SM_EDIT_HUB *e);
void SmHubExtOption(HWND hWnd, SM_EDIT_HUB *e);
UINT SmHubAdminOptionDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAdminOptionDlgUpdate(HWND hWnd, SM_EDIT_AO *a);
void SmHubAdminOptionDlgInit(HWND hWnd, SM_EDIT_AO *a);
void SmHubAdminOptionDlgOk(HWND hWnd, SM_EDIT_AO *a);
UINT SmHubAdminOptionValueDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAdminOptionValueDlgUpdate(HWND hWnd, SM_EDIT_AO *a);
void SmL3(HWND hWnd, SM_SERVER *s);
UINT SmL3Dlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3DlgInit(HWND hWnd, SM_SERVER *s);
void SmL3DlgUpdate(HWND hWnd, SM_SERVER *s);
void SmL3DlgRefresh(HWND hWnd, SM_SERVER *s);
UINT SmL3AddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3AddDlgUpdate(HWND hWnd, SM_SERVER *s);
UINT SmL3SwDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwDlgUpdate(HWND hWnd, SM_L3SW *w);
void SmL3SwDlgRefresh(HWND hWnd, SM_L3SW *w);
UINT SmL3SwIfDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwIfDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwIfDlgUpdate(HWND hWnd, SM_L3SW *w);
UINT SmL3SwTableDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwTableDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwTableDlgUpdate(HWND hWnd, SM_L3SW *w);
bool SmL3IsSwActive(SM_SERVER *s, char *name);
UINT SmGetCurrentSecureId(HWND hWnd);
UINT SmGetCurrentSecureIdFromReg();
UINT SmSelectSecureId(HWND hWnd);
void SmWriteSelectSecureIdReg(UINT id);
bool SmSelectKeyPair(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size);
bool SmSelectKeyPairEx(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size, UINT bitmap_id);
UINT SmSelectKeyPairDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSelectKeyPairDlgInit(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSelectKeyPairDlgUpdate(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSelectKeyPairDlgRefresh(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSecureManager(HWND hWnd);
UINT SmCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCrlDlgInit(HWND hWnd, SM_HUB *s);
void SmCrlDlgUpdate(HWND hWnd, SM_HUB *s);
void SmCrlDlgRefresh(HWND hWnd, SM_HUB *s);
UINT SmEditCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditCrlDlgInit(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgUpdate(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgOnOk(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgOnLoad(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgSetName(HWND hWnd, NAME *name);
void SmEditCrlDlgSetSerial(HWND hWnd, X_SERIAL *serial);
void SmEditCrlDlgSetHash(HWND hWnd, UCHAR *hash_md5, UCHAR *hash_sha1);
void SmHubAc(HWND hWnd, SM_EDIT_HUB *s);
UINT SmHubAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAcDlgInit(HWND hWnd, SM_EDIT_AC_LIST *p);
void SmHubAcDlgUpdate(HWND hWnd, SM_EDIT_AC_LIST *p);
void SmHubAcDlgRefresh(HWND hWnd, SM_EDIT_AC_LIST *p);
UINT SmHubEditAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubEditAcDlgInit(HWND hWnd, SM_EDIT_AC *p);
void SmHubEditAcDlgUpdate(HWND hWnd, SM_EDIT_AC *p);
void SmHubEditAcDlgOnOk(HWND hWnd, SM_EDIT_AC *p);
UINT SmLogFileDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLogFileDlgInit(HWND hWnd, SM_SERVER *p);
void SmLogFileDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmLogFileDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmLogFileStartDownload(HWND hWnd, SM_SERVER *s, char *server_name, char *filepath, UINT totalsize);
UINT SmReadLogFile(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool SmReadLogFileProc(DOWNLOAD_PROGRESS *g);
UINT SmSaveLogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicense(HWND hWnd, SM_SERVER *s);
UINT SmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicenseDlgInit(HWND hWnd, SM_SERVER *s);
void SmLicenseDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmLicenseDlgUpdate(HWND hWnd, SM_SERVER *s);
bool SmLicenseAdd(HWND hWnd, SM_SERVER *s);
UINT SmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicenseAddDlgInit(HWND hWnd, SM_SERVER *s);
void SmLicenseAddDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus);
void SmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size);
void SmLicenseAddDlgOnOk(HWND hWnd, SM_SERVER *s);
bool SmSetup(HWND hWnd, SM_SERVER *s);
UINT SmSetupDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupDlgInit(HWND hWnd, SM_SETUP *s);
void SmSetupDlgUpdate(HWND hWnd, SM_SETUP *s);
void SmSetupDlgOnOk(HWND hWnd, SM_SETUP *s);
UINT SmSetupHubDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupHubDlgUpdate(HWND hWnd, SM_SETUP *s);
bool SmSetupInit(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllHub(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllLocalBridge(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllLayer3(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllObjectInBridgeHub(HWND hWnd, SM_SETUP *s);
void SmSetupStep(HWND hWnd, SM_SETUP *s);
UINT SmSetupStepDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupStepDlgInit(HWND hWnd, SM_SETUP *s);
void SmSetupOnClose(HWND hWnd, SM_SETUP *s);
bool SmSetupIsNew(SM_SERVER *s);
void SmVLan(HWND hWnd, SM_SERVER *s);
UINT SmVLanDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmVLanDlgInit(HWND hWnd, SM_SERVER *s);
void SmVLanDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmVLanDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmHubMsg(HWND hWnd, SM_EDIT_HUB *s);
UINT SmHubMsgDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubMsgDlgInit(HWND hWnd, SM_EDIT_HUB *s);
void SmHubMsgDlgUpdate(HWND hWnd, SM_EDIT_HUB *s);
void SmHubMsgDlgOnOk(HWND hWnd, SM_EDIT_HUB *s);

