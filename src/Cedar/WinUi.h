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

// WinUi.h
// Win32 用ユーザーインターフェースコード

#ifdef	OS_WIN32

#define	WINUI_DEBUG_TEXT							"@winui_debug.txt"

#define	LV_INSERT_RESET_ALL_ITEM_MIN				500

#define WINUI_PASSWORD_NULL_USERNAME				"NULL"

#define WINUI_DEFAULT_DIALOG_UNIT_X					7
#define WINUI_DEFAULT_DIALOG_UNIT_Y					12

// Windows 用の型が windows.h をインクルードしていなくても使えるようにする
#ifndef	_WINDEF_

typedef void *HWND;
typedef void *HFONT;
typedef void *HICON;
typedef void *HMENU;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef void *HINSTANCE;

#endif	// _WINDEF_


// 定数
#define	FREE_REGKEY				"Software\\SoftEther Corporation\\UT-VPN Client\\Free Edition Info"
#define ONCE_MSG_REGKEY			"Software\\SoftEther Corporation\\UT-VPN\\Common"
#define ONCE_MSG_REGVALUE		"HideMessage_%u"

#define	SPLASH_BMP_REGKEY		"Software\\SoftEther Corporation\\UT-VPN\\SplashScreen"
#define	SPLASH_BMP_REGVALUE		"LastId"

#define	NICINFO_AUTOCLOSE_TIME_1	(20 * 1000)
#define	NICINFO_AUTOCLOSE_TIME_2	1800

extern bool UseAlpha;
extern UINT AlphaValue;


// マクロ
#define	DIALOG			DIALOGEX(false)
#define	DIALOG_WHITE	DIALOGEX(true)
#define	DIALOGEX(white)								\
	void *param = GetParam(hWnd);					\
	{												\
		UINT ret;									\
		ret = DlgProc(hWnd, msg, wParam, lParam, white);	\
		if (ret != 0) return ret;					\
	}

typedef UINT (__stdcall DIALOG_PROC)(HWND, UINT, WPARAM, LPARAM);

typedef UINT (WINUI_DIALOG_PROC)(HWND, UINT, WPARAM, LPARAM, void *);


// セキュア操作内容
#define	WINUI_SECURE_ENUM_OBJECTS		1			// オブジェクトの列挙
#define	WINUI_SECURE_WRITE_DATA			2			// データの書き込み
#define	WINUI_SECURE_READ_DATA			3			// データの読み込み
#define	WINUI_SECURE_WRITE_CERT			4			// 証明書の書き込み
#define	WINUI_SECURE_READ_CERT			5			// 証明書の読み込み
#define	WINUI_SECURE_WRITE_KEY			6			// 秘密鍵の書き込み
#define	WINUI_SECURE_SIGN_WITH_KEY		7			// 秘密鍵による署名
#define	WINUI_SECURE_DELETE_OBJECT		8			// オブジェクトの削除
#define	WINUI_SECURE_DELETE_CERT		9			// 証明書の削除
#define	WINUI_SECURE_DELETE_KEY			10			// 秘密鍵の削除
#define	WINUI_SECURE_DELETE_DATA		11			// データの削除

// セキュア操作構造体
typedef struct WINUI_SECURE_BATCH
{
	UINT Type;										// 動作の種類
	char *Name;										// 名前
	bool Private;									// プライベートモード
	BUF *InputData;									// 入力データ
	BUF *OutputData;								// 出力データ
	X *InputX;										// 入力証明書
	X *OutputX;										// 出力証明書
	K *InputK;										// 入力秘密鍵
	LIST *EnumList;									// 列挙リスト
	UCHAR OutputSign[128];							// 出力署名
	bool Succeed;									// 成功フラグ
} WINUI_SECURE_BATCH;

// ステータスウインドウ
typedef struct STATUS_WINDOW
{
	HWND hWnd;
	THREAD *Thread;
} STATUS_WINDOW;

// バッチ処理アイテム
typedef struct LVB_ITEM
{
	UINT NumStrings;				// 文字列数
	wchar_t **Strings;				// 文字列バッファ
	UINT Image;						// 画像番号
	void *Param;					// パラメータ
} LVB_ITEM;

// LV 挿入バッチ処理
typedef struct LVB
{
	LIST *ItemList;					// アイテムリスト
} LVB;


#ifdef	CreateWindow

// 内部用コード

// フォント
typedef struct FONT
{
	UINT Size;						// サイズ
	bool Bold;						// 太字
	bool Italic;					// 斜体
	bool UnderLine;					// 下線
	bool StrikeOut;					// 取り消し線
	char *Name;						// フォント名
	HFONT hFont;					// フォント
	UINT x, y;						// フォントサイズ
} FONT;

// フォントキャッシュリスト
static LIST *font_list = NULL;

// ダイアログ関係
typedef struct DIALOG_PARAM
{
	bool white;
	void *param;
	WINUI_DIALOG_PROC *proc;
	bool meiryo;
} DIALOG_PARAM;

// セキュアデバイスウインドウ関係
typedef struct SECURE_DEVICE_WINDOW
{
	WINUI_SECURE_BATCH *batch;
	UINT num_batch;
	UINT device_id;
	struct SECURE_DEVICE_THREAD *p;
	char *default_pin;
	UINT BitmapId;
} SECURE_DEVICE_WINDOW;

// スレッド
typedef struct SECURE_DEVICE_THREAD
{
	SECURE_DEVICE_WINDOW *w;
	HWND hWnd;
	bool Succeed;
	wchar_t *ErrorMessage;
	char *pin;
} SECURE_DEVICE_THREAD;

void StartSecureDevice(HWND hWnd, SECURE_DEVICE_WINDOW *w);

// パスフレーズ
typedef struct PASSPHRASE_DLG
{
	char pass[MAX_SIZE];
	BUF *buf;
	bool p12;
} PASSPHRASE_DLG;

void PassphraseDlgProcCommand(HWND hWnd, PASSPHRASE_DLG *p);

// ステータスウインドウ
typedef struct STATUS_WINDOW_PARAM
{
	HWND hWnd;
	SOCK *Sock;
	THREAD *Thread;
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
} STATUS_WINDOW_PARAM;

// 証明書表示ダイアログ
typedef struct CERT_DLG
{
	X *x, *issuer_x;
	bool ManagerMode;
} CERT_DLG;


typedef struct IMAGELIST_ICON
{
	UINT id;
	HICON hSmallImage;
	HICON hLargeImage;
	UINT Index;
} IMAGELIST_ICON;

typedef struct SEARCH_WINDOW_PARAM
{
	wchar_t *caption;
	HWND hWndFound;
} SEARCH_WINDOW_PARAM;

// リモート接続画面設定
typedef struct WINUI_REMOTE
{
	bool flag1;
	char *RegKeyName;					// レジストリキー名
	UINT Icon;							// アイコン
	wchar_t *Caption;					// キャプション
	wchar_t *Title;						// タイトル
	char *Hostname;						// ホスト名
	char *DefaultHostname;				// デフォルトホスト名
	LIST *CandidateList;				// 候補リスト
} WINUI_REMOTE;

void InitImageList();
void FreeImageList();
IMAGELIST_ICON *LoadIconForImageList(UINT id);
int CompareImageListIcon(void *p1, void *p2);
BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam);
void PrintCertInfo(HWND hWnd, CERT_DLG *p);
void CertDlgUpdate(HWND hWnd, CERT_DLG *p);
bool CALLBACK SearchWindowEnumProc(HWND hWnd, LPARAM lParam);
UINT RemoteDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void RemoteDlgInit(HWND hWnd, WINUI_REMOTE *r);
void RemoteDlgRefresh(HWND hWnd, WINUI_REMOTE *r);
void RemoteDlgOnOk(HWND hWnd, WINUI_REMOTE *r);
int CALLBACK LvSortProc(LPARAM param1, LPARAM param2, LPARAM sort_param);

// アイコンキャッシュ
typedef struct ICON_CACHE
{
	UINT id;
	bool small_icon;
	HICON hIcon;
} ICON_CACHE;

static LIST *icon_cache_list = NULL;

// ソート関係
typedef struct WINUI_LV_SORT
{
	HWND hWnd;
	UINT id;
	UINT subitem;
	bool desc;
	bool numeric;
} WINUI_LV_SORT;

// バージョン情報
typedef struct WINUI_ABOUT
{
	CEDAR *Cedar;
	char *ProductName;
	UINT Bitmap;
} WINUI_ABOUT;

UINT AboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void AboutDlgInit(HWND hWnd, WINUI_ABOUT *a);

typedef struct WIN9X_REBOOT_DLG
{
	UINT64 StartTime;
	UINT TotalTime;
} WIN9X_REBOOT_DLG;



// STRING
typedef struct STRING_DLG
{
	wchar_t String[MAX_SIZE];
	wchar_t *Title;
	wchar_t *Info;
	UINT Icon;
	bool AllowEmpty;
	bool AllowUnsafe;
} STRING_DLG;

void StringDlgInit(HWND hWnd, STRING_DLG *s);
void StringDlgUpdate(HWND hWnd, STRING_DLG *s);

// PIN コードは 5 分間キャッシュされる
#define	WINUI_SECUREDEVICE_PIN_CACHE_TIME		(5 * 60 * 1000)
extern char cached_pin_code[MAX_SIZE];
extern UINT64 cached_pin_code_expires;

// TCP 接続ダイアログ関係
typedef struct WINCONNECT_DLG_DATA
{
	wchar_t *caption;
	wchar_t *info;
	UINT icon_id;
	UINT timeout;
	char *hostname;
	UINT port;
	bool cancel;
	SOCK *ret_sock;
	THREAD *thread;
	HWND hWnd;
} WINCONNECT_DLG_DATA;

#endif	// WINUI_C

// 隠し
typedef struct KAKUSHI
{
	HWND hWnd;
	THREAD *Thread;
	volatile bool Halt;
	UINT64 StartTick, Span;
} KAKUSHI;

// フリー版に関する情報画面
typedef struct FREEINFO
{
	char ServerName[MAX_SERVER_STR_LEN + 1];
	HWND hWnd;
	THREAD *Thread;
	EVENT *Event;
} FREEINFO;

// メッセージ
typedef struct ONCEMSG_DLG
{
	UINT Icon;
	wchar_t *Title;
	wchar_t *Message;
	bool ShowCheckbox;
	bool Checked;
	UINT MessageHash;
	bool *halt;
} ONCEMSG_DLG;

// 悪いプロセスの定義
typedef struct BAD_PROCESS
{
	char *ExeName;
	char *Title;
} BAD_PROCESS;

// ビットマップ
typedef struct WINBMP
{
	void *hBitmap;
	UINT Width, Height, Bits;
	void *hDC;
} WINBMP;

// メモリ DC
typedef struct WINMEMDC
{
	void *hDC;
	UINT Width, Height;
	void *hBitmap;
	UCHAR *Data;
} WINMEMDC;

#ifdef	WINUI_C

// 競合するアンチウイルスソフトのプロセス名一覧
static BAD_PROCESS bad_processes[] =
{
	{"nod32krn.exe", "NOD32 Antivirus",},
};

static UINT num_bad_processes = sizeof(bad_processes) / sizeof(bad_processes[0]);

#endif	// WINUI_C

// 関数プロトタイプ
void InitWinUi(wchar_t *software_name, char *font, UINT fontsize);
void SetWinUiTitle(wchar_t *title);
void FreeWinUi();
HWND DlgItem(HWND hWnd, UINT id);
void SetText(HWND hWnd, UINT id, wchar_t *str);
void SetTextInner(HWND hWnd, UINT id, wchar_t *str);
void SetTextA(HWND hWnd, UINT id, char *str);
wchar_t *GetText(HWND hWnd, UINT id);
char *GetTextA(HWND hWnd, UINT id);
bool GetTxt(HWND hWnd, UINT id, wchar_t *str, UINT size);
bool GetTxtA(HWND hWnd, UINT id, char *str, UINT size);
bool IsEnable(HWND hWnd, UINT id);
bool IsDisable(HWND hWnd, UINT id);
void Enable(HWND hWnd, UINT id);
void Disable(HWND hWnd, UINT id);
void SetEnable(HWND hWnd, UINT id, bool b);
void Close(HWND hWnd);
void DoEvents(HWND hWnd);
void Refresh(HWND hWnd);
UINT GetInt(HWND hWnd, UINT id);
void SetInt(HWND hWnd, UINT id, UINT value);
void SetIntEx(HWND hWnd, UINT id, UINT value);
void Focus(HWND hWnd, UINT id);
void FocusEx(HWND hWnd, UINT id);
bool IsFocus(HWND hWnd, UINT id);
wchar_t *GetClass(HWND hWnd, UINT id);
char *GetClassA(HWND hWnd, UINT id);
void SelectEdit(HWND hWnd, UINT id);
void UnselectEdit(HWND hWnd, UINT id);
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam);
bool IsEmpty(HWND hWnd, UINT id);
UINT GetTextLen(HWND hWnd, UINT id, bool unicode);
UINT GetTextSize(HWND hWnd, UINT id, bool unicode);
UINT GetStyle(HWND hWnd, UINT id);
void SetStyle(HWND hWnd, UINT id, UINT style);
void RemoveStyle(HWND hWnd, UINT id, UINT style);
UINT GetExStyle(HWND hWnd, UINT id);
void SetExStyle(HWND hWnd, UINT id, UINT style);
void RemoveExStyle(HWND hWnd, UINT id, UINT style);
void Hide(HWND hWnd, UINT id);
void Show(HWND hWnd, UINT id);
void SetShow(HWND hWnd, UINT id, bool b);
bool IsHide(HWND hWnd, UINT id);
bool IsShow(HWND hWnd, UINT id);
void Top(HWND hWnd);
void NoTop(HWND hWnd);
void *GetParam(HWND hWnd);
void SetParam(HWND hWnd, void *param);
UINT DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, bool white_color);
void SetAplha(HWND hWnd, UINT value0_255);
void NoticeSettingChange();
void UiTest();
UINT DialogInternal(HWND hWnd, UINT id, DIALOG_PROC *proc, void *param);
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg);
UINT MsgBoxEx(HWND hWnd, UINT flag, wchar_t *msg, ...);
void SetTextEx(HWND hWnd, UINT id, wchar_t *str, ...);
void SetTextExA(HWND hWnd, UINT id, char *str, ...);
void FormatText(HWND hWnd, UINT id, ...);
void FormatTextA(HWND hWnd, UINT id, ...);
void Center(HWND hWnd);
void Center2(HWND hWnd);
void CenterParent(HWND hWnd);
void GetMonitorSize(UINT *width, UINT *height);
void DisableClose(HWND hWnd);
void EnableClose(HWND hWnd);
void InitFont();
void FreeFont();
int CompareFont(void *p1, void *p2);
HFONT GetFont(char *name, UINT size, bool bold, bool italic, bool underline, bool strikeout);
bool CalcFontSize(HFONT hFont, UINT *x, UINT *y);
bool GetFontSize(HFONT hFont, UINT *x, UINT *y);
void SetFont(HWND hWnd, UINT id, HFONT hFont);
void LimitText(HWND hWnd, UINT id, UINT count);
bool CheckTextLen(HWND hWnd, UINT id, UINT len, bool unicode);
bool CheckTextSize(HWND hWnd, UINT id, UINT size, bool unicode);
void Check(HWND hWnd, UINT id, bool b);
bool IsChecked(HWND hWnd, UINT id);
void SetIcon(HWND hWnd, UINT id, UINT icon_id);
void SetBitmap(HWND hWnd, UINT id, UINT bmp_id);
bool SecureDeviceWindow(HWND hWnd, WINUI_SECURE_BATCH *batch, UINT num_batch, UINT device_id, UINT bitmap_id);
UINT Dialog(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param);
UINT DialogEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white);
UINT DialogEx2(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white, bool meiryo);
HWND DialogCreateEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white);
UINT __stdcall InternalDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
UINT SecureDeviceWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
HFONT Font(UINT size, UINT bold);
void DlgFont(HWND hWnd, UINT id, UINT size, UINT bold);
void OpenAvi(HWND hWnd, UINT id, UINT avi_id);
void CloseAvi(HWND hWnd, UINT id);
void PlayAvi(HWND hWnd, UINT id, bool repeat);
void StopAvi(HWND hWnd, UINT id);
void EnableSecureDeviceWindowControls(HWND hWnd, bool enable);
void SecureDeviceThread(THREAD *t, void *param);
void Command(HWND hWnd, UINT id);
wchar_t *OpenDlg(HWND hWnd, wchar_t *filter, wchar_t *title);
char *OpenDlgA(HWND hWnd, char *filter, char *title);
wchar_t *SaveDlg(HWND hWnd, wchar_t *filter, wchar_t *title, wchar_t *default_name, wchar_t *default_ext);
char *SaveDlgA(HWND hWnd, char *filter, char *title, char *default_name, char *default_ext);
wchar_t *MakeFilter(wchar_t *str);
char *MakeFilterA(char *str);
void PkcsUtil();
UINT PkcsUtilProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PkcsUtilWrite(HWND hWnd);
void PkcsUtilErase(HWND hWnd);
bool PassphraseDlg(HWND hWnd, char *pass, UINT pass_size, BUF *buf, bool p12);
UINT PassphraseDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool PasswordDlg(HWND hWnd, UI_PASSWORD_DLG *p);
void PasswordDlgOnOk(HWND hWnd, UI_PASSWORD_DLG *p);
UINT PasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PasswordDlgProcChange(HWND hWnd, UI_PASSWORD_DLG *p);
UINT CbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data);
UINT CbAddStrA(HWND hWnd, UINT id, char *str, UINT data);
UINT CbAddStr9xA(HWND hWnd, UINT id, char *str, UINT data);
UINT CbInsertStr(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT data);
UINT CbInsertStrA(HWND hWnd, UINT id, UINT index, char *str, UINT data);
UINT CbInsertStr9xA(HWND hWnd, UINT id, UINT index, char *str, UINT data);
void CbSelectIndex(HWND hWnd, UINT id, UINT index);
UINT CbNum(HWND hWnd, UINT id);
UINT CbFindStr(HWND hWnd, UINT id, wchar_t *str);
UINT CbFindStr9xA(HWND hWnd, UINT id, char *str);
wchar_t *CbGetStr(HWND hWnd, UINT id);
UINT CbFindData(HWND hWnd, UINT id, UINT data);
UINT CbGetData(HWND hWnd, UINT id, UINT index);
void CbSelect(HWND hWnd, UINT id, int data);
void CbReset(HWND hWnd, UINT id);
void CbSetHeight(HWND hWnd, UINT id, UINT value);
UINT CbGetSelectIndex(HWND hWnd, UINT id);
UINT CbGetSelect(HWND hWnd, UINT id);
void SetRange(HWND hWnd, UINT id, UINT start, UINT end);
void SetPos(HWND hWnd, UINT id, UINT pos);
UINT LbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data);
UINT LbAddStrA(HWND hWnd, UINT id, char *str, UINT data);
UINT LbInsertStr(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT data);
UINT LbInsertStrA(HWND hWnd, UINT id, UINT index, char *str, UINT data);
void LbSelectIndex(HWND hWnd, UINT id, UINT index);
UINT LbNum(HWND hWnd, UINT id);
UINT LbFindStr(HWND hWnd, UINT id, wchar_t *str);
wchar_t *LbGetStr(HWND hWnd, UINT id);
UINT LbFindData(HWND hWnd, UINT id, UINT data);
UINT LbGetData(HWND hWnd, UINT id, UINT index);
void LbSelect(HWND hWnd, UINT id, int data);
void LbReset(HWND hWnd, UINT id);
void LbSetHeight(HWND hWnd, UINT id, UINT value);
UINT LbGetSelectIndex(HWND hWnd, UINT id);
UINT LbGetSelect(HWND hWnd, UINT id);
STATUS_WINDOW *StatusPrinterWindowStart(SOCK *s, wchar_t *account_name);
void StatusPrinterWindowStop(STATUS_WINDOW *sw);
void StatusPrinterWindowPrint(STATUS_WINDOW *sw, wchar_t *str);
void StatusPrinterWindowThread(THREAD *thread, void *param);
UINT StatusPrinterWindowDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CertDlg(HWND hWnd, X *x, X *issuer_x, bool manager);
UINT CertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void LvInit(HWND hWnd, UINT id);
void LvInitEx(HWND hWnd, UINT id, bool no_image);
void LvInitEx2(HWND hWnd, UINT id, bool no_image, bool large_icon);
void LvReset(HWND hWnd, UINT id);
void LvInsertColumn(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT width);
UINT GetIcon(UINT icon_id);
void LvInsert(HWND hWnd, UINT id, UINT icon, void *param, UINT num_str, ...);
UINT LvInsertItem(HWND hWnd, UINT id, UINT icon, void *param, wchar_t *str);
UINT LvInsertItemByImageListId(HWND hWnd, UINT id, UINT image, void *param, wchar_t *str);
UINT LvInsertItemByImageListIdA(HWND hWnd, UINT id, UINT image, void *param, char *str);
void LvSetItem(HWND hWnd, UINT id, UINT index, UINT pos, wchar_t *str);
void LvSetItemA(HWND hWnd, UINT id, UINT index, UINT pos, char *str);
void LvSetItemParam(HWND hWnd, UINT id, UINT index, void *param);
void LvSetItemImage(HWND hWnd, UINT id, UINT index, UINT icon);
void LvSetItemImageByImageListId(HWND hWnd, UINT id, UINT index, UINT image);
void LvDeleteItem(HWND hWnd, UINT id, UINT index);
UINT LvNum(HWND hWnd, UINT id);
void *LvGetParam(HWND hWnd, UINT id, UINT index);
wchar_t *LvGetStr(HWND hWnd, UINT id, UINT index, UINT pos);
char *LvGetStrA(HWND hWnd, UINT id, UINT index, UINT pos);
void LvShow(HWND hWnd, UINT id, UINT index);
UINT LvSearchParam(HWND hWnd, UINT id, void *param);
UINT LvSearchStr(HWND hWnd, UINT id, UINT pos, wchar_t *str);
UINT LvSearchStrA(HWND hWnd, UINT id, UINT pos, char *str);
UINT LvGetSelected(HWND hWnd, UINT id);
UINT LvGetFocused(HWND hWnd, UINT id);
wchar_t *LvGetFocusedStr(HWND hWnd, UINT id, UINT pos);
wchar_t *LvGetSelectedStr(HWND hWnd, UINT id, UINT pos);
char *LvGetSelectedStrA(HWND hWnd, UINT id, UINT pos);
bool LvIsSelected(HWND hWnd, UINT id);
UINT LvGetNextMasked(HWND hWnd, UINT id, UINT start);
bool LvIsMasked(HWND hWnd, UINT id);
bool LvIsSingleSelected(HWND hWnd, UINT id);
bool LvIsMultiMasked(HWND hWnd, UINT id);
UINT LvGetMaskedNum(HWND hWnd, UINT id);
void LvAutoSize(HWND hWnd, UINT id);
void LvSelect(HWND hWnd, UINT id, UINT index);
void LvSelectAll(HWND hWnd, UINT id);
void LvSwitchSelect(HWND hWnd, UINT id);
void LvSetView(HWND hWnd, UINT id, bool details);
UINT LvGetColumnWidth(HWND hWnd, UINT id, UINT index);
void CheckCertDlg(UI_CHECKCERT *p);
UINT CheckCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PrintCheckCertInfo(HWND hWnd, UI_CHECKCERT *p);
void ShowDlgDiffWarning(HWND hWnd, UI_CHECKCERT *p);
void CheckCertDialogOnOk(HWND hWnd, UI_CHECKCERT *p);
bool ConnectErrorDlg(UI_CONNECTERROR_DLG *p);
UINT ConnectErrorDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
HINSTANCE GetUiDll();
HICON LoadLargeIconInner(UINT id);
HICON LoadSmallIconInner(UINT id);
HICON LoadLargeIcon(UINT id);
HICON LoadSmallIcon(UINT id);
HICON LoadIconEx(UINT id, bool small_icon);
void InitIconCache();
void FreeIconCache();
LVB *LvInsertStart();
void LvInsertAdd(LVB *b, UINT icon, void *param, UINT num_str, ...);
void LvInsertEnd(LVB *b, HWND hWnd, UINT id);
void LvInsertEndEx(LVB *b, HWND hWnd, UINT id, bool force_reset);
void LvSetStyle(HWND hWnd, UINT id, UINT style);
void LvRemoveStyle(HWND hWnd, UINT id, UINT style);
HMENU LoadSubMenu(UINT menu_id, UINT pos, HMENU *parent_menu);
UINT GetMenuItemPos(HMENU hMenu, UINT id);
void DeleteMenuItem(HMENU hMenu, UINT pos);
void SetMenuItemEnable(HMENU hMenu, UINT pos, bool enable);
void SetMenuItemBold(HMENU hMenu, UINT pos, bool bold);
wchar_t *GetMenuStr(HMENU hMenu, UINT pos);
char *GetMenuStrA(HMENU hMenu, UINT pos);
void SetMenuStr(HMENU hMenu, UINT pos, wchar_t *str);
void SetMenuStrA(HMENU hMenu, UINT pos, char *str);
void RemoveShortcutKeyStrFromMenu(HMENU hMenu);
UINT GetMenuNum(HMENU hMenu);
void PrintMenu(HWND hWnd, HMENU hMenu);
void LvRename(HWND hWnd, UINT id, UINT pos);
void AllowFGWindow(UINT process_id);
HWND SearchWindow(wchar_t *caption);
char *RemoteDlg(HWND hWnd, char *regkey, UINT icon, wchar_t *caption, wchar_t *title, char *default_host);
LIST *ReadCandidateFromReg(UINT root, char *key, char *name);
void WriteCandidateToReg(UINT root, char *key, LIST *o, char *name);
UINT LvGetColumnNum(HWND hWnd, UINT id);
void LvSetItemParamEx(HWND hWnd, UINT id, UINT index, UINT subitem, void *param);
void LvSortEx(HWND hWnd, UINT id, UINT subitem, bool desc, bool numeric);
void LvSort(HWND hWnd, UINT id, UINT subitem, bool desc);
void *LvGetParamEx(HWND hWnd, UINT id, UINT index, UINT subitem);
void LvSortHander(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id);
void LvStandardHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id);
void IpSet(HWND hWnd, UINT id, UINT ip);
UINT IpGet(HWND hWnd, UINT id);
void IpClear(HWND hWnd, UINT id);
bool IpIsFilled(HWND hWnd, UINT id);
UINT IpGetFilledNum(HWND hWnd, UINT id);
void About(HWND hWnd, CEDAR *cedar, char *product_name, UINT bitmap);
void Win9xReboot(HWND hWnd);
void Win9xRebootThread(THREAD *t, void *p);
UINT Win9xRebootDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
wchar_t *StringDlg(HWND hWnd, wchar_t *title, wchar_t *info, wchar_t *def, UINT icon, bool allow_empty, bool allow_unsafe);
char *StringDlgA(HWND hWnd, wchar_t *title, wchar_t *info, char *def, UINT icon, bool allow_empty, bool allow_unsafe);
UINT StringDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void InitDialogInternational(HWND hWnd, void *param);
void AdjustWindowAndControlSize(HWND hWnd);
void AdjustDialogXY(UINT *x, UINT *y, UINT dlgfont_x, UINT dlgfont_y);
HFONT GetDialogDefaultFont();
HFONT GetDialogDefaultFontEx(bool meiryo);
void InitMenuInternational(HMENU hMenu, char *prefix);
void InitMenuInternationalUni(HMENU hMenu, char *prefix);
void ShowTcpIpConfigUtil(HWND hWnd, bool util_mode);
void ShowCpu64Warning();
UINT Cpu64DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT TcpIpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void TcpIpDlgInit(HWND hWnd);
void TcpIpDlgUpdate(HWND hWnd);
UINT TcpMsgDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT KakushiDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void KakushiThread(THREAD *thread, void *param);
KAKUSHI *InitKakushi();
void FreeKakushi(KAKUSHI *k);
void ShowEasterEgg(HWND hWnd);
bool ExecuteHamcoreExe(char *name);
bool Win32CnCheckAlreadyExists(bool lock);
void RegistWindowsFirewallAll();
void InitVistaWindowTheme(HWND hWnd);
void WinUiDebug(wchar_t *str);
void WinUiDebugInit();
void WinUiDebugFree();
void OnceMsg(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon);
void OnceMsgEx(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon, bool *halt);
UINT GetOnceMsgHash(wchar_t *title, wchar_t *message);
UINT OnceMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CheckBadProcesses(HWND hWnd);
BAD_PROCESS *IsBadProcess(char *exe);
void ShowBadProcessWarning(HWND hWnd, BAD_PROCESS *bad);
void SetFontMeiryo(HWND hWnd, UINT id);
void SetFontDefault(HWND hWnd, UINT id);
HFONT GetMeiryoFont();
HFONT GetMeiryoFontEx(UINT font_size);
bool ShowWindowsNetworkConnectionDialog();
SOCK *WinConnectEx2(HWND hWnd, char *server, UINT port, UINT timeout, UINT icon_id, wchar_t *caption, wchar_t *info);
UINT WinConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void WinConnectDlgThread(THREAD *thread, void *param);
void NicInfo(UI_NICINFO *info);
UINT NicInfoProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NicInfoInit(HWND hWnd, UI_NICINFO *info);
void NicInfoOnTimer(HWND hWnd, UI_NICINFO *info);
void NicInfoRefresh(HWND hWnd, UI_NICINFO *info);
void NicInfoShowStatus(HWND hWnd, UI_NICINFO *info, wchar_t *msg1, wchar_t *msg2, UINT icon, bool animate);
void NicInfoCloseAfterTime(HWND hWnd, UI_NICINFO *info, UINT tick);
bool IsNewStyleModeEnabled();
void DisableNewStyleMode();
void EnableNewStyleMode();
void InitGdiCache();
WINBMP *LoadBmpFromFileW(wchar_t *filename);
WINBMP *LoadBmpFromFileInnerW(wchar_t *filename);
WINBMP *LoadBmpFromFileA(char *filename);
WINBMP *LoadBmpFromResource(UINT id);
WINBMP *LoadBmpMain(void *hBitmap);
void FreeBmp(WINBMP *b);
void ShowSplash(HWND hWndParent, wchar_t *bmp_file_name, char *title, wchar_t *caption, UINT ticks, UINT line_color, void *param);
void ShowSplashEx(HWND hWndParent, char *software_name, UINT ticks, UINT line_color);
WINMEMDC *NewMemDC(UINT width, UINT height);
void FreeMemDC(WINMEMDC *m);
void LvSetBkImage(HWND hWnd, UINT id, char *bmp_file_name);
bool IsFullColor();

#endif	// OS_WIN32






