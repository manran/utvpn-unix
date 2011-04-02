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

// Microsoft.h
// Microsoft.c のヘッダ

#ifdef	OS_WIN32

// Windows 用の型が windows.h をインクルードしていなくても使えるようにする
#ifndef	_WINDEF_

typedef void *HWND;

#endif	// _WINDEF_

#ifndef	MICROSOFT_H
#define	MICROSOFT_H


// イベントログ定数
#define	MS_EVENTLOG_TYPE_INFORMATION		0
#define	MS_EVENTLOG_TYPE_WARNING			1
#define	MS_EVENTLOG_TYPE_ERROR				2

#define	MS_RC_EVENTLOG_TYPE_INFORMATION		0x40000001L
#define	MS_RC_EVENTLOG_TYPE_WARNING			0x80000002L
#define	MS_RC_EVENTLOG_TYPE_ERROR			0xC0000003L


// TCP/IP レジストリ値
#define	TCP_MAX_NUM_CONNECTIONS				16777214

#define	DEFAULT_TCP_MAX_WINDOW_SIZE_RECV	5955584
#define	DEFAULT_TCP_MAX_WINDOW_SIZE_SEND	131072
#define	DEFAULT_TCP_MAX_NUM_CONNECTIONS		16777214

// 定数
#define	SVC_ARG_INSTALL				"/install"
#define	SVC_ARG_UNINSTALL			"/uninstall"
#define	SVC_ARG_START				"/start"
#define	SVC_ARG_STOP				"/stop"
#define	SVC_ARG_TEST				"/test"
#define	SVC_ARG_USERMODE			"/usermode"
#define	SVC_ARG_USERMODE_SHOWTRAY	"/usermode_showtray"
#define	SVC_ARG_USERMODE_HIDETRAY	"/usermode_hidetray"
#define	SVC_ARG_SERVICE				"/service"
#define	SVC_ARG_SETUP_INSTALL		"/setup_install"
#define	SVC_ARG_SETUP_UNINSTALL		"/setup_uninstall"
#define	SVC_ARG_WIN9X_SERVICE		"/win9x_service"
#define	SVC_ARG_WIN9X_INSTALL		"/win9x_install"
#define	SVC_ARG_WIN9X_UNINSTALL		"/win9x_uninstall"
#define	SVC_ARG_TCP					"/tcp"
#define	SVC_ARG_TCP_SETUP			"/tcpsetup"
#define	SVC_ARG_TRAFFIC				"/traffic"
#define	SVC_ARG_UIHELP				"/uihelp"
#define	SVC_ARG_UIHELP_W			L"/uihelp"
#define SVC_ARG_SILENT				"/silent"

// サービスがフリーズした場合の自殺までの時間
#define	SVC_SELFKILL_TIMEOUT		(5 * 60 * 1000)

// Win32 版仮想 LAN カードのデバイスドライバの名称 (先頭部分)
#define	VLAN_ADAPTER_NAME			"UT-VPN Client Adapter"

// Win32 版仮想 LAN カードのデバイスドライバの名称 (フルネーム)
#define	VLAN_ADAPTER_NAME_TAG		"UT-VPN Client Adapter - %s"

// Win32 版仮想 LAN カードの [ネットワーク接続] における表示名 (フルネーム)
#define	VLAN_CONNECTION_NAME		"%s - UT-VPN Client"


// サービス時のコマンドライン書式
#define	SVC_RUN_COMMANDLINE			L"\"%s\" /service"

// モード値
#define	SVC_MODE_NONE				0
#define	SVC_MODE_INSTALL			1
#define	SVC_MODE_UNINSTALL			2
#define	SVC_MODE_START				3
#define	SVC_MODE_STOP				4
#define	SVC_MODE_TEST				5
#define	SVC_MODE_USERMODE			6
#define	SVC_MODE_SERVICE			7
#define	SVC_MODE_SETUP_INSTALL		8
#define	SVC_MODE_SETUP_UNINSTALL	9
#define	SVC_MODE_WIN9X_SERVICE		10
#define	SVC_MODE_WIN9X_INSTALL		11
#define	SVC_MODE_WIN9X_UNINSTALL	12
#define	SVC_MODE_TCP				13
#define	SVC_MODE_TCPSETUP			14
#define	SVC_MODE_TRAFFIC			15
#define	SVC_MODE_UIHELP				16


#define	WIN9X_SVC_REGKEY_1			"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
#define	WIN9X_SVC_REGKEY_2			"Software\\Microsoft\\Windows\\CurrentVersion\\Run"

#define	VISTA_MMCSS_KEYNAME			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks"
#define	VISTA_MMCSS_FILENAME		"mmcss_backup.dat"

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"
#define	SVC_DESCRIPT				"SVC_%s_DESCRIPT"

#define	SVC_USERMODE_SETTING_KEY	"Software\\SoftEther Corporation\\UT-VPN\\UserMode Settings"
#define	SVC_HIDETRAY_REG_VALUE		"HideTray_%S"

#define	SVC_CALLING_SM_PROCESS_ID_KEY	"Software\\SoftEther Corporation\\UT-VPN\\Service Control\\%s"
#define SVC_CALLING_SM_PROCESS_ID_VALUE	"ProcessId"

#define	MMCSS_PROFILE_KEYNAME		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile"

// その他の定数
#define	MS_REG_TCP_SETTING_KEY		"Software\\SoftEther Corporation\\Network Settings"



// ドライバ関係の定数
#define	DRIVER_INF_FILE_NAME		L"|vpn_driver.inf"
#define	DRIVER_INF_FILE_NAME_X64	L"|vpn_driver_x64.inf"
#define	DRIVER_INF_FILE_NAME_IA64	L"|vpn_driver_ia64.inf"
#define	DRIVER_INF_FILE_NAME_9X		L"|vpn_driver_9x.inf"
#define	DRIVER_SYS_FILE_NAME		L"|vpn_driver.sys"
#define	DRIVER_SYS_FILE_NAME_X64	L"|vpn_driver_x64.sys"
#define	DRIVER_SYS_FILE_NAME_IA64	L"|vpn_driver_ia64.sys"
#define	DRIVER_SYS_FILE_NAME_9X		L"|vpn_driver_9x.sys"
#define	DRIVER_INSTALL_INF_NAME_TAG	"Sen_%s.inf"
#define	DRIVER_INSTALL_SYS_NAME_TAG	"Sen_%s.sys"
#define	DRIVER_INSTALL_SYS_NAME_TAG_NEW	"Sen_%04u.sys"
#define	DRIVER_INSTALL_SYS_NAME_TAG_MAXID	128

// Vista 用ドライバインストーラ関係
#define	VISTA_DRIVER_INSTALLER_SRC	L"|driver_installer.exe"
#define	VISTA_DRIVER_INSTALLER_SRC_X64	L"|driver_installer_x64.exe"
#define	VISTA_DRIVER_INSTALLER_SRC_IA64	L"|driver_installer_ia64.exe"
#define	VISTA_DRIVER_INSTALLER_DST	L"%s\\driver_installer.exe"

#define	DRIVER_DEVICE_ID_TAG		"SenAdapter_%s"


#if		(defined(MICROSOFT_C) || defined(NETWORK_C)) && (defined(OS_WIN32))

typedef enum __TCP_TABLE_CLASS {
	_TCP_TABLE_BASIC_LISTENER,
	_TCP_TABLE_BASIC_CONNECTIONS,
	_TCP_TABLE_BASIC_ALL,
	_TCP_TABLE_OWNER_PID_LISTENER,
	_TCP_TABLE_OWNER_PID_CONNECTIONS,
	_TCP_TABLE_OWNER_PID_ALL,
	_TCP_TABLE_OWNER_MODULE_LISTENER,
	_TCP_TABLE_OWNER_MODULE_CONNECTIONS,
	_TCP_TABLE_OWNER_MODULE_ALL
} _TCP_TABLE_CLASS, *_PTCP_TABLE_CLASS;

// Win32 ネットワーク関係の API 関数へのポインタ
typedef struct NETWORK_WIN32_FUNCTIONS
{
	HINSTANCE hIpHlpApi32;
	DWORD (WINAPI *DeleteIpForwardEntry)(PMIB_IPFORWARDROW);
	DWORD (WINAPI *CreateIpForwardEntry)(PMIB_IPFORWARDROW);
	DWORD (WINAPI *GetIpForwardTable)(PMIB_IPFORWARDTABLE, PULONG, BOOL);
	DWORD (WINAPI *GetNetworkParams)(PFIXED_INFO, PULONG);
	DWORD (WINAPI *GetIfTable)(PMIB_IFTABLE, PULONG, BOOL);
	DWORD (WINAPI *IpRenewAddress)(PIP_ADAPTER_INDEX_MAP);
	DWORD (WINAPI *IpReleaseAddress)(PIP_ADAPTER_INDEX_MAP);
	DWORD (WINAPI *GetInterfaceInfo)(PIP_INTERFACE_INFO, PULONG);
	DWORD (WINAPI *GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
	DWORD (WINAPI *GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, _TCP_TABLE_CLASS, ULONG);
	DWORD (WINAPI *AllocateAndGetTcpExTableFromStack)(PVOID *, BOOL, HANDLE, DWORD, DWORD);
	DWORD (WINAPI *GetTcpTable)(PMIB_TCPTABLE, PDWORD, BOOL);
	DWORD (WINAPI *NotifyRouteChange)(PHANDLE, LPOVERLAPPED);
	BOOL (WINAPI *CancelIPChangeNotify)(LPOVERLAPPED);
	DWORD (WINAPI *NhpAllocateAndGetInterfaceInfoFromStack)(IP_INTERFACE_NAME_INFO **,
		PDWORD, BOOL, HANDLE, DWORD);
} NETWORK_WIN32_FUNCTIONS;
#endif


#ifdef	MICROSOFT_C
// 内部用構造体
typedef struct MS
{
	HINSTANCE hInst;
	HINSTANCE hKernel32;
	bool IsNt;
	bool IsAdmin;
	struct NT_API *nt;
	HANDLE hCurrentProcess;
	UINT CurrentProcessId;
	bool MiniDumpEnabled;
	char *ExeFileName;
	char *ExeFileDir;
	char *WindowsDir;
	char *System32Dir;
	char *TempDir;
	char *WinTempDir;
	char *WindowsDrive;
	char *ProgramFilesDir;
	char *CommonStartMenuDir;
	char *CommonProgramsDir;
	char *CommonStartupDir;
	char *CommonAppDataDir;
	char *CommonDesktopDir;
	char *PersonalStartMenuDir;
	char *PersonalProgramsDir;
	char *PersonalStartupDir;
	char *PersonalAppDataDir;
	char *PersonalDesktopDir;
	char *MyDocumentsDir;
	char *LocalAppDataDir;
	char *MyTempDir;
	char *UserName;
	char *UserNameEx;
	wchar_t *ExeFileNameW;
	wchar_t *ExeFileDirW;
	wchar_t *WindowsDirW;
	wchar_t *System32DirW;
	wchar_t *TempDirW;
	wchar_t *WinTempDirW;
	wchar_t *WindowsDriveW;
	wchar_t *ProgramFilesDirW;
	wchar_t *CommonStartMenuDirW;
	wchar_t *CommonProgramsDirW;
	wchar_t *CommonStartupDirW;
	wchar_t *CommonAppDataDirW;
	wchar_t *CommonDesktopDirW;
	wchar_t *PersonalStartMenuDirW;
	wchar_t *PersonalProgramsDirW;
	wchar_t *PersonalStartupDirW;
	wchar_t *PersonalAppDataDirW;
	wchar_t *PersonalDesktopDirW;
	wchar_t *MyDocumentsDirW;
	wchar_t *LocalAppDataDirW;
	wchar_t *MyTempDirW;
	wchar_t *UserNameW;
	wchar_t *UserNameExW;
	wchar_t *MinidumpBaseFileNameW;
	IO *LockFile;
} MS;

// Windows NT 用 API
typedef struct NT_API
{
	HINSTANCE hAdvapi32;
	HINSTANCE hShell32;
	HINSTANCE hNewDev;
	HINSTANCE hSetupApi;
	HINSTANCE hWtsApi32;
	HINSTANCE hPsApi;
	HINSTANCE hKernel32;
	HINSTANCE hSecur32;
	HINSTANCE hUser32;
	HINSTANCE hDbgHelp;
	BOOL (WINAPI *OpenProcessToken)(HANDLE, DWORD, PHANDLE);
	BOOL (WINAPI *LookupPrivilegeValue)(char *, char *, PLUID);
	BOOL (WINAPI *AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
	BOOL (WINAPI *InitiateSystemShutdown)(LPTSTR, LPTSTR, DWORD, BOOL, BOOL);
	BOOL (WINAPI *LogonUserW)(wchar_t *, wchar_t *, wchar_t *, DWORD, DWORD, HANDLE *);
	BOOL (WINAPI *LogonUserA)(char *, char *, char *, DWORD, DWORD, HANDLE *);
	BOOL (WINAPI *UpdateDriverForPlugAndPlayDevicesW)(HWND hWnd, wchar_t *hardware_id, wchar_t *inf_path, UINT flag, BOOL *need_reboot);
	UINT (WINAPI *CM_Get_DevNode_Status_Ex)(UINT *, UINT *, DWORD, UINT, HANDLE);
	UINT (WINAPI *CM_Get_Device_ID_ExA)(DWORD, char *, UINT, UINT, HANDLE);
	UINT (WINAPI *WTSQuerySessionInformation)(HANDLE, DWORD, WTS_INFO_CLASS, wchar_t *, DWORD *);
	void (WINAPI *WTSFreeMemory)(void *);
	BOOL (WINAPI *WTSDisconnectSession)(HANDLE, DWORD, BOOL);
	BOOL (WINAPI *WTSEnumerateSessions)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFO *, DWORD *);
	SC_HANDLE (WINAPI *OpenSCManager)(LPCTSTR, LPCTSTR, DWORD);
	SC_HANDLE (WINAPI *CreateServiceA)(SC_HANDLE, LPCTSTR, LPCTSTR, DWORD, DWORD, DWORD, DWORD, LPCTSTR, LPCTSTR, LPDWORD, LPCTSTR, LPCTSTR, LPCTSTR);
	SC_HANDLE (WINAPI *CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
	BOOL (WINAPI *ChangeServiceConfig2)(SC_HANDLE, DWORD, LPVOID);
	BOOL (WINAPI *CloseServiceHandle)(SC_HANDLE);
	SC_HANDLE (WINAPI *OpenService)(SC_HANDLE, LPCTSTR, DWORD);
	BOOL (WINAPI *QueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);
	BOOL (WINAPI *StartService)(SC_HANDLE, DWORD, LPCTSTR);
	BOOL (WINAPI *ControlService)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
	BOOL (WINAPI *SetServiceStatus)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);
	SERVICE_STATUS_HANDLE (WINAPI *RegisterServiceCtrlHandler)(LPCTSTR, LPHANDLER_FUNCTION);
	BOOL (WINAPI *StartServiceCtrlDispatcher)(CONST LPSERVICE_TABLE_ENTRY);
	BOOL (WINAPI *DeleteService)(SC_HANDLE);
	BOOL (WINAPI *EnumProcesses)(DWORD *, DWORD, DWORD *);
	BOOL (WINAPI *EnumProcessModules)(HANDLE, HMODULE *, DWORD, DWORD *);
	DWORD (WINAPI *GetModuleFileNameExA)(HANDLE, HMODULE, LPSTR, DWORD);
	DWORD (WINAPI *GetModuleFileNameExW)(HANDLE, HMODULE, LPWSTR, DWORD);
	LONG (WINAPI *RegDeleteKeyExA)(HKEY, LPCTSTR, REGSAM, DWORD);
	BOOL (WINAPI *IsWow64Process)(HANDLE, BOOL *);
	void (WINAPI *GetNativeSystemInfo)(SYSTEM_INFO *);
	BOOL (WINAPI *DuplicateTokenEx)(HANDLE, DWORD, SECURITY_ATTRIBUTES *, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, HANDLE *);
	BOOL (WINAPI *ConvertStringSidToSidA)(LPCSTR, PSID *);
	BOOL (WINAPI *SetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, void *, DWORD);
	BOOL (WINAPI *GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, void *, DWORD, PDWORD);
	BOOL (WINAPI *CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, void *, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
	BOOL (WINAPI *CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, void *, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	BOOL (WINAPI *LookupAccountSidA)(LPCSTR,PSID,LPSTR,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE);
	BOOL (WINAPI *LookupAccountNameA)(LPCSTR,LPCSTR,PSID,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE);
	BOOL (WINAPI *GetUserNameExA)(EXTENDED_NAME_FORMAT, LPSTR, PULONG);
	BOOL (WINAPI *GetUserNameExW)(EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
	BOOL (WINAPI *SwitchDesktop)(HDESK);
	HDESK (WINAPI *OpenDesktopA)(LPTSTR, DWORD, BOOL, ACCESS_MASK);
	BOOL (WINAPI *CloseDesktop)(HDESK);
	BOOL (WINAPI *SetProcessShutdownParameters)(DWORD, DWORD);
	HANDLE (WINAPI *RegisterEventSourceW)(LPCWSTR, LPCWSTR);
	BOOL (WINAPI *ReportEventW)(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCWSTR *, LPVOID);
	BOOL (WINAPI *DeregisterEventSource)(HANDLE);
	BOOL (WINAPI *Wow64DisableWow64FsRedirection)(void **);
	BOOLEAN (WINAPI *Wow64EnableWow64FsRedirection)(BOOLEAN);
	BOOL (WINAPI *Wow64RevertWow64FsRedirection)(void *);
	BOOL (WINAPI *GetFileInformationByHandle)(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
	HANDLE (WINAPI *GetProcessHeap)();
	BOOL (WINAPI *MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION);
} NT_API;

typedef struct MS_EVENTLOG
{
	HANDLE hEventLog;
} MS_EVENTLOG;

extern NETWORK_WIN32_FUNCTIONS *w32net;

#endif	// MICROSOFT_C

// 警告を出さないようにするための構造体
typedef struct NO_WARNING
{
	DWORD ThreadId;
	THREAD *NoWarningThread;
	EVENT *HaltEvent;
	volatile bool Halt;
	wchar_t *SoundFileName;
} NO_WARNING;

// ルートキーの ID
#define	REG_CLASSES_ROOT		0	// HKEY_CLASSES_ROOT
#define	REG_LOCAL_MACHINE		1	// HKEY_LOCAL_MACHINE
#define	REG_CURRENT_USER		2	// HKEY_CURRENT_USER
#define	REG_USERS				3	// HKEY_USERS

// サービス関数
typedef void (SERVICE_FUNCTION)();

// プロセスリスト項目
typedef struct MS_PROCESS
{
	char ExeFilename[MAX_PATH];		// EXE ファイル名
	wchar_t ExeFilenameW[MAX_PATH];	// EXE ファイル名 (Unicode)
	UINT ProcessId;					// プロセス ID
} MS_PROCESS;

#define	MAX_MS_ADAPTER_IP_ADDRESS	64

// ネットワークアダプタ
typedef struct MS_ADAPTER
{
	char Title[MAX_PATH];			// 表示名
	UINT Index;						// インデックス
	UINT Type;						// 種類
	UINT Status;					// ステータス
	UINT Mtu;						// MTU
	UINT Speed;						// 速度
	UINT AddressSize;				// アドレスサイズ
	UCHAR Address[8];				// アドレス
	UINT64 RecvBytes;				// 受信バイト数
	UINT64 RecvPacketsBroadcast;	// 受信ブロードキャストパケット数
	UINT64 RecvPacketsUnicast;		// 受信ユニキャストパケット数
	UINT64 SendBytes;				// 送信バイト数
	UINT64 SendPacketsBroadcast;	// 送信ブロードキャストパケット数
	UINT64 SendPacketsUnicast;		// 送信ユニキャストパケット数
	bool Info;						// 詳しい情報があるかどうか
	char Guid[MAX_SIZE];			// GUID
	UINT NumIpAddress;				// IP アドレス個数
	IP IpAddresses[MAX_MS_ADAPTER_IP_ADDRESS];	// IP アドレス
	IP SubnetMasks[MAX_MS_ADAPTER_IP_ADDRESS];	// サブネット マスク
	UINT NumGateway;				// ゲートウェイ個数
	IP Gateways[MAX_MS_ADAPTER_IP_ADDRESS];	// ゲートウェイ
	bool UseDhcp;					// DHCP 使用フラグ
	IP DhcpServer;					// DHCP サーバー
	UINT64 DhcpLeaseStart;			// DHCP リース開始日時
	UINT64 DhcpLeaseExpires;		// DHCP リース期限日時
	bool UseWins;					// WINS 使用フラグ
	IP PrimaryWinsServer;			// プライマリ WINS サーバー
	IP SecondaryWinsServer;			// セカンダリ WINS サーバー
} MS_ADAPTER;

// ネットワークアダプタリスト
typedef struct MS_ADAPTER_LIST
{
	UINT Num;						// 個数
	MS_ADAPTER **Adapters;			// 内容
} MS_ADAPTER_LIST;

// TCP 設定
typedef struct MS_TCP
{
	UINT RecvWindowSize;			// 受信ウインドウサイズ
	UINT SendWindowSize;			// 送信ウインドウサイズ
} MS_TCP;

// スリープ防止
typedef struct MS_NOSLEEP
{
	THREAD *Thread;					// スレッド
	EVENT *HaltEvent;				// 停止イベント
	volatile bool Halt;				// 停止フラグ
	bool NoScreenSaver;				// スクリーンセーバーも防止

	// 以下 Windows Vista 用
	wchar_t ScreenSaveActive[MAX_PATH];
	wchar_t SCRNSAVE_EXE[MAX_PATH];
} MS_NOSLEEP;

// 子ウインドウ列挙
typedef struct ENUM_CHILD_WINDOW_PARAM
{
	LIST *o;
	bool no_recursion;
	bool include_ipcontrol;
} ENUM_CHILD_WINDOW_PARAM;

// 関数プロトタイプ
void MsInit();
void MsFree();
char *MsCutExeNameFromCommandLine(char *str);
wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str);

DWORD MsRegAccessMaskFor64Bit(bool force32bit);
DWORD MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit);

bool MsRegIsKey(UINT root, char *name);
bool MsRegIsKeyEx(UINT root, char *name, bool force32bit);
bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit);

bool MsRegIsValue(UINT root, char *keyname, char *valuename);
bool MsRegIsValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegGetValueTypeAndSize(UINT root, char *keyname, char *valuename, UINT *type, UINT *size);
bool MsRegGetValueTypeAndSizeEx(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit);
bool MsRegGetValueTypeAndSizeEx2(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit);
bool MsRegGetValueTypeAndSizeW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size);
bool MsRegGetValueTypeAndSizeExW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit);
bool MsRegGetValueTypeAndSizeEx2W(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit);

bool MsRegReadValue(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size);
bool MsRegReadValueEx(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit);
bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit);
bool MsRegReadValueW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size);
bool MsRegReadValueExW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit);
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit);

char *MsRegReadStr(UINT root, char *keyname, char *valuename);
char *MsRegReadStrEx(UINT root, char *keyname, char *valuename, bool force32bit);
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
wchar_t *MsRegReadStrW(UINT root, char *keyname, char *valuename);
wchar_t *MsRegReadStrExW(UINT root, char *keyname, char *valuename, bool force32bit);
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

UINT MsRegReadInt(UINT root, char *keyname, char *valuename);
UINT MsRegReadIntEx(UINT root, char *keyname, char *valuename, bool force32bit);
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
LIST *MsRegReadStrList(UINT root, char *keyname, char *valuename);
LIST *MsRegReadStrListEx(UINT root, char *keyname, char *valuename, bool force32bit);
LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

BUF *MsRegReadBin(UINT root, char *keyname, char *valuename);
BUF *MsRegReadBinEx(UINT root, char *keyname, char *valuename, bool force32bit);
BUF *MsRegReadBinEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegNewKey(UINT root, char *keyname);
bool MsRegNewKeyEx(UINT root, char *keyname, bool force32bit);
bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegWriteValue(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size);
bool MsRegWriteValueEx(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);
bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);
bool MsRegWriteValueW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size);
bool MsRegWriteValueExW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);
bool MsRegWriteValueEx2W(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit);
bool MsRegWriteStrExpand(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrExpandEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
bool MsRegWriteStrExpandEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit);
bool MsRegWriteStrW(UINT root, char *keyname, char *valuename, wchar_t *str);
bool MsRegWriteStrExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit);
bool MsRegWriteStrEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit);
bool MsRegWriteStrExpandW(UINT root, char *keyname, char *valuename, wchar_t *str);
bool MsRegWriteStrExpandExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit);
bool MsRegWriteStrExpandEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit);

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value);
bool MsRegWriteIntEx(UINT root, char *keyname, char *valuename, UINT value, bool force32bit);
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit);
bool MsRegWriteBin(UINT root, char *keyname, char *valuename, void *data, UINT size);
bool MsRegWriteBinEx(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit);
bool MsRegWriteBinEx2(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit, bool force64bit);

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumKeyEx(UINT root, char *keyname, bool force32bit);
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);
TOKEN_LIST *MsRegEnumValue(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumValueEx(UINT root, char *keyname, bool force32bit);
TOKEN_LIST *MsRegEnumValueEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegDeleteKey(UINT root, char *keyname);
bool MsRegDeleteKeyEx(UINT root, char *keyname, bool force32bit);
bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename);
bool MsRegDeleteValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsIsNt();
bool MsIsAdmin();
bool MsEnablePrivilege(char *name, bool enable);
void *MsGetCurrentProcess();
UINT MsGetCurrentProcessId();
char *MsGetExeFileName();
char *MsGetExeDirName();
wchar_t *MsGetExeDirNameW();

bool MsShutdown(bool reboot, bool force);
bool MsShutdownEx(bool reboot, bool force, UINT time_limit, char *message);
bool MsCheckLogon(wchar_t *username, char *password);
bool MsIsPasswordEmpty(wchar_t *username);
TOKEN_LIST *MsEnumNetworkAdapters(char *start_with_name, char *start_with_name_2);
TOKEN_LIST *MsEnumNetworkAdaptersSen();
bool MsGetSenDeiverFilename(char *name, UINT size, char *instance_name);
bool MsMakeNewSenDriverFilename(char *name, UINT size);
void MsGenerateSenDriverFilenameFromInt(char *name, UINT size, UINT n);
TOKEN_LIST *MsEnumSenDriverFilenames();
char *MsGetNetworkAdapterGuid(char *tag_name, char *instance_name);
wchar_t *MsGetNetworkConnectionName(char *guid);
char *MsGetNetworkConfigRegKeyNameFromGuid(char *guid);
char *MsGetNetworkConfigRegKeyNameFromInstanceName(char *tag_name, char *instance_name);
void MsSetNetworkConfig(char *tag_name, char *instance_name, char *friendly_name, bool show_icon);
void MsInitNetworkConfig(char *tag_name, char *instance_name, char *connection_tag_name);

char *MsGetSpecialDir(int id);
wchar_t *MsGetSpecialDirW(int id);
void MsGetSpecialDirs();
bool MsCheckIsAdmin();
void MsInitTempDir();
void MsFreeTempDir();
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir);
void MsDeleteTempDir();
void MsDeleteAllFile(char *dir);
void MsDeleteAllFileW(wchar_t *dir);
char *MsCreateTempFileName(char *name);
char *MsCreateTempFileNameByExt(char *ext);
IO *MsCreateTempFile(char *name);
IO *MsCreateTempFileByExt(char *ext);

bool MsShowNetworkConfiguration(HWND hWnd);

bool MsInstallVLan(char *tag_name, char *connection_tag_name, char *instance_name);
bool MsUpgradeVLan(char *tag_name, char *connection_tag_name, char *instance_name);
bool MsEnableVLan(char *instance_name);
bool MsDisableVLan(char *instance_name);
bool MsUninstallVLan(char *instance_name);
bool MsIsVLanEnabled(char *instance_name);
void MsRestartVLan(char *instance_name);
bool MsIsVLanExists(char *tag_name, char *instance_name);
bool MsStartDriverInstall(char *instance_name, UCHAR *mac_address, char *sen_sys);
void MsFinishDriverInstall(char *instance_name, char *sen_sys);
void MsGetDriverPath(char *instance_name, wchar_t *src_inf, wchar_t *src_sys, wchar_t *dest_inf, wchar_t *dest_sys, char *sen_sys);
void MsGetDriverPathA(char *instance_name, char *src_inf, char *src_sys, char *dest_inf, char *dest_sys, char *sen_sys);
void MsGenMacAddress(UCHAR *mac);
char *MsGetMacAddress(char *tag_name, char *instance_name);
void MsSetMacAddress(char *tag_name, char *instance_name, char *mac_address);
char *MsGetDriverVersion(char *tag_name, char *instance_name);
char *MsGetDriverFileName(char *tag_name, char *instance_name);
void MsTest();
void MsInitGlobalNetworkConfig();
void MsSetThreadPriorityHigh();
void MsSetThreadPriorityLow();
void MsSetThreadPriorityIdle();
void MsSetThreadPriorityRealtime();
void MsRestoreThreadPriority();
char *MsGetLocalAppDataDir();
char *MsGetCommonAppDataDir();
char *MsGetWindowsDir();
char *MsGetSystem32Dir();
char *MsGetTempDir();
char *MsGetWindowsDrive();
char *MsGetProgramFilesDir();
char *MsGetCommonStartMenuDir();
char *MsGetCommonProgramsDir();
char *MsGetCommonStartupDir();
char *MsGetCommonAppDataDir();
char *MsGetCommonDesktopDir();
char *MsGetPersonalStartMenuDir();
char *MsGetPersonalProgramsDir();
char *MsGetPersonalStartupDir();
char *MsGetPersonalAppDataDir();
char *MsGetPersonalDesktopDir();
char *MsGetMyDocumentsDir();
char *MsGetMyTempDir();
char *MsGetUserName();
char *MsGetUserNameEx();
char *MsGetWinTempDir();
wchar_t *MsGetWindowsDirW();
wchar_t *MsGetExeFileNameW();
wchar_t *MsGetExeFileDirW();
wchar_t *MsGetWindowDirW();
wchar_t *MsGetSystem32DirW();
wchar_t *MsGetTempDirW();
wchar_t *MsGetWindowsDriveW();
wchar_t *MsGetProgramFilesDirW();
wchar_t *MsGetCommonStartMenuDirW();
wchar_t *MsGetCommonProgramsDirW();
wchar_t *MsGetCommonStartupDirW();
wchar_t *MsGetCommonAppDataDirW();
wchar_t *MsGetCommonDesktopDirW();
wchar_t *MsGetPersonalStartMenuDirW();
wchar_t *MsGetPersonalProgramsDirW();
wchar_t *MsGetPersonalStartupDirW();
wchar_t *MsGetPersonalAppDataDirW();
wchar_t *MsGetPersonalDesktopDirW();
wchar_t *MsGetMyDocumentsDirW();
wchar_t *MsGetLocalAppDataDirW();
wchar_t *MsGetMyTempDirW();
wchar_t *MsGetUserNameW();
wchar_t *MsGetUserNameExW();
wchar_t *MsGetWinTempDirW();
UINT MsGetProcessId();
void MsTerminateProcess();
bool MsIsServiceInstalled(char *name);
bool MsInstallService(char *name, char *title, wchar_t *description, char *path);
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code);
bool MsInstallServiceW(char *name, wchar_t *title, wchar_t *description, wchar_t *path);
bool MsUpdateServiceConfig(char *name);
bool MsUninstallService(char *name);
bool MsStartService(char *name);
bool MsStartServiceEx(char *name, UINT *error_code);
bool MsStopService(char *name);
bool MsIsServiceRunning(char *name);
bool MsIsTerminalServiceInstalled();
bool MsIsUserSwitchingInstalled();
bool MsIsTerminalServiceMultiUserInstalled();
UINT MsGetCurrentTerminalSessionId();
bool MsIsTerminalSessionActive(UINT session_id);
bool MsIsCurrentTerminalSessionActive();
bool MsIsCurrentDesktopAvailableForVnc();
wchar_t *MsGetSessionUserName(UINT session_id);
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsTestMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsServiceMode(SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
void MsUserMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
bool MsIsUserMode();
void MsTestOnly();
void MsStopUserModeFromService();
char *MsGetPenCoreDllFileName();
void MsPlaySound(char *name);
void MsSetThreadSingleCpu();
void MsWin9xTest();
bool MsCheckVLanDeviceIdFromRootEnum(char *name);
bool MsInstallVLan9x(char *instance_name);
void MsUpdateCompatibleIDs(char *instance_name);
LIST *MsGetProcessList();
LIST *MsGetProcessList9x();
LIST *MsGetProcessListNt();
void MsFreeProcessList(LIST *o);
void MsPrintProcessList(LIST *o);
int MsCompareProcessList(void *p1, void *p2);
MS_PROCESS *MsSearchProcessById(LIST *o, UINT id);
void MsGetCurrentProcessExeName(char *name, UINT size);
void MsGetCurrentProcessExeNameW(wchar_t *name, UINT size);
bool MsKillProcess(UINT id);
void MsKillOtherInstance();
void MsKillOtherInstanceEx(char *exclude_svcname);
bool MsGetShortPathNameA(char *long_path, char *short_path, UINT short_path_size);
bool MsGetShortPathNameW(wchar_t *long_path, wchar_t *short_path, UINT short_path_size);
void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid);
UINT MsReadCallingServiceManagerProcessId(char *svcname, bool current_user);


MS_ADAPTER_LIST *MsCreateAdapterListInner();
MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info);
void MsFreeAdapter(MS_ADAPTER *a);
void MsFreeAdapterList(MS_ADAPTER_LIST *o);
wchar_t *MsGetAdapterTypeStr(UINT type);
wchar_t *MsGetAdapterStatusStr(UINT status);
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a);
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o);
void MsInitAdapterListModule();
void MsFreeAdapterListModule();
MS_ADAPTER_LIST *MsCreateAdapterList();
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info);
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a);
MS_ADAPTER *MsGetAdapter(char *title);

void *MsLoadLibrary(char *name);
void *MsLoadLibraryW(wchar_t *name);
void *MsLoadLibraryAsDataFile(char *name);
void *MsLoadLibraryAsDataFileW(wchar_t *name);

void MsPrintTick();
bool MsDisableIme();

void MsGetTcpConfig(MS_TCP *tcp);
void MsSetTcpConfig(MS_TCP *tcp);
void MsSaveTcpConfigReg(MS_TCP *tcp);
bool MsLoadTcpConfigReg(MS_TCP *tcp);
bool MsIsTcpConfigSupported();
void MsApplyTcpConfig();
bool MsIsShouldShowTcpConfigApp();
void MsDeleteTcpConfigReg();

UINT MsGetConsoleWidth();
UINT MsSetConsoleWidth(UINT size);
NO_WARNING *MsInitNoWarning();
void MsFreeNoWarning(NO_WARNING *nw);
void MsNoWarningThreadProc(THREAD *thread, void *param);
char *MsNoWarningSoundInit();
void MsNoWarningSoundFree(char *s);
bool MsCloseWarningWindow(UINT thread_id);
LIST *MsEnumChildWindows(LIST *o, HWND hWnd);
void MsAddWindowToList(LIST *o, HWND hWnd);
UINT MsGetThreadLocale();
LIST *NewWindowList();
int CmpWindowList(void *p1, void *p2);
void AddWindow(LIST *o, HWND hWnd);
void FreeWindowList(LIST *o);
LIST *EnumAllChildWindow(HWND hWnd);
LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self);
LIST *EnumAllWindow();
LIST *EnumAllWindowEx(bool no_recursion, bool include_ipcontrol);
LIST *EnumAllTopWindow();

bool MsExecDriverInstaller(char *arg);
bool MsIsVista();
bool MsIsWin2000();
bool MsIsWin2000OrGreater();
void MsRegistWindowsFirewall(char *title);
void MsRegistWindowsFirewallEx(char *title, char *exe);
void MsRegistWindowsFirewallEx2(char *title, char *exe);
bool MsIs64BitWindows();
bool MsIsX64();
bool MsIsIA64();
void *MsDisableWow64FileSystemRedirection();
void MsRestoreWow64FileSystemRedirection(void *p);
void MsSetWow64FileSystemRedirectionEnable(bool enable);

bool MsCheckFileDigitalSignature(HWND hWnd, char *name, bool *danger);
bool MsCheckFileDigitalSignatureW(HWND hWnd, wchar_t *name, bool *danger);

bool MsGetProcessExeName(char *path, UINT size, UINT id);
bool MsGetProcessExeNameW(wchar_t *path, UINT size, UINT id);
bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd);
bool MsGetWindowOwnerProcessExeNameW(wchar_t *path, UINT size, HWND hWnd);

void *MsRunAsUserEx(char *filename, char *arg, bool hide);
void *MsRunAsUserExW(wchar_t *filename, wchar_t *arg, bool hide);
void *MsRunAsUserExInner(char *filename, char *arg, bool hide);
void *MsRunAsUserExInnerW(wchar_t *filename, wchar_t *arg, bool hide);

UINT MsGetCursorPosHash();
bool MsIsProcessExists(char *exename);
bool MsIsProcessExistsW(wchar_t *exename);

void MsGetComputerName(char *name, UINT size);
void MsNoSleepThread(THREAD *thread, void *param);
void MsNoSleepThreadVista(THREAD *thread, void *param);
UINT64 MsGetScreenSaverTimeout();
void *MsNoSleepStart(bool no_screensaver);
void MsNoSleepEnd(void *p);
bool MsIsRemoteDesktopAvailable();
bool MsIsRemoteDesktopCanEnableByRegistory();
bool MsIsRemoteDesktopEnabled();
bool MsEnableRemoteDesktop();

void MsSetFileToHidden(char *name);
void MsSetFileToHiddenW(wchar_t *name);
bool MsGetFileVersion(char *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4);
bool MsGetFileVersionW(wchar_t *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4);

bool MsExtractCabinetFileFromExe(char *exe, char *cab);
bool MsExtractCabinetFileFromExeW(wchar_t *exe, wchar_t *cab);
BUF *MsExtractResourceFromExe(char *exe, char *type, char *name);
BUF *MsExtractResourceFromExeW(wchar_t *exe, char *type, char *name);
bool MsExtractCab(char *cab_name, char *dest_dir_name);
bool MsExtractCabW(wchar_t *cab_name, wchar_t *dest_dir_name);
bool MsGetCabarcExeFilename(char *name, UINT size);
bool MsGetCabarcExeFilenameW(wchar_t *name, UINT size);
bool MsExtractCabFromMsi(char *msi, char *cab);
bool MsExtractCabFromMsiW(wchar_t *msi, wchar_t *cab);
bool MsIsDirectory(char *name);
bool MsIsDirectoryW(wchar_t *name);
bool MsUniIsDirectory(wchar_t *name);
bool MsUniFileDelete(wchar_t *name);
bool MsUniDirectoryDelete(wchar_t *name);
bool MsUniMakeDir(wchar_t *name);
void MsUniMakeDirEx(wchar_t *name);
void MsMakeDirEx(char *name);
bool MsMakeDir(char *name);
bool MsDirectoryDelete(char *name);
bool MsFileDelete(char *name);
bool MsExecute(char *exe, char *arg);
bool MsExecuteW(wchar_t *exe, wchar_t *arg);
bool MsExecuteEx(char *exe, char *arg, void **process_handle);
bool MsExecuteExW(wchar_t *exe, wchar_t *arg, void **process_handle);
UINT MsWaitProcessExit(void *process_handle);
bool MsIsFileLocked(char *name);
bool MsIsFileLockedW(wchar_t *name);
bool MsIsLocalDrive(char *name);
bool MsIsLocalDriveW(wchar_t *name);
void MsUpdateSystem();
bool MsGetPhysicalMacAddressFromNetbios(void *address);
bool MsGetPhysicalMacAddressFromApi(void *address);
bool MsGetPhysicalMacAddress(void *address);
bool MsIsUseWelcomeLogin();
UINT64 MsGetHiResCounter();
double MsGetHiResTimeSpan(UINT64 diff);
UINT64 MsGetHiResTimeSpanUSec(UINT64 diff);
BUF *MsRegSubkeysToBuf(UINT root, char *keyname, bool force32bit, bool force64bit);
void MsBufToRegSubkeys(UINT root, char *keyname, BUF *b, bool overwrite, bool force32bit, bool force64bit);
void MsRegDeleteSubkeys(UINT root, char *keyname, bool force32bit, bool force64bit);
void MsRestartMMCSS();
bool MsIsMMCSSNetworkThrottlingEnabled();
void MsSetMMCSSNetworkThrottlingEnable(bool enable);
void MsSetShutdownParameters(UINT level, UINT flag);
void MsChangeIconOnTrayEx2(void *icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags);
bool MsIsTrayInited();
UINT MsGetClipboardOwnerProcessId();
void MsDeleteClipboard();
void *MsInitEventLog(wchar_t *src_name);
void MsFreeEventLog(void *p);
bool MsWriteEventLog(void *p, UINT type, wchar_t *str);
bool MsIsWinXPOrWinVista();
bool MsGetFileInformation(void *h, void *info);
void MsSetErrorModeToSilent();
void MsSetEnableMinidump(bool enabled);
void MsWriteMinidump(wchar_t *filename, void *ex);

// 内部関数
#ifdef	MICROSOFT_C

LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);
HKEY MsGetRootKeyFromInt(UINT root);
NT_API *MsLoadNtApiFunctions();
void MsFreeNtApiFunctions(NT_API *nt);
void MsDestroyDevInfo(HDEVINFO info);
HDEVINFO MsGetDevInfoFromDeviceId(SP_DEVINFO_DATA *dev_info_data, char *device_id);
bool MsStartDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsStopDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsDeleteDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsIsDeviceRunning(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv);
void CALLBACK MsServiceHandler(DWORD opcode);
void MsServiceStoperThread(THREAD *t, void *p);
void MsServiceStoperMainThread(THREAD *t, void *p);
void MsServiceStarterMainThread(THREAD *t, void *p);
LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void MsShowIconOnTray(HWND hWnd, HICON icon, wchar_t *tooltip, UINT msg);
void MsRestoreIconOnTray();
void MsChangeIconOnTray(HICON icon, wchar_t *tooltip);
void MsChangeIconOnTrayEx(HICON icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags);
void MsHideIconOnTray();
void MsUserModeTrayMenu(HWND hWnd);
bool MsAppendMenu(HMENU hMenu, UINT flags, UINT_PTR id, wchar_t *str);
bool MsInsertMenu(HMENU hMenu, UINT pos, UINT flags, UINT_PTR id_new_item, wchar_t *lp_new_item);
bool CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam);
BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam);
bool CALLBACK MsEnumThreadWindowProc(HWND hWnd, LPARAM lParam);
HANDLE MsCreateUserToken();
SID *MsGetSidFromAccountName(char *name);
void MsFreeSid(SID *sid);

#endif	// MICROSOFT_C

#endif	// MICROSOFT_H

#endif	// OS_WIN32

