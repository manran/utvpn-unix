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

// Microsoft.c
// Microsoft Windows 用コード
// (Windows 以外の環境ではコンパイルされない)

#ifdef	WIN32

#define	MICROSOFT_C

typedef enum    _PNP_VETO_TYPE {
    PNP_VetoTypeUnknown,            // Name is unspecified
    PNP_VetoLegacyDevice,           // Name is an Instance Path
    PNP_VetoPendingClose,           // Name is an Instance Path
    PNP_VetoWindowsApp,             // Name is a Module
    PNP_VetoWindowsService,         // Name is a Service
    PNP_VetoOutstandingOpen,        // Name is an Instance Path
    PNP_VetoDevice,                 // Name is an Instance Path
    PNP_VetoDriver,                 // Name is a Driver Service Name
    PNP_VetoIllegalDeviceRequest,   // Name is an Instance Path
    PNP_VetoInsufficientPower,      // Name is unspecified
    PNP_VetoNonDisableable,         // Name is an Instance Path
    PNP_VetoLegacyDriver,           // Name is a Service
    PNP_VetoInsufficientRights      // Name is unspecified
}   PNP_VETO_TYPE, *PPNP_VETO_TYPE;

#define	_WIN32_IE			0x0600
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#define   SECURITY_WIN32
#include <winsock2.h>
#include <windows.h>
#include <Wintrust.h>
#include <Softpub.h>
#include <Iphlpapi.h>
#include <tlhelp32.h>
#include <wincon.h>
#include <Nb30.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <setupapi.h>
#include <regstr.h>
#include <process.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <cfgmgr32.h>
#include <sddl.h>
#include <Aclapi.h>


static MS *ms = NULL;

// 関数プロトタイプ
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg);
UINT MsgBoxEx(HWND hWnd, UINT flag, wchar_t *msg, ...);
void ShowTcpIpConfigUtil(HWND hWnd, bool util_mode);
void CmTraffic(HWND hWnd);
void CnStart();
void InitCedar();
void FreeCedar();
void InitWinUi(wchar_t *software_name, char *font, UINT fontsize);
void FreeWinUi();

// グローバル変数
void *ms_critical_section = NULL;
UINT64 ms_uint64_1 = 0;

// アダプタリスト関係
static LOCK *lock_adapter_list = NULL;
static MS_ADAPTER_LIST *last_adapter_list = NULL;

// サービス関係
static SERVICE_STATUS_HANDLE ssh = NULL;
static SERVICE_STATUS status;
static char g_service_name[MAX_SIZE];
static SERVICE_FUNCTION *g_start, *g_stop;
static bool exiting = false;
static bool wnd_end;
static bool is_usermode = false;
static HICON tray_icon;
static NOTIFYICONDATA nid;
static NOTIFYICONDATAW nid_nt;
static bool service_for_9x_mode = false;
static THREAD *starter_thread = NULL;
static EVENT *server_stopped_event = NULL;
static THREAD *service_stopper_thread = NULL;
static bool tray_inited = false;
static HWND hWndUsermode = NULL;

// [ネットワーク接続] を開くためのショートカット (最新版では未使用)
static UCHAR network_connection_link[] =
{
	0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x46, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x14, 0x00, 
	0x1F, 0x50, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 
	0x30, 0x9D, 0x14, 0x00, 0x2E, 0x00, 0x20, 0x20, 0xEC, 0x21, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xDD, 
	0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D, 0x14, 0x00, 0x70, 0x00, 0xC7, 0xAC, 0x07, 0x70, 0x02, 0x32, 
	0xD1, 0x11, 0xAA, 0xD2, 0x00, 0x80, 0x5F, 0xC1, 0x27, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};

// Windows Vista 関係の新しいセキュリティ構造体等
#if	0
typedef struct _TOKEN_MANDATORY_LABEL
{
	SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;
#endif

#define SE_GROUP_INTEGRITY                 (0x00000020L)

typedef enum _TOKEN_INFORMATION_CLASS_VISTA
{
	VistaTokenUser = 1,
	VistaTokenGroups,
	VistaTokenPrivileges,
	VistaTokenOwner,
	VistaTokenPrimaryGroup,
	VistaTokenDefaultDacl,
	VistaTokenSource,
	VistaTokenType,
	VistaTokenImpersonationLevel,
	VistaTokenStatistics,
	VistaTokenRestrictedSids,
	VistaTokenSessionId,
	VistaTokenGroupsAndPrivileges,
	VistaTokenSessionReference,
	VistaTokenSandBoxInert,
	VistaTokenAuditPolicy,
	VistaTokenOrigin,
	VistaTokenElevationType,
	VistaTokenLinkedToken,
	VistaTokenElevation,
	VistaTokenHasRestrictions,
	VistaTokenAccessInformation,
	VistaTokenVirtualizationAllowed,
	VistaTokenVirtualizationEnabled,
	VistaTokenIntegrityLevel,
	VistaTokenUIAccess,
	VistaTokenMandatoryPolicy,
	VistaTokenLogonSid,
	VistaMaxTokenInfoClass
} TOKEN_INFORMATION_CLASS_VISTA, *PTOKEN_INFORMATION_CLASS_VISTA;

// エラーを表示しないモードにする
void MsSetErrorModeToSilent()
{
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
}

// ファイル情報の取得
bool MsGetFileInformation(void *h, void *info)
{
	// 引数チェック
	if (h == INVALID_HANDLE_VALUE || info == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	if (ms->nt->GetFileInformationByHandle == NULL)
	{
		return false;
	}

	return ms->nt->GetFileInformationByHandle(h, info);
}

// プロセスのシャットダウンパラメータの設定
void MsSetShutdownParameters(UINT level, UINT flag)
{
	if (MsIsNt() == false)
	{
		return;
	}

	if (ms->nt == false || ms->nt->SetProcessShutdownParameters == NULL)
	{
		return;
	}

	ms->nt->SetProcessShutdownParameters(level, flag);
}

// OS のバージョンが Windows XP または Windows Vista 以降かどうか取得する
bool MsIsWinXPOrWinVista()
{
	OS_INFO *info = GetOsInfo();
	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) >= 3)
	{
		return true;
	}

	return false;
}

// イベントログに書き込む
bool MsWriteEventLog(void *p, UINT type, wchar_t *str)
{
	MS_EVENTLOG *g = (MS_EVENTLOG *)p;
	wchar_t *strings[2];
	UINT id = 0;
	UINT typeapi = 0;
	// 引数チェック
	if (g == NULL || type >= 5 || str == NULL)
	{
		return false;
	}

	strings[0] = str;

	switch (type)
	{
	case MS_EVENTLOG_TYPE_INFORMATION:
		id = MS_RC_EVENTLOG_TYPE_INFORMATION;
		typeapi = EVENTLOG_INFORMATION_TYPE;
		break;

	case MS_EVENTLOG_TYPE_WARNING:
		id = MS_RC_EVENTLOG_TYPE_WARNING;
		typeapi = EVENTLOG_WARNING_TYPE;
		break;

	case MS_EVENTLOG_TYPE_ERROR:
		id = MS_RC_EVENTLOG_TYPE_ERROR;
		typeapi = EVENTLOG_ERROR_TYPE;
		break;
	}

	return ms->nt->ReportEventW(g->hEventLog, typeapi, 0, id, NULL, 1, 0, strings, NULL);
}

// イベントログの解放
void MsFreeEventLog(void *p)
{
	MS_EVENTLOG *g = (MS_EVENTLOG *)p;
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	ms->nt->DeregisterEventSource(g->hEventLog);

	Free(g);
}

// イベントログの初期化
void *MsInitEventLog(wchar_t *src_name)
{
	MS_EVENTLOG *g;
	HANDLE h;
	wchar_t keyname[MAX_PATH];
	char keyname_a[MAX_PATH];
	wchar_t *exename;
	// 引数チェック
	if (src_name == NULL)
	{
		return NULL;
	}

	// レジストリにキーを書き込む
	exename = MsGetExeFileNameW();
	UniFormat(keyname, sizeof(keyname),
		L"SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Application\\%s",
		src_name);
	UniToStr(keyname_a, sizeof(keyname_a), keyname);

	MsRegWriteStrExpandExW(REG_LOCAL_MACHINE, keyname_a, "EventMessageFile",
		exename, false);

	MsRegWriteIntEx(REG_LOCAL_MACHINE, keyname_a, "TypesSupported", 7, false);

	h = ms->nt->RegisterEventSourceW(NULL, src_name);
	if (h == NULL)
	{
		return NULL;
	}

	g = ZeroMalloc(sizeof(MS_EVENTLOG));

	g->hEventLog = h;

	return (void *)g;
}

// クリップボードを空にする
void MsDeleteClipboard()
{
	OpenClipboard(NULL);

	EmptyClipboard();

	CloseClipboard();
}

// クリップボード所有者のプロセス ID を取得する
UINT MsGetClipboardOwnerProcessId()
{
	HWND hWnd = GetClipboardOwner();
	DWORD pid = 0;

	if (hWnd == NULL)
	{
		return 0;
	}

	GetWindowThreadProcessId(hWnd, &pid);

	return pid;
}

// MMCSS の再起動
// 注意: この実装は完璧ではない。
void MsRestartMMCSS()
{
	MsStopService("CTAudSvcService");
	MsStopService("audiosrv");
	MsStopService("MMCSS");
	MsStartService("MMCSS");
	MsStartService("audiosrv");
	MsStartService("CTAudSvcService");
}

// MMCSS によるネットワークスロットリングを有効 / 無効にする
void MsSetMMCSSNetworkThrottlingEnable(bool enable)
{
	UINT value;
	if (MsIsVista() == false)
	{
		return;
	}

	if (enable)
	{
		value = 0x0000000a;
	}
	else
	{
		value = 0xffffffff;
	}

	MsRegWriteIntEx2(REG_LOCAL_MACHINE, MMCSS_PROFILE_KEYNAME, "NetworkThrottlingIndex",
		value,
		false, true);

	MsRestartMMCSS();
}

// MMCSS によるネットワークスロットリングが有効になっているかどうか調査
bool MsIsMMCSSNetworkThrottlingEnabled()
{
	UINT value;
	if (MsIsVista() == false)
	{
		return false;
	}

	if (MsRegIsKeyEx2(REG_LOCAL_MACHINE, MMCSS_PROFILE_KEYNAME, false, true) == false)
	{
		return false;
	}

	value = MsRegReadIntEx2(REG_LOCAL_MACHINE, MMCSS_PROFILE_KEYNAME,
		"NetworkThrottlingIndex", false, true);

	if (value == 0)
	{
		return false;
	}

	if (value == 0x0000000a)
	{
		return true;
	}

	return false;
}

// サブキーをすべて削除する
void MsRegDeleteSubkeys(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	TOKEN_LIST *t;
	UINT i;
	// 引数チェック
	if (keyname == NULL)
	{
		return;
	}

	t = MsRegEnumKeyEx2(root, keyname, force32bit, force64bit);
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char tmp[MAX_PATH];

		Format(tmp, sizeof(tmp), "%s\\%s", keyname, t->Token[i]);

		MsRegDeleteKeyEx2(root, tmp, force32bit, force64bit);
	}

	FreeToken(t);
}

// バッファのデータをレジストリのサブキーに変換する
void MsBufToRegSubkeys(UINT root, char *keyname, BUF *b, bool overwrite, bool force32bit, bool force64bit)
{
	UINT i;
	UINT a;
	UINT num_keys;
	// 引数チェック
	if (keyname == NULL || b == NULL)
	{
		return;
	}

	SeekBuf(b, 0, 0);

	num_keys = ReadBufInt(b);

	for (i = 0;i < num_keys;i++)
	{
		char subkeyname[MAX_PATH];
		char fullkeyname[MAX_PATH];
		UINT j;
		UINT num_values;

		Zero(subkeyname, sizeof(subkeyname));
		ReadBufStr(b, subkeyname, sizeof(subkeyname));

		Format(fullkeyname, sizeof(fullkeyname), "%s\\%s", keyname, subkeyname);

		num_values = ReadBufInt(b);

		for (j = 0;j < num_values;j++)
		{
			char valuename[MAX_PATH];
			char data[MAX_SIZE];

			Zero(valuename, sizeof(valuename));
			ReadBufStr(b, valuename, sizeof(valuename));

			a = ReadBufInt(b);

			if (a == 0)
			{
				Zero(data, sizeof(data));
				ReadBufStr(b, data, sizeof(data));

				if (overwrite || MsRegIsValueEx2(root, fullkeyname, valuename, force32bit, force64bit) == false)
				{
					MsRegWriteStrEx2(root, fullkeyname, valuename, data, force32bit, force64bit);
				}
			}
			else
			{
				if (overwrite || MsRegIsValueEx2(root, fullkeyname, valuename, force32bit, force64bit) == false)
				{
					MsRegWriteIntEx2(root, fullkeyname, valuename, ReadBufInt(b), force32bit, force64bit);
				}
			}
		}
	}
}

// レジストリのサブキーのデータをバッファに変換する
BUF *MsRegSubkeysToBuf(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	TOKEN_LIST *t;
	UINT i;
	BUF *b;
	// 引数チェック
	if (keyname == NULL)
	{
		return NULL;
	}

	t = MsRegEnumKeyEx2(root, keyname, force32bit, force64bit);

	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	WriteBufInt(b, t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		char tmp[MAX_PATH];
		TOKEN_LIST *v;

		Format(tmp, sizeof(tmp), "%s\\%s", keyname, name);

		WriteBufStr(b, name);

		v = MsRegEnumValueEx2(root, tmp, force32bit, force64bit);
		if (v == NULL)
		{
			WriteBufInt(b, 0);
		}
		else
		{
			UINT j;

			WriteBufInt(b, v->NumTokens);

			for (j = 0;j < v->NumTokens;j++)
			{
				char *valuename = v->Token[j];
				char *str;

				WriteBufStr(b, valuename);

				str = MsRegReadStrEx2(root, tmp, valuename, force32bit, force64bit);
				if (str != NULL)
				{
					WriteBufInt(b, 0);
					WriteBufStr(b, str);
					Free(str);
				}
				else
				{
					WriteBufInt(b, 1);
					WriteBufInt(b, MsRegReadIntEx2(root, tmp, valuename, force32bit, force64bit));
				}
			}

			FreeToken(v);
		}
	}

	FreeToken(t);

	return b;
}

// 指定した EXE ファイル名のプロセスが存在しているかどうかチェック
bool MsIsProcessExists(char *exename)
{
	LIST *o;
	bool ret = false;
	UINT i;
	// 引数チェック
	if (exename == NULL)
	{
		return false;
	}

	o = MsGetProcessList();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *proc = LIST_DATA(o, i);
		char exe[MAX_PATH];

		GetFileNameFromFilePath(exe, sizeof(exe), proc->ExeFilename);

		if (StrCmpi(exename, exe) == 0)
		{
			ret = true;
			break;
		}
	}

	MsFreeProcessList(o);

	return ret;
}
bool MsIsProcessExistsW(wchar_t *exename)
{
	LIST *o;
	bool ret = false;
	UINT i;
	// 引数チェック
	if (exename == NULL)
	{
		return false;
	}

	o = MsGetProcessList();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *proc = LIST_DATA(o, i);
		wchar_t exe[MAX_PATH];

		GetFileNameFromFilePathW(exe, sizeof(exe), proc->ExeFilenameW);

		if (UniStrCmpi(exename, exe) == 0)
		{
			ret = true;
			break;
		}
	}

	MsFreeProcessList(o);

	return ret;
}

typedef struct _ASTAT_
{
	ADAPTER_STATUS adapt;
	NAME_BUFFER    NameBuff[30];
} ASTAT, *PASTAT;

// 高精度カウンタの値から精密な時間を取得する
double MsGetHiResTimeSpan(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (double)diff / (double)freq;
}
UINT64 MsGetHiResTimeSpanUSec(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (UINT64)(diff) * 1000ULL * 1000ULL / (UINT64)freq;
}

// 高精度カウンタを取得する
UINT64 MsGetHiResCounter()
{
	LARGE_INTEGER t;
	UINT64 ret;

	if (QueryPerformanceCounter(&t) == false)
	{
		return Tick64();
	}

	Copy(&ret, &t, sizeof(UINT64));

	return ret;
}

// ようこそ画面を使用しているかどうか
bool MsIsUseWelcomeLogin()
{
	UINT os_type;
	if (MsIsNt() == false)
	{
		return false;
	}

	os_type = GetOsInfo()->OsType;

	if (OS_IS_WINDOWS_NT(os_type))
	{
		if (GET_KETA(os_type, 100) == 3)
		{
			if (MsRegReadIntEx2(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
				"LogonType", false, true) == 0)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}

	return false;
}

// コンピュータの物理的な MAC アドレスを 1 つ取得する
bool MsGetPhysicalMacAddress(void *address)
{
	// 引数チェック
	if (address == NULL)
	{
		return false;
	}

	if (MsGetPhysicalMacAddressFromApi(address))
	{
		return true;
	}

	if (MsGetPhysicalMacAddressFromNetbios(address))
	{
		return true;
	}

	return false;
}

// 物理的な MAC アドレスを取得する (API から)
bool MsGetPhysicalMacAddressFromApi(void *address)
{
	MS_ADAPTER_LIST *o;
	UINT i;
	bool ret = false;
	// 引数チェック
	if (address == NULL)
	{
		return false;
	}

	Zero(address, 6);

	o = MsCreateAdapterList();

	for (i = 0;i < o->Num;i++)
	{
		MS_ADAPTER *a = o->Adapters[i];

		if (a->AddressSize == 6 && a->Mtu == 1500)
		{
			bool b = false;
			switch (a->Type)
			{
			case MIB_IF_TYPE_OTHER:
			case MIB_IF_TYPE_ETHERNET:
				b = true;
				break;

			case MIB_IF_TYPE_TOKENRING:
			case MIB_IF_TYPE_FDDI:
			case MIB_IF_TYPE_PPP:
			case MIB_IF_TYPE_LOOPBACK:
			case MIB_IF_TYPE_SLIP:
				b = false;
				break;

			default:
				b = true;
				break;
			}

			if (b)
			{
				if (SearchStrEx(a->Title, "WAN", 0, false) == INFINITE)
				{
					if (a->Status == MIB_IF_OPER_STATUS_CONNECTED || a->Status == MIB_IF_OPER_STATUS_OPERATIONAL)
					{
						if (a->AddressSize == 6)
						{
							if (IsZero(a->Address, 6) == false)
							{
								if (Cmp(address, a->Address, 6) <= 0)
								{
									Copy(address, a->Address, 6);
									ret = true;
								}
							}
						}
					}
				}
			}
		}
	}

	MsFreeAdapterList(o);

	return ret;
}

// 物理的な MAC アドレスを取得する (NetBIOS から)
bool MsGetPhysicalMacAddressFromNetbios(void *address)
{
	NCB ncb;
	UCHAR ret;
	LANA_ENUM lenum;
	UINT i;
	ASTAT adapter;
	bool b = false;
	// 引数チェック
	if (address == NULL)
	{
		return false;
	}

	Zero(&ncb, sizeof(ncb));
	Zero(&lenum, sizeof(lenum));

	ncb.ncb_command = NCBENUM;
	ncb.ncb_buffer = (UCHAR *)&lenum;
	ncb.ncb_length = sizeof(lenum);
	ret = Netbios(&ncb);

	Zero(address, 6);

	for (i = 0;i < lenum.length;i++)
	{
		Zero(&ncb, sizeof(ncb));
		ncb.ncb_command = NCBRESET;
		ncb.ncb_lana_num = lenum.lana[i];

		ret = Netbios(&ncb);

		Zero(&ncb, sizeof(ncb));
		ncb.ncb_command = NCBASTAT;
		ncb.ncb_lana_num = lenum.lana[i];

		StrCpy(ncb.ncb_callname, sizeof(ncb.ncb_callname), "*               ");
		Zero(&adapter, sizeof(adapter));
		ncb.ncb_buffer = (char *)&adapter;
		ncb.ncb_length = sizeof(adapter);

		ret = Netbios(&ncb);

		if (ret == 0)
		{
			if (Cmp(address, adapter.adapt.adapter_address, 6) <= 0)
			{
				Copy(address, adapter.adapt.adapter_address, 6);
				b = true;
			}
		}
	}

	return b;
}

// システム全体のアップデート通知
void MsUpdateSystem()
{
	static DWORD dw = 0;

	SendMessageTimeoutA(HWND_BROADCAST, WM_WININICHANGE, 0, 0, SMTO_NORMAL, 1, (PDWORD_PTR)&dw);
}

// 指定されたパスがローカルドライブかどうか取得する
bool MsIsLocalDrive(char *name)
{
	char tmp[MAX_PATH];
	UINT ret;

	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	Zero(tmp, sizeof(tmp));
	InnerFilePath(tmp, sizeof(tmp), name);

	if (StartWith(tmp, "\\\\"))
	{
		// ネットワークディレクトリ
		return false;
	}

	if (tmp[1] != ':' || tmp[2] != '\\')
	{
		// ドライブ名でない
		return false;
	}

	tmp[3] = 0;

	ret = GetDriveType(tmp);

	if (ret == DRIVE_REMOTE || ret == DRIVE_CDROM || ret == DRIVE_RAMDISK)
	{
		return false;
	}

	return true;
}
bool MsIsLocalDriveW(wchar_t *name)
{
	char name_a[MAX_PATH];

	UniToStr(name_a, sizeof(name_a), name);

	return MsIsLocalDrive(name_a);
}

// 指定されたファイルがロックされているかどうか取得する
bool MsIsFileLocked(char *name)
{
	HANDLE h;
	char tmp[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	InnerFilePath(tmp, sizeof(tmp), name);

	h = CreateFile(tmp, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		return true;
	}

	CloseHandle(h);

	return false;
}
bool MsIsFileLockedW(wchar_t *name)
{
	HANDLE h;
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char name_a[MAX_SIZE];

		UniToStr(name_a, sizeof(name_a), name);

		return MsIsFileLocked(name_a);
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	h = CreateFileW(tmp, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		return true;
	}

	CloseHandle(h);

	return false;
}

// プロセスの終了を待機
UINT MsWaitProcessExit(void *process_handle)
{
	HANDLE h = (HANDLE)process_handle;
	UINT ret = 1;

	if (h == NULL)
	{
		return 1;
	}

	while (true)
	{
		WaitForSingleObject(h, INFINITE);

		ret = 1;
		if (GetExitCodeProcess(h, &ret) == false)
		{
			break;
		}

		if (ret != STILL_ACTIVE)
		{
			break;
		}
	}

	CloseHandle(h);

	return ret;
}

// ファイルの実行 (プロセスハンドル取得)
bool MsExecuteEx(char *exe, char *arg, void **process_handle)
{
	SHELLEXECUTEINFO info;
	HANDLE h;
	// 引数チェック
	if (exe == NULL || process_handle == NULL)
	{
		return false;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.lpVerb = "open";
	info.lpFile = exe;
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpParameters = arg;
	info.nShow = SW_SHOWNORMAL;
	if (ShellExecuteEx(&info) == false)
	{
		return false;
	}

	h = info.hProcess;

	*process_handle = (void *)h;

	return true;
}
bool MsExecuteExW(wchar_t *exe, wchar_t *arg, void **process_handle)
{
	SHELLEXECUTEINFOW info;
	HANDLE h;
	// 引数チェック
	if (exe == NULL || process_handle == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char exe_a[MAX_SIZE];
		char arg_a[MAX_SIZE];

		UniToStr(exe_a, sizeof(exe_a), exe);
		UniToStr(arg_a, sizeof(arg_a), arg);

		return MsExecuteEx(exe_a, arg_a, process_handle);
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.lpVerb = L"open";
	info.lpFile = exe;
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpParameters = arg;
	info.nShow = SW_SHOWNORMAL;
	if (ShellExecuteExW(&info) == false)
	{
		return false;
	}

	h = info.hProcess;

	*process_handle = (void *)h;

	return true;
}

// ファイルの実行
bool MsExecute(char *exe, char *arg)
{
	DWORD d;
	// 引数チェック
	if (exe == NULL)
	{
		return false;
	}

	d = (DWORD)ShellExecuteA(NULL, "open", exe, arg, MsGetExeDirName(), SW_SHOWNORMAL);

	if (d > 32)
	{
		return true;
	}

	return false;
}
bool MsExecuteW(wchar_t *exe, wchar_t *arg)
{
	DWORD d;
	// 引数チェック
	if (exe == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char exe_a[MAX_SIZE];
		char arg_a[MAX_SIZE];

		UniToStr(exe_a, sizeof(exe_a), exe);
		UniToStr(arg_a, sizeof(arg_a), arg);

		return MsExecute(exe_a, arg_a);
	}

	d = (DWORD)ShellExecuteW(NULL, L"open", exe, arg, MsGetExeDirNameW(), SW_SHOWNORMAL);

	if (d > 32)
	{
		return true;
	}

	return false;
}

// ディレクトリの再帰作成
void MsUniMakeDirEx(wchar_t *name)
{
	UINT wp;
	wchar_t *tmp;
	UINT i, len;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	tmp = ZeroMalloc(UniStrSize(name) * 2);
	wp = 0;
	len = UniStrLen(name);
	for (i = 0;i < len;i++)
	{
		wchar_t c = name[i];

		if (c == '\\')
		{
			if (UniStrCmpi(tmp, L"\\\\") != 0 && UniStrCmpi(tmp, L"\\") != 0)
			{
				MsUniMakeDir(tmp);
			}
		}

		tmp[wp++] = c;
	}

	Free(tmp);

	MsUniMakeDir(name);
}
void MsMakeDirEx(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);

	MsUniMakeDirEx(name_w);

	Free(name_w);
}

// ディレクトリの作成
bool MsUniMakeDir(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(name);
		bool ret = MsMakeDir(s);
		Free(s);
		return ret;
	}

	return CreateDirectoryW(name, NULL);
}
bool MsMakeDir(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	return CreateDirectoryA(name, NULL);
}

// ディレクトリの削除
bool MsUniDirectoryDelete(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(name);
		bool ret = MsDirectoryDelete(s);
		Free(s);
		return ret;
	}

	return RemoveDirectoryW(name);
}
bool MsDirectoryDelete(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	return RemoveDirectoryA(name);
}

// ファイルの削除
bool MsUniFileDelete(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		bool ret;
		char *s = CopyUniToStr(name);
		ret = MsFileDelete(s);
		Free(s);
		return ret;
	}

	return DeleteFileW(name);
}
bool MsFileDelete(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	return DeleteFileA(name);
}

// 指定したファイル名がディレクトリかどうか取得する
bool MsUniIsDirectory(wchar_t *name)
{
	DWORD ret;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(name);
		ret = MsIsDirectory(s);
		Free(s);

		return ret;
	}

	ret = GetFileAttributesW(name);
	if (ret == 0xffffffff)
	{
		return false;
	}

	if (ret & FILE_ATTRIBUTE_DIRECTORY)
	{
		return true;
	}

	return false;
}
bool MsIsDirectoryW(wchar_t *name)
{
	return MsUniIsDirectory(name);
}
bool MsIsDirectory(char *name)
{
	DWORD ret;
	char tmp[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	InnerFilePath(tmp, sizeof(tmp), name);

	ret = GetFileAttributesA(tmp);
	if (ret == 0xffffffff)
	{
		return false;
	}

	if (ret & FILE_ATTRIBUTE_DIRECTORY)
	{
		return true;
	}

	return false;
}

// MSI ファイルから Cabinet を取り出す
bool MsExtractCabFromMsi(char *msi, char *cab)
{
	wchar_t msi_w[MAX_PATH];
	wchar_t cab_w[MAX_PATH];

	StrToUni(msi_w, sizeof(msi_w), msi);
	StrToUni(cab_w, sizeof(cab_w), cab);

	return MsExtractCabFromMsiW(msi_w, cab_w);
}
bool MsExtractCabFromMsiW(wchar_t *msi, wchar_t *cab)
{
	BUF *b;
	bool ret = false;
	UINT i;
	char sign[] = {'M', 'S', 'C', 'F', 0, 0, 0, 0,};
	void *pointer = NULL;
	UINT current_pos = 0;
	UINT sign_size;
	// 引数チェック
	if (msi == NULL || cab == NULL)
	{
		return false;
	}

	// MSI を読み込む
	b = ReadDumpW(msi);
	if (b == NULL)
	{
		return false;
	}

	if (b->Size < 128)
	{
		FreeBuf(b);
		return false;
	}

	sign_size = sizeof(sign);

	// "MSCF" を検索する
	for (i = 0;i < (b->Size - sign_size);i++)
	{
		char *p = ((UCHAR *)b->Buf) + i;

		if (Cmp(p, sign, sign_size) == 0)
		{
			pointer = p;
			current_pos = i;
		}
	}

	if (pointer != NULL)
	{
		UINT size = b->Size - current_pos;
		BUF *b2 = NewBuf();

		WriteBuf(b2, pointer, size);

		ret = DumpBufW(b2, cab);

		FreeBuf(b2);

	}

	FreeBuf(b);

	return ret;
}

// Cabinet ファイルからファイルを取り出す
bool MsExtractCab(char *cab_name, char *dest_dir_name)
{
	wchar_t cab_name_w[MAX_SIZE];
	wchar_t dest_dir_name_w[MAX_SIZE];

	StrToUni(cab_name_w, sizeof(cab_name_w), cab_name);
	StrToUni(dest_dir_name_w, sizeof(dest_dir_name_w), dest_dir_name);

	return MsExtractCabW(cab_name_w, dest_dir_name_w);
}
bool MsExtractCabW(wchar_t *cab_name, wchar_t *dest_dir_name)
{
	wchar_t cabarc[MAX_PATH];
	wchar_t arg[MAX_PATH * 2];
	wchar_t tmp[MAX_PATH];

	// 引数チェック
	if (cab_name == NULL || dest_dir_name == NULL)
	{
		return false;
	}

	if (MsGetCabarcExeFilenameW(cabarc, sizeof(cabarc)) == false)
	{
		return false;
	}

	UniStrCpy(tmp, sizeof(tmp), dest_dir_name);
	if (UniEndWith(tmp, L"\\"))
	{
		tmp[UniStrLen(tmp) - 1] = 0;
	}

	UniFormat(arg, sizeof(arg),
		L"-o X \"%s\" * \"%s\"\\",
		cab_name,
		tmp);

	MakeDirW(dest_dir_name);

	if (RunW(cabarc, arg, true, true) == false)
	{
		return false;
	}

	return true;
}

// cabarc.exe の展開
bool MsGetCabarcExeFilename(char *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	ConbinePath(name, size, MsGetMyTempDir(), "cabarc.exe");

	if (IsFileExists(name))
	{
		return true;
	}

	if (FileCopy("|cabarc.exe", name) == false)
	{
		return false;
	}

	return true;
}
bool MsGetCabarcExeFilenameW(wchar_t *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	ConbinePathW(name, size, MsGetMyTempDirW(), L"cabarc.exe");

	if (IsFileExistsW(name))
	{
		return true;
	}

	if (FileCopyW(L"|cabarc.exe", name) == false)
	{
		return false;
	}

	return true;
}

// EXE ファイルから Cabinet ファイルを取り出す
bool MsExtractCabinetFileFromExe(char *exe, char *cab)
{
	BUF *b;
	// 引数チェック
	if (exe == NULL || cab == NULL)
	{
		return false;
	}

	b = MsExtractResourceFromExe(exe, RT_RCDATA, "CABINET");
	if (b == NULL)
	{
		return false;
	}

	if (DumpBuf(b, cab) == false)
	{
		FreeBuf(b);

		return false;
	}

	FreeBuf(b);

	return true;
}
bool MsExtractCabinetFileFromExeW(wchar_t *exe, wchar_t *cab)
{
	BUF *b;
	// 引数チェック
	if (exe == NULL || cab == NULL)
	{
		return false;
	}

	b = MsExtractResourceFromExeW(exe, RT_RCDATA, "CABINET");
	if (b == NULL)
	{
		return false;
	}

	if (DumpBufW(b, cab) == false)
	{
		FreeBuf(b);

		return false;
	}

	FreeBuf(b);

	return true;
}

// EXE ファイルからリソースを取り出す
BUF *MsExtractResourceFromExe(char *exe, char *type, char *name)
{
	HINSTANCE h;
	HRSRC hr;
	HGLOBAL hg;
	UINT size;
	void *data;
	BUF *buf;
	// 引数チェック
	if (exe == NULL || type == NULL || name == NULL)
	{
		return NULL;
	}

	h = LoadLibraryExA(exe, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (h == NULL)
	{
		return NULL;
	}

	hr = FindResourceA(h, name, type);
	if (hr == NULL)
	{
		FreeLibrary(h);
		return NULL;
	}

	hg = LoadResource(h, hr);
	if (hg == NULL)
	{
		FreeLibrary(h);
		return NULL;
	}

	size = SizeofResource(h, hr);
	data = (void *)LockResource(hg);

	buf = NewBuf();
	WriteBuf(buf, data, size);

	FreeResource(hg);
	FreeLibrary(h);

	SeekBuf(buf, 0, 0);

	return buf;
}
BUF *MsExtractResourceFromExeW(wchar_t *exe, char *type, char *name)
{
	HINSTANCE h;
	HRSRC hr;
	HGLOBAL hg;
	UINT size;
	void *data;
	BUF *buf;
	// 引数チェック
	if (exe == NULL || type == NULL || name == NULL)
	{
		return NULL;
	}

	if (IsNt() == false)
	{
		char exe_a[MAX_PATH];

		UniToStr(exe_a, sizeof(exe_a), exe);

		return MsExtractResourceFromExe(exe_a, type, name);
	}

	h = LoadLibraryExW(exe, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (h == NULL)
	{
		return NULL;
	}

	hr = FindResource(h, name, type);
	if (hr == NULL)
	{
		FreeLibrary(h);
		return NULL;
	}

	hg = LoadResource(h, hr);
	if (hg == NULL)
	{
		FreeLibrary(h);
		return NULL;
	}

	size = SizeofResource(h, hr);
	data = (void *)LockResource(hg);

	buf = NewBuf();
	WriteBuf(buf, data, size);

	FreeResource(hg);
	FreeLibrary(h);

	SeekBuf(buf, 0, 0);

	return buf;
}

// ファイルのバージョン情報を取得する
bool MsGetFileVersion(char *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4)
{
	void *data;
	UINT size;
	DWORD h;
	bool ret = false;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	h = 0;
	size = GetFileVersionInfoSize(name, &h);
	if (size == 0)
	{
		return false;
	}

	data = ZeroMalloc(size);

	if (GetFileVersionInfoA(name, 0, size, data))
	{
		VS_FIXEDFILEINFO *info = NULL;
		UINT info_size = 0;
		if (VerQueryValueA(data, "\\", &info, &info_size))
		{
			if (v1 != NULL)
			{
				*v1 = HIWORD(info->dwFileVersionMS);
			}

			if (v2 != NULL)
			{
				*v2 = LOWORD(info->dwFileVersionMS);
			}

			if (v3 != NULL)
			{
				*v3 = HIWORD(info->dwFileVersionLS);
			}

			if (v4 != NULL)
			{
				*v4 = LOWORD(info->dwFileVersionLS);
			}

			ret = true;
		}
	}

	Free(data);

	return ret;
}
bool MsGetFileVersionW(wchar_t *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4)
{
	void *data;
	UINT size;
	DWORD h;
	bool ret = false;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char name_a[MAX_PATH];

		UniToStr(name_a, sizeof(name_a), name);

		return MsGetFileVersion(name_a, v1, v2, v3, v4);
	}

	h = 0;
	size = GetFileVersionInfoSizeW(name, &h);
	if (size == 0)
	{
		return false;
	}

	data = ZeroMalloc(size);

	if (GetFileVersionInfoW(name, 0, size, data))
	{
		VS_FIXEDFILEINFO *info = NULL;
		UINT info_size = 0;
		if (VerQueryValue(data, "\\", &info, &info_size))
		{
			if (v1 != NULL)
			{
				*v1 = HIWORD(info->dwFileVersionMS);
			}

			if (v2 != NULL)
			{
				*v2 = LOWORD(info->dwFileVersionMS);
			}

			if (v3 != NULL)
			{
				*v3 = HIWORD(info->dwFileVersionLS);
			}

			if (v4 != NULL)
			{
				*v4 = LOWORD(info->dwFileVersionLS);
			}

			ret = true;
		}
	}

	Free(data);

	return ret;
}

// ファイルを隠しファイルにする
void MsSetFileToHidden(char *name)
{
	char tmp[MAX_PATH];
	DWORD d;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	NormalizePath(tmp, sizeof(tmp), name);

	d = GetFileAttributesA(tmp);
	if (d != INVALID_FILE_ATTRIBUTES)
	{
		d |= FILE_ATTRIBUTE_HIDDEN;

		SetFileAttributesA(tmp, d);
	}
}
void MsSetFileToHiddenW(wchar_t *name)
{
	wchar_t tmp[MAX_PATH];
	DWORD d;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	if (IsNt() == false)
	{
		char name_a[MAX_SIZE];

		UniToStr(name_a, sizeof(name_a), name);

		MsSetFileToHidden(name_a);

		return;
	}

	NormalizePathW(tmp, sizeof(tmp), name);

	d = GetFileAttributesW(tmp);
	if (d != INVALID_FILE_ATTRIBUTES)
	{
		d |= FILE_ATTRIBUTE_HIDDEN;

		SetFileAttributesW(tmp, d);
	}
}

// スリープ防止用スレッド
void MsNoSleepThread(THREAD *thread, void *param)
{
	MS_NOSLEEP *e;
	EXECUTION_STATE (WINAPI *_SetThreadExecutionState)(EXECUTION_STATE);
	HINSTANCE hKernel32;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	hKernel32 = LoadLibrary("kernel32.dll");

	_SetThreadExecutionState =
		(EXECUTION_STATE (__stdcall *)(EXECUTION_STATE))
		GetProcAddress(hKernel32, "SetThreadExecutionState");

	e = (MS_NOSLEEP *)param;

	while (e->Halt == false)
	{
		DWORD flag = ES_SYSTEM_REQUIRED;

		if (e->NoScreenSaver)
		{
			flag |= ES_DISPLAY_REQUIRED;
		}

		if (_SetThreadExecutionState != NULL)
		{
			_SetThreadExecutionState(flag);
		}

		Wait(e->HaltEvent, 30 * 1000);
	}

	FreeLibrary(hKernel32);
}

// スリープ防止用スレッド (Windows Vista 用)
void MsNoSleepThreadVista(THREAD *thread, void *param)
{
	MS_NOSLEEP *e;
	char *key = "Control Panel\\Desktop";
	UINT64 last_set_flag = 0;
	UINT last_c_x = INFINITE, last_c_y = INFINITE;
	UINT64 last_mouse_move_time = 0;
	EXECUTION_STATE (WINAPI *_SetThreadExecutionState)(EXECUTION_STATE);
	HINSTANCE hKernel32;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	hKernel32 = LoadLibrary("kernel32.dll");

	_SetThreadExecutionState =
		(EXECUTION_STATE (__stdcall *)(EXECUTION_STATE))
		GetProcAddress(hKernel32, "SetThreadExecutionState");

	e = (MS_NOSLEEP *)param;

	while (e->Halt == false)
	{
		DWORD flag = ES_SYSTEM_REQUIRED;
		UINT64 now = Tick64();
		POINT p;
		bool mouse_move = false;

		Zero(&p, sizeof(p));
		GetCursorPos(&p);

		if (p.x != last_c_x || p.y != last_c_y)
		{
			if (last_c_x != INFINITE && last_c_y != INFINITE)
			{
				mouse_move = true;
			}

			last_c_x = p.x;
			last_c_y = p.y;
		}

		if (mouse_move)
		{
			last_mouse_move_time = now;
		}

		if (last_mouse_move_time == 0 || (now > (last_mouse_move_time + 50000ULL)))
		{
			wchar_t *active;
			wchar_t *exe;
			// マウスが 50 秒以上動かない場合はスクリーンセーバーの設定を削除する

			active = MsRegReadStrW(REG_CURRENT_USER, key, "ScreenSaveActive");
			exe = MsRegReadStrW(REG_CURRENT_USER, key, "SCRNSAVE.EXE");

			if (UniToInt(active) != 0 && UniIsEmptyStr(exe) == false)
			{
				// スクリーンセーバーが設定されている
				UniStrCpy(e->ScreenSaveActive, sizeof(e->ScreenSaveActive), active);
				UniStrCpy(e->SCRNSAVE_EXE, sizeof(e->SCRNSAVE_EXE), exe);

				MsRegWriteStrW(REG_CURRENT_USER, key, "ScreenSaveActive", L"0");
				MsRegDeleteValue(REG_CURRENT_USER, key, "SCRNSAVE.EXE");

				Debug("Push SS Settings.\n");
			}

			Free(active);
			Free(exe);

			last_mouse_move_time = now;
		}
		else
		{
			if (mouse_move)
			{
				if (UniIsEmptyStr(e->ScreenSaveActive) == false && UniIsEmptyStr(e->SCRNSAVE_EXE) == false)
				{
					// マウスが動いた場合でスクリーンセーバーが設定されていない場合は
					// スクリーンセーバーの設定を復元する
					wchar_t *active;
					wchar_t *exe;

					active = MsRegReadStrW(REG_CURRENT_USER, key, "ScreenSaveActive");
					exe = MsRegReadStrW(REG_CURRENT_USER, key, "SCRNSAVE.EXE");

					if (UniToInt(active) != 0 && UniIsEmptyStr(exe) == false)
					{
					}
					else
					{
						MsRegWriteStrW(REG_CURRENT_USER, key, "ScreenSaveActive", e->ScreenSaveActive);
						MsRegWriteStrW(REG_CURRENT_USER, key, "SCRNSAVE.EXE", e->SCRNSAVE_EXE);

						Zero(e->ScreenSaveActive, sizeof(e->ScreenSaveActive));
						Zero(e->SCRNSAVE_EXE, sizeof(e->SCRNSAVE_EXE));

						Debug("Pop SS Settings.\n");
					}

					Free(active);
					Free(exe);
				}
			}
		}

		if (last_set_flag == 0 || (now > (last_set_flag + 50000ULL)))
		{
			// フラグセット (50 秒間隔)
			last_set_flag = now;

			if (_SetThreadExecutionState != NULL)
			{
				_SetThreadExecutionState(flag);
			}
		}

		Wait(e->HaltEvent, 512);
	}

	if (true)
	{
		// スクリーンセーバーの設定を復元する
		wchar_t *active;
		wchar_t *exe;

		if (UniIsEmptyStr(e->ScreenSaveActive) == false && UniIsEmptyStr(e->SCRNSAVE_EXE) == false)
		{
			active = MsRegReadStrW(REG_CURRENT_USER, key, "ScreenSaveActive");
			exe = MsRegReadStrW(REG_CURRENT_USER, key, "SCRNSAVE.EXE");

			if (UniToInt(active) != 0 && UniIsEmptyStr(exe) != 0)
			{
			}
			else
			{
				MsRegWriteStrW(REG_CURRENT_USER, key, "ScreenSaveActive", e->ScreenSaveActive);
				MsRegWriteStrW(REG_CURRENT_USER, key, "SCRNSAVE.EXE", e->SCRNSAVE_EXE);

				Zero(e->ScreenSaveActive, sizeof(e->ScreenSaveActive));
				Zero(e->SCRNSAVE_EXE, sizeof(e->SCRNSAVE_EXE));

				Debug("Pop SS Settings.\n");
			}

			Free(active);
			Free(exe);
		}
	}

	FreeLibrary(hKernel32);
}

// スリープ防止の開始
void *MsNoSleepStart(bool no_screensaver)
{
	MS_NOSLEEP *e;
	bool is_vista = MsIsVista();
	bool is_nt_4 = false;
	UINT os_type = GetOsInfo()->OsType;

	if (OS_IS_WINDOWS_NT(os_type))
	{
		if (GET_KETA(os_type, 100) == 1)
		{
			is_nt_4 = true;
		}
	}

	e = ZeroMalloc(sizeof(MS_NOSLEEP));

	e->HaltEvent = NewEvent();
	e->NoScreenSaver = no_screensaver;

	if (e->NoScreenSaver == false || (is_vista == false && is_nt_4 == false))
	{
		e->Thread = NewThread(MsNoSleepThread, e);
	}
	else
	{
		e->Thread = NewThread(MsNoSleepThreadVista, e);
	}

	return (void *)e;
}

// スリープ防止の停止
void MsNoSleepEnd(void *p)
{
	MS_NOSLEEP *e;
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	e = (MS_NOSLEEP *)p;

	e->Halt = true;
	Set(e->HaltEvent);

	WaitThread(e->Thread, INFINITE);
	ReleaseThread(e->Thread);
	ReleaseEvent(e->HaltEvent);

	Free(e);
}

// コンピュータ名の取得
void MsGetComputerName(char *name, UINT size)
{
	DWORD sz;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	sz = size;
	GetComputerName(name, &sz);
}

// マウスカーソルの位置のハッシュ値を取得
UINT MsGetCursorPosHash()
{
	POINT p;

	Zero(&p, sizeof(p));

	if (GetCursorPos(&p) == false)
	{
		return 0;
	}

	return MAKELONG((USHORT)p.x, (USHORT)p.y);
}

// 一般ユーザー権限としてのプロセスの起動
void *MsRunAsUserEx(char *filename, char *arg, bool hide)
{
	void *ret = MsRunAsUserExInner(filename, arg, hide);

	if (ret == NULL)
	{
		Debug("MsRunAsUserExInner Failed.\n");
		ret = Win32RunEx(filename, arg, hide);
	}

	return ret;
}
void *MsRunAsUserExW(wchar_t *filename, wchar_t *arg, bool hide)
{
	void *ret = MsRunAsUserExInnerW(filename, arg, hide);

	if (ret == NULL)
	{
		Debug("MsRunAsUserExInner Failed.\n");
		ret = Win32RunExW(filename, arg, hide);
	}

	return ret;
}
void *MsRunAsUserExInner(char *filename, char *arg, bool hide)
{
	void *ret;
	wchar_t *filename_w;
	wchar_t *arg_w;

	filename_w = CopyStrToUni(filename);
	arg_w = CopyStrToUni(arg);

	ret = MsRunAsUserExInnerW(filename_w, arg_w, hide);

	Free(filename_w);
	Free(arg_w);

	return ret;
}
void *MsRunAsUserExInnerW(wchar_t *filename, wchar_t *arg, bool hide)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	HANDLE hToken;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	if (MsIsVista() == false)
	{
		// Windows Vista 以外では使用できない
		return NULL;
	}

	UniStrCpy(name, sizeof(name), filename);
	UniTrim(name);

	if (UniSearchStr(name, L"\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\"", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\" %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	UniTrim(cmdline);

	hToken = MsCreateUserToken();

	if (hToken == NULL)
	{
		return NULL;
	}

	if (ms->nt->CreateProcessAsUserW(hToken, NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		return NULL;
	}

	CloseHandle(hToken);

	CloseHandle(ret.hThread);
	return ret.hProcess;
}

// アカウント名から SID を取得する
SID *MsGetSidFromAccountName(char *name)
{
	SID *sid;
	UINT sid_size = 4096;
	char *domain_name;
	UINT domain_name_size = 4096;
	SID_NAME_USE use = SidTypeUser;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	if (MsIsNt() == false)
	{
		return NULL;
	}

	sid = ZeroMalloc(sid_size);
	domain_name = ZeroMalloc(domain_name_size);

	if (ms->nt->LookupAccountNameA(NULL, name, sid, &sid_size, domain_name, &domain_name_size, &use) == false)
	{
		Free(sid);
		Free(domain_name);
		return NULL;
	}

	Free(domain_name);

	return sid;
}

// SID を解放する
void MsFreeSid(SID *sid)
{
	// 引数チェック
	if (sid == NULL)
	{
		return;
	}

	Free(sid);
}

// 一般ユーザーのトークンを作成する
HANDLE MsCreateUserToken()
{
	char *medium_sid = "S-1-16-8192";
	char *administrators_sid = "S-1-5-32-544";
	SID *sid = NULL;
	TOKEN_MANDATORY_LABEL til;
	HANDLE hCurrentToken, hNewToken;
	if (MsIsNt() == false)
	{
		return NULL;
	}
	if (ms->nt->ConvertStringSidToSidA == NULL ||
		ms->nt->OpenProcessToken == NULL ||
		ms->nt->DuplicateTokenEx == NULL ||
		ms->nt->GetTokenInformation == NULL ||
		ms->nt->SetTokenInformation == NULL)
	{
		return NULL;
	}

	Zero(&til, sizeof(til));

	if (ms->nt->ConvertStringSidToSidA(medium_sid, &sid) == false)
	{
		return NULL;
	}

	til.Label.Attributes = SE_GROUP_INTEGRITY;
	til.Label.Sid = sid;

	if (ms->nt->OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hCurrentToken) == false)
	{
		LocalFree(sid);
		return NULL;
	}

	if (ms->nt->DuplicateTokenEx(hCurrentToken, MAXIMUM_ALLOWED, NULL,
		SecurityImpersonation, TokenPrimary, &hNewToken) == false)
	{
		CloseHandle(hCurrentToken);
		LocalFree(sid);
		return NULL;
	}

	if (ms->nt->SetTokenInformation(hNewToken, VistaTokenIntegrityLevel, &til,
		sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(sid)) == false)
	{
		CloseHandle(hNewToken);
		CloseHandle(hCurrentToken);
		LocalFree(sid);
		return NULL;
	}

	CloseHandle(hCurrentToken);
	LocalFree(sid);

	return hNewToken;
}

// ファイルのデジタル署名をチェック
bool MsCheckFileDigitalSignature(HWND hWnd, char *name, bool *danger)
{
	wchar_t tmp[MAX_PATH];

	swprintf(tmp, sizeof(tmp), L"%S", name);

	return MsCheckFileDigitalSignatureW(hWnd, tmp, danger);
}
bool MsCheckFileDigitalSignatureW(HWND hWnd, wchar_t *name, bool *danger)
{
	HRESULT ret = S_OK;
	wchar_t *tmp;
	LONG (WINAPI *_WinVerifyTrust)(HWND, GUID *, LPVOID) = NULL;
	HINSTANCE hDll;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (danger != NULL)
	{
		*danger = false;
	}

	tmp = name;

	hDll = LoadLibrary("Wintrust.dll");
	if (hDll == NULL)
	{
		return false;
	}

	_WinVerifyTrust =
		(LONG (__stdcall *)(HWND,GUID *,LPVOID))
		GetProcAddress(hDll, "WinVerifyTrust");
	if (_WinVerifyTrust == NULL)
	{
		FreeLibrary(hDll);
		return false;
	}
	else
	{
		GUID action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		WINTRUST_FILE_INFO file;
		WINTRUST_DATA data;

		Zero(&file, sizeof(file));
		file.cbStruct = sizeof(file);
		file.pcwszFilePath = tmp;

		Zero(&data, sizeof(data));
		data.cbStruct = sizeof(data);
		data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
		data.dwUIChoice = (hWnd != NULL ? WTD_UI_NOGOOD : WTD_UI_NONE);
		data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN;
		data.dwUnionChoice = WTD_CHOICE_FILE;
		data.pFile = &file;

		ret = _WinVerifyTrust(hWnd, &action_id, &data);

		if (ret == ERROR_SUCCESS && danger != NULL)
		{
			if (hWnd != NULL)
			{
				if (MsCheckFileDigitalSignatureW(NULL, name, NULL) == false)
				{
					// 危険なファイルだがユーザーが [OK] を選択してしまった
					*danger = true;
				}
			}
		}
	}

	FreeLibrary(hDll);

	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

// WoW64 リダイレクションを有効または無効にする
void MsSetWow64FileSystemRedirectionEnable(bool enable)
{
	if (MsIs64BitWindows() == false)
	{
		return;
	}

	if (ms->nt->Wow64EnableWow64FsRedirection == NULL)
	{
		return;
	}

	ms->nt->Wow64EnableWow64FsRedirection(enable ? 1 : 0);
}

// WoW64 リダイレクションを無効にする
void *MsDisableWow64FileSystemRedirection()
{
	void *p = NULL;
	if (MsIs64BitWindows() == false)
	{
		return NULL;
	}

	if (ms->nt->Wow64DisableWow64FsRedirection == NULL ||
		ms->nt->Wow64RevertWow64FsRedirection == NULL)
	{
		return NULL;
	}

	if (ms->nt->Wow64DisableWow64FsRedirection(&p) == false)
	{
		return NULL;
	}

	if (p == NULL)
	{
		p = (void *)0x12345678;
	}

	return p;
}

// WoW64 リダイレクションを元に戻す
void MsRestoreWow64FileSystemRedirection(void *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}
	if (p == (void *)0x12345678)
	{
		p = NULL;
	}
	if (MsIs64BitWindows() == false)
	{
		return;
	}

	if (ms->nt->Wow64DisableWow64FsRedirection == NULL ||
		ms->nt->Wow64RevertWow64FsRedirection == NULL)
	{
		return;
	}

	ms->nt->Wow64RevertWow64FsRedirection(p);
}

// 現在 x64 版 Windows が動作しているかどうか取得
bool MsIsX64()
{
	SYSTEM_INFO info;

	if (MsIs64BitWindows() == false)
	{
		return false;
	}
	if (ms->nt->GetNativeSystemInfo == NULL)
	{
		return false;
	}

	Zero(&info, sizeof(info));
	ms->nt->GetNativeSystemInfo(&info);

	if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return true;
	}

	return false;
}

// 現在 IA64 版 Windows が動作しているかどうか取得
bool MsIsIA64()
{
	if (MsIs64BitWindows() == false)
	{
		return false;
	}

	if (MsIsX64())
	{
		return false;
	}

	return true;
}

// 64bit Windows かどうか取得
bool MsIs64BitWindows()
{
	if (Is64())
	{
		return true;
	}
	else
	{
		if (MsIsNt() == false)
		{
			return false;
		}
		else
		{
			if (ms == NULL || ms->nt == NULL)
			{
				return false;
			}

			if (ms->nt->IsWow64Process == NULL)
			{
				return false;
			}
			else
			{
				bool b = false;
				if (ms->nt->IsWow64Process(GetCurrentProcess(), &b) == false)
				{
					return false;
				}
				return b;
			}
		}
	}
}

// Windows ファイアウォール登録
void MsRegistWindowsFirewallEx2(char *title, char *exe)
{
	char *dir = MsGetExeDirName();
	char tmp[MAX_PATH];
	// 引数チェック
	if (title == NULL || exe == NULL)
	{
		return;
	}

	ConbinePath(tmp, sizeof(tmp), dir, exe);

	if (IsFileExists(tmp) == false)
	{
		return;
	}

	MsRegistWindowsFirewallEx(title, tmp);
}
void MsRegistWindowsFirewall(char *title)
{
	// 引数チェック
	if (title == NULL)
	{
		return;
	}

	MsRegistWindowsFirewallEx(title, MsGetExeFileName());
}
void MsRegistWindowsFirewallEx(char *title, char *exe)
{
	char *data =
		"Option Explicit\r\nConst NET_FW_PROFILE_DOMAIN = 0\r\nConst NET_FW_PROFILE_STANDARD = 1\r\n"
		"Const NET_FW_SCOPE_ALL = 0\r\nConst NET_FW_IP_VERSION_ANY = 2\r\nDim fwMgr\r\n"
		"Set fwMgr = CreateObject(\"HNetCfg.FwMgr\")\r\nDim profile\r\n"
		"Set profile = fwMgr.LocalPolicy.CurrentProfile\r\nDim app\r\n"
		"Set app = CreateObject(\"HNetCfg.FwAuthorizedApplication\")\r\n"
		"app.ProcessImageFileName = \"$PATH$\"\r\napp.Name = \"$TITLE$\"\r\n"
		"app.Scope = NET_FW_SCOPE_ALL\r\napp.IpVersion = NET_FW_IP_VERSION_ANY\r\n"
		"app.Enabled = TRUE\r\nOn Error Resume Next\r\nprofile.AuthorizedApplications."
		"Add app\r\n";
	char *tmp;
	UINT tmp_size;
	char filename[MAX_PATH];
	char cscript[MAX_PATH];
	char arg[MAX_PATH];
	UINT ostype;
	IO *o;
	char hash[MAX_PATH];
	UCHAR hashbin[SHA1_SIZE];
	// 引数チェック
	if (title == NULL || exe == NULL)
	{
		return;
	}

	// OS チェック (Windows XP, Windows Server 2003, Windows Vista, Windows 7 以外では実施しない)
	ostype = GetOsInfo()->OsType;
	if (OS_IS_WINDOWS_NT(ostype) == false)
	{
		return;
	}
	if (GET_KETA(ostype, 100) != 3 && GET_KETA(ostype, 100) != 4 && GET_KETA(ostype, 100) != 5 && GET_KETA(ostype, 100) != 6)
	{
		return;
	}

	tmp_size = StrLen(data) * 4;
	tmp = ZeroMalloc(tmp_size);

	HashSha1(hashbin, exe, StrLen(exe));
	BinToStr(hash, sizeof(hash), hashbin, 6);

	ReplaceStrEx(tmp, tmp_size, data, "$TITLE$", title, false);
	ReplaceStrEx(tmp, tmp_size, tmp, "$PATH$", exe, false);

	Format(filename, sizeof(filename), "%s\\winfire_%s.vbs", MsGetMyTempDir(), hash);
	o = FileCreate(filename);
	FileWrite(o, tmp, StrLen(tmp));
	FileClose(o);

	Format(cscript, sizeof(cscript), "%s\\cscript.exe", MsGetSystem32Dir());
	Format(arg, sizeof(arg), "\"%s\"", filename);

	Run(cscript, arg, true, false);

	Debug("cscript %s\n", arg);

	Free(tmp);
}

// Vista 用ドライバインストーラの実行
bool MsExecDriverInstaller(char *arg)
{
	wchar_t tmp[MAX_PATH];
	wchar_t hamcore_dst[MAX_PATH];
	wchar_t hamcore_src[MAX_PATH];
	HANDLE h;
	UINT retcode;
	SHELLEXECUTEINFOW info;
	wchar_t *src_exe;
	wchar_t *arg_w;
	// 引数チェック
	if (arg == NULL)
	{
		return false;
	}

	UniFormat(hamcore_dst, sizeof(hamcore_dst), L"%s\\hamcore.utvpn", MsGetMyTempDirW());
	UniFormat(hamcore_src, sizeof(hamcore_src), L"%s\\hamcore.utvpn", MsGetExeDirNameW());

	// ファイル展開
	src_exe = VISTA_DRIVER_INSTALLER_SRC;

	if (MsIsX64())
	{
		src_exe = VISTA_DRIVER_INSTALLER_SRC_X64;
	}
	if (MsIsIA64())
	{
		src_exe = VISTA_DRIVER_INSTALLER_SRC_IA64;
	}

	UniFormat(tmp, sizeof(tmp), VISTA_DRIVER_INSTALLER_DST, MsGetMyTempDirW());

	if (FileCopyW(src_exe, tmp) == false)
	{
		return false;
	}

	if (FileCopyW(hamcore_src, hamcore_dst) == false)
	{
		return false;
	}

	arg_w = CopyStrToUni(arg);

	// 実行
	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.lpVerb = L"open";
	info.lpFile = tmp;
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpParameters = arg_w;
	info.nShow = SW_SHOWNORMAL;
	if (ShellExecuteExW(&info) == false)
	{
		Free(arg_w);
		return false;
	}

	Free(arg_w);

	h = info.hProcess;
	retcode = 1;

	while (true)
	{
		// 完了まで待機
		WaitForSingleObject(h, INFINITE);

		// 終了コードを取得
		retcode = 1;
		if (GetExitCodeProcess(h, &retcode) == false)
		{
			break;
		}

		if (retcode != STILL_ACTIVE)
		{
			break;
		}
	}

	CloseHandle(h);

	if (retcode & 1)
	{
		return false;
	}

	return true;
}

// 現在のスレッドのロケールを取得
UINT MsGetThreadLocale()
{
	return (UINT)GetThreadLocale();
}

// 現在のコンソールの横幅を設定する
UINT MsSetConsoleWidth(UINT size)
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD c;
	UINT old_x, old_y;
	// 引数チェック
	if (size == 0)
	{
		return 0;
	}
	if (h == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Zero(&info, sizeof(info));
	if (GetConsoleScreenBufferInfo(h, &info) == false)
	{
		return 0;
	}

	old_x = info.dwSize.X;
	old_y = info.dwSize.Y;

	c.X = size;
	c.Y = old_y;

	SetConsoleScreenBufferSize(h, c);

	return old_x;
}

// 現在のコンソールの横幅を取得する
UINT MsGetConsoleWidth()
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;

	if (h == INVALID_HANDLE_VALUE)
	{
		return 80;
	}

	Zero(&info, sizeof(info));
	if (GetConsoleScreenBufferInfo(h, &info) == false)
	{
		return 80;
	}

	return info.dwSize.X;
}

// MS-IME を無効にする
bool MsDisableIme()
{
	HINSTANCE h;
	bool ret = false;
	char dll_name[MAX_PATH];
	BOOL (WINAPI *_ImmDisableIME)(DWORD);

	Format(dll_name, sizeof(dll_name), "%s\\imm32.dll", MsGetSystem32Dir());
	h = MsLoadLibrary(dll_name);
	if (h == NULL)
	{
		return false;
	}

	_ImmDisableIME = (BOOL (__stdcall *)(DWORD))GetProcAddress(h, "ImmDisableIME");

	if (_ImmDisableIME != NULL)
	{
		ret = _ImmDisableIME(-1);
	}

	FreeLibrary(h);

	return ret;
}

// 現在時刻を表示する
void MsPrintTick()
{
	UINT tick = timeGetTime();
	static UINT tick_init = 0;
	if (tick_init == 0)
	{
		tick_init = tick;
		tick = 0;
	}
	else
	{
		tick -= tick_init;
	}

	printf("[%u]\n", tick);
}

// LoadLibrary の hamcore 対応版 (データファイルとして読み込み)
void *MsLoadLibraryAsDataFileW(wchar_t *name)
{
	BUF *b;
	wchar_t tmp_dll_name[MAX_SIZE];
	char hash_str[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	Hash(hash, name, UniStrLen(name), true);

	BinToStr(hash_str, sizeof(hash_str), hash, 4);

	UniFormat(tmp_dll_name, sizeof(tmp_dll_name), L"%s\\%S.dll", MsGetMyTempDirW(), hash_str);

	if (IsFileExistsW(tmp_dll_name) == false)
	{
		b = ReadDumpW(name);
		if (b == NULL)
		{
			return NULL;
		}

		DumpBufW(b, tmp_dll_name);
		FreeBuf(b);
	}

	return LoadLibraryExW(tmp_dll_name, NULL, LOAD_LIBRARY_AS_DATAFILE);
}
void *MsLoadLibraryAsDataFile(char *name)
{
	wchar_t name_w[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	StrToUni(name_w, sizeof(name_w), name);

	return MsLoadLibraryAsDataFileW(name_w);
}

// LoadLibrary の hamcore 対応版
void *MsLoadLibraryW(wchar_t *name)
{
	BUF *b;
	wchar_t tmp_dll_name[MAX_SIZE];
	char hash_str[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	Hash(hash, name, UniStrSize(name), true);

	BinToStr(hash_str, sizeof(hash_str), hash, 4);

	UniFormat(tmp_dll_name, sizeof(tmp_dll_name), L"%s\\%S.dll", MsGetMyTempDirW(), hash_str);

	if (IsFileExistsW(tmp_dll_name) == false)
	{
		b = ReadDumpW(name);
		if (b == NULL)
		{
			return NULL;
		}

		DumpBufW(b, tmp_dll_name);
		FreeBuf(b);
	}

	if (IsNt())
	{
		return LoadLibraryW(tmp_dll_name);
	}
	else
	{
		char tmp_dll_name_a[MAX_SIZE];
		HINSTANCE ret;

		UniToStr(tmp_dll_name_a, sizeof(tmp_dll_name_a), tmp_dll_name);

		ret = LoadLibraryA(tmp_dll_name_a);

		return ret;
	}
}
void *MsLoadLibrary(char *name)
{
	wchar_t name_w[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	StrToUni(name_w, sizeof(name_w), name);

	return MsLoadLibraryW(name_w);
}

// 単一のアダプタの取得
MS_ADAPTER *MsGetAdapter(char *title)
{
	MS_ADAPTER_LIST *o;
	MS_ADAPTER *ret = NULL;
	UINT i;
	// 引数チェック
	if (title == NULL)
	{
		return NULL;
	}

	o = MsCreateAdapterList();
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (StrCmpi(o->Adapters[i]->Title, title) == 0)
		{
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	MsFreeAdapterList(o);

	return ret;
}

// 32 ビットオーバーフローチェック
#define	CHECK_32BIT_OVERFLOW(old_value, new_value)				\
{																\
	if ((old_value) > (new_value))								\
	{															\
		(new_value) += ((UINT64)4294967296ULL);					\
	}															\
}

// 指定したアダプタの TCP/IP 情報を取得する
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a)
{
	IP_ADAPTER_INFO *info, *info_top;
	UINT info_size;
	UINT ret;
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	if (w32net->GetAdaptersInfo == NULL)
	{
		return;
	}

	info_top = ZeroMalloc(sizeof(IP_ADAPTER_INFO));
	info_size = sizeof(IP_ADAPTER_INFO);

	ret = w32net->GetAdaptersInfo(info_top, &info_size);
	if (ret == ERROR_INSUFFICIENT_BUFFER || ret == ERROR_BUFFER_OVERFLOW)
	{
		Free(info_top);
		info_size *= 2;
		info_top = ZeroMalloc(info_size);

		if (w32net->GetAdaptersInfo(info_top, &info_size) != NO_ERROR)
		{
			Free(info_top);
			return;
		}
	}
	else if (ret != NO_ERROR)
	{
		Free(info_top);
		return;
	}

	// 自分のエントリを検索する
	info = info_top;

	while (info != NULL)
	{
		if (info->Index == a->Index)
		{
			IP_ADDR_STRING *s;

			// IP アドレス
			a->NumIpAddress = 0;
			s = &info->IpAddressList;
			while (s != NULL)
			{
				if (a->NumIpAddress < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->IpAddresses[a->NumIpAddress], s->IpAddress.String);
					StrToIP(&a->SubnetMasks[a->NumIpAddress], s->IpMask.String);
					a->NumIpAddress++;
				}
				s = s->Next;
			}

			// ゲートウェイ
			a->NumGateway = 0;
			s = &info->GatewayList;
			while (s != NULL)
			{
				if (a->NumGateway < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->Gateways[a->NumGateway], s->IpAddress.String);
					a->NumGateway++;
				}
				s = s->Next;
			}

			// DHCP サーバー
			a->UseDhcp = (info->DhcpEnabled == 0 ? false : true);
			if (a->UseDhcp)
			{
				SYSTEMTIME st;

				StrToIP(&a->DhcpServer, info->DhcpServer.IpAddress.String);
				TimeToSystem(&st, info->LeaseObtained);
				a->DhcpLeaseStart = SystemToUINT64(&st);

				TimeToSystem(&st, info->LeaseExpires);
				a->DhcpLeaseExpires = SystemToUINT64(&st);
			}

			// WINS サーバー
			a->UseWins = info->HaveWins;
			if (a->UseWins)
			{
				StrToIP(&a->PrimaryWinsServer, info->PrimaryWinsServer.IpAddress.String);
				StrToIP(&a->SecondaryWinsServer, info->SecondaryWinsServer.IpAddress.String);
			}

			StrCpy(a->Guid, sizeof(a->Guid), info->AdapterName);

			a->Info = true;

			break;
		}

		info = info->Next;
	}

	Free(info_top);
}

// アダプタリストの生成
MS_ADAPTER_LIST *MsCreateAdapterList()
{
	return MsCreateAdapterListEx(false);
}
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info)
{
	MS_ADAPTER_LIST *ret;

	if (no_info)
	{
		ret = MsCreateAdapterListInnerEx(true);

		return ret;
	}

	Lock(lock_adapter_list);
	{
		MS_ADAPTER_LIST *old = last_adapter_list;
		UINT i;

		// 新しくアダプタリストを取ってくる
		ret = MsCreateAdapterListInner();

		if (ret == NULL)
		{
			Unlock(lock_adapter_list);
			return NULL;
		}

		// 取ってきたアダプタリストの各エントリについて、前回取得したものが
		// 存在するかどうかチェックする
		for (i = 0;i < ret->Num;i++)
		{
			UINT j;
			for (j = 0;j < old->Num;j++)
			{
				MS_ADAPTER *o = old->Adapters[j];
				MS_ADAPTER *n = ret->Adapters[i];

				if (StrCmpi(o->Title, n->Title) == 0)
				{
					// 古いもののほうが値が小さい場合、インクリメントする
					CHECK_32BIT_OVERFLOW(o->RecvBytes, n->RecvBytes);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsBroadcast, n->RecvPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsUnicast, n->RecvPacketsUnicast);
					CHECK_32BIT_OVERFLOW(o->SendBytes, n->SendBytes);
					CHECK_32BIT_OVERFLOW(o->SendPacketsBroadcast, n->SendPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->SendPacketsUnicast, n->SendPacketsUnicast);
					break;
				}
			}
		}

		// 古いアダプタリストを解放する
		MsFreeAdapterList(old);

		// 新しく取得したアダプタリストのクローンを保存しておく
		last_adapter_list = MsCloneAdapterList(ret);
	}
	Unlock(lock_adapter_list);

	return ret;
}

// アダプタリストモジュールの初期化
void MsInitAdapterListModule()
{
	lock_adapter_list = NewLock(NULL);

	last_adapter_list = MsCreateAdapterListInner();
}

// アダプタリストモジュールの解放
void MsFreeAdapterListModule()
{
	if (last_adapter_list != NULL)
	{
		MsFreeAdapterList(last_adapter_list);
		last_adapter_list = NULL;
	}

	DeleteLock(lock_adapter_list);
	lock_adapter_list = NULL;
}

// アダプタリストのクローン
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o)
{
	MS_ADAPTER_LIST *ret;
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = o->Num;
	ret->Adapters = ZeroMalloc(sizeof(MS_ADAPTER *) * ret->Num);

	for (i = 0;i < ret->Num;i++)
	{
		ret->Adapters[i] = ZeroMalloc(sizeof(MS_ADAPTER));
		Copy(ret->Adapters[i], o->Adapters[i], sizeof(MS_ADAPTER));
	}

	return ret;
}

// アダプタのクローン
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a)
{
	MS_ADAPTER *ret;
	// 引数チェック
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER));
	Copy(ret, a, sizeof(MS_ADAPTER));

	return ret;
}

// アダプタリストの作成
MS_ADAPTER_LIST *MsCreateAdapterListInner()
{
	return MsCreateAdapterListInnerEx(false);
}
MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info)
{
	LIST *o;
	UINT i;
	UINT retcode;
	MIB_IFTABLE *table;
	UINT table_size = sizeof(MIB_IFTABLE);
	MS_ADAPTER_LIST *ret;

	table = ZeroMalloc(table_size);

	if (w32net->GetIfTable == NULL)
	{
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	retcode = w32net->GetIfTable(table, &table_size, TRUE);
	if (retcode == ERROR_INSUFFICIENT_BUFFER || retcode == ERROR_BUFFER_OVERFLOW)
	{
		Free(table);
		table_size *= 2;
		table = ZeroMalloc(table_size);
		if (w32net->GetIfTable(table, &table_size, TRUE) != NO_ERROR)
		{
			Free(table);
			return NULL;
		}
	}
	else if (retcode != NO_ERROR)
	{
		Free(table);
		return NULL;
	}

	o = NewListFast(NULL);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_IFROW *r = &table->table[i];
		char title[MAX_PATH];
		UINT num = 0;
		MS_ADAPTER *a;
		UINT j;

		//if (r->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED || r->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL)
		{
			//if (r->dwType & IF_TYPE_ETHERNET_CSMACD)
			{
				for (j = 1;;j++)
				{
					UINT k;
					bool exists;
					if (j == 1)
					{
						StrCpy(title, sizeof(title), (char *)r->bDescr);
					}
					else
					{
						Format(title, sizeof(title), "%s (%u)", (char *)r->bDescr, j);
					}

					exists = false;

					for (k = 0;k < LIST_NUM(o);k++)
					{
						MS_ADAPTER *a = LIST_DATA(o, k);

						if (StrCmpi(a->Title, title) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						break;
					}
				}

				a = ZeroMalloc(sizeof(MS_ADAPTER));

				// アダプタ情報作成
				StrCpy(a->Title, sizeof(a->Title), title);
				a->Index = r->dwIndex;
				a->Type = r->dwType;
				a->Status = r->dwOperStatus;
				a->Mtu = r->dwMtu;
				a->Speed = r->dwSpeed;
				a->AddressSize = MIN(sizeof(a->Address), r->dwPhysAddrLen);
				Copy(a->Address, r->bPhysAddr, a->AddressSize);
				a->RecvBytes = r->dwInOctets;
				a->RecvPacketsBroadcast = r->dwInNUcastPkts;
				a->RecvPacketsUnicast = r->dwInUcastPkts;
				a->SendBytes = r->dwOutOctets;
				a->SendPacketsBroadcast = r->dwOutNUcastPkts;
				a->SendPacketsUnicast = r->dwOutUcastPkts;

				// TCP/IP 情報取得
				if (no_info == false)
				{
					MsGetAdapterTcpIpInformation(a);
				}

				Add(o, a);
			}
		}
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = LIST_NUM(o);
	ret->Adapters = ToArray(o);

	ReleaseList(o);
	Free(table);

	return ret;
}

// アダプタリストの解放
void MsFreeAdapterList(MS_ADAPTER_LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < o->Num;i++)
	{
		MsFreeAdapter(o->Adapters[i]);
	}
	Free(o->Adapters);

	Free(o);
}

// アダプタ情報の解放
void MsFreeAdapter(MS_ADAPTER *a)
{
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	Free(a);
}

// アダプタの状態文字列を取得する
wchar_t *MsGetAdapterStatusStr(UINT status)
{
	wchar_t *ret;

	switch (status)
	{
	case MIB_IF_OPER_STATUS_NON_OPERATIONAL:
		ret = _UU("MS_NON_OPERATIONAL");
		break;

	case MIB_IF_OPER_STATUS_UNREACHABLE:
		ret = _UU("MS_UNREACHABLE");
		break;

	case MIB_IF_OPER_STATUS_DISCONNECTED:
		ret = _UU("MS_DISCONNECTED");
		break;

	case MIB_IF_OPER_STATUS_CONNECTING:
		ret = _UU("MS_CONNECTING");
		break;

	case MIB_IF_OPER_STATUS_CONNECTED:
		ret = _UU("MS_CONNECTED");
		break;

	default:
		ret = _UU("MS_OPERATIONAL");
		break;
	}

	return ret;
}

// アダプタの種類文字列を取得する
wchar_t *MsGetAdapterTypeStr(UINT type)
{
	wchar_t *ret;

	switch (type)
	{
	case MIB_IF_TYPE_ETHERNET:
		ret = _UU("MS_ETHERNET");
		break;

	case MIB_IF_TYPE_TOKENRING:
		ret = _UU("MS_TOKENRING");
		break;

	case MIB_IF_TYPE_FDDI:
		ret = _UU("MS_FDDI");
		break;

	case MIB_IF_TYPE_PPP:
		ret = _UU("MS_PPP");
		break;

	case MIB_IF_TYPE_LOOPBACK:
		ret = _UU("MS_LOOPBACK");
		break;

	case MIB_IF_TYPE_SLIP:
		ret = _UU("MS_SLIP");
		break;

	default:
		ret = _UU("MS_OTHER");
		break;
	}

	return ret;
}

// 自分自身の EXE の自分以外のインスタンスをすべて終了する
void MsKillOtherInstance()
{
	MsKillOtherInstanceEx(NULL);
}
void MsKillOtherInstanceEx(char *exclude_svcname)
{
	UINT me, i;
	wchar_t me_path[MAX_PATH];
	wchar_t me_path_short[MAX_PATH];
	LIST *o = MsGetProcessList();
	UINT e_procid = 0;
	UINT e_procid2 = 0;

	if (exclude_svcname != NULL)
	{
		e_procid = MsReadCallingServiceManagerProcessId(exclude_svcname, false);
		e_procid2 = MsReadCallingServiceManagerProcessId(exclude_svcname, true);
	}

	me = MsGetProcessId();

	MsGetCurrentProcessExeNameW(me_path, sizeof(me_path));
	MsGetShortPathNameW(me_path, me_path_short, sizeof(me_path_short));

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		if (p->ProcessId != me)
		{
			if ((e_procid == 0 || (e_procid != p->ProcessId)) && (e_procid2 == 0 || (e_procid2 != p->ProcessId)))
			{
				wchar_t tmp[MAX_PATH];
				MsGetShortPathNameW(p->ExeFilenameW, tmp, sizeof(tmp));
				if (UniStrCmpi(me_path_short, tmp) == 0)
				{
					MsKillProcess(p->ProcessId);
				}
			}
		}
	}

	MsFreeProcessList(o);
}

// 短いファイル名を取得する
bool MsGetShortPathNameA(char *long_path, char *short_path, UINT short_path_size)
{
	// 引数チェック
	if (long_path == NULL || short_path == NULL)
	{
		return false;
	}

	if (GetShortPathNameA(long_path, short_path, short_path_size) == 0)
	{
		StrCpy(short_path, short_path_size, long_path);
		return false;
	}

	return true;
}
bool MsGetShortPathNameW(wchar_t *long_path, wchar_t *short_path, UINT short_path_size)
{
	// 引数チェック
	if (long_path == NULL || short_path == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char short_path_a[MAX_SIZE];
		char long_path_a[MAX_SIZE];
		bool ret;

		UniToStr(long_path_a, sizeof(long_path_a), long_path);

		ret = MsGetShortPathNameA(long_path_a, short_path_a, sizeof(short_path_a));

		StrToUni(short_path, short_path_size, short_path_a);

		return ret;
	}

	if (GetShortPathNameW(long_path, short_path, short_path_size) == 0)
	{
		UniStrCpy(short_path, short_path_size, long_path);
		return false;
	}

	return true;
}

// 指定したプロセスの強制終了
bool MsKillProcess(UINT id)
{
	HANDLE h;
	// 引数チェック
	if (id == 0)
	{
		return false;
	}

	h = OpenProcess(PROCESS_TERMINATE, FALSE, id);
	if (h == NULL)
	{
		return false;
	}

	if (TerminateProcess(h, 0) == FALSE)
	{
		CloseHandle(h);
		return false;
	}

	CloseHandle(h);

	return true;
}

// 現在の EXE ファイル名を取得
void MsGetCurrentProcessExeName(char *name, UINT size)
{
	UINT id;
	LIST *o;
	MS_PROCESS *p;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	id = MsGetCurrentProcessId();
	o = MsGetProcessList();
	p = MsSearchProcessById(o, id);
	if (p != NULL)
	{
		p = MsSearchProcessById(o, id);
		StrCpy(name, size, p->ExeFilename);
	}
	else
	{
		StrCpy(name, size, MsGetExeFileName());
	}
	MsFreeProcessList(o);
}
void MsGetCurrentProcessExeNameW(wchar_t *name, UINT size)
{
	UINT id;
	LIST *o;
	MS_PROCESS *p;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	id = MsGetCurrentProcessId();
	o = MsGetProcessList();
	p = MsSearchProcessById(o, id);
	if (p != NULL)
	{
		p = MsSearchProcessById(o, id);
		UniStrCpy(name, size, p->ExeFilenameW);
	}
	else
	{
		UniStrCpy(name, size, MsGetExeFileNameW());
	}
	MsFreeProcessList(o);
}

// プロセスをプロセス ID から検索する
MS_PROCESS *MsSearchProcessById(LIST *o, UINT id)
{
	MS_PROCESS *p, t;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.ProcessId = id;

	p = Search(o, &t);

	return p;
}

// プロセスリスト比較
int MsCompareProcessList(void *p1, void *p2)
{
	MS_PROCESS *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MS_PROCESS **)p1;
	e2 = *(MS_PROCESS **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->ProcessId > e2->ProcessId)
	{
		return 1;
	}
	else if (e1->ProcessId < e2->ProcessId)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// プロセスリストの表示
void MsPrintProcessList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		UniPrint(L"%-4u: %s\n", p->ProcessId, p->ExeFilenameW);
	}
}

// プロセスリストの解放
void MsFreeProcessList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		Free(p);
	}

	ReleaseList(o);
}

// プロセスリストの取得 (WinNT 用)
LIST *MsGetProcessListNt()
{
	LIST *o;
	UINT max = 16384;
	DWORD *processes;
	UINT needed, num;
	UINT i;

	o = NewListFast(MsCompareProcessList);

	if (ms->nt->EnumProcesses == NULL)
	{
		return o;
	}

	processes = ZeroMalloc(sizeof(DWORD) * max);

	if (ms->nt->EnumProcesses(processes, sizeof(DWORD) * max, &needed) == FALSE)
	{
		Free(processes);
		return NULL;
	}

	num = needed / sizeof(DWORD);

	for (i = 0;i < num;i++)
	{
		UINT id = processes[i];
		HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			false, id);

		if (h != NULL)
		{
			HINSTANCE hInst = NULL;
			DWORD needed;
			if (ms->nt->EnumProcessModules(h, &hInst, sizeof(hInst), &needed))
			{
				MS_PROCESS *p = ZeroMalloc(sizeof(MS_PROCESS));
				ms->nt->GetModuleFileNameExA(h, hInst, p->ExeFilename, sizeof(p->ExeFilename) - 1);
				ms->nt->GetModuleFileNameExW(h, hInst, p->ExeFilenameW, sizeof(p->ExeFilenameW) / sizeof(wchar_t) - 1);
				p->ProcessId = id;
				Add(o, p);
			}
			CloseHandle(h);
		}
	}

	Sort(o);

	Free(processes);

	return o;
}

// プロセスリストの取得 (Win9x 用)
LIST *MsGetProcessList9x()
{
	HANDLE h;
	LIST *o;
	HANDLE (WINAPI *CreateToolhelp32Snapshot)(DWORD, DWORD);
	BOOL (WINAPI *Process32First)(HANDLE, LPPROCESSENTRY32);
	BOOL (WINAPI *Process32Next)(HANDLE, LPPROCESSENTRY32);

	CreateToolhelp32Snapshot =
		(HANDLE (__stdcall *)(DWORD,DWORD))
		GetProcAddress(ms->hKernel32, "CreateToolhelp32Snapshot");
	Process32First =
		(BOOL (__stdcall *)(HANDLE,LPPROCESSENTRY32))
		GetProcAddress(ms->hKernel32, "Process32First");
	Process32Next =
		(BOOL (__stdcall *)(HANDLE,LPPROCESSENTRY32))
		GetProcAddress(ms->hKernel32, "Process32Next");

	o = NewListFast(MsCompareProcessList);

	if (CreateToolhelp32Snapshot != NULL && Process32First != NULL && Process32Next != NULL)
	{
		h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (h != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 e;
			Zero(&e, sizeof(e));
			e.dwSize = sizeof(e);

			if (Process32First(h, &e))
			{
				while (true)
				{
					MS_PROCESS *p = ZeroMalloc(sizeof(MS_PROCESS));
					StrCpy(p->ExeFilename, sizeof(p->ExeFilename), e.szExeFile);
					StrToUni(p->ExeFilenameW, sizeof(p->ExeFilenameW), p->ExeFilename);
					p->ProcessId = e.th32ProcessID;
					Add(o, p);
					if (Process32Next(h, &e) == false)
					{
						break;
					}
				}
			}
			CloseHandle(h);
		}
	}

	Sort(o);

	return o;
}

// プロセスリストの取得
LIST *MsGetProcessList()
{
	if (MsIsNt() == false)
	{
		// Windows 9x
		return MsGetProcessList9x();
	}
	else
	{
		// Windows NT, 2000, XP
		return MsGetProcessListNt();
	}
}

// 現在のスレッドを 1 つの CPU で動作するように強制する
void MsSetThreadSingleCpu()
{
	SetThreadAffinityMask(GetCurrentThread(), 1);
}

// サウンドの再生
void MsPlaySound(char *name)
{
	char tmp[MAX_SIZE];
	char wav[MAX_SIZE];
	char *temp;
	BUF *b;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "|%s", name);

	b = ReadDump(tmp);
	if (b == NULL)
	{
		return;
	}

	temp = MsGetMyTempDir();
	Format(wav, sizeof(tmp), "%s\\%s", temp, name);
	DumpBuf(b, wav);

	PlaySound(wav, NULL, SND_ASYNC | SND_FILENAME | SND_NODEFAULT);

	FreeBuf(b);
}

// タスクトレイにアイコンを表示する
void MsShowIconOnTray(HWND hWnd, HICON icon, wchar_t *tooltip, UINT msg)
{
	// 引数チェック
	if (hWnd == NULL || icon == NULL)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		Zero(&nid, sizeof(nid));
		nid.cbSize = sizeof(nid);
		nid.hWnd = hWnd;
		nid.uID = 1;
		nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
		nid.uCallbackMessage = msg;
		nid.hIcon = icon;
		UniToStr(nid.szTip, sizeof(nid.szTip), tooltip);
		Shell_NotifyIcon(NIM_ADD, &nid);
	}
	else
	{
		Zero(&nid_nt, sizeof(nid_nt));
		nid_nt.cbSize = sizeof(nid_nt);
		nid_nt.hWnd = hWnd;
		nid_nt.uID = 1;
		nid_nt.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
		nid_nt.uCallbackMessage = msg;
		nid_nt.hIcon = icon;
		UniStrCpy(nid_nt.szTip, sizeof(nid_nt.szTip), tooltip);
		Shell_NotifyIconW(NIM_ADD, &nid_nt);
	}

	tray_inited = true;
}

// タスクトレイが初期化されているかどうか確認する
bool MsIsTrayInited()
{
	return tray_inited;
}

// タスクトレイのアイコンを復元する
void MsRestoreIconOnTray()
{
	if (tray_inited == false)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		Shell_NotifyIcon(NIM_ADD, &nid);
	}
	else
	{
		Shell_NotifyIconW(NIM_ADD, &nid_nt);
	}
}

// タスクトレイのアイコンを変更する (いけー)
void MsChangeIconOnTrayEx2(void *icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags)
{
	MsChangeIconOnTrayEx((HICON)icon, tooltip, info_title, info, info_flags);
}

// タスクトレイのアイコンを変更する
void MsChangeIconOnTray(HICON icon, wchar_t *tooltip)
{
	MsChangeIconOnTrayEx(icon, tooltip, NULL, NULL, NIIF_NONE);
}
void MsChangeIconOnTrayEx(HICON icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags)
{
	bool changed = false;

	if (tray_inited == false)
	{
		return;
	}

	if (icon != NULL)
	{
		if (MsIsNt() == false)
		{
			if (nid.hIcon != icon)
			{
				changed = true;
				nid.hIcon = icon;
			}
		}
		else
		{
			if (nid_nt.hIcon != icon)
			{
				changed = true;
				nid_nt.hIcon = icon;
			}
		}
	}

	if (tooltip != NULL)
	{
		if (MsIsNt() == false)
		{
			char tmp[MAX_SIZE];

			UniToStr(tmp, sizeof(tmp), tooltip);

			if (StrCmp(nid.szTip, tmp) != 0)
			{
				StrCpy(nid.szTip, sizeof(nid.szTip), tmp);
				changed = true;
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniStrCpy(tmp, sizeof(tmp), tooltip);

			if (UniStrCmp(nid_nt.szTip, tmp) != 0)
			{
				UniStrCpy(nid_nt.szTip, sizeof(nid_nt.szTip), tmp);
				changed = true;
			}
		}
	}

	if (info_title != NULL && info != NULL)
	{
		if (MsIsNt() == false)
		{
			char tmp1[MAX_SIZE];
			char tmp2[MAX_PATH];

			UniToStr(tmp1, sizeof(tmp1), info_title);
			UniToStr(tmp2, sizeof(tmp2), info);

			if (StrCmp(nid.szInfo, tmp1) != 0 ||
				StrCmp(nid.szInfoTitle, tmp2) != 0)
			{
				StrCpy(nid.szInfo, sizeof(nid.szInfo), tmp1);
				StrCpy(nid.szInfoTitle, sizeof(nid.szInfoTitle), tmp2);
				nid.dwInfoFlags = info_flags;

				changed = true;
			}
		}
		else
		{
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_PATH];

			UniStrCpy(tmp1, sizeof(tmp1), info_title);
			UniStrCpy(tmp2, sizeof(tmp2), info);

			if (UniStrCmp(nid_nt.szInfo, tmp1) != 0 ||
				UniStrCmp(nid_nt.szInfoTitle, tmp2) != 0)
			{
				UniStrCpy(nid_nt.szInfo, sizeof(nid_nt.szInfo), tmp1);
				UniStrCpy(nid_nt.szInfoTitle, sizeof(nid_nt.szInfoTitle), tmp2);
				nid_nt.dwInfoFlags = info_flags;

				changed = true;
			}
		}
	}

	if (changed)
	{
		if (MsIsNt() == false)
		{
			Shell_NotifyIcon(NIM_MODIFY, &nid);
		}
		else
		{
			Shell_NotifyIconW(NIM_MODIFY, &nid_nt);
		}
	}
}

// タスクトレイのアイコンを削除する
void MsHideIconOnTray()
{
	if (MsIsNt() == false)
	{
		Shell_NotifyIcon(NIM_DELETE, &nid);
	}
	else
	{
		Shell_NotifyIconW(NIM_DELETE, &nid_nt);
	}

	tray_inited = false;
}

// メニュー項目の挿入
bool MsInsertMenu(HMENU hMenu, UINT pos, UINT flags, UINT_PTR id_new_item, wchar_t *lp_new_item)
{
	bool ret;

	if (MsIsNt())
	{
		ret = InsertMenuW(hMenu, pos, flags, id_new_item, lp_new_item);
	}
	else
	{
		char *s = CopyUniToStr(lp_new_item);
		ret = InsertMenuA(hMenu, pos, flags, id_new_item, s);
		Free(s);
	}

	return ret;
}

// メニュー項目の追加
bool MsAppendMenu(HMENU hMenu, UINT flags, UINT_PTR id, wchar_t *str)
{
	bool ret;

	if (MsIsNt())
	{
		ret = AppendMenuW(hMenu, flags, id, str);
	}
	else
	{
		char *s = CopyUniToStr(str);
		ret = AppendMenuA(hMenu, flags, id, s);
		Free(s);
	}

	return ret;
}

// メニュー表示
void MsUserModeTrayMenu(HWND hWnd)
{
	HMENU h;
	POINT p;
	wchar_t tmp[MAX_SIZE];
	wchar_t caption[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	// メニューを作成する
	h = CreatePopupMenu();
	MsAppendMenu(h, MF_ENABLED | MF_STRING, 10001, _UU("SVC_USERMODE_MENU_1"));
	MsAppendMenu(h, MF_SEPARATOR, 10002, NULL);

	if (MsIsNt())
	{
		GetWindowTextW(hWnd, caption, sizeof(caption));
	}
	else
	{
		char tmp[MAX_SIZE];
		GetWindowTextA(hWnd, tmp, sizeof(tmp));
		StrToUni(caption, sizeof(caption), tmp);
	}

	UniFormat(tmp, sizeof(tmp), _UU("SVC_USERMODE_MENU_2"), caption);
	MsAppendMenu(h, MF_ENABLED | MF_STRING, 10003, tmp);

	// メニューを表示する
	GetCursorPos(&p);

	SetForegroundWindow(hWnd);
	TrackPopupMenu(h, TPM_LEFTALIGN, p.x, p.y, 0, hWnd, NULL);
	PostMessage(hWnd, WM_NULL, 0, 0);

	DestroyMenu(h);
}

// ユーザーモード用ウインドウプロシージャ
LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	wchar_t tmp[MAX_SIZE];
	char title[MAX_SIZE];
	wchar_t title_w[MAX_SIZE];
	char value_name[MAX_SIZE];
	static UINT taskbar_msg = 0;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	if (msg == taskbar_msg && taskbar_msg != 0)
	{
		// タスクバーが再生成された
		if (MsRegReadInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, value_name) == 0 &&
			service_for_9x_mode == false)
		{
			MsRestoreIconOnTray();
		}
	}

	switch (msg)
	{
	case WM_ENDSESSION:
		// 再開
		if (wParam == false)
		{
			break;
		}
	case WM_CREATE:
		// 開始
		exiting = false;
		g_start();
		GetWindowText(hWnd, title, sizeof(title));
		StrToUni(title_w, sizeof(title_w), title);
		UniFormat(tmp, sizeof(tmp), _UU("SVC_TRAY_TOOLTIP"), title);

		if (taskbar_msg == 0)
		{
			taskbar_msg = RegisterWindowMessage("TaskbarCreated");
		}

		Format(value_name, sizeof(value_name), SVC_HIDETRAY_REG_VALUE, title_w);
		if (MsRegReadInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, value_name) == 0 &&
			service_for_9x_mode == false)
		{
			MsShowIconOnTray(hWnd, tray_icon, tmp, WM_APP + 33);
		}

		break;
	case WM_APP + 33:
		if (wParam == 1)
		{
			// タスクトレイのアイコンに対する操作
			switch (lParam)
			{
			case WM_RBUTTONDOWN:
				// 右クリック
				MsUserModeTrayMenu(hWnd);
				break;
			case WM_LBUTTONDBLCLK:
				// 左ダブルクリック
				break;
			}
		}
		break;
	case WM_LBUTTONDOWN:
		MsUserModeTrayMenu(hWnd);
		break;
	case WM_QUERYENDSESSION:
		if (exiting == false)
		{
			exiting = true;
			MsHideIconOnTray();
			g_stop();
			DestroyWindow(hWnd);
		}
		return TRUE;
	case WM_CLOSE:
		// 停止
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			MsHideIconOnTray();
			DestroyWindow(hWnd);
		}
		break;
	case WM_DESTROY:
		wnd_end = true;
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case 10001:
			GetWindowText(hWnd, title, sizeof(title));
			StrToUni(title_w, sizeof(title_w), title);
			// 確認メッセージの表示
			if (MsgBoxEx(hWnd, MB_ICONINFORMATION | MB_OKCANCEL | MB_DEFBUTTON2 |
				MB_SYSTEMMODAL, _UU("SVC_HIDE_TRAY_MSG"), title, title) == IDOK)
			{
				char tmp[MAX_SIZE];
				Format(tmp, sizeof(tmp), SVC_HIDETRAY_REG_VALUE, title_w);
				// レジストリに書き込む
				MsRegWriteInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, tmp, 1);
				// アイコンを消す
				MsHideIconOnTray();
			}
			break;
		case 10003:
			SendMessage(hWnd, WM_CLOSE, 0, 0);
			break;
		}
		break;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

// PenCore.dll の名前の取得
char *MsGetPenCoreDllFileName()
{
	return PENCORE_DLL_NAME;
}

// これがユーザーモードかどうか取得
bool MsIsUserMode()
{
	return is_usermode;
}

// サービス側からユーザーモードの終了を指示
void MsStopUserModeFromService()
{
	if (hWndUsermode != NULL)
	{
		PostMessage(hWndUsermode, WM_CLOSE, 0, 0);
	}
}

// テストのみ実行 (デバッグ用)
void MsTestOnly()
{
	g_start();
	GetLine(NULL, 0);
	g_stop();

	_exit(0);
}

// ユーザーモードとして起動
void MsUserMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon)
{
	wchar_t *title_w = CopyStrToUni(title);

	MsUserModeW(title_w, start, stop, icon);

	Free(title_w);
}
void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon)
{
	WNDCLASS wc;
	HINSTANCE hDll;
	HWND hWnd;
	MSG msg;
	INSTANCE *inst;
	char title_a[MAX_PATH];
	// 引数チェック
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	UniToStr(title_a, sizeof(title_a), title);

	is_usermode = true;
	g_start = start;
	g_stop = stop;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		if (service_for_9x_mode == false)
		{
			// Win9x サービスモードの場合はエラーを表示しない
			MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_USERMODE_MUTEX"), ms->ExeFileNameW);
		}
		return;
	}

	if (Is64())
	{
		hDll = MsLoadLibraryAsDataFile(MsGetPenCoreDllFileName());
	}
	else
	{
		hDll = MsLoadLibrary(MsGetPenCoreDllFileName());
	}

	// アイコン読み込み
	tray_icon = LoadImage(hDll, MAKEINTRESOURCE(icon), IMAGE_ICON, 16, 16,
		(MsIsNt() ? LR_SHARED : 0) | LR_VGACOLOR);

	// メインウインドウの作成
	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL,IDC_ARROW);
	wc.hIcon = LoadIcon(hDll, MAKEINTRESOURCE(icon));
	wc.hInstance = ms->hInst;
	wc.lpfnWndProc = MsUserModeWindowProc;
	wc.lpszClassName = title_a;
	if (RegisterClass(&wc) == 0)
	{
		return;
	}

	hWnd = CreateWindow(title_a, title_a, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, ms->hInst, NULL);

	if (hWnd == NULL)
	{
		return;
	}

	hWndUsermode = hWnd;

	wnd_end = false;
	// ウインドウループ
	while (wnd_end == false)
	{
		GetMessage(&msg, NULL, 0, 0);
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	FreeSingleInstance(inst);

	hWndUsermode = NULL;

	// 強制終了して良い
	_exit(0);
}

// サービス停止処理メインスレッド
void MsServiceStoperMainThread(THREAD *t, void *p)
{
	// 停止処理
	g_stop();
}

// サービス停止処理用スレッド
void MsServiceStoperThread(THREAD *t, void *p)
{
	THREAD *thread;
	UINT64 selfkill_timeout = Tick64() + SVC_SELFKILL_TIMEOUT;

	thread = NewThread(MsServiceStoperMainThread, NULL);

	// まだ開始中の場合は開始スレッドの終了を待つ
	while (WaitThread(starter_thread, 250) == false)
	{
		if (Tick64() >= selfkill_timeout)
		{
			// フリーズ時用の自殺
			_exit(0);
		}
		// 開始処理が完了するまでの間、一定時間ごとに SetServiceStatus を呼び出す
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint++;
		status.dwCurrentState = SERVICE_STOP_PENDING;
		ms->nt->SetServiceStatus(ssh, &status);
	}

	ReleaseThread(starter_thread);
	starter_thread = NULL;

	while (WaitThread(thread, 250) == false)
	{
		if (Tick64() >= selfkill_timeout)
		{
			// フリーズ時用の自殺
			_exit(0);
		}
		// 停止処理が完了するまでの間、一定時間ごとに SetServiceStatus を呼び出す
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint++;
		status.dwCurrentState = SERVICE_STOP_PENDING;
		ms->nt->SetServiceStatus(ssh, &status);
	}

	ReleaseThread(thread);

	// 停止が完了したことを報告する
	status.dwWin32ExitCode = 0;
	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_STOPPED;
	ms->nt->SetServiceStatus(ssh, &status);

	Set(server_stopped_event);
}

// サービスハンドラ
void CALLBACK MsServiceHandler(DWORD opcode)
{
	switch (opcode)
	{
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		// 停止要求
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint = 0;
		status.dwCurrentState = SERVICE_STOP_PENDING;

		// 停止用スレッドを立てる
		service_stopper_thread = NewThread(MsServiceStoperThread, NULL);
		break;
	}

	ms->nt->SetServiceStatus(ssh, &status);
}

// サービス開始用スレッド
void MsServiceStarterMainThread(THREAD *t, void *p)
{
	// 開始
	g_start();
}

// サービスのディスパッチ関数
void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv)
{
	// サービスの準備
	Zero(&status, sizeof(status));
	status.dwServiceType = SERVICE_WIN32;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	ssh = ms->nt->RegisterServiceCtrlHandler(g_service_name, MsServiceHandler);

	if (ssh == NULL)
	{
		Alert("RegisterServiceCtrlHandler() Failed.", "MsServiceDispatcher()");
		return;
	}

	status.dwWaitHint = 10000;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_START_PENDING;
	ms->nt->SetServiceStatus(ssh, &status);

	// サービス開始用スレッドを作成する
	starter_thread = NewThread(MsServiceStarterMainThread, NULL);

	// 開始完了を報告する
	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_RUNNING;
	ms->nt->SetServiceStatus(ssh, &status);
}

// サービスとして動作
void MsServiceMode(SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	SERVICE_TABLE_ENTRY dispatch_table[] =
	{
		{"", MsServiceDispatcher},
		{NULL, NULL},
	};
	INSTANCE *inst;
	// 引数チェック
	if (start == NULL || stop == NULL)
	{
		return;
	}

	MsSetErrorModeToSilent();

	g_start = start;
	g_stop = stop;

	server_stopped_event = NewEvent();

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		MsgBoxEx(NULL, MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION,
			_UU("SVC_SERVICE_MUTEX"), g_service_name, ms->ExeFileNameW);
		return;
	}

	// サービス設定を更新する
	MsUpdateServiceConfig(g_service_name);

	if (ms->nt->StartServiceCtrlDispatcher(dispatch_table) == false)
	{
		Alert("StartServiceCtrlDispatcher() Failed.", "MsServiceMode()");
		return;
	}

	MsUpdateServiceConfig(g_service_name);

	FreeSingleInstance(inst);

	// サービス終了後は直ちにプロセスを終了する
	Wait(server_stopped_event, INFINITE);
	ReleaseEvent(server_stopped_event);
	WaitThread(service_stopper_thread, INFINITE);
	ReleaseThread(service_stopper_thread);
	server_stopped_event = NULL;

	_exit(0);
}

// テストモードとして起動
void MsTestMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	wchar_t *title_w = CopyStrToUni(title);

	MsTestModeW(title_w, start, stop);
	Free(title_w);
}
void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	INSTANCE *inst;
	// 引数チェック
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	is_usermode = true;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		// すでに起動している
		MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_TEST_MUTEX"), ms->ExeFileNameW);
		return;
	}

	// 起動
	start();

	// メッセージ表示
	MsgBoxEx(NULL, MB_ICONINFORMATION | MB_SYSTEMMODAL, _UU("SVC_TEST_MSG"), title);

	// 停止
	stop();

	FreeSingleInstance(inst);
}

// サービスマネージャを呼び出し中のプロセスのプロセス ID を書き込む
void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	if (pid != 0)
	{
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
		MsRegWriteInt(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
	}
	else
	{
		MsRegDeleteValue(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKey(REG_LOCAL_MACHINE, tmp);

		MsRegDeleteValue(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKey(REG_CURRENT_USER, tmp);
	}
}

// サービスマネージャを呼び出し中のプロセス ID を取得する
UINT MsReadCallingServiceManagerProcessId(char *svcname, bool current_user)
{
	char tmp[MAX_PATH];
	// 引数チェック
	if (svcname == NULL)
	{
		return 0;
	}

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	return MsRegReadInt(current_user ? REG_CURRENT_USER : REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
}

// サービスメイン関数
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon)
{
	UINT mode;
	UINT ret = 0;
	char *arg;
	wchar_t *arg_w;
	TOKEN_LIST *t = NULL;
	UNI_TOKEN_LIST *ut = NULL;
	char *service_name;
	wchar_t *service_title;
	wchar_t *service_description;
	wchar_t *service_title_uni;
	char tmp[MAX_SIZE];
	bool restoreReg = false;
	bool silent = false;
	// 引数チェック
	if (name == NULL || start == NULL || stop == NULL)
	{
		return ret;
	}

	// Mayaqua の開始
	InitMayaqua(false, false, 0, NULL);

	// MS-IME の停止
	MsDisableIme();

	// サービスに関する情報を string table から取得
	Format(tmp, sizeof(tmp), SVC_NAME, name);
	service_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	service_title = _UU(tmp);
	service_title_uni = _UU(tmp);
	Format(tmp, sizeof(tmp), SVC_DESCRIPT, name);
	service_description = _UU(tmp);

	if (StrLen(service_name) == 0 || UniStrLen(service_title) == 0)
	{
		// サービス情報が見つからない
		MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_NOT_FOUND"), name);
	}
	else
	{
		wchar_t path[MAX_SIZE];
		// 引数のチェック
		mode = SVC_MODE_NONE;

		t = GetCommandLineToken();
		arg = NULL;

		ut = GetCommandLineUniToken();
		arg_w = NULL;

		if (t->NumTokens >= 1)
		{
			arg = t->Token[0];
		}
		if(t->NumTokens >= 2)
		{
			if(StrCmpi(t->Token[1], SVC_ARG_SILENT) == 0)
			{
				silent = true;
			}
		}

		if (ut->NumTokens >= 1)
		{
			arg_w = ut->Token[0];
		}

		if (arg != NULL)
		{
			if (StrCmpi(arg, SVC_ARG_INSTALL) == 0)
			{
				mode = SVC_MODE_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_UNINSTALL) == 0)
			{
				mode = SVC_MODE_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_START) == 0)
			{
				mode = SVC_MODE_START;
			}
			if (StrCmpi(arg, SVC_ARG_STOP) == 0)
			{
				mode = SVC_MODE_STOP;
			}
			if (StrCmpi(arg, SVC_ARG_TEST) == 0)
			{
				mode = SVC_MODE_TEST;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE) == 0)
			{
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_INSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_UNINSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_WIN9X_SERVICE) == 0)
			{
				mode = SVC_MODE_WIN9X_SERVICE;
			}
			if (StrCmpi(arg, SVC_ARG_WIN9X_INSTALL) == 0)
			{
				mode = SVC_MODE_WIN9X_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_WIN9X_UNINSTALL) == 0)
			{
				mode = SVC_MODE_WIN9X_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_TCP) == 0)
			{
				mode = SVC_MODE_TCP;
			}
			if (StrCmpi(arg, SVC_ARG_TCP_SETUP) == 0)
			{
				mode = SVC_MODE_TCPSETUP;
			}
			if (StrCmpi(arg, SVC_ARG_TRAFFIC) == 0)
			{
				mode = SVC_MODE_TRAFFIC;
			}
			if (StrCmpi(arg, SVC_ARG_UIHELP) == 0)
			{
				mode = SVC_MODE_UIHELP;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE_SHOWTRAY) == 0)
			{
				char tmp[MAX_SIZE];
				mode = SVC_MODE_USERMODE;
				Format(tmp, sizeof(tmp), SVC_HIDETRAY_REG_VALUE, service_title);
				MsRegDeleteValue(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, tmp);
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE_HIDETRAY) == 0)
			{
				char tmp[MAX_SIZE];
				mode = SVC_MODE_USERMODE;
				Format(tmp, sizeof(tmp), SVC_HIDETRAY_REG_VALUE, service_title);
				MsRegWriteInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, tmp, 1);
			}
			if (StrCmpi(arg, SVC_ARG_SERVICE) == 0)
			{
				mode = SVC_MODE_SERVICE;
			}

			if (mode != SVC_MODE_NONE)
			{
				// Network Config
				MsInitGlobalNetworkConfig();
			}
		}

		// サービスとして実行する際のコマンドライン名を取得する
		UniFormat(path, sizeof(path), SVC_RUN_COMMANDLINE, ms->ExeFileNameW);

		if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
			mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
			(ms->IsNt == false))
		{
			// Windows NT 以外で NT 系のコマンドを使用しようとした
			MsgBox(NULL, MB_ICONSTOP, _UU("SVC_NT_ONLY"));
		}
		else if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
			mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
			(ms->IsAdmin == false))
		{
			// Administrators 権限が無い
			MsgBox(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_ADMIN"));
		}
		else
		{
			// モードごとに処理を行う
			switch (mode)
			{
			case SVC_MODE_NONE:
				// 案内メッセージを表示して終了する
				if (arg_w != NULL && UniEndWith(arg_w, L".uvpn"))
				{
					if (MsgBox(NULL, MB_ICONQUESTION | MB_YESNO, _UU("CM_VPN_FILE_CLICKED")) == IDYES)
					{
						wchar_t vpncmgr[MAX_PATH];
						wchar_t filename[MAX_PATH];

						UniFormat(filename, sizeof(filename), L"\"%s\"", arg_w);

						if (Is64() == false)
						{
							UniFormat(vpncmgr, sizeof(vpncmgr), L"%s\\utvpncmgr.exe", MsGetExeDirNameW());
						}
						else
						{
							UniFormat(vpncmgr, sizeof(vpncmgr), L"%s\\utvpncmgr_x64.exe", MsGetExeDirNameW());
						}

						RunW(vpncmgr, filename, false, false);
					}
				}
				else
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_HELP"),
						service_title, service_name, service_title, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_title);
				}
				break;

			case SVC_MODE_SETUP_INSTALL:
				// setup.exe インストール モード
				// 古いものをアンインストールする
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					MsUninstallService(service_name);
				}
				if (MsInstallServiceW(service_name, service_title, service_description, path) == false)
				{
					ret = 1;
				}
				MsStartService(service_name);
				MsWriteCallingServiceManagerProcessId(service_name, 0);
				break;

			case SVC_MODE_SETUP_UNINSTALL:
				// setup.exe アンインストール モード
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					if (MsUninstallService(service_name) == false)
					{
						ret = 1;
					}
				}
				break;

			case SVC_MODE_INSTALL:
				// サービスのインストール
				// すでにインストールされているかどうか確認する
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					// すでにインストールされている
					// アンインストールするかどうか確認のメッセージを表示する
					if (silent == false)
					{
						if (MsgBoxEx(NULL, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SVC_ALREADY_INSTALLED"),
							service_title, service_name) == IDNO)
						{
							// 処理をキャンセルする
							break;
						}
					}
					// 既存のサービスが動作しているか?
					if (MsIsServiceRunning(service_name))
					{
						// 停止を試みる
						if (MsStopService(service_name) == false)
						{
							// 停止に失敗した
							MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_STOP_FAILED"),
								service_title, service_name);
							break;
						}
					}
					// アンインストールする
					if (MsUninstallService(service_name) == false)
					{
						// アンインストールに失敗した
						MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_UNINSTALL_FAILED"),
							service_title, service_name);
						break;
					}
				}

				// インストールを行う
				if (MsInstallServiceW(service_name, service_title, service_description, path) == false)
				{
					// インストールに失敗した
					MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_INSTALL_FAILED"),
						service_title, service_name);
					break;
				}

				// サービスを開始する
				if (MsStartService(service_name) == false)
				{
					// 開始に失敗した
					MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_INSTALL_FAILED_2"),
						service_title, service_name, path);
					break;
				}

				// すべて成功した
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_INSTALL_OK"),
						service_title, service_name, path);
				}
				break;

			case SVC_MODE_UNINSTALL:
				// サービスのアンインストール
				// すでにインストールされているかどうか確認する
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_INSTALLED"),
							service_title, service_name, path);
					}
					break;
				}

				// サービスが起動中の場合は停止する
				if (MsIsServiceRunning(service_name))
				{
					// サービスを停止する
					if (MsStopService(service_name) == false)
					{
						// 停止に失敗した
						MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_STOP_FAILED"),
							service_title, service_name);
						break;
					}
				}

				// サービスをアンインストールする
				if (MsUninstallService(service_name) == false)
				{
					MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_UNINSTALL_FAILED"),
						service_title, service_name);
					break;
				}

				// すべて成功した
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_UNINSTALL_OK"),
						service_title, service_name);
				}
				break;

			case SVC_MODE_START:
				// サービスの開始
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					// サービスはインストールされていない
					MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_INSTALLED"),
						service_title, service_name);
					break;
				}

				// サービスが起動中かどうか確認する
				if (MsIsServiceRunning(service_name))
				{
					// サービスが起動中
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVR_ALREADY_START"),
							service_title, service_name);
					}
					break;
				}

				// サービスを起動する
				if (MsStartService(service_name) == false)
				{
					// 開始に失敗した
					MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_START_FAILED"),
						service_title, service_name);
					break;
				}

				// すべて成功した
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_START_OK"),
						service_title, service_name);
				}
				break;

			case SVC_MODE_STOP:
				// サービスの停止
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					// サービスはインストールされていない
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_INSTALLED"),
							service_title, service_name);
					}
					break;
				}

				// サービスが起動中かどうか確認する
				if (MsIsServiceRunning(service_name) == false)
				{
					// サービスが停止中
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_ALREADY_STOP"),
							service_title, service_name);
					}
					break;
				}
				// サービスを停止する
				if (MsStopService(service_name) == false)
				{
					// 停止に失敗した
					MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_STOP_FAILED"),
						service_title, service_name);
					break;
				}

				// すべて成功した
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_STOP_OK"),
						service_title, service_name);
				}
				break;

			case SVC_MODE_TEST:
				// テストモード
				MsTestModeW(service_title, start, stop);
				break;

			case SVC_MODE_WIN9X_SERVICE:
				// Win9x サービスモード
				// (タスクトレイのアイコンを無条件で非表示にする)
				if (MsIsNt())
				{
					// Windows 2000 以降では動作させない
					break;
				}
				service_for_9x_mode = true;
			case SVC_MODE_USERMODE:
				// ユーザーモード
				MsUserModeW(service_title, start, stop, icon);
				break;

			case SVC_MODE_WIN9X_INSTALL:
				// Win9x インストールモード
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsNt() == false)
				{
					// レジストリキーの追加
					char cmdline[MAX_PATH];
					Format(cmdline, sizeof(cmdline), "\"%s\" %s",
						MsGetExeFileName(), SVC_ARG_WIN9X_SERVICE);
					MsRegWriteStr(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_1,
						name, cmdline);
					MsRegWriteStr(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_2,
						name, cmdline);

					// 実行
					Run(MsGetExeFileName(), SVC_ARG_WIN9X_SERVICE, false, false);
				}
				break;

			case SVC_MODE_WIN9X_UNINSTALL:
				// Win9x アンインストールモード
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsNt() == false)
				{
					// レジストリキーの削除
					MsRegDeleteValue(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_1,
						name);
					MsRegDeleteValue(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_2,
						name);

					// 自分以外のすべてのプロセスを終了
					MsKillOtherInstance();
				}
				break;

			case SVC_MODE_SERVICE:
				// サービスとして動作
				StrCpy(g_service_name, sizeof(g_service_name), service_name);
				MsServiceMode(start, stop);
				break;

			case SVC_MODE_TCP:
				// TCP ユーティリティ
				InitCedar();
				InitWinUi(service_title_uni, NULL, 0);
				ShowTcpIpConfigUtil(NULL, true);
				FreeWinUi();
				FreeCedar();
				break;

			case SVC_MODE_TCPSETUP:
				// TCP 最適化モード (インストーラから呼ばれる)
				InitCedar();
				InitWinUi(service_title_uni, NULL, 0);
				ShowTcpIpConfigUtil(NULL, false);
				FreeWinUi();
				FreeCedar();
				break;

			case SVC_MODE_TRAFFIC:
				// 通信スループット測定ツール
				InitCedar();
				InitWinUi(service_title_uni, NULL, 0);
				CmTraffic(NULL);
				FreeWinUi();
				FreeCedar();
				break;

			case SVC_MODE_UIHELP:
				// UI Helper の起動
				CnStart();
				break;
			}

		}
		FreeToken(t);
		UniFreeToken(ut);

		if (restoreReg)
		{
			MsWriteCallingServiceManagerProcessId(service_name, 0);
		}
	}

	FreeMayaqua();

	return 0;
}

// 指定したセッションのユーザー名を取得する
wchar_t *MsGetSessionUserName(UINT session_id)
{
	if (MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled())
	{
		wchar_t *ret;
		wchar_t *name;
		UINT size = 0;
		if (ms->nt->WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id,
			WTSUserName, (wchar_t *)&name, &size) == false)
		{
			return NULL;
		}

		if (name == NULL || UniStrLen(name) == 0)
		{
			ret = NULL;
		}
		else
		{
			ret = UniCopyStr(name);
		}

		ms->nt->WTSFreeMemory(name);

		return ret;
	}
	return NULL;
}

// 現在のデスクトップが VNC で利用可能かどうか取得する
bool MsIsCurrentDesktopAvailableForVnc()
{
	if (MsIsNt() == false)
	{
		return true;
	}

	if (MsIsCurrentTerminalSessionActive() == false)
	{
		return false;
	}

	if (ms->nt->OpenDesktopA == NULL ||
		ms->nt->CloseDesktop == NULL ||
		ms->nt->SwitchDesktop == NULL)
	{
		return true;
	}
	else
	{
		HDESK hDesk = ms->nt->OpenDesktopA("default", 0, false, DESKTOP_SWITCHDESKTOP);
		bool ret;

		if (hDesk == NULL)
		{
			return false;
		}

		ret = ms->nt->SwitchDesktop(hDesk);
		ms->nt->CloseDesktop(hDesk);

		return ret;
	}
}

// 現在のターミナルセッションがアクティブかどうか取得する
bool MsIsCurrentTerminalSessionActive()
{
	return MsIsTerminalSessionActive(MsGetCurrentTerminalSessionId());
}

// 指定したターミナルセッションがアクティブかどうか取得する
bool MsIsTerminalSessionActive(UINT session_id)
{
	if (MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled())
	{
		UINT *status = NULL;
		UINT size = sizeof(status);
		bool active = true;

		if (ms->nt->WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id,
			WTSConnectState, (wchar_t *)&status, &size) == false)
		{
			return true;
		}

		switch (*status)
		{
		case WTSDisconnected:
		case WTSShadow:
		case WTSIdle:
		case WTSDown:
		case WTSReset:
			active = false;
			break;
		}

		ms->nt->WTSFreeMemory(status);

		return active;
	}

	return true;
}

// 現在のターミナルセッション ID を取得する
UINT MsGetCurrentTerminalSessionId()
{
	if (MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled())
	{
		UINT ret;
		UINT *session_id = NULL;
		UINT size = sizeof(session_id);
		if (ms->nt->WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
			WTSSessionId, (wchar_t *)&session_id, &size) == false)
		{
			return 0;
		}

		ret = *session_id;

		ms->nt->WTSFreeMemory(session_id);

		return ret;
	}

	return 0;
}

// ターミナルサービスがインストールされていて複数セッションがログイン可能かどうか調べる
bool MsIsTerminalServiceMultiUserInstalled()
{
	OS_INFO *info = GetOsInfo();
	OSVERSIONINFOEX i;
	if (MsIsTerminalServiceInstalled() == false)
	{
		return false;
	}

	if (OS_IS_SERVER(info->OsType) == false)
	{
		return false;
	}

	Zero(&i, sizeof(i));
	i.dwOSVersionInfoSize = sizeof(i);
	if (GetVersionEx((OSVERSIONINFO *)&i) == false)
	{
		return false;
	}

	if (i.wSuiteMask & VER_SUITE_SINGLEUSERTS)
	{
		return false;
	}

	return true;
}

// ユーザー切り替えがインストールされているかどうか調べる
bool MsIsUserSwitchingInstalled()
{
	OS_INFO *info = GetOsInfo();
	OSVERSIONINFOEX i;

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (ms->nt->WTSDisconnectSession == NULL ||
		ms->nt->WTSFreeMemory == NULL ||
		ms->nt->WTSQuerySessionInformation == NULL)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) < 2)
	{
		return false;
	}

	Zero(&i, sizeof(i));
	i.dwOSVersionInfoSize = sizeof(i);
	if (GetVersionEx((OSVERSIONINFO *)&i) == false)
	{
		return false;
	}

	if (i.wSuiteMask & VER_SUITE_SINGLEUSERTS)
	{
		return true;
	}

	return false;
}

// リモートデスクトップを有効にする
bool MsEnableRemoteDesktop()
{
	OS_INFO *info = GetOsInfo();

	if (MsIsRemoteDesktopAvailable() == false)
	{
		return false;
	}

	if (MsIsRemoteDesktopEnabled())
	{
		return true;
	}

	if (GET_KETA(info->OsType, 100) == 2)
	{
		// Windows 2000
		return false;
	}

	if (MsRegWriteInt(REG_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
		"fDenyTSConnections", 0) == false)
	{
		return false;
	}

	if (MsIsVista())
	{
		if (MsRegWriteInt(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
			"UserAuthentication", 0) == false)
		{
			return false;
		}
	}

	return true;
}

// リモートデスクトップが有効かどうか調べる
bool MsIsRemoteDesktopEnabled()
{
	OS_INFO *info = GetOsInfo();

	if (MsIsRemoteDesktopAvailable() == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) == 2)
	{
		// Windows 2000
		return MsIsServiceRunning("TermService");
	}
	else
	{
		// Windows XP 以降
		bool b = MsRegReadInt(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
			"fDenyTSConnections");

		if (MsIsVista() == false)
		{
			return b ? false : true;
		}
		else
		{
			if (b)
			{
				return false;
			}
			else
			{
				if (MsRegReadInt(REG_LOCAL_MACHINE,
					"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
					"UserAuthentication"))
				{
					return false;
				}
				else
				{
					return true;
				}
			}
		}
	}
}

// レジストリ操作によってリモートデスクトップが利用可能になるかどうか調べる
bool MsIsRemoteDesktopCanEnableByRegistory()
{
	OS_INFO *info = GetOsInfo();
	if (MsIsRemoteDesktopAvailable() == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) == 2)
	{
		// Windows 2000
		return false;
	}
	else
	{
		// それ以外
		return true;
	}
}

// Windows 2000 かどうか調べる
bool MsIsWin2000()
{
	OS_INFO *info = GetOsInfo();

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) == 2)
	{
		return true;
	}

	return false;
}

// Windows 2000 以降かどうか調べる
bool MsIsWin2000OrGreater()
{
	OS_INFO *info = GetOsInfo();

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) >= 2)
	{
		return true;
	}

	return false;
}

// リモートデスクトップが利用可能かどうか調べる
bool MsIsRemoteDesktopAvailable()
{
	OS_INFO *info = GetOsInfo();
	if (MsIsTerminalServiceInstalled() == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) == 2)
	{
		// Windows 2000
		if (info->OsType == 2200)
		{
			// Windows 2000 Professional
			return false;
		}
		else
		{
			// Windows 2000 サーバー系
			return true;
		}
	}
	else if (GET_KETA(info->OsType, 100) == 3)
	{
		// Windows XP
		if (info->OsType == OSTYPE_WINDOWS_XP_HOME)
		{
			// Home Edition
			return false;
		}
		else
		{
			// Professional Edition
			return true;
		}
	}
	else if (GET_KETA(info->OsType, 100) == 4)
	{
		// Windows Server 2003
		return true;
	}
	else if (GET_KETA(info->OsType, 100) >= 5)
	{
		// Windows Vista 以降
		OSVERSIONINFOEX i;

		Zero(&i, sizeof(i));
		i.dwOSVersionInfoSize = sizeof(i);
		if (GetVersionEx((OSVERSIONINFO *)&i) == false)
		{
			return false;
		}

		if (i.wSuiteMask & VER_SUITE_PERSONAL)
		{
			// Home 系
			return false;
		}
		else
		{
			return true;
		}
	}

	return false;
}

// ターミナルサービスがインストールされているかどうか調べる
bool MsIsTerminalServiceInstalled()
{
	OS_INFO *info = GetOsInfo();
	OSVERSIONINFOEX i;

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (ms->nt->WTSDisconnectSession == NULL ||
		ms->nt->WTSFreeMemory == NULL ||
		ms->nt->WTSQuerySessionInformation == NULL)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) < 2)
	{
		return false;
	}

	Zero(&i, sizeof(i));
	i.dwOSVersionInfoSize = sizeof(i);
	if (GetVersionEx((OSVERSIONINFO *)&i) == false)
	{
		return false;
	}

	if (i.wSuiteMask & VER_SUITE_TERMINAL || i.wSuiteMask & VER_SUITE_SINGLEUSERTS)
	{
		return true;
	}

	return false;
}

// サービスを停止する
bool MsStopService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		ret = ms->nt->ControlService(service, SERVICE_CONTROL_STOP, &st);

		ms->nt->CloseServiceHandle(service);
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name) == false)
			{
				break;
			}

			SleepThread(250);
		}
	}

	ms->nt->CloseServiceHandle(sc);
	return ret;
}

// サービスを起動する
bool MsStartService(char *name)
{
	return MsStartServiceEx(name, NULL);
}
bool MsStartServiceEx(char *name, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	static UINT dummy = 0;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}
	if (error_code == NULL)
	{
		error_code = &dummy;
	}

	*error_code = 0;

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		ret = ms->nt->StartService(service, 0, NULL);

		ms->nt->CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name))
			{
				break;
			}

			SleepThread(250);
		}
	}

	ms->nt->CloseServiceHandle(sc);
	return ret;
}

// サービスが起動しているかどうか取得する
bool MsIsServiceRunning(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// 引数チェック
	if (name == NULL || IsEmptyStr(name))
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		Zero(&st, sizeof(st));
		if (ms->nt->QueryServiceStatus(service, &st))
		{
			switch (st.dwCurrentState)
			{
			case SERVICE_CONTINUE_PENDING:
			case SERVICE_PAUSE_PENDING:
			case SERVICE_PAUSED:
			case SERVICE_RUNNING:
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				ret = true;
				break;
			}
		}

		ms->nt->CloseServiceHandle(service);
	}

	ms->nt->CloseServiceHandle(sc);
	return ret;
}

// サービスをアンインストールする
bool MsUninstallService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	MsStopService(name);

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (ms->nt->DeleteService(service))
		{
			ret = true;
		}
		ms->nt->CloseServiceHandle(service);
	}

	ms->nt->CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

// サービス設定を更新する
bool MsUpdateServiceConfig(char *name)
{
	SC_HANDLE sc, service;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	// Windows 起動直後かどうか (デッドロック防止)
	if (timeGetTime() <= (60 * 30 * 1000))
	{
		if (MsRegReadInt(REG_LOCAL_MACHINE, "Software\\SoftEther Corporation\\Update Service Config", name) != 0)
		{
			return false;
		}
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			MsRegWriteInt(REG_LOCAL_MACHINE, "Software\\SoftEther Corporation\\Update Service Config", name, 1);
		}
		ms->nt->CloseServiceHandle(service);
	}

	ms->nt->CloseServiceHandle(sc);

	return true;
}

// サービスをインストールする
bool MsInstallService(char *name, char *title, wchar_t *description, char *path)
{
	wchar_t title_w[MAX_PATH];
	wchar_t path_w[MAX_PATH];
	// 引数チェック
	if (name == NULL || title == NULL || path == NULL)
	{
		return false;
	}

	StrToUni(title_w, sizeof(title_w), title);
	StrToUni(path_w, sizeof(path_w), path);

	return MsInstallServiceW(name, title_w, description, path_w);
}
bool MsInstallServiceW(char *name, wchar_t *title, wchar_t *description, wchar_t *path)
{
	return MsInstallServiceExW(name, title, description, path, NULL);
}
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	wchar_t name_w[MAX_SIZE];
	static UINT temp_int = 0;
	// 引数チェック
	if (name == NULL || title == NULL || path == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}
	if (error_code == NULL)
	{
		error_code = &temp_int;
	}

	*error_code = 0;

	StrToUni(name_w, sizeof(name_w), name);

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = ms->nt->CreateServiceW(sc, name_w, title, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS , SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);

	if (service != NULL)
	{
		ret = true;

		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&d, sizeof(d));
			d.lpDescription = description;
			ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			Free(e);
		}

		ms->nt->CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	ms->nt->CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

// 指定したサービスがインストールされているかどうか調べる
bool MsIsServiceInstalled(char *name)
{
	SC_HANDLE sc;
	SC_HANDLE service;
	bool ret = false;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		ret = true;
	}

	ms->nt->CloseServiceHandle(service);
	ms->nt->CloseServiceHandle(sc);

	return ret;
}

// プロセスの強制終了
void MsTerminateProcess()
{
	TerminateProcess(GetCurrentProcess(), 0);
	_exit(0);
}

// プロセス ID の取得
UINT MsGetProcessId()
{
	return GetCurrentProcessId();
}

// MS 構造体の取得
MS *MsGetMs()
{
	return ms;
}

// スレッドの優先順位を最低にする
void MsSetThreadPriorityIdle()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

// スレッドの優先順位を上げる
void MsSetThreadPriorityHigh()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
}

// スレッドの優先順位を下げる
void MsSetThreadPriorityLow()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
}

// スレッドの優先順位を最高にする
void MsSetThreadPriorityRealtime()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

// スレッドの優先順位を戻す
void MsRestoreThreadPriority()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

// TCP 設定アプリケーションを表示するべきかどうかチェックする
bool MsIsShouldShowTcpConfigApp()
{
	MS_TCP tcp1, tcp2;
	if (MsIsTcpConfigSupported() == false)
	{
		return false;
	}

	MsGetTcpConfig(&tcp1);
	if (MsLoadTcpConfigReg(&tcp2) == false)
	{
		return true;
	}

	if (Cmp(&tcp1, &tcp2, sizeof(MS_TCP) != 0))
	{
		return true;
	}

	return false;
}

// レジストリの一時設定内容データを Windows の TCP パラメータに適用する
void MsApplyTcpConfig()
{
	if (MsIsTcpConfigSupported())
	{
		MS_TCP tcp;

		if (MsLoadTcpConfigReg(&tcp))
		{
			MsSetTcpConfig(&tcp);
		}
	}
}

// 現在の状態で TCP の動的構成がサポートされているかどうかチェックする
bool MsIsTcpConfigSupported()
{
	if (MsIsNt() && MsIsAdmin())
	{
		UINT type = GetOsInfo()->OsType;

		if (GET_KETA(type, 100) >= 2)
		{
			return true;
		}
	}

	return false;
}

// TCP 設定をレジストリ設定から読み込む
bool MsLoadTcpConfigReg(MS_TCP *tcp)
{
	// 引数チェック
	if (tcp == NULL)
	{
		return false;
	}

	if (MsIsNt())
	{
		Zero(tcp, sizeof(MS_TCP));

		if (MsRegIsValueEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true) == false ||
			MsRegIsValueEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true) == false)
		{
			return false;
		}

		tcp->RecvWindowSize = MsRegReadIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true);
		tcp->SendWindowSize = MsRegReadIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true);

		return true;
	}
	else
	{
		return false;
	}
}

// TCP 設定をレジストリから削除する
void MsDeleteTcpConfigReg()
{
	if (MsIsNt() && MsIsAdmin())
	{
		MsRegDeleteKeyEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, true);
	}
}

// TCP 設定をレジストリ設定に書き込む
void MsSaveTcpConfigReg(MS_TCP *tcp)
{
	// 引数チェック
	if (tcp == NULL)
	{
		return;
	}

	if (MsIsNt() && MsIsAdmin())
	{
		MsRegWriteIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", tcp->RecvWindowSize, true);
		MsRegWriteIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", tcp->SendWindowSize, true);
	}
}

// 現在の TCP 設定を取得する
void MsGetTcpConfig(MS_TCP *tcp)
{
	// 引数チェック
	if (tcp == NULL)
	{
		return;
	}

	Zero(tcp, sizeof(MS_TCP));

	if (MsIsNt())
	{
		// ネットワーク設定初期化
		MsInitGlobalNetworkConfig();

		// GlobalMaxTcpWindowSize または TcpWindowSize の値が存在すれば読み込む
		tcp->RecvWindowSize = MAX(tcp->RecvWindowSize, MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TcpWindowSize"));
		tcp->RecvWindowSize = MAX(tcp->RecvWindowSize, MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "GlobalMaxTcpWindowSize"));
		tcp->RecvWindowSize = MAX(tcp->RecvWindowSize, MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "DefaultReceiveWindow"));

		// DefaultSendWindow の値が存在すれば読み込む
		tcp->SendWindowSize = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "DefaultSendWindow");
	}
}

// TCP 設定を書き込む
void MsSetTcpConfig(MS_TCP *tcp)
{
	// 引数チェック
	if (tcp == NULL)
	{
		return;
	}

	if (MsIsNt() && MsIsAdmin())
	{
		bool window_scaling = false;
		UINT tcp1323opts;

		if (tcp->RecvWindowSize >= 65536 || tcp->SendWindowSize >= 65536)
		{
			window_scaling = true;
		}

		// Tcp1323Opts の設定
		tcp1323opts = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts");
		if (window_scaling)
		{
			if (tcp1323opts == 0)
			{
				tcp1323opts = 1;
			}
			if (tcp1323opts == 2)
			{
				tcp1323opts = 3;
			}
		}
		else
		{
			if (tcp1323opts == 1)
			{
				tcp1323opts = 0;
			}
			if (tcp1323opts == 3)
			{
				tcp1323opts = 2;
			}
		}
		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts", tcp1323opts);

		// 受信ウインドウの設定
		if (tcp->RecvWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize", tcp->RecvWindowSize);
		}

		// 送信ウインドウの設定
		if (tcp->SendWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow", tcp->SendWindowSize);
		}
	}
}

// グローバルなネットワーク設定を初期化する
void MsInitGlobalNetworkConfig()
{
	if (MsIsNt())
	{
		UINT current_window_size;

		if (MsRegReadInt(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"packetix_no_optimize") == 0)

		{
			// TCP コネクション数を最大にする
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpNumConnections", TCP_MAX_NUM_CONNECTIONS);

			// タスク オフロードを無効化する
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"DisableTaskOffload", 1);
		}

		current_window_size = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TcpWindowSize");

		if (current_window_size == 65535 || current_window_size == 5980160 ||
			current_window_size == 16777216 || current_window_size == 16777214)
		{
			// 古いバージョンの VPN が書き込んでしまった変な値を削除する
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"Tcp1323Opts");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize");

			// vpn_no_change = true にする
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "vpn_no_change", 1);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "vpn_no_change", 1);
		}
	}
	else
	{
		if (MsRegReadInt(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\VxD\\MSTCP",
			"packetix_no_optimize") == 0)
		{
			// DeadGWDetect を無効にする
			MsRegWriteStr(REG_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\VxD\\MSTCP",
				"DeadGWDetect", "0");
		}
	}

	MsApplyTcpConfig();
}

// 仮想 LAN カードをアップグレードする
bool MsUpgradeVLan(char *tag_name, char *connection_tag_name, char *instance_name)
{
	wchar_t infpath[MAX_PATH];
	char hwid[MAX_PATH];
	wchar_t hwid_w[MAX_PATH];
	bool ret = false;
	bool need_reboot;
	bool before_status;
	UCHAR old_mac_address[6];
	char *s;
	NO_WARNING *nw;
	char sen_sys[MAX_PATH];
	// 引数チェック
	if (instance_name == NULL || tag_name == NULL || connection_tag_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		// Windows 9x ではアップグレードできない
		return false;
	}

	Zero(hwid, sizeof(hwid));
	Format(hwid, sizeof(hwid), DRIVER_DEVICE_ID_TAG, instance_name);
	StrToUni(hwid_w, sizeof(hwid_w), hwid);

	// 指定された名前の仮想 LAN カードがすでに登録されているかどうかを調べる
	if (MsIsVLanExists(tag_name, instance_name) == false)
	{
		// 登録されていない
		return false;
	}

	// 現在使用している .sys ファイル名を取得する
	if (MsGetSenDeiverFilename(sen_sys, sizeof(sen_sys), instance_name) == false)
	{
		// 不明なので新しいファイル名を作成する
		if (MsMakeNewSenDriverFilename(sen_sys, sizeof(sen_sys)) == false)
		{
			// 失敗
			return false;
		}
	}

	// 現在の動作状況を取得する
	before_status = MsIsVLanEnabled(instance_name);

	// 以前の MAC アドレスを取得する
	s = MsGetMacAddress(tag_name, instance_name);
	if (s == NULL)
	{
		Zero(old_mac_address, 6);
	}
	else
	{
		BUF *b;
		b = StrToBin(s);
		Free(s);

		if (b->Size == 6)
		{
			Copy(old_mac_address, b->Buf, b->Size);
		}
		else
		{
			Zero(old_mac_address, 6);
		}

		FreeBuf(b);
	}

	// インストール開始
	if (MsStartDriverInstall(instance_name, IsZero(old_mac_address, 6) ? NULL : old_mac_address, sen_sys) == false)
	{
		return false;
	}
	MsGetDriverPath(instance_name, NULL, NULL, infpath, NULL, sen_sys);

	nw = NULL;

	//if (MsIsVista() == false)
	{
		nw = MsInitNoWarning();
	}

	// インストールを行う
	if (ms->nt->UpdateDriverForPlugAndPlayDevicesW(
		NULL, hwid_w, infpath, 1, &need_reboot))
	{
		ret = true;
	}
	MsFreeNoWarning(nw);

	// インストール完了
	MsFinishDriverInstall(instance_name, sen_sys);

	MsInitNetworkConfig(tag_name, instance_name, connection_tag_name);

	// 動作を復元する
	if (before_status)
	{
		MsEnableVLan(instance_name);
	}
	else
	{
		MsDisableVLan(instance_name);
	}

	return ret;
}

// Windows 9x 用テスト
void MsWin9xTest()
{
}

// 仮想 LAN カードの CompatibleIDs を更新する
void MsUpdateCompatibleIDs(char *instance_name)
{
	TOKEN_LIST *t;
	char id[MAX_SIZE];
	char device_title[MAX_SIZE];
	char device_title_old[MAX_SIZE];
	// 引数チェック
	if (instance_name == NULL)
	{
		return;
	}

	Format(id, sizeof(id), DRIVER_DEVICE_ID_TAG, instance_name);
	Format(device_title, sizeof(device_title), VLAN_ADAPTER_NAME_TAG, instance_name);
	Format(device_title_old, sizeof(device_title_old), "---dummy-string-ut--", instance_name);

	t = MsRegEnumKey(REG_LOCAL_MACHINE, "Enum\\Root\\Net");
	if (t != NULL)
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			char keyname[MAX_PATH];
			char *str;
			char *title;

			Format(keyname, sizeof(keyname), "Enum\\Root\\Net\\%s", t->Token[i]);

			title = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "DeviceDesc");

			if (title != NULL)
			{
				if (StrCmpi(title, device_title) == 0 || StrCmpi(title, device_title_old) == 0)
				{
					Format(keyname, sizeof(keyname), "Enum\\Root\\Net\\%s",t->Token[i]);
					str = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "CompatibleIDs");
					if (str != NULL)
					{
						Free(str);
					}
					else
					{
						MsRegWriteStr(REG_LOCAL_MACHINE, keyname, "CompatibleIDs", id);
					}
				}
				Free(title);
			}
		}

		FreeToken(t);
	}

	MsRegWriteStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup", "SourcePath",
		ms->System32Dir);
}

// 仮想 LAN カードをインストールする (Win9x 用)
bool MsInstallVLan9x(char *instance_name)
{
	char sysdir[MAX_PATH];
	char infdir[MAX_PATH];
	char otherdir[MAX_PATH];
	char syspath[MAX_PATH];
	char syspath2[MAX_PATH];
	char infpath[MAX_PATH];
	char vpn16[MAX_PATH];
	char infpath_src[MAX_PATH];
	char syspath_src[MAX_PATH];
	char sen_sys[MAX_PATH];
	// 引数チェック
	if (instance_name == NULL)
	{
		return false;
	}

	StrCpy(sysdir, sizeof(sysdir), MsGetSystem32Dir());
	Format(infdir, sizeof(infdir), "%s\\inf", MsGetWindowsDir());
	Format(otherdir, sizeof(otherdir), "%s\\other", infdir);
	Format(syspath, sizeof(syspath), "%s\\Sen_%s.sys", sysdir, instance_name);
	Format(syspath2, sizeof(syspath2), "%s\\Sen_%s.sys", infdir, instance_name);
	Format(infpath, sizeof(infpath), "%s\\Sen_%s.inf", infdir, instance_name);
	Format(vpn16, sizeof(vpn16), "%s\\vpn16.exe", MsGetMyTempDir());

	MakeDir(otherdir);

	Format(sen_sys, sizeof(sen_sys), DRIVER_INSTALL_SYS_NAME_TAG, instance_name);

	// vpn16.exe のコピー
	FileCopy("|vpn16.exe", vpn16);

	// インストール開始
	if (MsStartDriverInstall(instance_name, NULL, sen_sys) == false)
	{
		return false;
	}
	MsGetDriverPathA(instance_name, NULL, NULL, infpath_src, syspath_src, sen_sys);

	// inf ファイルのコピー
	FileCopy(infpath_src, infpath);

	// sys ファイルのコピー
	FileCopy(syspath_src, syspath);

	// デバイスドライバのインストール
	if (Run(vpn16, instance_name, false, true) == false)
	{
		return false;
	}

	// CompatibleIDs の更新
	MsUpdateCompatibleIDs(instance_name);

	return true;
}

// 子ウインドウ列挙プロシージャ
bool CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;

	if (o != NULL)
	{
		MsEnumChildWindows(o, hWnd);
	}

	return true;
}

// 指定したウインドウとその子ウインドウをすべて列挙する
LIST *MsEnumChildWindows(LIST *o, HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (o == NULL)
	{
		o = NewListFast(NULL);
	}

	MsAddWindowToList(o, hWnd);

	EnumChildWindows(hWnd, MsEnumChildWindowProc, (LPARAM)o);

	return o;
}

// ウインドウをリストに追加する
void MsAddWindowToList(LIST *o, HWND hWnd)
{
	// 引数チェック
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	if (IsInList(o, hWnd) == false)
	{
		Add(o, hWnd);
	}
}

// スレッドの所有するウインドウの列挙
bool CALLBACK MsEnumThreadWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;

	if (o == NULL)
	{
		return false;
	}

	MsEnumChildWindows(o, hWnd);

	return true;
}

// ウインドウ列挙プロシージャ
BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || o == NULL)
	{
		return TRUE;
	}

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0))
	{
		AddWindow(o, hWnd);
	}

	return TRUE;
}

// 子ウインドウ列挙プロシージャ
BOOL CALLBACK EnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	ENUM_CHILD_WINDOW_PARAM *p = (ENUM_CHILD_WINDOW_PARAM *)lParam;
	LIST *o;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return TRUE;
	}

	o = p->o;

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (p->include_ipcontrol || (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0)))
	{
		AddWindow(o, hWnd);

		if (p->no_recursion == false)
		{
			EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)p);
		}
	}

	return TRUE;
}
LIST *EnumAllWindow()
{
	return EnumAllWindowEx(false, false);
}
LIST *EnumAllWindowEx(bool no_recursion, bool include_ipcontrol)
{
	ENUM_CHILD_WINDOW_PARAM p;
	LIST *o = NewWindowList();

	Zero(&p, sizeof(p));
	p.o = o;
	p.no_recursion = no_recursion;
	p.include_ipcontrol = include_ipcontrol;

	EnumWindows(EnumChildWindowProc, (LPARAM)&p);

	return o;
}
LIST *EnumAllTopWindow()
{
	LIST *o = NewWindowList();

	EnumWindows(EnumTopWindowProc, (LPARAM)o);

	return o;
}

// 特定のウインドウの中にあるすべての子ウインドウを列挙する
LIST *EnumAllChildWindow(HWND hWnd)
{
	return EnumAllChildWindowEx(hWnd, false, false, false);
}
LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self)
{
	ENUM_CHILD_WINDOW_PARAM p;
	LIST *o = NewWindowList();

	Zero(&p, sizeof(p));
	p.include_ipcontrol = include_ipcontrol;
	p.no_recursion = no_recursion;
	p.o = o;

	if (no_self == false)
	{
		AddWindow(o, hWnd);
	}

	EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)&p);

	return o;
}

// ウインドウリストの解放
void FreeWindowList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// ウインドウリストにウインドウを追加
void AddWindow(LIST *o, HWND hWnd)
{
	HWND t, *e;
	// 引数チェック
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	t = hWnd;

	if (Search(o, &t) != NULL)
	{
		return;
	}

	e = ZeroMalloc(sizeof(HWND));
	*e = hWnd;

	Insert(o, e);
}

// ウインドウリストの比較
int CmpWindowList(void *p1, void *p2)
{
	HWND *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HWND **)p1;
	h2 = *(HWND **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}

	return Cmp(h1, h2, sizeof(HWND));
}

// 新しいウインドウリストの作成
LIST *NewWindowList()
{
	return NewListFast(CmpWindowList);
}

// Windows Vista かどうか判別
bool MsIsVista()
{
	OS_INFO *info = GetOsInfo();

	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		if (GET_KETA(info->OsType, 100) >= 5)
		{
			return true;
		}
	}

	return false;
}

// ウインドウの所有者のプロセスパスを取得する
bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd)
{
	DWORD procId = 0;
	// 引数チェック
	if (path == NULL || hWnd == NULL)
	{
		return false;
	}

	GetWindowThreadProcessId(hWnd, &procId);
	if (procId == 0)
	{
		return false;
	}

	if (MsGetProcessExeName(path, size, procId) == false)
	{
		return false;
	}

	return true;
}
bool MsGetWindowOwnerProcessExeNameW(wchar_t *path, UINT size, HWND hWnd)
{
	DWORD procId = 0;
	// 引数チェック
	if (path == NULL || hWnd == NULL)
	{
		return false;
	}

	GetWindowThreadProcessId(hWnd, &procId);
	if (procId == 0)
	{
		return false;
	}

	if (MsGetProcessExeNameW(path, size, procId) == false)
	{
		return false;
	}

	return true;
}

// プロセス ID からプロセスパスを取得する
bool MsGetProcessExeName(char *path, UINT size, UINT id)
{
	LIST *o;
	MS_PROCESS *proc;
	bool ret = false;
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	o = MsGetProcessList();
	proc = MsSearchProcessById(o, id);

	if (proc != NULL)
	{
		ret = true;
		StrCpy(path, size, proc->ExeFilename);
	}

	MsFreeProcessList(o);

	return ret;
}
bool MsGetProcessExeNameW(wchar_t *path, UINT size, UINT id)
{
	LIST *o;
	MS_PROCESS *proc;
	bool ret = false;
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	o = MsGetProcessList();
	proc = MsSearchProcessById(o, id);

	if (proc != NULL)
	{
		ret = true;
		UniStrCpy(path, size, proc->ExeFilenameW);
	}

	MsFreeProcessList(o);

	return ret;
}

// 警告ダイアログを閉じる
bool MsCloseWarningWindow(UINT thread_id)
{
	UINT i;
	LIST *o;
	bool ret = false;

	if (MsIsVista() == false)
	{
		o = NewListFast(NULL);
		EnumThreadWindows(thread_id, MsEnumThreadWindowProc, (LPARAM)o);
	}
	else
	{
		o = EnumAllTopWindow();
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND hWnd;
		
		if (MsIsVista() == false)
		{
			hWnd = LIST_DATA(o, i);
		}
		else
		{
			hWnd = *((HWND *)LIST_DATA(o, i));
		}

		if (hWnd != NULL)
		{
			OS_INFO *info = GetOsInfo();

			if (MsIsNt())
			{
				// このウインドウがドライバの警告画面かどうかを取得する
				if (MsIsVista() == false)
				{
					// Windows Vista 以外
					HWND hStatic, hOk, hCancel, hDetail;

					hStatic = GetDlgItem(hWnd, 0x14C1);
					hOk = GetDlgItem(hWnd, 0x14B7);
					hCancel = GetDlgItem(hWnd, 0x14BA);
					hDetail = GetDlgItem(hWnd, 0x14B9);

					if ((hStatic != NULL || hDetail != NULL) && hOk != NULL && hCancel != NULL)
					{
						char tmp[MAX_SIZE];
						bool b = false;

						if (GetClassName(hStatic, tmp, sizeof(tmp)) != 0)
						{
							if (StrCmpi(tmp, "static") == 0)
							{
								b = true;
							}
						}

						if (GetClassName(hDetail, tmp, sizeof(tmp)) != 0)
						{
							if (StrCmpi(tmp, "button") == 0)
							{
								b = true;
							}
						}

						if (b)
						{
							if (GetClassName(hOk, tmp, sizeof(tmp)) != 0)
							{
								if (StrCmpi(tmp, "button") == 0)
								{
									if (GetClassName(hCancel, tmp, sizeof(tmp)) != 0)
									{
										if (StrCmpi(tmp, "button") == 0)
										{
											// 発見したので OK ボタンを押す
											PostMessage(hWnd, WM_COMMAND, 0x14B7, 0);

											ret = true;
										}
									}
								}
							}
						}
					}
				}
				else
				{
					// Windows Vista
					char exe[MAX_PATH];

					if (MsGetWindowOwnerProcessExeName(exe, sizeof(exe), hWnd))
					{
						if (EndWith(exe, "rundll32.exe"))
						{
							LIST *o;
							HWND h;
							UINT i;

							o = EnumAllChildWindow(hWnd);

							if (o != NULL)
							{
								for (i = 0;i < LIST_NUM(o);i++)
								{
									char tmp[MAX_SIZE];

									h = *((HWND *)LIST_DATA(o, i));

									Zero(tmp, sizeof(tmp));
									GetClassNameA(h, tmp, sizeof(tmp));

									if (StrCmpi(tmp, "DirectUIHWND") == 0)
									{
										LIST *o = EnumAllChildWindow(h);

										if (o != NULL)
										{
											UINT j;
											UINT numDirectUIHWND = 0;
											UINT numButton = 0;
											HWND hButton1 = NULL;
											HWND hButton2 = NULL;

											for (j = 0;j < LIST_NUM(o);j++)
											{
												HWND hh;
												char tmp[MAX_SIZE];

												hh = *((HWND *)LIST_DATA(o, j));

												Zero(tmp, sizeof(tmp));
												GetClassNameA(hh, tmp, sizeof(tmp));

												if (StrCmpi(tmp, "DirectUIHWND") == 0)
												{
													numDirectUIHWND++;
												}

												if (StrCmpi(tmp, "button") == 0)
												{
													numButton++;
													if (hButton1 == NULL)
													{
														hButton1 = hh;
													}
													else
													{
														hButton2 = hh;
													}
												}
											}

											if (numDirectUIHWND == 1 && numButton == 2)
											{
												if (hButton1 != NULL && hButton2 != NULL)
												{
													HWND hButton;
													HWND hParent;
													RECT r1, r2;

													GetWindowRect(hButton1, &r1);
													GetWindowRect(hButton2, &r2);

													hButton = hButton1;

													if (r1.top < r2.top)
													{
														hButton = hButton2;
													}

													hParent = GetParent(hButton);

													// 発見したので OK ボタンを押す
													PostMessage(hParent, WM_COMMAND, 1, 0);

													ret = true;
												}
											}

											FreeWindowList(o);
										}
									}
								}

								FreeWindowList(o);
							}
						}
					}
				}
			}
		}
	}

	if (MsIsVista() == false)
	{
		ReleaseList(o);
	}
	else
	{
		FreeWindowList(o);
	}

	return ret;
}

// 警告を出さないようにするためのスレッド
void MsNoWarningThreadProc(THREAD *thread, void *param)
{
	NO_WARNING *nw;
	UINT interval;
	UINT i;
	bool found0 = false;
	// 引数チェック
	if (thread == NULL)
	{
		return;
	}

	nw = (NO_WARNING *)param;

	nw->NoWarningThread = thread;
	AddRef(thread->ref);

	NoticeThreadInit(thread);

	interval = 50;

	if (MsIsVista())
	{
		interval = 1000;
	}

	i = 0;

	while (nw->Halt == false)
	{
		bool found;

		// 警告ダイアログを閉じる
		found = MsCloseWarningWindow(nw->ThreadId);
		if (i == 0)
		{
			found0 = found;
		}
		else
		{
			if (found0 == false && found)
			{
				break;
			}
		}
		i++;

		// 親スレッドが指示するまでループする
		Wait(nw->HaltEvent, interval);
	}
}

// 警告音を消す処理の初期化
char *MsNoWarningSoundInit()
{
	char *ret = MsRegReadStr(REG_CURRENT_USER, "AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current", "");

	if (IsEmptyStr(ret))
	{
		Free(ret);
		ret = NULL;
	}
	else
	{
		MsRegWriteStr(REG_CURRENT_USER,
			"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
			"", "");
	}

	return ret;
}

// 警告音を消す処理の解放
void MsNoWarningSoundFree(char *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	MsRegWriteStrExpand(REG_CURRENT_USER,
		"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
		"", s);

	Free(s);
}

// 警告を出さないようにする処理の開始
NO_WARNING *MsInitNoWarning()
{
	wchar_t *tmp;
	THREAD *thread;
	NO_WARNING *nw = ZeroMalloc(sizeof(NO_WARNING));

	// 現在のサウンドファイル名を取得する
	tmp = MsRegReadStrW(REG_CURRENT_USER, "AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current", "");
	if (UniIsEmptyStr(tmp) == false)
	{
		nw->SoundFileName = CopyUniStr(tmp);

		MsRegWriteStrW(REG_CURRENT_USER,
			"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
			"", L"");
	}

	Free(tmp);

	nw->ThreadId = GetCurrentThreadId();
	nw->HaltEvent = NewEvent();

	thread = NewThread(MsNoWarningThreadProc, nw);
	WaitThreadInit(thread);

	ReleaseThread(thread);

	return nw;
}

// 警告を出さないようにする処理の終了
void MsFreeNoWarning(NO_WARNING *nw)
{
	// 引数チェック
	if (nw == NULL)
	{
		return;
	}

	nw->Halt = true;
	Set(nw->HaltEvent);

	WaitThread(nw->NoWarningThread, INFINITE);
	ReleaseThread(nw->NoWarningThread);

	ReleaseEvent(nw->HaltEvent);

	if (nw->SoundFileName != NULL)
	{
		MsRegWriteStrExpandW(REG_CURRENT_USER,
			"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
			"", nw->SoundFileName);

		Free(nw->SoundFileName);
	}

	Free(nw);
}

// 仮想 LAN カードをインストールする
bool MsInstallVLan(char *tag_name, char *connection_tag_name, char *instance_name)
{
	wchar_t infpath[MAX_PATH];
	wchar_t inf_class_name[MAX_PATH];
	GUID inf_class_guid;
	HDEVINFO device_info;
	SP_DEVINFO_DATA device_info_data;
	char hwid[MAX_PATH];
	wchar_t hwid_w[MAX_PATH];
	bool ret = false;
	bool need_reboot;
	char sen_sys[MAX_PATH];
	UINT i;
	// 引数チェック
	if (instance_name == NULL || tag_name == NULL || connection_tag_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		// Windows 9x 用
		return MsInstallVLan9x(instance_name);
	}

	Zero(hwid, sizeof(hwid));
	Format(hwid, sizeof(hwid), DRIVER_DEVICE_ID_TAG, instance_name);
	StrToUni(hwid_w, sizeof(hwid_w), hwid);

	// 指定された名前の仮想 LAN カードがすでに登録されているかどうかを調べる
	if (MsIsVLanExists(tag_name, instance_name))
	{
		// すでに登録されている
		return false;
	}

	// インストール先 .sys ファイル名の決定
	if (MsMakeNewSenDriverFilename(sen_sys, sizeof(sen_sys)) == false)
	{
		return false;
	}

	// インストール開始
	if (MsStartDriverInstall(instance_name, NULL, sen_sys) == false)
	{
		return false;
	}
	MsGetDriverPath(instance_name, NULL, NULL, infpath, NULL, sen_sys);

	// inf ファイルのクラス GUID を取得する
	if (SetupDiGetINFClassW(infpath, &inf_class_guid, inf_class_name, sizeof(inf_class_name), NULL))
	{
		// デバイス情報セットを取得する
		device_info = SetupDiCreateDeviceInfoList(&inf_class_guid, NULL);
		if (device_info != INVALID_HANDLE_VALUE)
		{
			// Windows 2000 以降
			Zero(&device_info_data, sizeof(device_info_data));
			device_info_data.cbSize = sizeof(device_info_data);
			if (SetupDiCreateDeviceInfoW(device_info, inf_class_name, &inf_class_guid,
				NULL, NULL, DICD_GENERATE_ID, &device_info_data))
			{
				// レジストリ情報を設定する
				if (SetupDiSetDeviceRegistryProperty(device_info, &device_info_data,
					SPDRP_HARDWAREID, (BYTE *)hwid, sizeof(hwid)))
				{
					NO_WARNING *nw = NULL;
					
					//if (MsIsVista() == false)
					{
						nw = MsInitNoWarning();
					}

					// クラスインストーラを起動する
					if (SetupDiCallClassInstaller(DIF_REGISTERDEVICE, device_info,
						&device_info_data))
					{
						// インストールを行う
						if (ms->nt->UpdateDriverForPlugAndPlayDevicesW(
							NULL, hwid_w, infpath, 1, &need_reboot))
						{
							ret = true;
						}
						else
						{
							// インストール失敗
							SetupDiCallClassInstaller(DIF_REMOVE, device_info,
								&device_info_data);
						}
					}
					else
					{
						Debug("SetupDiCallClassInstaller Error: %X\n", GetLastError());
					}

					MsFreeNoWarning(nw);
				}
			}
			// デバイス情報セットを削除する
			SetupDiDestroyDeviceInfoList(device_info);
		}
	}

	// インストール完了
	MsFinishDriverInstall(instance_name, sen_sys);

	for (i = 0;i < 5;i++)
	{
		MsInitNetworkConfig(tag_name, instance_name, connection_tag_name);
		SleepThread(MsIsVista() ? 1000 : 300);
	}

	if (ret)
	{
		MsDisableVLan(instance_name);
		MsEnableVLan(instance_name);
	}

	return ret;
}

// デバイス ID からデバイス情報を取得する
HDEVINFO MsGetDevInfoFromDeviceId(SP_DEVINFO_DATA *dev_info_data, char *device_id)
{
	HDEVINFO dev_info;
	SP_DEVINFO_LIST_DETAIL_DATA detail_data;
	SP_DEVINFO_DATA data;
	UINT i;
	bool found;
	char target_name[MAX_SIZE];
	// 引数チェック
	if (dev_info_data == NULL || device_id == NULL)
	{
		return NULL;
	}

	StrCpy(target_name, sizeof(target_name), device_id);

	// デバイス情報リストを作成
	dev_info = SetupDiGetClassDevsEx(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT, NULL, NULL, NULL);
	if (dev_info == NULL)
	{
		return NULL;
	}

	Zero(&detail_data, sizeof(detail_data));
	detail_data.cbSize = sizeof(detail_data);
	if (SetupDiGetDeviceInfoListDetail(dev_info, &detail_data) == false)
	{
		MsDestroyDevInfo(dev_info);
		return NULL;
	}

	Zero(&data, sizeof(data));
	data.cbSize = sizeof(data);

	// 列挙開始
	found = false;
	for (i = 0;SetupDiEnumDeviceInfo(dev_info, i, &data);i++)
	{
		char *buffer;
		UINT buffer_size = 8092;
		DWORD data_type;

		buffer = ZeroMalloc(buffer_size);

		if (SetupDiGetDeviceRegistryProperty(dev_info, &data, SPDRP_HARDWAREID, &data_type, (PBYTE)buffer, buffer_size, NULL))
		{
			if (StrCmpi(buffer, target_name) == 0)
			{
				// 発見
				found = true;
			}
		}

		Free(buffer);

		if (found)
		{
			break;
		}
	}

	if (found == false)
	{
		MsDestroyDevInfo(dev_info);
		return NULL;
	}
	else
	{
		Copy(dev_info_data, &data, sizeof(data));
		return dev_info;
	}
}

// 指定したデバイスが動作中かどうかを調べる
bool MsIsDeviceRunning(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_DEVINFO_LIST_DETAIL_DATA detail;
	UINT status = 0, problem = 0;
	// 引数チェック
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&detail, sizeof(detail));
	detail.cbSize = sizeof(detail);

	if (SetupDiGetDeviceInfoListDetail(info, &detail) == false ||
		ms->nt->CM_Get_DevNode_Status_Ex(&status, &problem, dev_info_data->DevInst,
		0, detail.RemoteMachineHandle) != CR_SUCCESS)
	{
		return false;
	}

	if (status & 8)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// 指定したデバイスを開始させる
bool MsStartDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_PROPCHANGE_PARAMS p;
	// 引数チェック
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	p.StateChange = DICS_ENABLE;
	p.Scope = DICS_FLAG_GLOBAL;
	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)))
	{
		SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info, dev_info_data);
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	p.StateChange = DICS_ENABLE;
	p.Scope = DICS_FLAG_CONFIGSPECIFIC;

	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)) == false ||
		SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info, dev_info_data) == false)
	{
		return false;
	}

	return true;
}

// 指定したデバイスを停止させる
bool MsStopDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_PROPCHANGE_PARAMS p;
	// 引数チェック
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	p.StateChange = DICS_DISABLE;
	p.Scope = DICS_FLAG_CONFIGSPECIFIC;

	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)) == false ||
		SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info, dev_info_data) == false)
	{
		return false;
	}

	return true;
}

// 指定したデバイスを削除する
bool MsDeleteDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_REMOVEDEVICE_PARAMS p;
	SP_DEVINFO_LIST_DETAIL_DATA detail;
	char device_id[MAX_PATH];
	// 引数チェック
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&detail, sizeof(detail));
	detail.cbSize = sizeof(detail);

	if (SetupDiGetDeviceInfoListDetail(info, &detail) == false ||
		ms->nt->CM_Get_Device_ID_Ex(dev_info_data->DevInst, device_id, sizeof(device_id),
		0, detail.RemoteMachineHandle) != CR_SUCCESS)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_REMOVE;
	p.Scope = DI_REMOVEDEVICE_GLOBAL;

	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)) == false)
	{
		Debug("SetupDiSetClassInstallParams Failed. Err=%u\n", GetLastError());
		return false;
	}

	if (SetupDiCallClassInstaller(DIF_REMOVE, info, dev_info_data) == false)
	{
		Debug("SetupDiCallClassInstaller Failed. Err=%u\n", GetLastError());
		return false;
	}

	return true;
}

// 仮想 LAN カードを有効にする
bool MsEnableVLan(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// 引数チェック
	if (instance_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsStartDevice(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// 仮想 LAN カードを無効にする
bool MsDisableVLan(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// 引数チェック
	if (instance_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsStopDevice(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// 仮想 LAN カードを再起動する
void MsRestartVLan(char *instance_name)
{
	// 引数チェック
	if (instance_name == NULL)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		return;
	}

	if (MsIsVLanEnabled(instance_name) == false)
	{
		return;
	}

	MsDisableVLan(instance_name);
	MsEnableVLan(instance_name);
}

// 仮想 LAN カードが動作しているかどうか取得する
bool MsIsVLanEnabled(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// 引数チェック
	if (instance_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return true;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsIsDeviceRunning(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// 仮想 LAN カードをアンインストールする
bool MsUninstallVLan(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// 引数チェック
	if (instance_name == NULL)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsDeleteDevice(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// 汎用テスト関数
void MsTest()
{
}

// デバイス情報の破棄
void MsDestroyDevInfo(HDEVINFO info)
{
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	SetupDiDestroyDeviceInfoList(info);
}

// ドライバインストールの開始
bool MsStartDriverInstall(char *instance_name, UCHAR *mac_address, char *sen_sys)
{
	wchar_t src_inf[MAX_PATH];
	wchar_t src_sys[MAX_PATH];
	wchar_t dest_inf[MAX_PATH];
	wchar_t dest_sys[MAX_PATH];
	UCHAR mac_address_bin[6];
	char mac_address_str[32];
	UINT size;
	char *tmp;
	BUF *b;
	IO *io;
	// 引数チェック
	if (instance_name == NULL || sen_sys == NULL)
	{
		return false;
	}

	MsGetDriverPath(instance_name, src_inf, src_sys, dest_inf, dest_sys, sen_sys);

	// INF ファイルの処理
	io = FileOpenW(src_inf, false);
	if (io == NULL)
	{
		return false;
	}

	size = FileSize(io);
	tmp = ZeroMalloc(size * 2);
	if (FileRead(io, tmp, size) == false)
	{
		FileClose(io);
		Free(tmp);
		return false;
	}

	FileClose(io);

	if (mac_address == NULL)
	{
		MsGenMacAddress(mac_address_bin);
	}
	else
	{
		Copy(mac_address_bin, mac_address, 6);
	}

	BinToStr(mac_address_str, sizeof(mac_address_str), mac_address_bin, sizeof(mac_address_bin));

	//ReplaceStrEx(tmp, size * 2, tmp, "$TAG_DRIVER_VER$", DRIVER_VER_STR, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$TAG_INSTANCE_NAME$", instance_name, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$TAG_MAC_ADDRESS$", mac_address_str, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$TAG_SYS_NAME$", sen_sys, false);

	if (MsIsVista())
	{
		//ReplaceStrEx(tmp, size * 2, tmp, "\"100\"", "\"2000\"", false);
	}

	io = FileCreateW(dest_inf);
	if (io == NULL)
	{
		Free(tmp);
		return false;
	}

	FileWrite(io, tmp, StrLen(tmp));
	FileClose(io);

	Free(tmp);

	// SYS ファイルの処理
	b = ReadDumpW(src_sys);
	if (b == NULL)
	{
		return false;
	}

	if (DumpBufW(b, dest_sys) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	return true;
}

// MAC アドレスの生成
void MsGenMacAddress(UCHAR *mac)
{
	UCHAR hash_src[40];
	UCHAR hash[20];
	UINT64 now;
	// 引数チェック
	if (mac == NULL)
	{
		return;
	}

	Rand(hash_src, 40);
	now = SystemTime64();
	Copy(hash_src, &now, sizeof(now));

	Hash(hash, hash_src, sizeof(hash_src), true);

	mac[0] = 0x00;
	mac[1] = 0xAC;
	mac[2] = hash[0];
	mac[3] = hash[1];
	mac[4] = hash[2];
	mac[5] = hash[3];
}

// ドライバインストールの完了
void MsFinishDriverInstall(char *instance_name, char *sen_sys)
{
	wchar_t src_inf[MAX_PATH];
	wchar_t src_sys[MAX_PATH];
	wchar_t dest_inf[MAX_PATH];
	wchar_t dest_sys[MAX_PATH];
	// 引数チェック
	if (instance_name == NULL)
	{
		return;
	}

	MsGetDriverPath(instance_name, src_inf, src_sys, dest_inf, dest_sys, sen_sys);

	// ファイル削除
	FileDeleteW(dest_inf);
	FileDeleteW(dest_sys);
}

// ドライバファイルのパスの取得
void MsGetDriverPath(char *instance_name, wchar_t *src_inf, wchar_t *src_sys, wchar_t *dest_inf, wchar_t *dest_sys, char *sen_sys)
{
	wchar_t *src_filename;
	wchar_t *src_sys_filename;
	// 引数チェック
	if (instance_name == NULL)
	{
		return;
	}

	src_filename = DRIVER_INF_FILE_NAME;
	src_sys_filename = DRIVER_SYS_FILE_NAME;

	if (MsIsNt() == false)
	{
		src_filename = DRIVER_INF_FILE_NAME_9X;
		src_sys_filename = DRIVER_SYS_FILE_NAME_9X;
	}
	else if (MsIsIA64() || MsIsX64())
	{
		if (MsIsX64())
		{
			src_filename = DRIVER_INF_FILE_NAME_X64;
			src_sys_filename = DRIVER_SYS_FILE_NAME_X64;
		}
		else
		{
			src_filename = DRIVER_INF_FILE_NAME_IA64;
			src_sys_filename = DRIVER_SYS_FILE_NAME_IA64;
		}
	}

	if (src_inf != NULL)
	{
		UniStrCpy(src_inf, MAX_PATH, src_filename);
	}

	if (src_sys != NULL)
	{
		UniStrCpy(src_sys, MAX_PATH, src_sys_filename);
	}

	if (dest_inf != NULL)
	{
		char inf_name[MAX_PATH];
		Format(inf_name, sizeof(inf_name), DRIVER_INSTALL_INF_NAME_TAG, instance_name);
		UniFormat(dest_inf, MAX_PATH, L"%s\\%S", ms->MyTempDirW, inf_name);
	}

	if (dest_sys != NULL)
	{
		char sys_name[MAX_PATH];
		StrCpy(sys_name, sizeof(sys_name), sen_sys);
		UniFormat(dest_sys, MAX_PATH, L"%s\\%S", ms->MyTempDirW, sys_name);
	}
}
void MsGetDriverPathA(char *instance_name, char *src_inf, char *src_sys, char *dest_inf, char *dest_sys, char *sen_sys)
{
	wchar_t src_inf_w[MAX_PATH];
	wchar_t src_sys_w[MAX_PATH];
	wchar_t dest_inf_w[MAX_PATH];
	wchar_t dest_sys_w[MAX_PATH];

	// 引数チェック
	if (instance_name == NULL)
	{
		return;
	}

	MsGetDriverPath(instance_name, src_inf_w, src_sys_w, dest_inf_w, dest_sys_w, sen_sys);

	UniToStr(src_inf, MAX_PATH, src_inf_w);
	UniToStr(src_sys, MAX_PATH, src_sys_w);
	UniToStr(dest_inf, MAX_PATH, dest_inf_w);
	UniToStr(dest_sys, MAX_PATH, dest_sys_w);
}

// 指定された名前の仮想 LAN カードがすでに登録されているかどうかを調べる
bool MsIsVLanExists(char *tag_name, char *instance_name)
{
	char *guid;
	// 引数チェック
	if (instance_name == NULL || tag_name == NULL)
	{
		return false;
	}

	guid = MsGetNetworkAdapterGuid(tag_name, instance_name);
	if (guid == NULL)
	{
		return false;
	}

	Free(guid);
	return true;
}

// ネットワーク設定ダイアログを表示する
// ※ これはもう使っていない。うまく動かないからである。
//    代わりに ShowWindowsNetworkConnectionDialog() を使うこと。
bool MsShowNetworkConfiguration(HWND hWnd)
{
	IO *link_file = MsCreateTempFileByExt(".lnk");
	char name[MAX_PATH];
	SHELLEXECUTEINFO info;

	// ファイル名確保
	StrCpy(name, sizeof(name), link_file->Name);

	// ショートカット作成
	if (FileWrite(link_file, network_connection_link, sizeof(network_connection_link)) == false)
	{
		FileCloseAndDelete(link_file);
		return false;
	}

	FileClose(link_file);

	// ショートカットの実行
	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.hwnd = (HWND)hWnd;
	info.lpVerb = "open";
	info.lpFile = name;
	info.nShow = SW_SHOWDEFAULT;
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	if (ShellExecuteEx(&info) == false)
	{
		FileDelete(name);
		return false;
	}

	// プロセス終了まで待機
	WaitForSingleObject(info.hProcess, INFINITE);
	CloseHandle(info.hProcess);

	// ファイルの削除
	FileDelete(name);

	return true;
}

// 拡張子を元に一時ファイルを作成する
IO *MsCreateTempFileByExt(char *ext)
{
	char *tmp = MsCreateTempFileNameByExt(ext);
	IO *ret;

	if (tmp == NULL)
	{
		return NULL;
	}

	ret = FileCreate(tmp);
	Free(tmp);

	return ret;
}

// 拡張子を指定するとその拡張子を持つ一時ファイルを作成する
char *MsCreateTempFileNameByExt(char *ext)
{
	UCHAR rand[2];
	char *ret = NULL;
	// 引数チェック
	if (ext == NULL)
	{
		ext = "tmp";
	}
	if (ext[0] == '.')
	{
		ext++;
	}
	if (StrLen(ext) == 0)
	{
		ext = "tmp";
	}

	while (true)
	{
		char new_filename[MAX_PATH];
		char *fullpath;
		char rand_str[MAX_PATH];
		IO *io;
		Rand(rand, sizeof(rand));

		BinToStr(rand_str, sizeof(rand_str), rand, sizeof(rand));
		Format(new_filename, sizeof(new_filename), "__%s.%s", rand_str, ext);

		fullpath = MsCreateTempFileName(new_filename);
		io = FileOpen(fullpath, false);
		if (io == NULL)
		{
			ret = fullpath;
			break;
		}
		FileClose(io);

		Free(fullpath);
	}

	return ret;
}

// 一時ファイルを作成する
IO *MsCreateTempFile(char *name)
{
	IO *ret;
	char *tmp;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	tmp = MsCreateTempFileName(name);
	if (tmp == NULL)
	{
		return NULL;
	}

	ret = FileCreate(tmp);
	Free(tmp);

	return ret;
}

// 一時ファイル名を作成する
char *MsCreateTempFileName(char *name)
{
	char tmp[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	Format(tmp, sizeof(tmp), "%s\\%s", ms->MyTempDir, name);

	return CopyStr(tmp);
}

// システムに残っているが使用されていない VPN 用一時ディレクトリを削除する
void MsDeleteTempDir()
{
	HANDLE h;
	wchar_t dir_mask[MAX_PATH];
	WIN32_FIND_DATAA data_a;
	WIN32_FIND_DATAW data_w;

	Zero(&data_a, sizeof(data_a));
	Zero(&data_w, sizeof(data_w));

	UniFormat(dir_mask, sizeof(dir_mask), L"%s\\*", ms->TempDirW);

	if (IsNt())
	{
		h = FindFirstFileW(dir_mask, &data_w);
	}
	else
	{
		char *tmp_a = CopyUniToStr(dir_mask);

		h = FindFirstFileA(tmp_a, &data_a);

		Free(tmp_a);
	}

	if (h != INVALID_HANDLE_VALUE)
	{
		bool b = true;

		do
		{
			if (IsNt() == false)
			{
				Zero(&data_w, sizeof(data_w));
				StrToUni(data_w.cFileName, sizeof(data_w.cFileName), data_a.cFileName);
				data_w.dwFileAttributes = data_a.dwFileAttributes;
				data_w.ftCreationTime = data_a.ftCreationTime;
				data_w.ftLastWriteTime = data_a.ftLastWriteTime;
				data_w.nFileSizeHigh = data_a.nFileSizeHigh;
				data_w.nFileSizeLow = data_a.nFileSizeLow;
			}

			if (UniStrCmpi(data_w.cFileName, L".") != 0 &&
				UniStrCmpi(data_w.cFileName, L"..") != 0)
			{
				if (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (UniStartWith(data_w.cFileName, L"VPN_") && UniStrLen(data_w.cFileName) == 8)
					{
						wchar_t lock_file_name[MAX_PATH];
						wchar_t dir_name[MAX_PATH];
						bool delete_now = false;
						IO *io;

						UniFormat(dir_name, sizeof(dir_name), L"%s\\%s",
							ms->TempDirW, data_w.cFileName);
						MsGenLockFile(lock_file_name, sizeof(lock_file_name), dir_name);

						io = FileOpenExW(lock_file_name, false, false);
						if (io != NULL)
						{
							// ロックファイルがロックされていなければ削除マーク
							FileClose(io);
							io = FileOpenW(lock_file_name, true);
							if (io != NULL)
							{
								delete_now = true;
								FileClose(io);
							}
						}
						else
						{
							DIRLIST *d;

							// 中にあるすべてのファイルがロックされていなければ削除マーク
							delete_now = true;

							d = EnumDirW(dir_name);
							if (d != NULL)
							{
								UINT i;

								for (i = 0;i < d->NumFiles;i++)
								{
									wchar_t full_path[MAX_PATH];

									UniFormat(full_path, sizeof(full_path), L"%s\\%s", dir_name, d->File[i]->FileNameW);

									io = FileOpenW(full_path, true);
									if (io != NULL)
									{
										delete_now = true;
										FileClose(io);
									}
								}
								FreeDir(d);
							}
						}
						if (delete_now)
						{
							MsDeleteAllFileW(dir_name);

							Win32DeleteDirW(dir_name);
						}
					}
				}
			}


			Zero(&data_w, sizeof(data_w));
			Zero(&data_a, sizeof(data_a));

			if (IsNt())
			{
				b = FindNextFileW(h, &data_w);
			}
			else
			{
				b = FindNextFileA(h, &data_a);
			}
		}
		while (b);

		FindClose(h);
	}
}

// 指定したディレクトリ内のファイルをすべて削除する
void MsDeleteAllFile(char *dir)
{
	HANDLE h;
	char file_mask[MAX_PATH];
	WIN32_FIND_DATA data;
	// 引数チェック
	if (dir == NULL || IsEmptyStr(dir))
	{
		return;
	}

	Format(file_mask, sizeof(file_mask), "%s\\*.*", dir);

	h = FindFirstFile(file_mask, &data);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (StrCmpi(data.cFileName, ".") != 0 &&
				StrCmpi(data.cFileName, "..") != 0)
			{
				char fullpath[MAX_PATH];
				Format(fullpath, sizeof(fullpath), "%s\\%s", dir, data.cFileName);
				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == false)
				{
					DeleteFile(fullpath);
				}
				else
				{
					MsDeleteAllFile(fullpath);
					RemoveDirectory(fullpath);
				}
			}
		}
		while (FindNextFile(h, &data));

		FindClose(h);
	}
}
void MsDeleteAllFileW(wchar_t *dir)
{
	HANDLE h;
	wchar_t file_mask[MAX_PATH];
	WIN32_FIND_DATAW data;
	// 引数チェック
	if (dir == NULL || UniIsEmptyStr(dir))
	{
		return;
	}

	if (IsNt() == false)
	{
		char *dir_a = CopyUniToStr(dir);

		MsDeleteAllFile(dir_a);

		Free(dir_a);

		return;
	}

	UniFormat(file_mask, sizeof(file_mask), L"%s\\*.*", dir);

	h = FindFirstFileW(file_mask, &data);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (UniStrCmpi(data.cFileName, L".") != 0 &&
				UniStrCmpi(data.cFileName, L"..") != 0)
			{
				wchar_t fullpath[MAX_PATH];

				UniFormat(fullpath, sizeof(fullpath), L"%s\\%s", dir, data.cFileName);

				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == false)
				{
					DeleteFileW(fullpath);
				}
				else
				{
					MsDeleteAllFileW(fullpath);
					RemoveDirectoryW(fullpath);
				}
			}
		}
		while (FindNextFileW(h, &data));

		FindClose(h);
	}
}

// 一時ディレクトリを初期化する
void MsInitTempDir()
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[16];
	UCHAR random[2];
	wchar_t lockfilename[MAX_PATH];
	UINT num = 0;

	// 使われていない一時ディレクトリの削除
	MsDeleteTempDir();

	// 一時ディレクトリ名の決定
	while (true)
	{
		random[0] = rand() % 256;
		random[1] = rand() % 256;
		BinToStrW(tmp2, sizeof(tmp2), random, sizeof(random));

		UniFormat(tmp, sizeof(tmp), L"%s\\VPN_%s", ms->TempDirW, tmp2);

		// ディレクトリの作成
		if (MakeDirW(tmp))
		{
			break;
		}

		if ((num++) >= 100)
		{
			// 何度も失敗する
			char msg[MAX_SIZE];
			Format(msg, sizeof(msg),
				"Couldn't create Temporary Directory: %s\r\n\r\n"
				"Please contact your system administrator.",
				tmp);
			exit(0);
		}
	}

	ms->MyTempDirW = CopyUniStr(tmp);
	ms->MyTempDir = CopyUniToStr(tmp);

	// ロックファイルの作成
	MsGenLockFile(lockfilename, sizeof(lockfilename), ms->MyTempDirW);
	ms->LockFile = FileCreateW(lockfilename);
}

// 一時ディレクトリを解放する
void MsFreeTempDir()
{
	wchar_t lock_file_name[MAX_SIZE];

	// ロックファイルの削除
	MsGenLockFile(lock_file_name, sizeof(lock_file_name), ms->MyTempDirW);
	FileClose(ms->LockFile);

	// メモリ解放
	Free(ms->MyTempDir);
	Free(ms->MyTempDirW);
	ms->MyTempDir = NULL;
	ms->MyTempDirW = NULL;

	// ディレクトリ削除
	MsDeleteTempDir();
}

// ロックファイル名の生成
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir)
{
	// 引数チェック
	if (name == NULL || temp_dir == NULL)
	{
		return;
	}

	UniFormat(name, size, L"%s\\VPN_Lock.dat", temp_dir);
}

// ネットワーク設定の初期化
void MsInitNetworkConfig(char *tag_name, char *instance_name, char *connection_tag_name)
{
	char tmp[MAX_SIZE];
	char *config_str;
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL || connection_tag_name == NULL)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		return;
	}

	// 文字列などの設定
	Format(tmp, sizeof(tmp), connection_tag_name, instance_name);
	MsSetNetworkConfig(tag_name, instance_name, tmp, true);

	// インターフェイス・メトリック値の設定
	config_str = MsGetNetworkAdapterGuid(tag_name, instance_name);
	if (config_str != NULL)
	{
		Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
			config_str);

		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, "InterfaceMetric", 1);
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, "EnableDeadGWDetect", 0);

		if (MsRegReadInt(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"packetix_no_optimize") == 0)
		{
			MsRegWriteInt(REG_LOCAL_MACHINE,
				"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"EnableDeadGWDetect",
				0);
		}

		Free(config_str);
	}
}

// ネットワーク設定を行う
void MsSetNetworkConfig(char *tag_name, char *instance_name, char *friendly_name, bool show_icon)
{
	char *key;
	char *old_name;
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL || friendly_name == NULL)
	{
		return;
	}

	key = MsGetNetworkConfigRegKeyNameFromInstanceName(tag_name, instance_name);
	if (key == NULL)
	{
		return;
	}

	old_name = MsRegReadStr(REG_LOCAL_MACHINE, key, "Name");
	if (old_name != NULL)
	{
		if (MsIsVista())
		{
			char arg[MAX_PATH];
			char netsh[MAX_PATH];

			Format(netsh, sizeof(netsh), "%s\\netsh.exe", MsGetSystem32Dir());

			if (StrCmp(old_name, friendly_name) != 0)
			{
				Format(arg, sizeof(arg), "interface set interface name=\"%s\" newname=\"%s\"",
					old_name, friendly_name);

				Run(netsh, arg, true, true);
			}

			Format(arg, sizeof(arg), "netsh interface ipv4 set interface interface=\"%s\" metric=1",
				friendly_name);

			Run(netsh, arg, true, true);
		}
	}

	if (StrCmp(old_name, friendly_name) != 0)
	{
		MsRegWriteStr(REG_LOCAL_MACHINE, key, "Name", friendly_name);
	}

	MsRegWriteInt(REG_LOCAL_MACHINE, key, "ShowIcon", show_icon ? 1 : 0);

	Free(key);

	Free(old_name);
}

// ネットワーク設定キー名をインスタンス名から取得
char *MsGetNetworkConfigRegKeyNameFromInstanceName(char *tag_name, char *instance_name)
{
	char *guid, *ret;
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	guid = MsGetNetworkAdapterGuid(tag_name, instance_name);
	if (guid == NULL)
	{
		return NULL;
	}

	ret = MsGetNetworkConfigRegKeyNameFromGuid(guid);

	Free(guid);

	return ret;
}

// ネットワーク設定キー名を GUID から取得
char *MsGetNetworkConfigRegKeyNameFromGuid(char *guid)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (guid == NULL)
	{
		return NULL;
	}

	Format(tmp, sizeof(tmp),
		"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
		guid);

	return CopyStr(tmp);
}

// MAC アドレスの設定
void MsSetMacAddress(char *tag_name, char *instance_name, char *mac_address)
{
	TOKEN_LIST *key_list;
	UINT i;
	char dest_name[MAX_SIZE];
	char mac_str[MAX_SIZE];
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL)
	{
		return;
	}

	// MAC アドレスの正規化
	if (NormalizeMacAddress(mac_str, sizeof(mac_str), mac_address) == false)
	{
		return;
	}

	// 目的の名前を生成
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// キーを列挙
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// DriverDesc を読み込む
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// MAC アドレスの書き込み
				MsRegWriteStr(REG_LOCAL_MACHINE, full_key_name, "NetworkAddress", mac_str);
				Free(driver_desc);

				// ドライバの再起動
				MsRestartVLan(instance_name);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	return;
}

// デバイスドライバのファイル名の取得
char *MsGetDriverFileName(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// 目的の名前を生成
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// キーを列挙
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// DriverDesc を読み込む
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// ファイル名を読み込む
				ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DeviceVxDs");
				Free(driver_desc);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	return ret;
}

// デバイスドライバのバージョンの取得
char *MsGetDriverVersion(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	TOKEN_LIST *t;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// 目的の名前を生成
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// キーを列挙
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// DriverDesc を読み込む
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// バージョン情報を読み込む
				ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverVersion");
				if (ret == NULL)
				{
					ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "SenVersion");
				}
				Free(driver_desc);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	if (ret == NULL)
	{
		return NULL;
	}

	t = ParseToken(ret, ", ");
	if (t->NumTokens == 2)
	{
		Free(ret);
		ret = CopyStr(t->Token[1]);
	}
	FreeToken(t);

	return ret;
}

// MAC アドレスの取得
char *MsGetMacAddress(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// 目的の名前を生成
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// キーを列挙
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}

	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// DriverDesc を読み込む
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// MAC アドレスを読み込む
				ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "NetworkAddress");

				if (IsEmptyStr(ret) == false)
				{
					// MAC アドレスにハイフンを入れる
					BUF *b = StrToBin(ret);
					if (b != NULL && b->Size == 6)
					{
						char tmp[MAX_SIZE];
						MacToStr(tmp, sizeof(tmp), b->Buf);

						Free(ret);
						ret = CopyStr(tmp);
					}
					FreeBuf(b);
				}

				Free(driver_desc);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	return ret;
}

// 仮想 LAN カードのデバイス名が本当に存在するかどうかチェックする
bool MsCheckVLanDeviceIdFromRootEnum(char *name)
{
	TOKEN_LIST *t;
	char *root;
	char *keyname;
	UINT i;
	bool ret;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (MsIsNt())
	{
		root = "SYSTEM\\CurrentControlSet\\Enum\\Root\\NET";
		keyname = "HardwareID";
	}
	else
	{
		root = "Enum\\Root\\Net";
		keyname = "CompatibleIDs";
	}

	t = MsRegEnumKey(REG_LOCAL_MACHINE, root);
	if (t == NULL)
	{
		return false;
	}

	ret = false;

	for (i = 0;i < t->NumTokens;i++)
	{
		char *subname = t->Token[i];
		char fullname[MAX_SIZE];
		char *value;

		Format(fullname, sizeof(fullname), "%s\\%s", root, subname);

		value = MsRegReadStr(REG_LOCAL_MACHINE, fullname, keyname);
		if (value != NULL)
		{
			if (StrCmpi(value, name) == 0)
			{
				ret = true;
			}
			Free(value);
		}

		if (ret)
		{
			break;
		}
	}

	FreeToken(t);

	return ret;
}

// ネットワークアダプタの GUID の取得
char *MsGetNetworkAdapterGuid(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// 引数チェック
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// 目的の名前を生成
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// キーを列挙
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;
		char *device_id;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		device_id = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "MatchingDeviceId");

		if (device_id != NULL)
		{
			if (MsCheckVLanDeviceIdFromRootEnum(device_id))
			{
				// DriverDesc を読み込む
				driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
				if (driver_desc != NULL)
				{
					if (StrCmpi(dest_name, driver_desc) == 0)
					{
						// NetCfgInstanceId を読み込む
						if (MsIsNt())
						{
							ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "NetCfgInstanceId");
						}
						else
						{
							ret = CopyStr("");
						}
						Free(driver_desc);
						Free(device_id);
						break;
					}
					Free(driver_desc);
				}
			}
			Free(device_id);
		}
	}

	FreeToken(key_list);

	return ret;
}
// ネットワーク接続名の取得
wchar_t *MsGetNetworkConnectionName(char *guid)
{
	wchar_t *ncname = NULL;
	// 引数チェック
	if (guid == NULL)
	{
		return NULL;
	}

	// ネットワーク接続名を取得
	if (IsNt() != false && GetOsInfo()->OsType >= OSTYPE_WINDOWS_2000_PROFESSIONAL)
	{
		char tmp[MAX_SIZE];
		Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", guid);
		ncname = MsRegReadStrW(REG_LOCAL_MACHINE, tmp, "Name");
	}

	return ncname;
}

// 新しい Sen のドライバファイル名を生成
bool MsMakeNewSenDriverFilename(char *name, UINT size)
{
	TOKEN_LIST *t = MsEnumSenDriverFilenames();
	UINT i;
	bool ret = false;

	i = 0;
	while (true)
	{
		char tmp[MAX_PATH];
		UINT n;

		i++;
		if (i >= 10000)
		{
			break;
		}

		n = Rand32() % DRIVER_INSTALL_SYS_NAME_TAG_MAXID;

		MsGenerateSenDriverFilenameFromInt(tmp, sizeof(tmp), n);

		if (IsInToken(t, tmp) == false)
		{
			StrCpy(name, size, tmp);
			ret = true;
			break;
		}
	}

	FreeToken(t);

	return ret;
}

// Sen のドライバファイル名を整数から生成
void MsGenerateSenDriverFilenameFromInt(char *name, UINT size, UINT n)
{
	Format(name, size, DRIVER_INSTALL_SYS_NAME_TAG_NEW, n);
}

// インストールされている Sen のドライバファイル名の列挙
TOKEN_LIST *MsEnumSenDriverFilenames()
{
	TOKEN_LIST *neos = MsEnumNetworkAdaptersSen();
	LIST *o = NewListFast(NULL);
	TOKEN_LIST *ret;
	UINT i;

	for (i = 0;i < neos->NumTokens;i++)
	{
		char filename[MAX_PATH];
		if (MsGetSenDeiverFilename(filename, sizeof(filename), neos->Token[i]))
		{
			Add(o, CopyStr(filename));
		}
	}

	FreeToken(neos);

	ret = ListToTokenList(o);
	FreeStrList(o);

	return ret;
}

// Sen のドライバファイル名を取得
bool MsGetSenDeiverFilename(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	char *ret;
	// 引数チェック
	if (name == NULL || instance_name == NULL)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Services\\Sen_%s", instance_name);

	ret = MsRegReadStr(REG_LOCAL_MACHINE, tmp, "ImagePath");
	if (ret == NULL)
	{
		return false;
	}

	GetFileNameFromFilePath(name, size, ret);
	Free(ret);

	return true;
}

// ネットワークアダプタの列挙 (Sen のみ)
TOKEN_LIST *MsEnumNetworkAdaptersSen()
{
	TOKEN_LIST *key_list;
	TOKEN_LIST *ret;
	LIST *o;
	UINT i;

	// キーを列挙
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareStr);

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;
		char *device_id;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// DriverDesc を読み込む
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			// 特定の名前で始まっているかどうか確認する
			device_id = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "MatchingDeviceId");

			if (device_id != NULL)
			{
				if (MsCheckVLanDeviceIdFromRootEnum(device_id))
				{
					char *tag = "senadapter_";
					if (StartWith(device_id, tag))
					{
						char tmp[MAX_SIZE];
						StrCpy(tmp, sizeof(tmp), &device_id[StrLen(tag)]);

						Add(o, CopyStr(tmp));
					}
				}
				Free(device_id);
			}

			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = LIST_NUM(o);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return ret;
}

// ネットワークアダプタの列挙
TOKEN_LIST *MsEnumNetworkAdapters(char *start_with_name, char *start_with_name_2)
{
	TOKEN_LIST *key_list;
	TOKEN_LIST *ret;
	LIST *o;
	UINT i;

	// キーを列挙
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareStr);

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;
		char *device_id;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// DriverDesc を読み込む
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			// 特定の名前で始まっているかどうか確認する
			if ((IsEmptyStr(start_with_name) && IsEmptyStr(start_with_name_2)) ||
				(StartWith(driver_desc, start_with_name) || StartWith(driver_desc, start_with_name_2)))
			{
				device_id = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "MatchingDeviceId");

				if (device_id != NULL)
				{
					if (MsCheckVLanDeviceIdFromRootEnum(device_id))
					{
						char instance_name[MAX_SIZE];
						// 名前からインスタンス名だけを抽出する
						if (StartWith(driver_desc, start_with_name))
						{
							if (StrLen(driver_desc) > (StrLen(start_with_name) + 3))
							{
								StrCpy(instance_name, sizeof(instance_name),
									driver_desc + StrLen(start_with_name) + 3);
								Add(o, CopyStr(instance_name));
							}
						}
						else
						{
							if (StrLen(driver_desc) > (StrLen(start_with_name_2) + 3))
							{
								StrCpy(instance_name, sizeof(instance_name),
									driver_desc + StrLen(start_with_name_2) + 3);
								Add(o, CopyStr(instance_name));
							}
						}
					}
					Free(device_id);
				}
			}

			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = LIST_NUM(o);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return ret;
}

// ドメインへのログオンを試行する
bool MsCheckLogon(wchar_t *username, char *password)
{
	wchar_t password_unicode[MAX_SIZE];
	HANDLE h;
	// 引数チェック
	if (username == NULL || password == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	StrToUni(password_unicode, sizeof(password_unicode), password);

	if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
	{
		if (ms->nt->LogonUserW(username, NULL, password_unicode, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// ログオン失敗
			return false;
		}
	}
	else
	{
		char username_ansi[MAX_SIZE];
		UniToStr(username_ansi, sizeof(username_ansi), username);

		if (ms->nt->LogonUserA(username_ansi, NULL, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// ログオン失敗
			return false;
		}
	}

	CloseHandle(h);

	return true;
}

// ドメインへのログオンを試行する
bool MsIsPasswordEmpty(wchar_t *username)
{
	HANDLE h;
	// 引数チェック
	if (username == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
	{
		if (ms->nt->LogonUserW(username, NULL, L"", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// ログオン失敗
			if (GetLastError() == 1327)
			{
				// パスワードが空
				return true;
			}
			else
			{
				// パスワードが間違っている
				return false;
			}
		}
	}
	else
	{
		char username_ansi[MAX_SIZE];
		UniToStr(username_ansi, sizeof(username_ansi), username);

		if (ms->nt->LogonUserA(username_ansi, NULL, "", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// ログオン失敗
			if (GetLastError() == 1327)
			{
				// パスワードが空
				return true;
			}
			else
			{
				// パスワードが間違っている
				return false;
			}
		}
	}

	CloseHandle(h);

	// ログオン成功ということはパスワードが空ということになる
	return false;
}

// シャットダウンの実行 (NT)
bool MsShutdownEx(bool reboot, bool force, UINT time_limit, char *message)
{
	if (MsIsNt() == false)
	{
		return MsShutdown(reboot, force);
	}

	// 特権の取得
	if (MsEnablePrivilege(SE_SHUTDOWN_NAME, true) == false)
	{
		return false;
	}

	// シャットダウンの実行
	if (ms->nt->InitiateSystemShutdown(NULL, message, time_limit, force, reboot) == false)
	{
		MsEnablePrivilege(SE_SHUTDOWN_NAME, false);
		return false;
	}

	// 特権の解放
	MsEnablePrivilege(SE_SHUTDOWN_NAME, false);

	return true;
}

// シャットダウンの実行
bool MsShutdown(bool reboot, bool force)
{
	UINT flag = 0;
	// 特権の取得
	if (MsEnablePrivilege(SE_SHUTDOWN_NAME, true) == false)
	{
		return false;
	}

	flag |= (reboot ? EWX_REBOOT : EWX_SHUTDOWN);
	flag |= (force ? EWX_FORCE : 0);

	// シャットダウンの実行
	if (ExitWindowsEx(flag, 0) == false)
	{
		MsEnablePrivilege(SE_SHUTDOWN_NAME, false);
		return false;
	}

	// 特権の解放
	MsEnablePrivilege(SE_SHUTDOWN_NAME, false);

	return true;
}

// 特権を有効または無効にする
bool MsEnablePrivilege(char *name, bool enable)
{
	HANDLE hToken;
	NT_API *nt = ms->nt;
	LUID luid;
	TOKEN_PRIVILEGES *tp;
	bool ret;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}
	if (MsIsNt() == false)
	{
		return true;
	}

	// プロセストークンを開く
	if (nt->OpenProcessToken(ms->hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == false)
	{
		return false;
	}

	// ローカル一意識別子を取得する
	if (nt->LookupPrivilegeValue(NULL, name, &luid) == FALSE)
	{
		CloseHandle(hToken);
		return false;
	}

	// 特権を有効 / 無効にするための構造体を作成する
	tp = ZeroMalloc(sizeof(TOKEN_PRIVILEGES));
	tp->PrivilegeCount = 1;
	tp->Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	Copy(&tp->Privileges[0].Luid, &luid, sizeof(LUID));

	// 特権を操作する
	ret = nt->AdjustTokenPrivileges(hToken, false, tp, sizeof(TOKEN_PRIVILEGES), 0, 0);

	Free(tp);
	CloseHandle(hToken);

	return ret;
}

// 現在の OS が NT 系かどうか取得
bool MsIsNt()
{
	if (ms == NULL)
	{
		OSVERSIONINFO os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		GetVersionEx(&os);
		if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	return ms->IsNt;
}

// 現在のユーザーが Admin かどうか取得
bool MsIsAdmin()
{
	return ms->IsAdmin;
}

// NT 系関数のロード
NT_API *MsLoadNtApiFunctions()
{
	NT_API *nt = ZeroMalloc(sizeof(NT_API));
	OSVERSIONINFO info;

	Zero(&info, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);
	GetVersionEx(&info);

	nt->hKernel32 = LoadLibrary("kernel32.dll");
	if (nt->hKernel32 == NULL)
	{
		Free(nt);
		return NULL;
	}

	nt->hAdvapi32 = LoadLibrary("advapi32.dll");
	if (nt->hAdvapi32 == NULL)
	{
		Free(nt);
		return NULL;
	}

	nt->hShell32 = LoadLibrary("shell32.dll");
	if (nt->hShell32 == NULL)
	{
		FreeLibrary(nt->hAdvapi32);
		Free(nt);
		return NULL;
	}

	nt->hPsApi = LoadLibrary("psapi.dll");

	if (info.dwMajorVersion >= 5)
	{
		nt->hNewDev = LoadLibrary("newdev.dll");
		if (nt->hNewDev == NULL)
		{
			FreeLibrary(nt->hShell32);
			FreeLibrary(nt->hAdvapi32);
			Free(nt);
			return NULL;
		}

		nt->hSetupApi = LoadLibrary("setupapi.dll");
	}

	nt->hSecur32 = LoadLibrary("secur32.dll");

	nt->hUser32 = LoadLibrary("user32.dll");

	nt->hDbgHelp = LoadLibrary("dbghelp.dll");

	// 関数の読み込み
	nt->IsWow64Process =
		(BOOL (__stdcall *)(HANDLE,BOOL *))
		GetProcAddress(nt->hKernel32, "IsWow64Process");

	nt->GetFileInformationByHandle =
		(BOOL (__stdcall *)(HANDLE,LPBY_HANDLE_FILE_INFORMATION))
		GetProcAddress(nt->hKernel32, "GetFileInformationByHandle");

	nt->GetProcessHeap =
		(HANDLE (__stdcall *)())
		GetProcAddress(nt->hKernel32, "GetProcessHeap");

	nt->SetProcessShutdownParameters =
		(BOOL (__stdcall *)(DWORD,DWORD))
		GetProcAddress(nt->hKernel32, "SetProcessShutdownParameters");

	nt->GetNativeSystemInfo =
		(void (__stdcall *)(SYSTEM_INFO *))
		GetProcAddress(nt->hKernel32, "GetNativeSystemInfo");

	nt->AdjustTokenPrivileges =
		(BOOL (__stdcall *)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD))
		GetProcAddress(nt->hAdvapi32, "AdjustTokenPrivileges");

	nt->LookupPrivilegeValue =
		(BOOL (__stdcall *)(char *,char *,PLUID))
		GetProcAddress(nt->hAdvapi32, "LookupPrivilegeValueA");

	nt->OpenProcessToken =
		(BOOL (__stdcall *)(HANDLE,DWORD,PHANDLE))
		GetProcAddress(nt->hAdvapi32, "OpenProcessToken");

	nt->InitiateSystemShutdown =
		(BOOL (__stdcall *)(LPTSTR,LPTSTR,DWORD,BOOL,BOOL))
		GetProcAddress(nt->hAdvapi32, "InitiateSystemShutdownA");

	nt->LogonUserW =
		(BOOL (__stdcall *)(wchar_t *,wchar_t *,wchar_t *,DWORD,DWORD,HANDLE *))
		GetProcAddress(nt->hAdvapi32, "LogonUserW");

	nt->LogonUserA =
		(BOOL (__stdcall *)(char *,char *,char *,DWORD,DWORD,HANDLE * ))
		GetProcAddress(nt->hAdvapi32, "LogonUserA");

	nt->DuplicateTokenEx =
		(BOOL (__stdcall *)(HANDLE,DWORD,SECURITY_ATTRIBUTES *,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,HANDLE *))
		GetProcAddress(nt->hAdvapi32, "DuplicateTokenEx");

	nt->ConvertStringSidToSidA =
		(BOOL (__stdcall *)(LPCSTR,PSID *))
		GetProcAddress(nt->hAdvapi32, "ConvertStringSidToSidA");

	nt->GetTokenInformation =
		(BOOL (__stdcall *)(HANDLE,TOKEN_INFORMATION_CLASS,void *,DWORD,PDWORD))
		GetProcAddress(nt->hAdvapi32, "GetTokenInformation");

	nt->SetTokenInformation =
		(BOOL (__stdcall *)(HANDLE,TOKEN_INFORMATION_CLASS,void *,DWORD))
		GetProcAddress(nt->hAdvapi32, "SetTokenInformation");

	nt->CreateProcessAsUserA =
		(BOOL (__stdcall *)(HANDLE,LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,void *,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION))
		GetProcAddress(nt->hAdvapi32, "CreateProcessAsUserA");

	nt->CreateProcessAsUserW =
		(BOOL (__stdcall *)(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,void *,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION))
		GetProcAddress(nt->hAdvapi32, "CreateProcessAsUserW");

	nt->LookupAccountSidA =
		(BOOL (__stdcall *)(LPCSTR,PSID,LPSTR,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE))
		GetProcAddress(nt->hAdvapi32, "LookupAccountSidA");

	nt->LookupAccountNameA =
		(BOOL (__stdcall *)(LPCSTR,LPCSTR,PSID,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE))
		GetProcAddress(nt->hAdvapi32, "LookupAccountNameA");

	if (info.dwMajorVersion >= 5)
	{
		nt->UpdateDriverForPlugAndPlayDevicesW =
			(BOOL (__stdcall *)(HWND,wchar_t *,wchar_t *,UINT,BOOL *))
			GetProcAddress(nt->hNewDev, "UpdateDriverForPlugAndPlayDevicesW");

		nt->CM_Get_Device_ID_ExA =
			(UINT (__stdcall *)(DWORD,char *,UINT,UINT,HANDLE))
			GetProcAddress(nt->hSetupApi, "CM_Get_Device_ID_ExA");

		nt->CM_Get_DevNode_Status_Ex =
			(UINT (__stdcall *)(UINT *,UINT *,DWORD,UINT,HANDLE))
			GetProcAddress(nt->hSetupApi, "CM_Get_DevNode_Status_Ex");
	}

	nt->hWtsApi32 = LoadLibrary("wtsapi32.dll");
	if (nt->hWtsApi32 != NULL)
	{
		// ターミナルサービス関係の API
		nt->WTSQuerySessionInformation =
			(UINT (__stdcall *)(HANDLE,DWORD,WTS_INFO_CLASS,wchar_t *,DWORD *))
			GetProcAddress(nt->hWtsApi32, "WTSQuerySessionInformationW");
		nt->WTSFreeMemory =
			(void (__stdcall *)(void *))
			GetProcAddress(nt->hWtsApi32, "WTSFreeMemory");
		nt->WTSDisconnectSession =
			(BOOL (__stdcall *)(HANDLE,DWORD,BOOL))
			GetProcAddress(nt->hWtsApi32, "WTSDisconnectSession");
		nt->WTSEnumerateSessionsA =
			(BOOL (__stdcall *)(HANDLE,DWORD,DWORD,PWTS_SESSION_INFOA *,DWORD *))
			GetProcAddress(nt->hWtsApi32, "WTSEnumerateSessionsA");
	}

	// サービス系 API
	nt->OpenSCManager =
		(SC_HANDLE (__stdcall *)(LPCTSTR,LPCTSTR,DWORD))
		GetProcAddress(nt->hAdvapi32, "OpenSCManagerA");
	nt->CreateServiceA =
		(SC_HANDLE (__stdcall *)(SC_HANDLE,LPCTSTR,LPCTSTR,DWORD,DWORD,DWORD,DWORD,LPCTSTR,LPCTSTR,LPDWORD,LPCTSTR,LPCTSTR,LPCTSTR))
		GetProcAddress(nt->hAdvapi32, "CreateServiceA");
	nt->CreateServiceW =
		(SC_HANDLE (__stdcall *)(SC_HANDLE,LPCWSTR,LPCWSTR,DWORD,DWORD,DWORD,DWORD,LPCWSTR,LPCWSTR,LPDWORD,LPCWSTR,LPCWSTR,LPCWSTR))
		GetProcAddress(nt->hAdvapi32, "CreateServiceW");
	nt->ChangeServiceConfig2 =
		(BOOL (__stdcall *)(SC_HANDLE,DWORD,LPVOID))
		GetProcAddress(nt->hAdvapi32, "ChangeServiceConfig2W");
	nt->CloseServiceHandle =
		(BOOL (__stdcall *)(SC_HANDLE))
		GetProcAddress(nt->hAdvapi32, "CloseServiceHandle");
	nt->OpenService =
		(SC_HANDLE (__stdcall *)(SC_HANDLE,LPCTSTR,DWORD))
		GetProcAddress(nt->hAdvapi32, "OpenServiceA");
	nt->QueryServiceStatus =
		(BOOL (__stdcall *)(SC_HANDLE,LPSERVICE_STATUS))
		GetProcAddress(nt->hAdvapi32, "QueryServiceStatus");
	nt->StartService =
		(BOOL (__stdcall *)(SC_HANDLE,DWORD,LPCTSTR))
		GetProcAddress(nt->hAdvapi32, "StartServiceA");
	nt->ControlService =
		(BOOL (__stdcall *)(SC_HANDLE,DWORD,LPSERVICE_STATUS))
		GetProcAddress(nt->hAdvapi32, "ControlService");
	nt->SetServiceStatus =
		(BOOL (__stdcall *)(SERVICE_STATUS_HANDLE,LPSERVICE_STATUS))
		GetProcAddress(nt->hAdvapi32, "SetServiceStatus");
	nt->RegisterServiceCtrlHandler =
		(SERVICE_STATUS_HANDLE (__stdcall *)(LPCTSTR,LPHANDLER_FUNCTION))
		GetProcAddress(nt->hAdvapi32, "RegisterServiceCtrlHandlerW");
	nt->StartServiceCtrlDispatcher =
		(BOOL (__stdcall *)(const LPSERVICE_TABLE_ENTRY))
		GetProcAddress(nt->hAdvapi32, "StartServiceCtrlDispatcherW");
	nt->DeleteService =
		(BOOL (__stdcall *)(SC_HANDLE))
		GetProcAddress(nt->hAdvapi32, "DeleteService");
	nt->RegisterEventSourceW =
		(HANDLE (__stdcall *)(LPCWSTR,LPCWSTR))
		GetProcAddress(nt->hAdvapi32, "RegisterEventSourceW");
	nt->ReportEventW =
		(BOOL (__stdcall *)(HANDLE,WORD,WORD,DWORD,PSID,WORD,DWORD,LPCWSTR *,LPVOID))
		GetProcAddress(nt->hAdvapi32, "ReportEventW");
	nt->DeregisterEventSource =
		(BOOL (__stdcall *)(HANDLE))
		GetProcAddress(nt->hAdvapi32, "DeregisterEventSource");
	nt->Wow64DisableWow64FsRedirection =
		(BOOL (__stdcall *)(void **))
		GetProcAddress(nt->hKernel32, "Wow64DisableWow64FsRedirection");
	nt->Wow64EnableWow64FsRedirection =
		(BOOLEAN (__stdcall *)(BOOLEAN))
		GetProcAddress(nt->hKernel32, "Wow64EnableWow64FsRedirection");
	nt->Wow64RevertWow64FsRedirection =
		(BOOL (__stdcall *)(void *))
		GetProcAddress(nt->hKernel32, "Wow64RevertWow64FsRedirection");

	if (nt->hPsApi != NULL)
	{
		// プロセス系 API
		nt->EnumProcesses =
			(BOOL (__stdcall *)(DWORD *,DWORD,DWORD *))
			GetProcAddress(nt->hPsApi, "EnumProcesses");

		nt->EnumProcessModules =
			(BOOL (__stdcall *)(HANDLE,HMODULE * ,DWORD,DWORD *))
			GetProcAddress(nt->hPsApi, "EnumProcessModules");

		nt->GetModuleFileNameExA =
			(DWORD (__stdcall *)(HANDLE,HMODULE,LPSTR,DWORD))
			GetProcAddress(nt->hPsApi, "GetModuleFileNameExA");

		nt->GetModuleFileNameExW =
			(DWORD (__stdcall *)(HANDLE,HMODULE,LPWSTR,DWORD))
			GetProcAddress(nt->hPsApi, "GetModuleFileNameExW");
	}

	// レジストリ系 API
	nt->RegDeleteKeyExA =
		(LONG (__stdcall *)(HKEY,LPCTSTR,REGSAM,DWORD))
		GetProcAddress(nt->hAdvapi32, "RegDeleteKeyExA");

	// セキュリティ系 API
	if (nt->hSecur32 != NULL)
	{
		nt->GetUserNameExA =
			(BOOL (__stdcall *)(EXTENDED_NAME_FORMAT,LPSTR,PULONG))
			GetProcAddress(nt->hSecur32, "GetUserNameExA");

		nt->GetUserNameExW =
			(BOOL (__stdcall *)(EXTENDED_NAME_FORMAT,LPWSTR,PULONG))
			GetProcAddress(nt->hSecur32, "GetUserNameExW");
	}

	// デスクトップ系 API
	if (nt->hUser32 != NULL)
	{
		nt->SwitchDesktop =
			(BOOL (__stdcall *)(HDESK))
			GetProcAddress(nt->hUser32, "SwitchDesktop");
		nt->OpenDesktopA =
			(HDESK (__stdcall *)(LPTSTR,DWORD,BOOL,ACCESS_MASK))
			GetProcAddress(nt->hUser32, "OpenDesktopA");
		nt->CloseDesktop =
			(BOOL (__stdcall *)(HDESK))
			GetProcAddress(nt->hUser32, "CloseDesktop");
	}

	// デバッグ系 API
	if (nt->hDbgHelp != NULL)
	{
		nt->MiniDumpWriteDump =
			(BOOL (__stdcall *)(HANDLE,DWORD,HANDLE,MINIDUMP_TYPE,PMINIDUMP_EXCEPTION_INFORMATION,PMINIDUMP_USER_STREAM_INFORMATION,PMINIDUMP_CALLBACK_INFORMATION))
			GetProcAddress(nt->hDbgHelp, "MiniDumpWriteDump");
	}

	return nt;
}

// NT 系関数の解放
void MsFreeNtApiFunctions(NT_API *nt)
{
	// 引数チェック
	if (nt == NULL)
	{
		return;
	}

	if (nt->hSecur32 != NULL)
	{
		FreeLibrary(nt->hSecur32);
	}

	if (nt->hNewDev != NULL)
	{
		FreeLibrary(nt->hSetupApi);
		FreeLibrary(nt->hNewDev);
	}

	FreeLibrary(nt->hAdvapi32);

	FreeLibrary(nt->hShell32);

	if (nt->hWtsApi32 != NULL)
	{
		FreeLibrary(nt->hWtsApi32);
	}

	if (nt->hPsApi != NULL)
	{
		FreeLibrary(nt->hPsApi);
	}

	if (nt->hUser32 != NULL)
	{
		FreeLibrary(nt->hUser32);
	}

	if (nt->hDbgHelp != NULL)
	{
		FreeLibrary(nt->hDbgHelp);
	}

	FreeLibrary(nt->hKernel32);

	Free(nt);
}

// 64 bit アプリケーションのために 32 bit レジストリキーへのアクセスを強制するアクセスマスクを生成する
DWORD MsRegAccessMaskFor64Bit(bool force32bit)
{
	return MsRegAccessMaskFor64BitEx(force32bit, false);
}
DWORD MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit)
{
	if (MsIs64BitWindows() == false)
	{
		return 0;
	}
	if (force32bit)
	{
		return KEY_WOW64_32KEY;
	}
	if (force64bit)
	{
		return KEY_WOW64_64KEY;
	}

	return 0;
}

// 値の削除
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename)
{
	return MsRegDeleteValueEx(root, keyname, valuename, false);
}
bool MsRegDeleteValueEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegDeleteValueEx2(root, keyname, valuename, force32bit, false);
}
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	bool ret;
	// 引数チェック
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegDeleteValue(h, valuename) != ERROR_SUCCESS)
	{
		ret = false;
	}
	else
	{
		ret = true;
	}

	RegCloseKey(h);

	return ret;
}

// キーの削除
bool MsRegDeleteKey(UINT root, char *keyname)
{
	return MsRegDeleteKeyEx(root, keyname, false);
}
bool MsRegDeleteKeyEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegDeleteKeyEx2(root, keyname, force32bit, false);
}
bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	// 引数チェック
	if (keyname == NULL)
	{
		return false;
	}

	if (MsIsNt() && ms->nt->RegDeleteKeyExA != NULL)
	{
		if (ms->nt->RegDeleteKeyExA(MsGetRootKeyFromInt(root), keyname, MsRegAccessMaskFor64BitEx(force32bit, force64bit), 0) != ERROR_SUCCESS)
		{
			return false;
		}
	}
	else
	{
		if (RegDeleteKey(MsGetRootKeyFromInt(root), keyname) != ERROR_SUCCESS)
		{
			return false;
		}
	}

	return true;
}

// 値の列挙
TOKEN_LIST *MsRegEnumValue(UINT root, char *keyname)
{
	return MsRegEnumValueEx(root, keyname, false);
}
TOKEN_LIST *MsRegEnumValueEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegEnumValueEx2(root, keyname, force32bit, false);
}
TOKEN_LIST *MsRegEnumValueEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT i;
	TOKEN_LIST *t;
	LIST *o;

	if (keyname == NULL)
	{
		h = MsGetRootKeyFromInt(root);
	}
	else
	{
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
		{
			return NULL;
		}
	}

	o = NewListFast(CompareStr);

	for (i = 0;;i++)
	{
		char tmp[MAX_SIZE];
		UINT ret;
		UINT size = sizeof(tmp);

		Zero(tmp, sizeof(tmp));
		ret = RegEnumValue(h, i, tmp, &size, NULL, NULL, NULL, NULL);
		if (ret == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if (ret != ERROR_SUCCESS)
		{
			break;
		}

		Add(o, CopyStr(tmp));
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	if (keyname != NULL)
	{
		RegCloseKey(h);
	}

	return t;
}

// キーの列挙
TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname)
{
	return MsRegEnumKeyEx(root, keyname, false);
}
TOKEN_LIST *MsRegEnumKeyEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegEnumKeyEx2(root, keyname, force32bit, false);
}
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT i;
	TOKEN_LIST *t;
	LIST *o;

	if (keyname == NULL)
	{
		h = MsGetRootKeyFromInt(root);
	}
	else
	{
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
		{
			return NULL;
		}
	}

	o = NewListFast(CompareStr);

	for (i = 0;;i++)
	{
		char tmp[MAX_SIZE];
		UINT ret;
		UINT size = sizeof(tmp);
		FILETIME ft;

		Zero(tmp, sizeof(tmp));
		ret = RegEnumKeyEx(h, i, tmp, &size, NULL, NULL, NULL, &ft);
		if (ret == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if (ret != ERROR_SUCCESS)
		{
			break;
		}

		Add(o, CopyStr(tmp));
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	if (keyname != NULL)
	{
		RegCloseKey(h);
	}

	return t;
}

// バイナリデータを設定する
bool MsRegWriteBin(UINT root, char *keyname, char *valuename, void *data, UINT size)
{
	return MsRegWriteBinEx(root, keyname, valuename, data, size, false);
}
bool MsRegWriteBinEx(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit)
{
	return MsRegWriteBinEx2(root, keyname, valuename, data, size, force32bit, false);
}
bool MsRegWriteBinEx2(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit, bool force64bit)
{
	// 引数チェック
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_BINARY, data, size, force32bit, force64bit);
}

// 整数値を設定する
bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value)
{
	return MsRegWriteIntEx(root, keyname, valuename, value, false);
}
bool MsRegWriteIntEx(UINT root, char *keyname, char *valuename, UINT value, bool force32bit)
{
	return MsRegWriteIntEx2(root, keyname, valuename, value, force32bit, false);
}
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit)
{
	// 引数チェック
	if (keyname == NULL)
	{
		return false;
	}

	// エンディアン補正
	if (IsBigEndian())
	{
		value = Swap32(value);
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_DWORD_LITTLE_ENDIAN, &value, sizeof(UINT), force32bit, force64bit);
}

// 文字列を設定する
bool MsRegWriteStrExpand(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrExpandEx(root, keyname, valuename, str, false);
}
bool MsRegWriteStrExpandEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit)
{
	return MsRegWriteStrExpandEx2(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrExpandEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	// 引数チェック
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_EXPAND_SZ, str, StrSize(str), force32bit, force64bit);
}
bool MsRegWriteStrExpandW(UINT root, char *keyname, char *valuename, wchar_t *str)
{
	return MsRegWriteStrExpandExW(root, keyname, valuename, str, false);
}
bool MsRegWriteStrExpandExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit)
{
	return MsRegWriteStrExpandEx2W(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrExpandEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit)
{
	// 引数チェック
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2W(root, keyname, valuename, REG_EXPAND_SZ, str, UniStrSize(str), force32bit, force64bit);
}

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrEx(root, keyname, valuename, str, false);
}
bool MsRegWriteStrEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit)
{
	return MsRegWriteStrEx2(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	// 引数チェック
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_SZ, str, StrSize(str), force32bit, force64bit);
}
bool MsRegWriteStrW(UINT root, char *keyname, char *valuename, wchar_t *str)
{
	return MsRegWriteStrExW(root, keyname, valuename, str, false);
}
bool MsRegWriteStrExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit)
{
	return MsRegWriteStrEx2W(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit)
{
	// 引数チェック
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2W(root, keyname, valuename, REG_SZ, str, UniStrSize(str), force32bit, force64bit);
}

// 値を設定する
bool MsRegWriteValue(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size)
{
	return MsRegWriteValueEx(root, keyname, valuename, type, data, size, false);
}
bool MsRegWriteValueEx(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit)
{
	return MsRegWriteValueEx2(root, keyname, valuename, type, data, size, force32bit, false);
}
bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	// 引数チェック
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	// キーを作成する
	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	// キーを開く
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// 値を書き込む
	if (RegSetValueEx(h, valuename, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return false;
	}

	// キーを閉じる
	RegCloseKey(h);

	return true;
}
bool MsRegWriteValueW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size)
{
	return MsRegWriteValueExW(root, keyname, valuename, type, data, size, false);
}
bool MsRegWriteValueExW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit)
{
	return MsRegWriteValueEx2W(root, keyname, valuename, type, data, size, force32bit, false);
}
bool MsRegWriteValueEx2W(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	wchar_t valuename_w[MAX_SIZE];
	// 引数チェック
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	if (IsNt() == false)
	{
		UINT size_a;
		void *data_a;
		bool ret;

		if (type == REG_SZ || type == REG_MULTI_SZ || type == REG_EXPAND_SZ)
		{
			data_a = CopyUniToStr(data);
			size_a = StrSize(data_a);
		}
		else
		{
			data_a = Clone(data, size);
			size_a = size;
		}

		ret = MsRegWriteValueEx2(root, keyname, valuename, type, data_a, size_a, force32bit, force64bit);

		Free(data_a);

		return ret;
	}

	StrToUni(valuename_w, sizeof(valuename_w), valuename);

	// キーを作成する
	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	// キーを開く
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// 値を書き込む
	if (RegSetValueExW(h, valuename_w, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return false;
	}

	// キーを閉じる
	RegCloseKey(h);

	return true;
}

// バイナリデータを取得する
BUF *MsRegReadBin(UINT root, char *keyname, char *valuename)
{
	return MsRegReadBinEx(root, keyname, valuename, false);
}
BUF *MsRegReadBinEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadBinEx2(root, keyname, valuename, force32bit, false);
}
BUF *MsRegReadBinEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	UINT type, size;
	BUF *b;
	// 引数チェック
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	// 値を読み込む
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	b = NewBuf();

	WriteBuf(b, ret, size);
	SeekBuf(b, 0, 0);

	Free(ret);

	return b;
}

// 整数値を取得する
UINT MsRegReadInt(UINT root, char *keyname, char *valuename)
{
	return MsRegReadIntEx(root, keyname, valuename, false);
}
UINT MsRegReadIntEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadIntEx2(root, keyname, valuename, force32bit, false);
}
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	UINT type, size;
	UINT value;
	// 引数チェック
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	// 値を読み込む
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	// 種類をチェックする
	if (type != REG_DWORD_LITTLE_ENDIAN && type != REG_DWORD_BIG_ENDIAN)
	{
		// DWORD 以外である
		Free(ret);
		return 0;
	}

	// サイズをチェックする
	if (size != sizeof(UINT))
	{
		Free(ret);
		return 0;
	}

	Copy(&value, ret, sizeof(UINT));

	Free(ret);

	// エンディアン変換
	if (IsLittleEndian())
	{
#ifdef	REG_DWORD_BIG_ENDIAN
		if (type == REG_DWORD_BIG_ENDIAN)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_BIG_ENDIAN
	}
	else
	{
#ifdef	REG_DWORD_LITTLE_ENDIAN_FLAG
		if (type == REG_DWORD_LITTLE_ENDIAN_FLAG)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_LITTLE_ENDIAN_FLAG
	}

	return value;
}

// 文字列リストを取得する
LIST *MsRegReadStrList(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrListEx(root, keyname, valuename, false);
}
LIST *MsRegReadStrListEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrListEx2(root, keyname, valuename, force32bit, false);
}
LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	LIST *o;
	char *ret;
	UINT type, size;
	// 引数チェック
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// 値を読み込む
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// 種類をチェックする
	if (type != REG_MULTI_SZ)
	{
		// 文字列リスト以外である
		Free(ret);
		return NULL;
	}

	if (size < 2)
	{
		// サイズ不正
		Free(ret);
		return NULL;
	}

	if (ret[size - 1] != 0)
	{
		// データ不正
		Free(ret);
		return NULL;
	}

	// リスト作成
	o = StrToStrList(ret, size);

	Free(ret);

	return o;
}

// 文字列を取得する
char *MsRegReadStr(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrEx(root, keyname, valuename, false);
}
char *MsRegReadStrEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrEx2(root, keyname, valuename, force32bit, false);
}
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	UINT type, size;
	// 引数チェック
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// 値を読み込む
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// 種類をチェックする
	if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
	{
		// 文字列以外である
		Free(ret);

		if (type == REG_MULTI_SZ)
		{
			// 文字列リストである
			LIST *o = MsRegReadStrList(root, keyname, valuename);
			if (o != NULL)
			{
				if (LIST_NUM(o) >= 1)
				{
					ret = CopyStr(LIST_DATA(o, 0));
					FreeStrList(o);
					return ret;
				}
			}
		}
		return NULL;
	}

	if (size == 0)
	{
		// サイズ不正
		Free(ret);

		return CopyStr("");
	}

	if (ret[size - 1] != 0)
	{
		// データ不正
		Free(ret);
		return NULL;
	}

	return ret;
}
wchar_t *MsRegReadStrW(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrExW(root, keyname, valuename, false);
}
wchar_t *MsRegReadStrExW(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrEx2W(root, keyname, valuename, force32bit, false);
}
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	wchar_t *ret;
	UINT type, size;
	// 引数チェック
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// 値を読み込む
	if (MsRegReadValueEx2W(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// 種類をチェックする
	if (type != REG_SZ && type != REG_EXPAND_SZ)
	{
		// 文字列以外である
		Free(ret);

		return NULL;
	}

	if (ret[size / sizeof(wchar_t) - 1] != 0)
	{
		// データ不正
		Free(ret);
		return NULL;
	}

	return ret;
}

// 値を読み込む
bool MsRegReadValue(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size)
{
	return MsRegReadValueEx(root, keyname, valuename, data, type, size, false);
}
bool MsRegReadValueEx(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit)
{
	return MsRegReadValueEx2(root, keyname, valuename, data, type, size, force32bit, false);
}
bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	// 引数チェック
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	// キーを開く
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// 値を開く
	*data = ZeroMalloc(*size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		// 読み取り完了
		RegCloseKey(h);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		// 変なエラーが発生した
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
		return false;
	}

	// メモリを再確保してデータを取得
	*data = ReAlloc(*data, *size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		// エラー発生
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
	}

	RegCloseKey(h);

	return true;
}
bool MsRegReadValueW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size)
{
	return MsRegReadValueExW(root, keyname, valuename, data, type, size, false);
}
bool MsRegReadValueExW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit)
{
	return MsRegReadValueEx2W(root, keyname, valuename, data, type, size, force32bit, false);
}
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	wchar_t valuename_w[MAX_SIZE];
	// 引数チェック
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (IsNt() == false)
	{
		bool ret;
		void *data_a = NULL;
		UINT type_a = 0, size_a = 0;

		ret = MsRegReadValueEx2(root, keyname, valuename, &data_a, &type_a, &size_a, force32bit, force64bit);

		if (ret != false)
		{
			if (type_a == REG_SZ || type_a == REG_MULTI_SZ || type_a == REG_EXPAND_SZ)
			{
				*data = CopyStrToUni(data_a);
				Free(data_a);

				size_a = UniStrSize(*data);
			}
			else
			{
				*data = data_a;
			}

			*type = type_a;
			*size = size_a;
		}

		return ret;
	}

	StrToUni(valuename_w, sizeof(valuename_w), valuename);

	// キーを開く
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// 値を開く
	*data = ZeroMalloc(*size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		// 読み取り完了
		RegCloseKey(h);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		// 変なエラーが発生した
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
		return false;
	}

	// メモリを再確保してデータを取得
	*data = ReAlloc(*data, *size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		// エラー発生
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
	}

	RegCloseKey(h);

	return true;
}

// 値の種類とサイズを取得する
bool MsRegGetValueTypeAndSize(UINT root, char *keyname, char *valuename, UINT *type, UINT *size)
{
	return MsRegGetValueTypeAndSizeEx(root, keyname, valuename, type, size, false);
}
bool MsRegGetValueTypeAndSizeEx(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit)
{
	return MsRegGetValueTypeAndSizeEx2(root, keyname, valuename, type, size, force32bit, false);
}
bool MsRegGetValueTypeAndSizeEx2(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	// 引数チェック
	if (keyname == NULL)
	{
		return false;
	}
	if (type != NULL)
	{
		*type = 0;
	}
	if (size != NULL)
	{
		*size = 0;
	}

	// キーを開く
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// 値を開く
	ret = RegQueryValueEx(h, valuename, 0, type, NULL, size);

	if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA)
	{
		RegCloseKey(h);
		return true;
	}

	RegCloseKey(h);

	return false;
}
bool MsRegGetValueTypeAndSizeW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size)
{
	return MsRegGetValueTypeAndSizeExW(root, keyname, valuename, type, size, false);
}
bool MsRegGetValueTypeAndSizeExW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit)
{
	return MsRegGetValueTypeAndSizeEx2W(root, keyname, valuename, type, size, force32bit, false);
}
bool MsRegGetValueTypeAndSizeEx2W(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	wchar_t valuename_w[MAX_SIZE];
	// 引数チェック
	if (keyname == NULL)
	{
		return false;
	}
	if (type != NULL)
	{
		*type = 0;
	}
	if (size != NULL)
	{
		*size = 0;
	}
	if (IsNt() == false)
	{
		UINT type_a = 0;
		UINT size_a = 0;

		bool ret = MsRegGetValueTypeAndSizeEx2(root, keyname, valuename, &type_a, &size_a, force32bit, force64bit);

		if (type_a == REG_SZ || type_a == REG_MULTI_SZ || type_a == REG_EXPAND_SZ)
		{
			size_a = size_a * sizeof(wchar_t);
		}

		if (type != NULL)
		{
			*type = type_a;
		}

		if (size != NULL)
		{
			*size = size_a;
		}

		return ret;
	}

	StrToUni(valuename_w, sizeof(valuename_w), valuename);

	// キーを開く
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// 値を開く
	ret = RegQueryValueExW(h, valuename_w, 0, type, NULL, size);

	if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA)
	{
		RegCloseKey(h);
		return true;
	}

	RegCloseKey(h);

	return false;
}

// 指定された値がレジストリに存在するかどうか確認する
bool MsRegIsValue(UINT root, char *keyname, char *valuename)
{
	return MsRegIsValueEx(root, keyname, valuename, false);
}
bool MsRegIsValueEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegIsValueEx2(root, keyname, valuename, force32bit, false);
}
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT type, size;
	UINT ret;
	// 引数チェック
	if (keyname == NULL)
	{
		return false;
	}

	// キーを開く
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// 値を開く
	size = 0;
	ret = RegQueryValueEx(h, valuename, 0, &type, NULL, &size);

	if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA)
	{
		RegCloseKey(h);
		return true;
	}

	RegCloseKey(h);

	return false;
}

// レジストリにキーを作成する
bool MsRegNewKey(UINT root, char *keyname)
{
	return MsRegNewKeyEx(root, keyname, false);
}
bool MsRegNewKeyEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegNewKeyEx2(root, keyname, force32bit, false);
}
bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	// 引数チェック
	if (keyname == NULL)
	{
		return false;
	}

	// キーが存在するかどうか確認する
	if (MsRegIsKeyEx2(root, keyname, force32bit, force64bit))
	{
		// すでに存在している
		return true;
	}

	// キーを作成する
	if (RegCreateKeyEx(MsGetRootKeyFromInt(root), keyname, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), NULL, &h, NULL) != ERROR_SUCCESS)
	{
		// 失敗
		return false;
	}

	RegCloseKey(h);

	return true;
}

// 指定されたキーがレジストリに存在するかどうか確認する
bool MsRegIsKey(UINT root, char *name)
{
	return MsRegIsKeyEx(root, name, false);
}
bool MsRegIsKeyEx(UINT root, char *name, bool force32bit)
{
	return MsRegIsKeyEx2(root, name, force32bit, false);
}
bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit)
{
	HKEY h;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), name, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

// ルートキーハンドルの取得
HKEY MsGetRootKeyFromInt(UINT root)
{
	switch (root)
	{
	case REG_CLASSES_ROOT:
		return HKEY_CLASSES_ROOT;

	case REG_LOCAL_MACHINE:
		return HKEY_LOCAL_MACHINE;

	case REG_CURRENT_USER:
		return HKEY_CURRENT_USER;

	case REG_USERS:
		return HKEY_USERS;
	}

	return NULL;
}

// コマンドライン文字列から実行ファイル名の部分をカットする (Unicode 版)
wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	if (str[0] != L'\"')
	{
		UINT i = UniSearchStrEx(str, L" ", 0, true);
		if (i == INFINITE)
		{
			return str + UniStrLen(str);
		}
		else
		{
			return str + i + 1;
		}
	}
	else
	{
		str++;
		while (true)
		{
			if ((*str) == 0)
			{
				return str + UniStrLen(str);
			}
			if ((*str) == L'\"')
			{
				break;
			}
			str++;
		}

		while (true)
		{
			if ((*str) == 0)
			{
				return str + UniStrLen(str);
			}
			if ((*str) == L' ')
			{
				return str + 1;
			}
			str++;
		}
	}
}

// コマンドライン文字列から実行ファイル名の部分をカットする
char *MsCutExeNameFromCommandLine(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	if (str[0] != '\"')
	{
		UINT i = SearchStrEx(str, " ", 0, true);
		if (i == INFINITE)
		{
			return str + StrLen(str);
		}
		else
		{
			return str + i + 1;
		}
	}
	else
	{
		str++;
		while (true)
		{
			if ((*str) == 0)
			{
				return str + StrLen(str);
			}
			if ((*str) == '\"')
			{
				break;
			}
			str++;
		}

		while (true)
		{
			if ((*str) == 0)
			{
				return str + StrLen(str);
			}
			if ((*str) == ' ')
			{
				return str + 1;
			}
			str++;
		}
	}
}

// プロセスハンドルの取得
void *MsGetCurrentProcess()
{
	return ms->hCurrentProcess;
}

// プロセス ID の取得
UINT MsGetCurrentProcessId()
{
	return ms->CurrentProcessId;
}

// EXE ファイル名の取得
char *MsGetExeFileName()
{
	return ms == NULL ? "Unknown" : ms->ExeFileName;
}

// EXE ファイルが置いてあるディレクトリ名の取得
char *MsGetExeDirName()
{
	return ms->ExeFileDir;
}
wchar_t *MsGetExeDirNameW()
{
	return ms->ExeFileDirW;
}

// 特殊なディレクトリ名の取得
char *MsGetSpecialDir(int id)
{
	LPITEMIDLIST t = NULL;
	char tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return CopyStr(ms->ExeFileDir);
	}

	if (SHGetPathFromIDList(t, tmp) == false)
	{
		return CopyStr(ms->ExeFileDir);
	}

	Win32NukuEn(tmp, sizeof(tmp), tmp);

	return CopyStr(tmp);
}
wchar_t *MsGetSpecialDirW(int id)
{
	LPITEMIDLIST t = NULL;
	wchar_t tmp[MAX_PATH];

	if (IsNt() == false)
	{
		char *tmp = MsGetSpecialDir(id);
		wchar_t *ret = CopyStrToUni(tmp);

		Free(tmp);

		return ret;
	}

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	if (SHGetPathFromIDListW(t, tmp) == false)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	Win32NukuEnW(tmp, sizeof(tmp), tmp);

	return UniCopyStr(tmp);
}

// 特殊なディレクトリをすべて取得する
void MsGetSpecialDirs()
{
	char tmp[MAX_PATH];

	// System32
	GetSystemDirectory(tmp, sizeof(tmp));
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->System32Dir = CopyStr(tmp);
	ms->System32DirW = CopyStrToUni(tmp);

	// Windows ディレクトリは System32 ディレクトリの 1 つ上にある
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->WindowsDir = CopyStr(tmp);
	ms->WindowsDirW = CopyStrToUni(tmp);

	// Windows ディレクトリの下の Temp ディレクトリ
	Format(tmp, sizeof(tmp), "%s\\Temp", ms->WindowsDir);
	ms->WinTempDir = CopyStr(tmp);
	ms->WinTempDirW = CopyStrToUni(tmp);
	MsUniMakeDirEx(ms->WinTempDirW);

	// システムドライブ
	tmp[2] = 0;
	ms->WindowsDrive = CopyStr(tmp);
	ms->WindowsDriveW = CopyStrToUni(tmp);

	// Temp
	GetTempPath(MAX_PATH, tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->TempDir = CopyStr(tmp);

	// Temp (Unicode) の取得
	if (IsNt())
	{
		wchar_t tmp_w[MAX_PATH];

		GetTempPathW(MAX_PATH, tmp_w);
		Win32NukuEnW(tmp_w, sizeof(tmp_w), tmp_w);

		ms->TempDirW = CopyUniStr(tmp_w);
	}
	else
	{
		ms->TempDirW = CopyStrToUni(tmp);
	}
	MakeDirExW(ms->TempDirW);
	MakeDirEx(ms->TempDir);

	// Program Files
	ms->ProgramFilesDir = MsGetSpecialDir(CSIDL_PROGRAM_FILES);
	if (StrCmpi(ms->ProgramFilesDir, ms->ExeFileDir) == 0)
	{
		char tmp[MAX_PATH];
		Format(tmp, sizeof(tmp), "%s\\Program Files", ms->WindowsDrive);

		Free(ms->ProgramFilesDir);
		ms->ProgramFilesDir = CopyStr(tmp);
	}

	ms->ProgramFilesDirW = MsGetSpecialDirW(CSIDL_PROGRAM_FILES);
	if (UniStrCmpi(ms->ProgramFilesDirW, ms->ExeFileDirW) == 0)
	{
		wchar_t tmp[MAX_PATH];
		UniFormat(tmp, sizeof(tmp), L"%s\\Program Files", ms->WindowsDriveW);

		Free(ms->ProgramFilesDirW);
		ms->ProgramFilesDirW = UniCopyStr(tmp);
	}

	if (MsIsNt())
	{
		// 共通のスタートメニュー
		ms->CommonStartMenuDir = MsGetSpecialDir(CSIDL_COMMON_STARTMENU);
		ms->CommonStartMenuDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTMENU);

		// 共通のプログラム
		ms->CommonProgramsDir = MsGetSpecialDir(CSIDL_COMMON_PROGRAMS);
		ms->CommonProgramsDirW = MsGetSpecialDirW(CSIDL_COMMON_PROGRAMS);

		// 共通のスタートアップ
		ms->CommonStartupDir = MsGetSpecialDir(CSIDL_COMMON_STARTUP);
		ms->CommonStartupDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTUP);

		// 共通のアプリケーションデータ
		ms->CommonAppDataDir = MsGetSpecialDir(CSIDL_COMMON_APPDATA);
		ms->CommonAppDataDirW = MsGetSpecialDirW(CSIDL_COMMON_APPDATA);

		// 共通のデスクトップ
		ms->CommonDesktopDir = MsGetSpecialDir(CSIDL_COMMON_DESKTOPDIRECTORY);
		ms->CommonDesktopDirW = MsGetSpecialDirW(CSIDL_COMMON_DESKTOPDIRECTORY);

		// Local Settings
		ms->LocalAppDataDir = MsGetSpecialDir(CSIDL_LOCAL_APPDATA);
		ms->LocalAppDataDirW = MsGetSpecialDirW(CSIDL_LOCAL_APPDATA);
	}
	else
	{
		// 個別のスタートメニュー
		ms->PersonalStartMenuDir = MsGetSpecialDir(CSIDL_STARTMENU);
		ms->CommonStartMenuDir = CopyStr(ms->PersonalStartMenuDir);
		ms->PersonalStartMenuDirW = MsGetSpecialDirW(CSIDL_STARTMENU);
		ms->CommonStartMenuDirW = CopyUniStr(ms->PersonalStartMenuDirW);

		// 個別のプログラム
		ms->PersonalProgramsDir = MsGetSpecialDir(CSIDL_PROGRAMS);
		ms->CommonProgramsDir = CopyStr(ms->PersonalProgramsDir);
		ms->PersonalProgramsDirW = MsGetSpecialDirW(CSIDL_PROGRAMS);
		ms->CommonProgramsDirW = CopyUniStr(ms->PersonalProgramsDirW);

		// 個別のスタートアップ
		ms->PersonalStartupDir = MsGetSpecialDir(CSIDL_STARTUP);
		ms->CommonStartupDir = CopyStr(ms->PersonalStartupDir);
		ms->PersonalStartupDirW = MsGetSpecialDirW(CSIDL_STARTUP);
		ms->CommonStartupDirW = CopyUniStr(ms->PersonalStartupDirW);

		// 個別のアプリケーションデータ
		ms->PersonalAppDataDir = MsGetSpecialDir(CSIDL_APPDATA);
		ms->CommonAppDataDir = CopyStr(ms->PersonalAppDataDir);
		ms->PersonalAppDataDirW = MsGetSpecialDirW(CSIDL_APPDATA);
		ms->CommonAppDataDirW = CopyUniStr(ms->PersonalAppDataDirW);

		// 個別のデスクトップ
		ms->PersonalDesktopDir = MsGetSpecialDir(CSIDL_DESKTOP);
		ms->CommonDesktopDir = CopyStr(ms->PersonalDesktopDir);
		ms->PersonalDesktopDirW = MsGetSpecialDirW(CSIDL_DESKTOP);
		ms->CommonDesktopDirW = CopyUniStr(ms->PersonalDesktopDirW);

		// Local Settings
		ms->LocalAppDataDir = CopyStr(ms->PersonalAppDataDir);
		ms->LocalAppDataDirW = CopyUniStr(ms->PersonalAppDataDirW);
	}
}

// 現在のユーザーが Administrators かどうかチェックする
bool MsCheckIsAdmin()
{
	UCHAR test_bit[32];
	UCHAR tmp[32];
	char *name = "Vpn_Check_Admin_Key";
	DWORD type;
	DWORD size;
	Rand(test_bit, sizeof(test_bit));

	if (RegSetValueEx(HKEY_LOCAL_MACHINE, name, 0, REG_BINARY, test_bit, sizeof(test_bit)) != ERROR_SUCCESS)
	{
		return false;
	}

	size = sizeof(tmp);
	if (RegQueryValueEx(HKEY_LOCAL_MACHINE, name, 0, &type, tmp, &size) != ERROR_SUCCESS)
	{
		return false;
	}

	RegDeleteValue(HKEY_LOCAL_MACHINE, name);

	if (Cmp(test_bit, tmp, 32) != 0)
	{
		return false;
	}

	return true;
}

// ライブラリの初期化
void MsInit()
{
	char *str_ansi;
	wchar_t *str_unicode;
	OSVERSIONINFO os;
	char tmp[MAX_SIZE];
	UINT size;
	if (ms != NULL)
	{
		// すでに初期化されている
		return;
	}

	ms = ZeroMalloc(sizeof(MS));

	// インスタンスハンドルの取得
	ms->hInst = GetModuleHandleA(NULL);

	// KERNEL32.DLL の取得
	ms->hKernel32 = LoadLibrary("kernel32.dll");

	// OS からコマンドライン文字列を取得する
	str_ansi = CopyStr(GetCommandLineA());
	Trim(str_ansi);
	str_unicode = UniCopyStr(GetCommandLineW());
	UniTrim(str_unicode);

	SetCommandLineStr(MsCutExeNameFromCommandLine(str_ansi));
	SetCommandLineUniStr(MsCutExeNameFromUniCommandLine(str_unicode));

	Free(str_unicode);
	Free(str_ansi);

	// OS のバージョンを取得する
	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	GetVersionEx(&os);

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		// NT 系
		ms->IsNt = true;

		ms->nt = MsLoadNtApiFunctions();

		if (ms->nt == NULL)
		{
			ms->IsNt = false;
			ms->IsAdmin = true;
		}
		else
		{
			// Administrators 判定
			ms->IsAdmin = MsCheckIsAdmin();
		}
	}
	else
	{
		// 9x 系: 常に Administrators を偽装
		ms->IsAdmin = true;
	}

	// 現在のプロセスに関する情報を取得する
	ms->hCurrentProcess = GetCurrentProcess();
	ms->CurrentProcessId = GetCurrentProcessId();

	// EXE ファイル名を取得
	GetModuleFileName(NULL, tmp, sizeof(tmp));
	ms->ExeFileName = CopyStr(tmp);
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	ms->ExeFileDir = CopyStr(tmp);

	// EXE ファイル名 (Unicode) を取得
	if (IsNt())
	{
		wchar_t tmp_w[MAX_PATH];

		GetModuleFileNameW(NULL, tmp_w, sizeof(tmp_w));
		ms->ExeFileNameW = CopyUniStr(tmp_w);

		Win32GetDirFromPathW(tmp_w, sizeof(tmp_w), tmp_w);
		ms->ExeFileDirW = CopyUniStr(tmp_w);
	}
	else
	{
		ms->ExeFileNameW = CopyStrToUni(ms->ExeFileName);
		ms->ExeFileDirW = CopyStrToUni(ms->ExeFileDir);
	}

	// 特殊なディレクトリを取得
	MsGetSpecialDirs();

	// 一時ディレクトリの初期化
	MsInitTempDir();

	// ユーザー名の取得
	size = sizeof(tmp);
	GetUserName(tmp, &size);
	ms->UserName = CopyStr(tmp);

	// ユーザー名の取得 (Unicode)
	if (IsNt())
	{
		wchar_t tmp_w[MAX_PATH];

		size = sizeof(tmp_w);

		GetUserNameW(tmp_w, &size);
		ms->UserNameW = CopyUniStr(tmp_w);
	}
	else
	{
		ms->UserNameW = CopyStrToUni(ms->UserName);
	}

	// フルユーザー名の取得
	if (ms->nt != NULL && ms->nt->GetUserNameExA != NULL)
	{
		wchar_t tmp_w[MAX_PATH];

		size = sizeof(tmp);
		if (ms->nt->GetUserNameExA(NameSamCompatible, tmp, &size))
		{
			ms->UserNameEx = CopyStr(tmp);
		}

		size = sizeof(tmp_w);
		if (ms->nt->GetUserNameExW(NameSamCompatible, tmp_w, &size))
		{
			ms->UserNameExW = CopyUniStr(tmp_w);
		}
	}

	if (ms->UserNameEx == NULL)
	{
		ms->UserNameEx = CopyStr(ms->UserName);
	}
	if (ms->UserNameExW == NULL)
	{
		ms->UserNameExW = CopyUniStr(ms->UserNameW);
	}

	ms_critical_section = ZeroMalloc(sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(ms_critical_section);

	// アダプタリストの初期化
	MsInitAdapterListModule();

	// minidump ベースファイル名の初期化
	if (true)
	{
		wchar_t tmp[MAX_PATH];
		if (MsIsAdmin())
		{
			CombinePathW(tmp, sizeof(tmp), ms->ExeFileDirW, L"vpn_debug\\dump");
		}
		else
		{
			CombinePathW(tmp, sizeof(tmp), ms->TempDirW, L"vpn_debug\\dump");
		}
		ms->MinidumpBaseFileNameW = CopyUniStr(tmp);
	}

	MsSetEnableMinidump(true);

	if (MsIsNt())
	{
		if (ms->nt->MiniDumpWriteDump != NULL)
		{
			SetUnhandledExceptionFilter(MsExceptionHandler);
		}
	}
}

// minidump を作成するかどうか選択する
void MsSetEnableMinidump(bool enabled)
{
	ms->MiniDumpEnabled = enabled;
}

// minidump を出力する
void MsWriteMinidump(wchar_t *filename, void *ex)
{
	wchar_t tmp[MAX_PATH];
	wchar_t dir[MAX_PATH];
	HANDLE h;
	MINIDUMP_EXCEPTION_INFORMATION info;
	struct _EXCEPTION_POINTERS *exp = (struct _EXCEPTION_POINTERS *)ex;

	if (filename != NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}
	else
	{
		SYSTEMTIME tm;

		Zero(&tm, sizeof(tm));
		GetLocalTime(&tm);

		UniFormat(tmp, sizeof(tmp), L"%s_%04u%02u%02u_%02u%02u%02u.dmp",
			ms->MinidumpBaseFileNameW,
			tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond);
	}

	GetDirNameFromFilePathW(dir, sizeof(dir), tmp);

	CreateDirectoryW(dir, NULL);

	Zero(&info, sizeof(info));

	if (exp != NULL)
	{
		info.ThreadId = GetCurrentThreadId();
		info.ExceptionPointers = exp;
		info.ClientPointers = true;
	}

	h = CreateFileW(tmp, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		ms->nt->MiniDumpWriteDump(ms->hCurrentProcess, ms->CurrentProcessId,
			h,
			MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithDataSegs |
			MiniDumpWithHandleData
			,
			info.ThreadId == 0 ? NULL : &info, NULL, NULL);

		FlushFileBuffers(h);
		CloseHandle(h);
	}
}

// 例外ハンドラ
LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (ms->MiniDumpEnabled)
	{
		MsWriteMinidump(NULL, ExceptionInfo);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

// ライブラリの解放
void MsFree()
{
	if (ms == NULL)
	{
		// 初期化されていない
		return;
	}

	// アダプタリストの解放
	MsFreeAdapterListModule();

	// 一時ディレクトリの解放
	MsFreeTempDir();

	if (ms->IsNt)
	{
		// NT 系 API の解放
		MsFreeNtApiFunctions(ms->nt);
	}

	// メモリ解放
	// ANSI
	Free(ms->WindowsDir);
	Free(ms->System32Dir);
	Free(ms->TempDir);
	Free(ms->WinTempDir);
	Free(ms->WindowsDrive);
	Free(ms->ProgramFilesDir);
	Free(ms->CommonStartMenuDir);
	Free(ms->CommonProgramsDir);
	Free(ms->CommonStartupDir);
	Free(ms->CommonAppDataDir);
	Free(ms->CommonDesktopDir);
	Free(ms->PersonalStartMenuDir);
	Free(ms->PersonalProgramsDir);
	Free(ms->PersonalStartupDir);
	Free(ms->PersonalAppDataDir);
	Free(ms->PersonalDesktopDir);
	Free(ms->MyDocumentsDir);
	Free(ms->ExeFileDir);
	Free(ms->ExeFileName);
	Free(ms->UserName);
	Free(ms->UserNameEx);
	Free(ms->LocalAppDataDir);
	// Unicode
	Free(ms->WindowsDirW);
	Free(ms->System32DirW);
	Free(ms->TempDirW);
	Free(ms->WinTempDirW);
	Free(ms->WindowsDriveW);
	Free(ms->ProgramFilesDirW);
	Free(ms->CommonStartMenuDirW);
	Free(ms->CommonProgramsDirW);
	Free(ms->CommonStartupDirW);
	Free(ms->CommonAppDataDirW);
	Free(ms->CommonDesktopDirW);
	Free(ms->PersonalStartMenuDirW);
	Free(ms->PersonalProgramsDirW);
	Free(ms->PersonalStartupDirW);
	Free(ms->PersonalAppDataDirW);
	Free(ms->PersonalDesktopDirW);
	Free(ms->MyDocumentsDirW);
	Free(ms->ExeFileDirW);
	Free(ms->ExeFileNameW);
	Free(ms->UserNameW);
	Free(ms->UserNameExW);
	Free(ms->LocalAppDataDirW);
	Free(ms->MinidumpBaseFileNameW);
	Free(ms);
	ms = NULL;

	Free(ms_critical_section);
	ms_critical_section = NULL;
}

// ディレクトリ取得関係
char *MsGetCommonAppDataDir()
{
	return ms->CommonAppDataDir;
}
char *MsGetLocalAppDataDir()
{
	return ms->LocalAppDataDir;
}
char *MsGetWindowsDir()
{
	return ms->WindowsDir;
}
wchar_t *MsGetWindowsDirW()
{
	return ms->WindowsDirW;
}
char *MsGetSystem32Dir()
{
	return ms->System32Dir;
}
char *MsGetTempDir()
{
	return ms->TempDir;
}
char *MsGetWindowsDrive()
{
	return ms->WindowsDrive;
}
char *MsGetProgramFilesDir()
{
	return ms->ProgramFilesDir;
}
char *MsGetCommonStartMenuDir()
{
	return ms->CommonStartMenuDir;
}
char *MsGetCommonProgramsDir()
{
	return ms->CommonProgramsDir;
}
char *MsGetCommonStartupDir()
{
	return ms->CommonStartupDir;
}
char *MsGetCommonDesktopDir()
{
	return ms->CommonDesktopDir;
}
char *MsGetPersonalStartMenuDir()
{
	if (ms->PersonalStartMenuDir == NULL)
	{
		ms->PersonalStartMenuDir = MsGetSpecialDir(CSIDL_STARTMENU);
	}
	return ms->PersonalStartMenuDir;
}
char *MsGetPersonalProgramsDir()
{
	if (ms->PersonalProgramsDir == NULL)
	{
		ms->PersonalProgramsDir = MsGetSpecialDir(CSIDL_PROGRAMS);
	}
	return ms->PersonalProgramsDir;
}
char *MsGetPersonalStartupDir()
{
	if (ms->PersonalStartupDir == NULL)
	{
		ms->PersonalStartupDir = MsGetSpecialDir(CSIDL_STARTUP);
	}
	return ms->PersonalStartupDir;
}
char *MsGetPersonalAppDataDir()
{
	if (ms->PersonalAppDataDir == NULL)
	{
		ms->PersonalAppDataDir = MsGetSpecialDir(CSIDL_APPDATA);
	}
	return ms->PersonalAppDataDir;
}
char *MsGetPersonalDesktopDir()
{
	if (ms->PersonalDesktopDir == NULL)
	{
		ms->PersonalDesktopDir = MsGetSpecialDir(CSIDL_DESKTOP);
	}
	return ms->PersonalDesktopDir;
}
char *MsGetMyDocumentsDir()
{
	if (ms->MyDocumentsDir == NULL)
	{
		ms->MyDocumentsDir = MsGetSpecialDir(CSIDL_PERSONAL);
	}
	return ms->MyDocumentsDir;
}
char *MsGetMyTempDir()
{
	return ms->MyTempDir;
}
char *MsGetUserName()
{
	return ms->UserName;
}
char *MsGetUserNameEx()
{
	return ms->UserNameEx;
}
char *MsGetWinTempDir()
{
	return ms->WinTempDir;
}

wchar_t *MsGetExeFileNameW()
{
	return ms == NULL ? L"Unknown" : ms->ExeFileNameW;
}
wchar_t *MsGetExeFileDirW()
{
	return ms->ExeFileDirW;
}
wchar_t *MsGetWindowDirW()
{
	return ms->WindowsDirW;
}
wchar_t *MsGetSystem32DirW()
{
	return ms->System32DirW;
}
wchar_t *MsGetTempDirW()
{
	return ms->TempDirW;
}
wchar_t *MsGetWindowsDriveW()
{
	return ms->WindowsDriveW;
}
wchar_t *MsGetProgramFilesDirW()
{
	return ms->ProgramFilesDirW;
}
wchar_t *MsGetCommonStartMenuDirW()
{
	return ms->CommonStartMenuDirW;
}
wchar_t *MsGetCommonProgramsDirW()
{
	return ms->CommonProgramsDirW;
}
wchar_t *MsGetCommonStartupDirW()
{
	return ms->CommonStartupDirW;
}
wchar_t *MsGetCommonAppDataDirW()
{
	return ms->CommonAppDataDirW;
}
wchar_t *MsGetCommonDesktopDirW()
{
	return ms->CommonDesktopDirW;
}
wchar_t *MsGetPersonalStartMenuDirW()
{
	if (ms->PersonalStartMenuDirW == NULL)
	{
		ms->PersonalStartMenuDirW = MsGetSpecialDirW(CSIDL_STARTMENU);
	}

	return ms->PersonalStartMenuDirW;
}
wchar_t *MsGetPersonalProgramsDirW()
{
	if (ms->PersonalProgramsDirW == NULL)
	{
		ms->PersonalProgramsDirW = MsGetSpecialDirW(CSIDL_PROGRAMS);
	}

	return ms->PersonalProgramsDirW;
}
wchar_t *MsGetPersonalStartupDirW()
{
	if (ms->PersonalStartupDirW == NULL)
	{
		ms->PersonalStartupDirW = MsGetSpecialDirW(CSIDL_STARTUP);
	}

	return ms->PersonalStartupDirW;
}
wchar_t *MsGetPersonalAppDataDirW()
{
	if (ms->PersonalAppDataDirW == NULL)
	{
		ms->PersonalAppDataDirW = MsGetSpecialDirW(CSIDL_APPDATA);
	}

	return ms->PersonalAppDataDirW;
}
wchar_t *MsGetPersonalDesktopDirW()
{
	if (ms->PersonalDesktopDirW == NULL)
	{
		ms->PersonalDesktopDirW = MsGetSpecialDirW(CSIDL_DESKTOP);
	}

	return ms->PersonalDesktopDirW;
}
wchar_t *MsGetMyDocumentsDirW()
{
	if (ms->MyDocumentsDirW == NULL)
	{
		ms->MyDocumentsDirW = MsGetSpecialDirW(CSIDL_PERSONAL);
	}

	return ms->MyDocumentsDirW;
}
wchar_t *MsGetLocalAppDataDirW()
{
	return ms->LocalAppDataDirW;
}
wchar_t *MsGetMyTempDirW()
{
	return ms->MyTempDirW;
}
wchar_t *MsGetUserNameW()
{
	return ms->UserNameW;
}
wchar_t *MsGetUserNameExW()
{
	return ms->UserNameExW;
}
wchar_t *MsGetWinTempDirW()
{
	return ms->WinTempDirW;
}


#endif	// WIN32

