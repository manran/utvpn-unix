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

// Mayaqua.c
// Mayaqua Kernel プログラム

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// グローバル変数
bool g_memcheck;								// メモリチェックの有効化
bool g_debug;									// デバッグモード
UINT64 kernel_status[NUM_KERNEL_STATUS];		// カーネル状態
UINT64 kernel_status_max[NUM_KERNEL_STATUS];	// カーネル状態 (最大値)
LOCK *kernel_status_lock[NUM_KERNEL_STATUS];	// カーネル状態ロック
BOOL kernel_status_inited = false;				// カーネル状態初期化フラグ
bool g_little_endian = true;
char *cmdline = NULL;							// コマンドライン
wchar_t *uni_cmdline = NULL;					// Unicode コマンドライン

// スタティック変数
static char *exename = NULL;						// EXE ファイル名 (ANSI)
static wchar_t *exename_w = NULL;					// EXE ファイル名 (Unicode)
static TOKEN_LIST *cmdline_token = NULL;			// コマンドライントークン
static UNI_TOKEN_LIST *cmdline_uni_token = NULL;	// コマンドライントークン (Unicode)
static OS_INFO *os_info = NULL;						// OS 情報
static bool dot_net_mode = false;
static bool minimal_mode = false;
static UINT last_time_check = 0;
static UINT first_time_check = 0;
static bool is_nt = false;
static bool is_ham_mode = false;
static UINT init_mayaqua_counter = 0;
static bool use_probe = false;
static BUF *probe_buf = NULL;
static LOCK *probe_lock = NULL;
static UINT64 probe_start = 0;
static UINT64 probe_last = 0;
static bool probe_enabled = false;

// チェックサムを計算する
USHORT CalcChecksum16(void *buf, UINT size)
{
	int sum = 0;
	USHORT *addr = (USHORT *)buf;
	int len = (int)size;
	USHORT *w = addr;
	int nleft = len;
	USHORT answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(UCHAR *)(&answer) = *(UCHAR *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	answer = ~sum;

	return answer;
}

// データ付き Probe の書き込み
void WriteProbeData(char *filename, UINT line, char *str, void *data, UINT size)
{
	char tmp[MAX_SIZE];
	USHORT cs;

	if (IsProbeEnabled() == false)
	{
		return;
	}

	// データのチェックサムをとる
	if (size != 0)
	{
		cs = CalcChecksum16(data, size);
	}
	else
	{
		cs = 0;
	}

	// 文字列の生成
	snprintf(tmp, sizeof(tmp), "\"%s\" (Size=%5u, Crc=0x%04X)", str, size, cs);

	WriteProbe(filename, line, tmp);
}

// Probe の書き込み
void WriteProbe(char *filename, UINT line, char *str)
{
#ifdef	OS_WIN32
	char *s;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UINT64 now = 0;
	UINT64 time;

	if (IsProbeEnabled() == false)
	{
		return;
	}

	now = MsGetHiResCounter();

	Lock(probe_lock);
	{
		UINT64 diff;
		
		time = MsGetHiResTimeSpanUSec(now - probe_start);

		diff = time - probe_last;

		if (time < probe_last)
		{
			diff = 0;
		}

		probe_last = time;

		ToStr64(tmp, time);
		MakeCharArray2(tmp2, ' ', (UINT)(MIN(12, (int)12 - (int)StrLen(tmp))));
		WriteBuf(probe_buf, tmp2, StrLen(tmp2));
		WriteBuf(probe_buf, tmp, StrLen(tmp));

		s = " [+";
		WriteBuf(probe_buf, s, StrLen(s));

		ToStr64(tmp, diff);
		MakeCharArray2(tmp2, ' ', (UINT)(MIN(12, (int)12 - (int)StrLen(tmp))));
		WriteBuf(probe_buf, tmp2, StrLen(tmp2));
		WriteBuf(probe_buf, tmp, StrLen(tmp));

		s = "] - ";
		WriteBuf(probe_buf, s, StrLen(s));

		WriteBuf(probe_buf, filename, StrLen(filename));

		s = "(";
		WriteBuf(probe_buf, s, StrLen(s));

		ToStr64(tmp, (UINT64)line);
		WriteBuf(probe_buf, tmp, StrLen(tmp));

		s = "): ";
		WriteBuf(probe_buf, s, StrLen(s));

		WriteBuf(probe_buf, str, StrLen(str));

		s = "\r\n";
		WriteBuf(probe_buf, s, StrLen(s));
	}
	Unlock(probe_lock);
#endif	// OS_WIN32
}

// Probe の初期化
void InitProbe()
{
	probe_buf = NewBuf();
	probe_lock = NewLock();
	probe_enabled = false;

	probe_start = 0;

#ifdef	OS_WIN32
	probe_start = MsGetHiResCounter();
#endif	// OS_WIN32
}

// Probe の解放
void FreeProbe()
{
	if (probe_buf->Size >= 1)
	{
		SYSTEMTIME st;
		char filename[MAX_SIZE];

		// ファイルにすべて書き出す
		MakeDirEx("@probe_log");

		LocalTime(&st);

		snprintf(filename, sizeof(filename), "@probe_log/%04u%02u%02u_%02u%02u%02u.log",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

		DumpBuf(probe_buf, filename);
	}

	FreeBuf(probe_buf);
	DeleteLock(probe_lock);
}

// Probe を有効 / 無効にする
void EnableProbe(bool enable)
{
	probe_enabled = enable;
}

// Probe が有効かどうか取得する
bool IsProbeEnabled()
{
#ifndef	USE_PROBE
	return false;
#else	// USE_PROBE
	return probe_enabled;
#endif	// USE_PROBE
}

// Ham モードに設定する
void SetHamMode()
{
	is_ham_mode = true;
}

// Ham モードかどうか取得する
bool IsHamMode()
{
	return is_ham_mode;
}

// 前回の呼び出しから現在までにかかった時間を表示
void TimeCheck()
{
#ifdef OS_WIN32
	UINT now, ret, total;
	now = Win32GetTick();
	if (last_time_check == 0)
	{
		ret = 0;
	}
	else
	{
		ret = now - last_time_check;
	}
	last_time_check = now;

	if (first_time_check == 0)
	{
		first_time_check = now;
	}

	total = now - first_time_check;

	printf(" -- %3.3f / %3.3f\n", (double)ret / 1000.0f, (double)total / 1000.0f);
#endif	// OS_WIN32
}

// IA64 かどうか
bool IsIA64()
{
	if (Is64() == false)
	{
		return false;
	}

#ifndef	MAYAQUA_IA_64
	return false;
#else	// MAYAQUA_IA_64
	return true;
#endif	// MAYAQUA_IA_64
}

// x64 かどうか
bool IsX64()
{
	if (Is64() == false)
	{
		return false;
	}

#ifndef	MAYAQUA_IA_64
	return true;
#else	// MAYAQUA_IA_64
	return false;
#endif	// MAYAQUA_IA_64
}

// 64bit かどうか
bool Is64()
{
#ifdef	CPU_64
	return true;
#else	// CPU_64
	return false;
#endif	// CPU_64
}

// 32bit かどうか
bool Is32()
{
	return Is64() ? false : true;
}

// .NET モード
void MayaquaDotNetMode()
{
	dot_net_mode = true;
}

// .NET モードかどうか取得
bool MayaquaIsDotNetMode()
{
	return dot_net_mode;
}

// エンディアンチェック
void CheckEndian()
{
	unsigned short test;
	UCHAR *buf;

	test = 0x1234;
	buf = (UCHAR *)&test;
	if (buf[0] == 0x12)
	{
		g_little_endian = false;
	}
	else
	{
		g_little_endian = true;
	}
}

// 最小モードにする
void MayaquaMinimalMode()
{
	minimal_mode = true;
}
bool MayaquaIsMinimalMode()
{
	return minimal_mode;
}

// NT かどうか
bool IsNt()
{
	return is_nt;
}

// Unicode をサポートしているかどうか
bool IsUnicode()
{
#ifdef	OS_WIN32
	// Windows
	return IsNt();
#else	// OS_WIN32
	// UNIX
	return true;
#endif	// OS_WIN32
}

// Mayaqua ライブラリの初期化
void InitMayaqua(bool memcheck, bool debug, int argc, char **argv)
{
	wchar_t tmp[MAX_PATH];

	if ((init_mayaqua_counter++) > 0)
	{
		return;
	}

	g_memcheck = memcheck;
	g_debug = debug;
	cmdline = NULL;
	if (dot_net_mode == false)
	{
		// .NET モードでこれを呼ぶとなぜか落ちる
		setbuf(stdout, NULL);
	}

	// NT かどうか取得
#ifdef	OS_WIN32
	is_nt = Win32IsNt();
#endif	// OS_WIN32

	// エンディアンチェック
	CheckEndian();

#ifdef	OS_WIN32
	_configthreadlocale(_DISABLE_PER_THREAD_LOCALE);
#endif	// OS_WIN32

	// CRT のロケール情報を日本語にする
	setlocale(LC_ALL, "");

	// OS の初期化
	OSInit();

	// 乱数の初期化
	srand((UINT)SystemTime64());

	tick_manual_lock = NewLock();

	// FIFO システムの初期化
	InitFifo();

	// カーネルステータスの初期化
	InitKernelStatus();

	// トラッキングの初期化
	InitTracking();

	// スレッドプールの初期化
	InitThreading();

	// 文字列ライブラリの初期化
	InitStringLibrary();

	// ロケール情報の初期化
	SetLocale(NULL);

	// 暗号化ライブラリの初期化
	InitCryptLibrary();

	// リアルタイムクロックの初期化
	InitTick64();

	// ネットワーク通信モジュールの初期化
	InitNetwork();

	// EXE ファイル名の取得の初期化
	InitGetExeName(argc >= 1 ? argv[0] : NULL);

	// コマンドライン文字列の初期化
	InitCommandLineStr(argc, argv);

	// OS 情報の初期化
	InitOsInfo();

	// オペレーティングシステム固有の初期化
#ifdef	OS_WIN32
	MsInit();	// Microsoft Win32
#endif	// OS_WIN32

	// セキュリティトークンモジュールの初期化
	InitSecure();

	if (OSIsSupportedOs() == false)
	{
		// 強制終了
		exit(0);
	}

	// RSA チェック
	if (RsaCheckEx() == false)
	{
		// 強制終了
		Alert("OpenSSL Library Init Failed. (too old?)\nPlease install the latest version of OpenSSL.\n\n", "RsaCheck()");
		exit(0);
	}

	// HamCore ファイルシステムの初期化
	InitHamcore();

	// デフォルトで japanese.stb を読み込む
	LoadTable(DEFAULT_TABLE_FILE_NAME);

	if (exename == NULL)
	{
		// 実行可能ファイル名
		exename = CopyStr("unknown");
	}

	// 自分自身の実行可能ファイル名が見つかるかどうか検査する
	// (見つからない場合は変なパスで起動されているので終了する)
	GetExeNameW(tmp, sizeof(tmp));
	if (IsFileExistsW(tmp) == false)
	{
		wchar_t tmp2[MAX_SIZE];

		UniFormat(tmp2, sizeof(tmp2),
			L"Error: Executable binary file \"%s\" not found.\r\n\r\n"
			L"Please execute program with full path.\r\n",
			tmp);

		AlertW(tmp2, NULL);
		_exit(0);
	}

	CheckUnixTempDir();

	// Probe の初期化
	InitProbe();
}

// Mayaqua ライブラリの解放
void FreeMayaqua()
{
	if ((--init_mayaqua_counter) > 0)
	{
		return;
	}

	// Probe の解放
	FreeProbe();

	// テーブルを削除
	FreeTable();

	// セキュリティトークンモジュールの解放
	FreeSecure();

	// オペレーティングシステム固有の解放
#ifdef	OS_WIN32
	MsFree();
#endif	// OS_WIN32

	// OS 情報の解放
	FreeOsInfo();

	// HamCore ファイルシステムの解放
	FreeHamcore();

	// コマンドライン文字列の解放
	FreeCommandLineStr();

	// コマンドライントークンの解放
	FreeCommandLineTokens();

	// ネットワーク通信モジュールの解放
	FreeNetwork();

	// リアルタイムクロックの解放
	FreeTick64();

	// 暗号化ライブラリの解放
	FreeCryptLibrary();

	// 文字列ライブラリの解放
	FreeStringLibrary();

	// スレッドプールの解放
	FreeThreading();

#ifndef	VPN_SPEED
	// カーネル状態の表示
	if (g_debug)
	{
		PrintKernelStatus();
	}

	// デバッグ情報の表示
	if (g_memcheck)
	{
		PrintDebugInformation();
	}
#endif	// VPN_SPEED

	// トラッキングの解放
	FreeTracking();

	// カーネルステータスの解放
	FreeKernelStatus();

	DeleteLock(tick_manual_lock);
	tick_manual_lock = NULL;

	// OS の解放
	OSFree();
}

// UNIX で /tmp が使用できるかどうか確認する
void CheckUnixTempDir()
{
	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		char tmp[128], tmp2[64];
		UINT64 now = SystemTime64();
		IO *o;

		MakeDir("/tmp");

		Format(tmp2, sizeof(tmp2), "%I64u", now);

		Format(tmp, sizeof(tmp), "/tmp/.%s", tmp2);

		o = FileCreate(tmp);
		if (o == NULL)
		{
			o = FileOpen(tmp, false);
			if (o == NULL)
			{
				Print("Unable to use /tmp.\n\n");
				exit(0);
				return;
			}
		}

		FileClose(o);

		FileDelete(tmp);
	}
}

// アラートの表示
void Alert(char *msg, char *caption)
{
	OSAlert(msg, caption);
}
void AlertW(wchar_t *msg, wchar_t *caption)
{
	OSAlertW(msg, caption);
}

// OS 情報の表示
void PrintOsInfo(OS_INFO *info)
{
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	Print(
		"OS Type          : %u\n"
		"OS Service Pack  : %u\n"
		"os_is_windows    : %s\n"
		"os_is_windows_nt : %s\n"
		"OS System Name   : %s\n"
		"OS Product Name  : %s\n"
		"OS Vendor Name   : %s\n"
		"OS Version       : %s\n"
		"Kernel Name      : %s\n"
		"Kernel Version   : %s\n",
		info->OsType,
		info->OsServicePack,
		OS_IS_WINDOWS(info->OsType) ? "true" : "false",
		OS_IS_WINDOWS_NT(info->OsType) ? "true" : "false",
		info->OsSystemName,
		info->OsProductName,
		info->OsVendorName,
		info->OsVersion,
		info->KernelName,
		info->KernelVersion);

#ifdef	OS_WIN32
	{
		char *exe, *dir;
		exe = MsGetExeFileName();
		dir = MsGetExeDirName();

		Print(
			"EXE File Path    : %s\n"
			"EXE Dir Path     : %s\n"
			"Process Id       : %u\n"
			"Process Handle   : 0x%X\n",
			exe, dir, MsGetCurrentProcessId(), MsGetCurrentProcess());
	}
#endif	// OS_WIN32
}

// OS 種類の取得
UINT GetOsType()
{
	OS_INFO *i = GetOsInfo();

	if (i == NULL)
	{
		return 0;
	}

	return i->OsType;
}

// OS 情報の取得
OS_INFO *GetOsInfo()
{
	return os_info;
}

// OS 情報の初期化
void InitOsInfo()
{
	if (os_info != NULL)
	{
		return;
	}

	os_info = ZeroMalloc(sizeof(OS_INFO));

	OSGetOsInfo(os_info);
}

// OS 情報の解放
void FreeOsInfo()
{
	if (os_info == NULL)
	{
		return;
	}

	Free(os_info->OsSystemName);
	Free(os_info->OsProductName);
	Free(os_info->OsVendorName);
	Free(os_info->OsVersion);
	Free(os_info->KernelName);
	Free(os_info->KernelVersion);
	Free(os_info);

	os_info = NULL;
}

// Unicode コマンドライントークンの取得
UNI_TOKEN_LIST *GetCommandLineUniToken()
{
	if (cmdline_uni_token == NULL)
	{
		return UniNullToken();
	}
	else
	{
		return UniCopyToken(cmdline_uni_token);
	}
}

// コマンドライントークンの取得
TOKEN_LIST *GetCommandLineToken()
{
	if (cmdline_token == NULL)
	{
		return NullToken();
	}
	else
	{
		return CopyToken(cmdline_token);
	}
}

// コマンドライン文字列をトークンに変換する
void ParseCommandLineTokens()
{
	if (cmdline_token != NULL)
	{
		FreeToken(cmdline_token);
	}
	cmdline_token = ParseCmdLine(cmdline);

	if (cmdline_uni_token != NULL)
	{
		UniFreeToken(cmdline_uni_token);
	}
	cmdline_uni_token = UniParseCmdLine(uni_cmdline);
}

// コマンドライントークンを解放する
void FreeCommandLineTokens()
{
	if (cmdline_token != NULL)
	{
		FreeToken(cmdline_token);
	}
	cmdline_token = NULL;

	if (cmdline_uni_token != NULL)
	{
		UniFreeToken(cmdline_uni_token);
	}
	cmdline_uni_token = NULL;
}

// コマンドライン文字列の初期化
void InitCommandLineStr(int argc, char **argv)
{
	if (argc >= 1)
	{
#ifdef	OS_UNIX
		exename_w = CopyUtfToUni(argv[0]);
		exename = CopyUniToStr(exename_w);
#else	// OS_UNIX
		exename = CopyStr(argv[0]);
		exename_w = CopyStrToUni(exename);
#endif	// OS_UNIX
	}
	if (argc < 2 || argv == NULL)
	{
		// コマンドライン文字列無し
		SetCommandLineStr(NULL);
	}
	else
	{
		// コマンドライン文字列有り
		int i, total_len = 1;
		char *tmp;

		for (i = 1;i < argc;i++)
		{
			total_len += StrLen(argv[i]) * 2 + 32;
		}
		tmp = ZeroMalloc(total_len);

		for (i = 1;i < argc;i++)
		{
			UINT s_size = StrLen(argv[i]) * 2;
			char *s = ZeroMalloc(s_size);
			bool dq = (SearchStrEx(argv[i], " ", 0, true) != INFINITE);
			ReplaceStrEx(s, s_size, argv[i], "\"", "\"\"", true);
			if (dq)
			{
				StrCat(tmp, total_len, "\"");
			}
			StrCat(tmp, total_len, s);
			if (dq)
			{
				StrCat(tmp, total_len, "\"");
			}
			StrCat(tmp, total_len, " ");
			Free(s);
		}

		Trim(tmp);
		SetCommandLineStr(tmp);
		Free(tmp);
	}
}

// コマンドライン文字列の解放
void FreeCommandLineStr()
{
	SetCommandLineStr(NULL);

	if (exename != NULL)
	{
		Free(exename);
		exename = NULL;
	}

	if (exename_w != NULL)
	{
		Free(exename_w);
		exename_w = NULL;
	}
}

// Unicode コマンドライン文字列の取得
wchar_t *GetCommandLineUniStr()
{
	if (uni_cmdline == NULL)
	{
		return UniCopyStr(L"");
	}
	else
	{
		return UniCopyStr(uni_cmdline);
	}
}

// コマンドライン文字列の取得
char *GetCommandLineStr()
{
	if (cmdline == NULL)
	{
		return CopyStr("");
	}
	else
	{
		return CopyStr(cmdline);
	}
}

// Unicode コマンドライン文字列の設定
void SetCommandLineUniStr(wchar_t *str)
{
	if (uni_cmdline != NULL)
	{
		Free(uni_cmdline);
	}
	if (str == NULL)
	{
		uni_cmdline = NULL;
	}
	else
	{
		uni_cmdline = CopyUniStr(str);
	}

	ParseCommandLineTokens();
}

// コマンドライン文字列の設定
void SetCommandLineStr(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		if (cmdline != NULL)
		{
			Free(cmdline);
		}
		cmdline = NULL;
	}
	else
	{
		if (cmdline != NULL)
		{
			Free(cmdline);
		}
		cmdline = CopyStr(str);
	}

	if (cmdline == NULL)
	{
		if (uni_cmdline != NULL)
		{
			Free(uni_cmdline);
			uni_cmdline = NULL;
		}
	}
	else
	{
		if (uni_cmdline != NULL)
		{
			Free(uni_cmdline);
		}
		uni_cmdline = CopyStrToUni(cmdline);
	}

	ParseCommandLineTokens();
}

// カーネルステータスの表示
void PrintKernelStatus()
{
	bool leaked = false;

	Print("\n");
	Print(
		"     --------- Mayaqua Kernel Status ---------\n"
		"        Malloc Count ............... %u\n"
		"        ReAlloc Count .............. %u\n"
		"        Free Count ................. %u\n"
		"        Total Memory Size .......... %I64u bytes\n"
		"      * Current Memory Blocks ...... %u Blocks (Peek: %u)\n"
		"        Total Memory Blocks ........ %u Blocks\n"
		"      * Current MemPool Blocks ..... %u Blocks (Peek: %u)\n"
		"        Total MemPool Mallocs ...... %u Mallocs\n"
		"        Total MemPool ReAllocs ..... %u ReAllocs\n"
		"        NewLock Count .............. %u\n"
		"        DeleteLock Count ........... %u\n"
		"      * Current Lock Objects ....... %u Objects\n"
		"      * Current Locked Objects ..... %u Objects\n"
		"        NewRef Count ............... %u\n"
		"        FreeRef Count .............. %u\n"
		"      * Current Ref Objects ........ %u Objects\n"
		"      * Current Ref Count .......... %u Refs\n"
		"        GetTime Count .............. %u\n"
		"        GetTick Count .............. %u\n"
		"        NewThread Count ............ %u\n"
		"        FreeThread Count ........... %u\n"
		"      * Current Threads ............ %u Threads\n"
		"        Wait For Event Count ....... %u\n\n",
		KS_GET(KS_MALLOC_COUNT),
		KS_GET(KS_REALLOC_COUNT),
		KS_GET(KS_FREE_COUNT),
		KS_GET64(KS_TOTAL_MEM_SIZE),
		KS_GET(KS_CURRENT_MEM_COUNT),
		KS_GETMAX(KS_CURRENT_MEM_COUNT),
		KS_GET(KS_TOTAL_MEM_COUNT),
		KS_GET(KS_MEMPOOL_CURRENT_NUM),
		KS_GETMAX(KS_MEMPOOL_CURRENT_NUM),
		KS_GET(KS_MEMPOOL_MALLOC_COUNT),
		KS_GET(KS_MEMPOOL_REALLOC_COUNT),
		KS_GET(KS_NEWLOCK_COUNT),
		KS_GET(KS_DELETELOCK_COUNT),
		KS_GET(KS_CURRENT_LOCK_COUNT),
		KS_GET(KS_CURRENT_LOCKED_COUNT),
		KS_GET(KS_NEWREF_COUNT),
		KS_GET(KS_FREEREF_COUNT),
		KS_GET(KS_CURRENT_REF_COUNT),
		KS_GET(KS_CURRENT_REFED_COUNT),
		KS_GET(KS_GETTIME_COUNT),
		KS_GET(KS_GETTICK_COUNT),
		KS_GET(KS_NEWTHREAD_COUNT),
		KS_GET(KS_FREETHREAD_COUNT),
		KS_GET(KS_NEWTHREAD_COUNT) - KS_GET(KS_FREETHREAD_COUNT),
		KS_GET(KS_WAIT_COUNT)
		);

	if (KS_GET(KS_CURRENT_MEM_COUNT) != 0 || KS_GET(KS_CURRENT_LOCK_COUNT) != 0 ||
		KS_GET(KS_MEMPOOL_CURRENT_NUM) != 0 ||
		KS_GET(KS_CURRENT_LOCKED_COUNT) != 0 || KS_GET(KS_CURRENT_REF_COUNT) != 0)
	{
		leaked = true;
	}

	if (leaked)
	{
		Print("      !!! MEMORY LEAKS DETECTED !!!\n\n");
		if (g_memcheck == false)
		{
			GetLine(NULL, 0);
		}
	}
	else
	{
		Print("        @@@ NO MEMORY LEAKS @@@\n\n");
	}
}

// カーネルステータスの初期化
void InitKernelStatus()
{
	UINT i;

	// メモリ初期化
	Zero(kernel_status, sizeof(kernel_status));
	Zero(kernel_status_max, sizeof(kernel_status_max));

	// ロック初期化
	for (i = 0;i < NUM_KERNEL_STATUS;i++)
	{
		kernel_status_lock[i] = OSNewLock();
	}

	kernel_status_inited = true;
}

// カーネルステータスの解放
void FreeKernelStatus()
{
	UINT i;

	kernel_status_inited = false;

	// ロック解放
	for (i = 0;i < NUM_KERNEL_STATUS;i++)
	{
		OSDeleteLock(kernel_status_lock[i]);
	}
}

// カーネルステータスのロック
void LockKernelStatus(UINT id)
{
	// 引数チェック
	if (id >= NUM_KERNEL_STATUS)
	{
		return;
	}

	OSLock(kernel_status_lock[id]);
}

// カーネルステータスのロック解除
void UnlockKernelStatus(UINT id)
{
	// 引数チェック
	if (id >= NUM_KERNEL_STATUS)
	{
		return;
	}

	OSUnlock(kernel_status_lock[id]);
}

// デバッグ情報の表示
void PrintDebugInformation()
{
	MEMORY_STATUS memory_status;
	GetMemoryStatus(&memory_status);

	// ヘッダ
	Print("====== SoftEther UT-VPN System Debug Information ======\n");

	// メモリ情報
	Print(" <Memory Status>\n"
		"       Number of Allocated Memory Blocks: %u\n"
		"   Total Size of Allocated Memory Blocks: %u bytes\n",
		memory_status.MemoryBlocksNum, memory_status.MemorySize);

	// フッタ
	Print("====================================================\n");

	if (KS_GET(KS_CURRENT_MEM_COUNT) != 0 || KS_GET(KS_CURRENT_LOCK_COUNT) != 0 ||
		KS_GET(KS_CURRENT_LOCKED_COUNT) != 0 || KS_GET(KS_CURRENT_REF_COUNT) != 0)
	{
		// メモリリークしている可能性があるのでデバッグメニューを出す
		MemoryDebugMenu();
	}
}




