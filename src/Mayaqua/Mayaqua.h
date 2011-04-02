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

// Mayaqua.h
// Mayaqua Kernel ヘッダファイル

#ifndef	MAYAQUA_H
#define	MAYAQUA_H

// PenCore.dll 関係
#define	PENCORE_DLL_NAME		"|PenCore.dll"

//#define	USE_PROBE						// Probe を使う

// リリースフラグ用マクロ
#ifdef	VPN_SPEED

#define	DONT_USE_KERNEL_STATUS			// カーネルステータスを更新しない
#define	WIN32_USE_HEAP_API_FOR_MEMORY	// メモリ確保にヒープ API を使用する
#define	WIN32_NO_DEBUG_HELP_DLL			// デバッグ用 DLL を呼び出さない
#define	DONT_CHECK_HEAP					// ヒープの状態をチェックしない

#endif	// VPN_SPEED

#ifdef	VPN_EXE
// 実行可能ファイルビルド用
#ifdef	WIN32
#include <windows.h>
#include "../PenCore/resource.h"
int main(int argc, char *argv[]);
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	return main(0, NULL);
}
#endif	// WIN32
#endif	// VPN_EXE

// 定数
#define	DEFAULT_TABLE_FILE_NAME		"|strtable.stb"		// デフォルト文字列テーブル
#define	STRTABLE_ID					"UT_VPN_20100520"	// 文字列テーブル識別子

// OS の判別
#ifdef	WIN32
#define	OS_WIN32		// Microsoft Windows
#else
#define	OS_UNIX			// UNIX
#endif	// WIN32

// ディレクトリ区切り
#ifdef	OS_WIN32
#define	PATH_BACKSLASH	// バックスラッシュ (\)
#else	// WIN32
#define	PATH_SLASH		// スラッシュ (/)
#endif	// WIN32

// 文字コード
#ifdef	OS_WIN32
#define	CODE_SHIFTJIS	// Shift_JIS コード
#else	// WIN32
#define	CODE_EUC		// euc-jp コード
#endif	// WIN32

// エンディアン
#define	IsBigEndian()		(g_little_endian ? false : true)
#define	IsLittleEndian()	(g_little_endian)

#ifdef	OS_WIN32
// snprintf 関数の置換
#define	snprintf	_snprintf
#endif	// OS_WIN32

// コンパイラ依存
#ifndef	OS_WIN32
// gcc コンパイラ
#define	GCC_PACKED		__attribute__ ((__packed__))
#else	// OS_WIN32
// VC++ コンパイラ
#define	GCC_PACKED
#endif	// OS_WIN32

// 現在のファイルと行番号を表示するマクロ
#define	WHERE			printf("%s: %u\n", __FILE__, __LINE__); SleepThread(10);
#define	WHERE32			{	\
	char tmp[128]; sprintf(tmp, "%s: %u", __FILE__, __LINE__); Win32DebugAlert(tmp);	\
	}
#define TIMECHECK		printf("%-12s:%5u", __FILE__, __LINE__);TimeCheck();

// プローブ関係
#ifdef	USE_PROBE
#define	PROBE_WHERE						WriteProbe(__FILE__, __LINE__, "");
#define	PROBE_STR(str)					WriteProbe(__FILE__, __LINE__, (str));
#define	PROBE_DATA2(str, data, size)	WriteProbeData(__FILE__, __LINE__, (str), (data), (size));
#define	PROBE_DATA(data, size)			WriteProbeData(__FILE__, __LINE__, "", (data), (size));
#else	// USE_PROBE
#define	PROBE_WHERE
#define	PROBE_STR(str)
#define	PROBE_DATA2(str, data, size)
#define	PROBE_DATA(data, size)
#endif	// USE_PROBE

// 現在の時間を表示するマクロ
#ifdef	WIN32
#define	WHEN			{WHERE; MsPrintTick();}
#else	// WIN32
#define	WHEN
#endif	// WIN32

#ifdef	OS_UNIX
// UNIX 系 OS にのみ必要なヘッダ
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <dirent.h>
#ifdef	UNIX_LINUX
#include <sys/vfs.h>
#elif	UNIX_BSD
#include <sys/param.h>
#include <sys/mount.h>
#endif
#ifdef	UNIX_SOLARIS
#include <sys/statvfs.h>
#define	USE_STATVFS
#endif	// UNIX_SOLARIS
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#ifdef	UNIX_SOLARIS
#include <sys/filio.h>
#endif	// UNIX_SOLARIS
#include <sys/poll.h>
#include <sys/resource.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
//#include <netinet/ip.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <readline/readline.h>
#include <readline/history.h>
//#include <curses.h>

#ifdef	UNIX_LINUX
typedef void *iconv_t;
iconv_t iconv_open (__const char *__tocode, __const char *__fromcode);
size_t iconv (iconv_t __cd, char **__restrict __inbuf,
                     size_t *__restrict __inbytesleft,
                     char **__restrict __outbuf,
                     size_t *__restrict __outbytesleft);
int iconv_close (iconv_t __cd);
#else	// UNIX_LINUX
#include <iconv.h>
#endif	// UNIX_LINUX


#ifdef	UNIX_LINUX
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#endif	// UNIX_SOLARIS

#ifndef	NO_VLAN

#include <Mayaqua/TunTap.h>

#endif	// NO_VLAN

#define	closesocket(s)		close(s)

#else	// Win32 のみ

#include <conio.h>

#endif	// OS_UNIX

// IPv6 サポートフラグ
#ifndef	WIN32
#ifndef	AF_INET6
#define	NO_IPV6
#endif	// AF_INET6
#endif	// WIN32

// 基本型宣言
#include <Mayaqua/MayaType.h>

// オブジェクト管理
#include <Mayaqua/Object.h>

// オブジェクト追跡
#include <Mayaqua/Tracking.h>

// ファイル入出力
#include <Mayaqua/FileIO.h>

// メモリ管理
#include <Mayaqua/Memory.h>

// 文字列処理
#include <Mayaqua/Str.h>

// 国際化文字列処理
#include <Mayaqua/Internat.h>

// 暗号化処理
#include <Mayaqua/Encrypt.h>

// セキュアトークン
#include <Mayaqua/Secure.h>

// カーネル
#include <Mayaqua/Kernel.h>

// パッケージ
#include <Mayaqua/Pack.h>

// 設定ファイル
#include <Mayaqua/Cfg.h>

// 文字列テーブル
#include <Mayaqua/Table.h>

// ネットワーク通信
#include <Mayaqua/Network.h>

// 64 bit リアルタイムクロック
#include <Mayaqua/Tick64.h>

// OS 依存コード
#include <Mayaqua/OS.h>

// Microsoft Windows 用コード
#include <Mayaqua/Microsoft.h>


// グローバル変数
extern bool g_memcheck;
extern bool g_debug;
extern char *cmdline;
extern wchar_t *uni_cmdline;
extern bool g_little_endian;
extern LOCK *tick_manual_lock;

// カーネル状態
#define	NUM_KERNEL_STATUS	128
extern UINT64 kernel_status[NUM_KERNEL_STATUS];
extern UINT64 kernel_status_max[NUM_KERNEL_STATUS];
extern LOCK *kernel_status_lock[NUM_KERNEL_STATUS];
extern BOOL kernel_status_inited;

// カーネル状態操作マクロ
#define	KS_LOCK(id)		LockKernelStatus(id)
#define	KS_UNLOCK(id)	UnlockKernelStatus(id)
#define	KS_GET64(id)	(kernel_status[id])
#define	KS_GET(id)		((UINT)KS_GET64(id))
#define	KS_GETMAX64(id)	(kernel_status_max[id])
#define	KS_GETMAX(id)	((UINT)KS_GETMAX64(id))

#ifdef	DONT_USE_KERNEL_STATUS
// カーネルステータス操作を無効にする
#define	KS_INC(id)
#define	KS_DEC(id)
#define	KS_ADD(id, n)
#define	KS_SUB(id, n)
#else	// DONT_USE_KERNEL_STATUS
// カーネルステータス操作を有効にする
#define	KS_INC(id)							\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id]++;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#define	KS_DEC(id)							\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id]--;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#define	KS_ADD(id, n)						\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id] += n;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#define	KS_SUB(id, n)						\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id] -= n;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#endif	// DONT_USE_KERNEL_STATUS

// カーネル状態一覧
// 文字列関係
#define	KS_STRCPY_COUNT			0		// StrCpy 呼び出し回数
#define	KS_STRLEN_COUNT			1		// StrLen 呼び出し回数
#define	KS_STRCHECK_COUNT		2		// StrCheck 呼び出し回数
#define	KS_STRCAT_COUNT			3		// StrCat 呼び出し回数
#define	KS_FORMAT_COUNT			4		// Format 呼び出し回数
// メモリ関係
#define	KS_MALLOC_COUNT			5		// Malloc 呼び出し回数
#define	KS_REALLOC_COUNT		6		// ReAlloc 呼び出し回数
#define	KS_FREE_COUNT			7		// Free 呼び出し回数
#define	KS_TOTAL_MEM_SIZE		8		// これまでに確保したメモリの合計サイズ
#define	KS_CURRENT_MEM_COUNT	9		// 現在確保しているメモリブロック数
#define	KS_TOTAL_MEM_COUNT		10		// これまでに確保したメモリブロック数の合計
#define	KS_ZERO_COUNT			11		// Zero 呼び出し回数
#define	KS_COPY_COUNT			12		// Copy 呼び出し回数
// ロック関係
#define	KS_NEWLOCK_COUNT		13		// NewLock を呼び出した回数
#define	KS_DELETELOCK_COUNT		14		// DeleteLock を呼び出した回数
#define	KS_LOCK_COUNT			15		// Lock を呼び出した回数
#define	KS_UNLOCK_COUNT			16		// Unlock を呼び出した回数
#define	KS_CURRENT_LOCK_COUNT	17		// 現在の LOCK オブジェクト数
#define	KS_CURRENT_LOCKED_COUNT	18		// 現在のロックされている LOCK オブジェクト数
// カウンタ情報
#define	KS_NEW_COUNTER_COUNT	19		// NewCounter を呼び出した回数
#define	KS_DELETE_COUNTER_COUNT	20		// DeleteCounter を呼び出した回数
#define	KS_INC_COUNT			21		// Inc を呼び出した回数
#define	KS_DEC_COUNT			22		// Dec を呼び出した回数
#define	KS_CURRENT_COUNT		23		// 現在のカウント数の合計
// 参照カウンタ情報
#define	KS_NEWREF_COUNT			24		// NewRef を呼び出した回数
#define	KS_FREEREF_COUNT		72		// REF オブジェクトを削除した回数
#define	KS_ADDREF_COUNT			25		// AddRef を呼び出した回数
#define	KS_RELEASE_COUNT		26		// Release を呼び出した回数
#define	KS_CURRENT_REF_COUNT	27		// 現在の REF オブジェクト数
#define	KS_CURRENT_REFED_COUNT	28		// 現在の参照数の合計
// バッファ情報
#define	KS_NEWBUF_COUNT			29		// NewBuf を呼び出した回数
#define	KS_FREEBUF_COUNT		30		// FreeBuf を呼び出した回数
#define	KS_CURRENT_BUF_COUNT	31		// 現在の BUF オブジェクトの数
#define	KS_READ_BUF_COUNT		32		// ReadBuf を呼び出した回数
#define	KS_WRITE_BUF_COUNT		33		// WriteBuf を呼び出した回数
#define	KS_ADJUST_BUFSIZE_COUNT	34		// バッファサイズを調整した回数
#define	KS_SEEK_BUF_COUNT		35		// SeekBuf を呼び出した回数
// FIFO 情報
#define	KS_NEWFIFO_COUNT		36		// NewFifo を呼び出した回数
#define	KS_FREEFIFO_COUNT		37		// FIFO オブジェクトを削除した回数
#define	KS_READ_FIFO_COUNT		38		// ReadFifo を呼び出した回数
#define	KS_WRITE_FIFO_COUNT		39		// WriteFifo を呼び出した回数
#define	KS_PEEK_FIFO_COUNT		40		// PeekFifo を呼び出した回数
// リスト関係
#define	KS_NEWLIST_COUNT		41		// NewList を呼び出した回数
#define	KS_FREELIST_COUNT		42		// LIST オブジェクトを削除した回数
#define	KS_INSERT_COUNT			43		// Add を呼び出した回数
#define	KS_DELETE_COUNT			44		// Delete を呼び出した回数
#define	KS_SORT_COUNT			45		// Sort を呼び出した回数
#define	KS_SEARCH_COUNT			46		// Search を呼び出した回数
#define	KS_TOARRAY_COUNT		47		// ToArray を呼び出した回数
// キュー関係
#define	KS_NEWQUEUE_COUNT		48		// NewQueue を呼び出した回数
#define	KS_FREEQUEUE_COUNT		49		// QUEUE オブジェクトを削除した回数
#define	KS_PUSH_COUNT			50		// Push を呼び出した回数
#define	KS_POP_COUNT			51		// POP を呼び出した回数
// スタック関係
#define	KS_NEWSK_COUNT			52		// NewSk を呼び出した回数
#define	KS_FREESK_COUNT			53		// SK オブジェクトを削除した回数
#define	KS_INSERT_QUEUE_COUNT	54		// InsertQueue を呼び出した回数
#define	KS_GETNEXT_COUNT		55		// GetNext を呼び出した回数
// カーネル関係
#define	KS_GETTIME_COUNT		56		// 時刻を取得した回数
#define	KS_GETTICK_COUNT		57		// システムタイマを取得した回数
#define	KS_NEWTHREAD_COUNT		58		// NewThread を呼び出した回数
#define	KS_FREETHREAD_COUNT		59		// THREAD オブジェクトを削除した回数
#define	KS_WAITFORTHREAD_COUNT	60		// WaitForThread を呼び出した回数
#define	KS_NEWEVENT_COUNT		61		// NewEvent を呼び出した回数
#define	KS_FREEEVENT_COUNT		62		// EVENT オブジェクトを削除した回数
#define	KS_WAIT_COUNT			63		// Wait を呼び出した回数
#define	KS_SLEEPTHREAD_COUNT	64		// SleepThread を呼び出した回数
// IO 関係
#define	KS_IO_OPEN_COUNT		65		// ファイルを開いた回数
#define	KS_IO_CREATE_COUNT		66		// ファイルを作成した回数
#define	KS_IO_CLOSE_COUNT		67		// ファイルを閉じた回数
#define	KS_IO_READ_COUNT		68		// ファイルから読み込んだ回数
#define	KS_IO_WRITE_COUNT		69		// ファイルに書き込んだ回数
#define	KS_IO_TOTAL_READ_SIZE	70		// ファイルから読み込んだ合計バイト数
#define	KS_IO_TOTAL_WRITE_SIZE	71		// ファイルに書き込んだ合計バイト数
// メモリプール関係
#define	KS_MEMPOOL_MALLOC_COUNT	75		// メモリプールを確保した回数
#define	KS_MEMPOOL_FREE_COUNT	73		// メモリプールを解放した回数
#define	KS_MEMPOOL_CURRENT_NUM	74		// 現在のメモリプールの個数
#define	KS_MEMPOOL_REALLOC_COUNT	76	// メモリプールを ReAlloc した回数


// マクロ
#define	IsDebug()		(g_debug)		// デバッグモード
#define	IsMemCheck()	(g_memcheck)	// メモリチェックモード

// 関数プロトタイプ
void InitMayaqua(bool memcheck, bool debug, int argc, char **argv);
void FreeMayaqua();
bool IsNt();
bool IsUnicode();
void MayaquaDotNetMode();
bool MayaquaIsDotNetMode();
void MayaquaMinimalMode();
bool MayaquaIsMinimalMode();
bool Is64();
bool Is32();
bool IsIA64();
bool IsX64();
void InitKernelStatus();
void FreeKernelStatus();
void PrintDebugInformation();
void LockKernelStatus(UINT id);
void UnlockKernelStatus(UINT id);
void PrintKernelStatus();
void InitCommandLineStr(int argc, char **argv);
void FreeCommandLineStr();
void SetCommandLineStr(char *str);
void SetCommandLineUniStr(wchar_t *str);
char *GetCommandLineStr();
wchar_t *GetCommandLineUniStr();
void ParseCommandLineTokens();
void FreeCommandLineTokens();
TOKEN_LIST *GetCommandLineToken();
UNI_TOKEN_LIST *GetCommandLineUniToken();
void InitOsInfo();
void FreeOsInfo();
void Alert(char *msg, char *caption);
void AlertW(wchar_t *msg, wchar_t *caption);
OS_INFO *GetOsInfo();
UINT GetOsType();
void PrintOsInfo(OS_INFO *info);
void CheckEndian();
void CheckUnixTempDir();
void TimeCheck();
void SetHamMode();
bool IsHamMode();
void InitProbe();
void FreeProbe();
void EnableProbe(bool enable);
bool IsProbeEnabled();
void WriteProbe(char *filename, UINT line, char *str);
void WriteProbeData(char *filename, UINT line, char *str, void *data, UINT size);
USHORT CalcChecksum16(void *buf, UINT size);

#ifdef	OS_WIN32
// インポートライブラリ (for Win32)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma warning( disable : 4099 )
#endif	// OS_WIN32

// デバッグ用
#ifndef	ENCRYPT_C
//#define	Disconnect(s)		{Debug("Disconnect() Called: %s %u\n", __FILE__, __LINE__);Disconnect(s);}
#endif


#endif	// MAYAQUA_H


