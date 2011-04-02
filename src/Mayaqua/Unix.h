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

// Unix.h
// Unix.c のヘッダ

#ifdef	OS_UNIX

#ifndef	UNIX_H
#define	UNIX_H

// 定数
#define	UNIX_THREAD_STACK_SIZE			(200 * 1000)	// スタックサイズ
#define	UNIX_MAX_CHILD_PROCESSES		2000000			// 最大子プロセス数
#define	UNIX_LINUX_MAX_THREADS			200000000		// 最大スレッド数
#define	UNIX_MAX_LOCKS					65536			// 最大ロック数
#define	UNIX_MAX_MEMORY					(2147483648UL)	// 最大メモリ容量
#define	UNIX_MAX_FD						(655360)		// 最大 FD 数
#define	MAXIMUM_WAIT_OBJECTS			64				// 最大 select 数

#define	UNIX_SERVICE_STOP_TIMEOUT_1		(600 * 1000)	// サービス停止までのタイムアウト
#define	UNIX_SERVICE_STOP_TIMEOUT_2		(900 * 1000)	// サービス停止までのタイムアウト (親プロセス)


// サービス関係
typedef void (SERVICE_FUNCTION)();

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"

#define	UNIX_SVC_ARG_START				"start"
#define	UNIX_SVC_ARG_STOP				"stop"
#define	UNIX_SVC_ARG_EXEC_SVC			"execsvc"
#define	UNIX_ARG_EXIT					"exit"

#define	UNIX_SVC_MODE_START				1
#define	UNIX_SVC_MODE_STOP				2
#define	UNIX_SVC_MODE_EXEC_SVC			3
#define	UNIX_SVC_MODE_EXIT				4


// 関数プロトタイプ
OS_DISPATCH_TABLE *UnixGetDispatchTable();
void UnixInit();
void UnixFree();
void *UnixMemoryAlloc(UINT size);
void *UnixMemoryReAlloc(void *addr, UINT size);
void UnixMemoryFree(void *addr);
UINT UnixGetTick();
void UnixGetSystemTime(SYSTEMTIME *system_time);
void UnixInc32(UINT *value);
void UnixDec32(UINT *value);
void UnixSleep(UINT time);
LOCK *UnixNewLock();
bool UnixLock(LOCK *lock);
void UnixUnlock(LOCK *lock);
void UnixUnlockEx(LOCK *lock, bool inner);
void UnixDeleteLock(LOCK *lock);
void UnixInitEvent(EVENT *event);
void UnixSetEvent(EVENT *event);
void UnixResetEvent(EVENT *event);
bool UnixWaitEvent(EVENT *event, UINT timeout);
void UnixFreeEvent(EVENT *event);
bool UnixWaitThread(THREAD *t);
void UnixFreeThread(THREAD *t);
bool UnixInitThread(THREAD *t);
UINT UnixThreadId();
void *UnixFileOpen(char *name, bool write_mode, bool read_lock);
void *UnixFileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *UnixFileCreate(char *name);
void *UnixFileCreateW(wchar_t *name);
bool UnixFileWrite(void *pData, void *buf, UINT size);
bool UnixFileRead(void *pData, void *buf, UINT size);
void UnixFileClose(void *pData, bool no_flush);
void UnixFileFlush(void *pData);
UINT64 UnixFileSize(void *pData);
bool UnixFileSeek(void *pData, UINT mode, int offset);
bool UnixFileDelete(char *name);
bool UnixFileDeleteW(wchar_t *name);
bool UnixMakeDir(char *name);
bool UnixMakeDirW(wchar_t *name);
bool UnixDeleteDir(char *name);
bool UnixDeleteDirW(wchar_t *name);
CALLSTACK_DATA *UnixGetCallStack();
bool UnixGetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool UnixFileRename(char *old_name, char *new_name);
bool UnixFileRenameW(wchar_t *old_name, wchar_t *new_name);
bool UnixRun(char *filename, char *arg, bool hide, bool wait);
bool UnixRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool UnixIsSupportedOs();
void UnixGetOsInfo(OS_INFO *info);
void UnixAlert(char *msg, char *caption);
void UnixAlertW(wchar_t *msg, wchar_t *caption);
char *UnixGetProductId();
void UnixSetHighPriority();
void UnixRestorePriority();
void *UnixNewSingleInstance(char *instance_name);
void UnixFreeSingleInstance(void *data);
void UnixGetMemInfo(MEMINFO *info);
void UnixYield();


void UnixSetThreadPriorityRealtime();
void UnixSetThreadPriorityLow();
void UnixSetThreadPriorityHigh();
void UnixSetThreadPriorityIdle();
void UnixRestoreThreadPriority();
void UnixSetResourceLimit(UINT id, UINT value);
UINT64 UnixGetTick64();
void UnixSigChldHandler(int sig);
void UnixCloseIO();
void UnixDaemon(bool debug_mode);
void UnixGetCurrentDir(char *dir, UINT size);
void UnixGetCurrentDirW(wchar_t *dir, UINT size);
bool UnixCheckExecAccess(char *name);
bool UnixCheckExecAccessW(wchar_t *name);
DIRLIST *UnixEnumDirEx(char *dirname, COMPARE *compare);
DIRLIST *UnixEnumDirExW(wchar_t *dirname, COMPARE *compare);
bool UnixGetDiskFreeMain(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool UnixGetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool UnixGetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
void UnixInitSolarisSleep();
void UnixFreeSolarisSleep();
void UnixSolarisSleep(UINT msec);

UINT UnixService(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixServiceMain(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixGenPidFileName(char *name, UINT size);
void UnixStartService(char *name);
void UnixStopService(char *name);
void UnixExecService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixUsage(char *name);
void UnixWritePidFile(UINT pid);
UINT UnixReadPidFile();
bool UnixIsProcess(UINT pid);
bool UnixWaitProcessEx(UINT pid, UINT timeout);
void UnixWaitProcess(UINT pid);
void UnixDeletePidFile();
void UnixStopThread(THREAD *t, void *param);


#endif	// UNIX_H

#endif	// OS_UNIX

