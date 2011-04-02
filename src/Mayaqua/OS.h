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

// OS.h
// OS.c のヘッダ

#ifndef	OS_H
#define	OS_H

// 関数プロトタイプ
char *OsTypeToStr(UINT type);

void OSInit();
void OSFree();
void *OSMemoryAlloc(UINT size);
void *OSMemoryReAlloc(void *addr, UINT size);
void OSMemoryFree(void *addr);
UINT OSGetTick();
void OSGetSystemTime(SYSTEMTIME *system_time);
void OSInc32(UINT *value);
void OSDec32(UINT *value);
void OSSleep(UINT time);
LOCK *OSNewLock();
bool OSLock(LOCK *lock);
void OSUnlock(LOCK *lock);
void OSDeleteLock(LOCK *lock);
void OSInitEvent(EVENT *event);
void OSSetEvent(EVENT *event);
void OSResetEvent(EVENT *event);
bool OSWaitEvent(EVENT *event, UINT timeout);
void OSFreeEvent(EVENT *event);
bool OSWaitThread(THREAD *t);
void OSFreeThread(THREAD *t);
bool OSInitThread(THREAD *t);
void *OSFileOpen(char *name, bool write_mode, bool read_lock);
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *OSFileCreate(char *name);
void *OSFileCreateW(wchar_t *name);
bool OSFileWrite(void *pData, void *buf, UINT size);
bool OSFileRead(void *pData, void *buf, UINT size);
void OSFileClose(void *pData, bool no_flush);
void OSFileFlush(void *pData);
UINT64 OSFileSize(void *pData);
bool OSFileSeek(void *pData, UINT mode, int offset);
bool OSFileDelete(char *name);
bool OSFileDeleteW(wchar_t *name);
bool OSMakeDir(char *name);
bool OSMakeDirW(wchar_t *name);
bool OSDeleteDir(char *name);
bool OSDeleteDirW(wchar_t *name);
CALLSTACK_DATA *OSGetCallStack();
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool OSFileRename(char *old_name, char *new_name);
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name);
UINT OSThreadId();
bool OSRun(char *filename, char *arg, bool hide, bool wait);
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool OSIsSupportedOs();
void OSGetOsInfo(OS_INFO *info);
void OSAlert(char *msg, char *caption);
void OSAlertW(wchar_t *msg, wchar_t *caption);
char* OSGetProductId();
void OSSetHighPriority();
void OSRestorePriority();
void *OSNewSingleInstance(char *instance_name);
void OSFreeSingleInstance(void *data);
void OSGetMemInfo(MEMINFO *info);
void OSYield();

// ディスパッチテーブル
typedef struct OS_DISPATCH_TABLE
{
	void (*Init)();
	void (*Free)();
	void *(*MemoryAlloc)(UINT size);
	void *(*MemoryReAlloc)(void *addr, UINT size);
	void (*MemoryFree)(void *addr);
	UINT (*GetTick)();
	void (*GetSystemTime)(SYSTEMTIME *system_time);
	void (*Inc32)(UINT *value);
	void (*Dec32)(UINT *value);
	void (*Sleep)(UINT time);
	LOCK *(*NewLock)();
	bool (*Lock)(LOCK *lock);
	void (*Unlock)(LOCK *lock);
	void (*DeleteLock)(LOCK *lock);
	void (*InitEvent)(EVENT *event);
	void (*SetEvent)(EVENT *event);
	void (*ResetEvent)(EVENT *event);
	bool (*WaitEvent)(EVENT *event, UINT timeout);
	void (*FreeEvent)(EVENT *event);
	bool (*WaitThread)(THREAD *t);
	void (*FreeThread)(THREAD *t);
	bool (*InitThread)(THREAD *t);
	UINT (*ThreadId)();
	void *(*FileOpen)(char *name, bool write_mode, bool read_lock);
	void *(*FileOpenW)(wchar_t *name, bool write_mode, bool read_lock);
	void *(*FileCreate)(char *name);
	void *(*FileCreateW)(wchar_t *name);
	bool (*FileWrite)(void *pData, void *buf, UINT size);
	bool (*FileRead)(void *pData, void *buf, UINT size);
	void (*FileClose)(void *pData, bool no_flush);
	void (*FileFlush)(void *pData);
	UINT64 (*FileSize)(void *pData);
	bool (*FileSeek)(void *pData, UINT mode, int offset);
	bool (*FileDelete)(char *name);
	bool (*FileDeleteW)(wchar_t *name);
	bool (*MakeDir)(char *name);
	bool (*MakeDirW)(wchar_t *name);
	bool (*DeleteDir)(char *name);
	bool (*DeleteDirW)(wchar_t *name);
	CALLSTACK_DATA *(*GetCallStack)();
	bool (*GetCallStackSymbolInfo)(CALLSTACK_DATA *s);
	bool (*FileRename)(char *old_name, char *new_name);
	bool (*FileRenameW)(wchar_t *old_name, wchar_t *new_name);
	bool (*Run)(char *filename, char *arg, bool hide, bool wait);
	bool (*RunW)(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
	bool (*IsSupportedOs)();
	void (*GetOsInfo)(OS_INFO *info);
	void (*Alert)(char *msg, char *caption);
	void (*AlertW)(wchar_t *msg, wchar_t *caption);
	char *(*GetProductId)();
	void (*SetHighPriority)();
	void (*RestorePriority)();
	void *(*NewSingleInstance)(char *instance_name);
	void (*FreeSingleInstance)(void *data);
	void (*GetMemInfo)(MEMINFO *info);
	void (*Yield)();
} OS_DISPATCH_TABLE;

// OS 固有ヘッダのインクルード
#ifdef	OS_WIN32
#include <Mayaqua/Win32.h>
#else	//OS_WIN32
#include <Mayaqua/Unix.h>
#endif	// OS_WIN32

#endif	// OS_H

