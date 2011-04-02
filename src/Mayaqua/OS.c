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

// OS.c
// オペレーティングシステム依存コード

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

#undef	Lock
#undef	Unlock

// ディスパッチテーブル
static OS_DISPATCH_TABLE *os = NULL;

// OS 種類を文字列に変換
char *OsTypeToStr(UINT type)
{
	switch (type)
	{
	case 0:
		return "Unsupported OS by SoftEther Corporation\0\n";
	case OSTYPE_WINDOWS_95:
		return "Windows 95\0\n";
	case OSTYPE_WINDOWS_98:
		return "Windows 98\0\n";
	case OSTYPE_WINDOWS_ME:
		return "Windows Millennium Edition\0\n";
	case OSTYPE_WINDOWS_UNKNOWN:
		return "Windows 9x Unknown Version\0\n";
	case OSTYPE_WINDOWS_NT_4_WORKSTATION:
		return "Windows NT 4.0 Workstation\0\n";
	case OSTYPE_WINDOWS_NT_4_SERVER:
		return "Windows NT 4.0 Server\0\n";
	case OSTYPE_WINDOWS_NT_4_SERVER_ENTERPRISE:
		return "Windows NT 4.0 Server, Enterprise Edition\0\n";
	case OSTYPE_WINDOWS_NT_4_BACKOFFICE:
		return "BackOffice Server 4.5\0\n";
	case OSTYPE_WINDOWS_NT_4_SMS:
		return "Small Business Server 4.5\0\n";
	case OSTYPE_WINDOWS_2000_PROFESSIONAL:
		return "Windows 2000 Professional\0\n";
	case OSTYPE_WINDOWS_2000_SERVER:
		return "Windows 2000 Server\0\n";
	case OSTYPE_WINDOWS_2000_ADVANCED_SERVER:
		return "Windows 2000 Advanced Server\0\n";
	case OSTYPE_WINDOWS_2000_DATACENTER_SERVER:
		return "Windows 2000 Datacenter Server\0\n";
	case OSTYPE_WINDOWS_2000_BACKOFFICE:
		return "BackOffice Server 2000\0\n";
	case OSTYPE_WINDOWS_2000_SBS:
		return "Small Business Server 2000\0\n";
	case OSTYPE_WINDOWS_XP_HOME:
		return "Windows XP Home Edition\0\n";
	case OSTYPE_WINDOWS_XP_PROFESSIONAL:
		return "Windows XP Professional\0\n";
	case OSTYPE_WINDOWS_2003_WEB:
		return "Windows Server 2003 Web Edition\0\n";
	case OSTYPE_WINDOWS_2003_STANDARD:
		return "Windows Server 2003 Standard Edition\0\n";
	case OSTYPE_WINDOWS_2003_ENTERPRISE:
		return "Windows Server 2003 Enterprise Edition\0\n";
	case OSTYPE_WINDOWS_2003_DATACENTER:
		return "Windows Server 2003 Datacenter Edition\0\n";
	case OSTYPE_WINDOWS_2003_BACKOFFICE:
		return "BackOffice Server 2003\0\n";
	case OSTYPE_WINDOWS_2003_SBS:
		return "Small Business Server 2003\0\n";
	case OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL:
		return "Windows Vista\0\n";
	case OSTYPE_WINDOWS_LONGHORN_SERVER:
		return "Windows Server 2008\0\n";
	case OSTYPE_WINDOWS_7:
		return "Windows 7\0\n";
	case OSTYPE_WINDOWS_SERVER_2008_R2:
		return "Windows Server 2008 R2\0\n";
	case OSTYPE_WINDOWS_8:
		return "Windows 8 or greater\0\n";
	case OSTYPE_WINDOWS_SERVER_8:
		return "Windows Server 8 or greater\0\n";
	case OSTYPE_UNIX_UNKNOWN:
		return "UNIX System\0\n";
	case OSTYPE_LINUX:
		return "Linux\0\n";
	case OSTYPE_SOLARIS:
		return "Sun Solaris\0\n";
	case OSTYPE_CYGWIN:
		return "Gnu Sygwin\0\n";
	case OSTYPE_BSD:
		return "BSD System\0\n";
	case OSTYPE_MACOS_X:
		return "Mac OS X\0\n";
	}

	return "Unknown OS";
}

// 初期化
void OSInit()
{
	// ディスパッチテーブルの取得
#ifdef	OS_WIN32
	os = Win32GetDispatchTable();
#else	// OS_WIN32
	os = UnixGetDispatchTable();
#endif	// OS_WIN32

	// OS 固有の初期化関数の呼び出し
	os->Init();
}

// 解放
void OSFree()
{
	os->Free();
}

// メモリ情報取得
void OSGetMemInfo(MEMINFO *info)
{
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	os->GetMemInfo(info);
}

// イールド
void OSYield()
{
	os->Yield();
}

// シングルインスタンス開始
void *OSNewSingleInstance(char *instance_name)
{
	return os->NewSingleInstance(instance_name);
}

void OSFreeSingleInstance(void *data)
{
	os->FreeSingleInstance(data);
}

// 優先順位を上げる
void OSSetHighPriority()
{
	os->SetHighPriority();
}

// 優先順位を戻す
void OSRestorePriority()
{
	os->RestorePriority();
}

// プロダクト ID の取得
char* OSGetProductId()
{
	return os->GetProductId();
}

// OS がサポートされているかどうかチェックする
bool OSIsSupportedOs()
{
	return os->IsSupportedOs();
}

// OS 情報の取得
void OSGetOsInfo(OS_INFO *info)
{
	os->GetOsInfo(info);
}

// アラートの表示
void OSAlert(char *msg, char *caption)
{
	os->Alert(msg, caption);
}
void OSAlertW(wchar_t *msg, wchar_t *caption)
{
	os->AlertW(msg, caption);
}

// プロセス起動
bool OSRun(char *filename, char *arg, bool hide, bool wait)
{
	return os->Run(filename, arg, hide, wait);
}
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	return os->RunW(filename, arg, hide, wait);
}

// スレッド ID の取得
UINT OSThreadId()
{
	return os->ThreadId();
}

// リネーム
bool OSFileRename(char *old_name, char *new_name)
{
	return os->FileRename(old_name, new_name);
}
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	return os->FileRenameW(old_name, new_name);
}

// ファイルサイズを取得する
UINT64 OSFileSize(void *pData)
{
	return os->FileSize(pData);
}

// ファイルをシークする
bool OSFileSeek(void *pData, UINT mode, int offset)
{
	return os->FileSeek(pData, mode, offset);
}

// ファイルを削除する
bool OSFileDelete(char *name)
{
	return os->FileDelete(name);
}
bool OSFileDeleteW(wchar_t *name)
{
	return os->FileDeleteW(name);
}

// ディレクトリを作成する
bool OSMakeDir(char *name)
{
	return os->MakeDir(name);
}
bool OSMakeDirW(wchar_t *name)
{
	return os->MakeDirW(name);
}

// ディレクトリを削除する
bool OSDeleteDir(char *name)
{
	return os->DeleteDir(name);
}
bool OSDeleteDirW(wchar_t *name)
{
	return os->DeleteDirW(name);
}

// ファイルを開く
void *OSFileOpen(char *name, bool write_mode, bool read_lock)
{
	return os->FileOpen(name, write_mode, read_lock);
}
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	return os->FileOpenW(name, write_mode, read_lock);
}

// ファイルを作成する
void *OSFileCreate(char *name)
{
	return os->FileCreate(name);
}
void *OSFileCreateW(wchar_t *name)
{
	return os->FileCreateW(name);
}

// ファイルに書き込む
bool OSFileWrite(void *pData, void *buf, UINT size)
{
	return os->FileWrite(pData, buf, size);
}

// ファイルから読み込む
bool OSFileRead(void *pData, void *buf, UINT size)
{
	return os->FileRead(pData, buf, size);
}

// ファイルを閉じる
void OSFileClose(void *pData, bool no_flush)
{
	os->FileClose(pData, no_flush);
}

// ファイルのフラッシュ
void OSFileFlush(void *pData)
{
	os->FileFlush(pData);
}

// コールスタックの取得
CALLSTACK_DATA *OSGetCallStack()
{
	return os->GetCallStack();
}

// シンボル情報の取得
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	return os->GetCallStackSymbolInfo(s);
}

// スレッドの終了を待機
bool OSWaitThread(THREAD *t)
{
	return os->WaitThread(t);
}

// スレッドの解放
void OSFreeThread(THREAD *t)
{
	os->FreeThread(t);
}

// スレッドの初期化
bool OSInitThread(THREAD *t)
{
	return os->InitThread(t);
}

// メモリ確保
void *OSMemoryAlloc(UINT size)
{
	return os->MemoryAlloc(size);
}

// メモリ再確保
void *OSMemoryReAlloc(void *addr, UINT size)
{
	return os->MemoryReAlloc(addr, size);
}

// メモリ解放
void OSMemoryFree(void *addr)
{
	os->MemoryFree(addr);
}

// システムタイマの取得
UINT OSGetTick()
{
	return os->GetTick();
}

// システム時刻の取得
void OSGetSystemTime(SYSTEMTIME *system_time)
{
	os->GetSystemTime(system_time);
}

// 32bit インクリメント
void OSInc32(UINT *value)
{
	os->Inc32(value);
}

// 32bit デクリメント
void OSDec32(UINT *value)
{
	os->Dec32(value);
}

// スレッドの休止
void OSSleep(UINT time)
{
	os->Sleep(time);
}

// ロック作成
LOCK *OSNewLock()
{
	return os->NewLock();
}

// ロック
bool OSLock(LOCK *lock)
{
	return os->Lock(lock);
}

// ロック解除
void OSUnlock(LOCK *lock)
{
	os->Unlock(lock);
}

// ロック削除
void OSDeleteLock(LOCK *lock)
{
	os->DeleteLock(lock);
}

// イベント初期化
void OSInitEvent(EVENT *event)
{
	os->InitEvent(event);
}

// イベントのセット
void OSSetEvent(EVENT *event)
{
	os->SetEvent(event);
}

// イベントのリセット
void OSResetEvent(EVENT *event)
{
	os->ResetEvent(event);
}

// イベントの待機
bool OSWaitEvent(EVENT *event, UINT timeout)
{
	return os->WaitEvent(event, timeout);
}

// イベントの解放
void OSFreeEvent(EVENT *event)
{
	os->FreeEvent(event);
}

