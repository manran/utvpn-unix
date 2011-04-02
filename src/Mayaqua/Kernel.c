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

// Kernel.c
// システムサービス処理ルーチン

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

#ifndef TM_YEAR_MAX
#define TM_YEAR_MAX         2106
#endif
#ifndef TM_MON_MAX
#define TM_MON_MAX          1
#endif
#ifndef TM_MDAY_MAX
#define TM_MDAY_MAX         7
#endif
#ifndef TM_HOUR_MAX
#define TM_HOUR_MAX         6
#endif
#ifndef TM_MIN_MAX
#define TM_MIN_MAX          28
#endif
#ifndef TM_SEC_MAX
#define TM_SEC_MAX          14
#endif

/* free mktime function
   Copyright 1988, 1989 by David MacKenzie <djm@ai.mit.edu>
   and Michael Haertel <mike@ai.mit.edu>
   Unlimited distribution permitted provided this copyright notice is
   retained and any functional modifications are prominently identified.  */
#define ADJUST_TM(tm_member, tm_carry, modulus) \
	if ((tm_member) < 0){ \
		tm_carry -= (1 - ((tm_member)+1) / (modulus)); \
		tm_member = (modulus-1) + (((tm_member)+1) % (modulus)); \
	} else if ((tm_member) >= (modulus)) { \
		tm_carry += (tm_member) / (modulus); \
		tm_member = (tm_member) % (modulus); \
	}
#define leap(y) (((y) % 4 == 0 && (y) % 100 != 0) || (y) % 400 == 0)
#define nleap(y) (((y) - 1969) / 4 - ((y) - 1901) / 100 + ((y) - 1601) / 400)
#define leapday(m, y) ((m) == 1 && leap (y))
#define monthlen(m, y) (ydays[(m)+1] - ydays[m] + leapday (m, y))
static int ydays[] =
{
	0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365
};


static wchar_t *default_locale_str =
L"- - $ : : $ Sun Mon Tue Wed Thu Fri Sat : : : $ (None)";

static LOCALE current_locale;
LOCK *tick_manual_lock = NULL;
UINT g_zero = 0;

// リアルタイムシステムタイマの取得
UINT TickRealtime()
{
#if	defined(OS_WIN32) || defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC) || defined(CLOCK_HIGHRES)
	return Tick() + 1;
#else
	return TickRealtimeManual() + 1;
#endif
}

#ifndef	OS_WIN32

static UINT64 last_manual_tick = 0;
static UINT64 manual_tick_add_value = 0;

// clock_gettime が無いシステム向け (MacOS X など)
UINT TickRealtimeManual()
{
	UINT64 ret;
	Lock(tick_manual_lock);
	{
		ret = TickGetRealtimeTickValue64();

		if (last_manual_tick != 0 && (last_manual_tick > ret))
		{
			manual_tick_add_value += (last_manual_tick - ret);
		}

		last_manual_tick = ret;
	}
	Unlock(tick_manual_lock);

	return (UINT)(ret + manual_tick_add_value);
}

// 現在時刻から適当な値を返す
UINT64 TickGetRealtimeTickValue64()
{
	struct timeval tv;
	struct timezone tz;
	UINT64 ret;

	memset(&tv, 0, sizeof(tv));
	memset(&tz, 0, sizeof(tz));

	gettimeofday(&tv, &tz);

	ret = (UINT64)tv.tv_sec * 1000ULL + (UINT64)tv.tv_usec / 1000ULL;

	return ret;
}

#endif	// OS_WIN32

// ホームディレクトリを取得
void GetHomeDirW(wchar_t *path, UINT size)
{
	// 引数チェック
	if (path == NULL)
	{
		return;
	}

	if (GetEnvW(L"HOME", path, size) == false)
	{
		wchar_t drive[MAX_SIZE];
		wchar_t hpath[MAX_SIZE];
		if (GetEnvW(L"HOMEDRIVE", drive, sizeof(drive)) &&
			GetEnvW(L"HOMEPATH", hpath, sizeof(hpath)))
		{
			UniFormat(path, sizeof(path), L"%s%s", drive, hpath);
		}
		else
		{
#ifdef	OS_WIN32
			Win32GetCurrentDirW(path, size);
#else	// OS_WIN32
			UnixGetCurrentDirW(path, size);
#endif	// OS_WIN32
		}
	}
}
void GetHomeDir(char *path, UINT size)
{
	// 引数チェック
	if (path == NULL)
	{
		return;
	}

	if (GetEnv("HOME", path, size) == false)
	{
		char drive[MAX_SIZE];
		char hpath[MAX_SIZE];
		if (GetEnv("HOMEDRIVE", drive, sizeof(drive)) &&
			GetEnv("HOMEPATH", hpath, sizeof(hpath)))
		{
			Format(path, sizeof(path), "%s%s", drive, hpath);
		}
		else
		{
#ifdef	OS_WIN32
			Win32GetCurrentDir(path, size);
#else	// OS_WIN32
			UnixGetCurrentDir(path, size);
#endif	// OS_WIN32
		}
	}
}

// 環境変数文字列を取得
bool GetEnv(char *name, char *data, UINT size)
{
	char *ret;
	// 引数チェック
	if (name == NULL || data == NULL)
	{
		return false;
	}

	StrCpy(data, size, "");

	ret = getenv(name);
	if (ret == NULL)
	{
		return false;
	}

	StrCpy(data, size, ret);

	return true;
}
bool GetEnvW(wchar_t *name, wchar_t *data, UINT size)
{
#ifdef	OS_WIN32
	return GetEnvW_ForWin32(name, data, size);
#else	// OS_WIN32
	return GetEnvW_ForUnix(name, data, size);
#endif	// OS_WIN32
}

#ifdef	OS_WIN32
bool GetEnvW_ForWin32(wchar_t *name, wchar_t *data, UINT size)
{
	wchar_t *ret;
	// 引数チェック
	if (name == NULL || data == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		bool ret;
		char *name_a = CopyUniToStr(name);
		char data_a[MAX_SIZE];

		ret = GetEnv(name_a, data_a, sizeof(data_a));

		if (ret)
		{
			StrToUni(data, size, data_a);
		}

		Free(name_a);

		return ret;
	}

	UniStrCpy(data, size, L"");

	ret = _wgetenv(name);
	if (ret == NULL)
	{
		return false;
	}

	UniStrCpy(data, size, ret);

	return true;
}

#endif	// OS_WIN32

#ifdef	OS_UNIX

bool GetEnvW_ForUnix(wchar_t *name, wchar_t *data, UINT size)
{
	char *name_a;
	bool ret;
	char data_a[MAX_SIZE];
	// 引数チェック
	if (name == NULL || data == NULL)
	{
		return false;
	}

	name_a = CopyUniToUtf(name);

	ret = GetEnv(name_a, data_a, sizeof(data_a));

	if (ret)
	{
		UtfToUni(data, size, data_a);
	}

	Free(name_a);

	return ret;
}

#endif	// OS_UNIX

// メモリ情報取得
void GetMemInfo(MEMINFO *info)
{
	OSGetMemInfo(info);
}

// シングルインスタンスの開始
INSTANCE *NewSingleInstance(char *instance_name)
{
	return NewSingleInstanceEx(instance_name, false);
}
INSTANCE *NewSingleInstanceEx(char *instance_name, bool user_local)
{
	char name[MAX_SIZE];
	INSTANCE *ret;
	void *data;

	if (instance_name != NULL)
	{
		if (user_local == false)
		{
			HashInstanceName(name, sizeof(name), instance_name);
		}
		else
		{
			HashInstanceNameLocal(name, sizeof(name), instance_name);
		}

		data = OSNewSingleInstance(name);
	}
	else
	{
		data = OSNewSingleInstance(NULL);
	}

	if (data == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(INSTANCE));
	if (instance_name != NULL)
	{
		ret->Name = CopyStr(instance_name);
	}

	ret->pData = data;

	return ret;
}

// シングルインスタンスの解放
void FreeSingleInstance(INSTANCE *inst)
{
	// 引数チェック
	if (inst == NULL)
	{
		return;
	}

	OSFreeSingleInstance(inst->pData);

	if (inst->Name != NULL)
	{
		Free(inst->Name);
	}
	Free(inst);
}

// インスタンス名をハッシュする
void HashInstanceName(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	char key[11];
	// 引数チェック
	if (name == NULL || instance_name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), instance_name);
	Trim(tmp);
	StrUpper(tmp);

	Hash(hash, tmp, StrLen(tmp), SHA1_SIZE);
	BinToStr(key, sizeof(key), hash, 5);
	key[10] = 0;

	Format(name, size, "VPN-%s", key);

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2 ||
			GetOsInfo()->OsType == OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER)
		{
			StrCpy(tmp, sizeof(tmp), name);
			Format(name, size, "Global\\%s", tmp);
		}
	}
}
void HashInstanceNameLocal(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	char key[11];
	// 引数チェック
	if (name == NULL || instance_name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), instance_name);
	Trim(tmp);
	StrUpper(tmp);

	Hash(hash, tmp, StrLen(tmp), SHA1_SIZE);
	BinToStr(key, sizeof(key), hash, 5);
	key[10] = 0;

	Format(name, size, "VPN-%s", key);

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2 ||
			GetOsInfo()->OsType == OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER)
		{
			StrCpy(tmp, sizeof(tmp), name);
			Format(name, size, "Local\\%s", tmp);
		}
	}
}

// プロセスの起動
bool Run(char *filename, char *arg, bool hide, bool wait)
{
	// 引数チェック
	if (filename == NULL)
	{
		return false;
	}

	return OSRun(filename, arg, hide, wait);
}
bool RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	// 引数チェック
	if (filename == NULL)
	{
		return false;
	}

	return OSRunW(filename, arg, hide, wait);
}

// 日付・時刻関係の関数
void GetDateTimeStr64Uni(wchar_t *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	if (str == NULL)
	{
		return;
	}

	GetDateTimeStr64(tmp, sizeof(tmp), sec64);
	StrToUni(str, size, tmp);
}
void GetDateTimeStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStr(str, size, &st);
}
void GetDateTimeStrMilli64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrMilli(str, size, &st);
}
void GetDateStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStr(str, size, &st);
}
void GetDateTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrEx(str, size, &st, locale);
}
void GetTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStrEx(str, size, &st, locale);
}
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStrEx(str, size, &st, locale);
}
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStrMilli(str, size, &st);
}
void GetTimeStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStr(str, size, &st);
}

// 現在の POSIX 実装で使用しても安全な時刻に変換する
UINT64 SafeTime64(UINT64 sec64)
{
	return MAKESURE(sec64, 0, 2115947647000ULL);
}

// スレッドプール
static SK *thread_pool = NULL;
static COUNTER *thread_count = NULL;

// スレッドプールの初期化
void InitThreading()
{
	thread_pool = NewSk();
	thread_count = NewCounter();
}

// スレッドプールの解放
void FreeThreading()
{
	while (true)
	{
		if (Count(thread_count) == 0)
		{
			break;
		}

		SleepThread(25);
	}

	while (true)
	{
		THREAD_POOL_DATA *pd;
		THREAD *t = Pop(thread_pool);

		if (t == NULL)
		{
			break;
		}

		pd = (THREAD_POOL_DATA *)t->param;

		pd->ThreadProc = NULL;
		Set(pd->Event);

		WaitThreadInternal(t);

		pd = (THREAD_POOL_DATA *)t->param;
		ReleaseEvent(pd->Event);
		ReleaseEvent(pd->InitFinishEvent);

		ReleaseThreadInternal(t);

		Free(pd);
	}

	ReleaseSk(thread_pool);

	DeleteCounter(thread_count);
	thread_count = NULL;
}

// スレッドプールプロシージャ
void ThreadPoolProc(THREAD *t, void *param)
{
	THREAD_POOL_DATA *pd;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	pd = (THREAD_POOL_DATA *)param;

	NoticeThreadInitInternal(t);

	while (true)
	{
		THREAD *thread;
		UINT i, num;
		EVENT **ee;

		// 次の仕事を待つ
		Wait(pd->Event, INFINITE);

		if (pd->ThreadProc == NULL)
		{
			// プールスレッドの動作停止
			break;
		}

		thread = pd->Thread;
		thread->ThreadId = ThreadId();

		// 初期化完了
		Set(pd->InitFinishEvent);

		// スレッドプロシージャの実行
		pd->ThreadProc(pd->Thread, thread->param);

		thread->PoolHalting = true;

		// 待機イベントリストを叩く
		LockList(thread->PoolWaitList);
		{
			num = LIST_NUM(thread->PoolWaitList);
			ee = ToArray(thread->PoolWaitList);

			DeleteAll(thread->PoolWaitList);
		}
		UnlockList(thread->PoolWaitList);

		for (i = 0;i < num;i++)
		{
			EVENT *e = ee[i];

			Set(e);
			ReleaseEvent(e);
		}

		Free(ee);

		while (true)
		{
			if (Count(thread->ref->c) <= 1)
			{
				break;
			}

			Wait(thread->release_event, 256);
		}

		ReleaseThread(thread);

#ifdef	OS_WIN32
		// Win32 の場合: スレッドの優先順位を元に戻す
		MsRestoreThreadPriority();
#endif	// OS_WIN32

		// スレッドプールに自分自身を登録する
		LockSk(thread_pool);
		{
			Push(thread_pool, t);
		}
		UnlockSk(thread_pool);

		Dec(thread_count);
	}
}

// 何もしない
UINT DoNothing()
{
	return g_zero;
}

// スレッド作成 (プール)
THREAD *NewThread(THREAD_PROC *thread_proc, void *param)
{
	THREAD *host = NULL;
	THREAD_POOL_DATA *pd = NULL;
	THREAD *ret;
	bool new_thread = false;
	// 引数チェック
	if (thread_proc == NULL)
	{
		return NULL;
	}

	if (IsTrackingEnabled() == false)
	{
		DoNothing();
	}

	Inc(thread_count);

	LockSk(thread_pool);
	{
		// 現在プールに空いているスレッドがあるかどうか調べる
		host = Pop(thread_pool);
	}
	UnlockSk(thread_pool);

	if (host == NULL)
	{
		// 空いているスレッドが見つからなかったので新しいスレッドを作成する
		pd = ZeroMalloc(sizeof(THREAD_POOL_DATA));
		pd->Event = NewEvent();
		pd->InitFinishEvent = NewEvent();
		host = NewThreadInternal(ThreadPoolProc, pd);
		WaitThreadInitInternal(host);

		new_thread = true;
	}
	else
	{
		pd = (THREAD_POOL_DATA *)host->param;
	}

	// プールスレッドの作成
	ret = ZeroMalloc(sizeof(THREAD));
	ret->ref = NewRef();
	ret->thread_proc = thread_proc;
	ret->param = param;
	ret->pData = NULL;
	ret->init_finished_event = NewEvent();
	ret->PoolThread = true;
	ret->PoolWaitList = NewList(NULL);
	ret->PoolHostThread = host;
	ret->release_event = NewEvent();

	// 実行
	pd->ThreadProc = thread_proc;
	pd->Thread = ret;
	AddRef(ret->ref);

	Set(pd->Event);

	Wait(pd->InitFinishEvent, INFINITE);

	return ret;
}

// スレッドのクリーンアップ (プール)
void CleanupThread(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	ReleaseEvent(t->init_finished_event);
	ReleaseEvent(t->release_event);
	ReleaseList(t->PoolWaitList);

	Free(t);
}

// スレッド解放 (プール)
void ReleaseThread(THREAD *t)
{
	UINT ret;
	EVENT *e;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	e = t->release_event;
	if (e != NULL)
	{
		AddRef(e->ref);
	}

	ret = Release(t->ref);
	Set(e);

	ReleaseEvent(e);

	if (ret == 0)
	{
		CleanupThread(t);
	}
}

// スレッドの初期化完了を通知 (プール)
void NoticeThreadInit(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// 通知
	Set(t->init_finished_event);
}

// スレッドの初期化完了を待機 (プール)
void WaitThreadInit(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_WAITFORTHREAD_COUNT);

	// 待機
	Wait(t->init_finished_event, INFINITE);
}

// スレッドの終了を待機 (プール)
bool WaitThread(THREAD *t, UINT timeout)
{
	bool ret = false;
	EVENT *e = NULL;
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}

	LockList(t->PoolWaitList);
	{
		if (t->PoolHalting)
		{
			// 既に停止済み
			ret = true;
		}
		else
		{
			// 終了時通知イベントをリストに登録する
			e = NewEvent();
			AddRef(e->ref);
			Insert(t->PoolWaitList, e);
		}
	}
	UnlockList(t->PoolWaitList);

	if (e != NULL)
	{
		// イベント待機
		ret = Wait(e, timeout);

		LockList(t->PoolWaitList);
		{
			if (Delete(t->PoolWaitList, e))
			{
				ReleaseEvent(e);
			}
		}
		UnlockList(t->PoolWaitList);

		ReleaseEvent(e);
	}

	return ret;
}

// スレッド ID の取得
UINT ThreadId()
{
	return OSThreadId();
}

// スレッドの作成
THREAD *NewThreadInternal(THREAD_PROC *thread_proc, void *param)
{
	THREAD *t;
	UINT retry = 0;
	// 引数チェック
	if (thread_proc == NULL)
	{
		return NULL;
	}

	// スレッドオブジェクト初期化
	t = ZeroMalloc(sizeof(THREAD));
	t->init_finished_event = NewEvent();

	t->param = param;
	t->ref = NewRef();
	t->thread_proc = thread_proc;

	// OS がスレッドを初期化するまで待機
	while (true)
	{
		if ((retry++) > 60)
		{
			printf("\n\n*** error: new thread create failed.\n\n");
			AbortExit();
		}
		if (OSInitThread(t))
		{
			break;
		}
		SleepThread(500);
	}

	// KS
	KS_INC(KS_NEWTHREAD_COUNT);

	return t;
}

// スレッドの解放
void ReleaseThreadInternal(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	if (Release(t->ref) == 0)
	{
		CleanupThreadInternal(t);
	}
}

// スレッドのクリーンアップ
void CleanupThreadInternal(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// スレッドの解放
	OSFreeThread(t);

	// イベント解放
	ReleaseEvent(t->init_finished_event);
	// メモリ解放
	Free(t);

	// KS
	KS_INC(KS_FREETHREAD_COUNT);
}

// スレッドの終了を待機する
bool WaitThreadInternal(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}

	return OSWaitThread(t);
}

// スレッドの初期化が完了したことを通知する
void NoticeThreadInitInternal(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// 通知
	Set(t->init_finished_event);
}

// スレッドの初期化が完了するまで待機する
void WaitThreadInitInternal(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_WAITFORTHREAD_COUNT);

	// 待機
	Wait(t->init_finished_event, INFINITE);
}

// 日時文字列をロケール情報を使用して取得
void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// 引数チェック
	if (str == NULL || st == NULL)
	{
		return;
	}

	GetDateStrEx(tmp1, sizeof(tmp1), st, locale);
	GetTimeStrEx(tmp2, sizeof(tmp2), st, locale);
	UniFormat(str, size, L"%s %s", tmp1, tmp2);
}

// 時刻文字列をロケール情報を使用して取得
void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t *tag = L"%02u%s%02u%s%02u%s";
	// 引数チェック
	if (str == NULL || st == NULL)
	{
		return;
	}

	if (_GETLANG() == SE_LANG_JAPANESE || _GETLANG() == SE_LANG_CHINESE_ZH)
	{
		tag = L"%2u%s%2u%s%2u%s";
	}

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
		tag,
		st->wHour, locale->HourStr,
		st->wMinute, locale->MinuteStr,
		st->wSecond, locale->SecondStr);
}

// 日付文字列をロケール情報を使用して取得
void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t *tag = L"%04u%s%02u%s%02u%s (%s)";
	// 引数チェック
	if (str == NULL || st == NULL)
	{
		return;
	}

	if (_GETLANG() == SE_LANG_JAPANESE || _GETLANG() == SE_LANG_CHINESE_ZH)
	{
		tag = L"%4u%s%2u%s%2u%s(%s)";
	}

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
		tag,
		st->wYear, locale->YearStr,
		st->wMonth, locale->MonthStr,
		st->wDay, locale->DayStr,
		locale->DayOfWeek[st->wDayOfWeek]);
}

// 時刻文字列をミリ秒単位で取得 (例: 12:34:56.789)
void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st)
{
	// 引数チェック
	if (st == NULL || str == NULL)
	{
		return;
	}

	Format(str, size, "%02u:%02u:%02u.%03u",
		st->wHour, st->wMinute, st->wSecond, st->wMilliseconds);
}

// 時刻文字列を取得 (例: 12:34:56)
void GetTimeStr(char *str, UINT size, SYSTEMTIME *st)
{
	// 引数チェック
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%02u:%02u:%02u",
		st->wHour, st->wMinute, st->wSecond);
}

// 日付文字列を取得 (例: 2004/07/23)
void GetDateStr(char *str, UINT size, SYSTEMTIME *st)
{
	// 引数チェック
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u",
		st->wYear, st->wMonth, st->wDay);
}

// 日時文字列を取得 (例: 2004/07/23 12:34:56)
void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st)
{
	// 引数チェック
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u %02u:%02u:%02u",
		st->wYear, st->wMonth, st->wDay,
		st->wHour, st->wMinute, st->wSecond);
}

// 日時文字列をミリ秒単位で取得 (例: 2004/07/23 12:34:56.789)
void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st)
{
	// 引数チェック
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
		st->wYear, st->wMonth, st->wDay,
		st->wHour, st->wMinute, st->wSecond,
		st->wMilliseconds);
}

// 時間文字列の取得
void GetSpanStr(char *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), "");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
	{
		Format(tmp, sizeof(tmp), "%u:", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)));
	}

	Format(tmp, sizeof(tmp), "%s%02u:%02u:%02u", tmp,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60)) / 1000);

	Trim(tmp);
	StrCpy(str, size, tmp);
}

// 時間文字列の取得 (ミリ秒単位)
void GetSpanStrMilli(char *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), "");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
	{
		Format(tmp, sizeof(tmp), "%u:", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)));
	}

	Format(tmp, sizeof(tmp), "%s%02u:%02u:%02u.%03u", tmp,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60)) / 1000,
		(UINT)(sec64 % (UINT64)(1000)));

	Trim(tmp);
	StrCpy(str, size, tmp);
}

// 時間文字列の取得 (拡張)
void GetSpanStrEx(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	locale = (locale != NULL ? locale : &current_locale);

	UniStrCpy(tmp, sizeof(tmp), L"");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
	{
		UniFormat(tmp, sizeof(tmp), L"%u%s ", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)),
			locale->SpanDay);
	}

	UniFormat(tmp, sizeof(tmp), L"%s%u%s %02u%s %02u%s", tmp,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
		locale->SpanHour,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
		locale->SpanMinute,
		(UINT)(sec64 % (UINT64)(1000 * 60)) / 1000,
		locale->SpanSecond);

	UniTrim(tmp);
	UniStrCpy(str, size, tmp);
}

// 現在のロケール情報を取得
void GetCurrentLocale(LOCALE *locale)
{
	// 引数チェック
	if (locale == NULL)
	{
		return;
	}

	Copy(locale, &current_locale, sizeof(LOCALE));
}

// ロケール情報を設定
void SetLocale(wchar_t *str)
{
	wchar_t *set_locale_str;
	LOCALE tmp;

	if (str != NULL)
	{
		set_locale_str = str;
	}
	else
	{
		set_locale_str = default_locale_str;
	}

	if (LoadLocale(&tmp, set_locale_str) == false)
	{
		if (LoadLocale(&tmp, default_locale_str) == false)
		{
			return;
		}
	}

	Copy(&current_locale, &tmp, sizeof(LOCALE));
}

#define	COPY_LOCALE_STR(dest, size, src)	UniStrCpy(dest, size, UniStrCmp(src, L"$") == 0 ? L"" : src)

// ロケール情報の読み込み
bool LoadLocale(LOCALE *locale, wchar_t *str)
{
	UNI_TOKEN_LIST *tokens;
	UINT i;
	// 引数チェック
	if (locale == NULL || str == NULL)
	{
		return false;
	}

	// トークンの解析
	tokens = UniParseToken(str, L" ");
	if (tokens->NumTokens != 18)
	{
		UniFreeToken(tokens);
		return false;
	}

	// 構造体にセット
	Zero(locale, sizeof(LOCALE));
	COPY_LOCALE_STR(locale->YearStr, sizeof(locale->YearStr), tokens->Token[0]);
	COPY_LOCALE_STR(locale->MonthStr, sizeof(locale->MonthStr), tokens->Token[1]);
	COPY_LOCALE_STR(locale->DayStr, sizeof(locale->DayStr), tokens->Token[2]);
	COPY_LOCALE_STR(locale->HourStr, sizeof(locale->HourStr), tokens->Token[3]);
	COPY_LOCALE_STR(locale->MinuteStr, sizeof(locale->MinuteStr), tokens->Token[4]);
	COPY_LOCALE_STR(locale->SecondStr, sizeof(locale->SecondStr), tokens->Token[5]);

	for (i = 0;i < 7;i++)
	{
		COPY_LOCALE_STR(locale->DayOfWeek[i], sizeof(locale->DayOfWeek[i]),
			tokens->Token[6 + i]);
	}

	COPY_LOCALE_STR(locale->SpanDay, sizeof(locale->SpanDay), tokens->Token[13]);
	COPY_LOCALE_STR(locale->SpanHour, sizeof(locale->SpanHour), tokens->Token[14]);
	COPY_LOCALE_STR(locale->SpanMinute, sizeof(locale->SpanMinute), tokens->Token[15]);
	COPY_LOCALE_STR(locale->SpanSecond, sizeof(locale->SpanSecond), tokens->Token[16]);

	COPY_LOCALE_STR(locale->Unknown, sizeof(locale->Unknown), tokens->Token[17]);

	UniFreeToken(tokens);
	return true;
}

// tm を SYSTEMTIME に変換
void TmToSystem(SYSTEMTIME *st, struct tm *t)
{
	struct tm tmp;
	// 引数チェック
	if (st == NULL || t == NULL)
	{
		return;
	}

	Copy(&tmp, t, sizeof(struct tm));
	NormalizeTm(&tmp);

	Zero(st, sizeof(SYSTEMTIME));
	st->wYear = MAKESURE(tmp.tm_year + 1900, 1970, 2037);
	st->wMonth = MAKESURE(tmp.tm_mon + 1, 1, 12);
	st->wDay = MAKESURE(tmp.tm_mday, 1, 31);
	st->wDayOfWeek = MAKESURE(tmp.tm_wday, 0, 6);
	st->wHour = MAKESURE(tmp.tm_hour, 0, 23);
	st->wMinute = MAKESURE(tmp.tm_min, 0, 59);
	st->wSecond = MAKESURE(tmp.tm_sec, 0, 59);
	st->wMilliseconds = 0;
}

// SYSTEMTIME を tm に変換
void SystemToTm(struct tm *t, SYSTEMTIME *st)
{
	// 引数チェック
	if (t == NULL || st == NULL)
	{
		return;
	}

	Zero(t, sizeof(struct tm));
	t->tm_year = MAKESURE(st->wYear, 1970, 2037) - 1900;
	t->tm_mon = MAKESURE(st->wMonth, 1, 12) - 1;
	t->tm_mday = MAKESURE(st->wDay, 1, 31);
	t->tm_hour = MAKESURE(st->wHour, 0, 23);
	t->tm_min = MAKESURE(st->wMinute, 0, 59);
	t->tm_sec = MAKESURE(st->wSecond, 0, 59);

	t->tm_isdst = -1;
	NormalizeTm(t);
}

// time_t を SYSTEMTIME に変換
void TimeToSystem(SYSTEMTIME *st, time_t t)
{
	struct tm tmp;
	// 引数チェック
	if (st == NULL)
	{
		return;
	}

	TimeToTm(&tmp, t);
	TmToSystem(st, &tmp);
}

// SYSTEMTIME を time_t に変換
time_t SystemToTime(SYSTEMTIME *st)
{
	struct tm t;
	// 引数チェック
	if (st == NULL)
	{
		return 0;
	}

	SystemToTm(&t, st);
	return TmToTime(&t);
}

// tm を time_t に変換
time_t TmToTime(struct tm *t)
{
	time_t tmp;
	// 引数チェック
	if (t == NULL)
	{
		return 0;
	}

	tmp = c_mkgmtime(t);
	if (tmp == (time_t)-1)
	{
		return 0;
	}
	return tmp;
}

// time_t を tm に変換
void TimeToTm(struct tm *t, time_t time)
{
	struct tm *ret;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

#ifndef	OS_UNIX
	ret = gmtime(&time);
#else	// OS_UNIX
	ret = malloc(sizeof(struct tm));
	memset(ret, 0, sizeof(ret));
	gmtime_r(&time, ret);
#endif	// OS_UNIX

	if (ret == NULL)
	{
		Zero(t, sizeof(struct tm));
	}
	else
	{
		Copy(t, ret, sizeof(struct tm));
	}

#ifdef	OS_UNIX
	free(ret);
#endif	// OS_UNIX
}

// tm を正規化
void NormalizeTm(struct tm *t)
{
	struct tm *ret;
	time_t tmp;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	tmp = c_mkgmtime(t);
	if (tmp == (time_t)-1)
	{
		return;
	}

#ifndef	OS_UNIX
	ret = gmtime(&tmp);
#else	// OS_UNIX
	ret = malloc(sizeof(struct tm));
	memset(ret, 0, sizeof(ret));
	gmtime_r(&tmp, ret);
#endif	// OS_UNIX

	if (ret == NULL)
	{
		Zero(t, sizeof(struct tm));
	}
	else
	{
		Copy(t, ret, sizeof(struct tm));
	}

#ifdef	OS_UNIX
	free(ret);
#endif	// OS_UNIX
}

// SYSTEMTIME を正規化
void NormalizeSystem(SYSTEMTIME *st)
{
	UINT64 sec64;
	// 引数チェック
	if (st == NULL)
	{
		return;
	}

	sec64 = SystemToUINT64(st);
	UINT64ToSystem(st, sec64);
}

// 64bit ローカル時刻をシステム時刻に変換
UINT64 LocalToSystem64(UINT64 t)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	LocalToSystem(&st, &st);
	return SystemToUINT64(&st);
}

// 64bit システム時刻をローカル時刻に変換
UINT64 SystemToLocal64(UINT64 t)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	SystemToLocal(&st, &st);
	return SystemToUINT64(&st);
}

// ローカル時刻をシステム時刻に変換
void LocalToSystem(SYSTEMTIME *system, SYSTEMTIME *local)
{
	UINT64 sec64;
	// 引数チェック
	if (local == NULL || system == NULL)
	{
		return;
	}

	sec64 = (UINT64)((INT64)SystemToUINT64(local) - GetTimeDiffEx(local, true));
	UINT64ToSystem(system, sec64);
}

// システム時刻をローカル時刻に変換
void SystemToLocal(SYSTEMTIME *local, SYSTEMTIME *system)
{
	UINT64 sec64;
	// 引数チェック
	if (local == NULL || system == NULL)
	{
		return;
	}

	sec64 = (UINT64)((INT64)SystemToUINT64(system) + GetTimeDiffEx(system, false));
	UINT64ToSystem(local, sec64);
}

// 指定時刻をベースにしてシステム時刻とローカル時刻との間の時差を取得
INT64 GetTimeDiffEx(SYSTEMTIME *basetime, bool local_time)
{
	time_t tmp;
	struct tm t1, t2;
	SYSTEMTIME snow;
	struct tm now;
	SYSTEMTIME s1, s2;
	INT64 ret;

	Copy(&snow, basetime, sizeof(SYSTEMTIME));

	SystemToTm(&now, &snow);
	if (local_time == false)
	{
		tmp = c_mkgmtime(&now);
	}
	else
	{
		tmp = mktime(&now);
	}

	if (tmp == (time_t)-1)
	{
		return 0;
	}

	Copy(&t1, localtime(&tmp), sizeof(struct tm));
	Copy(&t2, gmtime(&tmp), sizeof(struct tm));
	TmToSystem(&s1, &t1);
	TmToSystem(&s2, &t2);

	ret = (INT)SystemToUINT64(&s1) - (INT)SystemToUINT64(&s2);

	return ret;
}

// システム時刻とローカル時刻との間の時差を取得
INT64 GetTimeDiff()
{
	time_t tmp;
	struct tm t1, t2;
	SYSTEMTIME snow;
	struct tm now;
	SYSTEMTIME s1, s2;
	INT64 ret;

	static INT64 cache = INFINITE;

	if (cache != INFINITE)
	{
		// 1 度測定したらキャッシュデータを返す
		return cache;
	}

	SystemTime(&snow);
	SystemToTm(&now, &snow);
	tmp = c_mkgmtime(&now);
	if (tmp == (time_t)-1)
	{
		return 0;
	}

	Copy(&t1, localtime(&tmp), sizeof(struct tm));
	Copy(&t2, gmtime(&tmp), sizeof(struct tm));
	TmToSystem(&s1, &t1);
	TmToSystem(&s2, &t2);

	cache = ret = (INT)SystemToUINT64(&s1) - (INT)SystemToUINT64(&s2);

	return ret;
}

// UINT64 を SYSTEMTIME に変換
void UINT64ToSystem(SYSTEMTIME *st, UINT64 sec64)
{
	UINT64 tmp64;
	UINT sec, millisec;
	time_t time;
	// 引数チェック
	if (st == NULL)
	{
		return;
	}

	sec64 = SafeTime64(sec64 + 32400000ULL);
	tmp64 = sec64 / (UINT64)1000;
	millisec = (UINT)(sec64 - tmp64 * (UINT64)1000);
	sec = (UINT)tmp64;
	time = (time_t)sec;
	TimeToSystem(st, time);
	st->wMilliseconds = (WORD)millisec;
}

// SYSTEMTIME を UINT64 に変換
UINT64 SystemToUINT64(SYSTEMTIME *st)
{
	UINT64 sec64;
	time_t time;
	// 引数チェック
	if (st == NULL)
	{
		return 0;
	}

	time = SystemToTime(st);
	sec64 = (UINT64)time * (UINT64)1000;
	sec64 += st->wMilliseconds;

	return sec64 - 32400000ULL;
}

// ローカル時刻を UINT64 で取得
UINT64 LocalTime64()
{
	SYSTEMTIME s;
	LocalTime(&s);
	return SystemToUINT64(&s);
}

// システム時刻を UINT64 で取得
UINT64 SystemTime64()
{
	SYSTEMTIME s;
	SystemTime(&s);
	return SystemToUINT64(&s);
}

// ローカル時刻の取得
void LocalTime(SYSTEMTIME *st)
{
	SYSTEMTIME tmp;
	// 引数チェック
	if (st == NULL)
	{
		return;
	}

	SystemTime(&tmp);
	SystemToLocal(st, &tmp);
}

// システム時刻の取得
void SystemTime(SYSTEMTIME *st)
{
	// 引数チェック
	if (st == NULL)
	{
		return;
	}

	OSGetSystemTime(st);

	// KS
	KS_INC(KS_GETTIME_COUNT);
}

/* free mktime function
   Copyright 1988, 1989 by David MacKenzie <djm@ai.mit.edu>
   and Michael Haertel <mike@ai.mit.edu>
   Unlimited distribution permitted provided this copyright notice is
   retained and any functional modifications are prominently identified.  */
time_t c_mkgmtime(struct tm *tm)
{
	int years, months, days, hours, minutes, seconds;

	years = tm->tm_year + 1900;   /* year - 1900 -> year */
	months = tm->tm_mon;          /* 0..11 */
	days = tm->tm_mday - 1;       /* 1..31 -> 0..30 */
	hours = tm->tm_hour;          /* 0..23 */
	minutes = tm->tm_min;         /* 0..59 */
	seconds = tm->tm_sec;         /* 0..61 in ANSI C. */

	ADJUST_TM(seconds, minutes, 60);
	ADJUST_TM(minutes, hours, 60);
	ADJUST_TM(hours, days, 24);
	ADJUST_TM(months, years, 12);
	if (days < 0)
		do {
			if (--months < 0) {
				--years;
				months = 11;
			}
			days += monthlen(months, years);
		} while (days < 0);
	else
		while (days >= monthlen(months, years)) {
			days -= monthlen(months, years);
			if (++months >= 12) {
				++years;
				months = 0;
			}
		}

		/* Restore adjusted values in tm structure */
		tm->tm_year = years - 1900;
		tm->tm_mon = months;
		tm->tm_mday = days + 1;
		tm->tm_hour = hours;
		tm->tm_min = minutes;
		tm->tm_sec = seconds;

		/* Set `days' to the number of days into the year. */
		days += ydays[months] + (months > 1 && leap (years));
		tm->tm_yday = days;

		/* Now calculate `days' to the number of days since Jan 1, 1970. */
		days = (unsigned)days + 365 * (unsigned)(years - 1970) +
			(unsigned)(nleap (years));
		tm->tm_wday = ((unsigned)days + 4) % 7; /* Jan 1, 1970 was Thursday. */
		tm->tm_isdst = 0;

		if (years < 1970)
			return (time_t)-1;

#if (defined(TM_YEAR_MAX) && defined(TM_MON_MAX) && defined(TM_MDAY_MAX))
#if (defined(TM_HOUR_MAX) && defined(TM_MIN_MAX) && defined(TM_SEC_MAX))
		if (years > TM_YEAR_MAX ||
			(years == TM_YEAR_MAX &&
			(tm->tm_yday > ydays[TM_MON_MAX] + (TM_MDAY_MAX - 1) +
			(TM_MON_MAX > 1 && leap (TM_YEAR_MAX)) ||
			(tm->tm_yday == ydays[TM_MON_MAX] + (TM_MDAY_MAX - 1) +
			(TM_MON_MAX > 1 && leap (TM_YEAR_MAX)) &&
			(hours > TM_HOUR_MAX ||
			(hours == TM_HOUR_MAX &&
			(minutes > TM_MIN_MAX ||
			(minutes == TM_MIN_MAX && seconds > TM_SEC_MAX) )))))))
			return (time_t)-1;
#endif
#endif

		return (time_t)(86400L * (unsigned long)(unsigned)days +
			3600L * (unsigned long)hours +
			(unsigned long)(60 * minutes + seconds));
}

// システムタイマの取得
UINT Tick()
{
	// KS
	KS_INC(KS_GETTICK_COUNT);
	return OSGetTick();
}

// スレッドのスリープ
void SleepThread(UINT time)
{
	// KS
	KS_INC(KS_SLEEPTHREAD_COUNT);

	OSSleep(time);
}

// イールド
void YieldCpu()
{
	OSYield();
}

// システム停止 (異常終了)
void AbortExit()
{
#ifdef	OS_WIN32
	_exit(1);
#else	// OS_WIN32

#ifdef	RLIMIT_CORE
	UnixSetResourceLimit(RLIMIT_CORE, 0);
#endif	// RLIMIT_CORE

	abort();
#endif	// OS_WIN32
}


void AbortExitEx(char *msg)
{
	FILE *f;
	// 引数チェック
	if (msg == NULL)
	{
		msg = "Unknown Error";
	}

	f = fopen("abort_error_log.txt", "w");
	if (f != NULL)
	{
		fwrite(msg, 1, strlen(msg), f);
		fclose(f);
	}

	fputs("Fatal Error: ", stdout);
	fputs(msg, stdout);
	fputs("\r\n", stdout);

#ifdef	OS_WIN32
	_exit(1);
#else	// OS_WIN32

#ifdef	RLIMIT_CORE
	UnixSetResourceLimit(RLIMIT_CORE, 0);
#endif	// RLIMIT_CORE

	abort();
#endif	// OS_WIN32
}

