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

// Object.c
// オブジェクト管理コード

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// 試しにロックをかけてみるスレッド
void CheckDeadLockThread(THREAD *t, void *param)
{
	DEADCHECK *c = (DEADCHECK *)param;

	if (t == NULL || c == NULL)
	{
		return;
	}

	NoticeThreadInit(t);

	Lock(c->Lock);
	Unlock(c->Lock);
	c->Unlocked = true;
}

// デッドロックの検出
void CheckDeadLock(LOCK *lock, UINT timeout, char *name)
{
	DEADCHECK c;
	THREAD *t;
	char msg[MAX_PATH];

	if (lock == NULL)
	{
		return;
	}
	if (name == NULL)
	{
		name = "Unknown";
	}

	Format(msg, sizeof(msg), "error: CheckDeadLock() Failed: %s\n", name);

	Zero(&c, sizeof(c));
	c.Lock = lock;
	c.Timeout = timeout;
	c.Unlocked = false;

	t = NewThread(CheckDeadLockThread, &c);
	WaitThreadInit(t);
	if (WaitThread(t, timeout) == false)
	{
		if (c.Unlocked == false)
		{
			// デッドロック発生
			AbortExitEx(msg);
		}
		else
		{
			WaitThread(t, INFINITE);
		}
	}

	ReleaseThread(t);
}

// ロックオブジェクトの作成
LOCK *NewLockMain()
{
	LOCK *lock;
	UINT retry = 0;

	while (true)
	{
		if ((retry++) > OBJECT_ALLOC__MAX_RETRY)
		{
			AbortExitEx("error: OSNewLock() failed.\n\n");
		}
		lock = OSNewLock();
		if (lock != NULL)
		{
			break;
		}
		SleepThread(OBJECT_ALLOC_FAIL_SLEEP_TIME);
	}

	return lock;
}
LOCK *NewLock()
{
	LOCK *lock = NewLockMain();

	// KS
	KS_INC(KS_NEWLOCK_COUNT);
	KS_INC(KS_CURRENT_LOCK_COUNT);

	return lock;
}

// ロックオブジェクトの削除
void DeleteLock(LOCK *lock)
{
	// 引数チェック
	if (lock == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_DELETELOCK_COUNT);
	KS_DEC(KS_CURRENT_LOCK_COUNT);

	OSDeleteLock(lock);
}

// ロック
bool LockInner(LOCK *lock)
{
	// 引数チェック
	if (lock == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_LOCK_COUNT);
	KS_INC(KS_CURRENT_LOCKED_COUNT);

	return OSLock(lock);
}

// ロック解除
void UnlockInner(LOCK *lock)
{
	// 引数チェック
	if (lock == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_UNLOCK_COUNT);
	KS_DEC(KS_CURRENT_LOCKED_COUNT);

	OSUnlock(lock);
}

// カウンタの作成
COUNTER *NewCounter()
{
	COUNTER *c;

	// メモリ確保
	c = Malloc(sizeof(COUNTER));

	// 初期化
	c->Ready = true;
	c->c = 0;

	// ロック作成
	c->lock = NewLock();

	// KS
	KS_INC(KS_NEW_COUNTER_COUNT);

	return c;
}

// カウンタの削除
void DeleteCounter(COUNTER *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_DELETE_COUNTER_COUNT);
	KS_SUB(KS_CURRENT_COUNT, c->c);

	DeleteLock(c->lock);
	Free(c);
}

// カウント値の取得
UINT Count(COUNTER *c)
{
	UINT ret;
	// 引数チェック
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		if (c->Ready == false)
		{
			ret = 0;
		}
		else
		{
			ret = c->c;
		}
	}
	Unlock(c->lock);

	return ret;
}

// インクリメント
UINT Inc(COUNTER *c)
{
	UINT ret;
	// 引数チェック
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		if (c->Ready == false)
		{
			ret = 0;
		}
		else
		{
			c->c++;
			ret = c->c;
		}
	}
	Unlock(c->lock);

	// KS
	KS_INC(KS_INC_COUNT);
	KS_INC(KS_CURRENT_COUNT);

	return ret;
}

// デクリメント
UINT Dec(COUNTER *c)
{
	UINT ret;
	// 引数チェック
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		if (c->Ready == false)
		{
			ret = 0;
		}
		else
		{
			if (c->c != 0)
			{
				c->c--;
				ret = c->c;
			}
			else
			{
				ret = 0;
			}
		}
	}
	Unlock(c->lock);

	// KS
	KS_INC(KS_DEC_COUNT);
	KS_DEC(KS_CURRENT_COUNT);

	return ret;
}


// 参照カウンタの解放
UINT Release(REF *ref)
{
	UINT c;
	// 引数チェック
	if (ref == NULL)
	{
		return 0;
	}

	// KS
	KS_INC(KS_RELEASE_COUNT);
	KS_DEC(KS_CURRENT_REFED_COUNT);

	c = Dec(ref->c);
	if (c == 0)
	{
		// KS
		KS_DEC(KS_CURRENT_REF_COUNT);
		KS_INC(KS_FREEREF_COUNT);

		DeleteCounter(ref->c);
		ref->c = 0;
		Free(ref);
	}
	return c;
}

// 参照カウンタの増加
UINT AddRef(REF *ref)
{
	UINT c;
	// 引数チェック
	if (ref == NULL)
	{
		return 0;
	}

	c = Inc(ref->c);

	// KS
	KS_INC(KS_ADDREF_COUNT);
	KS_INC(KS_CURRENT_REFED_COUNT);

	return c;
}

// 参照カウンタ作成
REF *NewRef()
{
	REF *ref;

	// メモリ確保
	ref = Malloc(sizeof(REF));

	// カウンタ作成
	ref->c = NewCounter();

	// 1 回だけインクリメント
	Inc(ref->c);

	// KS
	KS_INC(KS_NEWREF_COUNT);
	KS_INC(KS_CURRENT_REF_COUNT);
	KS_INC(KS_ADDREF_COUNT);
	KS_INC(KS_CURRENT_REFED_COUNT);

	return ref;
}

// イベントオブジェクトの作成
EVENT *NewEvent()
{
	// メモリ確保
	EVENT *e = Malloc(sizeof(EVENT));

	// 参照カウンタ
	e->ref = NewRef();

	// イベント初期化
	OSInitEvent(e);

	// KS
	KS_INC(KS_NEWEVENT_COUNT);

	return e;
}

// イベントの解放
void ReleaseEvent(EVENT *e)
{
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	if (Release(e->ref) == 0)
	{
		CleanupEvent(e);
	}
}

// イベントの削除
void CleanupEvent(EVENT *e)
{
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	// イベント解放
	OSFreeEvent(e);

	// メモリ解放
	Free(e);

	// KS
	KS_INC(KS_FREEEVENT_COUNT);
}

// イベントのセット
void Set(EVENT *e)
{
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	OSSetEvent(e);
}

// イベントの待機
bool Wait(EVENT *e, UINT timeout)
{
	// 引数チェック
	if (e == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_WAIT_COUNT);

	return OSWaitEvent(e, timeout);
}



