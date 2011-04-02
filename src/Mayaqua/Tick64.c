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

// Tick64.c
// 64bit リアルタイムクロックプログラム

#ifdef	WIN32
#include <windows.h>
#endif	// WIN32


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

static TICK64 *tk64 = NULL;
static EVENT *halt_tick_event = NULL;

// 高解像度時刻を取得
UINT64 TickHighres64()
{
	UINT64 ret = 0;

#ifdef	OS_WIN32

	ret = (UINT64)(MsGetHiResTimeSpan(MsGetHiResCounter()) * 1000.0f);

#else	// OS_WIN32

	return Tick64();

#endif	// OS_WIN32

	return ret;
}

// Tick 値を時刻に変換
UINT64 Tick64ToTime64(UINT64 tick)
{
	UINT64 ret = 0;
	if (tick == 0)
	{
		return 0;
	}
	LockList(tk64->AdjustTime);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(tk64->AdjustTime);i++)
		{
			ADJUST_TIME *t = LIST_DATA(tk64->AdjustTime, i);
			if (t->Tick <= tick)
			{
				ret = t->Time + (tick - t->Tick);
			}
		}
	}
	UnlockList(tk64->AdjustTime);
	if (ret == 0)
	{
		ret++;
	}
	return ret;
}

// Tick 値を時刻に変換
UINT64 TickToTime(UINT64 tick)
{
	return Tick64ToTime64(tick);
}

// Tick 値を取得
UINT64 Tick64()
{
#ifdef	OS_WIN32
	return Win32FastTick64();
#else	// OS_WIN32
	UINT64 tick64;
	if (tk64 == NULL)
	{
		return 0;
	}
	Lock(tk64->TickLock);
	{
		tick64 = tk64->Tick;
	}
	Unlock(tk64->TickLock);
	return tick64;
#endif	// OS_WIN32
}

// リアルタイムクロック測定用スレッド
void Tick64Thread(THREAD *thread, void *param)
{
	UINT n = 0;
	bool first = false;
	bool create_first_entry = true;
	UINT tick_span;
	// 引数チェック
	if (thread == NULL)
	{
		return;
	}

#ifdef	OS_WIN32

	// Win32 スレッドの優先順位を上げる
	MsSetThreadPriorityRealtime();

	tick_span = TICK64_SPAN_WIN32;

#else	// OS_WIN32

	// POSIX スレッドの優先順位を上げる
	UnixSetThreadPriorityRealtime();

	tick_span = TICK64_SPAN;

#endif	// OS_WIN32

	while (true)
	{
		UINT tick;
		UINT64 tick64;

#ifndef	OS_WIN32
		tick = TickRealtime();		// 現在のシステムクロックを取得

		if (tk64->LastTick > tick)
		{
			if ((tk64->LastTick - tick) >= (UINT64)0x0fffffff)
			{
				// tick の値が 1 周した
				tk64->RoundCount++;
			}
			else
			{
				// tick の値が逆戻りした (システム管理者がハードウェア時計を変更した)
				// 通常これは 1 秒以内の誤差として発生する
				tick = tk64->LastTick;
			}
		}
		tk64->LastTick = tick;

		tick64 = (UINT64)tk64->RoundCount * (UINT64)4294967296LL + (UINT64)tick;

		Lock(tk64->TickLock);
		{
			if (tk64->TickStart == 0)
			{
				tk64->TickStart = tick64;
			}
			tick64 = tk64->Tick = tick64 - tk64->TickStart + (UINT64)1;
		}
		Unlock(tk64->TickLock);
#else	// OS_WIN32
		tick64 = Win32FastTick64();
		tick = (UINT)tick64;
#endif	// OS_WIN32

		if (create_first_entry)
		{
			ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));
			t->Tick = tick64;
			t->Time = SystemTime64();
			tk64->Tick64WithTime64 = tick64;
			tk64->Time64 = t->Time;
			Add(tk64->AdjustTime, t);

			// 初期化完了を通知
			NoticeThreadInit(thread);
			create_first_entry = false;
		}

		// 時刻補正
		n += tick_span;
		if (n >= 1000 || first == false)
		{
			UINT64 now = SystemTime64();

			if (now < tk64->Time64 ||
				Diff64((now - tk64->Time64) + tk64->Tick64WithTime64, tick64) >= tick_span)
			{
				ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));
				LockList(tk64->AdjustTime);
				{
					t->Tick = tick64;
					t->Time = now;
					Add(tk64->AdjustTime, t);
					Debug("Adjust Time: Tick = %I64u, Time = %I64u\n",
						t->Tick, t->Time);

					// 時計が狂っているシステムでメモリを無限に食わないように
					if (LIST_NUM(tk64->AdjustTime) > MAX_ADJUST_TIME)
					{
						// 2 個目を削除する
						ADJUST_TIME *t2 = LIST_DATA(tk64->AdjustTime, 1);

						Delete(tk64->AdjustTime, t2);

						Debug("NUM_ADJUST TIME: %u\n", LIST_NUM(tk64->AdjustTime));

						Free(t2);
					}
				}
				UnlockList(tk64->AdjustTime);
				tk64->Time64 = now;
				tk64->Tick64WithTime64 = tick64;
			}
			first = true;
			n = 0;
		}

		if (tk64->Halt)
		{
			break;
		}

#ifdef	OS_WIN32
		Wait(halt_tick_event, tick_span);
#else	// OS_WIN32
		SleepThread(tick_span);
#endif	// OS_WIN32
	}
}

// 2 つの 64 bit 整数の差の絶対値を取得
UINT64 Diff64(UINT64 a, UINT64 b)
{
	if (a > b)
	{
		return a - b;
	}
	else
	{
		return b - a;
	}
}

// Tick64 の初期化
void InitTick64()
{
	if (tk64 != NULL)
	{
		// すでに初期化されている
		return;
	}

	halt_tick_event = NewEvent();

	// 構造体の初期化
	tk64 = ZeroMalloc(sizeof(TICK64));
	tk64->TickLock = NewLock();
	tk64->AdjustTime = NewList(NULL);

	// スレッドの作成
	tk64->Thread = NewThread(Tick64Thread, NULL);
	WaitThreadInit(tk64->Thread);
}

// Tick64 の解放
void FreeTick64()
{
	UINT i;
	if (tk64 == NULL)
	{
		// 初期化されていない
		return;
	}

	// 終了処理
	tk64->Halt = true;
	Set(halt_tick_event);
	WaitThread(tk64->Thread, INFINITE);
	ReleaseThread(tk64->Thread);

	// 解放処理
	for (i = 0;i < LIST_NUM(tk64->AdjustTime);i++)
	{
		ADJUST_TIME *t = LIST_DATA(tk64->AdjustTime, i);
		Free(t);
	}
	ReleaseList(tk64->AdjustTime);
	DeleteLock(tk64->TickLock);
	Free(tk64);
	tk64 = NULL;

	ReleaseEvent(halt_tick_event);
	halt_tick_event = NULL;
}

