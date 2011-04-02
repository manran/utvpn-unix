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

// Tracking.c
// オブジェクト追跡モジュール

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// グローバル変数
static LOCK *obj_lock;
static LOCK *obj_id_lock;
static UINT obj_id;
static LOCK *cs_lock;
static bool disable_tracking = false;
static TRACKING_LIST **hashlist;

static bool do_not_get_callstack;

// 追跡を有効にする
void TrackingEnable()
{
	disable_tracking = false;
}

// 追跡を無効にする
void TrackingDisable()
{
	disable_tracking = true;
}

// 追跡が有効かどうか取得
bool IsTrackingEnabled()
{
	return !disable_tracking;
}

// メモリデバッグメニュー
void MemoryDebugMenu()
{
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	char *cmd;
	Print("Mayaqua Kernel Memory Debug Tools\n"
		"Copyright (C) SoftEther Corporation. All Rights Reserved.\n\n");
	g_memcheck = false;
	while (true)
	{
		Print("debug>");
		GetLine(tmp, sizeof(tmp));
		t = ParseToken(tmp, " \t");
		if (t->NumTokens == 0)
		{
			FreeToken(t);
			DebugPrintAllObjects();
			continue;
		}
		cmd = t->Token[0];
		if (!StrCmpi(cmd, "?"))
		{
			DebugPrintCommandList();
		}
		else if (!StrCmpi(cmd, "a"))
		{
			DebugPrintAllObjects();
		}
		else if (!StrCmpi(cmd, "i"))
		{
			if (t->NumTokens == 1)
			{
				Print("Usage: i <obj_id>\n\n");
			}
			else
			{
				DebugPrintObjectInfo(ToInt(t->Token[1]));
			}
		}
		else if (!StrCmpi(cmd, "q"))
		{
			break;
		}
		else if (ToInt(cmd) != 0)
		{
			DebugPrintObjectInfo(ToInt(t->Token[0]));
		}
		else
		{
			Print("Command Not Found,\n\n");
		}
		FreeToken(t);
	}
	FreeToken(t);
	g_memcheck = true;
}

// オブジェクトを時間順にソートする
int SortObjectView(void *p1, void *p2)
{
	TRACKING_OBJECT *o1, *o2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	o1 = *(TRACKING_OBJECT **)p1;
	o2 = *(TRACKING_OBJECT **)p2;
	if (o1 == NULL || o2 == NULL)
	{
		return 0;
	}

	if (o1->Id > o2->Id)
	{
		return 1;
	}
	else if (o1->Id == o2->Id)
	{
		return 0;
	}
	return -1;
}

// オブジェクト情報の表示
void PrintObjectInfo(TRACKING_OBJECT *o)
{
	SYSTEMTIME t;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	UINT64ToSystem(&t, o->CreatedDate);
	GetDateTimeStrMilli(tmp, sizeof(tmp), &t);

	Print("    TRACKING_OBJECT ID: %u\n"
		"  TRACKING_OBJECT TYPE: %s\n"
		"      ADDRESS: 0x%p\n"
		"  TRACKING_OBJECT SIZE: %u bytes\n"
		" CREATED DATE: %s\n",
		o->Id, o->Name, UINT64_TO_POINTER(o->Address), o->Size, tmp);

	PrintCallStack(o->CallStack);
}

// オブジェクト情報を表示する
void DebugPrintObjectInfo(UINT id)
{
	UINT i;
	TRACKING_OBJECT *o;

	// 検索
	o = NULL;
	LockTrackingList();
	{
		for (i = 0;i < TRACKING_NUM_ARRAY;i++)
		{
			if (hashlist[i] != NULL)
			{
				TRACKING_LIST *t = hashlist[i];

				while (true)
				{
					if (t->Object->Id == id)
					{
						o = t->Object;
						break;
					}

					if (t->Next == NULL)
					{
						break;
					}

					t = t->Next;
				}

				if (o != NULL)
				{
					break;
				}
			}
		}
	}
	UnlockTrackingList();

	if (o == NULL)
	{
		// ID が発見できなかった
		Print("obj_id %u Not Found.\n\n", id);
		return;
	}

	PrintObjectInfo(o);
	Print("\n");
}

// オブジェクトのサマリーの表示
void PrintObjectList(TRACKING_OBJECT *o)
{
	char tmp[MAX_SIZE];
	SYSTEMTIME t;
	UINT64ToSystem(&t, o->CreatedDate);
	GetTimeStrMilli(tmp, sizeof(tmp), &t);
	TrackGetObjSymbolInfo(o);
	Print("%-4u - [%-6s] %s 0x%p size=%-5u %11s %u\n",
		o->Id, o->Name, tmp, UINT64_TO_POINTER(o->Address), o->Size, o->FileName, o->LineNumber);
}

// すべてのオブジェクトの表示
void DebugPrintAllObjects()
{
	UINT i;
	LIST *view;

	// リスト作成
	view = NewListFast(SortObjectView);
	LockTrackingList();
	{
		for (i = 0;i < TRACKING_NUM_ARRAY;i++)
		{
			if (hashlist[i] != NULL)
			{
				TRACKING_LIST *t = hashlist[i];

				while (true)
				{
					Add(view, t->Object);

					if (t->Next == NULL)
					{
						break;
					}

					t = t->Next;
				}
			}
		}
	}
	UnlockTrackingList();

	// ソート
	Sort(view);

	// 描画
	for (i = 0;i < LIST_NUM(view);i++)
	{
		TRACKING_OBJECT *o = (TRACKING_OBJECT *)LIST_DATA(view, i);
		PrintObjectList(o);
	}

	// リスト解放
	ReleaseList(view);

	Print("\n");
}

// コマンド一覧
void DebugPrintCommandList()
{
	Print(
		"a - All Objects\n"
		"i - Object Information\n"
		"? - Help\n"
		"q - Quit\n\n"
		);
}

// メモリの使用状態を表示する
void PrintMemoryStatus()
{
	MEMORY_STATUS s;
	GetMemoryStatus(&s);
	Print("MEMORY STATUS:\n"
		" NUM_OF_MEMORY_BLOCKS: %u\n"
		" SIZE_OF_TOTAL_MEMORY: %u bytes\n",
		s.MemoryBlocksNum, s.MemorySize);
}

// メモリの使用状態を取得する
void GetMemoryStatus(MEMORY_STATUS *status)
{
	UINT i, num, size;
	// 引数チェック
	if (status == NULL)
	{
		return;
	}

	LockTrackingList();
	{
		size = num = 0;

		for (i = 0;i < TRACKING_NUM_ARRAY;i++)
		{
			if (hashlist[i] != NULL)
			{
				TRACKING_LIST *t = hashlist[i];

				while (true)
				{
					TRACKING_OBJECT *o = t->Object;

					if (StrCmpi(o->Name, "MEM") == 0)
					{
						num++;
						size += o->Size;
					}

					if (t->Next == NULL)
					{
						break;
					}

					t = t->Next;
				}
			}
		}
	}
	UnlockTrackingList();

	status->MemoryBlocksNum = num;
	status->MemorySize = size;
}

// オブジェクトからシンボル情報を取得する
void TrackGetObjSymbolInfo(TRACKING_OBJECT *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	if (!(o->LineNumber == 0 && o->FileName[0] == 0))
	{
		return;
	}

	if (o->CallStack != NULL)
	{
		GetCallStackSymbolInfo(o->CallStack);
		if (StrLen(o->CallStack->filename) != 0 && o->CallStack->line != 0)
		{
			StrCpy(o->FileName, sizeof(o->FileName), o->CallStack->filename);
			o->LineNumber = o->CallStack->line;
		}
	}
}

// 新しいオブジェクトを追跡リストに入れる
void TrackNewObj(UINT64 addr, char *name, UINT size)
{
	TRACKING_OBJECT *o;
	UINT new_id;
	// 引数チェック
	if (addr == 0 || name == NULL)
	{
		return;
	}

	if (IsMemCheck() == false)
	{
		// リリースモードでは追跡しない
		return;
	}

	if (disable_tracking)
	{
		return;
	}

	// 新しい ID の生成
	OSLock(obj_id_lock);
	{
		new_id = ++obj_id;
	}
	OSUnlock(obj_id_lock);

	o = OSMemoryAlloc(sizeof(TRACKING_OBJECT));
	o->Id = new_id;
	o->Address = addr;
	o->Name = name;
	o->Size = size;
	o->CreatedDate = LocalTime64();
	o->CallStack = WalkDownCallStack(GetCallStack(), 2);

	o->FileName[0] = 0;
	o->LineNumber = 0;

	LockTrackingList();
	{
		InsertTrackingList(o);
	}
	UnlockTrackingList();
}

// 追跡リストからオブジェクトを削除する
void TrackDeleteObj(UINT64 addr)
{
	TRACKING_OBJECT *o;
	// 引数チェック
	if (addr == 0)
	{
		return;
	}

	if (IsMemCheck() == false)
	{
		// リリースモードでは追跡しない
		return;
	}

	if (disable_tracking)
	{
		return;
	}

	LockTrackingList();
	{
		o = SearchTrackingList(addr);
		if (o == NULL)
		{
			UnlockTrackingList();

			if (IsDebug())
			{
				printf("TrackDeleteObj: 0x%x is not Object!!\n", (void *)addr);
			}
			return;
		}
		DeleteTrackingList(o, true);
	}
	UnlockTrackingList();
}

// 追跡しているオブジェクトのサイズを変更する
void TrackChangeObjSize(UINT64 addr, UINT size, UINT64 new_addr)
{
	TRACKING_OBJECT *o;
	// 引数チェック
	if (addr == 0)
	{
		return;
	}

	if (IsMemCheck() == false)
	{
		// リリースモードでは追跡しない
		return;
	}

	if (disable_tracking)
	{
		return;
	}

	LockTrackingList();
	{
		o = SearchTrackingList(addr);
		if (o == NULL)
		{
			UnlockTrackingList();
			return;
		}

		DeleteTrackingList(o, false);

		o->Size = size;
		o->Address = new_addr;

		InsertTrackingList(o);
	}
	UnlockTrackingList();
}

// メモリアドレス比較関数
int CompareTrackingObject(const void *p1, const void *p2)
{
	TRACKING_OBJECT *o1, *o2;
	// 引数チェック
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	o1 = *(TRACKING_OBJECT **)p1;
	o2 = *(TRACKING_OBJECT **)p2;
	if (o1 == NULL || o2 == NULL)
	{
		return 0;
	}

	if (o1->Address > o2->Address)
	{
		return 1;
	}
	if (o1->Address == o2->Address)
	{
		return 0;
	}
	return -1;
}

// オブジェクトをトラッキングリストから検索
TRACKING_OBJECT *SearchTrackingList(UINT64 Address)
{
	UINT i;
	// 引数チェック
	if (Address == 0)
	{
		return NULL;
	}

	i = TRACKING_HASH(Address);

	if (hashlist[i] != NULL)
	{
		TRACKING_LIST *tt = hashlist[i];

		while (true)
		{
			if (tt->Object->Address == Address)
			{
				return tt->Object;
			}

			tt = tt->Next;

			if (tt == NULL)
			{
				break;
			}
		}
	}

	return NULL;
}

// オブジェクトをトラッキングリストから削除
void DeleteTrackingList(TRACKING_OBJECT *o, bool free_object_memory)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	i = TRACKING_HASH(o->Address);

	if (hashlist[i] != NULL)
	{
		TRACKING_LIST *ft = NULL;

		if (hashlist[i]->Object == o)
		{
			ft = hashlist[i];
			hashlist[i] = hashlist[i]->Next;
		}
		else
		{
			TRACKING_LIST *tt = hashlist[i];
			TRACKING_LIST *prev = NULL;

			while (true)
			{
				if (tt->Object == o)
				{
					prev->Next = tt->Next;
					ft = tt;
					break;
				}

				if (tt->Next == NULL)
				{
					break;
				}

				prev = tt;
				tt = tt->Next;
			}
		}

		if (ft != NULL)
		{
			OSMemoryFree(ft);

			if (free_object_memory)
			{
				FreeCallStack(o->CallStack);
				OSMemoryFree(o);
			}
		}
	}
}

// オブジェクトをトラッキングリストに挿入
void InsertTrackingList(TRACKING_OBJECT *o)
{
	UINT i;
	TRACKING_LIST *t;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	t = OSMemoryAlloc(sizeof(TRACKING_LIST));
	t->Object = o;
	t->Next = NULL;

	i = TRACKING_HASH(o->Address);

	if (hashlist[i] == NULL)
	{
		hashlist[i] = t;
	}
	else
	{
		TRACKING_LIST *tt = hashlist[i];
		while (true)
		{
			if (tt->Next == NULL)
			{
				tt->Next = t;
				break;
			}

			tt = tt->Next;
		}
	}
}

// トラッキングリストのロック
void LockTrackingList()
{
	OSLock(obj_lock);
}

// トラッキングリストのロック解除
void UnlockTrackingList()
{
	OSUnlock(obj_lock);
}

// トラッキングの初期化
void InitTracking()
{
	UINT i;
	CALLSTACK_DATA *s;

	// ハッシュリスト初期化
	hashlist = (TRACKING_LIST **)OSMemoryAlloc(sizeof(TRACKING_LIST *) * TRACKING_NUM_ARRAY);

	for (i = 0;i < TRACKING_NUM_ARRAY;i++)
	{
		hashlist[i] = NULL;
	}

	obj_id = 0;

	// ロック作成
	obj_lock = OSNewLock();
	obj_id_lock = OSNewLock();
	cs_lock = OSNewLock();

	s = GetCallStack();
	if (s == NULL)
	{
		do_not_get_callstack = true;
	}
	else
	{
		do_not_get_callstack = false;
		FreeCallStack(s);
	}
}

// トラッキングの解放
void FreeTracking()
{
	UINT i;
	// ロック削除
	OSDeleteLock(obj_lock);
	OSDeleteLock(obj_id_lock);
	OSDeleteLock(cs_lock);
	cs_lock = NULL;
	obj_id_lock = NULL;
	obj_lock = NULL;

	// すべての要素を解放
	for (i = 0;i < TRACKING_NUM_ARRAY;i++)
	{
		if (hashlist[i] != NULL)
		{
			TRACKING_LIST *t = hashlist[i];

			while (true)
			{
				TRACKING_LIST *t2 = t;
				TRACKING_OBJECT *o = t->Object;

				FreeCallStack(o->CallStack);
				OSMemoryFree(o);

				t = t->Next;

				OSMemoryFree(t2);

				if (t == NULL)
				{
					break;
				}
			}
		}
	}

	// リスト解放
	OSMemoryFree(hashlist);
}

// コールスタックを表示する
void PrintCallStack(CALLSTACK_DATA *s)
{
	char tmp[MAX_SIZE * 2];

	GetCallStackStr(tmp, sizeof(tmp), s);
	Print("%s", tmp);
}

// コールスタックを文字列に変換する
void GetCallStackStr(char *str, UINT size, CALLSTACK_DATA *s)
{
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	char tmp3[MAX_SIZE];
	UINT num, i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	if (s == NULL)
	{
		StrCpy(str, size, "(Unknown)\n");
	}
	else
	{
		num = 0;
		str[0] = 0;
		while (true)
		{
			if (s == NULL)
			{
				break;
			}

			GetCallStackSymbolInfo(s);

			if (s->name == NULL)
			{
				Format(tmp, sizeof(tmp), "0x%p ---", UINT64_TO_POINTER(s->offset));
			}
			else
			{
				Format(tmp, sizeof(tmp), "0x%p %s() + 0x%02x",
					(void *)s->offset, s->name, UINT64_TO_POINTER(s->disp));
			}
			for (i = 0;i < num;i++)
			{
				tmp2[i] = ' ';
			}
			tmp2[i] = '\0';
			StrCpy(tmp3, sizeof(tmp3), tmp2);
			StrCat(tmp3, sizeof(tmp3), tmp);
			Format(tmp, sizeof(tmp), "%-55s %11s %u\n", tmp3, s->filename, s->line);
			StrCat(str, size, tmp);
			num++;
			s = s->next;
		}
	}
}

// 現在のコールスタックの取得
CALLSTACK_DATA *GetCallStack()
{
	CALLSTACK_DATA *s;
	if (do_not_get_callstack)
	{
		// コールスタックは取得しない
		return NULL;
	}

	OSLock(cs_lock);
	{
		// コールスタックの取得
		s = OSGetCallStack();
	}
	OSUnlock(cs_lock);
	if (s == NULL)
	{
		return NULL;
	}

	// コールスタックを 3 つ分だけ下降する
	s = WalkDownCallStack(s, 3);

	return s;
}

// コールスタックのシンボル情報を取得
bool GetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	bool ret;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	OSLock(cs_lock);
	{
		ret = OSGetCallStackSymbolInfo(s);
	}
	OSUnlock(cs_lock);

	return ret;
}

// コールスタックを指定された数だけ下降する
CALLSTACK_DATA *WalkDownCallStack(CALLSTACK_DATA *s, UINT num)
{
	CALLSTACK_DATA *cs, *tmp;
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	cs = s;
	i = 0;

	while (true)
	{
		if (i >= num)
		{
			return cs;
		}
		i++;
		tmp = cs;
		cs = tmp->next;
		OSMemoryFree(tmp->name);
		OSMemoryFree(tmp);

		if (cs == NULL)
		{
			return NULL;
		}
	}
}

// コールスタックの解放
void FreeCallStack(CALLSTACK_DATA *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	while (true)
	{
		CALLSTACK_DATA *next = s->next;
		OSMemoryFree(s->name);
		OSMemoryFree(s);
		if (next == NULL)
		{
			break;
		}
		s = next;
	}
}


