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

// Memory.c
// メモリ管理プログラム

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <zlib/zlib.h>
#include <Mayaqua/Mayaqua.h>

#define	MEMORY_SLEEP_TIME		150
#define	MEMORY_MAX_RETRY		30
#define	INIT_BUF_SIZE			10240

#define	FIFO_INIT_MEM_SIZE		4096
#define	FIFO_REALLOC_MEM_SIZE	(65536 * 10)	// 絶妙な値
#define FIFO_REALLOC_MEM_SIZE_SMALL	65536

#define	INIT_NUM_RESERVED		32
static UINT fifo_default_realloc_mem_size = FIFO_REALLOC_MEM_SIZE;

// バイナリを検索
UINT SearchBin(void *data, UINT data_start, UINT data_size, void *key, UINT key_size)
{
	UINT i;
	// 引数チェック
	if (data == NULL || key == NULL || key_size == 0 || data_size == 0 ||
		(data_start >= data_size) || (data_start + key_size > data_size))
	{
		return INFINITE;
	}

	for (i = data_start;i < (data_size - key_size + 1);i++)
	{
		UCHAR *p = ((UCHAR *)data) + i;

		if (Cmp(p, key, key_size) == 0)
		{
			return i;
		}
	}

	return INFINITE;
}

// すぐにクラッシュする
void CrashNow()
{
	// これでとりあえずどのような OS 上でもプロセスは落ちるはずである
	while (true)
	{
		UINT r = Rand32();
		UCHAR *c = (UCHAR *)r;

		*c = Rand8();
	}
}

// バッファを候補に変換
LIST *BufToCandidate(BUF *b)
{
	LIST *o;
	UINT i;
	UINT num;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	num = ReadBufInt(b);
	o = NewCandidateList();

	for (i = 0;i < num;i++)
	{
		CANDIDATE *c;
		wchar_t *s;
		UINT64 sec64;
		UINT len, size;
		sec64 = ReadBufInt64(b);
		len = ReadBufInt(b);
		if (len >= 65536)
		{
			break;
		}
		size = (len + 1) * 2;
		s = ZeroMalloc(size);
		if (ReadBuf(b, s, size) != size)
		{
			Free(s);
			break;
		}
		else
		{
			c = ZeroMalloc(sizeof(CANDIDATE));
			c->LastSelectedTime = sec64;
			c->Str = s;
			Add(o, c);
		}
	}

	Sort(o);
	return o;
}

// 候補をバッファに変換
BUF *CandidateToBuf(LIST *o)
{
	BUF *b;
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBufInt(b, LIST_NUM(o));
	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		WriteBufInt64(b, c->LastSelectedTime);
		WriteBufInt(b, UniStrLen(c->Str));
		WriteBuf(b, c->Str, UniStrSize(c->Str));
	}

	SeekBuf(b, 0, 0);

	return b;
}

// 候補の追加
void AddCandidate(LIST *o, wchar_t *str, UINT num_max)
{
	UINT i;
	bool exists;
	// 引数チェック
	if (o == NULL || str == NULL)
	{
		return;
	}
	if (num_max == 0)
	{
		num_max = 0x7fffffff;
	}

	// 文字列コピー
	str = UniCopyStr(str);
	UniTrim(str);

	exists = false;
	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		if (UniStrCmpi(c->Str, str) == 0)
		{
			// 既存のものを発見したので時刻を更新する
			c->LastSelectedTime = SystemTime64();
			exists = true;
			break;
		}
	}

	if (exists == false)
	{
		// 新しく挿入する
		CANDIDATE *c = ZeroMalloc(sizeof(CANDIDATE));
		c->LastSelectedTime = SystemTime64();
		c->Str = UniCopyStr(str);
		Insert(o, c);
	}

	// 文字列解放
	Free(str);

	// 現在の候補数を調べて、num_max より多ければ
	// 古いものから順に削除する
	if (LIST_NUM(o) > num_max)
	{
		while (LIST_NUM(o) > num_max)
		{
			UINT index = LIST_NUM(o) - 1;
			CANDIDATE *c = LIST_DATA(o, index);
			Delete(o, c);
			Free(c->Str);
			Free(c);
		}
	}
}

// 候補の比較
int ComapreCandidate(void *p1, void *p2)
{
	CANDIDATE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CANDIDATE **)p1;
	c2 = *(CANDIDATE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}
	if (c1->LastSelectedTime > c2->LastSelectedTime)
	{
		return -1;
	}
	else if (c1->LastSelectedTime < c2->LastSelectedTime)
	{
		return 1;
	}
	else
	{
		return UniStrCmpi(c1->Str, c2->Str);
	}
}

// 候補リストの解放
void FreeCandidateList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		Free(c->Str);
		Free(c);
	}

	ReleaseList(o);
}

// 新しい候補リストの作成
LIST *NewCandidateList()
{
	return NewList(ComapreCandidate);
}

// 指定したアドレスがすべてゼロかどうか調べる
bool IsZero(void *data, UINT size)
{
	UINT i;
	UCHAR *c = (UCHAR *)data;
	// 引数チェック
	if (data == NULL || size == 0)
	{
		return true;
	}

	for (i = 0;i < size;i++)
	{
		if (c[i] != 0)
		{
			return false;
		}
	}

	return true;
}

// データを展開する
UINT Uncompress(void *dst, UINT dst_size, void *src, UINT src_size)
{
	unsigned long dst_size_long = dst_size;
	// 引数チェック
	if (dst == NULL || dst_size_long == 0 || src == NULL)
	{
		return 0;
	}

	if (uncompress(dst, &dst_size_long, src, src_size) != Z_OK)
	{
		return 0;
	}

	return (UINT)dst_size_long;
}

// データを圧縮する
UINT Compress(void *dst, UINT dst_size, void *src, UINT src_size)
{
	return CompressEx(dst, dst_size, src, src_size, Z_DEFAULT_COMPRESSION);
}

// データをオプション付きで圧縮する
UINT CompressEx(void *dst, UINT dst_size, void *src, UINT src_size, UINT level)
{
	unsigned long dst_size_long = dst_size;
	// 引数チェック
	if (dst == NULL || dst_size_long == 0 || src == NULL)
	{
		return 0;
	}

	if (compress2(dst, &dst_size_long, src, src_size, (int)level) != Z_OK)
	{
		return 0;
	}

	return dst_size_long;
}

// src_size データを圧縮した場合の最大サイズを取得する
UINT CalcCompress(UINT src_size)
{
	// あっ これは いい加減！
	return src_size * 2 + 100;
}

// スタックの作成
SK *NewSk()
{
	return NewSkEx(false);
}
SK *NewSkEx(bool no_compact)
{
	SK *s;

	s = Malloc(sizeof(SK));
	s->lock = NewLock();
	s->ref = NewRef();
	s->num_item = 0;
	s->num_reserved = INIT_NUM_RESERVED;
	s->p = Malloc(sizeof(void *) * s->num_reserved);
	s->no_compact = no_compact;

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(s), "SK", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWSK_COUNT);

	return s;
}

// スタックの解放
void ReleaseSk(SK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSk(s);
	}
}

// スタックのクリーンアップ
void CleanupSk(SK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// メモリ解放
	Free(s->p);
	DeleteLock(s->lock);
	Free(s);

#ifndef	DONT_USE_KERNEL_STATUS
	TrackDeleteObj(POINTER_TO_UINT64(s));
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_FREESK_COUNT);
}

// スタックのロック
void LockSk(SK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Lock(s->lock);
}

// スタックのロック解除
void UnlockSk(SK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Unlock(s->lock);
}

// スタックの Push
void Push(SK *s, void *p)
{
	UINT i;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	i = s->num_item;
	s->num_item++;

	// サイズ拡大
	if (s->num_item > s->num_reserved)
	{
		s->num_reserved = s->num_reserved * 2;
		s->p = ReAlloc(s->p, sizeof(void *) * s->num_reserved);
	}
	s->p[i] = p;

	// KS
	KS_INC(KS_PUSH_COUNT);
}

// スタックの Pop
void *Pop(SK *s)
{
	void *ret;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}
	if (s->num_item == 0)
	{
		return NULL;
	}
	ret = s->p[s->num_item - 1];
	s->num_item--;

	// サイズ縮小
	if (s->no_compact == false)
	{
		// no_compact が true の場合は縮小しない
		if ((s->num_item * 2) <= s->num_reserved)
		{
			if (s->num_reserved >= (INIT_NUM_RESERVED * 2))
			{
				s->num_reserved = s->num_reserved / 2;
				s->p = ReAlloc(s->p, sizeof(void *) * s->num_reserved);
			}
		}
	}

	// KS
	KS_INC(KS_POP_COUNT);

	return ret;
}

// 1 つ取得
void *GetNext(QUEUE *q)
{
	void *p = NULL;
	// 引数チェック
	if (q == NULL)
	{
		return NULL;
	}

	if (q->num_item == 0)
	{
		// アイテム無し
		return NULL;
	}

	// FIFO から読み込む
	ReadFifo(q->fifo, &p, sizeof(void *));
	q->num_item--;

	// KS
	KS_INC(KS_GETNEXT_COUNT);

	return p;
}

// キューに Int 型を挿入
void InsertQueueInt(QUEUE *q, UINT value)
{
	UINT *p;
	// 引数チェック
	if (q == NULL)
	{
		return;
	}

	p = Clone(&value, sizeof(UINT));

	InsertQueue(q, p);
}

// キューに挿入
void InsertQueue(QUEUE *q, void *p)
{
	// 引数チェック
	if (q == NULL || p == NULL)
	{
		return;
	}

	// FIFO に書き込む
	WriteFifo(q->fifo, &p, sizeof(void *));

	q->num_item++;

	// KS
	KS_INC(KS_INSERT_QUEUE_COUNT);
}

// キューのロック
void LockQueue(QUEUE *q)
{
	// 引数チェック
	if (q == NULL)
	{
		return;
	}

	Lock(q->lock);
}

// キューのロック解除
void UnlockQueue(QUEUE *q)
{
	// 引数チェック
	if (q == NULL)
	{
		return;
	}

	Unlock(q->lock);
}

// キューの解放
void ReleaseQueue(QUEUE *q)
{
	// 引数チェック
	if (q == NULL)
	{
		return;
	}

	if (q->ref == NULL || Release(q->ref) == 0)
	{
		CleanupQueue(q);
	}
}

// キューのクリーンアップ
void CleanupQueue(QUEUE *q)
{
	// 引数チェック
	if (q == NULL)
	{
		return;
	}

	// メモリ解放
	ReleaseFifo(q->fifo);
	DeleteLock(q->lock);
	Free(q);

#ifndef	DONT_USE_KERNEL_STATUS
	TrackDeleteObj(POINTER_TO_UINT64(q));
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_FREEQUEUE_COUNT);
}

// キューの作成
QUEUE *NewQueue()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NewLock();
	q->ref = NewRef();
	q->num_item = 0;
	q->fifo = NewFifo();

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(q), "QUEUE", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}
QUEUE *NewQueueFast()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NULL;
	q->ref = NULL;
	q->num_item = 0;
	q->fifo = NewFifoFast();

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(q), "QUEUE", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}

// リストに比較関数をセットする
void SetCmp(LIST *o, COMPARE *cmp)
{
	// 引数チェック
	if (o == NULL || cmp == NULL)
	{
		return;
	}

	if (o->cmp != cmp)
	{
		o->cmp = cmp;
		o->sorted = false;
	}
}

// リストのクローン
LIST *CloneList(LIST *o)
{
	LIST *n = NewList(o->cmp);

	// メモリ再確保
	Free(n->p);
	n->p = ToArray(o);
	n->num_item = n->num_reserved = LIST_NUM(o);
	n->sorted = o->sorted;

	return n;
}

// リストを配列にコピー
void CopyToArray(LIST *o, void *p)
{
	// 引数チェック
	if (o == NULL || p == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_TOARRAY_COUNT);

	Copy(p, o->p, sizeof(void *) * o->num_item);
}

// リストを配列化する
void *ToArray(LIST *o)
{
	return ToArrayEx(o, false);
}
void *ToArrayEx(LIST *o, bool fast)
{
	void *p;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	// メモリ確保
	if (fast == false)
	{
		p = Malloc(sizeof(void *) * LIST_NUM(o));
	}
	else
	{
		p = MallocFast(sizeof(void *) * LIST_NUM(o));
	}
	// コピー
	CopyToArray(o, p);

	return p;
}

// リストのサーチ
void *Search(LIST *o, void *target)
{
	void **ret;
	// 引数チェック
	if (o == NULL || target == NULL)
	{
		return NULL;
	}
	if (o->cmp == NULL)
	{
		return NULL;
	}

	// ソートのチェック
	if (o->sorted == false)
	{
		// 未ソートなのでソートを行う
		Sort(o);
	}

	// なんだ C ライブラリのバイナリサーチ関数を呼んでいるだけか
	ret = (void **)bsearch(&target, o->p, o->num_item, sizeof(void *),
		(int(*)(const void *, const void *))o->cmp);

	// KS
	KS_INC(KS_SEARCH_COUNT);

	if (ret != NULL)
	{
		return *ret;
	}
	else
	{
		return NULL;
	}
}

// リストに項目を挿入
// 本当はもうちょっとましなデータ構造 & アルゴリズムにするべき
void Insert(LIST *o, void *p)
{
	int low, high, middle;
	UINT pos;
	int i;
	// 引数チェック
	if (o == NULL || p == NULL)
	{
		return;
	}

	if (o->cmp == NULL)
	{
		// ソート関数が無い場合は単純に追加する
		Add(o, p);
		return;
	}

	// ソートされていない場合は直ちにソートする
	if (o->sorted == false)
	{
		Sort(o);
	}

	low = 0;
	high = LIST_NUM(o) - 1;

	pos = INFINITE;

	while (low <= high)
	{
		int ret;

		middle = (low + high) / 2;
		ret = o->cmp(&(o->p[middle]), &p);

		if (ret == 0)
		{
			pos = middle;
			break;
		}
		else if (ret > 0)
		{
			high = middle - 1;
		}
		else
		{
			low = middle + 1;
		}
	}

	if (pos == INFINITE)
	{
		pos = low;
	}

	o->num_item++;
	if (o->num_item > o->num_reserved)
	{
		o->num_reserved *= 2;
		o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	if (LIST_NUM(o) >= 2)
	{
		for (i = (LIST_NUM(o) - 2);i >= (int)pos;i--)
		{
			o->p[i + 1] = o->p[i];
		}
	}

	o->p[pos] = p;

	// KS
	KS_INC(KS_INSERT_COUNT);
}

// ソートフラグの設定
void SetSortFlag(LIST *o, bool sorted)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	o->sorted = sorted;
}

// リストのソート
void Sort(LIST *o)
{
	// 引数チェック
	if (o == NULL || o->cmp == NULL)
	{
		return;
	}

	qsort(o->p, o->num_item, sizeof(void *), (int(*)(const void *, const void *))o->cmp);
	o->sorted = true;

	// KS
	KS_INC(KS_SORT_COUNT);
}

// ある文字列項目がリスト内に存在しているかどうか調べる (Unicode 版)
bool IsInListUniStr(LIST *o, wchar_t *str)
{
	UINT i;
	// 引数チェック
	if (o == NULL || str == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);

		if (UniStrCmpi(s, str) == 0)
		{
			return true;
		}
	}

	return false;
}

// リスト内のポインタを置換する
bool ReplaceListPointer(LIST *o, void *oldptr, void *newptr)
{
	UINT i;
	// 引数チェック
	if (o == NULL || oldptr == NULL || newptr == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *p = LIST_DATA(o, i);

		if (p == oldptr)
		{
			o->p[i] = newptr;
			return true;
		}
	}

	return false;
}

// ある文字列項目がリスト内に存在しているかどうか調べる
bool IsInListStr(LIST *o, char *str)
{
	UINT i;
	// 引数チェック
	if (o == NULL || str == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *s = LIST_DATA(o, i);

		if (StrCmpi(s, str) == 0)
		{
			return true;
		}
	}

	return false;
}

// リスト内を UINT 形式のポインタで走査してポインタを取得する
void *ListKeyToPointer(LIST *o, UINT key)
{
	UINT i;
	// 引数チェック
	if (o == NULL || key == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *p = LIST_DATA(o, i);

		if (POINTER_TO_KEY(p) == key)
		{
			return p;
		}
	}

	return NULL;
}

// あるキーがリスト内に存在するかどうか調べる
bool IsInListKey(LIST *o, UINT key)
{
	void *p;
	// 引数チェック
	if (o == NULL || key == 0)
	{
		return false;
	}

	p = ListKeyToPointer(o, key);
	if (p == NULL)
	{
		return false;
	}

	return true;
}

// ある項目がリスト内に存在するかどうか調べる
bool IsInList(LIST *o, void *p)
{
	UINT i;
	// 引数チェック
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *q = LIST_DATA(o, i);
		if (p == q)
		{
			return true;
		}
	}

	return false;
}

// リストへの要素の追加
void Add(LIST *o, void *p)
{
	UINT i;
	// 引数チェック
	if (o == NULL || p == NULL)
	{
		return;
	}

	i = o->num_item;
	o->num_item++;

	if (o->num_item > o->num_reserved)
	{
		o->num_reserved = o->num_reserved * 2;
		o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	o->p[i] = p;
	o->sorted = false;

	// KS
	KS_INC(KS_INSERT_COUNT);
}

// リストからキーで指定した要素の削除
bool DeleteKey(LIST *o, UINT key)
{
	void *p;
	// 引数チェック
	if (o == NULL || key == 0)
	{
		return false;
	}

	p = ListKeyToPointer(o, key);
	if (p == NULL)
	{
		return false;
	}

	return Delete(o, p);
}

// リストから要素の削除
bool Delete(LIST *o, void *p)
{
	UINT i, n;
	// 引数チェック
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < o->num_item;i++)
	{
		if (o->p[i] == p)
		{
			break;
		}
	}
	if (i == o->num_item)
	{
		return false;
	}

	n = i;
	for (i = n;i < (o->num_item - 1);i++)
	{
		o->p[i] = o->p[i + 1];
	}
	o->num_item--;
	if ((o->num_item * 2) <= o->num_reserved)
	{
		if (o->num_reserved > (INIT_NUM_RESERVED * 2))
		{
			o->num_reserved = o->num_reserved / 2;
			o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
		}
	}

	// KS
	KS_INC(KS_DELETE_COUNT);

	return true;
}

// リストからすべての要素の削除
void DeleteAll(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	o->num_item = 0;
	o->num_reserved = INIT_NUM_RESERVED;
	o->p = ReAlloc(o->p, sizeof(void *) * INIT_NUM_RESERVED);
}

// リストのロック
void LockList(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	Lock(o->lock);
}

// リストのロック解除
void UnlockList(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	Unlock(o->lock);
}

// リストの解放
void ReleaseList(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	if (o->ref == NULL || Release(o->ref) == 0)
	{
		CleanupList(o);
	}
}

// リストのクリーンアップ
void CleanupList(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	Free(o->p);
	if (o->lock != NULL)
	{
		DeleteLock(o->lock);
	}
	Free(o);

	// KS
	KS_INC(KS_FREELIST_COUNT);

#ifndef	DONT_USE_KERNEL_STATUS
	TrackDeleteObj(POINTER_TO_UINT64(o));
#endif	// DONT_USE_KERNEL_STATUS
}

// 文字列比較関数 (Unicode)
int CompareUniStr(void *p1, void *p2)
{
	wchar_t *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(wchar_t **)p1;
	s2 = *(wchar_t **)p2;

	return UniStrCmp(s1, s2);
}

// 文字列をリストに挿入する
bool InsertStr(LIST *o, char *str)
{
	// 引数チェック
	if (o == NULL || str == NULL)
	{
		return false;
	}

	if (Search(o, str) == NULL)
	{
		Insert(o, str);

		return true;
	}

	return false;
}

// 文字列比較関数
int CompareStr(void *p1, void *p2)
{
	char *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(char **)p1;
	s2 = *(char **)p2;

	return StrCmpi(s1, s2);
}

// 高速リスト (ロック無し) の作成
LIST *NewListFast(COMPARE *cmp)
{
	return NewListEx(cmp, true);
}

// リストの作成
LIST *NewList(COMPARE *cmp)
{
	return NewListEx(cmp, false);
}
LIST *NewListEx(COMPARE *cmp, bool fast)
{
	return NewListEx2(cmp, fast, false);
}
LIST *NewListEx2(COMPARE *cmp, bool fast, bool fast_malloc)
{
	LIST *o;

	if (fast_malloc == false)
	{
		o = Malloc(sizeof(LIST));
	}
	else
	{
		o = MallocFast(sizeof(LIST));
	}

	if (fast == false)
	{
		o->lock = NewLock();
		o->ref = NewRef();
	}
	else
	{
		o->lock = NULL;
		o->ref = NULL;
	}
	o->num_item = 0;
	o->num_reserved = INIT_NUM_RESERVED;

	if (fast_malloc == false)
	{
		o->p = Malloc(sizeof(void *) * o->num_reserved);
	}
	else
	{
		o->p = MallocFast(sizeof(void *) * o->num_reserved);
	}

	o->cmp = cmp;
	o->sorted = true;

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(o), "LIST", 0);
#endif	//DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWLIST_COUNT);

	return o;
}

// FIFO から peek する
UINT PeekFifo(FIFO *f, void *p, UINT size)
{
	UINT read_size;
	if (f == NULL || size == 0)
	{
		return 0;
	}

	// KS
	KS_INC(KS_PEEK_FIFO_COUNT);

	read_size = MIN(size, f->size);
	if (read_size == 0)
	{
		return 0;
	}

	if (p != NULL)
	{
		Copy(p, (UCHAR *)f->p + f->pos, read_size);
	}

	return read_size;
}

// FIFO から読み取る
UINT ReadFifo(FIFO *f, void *p, UINT size)
{
	UINT read_size;
	// 引数チェック
	if (f == NULL || size == 0)
	{
		return 0;
	}

	read_size = MIN(size, f->size);
	if (read_size == 0)
	{
		return 0;
	}
	if (p != NULL)
	{
		Copy(p, (UCHAR *)f->p + f->pos, read_size);
	}
	f->pos += read_size;
	f->size -= read_size;

	if (f->size == 0)
	{
		f->pos = 0;
	}

	// メモリの詰め直し
	if (f->pos >= FIFO_INIT_MEM_SIZE &&
		f->memsize >= f->realloc_mem_size &&
		(f->memsize / 2) > f->size)
	{
		void *new_p;
		UINT new_size;

		new_size = MAX(f->memsize / 2, FIFO_INIT_MEM_SIZE);
		new_p = Malloc(new_size);
		Copy(new_p, (UCHAR *)f->p + f->pos, f->size);

		Free(f->p);

		f->memsize = new_size;
		f->p = new_p;
		f->pos = 0;
	}

	// KS
	KS_INC(KS_READ_FIFO_COUNT);

	return read_size;
}

// FIFO に書き込む
void WriteFifo(FIFO *f, void *p, UINT size)
{
	UINT i, need_size;
	bool realloc_flag;
	// 引数チェック
	if (f == NULL || size == 0)
	{
		return;
	}

	i = f->size;
	f->size += size;
	need_size = f->pos + f->size;
	realloc_flag = false;

	// メモリ拡張
	while (need_size > f->memsize)
	{
		f->memsize = MAX(f->memsize, FIFO_INIT_MEM_SIZE) * 3;
		realloc_flag = true;
	}

	if (realloc_flag)
	{
		f->p = ReAlloc(f->p, f->memsize);
	}

	// データ書き込み
	if (p != NULL)
	{
		Copy((UCHAR *)f->p + f->pos + i, p, size);
	}

	// KS
	KS_INC(KS_WRITE_FIFO_COUNT);
}

// FIFO のクリア
void ClearFifo(FIFO *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	f->size = f->pos = 0;
	f->memsize = FIFO_INIT_MEM_SIZE;
	f->p = ReAlloc(f->p, f->memsize);
}

// FIFO のサイズ取得
UINT FifoSize(FIFO *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return 0;
	}

	return f->size;
}

// FIFO のロック
void LockFifo(FIFO *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	Lock(f->lock);
}

// FIFO のロック解除
void UnlockFifo(FIFO *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	Unlock(f->lock);
}

// FIFO の解放
void ReleaseFifo(FIFO *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	if (f->ref == NULL || Release(f->ref) == 0)
	{
		CleanupFifo(f);
	}
}

// FIFO のクリーンアップ
void CleanupFifo(FIFO *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	DeleteLock(f->lock);
	Free(f->p);
	Free(f);

#ifndef	DONT_USE_KERNEL_STATUS
	TrackDeleteObj(POINTER_TO_UINT64(f));
#endif	//DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_FREEFIFO_COUNT);
}

// FIFO システムの初期化
void InitFifo()
{
	fifo_default_realloc_mem_size = FIFO_REALLOC_MEM_SIZE;
}

// FIFO の作成
FIFO *NewFifo()
{
	return NewFifoEx(0, false);
}
FIFO *NewFifoFast()
{
	return NewFifoEx(0, true);
}
FIFO *NewFifoEx(UINT realloc_mem_size, bool fast)
{
	FIFO *f;

	// メモリ確保
	f = Malloc(sizeof(FIFO));

	if (fast == false)
	{
		f->lock = NewLock();
		f->ref = NewRef();
	}
	else
	{
		f->lock = NULL;
		f->ref = NULL;
	}

	f->size = f->pos = 0;
	f->memsize = FIFO_INIT_MEM_SIZE;
	f->p = Malloc(FIFO_INIT_MEM_SIZE);

	if (realloc_mem_size == 0)
	{
		realloc_mem_size = fifo_default_realloc_mem_size;
	}

	f->realloc_mem_size = realloc_mem_size;

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(f), "FIFO", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWFIFO_COUNT);

	return f;
}

// FIFO のデフォルトのメモリ再確保サイズを取得する
UINT GetFifoDefaultReallocMemSize()
{
	return fifo_default_realloc_mem_size;
}

// FIFO のデフォルトのメモリ再確保サイズを設定する
void SetFifoDefaultReallocMemSize(UINT size)
{
	if (size == 0)
	{
		size = FIFO_REALLOC_MEM_SIZE;
	}

	fifo_default_realloc_mem_size = size;
}

// バッファをファイルから読み込む
BUF *FileToBuf(IO *o)
{
	UCHAR hash1[MD5_SIZE], hash2[MD5_SIZE];
	UINT size;
	void *buf;
	BUF *b;

	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	// サイズを読み込む
	if (FileRead(o, &size, sizeof(size)) == false)
	{
		return NULL;
	}
	size = Endian32(size);

	if (size > FileSize(o))
	{
		return NULL;
	}

	// ハッシュを読み込む
	if (FileRead(o, hash1, sizeof(hash1)) == false)
	{
		return NULL;
	}

	// バッファを読み込む
	buf = Malloc(size);
	if (FileRead(o, buf, size) == false)
	{
		Free(buf);
		return NULL;
	}

	// ハッシュをとる
	Hash(hash2, buf, size, false);

	// ハッシュを比較する
	if (Cmp(hash1, hash2, sizeof(hash1)) != 0)
	{
		// ハッシュが異なる
		Free(buf);
		return NULL;
	}

	// バッファを作成する
	b = NewBuf();
	WriteBuf(b, buf, size);
	Free(buf);
	b->Current = 0;

	return b;
}

// ダンプファイルをバッファに読み込む
BUF *ReadDump(char *filename)
{
	IO *o;
	BUF *b;
	UINT size;
	void *data;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	o = FileOpen(filename, false);
	if (o == NULL)
	{
		return NULL;
	}

	size = FileSize(o);
	data = Malloc(size);
	FileRead(o, data, size);
	FileClose(o);

	b = NewBuf();
	WriteBuf(b, data, size);
	b->Current = 0;
	Free(data);

	return b;
}
BUF *ReadDumpW(wchar_t *filename)
{
	IO *o;
	BUF *b;
	UINT size;
	void *data;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	o = FileOpenW(filename, false);
	if (o == NULL)
	{
		return NULL;
	}

	size = FileSize(o);
	data = Malloc(size);
	FileRead(o, data, size);
	FileClose(o);

	b = NewBuf();
	WriteBuf(b, data, size);
	b->Current = 0;
	Free(data);

	return b;
}

// バッファ内容をファイルにダンプする
bool DumpBuf(BUF *b, char *filename)
{
	IO *o;
	// 引数チェック
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	o = FileCreate(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, b->Buf, b->Size);
	FileClose(o);

	return true;
}
bool DumpBufW(BUF *b, wchar_t *filename)
{
	IO *o;
	// 引数チェック
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	o = FileCreateW(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, b->Buf, b->Size);
	FileClose(o);

	return true;
}

// バッファをファイルに書き込む
bool BufToFile(IO *o, BUF *b)
{
	UCHAR hash[MD5_SIZE];
	UINT size;

	// 引数チェック
	if (o == NULL || b == NULL)
	{
		return false;
	}

	// データをハッシュする
	Hash(hash, b->Buf, b->Size, false);

	size = Endian32(b->Size);

	// サイズを書き込む
	if (FileWrite(o, &size, sizeof(size)) == false)
	{
		return false;
	}

	// ハッシュを書き込む
	if (FileWrite(o, hash, sizeof(hash)) == false)
	{
		return false;
	}

	// データを書き込む
	if (FileWrite(o, b->Buf, b->Size) == false)
	{
		return false;
	}

	return true;
}

// バッファの作成
BUF *NewBuf()
{
	BUF *b;

	// メモリ確保
	b = Malloc(sizeof(BUF));
	b->Buf = Malloc(INIT_BUF_SIZE);
	b->Size = 0;
	b->Current = 0;
	b->SizeReserved = INIT_BUF_SIZE;

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(b), "BUF", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWBUF_COUNT);
	KS_INC(KS_CURRENT_BUF_COUNT);

	return b;
}

// バッファのクリア
void ClearBuf(BUF *b)
{
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	b->Size = 0;
	b->Current = 0;
}

// バッファへ書き込み
void WriteBuf(BUF *b, void *buf, UINT size)
{
	UINT new_size;
	// 引数チェック
	if (b == NULL || buf == NULL || size == 0)
	{
		return;
	}

	new_size = b->Current + size;
	if (new_size > b->Size)
	{
		// サイズを調整する
		AdjustBufSize(b, new_size);
	}
	if (b->Buf != NULL)
	{
		Copy((UCHAR *)b->Buf + b->Current, buf, size);
	}
	b->Current += size;
	b->Size = new_size;

	// KS
	KS_INC(KS_WRITE_BUF_COUNT);
}

// バッファに文字列を追記
void AddBufStr(BUF *b, char *str)
{
	// 引数チェック
	if (b == NULL || str == NULL)
	{
		return;
	}

	WriteBuf(b, str, StrLen(str));
}

// バッファに 1 行書き込む
void WriteBufLine(BUF *b, char *str)
{
	char *crlf = "\r\n";
	// 引数チェック
	if (b == NULL || str == NULL)
	{
		return;
	}

	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, crlf, StrLen(crlf));
}

// バッファに文字列を書き込む
bool WriteBufStr(BUF *b, char *str)
{
	UINT len;
	// 引数チェック
	if (b == NULL || str == NULL)
	{
		return false;
	}

	// 文字列長
	len = StrLen(str);
	if (WriteBufInt(b, len + 1) == false)
	{
		return false;
	}

	// 文字列本体
	WriteBuf(b, str, len);

	return true;
}

// バッファから文字列を読み込む
bool ReadBufStr(BUF *b, char *str, UINT size)
{
	UINT len;
	UINT read_size;
	// 引数チェック
	if (b == NULL || str == NULL || size == 0)
	{
		return false;
	}

	// 文字列長を読み込む
	len = ReadBufInt(b);
	if (len == 0)
	{
		return false;
	}
	len--;
	if (len <= (size - 1))
	{
		size = len + 1;
	}

	read_size = MIN(len, (size - 1));

	// 文字列本体を読み込む
	if (ReadBuf(b, str, read_size) != read_size)
	{
		return false;
	}
	if (read_size < len)
	{
		ReadBuf(b, NULL, len - read_size);
	}
	str[read_size] = 0;

	return true;
}

// バッファに 64 bit 整数を書き込む
bool WriteBufInt64(BUF *b, UINT64 value)
{
	// 引数チェック
	if (b == NULL)
	{
		return false;
	}

	value = Endian64(value);

	WriteBuf(b, &value, sizeof(UINT64));
	return true;
}

// バッファに整数を書き込む
bool WriteBufInt(BUF *b, UINT value)
{
	// 引数チェック
	if (b == NULL)
	{
		return false;
	}

	value = Endian32(value);

	WriteBuf(b, &value, sizeof(UINT));
	return true;
}

// バッファから 64bit 整数を読み込む
UINT64 ReadBufInt64(BUF *b)
{
	UINT64 value;
	// 引数チェック
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &value, sizeof(UINT64)) != sizeof(UINT64))
	{
		return 0;
	}
	return Endian64(value);
}

// バッファから整数を読み込む
UINT ReadBufInt(BUF *b)
{
	UINT value;
	// 引数チェック
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &value, sizeof(UINT)) != sizeof(UINT))
	{
		return 0;
	}
	return Endian32(value);
}

// バッファにバッファを書き込み
void WriteBufBuf(BUF *b, BUF *bb)
{
	// 引数チェック
	if (b == NULL || bb == NULL)
	{
		return;
	}

	WriteBuf(b, bb->Buf, bb->Size);
}

// バッファからバッファを読み込み
BUF *ReadBufFromBuf(BUF *b, UINT size)
{
	BUF *ret;
	UCHAR *data;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	data = Malloc(size);
	if (ReadBuf(b, data, size) != size)
	{
		Free(data);
		return NULL;
	}

	ret = NewBuf();
	WriteBuf(ret, data, size);
	SeekBuf(ret, 0, 0);

	Free(data);

	return ret;
}

// バッファから読み込み
UINT ReadBuf(BUF *b, void *buf, UINT size)
{
	UINT size_read;
	// 引数チェック
	if (b == NULL || size == 0)
	{
		return 0;
	}

	if (b->Buf == NULL)
	{
		Zero(buf, size);
		return 0;
	}
	size_read = size;
	if ((b->Current + size) >= b->Size)
	{
		size_read = b->Size - b->Current;
		if (buf != NULL)
		{
			Zero((UCHAR *)buf + size_read, size - size_read);
		}
	}

	if (buf != NULL)
	{
		Copy(buf, (UCHAR *)b->Buf + b->Current, size_read);
	}

	b->Current += size_read;

	// KS
	KS_INC(KS_READ_BUF_COUNT);

	return size_read;
}

// バッファサイズの調整
void AdjustBufSize(BUF *b, UINT new_size)
{
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	if (b->SizeReserved >= new_size)
	{
		return;
	}

	while (b->SizeReserved < new_size)
	{
		b->SizeReserved = b->SizeReserved * 2;
	}
	b->Buf = ReAlloc(b->Buf, b->SizeReserved);

	// KS
	KS_INC(KS_ADJUST_BUFSIZE_COUNT);
}

// バッファのシーク
void SeekBuf(BUF *b, UINT offset, int mode)
{
	UINT new_pos;
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	if (mode == 0)
	{
		// 絶対位置
		new_pos = offset;
	}
	else
	{
		if (mode > 0)
		{
			// 右へ移動
			new_pos = b->Current + offset;
		}
		else
		{
			// 左へ移動
			if (b->Current >= offset)
			{
				new_pos = b->Current - offset;
			}
			else
			{
				new_pos = 0;
			}
		}
	}
	b->Current = MAKESURE(new_pos, 0, b->Size);

	KS_INC(KS_SEEK_BUF_COUNT);
}

// バッファの解放
void FreeBuf(BUF *b)
{
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	// メモリ解放
	Free(b->Buf);
	Free(b);

	// KS
	KS_INC(KS_FREEBUF_COUNT);
	KS_DEC(KS_CURRENT_BUF_COUNT);

#ifndef	DONT_USE_KERNEL_STATUS
	TrackDeleteObj(POINTER_TO_UINT64(b));
#endif	// DONT_USE_KERNEL_STATUS
}

// Unicode 文字列のエンディアン変換
void EndianUnicode(wchar_t *str)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);

	for (i = 0;i < len;i++)
	{
		str[i] = Endian16(str[i]);
	}
}

// エンディアン変換 16bit
USHORT Endian16(USHORT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap16(src);
	}
	else
	{
		return src;
	}
}

// エンディアン変換 32bit
UINT Endian32(UINT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap32(src);
	}
	else
	{
		return src;
	}
}

// エンディアン変換 64bit
UINT64 Endian64(UINT64 src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap64(src);
	}
	else
	{
		return src;
	}
}

// 任意のデータのスワップ
void Swap(void *buf, UINT size)
{
	UCHAR *tmp, *src;
	UINT i;
	// 引数チェック
	if (buf == NULL || size == 0)
	{
		return;
	}

	src = (UCHAR *)buf;
	tmp = Malloc(size);
	for (i = 0;i < size;i++)
	{
		tmp[size - i - 1] = src[i];
	}

	Copy(buf, tmp, size);
	Free(buf);
}

// 16bit スワップ
USHORT Swap16(USHORT value)
{
	USHORT r;
	// 汚いコード
	((BYTE *)&r)[0] = ((BYTE *)&value)[1];
	((BYTE *)&r)[1] = ((BYTE *)&value)[0];
	return r;
}

// 32bit スワップ
UINT Swap32(UINT value)
{
	UINT r;
	// 汚いコード
	((BYTE *)&r)[0] = ((BYTE *)&value)[3];
	((BYTE *)&r)[1] = ((BYTE *)&value)[2];
	((BYTE *)&r)[2] = ((BYTE *)&value)[1];
	((BYTE *)&r)[3] = ((BYTE *)&value)[0];
	return r;
}

// 64bit スワップ
UINT64 Swap64(UINT64 value)
{
	UINT64 r;
	// 汚いコード
	((BYTE *)&r)[0] = ((BYTE *)&value)[7];
	((BYTE *)&r)[1] = ((BYTE *)&value)[6];
	((BYTE *)&r)[2] = ((BYTE *)&value)[5];
	((BYTE *)&r)[3] = ((BYTE *)&value)[4];
	((BYTE *)&r)[4] = ((BYTE *)&value)[3];
	((BYTE *)&r)[5] = ((BYTE *)&value)[2];
	((BYTE *)&r)[6] = ((BYTE *)&value)[1];
	((BYTE *)&r)[7] = ((BYTE *)&value)[0];
	return r;
}

// Base64 エンコード
UINT Encode64(char *dst, char *src)
{
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	return B64_Encode(dst, src, StrLen(src));
}

// Base64 デコード
UINT Decode64(char *dst, char *src)
{
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	return B64_Decode(dst, src, StrLen(src));
}

// Base64 エンコード
int B64_Encode(char *set, char *source, int len)
{
	BYTE *src;
	int i,j;
	src = (BYTE *)source;
	j = 0;
	i = 0;
	if (!len)
	{
		return 0;
	}
	while (TRUE)
	{
		if (i >= len)
		{
			return j;
		}
		if (set)
		{
			set[j] = B64_CodeToChar((src[i]) >> 2);
		}
		if (i + 1 >= len)
		{
			if (set)
			{
				set[j + 1] = B64_CodeToChar((src[i] & 0x03) << 4);
				set[j + 2] = '=';
				set[j + 3] = '=';
			}
			return j + 4;
		}
		if (set)
		{
			set[j + 1] = B64_CodeToChar(((src[i] & 0x03) << 4) + ((src[i + 1] >> 4)));
		}
		if (i + 2 >= len)
		{
			if (set)
			{
				set[j + 2] = B64_CodeToChar((src[i + 1] & 0x0f) << 2);
				set[j + 3] = '=';
			}
			return j + 4;
		}
		if (set)
		{
			set[j + 2] = B64_CodeToChar(((src[i + 1] & 0x0f) << 2) + ((src[i + 2] >> 6)));
			set[j + 3] = B64_CodeToChar(src[i + 2] & 0x3f);
		}
		i += 3;
		j += 4;
	}
}

// Base64 デコード
int B64_Decode(char *set, char *source, int len)
{
	int i,j;
	char a1,a2,a3,a4;
	char *src;
	int f1,f2,f3,f4;
	src = source;
	i = 0;
	j = 0;
	while (TRUE)
	{
		f1 = f2 = f3 = f4 = 0;
		if (i >= len)
		{
			break;
		}
		f1 = 1;
		a1 = B64_CharToCode(src[i]);
		if (a1 == -1)
		{
			f1 = 0;
		}
		if (i >= len + 1)
		{
			a2 = 0;
		}
		else
		{
			a2 = B64_CharToCode(src[i + 1]);
			f2 = 1;
			if (a2 == -1)
			{
				f2 = 0;
			}
		}
		if (i >= len + 2)
		{
			a3 = 0;
		}
		else
		{
			a3 = B64_CharToCode(src[i + 2]);
			f3 = 1;
			if (a3 == -1)
			{
				f3 = 0;
			}
		}
		if (i >= len + 3)
		{
			a4 = 0;
		}
		else
		{
			a4 = B64_CharToCode(src[i + 3]);
			f4 = 1;
			if (a4 == -1)
			{
				f4 = 0;
			}
		}
		if (f1 && f2)
		{
			if (set)
			{
				set[j] = (a1 << 2) + (a2 >> 4);
			}
			j++;
		}
		if (f2 && f3)
		{
			if (set)
			{
				set[j] = (a2 << 4) + (a3 >> 2);
			}
			j++;
		}
		if (f3 && f4)
		{
			if (set)
			{
				set[j] = (a3 << 6) + a4;
			}
			j++;
		}
		i += 4;
	}
	return j;
}

// Base64 - コードを文字に変換
char B64_CodeToChar(BYTE c)
{
	BYTE r;
	r = '=';
	if (c <= 0x19)
	{
		r = c + 'A';
	}
	if (c >= 0x1a && c <= 0x33)
	{
		r = c - 0x1a + 'a';
	}
	if (c >= 0x34 && c <= 0x3d)
	{
		r = c - 0x34 + '0';
	}
	if (c == 0x3e)
	{
		r = '+';
	}
	if (c == 0x3f)
	{
		r = '/';
	}
	return r;
}

// Base64 - 文字をコードに変換
char B64_CharToCode(char c)
{
	if (c >= 'A' && c <= 'Z')
	{
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z')
	{
		return c - 'a' + 0x1a;
	}
	if (c >= '0' && c <= '9')
	{
		return c - '0' + 0x34;
	}
	if (c == '+')
	{
		return 0x3e;
	}
	if (c == '/')
	{
		return 0x3f;
	}
	if (c == '=')
	{
		return -1;
	}
	return 0;
}

// 高速な Malloc (現在未実装)
// 実は小さなバッファをたくさんまとめておいてそれを動的に割り当てるコードを昔
// 書いたのだが、Windows, Linux, Solaris で試しても普通の malloc() と比べて
// ほとんど速度に影響がなかったので、やめにした。
void *MallocFast(UINT size)
{
	return Malloc(size);
}

// Malloc
void *Malloc(UINT size)
{
	return MallocEx(size, false);
}
void *MallocEx(UINT size, bool zero_clear_when_free)
{
	MEMTAG *tag;
	UINT real_size;

	real_size = CALC_MALLOCSIZE(size);

	tag = InternalMalloc(real_size);

	Zero(tag, sizeof(MEMTAG));
	tag->Magic = MEMTAG_MAGIC;
	tag->Size = size;
	tag->ZeroFree = zero_clear_when_free;

	return MEMTAG_TO_POINTER(tag);
}

// ReAlloc
void *ReAlloc(void *addr, UINT size)
{
	MEMTAG *tag;
	bool zerofree;
	// 引数チェック
	if (IS_NULL_POINTER(addr))
	{
		return NULL;
	}

	tag = POINTER_TO_MEMTAG(addr);
	CheckMemTag(tag);

	zerofree = tag->ZeroFree;

	if (tag->Size == size)
	{
		// サイズ変更無し
		return addr;
	}
	else
	{
		if (zerofree)
		{
			// サイズ変更有り (ゼロクリア必須)
			void *new_p = MallocEx(size, true);

			if (tag->Size <= size)
			{
				// サイズ拡大
				Copy(new_p, addr, tag->Size);
			}
			else
			{
				// サイズ縮小
				Copy(new_p, addr, size);
			}

			// 古いブロックの解放
			Free(addr);

			return new_p;
		}
		else
		{
			// サイズ変更有り
			MEMTAG *tag2 = InternalReAlloc(tag, CALC_MALLOCSIZE(size));

			Zero(tag2, sizeof(MEMTAG));
			tag2->Magic = MEMTAG_MAGIC;
			tag2->Size = size;

			return MEMTAG_TO_POINTER(tag2);
		}
	}
}

// Free
void Free(void *addr)
{
	MEMTAG *tag;
	// 引数チェック
	if (IS_NULL_POINTER(addr))
	{
		return;
	}

	tag = POINTER_TO_MEMTAG(addr);
	CheckMemTag(tag);

	if (tag->ZeroFree)
	{
		// ゼロクリア
		Zero(addr, tag->Size);
	}

	// メモリ解放
	tag->Magic = 0;
	InternalFree(tag);
}

// memtag をチェック
void CheckMemTag(MEMTAG *tag)
{
#ifndef	DONT_CHECK_HEAP
	// 引数チェック
	if (tag == NULL)
	{
		AbortExitEx("CheckMemTag: tag == NULL");
		return;
	}

	if (tag->Magic != MEMTAG_MAGIC)
	{
		AbortExitEx("CheckMemTag: tag->Magic != MEMTAG_MAGIC");
		return;
	}
#endif	// DONT_CHECK_HEAP
}

// ZeroMalloc
void *ZeroMalloc(UINT size)
{
	return ZeroMallocEx(size, false);
}
void *ZeroMallocEx(UINT size, bool zero_clear_when_free)
{
	void *p = MallocEx(size, zero_clear_when_free);
	Zero(p, size);
	return p;
}
void *ZeroMallocFast(UINT size)
{
	void *p = MallocFast(size);
	Zero(p, size);
	return p;
}

// メモリ確保
void *InternalMalloc(UINT size)
{
	void *addr;
	UINT retry = 0;
	size = MORE(size, 1);

	// KS
	KS_INC(KS_MALLOC_COUNT);
	KS_INC(KS_TOTAL_MEM_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);
	KS_INC(KS_CURRENT_MEM_COUNT);

	// メモリが確保されるまで試行する
	while (true)
	{
		if ((retry++) > MEMORY_MAX_RETRY)
		{
			AbortExitEx("InternalMalloc: error: malloc() failed.\n\n");
		}
		addr = OSMemoryAlloc(size);
		if (addr != NULL)
		{
			break;
		}

		OSSleep(MEMORY_SLEEP_TIME);
	}

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(addr), "MEM", size);
#endif	//DONT_USE_KERNEL_STATUS

	return addr;
}

// メモリ解放
void InternalFree(void *addr)
{
	// 引数チェック
	if (addr == NULL)
	{
		return;
	}

	// KS
	KS_DEC(KS_CURRENT_MEM_COUNT);
	KS_INC(KS_FREE_COUNT);

#ifndef	DONT_USE_KERNEL_STATUS
	TrackDeleteObj(POINTER_TO_UINT64(addr));
#endif	// DONT_USE_KERNEL_STATUS

	// メモリ解放
	OSMemoryFree(addr);
}

// メモリ再確保
void *InternalReAlloc(void *addr, UINT size)
{
	void *new_addr;
	UINT retry = 0;
	size = MORE(size, 1);

	// KS
	KS_INC(KS_REALLOC_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);

	// メモリが確保されるまで試行する
	while (true)
	{
		if ((retry++) > MEMORY_MAX_RETRY)
		{
			AbortExitEx("InternalReAlloc: error: realloc() failed.\n\n");
		}
		new_addr = OSMemoryReAlloc(addr, size);
		if (new_addr != NULL)
		{
			break;
		}

		OSSleep(MEMORY_SLEEP_TIME);
	}

#ifndef	DONT_USE_KERNEL_STATUS
	TrackChangeObjSize((DWORD)addr, size, (DWORD)new_addr);
#endif	// DONT_USE_KERNEL_STATUS

	return new_addr;
}

// メモリ領域のクローン
void *Clone(void *addr, UINT size)
{
	void *ret;
	// 引数チェック
	if (addr == NULL)
	{
		return NULL;
	}

	ret = Malloc(size);
	Copy(ret, addr, size);

	return ret;
}

// メモリコピー
void Copy(void *dst, void *src, UINT size)
{
	// 引数チェック
	if (dst == NULL || src == NULL || size == 0 || dst == src)
	{
		return;
	}

	// KS
	KS_INC(KS_COPY_COUNT);

	memcpy(dst, src, size);
}

// メモリ比較
int Cmp(void *p1, void *p2, UINT size)
{
	// 引数チェック
	if (p1 == NULL || p2 == NULL || size == 0)
	{
		return 0;
	}

	return memcmp(p1, p2, (size_t)size);
}

// メモリのゼロクリア
void Zero(void *addr, UINT size)
{
	ZeroMem(addr, size);
}
void ZeroMem(void *addr, UINT size)
{
	// 引数チェック
	if (addr == NULL || size == 0)
	{
		return;
	}

	// KS
	KS_INC(KS_ZERO_COUNT);

	memset(addr, 0, size);
}

// 文字列マップエントリの比較
int StrMapCmp(void *p1, void *p2)
{
	STRMAP_ENTRY *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(STRMAP_ENTRY **)p1;
	s2 = *(STRMAP_ENTRY **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}
	return StrCmpi(s1->Name, s2->Name);
}

// 文字列マップ（文字列で検索できるデータ）の作成
LIST *NewStrMap()
{
	return NewList(StrMapCmp);
}

// 文字列マップの検索
void *StrMapSearch(LIST *map, char *key)
{
	STRMAP_ENTRY tmp, *result;
	tmp.Name = key;
	result = (STRMAP_ENTRY*)Search(map, &tmp);
	if(result != NULL)
	{
		return result->Value;
	}
	return NULL;
}
