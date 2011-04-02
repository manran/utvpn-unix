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

// Pack.c
// データパッケージコード

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// BUF を PACK に変換
PACK *BufToPack(BUF *b)
{
	PACK *p;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	p = NewPack();
	if (ReadPack(b, p) == false)
	{
		FreePack(p);
		return NULL;
	}

	return p;
}

// PACK を BUF に変換
BUF *PackToBuf(PACK *p)
{
	BUF *b;
	// 引数チェック
	if (p == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WritePack(b, p);

	return b;
}

// PACK を読み込む
bool ReadPack(BUF *b, PACK *p)
{
	UINT i, num;
	// 引数チェック
	if (b == NULL || p == NULL)
	{
		return false;
	}

	// ELEMENT 数
	num = ReadBufInt(b);
	if (num > MAX_ELEMENT_NUM)
	{
		// 個数オーバー
		return false;
	}

	// ELEMENT を読み込む
	for (i = 0;i < num;i++)
	{
		ELEMENT *e;
		e = ReadElement(b);
		if (AddElement(p, e) == false)
		{
			// 追加エラー
			return false;
		}
	}

	return true;
}

// PACK を書き出す
void WritePack(BUF *b, PACK *p)
{
	UINT i;
	// 引数チェック
	if (b == NULL || p == NULL)
	{
		return;
	}

	// ELEMENT 数
	WriteBufInt(b, LIST_NUM(p->elements));

	// ELEMENT を書き出す
	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);
		WriteElement(b, e);
	}
}

// ELEMENT を読み込む
ELEMENT *ReadElement(BUF *b)
{
	UINT i;
	char name[MAX_ELEMENT_NAME_LEN + 1];
	UINT type, num_value;
	VALUE **values;
	ELEMENT *e;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	// 名前
	if (ReadBufStr(b, name, sizeof(name)) == false)
	{
		return NULL;
	}

	// 項目の種類
	type = ReadBufInt(b);

	// 項目数
	num_value = ReadBufInt(b);
	if (num_value > MAX_VALUE_NUM)
	{
		// 個数オーバー
		return NULL;
	}

	// VALUE
	values = (VALUE **)Malloc(sizeof(VALUE *) * num_value);
	for (i = 0;i < num_value;i++)
	{
		values[i] = ReadValue(b, type);
	}

	// ELEMENT を作成
	e = NewElement(name, type, num_value, values);

	Free(values);

	return e;
}

// ELEMENT を書き出す
void WriteElement(BUF *b, ELEMENT *e)
{
	UINT i;
	// 引数チェック
	if (b == NULL || e == NULL)
	{
		return;
	}

	// 名前
	WriteBufStr(b, e->name);
	// 項目の種類
	WriteBufInt(b, e->type);
	// 項目数
	WriteBufInt(b, e->num_value);
	// VALUE
	for (i = 0;i < e->num_value;i++)
	{
		VALUE *v = e->values[i];
		WriteValue(b, v, e->type);
	}
}

// VALUE を読み込む
VALUE *ReadValue(BUF *b, UINT type)
{
	UINT len;
	BYTE *u;
	void *data;
	char *str;
	wchar_t *unistr;
	UINT unistr_size;
	UINT size;
	UINT u_size;
	VALUE *v = NULL;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	// データ項目
	switch (type)
	{
	case VALUE_INT:			// 整数
		v = NewIntValue(ReadBufInt(b));
		break;
	case VALUE_INT64:
		v = NewInt64Value(ReadBufInt64(b));
		break;
	case VALUE_DATA:		// データ
		size = ReadBufInt(b);
		if (size > MAX_VALUE_SIZE)
		{
			// サイズオーバー
			break;
		}
		data = Malloc(size);
		if (ReadBuf(b, data, size) != size)
		{
			// 読み込み失敗
			Free(data);
			break;
		}
		v = NewDataValue(data, size);
		Free(data);
		break;
	case VALUE_STR:			// ANSI 文字列
		len = ReadBufInt(b);
		if ((len + 1) > MAX_VALUE_SIZE)
		{
			// サイズオーバー
			break;
		}
		str = Malloc(len + 1);
		// 文字列本体
		if (ReadBuf(b, str, len) != len)
		{
			// 読み込み失敗
			Free(str);
			break;
		}
		str[len] = 0;
		v = NewStrValue(str);
		Free(str);
		break;
	case VALUE_UNISTR:		// Unicode 文字列
		u_size = ReadBufInt(b);
		if (u_size > MAX_VALUE_SIZE)
		{
			// サイズオーバー
			break;
		}
		// UTF-8 の読み込み
		u = ZeroMalloc(u_size + 1);
		if (ReadBuf(b, u, u_size) != u_size)
		{
			// 読み込み失敗
			Free(u);
			break;
		}
		// Unicode 文字列に変換
		unistr_size = CalcUtf8ToUni(u, u_size);
		if (unistr_size == 0)
		{
			Free(u);
			break;
		}
		unistr = Malloc(unistr_size);
		Utf8ToUni(unistr, unistr_size, u, u_size);
		Free(u);
		v = NewUniStrValue(unistr);
		Free(unistr);
		break;
	}

	return v;
}

// VALUE を書き出す
void WriteValue(BUF *b, VALUE *v, UINT type)
{
	UINT len;
	BYTE *u;
	UINT u_size;
	// 引数チェック
	if (b == NULL || v == NULL)
	{
		return;
	}

	// データ項目
	switch (type)
	{
	case VALUE_INT:			// 整数
		WriteBufInt(b, v->IntValue);
		break;
	case VALUE_INT64:		// 64 bit 整数
		WriteBufInt64(b, v->Int64Value);
		break;
	case VALUE_DATA:		// データ
		// サイズ
		WriteBufInt(b, v->Size);
		// 本体
		WriteBuf(b, v->Data, v->Size);
		break;
	case VALUE_STR:			// ANSI 文字列
		len = StrLen(v->Str);
		// 長さ
		WriteBufInt(b, len);
		// 文字列本体
		WriteBuf(b, v->Str, len);
		break;
	case VALUE_UNISTR:		// Unicode 文字列
		// UTF-8 に変換する
		u_size = CalcUniToUtf8(v->UniStr) + 1;
		u = ZeroMalloc(u_size);
		UniToUtf8(u, u_size, v->UniStr);
		// サイズ
		WriteBufInt(b, u_size);
		// UTF-8 文字列本体
		WriteBuf(b, u, u_size);
		Free(u);
		break;
	}
}

// データサイズの取得
UINT GetDataValueSize(ELEMENT *e, UINT index)
{
	// 引数チェック
	if (e == NULL)
	{
		return 0;
	}
	if (e->values == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}
	if (e->values[index] == NULL)
	{
		return 0;
	}

	return e->values[index]->Size;
}

// データの取得
void *GetDataValue(ELEMENT *e, UINT index)
{
	// 引数チェック
	if (e == NULL)
	{
		return NULL;
	}
	if (e->values == NULL)
	{
		return NULL;
	}
	if (index >= e->num_value)
	{
		return NULL;
	}
	if (e->values[index] == NULL)
	{
		return NULL;
	}

	return e->values[index]->Data;
}

// Unicode 文字列型の取得
wchar_t *GetUniStrValue(ELEMENT *e, UINT index)
{
	// 引数チェック
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}

	return e->values[index]->UniStr;
}

// ANSI 文字列型の取得
char *GetStrValue(ELEMENT *e, UINT index)
{
	// 引数チェック
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}

	return e->values[index]->Str;
}

// 64 bit 整数型値の取得
UINT64 GetInt64Value(ELEMENT *e, UINT index)
{
	// 引数チェック
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}

	return e->values[index]->Int64Value;
}

// 整数型値の取得
UINT GetIntValue(ELEMENT *e, UINT index)
{
	// 引数チェック
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}

	return e->values[index]->IntValue;
}

// PACK のソート関数
int ComparePackName(void *p1, void *p2)
{
	ELEMENT *o1, *o2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	o1 = *(ELEMENT **)p1;
	o2 = *(ELEMENT **)p2;
	if (o1 == NULL || o2 == NULL)
	{
		return 0;
	}

	return StrCmpi(o1->name, o2->name);
}

// VALUE の削除
void FreeValue(VALUE *v, UINT type)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	switch (type)
	{
	case VALUE_INT:
	case VALUE_INT64:
		break;
	case VALUE_DATA:
		Free(v->Data);
		break;
	case VALUE_STR:
		Free(v->Str);
		break;
	case VALUE_UNISTR:
		Free(v->UniStr);
		break;
	}

	// メモリ解放
	Free(v);
}

// Unicode 文字列型の VALUE の作成
VALUE *NewUniStrValue(wchar_t *str)
{
	VALUE *v;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	// メモリ確保
	v = Malloc(sizeof(VALUE));

	// 文字列コピー
	v->Size = UniStrSize(str);
	v->UniStr = Malloc(v->Size);
	UniStrCpy(v->UniStr, v->Size, str);

	UniTrim(v->UniStr);

	return v;
}

// ANSI 文字列型の VALUE の作成
VALUE *NewStrValue(char *str)
{
	VALUE *v;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	// メモリ確保
	v = Malloc(sizeof(VALUE));

	// 文字列コピー
	v->Size = StrLen(str) + 1;
	v->Str = Malloc(v->Size);
	StrCpy(v->Str, v->Size, str);

	Trim(v->Str);

	return v;
}

// データ型の VALUE の作成
VALUE *NewDataValue(void *data, UINT size)
{
	VALUE *v;
	// 引数チェック
	if (data == NULL)
	{
		return NULL;
	}

	// メモリ確保
	v = Malloc(sizeof(VALUE));

	// データコピー
	v->Size = size;
	v->Data = Malloc(v->Size);
	Copy(v->Data, data, size);

	return v;
}

// 64 bit 整数型の VALUE の作成
VALUE *NewInt64Value(UINT64 i)
{
	VALUE *v;

	v = Malloc(sizeof(VALUE));
	v->Int64Value = i;
	v->Size = sizeof(UINT64);

	return v;
}

// 整数型の VALUE の作成
VALUE *NewIntValue(UINT i)
{
	VALUE *v;

	// メモリ確保
	v = Malloc(sizeof(VALUE));
	v->IntValue = i;
	v->Size = sizeof(UINT);

	return v;
}

// ELEMENT の削除
void FreeElement(ELEMENT *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->num_value;i++)
	{
		FreeValue(e->values[i], e->type);
	}
	Free(e->values);

	Free(e);
}

// ELEMENT の作成
ELEMENT *NewElement(char *name, UINT type, UINT num_value, VALUE **values)
{
	ELEMENT *e;
	UINT i;
	// 引数チェック
	if (name == NULL || num_value == 0 || values == NULL)
	{
		return NULL;
	}

	// メモリ確保
	e = Malloc(sizeof(ELEMENT));
	StrCpy(e->name, sizeof(e->name), name);
	e->num_value = num_value;
	e->type = type;

	// 要素へのポインタリストのコピー
	e->values = (VALUE **)Malloc(sizeof(VALUE *) * num_value);
	for (i = 0;i < e->num_value;i++)
	{
		e->values[i] = values[i];
	}

	return e;
}

// PACK から ELEMENT を検索して取得
ELEMENT *GetElement(PACK *p, char *name, UINT type)
{
	ELEMENT t;
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	// 検索
	StrCpy(t.name, sizeof(t.name), name);
	e = Search(p->elements, &t);

	if (e == NULL)
	{
		return NULL;
	}

	// 型検査
	if (type != INFINITE)
	{
		if (e->type != type)
		{
			return NULL;
		}
	}

	return e;
}

// PACK から ELEMENT を削除
void DelElement(PACK *p, char *name)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return;
	}

	e = GetElement(p, name, INFINITE);
	if (e != NULL)
	{
		Delete(p->elements, e);

		FreeElement(e);
	}
}

// PACK に ELEMENT を追加
bool AddElement(PACK *p, ELEMENT *e)
{
	// 引数チェック
	if (p == NULL || e == NULL)
	{
		return false;
	}

	// サイズチェック
	if (LIST_NUM(p->elements) >= MAX_ELEMENT_NUM)
	{
		// これ以上追加できない
		FreeElement(e);
		return false;
	}

	// 同じ名前が存在しないかどうかチェック
	if (GetElement(p, e->name, INFINITE))
	{
		// 存在している
		FreeElement(e);
		return false;
	}

	if (e->num_value == 0)
	{
		// 項目が 1 つも存在していない VALUE は追加できない
		FreeElement(e);
		return false;
	}

	// 追加
	Add(p->elements, e);
	return true;
}

// PACK オブジェクトの解放
void FreePack(PACK *p)
{
	UINT i;
	ELEMENT **elements;
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	elements = ToArray(p->elements);
	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		FreeElement(elements[i]);
	}
	Free(elements);

	ReleaseList(p->elements);
	Free(p);
}

// PACK オブジェクトの作成
PACK *NewPack()
{
	PACK *p;

	// メモリ確保
	p = MallocEx(sizeof(PACK), true);

	// リスト作成
	p->elements = NewListFast(ComparePackName);

	return p;
}


