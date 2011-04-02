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

// Pack.h
// Pack.c のヘッダ

#ifndef	PACK_H
#define	PACK_H

// 定数
#ifdef CPU_64

#define	MAX_VALUE_SIZE			(384 * 1024 * 1024)	// 1 つの VALUE に格納できるデータサイズ
#define	MAX_VALUE_NUM			262144	// 1 つの ELEMENT に格納できる最大 VALUE 数
#define	MAX_ELEMENT_NAME_LEN	63		// ELEMENT に付けることのできる名前の長さ
#define	MAX_ELEMENT_NUM			262144	// 1 つの PACK に格納できる最大 ELEMENT 数
#define	MAX_PACK_SIZE			(512 * 1024 * 1024)	// シリアル化された PACK の最大サイズ

#else	// CPU_64

#define	MAX_VALUE_SIZE			(96 * 1024 * 1024)	// 1 つの VALUE に格納できるデータサイズ
#define	MAX_VALUE_NUM			65536	// 1 つの ELEMENT に格納できる最大 VALUE 数
#define	MAX_ELEMENT_NAME_LEN	63		// ELEMENT に付けることのできる名前の長さ
#define	MAX_ELEMENT_NUM			131072	// 1 つの PACK に格納できる最大 ELEMENT 数
#define	MAX_PACK_SIZE			(128 * 1024 * 1024)	// シリアル化された PACK の最大サイズ

#endif	// CPU_64

// VALUE の種類
#define	VALUE_INT			0		// 整数型
#define	VALUE_DATA			1		// データ型
#define	VALUE_STR			2		// ANSI 文字列型
#define	VALUE_UNISTR		3		// Unicode 文字列型
#define	VALUE_INT64			4		// 64 bit 整数型

// VALUE オブジェクト
struct VALUE
{
	UINT Size;				// サイズ
	UINT IntValue;			// 整数値
	void *Data;				// データ
	char *Str;				// ANSI 文字列
	wchar_t *UniStr;		// Unicode 文字列
	UINT64 Int64Value;		// 64 bit 整数型
};

// ELEMENT オブジェクト
struct ELEMENT
{
	char name[MAX_ELEMENT_NAME_LEN + 1];	// 要素名
	UINT num_value;			// 値の数 (>=1)
	UINT type;				// 型
	VALUE **values;			// 値へのポインタのリスト
};

// PACK オブジェクト
struct PACK
{
	LIST *elements;			// 要素リスト
};


// 関数プロトタイプ
PACK *NewPack();
bool AddElement(PACK *p, ELEMENT *e);
void DelElement(PACK *p, char *name);
ELEMENT *GetElement(PACK *p, char *name, UINT type);
void FreePack(PACK *p);
ELEMENT *NewElement(char *name, UINT type, UINT num_value, VALUE **values);
VALUE *NewIntValue(UINT i);
VALUE *NewDataValue(void *data, UINT size);
VALUE *NewStrValue(char *str);
VALUE *NewUniStrValue(wchar_t *str);
void FreeValue(VALUE *v, UINT type);
int ComparePackName(void *p1, void *p2);
void FreeElement(ELEMENT *e);
UINT GetValueNum(ELEMENT *e);
UINT GetIntValue(ELEMENT *e, UINT index);
UINT64 GetInt64Value(ELEMENT *e, UINT index);
char *GetStrValue(ELEMENT *e, UINT index);
wchar_t *GetUniStrValue(ELEMENT *e, UINT index);
UINT GetDataValueSize(ELEMENT *e, UINT index);
void *GetDataValue(ELEMENT *e, UINT index);
BUF *PackToBuf(PACK *p);
void WritePack(BUF *b, PACK *p);
void WriteElement(BUF *b, ELEMENT *e);
void WriteValue(BUF *b, VALUE *v, UINT type);
PACK *BufToPack(BUF *b);
bool ReadPack(BUF *b, PACK *p);
ELEMENT *ReadElement(BUF *b);
VALUE *ReadValue(BUF *b, UINT type);
void Bit160ToStr(char *str, UCHAR *data);
void Bit128ToStr(char *str, UCHAR *data);
VALUE *NewInt64Value(UINT64 i);

#endif	// PACK_H
