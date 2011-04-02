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

// Str.c
// 文字列処理ルーチン

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// トークン関数の呼び出し用ロック処理
LOCK *token_lock = NULL;
static char *default_spliter = " ,\t\r\n";

typedef struct BYTESTR
{
	UINT64 base_value;
	char *string;
} BYTESTR;

static BYTESTR bytestr[] =
{
	{0, "PBytes"},
	{0, "TBytes"},
	{0, "GBytes"},
	{0, "MBytes"},
	{0, "KBytes"},
	{0, "Bytes"},
};

// HEX 文字列を 64 bit 整数に変換
UINT64 HexToInt64(char *str)
{
	UINT len, i;
	UINT64 ret = 0;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		str += 2;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		{
			ret = ret * 16ULL + (UINT64)HexTo4Bit(c);
		}
		else
		{
			break;
		}
	}

	return ret;
}

// HEX 文字列を 32 bit 整数に変換
UINT HexToInt(char *str)
{
	UINT len, i;
	UINT ret = 0;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		str += 2;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		{
			ret = ret * 16 + (UINT)HexTo4Bit(c);
		}
		else
		{
			break;
		}
	}

	return ret;
}

// 64 bit 整数を HEX に変換
void ToHex64(char *str, UINT64 value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	// 空文字に設定
	StrCpy(tmp, 0, "");

	// 末尾桁から追加する
	while (true)
	{
		UINT a = (UINT)(value % (UINT64)16);
		value = value / (UINT)16;
		tmp[wp++] = FourBitToHex(a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	// 逆順にする
	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

// 32 bit 整数を HEX に変換
void ToHex(char *str, UINT value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	// 空文字に設定
	StrCpy(tmp, 0, "");

	// 末尾桁から追加する
	while (true)
	{
		UINT a = (UINT)(value % (UINT)16);
		value = value / (UINT)16;
		tmp[wp++] = FourBitToHex(a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	// 逆順にする
	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

// 4 bit 数値を 16 進文字列に変換
char FourBitToHex(UINT value)
{
	value = value % 16;

	if (value <= 9)
	{
		return '0' + value;
	}
	else
	{
		return 'a' + (value - 10);
	}
}

// 16 進文字列を 4 bit 整数に変換
UINT HexTo4Bit(char c)
{
	if ('0' <= c && c <= '9')
	{
		return c - '0';
	}
	else if ('a' <= c && c <= 'f')
	{
		return c - 'a' + 10;
	}
	else if ('A' <= c && c <= 'F')
	{
		return c - 'A' + 10;
	}
	else
	{
		return 0;
	}
}

// 標準のトークン区切り文字を取得する
char *DefaultTokenSplitChars()
{
	return " ,\t\r\n";
}

// 指定された文字が文字列に含まれるかどうかチェック
bool IsCharInStr(char *str, char c)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] == c)
		{
			return true;
		}
	}

	return false;
}

// 文字列からトークンを切り出す (区切り文字間の空間を無視しない)
TOKEN_LIST *ParseTokenWithNullStr(char *str, char *split_chars)
{
	LIST *o;
	UINT i, len;
	BUF *b;
	char zero = 0;
	TOKEN_LIST *t;
	// 引数チェック
	if (str == NULL)
	{
		return NullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = DefaultTokenSplitChars();
	}

	b = NewBuf();
	o = NewListFast(NULL);

	len = StrLen(str);

	for (i = 0;i < (len + 1);i++)
	{
		char c = str[i];
		bool flag = IsCharInStr(split_chars, c);

		if (c == '\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			WriteBuf(b, &c, sizeof(char));
		}
		else
		{
			WriteBuf(b, &zero, sizeof(char));

			Insert(o, CopyStr((char *)b->Buf));
			ClearBuf(b);
		}
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);
	FreeBuf(b);

	return t;
}

// 文字列からトークンを切り出す (区切り文字間の空間を無視する)
TOKEN_LIST *ParseTokenWithoutNullStr(char *str, char *split_chars)
{
	LIST *o;
	UINT i, len;
	bool last_flag;
	BUF *b;
	char zero = 0;
	TOKEN_LIST *t;
	// 引数チェック
	if (str == NULL)
	{
		return NullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = DefaultTokenSplitChars();
	}

	b = NewBuf();
	o = NewListFast(NULL);

	len = StrLen(str);
	last_flag = false;

	for (i = 0;i < (len + 1);i++)
	{
		char c = str[i];
		bool flag = IsCharInStr(split_chars, c);

		if (c == '\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			WriteBuf(b, &c, sizeof(char));
		}
		else
		{
			if (last_flag == false)
			{
				WriteBuf(b, &zero, sizeof(char));

				if ((StrLen((char *)b->Buf)) != 0)
				{
					Insert(o, CopyStr((char *)b->Buf));
				}
				ClearBuf(b);
			}
		}

		last_flag = flag;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);
	FreeBuf(b);

	return t;
}

// 文字列が含まれているかどうかチェック
bool InStr(char *str, char *keyword)
{
	return InStrEx(str, keyword, false);
}
bool InStrEx(char *str, char *keyword, bool case_sensitive)
{
	// 引数チェック
	if (IsEmptyStr(str) || IsEmptyStr(keyword))
	{
		return false;
	}

	if (SearchStrEx(str, keyword, 0, case_sensitive) == INFINITE)
	{
		return false;
	}

	return true;
}

// INI から値を取得
UINT IniIntValue(LIST *o, char *key)
{
	INI_ENTRY *e;
	// 引数チェック
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return 0;
	}

	return ToInt(e->Value);
}
UINT64 IniInt64Value(LIST *o, char *key)
{
	INI_ENTRY *e;
	// 引数チェック
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return 0;
	}

	return ToInt64(e->Value);
}
char *IniStrValue(LIST *o, char *key)
{
	INI_ENTRY *e;
	// 引数チェック
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return "";
	}

	return e->Value;
}
wchar_t *IniUniStrValue(LIST *o, char *key)
{
	INI_ENTRY *e;
	// 引数チェック
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return L"";
	}

	return e->UnicodeValue;
}

// INI を解放する
void FreeIni(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		INI_ENTRY *e = LIST_DATA(o, i);

		Free(e->Key);
		Free(e->Value);
		Free(e->UnicodeValue);

		Free(e);
	}

	ReleaseList(o);
}

// INI ファイルのエントリを取得する
INI_ENTRY *GetIniEntry(LIST *o, char *key)
{
	UINT i;
	// 引数チェック
	if (o == NULL || key == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		INI_ENTRY *e = LIST_DATA(o, i);

		if (StrCmpi(e->Key, key) == 0)
		{
			return e;
		}
	}

	return NULL;
}

// INI ファイルを読み込む
LIST *ReadIni(BUF *b)
{
	LIST *o;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	SeekBuf(b, 0, 0);

	while (true)
	{
		char *line = CfgReadNextLine(b);

		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			if (StartWith(line, "#") == false &&
				StartWith(line, "//") == false &&
				StartWith(line, ";") == false)
			{
				char *key, *value;
				UINT size = StrLen(line) + 1;

				key = ZeroMalloc(size);
				value = ZeroMalloc(size);

				if (GetKeyAndValue(line, key, size, value, size, NULL))
				{
					UINT uni_size;
					INI_ENTRY *e = ZeroMalloc(sizeof(INI_ENTRY));
					e->Key = CopyStr(key);
					e->Value = CopyStr(value);

					uni_size = CalcUtf8ToUni((BYTE *)value, StrLen(value));
					e->UnicodeValue = ZeroMalloc(uni_size);
					Utf8ToUni(e->UnicodeValue, uni_size, (BYTE *)value, StrLen(value));

					Add(o, e);
				}

				Free(key);
				Free(value);
			}
		}

		Free(line);
	}

	return o;
}

// 指定された文字が区切り文字かどうかチェック
bool IsSplitChar(char c, char *split_str)
{
	UINT i, len;
	char c_upper = ToUpper(c);
	if (split_str == NULL)
	{
		split_str = default_spliter;
	}

	len = StrLen(split_str);

	for (i = 0;i < len;i++)
	{
		if (ToUpper(split_str[i]) == c_upper)
		{
			return true;
		}
	}

	return false;
}

// 文字列からキーと値を取得する
bool GetKeyAndValue(char *str, char *key, UINT key_size, char *value, UINT value_size, char *split_str)
{
	UINT mode = 0;
	UINT wp1 = 0, wp2 = 0;
	UINT i, len;
	char *key_tmp, *value_tmp;
	bool ret = false;
	if (split_str == NULL)
	{
		split_str = default_spliter;
	}

	len = StrLen(str);

	key_tmp = ZeroMalloc(len + 1);
	value_tmp = ZeroMalloc(len + 1);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		switch (mode)
		{
		case 0:
			if (IsSplitChar(c, split_str) == false)
			{
				mode = 1;
				key_tmp[wp1] = c;
				wp1++;
			}
			break;

		case 1:
			if (IsSplitChar(c, split_str) == false)
			{
				key_tmp[wp1] = c;
				wp1++;
			}
			else
			{
				mode = 2;
			}
			break;

		case 2:
			if (IsSplitChar(c, split_str) == false)
			{
				mode = 3;
				value_tmp[wp2] = c;
				wp2++;
			}
			break;

		case 3:
			value_tmp[wp2] = c;
			wp2++;
			break;
		}
	}

	if (mode != 0)
	{
		ret = true;
		StrCpy(key, key_size, key_tmp);
		StrCpy(value, value_size, value_tmp);
	}

	Free(key_tmp);
	Free(value_tmp);

	return ret;
}

// 指定した文字の列を生成する
char *MakeCharArray(char c, UINT count)
{
	UINT i;
	char *ret = Malloc(count + 1);

	for (i = 0;i < count;i++)
	{
		ret[i] = c;
	}

	ret[count] = 0;

	return ret;
}
void MakeCharArray2(char *str, char c, UINT count)
{
	UINT i;

	for (i = 0;i < count;i++)
	{
		str[i] = c;
	}

	str[count] = 0;
}

// 指定した文字列の横幅を取得する
UINT StrWidth(char *str)
{
	wchar_t *s;
	UINT ret;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	s = CopyStrToUni(str);
	ret = UniStrWidth(s);
	Free(s);

	return ret;
}

// 指定した文字列がすべて大文字かどうかチェックする
bool IsAllUpperStr(char *str)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

// 改行コードを正規化する
char *NormalizeCrlf(char *str)
{
	char *ret;
	UINT ret_size, i, len, wp;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	ret_size = sizeof(char) * (len + 32) * 2;
	ret = Malloc(ret_size);

	wp = 0;

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		switch (c)
		{
		case '\r':
			if (str[i + 1] == '\n')
			{
				i++;
			}
			ret[wp++] = '\r';
			ret[wp++] = '\n';
			break;

		case '\n':
			ret[wp++] = '\r';
			ret[wp++] = '\n';
			break;

		default:
			ret[wp++] = c;
			break;
		}
	}

	ret[wp++] = 0;

	return ret;
}

// トークンリストを重複の無いものに変換する
TOKEN_LIST *UniqueToken(TOKEN_LIST *t)
{
	UINT i, num, j, n;
	TOKEN_LIST *ret;
	// 引数チェック
	if (t == NULL)
	{
		return NULL;
	}

	num = 0;
	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (StrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			num++;
		}
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->Token = ZeroMalloc(sizeof(char *) * num);
	ret->NumTokens = num;

	n = 0;

	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (StrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			ret->Token[n++] = CopyStr(t->Token[i]);
		}
	}

	return ret;
}

// バイト文字列に変換する (1,000 単位)
void ToStrByte1000(char *str, UINT size, UINT64 v)
{
	UINT i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	// gcc での警告対策
	bytestr[0].base_value = 1000000000UL;
	bytestr[0].base_value *= 1000UL;
	bytestr[0].base_value *= 1000UL;
	bytestr[1].base_value = 1000000000UL;
	bytestr[1].base_value *= 1000UL;
	bytestr[2].base_value = 1000000000UL;
	bytestr[3].base_value = 1000000UL;
	bytestr[4].base_value = 1000UL;
	bytestr[5].base_value = 0UL;

	for (i = 0;i < sizeof(bytestr) / sizeof(bytestr[0]);i++)
	{
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value)
		{
			if (b->base_value != 0)
			{
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			}
			else
			{
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

// バイト文字列に変換する
void ToStrByte(char *str, UINT size, UINT64 v)
{
	UINT i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	// gcc での警告対策
	bytestr[0].base_value = 1073741824UL;
	bytestr[0].base_value *= 1024UL;
	bytestr[0].base_value *= 1024UL;
	bytestr[1].base_value = 1073741824UL;
	bytestr[1].base_value *= 1024UL;
	bytestr[2].base_value = 1073741824UL;
	bytestr[3].base_value = 1048576UL;
	bytestr[4].base_value = 1024UL;
	bytestr[5].base_value = 0UL;

	for (i = 0;i < sizeof(bytestr) / sizeof(bytestr[0]);i++)
	{
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value)
		{
			if (b->base_value != 0)
			{
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			}
			else
			{
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

// 数字を文字列に変換して 3 桁ずつカンマで区切る
void ToStr3(char *str, UINT size, UINT64 v)
{
	char tmp[128];
	char tmp2[128];
	UINT i, len, wp;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	ToStr64(tmp, v);

	wp = 0;
	len = StrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	wp = 0;

	for (i = 0;i < len;i++)
	{
		if (i != 0 && (i % 3) == 0)
		{
			tmp[wp++] = ',';
		}
		tmp[wp++] = tmp2[i];
	}
	tmp[wp++] = 0;
	wp = 0;
	len = StrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	StrCpy(str, size, tmp2);
}

// MAC アドレスを文字列にする
void MacToStr(char *str, UINT size, UCHAR *mac_address)
{
	// 引数チェック
	if (str == NULL || mac_address == NULL)
	{
		return;
	}

	Format(str, size, "%02X-%02X-%02X-%02X-%02X-%02X",
		mac_address[0],
		mac_address[1],
		mac_address[2],
		mac_address[3],
		mac_address[4],
		mac_address[5]);
}

// 文字列が空かどうか調べる
bool IsEmptyStr(char *str)
{
	char *s;
	// 引数チェック
	if (str == NULL)
	{
		return true;
	}

	s = CopyStr(str);
	Trim(s);

	if (StrLen(s) == 0)
	{
		Free(s);
		return true;
	}
	else
	{
		Free(s);
		return false;
	}
}

// トークンリストを文字列リストに変換する
LIST *TokenListToList(TOKEN_LIST *t)
{
	UINT i;
	LIST *o;
	// 引数チェック
	if (t == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);
	for (i = 0;i < t->NumTokens;i++)
	{
		Insert(o, CopyStr(t->Token[i]));
	}

	return o;
}

// 文字列リストをトークンリストに変換する
TOKEN_LIST *ListToTokenList(LIST *o)
{
	UINT i;
	TOKEN_LIST *t;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = CopyStr(LIST_DATA(o, i));
	}

	return t;
}

// 文字列リストを解放する
void FreeStrList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *s = LIST_DATA(o, i);
		Free(s);
	}

	ReleaseList(o);
}

// 文字列リストを文字列に変換する
BUF *StrListToStr(LIST *o)
{
	BUF *b;
	UINT i;
	char c;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}
	b = NewBuf();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *s = LIST_DATA(o, i);
		WriteBuf(b, s, StrLen(s) + 1);
	}

	c = 0;
	WriteBuf(b, &c, 1);

	SeekBuf(b, 0, 0);

	return b;
}

// 文字列 (NULL区切り) をリストに変換する
LIST *StrToStrList(char *str, UINT size)
{
	LIST *o;
	char *tmp;
	UINT tmp_size;
	UINT i;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	i = 0;
	while (true)
	{
		if (i >= size)
		{
			break;
		}
		if (*str == 0)
		{
			break;
		}

		tmp_size = StrSize(str);
		tmp = ZeroMalloc(tmp_size);
		StrCpy(tmp, tmp_size, str);
		Add(o, tmp);
		str += StrLen(str) + 1;
		i++;
	}

	return o;
}

// 指定された文字列が数字かどうかチェック
bool IsNum(char *str)
{
	char c;
	UINT i, len;
	UINT n = 0;
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StrLen(tmp) == 0)
	{
		return false;
	}

	t = ParseToken(tmp, " ");

	if (t->NumTokens >= 1)
	{
		StrCpy(tmp, sizeof(tmp), t->Token[0]);
	}

	FreeToken(t);

	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		bool b = false;
		c = tmp[i];
		if (('0' <= c && c <= '9') || (c == '+') || (c == '-') || (c == ','))
		{
			b = true;
		}

		if (b == false)
		{
			return false;
		}
	}

	for (i = 0;i < len;i++)
	{
		c = tmp[i];
		if (c == '-')
		{
			n++;
		}
	}
	if (n >= 2)
	{
		return false;
	}

	return true;
}

// 中身が無いトークンリスト
TOKEN_LIST *NullToken()
{
	TOKEN_LIST *ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

// トークンリストのコピー
TOKEN_LIST *CopyToken(TOKEN_LIST *src)
{
	TOKEN_LIST *ret;
	UINT i;
	// 引数チェック
	if (src == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = src->NumTokens;
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyStr(src->Token[i]);
	}

	return ret;
}

// コマンドラインをパースする
TOKEN_LIST *ParseCmdLine(char *str)
{
	TOKEN_LIST *t;
	LIST *o;
	UINT i, len, wp, mode;
	char c;
	char *tmp;
	bool ignore_space = false;
	// 引数チェック
	if (str == NULL)
	{
		// トークン無し
		return NullToken();
	}

	o = NewListFast(NULL);
	tmp = Malloc(StrSize(str) + 32);

	wp = 0;
	mode = 0;

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		c = str[i];

		switch (mode)
		{
		case 0:
			// 次のトークンを発見するモード
			if (c == ' ' || c == '\t')
			{
				// 次の文字へ進める
			}
			else
			{
				// トークンの開始
				if (c == '\"')
				{
					if (str[i + 1] == '\"')
					{
						// 2 重の " は 1 個の " 文字として見なす
						tmp[wp++] = '\"';
						i++;
					}
					else
					{
						// 1 個の " はスペース無視フラグを有効にする
						ignore_space = true;
					}
				}
				else
				{
					tmp[wp++] = c;
				}

				mode = 1;
			}
			break;

		case 1:
			if (ignore_space == false && (c == ' ' || c == '\t'))
			{
				// トークンの終了
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, CopyStr(tmp));
				mode = 0;
			}
			else
			{
				if (c == '\"')
				{
					if (str[i + 1] == '\"')
					{
						// 2 重の " は 1 個の " 文字として見なす
						tmp[wp++] = L'\"';
						i++;
					}
					else
					{
						if (ignore_space == false)
						{
							// 1 個の " はスペース無視フラグを有効にする
							ignore_space = true;
						}
						else
						{
							// スペース無視フラグを無効にする
							ignore_space = false;
						}
					}
				}
				else
				{
					tmp[wp++] = c;
				}
			}
			break;
		}
	}

	if (wp != 0)
	{
		tmp[wp++] = 0;
		Insert(o, CopyStr(tmp));
	}

	Free(tmp);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return t;
}

// 64bit 整数を文字列に変換
void ToStr64(char *str, UINT64 value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	// 空文字に設定
	StrCpy(tmp, 0, "");

	// 末尾桁から追加する
	while (true)
	{
		UINT a = (UINT)(value % (UINT64)10);
		value = value / (UINT64)10;
		tmp[wp++] = (char)('0' + a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	// 逆順にする
	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

// 文字列を 64bit 整数に変換
UINT64 ToInt64(char *str)
{
	UINT len, i;
	UINT64 ret = 0;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		if (c != ',')
		{
			if ('0' <= c && c <= '9')
			{
				ret = ret * (UINT64)10 + (UINT64)(c - '0');
			}
			else
			{
				break;
			}
		}
	}

	return ret;
}

// str が key で終了するかどうかチェック
bool EndWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	// 引数チェック
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// 比較
	str_len = StrLen(str);
	key_len = StrLen(key);
	if (str_len < key_len)
	{
		return false;
	}

	if (StrCmpi(str + (str_len - key_len), key) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// str が key で始まるかどうかチェック
bool StartWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	char *tmp;
	bool ret;
	// 引数チェック
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// 比較
	str_len = StrLen(str);
	key_len = StrLen(key);
	if (str_len < key_len)
	{
		return false;
	}
	if (str_len == 0 || key_len == 0)
	{
		return false;
	}
	tmp = CopyStr(str);
	tmp[key_len] = 0;

	if (StrCmpi(tmp, key) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(tmp);

	return ret;
}

// バイナリデータを表示
void PrintBin(void *data, UINT size)
{
	char *tmp;
	UINT i;
	// 引数チェック
	if (data == NULL)
	{
		return;
	}

	i = size * 3 + 1;
	tmp = Malloc(i);
	BinToStrEx(tmp, i, data, size);
	Print("%s\n", tmp);
	Free(tmp);
}

// 文字列を MAC アドレスに変換する
bool StrToMac(UCHAR *mac_address, char *str)
{
	BUF *b;
	// 引数チェック
	if (mac_address == NULL || str == NULL)
	{
		return false;
	}

	b = StrToBin(str);
	if (b == NULL)
	{
		return false;
	}

	if (b->Size != 6)
	{
		FreeBuf(b);
		return false;
	}

	Copy(mac_address, b->Buf, 6);

	FreeBuf(b);

	return true;
}

// 16 進文字列をバイナリデータに変換する
BUF *StrToBin(char *str)
{
	BUF *b;
	UINT len, i;
	char tmp[3];
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp[0] = 0;
	b = NewBuf();
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		c = ToUpper(c);
		if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))
		{
			if (tmp[0] == 0)
			{
				tmp[0] = c;
				tmp[1] = 0;
			}
			else if (tmp[1] == 0)
			{
				UCHAR data;
				char tmp2[64];
				tmp[1] = c;
				tmp[2] = 0;
				StrCpy(tmp2, sizeof(tmp2), "0x");
				StrCat(tmp2, sizeof(tmp2), tmp);
				data = (UCHAR)strtoul(tmp2, NULL, 0);
				WriteBuf(b, &data, 1);
				Zero(tmp, sizeof(tmp));	
			}
		}
		else if (c == ' ' || c == ',' || c == '-' || c == ':')
		{
			// 何もしない
		}
		else
		{
			break;
		}
	}

	return b;
}

// バイナリデータを 16 進文字列に変換する (スペースも入れる)
void BinToStrEx(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	// 引数チェック
	if (str == NULL || data == NULL)
	{
		return;
	}

	// サイズの計算
	size = data_size * 3 + 1;
	// メモリ確保
	tmp = ZeroMalloc(size);
	// 変換
	for (i = 0;i < data_size;i++)
	{
		Format(&tmp[i * 3], 0, "%02X ", buf[i]);
	}
	Trim(tmp);
	// コピー
	StrCpy(str, str_size, tmp);
	// メモリ解放
	Free(tmp);
}
void BinToStrEx2(char *str, UINT str_size, void *data, UINT data_size, char padding_char)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	// 引数チェック
	if (str == NULL || data == NULL)
	{
		return;
	}

	// サイズの計算
	size = data_size * 3 + 1;
	// メモリ確保
	tmp = ZeroMalloc(size);
	// 変換
	for (i = 0;i < data_size;i++)
	{
		Format(&tmp[i * 3], 0, "%02X%c", buf[i], padding_char);
	}
	if (StrLen(tmp) >= 1)
	{
		if (tmp[StrLen(tmp) - 1] == padding_char)
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}
	// コピー
	StrCpy(str, str_size, tmp);
	// メモリ解放
	Free(tmp);
}
// バイナリデータを文字列に変換してコピーする
char *CopyBinToStrEx(void *data, UINT data_size)
{
	char *ret;
	UINT size;
	// 引数チェック
	if (data == NULL)
	{
		return NULL;
	}

	size = data_size * 3 + 1;
	ret = ZeroMalloc(size);

	BinToStrEx(ret, size, data, data_size);

	return ret;
}
char *CopyBinToStr(void *data, UINT data_size)
{
	char *ret;
	UINT size;
	// 引数チェック
	if (data == NULL)
	{
		return NULL;
	}

	size = data_size * 2 + 1;
	ret = ZeroMalloc(size);

	BinToStr(ret, size, data, data_size);

	return ret;
}

// バイナリデータを 16 進文字列に変換する
void BinToStr(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	// 引数チェック
	if (str == NULL || data == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	// サイズの計算
	size = data_size * 2 + 1;
	// メモリ確保
	tmp = ZeroMalloc(size);
	// 変換
	for (i = 0;i < data_size;i++)
	{
		sprintf(&tmp[i * 2], "%02X", buf[i]);
	}
	// コピー
	StrCpy(str, str_size, tmp);
	// メモリ解放
	Free(tmp);
}
void BinToStrW(wchar_t *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UINT tmp_size;
	// 引数チェック
	if (str == NULL || data == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	tmp_size = (data_size * 2 + 4) * sizeof(wchar_t);
	tmp = ZeroMalloc(tmp_size);

	BinToStr(tmp, tmp_size, data, data_size);

	StrToUni(str, str_size, tmp);

	Free(tmp);
}

// 160 ビット列を文字列にする
void Bit160ToStr(char *str, UCHAR *data)
{
	// 引数チェック
	if (str == NULL || data == NULL)
	{
		return;
	}

	Format(str, 0,
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], 
		data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
}

// 128 ビット列を文字列にする
void Bit128ToStr(char *str, UCHAR *data)
{
	// 引数チェック
	if (str == NULL || data == NULL)
	{
		return;
	}

	Format(str, 0,
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], 
		data[10], data[11], data[12], data[13], data[14], data[15]);
}

// 文字列をコピーする
char *CopyStr(char *str)
{
	UINT len;
	char *dst;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	dst = Malloc(len + 1);
	StrCpy(dst, len + 1, str);
	return dst;
}

// 安全な文字列かどうかチェック
bool IsSafeStr(char *str)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		if (IsSafeChar(str[i]) == false)
		{
			return false;
		}
	}
	if (str[0] == ' ')
	{
		return false;
	}
	if (len != 0)
	{
		if (str[len - 1] == ' ')
		{
			return false;
		}
	}
	return true;
}

// 安全な文字かどうかチェック
bool IsSafeChar(char c)
{
	UINT i, len;
	char *check_str =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789"
		" ()-_#%&.";

	len = StrLen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return true;
		}
	}
	return false;
}

// 文字列から指定した文字を削除する
void TruncateCharFromStr(char *str, char replace)
{
	char *src,*dst;

	if (str == NULL)
	{
		return;
	}

	src = dst = str;

	while(*src != '\0')
	{
		if(*src != replace)
		{
			*dst = *src;
			dst++;
		}
		src++;
	}
	*dst = *src;

	//BUF *b = NewBuf();
	//UINT i, len;
	//char zero = 0;

	//len = StrLen(str);
	//for (i = 0;i < len;i++)
	//{
	//	char c = str[i];

	//	if (c != replace)
	//	{
	//		WriteBuf(b, &c, 1);
	//	}
	//}

	//if (b->Size == 0)
	//{
	//	char c = '_';
	//	WriteBuf(b, &c, 1);
	//}

	//WriteBuf(b, &zero, 1);

	//StrCpy(str, 0, b->Buf);

	//FreeBuf(b);
}

// 安全な文字以外を置き換える
void EnSafeStr(char *str, char replace)
{
	if (str == NULL)
	{
		return;
	}

	while(*str != '\0')
	{
		if(IsSafeChar(*str) == false)
		{
			*str = replace;
		}
		str++;
	}
}

// 文字列ライブラリの動作チェック
bool CheckStringLibrary()
{
	wchar_t *compare_str = L"TEST_TEST_123_123456789012345";
	char *teststr = "TEST";
	wchar_t *testunistr = L"TEST";
	wchar_t tmp[64];
	UINT i1 = 123;
	UINT64 i2 = 123456789012345ULL;

	UniFormat(tmp, sizeof(tmp), L"%S_%s_%u_%I64u", teststr, testunistr,
		i1, i2);

	if (UniStrCmpi(tmp, compare_str) != 0)
	{
		return false;
	}

	return true;
}

// 文字列ライブラリの初期化
void InitStringLibrary()
{
	// トークン用ロックの作成
	token_lock = NewLock();

	// 国際ライブラリの初期化
	InitInternational();

	// 動作チェック
	if (CheckStringLibrary() == false)
	{
#ifdef	OS_WIN32
		Alert("String Library Init Failed.\r\nPlease check your locale settings.", NULL);
#else	// OS_WIN32
		Alert("String Library Init Failed.\r\nPlease check your locale settings and iconv() libraries.", NULL);
#endif	// OS_WIN32
		exit(0);
	}
}

// 文字列ライブラリの解放
void FreeStringLibrary()
{
	// 国際ライブラリの解放
	FreeInternational();

	// トークン用ロックの解放
	DeleteLock(token_lock);
	token_lock = NULL;
}

// 文字列の置換 (大文字小文字を区別しない)
UINT ReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, false);
}

// 文字列の置換 (大文字小文字を区別する)
UINT ReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, true);
}

// 文字列の置換
UINT ReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, j, num;
	UINT len_string, len_old, len_new;
	UINT len_ret;
	UINT wp;
	char *ret;
	// 引数チェック
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// 文字列長の取得
	len_string = StrLen(string);
	len_old = StrLen(old_keyword);
	len_new = StrLen(new_keyword);

	// 最終文字列長の計算
	len_ret = CalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	// メモリ確保
	ret = Malloc(len_ret + 1);
	ret[len_ret] = '\0';

	// 検索と置換
	i = 0;
	j = 0;
	num = 0;
	wp = 0;
	while (true)
	{
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			Copy(ret + wp, string + j, len_string - j);
			wp += len_string - j;
			break;
		}
		num++;
		Copy(ret + wp, string + j, i - j);
		wp += i - j;
		Copy(ret + wp, new_keyword, len_new);
		wp += len_new;
		i += len_old;
		j = i;
	}

	// 検索結果のコピー
	StrCpy(dst, size, ret);

	// メモリ解放
	Free(ret);

	return num;
}

// 文字列の置換後の文字列長を計算する
UINT CalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, num;
	UINT len_string, len_old, len_new;
	// 引数チェック
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// 文字列長の取得
	len_string = StrLen(string);
	len_old = StrLen(old_keyword);
	len_new = StrLen(new_keyword);

	if (len_old == len_new)
	{
		return len_string;
	}

	// 検索処理
	num = 0;
	i = 0;
	while (true)
	{
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			break;
		}
		i += len_old;
		num++;
	}

	// 計算
	return len_string + len_new * num - len_old * num;
}

// 文字列の検索 (大文字 / 小文字を区別する)
UINT SearchStr(char *string, char *keyword, UINT start)
{
	return SearchStrEx(string, keyword, start, true);
}

// 文字列の検索 (大文字 / 小文字を区別しない)
UINT SearchStri(char *string, char *keyword, UINT start)
{
	return SearchStrEx(string, keyword, start, false);
}

// 文字列 string から文字列 keyword を検索して最初に見つかった文字の場所を返す
// (1文字目に見つかったら 0, 見つからなかったら INFINITE)
UINT SearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive)
{
	UINT len_string, len_keyword;
	UINT i;
	char *cmp_string, *cmp_keyword;
	bool found;
	// 引数チェック
	if (string == NULL || keyword == NULL)
	{
		return INFINITE;
	}

	// string の長さを取得
	len_string = StrLen(string);
	if (len_string <= start)
	{
		// start の値が不正
		return INFINITE;
	}

	// keyword の長さを取得
	len_keyword = StrLen(keyword);
	if (len_keyword == 0)
	{
		// キーワードが無い
		return INFINITE;
	}

	if ((len_string - start) < len_keyword)
	{
		// キーワードの長さのほうが長い
		return INFINITE;
	}

	if (case_sensitive)
	{
		cmp_string = string;
		cmp_keyword = keyword;
	}
	else
	{
		cmp_string = Malloc(len_string + 1);
		StrCpy(cmp_string, len_string + 1, string);
		cmp_keyword = Malloc(len_keyword + 1);
		StrCpy(cmp_keyword, len_keyword + 1, keyword);
		StrUpper(cmp_string);
		StrUpper(cmp_keyword);
	}

	// 検索
	found = false;
	for (i = start;i < (len_string - len_keyword + 1);i++)
	{
		// 比較する
		if (!strncmp(&cmp_string[i], cmp_keyword, len_keyword))
		{
			// 発見した
			found = true;
			break;
		}
	}

	if (case_sensitive == false)
	{
		// メモリ解放
		Free(cmp_keyword);
		Free(cmp_string);
	}

	if (found == false)
	{
		return INFINITE;
	}
	return i;
}

// 指定した文字がトークンリスト内にあるかどうか調べる
bool IsInToken(TOKEN_LIST *t, char *str)
{
	UINT i;
	// 引数チェック
	if (t == NULL || str == NULL)
	{
		return false;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		if (StrCmpi(t->Token[i], str) == 0)
		{
			return true;
		}
	}

	return false;
}

// トークンリストの解放
void FreeToken(TOKEN_LIST *tokens)
{
	UINT i;
	if (tokens == NULL)
	{
		return;
	}
	for (i = 0;i < tokens->NumTokens;i++)
	{
		if (tokens->Token[i] != 0)
		{
			Free(tokens->Token[i]);
		}
	}
	Free(tokens->Token);
	Free(tokens);
}

// トークンのパース
TOKEN_LIST *ParseToken(char *src, char *separator)
{
	TOKEN_LIST *ret;
	char *tmp;
	char *str1, *str2;
	UINT len;
	UINT num;
	if (src == NULL)
	{
		ret = ZeroMalloc(sizeof(TOKEN_LIST));
		ret->Token = ZeroMalloc(0);
		return ret;
	}
	if (separator == NULL)
	{
		separator = " ,\t\r\n";
	}
	len = StrLen(src);
	str1 = Malloc(len + 1);
	str2 = Malloc(len + 1);
	StrCpy(str1, 0, src);
	StrCpy(str2, 0, src);

	Lock(token_lock);
	{
		tmp = strtok(str1, separator);
		num = 0;
		while (tmp != NULL)
		{
			num++;
			tmp = strtok(NULL, separator);
		}
		ret = Malloc(sizeof(TOKEN_LIST));
		ret->NumTokens = num;
		ret->Token = (char **)Malloc(sizeof(char *) * num);
		num = 0;
		tmp = strtok(str2, separator);
		while (tmp != NULL)
		{
			ret->Token[num] = (char *)Malloc(StrLen(tmp) + 1);
			StrCpy(ret->Token[num], 0, tmp);
			num++;
			tmp = strtok(NULL, separator);
		}
	}
	Unlock(token_lock);

	Free(str1);
	Free(str2);
	return ret;
}

// 1 行を標準入力から取得
bool GetLine(char *str, UINT size)
{
	bool ret;
	wchar_t *unistr;
	UINT unistr_size = (size + 1) * sizeof(wchar_t);

	unistr = Malloc(unistr_size);

	ret = UniGetLine(unistr, unistr_size);

	UniToStr(str, size, unistr);

	Free(unistr);

	return ret;
}

// 末尾の \r \n を削除
void TrimCrlf(char *str)
{
	UINT len;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	len = StrLen(str);
	if (len == 0)
	{
		return;
	}

	if (str[len - 1] == '\n')
	{
		if (len >= 2 && str[len - 2] == '\r')
		{
			str[len - 2] = 0;
		}
		str[len - 1] = 0;
	}
	else if (str[len - 1] == '\r')
	{
		str[len - 1] = 0;
	}
}

// 文字列の左右の空白を削除
void Trim(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	// 左側を trim
	TrimLeft(str);

	// 右側を trim
	TrimRight(str);
}

// 文字列の右側の空白を削除
void TrimRight(char *str)
{
	char *buf, *tmp;
	UINT len, i, wp, wp2;
	BOOL flag;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	len = StrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[len - 1] != ' ' && str[len - 1] != '\t')
	{
		return;
	}

	buf = Malloc(len + 1);
	tmp = Malloc(len + 1);
	flag = FALSE;
	wp = 0;
	wp2 = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != ' ' && str[i] != '\t')
		{
			Copy(buf + wp, tmp, wp2);
			wp += wp2;
			wp2 = 0;
			buf[wp++] = str[i];
		}
		else
		{
			tmp[wp2++] = str[i];
		}
	}
	buf[wp] = 0;
	StrCpy(str, 0, buf);
	Free(buf);
	Free(tmp);
}

// 文字列の左側の空白を削除
void TrimLeft(char *str)
{
	char *buf;
	UINT len, i, wp;
	BOOL flag;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	len = StrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[0] != ' ' && str[0] != '\t')
	{
		return;
	}

	buf = Malloc(len + 1);
	flag = FALSE;
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != ' ' && str[i] != '\t')
		{
			flag = TRUE;
		}
		if (flag)
		{
			buf[wp++] = str[i];
		}
	}
	buf[wp] = 0;
	StrCpy(str, 0, buf);
	Free(buf);
}

// 整数を 16 進文字列に変換 (8桁固定)
void ToStrx8(char *str, UINT i)
{
	sprintf(str, "0x%08x", i);
}

// 整数を 16 進文字列に変換
void ToStrx(char *str, UINT i)
{
	sprintf(str, "0x%02x", i);
}

// 符号付整数を文字列に変換
void ToStri(char *str, int i)
{
	sprintf(str, "%i", i);
}

// 整数を文字列に変換
void ToStr(char *str, UINT i)
{
	sprintf(str, "%u", i);
}

// 文字列を符号付整数に変換
int ToInti(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	return (int)ToInt(str);
}

// 文字列を bool に変換
bool ToBool(char *str)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (IsEmptyStr(tmp))
	{
		return false;
	}

	if (ToInt(tmp) != 0)
	{
		return true;
	}

	if (StartWith("true", tmp))
	{
		return true;
	}

	if (StartWith("yes", tmp))
	{
		return true;
	}

	if (StartWith(tmp, "true"))
	{
		return true;
	}

	if (StartWith(tmp, "yes"))
	{
		return true;
	}

	return false;
}

// 文字列を整数に変換
UINT ToInt(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	// 8 進数表記を無視する
	while (true)
	{
		if (*str != '0')
		{
			break;
		}
		if ((*(str + 1) == 'x') || (*(str + 1) == 'X'))
		{
			break;
		}
		str++;
	}

	return (UINT)strtoul(str, NULL, 0);
}

// 64bit 整数のためのフォーマット文字列を置換する
char *ReplaceFormatStringFor64(char *fmt)
{
	char *tmp;
	char *ret;
	UINT tmp_size;
	// 引数チェック
	if (fmt == NULL)
	{
		return NULL;
	}

	tmp_size = StrSize(fmt) * 2;
	tmp = ZeroMalloc(tmp_size);

#ifdef	OS_WIN32
	ReplaceStrEx(tmp, tmp_size, fmt, "%ll", "%I64", false);
#else	// OS_WIN32
	ReplaceStrEx(tmp, tmp_size, fmt, "%I64", "%ll", false);
#endif	// OS_WIN32

	ret = CopyStr(tmp);
	Free(tmp);

	return ret;
}

// 文字列を画面に表示する
void PrintStr(char *str)
{
	wchar_t *unistr = NULL;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

#ifdef	OS_UNIX
	fputs(str, stdout);
#else	// OS_UNIX
	unistr = CopyStrToUni(str);
	UniPrintStr(unistr);
	Free(unistr);
#endif	// OS_UNIX
}

// 文字列を引数付きで表示する
void PrintArgs(char *fmt, va_list args)
{
	wchar_t *ret;
	wchar_t *fmt_wchar;
	char *tmp;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	fmt_wchar = CopyStrToUni(fmt);
	ret = InternalFormatArgs(fmt_wchar, args, true);

	tmp = CopyUniToStr(ret);
	PrintStr(tmp);
	Free(tmp);

	Free(ret);
	Free(fmt_wchar);
}

// 文字列を表示する
void Print(char *fmt, ...)
{
	va_list args;
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	PrintArgs(fmt, args);
	va_end(args);
}

// デバッグ文字列を引数付きで表示する
void DebugArgs(char *fmt, va_list args)
{
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}
	if (g_debug == false)
	{
		return;
	}

	PrintArgs(fmt, args);
}

// デバッグ文字列を表示する
void Debug(char *fmt, ...)
{
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}
	if (g_debug == false)
	{
		return;
	}

	va_start(args, fmt);

	DebugArgs(fmt, args);

	va_end(args);
}

// 文字列をフォーマットして結果を返す
char *CopyFormat(char *fmt, ...)
{
	char *buf;
	char *ret;
	UINT size;
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return NULL;
	}

	size = MAX(StrSize(fmt) * 10, MAX_SIZE * 10);
	buf = Malloc(size);

	va_start(args, fmt);
	FormatArgs(buf, size, fmt, args);

	ret = CopyStr(buf);
	Free(buf);

	va_end(args);
	return ret;
}

// 文字列をフォーマットする
void Format(char *buf, UINT size, char *fmt, ...)
{
	va_list args;
	// 引数チェック
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	FormatArgs(buf, size, fmt, args);
	va_end(args);
}

// 文字列をフォーマットする (引数リスト)
void FormatArgs(char *buf, UINT size, char *fmt, va_list args)
{
	wchar_t *tag;
	wchar_t *ret;
	// 引数チェック
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	tag = CopyStrToUni(fmt);
	ret = InternalFormatArgs(tag, args, true);

	UniToStr(buf, size, ret);
	Free(ret);
	Free(tag);
}

// 文字列を大文字・小文字を区別せずに比較する
int StrCmpi(char *str1, char *str2)
{
	UINT i;
	// 引数チェック
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	// 文字列比較
	i = 0;
	while (true)
	{
		char c1, c2;
		c1 = ToUpper(str1[i]);
		c2 = ToUpper(str2[i]);
		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}

// 文字列を比較する
int StrCmp(char *str1, char *str2)
{
	// 引数チェック
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	return strcmp(str1, str2);
}

// 文字列を小文字にする
void StrLower(char *str)
{
	UINT len, i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = ToLower(str[i]);
	}
}

// 文字列を大文字にする
void StrUpper(char *str)
{
	UINT len, i;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = ToUpper(str[i]);
	}
}

// 文字を小文字にする
char ToLower(char c)
{
	if ('A' <= c && c <= 'Z')
	{
		c += 'z' - 'Z';
	}
	return c;
}

// 文字を大文字にする
char ToUpper(char c)
{
	if ('a' <= c && c <= 'z')
	{
		c += 'Z' - 'z';
	}
	return c;
}

// 文字列を結合
UINT StrCat(char *dst, UINT size, char *src)
{
	UINT len1, len2, len_test;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	// KS
	KS_INC(KS_STRCAT_COUNT);

	if (size == 0)
	{
		// 長さを無視
		size = 0x7fffffff;
	}

	len1 = StrLen(dst);
	len2 = StrLen(src);
	len_test = len1 + len2 + 1;
	if (len_test > size)
	{
		if (len2 <= (len_test - size))
		{
			return 0;
		}
		len2 -= len_test - size;
	}
	Copy(dst + len1, src, len2);
	dst[len1 + len2] = 0;

	return len1 + len2;
}
UINT StrCatLeft(char *dst, UINT size, char *src)
{
	char *s;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	s = CopyStr(dst);
	StrCpy(dst, size, src);
	StrCat(dst, size, s);

	Free(s);

	return StrLen(dst);
}

// 文字列をコピー
UINT StrCpy(char *dst, UINT size, char *src)
{
	UINT len;
	// 引数チェック
	if (dst == src)
	{
		return StrLen(src);
	}
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= 1)
			{
				dst[0] = '\0';
			}
		}
		return 0;
	}
	if (size == 1)
	{
		dst[0] = '\0';
		return 0;
	}
	if (size == 0)
	{
		// 長さを無視
		size = 0x7fffffff;
	}

	// 長さをチェック
	len = StrLen(src);
	if (len <= (size - 1))
	{
		Copy(dst, src, len + 1);
	}
	else
	{
		len = size - 1;
		Copy(dst, src, len);
		dst[len] = '\0';
	}

	// KS
	KS_INC(KS_STRCPY_COUNT);

	return len;
}

// 文字列バッファが指定されたサイズに収まっているかどうかを確認
bool StrCheckSize(char *str, UINT size)
{
	// 引数チェック
	if (str == NULL || size == 0)
	{
		return false;
	}

	return StrCheckLen(str, size - 1);
}

// 文字列が指定された長さ以内であることを確認
bool StrCheckLen(char *str, UINT len)
{
	UINT count = 0;
	UINT i;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_STRCHECK_COUNT);

	for (i = 0;;i++)
	{
		if (str[i] == '\0')
		{
			return true;
		}
		count++;
		if (count > len)
		{
			return false;
		}
	}
}

// 文字列を格納するために必要なメモリサイズを取得
UINT StrSize(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	return StrLen(str) + 1;
}

// 文字列の長さを取得
UINT StrLen(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	// KS
	KS_INC(KS_STRLEN_COUNT);

	return (UINT)strlen(str);
}


