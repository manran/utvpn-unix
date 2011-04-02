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

// Internat.c
// 国際化のための文字列変換ライブラリ

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

extern LOCK *token_lock;
static char charset[MAX_SIZE] = "EUCJP";
static LOCK *iconv_lock = NULL;
void *iconv_cache_wide_to_str = 0;
void *iconv_cache_str_to_wide = 0;

// 文字列が含まれているかどうかチェック
bool UniInStr(wchar_t *str, wchar_t *keyword)
{
	return UniInStrEx(str, keyword, false);
}
bool UniInStrEx(wchar_t *str, wchar_t *keyword, bool case_sensitive)
{
	// 引数チェック
	if (UniIsEmptyStr(str) || UniIsEmptyStr(keyword))
	{
		return false;
	}

	if (UniSearchStrEx(str, keyword, 0, case_sensitive) == INFINITE)
	{
		return false;
	}

	return true;
}

// バイナリデータに変換
BUF *UniStrToBin(wchar_t *str)
{
	char *str_a = CopyUniToStr(str);
	BUF *ret;

	ret = StrToBin(str_a);

	Free(str_a);

	return ret;
}

// 指定した文字の列を生成する
wchar_t *UniMakeCharArray(wchar_t c, UINT count)
{
	UINT i;
	wchar_t *ret = Malloc(sizeof(wchar_t) * (count + 1));

	for (i = 0;i < count;i++)
	{
		ret[i] = c;
	}

	ret[count] = 0;

	return ret;
}

// 安全な文字かどうかチェック
bool UniIsSafeChar(wchar_t c)
{
	UINT i, len;
	wchar_t *check_str =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz"
		L"0123456789"
		L" ()-_#%&.";

	len = UniStrLen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return true;
		}
	}
	return false;
}

// トークンリストを文字列リストに変換する
LIST *UniTokenListToList(UNI_TOKEN_LIST *t)
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
		Insert(o, UniCopyStr(t->Token[i]));
	}

	return o;
}

// 文字列リストをトークンリストに変換する
UNI_TOKEN_LIST *UniListToTokenList(LIST *o)
{
	UINT i;
	UNI_TOKEN_LIST *t;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = UniCopyStr(LIST_DATA(o, i));
	}

	return t;
}

// 文字列リストを解放する
void UniFreeStrList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		Free(s);
	}

	ReleaseList(o);
}

// 文字列リストを文字列に変換する
BUF *UniStrListToStr(LIST *o)
{
	BUF *b;
	UINT i;
	wchar_t c;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}
	b = NewBuf();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		WriteBuf(b, s, UniStrSize(s));
	}

	c = 0;
	WriteBuf(b, &c, sizeof(c));

	SeekBuf(b, 0, 0);

	return b;
}

// 文字列 (NULL区切り) をリストに変換する
LIST *UniStrToStrList(wchar_t *str, UINT size)
{
	LIST *o;
	wchar_t *tmp;
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

		tmp_size = UniStrSize(str);
		tmp = ZeroMalloc(tmp_size);
		UniStrCpy(tmp, tmp_size, str);
		Add(o, tmp);
		str += UniStrLen(str) + 1;
		i++;
	}

	return o;
}

// 改行コードを正規化する
wchar_t *UniNormalizeCrlf(wchar_t *str)
{
	wchar_t *ret;
	UINT ret_size, i, len, wp;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);
	ret_size = sizeof(wchar_t) * (len + 32) * 2;
	ret = Malloc(ret_size);

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = str[i];

		switch (c)
		{
		case L'\r':
			if (str[i + 1] == L'\n')
			{
				i++;
			}
			ret[wp++] = L'\r';
			ret[wp++] = L'\n';
			break;

		case L'\n':
			ret[wp++] = L'\r';
			ret[wp++] = L'\n';
			break;

		default:
			ret[wp++] = c;
			break;
		}
	}

	ret[wp++] = 0;

	return ret;
}

// str が key で終了するかどうかチェック
bool UniEndWith(wchar_t *str, wchar_t *key)
{
	UINT str_len;
	UINT key_len;
	// 引数チェック
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// 比較
	str_len = UniStrLen(str);
	key_len = UniStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}

	if (UniStrCmpi(str + (str_len - key_len), key) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// str が key で始まるかどうかチェック
bool UniStartWith(wchar_t *str, wchar_t *key)
{
	UINT str_len;
	UINT key_len;
	wchar_t *tmp;
	bool ret;
	// 引数チェック
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// 比較
	str_len = UniStrLen(str);
	key_len = UniStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}
	if (str_len == 0 || key_len == 0)
	{
		return false;
	}
	tmp = CopyUniStr(str);
	tmp[key_len] = 0;

	if (UniStrCmpi(tmp, key) == 0)
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

// 整数をカンマ区切り文字列に変換する
void UniToStr3(wchar_t *str, UINT size, UINT64 value)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	ToStr3(tmp, sizeof(tmp), value);

	StrToUni(str, size, tmp);
}

// 文字列のフォーマット (内部関数)
wchar_t *InternalFormatArgs(wchar_t *fmt, va_list args, bool ansi_mode)
{
	UINT i, len;
	wchar_t *tmp;
	UINT tmp_size;
	LIST *o;
	UINT mode = 0;
	UINT wp;
	UINT total_size;
	wchar_t *ret;
	// 引数チェック
	if (fmt == NULL)
	{
		return NULL;
	}

	len = UniStrLen(fmt);
	tmp_size = UniStrSize(fmt);
	tmp = Malloc(tmp_size);

	o = NewListFast(NULL);

	mode = 0;

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = fmt[i];

		if (mode == 0)
		{
			// 通常の文字モード
			switch (c)
			{
			case L'%':
				// 書式指定の開始
				if (fmt[i + 1] == L'%')
				{
					// 次の文字も % の場合は % を一文字出力するだけ
					i++;
					tmp[wp++] = c;
				}
				else
				{
					// 次の文字が % でない場合は状態遷移を行う
					mode = 1;
					tmp[wp++] = 0;
					wp = 0;
					Add(o, CopyUniStr(tmp));
					tmp[wp++] = c;
				}
				break;
			default:
				// 通常の文字
				tmp[wp++] = c;
				break;
			}
		}
		else
		{
			char *tag;
			char dst[MAX_SIZE];
			wchar_t *target_str;
			wchar_t *padding_str;
			bool left_padding;
			UINT target_str_len;
			UINT total_len;
			wchar_t *output_str;
			UINT padding;
			// 書式指定モード
			switch (c)
			{
			case L'c':
			case L'C':
			case L'd':
			case L'i':
			case L'o':
			case L'u':
			case L'x':
			case L'X':
				// int 型
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = CopyUniToStr(tmp);

				#ifdef	OS_WIN32
					ReplaceStrEx(tag, 0, tag, "ll", "I64", false);
				#else	// OS_WIN32
					ReplaceStrEx(tag, 0, tag, "I64", "ll", false);
				#endif	// OS_WIN32

				if ((UniStrLen(tmp) >= 5 && tmp[UniStrLen(tmp) - 4] == L'I' &&
					tmp[UniStrLen(tmp) - 3] == L'6' &&
					tmp[UniStrLen(tmp) - 2] == L'4') ||
					(
					UniStrLen(tmp) >= 4 && tmp[UniStrLen(tmp) - 3] == L'l' &&
					tmp[UniStrLen(tmp) - 2] == L'l'))
				{
					#ifdef	OS_WIN32
						_snprintf(dst, sizeof(dst), tag, va_arg(args, UINT64));
					#else	// OS_WIN32
						snprintf(dst, sizeof(dst), tag, va_arg(args, UINT64));
					#endif	// OS_WIN32
				}
				else
				{
					#ifdef	OS_WIN32
						_snprintf(dst, sizeof(dst), tag, va_arg(args, int));
					#else	// OS_WIN32
						snprintf(dst, sizeof(dst), tag, va_arg(args, int));
					#endif	// OS_WIN32
				}

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'e':
			case L'E':
			case L'f':
			case L'g':
			case L'G':
				// double 型
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = CopyUniToStr(tmp);

				#ifdef	OS_WIN32
					_snprintf(dst, sizeof(dst), tag, va_arg(args, double));
				#else	// OS_WIN32
					snprintf(dst, sizeof(dst), tag, va_arg(args, double));
				#endif	// OS_WIN32

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'n':
			case L'p':
				// ポインタ型
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = ZeroMalloc(UniStrSize(tmp) + 32);
				UniToStr(tag, 0, tmp);

				#ifdef	OS_WIN32
					_snprintf(dst, sizeof(dst), tag, va_arg(args, void *));
				#else	// OS_WIN32
					snprintf(dst, sizeof(dst), tag, va_arg(args, void *));
				#endif	// OS_WIN32

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L's':
			case L'S':
				// 文字列型
				tmp[wp++] = c;
				tmp[wp++] = 0;

				if (ansi_mode == false)
				{
					if (c == L'S')
					{
						c = L's';
					}
					else
					{
						c = L'S';
					}
				}

				if (c == L's')
				{
					target_str = CopyStrToUni(va_arg(args, char *));
				}
				else
				{
					target_str = CopyUniStr(va_arg(args, wchar_t *));
				}

				if (target_str == NULL)
				{
					target_str = CopyUniStr(L"(null)");
				}

				padding = 0;
				left_padding = false;
				if (tmp[1] == L'-')
				{
					// 左詰め
					if (UniStrLen(tmp) >= 3)
					{
						padding = UniToInt(&tmp[2]);
					}
					left_padding = true;
				}
				else
				{
					// 右詰め
					if (UniStrLen(tmp) >= 2)
					{
						padding = UniToInt(&tmp[1]);
					}
				}

				target_str_len = UniStrWidth(target_str);

				if (padding > target_str_len)
				{
					UINT len = padding - target_str_len;
					UINT i;
					padding_str = ZeroMalloc(sizeof(wchar_t) * (len + 1));
					for (i = 0;i < len;i++)
					{
						padding_str[i] = L' ';
					}
				}
				else
				{
					padding_str = ZeroMalloc(sizeof(wchar_t));
				}

				total_len = sizeof(wchar_t) * (UniStrLen(padding_str) + UniStrLen(target_str) + 1);
				output_str = ZeroMalloc(total_len);
				output_str[0] = 0;

				if (left_padding == false)
				{
					UniStrCat(output_str, total_len, padding_str);
				}
				UniStrCat(output_str, total_len, target_str);
				if (left_padding)
				{
					UniStrCat(output_str, total_len, padding_str);
				}

				Add(o, output_str);

				Free(target_str);
				Free(padding_str);

				wp = 0;
				mode = 0;
				break;
			default:
				// 通常の文字列
				tmp[wp++] = c;
				break;
			}
		}
	}
	tmp[wp++] = 0;
	wp = 0;

	if (UniStrLen(tmp) >= 1)
	{
		Add(o, CopyUniStr(tmp));
	}

	total_size = sizeof(wchar_t);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		total_size += UniStrLen(s) * sizeof(wchar_t);
	}

	ret = ZeroMalloc(total_size);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		UniStrCat(ret, total_size, s);
		Free(s);
	}

	ReleaseList(o);

	Free(tmp);

	return ret;
}

// 文字列の横幅サイズを取得する
UINT UniStrWidth(wchar_t *str)
{
	UINT i, len, ret;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	ret = 0;
	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] <= 255)
		{
			ret++;
		}
		else
		{
			ret += 2;
		}
	}
	return ret;
}

// Unicode 文字列をダンプ表示する
void DumpUniStr(wchar_t *str)
{
	UINT i, len;
	char *s;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	s = CopyUniToStr(str);

	Print("DumpUniStr: %s\n  ", s);

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		Print("0x%04X ", str[i]);
	}
	Print("\n");

	Free(s);
}

// 文字列をダンプ表示する
void DumpStr(char *str)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	Print("DumpStr: %s\n  ", str);

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		Print("0x%02X ", str[i]);
	}
	Print("\n");
}

// 1 文字 2 バイトの文字列を 1 文字 4 場合の wchar_t に変換する
wchar_t *Utf16ToWide(USHORT *str)
{
	wchar_t *ret;
	UINT len, i;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = 0;
	while (true)
	{
		if (str[len] == 0)
		{
			break;
		}
		len++;
	}

	ret = Malloc((len + 1) * sizeof(wchar_t));
	for (i = 0;i < len + 1;i++)
	{
		ret[i] = (wchar_t)str[i];
	}

	return ret;
}

// 1 文字 4 バイトの wchar_t 文字列を 1 文字 2 バイトに変換する
USHORT *WideToUtf16(wchar_t *str)
{
	USHORT *ret;
	UINT len;
	UINT ret_size;
	UINT i;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);

	ret_size = (len + 1) * 2;
	ret = Malloc(ret_size);

	for (i = 0;i < len + 1;i++)
	{
		ret[i] = (USHORT)str[i];
	}

	return ret;
}

// 国際ライブラリの初期化
void InitInternational()
{
#ifdef	OS_UNIX
	void *d;

	if (iconv_lock != NULL)
	{
		return;
	}

	GetCurrentCharSet(charset, sizeof(charset));
	d = IconvWideToStrInternal();
	if (d == (void *)-1)
	{
#ifdef	UNIX_MACOS
		StrCpy(charset, sizeof(charset), "utf8");
#else	// UNIX_MACOS
		StrCpy(charset, sizeof(charset), "EUCJP");
#endif	// UNIX_MACOS
		d = IconvWideToStrInternal();
		if (d == (void *)-1)
		{
			StrCpy(charset, sizeof(charset), "US");
		}
		else
		{
			IconvFreeInternal(d);
		}
	}
	else
	{
		IconvFreeInternal(d);
	}

	iconv_lock = NewLockMain();

	iconv_cache_wide_to_str = IconvWideToStrInternal();
	iconv_cache_str_to_wide = IconvStrToWideInternal();
#endif	// OS_UNIX
}

// 国際ライブラリの解放
void FreeInternational()
{
#ifdef	OS_UNIX
#endif	// OS_UNIX
}

#ifdef	OS_UNIX

// 文字列を Unicode に変換した場合のサイズを計算する
UINT UnixCalcStrToUni(char *str)
{
	wchar_t *tmp;
	UINT len, tmp_size;
	UINT ret;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	len = StrLen(str);
	tmp_size = len * 5 + 10;
	tmp = ZeroMalloc(tmp_size);
	UnixStrToUni(tmp, tmp_size, str);
	ret = UniStrLen(tmp);
	Free(tmp);

	return (ret + 1) * sizeof(wchar_t);
}

// 文字列を Unicode に変換する
UINT UnixStrToUni(wchar_t *s, UINT size, char *str)
{
	void *d;
	char *inbuf;
	size_t insize;
	char *outbuf;
	char *outbuf_orig;
	size_t outsize;
	wchar_t *tmp;
	// 引数チェック
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	d = IconvStrToWide();
	if (d == (void *)-1)
	{
		UniStrCpy(s, size, L"");
		return 0;
	}

	inbuf = (char *)str;
	insize = StrLen(str) + 1;
	outsize = insize * 5 + 10;
	outbuf_orig = outbuf = ZeroMalloc(outsize);

	if (iconv((iconv_t)d, (char **)&inbuf, (size_t *)&insize, (char **)&outbuf, (size_t *)&outsize) == (size_t)(-1))
	{
		Free(outbuf_orig);
		UniStrCpy(s, size, L"");
		IconvFree(d);
		return 0;
	}

	tmp = Utf16ToWide((USHORT *)outbuf_orig);
	Free(outbuf_orig);

	UniStrCpy(s, size, tmp);
	IconvFree(d);

	Free(tmp);

	return UniStrLen(s);
}

// Unicode を文字列にした場合のサイズを計算する
UINT UnixCalcUniToStr(wchar_t *s)
{
	char *tmp;
	UINT tmp_size;
	UINT ret;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	tmp_size = UniStrLen(s) * 5 + 10;
	tmp = ZeroMalloc(tmp_size);
	UnixUniToStr(tmp, tmp_size, s);

	ret = StrSize(tmp);
	Free(tmp);

	return ret;
}

// Unicode を文字列に変換する
UINT UnixUniToStr(char *str, UINT size, wchar_t *s)
{
	USHORT *tmp;
	char *inbuf;
	size_t insize;
	char *outbuf;
	char *outbuf_orig;
	size_t outsize;
	void *d;
	// 引数チェック
	if (str == NULL || s == NULL)
	{
		return 0;
	}

	// まず wchar_t 文字列を 2 バイトの並びに変換する
	tmp = WideToUtf16(s);
	inbuf = (char *)tmp;
	insize = (UniStrLen(s) + 1) * 2;
	outsize = insize * 5 + 10;
	outbuf_orig = outbuf = ZeroMalloc(outsize);

	d = IconvWideToStr();
	if (d == (void *)-1)
	{
		StrCpy(str, size, "");
		Free(outbuf);
		Free(tmp);
		return 0;
	}

	if (iconv((iconv_t)d, (char **)&inbuf, (size_t *)&insize, (char **)&outbuf, (size_t *)&outsize) == (size_t)(-1))
	{
		Free(outbuf_orig);
		IconvFree(d);
		StrCpy(str, size, "");
		Free(tmp);
		return 0;
	}

	StrCpy(str, size, outbuf_orig);

	Free(outbuf_orig);
	IconvFree(d);
	Free(tmp);

	return StrLen(str);
}

// whcar_t を char に変換する
void *IconvWideToStrInternal()
{
	return (void *)iconv_open(charset, IsBigEndian() ? "UTF-16BE" : "UTF-16LE");
}

// char を wchar_t に変換する
void *IconvStrToWideInternal()
{
	return (void *)iconv_open(IsBigEndian() ? "UTF-16BE" : "UTF-16LE", charset);
}

// ハンドルを閉じる
int IconvFreeInternal(void *d)
{
	iconv_close((iconv_t)d);
	return 0;
}

void *IconvWideToStr()
{
	if (iconv_cache_wide_to_str == (void *)-1)
	{
		return (void *)-1;
	}

	Lock(iconv_lock);

	return iconv_cache_wide_to_str;
}

void *IconvStrToWide()
{
	if (iconv_cache_str_to_wide == (void *)-1)
	{
		return (void *)-1;
	}

	Lock(iconv_lock);

	return iconv_cache_str_to_wide;
}

int IconvFree(void *d)
{
	Unlock(iconv_lock);

	return 0;
}

// 現在使用されている文字セットを環境変数から取得する
void GetCurrentCharSet(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	if (GetEnv("LANG", tmp, sizeof(tmp)) == false)
	{
		if (GetEnv("LOCATION", tmp, sizeof(tmp)) == false)
		{
			StrCpy(tmp, sizeof(tmp), "ja_JP.eucJP");
		}
	}

	Trim(tmp);

	t = ParseToken(tmp, ".");
	if (t->NumTokens >= 2)
	{
		StrCpy(name, size, t->Token[1]);
	}
	else
	{
		if (t->NumTokens == 1)
		{
			StrCpy(name, size, t->Token[0]);
		}
		else
		{
			StrCpy(name, size, "eucJP");
		}
	}
	FreeToken(t);

	StrUpper(name);
}

#endif	// OS_UNIX

// 指定された文字列が空白かどうかチェック
bool UniIsEmptyStr(wchar_t *str)
{
	return IsEmptyUniStr(str);
}
bool IsEmptyUniStr(wchar_t *str)
{
	bool ret;
	wchar_t *s;
	// 引数チェック
	if (str == NULL)
	{
		return true;
	}

	s = UniCopyStr(str);

	UniTrim(s);
	if (UniStrLen(s) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(s);

	return ret;
}

// 指定された文字列が数字かどうかチェック
bool UniIsNum(wchar_t *str)
{
	char tmp[MAX_SIZE];

	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	return IsNum(tmp);
}


// 中身が無い Unicode トークンリスト
UNI_TOKEN_LIST *UniNullToken()
{
	UNI_TOKEN_LIST *ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

// 中身が無い Unicode トークンリスト (別名)
UNI_TOKEN_LIST *NullUniToken()
{
	return UniNullToken();
}

// トークンリストを Unicode トークンリストに変換する
UNI_TOKEN_LIST *TokenListToUniTokenList(TOKEN_LIST *src)
{
	UNI_TOKEN_LIST *ret;
	UINT i;
	// 引数チェック
	if (src == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->NumTokens = src->NumTokens;
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);

	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyStrToUni(src->Token[i]);
	}

	return ret;
}

// Unicode トークンリストをトークンリストに変換する
TOKEN_LIST *UniTokenListToTokenList(UNI_TOKEN_LIST *src)
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
		ret->Token[i] = CopyUniToStr(src->Token[i]);
	}

	return ret;
}

// Unicode 文字列コピー
wchar_t *UniCopyStr(wchar_t *str)
{
	return CopyUniStr(str);
}

// トークンリストのコピー
UNI_TOKEN_LIST *UniCopyToken(UNI_TOKEN_LIST *src)
{
	UNI_TOKEN_LIST *ret;
	UINT i;
	// 引数チェック
	if (src == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = src->NumTokens;
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyUniStr(src->Token[i]);
	}

	return ret;
}

// コマンドライン文字列をパースする
UNI_TOKEN_LIST *UniParseCmdLine(wchar_t *str)
{
	UNI_TOKEN_LIST *t;
	LIST *o;
	UINT i, len, wp, mode;
	wchar_t c;
	wchar_t *tmp;
	bool ignore_space = false;
	// 引数チェック
	if (str == NULL)
	{
		// トークン無し
		return UniNullToken();
	}

	o = NewListFast(NULL);
	tmp = Malloc(UniStrSize(str) + 32);

	wp = 0;
	mode = 0;

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		c = str[i];

		switch (mode)
		{
		case 0:
			// 次のトークンを発見するモード
			if (c == L' ' || c == L'\t')
			{
				// 次の文字へ進める
			}
			else
			{
				// トークンの開始
				if (c == L'\"')
				{
					if (str[i + 1] == L'\"')
					{
						// 2 重の " は 1 個の " 文字として見なす
						tmp[wp++] = L'\"';
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
			if (ignore_space == false && (c == L' ' || c == L'\t'))
			{
				// トークンの終了
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, UniCopyStr(tmp));
				mode = 0;
			}
			else
			{
				if (c == L'\"')
				{
					if (str[i + 1] == L'\"')
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
		Insert(o, UniCopyStr(tmp));
	}

	Free(tmp);

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return t;
}

// Unicode 文字列を 64bit 整数に変換する
UINT64 UniToInt64(wchar_t *str)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	UniToStr(tmp, sizeof(tmp), str);

	return ToInt64(tmp);
}

// 64bit 整数を Unicode 文字列に変換する
void UniToStr64(wchar_t *str, UINT64 value)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	ToStr64(tmp, value);

	StrToUni(str, 0, tmp);
}

// ANSI を UTF に変換する
UINT StrToUtf(char *utfstr, UINT size, char *str)
{
	char *tmp;
	// 引数チェック
	if (utfstr == NULL || str == NULL)
	{
		StrCpy(utfstr, size, "");
		return 0;
	}

	tmp = CopyStrToUtf(str);

	StrCpy(utfstr, size, tmp);

	Free(tmp);

	return StrLen(utfstr);
}

// UTF を ANSI に変換する
UINT UtfToStr(char *str, UINT size, char *utfstr)
{
	char *tmp;
	// 引数チェック
	if (str == NULL || utfstr == NULL)
	{
		StrCpy(str, size, "");
		return 0;
	}

	tmp = CopyUtfToStr(utfstr);

	StrCpy(str, size, tmp);

	Free(tmp);

	return StrLen(str);
}

// Unicode を UTF に変換する
UINT UniToUtf(char *utfstr, UINT size, wchar_t *unistr)
{
	char *tmp;
	// 引数チェック
	if (utfstr == NULL || unistr == NULL)
	{
		StrCpy(utfstr, size, "");
		return 0;
	}

	tmp = CopyUniToStr(unistr);

	StrCpy(utfstr, size, tmp);

	Free(tmp);

	return StrLen(utfstr);
}

// UTF を Unicode に変換する
UINT UtfToUni(wchar_t *unistr, UINT size, char *utfstr)
{
	wchar_t *tmp;
	// 引数チェック
	if (unistr == NULL || utfstr == NULL)
	{
		UniStrCpy(unistr, size, L"");
		return 0;
	}

	tmp = CopyUtfToUni(utfstr);

	UniStrCpy(unistr, size, tmp);

	Free(tmp);

	return UniStrLen(unistr);
}

// UTF8 文字列を Unicode 文字列にコピーする
wchar_t *CopyUtfToUni(char *utfstr)
{
	UINT size;
	wchar_t *ret;
	UINT utfstr_len;
	// 引数チェック
	if (utfstr == NULL)
	{
		return NULL;
	}

	utfstr_len = StrLen(utfstr);

	size = CalcUtf8ToUni((BYTE *)utfstr, utfstr_len);
	ret = ZeroMalloc(size + sizeof(wchar_t));
	Utf8ToUni(ret, size, (BYTE *)utfstr, utfstr_len);

	return ret;
}

// UTF8 文字列を ANSI 文字列にコピーする
char *CopyUtfToStr(char *utfstr)
{
	wchar_t *uni;
	char *ret;
	// 引数チェック
	if (utfstr == NULL)
	{
		return NULL;
	}

	uni = CopyUtfToUni(utfstr);
	if (uni == NULL)
	{
		return CopyStr("");
	}

	ret = CopyUniToStr(uni);

	Free(uni);

	return ret;
}

// Unicode 文字列を ANSI 文字列にコピーする
char *CopyUniToStr(wchar_t *unistr)
{
	char *str;
	UINT str_size;
	// 引数チェック
	if (unistr == NULL)
	{
		return NULL;
	}

	str_size = CalcUniToStr(unistr);
	if (str_size == 0)
	{
		return CopyStr("");
	}
	str = Malloc(str_size);
	UniToStr(str, str_size, unistr);

	return str;
}

// ANSI 文字列を Unicode 文字列にコピーする
wchar_t *CopyStrToUni(char *str)
{
	wchar_t *uni;
	UINT uni_size;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	uni_size = CalcStrToUni(str);
	if (uni_size == 0)
	{
		return CopyUniStr(L"");
	}
	uni = Malloc(uni_size);
	StrToUni(uni, uni_size, str);

	return uni;
}

// Unicode 文字列を UTF8 文字列にコピーする
char *CopyUniToUtf(wchar_t *unistr)
{
	UINT size;
	char *ret;
	// 引数チェック
	if (unistr == NULL)
	{
		return NULL;
	}

	size = CalcUniToUtf8(unistr);
	ret = ZeroMalloc(size + sizeof(char));

	UniToUtf8((char *)ret, size, unistr);

	return ret;
}

// ANSI 文字列を UTF8 文字列にコピーする
char *CopyStrToUtf(char *str)
{
	wchar_t *unistr;
	char *ret;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	unistr = CopyStrToUni(str);
	if (unistr == NULL)
	{
		return CopyStr("");
	}

	ret = CopyUniToUtf(unistr);

	Free(unistr);

	return ret;
}

// Unicode 文字列をコピーする
wchar_t *CopyUniStr(wchar_t *str)
{
	UINT len;
	wchar_t *dst;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);
	dst = Malloc((len + 1) * sizeof(wchar_t));
	UniStrCpy(dst, 0, str);

	return dst;
}

// 安全な文字列かどうかチェック
bool IsSafeUniStr(wchar_t *str)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (IsSafeUniChar(str[i]) == false)
		{
			return false;
		}
	}
	if (str[0] == L' ')
	{
		return false;
	}
	if (len != 0)
	{
		if (str[len - 1] == L' ')
		{
			return false;
		}
	}
	return true;
}

// 安全な文字かどうかチェック
bool IsSafeUniChar(wchar_t c)
{
	UINT i, len;
	wchar_t *check_str =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz"
		L"0123456789"
		L" ()-_#%&.";

	len = UniStrLen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return true;
		}
	}
	return false;
}

// UTF-8 文字列を ANSI 文字列に変換する
UINT Utf8ToStr(char *str, UINT str_size, BYTE *u, UINT size)
{
	UINT ret, uni_size;
	wchar_t *tmp;
	// 引数チェック
	if (u == NULL || str == NULL)
	{
		return 0;
	}

	// Unicode に変換する
	uni_size = CalcUtf8ToUni(u, size);
	if (uni_size == 0)
	{
		if (str_size >= 1)
		{
			StrCpy(str, 0, "");
			return 0;
		}
	}
	tmp = Malloc(uni_size);
	Utf8ToUni(tmp, uni_size, u, size);

	// ANSI に変換する
	ret = UniToStr(str, str_size, tmp);
	Free(tmp);

	return ret;
}

// UTF-8 文字列を ANSI 文字列に変換した場合に必要なサイズを取得する
UINT CalcUtf8ToStr(BYTE *u, UINT size)
{
	UINT ret, uni_size;
	wchar_t *tmp;
	// 引数チェック
	if (u == NULL)
	{
		return 0;
	}

	// Unicode に変換する
	uni_size = CalcUtf8ToUni(u, size);
	if (uni_size == 0)
	{
		return 0;
	}
	tmp = Malloc(uni_size);
	Utf8ToUni(tmp, uni_size, u, size);

	// ANSI に変換する
	ret = CalcUniToStr(tmp);
	Free(tmp);

	return ret;
}

// ANSI 文字列を UTF-8 文字列に変換する
UINT StrToUtf8(BYTE *u, UINT size, char *str)
{
	UINT ret, uni_size;
	wchar_t *tmp;
	// 引数チェック
	if (u == NULL || str == NULL)
	{
		return 0;
	}

	// Unicode に変換する
	uni_size = CalcStrToUni(str);
	if (uni_size == 0)
	{
		return 0;
	}
	tmp = Malloc(uni_size);
	StrToUni(tmp, uni_size, str);

	// UTF-8 に変換する
	ret = UniToUtf8(u, size, tmp);

	Free(tmp);

	return ret;
}

// ANSI 文字列を UTF-8 文字列に変換するために必要なサイズを取得する
UINT CalcStrToUtf8(char *str)
{
	UINT ret;
	UINT uni_size;
	wchar_t *tmp;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	// Unicode に変換する
	uni_size = CalcStrToUni(str);
	if (uni_size == 0)
	{
		return 0;
	}
	tmp = Malloc(uni_size);
	StrToUni(tmp, uni_size, str);

	// UTF-8 に変換した場合のサイズを取得する
	ret = CalcUniToUtf8(tmp);
	Free(tmp);

	return ret;
}

// Unicode 文字列を ANSI 文字列に変換する
UINT UniToStr(char *str, UINT size, wchar_t *s)
{
#ifdef	OS_WIN32
	UINT ret;
	char *tmp;
	UINT new_size;
	// 引数チェック
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = CalcUniToStr(s);
	if (new_size == 0)
	{
		if (size >= 1)
		{
			StrCpy(str, 0, "");
		}
		return 0;
	}
	tmp = Malloc(new_size);
	tmp[0] = 0;
	wcstombs(tmp, s, new_size);
	tmp[new_size - 1] = 0;
	ret = StrCpy(str, size, tmp);
	Free(tmp);

	return ret;
#else	// OS_WIN32
	return UnixUniToStr(str, size, s);
#endif	// OS_WIN32
}

// Unicode 文字列を ANSI 文字列に変換するための必要なバイト数を取得する
UINT CalcUniToStr(wchar_t *s)
{
#ifdef	OS_WIN32
	UINT ret;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	ret = (UINT)wcstombs(NULL, s, UniStrLen(s));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return ret + 1;
#else	// OS_WIN32
	return UnixCalcUniToStr(s);
#endif	// OS_WIN32
}

// ANSI 文字列を Unicode 文字列に変換する
UINT StrToUni(wchar_t *s, UINT size, char *str)
{
#ifdef	OS_WIN32
	UINT ret;
	wchar_t *tmp;
	UINT new_size;
	// 引数チェック
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = CalcStrToUni(str);
	if (new_size == 0)
	{
		if (size >= 2)
		{
			UniStrCpy(s, 0, L"");
		}
		return 0;
	}
	tmp = Malloc(new_size);
	tmp[0] = 0;
	mbstowcs(tmp, str, StrLen(str));
	tmp[(new_size - 1) / sizeof(wchar_t)] = 0;
	ret = UniStrCpy(s, size, tmp);
	Free(tmp);

	return ret;
#else	// OS_WIN32
	return UnixStrToUni(s, size, str);
#endif	// OS_WIN32
}

// ANSI 文字列を Unicode 文字列に変換するための必要なバイト数を取得する
UINT CalcStrToUni(char *str)
{
#ifdef	OS_WIN32
	UINT ret;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	ret = (UINT)mbstowcs(NULL, str, StrLen(str));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return (ret + 1) * sizeof(wchar_t);
#else	// OS_WIN32
	return UnixCalcStrToUni(str);
#endif	// OS_WIN32
}

// UTF-8 文字列を Unicode 文字列に変換する
UINT Utf8ToUni(wchar_t *s, UINT size, BYTE *u, UINT u_size)
{
	UINT i, wp, num;
	// 引数チェック
	if (s == NULL || u == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}
	if (u_size == 0)
	{
		u_size = StrLen((char *)u);
	}

	i = 0;
	wp = 0;
	num = 0;
	while (true)
	{
		UINT type;
		wchar_t c;
		BYTE c1, c2;

		type = GetUtf8Type(u, u_size, i);
		if (type == 0)
		{
			break;
		}
		switch (type)
		{
		case 1:
			c1 = 0;
			c2 = u[i];
			break;
		case 2:
			c1 = (((u[i] & 0x1c) >> 2) & 0x07);
			c2 = (((u[i] & 0x03) << 6) & 0xc0) | (u[i + 1] & 0x3f);
			break;
		case 3:
			c1 = ((((u[i] & 0x0f) << 4) & 0xf0)) | (((u[i + 1] & 0x3c) >> 2) & 0x0f);
			c2 = (((u[i + 1] & 0x03) << 6) & 0xc0) | (u[i + 2] & 0x3f);
			break;
		}
		i += type;

		c = 0;

		if (IsBigEndian())
		{
			if (sizeof(wchar_t) == 2)
			{
				((BYTE *)&c)[0] = c1;
				((BYTE *)&c)[1] = c2;
			}
			else
			{
				((BYTE *)&c)[2] = c1;
				((BYTE *)&c)[3] = c2;
			}
		}
		else
		{
			((BYTE *)&c)[0] = c2;
			((BYTE *)&c)[1] = c1;
		}

		if (wp < ((size / sizeof(wchar_t)) - 1))
		{
			s[wp++] = c;
			num++;
		}
		else
		{
			break;
		}
	}

	if (wp < (size / sizeof(wchar_t)))
	{
		s[wp++] = 0;
	}

	return num;
}

// UTF-8 を Unicode に変換した場合のバッファサイズを取得する
UINT CalcUtf8ToUni(BYTE *u, UINT u_size)
{
	// 引数チェック
	if (u == NULL)
	{
		return 0;
	}
	if (u_size == 0)
	{
		u_size = StrLen((char *)u);
	}

	return (Utf8Len(u, u_size) + 1) * sizeof(wchar_t);
}

// UTF-8 文字列の文字数を取得する
UINT Utf8Len(BYTE *u, UINT size)
{
	UINT i, num;
	// 引数チェック
	if (u == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = StrLen((char *)u);
	}

	i = num = 0;
	while (true)
	{
		UINT type;

		type = GetUtf8Type(u, size, i);
		if (type == 0)
		{
			break;
		}
		i += type;
		num++;
	}

	return num;
}

// Unicode 文字列を UTF-8 文字列に変換する
UINT UniToUtf8(BYTE *u, UINT size, wchar_t *s)
{
	UINT i, len, type, wp;
	// 引数チェック
	if (u == NULL || s == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}

	len = UniStrLen(s);
	wp = 0;
	for (i = 0;i < len;i++)
	{
		BYTE c1, c2;
		wchar_t c = s[i];

		if (IsBigEndian())
		{
			if (sizeof(wchar_t) == 2)
			{
				c1 = ((BYTE *)&c)[0];
				c2 = ((BYTE *)&c)[1];
			}
			else
			{
				c1 = ((BYTE *)&c)[2];
				c2 = ((BYTE *)&c)[3];
			}
		}
		else
		{
			c1 = ((BYTE *)&c)[1];
			c2 = ((BYTE *)&c)[0];
		}

		type = GetUniType(s[i]);
		switch (type)
		{
		case 1:
			if (wp < size)
			{
				u[wp++] = c2;
			}
			break;
		case 2:
			if (wp < size)
			{
				u[wp++] = 0xc0 | (((((c1 & 0x07) << 2) & 0x1c)) | (((c2 & 0xc0) >> 6) & 0x03));
			}
			if (wp < size)
			{
				u[wp++] = 0x80 | (c2 & 0x3f);
			}
			break;
		case 3:
			if (wp < size)
			{
				u[wp++] = 0xe0 | (((c1 & 0xf0) >> 4) & 0x0f);
			}
			if (wp < size)
			{
				u[wp++] = 0x80 | (((c1 & 0x0f) << 2) & 0x3c) | (((c2 & 0xc0) >> 6) & 0x03);
			}
			if (wp < size)
			{
				u[wp++] = 0x80 | (c2 & 0x3f);
			}
			break;
		}
	}
	if (wp < size)
	{
		u[wp] = 0;
	}
	return wp;
}

// Unicode 文字列を UTF-8 文字列に変換した場合の文字列長を計算する
UINT CalcUniToUtf8(wchar_t *s)
{
	UINT i, len, size;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	size = 0;
	len = UniStrLen(s);
	for (i = 0;i < len;i++)
	{
		size += GetUniType(s[i]);
	}

	return size;
}

// s で始まる UTF-8 文字列の offset 番地の最初の 1 文字が何バイトで構成されているかを取得
UINT GetUtf8Type(BYTE *s, UINT size, UINT offset)
{
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}
	if ((offset + 1) > size)
	{
		return 0;
	}
	if ((s[offset] & 0x80) == 0)
	{
		// 1 バイト
		return 1;
	}
	if ((s[offset] & 0x20) == 0)
	{
		// 2 バイト
		if ((offset + 2) > size)
		{
			return 0;
		}
		return 2;
	}
	// 3 バイト
	if ((offset + 3) > size)
	{
		return 0;
	}
	return 3;
}

// 文字 c を UTF-8 に変換した場合の種類 (バイト数)
UINT GetUniType(wchar_t c)
{
	BYTE c1, c2;

	if (IsBigEndian())
	{
		if (sizeof(wchar_t) == 2)
		{
			c1 = ((BYTE *)&c)[0];
			c2 = ((BYTE *)&c)[1];
		}
		else
		{
			c1 = ((BYTE *)&c)[2];
			c2 = ((BYTE *)&c)[3];
		}
	}
	else
	{
		c1 = ((BYTE *)&c)[1];
		c2 = ((BYTE *)&c)[0];
	}

	if (c1 == 0)
	{
		if (c2 <= 0x7f)
		{
			// 1 バイト
			return 1;
		}
		else
		{
			// 2 バイト
			return 2;
		}
	}
	if ((c1 & 0xf8) == 0)
	{
		// 2 バイト
		return 2;
	}
	// 3 バイト
	return 3;
}

// 文字列の置換 (大文字小文字を区別しない)
UINT UniReplaceStri(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword)
{
	return UniReplaceStrEx(dst, size, string, old_keyword, new_keyword, false);
}

// 文字列の置換 (大文字小文字を区別する)
UINT UniReplaceStr(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword)
{
	return UniReplaceStrEx(dst, size, string, old_keyword, new_keyword, true);
}

// 文字列の置換
UINT UniReplaceStrEx(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive)
{
	UINT i, j, num, len_string, len_old, len_new, len_ret, wp;
	wchar_t *ret;
	// 引数チェック
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// 文字列長の取得
	len_string = UniStrLen(string);
	len_old = UniStrLen(old_keyword);
	len_new = UniStrLen(new_keyword);

	// 最終文字列長の取得
	len_ret = UniCalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	// メモリ確保
	ret = Malloc((len_ret + 1) * sizeof(wchar_t));
	ret[len_ret] = 0;

	// 検索と置換
	i = j = num = wp = 0;
	while (true)
	{
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			Copy(&ret[wp], &string[j], (len_string - j) * sizeof(wchar_t));
			wp += len_string - j;
			break;
		}
		num++;
		Copy(&ret[wp], &string[j], (i - j) * sizeof(wchar_t));
		wp += i - j;
		Copy(&ret[wp], new_keyword, len_new * sizeof(wchar_t));
		wp += len_new;
		i += len_old;
		j = i;
	}

	// 検索結果のコピー
	UniStrCpy(dst, size, ret);

	// メモリ解放
	Free(ret);

	return num;
}

// 文字列の置換後の文字列長を計算する
UINT UniCalcReplaceStrEx(wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive)
{
	UINT i, num;
	UINT len_string, len_old, len_new;
	// 引数チェック
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// 文字列長の取得
	len_string = UniStrLen(string);
	len_old = UniStrLen(old_keyword);
	len_new = UniStrLen(new_keyword);

	if (len_old == len_new)
	{
		return len_string;
	}

	// 検索処理
	num = 0;
	i = 0;
	while (true)
	{
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
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
UINT UniSearchStr(wchar_t *string, wchar_t *keyword, UINT start)
{
	return UniSearchStrEx(string, keyword, start, true);
}

// 文字列の検索 (大文字 / 小文字を区別しない)
UINT UniSearchStri(wchar_t *string, wchar_t *keyword, UINT start)
{
	return UniSearchStrEx(string, keyword, start, false);
}

// 文字列 string から文字列 keyword を検索して最初に見つかった文字の場所を返す
// (1文字目に見つかったら 0, 見つからなかったら INFINITE)
UINT UniSearchStrEx(wchar_t *string, wchar_t *keyword, UINT start, bool case_sensitive)
{
	UINT len_string, len_keyword;
	UINT i;
	wchar_t *cmp_string, *cmp_keyword;
	bool found;
	// 引数チェック
	if (string == NULL || keyword == NULL)
	{
		return INFINITE;
	}

	// string の長さを取得
	len_string = UniStrLen(string);
	if (len_string <= start)
	{
		// start の値が不正
		return INFINITE;
	}

	// keyword の長さを取得
	len_keyword = UniStrLen(keyword);
	if (len_keyword == 0)
	{
		// キーワードが無い
		return INFINITE;
	}

	if (len_string < len_keyword)
	{
		return INFINITE;
	}

	if (len_string == len_keyword)
	{
		if (case_sensitive)
		{
			if (UniStrCmp(string, keyword) == 0)
			{
				return 0;
			}
			else
			{
				return INFINITE;
			}
		}
		else
		{
			if (UniStrCmpi(string, keyword) == 0)
			{
				return 0;
			}
			else
			{
				return INFINITE;
			}
		}
	}

	if (case_sensitive)
	{
		cmp_string = string;
		cmp_keyword = keyword;
	}
	else
	{
		cmp_string = Malloc((len_string + 1) * sizeof(wchar_t));
		UniStrCpy(cmp_string, (len_string + 1) * sizeof(wchar_t), string);
		cmp_keyword = Malloc((len_keyword + 1) * sizeof(wchar_t));
		UniStrCpy(cmp_keyword, (len_keyword + 1) * sizeof(wchar_t), keyword);
		UniStrUpper(cmp_string);
		UniStrUpper(cmp_keyword);
	}

	// 検索
	found = false;
	for (i = start;i < (len_string - len_keyword + 1);i++)
	{
		// 比較する
		if (!wcsncmp(&cmp_string[i], cmp_keyword, len_keyword))
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

// トークンリストの解放
void UniFreeToken(UNI_TOKEN_LIST *tokens)
{
	UINT i;
	if (tokens == NULL)
	{
		return;
	}
	for (i = 0;i < tokens->NumTokens;i++)
	{
		Free(tokens->Token[i]);
	}
	Free(tokens->Token);
	Free(tokens);
}

// UNIX 版トークンのパース
UNI_TOKEN_LIST *UnixUniParseToken(wchar_t *src, wchar_t *separator)
{
	UNI_TOKEN_LIST *ret;
	TOKEN_LIST *t;
	char *src_s;
	char *sep_s;

	// 引数チェック
	if (src == NULL || separator == NULL)
	{
		ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
		ret->Token = ZeroMalloc(0);
		return ret;
	}

	src_s = CopyUniToStr(src);
	sep_s = CopyUniToStr(separator);

	t = ParseToken(src_s, sep_s);

	ret = TokenListToUniTokenList(t);
	FreeToken(t);

	Free(src_s);
	Free(sep_s);

	return ret;
}

// トークンのパース
UNI_TOKEN_LIST *UniParseToken(wchar_t *src, wchar_t *separator)
{
#ifdef	OS_WIN32
	UNI_TOKEN_LIST *ret;
	wchar_t *tmp;
	wchar_t *str1, *str2;
	UINT len, num;

#ifdef	OS_UNIX
	wchar_t *state = NULL;
#endif	// OS_UNIX

	// 引数チェック
	if (src == NULL)
	{
		ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
		ret->Token = ZeroMalloc(0);
		return ret;
	}
	if (separator == NULL)
	{
		separator = L" .\t\r\n";
	}
	len = UniStrLen(src);
	str1 = Malloc((len + 1) * sizeof(wchar_t));
	str2 = Malloc((len + 1) * sizeof(wchar_t));
	UniStrCpy(str1, 0, src);
	UniStrCpy(str2, 0, src);

	Lock(token_lock);
	{
		tmp = wcstok(str1, separator
#ifdef	OS_UNIX
			, &state
#endif	// OS_UNIX
			);
		num = 0;
		while (tmp != NULL)
		{
			num++;
			tmp = wcstok(NULL, separator
#ifdef	OS_UNIX
				, &state
#endif	// OS_UNIX
				);
		}
		ret = Malloc(sizeof(UNI_TOKEN_LIST));
		ret->NumTokens = num;
		ret->Token = (wchar_t **)Malloc(sizeof(wchar_t *) * num);
		num = 0;
		tmp = wcstok(str2, separator
#ifdef	OS_UNIX
			, &state
#endif	// OS_UNIX
			);
		while (tmp != NULL)
		{
			ret->Token[num] = (wchar_t *)Malloc((UniStrLen(tmp) + 1) * sizeof(wchar_t));
			UniStrCpy(ret->Token[num], 0, tmp);
			num++;
			tmp = wcstok(NULL, separator
#ifdef	OS_UNIX
				, &state
#endif	// OS_UNIX
				);
		}
	}
	Unlock(token_lock);

	Free(str1);
	Free(str2);
	return ret;
#else	// OS_WIN32
	return UnixUniParseToken(src, separator);
#endif	// OS_WIN32
}

// 1 行を標準入力から取得
bool UniGetLine(wchar_t *str, UINT size)
{
#ifdef	OS_WIN32
	return UniGetLineWin32(str, size);
#else	// OS_WIN32
	return UniGetLineUnix(str, size);
#endif	// OS_WIN32
}
void AnsiGetLineUnix(char *str, UINT size)
{
	// 引数チェック
	if (str == NULL)
	{
		char tmp[MAX_SIZE];
		fgets(tmp, sizeof(tmp) - 1, stdin);
		return;
	}
	if (size <= 1)
	{
		return;
	}

	// 標準入力からデータを読み込み
	fgets(str, (int)(size - 1), stdin);

	TrimCrlf(str);
}
bool UniGetLineUnix(wchar_t *str, UINT size)
{
	char *str_a;
	UINT str_a_size = size;
	if (str == NULL || size < sizeof(wchar_t))
	{
		return false;
	}
	if (str_a_size >= 0x7fffffff)
	{
		str_a_size = MAX_SIZE;
	}
	str_a_size *= 2;

	str_a = ZeroMalloc(str_a_size);

	AnsiGetLineUnix(str_a, str_a_size);

	StrToUni(str, size, str_a);

	Free(str_a);

	return true;
}
bool UniGetLineWin32(wchar_t *str, UINT size)
{
	bool ret = false;

#ifdef	OS_WIN32
	ret = Win32InputW(str, size);
#endif	// OS_WIN32

	return ret;
}

// 末尾の \r \n を削除
void UniTrimCrlf(wchar_t *str)
{
	UINT len;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}

	if (str[len - 1] == L'\n')
	{
		if (len >= 2 && str[len - 2] == L'\r')
		{
			str[len - 2] = 0;
		}
		str[len - 1] = 0;
	}
	else if(str[len - 1] == L'\r')
	{
		str[len - 1] = 0;
	}
}

// 文字列の左右の空白を削除
void UniTrim(wchar_t *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	UniTrimLeft(str);
	UniTrimRight(str);
}

// 文字列の右側の空白を削除
void UniTrimRight(wchar_t *str)
{
	wchar_t *buf, *tmp;
	UINT len, i, wp, wp2;
	bool flag;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[len - 1] != L' ' && str[len - 1] != L'\t')
	{
		return;
	}

	buf = Malloc((len + 1) * sizeof(wchar_t));
	tmp = Malloc((len + 1) * sizeof(wchar_t));
	flag = false;
	wp = wp2 = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != L' ' && str[i] != L'\t')
		{
			Copy(&buf[wp], tmp, wp2 * sizeof(wchar_t));
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
	UniStrCpy(str, 0, buf);
	Free(buf);
	Free(tmp);
}

// 文字列の左側の空白を削除
void UniTrimLeft(wchar_t *str)
{
	wchar_t *buf;
	UINT len, i, wp;
	bool flag;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[0] != L' ' && str[0] != L'\t')
	{
		return;
	}

	buf = Malloc((len + 1) * sizeof(wchar_t));
	flag = false;
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != L' ' && str[i] != L'\t')
		{
			flag = true;
		}
		if (flag)
		{
			buf[wp++] = str[i];
		}
	}
	buf[wp] = 0;
	UniStrCpy(str, 0, buf);
	Free(buf);
}

// 整数を 16 進文字列に変換 (8桁固定)
void UniToStrx8(wchar_t *str, UINT i)
{
	UniFormat(str, 0, L"0x%08x", i);
}

// 整数を 16 進文字列に変換
void UniToStrx(wchar_t *str, UINT i)
{
	UniFormat(str, 0, L"0x%02x", i);
}

// 符号付整数を文字列に変換
void UniToStri(wchar_t *str, int i)
{
	UniFormat(str, 0, L"%i", i);
}

// 整数を文字列に変換
void UniToStru(wchar_t *str, UINT i)
{
	UniFormat(str, 0, L"%u", i);
}

// 文字列を符号付整数に変換
int UniToInti(wchar_t *str)
{
	char tmp[128];
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	UniToStr(tmp, sizeof(tmp), str);

	return ToInt(tmp);
}

// 文字列を整数に変換
UINT UniToInt(wchar_t *str)
{
	char tmp[128];
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	UniToStr(tmp, sizeof(tmp), str);

	return ToInti(tmp);
}

// 64bit 用フォーマット文字列置換
wchar_t *UniReplaceFormatStringFor64(wchar_t *fmt)
{
	wchar_t *tmp;
	wchar_t *ret;
	UINT tmp_size;
	// 引数チェック
	if (fmt == NULL)
	{
		return NULL;
	}

	tmp_size = UniStrSize(fmt) * 2;
	tmp = ZeroMalloc(tmp_size);

#ifdef	OS_WIN32
	UniReplaceStrEx(tmp, tmp_size, fmt, L"%ll", L"%I64", false);
#else	// OS_WIN32
	UniReplaceStrEx(tmp, tmp_size, fmt, L"%I64", L"%ll", false);

	if (1)
	{
		UINT i, len;
		bool f = false;
		len = UniStrLen(tmp);
		for (i = 0;i < len;i++)
		{
			if (tmp[i] == L'%')
			{
				f = true;
			}

			if (f)
			{
				switch (tmp[i])
				{
				case L'c':
				case L'C':
				case L'd':
				case L'i':
				case L'o':
				case L'u':
				case L'x':
				case L'X':
				case L'e':
				case L'E':
				case L'f':
				case L'g':
				case L'G':
				case L'n':
				case L'p':
				case L's':
				case L'S':
					if (tmp[i] == L's')
					{
						tmp[i] = L'S';
					}
					else if (tmp[i] == L'S')
					{
						tmp[i] = L's';
					}
					f = false;
					break;
				}
			}
		}
	}

#endif	// OS_WIN32

	ret = CopyUniStr(tmp);
	Free(tmp);

	return ret;
}

// 文字列を画面に表示する
void UniPrintStr(wchar_t *string)
{
	// 引数チェック
	if (string == NULL)
	{
		return;
	}

#ifdef	OS_UNIX
	if (true)
	{
		char *str = CopyUniToStr(string);

		if (str != NULL)
		{
			fputs(str, stdout);
		}
		else
		{
			fputs("", stdout);
		}

		Free(str);
	}
#else	// OS_UNIX
	Win32PrintW(string);
#endif	// OS_UNIX
}

// 文字列を引数付きで表示する
void UniPrintArgs(wchar_t *fmt, va_list args)
{
	wchar_t *str;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	str = InternalFormatArgs(fmt, args, false);

	UniPrintStr(str);

	Free(str);
}

// 文字列を表示する
void UniPrint(wchar_t *fmt, ...)
{
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniPrintArgs(fmt, args);
	va_end(args);
}

// デバッグ文字列を引数付きで表示する
void UniDebugArgs(wchar_t *fmt, va_list args)
{
	if (g_debug == false)
	{
		return;
	}

	UniPrintArgs(fmt, args);
}

// デバッグ文字列を表示する
void UniDebug(wchar_t *fmt, ...)
{
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniDebugArgs(fmt, args);
	va_end(args);
}

// 文字列をフォーマットする (引数リスト)
void UniFormatArgs(wchar_t *buf, UINT size, wchar_t *fmt, va_list args)
{
	wchar_t *ret;
	// 引数チェック
	if (buf == NULL || fmt == NULL)
	{
		return;
	}
	if (size == 1)
	{
		return;
	}

	// KS
	KS_INC(KS_FORMAT_COUNT);

	ret = InternalFormatArgs(fmt, args, false);

	UniStrCpy(buf, size, ret);

	Free(ret);
}

// 文字列をフォーマットして結果をコピーする
wchar_t *CopyUniFormat(wchar_t *fmt, ...)
{
	wchar_t *ret, *str;
	UINT size;
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return NULL;
	}

	size = MAX(UniStrSize(fmt) * 10, MAX_SIZE * 10);
	str = Malloc(size);

	va_start(args, fmt);
	UniFormatArgs(str, size, fmt, args);

	ret = UniCopyStr(str);
	Free(str);
	va_end(args);

	return ret;
}

// 文字列をフォーマットする
void UniFormat(wchar_t *buf, UINT size, wchar_t *fmt, ...)
{
	va_list args;
	// 引数チェック
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniFormatArgs(buf, size, fmt, args);
	va_end(args);
}

// 柔軟な文字列比較
int UniSoftStrCmp(wchar_t *str1, wchar_t *str2)
{
	UINT ret;
	wchar_t *tmp1, *tmp2;
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

	tmp1 = CopyUniStr(str1);
	tmp2 = CopyUniStr(str2);

	UniTrim(tmp1);
	UniTrim(tmp2);

	ret = UniStrCmpi(tmp1, tmp2);

	Free(tmp1);
	Free(tmp2);

	return ret;
}

// 文字列を大文字・小文字を区別せずに比較する
int UniStrCmpi(wchar_t *str1, wchar_t *str2)
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
		wchar_t c1, c2;
		c1 = UniToUpper(str1[i]);
		c2 = UniToUpper(str2[i]);
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
int UniStrCmp(wchar_t *str1, wchar_t *str2)
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

	return wcscmp(str1, str2);
}

// 文字列を小文字にする
void UniStrLower(wchar_t *str)
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
		str[i] = UniToLower(str[i]);
	}
}

// 文字列を大文字にする
void UniStrUpper(wchar_t *str)
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
		str[i] = UniToUpper(str[i]);
	}
}

// 文字を小文字にする
wchar_t UniToLower(wchar_t c)
{
	if (c >= L'A' && c <= L'Z')
	{
		c += L'a' - L'A';
	}

	return c;
}

// 文字を大文字にする
wchar_t UniToUpper(wchar_t c)
{
	if (c >= L'a' && c <= L'z')
	{
		c -= L'a' - L'A';
	}

	return c;
}

// 文字列結合
UINT UniStrCat(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len1, len2, len_test;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return 0;
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		// 長さ無視
		size = 0x3fffffff;
	}

	len1 = UniStrLen(dst);
	len2 = UniStrLen(src);
	len_test = len1 + len2 + 1;
	if (len_test > (size / sizeof(wchar_t)))
	{
		if (len2 <= (len_test - (size / sizeof(wchar_t))))
		{
			return 0;
		}
		len2 -= len_test - (size / sizeof(wchar_t));
	}
	Copy(&dst[len1], src, len2 * sizeof(wchar_t));
	dst[len1 + len2] = 0;

	return len1 + len2;
}
UINT UniStrCatLeft(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t *s;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	s = UniCopyStr(dst);
	UniStrCpy(dst, size, s);
	UniStrCat(dst, size, src);
	Free(s);

	return UniStrLen(dst);
}

// 文字列コピー
UINT UniStrCpy(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= sizeof(wchar_t))
			{
				dst[0] = L'\0';
			}
		}
		return 0;
	}
	if (dst == src)
	{
		return UniStrLen(src);
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		// 長さ無視
		size = 0x3fffffff;
	}

	// 長さをチェック
	len = UniStrLen(src);
	if (len <= (size / sizeof(wchar_t) - 1))
	{
		Copy(dst, src, (len + 1) * sizeof(wchar_t));
	}
	else
	{
		len = size / 2 - 1;
		Copy(dst, src, len * sizeof(wchar_t));
		dst[len] = 0;
	}

	return len;
}

// 文字が指定されたバッファサイズ以内かどうかチェック
bool UniCheckStrSize(wchar_t *str, UINT size)
{
	// 引数チェック
	if (str == NULL || size <= 1)
	{
		return false;
	}

	return UniCheckStrLen(str, size / sizeof(wchar_t) - 1);
}

// 文字数が指定された長さ以内かどうかチェック
bool UniCheckStrLen(wchar_t *str, UINT len)
{
	UINT count = 0;
	UINT i;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	for (i = 0;;i++)
	{
		if (str[i] == 0)
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

// 文字列の格納に必要なバッファサイズの取得
UINT UniStrSize(wchar_t *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	return (UniStrLen(str) + 1) * sizeof(wchar_t);
}

// 文字列の長さの取得
UINT UniStrLen(wchar_t *str)
{
	UINT i;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	i = 0;
	while (true)
	{
		if (str[i] == 0)
		{
			break;
		}
		i++;
	}

	return i;
}

