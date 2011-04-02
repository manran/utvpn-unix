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

// Internat.h
// Internat.c のヘッダ

#ifndef	INTERNAT_H
#define	INTERNAT_H

// 文字列トークン
struct UNI_TOKEN_LIST
{
	UINT NumTokens;
	wchar_t **Token;
};

UINT UniStrLen(wchar_t *str);
UINT UniStrSize(wchar_t *str);
UINT UniStrCpy(wchar_t *dst, UINT size, wchar_t *src);
bool UniCheckStrSize(wchar_t *str, UINT size);
bool UniCheckStrLen(wchar_t *str, UINT len);
UINT UniStrCat(wchar_t *dst, UINT size, wchar_t *src);
UINT UniStrCatLeft(wchar_t *dst, UINT size, wchar_t *src);
wchar_t UniToLower(wchar_t c);
wchar_t UniToUpper(wchar_t c);
void UniStrLower(wchar_t *str);
void UniStrUpper(wchar_t *str);
int UniStrCmp(wchar_t *str1, wchar_t *str2);
int UniStrCmpi(wchar_t *str1, wchar_t *str2);
int UniSoftStrCmp(wchar_t *str1, wchar_t *str2);
void UniFormat(wchar_t *buf, UINT size, wchar_t *fmt, ...);
wchar_t *CopyUniFormat(wchar_t *fmt, ...);
void UniFormatArgs(wchar_t *buf, UINT size, wchar_t *fmt, va_list args);
void UniDebugArgs(wchar_t *fmt, va_list args);
void UniDebug(wchar_t *fmt, ...);
void UniPrint(wchar_t *fmt, ...);
void UniPrintArgs(wchar_t *fmt, va_list args);
void UniPrintStr(wchar_t *string);
void UniToStrx8(wchar_t *str, UINT i);
void UniToStrx(wchar_t *str, UINT i);
void UniToStri(wchar_t *str, int i);
void UniToStru(wchar_t *str, UINT i);
int UniToInti(wchar_t *str);
UINT UniToInt(wchar_t *str);
void UniTrim(wchar_t *str);
void UniTrimLeft(wchar_t *str);
void UniTrimRight(wchar_t *str);
void UniTrimCrlf(wchar_t *str);
bool UniGetLine(wchar_t *str, UINT size);
bool UniGetLineWin32(wchar_t *str, UINT size);
bool UniGetLineUnix(wchar_t *str, UINT size);
void UniFreeToken(UNI_TOKEN_LIST *tokens);
UNI_TOKEN_LIST *UniParseToken(wchar_t *src, wchar_t *separator);
UINT UniSearchStrEx(wchar_t *string, wchar_t *keyword, UINT start, bool case_sensitive);
UINT UniSearchStri(wchar_t *string, wchar_t *keyword, UINT start);
UINT UniSearchStr(wchar_t *string, wchar_t *keyword, UINT start);
UINT UniCalcReplaceStrEx(wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStrEx(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStri(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword);
UINT UniReplaceStr(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword);
UINT GetUniType(wchar_t c);
UINT GetUtf8Type(BYTE *s, UINT size, UINT offset);
UINT CalcUniToUtf8(wchar_t *s);
UINT UniToUtf8(BYTE *u, UINT size, wchar_t *s);
UINT Utf8Len(BYTE *u, UINT size);
UINT CalcUtf8ToUni(BYTE *u, UINT u_size);
UINT Utf8ToUni(wchar_t *s, UINT size, BYTE *u, UINT u_size);
UINT CalcStrToUni(char *str);
UINT StrToUni(wchar_t *s, UINT size, char *str);
UINT CalcUniToStr(wchar_t *s);
UINT UniToStr(char *str, UINT size, wchar_t *s);
UINT CalcStrToUtf8(char *str);
UINT StrToUtf8(BYTE *u, UINT size, char *str);
UINT CalcUtf8ToStr(BYTE *u, UINT size);
UINT Utf8ToStr(char *str, UINT str_size, BYTE *u, UINT size);
bool IsSafeUniStr(wchar_t *str);
bool IsSafeUniChar(wchar_t c);
wchar_t *CopyUniStr(wchar_t *str);
wchar_t *CopyStrToUni(char *str);
UINT StrToUtf(char *utfstr, UINT size, char *str);
UINT UtfToStr(char *str, UINT size, char *utfstr);
UINT UniToUtf(char *utfstr, UINT size, wchar_t *unistr);
UINT UtfToUni(wchar_t *unistr, UINT size, char *utfstr);
char *CopyUniToUtf(wchar_t *unistr);
char *CopyStrToUtf(char *str);
char *CopyUniToStr(wchar_t *unistr);
wchar_t *CopyUtfToUni(char *utfstr);
char *CopyUtfToStr(char *utfstr);
wchar_t *UniReplaceFormatStringFor64(wchar_t *fmt);
void UniToStr64(wchar_t *str, UINT64 value);
UINT64 UniToInt64(wchar_t *str);
UNI_TOKEN_LIST *UniParseCmdLine(wchar_t *str);
UNI_TOKEN_LIST *UniCopyToken(UNI_TOKEN_LIST *src);
wchar_t *UniCopyStr(wchar_t *str);
TOKEN_LIST *UniTokenListToTokenList(UNI_TOKEN_LIST *src);
UNI_TOKEN_LIST *TokenListToUniTokenList(TOKEN_LIST *src);
UNI_TOKEN_LIST *UniNullToken();
UNI_TOKEN_LIST *NullUniToken();
bool UniIsNum(wchar_t *str);
bool IsEmptyUniStr(wchar_t *str);
bool UniIsEmptyStr(wchar_t *str);
void InitInternational();
void FreeInternational();
USHORT *WideToUtf16(wchar_t *str);
wchar_t *Utf16ToWide(USHORT *str);
void DumpUniStr(wchar_t *str);
void DumpStr(char *str);
wchar_t *InternalFormatArgs(wchar_t *fmt, va_list args, bool ansi_mode);
UINT UniStrWidth(wchar_t *str);
UNI_TOKEN_LIST *UnixUniParseToken(wchar_t *src, wchar_t *separator);
void UniToStr3(wchar_t *str, UINT size, UINT64 value);
bool UniEndWith(wchar_t *str, wchar_t *key);
bool UniStartWith(wchar_t *str, wchar_t *key);
wchar_t *UniNormalizeCrlf(wchar_t *str);
LIST *UniStrToStrList(wchar_t *str, UINT size);
BUF *UniStrListToStr(LIST *o);
void UniFreeStrList(LIST *o);
UNI_TOKEN_LIST *UniListToTokenList(LIST *o);
LIST *UniTokenListToList(UNI_TOKEN_LIST *t);
bool UniIsSafeChar(wchar_t c);
wchar_t *UniMakeCharArray(wchar_t c, UINT count);
BUF *UniStrToBin(wchar_t *str);
bool UniInStr(wchar_t *str, wchar_t *keyword);
bool UniInStrEx(wchar_t *str, wchar_t *keyword, bool case_sensitive);

#ifdef	OS_UNIX
void GetCurrentCharSet(char *name, UINT size);
UINT UnixCalcStrToUni(char *str);
UINT UnixStrToUni(wchar_t *s, UINT size, char *str);
UINT UnixCalcUniToStr(wchar_t *s);
UINT UnixUniToStr(char *str, UINT size, wchar_t *s);
void *IconvWideToStr();
void *IconvStrToWide();
int IconvFree(void *d);
void *IconvWideToStrInternal();
void *IconvStrToWideInternal();
int IconvFreeInternal(void *d);
#endif	// OS_UNIX

#endif	// INTERNAT_H



