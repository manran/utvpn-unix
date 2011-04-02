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

// Table.c
// 文字列テーブル読み込み & 管理ルーチン

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// TABLE のリスト
static LIST *TableList = NULL;
static wchar_t old_table_name[MAX_SIZE] = {0};		// 古いテーブル名

// エラー文字列を Unicode で取得する
wchar_t *GetUniErrorStr(UINT err)
{
	wchar_t *ret;
	char name[MAX_SIZE];
	Format(name, sizeof(name), "ERR_%u", err);

	ret = GetTableUniStr(name);
	if (UniStrLen(ret) != 0)
	{
		return ret;
	}
	else
	{
		return _UU("ERR_UNKNOWN");
	}
}

// エラー文字列を取得する
char *GetErrorStr(UINT err)
{
	char *ret;
	char name[MAX_SIZE];
	Format(name, sizeof(name), "ERR_%u", err);

	ret = GetTableStr(name);
	if (StrLen(ret) != 0)
	{
		return ret;
	}
	else
	{
		return _SS("ERR_UNKNOWN");
	}
}

// テーブルから整数値をロードする
UINT GetTableInt(char *name)
{
	char *str;
	// 引数チェック
	if (name == NULL)
	{
		return 0;
	}

	str = GetTableStr(name);
	return ToInt(str);
}

// テーブルから Unicode 文字列をロードする
wchar_t *GetTableUniStr(char *name)
{
	TABLE *t;
	// 引数チェック
	if (name == NULL)
	{
//		Debug("%s: ************\n", name);
		return L"";
	}

	// 検索
	t = FindTable(name);
	if (t == NULL)
	{
//		Debug("%s: UNICODE STRING NOT FOUND\n", name);
		return L"";
	}

	return t->unistr;
}

// テーブルから文字列をロードする
char *GetTableStr(char *name)
{
	TABLE *t;
	// 引数チェック
	if (name == NULL)
	{
		return "";
	}

#ifdef	OS_WIN32
	if (StrCmpi(name, "DEFAULT_FONT") == 0)
	{
		if (_II("LANG") == 2)
		{
			UINT os_type = GetOsType();
			if (OS_IS_WINDOWS_9X(os_type) ||
				GET_KETA(os_type, 100) <= 4)
			{
				// Windows 9x, Windows NT 4.0, Windows 2000, Windows XP, Windows Server 2003 の場合は SimSun フォントを利用する
				return "SimSun";
			}
		}
	}
#endif	// OS_WIN32

	// 検索
	t = FindTable(name);
	if (t == NULL)
	{
//		Debug("%s: ANSI STRING NOT FOUND\n", name);
		return "";
	}

	return t->str;
}

// 指定した名前で始まる文字列名を取得する
TOKEN_LIST *GetTableNameStartWith(char *str)
{
	UINT i;
	UINT len;
	LIST *o;
	TOKEN_LIST *t;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL)
	{
		return NullToken();
	}

	StrCpy(tmp, sizeof(tmp), str);
	StrUpper(tmp);

	len = StrLen(tmp);

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(TableList);i++)
	{
		TABLE *t = LIST_DATA(TableList, i);
		UINT len2 = StrLen(t->name);

		if (len2 >= len)
		{
			if (Cmp(t->name, tmp, len) == 0)
			{
				Insert(o, CopyStr(t->name));
			}
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

	return t;
}

// テーブルを検索する
TABLE *FindTable(char *name)
{
	TABLE *t, tt;
	// 引数チェック
	if (name == NULL || TableList == NULL)
	{
		return NULL;
	}

	tt.name = CopyStr(name);
	t = Search(TableList, &tt);
	Free(tt.name);

	return t;
}

// テーブル名を比較する関数
int CmpTableName(void *p1, void *p2)
{
	TABLE *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(TABLE **)p1;
	t2 = *(TABLE **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	return StrCmpi(t1->name, t2->name);
}

// 1 行を解釈する
TABLE *ParseTableLine(char *line, char *prefix, UINT prefix_size)
{
	UINT i, len;
	UINT len_name;
	UINT string_start;
	char *name;
	char *name2;
	UINT name2_size;
	wchar_t *unistr;
	char *str;
	UINT unistr_size, str_size;
	TABLE *t;
	// 引数チェック
	if (line == NULL || prefix == NULL)
	{
		return NULL;
	}
	TrimLeft(line);

	// 行無し
	len = StrLen(line);
	if (len == 0)
	{
		return NULL;
	}

	// コメント
	if (line[0] == '#' || (line[0] == '/' && line[1] == '/'))
	{
		return NULL;
	}

	// 名前の終了位置まで検索
	len_name = 0;
	for (i = 0;;i++)
	{
		if (line[i] == 0)
		{
			// トークンが 1 つしか無い
			return NULL;
		}
		if (line[i] == ' ' || line[i] == '\t')
		{
			break;
		}
		len_name++;
	}

	name = Malloc(len_name + 1);
	StrCpy(name, len_name + 1, line);

	string_start = len_name;
	for (i = len_name;i < len;i++)
	{
		if (line[i] != ' ' && line[i] != '\t')
		{
			break;
		}
		string_start++;
	}
	if (i == len)
	{
		Free(name);
		return NULL;
	}

	// アンエスケープ
	UnescapeStr(&line[string_start]);

	// Unicode に変換する
	unistr_size = CalcUtf8ToUni(&line[string_start], StrLen(&line[string_start]));
	if (unistr_size == 0)
	{
		Free(name);
		return NULL;
	}
	unistr = Malloc(unistr_size);
	Utf8ToUni(unistr, unistr_size, &line[string_start], StrLen(&line[string_start]));

	// ANSI に変換する
	str_size = CalcUniToStr(unistr);
	if (str_size == 0)
	{
		str_size = 1;
		str = Malloc(1);
		str[0] = 0;
	}
	else
	{
		str = Malloc(str_size);
		UniToStr(str, str_size, unistr);
	}

	if (StrCmpi(name, "PREFIX") == 0)
	{
		// プレフィックスが指定された
		StrCpy(prefix, prefix_size, str);
		Trim(prefix);

		if (StrCmpi(prefix, "$") == 0 || StrCmpi(prefix, "NULL") == 0)
		{
			prefix[0] = 0;
		}

		Free(name);
		Free(str);
		Free(unistr);

		return NULL;
	}

	name2_size = StrLen(name) + StrLen(prefix) + 2;
	name2 = ZeroMalloc(name2_size);

	if (prefix[0] != 0)
	{
		StrCat(name2, name2_size, prefix);
		StrCat(name2, name2_size, "@");
	}

	StrCat(name2, name2_size, name);

	Free(name);

	// TABLE を作成する
	t = Malloc(sizeof(TABLE));
	StrUpper(name2);
	t->name = name2;
	t->str = str;
	t->unistr = unistr;

	return t;
}

// 文字列のアンエスケープ
void UnescapeStr(char *src)
{
	UINT i, len, wp;
	char *tmp;
	// 引数チェック
	if (src == NULL)
	{
		return;
	}
	
	len = StrLen(src);
	tmp = Malloc(len + 1);
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (src[i] == '\\')
		{
			i++;
			switch (src[i])
			{
			case 0:
				goto FINISH;
			case '\\':
				tmp[wp++] = '\\';
				break;
			case ' ':
				tmp[wp++] = ' ';
				break;
			case 'n':
			case 'N':
				tmp[wp++] = '\n';
				break;
			case 'r':
			case 'R':
				tmp[wp++] = '\r';
				break;
			case 't':
			case 'T':
				tmp[wp++] = '\t';
				break;
			}
		}
		else
		{
			tmp[wp++] = src[i];
		}
	}
FINISH:
	tmp[wp++] = 0;
	StrCpy(src, 0, tmp);
	Free(tmp);
}

// テーブルを解放する
void FreeTable()
{
	UINT i, num;
	TABLE **tables;
	if (TableList == NULL)
	{
		return;
	}

	TrackingDisable();

	num = LIST_NUM(TableList);
	tables = ToArray(TableList);
	for (i = 0;i < num;i++)
	{
		TABLE *t = tables[i];
		Free(t->name);
		Free(t->str);
		Free(t->unistr);
		Free(t);
	}
	ReleaseList(TableList);
	TableList = NULL;
	Free(tables);

	Zero(old_table_name, sizeof(old_table_name));

	TrackingEnable();
}

// バッファから文字列テーブルを読み込む
bool LoadTableFromBuf(BUF *b)
{
	char *tmp;
	char prefix[MAX_SIZE];
	// 引数チェック
	if (b == NULL)
	{
		return false;
	}

	// すでにテーブルがある場合は削除する
	FreeTable();

	// リストを作成する
	TableList = NewList(CmpTableName);

	Zero(prefix, sizeof(prefix));

	// バッファの内容を 1 行ずつ読んでいく
	while (true)
	{
		TABLE *t;
		tmp = CfgReadNextLine(b);
		if (tmp == NULL)
		{
			break;
		}
		t = ParseTableLine(tmp, prefix, sizeof(prefix));
		if (t != NULL)
		{
			// 登録する
			Insert(TableList, t);
		}
		Free(tmp);
	}

	return true;
}

// Unicode 文字列キャッシュファイル名の生成
void GenerateUnicodeCacheFileName(wchar_t *name, UINT size, wchar_t *strfilename, UINT strfilesize, UCHAR *filehash)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t hashstr[64];
	wchar_t hashtemp[MAX_SIZE];
	wchar_t exe[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (name == NULL || strfilename == NULL || filehash == NULL)
	{
		return;
	}

	GetExeDirW(exe, sizeof(exe));
	UniStrCpy(hashtemp, sizeof(hashtemp), strfilename);
	BinToStrW(tmp, sizeof(tmp), filehash, MD5_SIZE);
	UniStrCat(hashtemp, sizeof(hashtemp), tmp);
	UniStrCat(hashtemp, sizeof(hashtemp), exe);
	UniStrLower(hashtemp);

	Hash(hash, hashtemp, UniStrLen(hashtemp) * sizeof(wchar_t), true);
	BinToStrW(hashstr, sizeof(hashstr), hash, 4);
	UniFormat(tmp, sizeof(tmp), UNICODE_CACHE_FILE, hashstr);
	UniStrLower(tmp);

#ifndef	OS_WIN32
	UniStrCpy(exe, sizeof(exe), L"/tmp");
#else	// OS_WIN32
	StrToUni(exe, sizeof(exe), MsGetTempDir());
#endif	// OS_WIN32

	UniFormat(name, size, L"%s/%s", exe, tmp);
	NormalizePathW(name, size, name);
}

// Unicode キャッシュの保存
void SaveUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash)
{
	UNICODE_CACHE c;
	BUF *b;
	UINT i;
	IO *io;
	wchar_t name[MAX_PATH];
	UCHAR binhash[MD5_SIZE];
	// 引数チェック
	if (strfilename == NULL || hash == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));
	UniToStr(c.StrFileName, sizeof(c.StrFileName), strfilename);
	c.StrFileSize = strfilesize;
	GetMachineName(c.MachineName, sizeof(c.MachineName));
	c.OsType = GetOsInfo()->OsType;
	Copy(c.hash, hash, MD5_SIZE);

#ifdef	OS_UNIX
	GetCurrentCharSet(c.CharSet, sizeof(c.CharSet));
#else	// OS_UNIX
	{
		UINT id = MsGetThreadLocale();
		Copy(c.CharSet, &id, sizeof(id));
	}
#endif	// OS_UNIX

	b = NewBuf();
	WriteBuf(b, &c, sizeof(c));

	WriteBufInt(b, LIST_NUM(TableList));
	for (i = 0;i < LIST_NUM(TableList);i++)
	{
		TABLE *t = LIST_DATA(TableList, i);
		WriteBufInt(b, StrLen(t->name));
		WriteBuf(b, t->name, StrLen(t->name));
		WriteBufInt(b, StrLen(t->str));
		WriteBuf(b, t->str, StrLen(t->str));
		WriteBufInt(b, UniStrLen(t->unistr));
		WriteBuf(b, t->unistr, UniStrLen(t->unistr) * sizeof(wchar_t));
	}

	Hash(binhash, b->Buf, b->Size, false);
	WriteBuf(b, binhash, MD5_SIZE);

	GenerateUnicodeCacheFileName(name, sizeof(name), strfilename, strfilesize, hash);

	io = FileCreateW(name);
	if (io != NULL)
	{
		SeekBuf(b, 0, 0);
		BufToFile(io, b);
		FileClose(io);
	}

	FreeBuf(b);
}

// Unicode キャッシュの読み込み
bool LoadUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash)
{
	UNICODE_CACHE c, t;
	BUF *b;
	UINT i, num;
	IO *io;
	wchar_t name[MAX_PATH];
	UCHAR binhash[MD5_SIZE];
	UCHAR binhash_2[MD5_SIZE];
	// 引数チェック
	if (strfilename == NULL || hash == NULL)
	{
		return false;
	}

	GenerateUnicodeCacheFileName(name, sizeof(name), strfilename, strfilesize, hash);

	io = FileOpenW(name, false);
	if (io == NULL)
	{
		return false;
	}

	b = FileToBuf(io);
	if (b == NULL)
	{
		FileClose(io);
		return false;
	}

	SeekBuf(b, 0, 0);
	FileClose(io);

	Hash(binhash, b->Buf, b->Size >= MD5_SIZE ? (b->Size - MD5_SIZE) : 0, false);
	Copy(binhash_2, ((UCHAR *)b->Buf) + (b->Size >= MD5_SIZE ? (b->Size - MD5_SIZE) : 0), MD5_SIZE);
	if (Cmp(binhash, binhash_2, MD5_SIZE) != 0)
	{
		FreeBuf(b);
		return false;
	}

	Zero(&c, sizeof(c));
	UniToStr(c.StrFileName, sizeof(c.StrFileName), strfilename);
	c.StrFileSize = strfilesize;
	DisableNetworkNameCache();
	GetMachineName(c.MachineName, sizeof(c.MachineName));
	EnableNetworkNameCache();
	c.OsType = GetOsInfo()->OsType;
	Copy(c.hash, hash, MD5_SIZE);

#ifdef	OS_UNIX
	GetCurrentCharSet(c.CharSet, sizeof(c.CharSet));
#else	// OS_UNIX
	{
		UINT id = MsGetThreadLocale();
		Copy(c.CharSet, &id, sizeof(id));
	}
#endif	// OS_UNIX

	Zero(&t, sizeof(t));
	ReadBuf(b, &t, sizeof(t));

	if (Cmp(&c, &t, sizeof(UNICODE_CACHE)) != 0)
	{
		FreeBuf(b);
		return false;
	}

	num = ReadBufInt(b);

	FreeTable();
	TableList = NewList(CmpTableName);

	for (i = 0;i < num;i++)
	{
		UINT len;
		TABLE *t = ZeroMalloc(sizeof(TABLE));

		len = ReadBufInt(b);
		t->name = ZeroMalloc(len + 1);
		ReadBuf(b, t->name, len);

		len = ReadBufInt(b);
		t->str = ZeroMalloc(len + 1);
		ReadBuf(b, t->str, len);

		len = ReadBufInt(b);
		t->unistr = ZeroMalloc((len + 1) * sizeof(wchar_t));
		ReadBuf(b, t->unistr, len * sizeof(wchar_t));

		Add(TableList, t);
	}

	FreeBuf(b);

	Sort(TableList);

	return true;
}

// 文字列テーブルを読み込む
bool LoadTableMain(wchar_t *filename)
{
	BUF *b;
	UINT64 t1, t2;
	UCHAR hash[MD5_SIZE];
	// 引数チェック
	if (filename == NULL)
	{
		return false;
	}

	if (MayaquaIsMinimalMode())
	{
		return true;
	}

	if (UniStrCmpi(old_table_name, filename) == 0)
	{
		// すでに読み込まれている
		return true;
	}

	t1 = Tick64();

	// ファイルを開く
	b = ReadDumpW(filename);
	if (b == NULL)
	{
		char tmp[MAX_SIZE];
		StrCpy(tmp, sizeof(tmp), "Error: Can't read string tables (file not found).\r\nPlease check hamcore.utvpn.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)");
		Alert(tmp, NULL);
		exit(0);
		return false;
	}

	Hash(hash, b->Buf, b->Size, false);

	if (LoadUnicodeCache(filename, b->Size, hash) == false)
	{
		if (LoadTableFromBuf(b) == false)
		{
			FreeBuf(b);
			return false;
		}

		SaveUnicodeCache(filename, b->Size, hash);

		Debug("Unicode Source: strtable.stb\n");
	}
	else
	{
		Debug("Unicode Source: unicode_cache\n");
	}

	FreeBuf(b);

	SetLocale(_UU("DEFAULE_LOCALE"));

	UniStrCpy(old_table_name, sizeof(old_table_name), filename);

	t2 = Tick64();

	if (StrCmpi(_SS("STRTABLE_ID"), STRTABLE_ID) != 0)
	{
		char tmp[MAX_SIZE];
		StrCpy(tmp, sizeof(tmp), "Error: Can't read string tables (invalid version).\r\nPlease check hamcore.utvpn.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)");
		Alert(tmp, NULL);
		exit(0);
		return false;
	}

	Debug("Unicode File Read Cost: %u (%u Lines)\n", (UINT)(t2 - t1), LIST_NUM(TableList));

	return true;
}
bool LoadTable(char *filename)
{
	wchar_t *filename_a = CopyStrToUni(filename);
	bool ret = LoadTableW(filename_a);

	Free(filename_a);

	return ret;
}
bool LoadTableW(wchar_t *filename)
{
	bool ret;
	BUF *b;
	wchar_t replace_name[MAX_PATH];

	Zero(replace_name, sizeof(replace_name));

	TrackingDisable();

	b = ReadDump("@table_name.txt");
	if (b != NULL)
	{
		char *s = CfgReadNextLine(b);
		if (s != NULL)
		{
			if (IsEmptyStr(s) == false)
			{
				StrToUni(replace_name, sizeof(replace_name), s);
				filename = replace_name;
			}

			Free(s);
		}
		FreeBuf(b);
	}

	ret = LoadTableMain(filename);

	TrackingEnable();

	return ret;
}


