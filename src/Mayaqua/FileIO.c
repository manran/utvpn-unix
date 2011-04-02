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

// FileIO.c
// ファイル入出力コード

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

static char exe_file_name[MAX_SIZE] = "/tmp/a.out";
static wchar_t exe_file_name_w[MAX_SIZE] = L"/tmp/a.out";
static LIST *hamcore = NULL;
static IO *hamcore_io = NULL;


// ファイルを保存する
bool SaveFileW(wchar_t *name, void *data, UINT size)
{
	IO *io;
	// 引数チェック
	if (name == NULL || (data == NULL && size != 0))
	{
		return false;
	}

	io = FileCreateW(name);
	if (io == NULL)
	{
		return false;
	}

	if (FileWrite(io, data, size) == false)
	{
		FileClose(io);
		return false;
	}

	FileClose(io);

	return true;
}
bool SaveFile(char *name, void *data, UINT size)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = SaveFileW(name_w, data, size);

	Free(name_w);

	return ret;
}

// ファイルが存在するかどうか確認する
bool IsFile(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileW(wchar_t *name)
{
	IO *io;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	io = FileOpenExW(name, false, false);
	if (io == NULL)
	{
		return false;
	}

	FileClose(io);

	return true;
}

// ファイルを置換してリネームする
bool FileReplaceRename(char *old_name, char *new_name)
{
	wchar_t *old_name_w = CopyStrToUni(old_name);
	wchar_t *new_name_w = CopyStrToUni(new_name);
	bool ret = FileReplaceRenameW(old_name_w, new_name_w);

	Free(old_name_w);
	Free(new_name_w);

	return ret;
}
bool FileReplaceRenameW(wchar_t *old_name, wchar_t *new_name)
{
	// 引数チェック
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	if (FileCopyW(old_name, new_name) == false)
	{
		return false;
	}

	FileDeleteW(old_name);

	return true;
}

// ファイル名を安全な名前にする
void ConvertSafeFileName(char *dst, UINT size, char *src)
{
	UINT i;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(dst, size, src);
	for (i = 0;i < StrLen(dst);i++)
	{
		if (IsSafeChar(dst[i]) == false)
		{
			dst[i] = '_';
		}
	}
}
void ConvertSafeFileNameW(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT i;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	UniStrCpy(dst, size, src);
	for (i = 0;i < UniStrLen(dst);i++)
	{
		if (UniIsSafeChar(dst[i]) == false)
		{
			dst[i] = L'_';
		}
	}
}

// ディスクの空き容量を取得する
bool GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	bool ret;
	// 引数チェック
	if (path == NULL)
	{
		path = "./";
	}

#ifdef	OS_WIN32
	ret = Win32GetDiskFree(path, free_size, used_size, total_size);
#else	// OS_WIN32
	ret = UnixGetDiskFree(path, free_size, used_size, total_size);
#endif	// OS_WIN32

	return ret;
}
bool GetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	bool ret;
	// 引数チェック
	if (path == NULL)
	{
		path = L"./";
	}

#ifdef	OS_WIN32
	ret = Win32GetDiskFreeW(path, free_size, used_size, total_size);
#else	// OS_WIN32
	ret = UnixGetDiskFreeW(path, free_size, used_size, total_size);
#endif	// OS_WIN32

	return ret;
}

// ディレクトリの列挙
DIRLIST *EnumDirEx(char *dirname, COMPARE *compare)
{
	wchar_t *dirname_w = CopyStrToUni(dirname);
	DIRLIST *ret = EnumDirExW(dirname_w, compare);

	Free(dirname_w);

	return ret;
}
DIRLIST *EnumDirExW(wchar_t *dirname, COMPARE *compare)
{
	DIRLIST *d = NULL;
	// 引数チェック
	if (dirname == NULL)
	{
		dirname = L"./";
	}

	if (compare == NULL)
	{
		compare = CompareDirListByName;
	}

#ifdef	OS_WIN32
	d = Win32EnumDirExW(dirname, compare);
#else	// OS_WIN32
	d = UnixEnumDirExW(dirname, compare);
#endif	// OS_WIN32

	return d;
}
DIRLIST *EnumDir(char *dirname)
{
	return EnumDirEx(dirname, NULL);
}
DIRLIST *EnumDirW(wchar_t *dirname)
{
	return EnumDirExW(dirname, NULL);
}

// DIRLIST リストの比較
int CompareDirListByName(void *p1, void *p2)
{
	DIRENT *d1, *d2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	d1 = *(DIRENT **)p1;
	d2 = *(DIRENT **)p2;
	if (d1 == NULL || d2 == NULL)
	{
		return 0;
	}
	return UniStrCmpi(d1->FileNameW, d2->FileNameW);
}

// ディレクトリ列挙の解放
void FreeDir(DIRLIST *d)
{
	UINT i;
	// 引数チェック
	if (d == NULL)
	{
		return;
	}

	for (i = 0;i < d->NumFiles;i++)
	{
		DIRENT *f = d->File[i];
		Free(f->FileName);
		Free(f->FileNameW);
		Free(f);
	}
	Free(d->File);
	Free(d);
}


// ファイル名を安全にする
void UniSafeFileName(wchar_t *name)
{
	UINT i, len, dlen;
	static wchar_t *danger_str = L"\\/:*?\"<>|";
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	dlen = UniStrLen(danger_str);
	len = UniStrLen(name);

	for (i = 0;i < len;i++)
	{
		wchar_t c = name[i];
		UINT j;
		for (j = 0;j < dlen;j++)
		{
			if (c == danger_str[j])
			{
				c = L'_';
			}
		}
		name[i] = c;
	}
}
void SafeFileNameW(wchar_t *name)
{
	UniSafeFileName(name);
}

// HamCore の読み込み
BUF *ReadHamcoreW(wchar_t *filename)
{
	char *filename_a = CopyUniToStr(filename);
	BUF *ret;

	ret = ReadHamcore(filename_a);

	Free(filename_a);

	return ret;
}
BUF *ReadHamcore(char *name)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t exe_dir[MAX_SIZE];
	BUF *b;
	char filename[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	if (name[0] == '|')
	{
		name++;
	}

	if (name[0] == '/' || name[0] == '\\')
	{
		name++;
	}

	StrCpy(filename, sizeof(filename), name);

	ReplaceStrEx(filename, sizeof(filename), filename, "/", "\\", true);

	if (MayaquaIsMinimalMode())
	{
		return NULL;
	}

	// ローカルディスクの hamcore/ ディレクトリにファイルがあればそれを読み込む
	GetExeDirW(exe_dir, sizeof(exe_dir));

	UniFormat(tmp, sizeof(tmp), L"%s/%S/%S", exe_dir, HAMCORE_DIR_NAME, filename);

	b = ReadDumpW(tmp);
	if (b != NULL)
	{
		return b;
	}

	// 無い場合は HamCore ファイルシステムから探す
	LockList(hamcore);
	{
		HC t, *c;
		UINT i;

		Zero(&t, sizeof(t));
		t.FileName = filename;
		c = Search(hamcore, &t);

		if (c == NULL)
		{
			// ファイルが存在しない
			b = NULL;
		}
		else
		{
			// ファイルが存在する
			if (c->Buffer != NULL)
			{
				// 既に読み込まれている
				b = NewBuf();
				WriteBuf(b, c->Buffer, c->Size);
				SeekBuf(b, 0, 0);
				c->LastAccess = Tick64();
			}
			else
			{
				// 読み込まれていないのでファイルから読み込む
				if (FileSeek(hamcore_io, 0, c->Offset) == false)
				{
					// シークに失敗した
					b = NULL;
				}
				else
				{
					// 圧縮データを読み込む
					void *data = Malloc(c->SizeCompressed);
					if (FileRead(hamcore_io, data, c->SizeCompressed) == false)
					{
						// 読み込みに失敗した
						Free(data);
						b = NULL;
					}
					else
					{
						// 展開する
						c->Buffer = ZeroMalloc(c->Size);
						if (Uncompress(c->Buffer, c->Size, data, c->SizeCompressed) != c->Size)
						{
							// 展開に失敗した
							Free(data);
							Free(c->Buffer);
							b = NULL;
						}
						else
						{
							// 成功した
							Free(data);
							b = NewBuf();
							WriteBuf(b, c->Buffer, c->Size);
							SeekBuf(b, 0, 0);
							c->LastAccess = Tick64();
						}
					}
				}
			}
		}

		// 有効期限の切れたキャッシュを削除する
		for (i = 0;i < LIST_NUM(hamcore);i++)
		{
			HC *c = LIST_DATA(hamcore, i);

			if (c->Buffer != NULL)
			{
				if (((c->LastAccess + HAMCORE_CACHE_EXPIRES) <= Tick64()) ||
					(StartWith(c->FileName, "Li")))
				{
					Free(c->Buffer);
					c->Buffer = NULL;
				}
			}
		}
	}
	UnlockList(hamcore);

	return b;
}

// HamCore ファイルシステムの初期化
void InitHamcore()
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	wchar_t exe_dir[MAX_PATH];
	UINT i, num;
	char header[HAMCORE_HEADER_SIZE];

	hamcore = NewList(CompareHamcore);

	if (MayaquaIsMinimalMode())
	{
		return;
	}

	GetExeDirW(exe_dir, sizeof(exe_dir));
	UniFormat(tmp, sizeof(tmp), L"%s/%S", exe_dir, HAMCORE_FILE_NAME);

	UniFormat(tmp2, sizeof(tmp2), L"%s/%S", exe_dir, HAMCORE_FILE_NAME_2);

	// _hamcore.utvpn がある場合は hamcore.utvpn に上書きする
	FileReplaceRenameW(tmp2, tmp);

	// hamcore.utvpn ファイルがあれば読み込む
	hamcore_io = FileOpenW(tmp, false);
	if (hamcore_io == NULL)
	{
		// 無い場合は別の場所を探す
#ifdef	OS_WIN32
		UniFormat(tmp, sizeof(tmp), L"%S/%S", MsGetSystem32Dir(), HAMCORE_FILE_NAME);
#else	// OS_WIN32
		UniFormat(tmp, sizeof(tmp), L"/bin/%S", HAMCORE_FILE_NAME);
#endif	// OS_WIN32

		hamcore_io = FileOpenW(tmp, false);
		if (hamcore_io == NULL)
		{
			return;
		}
	}

	// ファイルヘッダを読み込む
	Zero(header, sizeof(header));
	FileRead(hamcore_io, header, HAMCORE_HEADER_SIZE);

	if (Cmp(header, HAMCORE_HEADER_DATA, HAMCORE_HEADER_SIZE) != 0)
	{
		// ヘッダ不正
		FileClose(hamcore_io);
		hamcore_io = NULL;
		return;
	}

	// ファイル個数
	num = 0;
	FileRead(hamcore_io, &num, sizeof(num));
	num = Endian32(num);
	for (i = 0;i < num;i++)
	{
		// ファイル名
		char tmp[MAX_SIZE];
		UINT str_size = 0;
		HC *c;

		FileRead(hamcore_io, &str_size, sizeof(str_size));
		str_size = Endian32(str_size);
		if (str_size >= 1)
		{
			str_size--;
		}

		Zero(tmp, sizeof(tmp));
		FileRead(hamcore_io, tmp, str_size);

		c = ZeroMalloc(sizeof(HC));
		c->FileName = CopyStr(tmp);

		FileRead(hamcore_io, &c->Size, sizeof(UINT));
		c->Size = Endian32(c->Size);

		FileRead(hamcore_io, &c->SizeCompressed, sizeof(UINT));
		c->SizeCompressed = Endian32(c->SizeCompressed);

		FileRead(hamcore_io, &c->Offset, sizeof(UINT));
		c->Offset = Endian32(c->Offset);

		Insert(hamcore, c);
	}
}

// HamCore ファイルシステムの解放
void FreeHamcore()
{
	UINT i;
	for (i = 0;i < LIST_NUM(hamcore);i++)
	{
		HC *c = LIST_DATA(hamcore, i);
		Free(c->FileName);
		if (c->Buffer != NULL)
		{
			Free(c->Buffer);
		}
		Free(c);
	}
	ReleaseList(hamcore);

	FileClose(hamcore_io);
	hamcore_io = NULL;
	hamcore = NULL;
}

// Hamcore のビルド
void BuildHamcore()
{
	BUF *b;
	char tmp[MAX_SIZE];
	char exe_dir[MAX_SIZE];
	char *s;
	bool ok = true;
	LIST *o;
	UINT i;

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(tmp, sizeof(tmp), "%s/%s", exe_dir, HAMCORE_TEXT_NAME);

	b = ReadDump(tmp);
	if (b == NULL)
	{
		Print("Failed to open %s.\n", tmp);
		return;
	}

	o = NewListFast(CompareHamcore);

	while ((s = CfgReadNextLine(b)) != NULL)
	{
		char tmp[MAX_SIZE];
		BUF *b;
		Trim(s);

		Format(tmp, sizeof(tmp), "%s/%s/%s", exe_dir, HAMCORE_DIR_NAME, s);

		b = ReadDump(tmp);
		if (b == NULL)
		{
			Print("Failed to open %s.\n", s);
			ok = false;
		}
		else
		{
			HC *c = ZeroMalloc(sizeof(HC));
			UINT tmp_size;
			void *tmp;
			c->FileName = CopyStr(s);
			c->Size = b->Size;
			tmp_size = CalcCompress(c->Size);
			tmp = Malloc(tmp_size);
			c->SizeCompressed = Compress(tmp, tmp_size, b->Buf, b->Size);
			c->Buffer = tmp;
			Insert(o, c);
			Print("%s: %u -> %u\n", s, c->Size, c->SizeCompressed);
			FreeBuf(b);
		}

		Free(s);
	}

	if (ok)
	{
		// 各ファイルのバッファのオフセットを計算する
		UINT i, z;
		char tmp[MAX_SIZE];
		BUF *b;
		z = 0;
		z += HAMCORE_HEADER_SIZE;
		// ファイルの個数
		z += sizeof(UINT);
		// まずファイルテーブル
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			// ファイル名
			z += StrLen(c->FileName) + sizeof(UINT);
			// ファイルサイズ
			z += sizeof(UINT);
			z += sizeof(UINT);
			// オフセットデータ
			z += sizeof(UINT);
		}
		// ファイル本体
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			// バッファ本体
			c->Offset = z;
			printf("%s: offset: %u\n", c->FileName, c->Offset);
			z += c->SizeCompressed;
		}
		// 書き込み
		b = NewBuf();
		// ヘッダ
		WriteBuf(b, HAMCORE_HEADER_DATA, HAMCORE_HEADER_SIZE);
		WriteBufInt(b, LIST_NUM(o));
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			// ファイル名
			WriteBufStr(b, c->FileName);
			// ファイルサイズ
			WriteBufInt(b, c->Size);
			WriteBufInt(b, c->SizeCompressed);
			// オフセット
			WriteBufInt(b, c->Offset);
		}
		// 本体
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			WriteBuf(b, c->Buffer, c->SizeCompressed);
		}
		// 書き込み
		Format(tmp, sizeof(tmp), "%s/%s", exe_dir, HAMCORE_FILE_NAME "__");
		Print("Writing %s...\n", tmp);
		FileDelete(tmp);
		DumpBuf(b, tmp);
		FreeBuf(b);
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HC *c = LIST_DATA(o, i);
		Free(c->Buffer);
		Free(c->FileName);
		Free(c);
	}

	ReleaseList(o);

	FreeBuf(b);
}

// HC の比較
int CompareHamcore(void *p1, void *p2)
{
	HC *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(HC **)p1;
	c2 = *(HC **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}
	return StrCmpi(c1->FileName, c2->FileName);
}

// EXE ファイルがあるディレクトリ名の取得
void GetExeDir(char *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	GetDirNameFromFilePath(name, size, exe_file_name);
}
void GetExeDirW(wchar_t *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	GetDirNameFromFilePathW(name, size, exe_file_name_w);
}

// EXE ファイル名の取得
void GetExeName(char *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	StrCpy(name, size, exe_file_name);
}
void GetExeNameW(wchar_t *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	UniStrCpy(name, size, exe_file_name_w);
}

// EXE ファイル名の取得初期化
void InitGetExeName(char *arg)
{
	wchar_t *arg_w = NULL;
	// 引数チェック
	if (arg == NULL)
	{
		arg = "./a.out";
	}

	arg_w = CopyUtfToUni(arg);

#ifdef	OS_WIN32
	Win32GetExeNameW(exe_file_name_w, sizeof(exe_file_name_w));
#else	// OS_WIN32
	UnixGetExeNameW(exe_file_name_w, sizeof(exe_file_name_w), arg_w);
#endif	// OS_WIN32

	UniToStr(exe_file_name, sizeof(exe_file_name), exe_file_name_w);

	Free(arg_w);
}

// Unix における実行可能バイナリファイルのフルパスの取得
void UnixGetExeNameW(wchar_t *name, UINT size, wchar_t *arg)
{
	UNI_TOKEN_LIST *t;
	char *path_str;
	wchar_t *path_str_w;
	bool ok = false;
	// 引数チェック
	if (name == NULL || arg == NULL)
	{
		return;
	}

	path_str = GetCurrentPathEnvStr();
	path_str_w = CopyUtfToUni(path_str);

	t = ParseSplitedPathW(path_str_w);

	if (t != NULL)
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			wchar_t *s = t->Token[i];
			wchar_t tmp[MAX_SIZE];

			ConbinePathW(tmp, sizeof(tmp), s, arg);

			if (IsFileExistsInnerW(tmp))
			{
#ifdef	OS_UNIX
				if (UnixCheckExecAccessW(tmp) == false)
				{
					continue;
				}
#endif	// OS_UNIX
				ok = true;
				UniStrCpy(name, size, tmp);
				break;
			}
		}

		UniFreeToken(t);
	}

	Free(path_str);
	Free(path_str_w);

	if (ok == false)
	{
		// パスの検索に失敗した場合
#ifdef	OS_UNIX
		UnixGetCurrentDirW(name, size);
#else	// OS_UNIX
		Win32GetCurrentDirW(name, size);
#endif	// OS_UNIX
		ConbinePathW(name, size, name, arg);
	}
}

// 安全なファイル名を生成する
void MakeSafeFileName(char *dst, UINT size, char *src)
{
	char tmp[MAX_PATH];
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), src);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "..", "__", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "/", "_", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "\\", "_", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "@", "_", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "|", "_", false);

	StrCpy(dst, size, tmp);
}
void MakeSafeFileNameW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	UniStrCpy(tmp, sizeof(tmp), src);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"..", L"__", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"/", L"_", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"\\", L"_", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"@", L"_", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"|", L"_", false);

	UniStrCpy(dst, size, tmp);
}

// ファイルパスからファイル名を取得する
void GetFileNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath)
{
	wchar_t tmp[MAX_SIZE];
	UINT i, len, wp;
	// 引数チェック
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	len = MIN(UniStrLen(filepath), (MAX_SIZE - 2));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = filepath[i];

		switch (c)
		{
		case L'\\':
		case L'/':
		case 0:
			tmp[wp] = 0;
			wp = 0;
			break;

		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}

	UniStrCpy(dst, size, tmp);
}
void GetFileNameFromFilePath(char *dst, UINT size, char *filepath)
{
	char tmp[MAX_SIZE];
	UINT i, len, wp;
	// 引数チェック
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	len = MIN(StrLen(filepath), (MAX_SIZE - 2));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		char c = filepath[i];

		switch (c)
		{
		case '\\':
		case '/':
		case 0:
			tmp[wp] = 0;
			wp = 0;
			break;

		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}

	StrCpy(dst, size, tmp);
}
void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath)
{
	wchar_t tmp[MAX_SIZE];
	UINT wp;
	UINT i;
	UINT len;
	// 引数チェック
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	UniStrCpy(tmp, sizeof(tmp), filepath);
	if (UniEndWith(tmp, L"\\") || UniEndWith(tmp, L"/"))
	{
		tmp[UniStrLen(tmp) - 1] = 0;
	}

	len = UniStrLen(tmp);

	UniStrCpy(dst, size, L"");

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = tmp[i];
		if (c == L'/' || c == L'\\')
		{
			tmp[wp++] = 0;
			wp = 0;
			UniStrCat(dst, size, tmp);
			tmp[wp++] = c;
		}
		else
		{
			tmp[wp++] = c;
		}
	}

	if (UniStrLen(dst) == 0)
	{
		UniStrCpy(dst, size, L"/");
	}

	NormalizePathW(dst, size, dst);
}

// ファイルパスからディレクトリ名を取得する
void GetDirNameFromFilePath(char *dst, UINT size, char *filepath)
{
	char tmp[MAX_SIZE];
	UINT wp;
	UINT i;
	UINT len;
	// 引数チェック
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), filepath);
	if (EndWith(tmp, "\\") || EndWith(tmp, "/"))
	{
		tmp[StrLen(tmp) - 1] = 0;
	}

	len = StrLen(tmp);

	StrCpy(dst, size, "");

	wp = 0;

	for (i = 0;i < len;i++)
	{
		char c = tmp[i];
		if (c == '/' || c == '\\')
		{
			tmp[wp++] = 0;
			wp = 0;
			StrCat(dst, size, tmp);
			tmp[wp++] = c;
		}
		else
		{
			tmp[wp++] = c;
		}
	}

	if (StrLen(dst) == 0)
	{
		StrCpy(dst, size, "/");
	}

	NormalizePath(dst, size, dst);
}

// 2 つのパスを結合する
void ConbinePath(char *dst, UINT size, char *dirname, char *filename)
{
	wchar_t dst_w[MAX_PATH];
	wchar_t *dirname_w = CopyStrToUni(dirname);
	wchar_t *filename_w = CopyStrToUni(filename);

	ConbinePathW(dst_w, sizeof(dst_w), dirname_w, filename_w);

	Free(dirname_w);
	Free(filename_w);

	UniToStr(dst, size, dst_w);
}
void ConbinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename)
{
	bool is_full_path;
	wchar_t tmp[MAX_SIZE];
	wchar_t filename_ident[MAX_SIZE];
	// 引数チェック
	if (dst == NULL || dirname == NULL || filename == NULL)
	{
		return;
	}

	NormalizePathW(filename_ident, sizeof(filename_ident), filename);

	is_full_path = false;

	if (UniStartWith(filename_ident, L"\\") || UniStartWith(filename_ident, L"/"))
	{
		is_full_path = true;
	}

	filename = &filename_ident[0];

#ifdef	OS_WIN32
	if (UniStrLen(filename) >= 2)
	{
		if ((L'a' <= filename[0] && filename[0] <= L'z') || (L'A' <= filename[0] && filename[0] <= L'Z'))
		{
			if (filename[1] == L':')
			{
				is_full_path = true;
			}
		}
	}
#endif	// OS_WIN32

	if (is_full_path == false)
	{
		UniStrCpy(tmp, sizeof(tmp), dirname);
		if (UniEndWith(tmp, L"/") == false && UniEndWith(tmp, L"\\") == false)
		{
			UniStrCat(tmp, sizeof(tmp), L"/");
		}
		UniStrCat(tmp, sizeof(tmp), filename);
	}
	else
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}

	NormalizePathW(dst, size, tmp);
}
void CombinePath(char *dst, UINT size, char *dirname, char *filename)
{
	ConbinePath(dst, size, dirname, filename);
}
void CombinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename)
{
	ConbinePathW(dst, size, dirname, filename);
}

// ファイルが存在するかどうか確認する
bool IsFileExists(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileExistsW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileExistsW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return IsFileExistsInnerW(tmp);
}
bool IsFileExistsInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileExistsInnerW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileExistsInnerW(wchar_t *name)
{
	IO *o;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	o = FileOpenInnerW(name, false, false);
	if (o == NULL)
	{
		return false;
	}

	FileClose(o);

	return true;
}

// 現在の環境変数 PATH の内容を取得
char *GetCurrentPathEnvStr()
{
	char tmp[1024];
	char *tag_name;

#ifdef	OS_WIN32
	tag_name = "Path";
#else	// OS_WIN32
	tag_name = "PATH";
#endif	// OS_WIN32

	if (GetEnv(tag_name, tmp, sizeof(tmp)) == false)
	{
#ifdef	OS_WIN32
		Win32GetCurrentDir(tmp, sizeof(tmp));
#else	// OS_WIN32
		UnixGetCurrentDir(tmp, sizeof(tmp));
#endif	// OS_WIN32
	}

	return CopyStr(tmp);
}

// コロン文字列で区切られた複数のパスを取得する
UNI_TOKEN_LIST *ParseSplitedPathW(wchar_t *path)
{
	UNI_TOKEN_LIST *ret;
	wchar_t *tmp = UniCopyStr(path);
	wchar_t *split_str;
	UINT i;

	UniTrim(tmp);
	UniTrimCrlf(tmp);
	UniTrim(tmp);
	UniTrimCrlf(tmp);

#ifdef	OS_WIN32
	split_str = L";";
#else	// OS_WIN32
	split_str = L":";
#endif	// OS_WIN32

	ret = UniParseToken(tmp, split_str);

	if (ret != NULL)
	{
		for (i = 0;i < ret->NumTokens;i++)
		{
			UniTrim(ret->Token[i]);
			UniTrimCrlf(ret->Token[i]);
			UniTrim(ret->Token[i]);
			UniTrimCrlf(ret->Token[i]);
		}
	}

	Free(tmp);

	return ret;
}
TOKEN_LIST *ParseSplitedPath(char *path)
{
	TOKEN_LIST *ret;
	char *tmp = CopyStr(path);
	char *split_str;
	UINT i;

	Trim(tmp);
	TrimCrlf(tmp);
	Trim(tmp);
	TrimCrlf(tmp);

#ifdef	OS_WIN32
	split_str = ";";
#else	// OS_WIN32
	split_str = ":";
#endif	// OS_WIN32

	ret = ParseToken(tmp, split_str);

	if (ret != NULL)
	{
		for (i = 0;i < ret->NumTokens;i++)
		{
			Trim(ret->Token[i]);
			TrimCrlf(ret->Token[i]);
			Trim(ret->Token[i]);
			TrimCrlf(ret->Token[i]);
		}
	}

	Free(tmp);

	return ret;
}

// 現在のディレクトリを取得する
void GetCurrentDirW(wchar_t *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32GetCurrentDirW(name, size);
#else	// OS_WIN32
	UnixGetCurrentDirW(name, size);
#endif	// OS_WIN32
}
void GetCurrentDir(char *name, UINT size)
{
	wchar_t name_w[MAX_PATH];

	GetCurrentDirW(name_w, sizeof(name_w));

	UniToStr(name, size, name_w);
}

// ファイルパスを正規化する
void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t tmp[MAX_SIZE];
	UNI_TOKEN_LIST *t;
	bool first_double_slash = false;
	bool first_single_slash = false;
	wchar_t win32_drive_char = 0;
	bool is_full_path = false;
	UINT i;
	SK *sk;
	// 引数チェック
	if (dst == NULL || src == 0)
	{
		return;
	}

	// パスを変換する (Win32, UNIX 変換)
	UniStrCpy(tmp, sizeof(tmp), src);
	ConvertPathW(tmp);
	UniTrim(tmp);

	// 先頭が "./" や "../" で始まっている場合はカレントディレクトリに置換する
	if (UniStartWith(tmp, L"./") || UniStartWith(tmp, L".\\") ||
		UniStartWith(tmp, L"../") || UniStartWith(tmp, L"..\\") ||
		UniStrCmpi(tmp, L".") == 0 || UniStrCmpi(tmp, L"..") == 0)
	{
		wchar_t cd[MAX_SIZE];
		Zero(cd, sizeof(cd));

#ifdef	OS_WIN32
		Win32GetCurrentDirW(cd, sizeof(cd));
#else	// OS_WIN32
		UnixGetCurrentDirW(cd, sizeof(cd));
#endif	// OS_WIN32

		if (UniStartWith(tmp, L".."))
		{
			UniStrCat(cd, sizeof(cd), L"/../");
			UniStrCat(cd, sizeof(cd), tmp + 2);
		}
		else
		{
			UniStrCat(cd, sizeof(cd), L"/");
			UniStrCat(cd, sizeof(cd), tmp);
		}

		UniStrCpy(tmp, sizeof(tmp), cd);
	}

	// 先頭が "~/" で始まっている場合はホームディレクトリに置換する
	if (UniStartWith(tmp, L"~/") || UniStartWith(tmp, L"~\\"))
	{
		wchar_t tmp2[MAX_SIZE];
		GetHomeDirW(tmp2, sizeof(tmp2));
		UniStrCat(tmp2, sizeof(tmp2), L"/");
		UniStrCat(tmp2, sizeof(tmp2), tmp + 2);
		UniStrCpy(tmp, sizeof(tmp), tmp2);
	}

	if (UniStartWith(tmp, L"//") || UniStartWith(tmp, L"\\\\"))
	{
		// 最初が "//" または "\\" で始まる
		first_double_slash = true;
		is_full_path = true;
	}
	else if (UniStartWith(tmp, L"/") || UniStartWith(tmp, L"\\"))
	{
		// 最初が "\" で始まる
		first_single_slash = true;
		is_full_path = true;
	}

	if (UniStrLen(tmp) >= 2)
	{
		if (tmp[1] == L':')
		{
			if (OS_IS_WINDOWS(GetOsInfo()->OsType))
			{
				// Win32 のドライブ文字列表記
				wchar_t tmp2[MAX_SIZE];
				is_full_path = true;
				win32_drive_char = tmp[0];
				UniStrCpy(tmp2, sizeof(tmp2), tmp + 2);
				UniStrCpy(tmp, sizeof(tmp), tmp2);
			}
		}
	}

	if (UniStrLen(tmp) == 1 && (tmp[0] == L'/' || tmp[0] == L'\\'))
	{
		tmp[0] = 0;
	}

	// トークン分割
	t = UniParseToken(tmp, L"/\\");

	sk = NewSk();

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *s = t->Token[i];

		if (UniStrCmpi(s, L".") == 0)
		{
			continue;
		}
		else if (UniStrCmpi(s, L"..") == 0)
		{
			if (sk->num_item >= 1 && (first_double_slash == false || sk->num_item >= 2))
			{
				Pop(sk);
			}
		}
		else
		{
			Push(sk, s);
		}
	}

	// トークン結合
	UniStrCpy(tmp, sizeof(tmp), L"");

	if (first_double_slash)
	{
		UniStrCat(tmp, sizeof(tmp), L"//");
	}
	else if (first_single_slash)
	{
		UniStrCat(tmp, sizeof(tmp), L"/");
	}

	if (win32_drive_char != 0)
	{
		wchar_t d[2];
		d[0] = win32_drive_char;
		d[1] = 0;
		UniStrCat(tmp, sizeof(tmp), d);
		UniStrCat(tmp, sizeof(tmp), L":/");
	}

	for (i = 0;i < sk->num_item;i++)
	{
		UniStrCat(tmp, sizeof(tmp), (wchar_t *)sk->p[i]);
		if (i != (sk->num_item - 1))
		{
			UniStrCat(tmp, sizeof(tmp), L"/");
		}
	}

	ReleaseSk(sk);

	UniFreeToken(t);

	ConvertPathW(tmp);

	UniStrCpy(dst, size, tmp);
}
void NormalizePath(char *dst, UINT size, char *src)
{
	wchar_t dst_w[MAX_SIZE];
	wchar_t *src_w = CopyStrToUni(src);

	NormalizePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

// ファイルを閉じて削除する
void FileCloseAndDelete(IO *o)
{
	wchar_t *name;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	name = CopyUniStr(o->NameW);
	FileClose(o);

	FileDeleteW(name);

	Free(name);
}

// ファイル名の変更
bool FileRename(char *old_name, char *new_name)
{
	wchar_t *old_name_w = CopyStrToUni(old_name);
	wchar_t *new_name_w = CopyStrToUni(new_name);
	bool ret = FileRenameW(old_name_w, new_name_w);

	Free(old_name_w);
	Free(new_name_w);

	return ret;
}
bool FileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// 引数チェック
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp1, sizeof(tmp1), old_name);
	InnerFilePathW(tmp2, sizeof(tmp2), new_name);

	return FileRenameInnerW(tmp1, tmp2);
}
bool FileRenameInner(char *old_name, char *new_name)
{
	wchar_t *old_name_w = CopyStrToUni(old_name);
	wchar_t *new_name_w = CopyStrToUni(new_name);
	bool ret = FileRenameInnerW(old_name_w, new_name_w);

	Free(old_name_w);
	Free(new_name_w);

	return ret;
}
bool FileRenameInnerW(wchar_t *old_name, wchar_t *new_name)
{
	// 引数チェック
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	return OSFileRenameW(old_name, new_name);
}

// パスの変換
void ConvertPath(char *path)
{
	UINT i, len;
#ifdef	PATH_BACKSLASH
	char new_char = '\\';
#else
	char new_char = '/';
#endif

	len = StrLen(path);
	for (i = 0;i < len;i++)
	{
		if (path[i] == '\\' || path[i] == '/')
		{
			path[i] = new_char;
		}
	}
}
void ConvertPathW(wchar_t *path)
{
	UINT i, len;
#ifdef	PATH_BACKSLASH
	wchar_t new_char = L'\\';
#else
	wchar_t new_char = L'/';
#endif

	len = UniStrLen(path);
	for (i = 0;i < len;i++)
	{
		if (path[i] == L'\\' || path[i] == L'/')
		{
			path[i] = new_char;
		}
	}
}

// ディレクトリの削除
bool DeleteDir(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = DeleteDirW(name_w);

	Free(name_w);

	return ret;
}
bool DeleteDirW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return DeleteDirInnerW(tmp);
}
bool DeleteDirInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = DeleteDirInnerW(name_w);

	Free(name_w);

	return ret;
}
bool DeleteDirInnerW(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	return OSDeleteDirW(name);
}

// 内部ファイルパスの生成
void InnerFilePathW(wchar_t *dst, UINT size, wchar_t *src)
{
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	if (src[0] != L'@')
	{
		NormalizePathW(dst, size, src);
	}
	else
	{
		wchar_t dir[MAX_SIZE];
		GetExeDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	}
}
void InnerFilePath(char *dst, UINT size, char *src)
{
	wchar_t dst_w[MAX_PATH];
	wchar_t *src_w = CopyStrToUni(src);

	InnerFilePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

// ディレクトリの再帰作成
void MakeDirEx(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);

	MakeDirExW(name_w);

	Free(name_w);
}
void MakeDirExW(wchar_t *name)
{
	LIST *o;
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	UINT i;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	UniStrCpy(tmp, sizeof(tmp), name);
	while (true)
	{
		wchar_t *s = CopyUniStr(tmp);

		Add(o, s);

		GetDirNameFromFilePathW(tmp2, sizeof(tmp2), tmp);

		if (UniStrCmpi(tmp2, tmp) == 0)
		{
			break;
		}

		UniStrCpy(tmp, sizeof(tmp), tmp2);
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT j = LIST_NUM(o) - i - 1;
		wchar_t *s = LIST_DATA(o, j);

		if (UniStrCmpi(s, L"\\") != 0 && UniStrCmpi(s, L"/") != 0)
		{
			MakeDirW(s);
		}
	}

	UniFreeStrList(o);
}

// ディレクトリの作成
bool MakeDir(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = MakeDirW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return MakeDirInnerW(tmp);
}
bool MakeDirInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = MakeDirInnerW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirInnerW(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	return OSMakeDirW(name);
}

// ファイルの削除
bool FileDelete(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = FileDeleteW(name_w);

	Free(name_w);

	return ret;
}
bool FileDeleteW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileDeleteInnerW(tmp);
}
bool FileDeleteInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = FileDeleteInnerW(name_w);

	Free(name_w);

	return ret;
}
bool FileDeleteInnerW(wchar_t *name)
{
	wchar_t name2[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	return OSFileDeleteW(name2);
}

// ファイルをシークする
bool FileSeek(IO *o, UINT mode, int offset)
{
	// 引数チェック
	if (o == NULL)
	{
		return false;
	}

	if (o->HamMode == false)
	{
		return OSFileSeek(o->pData, mode, offset);
	}
	else
	{
		return false;
	}
}

// ファイル名を指定してファイルサイズを取得する
UINT FileSizeEx(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	UINT ret = FileSizeExW(name_w);

	Free(name_w);

	return ret;
}
UINT FileSizeExW(wchar_t *name)
{
	IO *io;
	UINT size;
	// 引数チェック
	if (name == NULL)
	{
		return 0;
	}

	io = FileOpenW(name, false);
	if (io == NULL)
	{
		return 0;
	}

	size = FileSize(io);

	FileClose(io);

	return size;
}

// ファイルサイズを取得する
UINT64 FileSize64(IO *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return 0;
	}

	if (o->HamMode == false)
	{
		return OSFileSize(o->pData);
	}
	else
	{
		return (UINT64)o->HamBuf->Size;
	}
}
UINT FileSize(IO *o)
{
	UINT64 size = (UINT)(FileSize64(o));

	if (size >= 4294967296ULL)
	{
		size = 4294967295ULL;
	}

	return (UINT)size;
}

// ファイルから読み込む
bool FileRead(IO *o, void *buf, UINT size)
{
	// 引数チェック
	if (o == NULL || buf == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_IO_READ_COUNT);
	KS_ADD(KS_IO_TOTAL_READ_SIZE, size);

	if (size == 0)
	{
		return true;
	}

	if (o->HamMode == false)
	{
		return OSFileRead(o->pData, buf, size);
	}
	else
	{
		return ReadBuf(o->HamBuf, buf, size) == size ? true : false;
	}
}

// ファイルに書き込む
bool FileWrite(IO *o, void *buf, UINT size)
{
	// 引数チェック
	if (o == NULL || buf == NULL)
	{
		return false;
	}
	if (o->WriteMode == false)
	{
		return false;
	}

	// KS
	KS_INC(KS_IO_WRITE_COUNT);
	KS_ADD(KS_IO_TOTAL_WRITE_SIZE, size);

	if (size == 0)
	{
		return true;
	}

	return OSFileWrite(o->pData, buf, size);
}

// ファイルをフラッシュする
void FileFlush(IO *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	if (o->HamMode)
	{
		return;
	}

	OSFileFlush(o->pData);
}

// ファイルを閉じる
void FileClose(IO *o)
{
	FileCloseEx(o, false);
}
void FileCloseEx(IO *o, bool no_flush)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	if (o->HamMode == false)
	{
		OSFileClose(o->pData, no_flush);
	}
	else
	{
		FreeBuf(o->HamBuf);
	}
	Free(o);

	// KS
	KS_INC(KS_IO_CLOSE_COUNT);
}

// ファイルを作成する
IO *FileCreateInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileCreateInnerW(name_w);

	Free(name_w);

	return ret;
}
IO *FileCreateInnerW(wchar_t *name)
{
	IO *o;
	void *p;
	wchar_t name2[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	p = OSFileCreateW(name2);
	if (p == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = true;

	// KS
	KS_INC(KS_IO_CREATE_COUNT);

	return o;
}
IO *FileCreate(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileCreateW(name_w);

	Free(name_w);

	return ret;
}
IO *FileCreateW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileCreateInnerW(tmp);
}

// ファイルにすべてのデータを書き込む
bool FileWriteAll(char *name, void *data, UINT size)
{
	IO *io;
	// 引数チェック
	if (name == NULL || (data == NULL && size != 0))
	{
		return false;
	}

	io = FileCreate(name);

	if (io == NULL)
	{
		return false;
	}

	FileWrite(io, data, size);

	FileClose(io);

	return true;
}
bool FileWriteAllW(wchar_t *name, void *data, UINT size)
{
	IO *io;
	// 引数チェック
	if (name == NULL || (data == NULL && size != 0))
	{
		return false;
	}

	io = FileCreateW(name);

	if (io == NULL)
	{
		return false;
	}

	FileWrite(io, data, size);

	FileClose(io);

	return true;
}

// ファイルを開く
IO *FileOpenInner(char *name, bool write_mode, bool read_lock)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileOpenInnerW(name_w, write_mode, read_lock);

	Free(name_w);

	return ret;
}
IO *FileOpenInnerW(wchar_t *name, bool write_mode, bool read_lock)
{
	IO *o;
	void *p;
	wchar_t name2[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	p = OSFileOpenW(name2, write_mode, read_lock);
	if (p == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = write_mode;

	// KS
	KS_INC(KS_IO_OPEN_COUNT);

	return o;
}
IO *FileOpen(char *name, bool write_mode)
{
	return FileOpenEx(name, write_mode, true);
}
IO *FileOpenW(wchar_t *name, bool write_mode)
{
	return FileOpenExW(name, write_mode, true);
}
IO *FileOpenEx(char *name, bool write_mode, bool read_lock)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileOpenExW(name_w, write_mode, read_lock);

	Free(name_w);

	return ret;
}
IO *FileOpenExW(wchar_t *name, bool write_mode, bool read_lock)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	if (name[0] == L'|')
	{
		IO *o = ZeroMalloc(sizeof(IO));
		name++;
		UniStrCpy(o->NameW, sizeof(o->NameW), name);
		UniToStr(o->Name, sizeof(o->Name), o->NameW);
		o->HamMode = true;
		o->HamBuf = ReadHamcoreW(name);
		if (o->HamBuf == NULL)
		{
			Free(o);
			return NULL;
		}
		return o;
	}
	else
	{
		return FileOpenInnerW(tmp, write_mode, read_lock);
	}
}


