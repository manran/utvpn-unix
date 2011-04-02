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

// Cfg.c
// 設定情報操作モジュール

#define	CFG_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// 設定ファイルのバックアップの作成
void BackupCfg(FOLDER *f, char *original)
{
	wchar_t *original_w = CopyStrToUni(original);

	BackupCfgW(f, original_w);

	Free(original_w);
}
void BackupCfgW(FOLDER *f, wchar_t *original)
{
	wchar_t dirname[MAX_PATH];
	wchar_t filename[MAX_PATH];
	wchar_t fullpath[MAX_PATH];
	SYSTEMTIME st;
	// 引数チェック
	if (f == NULL || filename == NULL)
	{
		return;
	}

	// ディレクトリ名を決定
	UniFormat(dirname, sizeof(dirname), L"@backup.%s", original[0] == L'@' ? original + 1 : original);

	// ファイル名を決定
	LocalTime(&st);
	UniFormat(filename, sizeof(filename), L"%04u%02u%02u%02u_%s",
		st.wYear, st.wMonth, st.wDay, st.wHour, original[0] == L'@' ? original + 1 : original);

	// このファイル名が存在するかどうかチェックする
	if (IsFileExistsW(filename))
	{
		return;
	}

	// ディレクトリ作成
	MakeDirW(dirname);

	// ファイル保存
	UniFormat(fullpath, sizeof(fullpath), L"%s/%s", dirname, filename);
	CfgSaveW(f, fullpath);
}

// 設定ファイル R/W を閉じる
void FreeCfgRw(CFG_RW *rw)
{
	// 引数チェック
	if (rw == NULL)
	{
		return;
	}

	if (rw->Io != NULL)
	{
		FileClose(rw->Io);
	}

	DeleteLock(rw->lock);
	Free(rw->FileNameW);
	Free(rw->FileName);
	Free(rw);
}

// 設定ファイルの書き込み
UINT SaveCfgRw(CFG_RW *rw, FOLDER *f)
{
	UINT ret = 0;
	// 引数チェック
	if (rw == NULL || f == NULL)
	{
		return 0;
	}

	Lock(rw->lock);
	{
		if (rw->Io != NULL)
		{
			FileClose(rw->Io);
			rw->Io = NULL;
		}

		if (CfgSaveExW2(rw, f, rw->FileNameW, &ret))
		{
			if (rw->DontBackup == false)
			{
				BackupCfgW(f, rw->FileNameW);
			}
		}
		else
		{
			ret = 0;
		}

		rw->Io = FileOpenW(rw->FileNameW, false);
	}
	Unlock(rw->lock);

	return ret;
}

// 設定ファイル R/W の作成
CFG_RW *NewCfgRw(FOLDER **root, char *cfg_name)
{
	return NewCfgRwEx(root, cfg_name, false);
}
CFG_RW *NewCfgRwW(FOLDER **root, wchar_t *cfg_name)
{
	return NewCfgRwExW(root, cfg_name, false);
}
CFG_RW *NewCfgRwEx(FOLDER **root, char *cfg_name, bool dont_backup)
{
	wchar_t *cfg_name_w = CopyStrToUni(cfg_name);
	CFG_RW *ret = NewCfgRwExW(root, cfg_name_w, dont_backup);

	Free(cfg_name_w);

	return ret;
}
CFG_RW *NewCfgRwExW(FOLDER **root, wchar_t *cfg_name, bool dont_backup)
{
	CFG_RW *rw;
	FOLDER *f;
	// 引数チェック
	if (cfg_name == NULL || root == NULL)
	{
		return NULL;
	}

	f = CfgReadW(cfg_name);
	if (f == NULL)
	{
		rw = ZeroMalloc(sizeof(CFG_RW));
		rw->lock = NewLock();
		rw->FileNameW = CopyUniStr(cfg_name);
		rw->FileName = CopyUniToStr(cfg_name);
		rw->Io = FileCreateW(cfg_name);
		*root = NULL;
		rw->DontBackup = dont_backup;

		return rw;
	}

	rw = ZeroMalloc(sizeof(CFG_RW));
	rw->FileNameW = CopyUniStr(cfg_name);
	rw->FileName = CopyUniToStr(cfg_name);
	rw->Io = FileOpenW(cfg_name, false);
	rw->lock = NewLock();

	*root = f;

	rw->DontBackup = dont_backup;

	return rw;
}

// ファイルをコピーする
bool FileCopy(char *src, char *dst)
{
	BUF *b;
	bool ret = false;
	// 引数チェック
	if (src == NULL || dst == NULL)
	{
		return false;
	}

	b = ReadDump(src);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, 0, 0);

	ret = DumpBuf(b, dst);

	FreeBuf(b);

	return ret;
}
bool FileCopyW(wchar_t *src, wchar_t *dst)
{
	BUF *b;
	bool ret = false;
	// 引数チェック
	if (src == NULL || dst == NULL)
	{
		return false;
	}

	b = ReadDumpW(src);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, 0, 0);

	ret = DumpBufW(b, dst);

	FreeBuf(b);

	return ret;
}

// ファイルへ設定を保存する
void CfgSave(FOLDER *f, char *name)
{
	CfgSaveEx(NULL, f, name);
}
void CfgSaveW(FOLDER *f, wchar_t *name)
{
	CfgSaveExW(NULL, f, name);
}
bool CfgSaveEx(CFG_RW *rw, FOLDER *f, char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = CfgSaveExW(rw, f, name_w);

	Free(name_w);

	return ret;
}
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name)
{
	return CfgSaveExW2(rw, f, name, NULL);
}
bool CfgSaveExW2(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size)
{
	wchar_t tmp[MAX_SIZE];
	bool text = true;
	UCHAR hash[SHA1_SIZE];
	BUF *b;
	IO *o;
	bool ret = true;
	UINT dummy_int = 0;
	// 引数チェック
	if (name == NULL || f == NULL)
	{
		return false;
	}
	if (written_size == NULL)
	{
		written_size = &dummy_int;
	}

	// 同じディレクトリにある SAVE_BINARY_FILE_NAME_SWITCH ファイルがあるかどうか確認
	if (IsFileExistsW(SAVE_BINARY_FILE_NAME_SWITCH))
	{
		text = false;
	}

	// バッファに変換
	b = CfgFolderToBuf(f, text);
	if (b == NULL)
	{
		return false;
	}
	// 内容をハッシュする
	Hash(hash, b->Buf, b->Size, true);

	// 最後に書き込んだ内容と書き込む内容を比較する
	if (rw != NULL)
	{
		if (Cmp(hash, rw->LashHash, SHA1_SIZE) == 0)
		{
			// 内容が変更されていない
			ret = false;
		}
		else
		{
			Copy(rw->LashHash, hash, SHA1_SIZE);
		}
	}

	if (ret || OS_IS_UNIX(GetOsInfo()->OsType))
	{
		// 一時的なファイル名の生成
		UniFormat(tmp, sizeof(tmp), L"%s.log", name);
		// 現在存在するファイルを一時ファイルにコピー
		FileCopyW(name, tmp);

		// 新しいファイルを保存
		o = FileCreateW(name);
		if (o != NULL)
		{
			if (FileWrite(o, b->Buf, b->Size) == false)
			{
				// ファイル保存失敗
				FileClose(o);
				FileDeleteW(name);
				FileRenameW(tmp, name);

				if (rw != NULL)
				{
					Zero(rw->LashHash, sizeof(rw->LashHash));
				}
			}
			else
			{
				// ファイル保存成功
				FileClose(o);
				// 一時ファイルの削除
				FileDeleteW(tmp);
			}
		}
		else
		{
			// ファイル保存失敗
			FileRenameW(tmp, name);

			if (rw != NULL)
			{
				Zero(rw->LashHash, sizeof(rw->LashHash));
			}
		}
	}

	*written_size = b->Size;

	// メモリ解放
	FreeBuf(b);

	return ret;
}

// ファイルから設定を読み込む
FOLDER *CfgRead(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	FOLDER *ret = CfgReadW(name_w);

	Free(name_w);

	return ret;
}
FOLDER *CfgReadW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t newfile[MAX_SIZE];
	BUF *b;
	IO *o;
	UINT size;
	void *buf;
	FOLDER *f;
	bool delete_new = false;
	bool binary_file = false;
	bool invalid_file = false;
	UCHAR header[8];
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	// 新しいファイル名の生成
	UniFormat(newfile, sizeof(newfile), L"%s.new", name);
	// 一時的なファイル名の生成
	UniFormat(tmp, sizeof(tmp), L"%s.log", name);

	// 新しいファイルが存在していれば読み込む
	o = FileOpenW(newfile, false);
	if (o == NULL)
	{
		// 一時的なファイルを読む
		o = FileOpenW(tmp, false);
	}
	else
	{
		delete_new = true;
	}
	if (o == NULL)
	{
		// 一時的なファイルが無い場合は本来のファイルを読む
		o = FileOpenW(name, false);
	}
	else
	{
		// 一時的なファイルのサイズが 0 の場合も本来のファイルを読み込む
		if (FileSize(o) == 0)
		{
			invalid_file = true;
		}

		if (invalid_file)
		{
			FileClose(o);
			o = FileOpenW(name, false);
		}
	}
	if (o == NULL)
	{
		// 読み込みに失敗した
		return NULL;
	}

	// バッファに読み込む
	size = FileSize(o);
	buf = Malloc(size);
	FileRead(o, buf, size);
	b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBuf(b, 0, 0);

	// ファイルを閉じる
	FileClose(o);

	if (delete_new)
	{
		// 新しいファイルを削除する
		FileDeleteW(newfile);
	}

	// バッファの先頭 8 文字が "SEVPN_DB" の場合はバイナリファイル
	ReadBuf(b, header, sizeof(header));
	if (Cmp(header, TAG_BINARY, 8) == 0)
	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		binary_file = true;

		// ハッシュチェック
		ReadBuf(b, hash1, sizeof(hash1));

		Hash(hash2, ((UCHAR *)b->Buf) + 8 + SHA1_SIZE, b->Size - 8 - SHA1_SIZE, true);

		if (Cmp(hash1, hash2, SHA1_SIZE) != 0)
		{
			// 破損ファイル
			invalid_file = true;
			FreeBuf(b);
			return NULL;
		}
	}

	SeekBuf(b, 0, 0);

	if (binary_file)
	{
		SeekBuf(b, 8 + SHA1_SIZE, 0);
	}

	// バッファからフォルダに変換
	if (binary_file == false)
	{
		// テキストモード
		f = CfgBufTextToFolder(b);
	}
	else
	{
		// バイナリモード
		f = CfgBufBinToFolder(b);
	}

	// メモリ解放
	Free(buf);
	FreeBuf(b);

	FileDeleteW(newfile);

	return f;
}

// Cfg のテスト
void CfgTest2(FOLDER *f, UINT n)
{
}

void CfgTest()
{
#if	0
	FOLDER *root;
	BUF *b;
	Debug("\nCFG Test Begin\n");

	root = CfgCreateFolder(NULL, TAG_ROOT);
	CfgTest2(root, 5);

	b = CfgFolderToBufText(root);
	//Print("%s\n", b->Buf);
	SeekBuf(b, 0, 0);

	CfgDeleteFolder(root);

	DumpBuf(b, "test1.config");

	root = CfgBufTextToFolder(b);

	FreeBuf(b);

	b = CfgFolderToBufText(root);
//	Print("%s\n", b->Buf);
	DumpBuf(b, "test2.config");
	FreeBuf(b);

	CfgSave(root, "test.txt");

	CfgDeleteFolder(root);

	Debug("\nCFG Test End\n");
#endif
}

// 1 行読み込む
char *CfgReadNextLine(BUF *b)
{
	char *tmp;
	char *buf;
	UINT len;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	// 次の改行までの文字数を調査
	tmp = (char *)b->Buf + b->Current;
	if ((b->Size - b->Current) == 0)
	{
		// 最後まで読んだ
		return NULL;
	}
	len = 0;
	while (true)
	{
		if (tmp[len] == 13 || tmp[len] == 10)
		{
			if (tmp[len] == 13)
			{
				if (len < (b->Size - b->Current))
				{
					len++;
				}
			}
			break;
		}
		len++;
		if (len >= (b->Size - b->Current))
		{
			break;
		}
	}

	// len だけ読み込む
	buf = ZeroMalloc(len + 1);
	ReadBuf(b, buf, len);
	SeekBuf(b, 1, 1);

	if (StrLen(buf) >= 1)
	{
		if (buf[StrLen(buf) - 1] == 13)
		{
			buf[StrLen(buf) - 1] = 0;
		}
	}

	return buf;
}

// テキストストリームを読み込む
bool CfgReadNextTextBUF(BUF *b, FOLDER *current)
{
	char *buf;
	TOKEN_LIST *token;
	char *name;
	char *string;
	char *data;
	bool ret;
	FOLDER *f;

	// 引数チェック
	if (b == NULL || current == NULL)
	{
		return false;
	}

	ret = true;

	// 1 行読み込む
	buf = CfgReadNextLine(b);
	if (buf == NULL)
	{
		return false;
	}

	// この行を解析
	token = ParseToken(buf, "\t ");
	if (token == NULL)
	{
		Free(buf);
		return false;
	}

	if (token->NumTokens >= 1)
	{
		if (!StrCmpi(token->Token[0], TAG_DECLARE))
		{
			if (token->NumTokens >= 2)
			{
				// declare
				name = CfgUnescape(token->Token[1]);

				// フォルダの作成
				f = CfgCreateFolder(current, name);

				// 次のフォルダを読み込む
				while (true)
				{
					if (CfgReadNextTextBUF(b, f) == false)
					{
						break;
					}
				}

				Free(name);
			}
		}
		if (!StrCmpi(token->Token[0], "}"))
		{
			// end
			ret = false;
		}
		if (token->NumTokens >= 3)
		{
			name = CfgUnescape(token->Token[1]);
			data = token->Token[2];

			if (!StrCmpi(token->Token[0], TAG_STRING))
			{
				// string
				wchar_t *uni;
				UINT uni_size;
				string = CfgUnescape(data);
				uni_size = CalcUtf8ToUni(string, StrLen(string));
				if (uni_size != 0)
				{
					uni = Malloc(uni_size);
					Utf8ToUni(uni, uni_size, string, StrLen(string));
					CfgAddUniStr(current, name, uni);
					Free(uni);
				}
				Free(string);
			}
			if (!StrCmpi(token->Token[0], TAG_INT))
			{
				// uint
				CfgAddInt(current, name, ToInt(data));
			}
			if (!StrCmpi(token->Token[0], TAG_INT64))
			{
				// uint64
				CfgAddInt64(current, name, ToInt64(data));
			}
			if (!StrCmpi(token->Token[0], TAG_BOOL))
			{
				// bool
				bool b = false;
				if (!StrCmpi(data, TAG_TRUE))
				{
					b = true;
				}
				else if (ToInt(data) != 0)
				{
					b = true;
				}
				CfgAddBool(current, name, b);
			}
			if (!StrCmpi(token->Token[0], TAG_BYTE))
			{
				// byte
				char *unescaped_b64 = CfgUnescape(data);
				void *tmp = Malloc(StrLen(unescaped_b64) * 4 + 64);
				int size = B64_Decode(tmp, unescaped_b64, StrLen(unescaped_b64));
				CfgAddByte(current, name, tmp, size);
				Free(tmp);
				Free(unescaped_b64);
			}

			Free(name);
		}
	}

	// トークンの解放
	FreeToken(token);

	Free(buf);

	return ret;
}

// ストリームテキストをフォルダに変換
FOLDER *CfgBufTextToFolder(BUF *b)
{
	FOLDER *f, *c;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	// root フォルダから再帰的に読み込む
	c = CfgCreateFolder(NULL, "tmp");

	while (true)
	{
		// テキストストリームを読み込む
		if (CfgReadNextTextBUF(b, c) == false)
		{
			break;
		}
	}

	// root フォルダの取得
	f = CfgGetFolder(c, TAG_ROOT);
	if (f == NULL)
	{
		// root フォルダが見つからない
		CfgDeleteFolder(c);
		return NULL;
	}

	// tmp フォルダから root への参照を削除
	Delete(c->Folders, f);
	f->Parent = NULL;

	// tmp フォルダを削除
	CfgDeleteFolder(c);

	// root フォルダを返す
	return f;
}

// 次のフォルダを読み込む
void CfgReadNextFolderBin(BUF *b, FOLDER *parent)
{
	char name[MAX_SIZE];
	FOLDER *f;
	UINT n, i;
	UINT size;
	UCHAR *buf;
	wchar_t *string;
	// 引数チェック
	if (b == NULL || parent == NULL)
	{
		return;
	}

	// フォルダ名
	ReadBufStr(b, name, sizeof(name));
	f = CfgCreateFolder(parent, name);

	// サブフォルダ数
	n = ReadBufInt(b);
	for (i = 0;i < n;i++)
	{
		// サブフォルダ
		CfgReadNextFolderBin(b, f);
	}

	// アイテム数
	n = ReadBufInt(b);
	for (i = 0;i < n;i++)
	{
		UINT type;

		// 名前
		ReadBufStr(b, name, sizeof(name));
		// 種類
		type = ReadBufInt(b);

		switch (type)
		{
		case ITEM_TYPE_INT:
			// int
			CfgAddInt(f, name, ReadBufInt(b));
			break;

		case ITEM_TYPE_INT64:
			// int64
			CfgAddInt64(f, name, ReadBufInt64(b));
			break;

		case ITEM_TYPE_BYTE:
			// data
			size = ReadBufInt(b);
			buf = ZeroMalloc(size);
			ReadBuf(b, buf, size);
			CfgAddByte(f, name, buf, size);
			Free(buf);
			break;

		case ITEM_TYPE_STRING:
			// string
			size = ReadBufInt(b);
			buf = ZeroMalloc(size + 1);
			ReadBuf(b, buf, size);
			string = ZeroMalloc(CalcUtf8ToUni(buf, StrLen(buf)) + 4);
			Utf8ToUni(string, 0, buf, StrLen(buf));
			CfgAddUniStr(f, name, string);
			Free(string);
			Free(buf);
			break;

		case ITEM_TYPE_BOOL:
			// bool
			CfgAddBool(f, name, ReadBufInt(b) == 0 ? false : true);
			break;
		}
	}
}

// バイナリをフォルダに変換
FOLDER *CfgBufBinToFolder(BUF *b)
{
	FOLDER *f, *c;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	// 一時フォルダを作成
	c = CfgCreateFolder(NULL, "tmp");

	// バイナリを読み込む
	CfgReadNextFolderBin(b, c);

	// root の取得
	f = CfgGetFolder(c, TAG_ROOT);
	if (f == NULL)
	{
		// 見つからない
		CfgDeleteFolder(c);
		return NULL;
	}

	Delete(c->Folders, f);
	f->Parent = NULL;

	CfgDeleteFolder(c);

	return f;
}

// フォルダをバイナリに変換
BUF *CfgFolderToBufBin(FOLDER *f)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// ヘッダ
	WriteBuf(b, TAG_BINARY, 8);

	// ハッシュ領域
	Zero(hash, sizeof(hash));
	WriteBuf(b, hash, sizeof(hash));

	// ルートフォルダを出力 (再帰)
	CfgOutputFolderBin(b, f);

	// ハッシュ
	Hash(((UCHAR *)b->Buf) + 8, ((UCHAR *)b->Buf) + 8 + SHA1_SIZE, b->Size - 8 - SHA1_SIZE, true);

	return b;
}

// フォルダをストリームテキストに変換
BUF *CfgFolderToBufText(FOLDER *f)
{
	return CfgFolderToBufTextEx(f, false);
}
BUF *CfgFolderToBufTextEx(FOLDER *f, bool no_banner)
{
	BUF *b;
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	// ストリーム作成
	b = NewBuf();

	// 著作権情報
	if (no_banner == false)
	{
		WriteBuf(b, TAG_CPYRIGHT, StrLen(TAG_CPYRIGHT));
	}

	// ルートフォルダを出力 (再帰)
	CfgOutputFolderText(b, f, 0);

	return b;
}

// フォルダ内容を出力 (フォルダを列挙)
bool CfgEnumFolderProc(FOLDER *f, void *param)
{
	CFG_ENUM_PARAM *p;
	// 引数チェック
	if (f == NULL || param == NULL)
	{
		return false;
	}

	p = (CFG_ENUM_PARAM *)param;
	// フォルダ内容を出力 (再帰)
	CfgOutputFolderText(p->b, f, p->depth);

	return true;
}

// アイテム内容を出力 (列挙)
bool CfgEnumItemProc(ITEM *t, void *param)
{
	CFG_ENUM_PARAM *p;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return false;
	}

	p = (CFG_ENUM_PARAM *)param;
	CfgAddItemText(p->b, t, p->depth);

	return true;
}

// フォルダ内容を出力 (再帰、バイナリ)
void CfgOutputFolderBin(BUF *b, FOLDER *f)
{
	UINT i;
	// 引数チェック
	if (b == NULL || f == NULL)
	{
		return;
	}

	// フォルダ名
	WriteBufStr(b, f->Name);

	// サブフォルダ個数
	WriteBufInt(b, LIST_NUM(f->Folders));

	// サブフォルダ
	for (i = 0;i < LIST_NUM(f->Folders);i++)
	{
		FOLDER *sub = LIST_DATA(f->Folders, i);
		CfgOutputFolderBin(b, sub);

		if ((i % 100) == 99)
		{
			YieldCpu();
		}
	}

	// アイテム個数
	WriteBufInt(b, LIST_NUM(f->Items));

	// アイテム
	for (i = 0;i < LIST_NUM(f->Items);i++)
	{
		char *utf8;
		UINT utf8_size;
		ITEM *t = LIST_DATA(f->Items, i);

		// アイテム名
		WriteBufStr(b, t->Name);

		// 型
		WriteBufInt(b, t->Type);

		switch (t->Type)
		{
		case ITEM_TYPE_INT:
			// 整数
			WriteBufInt(b, *((UINT *)t->Buf));
			break;

		case ITEM_TYPE_INT64:
			// 64bit 整数
			WriteBufInt64(b, *((UINT64 *)t->Buf));
			break;

		case ITEM_TYPE_BYTE:
			// データサイズ
			WriteBufInt(b, t->size);
			// データ
			WriteBuf(b, t->Buf, t->size);
			break;

		case ITEM_TYPE_STRING:
			// 文字列
			utf8_size = CalcUniToUtf8((wchar_t *)t->Buf) + 1;
			utf8 = ZeroMalloc(utf8_size);
			UniToUtf8(utf8, utf8_size, (wchar_t *)t->Buf);
			WriteBufInt(b, StrLen(utf8));
			WriteBuf(b, utf8, StrLen(utf8));
			Free(utf8);
			break;

		case ITEM_TYPE_BOOL:
			// ブール型
			if (*((bool *)t->Buf) == false)
			{
				WriteBufInt(b, 0);
			}
			else
			{
				WriteBufInt(b, 1);
			}
			break;
		}
	}
}

// フォルダ内容を出力 (再帰、テキスト)
void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth)
{
	CFG_ENUM_PARAM p;
	// 引数チェック
	if (b == NULL || f == NULL)
	{
		return;
	}

	// フォルダの開始を出力
	CfgAddDeclare(b, f->Name, depth);
	depth++;

	Zero(&p, sizeof(CFG_ENUM_PARAM));
	p.depth = depth;
	p.b = b;
	p.f = f;

	// アイテム一覧を列挙
	CfgEnumItem(f, CfgEnumItemProc, &p);

	if (LIST_NUM(f->Folders) != 0 && LIST_NUM(f->Items) != 0)
	{
		WriteBuf(b, "\r\n", 2);
	}

	// フォルダ一覧を列挙
	CfgEnumFolder(f, CfgEnumFolderProc, &p);
	// フォルダの終了を出力
	depth--;
	CfgAddEnd(b, depth);

	//WriteBuf(b, "\r\n", 2);
}

// アイテム内容を出力
void CfgAddItemText(BUF *b, ITEM *t, UINT depth)
{
	char *data;
	char *sub = NULL;
	UINT len;
	UINT size;
	char *utf8;
	UINT utf8_size;
	wchar_t *string;
	// 引数チェック
	if (b == NULL || t == NULL)
	{
		return;
	}

	// データ種類別に処理をする
	data = NULL;
	switch (t->Type)
	{
	case ITEM_TYPE_INT:
		data = Malloc(32);
		ToStr(data, *((UINT *)t->Buf));
		break;

	case ITEM_TYPE_INT64:
		data = Malloc(64);
		ToStr64(data, *((UINT64 *)t->Buf));
		break;

	case ITEM_TYPE_BYTE:
		data = ZeroMalloc(t->size * 4 + 32);
		len = B64_Encode(data, t->Buf, t->size);
		data[len] = 0;
		break;

	case ITEM_TYPE_STRING:
		string = t->Buf;
		utf8_size = CalcUniToUtf8(string);
		utf8_size++;
		utf8 = ZeroMalloc(utf8_size);
		utf8[0] = 0;
		UniToUtf8(utf8, utf8_size, string);
		size = utf8_size;
		data = utf8;
		break;

	case ITEM_TYPE_BOOL:
		size = 32;
		data = Malloc(size);
		if (*((bool *)t->Buf) == false)
		{
			StrCpy(data, size, TAG_FALSE);
		}
		else
		{
			StrCpy(data, size, TAG_TRUE);
		}
		break;
	}
	if (data == NULL)
	{
		return;
	}

	// データ行を出力
	CfgAddData(b, t->Type, t->Name, data, sub, depth);

	// メモリ解放
	Free(data);
	if (sub != NULL)
	{
		Free(sub);
	}
}

// データ行を出力
void CfgAddData(BUF *b, UINT type, char *name, char *data, char *sub, UINT depth)
{
	char *tmp;
	char *name2;
	char *data2;
	char *sub2 = NULL;
	UINT tmp_size;
	// 引数チェック
	if (b == NULL || type == 0 || name == NULL || data == NULL)
	{
		return;
	}

	name2 = CfgEscape(name);
	data2 = CfgEscape(data);
	if (sub != NULL)
	{
		sub2 = CfgEscape(sub);
	}

	tmp_size = StrLen(name2) + StrLen(data2) + 2 + 64 + 1;
	tmp = Malloc(tmp_size);

	if (sub2 != NULL)
	{
		StrCpy(tmp, tmp_size, CfgTypeToStr(type));
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, name2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, data2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, sub2);
	}
	else
	{
		StrCpy(tmp, tmp_size, CfgTypeToStr(type));
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, name2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, data2);
	}

	Free(name2);
	Free(data2);
	if (sub2 != NULL)
	{
		Free(sub2);
	}
	CfgAddLine(b, tmp, depth);
	Free(tmp);
}

// データ種類文字列を整数値に変換
UINT CfgStrToType(char *str)
{
	if (!StrCmpi(str, TAG_INT)) return ITEM_TYPE_INT;
	if (!StrCmpi(str, TAG_INT64)) return ITEM_TYPE_INT64;
	if (!StrCmpi(str, TAG_BYTE)) return ITEM_TYPE_BYTE;
	if (!StrCmpi(str, TAG_STRING)) return ITEM_TYPE_STRING;
	if (!StrCmpi(str, TAG_BOOL)) return ITEM_TYPE_BOOL;
	return 0;
}

// データの種類を文字列に変換
char *CfgTypeToStr(UINT type)
{
	switch (type)
	{
	case ITEM_TYPE_INT:
		return TAG_INT;
	case ITEM_TYPE_INT64:
		return TAG_INT64;
	case ITEM_TYPE_BYTE:
		return TAG_BYTE;
	case ITEM_TYPE_STRING:
		return TAG_STRING;
	case ITEM_TYPE_BOOL:
		return TAG_BOOL;
	}
	return NULL;
}

// End 行を出力
void CfgAddEnd(BUF *b, UINT depth)
{
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	CfgAddLine(b, "}", depth);
//	CfgAddLine(b, TAG_END, depth);
}

// Declare 行を出力
void CfgAddDeclare(BUF *b, char *name, UINT depth)
{
	char *tmp;
	char *name2;
	UINT tmp_size;
	// 引数チェック
	if (b == NULL || name == NULL)
	{
		return;
	}

	name2 = CfgEscape(name);

	tmp_size = StrLen(name2) + 2 + StrLen(TAG_DECLARE);
	tmp = Malloc(tmp_size);

	Format(tmp, 0, "%s %s", TAG_DECLARE, name2);
	CfgAddLine(b, tmp, depth);
	CfgAddLine(b, "{", depth);
	Free(tmp);
	Free(name2);
}

// 1 行を出力
void CfgAddLine(BUF *b, char *str, UINT depth)
{
	UINT i;
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	for (i = 0;i < depth;i++)
	{
		WriteBuf(b, "\t", 1);
	}
	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, "\r\n", 2);
}

// フォルダをストリームに変換
BUF *CfgFolderToBuf(FOLDER *f, bool textmode)
{
	return CfgFolderToBufEx(f, textmode, false);
}
BUF *CfgFolderToBufEx(FOLDER *f, bool textmode, bool no_banner)
{
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	if (textmode)
	{
		return CfgFolderToBufTextEx(f, no_banner);
	}
	else
	{
		return CfgFolderToBufBin(f);;
	}
}

// 文字列のエスケープ復元
char *CfgUnescape(char *str)
{
	char *tmp;
	char *ret;
	char tmp2[16];
	UINT len, wp, i;
	UINT code;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp = ZeroMalloc(len + 1);
	wp = 0;
	if (len == 1 && str[0] == '$')
	{
		// 空文字
		tmp[0] = 0;
	}
	else
	{
		for (i = 0;i < len;i++)
		{
			if (str[i] != '$')
			{
				tmp[wp++] = str[i];
			}
			else
			{
				tmp2[0] = '0';
				tmp2[1] = 'x';
				tmp2[2] = str[i + 1];
				tmp2[3] = str[i + 2];
				i += 2;
				tmp2[4] = 0;
				code = ToInt(tmp2);
				tmp[wp++] = (char)code;
			}
		}
	}
	ret = Malloc(StrLen(tmp) + 1);
	StrCpy(ret, StrLen(tmp) + 1, tmp);
	Free(tmp);
	return ret;
}

// 文字列のエスケープ
char *CfgEscape(char *str)
{
	char *tmp;
	char *ret;
	char tmp2[16];
	UINT len;
	UINT wp, i;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp = ZeroMalloc(len * 3 + 2);
	if (len == 0)
	{
		// 空文字
		StrCpy(tmp, (len * 3 + 2), "$");
	}
	else
	{
		// 空文字以外
		wp = 0;
		for (i = 0;i < len;i++)
		{
			if (CfgCheckCharForName(str[i]))
			{
				tmp[wp++] = str[i];
			}
			else
			{
				tmp[wp++] = '$';
				Format(tmp2, sizeof(tmp2), "%02X", (UINT)str[i]);
				tmp[wp++] = tmp2[0];
				tmp[wp++] = tmp2[1];
			}
		}
	}
	ret = Malloc(StrLen(tmp) + 1);
	StrCpy(ret, 0, tmp);
	Free(tmp);
	return ret;
}

// 名前に使用することができる文字かどうかチェック
bool CfgCheckCharForName(char c)
{
	if (c >= 0 && c <= 31)
	{
		return false;
	}
	if (c == ' ' || c == '\t')
	{
		return false;
	}
	if (c == '$')
	{
		return false;
	}
	return true;
}

// string 型の値の取得
bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size)
{
	wchar_t *tmp;
	UINT tmp_size;
	// 引数チェック
	if (f == NULL || name == NULL || str == NULL)
	{
		return false;
	}

	str[0] = 0;

	// unicode 文字列を一時的に取得する
	tmp_size = size * 4 + 10; // 一応これくらいとっておく
	tmp = Malloc(tmp_size);
	if (CfgGetUniStr(f, name, tmp, tmp_size) == false)
	{
		// 失敗
		Free(tmp);
		return false;
	}

	// ANSI 文字列にコピー
	UniToStr(str, size, tmp);
	Free(tmp);

	return true;
}

// unicode_string 型の値の取得
bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size)
{
	ITEM *t;
	// 引数チェック
	if (f == NULL || name == NULL || str == NULL)
	{
		return false;
	}

	str[0] = 0;

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return false;
	}
	if (t->Type != ITEM_TYPE_STRING)
	{
		return false;
	}
	UniStrCpy(str, size, t->Buf);
	return true;
}

// フォルダの存在を確認
bool CfgIsFolder(FOLDER *f, char *name)
{
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return false;
	}

	return (CfgGetFolder(f, name) == NULL) ? false : true;
}

// アイテムの存在を確認
bool CfgIsItem(FOLDER *f, char *name)
{
	ITEM *t;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return false;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return false;
	}

	return true;
}

// byte[] 型を BUF で取得
BUF *CfgGetBuf(FOLDER *f, char *name)
{
	ITEM *t;
	BUF *b;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, t->Buf, t->size);
	SeekBuf(b, 0, 0);

	return b;
}

// byte[] 型の値の取得
UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size)
{
	ITEM *t;
	// 引数チェック
	if (f == NULL || name == NULL || buf == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_BYTE)
	{
		return 0;
	}
	if (t->size <= size)
	{
		Copy(buf, t->Buf, t->size);
		return t->size;
	}
	else
	{
		Copy(buf, t->Buf, size);
		return t->size;
	}
}

// int64 型の値の取得
UINT64 CfgGetInt64(FOLDER *f, char *name)
{
	ITEM *t;
	UINT64 *ret;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_INT64)
	{
		return 0;
	}
	if (t->size != sizeof(UINT64))
	{
		return 0;
	}

	ret = (UINT64 *)t->Buf;
	return *ret;
}

// bool 型の値の取得
bool CfgGetBool(FOLDER *f, char *name)
{
	ITEM *t;
	bool *ret;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_BOOL)
	{
		return 0;
	}
	if (t->size != sizeof(bool))
	{
		return 0;
	}

	ret = (bool *)t->Buf;
	if (*ret == false)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// int 型の値の取得
UINT CfgGetInt(FOLDER *f, char *name)
{
	ITEM *t;
	UINT *ret;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_INT)
	{
		return 0;
	}
	if (t->size != sizeof(UINT))
	{
		return 0;
	}

	ret = (UINT *)t->Buf;
	return *ret;
}

// アイテムの検索
ITEM *CfgFindItem(FOLDER *parent, char *name)
{
	ITEM *t, tt;
	// 引数チェック
	if (parent == NULL || name == NULL)
	{
		return NULL;
	}

	tt.Name = ZeroMalloc(StrLen(name) + 1);
	StrCpy(tt.Name, 0, name);
	t = Search(parent->Items, &tt);
	Free(tt.Name);

	return t;
}

// フォルダの取得
FOLDER *CfgGetFolder(FOLDER *parent, char *name)
{
	return CfgFindFolder(parent, name);
}

// フォルダの検索
FOLDER *CfgFindFolder(FOLDER *parent, char *name)
{
	FOLDER *f, ff;
	// 引数チェック
	if (parent == NULL || name == NULL)
	{
		return NULL;
	}

	ff.Name = ZeroMalloc(StrLen(name) + 1);
	StrCpy(ff.Name, 0, name);
	f = Search(parent->Folders, &ff);
	Free(ff.Name);

	return f;
}

// string 型の追加
ITEM *CfgAddStr(FOLDER *f, char *name, char *str)
{
	wchar_t *tmp;
	UINT tmp_size;
	ITEM *t;
	// 引数チェック
	if (f == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	// Unicode 文字列に変換
	tmp_size = CalcStrToUni(str);
	if (tmp_size == 0)
	{
		return NULL;
	}
	tmp = Malloc(tmp_size);
	StrToUni(tmp, tmp_size, str);
	t = CfgAddUniStr(f, name, tmp);
	Free(tmp);

	return t;
}

// unicode_string 型の追加
ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str)
{
	// 引数チェック
	if (f == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	return CfgCreateItem(f, name, ITEM_TYPE_STRING, str, UniStrSize(str));
}

// バイナリの追加
ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b)
{
	// 引数チェック
	if (f == NULL || name == NULL || b == NULL)
	{
		return NULL;
	}
	return CfgAddByte(f, name, b->Buf, b->Size);
}

// バイト型の追加
ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size)
{
	// 引数チェック
	if (f == NULL || name == NULL || buf == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_BYTE, buf, size);
}

// 64bit 整数型の追加
ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i)
{
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_INT64, &i, sizeof(UINT64));
}

// IP アドレス型の取得
bool CfgGetIp(FOLDER *f, char *name, struct IP *ip)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (f == NULL || name == NULL || ip == NULL)
	{
		return false;
	}

	Zero(ip, sizeof(IP));

	if (CfgGetStr(f, name, tmp, sizeof(tmp)) == false)
	{
		return false;
	}

	if (StrToIP(ip, tmp) == false)
	{
		return false;
	}

	return true;
}
UINT CfgGetIp32(FOLDER *f, char *name)
{
	IP p;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	if (CfgGetIp(f, name, &p) == false)
	{
		return 0;
	}

	return IPToUINT(&p);
}
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr)
{
	IP ip;
	// 引数チェック
	Zero(addr, sizeof(IPV6_ADDR));
	if (f == NULL || name == NULL || addr == NULL)
	{
		return false;
	}

	if (CfgGetIp(f, name, &ip) == false)
	{
		return false;
	}

	if (IsIP6(&ip) == false)
	{
		return false;
	}

	if (IPToIPv6Addr(addr, &ip) == false)
	{
		return false;
	}

	return true;
}

// IP アドレス型の追加
ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (f == NULL || name == NULL || ip == NULL)
	{
		return NULL;
	}

	IPToStr(tmp, sizeof(tmp), ip);

	return CfgAddStr(f, name, tmp);
}
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip)
{
	IP p;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	UINTToIP(&p, ip);

	return CfgAddIp(f, name, &p);
}
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr)
{
	IP ip;
	// 引数チェック
	if (f == NULL || name == NULL || addr == NULL)
	{
		return NULL;
	}

	IPv6AddrToIP(&ip, addr);

	return CfgAddIp(f, name, &ip);
}

// 整数型の追加
ITEM *CfgAddInt(FOLDER *f, char *name, UINT i)
{
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_INT, &i, sizeof(UINT));
}

// bool 型の追加
ITEM *CfgAddBool(FOLDER *f, char *name, bool b)
{
	bool v;
	// 引数チェック
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	v = b ? 1 : 0;
	return CfgCreateItem(f, name, ITEM_TYPE_BOOL, &b, sizeof(bool));
}

// アイテム名の比較関数
int CmpItemName(void *p1, void *p2)
{
	ITEM *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(ITEM **)p1;
	f2 = *(ITEM **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	return StrCmpi(f1->Name, f2->Name);
}

// フォルダ名の比較関数
int CmpFolderName(void *p1, void *p2)
{
	FOLDER *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(FOLDER **)p1;
	f2 = *(FOLDER **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	return StrCmpi(f1->Name, f2->Name);
}

// アイテムの列挙
void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param)
{
	UINT i;
	// 引数チェック
	if (f == NULL || proc == NULL)
	{
		return;
	}
	
	for (i = 0;i < LIST_NUM(f->Items);i++)
	{
		ITEM *tt = LIST_DATA(f->Items, i);
		if (proc(tt, param) == false)
		{
			break;
		}
	}
}

// フォルダを列挙してトークンリストに格納
TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f)
{
	TOKEN_LIST *t, *ret;
	UINT i;
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(f->Folders);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = LIST_DATA(f->Folders, i);
		t->Token[i] = CopyStr(ff->Name);
	}

	ret = UniqueToken(t);
	FreeToken(t);

	return ret;
}

// アイテムを列挙してトークンリストに格納
TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f)
{
	TOKEN_LIST *t, *ret;
	UINT i;
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(f->Items);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = LIST_DATA(f->Items, i);
		t->Token[i] = CopyStr(ff->Name);
	}

	ret = UniqueToken(t);
	FreeToken(t);

	return ret;
}

// フォルダの列挙
void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param)
{
	UINT i;
	// 引数チェック
	if (f == NULL || proc == NULL)
	{
		return;
	}
	
	for (i = 0;i < LIST_NUM(f->Folders);i++)
	{
		FOLDER *ff = LIST_DATA(f->Folders, i);
		if (proc(ff, param) == false)
		{
			break;
		}

		if ((i % 100) == 99)
		{
			YieldCpu();
		}
	}
}

// アイテムの作成
ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size)
{
	UINT name_size;
	ITEM *t;
#ifdef	CHECK_CFG_NAME_EXISTS
	ITEM tt;
#endif	// CHECK_CFG_NAME_EXISTS
	// 引数チェック
	if (parent == NULL || name == NULL || type == 0 || buf == NULL)
	{
		return NULL;
	}

	name_size = StrLen(name) + 1;

#ifdef	CHECK_CFG_NAME_EXISTS

	// すでに同名のアイテムが無いかどうか確認
	tt.Name = ZeroMalloc(name_size);
	StrCpy(tt.Name, 0, name);
	t = Search(parent->Items, &tt);
	Free(tt.Name);
	if (t != NULL)
	{
		// 重複している
		return NULL;
	}

#endif	// CHECK_CFG_NAME_EXISTS

	t = ZeroMalloc(sizeof(ITEM));
	t->Buf = Malloc(size);
	Copy(t->Buf, buf, size);
	t->Name = ZeroMalloc(name_size);
	StrCpy(t->Name, 0, name);
	t->Type = type;
	t->size = size;
	t->Parent = parent;
	
	// 親のリストに追加
	Insert(parent->Items, t);

	return t;
}

// アイテムの削除
void CfgDeleteItem(ITEM *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// 親のリストから削除
	Delete(t->Parent->Items, t);

	// メモリ解放
	Free(t->Buf);
	Free(t->Name);
	Free(t);
}


// フォルダの削除
void CfgDeleteFolder(FOLDER *f)
{
	FOLDER **ff;
	ITEM **tt;
	UINT num, i;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	// サブフォルダをすべて削除
	num = LIST_NUM(f->Folders);
	ff = Malloc(sizeof(FOLDER *) * num);
	Copy(ff, f->Folders->p, sizeof(FOLDER *) * num);
	for (i = 0;i < num;i++)
	{
		CfgDeleteFolder(ff[i]);
	}
	Free(ff);

	// アイテムをすべて削除
	num = LIST_NUM(f->Items);
	tt = Malloc(sizeof(ITEM *) * num);
	Copy(tt, f->Items->p, sizeof(ITEM *) * num);
	for (i = 0;i < num;i++)
	{
		CfgDeleteItem(tt[i]);
	}
	Free(tt);

	// メモリ解放
	Free(f->Name);
	// 親のリストから削除
	if (f->Parent != NULL)
	{
		Delete(f->Parent->Folders, f);
	}
	// リストの解放
	ReleaseList(f->Folders);
	ReleaseList(f->Items);

	// 本体のメモリの解放
	Free(f);
}

// ルートの作成
FOLDER *CfgCreateRoot()
{
	return CfgCreateFolder(NULL, TAG_ROOT);
}

// フォルダの作成
FOLDER *CfgCreateFolder(FOLDER *parent, char *name)
{
	UINT size;
	FOLDER *f;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	size = StrLen(name) + 1;

#ifdef	CHECK_CFG_NAME_EXISTS

	// 親のリストの名前を検査
	if (parent != NULL)
	{
		FOLDER ff;
		ff.Name = ZeroMalloc(size);
		StrCpy(ff.Name, 0, name);
		f = Search(parent->Folders, &ff);
		Free(ff.Name);
		if (f != NULL)
		{
			// 既に同じ名前のフォルダが存在する
			return NULL;
		}
	}

#endif	// CHECK_CFG_NAME_EXISTS

	f = ZeroMalloc(sizeof(FOLDER));
	f->Items = NewListFast(CmpItemName);
	f->Folders = NewListFast(CmpFolderName);
	f->Name = ZeroMalloc(size);
	StrCpy(f->Name, 0, name);
	f->Parent = parent;

	// 親のリストに追加
	if (f->Parent != NULL)
	{
		Insert(f->Parent->Folders, f);
	}
	return f;
}


