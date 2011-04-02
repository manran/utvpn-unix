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

// Cfg.h
// Cfg.c のヘッダ

#ifndef	CFG_H
#define	CFG_H

// マクロ
//#define	CHECK_CFG_NAME_EXISTS			// 既存の名前との重複チェックを行う

#define	SAVE_BINARY_FILE_NAME_SWITCH	L"@save_binary"

// 定数
#define	TAG_DECLARE			"declare"
#define	TAG_STRING			"string"
#define	TAG_INT				"uint"
#define	TAG_INT64			"uint64"
#define	TAG_BOOL			"bool"
#define	TAG_BYTE			"byte"
#define	TAG_TRUE			"true"
#define	TAG_FALSE			"false"
#define	TAG_END				"end"
#define	TAG_ROOT			"root"

#define	TAG_CPYRIGHT		"\xef\xbb\xbf# SoftEther UT-VPN Software Configuration File\r\n# \r\n# You can edit this file when the program is not working.\r\n# \r\n"
#define	TAG_BINARY			"SEVPN_DB"

// データ型
#define	ITEM_TYPE_INT		1		// int
#define	ITEM_TYPE_INT64		2		// int64
#define	ITEM_TYPE_BYTE		3		// byte
#define	ITEM_TYPE_STRING	4		// string
#define	ITEM_TYPE_BOOL		5		// bool

// フォルダ
struct FOLDER
{
	char *Name;				// フォルダ名
	LIST *Items;			// アイテムのリスト
	LIST *Folders;			// サブフォルダ
	struct FOLDER *Parent;	// 親フォルダ
};

// アイテム
struct ITEM
{
	char *Name;				// アイテム名
	UINT Type;				// データ型
	void *Buf;				// データ
	UINT size;				// データサイズ
	FOLDER *Parent;			// 親フォルダ
};

// 設定ファイルリーダライタ
struct CFG_RW
{
	LOCK *lock;				// ロック
	char *FileName;			// ファイル名 (ANSI)
	wchar_t *FileNameW;		// ファイル名 (Unicode)
	IO *Io;					// IO
	UCHAR LashHash[SHA1_SIZE];	// 最後に書き込んだハッシュ値
	bool DontBackup;		// バックアップを使用しない
};

typedef bool (*ENUM_FOLDER)(FOLDER *f, void *param);
typedef bool (*ENUM_ITEM)(ITEM *t, void *param);

// 列挙用のパラメータ
struct CFG_ENUM_PARAM
{
	BUF *b;
	FOLDER *f;
	UINT depth;
};

int CmpItemName(void *p1, void *p2);
int CmpFolderName(void *p1, void *p2);
ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size);
void CfgDeleteFolder(FOLDER *f);
FOLDER *CfgCreateFolder(FOLDER *parent, char *name);
void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param);
TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f);
TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f);
void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param);
FOLDER *CfgFindFolder(FOLDER *parent, char *name);
ITEM *CfgFindItem(FOLDER *parent, char *name);
ITEM *CfgAddInt(FOLDER *f, char *name, UINT i);
ITEM *CfgAddBool(FOLDER *f, char *name, bool b);
ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i);
ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size);
ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b);
ITEM *CfgAddStr(FOLDER *f, char *name, char *str);
ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str);
FOLDER *CfgGetFolder(FOLDER *parent, char *name);
UINT CfgGetInt(FOLDER *f, char *name);
bool CfgGetBool(FOLDER *f, char *name);
UINT64 CfgGetInt64(FOLDER *f, char *name);
UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size);
BUF *CfgGetBuf(FOLDER *f, char *name);
bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size);
bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size);
bool CfgIsItem(FOLDER *f, char *name);
bool CfgIsFolder(FOLDER *f, char *name);
void CfgTest();
void CfgTest2(FOLDER *f, UINT n);
char *CfgEscape(char *name);
bool CfgCheckCharForName(char c);
char *CfgUnescape(char *str);
BUF *CfgFolderToBuf(FOLDER *f, bool textmode);
BUF *CfgFolderToBufEx(FOLDER *f, bool textmode, bool no_banner);
BUF *CfgFolderToBufText(FOLDER *f);
BUF *CfgFolderToBufTextEx(FOLDER *f, bool no_banner);
BUF *CfgFolderToBufBin(FOLDER *f);
void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth);
void CfgOutputFolderBin(BUF *b, FOLDER *f);
void CfgAddLine(BUF *b, char *str, UINT depth);
void CfgAddDeclare(BUF *b, char *name, UINT depth);
void CfgAddEnd(BUF *b, UINT depth);
void CfgAddData(BUF *b, UINT type, char *name, char *data, char *sub, UINT depth);
UINT CfgStrToType(char *str);
char *CfgTypeToStr(UINT type);
void CfgAddItemText(BUF *b, ITEM *t, UINT depth);
bool CfgEnumFolderProc(FOLDER *f, void *param);
bool CfgEnumItemProc(ITEM *t, void *param);
FOLDER *CfgBufTextToFolder(BUF *b);
FOLDER *CfgBufBinToFolder(BUF *b);
void CfgReadNextFolderBin(BUF *b, FOLDER *parent);
char *CfgReadNextLine(BUF *b);
bool CfgReadNextTextBuf(BUF *b, FOLDER *current);
void CfgSave(FOLDER *f, char *name);
void CfgSaveW(FOLDER *f, wchar_t *name);
bool CfgSaveEx(CFG_RW *rw, FOLDER *f, char *name);
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name);
bool CfgSaveExW2(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size);
FOLDER *CfgRead(char *name);
FOLDER *CfgReadW(wchar_t *name);
FOLDER *CfgCreateRoot();
void CfgTest();
void CfgTest2(FOLDER *f, UINT n);
CFG_RW *NewCfgRw(FOLDER **root, char *cfg_name);
CFG_RW *NewCfgRwW(FOLDER **root, wchar_t *cfg_name);
CFG_RW *NewCfgRwEx(FOLDER **root, char *cfg_name, bool dont_backup);
CFG_RW *NewCfgRwExW(FOLDER **root, wchar_t *cfg_name, bool dont_backup);
UINT SaveCfgRw(CFG_RW *rw, FOLDER *f);
void FreeCfgRw(CFG_RW *rw);
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip);
UINT CfgGetIp32(FOLDER *f, char *name);
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
bool FileCopy(char *src, char *dst);
bool FileCopyW(wchar_t *src, wchar_t *dst);
void BackupCfg(FOLDER *f, char *original);
void BackupCfgW(FOLDER *f, wchar_t *original);

#if	(!defined(CFG_C)) || (!defined(OS_UNIX))
bool CfgGetIp(FOLDER *f, char *name, struct IP *ip);
ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip);
#endif

#endif	// CFG_H



