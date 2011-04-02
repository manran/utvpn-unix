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

// Secure.h
// Secure.c のヘッダ

#ifndef	SECURE_H
#define	SECURE_H

// 定数
#define	MAX_SEC_DATA_SIZE		4096

// PKCS#11 関係の型宣言
#ifndef	SECURE_C
typedef struct CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef struct SEC_DATA_WIN32	SEC_DATA_WIN32;
typedef struct CK_TOKEN_INFO	CK_TOKEN_INFO;
typedef struct CK_DATE			CK_DATE;
#endif	// SECURE_C

// セキュアデバイス
struct SECURE_DEVICE
{
	UINT Id;								// デバイス ID
	UINT Type;								// 種類
	char *DeviceName;						// デバイス名
	char *Manufacturer;						// 製造元
	char *ModuleName;						// モジュール名
};

// セキュアデバイスの種類
#define	SECURE_IC_CARD				0		// IC カード
#define	SECURE_USB_TOKEN			1		// USB トークン

// セキュアデバイス情報
struct SEC_INFO
{
	wchar_t *Label;							// ラベル
	wchar_t *ManufacturerId;					// 製造元 ID
	wchar_t *Model;							// モデル
	wchar_t *SerialNumber;						// シリアル番号
	UINT MaxSession;						// 最大セッション数
	UINT MaxRWSession;						// 最大 R/W セッション数
	UINT MinPinLen;							// 最小 PIN 文字列長
	UINT MaxPinLen;							// 最大 PIN 文字列長
	UINT TotalPublicMemory;					// 合計メモリ容量 (Public)
	UINT FreePublicMemory;					// 空きメモリ容量 (Private)
	UINT TotalPrivateMemory;				// 合計メモリ容量 (Public)
	UINT FreePrivateMemory;					// 空きメモリ容量 (Private)
	char *HardwareVersion;					// ハードウェアバージョン
	char *FirmwareVersion;					// ファームウェアバージョン
};

// セキュアデバイス構造体
struct SECURE
{
	LOCK *lock;								// ロック
	SECURE_DEVICE *Dev;						// デバイス情報
	UINT Error;								// 最後に発生したエラー
	struct CK_FUNCTION_LIST *Api;			// API
	bool Initialized;						// 初期化フラグ
	UINT NumSlot;							// スロット数
	UINT *SlotIdList;						// スロット ID リスト
	bool SessionCreated;					// セッション作成フラグ
	UINT SessionId;							// セッション ID
	UINT SessionSlotNumber;					// セッションのスロット ID
	bool LoginFlag;							// ログイン済みフラグ
	SEC_INFO *Info;							// トークン情報
	LIST *EnumCache;						// 列挙キャッシュ

	// ドライバごとに異なる挙動をするための属性値
	bool IsEPass1000;						// ePass 1000
	bool IsReadOnly;						// 読み取り専用モード

#ifdef	OS_WIN32
	struct SEC_DATA_WIN32 *Data;			// データ
#endif	// OS_WIN32
};

// セキュアデバイスオブジェクト構造体
struct SEC_OBJ
{
	UINT Type;								// オブジェクトの種類
	UINT Object;							// オブジェクトハンドル
	bool Private;							// プライベートフラグ
	char *Name;								// 名前
};

#define	SEC_ERROR_NOERROR				0	// エラー無し
#define	SEC_ERROR_INVALID_SLOT_NUMBER	1	// スロット番号が不正
#define	SEC_ERROR_OPEN_SESSION			2	// セッション作成失敗
#define	SEC_ERROR_SESSION_EXISTS		3	// すでにセッションが存在する
#define	SEC_ERROR_NO_PIN_STR			4	// PIN 文字列が指定されていない
#define	SEC_ERROR_ALREADY_LOGIN			5	// すでにログインしている
#define	SEC_ERROR_BAD_PIN_CODE			6	// PIN コードが不正
#define	SEC_ERROR_NO_SESSION			7	// セッションが存在しない
#define	SEC_ERROR_DATA_TOO_BIG			8	// データが大きすぎる
#define	SEC_ERROR_NOT_LOGIN				9	// ログインしていない
#define	SEC_ERROR_BAD_PARAMETER			10	// パラメータ不正
#define	SEC_ERROR_HARDWARE_ERROR		11	// ハードウェアエラー
#define	SEC_ERROR_OBJ_NOT_FOUND			12	// オブジェクトが見つからない
#define	SEC_ERROR_INVALID_CERT			13	// 証明書が不正


#define	SEC_DATA						0	// データ
#define	SEC_X							1	// 証明書
#define	SEC_K							2	// 秘密鍵
#define	SEC_P							3	// 公開鍵



// 関数プロトタイプ
void InitSecure();
void FreeSecure();
void InitSecureDeviceList();
void FreeSecureDeviceList();
bool IsDeviceSupported(SECURE_DEVICE *dev);
LIST *GetSupportedDeviceList();
LIST *GetSecureDeviceList();
bool CheckSecureDeviceId(UINT id);
SECURE_DEVICE *GetSecureDevice(UINT id);
SECURE *OpenSec(UINT id);
void CloseSec(SECURE *sec);
bool OpenSecSession(SECURE *sec, UINT slot_number);
void CloseSecSession(SECURE *sec);
bool LoginSec(SECURE *sec, char *pin);
void LogoutSec(SECURE *sec);
void PrintSecInfo(SECURE *sec);
LIST *EnumSecObject(SECURE *sec);
void FreeSecObject(SEC_OBJ *obj);
void FreeEnumSecObject(LIST *o);
SEC_OBJ *FindSecObject(SECURE *sec, char *name, UINT type);
bool CheckSecObject(SECURE *sec, char *name, UINT type);
bool DeleteSecObjectByName(SECURE *sec, char *name, UINT type);
SEC_OBJ *CloneSecObject(SEC_OBJ *obj);
LIST *CloneEnumSecObject(LIST *o);
void EraseEnumSecObjectCache(SECURE *sec);
void DeleteSecObjFromEnumCache(SECURE *sec, char *name, UINT type);
void AddSecObjToEnumCache(SECURE *sec, char *name, UINT type, bool private_obj, UINT object);
bool WriteSecData(SECURE *sec, bool private_obj, char *name, void *data, UINT size);
int ReadSecDataFromObject(SECURE *sec, SEC_OBJ *obj, void *data, UINT size);
int ReadSecData(SECURE *sec, char *name, void *data, UINT size);
bool DeleteSecObject(SECURE *sec, SEC_OBJ *obj);
bool DeleteSecData(SECURE *sec, char *name);
void UINT64ToCkDate(void *p_ck_date, UINT64 time64);
bool WriteSecCert(SECURE *sec, bool private_obj, char *name, X *x);
bool DeleteSecCert(SECURE *sec, char *name);
X *ReadSecCertFromObject(SECURE *sec, SEC_OBJ *obj);
X *ReadSecCert(SECURE *sec, char *name);
bool WriteSecKey(SECURE *sec, bool private_obj, char *name, K *k);
bool DeleteSecKey(SECURE *sec, char *name);
bool SignSecByObject(SECURE *sec, SEC_OBJ *obj, void *dst, void *src, UINT size);
bool SignSec(SECURE *sec, char *name, void *dst, void *src, UINT size);
bool ChangePin(SECURE *sec, char *old_pin, char *new_pin);
void TestSec();
void TestSecMain(SECURE *sec);
bool IsJPKI(bool id);

bool LoadSecModule(SECURE *sec);
void FreeSecModule(SECURE *sec);
void GetSecInfo(SECURE *sec);
void FreeSecInfo(SECURE *sec);
SEC_INFO *TokenInfoToSecInfo(void *p_t);
void FreeSecInfoMemory(SEC_INFO *s);

#ifdef	OS_WIN32

bool Win32IsDeviceSupported(SECURE_DEVICE *dev);
bool Win32LoadSecModule(SECURE *sec);
void Win32FreeSecModule(SECURE *sec);

#endif	// OS_WIN32


#ifdef	SECURE_C
// 内部データ構造関連

// サポートしているセキュアデバイスリスト
static LIST *SecureDeviceList = NULL;

// サポートしているハードウェアリスト
// Q. なぜこのような静的なリストになっているのか? 動的に追加できないのか?
// A. 今のところ、手抜きのためこのような実装になっている。
SECURE_DEVICE SupportedList[] =
{
	{1,		SECURE_IC_CARD,		"Standard-9 IC Card",	"Dai Nippon Printing",	"DNPS9P11.DLL"},
	{2,		SECURE_USB_TOKEN,	"ePass 1000",			"Feitian Technologies",	"EP1PK111.DLL"},
	{3,		SECURE_IC_CARD,		"DNP Felica",			"Dai Nippon Printing",	"DNPFP11.DLL"},
	{4,		SECURE_USB_TOKEN,	"eToken",				"Aladdin",				"ETPKCS11.DLL"},
	{5,		SECURE_IC_CARD,		"Standard-9 IC Card",	"Fujitsu",				"F3EZSCL2.DLL"},
	{6,		SECURE_IC_CARD,		"ASECard",				"Athena",				"ASEPKCS.DLL"},
	{7,		SECURE_IC_CARD,		"Gemplus IC Card",		"Gemplus",				"PK2PRIV.DLL"},
	{8,		SECURE_IC_CARD,		"1-Wire & iButton",		"DALLAS SEMICONDUCTOR",	"DSPKCS.DLL"},
	{9,		SECURE_IC_CARD,		"JPKI IC Card",			"Japanese Government",	"JPKIPKCS11.DLL"},
	{10,	SECURE_IC_CARD,		"LGWAN IC Card",		"Japanese Government",	"P11STD9.DLL"},
	{11,	SECURE_IC_CARD,		"LGWAN IC Card",		"Japanese Government",	"P11STD9A.DLL"},
	{12,	SECURE_USB_TOKEN,	"iKey 1000",			"Rainbow Technologies",	"K1PK112.DLL"},
	{13,	SECURE_IC_CARD,		"JPKI IC Card #2",		"Japanese Government",	"libmusclepkcs11.dll"},
	{14,	SECURE_USB_TOKEN,	"SafeSign",				"A.E.T.",				"aetpkss1.dll"},
	{15,	SECURE_USB_TOKEN,	"LOCK STAR-PKI",		"Logicaltech Co.,LTD",	"LTPKCS11.dll"},
	{16,	SECURE_USB_TOKEN,	"ePass 2000",			"Feitian Technologies",	"ep2pk11.dll"},
	{17,	SECURE_IC_CARD,		"myuToken",				"iCanal Inc.",			"icardmodpk.dll"},
};

#ifdef	OS_WIN32

// Win32 用内部データ
typedef struct SEC_DATA_WIN32
{
	HINSTANCE hInst;
} SEC_DATA_WIN32;

#endif	// OS_WIN32

#endif	// SECURE_C

#endif	// SECURE_H



