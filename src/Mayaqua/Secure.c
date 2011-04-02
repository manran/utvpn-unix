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

// Secure.c
// セキュリティトークン管理モジュール

#define	SECURE_C
#define	ENCRYPT_C

#ifdef	WIN32
#include <windows.h>
#endif	// WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <Mayaqua/Mayaqua.h>
#include <Mayaqua/cryptoki.h>


#define	MAX_OBJ				1024		// ハードウェア内の最大オブジェクト数 (想定)

#define	A_SIZE(a, i)		(a[(i)].ulValueLen)
#define	A_SET(a, i, value, size)	(a[i].pValue = value;a[i].ulValueLen = size;)

#ifdef	OS_WIN32
// Win32 用コード

// Win32 用 DLL 読み込み
HINSTANCE Win32SecureLoadLibraryEx(char *dllname, DWORD flags)
{
	char tmp1[MAX_PATH];
	char tmp2[MAX_PATH];
	char tmp3[MAX_PATH];
	HINSTANCE h;
	// 引数チェック
	if (dllname == NULL)
	{
		return NULL;
	}

	Format(tmp1, sizeof(tmp1), "%s\\%s", MsGetSystem32Dir(), dllname);
	Format(tmp2, sizeof(tmp2), "%s\\JPKI\\%s", MsGetProgramFilesDir(), dllname);
	Format(tmp3, sizeof(tmp3), "%s\\LGWAN\\%s", MsGetProgramFilesDir(), dllname);

	h = LoadLibraryEx(dllname, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	h = LoadLibraryEx(tmp1, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	h = LoadLibraryEx(tmp2, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	h = LoadLibraryEx(tmp3, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	return NULL;
}

// 指定したデバイスがインストールされているか調査
bool Win32IsDeviceSupported(SECURE_DEVICE *dev)
{
	HINSTANCE hInst;
	// 引数チェック
	if (dev == NULL)
	{
		return false;
	}

	// DLL が読み込み可能かチェック
	hInst = Win32SecureLoadLibraryEx(dev->ModuleName, DONT_RESOLVE_DLL_REFERENCES);
	if (hInst == NULL)
	{
		return false;
	}

	FreeLibrary(hInst);

	return true;
}

// デバイスモジュールの読み込み
bool Win32LoadSecModule(SECURE *sec)
{
	SEC_DATA_WIN32 *w;
	HINSTANCE hInst;
	CK_FUNCTION_LIST_PTR api = NULL;
	CK_RV (*get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}

	if (sec->Dev->Id == 9)
	{
		char username[MAX_SIZE];
		DWORD size;
		// 住基ネットのデバイスドライバでは、Software\JPKI レジストリキーの内容を
		// SYSTEM の HKLU でも持っていなければならないので、もし持っていない場合は
		// 別のユーザーの値からコピーする
//		if (MsRegIsValue(REG_CURRENT_USER, "Software\\JPKI", "Name") == false ||
//			MsRegIsValue(REG_CURRENT_USER, "Software\\JPKI", "RWType") == false)
		size = sizeof(username);
		GetUserName(username, &size);
		if (StrCmpi(username, "System") == 0)
		{
			TOKEN_LIST *t = MsRegEnumKey(REG_USERS, NULL);

			if (t != NULL)
			{
				UINT i;

				for (i = 0;i < t->NumTokens;i++)
				{
					char tmp[MAX_PATH];

					if (StrCmpi(t->Token[i], ".DEFAULT") != 0 && StrCmpi(t->Token[i], "S-1-5-18") != 0)
					{
						Format(tmp, sizeof(tmp), "%s\\Software\\JPKI", t->Token[i]);

						if (MsRegIsValue(REG_USERS, tmp, "Name") && MsRegIsValue(REG_USERS, tmp, "RWType"))
						{
							char *name = MsRegReadStr(REG_USERS, tmp, "Name");
							char *port = MsRegReadStr(REG_USERS, tmp, "Port");
							UINT type = MsRegReadInt(REG_USERS, tmp, "RWType");

							MsRegWriteStr(REG_CURRENT_USER, "Software\\JPKI", "Name", name);
							MsRegWriteStr(REG_CURRENT_USER, "Software\\JPKI", "Port", port);
							MsRegWriteInt(REG_CURRENT_USER, "Software\\JPKI", "RWType", type);

							Free(name);
							Free(port);
							break;
						}
					}
				}

				FreeToken(t);
			}
		}
	}

	// ライブラリのロード
	hInst = Win32SecureLoadLibraryEx(sec->Dev->ModuleName, 0);
	if (hInst == NULL)
	{
		// 失敗
		return false;
	}

	// API の取得
	get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
		GetProcAddress(hInst, "C_GetFunctionList");

	if (get_function_list == NULL)
	{
		// 失敗
		FreeLibrary(hInst);
		return false;
	}

	get_function_list(&api);
	if (api == NULL)
	{
		// 失敗
		FreeLibrary(hInst);
		return false;
	}

	sec->Data = ZeroMalloc(sizeof(SEC_DATA_WIN32));
	w = sec->Data;

	w->hInst = hInst;
	sec->Api = api;

	return true;
}

// デバイスモジュールのアンロード
void Win32FreeSecModule(SECURE *sec)
{
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}
	if (sec->Data == NULL)
	{
		return;
	}

	// アンロード
	FreeLibrary(sec->Data->hInst);
	Free(sec->Data);

	sec->Data = NULL;
}

#endif	// OS_WIN32


// 指定されたデバイスが JPKI かどうか
bool IsJPKI(bool id)
{
	if (id == 9 || id == 13)
	{
		return true;
	}

	return false;
}

// セキュアデバイスの秘密鍵を名前を指定して署名
bool SignSec(SECURE *sec, char *name, void *dst, void *src, UINT size)
{
	SEC_OBJ *obj;
	UINT ret;
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL || dst == NULL || src == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	obj = FindSecObject(sec, name, SEC_K);
	if (obj == NULL)
	{
		return false;
	}

	ret = SignSecByObject(sec, obj, dst, src, size);

	FreeSecObject(obj);

	return ret;
}

// セキュアデバイスの秘密鍵で署名
bool SignSecByObject(SECURE *sec, SEC_OBJ *obj, void *dst, void *src, UINT size)
{
	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
	UINT ret;
	UCHAR hash[SIGN_HASH_SIZE];
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (obj == NULL || dst == NULL || src == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (obj->Type != SEC_K)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	// ハッシュ
	HashForSign(hash, sizeof(hash), src, size);

	// 署名初期化
	ret = sec->Api->C_SignInit(sec->SessionId, &mechanism, obj->Object);
	if (ret != CKR_OK)
	{
		// 失敗
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("C_SignInit Error: 0x%x\n", ret);
		return false;
	}

	// 署名実行
	size = 128;
	ret = sec->Api->C_Sign(sec->SessionId, hash, sizeof(hash), dst, &size);
	if (ret != CKR_OK || size != 128)
	{
		// 失敗
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("C_Sign Error: 0x%x\n", ret);
		return false;
	}

	return true;
}

// PIN コードの変更
bool ChangePin(SECURE *sec, char *old_pin, char *new_pin)
{
	// 引数チェック
	if (sec == NULL || old_pin == NULL || new_pin == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (sec->IsReadOnly)
	{
		sec->Error = SEC_ERROR_OPEN_SESSION;
		return false;
	}

	// PIN 変更
	if (sec->Api->C_SetPIN(sec->SessionId, old_pin, StrLen(old_pin),
		new_pin, StrLen(new_pin)) != CKR_OK)
	{
		return false;
	}

	return true;
}

// 秘密鍵オブジェクトの書き込み
bool WriteSecKey(SECURE *sec, bool private_obj, char *name, K *k)
{
	UINT key_type = CKK_RSA;
	CK_BBOOL b_true = true, b_false = false, b_private_obj = private_obj;
	UINT obj_class = CKO_PRIVATE_KEY;
	UINT object;
	UINT ret;
	BUF *b;
	RSA *rsa;
	UCHAR modules[MAX_SIZE], pub[MAX_SIZE], pri[MAX_SIZE], prime1[MAX_SIZE], prime2[MAX_SIZE];
	CK_ATTRIBUTE a[] =
	{
		{CKA_MODULUS,			modules,		0},		// 0
		{CKA_PUBLIC_EXPONENT,	pub,			0},		// 1
		{CKA_PRIVATE_EXPONENT,	pri,			0},		// 2
		{CKA_PRIME_1,			prime1,			0},		// 3
		{CKA_PRIME_2,			prime2,			0},		// 4
		{CKA_CLASS,				&obj_class,		sizeof(obj_class)},
		{CKA_TOKEN,				&b_true,		sizeof(b_true)},
		{CKA_PRIVATE,			&b_private_obj,	sizeof(b_private_obj)},
		{CKA_LABEL,				name,			StrLen(name)},
		{CKA_KEY_TYPE,			&key_type,		sizeof(key_type)},
		{CKA_DERIVE,			&b_false,		sizeof(b_false)},
		{CKA_SUBJECT,			name,			StrLen(name)},
		{CKA_SENSITIVE,			&b_true,		sizeof(b_true)},
		{CKA_DECRYPT,			&b_true,		sizeof(b_true)},
		{CKA_SIGN,				&b_true,		sizeof(b_true)},
		{CKA_SIGN_RECOVER,		&b_false,		sizeof(b_false)},
		{CKA_EXTRACTABLE,		&b_false,		sizeof(b_false)},
		{CKA_MODIFIABLE,		&b_false,		sizeof(b_false)},
	};
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL || k == NULL || k->private_key == false)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && private_obj)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}

	// 数値データ生成
	rsa = k->pkey->pkey.rsa;
	if (rsa == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	b = BigNumToBuf(rsa->n);
	ReadBuf(b, modules, sizeof(modules));
	A_SIZE(a, 0) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(rsa->e);
	ReadBuf(b, pub, sizeof(pub));
	A_SIZE(a, 1) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(rsa->d);
	ReadBuf(b, pri, sizeof(pri));
	A_SIZE(a, 2) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(rsa->p);
	ReadBuf(b, prime1, sizeof(prime1));
	A_SIZE(a, 3) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(rsa->q);
	ReadBuf(b, prime2, sizeof(prime2));
	A_SIZE(a, 4) = b->Size;
	FreeBuf(b);

	// 古い鍵があれば削除
	if (CheckSecObject(sec, name, SEC_K))
	{
		DeleteSecKey(sec, name);
	}

	// 作成
	if ((ret = sec->Api->C_CreateObject(sec->SessionId, a, sizeof(a) / sizeof(a[0]), &object)) != CKR_OK)
	{
		// 失敗
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("ret: 0x%x\n", ret);
		return false;
	}

	// キャッシュ消去
	EraseEnumSecObjectCache(sec);

	return true;
}

// 証明書オブジェクトを名前を指定して読み込み
X *ReadSecCert(SECURE *sec, char *name)
{
	SEC_OBJ *obj;
	X *x;
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}

	// 検索
	obj = FindSecObject(sec, name, SEC_X);
	if (obj == NULL)
	{
		return false;
	}

	// 取得
	x = ReadSecCertFromObject(sec, obj);

	FreeSecObject(obj);

	return x;
}

// 証明書オブジェクトの読み込み
X *ReadSecCertFromObject(SECURE *sec, SEC_OBJ *obj)
{
	UINT size;
	X *x;
	UCHAR value[4096];
	BUF *b;
	CK_ATTRIBUTE get[] =
	{
		{CKA_VALUE,		value,		sizeof(value)},
	};
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (obj->Type != SEC_X)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	// 取得
	if (sec->Api->C_GetAttributeValue(
		sec->SessionId, obj->Object, get, sizeof(get) / sizeof(get[0])) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return 0;
	}

	size = A_SIZE(get, 0);

	// 変換
	b = NewBuf();
	WriteBuf(b, value, size);
	SeekBuf(b, 0, 0);

	x = BufToX(b, false);
	if (x == NULL)
	{
		sec->Error = SEC_ERROR_INVALID_CERT;
	}

	FreeBuf(b);

	return x;
}

// 証明書オブジェクトの書き込み
bool WriteSecCert(SECURE *sec, bool private_obj, char *name, X *x)
{
	UINT obj_class = CKO_CERTIFICATE;
	CK_BBOOL b_true = true, b_false = false, b_private_obj = private_obj;
	UINT cert_type = CKC_X_509;
	CK_DATE start_date, end_date;
	UCHAR subject[MAX_SIZE];
	UCHAR issuer[MAX_SIZE];
	wchar_t w_subject[MAX_SIZE];
	wchar_t w_issuer[MAX_SIZE];
	UCHAR serial_number[MAX_SIZE];
	UCHAR value[4096];
	UINT ret;
	BUF *b;
	UINT object;
	CK_ATTRIBUTE a[] =
	{
		{CKA_SUBJECT,			subject,		0},			// 0
		{CKA_ISSUER,			issuer,			0},			// 1
		{CKA_SERIAL_NUMBER,		serial_number,	0},			// 2
		{CKA_VALUE,				value,			0},			// 3
		{CKA_CLASS,				&obj_class,		sizeof(obj_class)},
		{CKA_TOKEN,				&b_true,		sizeof(b_true)},
		{CKA_PRIVATE,			&b_private_obj,	sizeof(b_private_obj)},
		{CKA_LABEL,				name,			StrLen(name)},
		{CKA_CERTIFICATE_TYPE,	&cert_type,		sizeof(cert_type)},
#if	0		// 失敗するトークンがあるのでこれは使わない
		{CKA_START_DATE,		&start_date,	sizeof(start_date)},
		{CKA_END_DATE,			&end_date,		sizeof(end_date)},
#endif
	};
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && private_obj)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}

	// 証明書をバッファにコピー
	b = XToBuf(x, false);
	if (b == NULL)
	{
		sec->Error = SEC_ERROR_INVALID_CERT;
		return false;
	}
	if (b->Size > sizeof(value))
	{
		// サイズが大きすぎる
		FreeBuf(b);
		sec->Error = SEC_ERROR_DATA_TOO_BIG;
		return false;
	}
	Copy(value, b->Buf, b->Size);
	A_SIZE(a, 3) = b->Size;
	FreeBuf(b);

	// Subject と Issuer を UTF-8 にエンコードして格納
	GetPrintNameFromName(w_subject, sizeof(w_subject), x->subject_name);
	UniToUtf8(subject, sizeof(subject), w_subject);
	A_SIZE(a, 0) = StrLen(subject);
	if (x->root_cert == false)
	{
		GetPrintNameFromName(w_issuer, sizeof(w_issuer), x->issuer_name);
		UniToUtf8(issuer, sizeof(issuer), w_issuer);
		A_SIZE(a, 1) = StrLen(issuer);
	}

	// シリアル番号をコピー
	Copy(serial_number, x->serial->data, MIN(x->serial->size, sizeof(serial_number)));
	A_SIZE(a, 2) = MIN(x->serial->size, sizeof(serial_number));

	// 有効期限情報
	UINT64ToCkDate(&start_date, SystemToLocal64(x->notBefore));
	UINT64ToCkDate(&end_date, SystemToLocal64(x->notAfter));

	// 同一の名前のオブジェクトがあれば削除
	if (CheckSecObject(sec, name, SEC_X))
	{
		DeleteSecCert(sec, name);
	}

	// 作成
	if ((ret = sec->Api->C_CreateObject(sec->SessionId, a, sizeof(a) / sizeof(a[0]), &object)) != CKR_OK)
	{
		// 失敗
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("Error: 0x%02x\n", ret);
		return false;
	}

	// キャッシュ消去
	EraseEnumSecObjectCache(sec);

	return true;
}

// 秘密鍵オブジェクトの削除
bool DeleteSecKey(SECURE *sec, char *name)
{
	return DeleteSecObjectByName(sec, name, SEC_K);
}

// 証明書オブジェクトの削除
bool DeleteSecCert(SECURE *sec, char *name)
{
	return DeleteSecObjectByName(sec, name, SEC_X);
}

// CK_DATE を 64 bit 時刻に変換
UINT64 CkDateToUINT64(struct CK_DATE *ck_date)
{
	SYSTEMTIME st;
	char year[32], month[32], day[32];
	// 引数チェック
	if (ck_date == NULL)
	{
		return 0;
	}

	Zero(year, sizeof(year));
	Zero(month, sizeof(month));
	Zero(day, sizeof(day));

	Copy(year, ck_date->year, 4);
	Copy(month, ck_date->month, 2);
	Copy(day, ck_date->day, 2);

	st.wYear = ToInt(year);
	st.wMonth = ToInt(month);
	st.wDay = ToInt(day);

	return SystemToUINT64(&st);
}

// 64 bit 時刻を CK_DATE に変換
void UINT64ToCkDate(void *p_ck_date, UINT64 time64)
{
	SYSTEMTIME st;
	char year[32], month[32], day[32];
	struct CK_DATE *ck_date = (CK_DATE *)p_ck_date;
	// 引数チェック
	if (ck_date == NULL)
	{
		return;
	}

	UINT64ToSystem(&st, time64);

	Format(year, sizeof(year), "%04u", st.wYear);
	Format(month, sizeof(month), "%04u", st.wMonth);
	Format(day, sizeof(day), "%04u", st.wDay);

	Zero(ck_date, sizeof(CK_DATE));

	Copy(ck_date->year, year, 4);
	Copy(ck_date->month, month, 2);
	Copy(ck_date->day, day, 2);
}

// オブジェクトを名前で指定して削除
bool DeleteSecObjectByName(SECURE *sec, char *name, UINT type)
{
	bool ret;
	SEC_OBJ *obj;
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}

	// オブジェクト取得
	obj = FindSecObject(sec, name, type);
	if (obj == NULL)
	{
		// 失敗
		return false;
	}

	// オブジェクト削除
	ret = DeleteSecObject(sec, obj);

	// メモリ解放
	FreeSecObject(obj);

	return ret;
}

// データの削除
bool DeleteSecData(SECURE *sec, char *name)
{
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	return DeleteSecObjectByName(sec, name, SEC_DATA);
}

// セキュアオブジェクトの削除
bool DeleteSecObject(SECURE *sec, SEC_OBJ *obj)
{
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (obj == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}

	// オブジェクト消去
	if (sec->Api->C_DestroyObject(sec->SessionId, obj->Object) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return false;
	}

	// キャッシュ消去
	DeleteSecObjFromEnumCache(sec, obj->Name, obj->Type);

	return true;
}

// キャッシュから指定した名前のオブジェクトを削除する
void DeleteSecObjFromEnumCache(SECURE *sec, char *name, UINT type)
{
	UINT i;
	// 引数チェック
	if (sec == NULL || name == NULL || sec->EnumCache == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(sec->EnumCache);i++)
	{
		SEC_OBJ *obj = LIST_DATA(sec->EnumCache, i);

		if (StrCmpi(obj->Name, name) == 0)
		{
			if (obj->Type == type)
			{
				Delete(sec->EnumCache, obj);
				FreeSecObject(obj);
				break;
			}
		}
	}
}

// セキュアオブジェクトを名前で検索して読み込む
int ReadSecData(SECURE *sec, char *name, void *data, UINT size)
{
	UINT ret = 0;
	SEC_OBJ *obj;
	// 引数チェック
	if (sec == NULL || name == NULL || data == NULL)
	{
		return 0;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}

	// 読み込み
	obj = FindSecObject(sec, name, SEC_DATA);
	if (obj == NULL)
	{
		// 見つからない
		return 0;
	}

	// 読み込む
	ret = ReadSecDataFromObject(sec, obj, data, size);

	FreeSecObject(obj);

	return ret;
}

// キャッシュ消去
void EraseEnumSecObjectCache(SECURE *sec)
{
	// 引数チェック
	if (sec == NULL || sec->EnumCache == NULL)
	{
		return;
	}

	FreeEnumSecObject(sec->EnumCache);
	sec->EnumCache = NULL;
}

// セキュアオブジェクトの存在をチェックする
bool CheckSecObject(SECURE *sec, char *name, UINT type)
{
	SEC_OBJ *obj;
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}

	obj = FindSecObject(sec, name, type);

	if (obj == NULL)
	{
		return false;
	}
	else
	{
		FreeSecObject(obj);
		return true;
	}
}

// セキュアオブジェクト構造体のクローンの作成
SEC_OBJ *CloneSecObject(SEC_OBJ *obj)
{
	SEC_OBJ *ret;
	// 引数チェック
	if (obj == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(SEC_OBJ));
	ret->Name = CopyStr(obj->Name);
	ret->Object = obj->Object;
	ret->Private = obj->Private;
	ret->Type = obj->Type;

	return ret;
}

// セキュアオブジェクトを名前で検索して取得する
SEC_OBJ *FindSecObject(SECURE *sec, char *name, UINT type)
{
	LIST *o;
	UINT i;
	SEC_OBJ *ret = NULL;
	// 引数チェック
	if (sec == NULL)
	{
		return NULL;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return NULL;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}

	// 列挙
	o = EnumSecObject(sec);
	if (o == NULL)
	{
		return NULL;
	}
	for (i = 0;i < LIST_NUM(o);i++)
	{
		SEC_OBJ *obj = LIST_DATA(o, i);

		if (obj->Type == type || type == INFINITE)
		{
			if (StrCmpi(obj->Name, name) == 0)
			{
				ret = CloneSecObject(obj);
				break;
			}
		}
	}
	FreeEnumSecObject(o);

	if (ret == NULL)
	{
		sec->Error = SEC_ERROR_OBJ_NOT_FOUND;
	}

	return ret;
}

// セキュアオブジェクトの読み込み
int ReadSecDataFromObject(SECURE *sec, SEC_OBJ *obj, void *data, UINT size)
{
	UCHAR buf[MAX_SEC_DATA_SIZE];
	UINT i;
	CK_ATTRIBUTE get[] =
	{
		{CKA_VALUE,	 buf,	sizeof(buf)},
	};
	// 引数チェック
	if (sec == NULL)
	{
		return 0;
	}
	if (obj == NULL || data == NULL || size == 0)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return 0;
	}
	if (obj->Type != SEC_DATA)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return 0;
	}

	// 取得
	if (sec->Api->C_GetAttributeValue(
		sec->SessionId, obj->Object, get, sizeof(get) / sizeof(get[0])) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return 0;
	}

	// 結果の返却
	i = get[0].ulValueLen;
	if (i > MAX_SEC_DATA_SIZE || i > size)
	{
		// データが大きすぎる
		sec->Error = SEC_ERROR_DATA_TOO_BIG;
		return 0;
	}

	// メモリコピー
	Copy(data, buf, i);

	return i;
}

// セキュアオブジェクトの列挙結果の解放
void FreeEnumSecObject(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SEC_OBJ *obj = LIST_DATA(o, i);

		FreeSecObject(obj);
	}

	ReleaseList(o);
}

// セキュアオブジェクトの解放
void FreeSecObject(SEC_OBJ *obj)
{
	// 引数チェック
	if (obj == NULL)
	{
		return;
	}

	Free(obj->Name);
	Free(obj);
}

// セキュアオブジェクト列挙結果のクローン
LIST *CloneEnumSecObject(LIST *o)
{
	LIST *ret;
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewListFast(NULL);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		SEC_OBJ *obj = LIST_DATA(o, i);

		Add(ret, CloneSecObject(obj));
	}

	return ret;
}

// セキュアオブジェクトの列挙
LIST *EnumSecObject(SECURE *sec)
{
	CK_BBOOL b_true = true, b_false = false;
	UINT objects[MAX_OBJ];
	UINT i;
	UINT ret;
	LIST *o;
	CK_ATTRIBUTE dummy[1];
	CK_ATTRIBUTE a[] =
	{
		{CKA_TOKEN,		&b_true,		sizeof(b_true)},
	};
	UINT num_objects = MAX_OBJ;
	// 引数チェック
	if (sec == NULL)
	{
		return NULL;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return NULL;
	}

	Zero(dummy, sizeof(dummy));

	// キャッシュがあればキャッシュを返す
	if (sec->EnumCache != NULL)
	{
		return CloneEnumSecObject(sec->EnumCache);
	}

	// 列挙
//	if (sec->Dev->Id != 2 && sec->Dev->Id != 14)
//	{
		// 通常のトークン
		ret = sec->Api->C_FindObjectsInit(sec->SessionId, a, sizeof(a) / sizeof(a[0]));
//	}
//	else
//	{
		// ePass と SafeSign
//		ret = sec->Api->C_FindObjectsInit(sec->SessionId, dummy, 0);
//	}

	if (ret != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return NULL;
	}
	if (sec->Api->C_FindObjects(sec->SessionId, objects, sizeof(objects) / sizeof(objects[0]), &num_objects) != CKR_OK)
	{
		sec->Api->C_FindObjectsFinal(sec->SessionId);
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return NULL;
	}
	sec->Api->C_FindObjectsFinal(sec->SessionId);

	o = NewListFast(NULL);

	for (i = 0;i < num_objects;i++)
	{
		char label[MAX_SIZE];
		UINT obj_class = 0;
		bool priv = false;
		CK_ATTRIBUTE get[] =
		{
			{CKA_LABEL, label, sizeof(label) - 1},
			{CKA_CLASS, &obj_class, sizeof(obj_class)},
			{CKA_PRIVATE, &priv, sizeof(priv)},
		};

		Zero(label, sizeof(label));

		if (sec->Api->C_GetAttributeValue(sec->SessionId, objects[i],
			get, sizeof(get) / sizeof(get[0])) == CKR_OK)
		{
			UINT type = INFINITE;

			switch (obj_class)
			{
			case CKO_DATA:
				// データ
				type = SEC_DATA;
				break;

			case CKO_CERTIFICATE:
				// 証明書
				type = SEC_X;
				break;

			case CKO_PUBLIC_KEY:
				// 公開鍵
				type = SEC_P;
				break;

			case CKO_PRIVATE_KEY:
				// 秘密鍵
				type = SEC_K;
				break;
			}

			if (type != INFINITE)
			{
				SEC_OBJ *obj = ZeroMalloc(sizeof(SEC_OBJ));

				obj->Type = type;
				obj->Object = objects[i];
				obj->Private = (priv == false) ? false : true;
				EnSafeStr(label, '?');
				TruncateCharFromStr(label, '?');
				obj->Name = CopyStr(label);

				Add(o, obj);
			}
		}
	}

	// キャッシュ作成
	sec->EnumCache = CloneEnumSecObject(o);

	return o;
}

// データを書き込む
bool WriteSecData(SECURE *sec, bool private_obj, char *name, void *data, UINT size)
{
	UINT object_class = CKO_DATA;
	CK_BBOOL b_true = true, b_false = false, b_private_obj = private_obj;
	UINT object;
	CK_ATTRIBUTE a[] =
	{
		{CKA_TOKEN,		&b_true,		sizeof(b_true)},
		{CKA_CLASS,		&object_class,	sizeof(object_class)},
		{CKA_PRIVATE,	&b_private_obj,	sizeof(b_private_obj)},
		{CKA_LABEL,		name,			StrLen(name)},
		{CKA_VALUE,		data,			size},
	};
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (private_obj && sec->LoginFlag == false)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (name == NULL || data == NULL || size == 0)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (size > MAX_SEC_DATA_SIZE)
	{
		sec->Error = SEC_ERROR_DATA_TOO_BIG;
		return false;
	}

	// 同名のオブジェクトがあれば削除
	if (CheckSecObject(sec, name, SEC_DATA))
	{
		DeleteSecData(sec, name);
	}

	// オブジェクト作成
	if (sec->Api->C_CreateObject(sec->SessionId, a, sizeof(a) / sizeof(a[0]), &object) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return false;
	}

	// キャッシュ消去
	EraseEnumSecObjectCache(sec);

	return true;
}

// キャッシュに新規作成したオブジェクトの情報を追加する
void AddSecObjToEnumCache(SECURE *sec, char *name, UINT type, bool private_obj, UINT object)
{
	SEC_OBJ *obj;
	// 引数チェック
	if (sec == NULL || name == NULL || sec->EnumCache == NULL)
	{
		return;
	}

	obj = ZeroMalloc(sizeof(SEC_OBJ));
	obj->Name = CopyStr(name);
	obj->Object = object;
	obj->Private = private_obj;
	obj->Type = type;

	Add(sec->EnumCache, obj);
}

// トークン情報を表示
void PrintSecInfo(SECURE *sec)
{
	SEC_INFO *s;
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}

	s = sec->Info;
	if (s == NULL)
	{
		Print("No Token Info.\n");
		return;
	}

	Print(
		"               Label: %S\n"
		"      ManufacturerId: %S\n"
		"               Model: %S\n"
		"        SerialNumber: %S\n"
		"          MaxSession: %u\n"
		"        MaxRWSession: %u\n"
		"           MinPinLen: %u\n"
		"           MaxPinLen: %u\n"
		"   TotalPublicMemory: %u\n"
		"    FreePublicMemory: %u\n"
		"  TotalPrivateMemory: %u\n"
		"   FreePrivateMemory: %u\n"
		"     HardwareVersion: %s\n"
		"     FirmwareVersion: %s\n",
		s->Label, s->ManufacturerId, s->Model, s->SerialNumber,
		s->MaxSession, s->MaxRWSession, s->MinPinLen, s->MaxPinLen,
		s->TotalPublicMemory, s->FreePublicMemory, s->TotalPrivateMemory,
		s->FreePrivateMemory, s->HardwareVersion, s->FirmwareVersion
		);
}

// トークン情報を取得
void GetSecInfo(SECURE *sec)
{
	CK_TOKEN_INFO token_info;
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}
	if (sec->Info != NULL)
	{
		return;
	}

	// 取得
	Zero(&token_info, sizeof(token_info));
	if (sec->Api->C_GetTokenInfo(sec->SlotIdList[sec->SessionSlotNumber], &token_info) != CKR_OK)
	{
		// 失敗
		return;
	}

	sec->Info = TokenInfoToSecInfo(&token_info);
}

// トークン情報を解放
void FreeSecInfo(SECURE *sec)
{
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}
	if (sec->Info == NULL)
	{
		return;
	}

	FreeSecInfoMemory(sec->Info);
	sec->Info = NULL;
}

// トークン情報を SEC_INFO に変換
SEC_INFO *TokenInfoToSecInfo(void *p_t)
{
	SEC_INFO *s;
	char buf[MAX_SIZE];
	CK_TOKEN_INFO *t = (CK_TOKEN_INFO *)p_t;
	// 引数チェック
	if (t == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SEC_INFO));

	// Label
	Zero(buf, sizeof(buf));
	Copy(buf, t->label, sizeof(t->label));
	s->Label = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->Label, 0, buf, 0);

	// ManufacturerId
	Zero(buf, sizeof(buf));
	Copy(buf, t->manufacturerID, sizeof(t->manufacturerID));
	s->ManufacturerId = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->ManufacturerId, 0, buf, 0);

	// Model
	Zero(buf, sizeof(buf));
	Copy(buf, t->model, sizeof(t->model));
	s->Model = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->Model, 0, buf, 0);

	// SerialNumber
	Zero(buf, sizeof(buf));
	Copy(buf, t->serialNumber, sizeof(t->serialNumber));
	s->SerialNumber = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->SerialNumber, 0, buf, 0);

	// 数値
	s->MaxSession = t->ulMaxSessionCount;
	s->MaxRWSession = t->ulMaxRwSessionCount;
	s->MinPinLen = t->ulMinPinLen;
	s->MaxPinLen = t->ulMaxPinLen;
	s->TotalPublicMemory = t->ulTotalPublicMemory;
	s->FreePublicMemory = t->ulFreePublicMemory;
	s->TotalPrivateMemory = t->ulTotalPrivateMemory;
	s->FreePrivateMemory = t->ulFreePrivateMemory;

	// ハードウェアバージョン
	Format(buf, sizeof(buf), "%u.%02u", t->hardwareVersion.major, t->hardwareVersion.minor);
	s->HardwareVersion = CopyStr(buf);

	// ファームウェアバージョン
	Format(buf, sizeof(buf), "%u.%02u", t->firmwareVersion.major, t->firmwareVersion.minor);
	s->FirmwareVersion = CopyStr(buf);

	return s;
}

// SEC_INFO のメモリを解放
void FreeSecInfoMemory(SEC_INFO *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Free(s->Label);
	Free(s->ManufacturerId);
	Free(s->Model);
	Free(s->SerialNumber);
	Free(s->HardwareVersion);
	Free(s->FirmwareVersion);
	Free(s);
}

// ログアウトする
void LogoutSec(SECURE *sec)
{
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}
	if (sec->LoginFlag == false)
	{
		return;
	}

	// ログアウト
	sec->Api->C_Logout(sec->SessionId);

	// キャッシュ消去
	EraseEnumSecObjectCache(sec);

	sec->LoginFlag = false;
}

// ログインする
bool LoginSec(SECURE *sec, char *pin)
{
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;

	}
	if (sec->LoginFlag)
	{
		sec->Error = SEC_ERROR_ALREADY_LOGIN;
		return false;
	}
	if (pin == NULL)
	{
		sec->Error = SEC_ERROR_NO_PIN_STR;
		return false;
	}

	// ログイン
	if (sec->Api->C_Login(sec->SessionId, CKU_USER, pin, StrLen(pin)) != CKR_OK)
	{
		// ログイン失敗
		sec->Error = SEC_ERROR_BAD_PIN_CODE;
		return false;
	}

	// キャッシュ消去
	EraseEnumSecObjectCache(sec);

	sec->LoginFlag = true;

	return true;
}

// セッションを閉じる
void CloseSecSession(SECURE *sec)
{
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}
	if (sec->SessionCreated == false)
	{
		return;
	}

	// セッションを閉じる
	sec->Api->C_CloseSession(sec->SessionId);

	sec->SessionCreated = false;
	sec->SessionId = 0;
	sec->SessionSlotNumber = 0;

	FreeSecInfo(sec);

	// キャッシュ消去
	EraseEnumSecObjectCache(sec);
}

// セッションを開く
bool OpenSecSession(SECURE *sec, UINT slot_number)
{
	UINT err = 0;
	UINT session;
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated)
	{
		// すでに作成されている
		sec->Error = SEC_ERROR_SESSION_EXISTS;
		return false;
	}
	if (slot_number >= sec->NumSlot)
	{
		// スロット番号不正
		sec->Error = SEC_ERROR_INVALID_SLOT_NUMBER;
		return false;
	}

	// セッション作成
	if ((err = sec->Api->C_OpenSession(sec->SlotIdList[slot_number],
		CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session)) != CKR_OK)
	{
		// 読み書きモードでのセッション初期化に失敗した
		// 読み取り専用モードかな？
		if ((err = sec->Api->C_OpenSession(sec->SlotIdList[slot_number],
			CKF_SERIAL_SESSION, NULL, NULL, &session)) != CKR_OK)
		{
			// 作成失敗
			sec->Error = SEC_ERROR_OPEN_SESSION;
			return false;
		}
		else
		{
			sec->IsReadOnly = true;
		}
	}

	sec->SessionCreated = true;
	sec->SessionId = session;
	sec->SessionSlotNumber = slot_number;

	// トークン情報を取得
	GetSecInfo(sec);

	return true;
}

// セキュアデバイスを閉じる
void CloseSec(SECURE *sec)
{
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}

	// ログアウトする
	LogoutSec(sec);

	// セッションを閉じる
	CloseSecSession(sec);

	// トークン情報を解放
	FreeSecInfo(sec);

	// スロットリストメモリの解放
	if (sec->SlotIdList != NULL)
	{
		Free(sec->SlotIdList);
		sec->SlotIdList = NULL;
	}

	// モジュールのアンロード
	FreeSecModule(sec);

	// メモリ解放
	DeleteLock(sec->lock);
	Free(sec);
}

// セキュアデバイスを開く
SECURE *OpenSec(UINT id)
{
	SECURE_DEVICE *dev = GetSecureDevice(id);
	SECURE *sec;
	UINT err;

	if (dev == NULL)
	{
		return NULL;
	}

	sec = ZeroMalloc(sizeof(SECURE));

	sec->lock = NewLock();
	sec->Error = SEC_ERROR_NOERROR;
	sec->Dev = dev;

	// ePass かどうか取得する
	if (SearchStrEx(dev->DeviceName, "epass", 0, false) != INFINITE)
	{
		sec->IsEPass1000 = true;
	}

	// モジュールのロード
	if (LoadSecModule(sec) == false)
	{
		CloseSec(sec);
		return NULL;
	}

	// スロット一覧の取得
	sec->NumSlot = 0;
	if ((err = sec->Api->C_GetSlotList(true, NULL, &sec->NumSlot)) != CKR_OK || sec->NumSlot == 0)
	{
		// 失敗
		FreeSecModule(sec);
		CloseSec(sec);
		return NULL;
	}

	sec->SlotIdList = (UINT *)ZeroMalloc(sizeof(UINT *) * sec->NumSlot);

	if (sec->Api->C_GetSlotList(TRUE, sec->SlotIdList, &sec->NumSlot) != CKR_OK)
	{
		// 失敗
		Free(sec->SlotIdList);
		sec->SlotIdList = NULL;
		FreeSecModule(sec);
		CloseSec(sec);
		return NULL;
	}

	return sec;
}

// セキュアデバイスのモジュールをロードする
bool LoadSecModule(SECURE *sec)
{
	bool ret = false;
	// 引数チェック
	if (sec == NULL)
	{
		return false;
	}

#ifdef	OS_WIN32
	ret = Win32LoadSecModule(sec);
#endif	// OS_WIN32

	// 初期化
	if (sec->Api->C_Initialize(NULL) != CKR_OK)
	{
		// 初期化失敗
		FreeSecModule(sec);
		return false;
	}

	sec->Initialized = true;

	return ret;
}

// セキュアデバイスのモジュールをアンロードする
void FreeSecModule(SECURE *sec)
{
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}

	if (sec->Initialized)
	{
		// 初期化済みなので解放する
		sec->Api->C_Finalize(NULL);
		sec->Initialized = false;
	}

#ifdef	OS_WIN32
	Win32FreeSecModule(sec);
#endif	// OS_WIN32

}


// セキュアデバイスを取得する
SECURE_DEVICE *GetSecureDevice(UINT id)
{
	UINT i;

	if (id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(SecureDeviceList);i++)
	{
		SECURE_DEVICE *dev = LIST_DATA(SecureDeviceList, i);

		if (dev->Id == id)
		{
			return dev;
		}
	}

	return NULL;
}

// セキュアデバイスの ID を確認する
bool CheckSecureDeviceId(UINT id)
{
	UINT i;

	for (i = 0;i < LIST_NUM(SecureDeviceList);i++)
	{
		SECURE_DEVICE *dev = LIST_DATA(SecureDeviceList, i);

		if (dev->Id == id)
		{
			return true;
		}
	}

	return false;
}

// サポートされているデバイスリストを取得する
LIST *GetSecureDeviceList()
{
	return GetSupportedDeviceList();
}

// サポートされているデバイスリストを取得する
LIST *GetSupportedDeviceList()
{
	// 参照カウントの増加
	AddRef(SecureDeviceList->ref);

	return SecureDeviceList;
}

// 指定したデバイスがインストールされていて利用可能かどうか調べる
bool IsDeviceSupported(SECURE_DEVICE *dev)
{
	bool b = false;
#ifdef	OS_WIN32
	b = Win32IsDeviceSupported(dev);
#endif	// OS_WIN32
	return b;
}

// セキュアデバイスリストの初期化
void InitSecureDeviceList()
{
	UINT i, num_supported_list;
	SecureDeviceList = NewList(NULL);

	num_supported_list = sizeof(SupportedList) / sizeof(SECURE_DEVICE);
	for (i = 0; i < num_supported_list;i++)
	{
		SECURE_DEVICE *dev = &SupportedList[i];

		// サポートチェック
		if (IsDeviceSupported(dev))
		{
			// サポートされているのでリストに追加
			Add(SecureDeviceList, dev);
		}
	}
}

// テストメイン処理
void TestSecMain(SECURE *sec)
{
	char *test_str = "SoftEther UT-VPN";
	K *public_key, *private_key;
	// 引数チェック
	if (sec == NULL)
	{
		return;
	}

	Print("test_str: \"%s\"\n", test_str);

	Print("Writing Data...\n");
	if (WriteSecData(sec, true, "test_str", test_str, StrLen(test_str)) == false)
	{
		Print("WriteSecData() Failed.\n");
	}
	else
	{
		char data[MAX_SIZE];
		Zero(data, sizeof(data));
		Print("Reading Data...\n");
		if (ReadSecData(sec, "test_str", data, sizeof(data)) == false)
		{
			Print("ReadSecData() Failed.\n");
		}
		else
		{
			Print("test_str: \"%s\"\n", data);
		}
		Print("Deleting Data...\n");
		DeleteSecData(sec, "test_str");
	}

	Print("Generating Key...\n");
	if (RsaGen(&private_key, &public_key, 1024) == false)
	{
		Print("RsaGen() Failed.\n");
	}
	else
	{
		X *cert;
		NAME *name;
		X_SERIAL *serial;
		UINT num = 0x11220000;

		Print("Creating Cert...\n");
		serial = NewXSerial(&num, sizeof(UINT));
		name = NewName(L"Test", L"Test", L"Test", L"JP", L"Test", L"Test");
		cert = NewRootX(public_key, private_key, name, 365, NULL);
		FreeXSerial(serial);
		if (cert == NULL)
		{
			Print("NewRootX() Failed.\n");
		}
		else
		{
			Print("Writing Cert...\n");
			DeleteSecData(sec, "test_cer");
			if (WriteSecCert(sec, true, "test_cer", cert) == false)
			{
				Print("WriteSecCert() Failed.\n");
			}
			else
			{
				X *x;
				Print("Reading Cert...\n");
				x = ReadSecCert(sec, "test_cer");
				if (x == NULL)
				{
					Print("ReadSecCert() Failed.\n");
				}
				else
				{
					Print("Checking two Certs... ");
					if (CompareX(x, cert) == false)
					{
						Print("[FAILED]\n");
					}
					else
					{
						Print("Ok.\n");
					}
					FreeX(x);
				}
				if (cert != NULL)
				{
					X *x;
					XToFile(cert, "cert_tmp.cer", true);
					x = FileToX("cert_tmp.cer");
					if (CompareX(x, cert) == false)
					{
						Print("[FAILED]\n");
					}
					else
					{
						Print("Ok.\n");
						Print("Writing Private Key...\n");
						DeleteSecKey(sec, "test_key");
						if (WriteSecKey(sec, true, "test_key", private_key) == false)
						{
							Print("WriteSecKey() Failed.\n");
						}
						else
						{
							UCHAR sign_cpu[128];
							UCHAR sign_sec[128];
							K *pub = GetKFromX(cert);
							Print("Ok.\n");
							Print("Signing Data by CPU...\n");
							if (RsaSign(sign_cpu, test_str, StrLen(test_str), private_key) == false)
							{
								Print("RsaSign() Failed.\n");
							}
							else
							{
								Print("Ok.\n");
								Print("sign_cpu: ");
								PrintBin(sign_cpu, sizeof(sign_cpu));
								Print("Signing Data by %s..\n", sec->Dev->DeviceName);
								if (SignSec(sec, "test_key", sign_sec, test_str, StrLen(test_str)) == false)
								{
									Print("SignSec() Failed.\n");
								}
								else
								{
									Print("Ok.\n");
									Print("sign_sec: ");
									PrintBin(sign_sec, sizeof(sign_sec));
									Print("Compare...");
									if (Cmp(sign_sec, sign_cpu, sizeof(sign_cpu)) == 0)
									{
										Print("Ok.\n");
										Print("Verify...");
										if (RsaVerify(test_str, StrLen(test_str),
											sign_sec, pub) == false)
										{
											Print("[FAILED]\n");
										}
										else
										{
											Print("Ok.\n");
										}
									}
									else
									{
										Print("[DIFFIRENT]\n");
									}
								}
							}
							Print("Deleting test_key...\n");
//							DeleteSecKey(sec, "test_key");
							FreeK(pub);
						}
					}
					FreeX(x);
				}
			}
			Print("Deleting Cert..\n");
//			DeleteSecCert(sec, "test_cer");
			FreeX(cert);
		}
		FreeName(name);
		FreeK(private_key);
		FreeK(public_key);
	}
}

// セキュリティデバイスのテスト
void TestSec()
{
	UINT i;
	LIST *secure_device_list;
	Print("Secure Device Test Program\n"
		"Copyright (C) 2004-2010 SoftEther Corporation. All Rights Reserved.\n\n");

	// セキュアデバイスリストの取得
	secure_device_list = GetSecureDeviceList();
	if (secure_device_list != NULL)
	{
		UINT use_device_id;
		char tmp[MAX_SIZE];
		Print("--- Secure Device List ---\n");
		for (i = 0;i < LIST_NUM(secure_device_list);i++)
		{
			SECURE_DEVICE *dev = LIST_DATA(secure_device_list, i);
			Print("%2u - %s\n", dev->Id, dev->DeviceName);
		}
		Print("\n");
		Print("Device ID >");
		GetLine(tmp, sizeof(tmp));
		use_device_id = ToInt(tmp);
		if (use_device_id == 0)
		{
			Print("Canceled.\n");
		}
		else
		{
			SECURE *sec = OpenSec(use_device_id);
			Print("Opening Device...\n");
			if (sec == NULL)
			{
				Print("OpenSec() Failed.\n");
			}
			else
			{
				Print("Opening Session...\n");
				if (OpenSecSession(sec, 0) == false)
				{
					Print("OpenSecSession() Failed.\n");
				}
				else
				{
					while (true)
					{
						char pin[MAX_SIZE];
						Print("PIN Code >");
						GetLine(pin, sizeof(pin));
						Trim(pin);
						if (StrLen(pin) == 0)
						{
							Print("Canceled.\n");
							break;
						}
						else
						{
							Print("Login...\n");
							if (LoginSec(sec, pin))
							{
								TestSecMain(sec);
								Print("Logout...\n");
								LogoutSec(sec);
								break;
							}
							else
							{
								Print("Login Failed. Please Try Again.\n");
							}
						}
					}
					Print("Closing Session...\n");
					CloseSecSession(sec);
				}
				Print("Closing Device...\n");
				CloseSec(sec);
			}
		}
		ReleaseList(secure_device_list);
	}
	else
	{
		Print("GetSecureDeviceList() Error.\n");
	}
}

// セキュアデバイスリストの解放
void FreeSecureDeviceList()
{
	ReleaseList(SecureDeviceList);
}

// セキュリティトークンモジュールの初期化
void InitSecure()
{
	// セキュアデバイスリストの初期化
	InitSecureDeviceList();
}

// セキュリティトークンモジュールの解放
void FreeSecure()
{
	// セキュアデバイスリストの解放
	FreeSecureDeviceList();
}


