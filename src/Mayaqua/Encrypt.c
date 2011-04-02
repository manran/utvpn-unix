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

// Encrypt.c
// 暗号化および電子証明書ルーチン

#define	ENCRYPT_C

#define	__WINCRYPT_H__

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

LOCK *openssl_lock = NULL;

LOCK **ssl_lock_obj = NULL;
UINT ssl_lock_num;
static bool openssl_inited = false;

// コールバック関数用
typedef struct CB_PARAM
{
	char *password;
} CB_PARAM;

// 証明書が特定のディレクトリの CRL によって無効化されているかどうか確認する
bool IsXRevoked(X *x)
{
	char dirname[MAX_PATH];
	UINT i;
	bool ret = false;
	DIRLIST *t;
	// 引数チェック
	if (x == NULL)
	{
		return false;
	}

	GetExeDir(dirname, sizeof(dirname));

	// CRL ファイルの検索
	t = EnumDir(dirname);

	for (i = 0;i < t->NumFiles;i++)
	{
		char *name = t->File[i]->FileName;
		if (t->File[i]->Folder == false)
		{
			if (EndWith(name, ".crl"))
			{
				char filename[MAX_PATH];
				X_CRL *r;

				ConbinePath(filename, sizeof(filename), dirname, name);

				r = FileToXCrl(filename);

				if (r != NULL)
				{
					if (IsXRevokedByXCrl(x, r))
					{
						ret = true;
					}

					FreeXCrl(r);
				}
			}
		}
	}

	FreeDir(t);

	return ret;
}

// 証明書が CRL によって無効化されているかどうか確認する
bool IsXRevokedByXCrl(X *x, X_CRL *r)
{
#ifdef	OS_WIN32
	X509_REVOKED tmp;
	X509_CRL_INFO *info;
	int index;
	// 引数チェック
	if (x == NULL || r == NULL)
	{
		return false;
	}

	Zero(&tmp, sizeof(tmp));
	tmp.serialNumber = X509_get_serialNumber(x->x509);

	info = r->Crl->crl;

	if (sk_X509_REVOKED_is_sorted(info->revoked) == false)
	{
		sk_X509_REVOKED_sort(info->revoked);
	}

	index = sk_X509_REVOKED_find(info->revoked, &tmp);

	if (index < 0)
	{
		return false;
	}
	else
	{
		return true;
	}
#else	// OS_WIN32
	return false;
#endif	// OS_WIN32
}

// CRL の解放
void FreeXCrl(X_CRL *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	X509_CRL_free(r->Crl);

	Free(r);
}

// ファイルを CRL に変換
X_CRL *FileToXCrl(char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	X_CRL *ret = FileToXCrlW(filename_w);

	Free(filename_w);

	return ret;
}
X_CRL *FileToXCrlW(wchar_t *filename)
{
	BUF *b;
	X_CRL *r;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	r = BufToXCrl(b);

	FreeBuf(b);

	return r;
}

// バッファを CRL に変換
X_CRL *BufToXCrl(BUF *b)
{
	X_CRL *r;
	X509_CRL *x509crl;
	BIO *bio;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	x509crl	= NULL;

	if (d2i_X509_CRL_bio(bio, &x509crl) == NULL || x509crl == NULL)
	{
		FreeBio(bio);
		return NULL;
	}

	r = ZeroMalloc(sizeof(X_CRL));
	r->Crl = x509crl;

	FreeBio(bio);

	return r;
}

// バッファを公開鍵に変換
K *RsaBinToPublic(void *data, UINT size)
{
	RSA *rsa;
	K *k;
	BIO *bio;
	// 引数チェック
	if (data == NULL || size < 4)
	{
		return NULL;
	}

	rsa = RSA_new();

	if (rsa->e != NULL)
	{
		BN_free(rsa->e);
	}

	rsa->e = BN_new();
	BN_set_word(rsa->e, RSA_F4);

	if (rsa->n != NULL)
	{
		BN_free(rsa->n);
	}

	rsa->n = BinToBigNum(data, size);

	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	k = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	RSA_free(rsa);

	return k;
}

// 公開鍵をバッファに変換
BUF *RsaPublicToBuf(K *k)
{
	BUF *b;
	// 引数チェック
	if (k == NULL || k->pkey == NULL || k->pkey->pkey.rsa == NULL
		|| k->pkey->pkey.rsa->n == NULL)
	{
		return NULL;
	}

	b = BigNumToBuf(k->pkey->pkey.rsa->n);
	if (b == NULL)
	{
		return NULL;
	}

	return b;
}

// 公開鍵をバイナリに変換
void RsaPublicToBin(K *k, void *data)
{
	BUF *b;
	// 引数チェック
	if (k == NULL || k->pkey == NULL || k->pkey->pkey.rsa == NULL
		|| k->pkey->pkey.rsa->n == NULL || data == NULL)
	{
		return;
	}

	b = BigNumToBuf(k->pkey->pkey.rsa->n);
	if (b == NULL)
	{
		return;
	}

	Copy(data, b->Buf, b->Size);

	FreeBuf(b);
}

// 公開鍵サイズの取得
UINT RsaPublicSize(K *k)
{
	BUF *b;
	UINT ret;
	// 引数チェック
	if (k == NULL || k->pkey == NULL || k->pkey->pkey.rsa == NULL
		|| k->pkey->pkey.rsa->n == NULL)
	{
		return 0;
	}

	b = BigNumToBuf(k->pkey->pkey.rsa->n);
	if (b == NULL)
	{
		return 0;
	}

	ret = b->Size;

	FreeBuf(b);

	return ret;
}

// ポインタを 32 ビットにハッシュする
UINT HashPtrToUINT(void *p)
{
	UCHAR hash_data[MD5_SIZE];
	UINT ret;
	// 引数チェック
	if (p == NULL)
	{
		return 0;
	}

	Hash(hash_data, &p, sizeof(p), false);

	Copy(&ret, hash_data, sizeof(ret));

	return ret;
}

// NAME のコピー
NAME *CopyName(NAME *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return NULL;
	}

	return NewName(n->CommonName, n->Organization, n->Unit,
		n->Country, n->State, n->Local);
}

// バイナリを BIGNUM に変換
BIGNUM *BinToBigNum(void *data, UINT size)
{
	BIGNUM *bn;
	// 引数チェック
	if (data == NULL)
	{
		return NULL;
	}

	bn = BN_new();
	BN_bin2bn(data, size, bn);

	return bn;
}

// バッファを BIGNUM に変換
BIGNUM *BufToBigNum(BUF *b)
{
	if (b == NULL)
	{
		return NULL;
	}

	return BinToBigNum(b->Buf, b->Size);
}

// BIGNUM をバッファに変換
BUF *BigNumToBuf(BIGNUM *bn)
{
	UINT size;
	UCHAR *tmp;
	BUF *b;
	// 引数チェック
	if (bn == NULL)
	{
		return NULL;
	}

	size = BN_num_bytes(bn);
	tmp = ZeroMalloc(size);
	BN_bn2bin(bn, tmp);

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	SeekBuf(b, 0, 0);

	return b;
}

// OpenSSL のロックの初期化
void OpenSSL_InitLock()
{
	UINT i;

	// ロックオブジェクトの初期化
	ssl_lock_num = CRYPTO_num_locks();
	ssl_lock_obj = Malloc(sizeof(LOCK *) * ssl_lock_num);
	for (i = 0;i < ssl_lock_num;i++)
	{
		ssl_lock_obj[i] = NewLock();
	}

	// ロック関数の設定
	CRYPTO_set_locking_callback(OpenSSL_Lock);
	CRYPTO_set_id_callback(OpenSSL_Id);
}

// OpenSSL のロックの解放
void OpenSSL_FreeLock()
{
	UINT i;

	for (i = 0;i < ssl_lock_num;i++)
	{
		DeleteLock(ssl_lock_obj[i]);
	}
	Free(ssl_lock_obj);
	ssl_lock_obj = NULL;

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);
}

// OpenSSL のロック関数
void OpenSSL_Lock(int mode, int n, const char *file, int line)
{
	LOCK *lock = ssl_lock_obj[n];

	if (mode & CRYPTO_LOCK)
	{
		// ロック
		Lock(lock);
	}
	else
	{
		// ロック解除
		Unlock(lock);
	}
}

// スレッド ID の返却
unsigned long OpenSSL_Id(void)
{
	return (unsigned long)ThreadId();
}

// 証明書の表示名を取得
void GetPrintNameFromX(wchar_t *str, UINT size, X *x)
{
	// 引数チェック
	if (x == NULL || str == NULL)
	{
		return;
	}

	GetPrintNameFromName(str, size, x->subject_name);
}
void GetPrintNameFromXA(char *str, UINT size, X *x)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetPrintNameFromX(tmp, sizeof(tmp), x);

	UniToStr(str, size, tmp);
}
void GetAllNameFromXEx(wchar_t *str, UINT size, X *x)
{
	// 引数チェック
	if (x == NULL || str == NULL)
	{
		return;
	}

	GetAllNameFromNameEx(str, size, x->subject_name);
}
void GetAllNameFromXExA(char *str, UINT size, X *x)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetAllNameFromXEx(tmp, sizeof(tmp), x);

	UniToStr(str, size, tmp);
}

// NAME から表示名を取得
void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name)
{
	// 引数チェック
	if (str == NULL || name == NULL)
	{
		return;
	}

	if (name->CommonName != NULL)
	{
		UniStrCpy(str, size, name->CommonName);
	}
	else if (name->Organization != NULL)
	{
		UniStrCpy(str, size, name->Organization);
	}
	else if (name->Unit != NULL)
	{
		UniStrCpy(str, size, name->Unit);
	}
	else if (name->State != NULL)
	{
		UniStrCpy(str, size, name->State);
	}
	else if (name->Local != NULL)
	{
		UniStrCpy(str, size, name->Local);
	}
	else if (name->Country != NULL)
	{
		UniStrCpy(str, size, name->Country);
	}
	else
	{
		UniStrCpy(str, size, L"untitled");
	}
}

// 証明書からすべての名前文字列を取得
void GetAllNameFromX(wchar_t *str, UINT size, X *x)
{
	UCHAR md5[MD5_SIZE], sha1[SHA1_SIZE];
	char tmp1[MD5_SIZE * 3 + 8], tmp2[SHA1_SIZE * 3 + 8];
	wchar_t tmp3[sizeof(tmp1) + sizeof(tmp2) + 64];
	// 引数チェック
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetAllNameFromName(str, size, x->subject_name);

	if (x->serial != NULL && x->serial->size >= 1)
	{
		char tmp[128];
		wchar_t tmp2[128];

		BinToStr(tmp, sizeof(tmp), x->serial->data, x->serial->size);
		UniFormat(tmp2, sizeof(tmp2), L", SERIAL=\"%S\"", tmp);

		UniStrCat(str, size, tmp2);
	}

	// ダイジェスト値
	GetXDigest(x, md5, false);
	GetXDigest(x, sha1, true);

	BinToStr(tmp1, sizeof(tmp1), md5, MD5_SIZE);
	BinToStr(tmp2, sizeof(tmp2), sha1, SHA1_SIZE);

	UniFormat(tmp3, sizeof(tmp3), L" (Digest: MD5=\"%S\", SHA1=\"%S\")", tmp1, tmp2);
	UniStrCat(str, size, tmp3);
}
void GetAllNameFromA(char *str, UINT size, X *x)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetAllNameFromX(tmp, sizeof(tmp), x);
	UniToStr(str, size, tmp);
}

// NAME からすべての名前文字列を取得
void GetAllNameFromName(wchar_t *str, UINT size, NAME *name)
{
	// 引数チェック
	if (str == NULL || name == NULL)
	{
		return;
	}

	UniStrCpy(str, size, L"");
	if (name->CommonName != NULL)
	{
		UniFormat(str, size, L"%sCN=%s, ", str, name->CommonName);
	}
	if (name->Organization != NULL)
	{
		UniFormat(str, size, L"%sO=%s, ", str, name->Organization);
	}
	if (name->Unit != NULL)
	{
		UniFormat(str, size, L"%sOU=%s, ", str, name->Unit);
	}
	if (name->State != NULL)
	{
		UniFormat(str, size, L"%sS=%s, ", str, name->State);
	}
	if (name->Local != NULL)
	{
		UniFormat(str, size, L"%sL=%s, ", str, name->Local);
	}
	if (name->Country != NULL)
	{
		UniFormat(str, size, L"%sC=%s, ", str, name->Country);
	}

	if (UniStrLen(str) >= 3)
	{
		UINT len = UniStrLen(str);
		if (str[len - 2] == L',' &&
			str[len - 1] == L' ')
		{
			str[len - 2] = 0;
		}
	}
}
void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name)
{
	// 引数チェック
	if (str == NULL || name == NULL)
	{
		return;
	}

	UniStrCpy(str, size, L"");
	if (name->CommonName != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->CommonName);
	}
	if (name->Organization != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Organization);
	}
	if (name->Unit != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Unit);
	}
	if (name->State != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->State);
	}
	if (name->Local != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Local);
	}
	if (name->Country != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Country);
	}

	if (UniStrLen(str) >= 3)
	{
		UINT len = UniStrLen(str);
		if (str[len - 2] == L',' &&
			str[len - 1] == L' ')
		{
			str[len - 2] = 0;
		}
	}
}

// 鍵のクローン
K *CloneK(K *k)
{
	BUF *b;
	K *ret;
	// 引数チェック
	if (k == NULL)
	{
		return NULL;
	}

	b = KToBuf(k, false, NULL);
	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToK(b, k->private_key, false, NULL);
	FreeBuf(b);

	return ret;
}

// 証明書のクローン
X *CloneX(X *x)
{
	BUF *b;
	X *ret;
	// 引数チェック
	if (x == NULL)
	{
		return NULL;
	}

	b = XToBuf(x, false);
	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToX(b, false);
	FreeBuf(b);

	return ret;
}

// P12 を生成する
P12 *NewP12(X *x, K *k, char *password)
{
	PKCS12 *pkcs12;
	P12 *p12;
	// 引数チェック
	if (x == NULL || k == NULL)
	{
		return false;
	}
	if (password && StrLen(password) == 0)
	{
		password = NULL;
	}

	Lock(openssl_lock);
	{
		pkcs12 = PKCS12_create(password, NULL, k->pkey, x->x509, NULL, 0, 0, 0, 0, 0);
		if (pkcs12 == NULL)
		{
			Unlock(openssl_lock);
			return NULL;
		}
	}
	Unlock(openssl_lock);

	p12 = PKCS12ToP12(pkcs12);

	return p12;
}

// P12 が暗号化されているかどうかチェックする
bool IsEncryptedP12(P12 *p12)
{
	X *x;
	K *k;
	// 引数チェック
	if (p12 == NULL)
	{
		return false;
	}

	if (ParseP12(p12, &x, &k, NULL) == true)
	{
		FreeX(x);
		FreeK(k);
		return false;
	}

	return true;
}

// P12 から X と K を取り出す
bool ParseP12(P12 *p12, X **x, K **k, char *password)
{
	EVP_PKEY *pkey;
	X509 *x509;
	// 引数チェック
	if (p12 == NULL || x == NULL || k == NULL)
	{
		return false;
	}
	if (password && StrLen(password) == 0)
	{
		password = NULL;
	}
	if (password == NULL)
	{
		password = "";
	}

	// パスワード確認
	Lock(openssl_lock);
	{
		if (PKCS12_verify_mac(p12->pkcs12, password, -1) == false &&
			PKCS12_verify_mac(p12->pkcs12, NULL, -1) == false)
		{
			Unlock(openssl_lock);
			return false;
		}
	}
	Unlock(openssl_lock);

	// 抽出
	Lock(openssl_lock);
	{
		if (PKCS12_parse(p12->pkcs12, password, &pkey, &x509, NULL) == false)
		{
			if (PKCS12_parse(p12->pkcs12, NULL, &pkey, &x509, NULL) == false)
			{
				Unlock(openssl_lock);
				return false;
			}
		}
	}
	Unlock(openssl_lock);

	// 変換
	*x = X509ToX(x509);

	if (*x == NULL)
	{
		FreePKey(pkey);
		return false;
	}

	*k = ZeroMalloc(sizeof(K));
	(*k)->private_key = true;
	(*k)->pkey = pkey;

	return true;
}

// P12 をファイルに書き出す
bool P12ToFile(P12 *p12, char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret = P12ToFileW(p12, filename_w);

	return ret;
}
bool P12ToFileW(P12 *p12, wchar_t *filename)
{
	BUF *b;
	// 引数チェック
	if (p12 == NULL || filename == NULL)
	{
		return false;
	}

	b = P12ToBuf(p12);
	if (b == NULL)
	{
		return false;
	}

	if (DumpBufW(b, filename) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	return true;
}

// ファイルから P12 を読み込む
P12 *FileToP12(char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	P12 *ret = FileToP12W(filename_w);

	Free(filename_w);

	return ret;
}
P12 *FileToP12W(wchar_t *filename)
{
	BUF *b;
	P12 *p12;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	p12 = BufToP12(b);
	FreeBuf(b);

	return p12;
}

// P12 の解放
void FreeP12(P12 *p12)
{
	// 引数チェック
	if (p12 == NULL)
	{
		return;
	}

	FreePKCS12(p12->pkcs12);
	Free(p12);
}

// PKCS12 の解放
void FreePKCS12(PKCS12 *pkcs12)
{
	// 引数チェック
	if (pkcs12 == NULL)
	{
		return;
	}

	PKCS12_free(pkcs12);
}

// P12 を BUF に変換する
BUF *P12ToBuf(P12 *p12)
{
	BIO *bio;
	BUF *buf;
	// 引数チェック
	if (p12 == NULL)
	{
		return NULL;
	}

	bio = P12ToBio(p12);
	if (bio == NULL)
	{
		return NULL;
	}

	buf = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(buf, 0, 0);

	return buf;
}

// P12 を BIO に変換する
BIO *P12ToBio(P12 *p12)
{
	BIO *bio;
	// 引数チェック
	if (p12 == NULL)
	{
		return NULL;
	}

	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_PKCS12_bio(bio, p12->pkcs12);
	}
	Unlock(openssl_lock);

	return bio;
}

// BUF から P12 を読み込む
P12 *BufToP12(BUF *b)
{
	P12 *p12;
	BIO *bio;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	p12 = BioToP12(bio);
	FreeBio(bio);

	return p12;
}

// BIO から P12 を読み込む
P12 *BioToP12(BIO *bio)
{
	PKCS12 *pkcs12;
	// 引数チェック
	if (bio == NULL)
	{
		return NULL;
	}

	// 変換
	Lock(openssl_lock);
	{
		pkcs12 = d2i_PKCS12_bio(bio, NULL);
	}
	Unlock(openssl_lock);
	if (pkcs12 == NULL)
	{
		// 失敗
		return NULL;
	}

	return PKCS12ToP12(pkcs12);
}

// PKCS12 から P12 を生成する
P12 *PKCS12ToP12(PKCS12 *pkcs12)
{
	P12 *p12;
	// 引数チェック
	if (pkcs12 == NULL)
	{
		return NULL;
	}

	p12 = ZeroMalloc(sizeof(P12));
	p12->pkcs12 = pkcs12;

	return p12;
}

// バイナリを文字列に変換する
char *ByteToStr(BYTE *src, UINT src_size)
{
	UINT size;
	char *dst;
	UINT i;
	// 引数チェック
	if (src == NULL)
	{
		return NULL;
	}

	size = MAX(src_size * 3, 1);
	dst = Malloc(size);
	dst[size - 1] = 0;
	for (i = 0;i < src_size;i++)
	{
		char tmp[3];
		Format(tmp, sizeof(tmp), "%02x", src[i]);
		dst[i * 3 + 0] = tmp[0];
		dst[i * 3 + 1] = tmp[1];
		dst[i * 3 + 2] = ((i == (src_size - 1) ? 0 : ' '));
	}

	return dst;
}

// X_SERIAL の解放
void FreeXSerial(X_SERIAL *serial)
{
	// 引数チェック
	if (serial == NULL)
	{
		return;
	}

	Free(serial->data);
	Free(serial);
}

// X_SERIAL の比較
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2)
{
	// 引数チェック
	if (s1 == NULL || s2 == NULL)
	{
		return false;
	}

	if (s1->size != s2->size)
	{
		return false;
	}

	if (Cmp(s1->data, s2->data, s1->size) != 0)
	{
		return false;
	}

	return true;
}

// X_SERIAL のコピー
X_SERIAL *CloneXSerial(X_SERIAL *src)
{
	X_SERIAL *s;
	// 引数チェック
	if (src == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(X_SERIAL));
	s->data = ZeroMalloc(src->size);
	Copy(s->data, src->data, src->size);
	s->size = src->size;

	return s;
}

// X_SERIAL の初期化
X_SERIAL *NewXSerial(void *data, UINT size)
{
	X_SERIAL *serial;
	UCHAR *buf = (UCHAR *)data;
	UINT i;
	// 引数チェック
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	for (i = 0;i < size;i++)
	{
		if (buf[i] != 0)
		{
			break;
		}
	}
	if (i == size)
	{
		i = size - 1;
	}
	buf += i;

	serial = Malloc(sizeof(X_SERIAL));
	serial->size = size - i;
	serial->data = ZeroMalloc(size + 16);
	Copy(serial->data, buf, size - i);

	return serial;
}

// 2038 年 1 月 1 日までの日数を取得する
UINT GetDaysUntil2038()
{
	UINT64 now = SystemTime64();
	UINT64 target;
	SYSTEMTIME st;

	Zero(&st, sizeof(st));
	st.wYear = 2038;
	st.wMonth = 1;
	st.wDay = 1;

	target = SystemToUINT64(&st);

	if (now >= target)
	{
		return 0;
	}
	else
	{
		return (UINT)((target - now) / (UINT64)(1000 * 60 * 60 * 24));
	}
}

// X509 証明書を発行する
X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x;
	// 引数チェック
	if (pub == NULL || priv == NULL || name == NULL || ca == NULL)
	{
		return NULL;
	}

	x509 = NewX509(pub, priv, ca, name, days, serial);
	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);

	if (x == NULL)
	{
		return NULL;
	}

	return x;
}

// ルート証明書を作成する
X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x, *x2;
	// 引数チェック
	if (pub == NULL || priv == NULL || name == NULL)
	{
		return NULL;
	}

	x509 = NewRootX509(pub, priv, name, days, serial);
	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);
	if (x == NULL)
	{
		return NULL;
	}

	x2 = CloneX(x);
	FreeX(x);

	return x2;
}

// X509 証明書を発行する
X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	// 引数チェック
	if (pub == NULL || name == NULL || ca == NULL)
	{
		return NULL;
	}
	if (pub->private_key != false)
	{
		return NULL;
	}
	if (priv->private_key == false)
	{
		return NULL;
	}

	notBefore = SystemTime64();
	notAfter = notBefore + (UINT64)days * (UINT64)3600 * (UINT64)24 * (UINT64)1000;


	// X509 の作成
	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	// 有効期限の設定
	t1 = X509_get_notBefore(x509);
	t2 = X509_get_notAfter(x509);
	if (!UINT64ToAsn1Time(t1, notBefore))
	{
		FreeX509(x509);
		return NULL;
	}
	if (!UINT64ToAsn1Time(t2, notAfter))
	{
		FreeX509(x509);
		return NULL;
	}

	// 名前の設定
	subject_name = NameToX509Name(name);
	if (subject_name == NULL)
	{
		FreeX509(x509);
		return NULL;
	}
	issuer_name = X509_get_subject_name(ca->x509);
	if (issuer_name == NULL)
	{
		FreeX509Name(subject_name);
		FreeX509(x509);
		return NULL;
	}

	X509_set_issuer_name(x509, issuer_name);
	X509_set_subject_name(x509, subject_name);

	FreeX509Name(subject_name);

	// シリアル番号の設定
	if (serial == NULL)
	{
		char zero = 0;
		ASN1_INTEGER *s = x509->cert_info->serialNumber;
		OPENSSL_free(s->data);
		s->data = OPENSSL_malloc(sizeof(char));
		Copy(s->data, &zero, sizeof(char));
		s->length = sizeof(char);
	}
	else
	{
		ASN1_INTEGER *s = x509->cert_info->serialNumber;
		OPENSSL_free(s->data);
		s->data = OPENSSL_malloc(serial->size);
		Copy(s->data, serial->data, serial->size);
		s->length = serial->size;
	}

	Lock(openssl_lock);
	{
		// 公開鍵の設定
		X509_set_pubkey(x509, pub->pkey);

		// 署名
		X509_sign(x509, priv->pkey, EVP_sha1());
	}
	Unlock(openssl_lock);

	return x509;
}

// ルート X509 証明書を作成する
X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	// 引数チェック
	if (pub == NULL || name == NULL || priv == NULL)
	{
		return NULL;
	}
	if (days == 0)
	{
		days = 365;
	}
	if (priv->private_key == false)
	{
		return NULL;
	}
	if (pub->private_key != false)
	{
		return NULL;
	}

	notBefore = SystemTime64();
	notAfter = notBefore + (UINT64)days * (UINT64)3600 * (UINT64)24 * (UINT64)1000;

	// X509 の作成
	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	// 有効期限の設定
	t1 = X509_get_notBefore(x509);
	t2 = X509_get_notAfter(x509);
	if (!UINT64ToAsn1Time(t1, notBefore))
	{
		FreeX509(x509);
		return NULL;
	}
	if (!UINT64ToAsn1Time(t2, notAfter))
	{
		FreeX509(x509);
		return NULL;
	}

	// 名前の設定
	subject_name = NameToX509Name(name);
	if (subject_name == NULL)
	{
		FreeX509(x509);
		return NULL;
	}
	issuer_name = NameToX509Name(name);
	if (issuer_name == NULL)
	{
		FreeX509Name(subject_name);
		FreeX509(x509);
		return NULL;
	}

	X509_set_issuer_name(x509, issuer_name);
	X509_set_subject_name(x509, subject_name);

	FreeX509Name(subject_name);
	FreeX509Name(issuer_name);

	// シリアル番号の設定
	if (serial == NULL)
	{
		char zero = 0;
		ASN1_INTEGER *s = x509->cert_info->serialNumber;
		OPENSSL_free(s->data);
		s->data = OPENSSL_malloc(sizeof(char));
		Copy(s->data, &zero, sizeof(char));
		s->length = sizeof(char);
	}
	else
	{
		ASN1_INTEGER *s = x509->cert_info->serialNumber;
		OPENSSL_free(s->data);
		s->data = OPENSSL_malloc(serial->size);
		Copy(s->data, serial->data, serial->size);
		s->length = serial->size;
	}

	Lock(openssl_lock);
	{
		// 公開鍵の設定
		X509_set_pubkey(x509, pub->pkey);

		// 署名
		X509_sign(x509, priv->pkey, EVP_sha1());
	}
	Unlock(openssl_lock);

	return x509;
}

// NAME を X509_NAME に変換
void *NameToX509Name(NAME *nm)
{
	X509_NAME *xn;
	// 引数チェック
	if (nm == NULL)
	{
		return NULL;
	}

	xn = X509_NAME_new();
	if (xn == NULL)
	{
		return NULL;
	}

	// エントリの追加
	AddX509Name(xn, NID_commonName, nm->CommonName);
	AddX509Name(xn, NID_organizationName, nm->Organization);
	AddX509Name(xn, NID_organizationalUnitName, nm->Unit);
	AddX509Name(xn, NID_countryName, nm->Country);
	AddX509Name(xn, NID_stateOrProvinceName, nm->State);
	AddX509Name(xn, NID_localityName, nm->Local);

	return xn;
}

// X509_NAME にエントリを追加する
bool AddX509Name(void *xn, int nid, wchar_t *str)
{
	X509_NAME *x509_name;
	UINT utf8_size;
	BYTE *utf8;
	// 引数チェック
	if (xn == NULL || str == NULL)
	{
		return false;
	}

	// UTF-8 に変換
	utf8_size = CalcUniToUtf8(str);
	if (utf8_size == 0)
	{
		return false;
	}
	utf8 = ZeroMalloc(utf8_size + 1);
	UniToUtf8(utf8, utf8_size, str);
	utf8[utf8_size] = 0;

	// 追加
	x509_name = (X509_NAME *)xn;
	Lock(openssl_lock);
	{
		X509_NAME_add_entry_by_NID(x509_name, nid, MBSTRING_ASC, utf8, utf8_size, -1, 0);
	}
	Unlock(openssl_lock);
	Free(utf8);

	return true;
}

// X509_NAME を解放
void FreeX509Name(void *xn)
{
	X509_NAME *x509_name;
	// 引数チェック
	if (xn == NULL)
	{
		return;
	}

	x509_name = (X509_NAME *)xn;
	X509_NAME_free(x509_name);
}

// NAME の作成
NAME *NewName(wchar_t *common_name, wchar_t *organization, wchar_t *unit,
			  wchar_t *country, wchar_t *state, wchar_t *local)
{
	NAME *nm = ZeroMalloc(sizeof(NAME));

	if (UniIsEmptyStr(common_name) == false)
	{
		nm->CommonName = CopyUniStr(common_name);
	}

	if (UniIsEmptyStr(organization) == false)
	{
		nm->Organization = CopyUniStr(organization);
	}

	if (UniIsEmptyStr(unit) == false)
	{
		nm->Unit = CopyUniStr(unit);
	}

	if (UniIsEmptyStr(country) == false)
	{
		nm->Country = CopyUniStr(country);
	}

	if (UniIsEmptyStr(state) == false)
	{
		nm->State = CopyUniStr(state);
	}

	if (UniIsEmptyStr(local) == false)
	{
		nm->Local = CopyUniStr(local);
	}

	return nm;
}

// 証明書の有効期限を現在時刻で確認する
bool CheckXDateNow(X *x)
{
	// 引数チェック
	if (x == NULL)
	{
		return false;
	}

	return CheckXDate(x, SystemTime64());
}

// 証明書の有効期限を確認する
bool CheckXDate(X *x, UINT64 current_system_time)
{
	// 引数チェック
	if (x == NULL)
	{
		return false;
	}

	if (x->notBefore >= current_system_time || x->notAfter <= current_system_time)
	{
		return false;
	}
	return true;
}

// 証明書の有効期限情報を読み込む
void LoadXDates(X *x)
{
	// 引数チェック
	if (x == NULL)
	{
		return;
	}

	x->notBefore = Asn1TimeToUINT64(x->x509->cert_info->validity->notBefore);
	x->notAfter = Asn1TimeToUINT64(x->x509->cert_info->validity->notAfter);
}

// 64bit システム時刻を ASN1 時刻に変換する
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t)
{
	SYSTEMTIME st;
	// 引数チェック
	if (asn1_time == NULL)
	{
		return false;
	}

	UINT64ToSystem(&st, t);
	return SystemToAsn1Time(asn1_time, &st);
}

// システム時刻を ASN1 時刻に変換する
bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s)
{
	char tmp[20];
	ASN1_TIME *t;
	// 引数チェック
	if (asn1_time == NULL || s == NULL)
	{
		return false;
	}

	if (SystemToStr(tmp, sizeof(tmp), s) == false)
	{
		return false;
	}
	t = (ASN1_TIME *)asn1_time;
	if (t->data == NULL || t->length < sizeof(tmp))
	{
		t->data = OPENSSL_malloc(sizeof(tmp));
	}
	StrCpy((char *)t->data, t->length, tmp);
	t->length = StrLen(tmp);
	t->type = V_ASN1_UTCTIME;

	return true;
}

// システム時刻を文字列に変換する
bool SystemToStr(char *str, UINT size, SYSTEMTIME *s)
{
	// 引数チェック
	if (str == NULL || s == NULL)
	{
		return false;
	}

	Format(str, size, "%02u%02u%02u%02u%02u%02uZ",
		s->wYear % 100, s->wMonth, s->wDay,
		s->wHour, s->wMinute, s->wSecond);

	return true;
}

// ASN1 時刻を UINT64 時刻に変換する
UINT64 Asn1TimeToUINT64(void *asn1_time)
{
	SYSTEMTIME st;
	// 引数チェック
	if (asn1_time == NULL)
	{
		return 0;
	}

	if (Asn1TimeToSystem(&st, asn1_time) == false)
	{
		return 0;
	}
	return SystemToUINT64(&st);
}

// ASN1 時刻をシステム時刻に変換する
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time)
{
	ASN1_TIME *t;
	// 引数チェック
	if (s == NULL || asn1_time == NULL)
	{
		return false;
	}

	t = (ASN1_TIME *)asn1_time;
	if (StrToSystem(s, (char *)t->data) == false)
	{
		return false;
	}

	if (t->type == V_ASN1_GENERALIZEDTIME)
	{
		LocalToSystem(s, s);
	}

	return true;
}

// 文字列をシステム時刻に変換する
bool StrToSystem(SYSTEMTIME *s, char *str)
{
	// 引数チェック
	if (s == NULL || str == NULL)
	{
		return false;
	}
	if (StrLen(str) != 13)
	{
		return false;
	}
	if (str[12] != 'Z')
	{
		return false;
	}

	// 変換
	{
		char year[3] = {str[0], str[1], 0},
			month[3] = {str[2], str[3], 0},
			day[3] = {str[4], str[5], 0},
			hour[3] = {str[6], str[7], 0},
			minute[3] = {str[8], str[9], 0},
			second[3] = {str[10], str[11], 0};
		Zero(s, sizeof(SYSTEMTIME));
		s->wYear = ToInt(year);
		if (s->wYear >= 60)
		{
			s->wYear += 1900;
		}
		else
		{
			s->wYear += 2000;
		}
		s->wMonth = ToInt(month);
		s->wDay = ToInt(day);
		s->wHour = ToInt(hour);
		s->wMinute = ToInt(minute);
		s->wSecond = ToInt(second);
		NormalizeSystem(s);
	}

	return true;
}

// RSA 署名の検査
bool RsaVerify(void *data, UINT data_size, void *sign, K *k)
{
	return RsaVerifyEx(data, data_size, sign, k, 0);
}
bool RsaVerifyEx(void *data, UINT data_size, void *sign, K *k, UINT bits)
{
	UCHAR hash_data[SIGN_HASH_SIZE];
	UCHAR decrypt_data[SIGN_HASH_SIZE];
	// 引数チェック
	if (data == NULL || sign == NULL || k == NULL || k->private_key != false)
	{
		return false;
	}
	if (bits == 0)
	{
		bits = 1024;
	}

	// データをハッシュ
	if (HashForSign(hash_data, sizeof(hash_data), data, data_size) == false)
	{
		return false;
	}

	// 署名を解読
	if (RSA_public_decrypt(bits / 8, sign, decrypt_data, k->pkey->pkey.rsa, RSA_PKCS1_PADDING) <= 0)
	{
		return false;
	}

	// 比較
	if (Cmp(decrypt_data, hash_data, sizeof(SIGN_HASH_SIZE)) != 0)
	{
		return false;
	}

	return true;
}

// RSA 署名
bool RsaSign(void *dst, void *src, UINT size, K *k)
{
	return RsaSignEx(dst, src, size, k, 0);
}
bool RsaSignEx(void *dst, void *src, UINT size, K *k, UINT bits)
{
	UCHAR hash[SIGN_HASH_SIZE];
	// 引数チェック
	if (dst == NULL || src == NULL || k == NULL || k->pkey->type != EVP_PKEY_RSA)
	{
		return false;
	}
	if (bits == 0)
	{
		bits = 1024;
	}

	Zero(dst, bits / 8);

	// ハッシュ
	if (HashForSign(hash, sizeof(hash), src, size) == false)
	{
		return false;
	}

	// 署名
	if (RSA_private_encrypt(sizeof(hash), hash, dst, k->pkey->pkey.rsa, RSA_PKCS1_PADDING) <= 0)
	{
		return false;
	}

	return true;
}

// SHA-1 による署名データの生成
bool HashForSign(void *dst, UINT dst_size, void *src, UINT src_size)
{
	UCHAR *buf = (UCHAR *)dst;
	UCHAR sign_data[] =
	{
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
		0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
	};
	// 引数チェック
	if (dst == NULL || src == NULL || src_size == 0 || MIN_SIGN_HASH_SIZE > dst_size)
	{
		return false;
	}

	// ヘッダ部分
	Copy(buf, sign_data, sizeof(sign_data));

	// ハッシュ
	HashSha1(HASHED_DATA(buf), src, src_size);

	return true;
}

// RSA 公開鍵による復号化
bool RsaPublicDecrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// 引数チェック
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	Lock(openssl_lock);
	{
		ret = RSA_public_decrypt(size, src, tmp, k->pkey->pkey.rsa, RSA_NO_PADDING);
	}
	Unlock(openssl_lock);
	if (ret <= 0)
	{
/*		Debug("RSA Error: 0x%x\n",
			ERR_get_error());
*/		Free(tmp);
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

	return true;
}

// RSA 秘密鍵による暗号化
bool RsaPrivateEncrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// 引数チェック
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	Lock(openssl_lock);
	{
		ret = RSA_private_encrypt(size, src, tmp, k->pkey->pkey.rsa, RSA_NO_PADDING);
	}
	Unlock(openssl_lock);
	if (ret <= 0)
	{
/*		Debug("RSA Error: %u\n",
			ERR_GET_REASON(ERR_get_error()));
*/		Free(tmp);
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

	return true;
}

// RSA 秘密鍵による復号化
bool RsaPrivateDecrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// 引数チェック
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	Lock(openssl_lock);
	{
		ret = RSA_private_decrypt(size, src, tmp, k->pkey->pkey.rsa, RSA_NO_PADDING);
	}
	Unlock(openssl_lock);
	if (ret <= 0)
	{
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

	return true;
}

// RSA 公開鍵による暗号化
bool RsaPublicEncrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// 引数チェック
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	Lock(openssl_lock);
	{
		ret = RSA_public_encrypt(size, src, tmp, k->pkey->pkey.rsa, RSA_NO_PADDING);
	}
	Unlock(openssl_lock);
	if (ret <= 0)
	{
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

	return true;
}

// RSA 動作環境チェック
bool RsaCheckEx()
{
	UINT num = 20;
	UINT i;

	for (i = 0;i < num;i++)
	{
		if (RsaCheck())
		{
			return true;
		}

		SleepThread(100);
	}

	return false;
}
bool RsaCheck()
{
	RSA *rsa;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	UINT bit = 32;
	// 引数チェック

	// 鍵生成
	Lock(openssl_lock);
	{
		rsa = RSA_generate_key(bit, RSA_F4, NULL, NULL);
	}
	Unlock(openssl_lock);
	if (rsa == NULL)
	{
		Debug("RSA_generate_key: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	// 秘密鍵
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// 公開鍵
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	pub_key = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	RSA_free(rsa);

	size = RsaPublicSize(pub_key);

	if (size != ((bit + 7) / 8))
	{
		FreeK(priv_key);
		FreeK(pub_key);

		return false;
	}

	FreeK(priv_key);
	FreeK(pub_key);

	return true;
}

// RSA 鍵の生成
bool RsaGen(K **priv, K **pub, UINT bit)
{
	RSA *rsa;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	// 引数チェック
	if (priv == NULL || pub == NULL)
	{
		return false;
	}
	if (bit == 0)
	{
		bit = 1024;
	}

	// 鍵生成
	Lock(openssl_lock);
	{
		rsa = RSA_generate_key(bit, RSA_F4, NULL, NULL);
	}
	Unlock(openssl_lock);
	if (rsa == NULL)
	{
		Debug("RSA_generate_key: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	// 秘密鍵
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// 公開鍵
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	pub_key = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	*priv = priv_key;
	*pub = pub_key;

	RSA_free(rsa);

	size = RsaPublicSize(*pub);

	if (size != ((bit + 7) / 8))
	{
		FreeK(*priv);
		FreeK(*pub);

		return RsaGen(priv, pub, bit);
	}

	return true;
}

// 証明書 X が証明書 x_issuer の発行者によって署名されているかどうか確認する
bool CheckX(X *x, X *x_issuer)
{
	K *k;
	bool ret;
	// 引数チェック
	if (x == NULL || x_issuer == NULL)
	{
		return false;
	}

	k = GetKFromX(x_issuer);
	if (k == NULL)
	{
		return false;
	}

	ret = CheckSignature(x, k);
	FreeK(k);

	return ret;
}

// 証明書 X の署名を公開鍵 K で確認する
bool CheckSignature(X *x, K *k)
{
	// 引数チェック
	if (x == NULL || k == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	{
		if (X509_verify(x->x509, k->pkey) == 0)
		{
			Unlock(openssl_lock);
			return false;
		}
	}
	Unlock(openssl_lock);
	return true;
}

// 証明書から公開鍵を取得する
K *GetKFromX(X *x)
{
	EVP_PKEY *pkey;
	K *k;
	// 引数チェック
	if (x == NULL)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
		pkey = X509_get_pubkey(x->x509);
	}
	Unlock(openssl_lock);
	if (pkey == NULL)
	{
		return NULL;
	}

	k = ZeroMalloc(sizeof(K));
	k->pkey = pkey;

	return k;
}

// 名前の比較
bool CompareName(NAME *n1, NAME *n2)
{
	// 引数チェック
	if (n1 == NULL || n2 == NULL)
	{
		return false;
	}

	// 名前比較
	if (UniStrCmpi(n1->CommonName, n2->CommonName) == 0 &&
		UniStrCmpi(n1->Organization, n2->Organization) == 0 &&
		UniStrCmpi(n1->Unit, n2->Unit) == 0 &&
		UniStrCmpi(n1->Country, n2->Country) == 0 &&
		UniStrCmpi(n1->State, n2->State) == 0 &&
		UniStrCmpi(n1->Local, n2->Local) == 0)
	{
		return true;
	}

	return false;
}

// X の名前の解放
void FreeXNames(X *x)
{
	// 引数チェック
	if (x == NULL)
	{
		return;
	}

	FreeName(x->issuer_name);
	x->issuer_name = NULL;

	FreeName(x->subject_name);
	x->subject_name = NULL;
}

// 名前の解放
void FreeName(NAME *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	// 文字列を解放
	Free(n->CommonName);
	Free(n->Organization);
	Free(n->Unit);
	Free(n->Country);
	Free(n->State);
	Free(n->Local);

	// オブジェクトを解放
	Free(n);

	return;
}

// 証明書の名前を取得する
void LoadXNames(X *x)
{
	X509 *x509;
	// 引数チェック
	if (x == NULL)
	{
		return;
	}

	x509 = x->x509;
	x->issuer_name = X509NameToName(X509_get_issuer_name(x509));
	x->subject_name = X509NameToName(X509_get_subject_name(x509));
}

// X509_NAME 構造体を NAME 構造体に変換
NAME *X509NameToName(void *xn)
{
	NAME *n;
	// 引数チェック
	if (xn == NULL)
	{
		return NULL;
	}

	n = ZeroMalloc(sizeof(NAME));

	// 文字列を順番に取得する
	n->CommonName = GetUniStrFromX509Name(xn, NID_commonName);
	n->Organization = GetUniStrFromX509Name(xn, NID_organizationName);
	n->Unit = GetUniStrFromX509Name(xn, NID_organizationalUnitName);
	n->Country = GetUniStrFromX509Name(xn, NID_countryName);
	n->State = GetUniStrFromX509Name(xn, NID_stateOrProvinceName);
	n->Local = GetUniStrFromX509Name(xn, NID_localityName);

	return n;
}

// X509_NAME 構造体の中から Unicode 文字列を読み込む
wchar_t *GetUniStrFromX509Name(void *xn, int nid)
{
	UCHAR txt[1024];
	bool b = false;
	UINT i, size;
	int index;
	bool unicode = false;
	bool is_utf_8 = false;
	ASN1_OBJECT *obj;
	ASN1_STRING *data;
	// 引数チェック
	if (xn == NULL || nid == 0)
	{
		return NULL;
	}

	Zero(txt, sizeof(txt));
	if (X509_NAME_get_text_by_NID(xn, nid, (char *)txt, sizeof(txt) - 2) <= 0)
	{
		return NULL;
	}

	obj = OBJ_nid2obj(nid);
	if (obj == NULL)
	{
		return NULL;
	}
	index = X509_NAME_get_index_by_OBJ(xn, obj, -1);
	if (index < 0)
	{
		return NULL;
	}
	data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn, index));
	if (data == NULL)
	{
		return NULL;
	}
	if (data->type == V_ASN1_BMPSTRING)
	{
		unicode = true;
	}
	if (data->type == V_ASN1_UTF8STRING || data->type == V_ASN1_T61STRING)
	{
		is_utf_8 = true;
	}

	size = UniStrLen((wchar_t *)txt) * 4 + 8;
	for (i = 0;i < size;i++)
	{
		if (txt[i] >= 0x80)
		{
			unicode = true;
			break;
		}
	}

	if (is_utf_8)
	{
		wchar_t *ret;
		UINT ret_size;

		ret_size = CalcUtf8ToUni(txt, StrLen(txt));
		ret = ZeroMalloc(ret_size + 8);
		Utf8ToUni(ret, ret_size, txt, StrLen(txt));

		return ret;
	}
	else if (unicode == false)
	{
		wchar_t tmp[1024];
		StrToUni(tmp, sizeof(tmp), (char *)txt);
		return CopyUniStr(tmp);
	}
	else
	{
		EndianUnicode((wchar_t *)txt);
		return CopyUniStr((wchar_t *)txt);
	}
}

// 証明書 x1 と x2 が等しいかどうかチェックする
bool CompareX(X *x1, X *x2)
{
	// 引数チェック
	if (x1 == NULL || x2 == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	if (X509_cmp(x1->x509, x2->x509) == 0)
	{
		Unlock(openssl_lock);
		return true;
	}
	else
	{
		Unlock(openssl_lock);
		return false;
	}
}

// K が X の秘密鍵かどうかチェックする
bool CheckXandK(X *x, K *k)
{
	// 引数チェック
	if (x == NULL || k == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	if (X509_check_private_key(x->x509, k->pkey) != 0)
	{
		Unlock(openssl_lock);
		return true;
	}
	else
	{
		Unlock(openssl_lock);
		return false;
	}
}

// ファイルから X を読み込む
X *FileToX(char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	X *ret = FileToXW(filename_w);

	Free(filename_w);

	return ret;
}
X *FileToXW(wchar_t *filename)
{
	bool text;
	BUF *b;
	X *x;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	text = IsBase64(b);

	x = BufToX(b, text);
	FreeBuf(b);

	return x;
}

// X をファイルに書き出す
bool XToFile(X *x, char *filename, bool text)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret = XToFileW(x, filename_w, text);

	Free(filename_w);

	return ret;
}
bool XToFileW(X *x, wchar_t *filename, bool text)
{
	BUF *b;
	bool ret;
	// 引数チェック
	if (x == NULL || filename == NULL)
	{
		return false;
	}

	b = XToBuf(x, text);
	if (b == NULL)
	{
		return false;
	}

	ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

// ファイルから K を読み込む
K *FileToK(char *filename, bool private_key, char *password)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	K *ret;

	ret = FileToKW(filename_w, private_key, password);

	Free(filename_w);

	return ret;
}
K *FileToKW(wchar_t *filename, bool private_key, char *password)
{
	bool text;
	BUF *b;
	K *k;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	text = IsBase64(b);
	if (text == false)
	{
		k = BufToK(b, private_key, false, NULL);
	}
	else
	{
		k = BufToK(b, private_key, true, NULL);
		if (k == NULL)
		{
			k = BufToK(b, private_key, true, password);
		}
	}

	FreeBuf(b);

	return k;
}

// K をファイルに保存する
bool KToFile(K *k, char *filename, bool text, char *password)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret = KToFileW(k, filename_w, text, password);

	Free(filename_w);

	return ret;
}
bool KToFileW(K *k, wchar_t *filename, bool text, char *password)
{
	BUF *b;
	bool ret;
	// 引数チェック
	if (k == NULL || filename == NULL)
	{
		return false;
	}

	b = KToBuf(k, text, password);
	if (b == NULL)
	{
		return false;
	}

	ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

// K を BUF に変換する
BUF *KToBuf(K *k, bool text, char *password)
{
	BUF *buf;
	BIO *bio;
	// 引数チェック
	if (k == NULL)
	{
		return NULL;
	}

	bio = KToBio(k, text, password);
	if (bio == NULL)
	{
		return NULL;
	}

	buf = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(buf, 0, 0);

	return buf;
}

// K を BIO に変換する
BIO *KToBio(K *k, bool text, char *password)
{
	BIO *bio;
	// 引数チェック
	if (k == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	if (k->private_key)
	{
		// 秘密鍵
		if (text == false)
		{
			// バイナリ形式
			Lock(openssl_lock);
			{
				i2d_PrivateKey_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			// テキスト形式
			if (password == 0 || StrLen(password) == 0)
			{
				// 暗号化無し
				Lock(openssl_lock);
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL);
				}
				Unlock(openssl_lock);
			}
			else
			{
				// 暗号化する
				CB_PARAM cb;
				cb.password = password;
				Lock(openssl_lock);
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, EVP_des_ede3_cbc(),
						NULL, 0, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
				}
				Unlock(openssl_lock);
			}
		}
	}
	else
	{
		// 公開鍵
		if (text == false)
		{
			// バイナリ形式
			Lock(openssl_lock);
			{
				i2d_PUBKEY_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			// テキスト形式
			Lock(openssl_lock);
			{
				PEM_write_bio_PUBKEY(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
	}

	return bio;
}

// BUF が Base64 エンコードされているかどうか調べる
bool IsBase64(BUF *b)
{
	UINT i;
	// 引数チェック
	if (b == NULL)
	{
		return false;
	}

	for (i = 0;i < b->Size;i++)
	{
		char c = ((char *)b->Buf)[i];
		bool b = false;
		if ('a' <= c && c <= 'z')
		{
			b = true;
		}
		else if ('A' <= c && c <= 'Z')
		{
			b = true;
		}
		else if ('0' <= c && c <= '9')
		{
			b = true;
		}
		else if (c == ':' || c == '.' || c == ';' || c == ',')
		{
			b = true;
		}
		else if (c == '!' || c == '&' || c == '#' || c == '(' || c == ')')
		{
			b = true;
		}
		else if (c == '-' || c == ' ')
		{
			b = true;
		}
		else if (c == 13 || c == 10 || c == EOF)
		{
			b = true;
		}
		else if (c == '\t' || c == '=' || c == '+' || c == '/')
		{
			b = true;
		}
		if (b == false)
		{
			return false;
		}
	}
	return true;
}

// BUF に含まれている K が暗号化されているかどうか調べる
bool IsEncryptedK(BUF *b, bool private_key)
{
	K *k;
	// 引数チェック
	if (b == NULL)
	{
		return false;
	}
	if (IsBase64(b) == false)
	{
		return false;
	}

	k = BufToK(b, private_key, true, NULL);
	if (k != NULL)
	{
		FreeK(k);
		return false;
	}

	return true;
}

// BUF を K に変換
K *BufToK(BUF *b, bool private_key, bool text, char *password)
{
	BIO *bio;
	K *k;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	k = BioToK(bio, private_key, text, password);
	FreeBio(bio);

	return k;
}

// K を解放
void FreeK(K *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	FreePKey(k->pkey);
	Free(k);
}

// 秘密鍵を解放
void FreePKey(EVP_PKEY *pkey)
{
	// 引数チェック
	if (pkey == NULL)
	{
		return;
	}

	EVP_PKEY_free(pkey);
}

// BIO を K に変換する
K *BioToK(BIO *bio, bool private_key, bool text, char *password)
{
	EVP_PKEY *pkey;
	K *k;
	// 引数チェック
	if (bio == NULL)
	{
		return NULL;
	}

	if (password != NULL && StrLen(password) == 0)
	{
		password = NULL;
	}

	if (private_key == false)
	{
		// 公開鍵
		if (text == false)
		{
			// バイナリ形式
			pkey = d2i_PUBKEY_bio(bio, NULL);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			// テキスト形式
			CB_PARAM cb;
			cb.password = password;
			Lock(openssl_lock);
			{
				pkey = PEM_read_bio_PUBKEY(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			Unlock(openssl_lock);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}
	else
	{
		if (text == false)
		{
			// バイナリ形式
			Lock(openssl_lock);
			{
				pkey = d2i_PrivateKey_bio(bio, NULL);
			}
			Unlock(openssl_lock);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			// テキスト形式
			CB_PARAM cb;
			cb.password = password;
			Lock(openssl_lock);
			{
				pkey = PEM_read_bio_PrivateKey(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			Unlock(openssl_lock);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}

	k = ZeroMalloc(sizeof(K));
	k->pkey = pkey;
	k->private_key = private_key;

	return k;
}

// パスワードコールバック関数
int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param)
{
	CB_PARAM *cb;
	// 引数チェック
	if (buf == NULL || param == NULL || bufsize == 0)
	{
		return 0;
	}

	cb = (CB_PARAM *)param;
	if (cb->password == NULL)
	{
		return 0;
	}

	return StrCpy(buf, bufsize, cb->password);
}

// X を BUF に変換する
BUF *XToBuf(X *x, bool text)
{
	BIO *bio;
	BUF *b;
	// 引数チェック
	if (x == NULL)
	{
		return NULL;
	}

	bio = XToBio(x, text);
	if (bio == NULL)
	{
		return NULL;
	}

	b = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(b, 0, 0);

	return b;
}

// X を BIO に変換する
BIO *XToBio(X *x, bool text)
{
	BIO *bio;
	// 引数チェック
	if (x == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	Lock(openssl_lock);
	{
		if (text == false)
		{
			// バイナリ形式
			i2d_X509_bio(bio, x->x509);
		}
		else
		{
			// テキスト形式
			PEM_write_bio_X509(bio, x->x509);
		}
	}
	Unlock(openssl_lock);

	return bio;
}

// X の解放
void FreeX(X *x)
{
	// 引数チェック
	if (x == NULL)
	{
		return;
	}

	// 名前解放
	FreeXNames(x);


	// シリアル解放
	FreeXSerial(x->serial);

	if (x->do_not_free == false)
	{
		FreeX509(x->x509);
	}
	Free(x);
}

// X509 の解放
void FreeX509(X509 *x509)
{
	// 引数チェック
	if (x509 == NULL)
	{
		return;
	}

	Lock(openssl_lock);
	{
		X509_free(x509);
	}
	Unlock(openssl_lock);
}

// BUF を X に変換する
X *BufToX(BUF *b, bool text)
{
	X *x;
	BIO *bio;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	x = BioToX(bio, text);

	FreeBio(bio);

	return x;
}

// X のダイジェストを取得する
void GetXDigest(X *x, UCHAR *buf, bool sha1)
{
	// 引数チェック
	if (x == NULL)
	{
		return;
	}

	if (sha1 == false)
	{
		UINT size = MD5_SIZE;
		X509_digest(x->x509, EVP_md5(), buf, (unsigned int *)&size);
	}
	else
	{
		UINT size = SHA1_SIZE;
		X509_digest(x->x509, EVP_sha1(), buf, (unsigned int *)&size);
	}
}

// BIO を X に変換する
X *BioToX(BIO *bio, bool text)
{
	X *x;
	X509 *x509;
	// 引数チェック
	if (bio == NULL)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
		// x509 の読み込み
		if (text == false)
		{
			// バイナリモード
			x509 = d2i_X509_bio(bio, NULL);
		}
		else
		{
			// テキストモード
			x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		}
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);

	if (x == NULL)
	{
		return NULL;
	}

	return x;
}

// X509 を X に変換する
X *X509ToX(X509 *x509)
{
	X *x;
	K *k;
	BUF *b;
	UINT size;
	UINT type;
	// 引数チェック
	if (x509 == NULL)
	{
		return NULL;
	}

	x = ZeroMalloc(sizeof(X));
	x->x509 = x509;

	// 名前
	LoadXNames(x);

	// 有効期限
	LoadXDates(x);

	// ルート証明書かどうかチェックする
	if (CompareName(x->issuer_name, x->subject_name))
	{
		K *pubkey = GetKFromX(x);
		if (pubkey != NULL)
		{
			if (CheckXandK(x, pubkey))
			{
				x->root_cert = true;
			}
			FreeK(pubkey);
		}
	}

	// シリアル番号の取得
	x->serial = NewXSerial(x509->cert_info->serialNumber->data,
		x509->cert_info->serialNumber->length);
	if (x->serial == NULL)
	{
		char zero = 0;
		x->serial = NewXSerial(&zero, sizeof(char));
	}

	k = GetKFromX(x);
	if (k == NULL)
	{
		FreeX(x);
		return NULL;
	}

	b = KToBuf(k, false, NULL);

	size = b->Size;
	type = k->pkey->type;

	FreeBuf(b);

	FreeK(k);

	if (type == EVP_PKEY_RSA)
	{
		x->is_compatible_bit = true;

		switch (size)
		{
		case 162:
			x->bits = 1024;
			break;

		case 226:
			x->bits = 1536;
			break;

		case 294:
			x->bits = 2048;
			break;

		case 442:
			x->bits = 3072;
			break;

		case 550:
			x->bits = 4096;
			break;

		default:
			x->is_compatible_bit = false;
			break;
		}
	}

	return x;
}

// BIO を作成する
BIO *NewBio()
{
	return BIO_new(BIO_s_mem());
}

// BIO を解放する
void FreeBio(BIO *bio)
{
	// 引数チェック
	if (bio == NULL)
	{
		return;
	}

	BIO_free(bio);
}

// BIO を BUF に変換する
BUF *BioToBuf(BIO *bio)
{
	BUF *b;
	UINT size;
	void *tmp;
	// 引数チェック
	if (bio == NULL)
	{
		return NULL;
	}

	BIO_seek(bio, 0);
	size = bio->num_write;
	tmp = Malloc(size);
	BIO_read(bio, tmp, size);

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	return b;
}

// BUF を BIO に変換する
BIO *BufToBio(BUF *b)
{
	BIO *bio;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
		{
			Unlock(openssl_lock);
			return NULL;
		}
		BIO_write(bio, b->Buf, b->Size);
		BIO_seek(bio, 0);
	}
	Unlock(openssl_lock);

	return bio;
}

// 128bit 乱数生成
void Rand128(void *buf)
{
	Rand(buf, 16);
}

// 64bit 乱数生成
UINT64 Rand64()
{
	UINT64 i;
	Rand(&i, sizeof(i));
	return i;
}

// 32bit 乱数生成
UINT Rand32()
{
	UINT i;
	Rand(&i, sizeof(i));
	return i;
}

// 16bit 乱数生成
USHORT Rand16()
{
	USHORT i;
	Rand(&i, sizeof(i));
	return i;
}

// 8bit 乱数生成
UCHAR Rand8()
{
	UCHAR i;
	Rand(&i, sizeof(i));
	return i;
}

// 1bit 乱数生成
bool Rand1()
{
	return (Rand32() % 2) == 0 ? false : true;
}

// 乱数生成
void Rand(void *buf, UINT size)
{
	// 引数チェック
	if (buf == NULL || size == 0)
	{
		return;
	}
	RAND_bytes(buf, size);
}

// OpenSSL が確保しているスレッド固有情報を削除する
void FreeOpenSSLThreadState()
{
	ERR_remove_state(0);
}

// 暗号化ライブラリの解放
void FreeCryptLibrary()
{
	openssl_inited = false;

	DeleteLock(openssl_lock);
	openssl_lock = NULL;
//	RAND_Free_For_SoftEther();
	OpenSSL_FreeLock();
}

// 暗号化ライブラリの初期化
void InitCryptLibrary()
{
	char tmp[16];
//	RAND_Init_For_SoftEther()
	openssl_lock = NewLock();
	SSL_library_init();
	//OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	SSLeay_add_all_digests();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

#ifdef	OS_UNIX
	{
		char *name1 = "/dev/random";
		char *name2 = "/dev/urandom";
		IO *o;
		o = FileOpen(name1, false);
		if (o == NULL)
		{
			o = FileOpen(name2, false);
			if (o == NULL)
			{
				UINT64 now = SystemTime64();
				BUF *b;
				UINT i;
				b = NewBuf();
				for (i = 0;i < 4096;i++)
				{
					UCHAR c = rand() % 256;
					WriteBuf(b, &c, 1);
				}
				WriteBuf(b, &now, sizeof(now));
				RAND_seed(b->Buf, b->Size);
				FreeBuf(b);
			}
			else
			{
				FileClose(o);
			}
		}
		else
		{
			FileClose(o);
		}
	}
#endif	// OS_UNIX

	RAND_poll();

#ifdef	OS_WIN32
//	RAND_screen();
#endif
	Rand(tmp, sizeof(tmp));
	OpenSSL_InitLock();

	openssl_inited = true;
}

// 内部ハッシュ関数
void InternalHash(void *dst, void *src, UINT size, bool sha1)
{
	// 引数チェック
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	if (sha1 == false)
	{
		// MD5 ハッシュ
		MD5(src, size, dst);
	}
	else
	{
		// SHA ハッシュ
		SHA(src, size, dst);
	}
}

// SHA-1 専用ハッシュ関数
void HashSha1(void *dst, void *src, UINT size)
{
	SHA1(src, size, dst);
}

// ハッシュ関数
void Hash(void *dst, void *src, UINT size, bool sha1)
{
	InternalHash(dst, src, size, sha1);
}

// 新しい CRYPT オブジェクトの作成
CRYPT *NewCrypt(void *key, UINT size)
{
	CRYPT *c = ZeroMalloc(sizeof(CRYPT));

	SetKey(c, key, size);

	return c;
}

// CRYPT オブジェクトの解放
void FreeCrypt(CRYPT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// メモリ解放
	Free(c);
}

// 暗号化と解読
void InternalEncrypt(CRYPT *c, void *dst, void *src, UINT size)
{
	UINT x, y, sx, sy;
	UINT *state;
	UCHAR *endsrc;
	UCHAR *s = (UCHAR *)src;
	UCHAR *d = (UCHAR *)dst;
	// 引数チェック
	if (c == NULL || dst == NULL || src == NULL || size == 0)
	{
		return;
	}

	state = (UINT *)c->state;
	x = c->x;
	y = c->y;

	for (endsrc = s + size;s != endsrc;s++, d++)
	{
		x = (x + 1) & 0xff;
		sx = state[x];
		y = (sx + y) & 0xff;
		state[x] = sy = state[y];
		state[y] = sx;
		*d = *s ^ state[(sx + sy) & 0xff];
	}
	c->x = x;
	c->y = y;
}
void Encrypt(CRYPT *c, void *dst, void *src, UINT size)
{
	InternalEncrypt(c, dst, src, size);
}

// 鍵の更新
void SetKey(CRYPT *c, void *key, UINT size)
{
	UINT i, t, u, ki, si;
	UINT *state;
	UCHAR *k = (UCHAR *)key;
	// 引数チェック
	if (c == NULL || key == NULL)
	{
		return;
	}

	// 鍵のセット
	state = (UINT *)c->state;
	c->x = c->y = 0;
	for (i = 0;i < 256;i++)
	{
		state[i] = i;
	}
	ki = si = 0;

	for (i = 0;i < 256;i++)
	{
		t = state[i];
		si = (si + k[ki] + t) & 0xff;
		u = state[si];
		state[si] = t;
		state[i] = u;
		if (++ki >= size)
		{
			ki = 0;
		}
	}
}

