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

// Encrypt.h
// Encrypt.c のヘッダ

#ifndef	ENCRYPT_H
#define	ENCRYPT_H

// OpenSSL の関数
void RAND_Init_For_SoftEther();
void RAND_Free_For_SoftEther();



// 定数
#define	MIN_SIGN_HASH_SIZE		(15 + SHA1_SIZE)
#define	SIGN_HASH_SIZE			(MIN_SIGN_HASH_SIZE)

// マクロ
#define	HASHED_DATA(p)			(((UCHAR *)p) + 15)



// 暗号化コンテキスト
struct CRYPT
{
	int x, y;
	int state[256];
};

// 証明書内の名前
struct NAME
{
	wchar_t *CommonName;		// CN
	wchar_t *Organization;		// O
	wchar_t *Unit;				// OU
	wchar_t *Country;			// C
	wchar_t *State;				// ST
	wchar_t *Local;				// L
};

// シリアル番号
struct X_SERIAL
{
	UINT size;
	UCHAR *data;
};

// 証明書
struct X
{
	X509 *x509;
	NAME *issuer_name;
	NAME *subject_name;
	bool root_cert;
	UINT64 notBefore;
	UINT64 notAfter;
	X_SERIAL *serial;
	bool do_not_free;
	bool is_compatible_bit;
	UINT bits;
};

// 鍵
struct K
{
	EVP_PKEY *pkey;
	bool private_key;
};

// PKCS#12
struct P12
{
	PKCS12 *pkcs12;
};

// CEL
struct X_CRL
{
	X509_CRL *Crl;
};

// 定数
#define	MD5_SIZE	16
#define	SHA1_SIZE	20

// OpenSSL のロック
extern LOCK **ssl_lock_obj;

// 関数プロトタイプ
CRYPT *NewCrypt(void *key, UINT size);
void FreeCrypt(CRYPT *c);
void SetKey(CRYPT *c, void *key, UINT size);
void Encrypt(CRYPT *c, void *dst, void *src, UINT size);
void InternalEncrypt(CRYPT *c, void *dst, void *src, UINT size);
void Hash(void *dst, void *src, UINT size, bool sha1);
void HashSha1(void *dst, void *src, UINT size);
void InternalHash(void *dst, void *src, UINT size, bool sha1);
void InitCryptLibrary();
void Rand(void *buf, UINT size);
void Rand128(void *buf);
UINT64 Rand64();
UINT Rand32();
USHORT Rand16();
UCHAR Rand8();
bool Rand1();
UINT HashPtrToUINT(void *p);

void CertTest();
BIO *BufToBio(BUF *b);
BUF *BioToBuf(BIO *bio);
BIO *NewBio();
void FreeBio(BIO *bio);
X *BioToX(BIO *bio, bool text);
X *BufToX(BUF *b, bool text);
void FreeX509(X509 *x509);
void FreeX(X *x);
BIO *XToBio(X *x, bool text);
BUF *XToBuf(X *x, bool text);
K *BioToK(BIO *bio, bool private_key, bool text, char *password);
int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param);
void FreePKey(EVP_PKEY *pkey);
void FreeK(K *k);
K *BufToK(BUF *b, bool private_key, bool text, char *password);
bool IsEncryptedK(BUF *b, bool private_key);
bool IsBase64(BUF *b);
BIO *KToBio(K *k, bool text, char *password);
BUF *KToBuf(K *k, bool text, char *password);
X *FileToX(char *filename);
X *FileToXW(wchar_t *filename);
bool XToFile(X *x, char *filename, bool text);
bool XToFileW(X *x, wchar_t *filename, bool text);
K *FileToK(char *filename, bool private_key, char *password);
K *FileToKW(wchar_t *filename, bool private_key, char *password);
bool KToFile(K *k, char *filename, bool text, char *password);
bool KToFileW(K *k, wchar_t *filename, bool text, char *password);
bool CheckXandK(X *x, K *k);
bool CompareX(X *x1, X *x2);
NAME *X509NameToName(void *xn);
wchar_t *GetUniStrFromX509Name(void *xn, int nid);
void LoadXNames(X *x);
void FreeXNames(X *x);
void FreeName(NAME *n);
bool CompareName(NAME *n1, NAME *n2);
K *GetKFromX(X *x);
bool CheckSignature(X *x, K *k);
X *X509ToX(X509 *x509);
bool CheckX(X *x, X *x_issuer);
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time);
bool StrToSystem(SYSTEMTIME *s, char *str);
UINT64 Asn1TimeToUINT64(void *asn1_time);
bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s);
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t);
bool SystemToStr(char *str, UINT size, SYSTEMTIME *s);
void LoadXDates(X *x);
bool CheckXDate(X *x, UINT64 current_system_time);
bool CheckXDateNow(X *x);
NAME *NewName(wchar_t *common_name, wchar_t *organization, wchar_t *unit,
			  wchar_t *country, wchar_t *state, wchar_t *local);
void *NameToX509Name(NAME *nm);
void FreeX509Name(void *xn);
bool AddX509Name(void *xn, int nid, wchar_t *str);
X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
UINT GetDaysUntil2038();
X_SERIAL *NewXSerial(void *data, UINT size);
void FreeXSerial(X_SERIAL *serial);
char *ByteToStr(BYTE *src, UINT src_size);
P12 *BioToP12(BIO *bio);
P12 *PKCS12ToP12(PKCS12 *pkcs12);
P12 *BufToP12(BUF *b);
BIO *P12ToBio(P12 *p12);
BUF *P12ToBuf(P12 *p12);
void FreePKCS12(PKCS12 *pkcs12);
void FreeP12(P12 *p12);
P12 *FileToP12(char *filename);
P12 *FileToP12W(wchar_t *filename);
bool P12ToFile(P12 *p12, char *filename);
bool P12ToFileW(P12 *p12, wchar_t *filename);
bool ParseP12(P12 *p12, X **x, K **k, char *password);
bool IsEncryptedP12(P12 *p12);
P12 *NewP12(X *x, K *k, char *password);
X *CloneX(X *x);
K *CloneK(K *k);
void FreeCryptLibrary();
void GetPrintNameFromX(wchar_t *str, UINT size, X *x);
void GetPrintNameFromXA(char *str, UINT size, X *x);
void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromX(wchar_t *str, UINT size, X *x);
void GetAllNameFromA(char *str, UINT size, X *x);
void GetAllNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromXEx(wchar_t *str, UINT size, X *x);
void GetAllNameFromXExA(char *str, UINT size, X *x);
BUF *BigNumToBuf(BIGNUM *bn);
BIGNUM *BinToBigNum(void *data, UINT size);
BIGNUM *BufToBigNum(BUF *b);
X_SERIAL *CloneXSerial(X_SERIAL *src);
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2);
void GetXDigest(X *x, UCHAR *buf, bool sha1);
NAME *CopyName(NAME *n);


bool RsaGen(K **priv, K **pub, UINT bit);
bool RsaCheck();
bool RsaCheckEx();
bool RsaPublicEncrypt(void *dst, void *src, UINT size, K *k);
bool RsaPrivateDecrypt(void *dst, void *src, UINT size, K *k);
bool RsaPrivateEncrypt(void *dst, void *src, UINT size, K *k);
bool RsaPublicDecrypt(void *dst, void *src, UINT size, K *k);
bool RsaSign(void *dst, void *src, UINT size, K *k);
bool RsaSignEx(void *dst, void *src, UINT size, K *k, UINT bits);
bool HashForSign(void *dst, UINT dst_size, void *src, UINT src_size);
bool RsaVerify(void *data, UINT data_size, void *sign, K *k);
bool RsaVerifyEx(void *data, UINT data_size, void *sign, K *k, UINT bits);
UINT RsaPublicSize(K *k);
void RsaPublicToBin(K *k, void *data);
BUF *RsaPublicToBuf(K *k);
K *RsaBinToPublic(void *data, UINT size);

X_CRL *FileToXCrl(char *filename);
X_CRL *FileToXCrlW(wchar_t *filename);
X_CRL *BufToXCrl(BUF *b);
void FreeXCrl(X_CRL *r);
bool IsXRevokedByXCrl(X *x, X_CRL *r);
bool IsXRevoked(X *x);



void OpenSSL_InitLock();
void OpenSSL_FreeLock();
void OpenSSL_Lock(int mode, int n, const char *file, int line);
unsigned long OpenSSL_Id(void);
void FreeOpenSSLThreadState();

#ifdef	ENCRYPT_C
// 内部関数


#endif	// ENCRYPT_C

#endif	// ENCRYPT_H

