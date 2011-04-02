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

// MayaType.h
// Mayaqua Kernel 型宣言ヘッダファイル

#ifndef	MAYATYPE_H
#define	MAYATYPE_H

// windows.h ヘッダが include されているかどうかをチェック
#ifndef	WINDOWS_H
#ifdef	_WINDOWS_
#define	WINDOWS_H
#endif	// _WINDOWS_
#endif	// WINDOWS_H


#if	!defined(ENCRYPT_C) && !defined(HAM_C)
// OpenSSL が使用する構造体
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct X509_req_st X509_REQ;
typedef struct PKCS12 PKCS12;
typedef struct bignum_st BIGNUM;
typedef struct x509_crl_st X509_CRL;
#endif	// ENCRYPT_C

// 
// 定数
// 

// 標準のバッファサイズ
#define	STD_SIZE			512
#define	MAX_SIZE			512
#define	BUF_SIZE			512

// 対応 Windows OS 一覧
#define	SUPPORTED_WINDOWS_LIST		"Windows 98 / 98 SE / ME / NT 4.0 SP6a / 2000 SP4 / XP SP2, SP3 / Server 2003 SP2 / SBS 2003 SP2 / Storage Server 2003 SP2 / Vista SP1, SP2 / Server 2008 SP1, SP2 / Storage Server 2008 SP1, SP2 / Home Server / 7 / Server 2008 R2"

// 無限
#ifndef	WINDOWS_H
#define	INFINITE			(0xFFFFFFFF)
#endif


#define	SRC_NAME			__FILE__	// ソースコードのファイル名
#define	SRC_LINE			__LINE__	// ソースコード中の行番号

// 最大パスサイズ
#ifndef	WINDOWS_H
#define	MAX_PATH			260
#endif	// WINDOWS_H

// シークの種類
#ifndef	FILE_BEGIN
#define	FILE_BEGIN	SEEK_SET
#endif	// FILE_BEGIN
#ifndef	FILE_END
#define	FILE_END	SEEK_END
#endif	// FILE_END
#ifndef	FILE_CURRENT
#define	FILE_CURRENT	SEEK_CUR
#endif	// FILE_CURRENT

#ifndef	INVALID_SOCKET
#define	INVALID_SOCKET		(-1)
#endif	// INVALID_SOCKET

#ifndef	SOCKET_ERROR
#define	SOCKET_ERROR		(-1)
#endif	//SOCKET_ERROR

// 比較関数
typedef int (COMPARE)(void *p1, void *p2);

// 
// マクロ


#ifdef	MAX
#undef	MAX
#endif	// MAX

#ifdef	MIN
#undef	MIN
#endif	// MIN

// a と b の最小値を求める
#define	MIN(a, b)			((a) >= (b) ? (b) : (a))
// a と b の最大値を求める
#define	MAX(a, b)			((a) >= (b) ? (a) : (b))

// int を bool にする
#define	INT_TO_BOOL(i)		(((i) == 0) ? false : true)
#define	MAKEBOOL(i)			INT_TO_BOOL(i)
#define	BOOL_TO_INT(i)		(((i) == false) ? 0 : 1)

// max_value よりも小さい a を返す
#define	LESS(a, max_value)	((a) <= (max_value) ? (a) : (max_value))
// min_value よりも大きい a を返す
#define	MORE(a, min_value)	((a) >= (min_value) ? (a) : (min_value))
// a が b と c の内部にある値かどうか調べる
#define	INNER(a, b, c)		(((b) <= (c) && (a) >= (b) && (a) <= (c)) || ((b) >= (c) && (a) >= (c) && (a) <= (b)))
// a が b と c の外部にある値かどうか調べる
#define	OUTER(a, b, c)		(!INNER((a), (b), (c)))
// a を b と c の間にある値となるように調整する
#define	MAKESURE(a, b, c)		(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))

// ポインタを UINT にする
#define	POINTER_TO_KEY(p)		((sizeof(void *) == sizeof(UINT)) ? (UINT)(p) : HashPtrToUINT(p))
// UINT とポインタを比較する
#define	COMPARE_POINTER_AND_KEY(p, i)	(POINTER_TO_KEY(p) == (i))
// ポインタを UINT64 にする
#define	POINTER_TO_UINT64(p)	(((sizeof(void *) == sizeof(UINT64)) ? (UINT64)(p) : (UINT64)((UINT)(p))))
// UINT64 をポインタにする
#define	UINT64_TO_POINTER(i)	((sizeof(void *) == sizeof(UINT64)) ? (void *)(i) : (void *)((UINT)(i)))

// 
// 型宣言
// 

// BOOL 型
#ifndef	WINDOWS_H
typedef	unsigned int		BOOL;
#define	TRUE				1
#define	FALSE				0
#endif	// WINDOWS_H

// bool 型
#ifndef	WIN32HTML_CPP
typedef	unsigned int		bool;
#define	true				1
#define	false				0
#endif	// WIN32HTML_CPP

// 32bit 整数型
#ifndef	WINDOWS_H
typedef	unsigned int		UINT;
typedef	unsigned int		UINT32;
typedef	unsigned int		DWORD;
typedef	signed int			INT;
typedef	signed int			INT32;

typedef	int					UINT_PTR;
typedef	long				LONG_PTR;

#endif

// 16bit 整数型
typedef	unsigned short		WORD;
typedef	unsigned short		USHORT;
typedef	signed short		SHORT;

// 8bit 整数型
typedef	unsigned char		BYTE;
typedef	unsigned char		UCHAR;

#ifndef	WIN32HTML_CPP
typedef signed char			CHAR;
#endif	// WIN32HTML_CPP


// 64bit 整数型
typedef	unsigned long long	UINT64;
typedef signed long long	INT64;

#ifdef	OS_UNIX
// コンパイルエラーの回避
#define	__cdecl
#define	__declspec(x)
// socket 型
typedef	int SOCKET;
#else	// OS_UNIX
#ifndef	_WINSOCK2API_
typedef UINT_PTR SOCKET;
#endif	// _WINSOCK2API_
#endif	// OS_UNIX

// OS の種類
#define	OSTYPE_WINDOWS_95						1100	// Windows 95
#define	OSTYPE_WINDOWS_98						1200	// Windows 98
#define	OSTYPE_WINDOWS_ME						1300	// Windows Me
#define	OSTYPE_WINDOWS_UNKNOWN					1400	// Windows (不明)
#define	OSTYPE_WINDOWS_NT_4_WORKSTATION			2100	// Windows NT 4.0 Workstation
#define	OSTYPE_WINDOWS_NT_4_SERVER				2110	// Windows NT 4.0 Server
#define	OSTYPE_WINDOWS_NT_4_SERVER_ENTERPRISE	2111	// Windows NT 4.0 Server, Enterprise Edition
#define	OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER		2112	// Windows NT 4.0 Terminal Server
#define	OSTYPE_WINDOWS_NT_4_BACKOFFICE			2113	// BackOffice Server 4.5
#define	OSTYPE_WINDOWS_NT_4_SMS					2114	// Small Business Server 4.5
#define	OSTYPE_WINDOWS_2000_PROFESSIONAL		2200	// Windows 2000 Professional
#define	OSTYPE_WINDOWS_2000_SERVER				2211	// Windows 2000 Server
#define	OSTYPE_WINDOWS_2000_ADVANCED_SERVER		2212	// Windows 2000 Advanced Server
#define	OSTYPE_WINDOWS_2000_DATACENTER_SERVER	2213	// Windows 2000 Datacenter Server
#define	OSTYPE_WINDOWS_2000_BACKOFFICE			2214	// BackOffice Server 2000
#define	OSTYPE_WINDOWS_2000_SBS					2215	// Small Business Server 2000
#define	OSTYPE_WINDOWS_XP_HOME					2300	// Windows XP Home Edition
#define	OSTYPE_WINDOWS_XP_PROFESSIONAL			2301	// Windows XP Professional
#define	OSTYPE_WINDOWS_2003_WEB					2410	// Windows Server 2003 Web Edition
#define	OSTYPE_WINDOWS_2003_STANDARD			2411	// Windows Server 2003 Standard Edition
#define	OSTYPE_WINDOWS_2003_ENTERPRISE			2412	// Windows Server 2003 Enterprise Edition
#define	OSTYPE_WINDOWS_2003_DATACENTER			2413	// Windows Server 2003 DataCenter Edition
#define	OSTYPE_WINDOWS_2003_BACKOFFICE			2414	// BackOffice Server 2003
#define	OSTYPE_WINDOWS_2003_SBS					2415	// Small Business Server 2003
#define	OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL	2500	// Windows Vista
#define	OSTYPE_WINDOWS_LONGHORN_SERVER			2510	// Windows Server 2008
#define	OSTYPE_WINDOWS_7						2600	// Windows 7
#define	OSTYPE_WINDOWS_SERVER_2008_R2			2610	// Windows Server 2008 R2
#define	OSTYPE_WINDOWS_8						2700	// Windows 8
#define	OSTYPE_WINDOWS_SERVER_8					2710	// Windows Server 8
#define	OSTYPE_UNIX_UNKNOWN						3000	// 不明な UNIX
#define	OSTYPE_LINUX							3100	// Linux
#define	OSTYPE_SOLARIS							3200	// Solaris
#define	OSTYPE_CYGWIN							3300	// Cygwin
#define	OSTYPE_BSD								3400	// BSD
#define	OSTYPE_MACOS_X							3500	// MacOS X


// OS 判別用マクロ
#define	GET_KETA(t, i)			(((t) % (i * 10)) / i)
#define	OS_IS_WINDOWS_9X(t)		(GET_KETA(t, 1000) == 1)
#define	OS_IS_WINDOWS_NT(t)		(GET_KETA(t, 1000) == 2)
#define	OS_IS_WINDOWS(t)		(OS_IS_WINDOWS_9X(t) || OS_IS_WINDOWS_NT(t))
#define	OS_IS_SERVER(t)			(OS_IS_WINDOWS_NT(t) && GET_KETA(t, 10))
#define	OS_IS_WORKSTATION(t)	((OS_IS_WINDOWS_NT(t) && (!(GET_KETA(t, 10)))) || OS_IS_WINDOWS_9X(t))
#define	OS_IS_UNIX(t)			(GET_KETA(t, 1000) == 3)


// OS 情報
typedef struct OS_INFO
{
	UINT OsType;								// OS の種類
	UINT OsServicePack;							// サービスパック番号
	char *OsSystemName;							// OS システム名
	char *OsProductName;						// OS 製品名
	char *OsVendorName;							// OS ベンダ名
	char *OsVersion;							// OS バージョン
	char *KernelName;							// カーネル名
	char *KernelVersion;						// カーネルバージョン
} OS_INFO;

// 時刻型
#ifndef	WINDOWS_H
typedef struct SYSTEMTIME
{
	WORD wYear;
	WORD wMonth;
	WORD wDayOfWeek;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	WORD wMilliseconds;
} SYSTEMTIME;
#endif	// WINDOWS_H


// Object.h
typedef struct LOCK LOCK;
typedef struct COUNTER COUNTER;
typedef struct REF REF;
typedef struct EVENT EVENT;
typedef struct DEADCHECK DEADCHECK;

// Tracking.h
typedef struct CALLSTACK_DATA CALLSTACK_DATA;
typedef struct TRACKING_OBJECT TRACKING_OBJECT;
typedef struct MEMORY_STATUS MEMORY_STATUS;
typedef struct TRACKING_LIST TRACKING_LIST;

// FileIO.h
typedef struct IO IO;

// Memory.h
typedef struct MEMTAG MEMTAG;
typedef struct BUF BUF;
typedef struct FIFO FIFO;
typedef struct LIST LIST;
typedef struct QUEUE QUEUE;
typedef struct SK SK;
typedef struct CANDIDATE CANDIDATE;
typedef struct STRMAP_ENTRY STRMAP_ENTRY;

// Str.h
typedef struct TOKEN_LIST TOKEN_LIST;
typedef struct INI_ENTRY INI_ENTRY;

// Internat.h
typedef struct UNI_TOKEN_LIST UNI_TOKEN_LIST;

// Encrypt.h
typedef struct CRYPT CRYPT;
typedef struct NAME NAME;
typedef struct X_SERIAL X_SERIAL;
typedef struct X X;
typedef struct K K;
typedef struct P12 P12;
typedef struct X_CRL X_CRL;

// Secure.h
typedef struct SECURE_DEVICE SECURE_DEVICE;
typedef struct SEC_INFO SEC_INFO;
typedef struct SECURE SECURE;
typedef struct SEC_OBJ SEC_OBJ;

// Kernel.h
typedef struct MEMINFO MEMINFO;
typedef struct LOCALE LOCALE;
typedef struct THREAD THREAD;
typedef struct THREAD_POOL_DATA THREAD_POOL_DATA;
typedef struct INSTANCE INSTANCE;

// Pack.h
typedef struct VALUE VALUE;
typedef struct ELEMENT ELEMENT;
typedef struct PACK PACK;

// Cfg.h
typedef struct FOLDER FOLDER;
typedef struct ITEM ITEM;
typedef struct CFG_RW CFG_RW;
typedef struct CFG_ENUM_PARAM CFG_ENUM_PARAM;

// Table.h
typedef struct TABLE TABLE;

// Network.h
typedef struct IP IP;
typedef struct DNSCACHE DNSCACHE;
typedef struct SOCK_EVENT SOCK_EVENT;
typedef struct SOCK SOCK;
typedef struct SOCKSET SOCKSET;
typedef struct CANCEL CANCEL;
typedef struct ROUTE_ENTRY ROUTE_ENTRY;
typedef struct ROUTE_TABLE ROUTE_TABLE;
//typedef struct SOCKLIST SOCKLIST;
typedef struct IP_CLIENT IP_CLIENT;
typedef struct ROUTE_CHANGE ROUTE_CHANGE;
typedef struct ROUTE_CHANGE_DATA ROUTE_CHANGE_DATA;
typedef struct GETIP_THREAD_PARAM GETIP_THREAD_PARAM;
typedef struct WIN32_RELEASEADDRESS_THREAD_PARAM WIN32_RELEASEADDRESS_THREAD_PARAM;
typedef struct IPV6_ADDR IPV6_ADDR;

// Tick64.h
typedef struct ADJUST_TIME ADJUST_TIME;
typedef struct TICK64 TICK64;

// FileIO.h
typedef struct DIRENT DIRENT;
typedef struct DIRLIST DIRLIST;




#endif	// MAYATYPE_H

