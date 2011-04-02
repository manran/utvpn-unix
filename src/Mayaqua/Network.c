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

// Network.c
// ネットワーク通信モジュール

#define	ENCRYPT_C
#define	NETWORK_C

#define	__WINCRYPT_H__

#ifdef	WIN32
// Socket API のために windows.h をインクルード
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <Ws2tcpip.h>
#include <Wspiapi.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <Iphlpapi.h>
#endif	// WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
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

#ifdef	OS_WIN32
NETWORK_WIN32_FUNCTIONS *w32net;
struct ROUTE_CHANGE_DATA
{
	OVERLAPPED Overlapped;
	HANDLE Handle;
	UINT NumCalled;
};
#endif	// OS_WIN32

// SSL でブロッキングするかどうか
#if	defined(UNIX_BSD)
#define	FIX_SSL_BLOCKING
#endif

// IPV6_V6ONLY 定数
#ifdef	UNIX_LINUX
#ifndef	IPV6_V6ONLY
#define	IPV6_V6ONLY	26
#endif	// IPV6_V6ONLY
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
#ifndef	IPV6_V6ONLY
#define	IPV6_V6ONLY	0x27
#endif	// IPV6_V6ONLY
#endif	// UNIX_SOLARIS

// SSL_CTX
static SSL_CTX *ssl_ctx = NULL;

// DNS キャッシュリスト
static LIST *DnsCache;

// ロック関係
static LOCK *machine_name_lock = NULL;
static LOCK *disconnect_function_lock = NULL;
static LOCK *aho = NULL;
static LOCK *socket_library_lock = NULL;
extern LOCK *openssl_lock;
static LOCK *ssl_accept_lock = NULL;
static LOCK *ssl_connect_lock = NULL;
static TOKEN_LIST *cipher_list_token = NULL;
static COUNTER *num_tcp_connections = NULL;
static LOCK *dns_lock = NULL;
static LOCK *unix_dns_server_addr_lock = NULL;
static IP unix_dns_server;
static LIST *HostCacheList = NULL;
static LIST *WaitThreadList = NULL;
static bool disable_cache = false;
static bool NetworkReleaseMode = false;			// ネットワークリリースモード

static char *cipher_list = "RC4-MD5 RC4-SHA AES128-SHA AES256-SHA DES-CBC-SHA DES-CBC3-SHA";
static LIST *ip_clients = NULL;

// ルーティングテーブル変更検出を初期化
ROUTE_CHANGE *NewRouteChange()
{
#ifdef	OS_WIN32
	return Win32NewRouteChange();
#else	// OS_WIN32
	return NULL;
#endif	// OS_WIN32
}

// ルーティングテーブル変更検出を解放
void FreeRouteChange(ROUTE_CHANGE *r)
{
#ifdef	OS_WIN32
	Win32FreeRouteChange(r);
#endif	// OS_WIN32
}

// ルーティングテーブルが変更されたかどうか取得
bool IsRouteChanged(ROUTE_CHANGE *r)
{
#ifdef	OS_WIN32
	return Win32IsRouteChanged(r);
#else	// OS_WIN32
	return false;
#endif	// OS_WIN32
}

// ルーティングテーブル変更検出機能 (Win32)
#ifdef	OS_WIN32
ROUTE_CHANGE *Win32NewRouteChange()
{
	ROUTE_CHANGE *r;
	bool ret;

	if (MsIsNt() == false)
	{
		return NULL;
	}

	if (w32net->CancelIPChangeNotify == NULL ||
		w32net->NotifyRouteChange == NULL)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(ROUTE_CHANGE));

	r->Data = ZeroMalloc(sizeof(ROUTE_CHANGE_DATA));

	r->Data->Overlapped.hEvent = CreateEventA(NULL, false, true, NULL);

	ret = w32net->NotifyRouteChange(&r->Data->Handle, &r->Data->Overlapped);
	if (!(ret == NO_ERROR || ret == WSA_IO_PENDING || WSAGetLastError() == WSA_IO_PENDING))
	{
		Free(r->Data);
		Free(r);

		return NULL;
	}

	return r;
}

void Win32FreeRouteChange(ROUTE_CHANGE *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	w32net->CancelIPChangeNotify(&r->Data->Overlapped);
	CloseHandle(r->Data->Overlapped.hEvent);

	Free(r->Data);
	Free(r);
}

bool Win32IsRouteChanged(ROUTE_CHANGE *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return false;
	}

	if ((r->Data->NumCalled++) == 0)
	{
		return true;
	}

	if (WaitForSingleObject(r->Data->Overlapped.hEvent, 0) == WAIT_OBJECT_0)
	{
		w32net->NotifyRouteChange(&r->Data->Handle, &r->Data->Overlapped);
		return true;
	}

	return false;
}

#endif	// OS_WIN32


// TCP コネクションのプロセス ID の取得が成功するかどうかを取得
bool CanGetTcpProcessId()
{
	UINT i;
	bool ret = false;
	LIST *o = GetTcpTableList();

	if (o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		TCPTABLE *t = LIST_DATA(o, i);

		if (t->ProcessId != 0)
		{
			ret = true;
			break;
		}
	}

	FreeTcpTableList(o);

	return ret;
}




#define	USE_OLD_GETIP

// Linux における arp_filter を設定する
void SetLinuxArpFilter()
{
	char *filename = "/proc/sys/net/ipv4/conf/all/arp_filter";
	char *data = "1\n";
	IO *o;

	o = FileCreate(filename);
	if (o == NULL)
	{
		return;
	}

	FileWrite(o, data, StrLen(data));
	FileFlush(o);

	FileClose(o);
}

// 指定された文字列が IPv6 マスクかどうか判定する
bool IsIpMask6(char *str)
{
	IP mask;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	return StrToMask6(&mask, str);
}

// 指定された文字列が IPv6 アドレスかどうか判定する
bool IsStrIPv6Address(char *str)
{
	IP ip;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP6(&ip, str) == false)
	{
		return false;
	}

	return true;
}

// サブネットマスクを整数に変換する
UINT SubnetMaskToInt6(IP *a)
{
	UINT i;
	// 引数チェック
	if (IsIP6(a) == false)
	{
		return 0;
	}

	for (i = 0;i <= 128;i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt4(IP *a)
{
	UINT i;
	// 引数チェック
	if (IsIP4(a) == false)
	{
		return 0;
	}

	for (i = 0;i <= 32;i++)
	{
		IP tmp;

		IntToSubnetMask4(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt(IP *a)
{
	if (IsIP6(a))
	{
		return SubnetMaskToInt6(a);
	}
	else
	{
		return SubnetMaskToInt4(a);
	}
}

// 指定した IP アドレスがサブネットマスクかどうか調べる
bool IsSubnetMask6(IP *a)
{
	UINT i;
	// 引数チェック
	if (IsIP6(a) == false)
	{
		return false;
	}

	for (i = 0;i <= 128;i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return true;
		}
	}

	return false;
}

// MAC アドレスからグローバルアドレスを生成する
void GenerateEui64GlobalAddress(IP *ip, IP *prefix, IP *subnet, UCHAR *mac)
{
	UCHAR tmp[8];
	IP a;
	IP subnet_not;
	IP or1, or2;
	// 引数チェック
	if (ip == NULL || prefix == NULL || subnet == NULL || mac == NULL)
	{
		return;
	}

	GenerateEui64Address6(tmp, mac);

	ZeroIP6(&a);

	Copy(&a.ipv6_addr[8], tmp, 8);

	IPNot6(&subnet_not, subnet);
	IPAnd6(&or1, &a, &subnet_not);
	IPAnd6(&or2, prefix, subnet);

	IPOr6(ip, &or1, &or2);
}

// MAC アドレスからローカルアドレスを生成する
void GenerateEui64LocalAddress(IP *a, UCHAR *mac)
{
	UCHAR tmp[8];
	// 引数チェック
	if (a == NULL || mac == NULL)
	{
		return;
	}

	GenerateEui64Address6(tmp, mac);

	ZeroIP6(a);
	a->ipv6_addr[0] = 0xfe;
	a->ipv6_addr[1] = 0x80;

	Copy(&a->ipv6_addr[8], tmp, 8);
}

// MAC アドレスから EUI-64 アドレスを生成する
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac)
{
	// 引数チェック
	if (dst == NULL || mac == NULL)
	{
		return;
	}

	Copy(dst, mac, 3);
	Copy(dst + 5, mac, 3);

	dst[3] = 0xff;
	dst[4] = 0xfe;
	dst[0] = ((~(dst[0] & 0x02)) & 0x02) | (dst[0] & 0xfd);
}

// 同一のネットワークかどうか調べる
bool IsInSameNetwork6(IP *a1, IP *a2, IP *subnet)
{
	IP prefix1, prefix2;
	// 引数チェック
	if (IsIP6(a1) == false || IsIP6(a2) == false || IsIP6(subnet) == false)
	{
		return false;
	}

	if (a1->ipv6_scope_id != a2->ipv6_scope_id)
	{
		return false;
	}

	GetPrefixAddress6(&prefix1, a1, subnet);
	GetPrefixAddress6(&prefix2, a2, subnet);

	if (CmpIpAddr(&prefix1, &prefix2) == 0)
	{
		return true;
	}

	return false;
}

// ネットワークプレフィックスアドレスかどうかチェックする
bool IsNetworkAddress6(IP *ip, IP *subnet)
{
	return IsNetworkPrefixAddress6(ip, subnet);
}
bool IsNetworkPrefixAddress6(IP *ip, IP *subnet)
{
	IP host;
	// 引数チェック
	if (ip == NULL || subnet == NULL)
	{
		return false;
	}

	if (IsIP6(ip) == false || IsIP6(subnet) == false)
	{
		return false;
	}

	GetHostAddress6(&host, ip, subnet);

	if (IsZeroIp(&host))
	{
		return true;
	}

	return false;
}

// ユニキャストアドレスが有効かどうかチェックする
bool CheckUnicastAddress(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	if ((GetIPAddrType6(ip) & IPV6_ADDR_UNICAST) == 0)
	{
		return false;
	}

	return true;
}

// ホストアドレスの取得
void GetHostAddress6(IP *dst, IP *ip, IP *subnet)
{
	IP not;
	// 引数チェック
	if (dst == NULL || ip == NULL || subnet == NULL)
	{
		return;
	}

	IPNot6(&not, subnet);

	IPAnd6(dst, ip, &not);

	dst->ipv6_scope_id = ip->ipv6_scope_id;
}

// プレフィックスアドレスの取得
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet)
{
	// 引数チェック
	if (dst == NULL || ip == NULL || subnet == NULL)
	{
		return;
	}

	IPAnd6(dst, ip, subnet);

	dst->ipv6_scope_id = ip->ipv6_scope_id;
}

// 要請ノードマルチキャストアドレスを取得
void GetSoliciationMulticastAddr6(IP *dst, IP *src)
{
	IP prefix;
	IP mask104;
	IP or1, or2;

	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	ZeroIP6(&prefix);
	prefix.ipv6_addr[0] = 0xff;
	prefix.ipv6_addr[1] = 0x02;
	prefix.ipv6_addr[11] = 0x01;
	prefix.ipv6_addr[12] = 0xff;

	IntToSubnetMask6(&mask104, 104);

	IPAnd6(&or1, &prefix, &mask104);
	IPAnd6(&or2, src, &mask104);

	IPOr6(dst, &or1, &or2);

	dst->ipv6_scope_id = src->ipv6_scope_id;
}

// マルチキャストアドレスに対応した MAC アドレスの生成
void GenerateMulticastMacAddress6(UCHAR *mac, IP *ip)
{
	// 引数チェック
	if (mac == NULL)
	{
		return;
	}

	mac[0] = 0x33;
	mac[1] = 0x33;
	mac[2] = ip->ipv6_addr[12];
	mac[3] = ip->ipv6_addr[13];
	mac[4] = ip->ipv6_addr[14];
	mac[5] = ip->ipv6_addr[15];
}

// IPv6 アドレスのタイプの取得
UINT GetIPv6AddrType(IPV6_ADDR *addr)
{
	IP ip;
	// 引数チェック
	if (addr == NULL)
	{
		return 0;
	}

	IPv6AddrToIP(&ip, addr);

	return GetIPAddrType6(&ip);
}
UINT GetIPAddrType6(IP *ip)
{
	UINT ret = 0;
	// 引数チェック
	if (IsIP6(ip) == false)
	{
		return 0;
	}

	if (ip->ipv6_addr[0] == 0xff)
	{
		IP all_node, all_router;

		GetAllNodeMulticaseAddress6(&all_node);

		GetAllRouterMulticastAddress6(&all_router);

		ret |= IPV6_ADDR_MULTICAST;

		if (Cmp(ip->ipv6_addr, all_node.ipv6_addr, 16) == 0)
		{
			ret |= IPV6_ADDR_ALL_NODE_MULTICAST;
		}
		else if (Cmp(ip->ipv6_addr, all_router.ipv6_addr, 16) == 0)
		{
			ret |= IPV6_ADDR_ALL_ROUTER_MULTICAST;
		}
		else
		{
			if (ip->ipv6_addr[1] == 0x02 && ip->ipv6_addr[2] == 0 && ip->ipv6_addr[3] == 0 &&
				ip->ipv6_addr[4] == 0 && ip->ipv6_addr[5] == 0 && ip->ipv6_addr[6] == 0 &&
				ip->ipv6_addr[7] == 0 && ip->ipv6_addr[8] == 0 && ip->ipv6_addr[9] == 0 &&
				ip->ipv6_addr[10] == 0 && ip->ipv6_addr[11] == 0x01 && ip->ipv6_addr[12] == 0xff)
			{
				ret |= IPV6_ADDR_SOLICIATION_MULTICAST;
			}
		}
	}
	else
	{
		ret |= IPV6_ADDR_UNICAST;

		if (ip->ipv6_addr[0] == 0xfe && (ip->ipv6_addr[1] & 0xc0) == 0x80)
		{
			ret |= IPV6_ADDR_LOCAL_UNICAST;
		}
		else
		{
			ret |= IPV6_ADDR_GLOBAL_UNICAST;

			if (IsZero(&ip->ipv6_addr, 16))
			{
				ret |= IPV6_ADDR_ZERO;
			}
			else
			{
				IP loopback;

				GetLoopbackAddress6(&loopback);

				if (Cmp(ip->ipv6_addr, loopback.ipv6_addr, 16) == 0)
				{
					ret |= IPV6_ADDR_LOOPBACK;
				}
			}
		}
	}

	return ret;
}

// すべてのビットが立っているアドレス
void GetAllFilledAddress6(IP *ip)
{
	UINT i;
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	for (i = 0;i < 15;i++)
	{
		ip->ipv6_addr[i] = 0xff;
	}
}

// ループバックアドレス
void GetLoopbackAddress6(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	ip->ipv6_addr[15] = 0x01;
}

// 全ノードマルチキャストアドレス
void GetAllNodeMulticaseAddress6(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	ip->ipv6_addr[0] = 0xff;
	ip->ipv6_addr[1] = 0x02;
	ip->ipv6_addr[15] = 0x01;
}

// 全ルータマルチキャストアドレス
void GetAllRouterMulticastAddress6(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	ip->ipv6_addr[0] = 0xff;
	ip->ipv6_addr[1] = 0x02;
	ip->ipv6_addr[15] = 0x02;
}

// IPv6 アドレスの論理演算
void IPAnd6(IP *dst, IP *a, IP *b)
{
	UINT i;
	// 引数チェック
	if (dst == NULL || IsIP6(a) == false || IsIP6(b) == false)
	{
		return;
	}

	ZeroIP6(dst);
	for (i = 0;i < 16;i++)
	{
		dst->ipv6_addr[i] = a->ipv6_addr[i] & b->ipv6_addr[i];
	}
}
void IPOr6(IP *dst, IP *a, IP *b)
{
	UINT i;
	// 引数チェック
	if (dst == NULL || IsIP6(a) == false || IsIP6(b) == false)
	{
		return;
	}

	ZeroIP6(dst);
	for (i = 0;i < 16;i++)
	{
		dst->ipv6_addr[i] = a->ipv6_addr[i] | b->ipv6_addr[i];
	}
}
void IPNot6(IP *dst, IP *a)
{
	UINT i;
	// 引数チェック
	if (dst == NULL || IsIP6(a) == false)
	{
		return;
	}

	ZeroIP6(dst);
	for (i = 0;i < 16;i++)
	{
		dst->ipv6_addr[i] = ~(a->ipv6_addr[i]);
	}
}

// サブネットマスクの作成
void IntToSubnetMask6(IP *ip, UINT i)
{
	UINT j = i / 8;
	UINT k = i % 8;
	UINT z;
	IP a;

	ZeroIP6(&a);

	for (z = 0;z < 16;z++)
	{
		if (z < j)
		{
			a.ipv6_addr[z] = 0xff;
		}
		else if (z == j)
		{
			a.ipv6_addr[z] = ~(0xff >> k);
		}
	}

	Copy(ip, &a, sizeof(IP));
}

// IP アドレスを文字列に変換
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr)
{
	// 引数チェック
	if (str == NULL || addr == NULL)
	{
		return;
	}

	IPToStr6Array(str, size, addr->Value);
}
void IPToStr6Array(char *str, UINT size, UCHAR *bytes)
{
	IP ip;
	// 引数チェック
	if (str == NULL || bytes == NULL)
	{
		return;
	}

	SetIP6(&ip, bytes);

	IPToStr6(str, size, &ip);
}
void IPToStr6(char *str, UINT size, IP *ip)
{
	char tmp[MAX_SIZE];

	IPToStr6Inner(tmp, ip);

	StrCpy(str, size, tmp);
}
void IPToStr6Inner(char *str, IP *ip)
{
	UINT i;
	USHORT values[8];
	UINT zero_started_index;
	UINT max_zero_len;
	UINT max_zero_start;
	IP a;
	// 引数チェック
	if (str == NULL || ip == NULL)
	{
		return;
	}

	Copy(&a, ip, sizeof(IP));

	for (i = 0;i < 8;i++)
	{
		Copy(&values[i], &a.ipv6_addr[i * 2], sizeof(USHORT));
		values[i] = Endian16(values[i]);
	}

	// 省略できる場所があるかどうか検索
	zero_started_index = INFINITE;
	max_zero_len = 0;
	max_zero_start = INFINITE;
	for (i = 0;i < 9;i++)
	{
		USHORT v = (i != 8 ? values[i] : 1);

		if (values[i] == 0)
		{
			if (zero_started_index == INFINITE)
			{
				zero_started_index = i;
			}
		}
		else
		{
			UINT zero_len;

			if (zero_started_index != INFINITE)
			{
				zero_len = i - zero_started_index;
				if (zero_len >= 2)
				{
					if (max_zero_len < zero_len)
					{
						max_zero_start = zero_started_index;
						max_zero_len = zero_len;
					}
				}

				zero_started_index = INFINITE;
			}
		}
	}

	// 文字列を形成
	StrCpy(str, 0, "");
	for (i = 0;i < 8;i++)
	{
		char tmp[16];

		ToHex(tmp, values[i]);
		StrLower(tmp);

		if (i == max_zero_start)
		{
			if (i == 0)
			{
				StrCat(str, 0, "::");
			}
			else
			{
				StrCat(str, 0, ":");
			}
			i += max_zero_len - 1;
		}
		else
		{
			StrCat(str, 0, tmp);
			if (i != 7)
			{
				StrCat(str, 0, ":");
			}
		}
	}

	// スコープ ID
	if (ip->ipv6_scope_id != 0)
	{
		char tmp[64];

		StrCat(str, 0, "%");
		ToStr(tmp, ip->ipv6_scope_id);

		StrCat(str, 0, tmp);
	}
}

// 文字列を IP アドレスに変換
bool StrToIP6(IP *ip, char *str)
{
	TOKEN_LIST *t;
	char tmp[MAX_PATH];
	IP a;
	UINT i;
	UINT scope_id = 0;
	// 引数チェック
	if (str == NULL || ip == NULL)
	{
		return false;
	}

	ZeroIP6(&a);

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StartWith(tmp, "[") && EndWith(tmp, "]"))
	{
		// かぎかっこで囲まれている場合はそれを除去
		StrCpy(tmp, sizeof(tmp), &tmp[1]);

		if (StrLen(tmp) >= 1)
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	// スコープ ID がある場合はそれを解析して除去
	i = SearchStrEx(tmp, "%", 0, false);
	if (i != INFINITE)
	{
		char ss[MAX_PATH];

		StrCpy(ss, sizeof(ss), &tmp[i + 1]);

		tmp[i] = 0;

		Trim(tmp);

		Trim(ss);

		scope_id = ToInt(ss);
	}

	// トークン分割
	t = ParseTokenWithNullStr(tmp, ":");
	if (t->NumTokens >= 3 && t->NumTokens <= 8)
	{
		UINT i, n;
		bool b = true;
		UINT k = 0;

		n = 0;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *str = t->Token[i];

			if (i != 0 && i != (t->NumTokens - 1) && StrLen(str) == 0)
			{
				n++;
				if (n == 1)
				{
					k += 2 * (8 - t->NumTokens + 1);
				}
				else
				{
					b = false;
					break;
				}
			}
			else
			{
				UCHAR chars[2];

				if (CheckIPItemStr6(str) == false)
				{
					b = false;
					break;
				}

				IPItemStrToChars6(chars, str);

				a.ipv6_addr[k++] = chars[0];
				a.ipv6_addr[k++] = chars[1];
			}
		}

		if (n != 0 && n != 1)
		{
			b = false;
		}
		else if (n == 0 && t->NumTokens != 8)
		{
			b = false;
		}

		if (b == false)
		{
			FreeToken(t);
			return false;
		}
	}
	else
	{
		FreeToken(t);
		return false;
	}

	FreeToken(t);

	Copy(ip, &a, sizeof(IP));

	ip->ipv6_scope_id = scope_id;

	return true;
}
bool StrToIP6Addr(IPV6_ADDR *ip, char *str)
{
	IP ip2;
	// 引数チェック
	if (ip == NULL || str == NULL)
	{
		Zero(ip, sizeof(IPV6_ADDR));
		return false;
	}

	if (StrToIP6(&ip2, str) == false)
	{
		return false;
	}

	if (IPToIPv6Addr(ip, &ip2) == false)
	{
		return false;
	}

	return true;
}

// IP アドレスの文字から UCHAR 型に変換
void IPItemStrToChars6(UCHAR *chars, char *str)
{
	char tmp[5];
	BUF *b;
	UINT len;
	// 引数チェック
	if (chars == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	len = StrLen(str);
	switch (len)
	{
	case 0:
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = '0';
		break;

	case 1:
		tmp[0] = tmp[1] = tmp[2] = '0';
		tmp[3] = str[0];
		break;

	case 2:
		tmp[0] = tmp[1] = '0';
		tmp[2] = str[0];
		tmp[3] = str[1];
		break;

	case 3:
		tmp[0] = '0';
		tmp[1] = str[0];
		tmp[2] = str[1];
		tmp[3] = str[2];
		break;

	case 4:
		tmp[0] = str[0];
		tmp[1] = str[1];
		tmp[2] = str[2];
		tmp[3] = str[3];
		break;
	}

	b = StrToBin(tmp);

	chars[0] = ((UCHAR *)b->Buf)[0];
	chars[1] = ((UCHAR *)b->Buf)[1];

	FreeBuf(b);
}

// IP アドレスの要素文字列の中に不正な文字が含まれていないかどうかチェックする
bool CheckIPItemStr6(char *str)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	if (len >= 5)
	{
		// 長さ不正
		return false;
	}

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F') ||
			(c >= '0' && c <= '9'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

// ゼロの IPv4 アドレスを作成する
void ZeroIP4(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));
}

// ゼロの IPv6 アドレスを作成する
void ZeroIP6(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	SetIP6(ip, NULL);
}

// localhost の IP アドレスを取得する
void GetLocalHostIP6(IP *ip)
{
	ZeroIP6(ip);

	ip->ipv6_addr[15] = 1;
}

// IPV6_ADDR を IP に変換
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr)
{
	// 引数チェック
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	SetIP6(ip, addr->Value);
}

// IP を IPV6_ADDR に変換
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip)
{
	UINT i;
	// 引数チェック
	if (addr == NULL || ip == NULL)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	if (IsIP6(ip) == false)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	for (i = 0;i < 16;i++)
	{
		addr->Value[i] = ip->ipv6_addr[i];
	}

	return true;
}

// IPv6 アドレスをセットする
void SetIP6(IP *ip, UCHAR *value)
{
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->addr[0] = 223;
	ip->addr[1] = 255;
	ip->addr[2] = 255;
	ip->addr[3] = 254;

	if (value != NULL)
	{
		UINT i;

		for (i = 0;i < 16;i++)
		{
			ip->ipv6_addr[i] = value[i];
		}
	}
}

// 指定されたアドレスが IPv6 アドレスかどうかチェックする
bool IsIP6(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	if (ip->addr[0] == 223 && ip->addr[1] == 255 && ip->addr[2] == 255 && ip->addr[3] == 254)
	{
		return true;
	}

	return false;
}
bool IsIP4(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	return (IsIP6(ip) ? false : true);
}

// IPv6 のサブネット長をチェック
bool CheckSubnetLength6(UINT i)
{
	if (i >= 1 && i <= 127)
	{
		return true;
	}

	return false;
}

// ソケットから対応する TCP コネクションのプロセス ID を取得
UINT GetTcpProcessIdFromSocket(SOCK *s)
{
	LIST *o;
	TCPTABLE *t;
	UINT pid = 0;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	o = GetTcpTableList();
	if (o == NULL)
	{
		return 0;
	}

	t = GetTcpTableFromEndPoint(o, &s->LocalIP, s->LocalPort,
		&s->RemoteIP, s->RemotePort);

	if (t != NULL)
	{
		pid = t->ProcessId;
	}

	FreeTcpTableList(o);

	return pid;
}
UINT GetTcpProcessIdFromSocketReverse(SOCK *s)
{
	LIST *o;
	TCPTABLE *t;
	UINT pid = 0;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	o = GetTcpTableList();
	if (o == NULL)
	{
		return 0;
	}

	t = GetTcpTableFromEndPoint(o, &s->RemoteIP, s->RemotePort,
		&s->LocalIP, s->LocalPort);

	if (t != NULL)
	{
		pid = t->ProcessId;
	}

	FreeTcpTableList(o);

	return pid;
}

// エンドポイントから TCP テーブルを検索
TCPTABLE *GetTcpTableFromEndPoint(LIST *o, IP *local_ip, UINT local_port, IP *remote_ip, UINT remote_port)
{
	IP local;
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	SetIP(&local, 127, 0, 0, 1);

	if (local_ip == NULL)
	{
		local_ip = &local;
	}

	if (remote_ip == NULL)
	{
		remote_ip = &local;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		TCPTABLE *t = LIST_DATA(o, i);

		if (t->Status == TCP_STATE_SYN_SENT || t->Status == TCP_STATE_SYN_RCVD ||
			t->Status == TCP_STATE_ESTAB)
		{
			if (CmpIpAddr(&t->LocalIP, local_ip) == 0)
			{
				if (CmpIpAddr(&t->RemoteIP, remote_ip) == 0)
				{
					if (t->LocalPort == local_port)
					{
						if (t->RemotePort == remote_port)
						{
							return t;
						}
					}
				}
			}
		}
	}

	return NULL;
}

// TCP テーブルリストを取得 (Win32)
#ifdef	OS_WIN32
LIST *Win32GetTcpTableList()
{
	LIST *o;

	// Windows XP SP2 以降用
	o = Win32GetTcpTableListByGetExtendedTcpTable();
	if (o != NULL)
	{
		return o;
	}

	// Windows XP 以降用
	o = Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack();
	if (o != NULL)
	{
		return o;
	}

	// 古い Windows 用
	return Win32GetTcpTableListByGetTcpTable();
}

// TCP テーブルリストを取得: Windows XP SP2 以降用
LIST *Win32GetTcpTableListByGetExtendedTcpTable()
{
	UINT need_size;
	UINT i;
	MIB_TCPTABLE_OWNER_PID *table;
	bool ok = false;
	LIST *o;
	if (w32net->GetExtendedTcpTable == NULL)
	{
		return NULL;
	}

	for (i = 0;i < 128;i++)
	{
		UINT ret;
		table = MallocFast(sizeof(MIB_TCPTABLE_OWNER_PID));
		need_size = sizeof(MIB_TCPTABLE_OWNER_PID);
		ret = w32net->GetExtendedTcpTable(table, &need_size, true, AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);
			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}

		table = MallocFast(need_size);

		ret = w32net->GetExtendedTcpTable(table, &need_size, true, AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);

			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}
	}

	if (ok == false)
	{
		return NULL;
	}

	o = NewListEx(NULL, true);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_TCPROW_OWNER_PID *r = &table->table[i];
		TCPTABLE *t = ZeroMallocFast(sizeof(TCPTABLE));

		UINTToIP(&t->LocalIP, r->dwLocalAddr);
		t->LocalPort = Endian16((USHORT)r->dwLocalPort);

		if (r->dwState != TCP_STATE_LISTEN)
		{
			UINTToIP(&t->RemoteIP, r->dwRemoteAddr);
			t->RemotePort = Endian16((USHORT)r->dwRemotePort);
		}

		t->Status = r->dwState;
		t->ProcessId = r->dwOwningPid;

		Add(o, t);
	}

	Free(table);

	return o;
}

// TCP テーブルリストを取得: Windows XP 以降用
LIST *Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack()
{
	HANDLE heap;
	UINT i;
	MIB_TCPTABLE_OWNER_PID *table;
	bool ok = false;
	LIST *o;
	if (w32net->AllocateAndGetTcpExTableFromStack == NULL)
	{
		return NULL;
	}

	heap = GetProcessHeap();

	if (w32net->AllocateAndGetTcpExTableFromStack(&table, true, heap, HEAP_GROWABLE, AF_INET) != ERROR_SUCCESS)
	{
		return NULL;
	}

	o = NewListEx(NULL, true);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_TCPROW_OWNER_PID *r = &table->table[i];
		TCPTABLE *t = ZeroMallocFast(sizeof(TCPTABLE));

		UINTToIP(&t->LocalIP, r->dwLocalAddr);
		t->LocalPort = Endian16((USHORT)r->dwLocalPort);

		if (r->dwState != TCP_STATE_LISTEN)
		{
			UINTToIP(&t->RemoteIP, r->dwRemoteAddr);
			t->RemotePort = Endian16((USHORT)r->dwRemotePort);
		}

		t->ProcessId = r->dwOwningPid;
		t->Status = r->dwState;

		Add(o, t);
	}

	HeapFree(heap, 0, table);

	return o;
}

// TCP テーブルリストを取得: 古い Windows 用
LIST *Win32GetTcpTableListByGetTcpTable()
{
	UINT need_size;
	UINT i;
	MIB_TCPTABLE *table;
	bool ok = false;
	LIST *o;
	if (w32net->GetTcpTable == NULL)
	{
		return NULL;
	}

	for (i = 0;i < 128;i++)
	{
		UINT ret;
		table = MallocFast(sizeof(MIB_TCPTABLE));
		need_size = sizeof(MIB_TCPTABLE);
		ret = w32net->GetTcpTable(table, &need_size, true);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);
			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}

		table = MallocFast(need_size);

		ret = w32net->GetTcpTable(table, &need_size, true);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);

			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}
	}

	if (ok == false)
	{
		return NULL;
	}

	o = NewListEx(NULL, true);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_TCPROW *r = &table->table[i];
		TCPTABLE *t = ZeroMallocFast(sizeof(TCPTABLE));

		UINTToIP(&t->LocalIP, r->dwLocalAddr);
		t->LocalPort = Endian16((USHORT)r->dwLocalPort);

		if (r->dwState != TCP_STATE_LISTEN)
		{
			UINTToIP(&t->RemoteIP, r->dwRemoteAddr);
			t->RemotePort = Endian16((USHORT)r->dwRemotePort);
		}

		t->Status = r->dwState;

		Add(o, t);
	}

	Free(table);

	return o;
}

#endif	// OS_WIN32

// TCP テーブルの表示
void PrintTcpTableList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		Print("o == NULL\n\n");
		return;
	}

	Print("--- TCPTABLE: %u Entries ---\n", LIST_NUM(o));
	for (i = 0;i < LIST_NUM(o);i++)
	{
		char tmp1[MAX_PATH], tmp2[MAX_PATH];
		TCPTABLE *t = LIST_DATA(o, i);

		IPToStr(tmp1, sizeof(tmp1), &t->LocalIP);
		IPToStr(tmp2, sizeof(tmp2), &t->RemoteIP);

		Print("%s:%u <--> %s:%u  state=%u  pid=%u\n",
			tmp1, t->LocalPort,
			tmp2, t->RemotePort,
			t->Status,
			t->ProcessId);
	}
	Print("------\n\n");
}

// TCP テーブルの比較
int CompareTcpTable(void *p1, void *p2)
{
	TCPTABLE *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(TCPTABLE **)p1;
	t2 = *(TCPTABLE **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	return Cmp(t1, t2, sizeof(TCPTABLE));
}

// TCP テーブルリストを取得
LIST *GetTcpTableList()
{
#ifdef	OS_WIN32
	return Win32GetTcpTableList();
#else	// OS_WIN32
	return NULL;
#endif	// OS_WIN32
}

// TCP テーブルリストを解放
void FreeTcpTableList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		TCPTABLE *t = LIST_DATA(o, i);

		Free(t);
	}

	ReleaseList(o);
}

// 指定された IP アドレスから接続中のクライアント数の取得
UINT GetNumIpClient(IP *ip)
{
	IP_CLIENT *c;
	UINT ret = 0;
	// 引数チェック
	if (ip == NULL)
	{
		return 0;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			ret = c->NumConnections;
		}
	}
	UnlockList(ip_clients);

	return ret;
}

// IP クライアントエントリに追加
void AddIpClient(IP *ip)
{
	IP_CLIENT *c;
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c == NULL)
		{
			c = ZeroMallocFast(sizeof(IP_CLIENT));
			Copy(&c->IpAddress, ip, sizeof(IP));
			c->NumConnections = 0;

			Add(ip_clients, c);
		}

		c->NumConnections++;
	}
	UnlockList(ip_clients);
}

// IP クライアントリストから削除
void DelIpClient(IP *ip)
{
	IP_CLIENT *c;
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			c->NumConnections--;

			if (c->NumConnections == 0)
			{
				Delete(ip_clients, c);
				Free(c);
			}
		}
	}
	UnlockList(ip_clients);
}

// IP クライアントエントリの検索
IP_CLIENT *SearchIpClient(IP *ip)
{
	IP_CLIENT t;
	// 引数チェック
	if (ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.IpAddress, ip, sizeof(IP));

	return Search(ip_clients, &t);
}

// クライアントリストの初期化
void InitIpClientList()
{
	ip_clients = NewList(CompareIpClientList);
}

// クライアントリストの解放
void FreeIpClientList()
{
	UINT i;

	for (i = 0;i < LIST_NUM(ip_clients);i++)
	{
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		Free(c);
	}

	ReleaseList(ip_clients);
	ip_clients = NULL;
}

// クライアントリストエントリの比較
int CompareIpClientList(void *p1, void *p2)
{
	IP_CLIENT *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IP_CLIENT **)p1;
	c2 = *(IP_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}

// MAC アドレスの正規化
bool NormalizeMacAddress(char *dst, UINT size, char *src)
{
	BUF *b;
	bool ret = false;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return false;
	}

	b = StrToBin(src);

	if (b != NULL && b->Size == 6)
	{
		ret = true;

		BinToStr(dst, size, b->Buf, b->Size);
	}

	FreeBuf(b);

	return ret;
}

// IP アドレスが空かどうか識別する
bool IsZeroIP(IP *ip)
{
	return IsZeroIp(ip);
}
bool IsZeroIp(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return true;
	}

	if (IsIP6(ip) == false)
	{
		return IsZero(ip->addr, sizeof(ip->addr));
	}
	else
	{
		return IsZero(ip->ipv6_addr, sizeof(ip->ipv6_addr));
	}
}
bool IsZeroIP6Addr(IPV6_ADDR *addr)
{
	// 引数チェック
	if (addr == NULL)
	{
		return true;
	}

	return IsZero(addr, sizeof(IPV6_ADDR));
}

// 指定された IP アドレスがホストとして意味があるかどうかを調べる
bool IsHostIPAddress4(IP *ip)
{
	UINT a;
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	a = IPToUINT(ip);

	if (a == 0 || a == 0xffffffff)
	{
		return false;
	}

	return true;
}
bool IsHostIPAddress32(UINT ip)
{
	IP p;

	UINTToIP(&p, ip);

	return IsHostIPAddress4(&p);
}

// 指定された IP アドレスとサブネットマスクが正しくネットワークを示すかどうか調べる
bool IsNetworkAddress(IP *ip, IP *mask)
{
	if (IsIP4(ip))
	{
		return IsNetworkAddress4(ip, mask);
	}
	else
	{
		return IsNetworkAddress6(ip, mask);
	}
}
bool IsNetworkAddress4(IP *ip, IP *mask)
{
	UINT a, b;
	// 引数チェック
	if (ip == NULL || mask == NULL)
	{
		return false;
	}

	if (IsIP4(ip) == false || IsIP4(mask) == false)
	{
		return false;
	}

	if (IsSubnetMask4(mask) == false)
	{
		return false;
	}

	a = IPToUINT(ip);
	b = IPToUINT(mask);

	if ((a & b) == a)
	{
		return true;
	}

	return false;
}
bool IsNetworkAddress32(UINT ip, UINT mask)
{
	IP a, b;

	UINTToIP(&a, ip);
	UINTToIP(&b, mask);

	return IsNetworkAddress4(&a, &b);
}

// 整数をサブネットマスクに変換する
UINT IntToSubnetMask32(UINT i)
{
	UINT ret = 0xFFFFFFFF;

	// 汚いコード
	switch (i)
	{
	case 0:		ret = 0x00000000;	break;
	case 1:		ret = 0x80000000;	break;
	case 2:		ret = 0xC0000000;	break;
	case 3:		ret = 0xE0000000;	break;
	case 4:		ret = 0xF0000000;	break;
	case 5:		ret = 0xF8000000;	break;
	case 6:		ret = 0xFC000000;	break;
	case 7:		ret = 0xFE000000;	break;
	case 8:		ret = 0xFF000000;	break;
	case 9:		ret = 0xFF800000;	break;
	case 10:	ret = 0xFFC00000;	break;
	case 11:	ret = 0xFFE00000;	break;
	case 12:	ret = 0xFFF00000;	break;
	case 13:	ret = 0xFFF80000;	break;
	case 14:	ret = 0xFFFC0000;	break;
	case 15:	ret = 0xFFFE0000;	break;
	case 16:	ret = 0xFFFF0000;	break;
	case 17:	ret = 0xFFFF8000;	break;
	case 18:	ret = 0xFFFFC000;	break;
	case 19:	ret = 0xFFFFE000;	break;
	case 20:	ret = 0xFFFFF000;	break;
	case 21:	ret = 0xFFFFF800;	break;
	case 22:	ret = 0xFFFFFC00;	break;
	case 23:	ret = 0xFFFFFE00;	break;
	case 24:	ret = 0xFFFFFF00;	break;
	case 25:	ret = 0xFFFFFF80;	break;
	case 26:	ret = 0xFFFFFFC0;	break;
	case 27:	ret = 0xFFFFFFE0;	break;
	case 28:	ret = 0xFFFFFFF0;	break;
	case 29:	ret = 0xFFFFFFF8;	break;
	case 30:	ret = 0xFFFFFFFC;	break;
	case 31:	ret = 0xFFFFFFFE;	break;
	case 32:	ret = 0xFFFFFFFF;	break;
	}

	if (IsLittleEndian())
	{
		ret = Swap32(ret);
	}

	return ret;
}
void IntToSubnetMask4(IP *ip, UINT i)
{
	UINT m;
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	m = IntToSubnetMask32(i);

	UINTToIP(ip, m);
}

// 指定された IP アドレスがサブネットマスクかどうか調べる
bool IsSubnetMask(IP *ip)
{
	if (IsIP6(ip))
	{
		return IsSubnetMask6(ip);
	}
	else
	{
		return IsSubnetMask4(ip);
	}
}
bool IsSubnetMask4(IP *ip)
{
	UINT i;
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP6(ip))
	{
		return false;
	}

	i = IPToUINT(ip);

	if (IsLittleEndian())
	{
		i = Swap32(i);
	}

	// 汚いコード
	switch (i)
	{
	case 0x00000000:
	case 0x80000000:
	case 0xC0000000:
	case 0xE0000000:
	case 0xF0000000:
	case 0xF8000000:
	case 0xFC000000:
	case 0xFE000000:
	case 0xFF000000:
	case 0xFF800000:
	case 0xFFC00000:
	case 0xFFE00000:
	case 0xFFF00000:
	case 0xFFF80000:
	case 0xFFFC0000:
	case 0xFFFE0000:
	case 0xFFFF0000:
	case 0xFFFF8000:
	case 0xFFFFC000:
	case 0xFFFFE000:
	case 0xFFFFF000:
	case 0xFFFFF800:
	case 0xFFFFFC00:
	case 0xFFFFFE00:
	case 0xFFFFFF00:
	case 0xFFFFFF80:
	case 0xFFFFFFC0:
	case 0xFFFFFFE0:
	case 0xFFFFFFF0:
	case 0xFFFFFFF8:
	case 0xFFFFFFFC:
	case 0xFFFFFFFE:
	case 0xFFFFFFFF:
		return true;
	}

	return false;
}
bool IsSubnetMask32(UINT ip)
{
	IP p;

	UINTToIP(&p, ip);

	return IsSubnetMask4(&p);
}

// ネットワークリリースモード
void SetNetworkReleaseMode()
{
	NetworkReleaseMode = true;
}

#ifdef	OS_UNIX			// UNIX 用コード

// ソケットをノンブロッキングモードにしたり解除したりする
void UnixSetSocketNonBlockingMode(int fd, bool nonblock)
{
	UINT flag = 0;
	// 引数チェック
	if (fd == INVALID_SOCKET)
	{
		return;
	}

	if (nonblock)
	{
		flag = 1;
	}

#ifdef	FIONBIO
	ioctl(fd, FIONBIO, &flag);
#else	// FIONBIO
	{
		int flag = fcntl(fd, F_GETFL, 0);
		if (flag != -1)
		{
			if (nonblock)
			{
				flag |= O_NONBLOCK;
			}
			else
			{
				flag = flag & ~O_NONBLOCK;

				fcntl(fd, F_SETFL, flag);
			}
		}
	}
#endif	// FIONBIO
}

// 何もしない
void UnixIpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row)
{
}

// 何もしない
void UnixRouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry)
{
}

// 何もしない
int UnixCompareRouteEntryByMetric(void *p1, void *p2)
{
	return 1;
}

// 何もしない
ROUTE_TABLE *UnixGetRouteTable()
{
	ROUTE_TABLE *ret = ZeroMalloc(sizeof(ROUTE_TABLE));
	ret->NumEntry = 0;
	ret->Entry = ZeroMalloc(0);

	return ret;
}

// 何もしない
bool UnixAddRouteEntry(ROUTE_ENTRY *e, bool *already_exists)
{
	return true;
}

// 何もしない
void UnixDeleteRouteEntry(ROUTE_ENTRY *e)
{
	return;
}

// 何もしない
UINT UnixGetVLanInterfaceID(char *instance_name)
{
	return 1;
}

// 何もしない
char **UnixEnumVLan(char *tag_name)
{
	char **list;

	list = ZeroMalloc(sizeof(char *));

	return list;
}

// 何もしない
void UnixRenewDhcp()
{
}

// デフォルトの DNS サーバーの IP アドレスを取得
bool UnixGetDefaultDns(IP *ip)
{
	BUF *b;
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	Lock(unix_dns_server_addr_lock);
	{
		if (IsZero(&unix_dns_server, sizeof(IP)) == false)
		{
			Copy(ip, &unix_dns_server, sizeof(IP));
			Unlock(unix_dns_server_addr_lock);
			return true;
		}

		ip->addr[0] = 127;
		ip->addr[1] = 0;
		ip->addr[2] = 0;
		ip->addr[3] = 1;

		b = ReadDump("/etc/resolv.conf");
		if (b != NULL)
		{
			char *s;
			bool f = false;
			while ((s = CfgReadNextLine(b)) != NULL)
			{
				TOKEN_LIST *t = ParseToken(s, "\" \t,");
				if (t->NumTokens == 2)
				{
					if (StrCmpi(t->Token[0], "nameserver") == 0)
					{
						StrToIP(ip, t->Token[1]);
						f = true;
					}
				}
				FreeToken(t);

				Free(s);

				if (f)
				{
					break;
				}
			}
			FreeBuf(b);
		}
		Copy(&unix_dns_server, ip, sizeof(IP));
	}
	Unlock(unix_dns_server_addr_lock);

	return true;
}


// Select 処理
void UnixSelect(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	UINT reads[MAXIMUM_WAIT_OBJECTS];
	UINT writes[MAXIMUM_WAIT_OBJECTS];
	UINT num_read, num_write, i;
	UINT p1, p2;
	SOCK *s;
	UCHAR tmp[MAX_SIZE];
	// 引数チェック
	if (timeout == 0)
	{
		return;
	}

	// 配列の初期化
	Zero(reads, sizeof(reads));
	Zero(writes, sizeof(writes));
	num_read = num_write = 0;

	// イベント配列の設定
	if (set != NULL)
	{
		for (i = 0;i < set->NumSocket;i++)
		{
			s = set->Sock[i];
			if (s != NULL)
			{
				UnixInitAsyncSocket(s);
				reads[num_read++] = s->socket;
				if (s->WriteBlocked)
				{
					writes[num_write++] = s->socket;
				}
			}
		}
	}

	p1 = p2 = -1;

	if (c1 != NULL)
	{
		reads[num_read++] = p1 = c1->pipe_read;
	}
	if (c2 != NULL)
	{
		reads[num_read++] = p2 = c2->pipe_read;
	}

	// select を呼び出す
	UnixSelectInner(num_read, reads, num_write, writes, timeout);

	// pipe から読んでおく
	if (c1 != NULL && c1->SpecialFlag == false && p1 != -1)
	{
		read(p1, tmp, sizeof(tmp));
	}
	if (c2 != NULL && c2->SpecialFlag == false && p2 != -1)
	{
		read(p2, tmp, sizeof(tmp));
	}
}

// キャンセル
void UnixCancel(CANCEL *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	UnixWritePipe(c->pipe_write);
}

// キャンセルオブジェクトの解放
void UnixCleanupCancel(CANCEL *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	if (c->SpecialFlag == false)
	{
		UnixDeletePipe(c->pipe_read, c->pipe_write);
	}

	Free(c);
}

// 新しいキャンセルオブジェクトの作成
CANCEL *UnixNewCancel()
{
	CANCEL *c = ZeroMallocFast(sizeof(CANCEL));

	c->ref = NewRef();
	c->SpecialFlag = false;

	UnixNewPipe(&c->pipe_read, &c->pipe_write);

	return c;
}

// ソケットをソケットイベントに追加する
void UnixJoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	// 引数チェック
	if (sock == NULL || event == NULL || sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode != false || (sock->Type == SOCK_TCP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	LockList(event->SockList);
	{
		Add(event->SockList, sock);
		AddRef(sock->ref);
	}
	UnlockList(event->SockList);

	// ソケットを非同期にする
	UnixSetSocketNonBlockingMode(sock->socket, true);

	// SOCK_EVENT の参照カウンタを増加
	AddRef(event->ref);
	sock->SockEvent = event;

	// ソケットイベントを叩く
	SetSockEvent(event);
}

// ソケットイベントを待機する
bool UnixWaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	UINT num_read, num_write;
	UINT *reads, *writes;
	UINT n;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (event == NULL)
	{
		return false;
	}

	LockList(event->SockList);
	{
		UINT i;
		num_read = LIST_NUM(event->SockList) + 1;
		reads = ZeroMallocFast(sizeof(SOCK *) * num_read);

		num_write = 0;

		for (i = 0;i < (num_read - 1);i++)
		{
			SOCK *s = LIST_DATA(event->SockList, i);
			reads[i] = s->socket;
			if (s->WriteBlocked)
			{
				num_write++;
			}
		}

		reads[num_read - 1] = event->pipe_read;

		writes = ZeroMallocFast(sizeof(SOCK *) * num_write);

		n = 0;

		for (i = 0;i < (num_read - 1);i++)
		{
			SOCK *s = LIST_DATA(event->SockList, i);
			if (s->WriteBlocked)
			{
				writes[n++] = s->socket;
			}
		}
	}
	UnlockList(event->SockList);

	if (0)
	{
		UINT i;
		Print("UnixSelectInner: ");
		for (i = 0;i < num_read;i++)
		{
			Print("%u ", reads[i]);
		}
		Print("\n");
	}

	UnixSelectInner(num_read, reads, num_write, writes, timeout);

	read(event->pipe_read, tmp, sizeof(tmp));

	Free(reads);
	Free(writes);

	return true;
}

// ソケットイベントをセットする
void UnixSetSockEvent(SOCK_EVENT *event)
{
	// 引数チェック
	if (event == NULL)
	{
		return;
	}

	UnixWritePipe(event->pipe_write);
}

// ソケットの select の実行
void UnixSelectInner(UINT num_read, UINT *reads, UINT num_write, UINT *writes, UINT timeout)
{
	struct pollfd *p;
	UINT num;
	UINT i;
	UINT n;
	UINT num_read_total, num_write_total;

	if (num_read != 0 && reads == NULL)
	{
		num_read = 0;
	}
	if (num_write != 0 && writes == NULL)
	{
		num_write = 0;
	}

	if (timeout == 0)
	{
		return;
	}

	num_read_total = num_write_total = 0;
	for (i = 0;i < num_read;i++)
	{
		if (reads[i] != INVALID_SOCKET)
		{
			num_read_total++;
		}
	}
	for (i = 0;i < num_write;i++)
	{
		if (writes[i] != INVALID_SOCKET)
		{
			num_write_total++;
		}
	}

	num = num_read_total + num_write_total;
	p = ZeroMallocFast(sizeof(struct pollfd) * num);

	n = 0;

	for (i = 0;i < num_read;i++)
	{
		if (reads[i] != INVALID_SOCKET)
		{
			struct pollfd *pfd = &p[n++];
			pfd->fd = reads[i];
			pfd->events = POLLIN | POLLPRI | POLLERR | POLLHUP;
		}
	}

	for (i = 0;i < num_write;i++)
	{
		if (writes[i] != INVALID_SOCKET)
		{
			struct pollfd *pfd = &p[n++];
			pfd->fd = writes[i];
			pfd->events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLOUT;
		}
	}

	if (num != 0)
	{
		poll(p, num, timeout == INFINITE ? -1 : (int)timeout);
	}
	else
	{
		SleepThread(timeout);
	}

	Free(p);
}

// ソケットイベントのクリーンアップ
void UnixCleanupSockEvent(SOCK_EVENT *event)
{
	UINT i;
	// 引数チェック
	if (event == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(event->SockList);i++)
	{
		SOCK *s = LIST_DATA(event->SockList, i);

		ReleaseSock(s);
	}

	ReleaseList(event->SockList);

	UnixDeletePipe(event->pipe_read, event->pipe_write);

	Free(event);
}

// ソケットイベントを作成する
SOCK_EVENT *UnixNewSockEvent()
{
	SOCK_EVENT *e = ZeroMallocFast(sizeof(SOCK_EVENT));

	e->SockList = NewList(NULL);
	e->ref = NewRef();

	UnixNewPipe(&e->pipe_read, &e->pipe_write);

	return e;
}

// パイプを閉じる
void UnixDeletePipe(int p1, int p2)
{
	if (p1 != -1)
	{
		close(p1);
	}

	if (p2 != -1)
	{
		close(p2);
	}
}

// パイプに書き込む
void UnixWritePipe(int pipe_write)
{
	char c = 1;
	write(pipe_write, &c, 1);
}

// 新しいパイプを作成する
void UnixNewPipe(int *pipe_read, int *pipe_write)
{
	int fd[2];
	// 引数チェック
	if (pipe_read == NULL || pipe_write == NULL)
	{
		return;
	}

	fd[0] = fd[1] = 0;

	pipe(fd);

	*pipe_read = fd[0];
	*pipe_write = fd[1];

	UnixSetSocketNonBlockingMode(*pipe_write, true);
	UnixSetSocketNonBlockingMode(*pipe_read, true);
}

// 非同期ソケットの解放
void UnixFreeAsyncSocket(SOCK *sock)
{
	UINT p;
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}

	Lock(sock->lock);
	{
		if (sock->AsyncMode == false)
		{
			Unlock(sock->lock);
			return;
		}

		sock->AsyncMode = false;

		// このソケットが SockEvent に関連付けられているかどうか調べる
		if (sock->SockEvent != NULL)
		{
			SOCK_EVENT *e = sock->SockEvent;

			AddRef(e->ref);

			p = e->pipe_write;
			LockList(e->SockList);
			{
				if (Delete(e->SockList, sock))
				{
					ReleaseSock(sock);
				}
			}
			UnlockList(e->SockList);

			// ソケットイベントを解放する
			ReleaseSockEvent(sock->SockEvent);
			sock->SockEvent = NULL;

			SetSockEvent(e);

			ReleaseSockEvent(e);
		}
	}
	Unlock(sock->lock);
}

// ソケットを非同期に設定する
void UnixInitAsyncSocket(SOCK *sock)
{
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}
	if (sock->AsyncMode)
	{
		// すでに非同期ソケットになっている
		return;
	}
	if (sock->ListenMode != false || (sock->Type == SOCK_TCP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	UnixSetSocketNonBlockingMode(sock->socket, true);
}

// ソケットライブラリの初期化
void UnixInitSocketLibrary()
{
	// 特に何もしない
}

// ソケットライブラリの解放
void UnixFreeSocketLibrary()
{
	// 特に何もしない
}

#endif	// OS_UNIX

#ifdef	OS_WIN32		// Windows 用コード

NETWORK_WIN32_FUNCTIONS *w32net;

// IP_ADAPTER_INDEX_MAP の比較
int CompareIpAdapterIndexMap(void *p1, void *p2)
{
	IP_ADAPTER_INDEX_MAP *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(IP_ADAPTER_INDEX_MAP **)p1;
	a2 = *(IP_ADAPTER_INDEX_MAP **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	if (a1->Index > a2->Index)
	{
		return 1;
	}
	else if (a1->Index < a2->Index)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// アダプタの IP アドレスを更新
bool Win32RenewAddressByGuid(char *guid)
{
	IP_ADAPTER_INDEX_MAP a;
	// 引数チェック
	if (guid == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));
	if (Win32GetAdapterFromGuid(&a, guid) == false)
	{
		return false;
	}

	return Win32RenewAddress(&a);
}
bool Win32RenewAddress(void *a)
{
	DWORD ret;
	// 引数チェック
	if (a == NULL)
	{
		return false;
	}
	if (w32net->IpRenewAddress == NULL)
	{
		return false;
	}

	ret = w32net->IpRenewAddress(a);

	if (ret == NO_ERROR)
	{
		return true;
	}
	else
	{
		Debug("IpRenewAddress: Error: %u\n", ret);
		return false;
	}
}

// アダプタの IP アドレスを解放
bool Win32ReleaseAddress(void *a)
{
	DWORD ret;
	// 引数チェック
	if (a == NULL)
	{
		return false;
	}
	if (w32net->IpReleaseAddress == NULL)
	{
		return false;
	}

	ret = w32net->IpReleaseAddress(a);

	if (ret == NO_ERROR)
	{
		return true;
	}
	else
	{
		Debug("IpReleaseAddress: Error: %u\n", ret);
		return false;
	}
}
bool Win32ReleaseAddressByGuid(char *guid)
{
	IP_ADAPTER_INDEX_MAP a;
	// 引数チェック
	if (guid == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));
	if (Win32GetAdapterFromGuid(&a, guid) == false)
	{
		return false;
	}

	return Win32ReleaseAddress(&a);
}
void Win32ReleaseAddressByGuidExThread(THREAD *t, void *param)
{
	WIN32_RELEASEADDRESS_THREAD_PARAM *p;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	p = (WIN32_RELEASEADDRESS_THREAD_PARAM *)param;

	AddRef(p->Ref);

	NoticeThreadInit(t);

	AddWaitThread(t);

	if (p->Renew == false)
	{
		p->Ok = Win32ReleaseAddressByGuid(p->Guid);
	}
	else
	{
		p->Ok = Win32RenewAddressByGuid(p->Guid);
	}

	ReleaseWin32ReleaseAddressByGuidThreadParam(p);

	DelWaitThread(t);
}
bool Win32RenewAddressByGuidEx(char *guid, UINT timeout)
{
	return Win32ReleaseOrRenewAddressByGuidEx(guid, timeout, true);
}
bool Win32ReleaseAddressByGuidEx(char *guid, UINT timeout)
{
	return Win32ReleaseOrRenewAddressByGuidEx(guid, timeout, false);
}
bool Win32ReleaseOrRenewAddressByGuidEx(char *guid, UINT timeout, bool renew)
{
	THREAD *t;
	WIN32_RELEASEADDRESS_THREAD_PARAM *p;
	bool ret = false;
	UINT64 start_tick = 0;
	UINT64 end_tick = 0;
	// 引数チェック
	if (guid == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = INFINITE;
	}

	p = ZeroMalloc(sizeof(WIN32_RELEASEADDRESS_THREAD_PARAM));
	p->Ref = NewRef();
	StrCpy(p->Guid, sizeof(p->Guid), guid);
	p->Timeout = timeout;
	p->Renew = renew;

	t = NewThread(Win32ReleaseAddressByGuidExThread, p);
	WaitThreadInit(t);
	start_tick = Tick64();
	end_tick = start_tick + (UINT64)timeout;

	while (true)
	{
		UINT64 now = Tick64();
		UINT64 remain;
		UINT remain32;

		if (now >= end_tick)
		{
			break;
		}

		remain = end_tick - now;
		remain32 = MIN((UINT)remain, 100);

		if (WaitThread(t, remain32))
		{
			break;
		}
	}

	ReleaseThread(t);

	if (p->Ok)
	{
		ret = true;
	}

	ReleaseWin32ReleaseAddressByGuidThreadParam(p);

	return ret;
}
void ReleaseWin32ReleaseAddressByGuidThreadParam(WIN32_RELEASEADDRESS_THREAD_PARAM *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		Free(p);
	}
}

// アダプタを GUID から取得
bool Win32GetAdapterFromGuid(void *a, char *guid)
{
	bool ret = false;
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;
	wchar_t tmp[MAX_SIZE];

	// 引数チェック
	if (a == NULL || guid == NULL)
	{
		return false;
	}
	if (w32net->GetInterfaceInfo == NULL)
	{
		return false;
	}

	UniFormat(tmp, sizeof(tmp), L"\\DEVICE\\TCPIP_%S", guid);

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return false;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *e = LIST_DATA(o, i);

		if (UniStrCmpi(e->Name, tmp) == 0)
		{
			Copy(a, e, sizeof(IP_ADAPTER_INDEX_MAP));
			ret = true;
			break;
		}
	}

	ReleaseList(o);

	Free(info);

	return ret;
}

// テスト
void Win32NetworkTest()
{
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *a = LIST_DATA(o, i);

		DoNothing();
	}

	ReleaseList(o);

	Free(info);
}

// 指定された LAN カードの DHCP アドレスを更新する
void Win32RenewDhcp9x(UINT if_id)
{
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;
	// 引数チェック
	if (if_id == 0)
	{
		return;
	}

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *a = LIST_DATA(o, i);

		if (a->Index == if_id)
		{
			char arg[MAX_PATH];
			Format(arg, sizeof(arg), "/renew %u", i);
			Run("ipconfig.exe", arg, true, false);
		}
	}

	ReleaseList(o);

	Free(info);
}

// 指定された LAN カードの DHCP アドレスを解放する
void Win32ReleaseDhcp9x(UINT if_id, bool wait)
{
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;
	// 引数チェック
	if (if_id == 0)
	{
		return;
	}

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *a = LIST_DATA(o, i);

		if (a->Index == if_id)
		{
			char arg[MAX_PATH];
			Format(arg, sizeof(arg), "/release %u", i);
			Run("ipconfig.exe", arg, true, wait);
		}
	}

	ReleaseList(o);

	Free(info);
}

// DHCP サーバーから IP アドレスを再取得する
void Win32RenewDhcp()
{
	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		Run("ipconfig.exe", "/renew", true, false);
		if (MsIsVista())
		{
			Run("ipconfig.exe", "/renew6", true, false);
		}
		else
		{
			Run("netsh.exe", "int ipv6 renew", true, false);
		}
	}
	else
	{
		Run("ipconfig.exe", "/renew_all", true, false);
	}
}

// 指定された文字列を含む仮想 LAN カードの一覧を列挙する
char **Win32EnumVLan(char *tag_name)
{
	MIB_IFTABLE *p;
	UINT ret;
	UINT size_needed;
	UINT num_retry = 0;
	UINT i;
	LIST *o;
	char **ss;
	// 引数チェック
	if (tag_name == 0)
	{
		return NULL;
	}

RETRY:
	p = ZeroMallocFast(sizeof(MIB_IFTABLE));
	size_needed = 0;

	// 必要なサイズを調べる
	ret = w32net->GetIfTable(p, &size_needed, 0);
	if (ret == ERROR_INSUFFICIENT_BUFFER)
	{
		// 必要なサイズ分のメモリブロックを再確保
		Free(p);
		p = ZeroMallocFast(size_needed);
	}
	else if (ret != NO_ERROR)
	{
		// 取得失敗
FAILED:
		Free(p);
		return NULL;
	}

	// 実際に取得する
	ret = w32net->GetIfTable(p, &size_needed, FALSE);
	if (ret != NO_ERROR)
	{
		// 取得失敗
		if ((++num_retry) >= 5)
		{
			goto FAILED;
		}
		Free(p);
		goto RETRY;
	}

	// 検索
	ret = 0;
	o = NewListFast(CompareStr);
	for (i = 0;i < p->dwNumEntries;i++)
	{
		MIB_IFROW *r = &p->table[i];
		if (SearchStrEx(r->bDescr, tag_name, 0, false) != INFINITE)
		{
			char *s = CopyStr(r->bDescr);
			Add(o, s);
		}
	}

	Free(p);

	// ソート
	Sort(o);

	// 文字列に変換
	ss = ZeroMallocFast(sizeof(char *) * (LIST_NUM(o) + 1));
	for (i = 0;i < LIST_NUM(o);i++)
	{
		ss[i] = LIST_DATA(o, i);
	}
	ss[LIST_NUM(o)] = NULL;

	ReleaseList(o);

	return ss;
}

// 仮想 LAN カードのインスタンス名から仮想 LAN カードの ID を取得する
UINT Win32GetVLanInterfaceID(char *instance_name)
{
	MIB_IFTABLE *p;
	UINT ret;
	UINT size_needed;
	UINT num_retry = 0;
	UINT i;
	char ps_miniport_str[MAX_SIZE];
	char ps_miniport_str2[MAX_SIZE];
	// 引数チェック
	if (instance_name == 0)
	{
		return 0;
	}

RETRY:
	p = ZeroMallocFast(sizeof(MIB_IFTABLE));
	size_needed = 0;

	// 必要なサイズを調べる
	ret = w32net->GetIfTable(p, &size_needed, 0);
	if (ret == ERROR_INSUFFICIENT_BUFFER)
	{
		// 必要なサイズ分のメモリブロックを再確保
		Free(p);
		p = ZeroMallocFast(size_needed);
	}
	else if (ret != NO_ERROR)
	{
		// 取得失敗
FAILED:
		Free(p);
		Debug("******** GetIfTable Failed 1. Err = %u\n", ret);
		return 0;
	}

	// 実際に取得する
	ret = w32net->GetIfTable(p, &size_needed, FALSE);
	if (ret != NO_ERROR)
	{
		// 取得失敗
		if ((++num_retry) >= 5)
		{
			goto FAILED;
		}
		Free(p);
		Debug("******** GetIfTable Failed 2. Err = %u\n", ret);
		goto RETRY;
	}

	// "%s - パケット スケジューラ ミニポート"
	Format(ps_miniport_str, sizeof(ps_miniport_str), "%s - ", instance_name);
	Format(ps_miniport_str2, sizeof(ps_miniport_str2), "%s (Microsoft", instance_name);

	// 検索
	ret = 0;
	for (i = 0;i < p->dwNumEntries;i++)
	{
		MIB_IFROW *r = &p->table[i];
		if (instance_name[0] != '@')
		{
			if (StrCmpi(r->bDescr, instance_name) == 0 || StartWith(r->bDescr, ps_miniport_str) || StartWith(r->bDescr, ps_miniport_str2))
			{
				ret = r->dwIndex;
			}
		}
		else
		{
			if (SearchStrEx(r->bDescr, &instance_name[1], 0, false) != INFINITE)
			{
				ret = r->dwIndex;
			}
		}

		Debug("if[%u] (0x%x): %s\n", i, r->dwIndex, r->bDescr);
	}

	Free(p);

	return ret;
}

// デフォルトの DNS サーバーアドレスを取得する
bool Win32GetDefaultDns(IP *ip, char *domain, UINT size)
{
	FIXED_INFO *info;
	UINT info_size;
	char *dns_name;
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}
	Zero(ip, sizeof(IP));
	info_size = 0;
	info = ZeroMallocFast(sizeof(FIXED_INFO));
	if (w32net->GetNetworkParams(info, &info_size) == ERROR_BUFFER_OVERFLOW)
	{
		Free(info);
		info = ZeroMallocFast(info_size);
	}
	if (w32net->GetNetworkParams(info, &info_size) != NO_ERROR)
	{
		Free(info);
		return false;
	}

	if (info->DnsServerList.IpAddress.String == NULL)
	{
		Free(info);
		return false;
	}

	dns_name = info->DnsServerList.IpAddress.String;
	StrToIP(ip, dns_name);

	if (domain != NULL)
	{
		StrCpy(domain, size, info->DomainName);
		Trim(domain);
	}

	Free(info);

	return true;
}

// Win32 用 IP 変換関数
void Win32UINTToIP(IP *ip, UINT i)
{
	UINTToIP(ip, i);
}

// Win32 用 IP 変換関数
UINT Win32IPToUINT(IP *ip)
{
	return IPToUINT(ip);
}

// ルーティングテーブルからルーティングエントリを削除
void Win32DeleteRouteEntry(ROUTE_ENTRY *e)
{
	MIB_IPFORWARDROW *p;
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	p = ZeroMallocFast(sizeof(MIB_IPFORWARDROW));
	Win32RouteEntryToIpForwardRow(p, e);

	// 削除
	w32net->DeleteIpForwardEntry(p);

	Free(p);
}

// ルーティングテーブルにルーティングエントリを追加
bool Win32AddRouteEntry(ROUTE_ENTRY *e, bool *already_exists)
{
	bool ret = false;
	bool dummy = false;
	MIB_IPFORWARDROW *p;
	UINT err = 0;
	// 引数チェック
	if (e == NULL)
	{
		return false;
	}
	if (already_exists == NULL)
	{
		already_exists = &dummy;
	}

	*already_exists = false;

	p = ZeroMallocFast(sizeof(MIB_IPFORWARDROW));
	Win32RouteEntryToIpForwardRow(p, e);

	// 追加
	err = w32net->CreateIpForwardEntry(p);
	if (err != 0)
	{
		if (err == ERROR_OBJECT_ALREADY_EXISTS)
		{
			Debug("CreateIpForwardEntry: Already Exists\n");
			*already_exists = true;
			ret = true;
		}
		else
		{
			Debug("CreateIpForwardEntry Error: %u\n", err);
			ret = false;
		}
	}
	else
	{
		ret = true;
	}

	Free(p);

	return ret;
}

// ルーティングテーブルの取得
ROUTE_TABLE *Win32GetRouteTable()
{
	ROUTE_TABLE *t = ZeroMallocFast(sizeof(ROUTE_TABLE));
	MIB_IPFORWARDTABLE *p;
	UINT ret;
	UINT size_needed;
	UINT num_retry = 0;
	LIST *o;
	UINT i;
	ROUTE_ENTRY *e;

RETRY:
	p = ZeroMallocFast(sizeof(MIB_IFTABLE));
	size_needed = 0;

	// 必要なサイズを調べる
	ret = w32net->GetIpForwardTable(p, &size_needed, 0);
	if (ret == ERROR_INSUFFICIENT_BUFFER)
	{
		// 必要なサイズ分のメモリブロックを再確保
		Free(p);
		p = ZeroMallocFast(size_needed);
	}
	else if (ret != NO_ERROR)
	{
		// 取得失敗
FAILED:
		Free(p);
		t->Entry = MallocFast(0);
		return t;
	}

	// 実際に取得する
	ret = w32net->GetIpForwardTable(p, &size_needed, FALSE);
	if (ret != NO_ERROR)
	{
		// 取得失敗
		if ((++num_retry) >= 5)
		{
			goto FAILED;
		}
		Free(p);
		goto RETRY;
	}

	// リストに追加していく
	o = NewListFast(Win32CompareRouteEntryByMetric);
	for (i = 0;i < p->dwNumEntries;i++)
	{
		e = ZeroMallocFast(sizeof(ROUTE_ENTRY));
		Win32IpForwardRowToRouteEntry(e, &p->table[i]);
		Add(o, e);
	}
	Free(p);

	// メトリック順にソート
	Sort(o);

	// 結果を結合
	t->NumEntry = LIST_NUM(o);
	t->Entry = ToArrayEx(o, true);
	ReleaseList(o);

	return t;
}

// ルーティングエントリをメトリックによってソートする
int Win32CompareRouteEntryByMetric(void *p1, void *p2)
{
	ROUTE_ENTRY *e1, *e2;
	// 引数チェック
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	e1 = *(ROUTE_ENTRY **)p1;
	e2 = *(ROUTE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->Metric > e2->Metric)
	{
		return 1;
	}
	else if (e1->Metric == e2->Metric)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

// ROUTE_ENTRY を MIB_IPFORWARDROW に変換
void Win32RouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry)
{
	MIB_IPFORWARDROW *r;
	// 引数チェック
	if (entry == NULL || ip_forward_row == NULL)
	{
		return;
	}

	r = (MIB_IPFORWARDROW *)ip_forward_row;
	Zero(r, sizeof(MIB_IPFORWARDROW));

	// IP アドレス
	r->dwForwardDest = Win32IPToUINT(&entry->DestIP);
	// サブネットマスク
	r->dwForwardMask = Win32IPToUINT(&entry->DestMask);
	// ゲートウェイ IP アドレス
	r->dwForwardNextHop = Win32IPToUINT(&entry->GatewayIP);
	// ローカルルーティングフラグ
	if (entry->LocalRouting)
	{
		// ローカル
		r->dwForwardType = 3;
	}
	else
	{
		// リモートルータ
		r->dwForwardType = 4;
	}
	// プロトコル
	r->dwForwardProto = r->dwForwardType - 1;	// 大抵の場合 1 引けば良い
	if (entry->PPPConnection)
	{
		// PPP ちゃうかな？ 危険！
		r->dwForwardProto++;
	}
	// メトリック
	r->dwForwardMetric1 = entry->Metric;

	if (MsIsVista() == false)
	{
		r->dwForwardMetric2 = r->dwForwardMetric3 = r->dwForwardMetric4 = r->dwForwardMetric5 = INFINITE;
	}
	else
	{
		r->dwForwardMetric2 = r->dwForwardMetric3 = r->dwForwardMetric4 = r->dwForwardMetric5 = 0;
		r->dwForwardAge = 163240;
	}

	// インターフェイス ID
	r->dwForwardIfIndex = entry->InterfaceID;

	Debug("Win32RouteEntryToIpForwardRow()\n");
	Debug(" r->dwForwardDest=%X\n", r->dwForwardDest);
	Debug(" r->dwForwardMask=%X\n", r->dwForwardMask);
	Debug(" r->dwForwardNextHop=%X\n", r->dwForwardNextHop);
	Debug(" r->dwForwardType=%u\n", r->dwForwardType);
	Debug(" r->dwForwardProto=%u\n", r->dwForwardProto);
	Debug(" r->dwForwardMetric1=%u\n", r->dwForwardMetric1);
	Debug(" r->dwForwardMetric2=%u\n", r->dwForwardMetric2);
	Debug(" r->dwForwardIfIndex=%u\n", r->dwForwardIfIndex);
}

// MIB_IPFORWARDROW を ROUTE_ENTRY に変換
void Win32IpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row)
{
	MIB_IPFORWARDROW *r;
	// 引数チェック
	if (entry == NULL || ip_forward_row == NULL)
	{
		return;
	}

	r = (MIB_IPFORWARDROW *)ip_forward_row;

	Zero(entry, sizeof(ROUTE_ENTRY));
	// IP アドレス
	Win32UINTToIP(&entry->DestIP, r->dwForwardDest);
	// サブネットマスク
	Win32UINTToIP(&entry->DestMask, r->dwForwardMask);
	// ゲートウェイ IP アドレス
	Win32UINTToIP(&entry->GatewayIP, r->dwForwardNextHop);
	// ローカルルーティングフラグ
	if (r->dwForwardType == 3)
	{
		entry->LocalRouting = true;
	}
	else
	{
		entry->LocalRouting = false;
	}
	if (entry->LocalRouting && r->dwForwardProto == 3)
	{
		// PPP。危険！
		entry->PPPConnection = true;
	}
	// メトリック
	entry->Metric = r->dwForwardMetric1;
	// インターフェイス ID
	entry->InterfaceID = r->dwForwardIfIndex;
}

// ソケットライブラリの初期化
void Win32InitSocketLibrary()
{
	WSADATA data;
	Zero(&data, sizeof(data));
	WSAStartup(MAKEWORD(2, 2), &data);

	// DLL 関数の読み込み
	w32net = ZeroMalloc(sizeof(NETWORK_WIN32_FUNCTIONS));
	w32net->hIpHlpApi32 = LoadLibrary("iphlpapi.dll");

	if (w32net->hIpHlpApi32 != NULL)
	{
		w32net->CreateIpForwardEntry =
			(DWORD (__stdcall *)(PMIB_IPFORWARDROW))
			GetProcAddress(w32net->hIpHlpApi32, "CreateIpForwardEntry");

		w32net->DeleteIpForwardEntry =
			(DWORD (__stdcall *)(PMIB_IPFORWARDROW))
			GetProcAddress(w32net->hIpHlpApi32, "DeleteIpForwardEntry");

		w32net->GetIfTable =
			(DWORD (__stdcall *)(PMIB_IFTABLE, PULONG, BOOL))
			GetProcAddress(w32net->hIpHlpApi32, "GetIfTable");

		w32net->GetIpForwardTable =
			(DWORD (__stdcall *)(PMIB_IPFORWARDTABLE, PULONG, BOOL))
			GetProcAddress(w32net->hIpHlpApi32, "GetIpForwardTable");

		w32net->GetNetworkParams =
			(DWORD (__stdcall *)(PFIXED_INFO,PULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetNetworkParams");

		w32net->IpRenewAddress =
			(DWORD (__stdcall *)(PIP_ADAPTER_INDEX_MAP))
			GetProcAddress(w32net->hIpHlpApi32, "IpRenewAddress");

		w32net->IpReleaseAddress =
			(DWORD (__stdcall *)(PIP_ADAPTER_INDEX_MAP))
			GetProcAddress(w32net->hIpHlpApi32, "IpReleaseAddress");

		w32net->GetInterfaceInfo =
			(DWORD (__stdcall *)(PIP_INTERFACE_INFO, PULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetInterfaceInfo");

		w32net->GetAdaptersInfo =
			(DWORD (__stdcall *)(PIP_ADAPTER_INFO, PULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetAdaptersInfo");

		w32net->GetExtendedTcpTable =
			(DWORD (__stdcall *)(PVOID,PDWORD,BOOL,ULONG,_TCP_TABLE_CLASS,ULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetExtendedTcpTable");

		w32net->AllocateAndGetTcpExTableFromStack =
			(DWORD (__stdcall *)(PVOID *,BOOL,HANDLE,DWORD,DWORD))
			GetProcAddress(w32net->hIpHlpApi32, "AllocateAndGetTcpExTableFromStack");

		w32net->GetTcpTable =
			(DWORD (__stdcall *)(PMIB_TCPTABLE,PDWORD,BOOL))
			GetProcAddress(w32net->hIpHlpApi32, "GetTcpTable");

		w32net->NotifyRouteChange =
			(DWORD (__stdcall *)(PHANDLE,LPOVERLAPPED))
			GetProcAddress(w32net->hIpHlpApi32, "NotifyRouteChange");

		w32net->CancelIPChangeNotify =
			(BOOL (__stdcall *)(LPOVERLAPPED))
			GetProcAddress(w32net->hIpHlpApi32, "CancelIPChangeNotify");

		w32net->NhpAllocateAndGetInterfaceInfoFromStack =
			(DWORD (__stdcall *)(IP_INTERFACE_NAME_INFO **,PDWORD,BOOL,HANDLE,DWORD))
			GetProcAddress(w32net->hIpHlpApi32, "NhpAllocateAndGetInterfaceInfoFromStack");
	}
}

// ソケットライブラリの解放
void Win32FreeSocketLibrary()
{
	if (w32net != NULL)
	{
		FreeLibrary(w32net->hIpHlpApi32);

		Free(w32net);
		w32net = NULL;
	}

	WSACleanup();
}

// キャンセル
void Win32Cancel(CANCEL *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	SetEvent((HANDLE)c->hEvent);
}

// キャンセルのクリーンアップ
void Win32CleanupCancel(CANCEL *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	if (c->SpecialFlag == false)
	{
		CloseHandle(c->hEvent);
	}

	Free(c);
}

// 新しいキャンセルオブジェクト
CANCEL *Win32NewCancel()
{
	CANCEL *c = ZeroMallocFast(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = false;
	c->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	return c;
}

// ソケットイベントの待機
bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	// 引数チェック
	if (event == NULL || timeout == 0)
	{
		return false;
	}

	if (WaitForSingleObject((HANDLE)event->hEvent, timeout) == WAIT_OBJECT_0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// ソケットイベントのクリーンアップ
void Win32CleanupSockEvent(SOCK_EVENT *event)
{
	// 引数チェック
	if (event == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)event->hEvent);

	Free(event);
}

// ソケットイベントのセット
void Win32SetSockEvent(SOCK_EVENT *event)
{
	// 引数チェック
	if (event == NULL)
	{
		return;
	}

	SetEvent((HANDLE)event->hEvent);
}

// ソケットイベントの作成
SOCK_EVENT *Win32NewSockEvent()
{
	SOCK_EVENT *e = ZeroMallocFast(sizeof(SOCK_EVENT));

	e->ref = NewRef();
	e->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	return e;
}

// ソケットをソケットイベントに関連付けして非同期に設定する
void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	HANDLE hEvent;
	// 引数チェック
	if (sock == NULL || event == NULL || sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode != false || (sock->Type != SOCK_UDP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	hEvent = event->hEvent;

	// 関連付け
	WSAEventSelect(sock->socket, hEvent, FD_READ | FD_WRITE | FD_CLOSE);

	// SOCK_EVENT の参照カウンタを増加
	AddRef(event->ref);
	sock->SockEvent = event;
}

// ソケットを非同期に設定する
void Win32InitAsyncSocket(SOCK *sock)
{
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}
	if (sock->AsyncMode)
	{
		// すでに非同期ソケットになっている
		return;
	}
	if (sock->ListenMode != false || (sock->Type == SOCK_TCP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	// イベントの作成
	sock->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	// 関連付け
	WSAEventSelect(sock->socket, sock->hEvent, FD_READ | FD_WRITE | FD_CLOSE);
}

// 非同期ソケットを解放
void Win32FreeAsyncSocket(SOCK *sock)
{
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}

	// 非同期ソケット
	if (sock->hEvent != NULL)
	{
		CloseHandle((HANDLE)sock->hEvent);
	}
	sock->hEvent = NULL;
	sock->AsyncMode = false;

	// ソケットイベント
	if (sock->SockEvent != NULL)
	{
		ReleaseSockEvent(sock->SockEvent);
		sock->SockEvent = NULL;
	}
}

// Win32 版 Select 関数
void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	HANDLE array[MAXIMUM_WAIT_OBJECTS];
	UINT n, i;
	SOCK *s;
	// 引数チェック
	if (timeout == 0)
	{
		return;
	}

	// 配列の初期化
	Zero(array, sizeof(array));
	n = 0;

	// イベント配列の設定
	if (set != NULL)
	{
		for (i = 0;i < set->NumSocket;i++)
		{
			s = set->Sock[i];
			if (s != NULL)
			{
				Win32InitAsyncSocket(s);
				if (s->hEvent != NULL)
				{
					array[n++] = (HANDLE)s->hEvent;
				}
			}
		}
	}
	if (c1 != NULL && c1->hEvent != NULL)
	{
		array[n++] = c1->hEvent;
	}
	if (c2 != NULL && c2->hEvent != NULL)
	{
		array[n++] = c2->hEvent;
	}

	if (n == 0)
	{
		// 待つイベントが 1 つも登録されていない場合は
		// 通常の待ち関数を呼ぶ
		SleepThread(timeout);
	}
	else
	{
		// イベントが 1 つ以上登録されている場合はイベントを待つ
		if (n == 1)
		{
			// イベントが 1 つの場合は軽量版を呼び出す
			WaitForSingleObject(array[0], timeout);
		}
		else
		{
			// イベントが複数の場合
			WaitForMultipleObjects(n, array, false, timeout);
		}
	}
}

#endif	// OS_WIN32

// IPv6 がサポートされているかどうか調べる
bool IsIPv6Supported()
{
#ifdef	NO_IPV6
	return false;
#else	// NO_IPV6
	SOCKET s;

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	closesocket(s);

	return true;
#endif	// NO_IPV6
}

// ホストキャッシュからホスト名の取得
bool GetHostCache(char *hostname, UINT size, IP *ip)
{
	bool ret;
	// 引数チェック
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	ret = false;

	LockList(HostCacheList);
	{
		HOSTCACHE t, *c;
		Zero(&t, sizeof(t));
		Copy(&t.IpAddress, ip, sizeof(IP));

		c = Search(HostCacheList, &t);
		if (c != NULL)
		{
			if (IsEmptyStr(c->HostName) == false)
			{
				ret = true;
				StrCpy(hostname, size, c->HostName);
			}
			else
			{
				ret = true;
				StrCpy(hostname, size, "");
			}
		}
	}
	UnlockList(HostCacheList);

	return ret;
}

// ホスト名キャッシュへ追加
void AddHostCache(IP *ip, char *hostname)
{
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return;
	}
	if (IsNetworkNameCacheEnabled() == false)
	{
		return;
	}

	LockList(HostCacheList);
	{
		HOSTCACHE t, *c;
		UINT i;
		LIST *o;

		Zero(&t, sizeof(t));
		Copy(&t.IpAddress, ip, sizeof(IP));

		c = Search(HostCacheList, &t);
		if (c == NULL)
		{
			c = ZeroMalloc(sizeof(HOSTCACHE));
			Copy(&c->IpAddress, ip, sizeof(IP));
			Add(HostCacheList, c);
		}

		StrCpy(c->HostName, sizeof(c->HostName), hostname);
		c->Expires = Tick64() + (UINT64)EXPIRES_HOSTNAME;

		o = NewListFast(NULL);

		for (i = 0;i < LIST_NUM(HostCacheList);i++)
		{
			HOSTCACHE *c = LIST_DATA(HostCacheList, i);

			if (c->Expires <= Tick64())
			{
				Add(o, c);
			}
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			HOSTCACHE *c = LIST_DATA(o, i);

			if (Delete(HostCacheList, c))
			{
				Free(c);
			}
		}

		ReleaseList(o);
	}
	UnlockList(HostCacheList);
}

// ホスト名キャッシュの比較
int CompareHostCache(void *p1, void *p2)
{
	HOSTCACHE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(HOSTCACHE **)p1;
	c2 = *(HOSTCACHE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}

// ホスト名キャッシュの解放
void FreeHostCache()
{
	UINT i;

	for (i = 0;i < LIST_NUM(HostCacheList);i++)
	{
		HOSTCACHE *c = LIST_DATA(HostCacheList, i);

		Free(c);
	}

	ReleaseList(HostCacheList);
	HostCacheList = NULL;
}

// ホスト名キャッシュの初期化
void InitHostCache()
{
	HostCacheList = NewList(CompareHostCache);
}

// スレッドをスレッド待機リストに追加する
void AddWaitThread(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	AddRef(t->ref);

	LockList(WaitThreadList);
	{
		Add(WaitThreadList, t);
	}
	UnlockList(WaitThreadList);
}

// スレッドを待機リストから削除する
void DelWaitThread(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	LockList(WaitThreadList);
	{
		if (Delete(WaitThreadList, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(WaitThreadList);
}

// スレッド待機リストの作成
void InitWaitThread()
{
	WaitThreadList = NewList(NULL);
}

// スレッド待機リストの解放
void FreeWaitThread()
{
	UINT i, num;
	THREAD **threads;

	LockList(WaitThreadList);
	{
		num = LIST_NUM(WaitThreadList);
		threads = ToArray(WaitThreadList);
		DeleteAll(WaitThreadList);
	}
	UnlockList(WaitThreadList);

	for (i = 0;i < num;i++)
	{
		THREAD *t = threads[i];
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	Free(threads);

	ReleaseList(WaitThreadList);
	WaitThreadList = NULL;
}

// 暗号リスト名をチェックする
bool CheckCipherListName(char *name)
{
	UINT i;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	for (i = 0;i < cipher_list_token->NumTokens;i++)
	{
		if (StrCmpi(cipher_list_token->Token[i], name) == 0)
		{
			return true;
		}
	}

	return false;
}

// DHCP サーバーの IP アドレス更新
void RenewDhcp()
{
#ifdef	OS_WIN32
	Win32RenewDhcp();
#else
	UnixRenewDhcp();
#endif
}

// UNIX 用ドメイン名を取得
bool UnixGetDomainName(char *name, UINT size)
{
	bool ret = false;
	BUF *b = ReadDump("/etc/resolv.conf");

	if (b == NULL)
	{
		return false;
	}

	while (true)
	{
		char *s = CfgReadNextLine(b);
		TOKEN_LIST *t;

		if (s == NULL)
		{
			break;
		}

		Trim(s);

		t = ParseToken(s, " \t");
		if (t != NULL)
		{
			if (t->NumTokens == 2)
			{
				if (StrCmpi(t->Token[0], "domain") == 0)
				{
					StrCpy(name, size, t->Token[1]);
					ret = true;
				}
			}
			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ret;
}

// ドメイン名を取得
bool GetDomainName(char *name, UINT size)
{
	bool ret = false;
	IP ip;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

#ifdef	OS_WIN32
	ret = Win32GetDefaultDns(&ip, name, size);
#else	// OS_WIN32
	ret = UnixGetDomainName(name, size);
#endif	// OS_WIN32

	return ret;
}

// デフォルトの DNS サーバーの取得
bool GetDefaultDns(IP *ip)
{
	bool ret = false;
#ifdef	OS_WIN32
	ret = Win32GetDefaultDns(ip, NULL, 0);
#else
	ret = UnixGetDefaultDns(ip);
#endif	// OS_WIN32
	return ret;
}

// ソケットイベントの作成
SOCK_EVENT *NewSockEvent()
{
	SOCK_EVENT *e = NULL;
#ifdef	OS_WIN32
	e = Win32NewSockEvent();
#else
	e = UnixNewSockEvent();
#endif	// OS_WIN32
	return e;
}

// ソケットイベントのセット
void SetSockEvent(SOCK_EVENT *event)
{
#ifdef	OS_WIN32
	Win32SetSockEvent(event);
#else
	UnixSetSockEvent(event);
#endif	// OS_WIN32
}

// ソケットイベントのクリーンアップ
void CleanupSockEvent(SOCK_EVENT *event)
{
#ifdef	OS_WIN32
	Win32CleanupSockEvent(event);
#else
	UnixCleanupSockEvent(event);
#endif	// OS_WIN32
}

// ソケットイベントの待機
bool WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	bool ret = false;
#ifdef	OS_WIN32
	ret = Win32WaitSockEvent(event, timeout);
#else
	ret = UnixWaitSockEvent(event, timeout);
#endif	// OS_WIN32
	return ret;
}

// ソケットイベントの解放
void ReleaseSockEvent(SOCK_EVENT *event)
{
	// 引数チェック
	if (event == NULL)
	{
		return;
	}

	if (Release(event->ref) == 0)
	{
		CleanupSockEvent(event);
	}
}

// ソケットをソケットイベントに所属させる
void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
#ifdef	OS_WIN32
	Win32JoinSockToSockEvent(sock, event);
#else
	UnixJoinSockToSockEvent(sock, event);
#endif	// OS_WIN32
}

// 新しい特殊キャンセルオブジェクト
CANCEL *NewCancelSpecial(void *hEvent)
{
	CANCEL *c;
	// 引数チェック
	if (hEvent == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = true;

#ifdef	OS_WIN32
	c->hEvent = (HANDLE)hEvent;
#else	// OS_WIN32
	c->pipe_read = (int)hEvent;
	c->pipe_write = -1;
#endif	// OS_WIN32

	return c;
}

// キャンセルオブジェクトの作成
CANCEL *NewCancel()
{
	CANCEL *c = NULL;
#ifdef	OS_WIN32
	c = Win32NewCancel();
#else
	c = UnixNewCancel();
#endif	// OS_WIN32
	return c;
}

// キャンセルオブジェクトの解放
void ReleaseCancel(CANCEL *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupCancel(c);
	}
}

// キャンセルオブジェクトのクリーンアップ
void CleanupCancel(CANCEL *c)
{
#ifdef	OS_WIN32
	Win32CleanupCancel(c);
#else
	UnixCleanupCancel(c);
#endif
}

// キャンセル発動
void Cancel(CANCEL *c)
{
#ifdef	OS_WIN32
	Win32Cancel(c);
#else
	UnixCancel(c);
#endif
}

// 指定されたルーティングテーブルから最適なルートを計算する
ROUTE_ENTRY *GetBestRouteEntryFromRouteTable(ROUTE_TABLE *table, IP *ip)
{
	return GetBestRouteEntryFromRouteTableEx(table, ip, 0);
}
ROUTE_ENTRY *GetBestRouteEntryFromRouteTableEx(ROUTE_TABLE *table, IP *ip, UINT exclude_if_id)
{
	UINT i;
	UINT max_mask = 0;
	UINT min_metric = INFINITE;
	ROUTE_ENTRY *ret = NULL;
	ROUTE_ENTRY *tmp = NULL;
	// 引数チェック
	if (ip == NULL || table == NULL)
	{
		return NULL;
	}

	if (IsIP6(ip))
	{
		// IPv6 は非サポート
		return NULL;
	}

	// 対象となるルーティングテーブルのうち、
	//  第一条件: サブネットマスクが最も大きい
	//  第二条件: メトリック値が最も小さい
	// ものを選択する
	for (i = 0;i < table->NumEntry;i++)
	{
		ROUTE_ENTRY *e = table->Entry[i];
		UINT dest, net, mask;

		dest = IPToUINT(ip);
		net = IPToUINT(&e->DestIP);
		mask = IPToUINT(&e->DestMask);

		if (exclude_if_id != 0)
		{
			if (e->InterfaceID == exclude_if_id)
			{
				continue;
			}
		}

		// マスクテスト
		if ((dest & mask) == (net & mask))
		{
			// これはルーティングの対象となり得る
			if (mask >= max_mask)
			{
				max_mask = mask;
				if (min_metric >= e->Metric)
				{
					min_metric = e->Metric;
					tmp = e;
				}
			}
		}
	}

	if (tmp != NULL)
	{
		UINT dest, gateway, mask;

		// エントリを生成
		ret = ZeroMallocFast(sizeof(ROUTE_ENTRY));

		Copy(&ret->DestIP, ip, sizeof(IP));
		ret->DestMask.addr[0] = 255;
		ret->DestMask.addr[1] = 255;
		ret->DestMask.addr[2] = 255;
		ret->DestMask.addr[3] = 255;
		Copy(&ret->GatewayIP, &tmp->GatewayIP, sizeof(IP));
		ret->InterfaceID = tmp->InterfaceID;
		ret->LocalRouting = tmp->LocalRouting;
		ret->OldIfMetric = tmp->Metric;
		ret->Metric = 1;
		ret->PPPConnection = tmp->PPPConnection;

		// ルーティング制御関係の計算
		dest = IPToUINT(&tmp->DestIP);
		gateway = IPToUINT(&tmp->GatewayIP);
		mask = IPToUINT(&tmp->DestMask);
		if ((dest & mask) == (gateway & mask))
		{
#ifdef	OS_WIN32
			if (MsIsVista() == false)
			{
				// Windows 用調整
				ret->PPPConnection = true;
			}
#endif	// OS_WIN32
		}
	}

	return ret;
}

// ルーティングエントリを解放する
void FreeRouteEntry(ROUTE_ENTRY *e)
{
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	Free(e);
}

// 現在のルーティングテーブルを解析して最適なルートエントリを取得する
ROUTE_ENTRY *GetBestRouteEntry(IP *ip)
{
	return GetBestRouteEntryEx(ip, 0);
}
ROUTE_ENTRY *GetBestRouteEntryEx(IP *ip, UINT exclude_if_id)
{
	ROUTE_TABLE *table;
	ROUTE_ENTRY *e = NULL;
	// 引数チェック
	if (ip == NULL)
	{
		return NULL;
	}

	table = GetRouteTable();
	if (table == NULL)
	{
		return NULL;
	}

	e = GetBestRouteEntryFromRouteTableEx(table, ip, exclude_if_id);
	FreeRouteTable(table);

	return e;
}

// 仮想 LAN カードのインターフェース ID の取得
UINT GetVLanInterfaceID(char *tag_name)
{
	UINT ret = 0;
#ifdef	OS_WIN32
	ret = Win32GetVLanInterfaceID(tag_name);
#else	// OS_WIN32
	ret = UnixGetVLanInterfaceID(tag_name);
#endif	// OS_WIN32
	return ret;
}

// 仮想 LAN カードの列挙変数の解放
void FreeEnumVLan(char **s)
{
	char *a;
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	i = 0;
	while (true)
	{
		a = s[i++];
		if (a == NULL)
		{
			break;
		}
		Free(a);
	}

	Free(s);
}

// 仮想 LAN カードの列挙
char **EnumVLan(char *tag_name)
{
	char **ret = NULL;
#ifdef	OS_WIN32
	ret = Win32EnumVLan(tag_name);
#else	// OS_WIN32
	ret = UnixEnumVLan(tag_name);
#endif	// OS_WIN32
	return ret;
}

// ルーティングテーブルを表示する
void DebugPrintRouteTable(ROUTE_TABLE *r)
{
	UINT i;
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	if (IsDebug() == false)
	{
		return;
	}

	Debug("---- Routing Table (%u Entries) ----\n", r->NumEntry);

	for (i = 0;i < r->NumEntry;i++)
	{
		Debug("   ");

		DebugPrintRoute(r->Entry[i]);
	}

	Debug("------------------------------------\n");
}

// ルーティングテーブルエントリを表示する
void DebugPrintRoute(ROUTE_ENTRY *e)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	if (IsDebug() == false)
	{
		return;
	}

	RouteToStr(tmp, sizeof(tmp), e);

	Debug("%s\n", tmp);
}

// ルーティングテーブルエントリを文字列にする
void RouteToStr(char *str, UINT str_size, ROUTE_ENTRY *e)
{
	char dest_ip[MAX_PATH];
	char dest_mask[MAX_PATH];
	char gateway_ip[MAX_PATH];
	// 引数チェック
	if (str == NULL || e == NULL)
	{
		return;
	}

	IPToStr(dest_ip, sizeof(dest_ip), &e->DestIP);
	IPToStr(dest_mask, sizeof(dest_mask), &e->DestMask);
	IPToStr(gateway_ip, sizeof(gateway_ip), &e->GatewayIP);

	Format(str, str_size, "%s/%s %s m=%u oif=%u if=%u lo=%u p=%u",
		dest_ip, dest_mask, gateway_ip,
		e->Metric, e->OldIfMetric, e->InterfaceID,
		e->LocalRouting, e->PPPConnection);
}

// ルーティングテーブルの削除
void DeleteRouteEntry(ROUTE_ENTRY *e)
{
	Debug("DeleteRouteEntry();\n");
#ifdef	OS_WIN32
	Win32DeleteRouteEntry(e);
#else	// OS_WIN32
	UnixDeleteRouteEntry(e);
#endif
}

// ルーティングテーブルの追加
bool AddRouteEntry(ROUTE_ENTRY *e)
{
	bool dummy = false;
	return AddRouteEntryEx(e, &dummy);
}
bool AddRouteEntryEx(ROUTE_ENTRY *e, bool *already_exists)
{
	bool ret = false;
	Debug("AddRouteEntryEx();\n");
#ifdef	OS_WIN32
	ret = Win32AddRouteEntry(e, already_exists);
#else	// OS_WIN32
	ret = UnixAddRouteEntry(e, already_exists);
#endif
	return ret;
}

// ルーティングテーブルの取得
ROUTE_TABLE *GetRouteTable()
{
	ROUTE_TABLE *t = NULL;
	UINT i;
	BUF *buf = NewBuf();
	UCHAR hash[MD5_SIZE];

#ifdef	OS_WIN32
	t = Win32GetRouteTable();
#else	//OS_WIN32
	t = UnixGetRouteTable();
#endif	// OS_WIN32

	WriteBuf(buf, &t->NumEntry, sizeof(t->NumEntry));

	for (i = 0;i < t->NumEntry;i++)
	{
		ROUTE_ENTRY *e = t->Entry[i];

		WriteBuf(buf, e, sizeof(ROUTE_ENTRY));
	}

	Hash(hash, buf->Buf, buf->Size, false);

	FreeBuf(buf);

	Copy(&t->HashedValue, hash, sizeof(t->HashedValue));

	return t;
}

// ルーティングテーブルの解放
void FreeRouteTable(ROUTE_TABLE *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumEntry;i++)
	{
		Free(t->Entry[i]);
	}
	Free(t->Entry);
	Free(t);
}

// UDP 受信
UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	SOCKET s;
	int ret, sz;
	struct sockaddr_in addr;
	// 引数チェック
	if (sock == NULL || src_addr == NULL || src_port == NULL || data == NULL)
	{
		return false;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return false;
	}
	if (size == 0)
	{
		return false;
	}

	if (sock->IPv6)
	{
		return RecvFrom6(sock, src_addr, src_port, data, size);
	}

	s = sock->socket;

	sz = sizeof(addr);
	ret = recvfrom(s, data, size, 0, (struct sockaddr *)&addr, (int *)&sz);
	if (ret > 0)
	{
		InAddrToIP(src_addr, &addr.sin_addr);
		*src_port = (UINT)ntohs(addr.sin_port);

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		// Debug("UDP RecvFrom: %u\n", ret);

		return (UINT)ret;
	}
	else
	{
		sock->IgnoreRecvErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
//			Debug("RecvFrom Error: %u\n", e);
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}
}
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	SOCKET s;
	int ret, sz;
	struct sockaddr_in6 addr;
	// 引数チェック
	if (sock == NULL || src_addr == NULL || src_port == NULL || data == NULL)
	{
		return false;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return false;
	}
	if (size == 0)
	{
		return false;
	}

	s = sock->socket;

	sz = sizeof(addr);
	ret = recvfrom(s, data, size, 0, (struct sockaddr *)&addr, (int *)&sz);
	if (ret > 0)
	{
		InAddrToIP6(src_addr, &addr.sin6_addr);
		src_addr->ipv6_scope_id = addr.sin6_scope_id;
		*src_port = (UINT)ntohs(addr.sin6_port);

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		// Debug("UDP RecvFrom: %u\n", ret);

		return (UINT)ret;
	}
	else
	{
		sock->IgnoreRecvErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
			//			Debug("RecvFrom Error: %u\n", e);
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}
}

// OpenSSL のロック
void LockOpenSSL()
{
	Lock(openssl_lock);
}

// OpenSSL のロック解除
void UnlockOpenSSL()
{
	Unlock(openssl_lock);
}


// UDP 送信
UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size)
{
	SOCKET s;
	int ret;
	struct sockaddr_in addr;
	// 引数チェック
	if (sock == NULL || dest_addr == NULL || dest_port == 0 || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536)
	{
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (size == 0)
	{
		return 0;
	}

	if (sock->IPv6)
	{
		return SendTo6(sock, dest_addr, dest_port, data, size);
	}

	if (IsIP4(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((USHORT)dest_port);
	IPToInAddr(&addr.sin_addr, dest_addr);

	if (dest_addr->addr[0] == 255 && dest_addr->addr[1] == 255 && 
		dest_addr->addr[2] == 255 && dest_addr->addr[3] == 255)
	{
		if (sock->UdpBroadcast == false)
		{
			bool yes = true;

			sock->UdpBroadcast = true;

			setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}
UINT SendTo6(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size)
{
	SOCKET s;
	int ret;
	struct sockaddr_in6 addr;
	UINT type;
	// 引数チェック
	if (sock == NULL || dest_addr == NULL || dest_port == 0 || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536)
	{
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (size == 0)
	{
		return 0;
	}

	if (IsIP6(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons((USHORT)dest_port);
	IPToInAddr6(&addr.sin6_addr, dest_addr);
	addr.sin6_scope_id = dest_addr->ipv6_scope_id;

	type = GetIPAddrType6(dest_addr);

	if (type & IPV6_ADDR_MULTICAST)
	{
		if (sock->UdpBroadcast == false)
		{
			bool yes = true;

			sock->UdpBroadcast = true;

			setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}

// UDP ソケットの作成と初期化
// port が 0 の場合は OS がランダムに割り当てる
SOCK *NewUDP(UINT port)
{
	return NewUDPEx(port, false);
}
SOCK *NewUDPEx(UINT port, bool ipv6)
{
	if (ipv6 == false)
	{
		return NewUDP4(port);
	}
	else
	{
		return NewUDP6(port);
	}
}
SOCK *NewUDP4(UINT port)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in addr;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (port == 0)
	{
		addr.sin_port = 0;
	}
	else
	{
		addr.sin_port = htons((USHORT)port);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		// 失敗
		closesocket(s);
		return NULL;
	}

	sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	QuerySocketInformation(sock);

	return sock;
}
SOCK *NewUDP6(UINT port)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in6 addr;

	s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (port == 0)
	{
		addr.sin6_port = 0;
	}
	else
	{
		addr.sin6_port = htons((USHORT)port);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		// 失敗
		closesocket(s);
		return NULL;
	}

	sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	sock->IPv6 = true;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	QuerySocketInformation(sock);

	return sock;
}

// Select 関数
void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
#ifdef	OS_WIN32
	Win32Select(set, timeout, c1, c2);
#else
	UnixSelect(set, timeout, c1, c2);
#endif	// OS_WIN32
}

// ソケットセットにソケットを追加
void AddSockSet(SOCKSET *set, SOCK *sock)
{
	// 引数チェック
	if (set == NULL || sock == NULL)
	{
		return;
	}
	if (sock->Type == SOCK_TCP && sock->Connected == false)
	{
		return;
	}

	if (set->NumSocket >= MAX_SOCKSET_NUM)
	{
		// 上限
		return;
	}
	set->Sock[set->NumSocket++] = sock;
}

// ソケットセットの初期化
void InitSockSet(SOCKSET *set)
{
	// 引数チェック
	if (set == NULL)
	{
		return;
	}

	Zero(set, sizeof(SOCKSET));
}

// TCP すべて受信
bool RecvAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UINT recv_size, sz, ret;
	// 引数チェック
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}
	if (sock->AsyncMode)
	{
		return false;
	}

	recv_size = 0;

	while (true)
	{
		sz = size - recv_size;
		ret = Recv(sock, (UCHAR *)data + recv_size, sz, secure);
		if (ret == 0)
		{
			return false;
		}
		recv_size += ret;
		if (recv_size >= size)
		{
			return true;
		}
	}
}

// TCP 送信バッファを送信する
bool SendNow(SOCK *sock, int secure)
{
	bool ret;
	// 引数チェック
	if (sock == NULL || sock->AsyncMode != false)
	{
		return false;
	}
	if (sock->SendBuf->Size == 0)
	{
		return true;
	}

	ret = SendAll(sock, sock->SendBuf->Buf, sock->SendBuf->Size, secure);
	ClearBuf(sock->SendBuf);

	return ret;
}

// TCP 送信バッファ追加
void SendAdd(SOCK *sock, void *data, UINT size)
{
	// 引数チェック
	if (sock == NULL || data == NULL || size == 0 || sock->AsyncMode != false)
	{
		return;
	}

	WriteBuf(sock->SendBuf, data, size);
}

// TCP すべて送信
bool SendAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UCHAR *buf;
	UINT sent_size;
	UINT ret;
	// 引数チェック
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (sock->AsyncMode)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}

	buf = (UCHAR *)data;
	sent_size = 0;

	while (true)
	{
		ret = Send(sock, buf, size - sent_size, secure);
		if (ret == 0)
		{
			return false;
		}
		sent_size += ret;
		buf += ret;
		if (sent_size >= size)
		{
			return true;
		}
	}
}

// 使用したい暗号化アルゴリズム名を設定する
void SetWantToUseCipher(SOCK *sock, char *name)
{
	// 引数チェック
	if (sock == NULL || name == NULL)
	{
		return;
	}

	if (sock->WaitToUseCipher)
	{
		Free(sock->WaitToUseCipher);
	}
	sock->WaitToUseCipher = CopyStr(name);
}

// TCP-SSL 通信を開始する
bool StartSSL(SOCK *sock, X *x, K *priv)
{
	return StartSSLEx(sock, x, priv, false);
}
bool StartSSLEx(SOCK *sock, X *x, K *priv, bool client_tls)
{
	X509 *x509;
	EVP_PKEY *key;
	UINT prev_timeout = 1024;

#ifdef UNIX_SOLARIS
	SOCKET_TIMEOUT_PARAM *ttparam;
#endif //UNIX_SOLARIS

	// 引数チェック
	if (sock == NULL)
	{
		Debug("StartSSL Error: #0\n");
		return false;
	}
	if (sock->Connected == false || sock->socket == INVALID_SOCKET ||
		sock->ListenMode != false)
	{
		Debug("StartSSL Error: #1\n");
		return false;
	}
	if (x != NULL && priv == NULL)
	{
		Debug("StartSSL Error: #2\n");
		return false;
	}

	if (sock->SecureMode)
	{
		Debug("StartSSL Error: #3\n");
		// すでに SSL 通信が開始されている
		return true;
	}

	Lock(sock->ssl_lock);
	if (sock->SecureMode)
	{
		Debug("StartSSL Error: #4\n");
		// すでに SSL 通信が開始されている
		Unlock(sock->ssl_lock);
		return true;
	}

	Lock(openssl_lock);
	{
		if (sock->ServerMode)
		{
			SSL_CTX_set_ssl_version(ssl_ctx, SSLv23_method());
		}
		else
		{
			if (client_tls == false)
			{
				SSL_CTX_set_ssl_version(ssl_ctx, SSLv3_method());
			}
			else
			{
				SSL_CTX_set_ssl_version(ssl_ctx, TLSv1_client_method());
			}
		}
		sock->ssl = SSL_new(ssl_ctx);
		SSL_set_fd(sock->ssl, (int)sock->socket);
	}
	Unlock(openssl_lock);

	if (x != NULL)
	{
		// 証明書と秘密鍵のチェック
		if (CheckXandK(x, priv))
		{
			// 証明書を使用する
			x509 = x->x509;
			key = priv->pkey;

			Lock(openssl_lock);
			{
				SSL_use_certificate(sock->ssl, x509);
				SSL_use_PrivateKey(sock->ssl, key);
			}
			Unlock(openssl_lock);
		}
	}

	if (sock->WaitToUseCipher != NULL)
	{
		// 使用したい暗号化アルゴリズム名を設定する
		Lock(openssl_lock);
		{
			SSL_set_cipher_list(sock->ssl, sock->WaitToUseCipher);
		}
		Unlock(openssl_lock);
	}

	if (sock->ServerMode)
	{
//		Lock(ssl_connect_lock);

// SOLARIS用タイムアウトスレッドの起動
#ifdef UNIX_SOLARIS
		ttparam = NewSocketTimeout(sock);
#endif // UNIX_SOLARIS

		// サーバーモード
		if (SSL_accept(sock->ssl) <= 0)
		{

// タイムアウトスレッドの停止
#ifdef UNIX_SOLARIS
			FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS

			//			Unlock(ssl_connect_lock);
			// SSL-Accept 失敗
			Lock(openssl_lock);
			{
				SSL_free(sock->ssl);
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			Debug("StartSSL Error: #5\n");
			return false;
		}

// タイムアウトスレッドの停止
#ifdef UNIX_SOLARIS
		FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS

		//		Unlock(ssl_connect_lock);
	}
	else
	{
		prev_timeout = GetTimeout(sock);
		SetTimeout(sock, TIMEOUT_SSL_CONNECT);
		Lock(ssl_connect_lock);
		// クライアントモード
		if (SSL_connect(sock->ssl) <= 0)
		{
			Unlock(ssl_connect_lock);
			// SSL-connect 失敗
			Lock(openssl_lock);
			{
				SSL_free(sock->ssl);
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			Debug("StartSSL Error: #5\n");
			SetTimeout(sock, prev_timeout);
			return false;
		}
		Unlock(ssl_connect_lock);
		SetTimeout(sock, prev_timeout);
	}

	// SSL 通信が開始された
	sock->SecureMode = true;

	// リモートホストの証明書を取得する
	Lock(openssl_lock);
	{
		x509 = SSL_get_peer_certificate(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		// リモートホストに証明書は存在しない
		sock->RemoteX = NULL;
	}
	else
	{
		// 証明書を取得できた
		sock->RemoteX = X509ToX(x509);
	}

	// ローカルホストの証明書を取得する
	Lock(openssl_lock);
	{
		x509 = SSL_get_certificate(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		// リモートホストに証明書は存在しない
		sock->LocalX = NULL;
	}
	else
	{
		X *local_x;
		// 証明書を取得できた
		local_x = X509ToX(x509);
		local_x->do_not_free = true;
		sock->LocalX = CloneX(local_x);
		FreeX(local_x);
	}

	// 自動再試行モード
	SSL_set_mode(sock->ssl, SSL_MODE_AUTO_RETRY);

	// へんなフラグ
	SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	// 暗号化に使用しているアルゴリズム名を取得
	Lock(openssl_lock);
	{
		sock->CipherName = CopyStr((char *)SSL_get_cipher(sock->ssl));
	}
	Unlock(openssl_lock);

	Unlock(sock->ssl_lock);

	return true;
}

// TCP-SSL 受信
UINT SecureRecv(SOCK *sock, void *data, UINT size)
{
	SOCKET s;
	int ret, e = 0;
	SSL *ssl;

#ifdef UNIX_SOLARIS
	SOCKET_TIMEOUT_PARAM *ttparam;
#endif //UNIX_SOLARIS

	s = sock->socket;
	ssl = sock->ssl;

	if (sock->AsyncMode)
	{
		// 非同期モードの場合はデータが 1 バイトでも読み出し可能かどうか確認する。
		// 読み出し可能なデータが無い場合に read をしてしまうとブロッキングするため
		// それは避けなければならない。
		char c;
		Lock(sock->ssl_lock);
		{
			if (sock->Connected == false)
			{
				Unlock(sock->ssl_lock);
				Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
				return 0;
			}
			ret = SSL_peek(ssl, &c, sizeof(c));
		}
		Unlock(sock->ssl_lock);
		if (ret == 0)
		{
			// 通信が切れておる
			Disconnect(sock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}
		if (ret < 0)
		{
			// エラーが発生した
			e = SSL_get_error(ssl, ret);
			if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
			{
				// パケットがまだ届いていない、つまり read してはいけない
				return SOCK_LATER;
			}
		}
	}

	// 受信する
	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false)
		{
			Unlock(sock->ssl_lock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}

#ifdef	OS_UNIX
		if (sock->AsyncMode == false)
		{
			sock->CallingThread = pthread_self();
		}
#endif	// OS_UNIX

// SOLARIS用タイムアウトスレッドの起動
#ifdef UNIX_SOLARIS
		ttparam = NewSocketTimeout(sock);
#endif // UNIX_SOLARIS

		ret = SSL_read(ssl, data, size);

// タイムアウトスレッドの停止
#ifdef UNIX_SOLARIS
		FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS


#ifdef	OS_UNIX
		if (sock->AsyncMode == false)
		{
			sock->CallingThread = 0;
		}
#endif	// OS_UNIX

		if (ret < 0)
		{
			e = SSL_get_error(ssl, ret);
		}

	}
	Unlock(sock->ssl_lock);
	if (ret > 0)
	{
		// 受信成功
		sock->RecvSize += (UINT64)ret;
		sock->RecvNum++;
		return (UINT)ret;
	}
	if (ret == 0)
	{
		// 通信切断
		Disconnect(sock);
		Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
		return 0;
	}
	if (sock->AsyncMode)
	{
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
		{
			// パケットがまだ届いていない
			return SOCK_LATER;
		}
	}
	Disconnect(sock);
	Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
	return 0;
}

// TCP-SSL 送信
UINT SecureSend(SOCK *sock, void *data, UINT size)
{
	SOCKET s;
	int ret, e;
	SSL *ssl;
	s = sock->socket;
	ssl = sock->ssl;

	if (sock->AsyncMode)
	{
		// 非同期モード
		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	}

	// 送信
	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false)
		{
			Unlock(sock->ssl_lock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}

		ret = SSL_write(ssl, data, size);
		if (ret < 0)
		{
			e = SSL_get_error(ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

	if (ret > 0)
	{
		// 送信成功
		sock->SendSize += (UINT64)ret;
		sock->SendNum++;
		sock->WriteBlocked = false;
		return (UINT)ret;
	}
	if (ret == 0)
	{
		// 切断
		Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
		Disconnect(sock);
		return 0;
	}

	if (sock->AsyncMode)
	{
		// エラー値の確認
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
		{
			sock->WriteBlocked = true;
			return SOCK_LATER;
		}
		Debug("%s %u e=%u\n", __FILE__, __LINE__, e);
	}
	//Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
	Disconnect(sock);
	return 0;
}

// TCP 受信
UINT Recv(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;

#ifdef UNIX_SOLARIS
	SOCKET_TIMEOUT_PARAM *ttparam;
#endif //UNIX_SOLARIS

	// 引数チェック
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
		sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureRecv(sock, data, size);
	}

	// 受信
	s = sock->socket;


#ifdef	OS_UNIX
	if (sock->AsyncMode == false)
	{
		sock->CallingThread = pthread_self();
	}
#endif	// OS_UNIX

// SOLARIS用タイムアウトスレッドの開始
#ifdef UNIX_SOLARIS
	ttparam = NewSocketTimeout(sock);
#endif // UNIX_SOLARIS

	ret = recv(s, data, size, 0);

// タイムアウトスレッドの停止
#ifdef UNIX_SOLARIS
	FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS

#ifdef	OS_UNIX
	if (sock->AsyncMode == false)
	{
		sock->CallingThread = 0;
	}
#endif	// OS_UNIX

	if (ret > 0)
	{
		// 受信成功
		Lock(sock->lock);
		{
			sock->RecvSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		return (UINT)ret;
	}

	// 送信失敗
	if (sock->AsyncMode)
	{
		// 非同期モードの場合、エラーを調べる
		if (ret == SOCKET_ERROR)
		{
#ifdef	OS_WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				// ブロッキングしている
				return SOCK_LATER;
			}
			else
			{
				Debug("Socket Error: %u\n", WSAGetLastError());
			}
#else	// OS_WIN32
			if (errno == EAGAIN)
			{
				// ブロッキングしている
				return SOCK_LATER;
			}
#endif	// OS_WIN32
		}
	}

	// 切断された
	Disconnect(sock);
	return 0;
}

// TCP 送信
UINT Send(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;
	// 引数チェック
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
		sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureSend(sock, data, size);
	}

	// 送信
	s = sock->socket;
	ret = send(s, data, size, 0);
	if (ret > 0)
	{
		// 送信成功
		Lock(sock->lock);
		{
			sock->SendSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		sock->WriteBlocked = false;
		return (UINT)ret;
	}

	// 送信失敗
	if (sock->AsyncMode)
	{
		// 非同期モードの場合、エラーを調べる
		if (ret == SOCKET_ERROR)
		{
#ifdef	OS_WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				// ブロッキングしている
				sock->WriteBlocked = true;
				return SOCK_LATER;
			}
			else
			{
				Debug("Socket Error: %u\n", WSAGetLastError());
			}
#else	// OS_WIN32
			if (errno == EAGAIN)
			{
				// ブロッキングしている
				sock->WriteBlocked = true;
				return SOCK_LATER;
			}
#endif	// OS_WIN32
		}
	}

	// 切断された
	Disconnect(sock);
	return 0;
}

// タイムアウトの取得 (ミリ秒)
UINT GetTimeout(SOCK *sock)
{
	// 引数チェック
	if (sock == NULL)
	{
		return INFINITE;
	}
	if (sock->Type != SOCK_TCP)
	{
		return INFINITE;
	}

	return sock->TimeOut;
}

// タイムアウト時間の設定 (ミリ秒)
void SetTimeout(SOCK *sock, UINT timeout)
{
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}
	if (sock->Type != SOCK_TCP)
	{
		return;
	}

	if (timeout == INFINITE)
	{
		timeout = TIMEOUT_INFINITE;
	}

	sock->TimeOut = timeout;

//	Debug("SetTimeout(%u)\n",timeout);

#ifdef OS_WIN32
	setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(UINT));
	setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(UINT));
#endif

#ifdef OS_UNIX
#ifndef UNIX_SOLARIS
	{
		struct timeval tv_timeout;

		tv_timeout.tv_sec = timeout / 1000; // miliseconds to seconds
		tv_timeout.tv_usec = (timeout % 1000) * 1000; // miliseconds to microseconds

		setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv_timeout, sizeof(tv_timeout));
		setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv_timeout, sizeof(tv_timeout));
	}
#endif // UNIX_SOLARIS
#endif // OS_UNIX
}

// 接続受諾初期化
void AcceptInit(SOCK *s)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));
	if (GetHostName(tmp, sizeof(tmp), &s->RemoteIP) == false ||
		IsEmptyStr(tmp))
	{
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	}

	s->RemoteHostname = CopyStr(tmp);
}

// TCP 接続受諾
SOCK *Accept(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in addr;
	bool true_flag = true;
	// 引数チェック
	if (sock == NULL)
	{
		return NULL;
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}
	if (sock->IPv6)
	{
		return Accept6(sock);
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

#ifdef	OS_UNIX
	sock->CallingThread = pthread_self();
#endif	// OS_UNIX

	new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);

#ifdef	OS_UNIX
	sock->CallingThread = 0;
#endif	// OS_UNIX

	if (new_socket == INVALID_SOCKET)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	// TCP オプションの設定
	setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(bool));

	SetSockPriorityHigh(ret);

	// タイムアウト値の初期化
	SetTimeout(ret, TIMEOUT_INFINITE);

	// ソケット情報
	QuerySocketInformation(ret);

	AddIpClient(&ret->RemoteIP);

	return ret;
}
SOCK *Accept6(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in6 addr;
	bool true_flag = true;
	// 引数チェック
	if (sock == NULL)
	{
		return NULL;
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}
	if (sock->IPv6 == false)
	{
		return NULL;
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

#ifdef	OS_UNIX
	sock->CallingThread = pthread_self();
#endif	// OS_UNIX

	new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);

#ifdef	OS_UNIX
	sock->CallingThread = 0;
#endif	// OS_UNIX

	if (new_socket == INVALID_SOCKET)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	// TCP オプションの設定
	setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(bool));

	SetSockPriorityHigh(ret);

	// タイムアウト値の初期化
	SetTimeout(ret, TIMEOUT_INFINITE);

	// ソケット情報
	QuerySocketInformation(ret);

	AddIpClient(&ret->RemoteIP);

	return ret;
}

// TCP 待ち受け (IPv6)
SOCK *Listen6(UINT port)
{
	return ListenEx6(port, false);
}
SOCK *ListenEx6(UINT port, bool local_only)
{
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in6 addr;
	struct in6_addr in;
	bool true_flag = true;
	IP localhost;
	// 引数チェック
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

	// 初期化
	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	GetLocalHostIP6(&localhost);

	addr.sin6_port = htons((UINT)port);
	addr.sin6_family = AF_INET6;

	if (local_only)
	{
		IPToInAddr6(&addr.sin6_addr, &localhost);
	}

	// ソケットの作成
	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

#ifdef	OS_UNIX
	// UNIX 系では IPv6 Only フラグを立てる必要がある
	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &true_flag, sizeof(true_flag));
#endif	// OS_UNIX

	//SetSocketSendRecvBufferSize(s, SOCKET_BUFFER_SIZE);

#ifdef	OS_UNIX
	// Windows 系 OS は REUSEADDR の実装にバグがあるっぽいので
	// UNIX 系のみ有効にした。
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
#endif	// OS_UNIX

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) != 0)
	{
		// bind 失敗
		closesocket(s);
		return NULL;
	}
	if (listen(s, SOMAXCONN))
	{
		// listen 失敗
		closesocket(s);
		return NULL;
	}

	// 成功
	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->IPv6 = true;

	return sock;
}

// TCP 待ち受け
SOCK *Listen(UINT port)
{
	return ListenEx(port, false);
}
SOCK *ListenEx(UINT port, bool local_only)
{
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in addr;
	struct in_addr in;
	bool true_flag = true;
	IP localhost;
	// 引数チェック
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

	// 初期化
	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	SetIP(&localhost, 127, 0, 0, 1);

	addr.sin_port = htons((UINT)port);
	*((UINT *)&addr.sin_addr) = htonl(INADDR_ANY);
	addr.sin_family = AF_INET;

	if (local_only)
	{
		IPToInAddr(&addr.sin_addr, &localhost);
	}

	// ソケットの作成
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	//SetSocketSendRecvBufferSize(s, SOCKET_BUFFER_SIZE);

#ifdef	OS_UNIX
	// Windows 系 OS は REUSEADDR の実装にバグがあるっぽいので
	// UNIX 系のみ有効にした。
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
#endif	// OS_UNIX

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0)
	{
		// bind 失敗
		closesocket(s);
		return NULL;
	}
	if (listen(s, SOMAXCONN))
	{
		// listen 失敗
		closesocket(s);
		return NULL;
	}

	// 成功
	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;

	return sock;
}

// TCP 切断
void Disconnect(SOCK *sock)
{
	SOCKET s;
	bool true_flag = true;
	bool false_flag = false;
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}

	sock->Disconnecting = true;

#ifdef	OS_UNIX
	UnixFreeAsyncSocket(sock);
#endif	// UnixFreeAsyncSocket

	if (sock->Type == SOCK_TCP && sock->ListenMode)
	{
		// Listen 中のソケットの場合は localhost に対して接続する
		sock->CancelAccept = true;

		if (sock->IPv6 == false)
		{
			CheckTCPPort("127.0.0.1", sock->LocalPort);
		}
		else
		{
			CheckTCPPort("::1", sock->LocalPort);
		}
	}

	Lock(disconnect_function_lock);

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP)
	{
		if (sock->socket != INVALID_SOCKET)
		{
			// 強制切断フラグ
			#ifdef	SO_DONTLINGER
				setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(bool));
			#else	// SO_DONTLINGER
				setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(bool));
			#endif	// SO_DONTLINGER
//			setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
		}

		// TCP ソケット
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
				return;
			}
			s = sock->socket;

			if (sock->Connected)
			{
				struct linger ling;
				Zero(&ling, sizeof(ling));


#if	0
				// SSL 切断
				Lock(sock->ssl_lock);
				{
					if (sock->SecureMode)
					{
						SSL_shutdown(sock->ssl);
					}
				}
				Unlock(sock->ssl_lock);
#endif
				// 切断
				shutdown(s, 2);
			}

			// ソケットを閉じる
			closesocket(s);

#ifdef	OS_UNIX
#ifdef	FIX_SSL_BLOCKING
			if (sock->CallingThread != NULL)
			{
				pthread_kill(sock->CallingThread, 64);
			}
#endif	// FIX_SSL_BLOCKING
#endif	// OS_UNIX

			// SSL を解放
			Lock(sock->ssl_lock);
			{
				if (sock->SecureMode)
				{
					if (sock->ssl != NULL)
					{
						Lock(openssl_lock);
						{
							SSL_free(sock->ssl);
						}
						Unlock(openssl_lock);
						sock->ssl = NULL;
					}
					sock->Connected = false;
					// 証明書を解放
					if (sock->RemoteX != NULL)
					{
						FreeX(sock->RemoteX);
						sock->RemoteX = NULL;
					}
					if (sock->LocalX != NULL)
					{
						FreeX(sock->LocalX);
						sock->LocalX = NULL;
					}

					// 暗号化アルゴリズム名
					if (sock->CipherName != NULL)
					{
						Free(sock->CipherName);
						sock->CipherName = NULL;
					}
					sock->SecureMode = false;
				}
			}
			Unlock(sock->ssl_lock);

			// 初期化
			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;

			if (sock->ServerMode && sock->ListenMode == false)
			{
				DelIpClient(&sock->RemoteIP);
			}
		}
		Unlock(sock->lock);
	}
	else if (sock->Type == SOCK_UDP)
	{
		// UDP ソケット
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
				return;
			}

			s = sock->socket;

			// ソケットを閉じる
			closesocket(s);

			// 初期化
			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;
		}
		Unlock(sock->lock);
	}
	Unlock(sock->disconnect_lock);

	Unlock(disconnect_function_lock);
}

typedef struct TCP_PORT_CHECK
{
	REF *ref;
	char hostname[MAX_SIZE];
	UINT port;
	bool ok;
} TCP_PORT_CHECK;

// TCP ポートチェック用スレッド
void CheckTCPPortThread(THREAD *thread, void *param)
{
	TCP_PORT_CHECK *c;
	SOCK *s;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	c = (TCP_PORT_CHECK *)param;
	AddRef(c->ref);
	NoticeThreadInit(thread);

	AddWaitThread(thread);

	s = Connect(c->hostname, c->port);
	if (s != NULL)
	{
		c->ok = true;
		Disconnect(s);
		ReleaseSock(s);
	}

	if (Release(c->ref) == 0)
	{
		Free(c);
	}

	DelWaitThread(thread);
}

// TCP ポートに接続可能かどうかチェックする
bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout)
{
	SOCK *s;
	// 引数チェック
	if (hostname == NULL || port == 0 || port >= 65536)
	{
		return false;
	}

	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	s = ConnectEx(hostname, port, timeout);
	if (s == NULL)
	{
		return false;
	}
	else
	{
		Disconnect(s);
		ReleaseSock(s);
		return true;
	}
}
bool CheckTCPPort(char *hostname, UINT port)
{
	return CheckTCPPortEx(hostname, port, TIMEOUT_TCP_PORT_CHECK);
}

#ifdef	OS_UNIX
// タイムアウト付き接続 (UNIX 版)
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag)
{
	SOCKSET set;
	bool ok = false;
	UINT64 start_time;
	// 引数チェック
	if (s == INVALID_SOCKET || addr == NULL)
	{
		return -1;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	UnixSetSocketNonBlockingMode(s, true);

	start_time = Tick64();

	while (true)
	{
		int ret;
		ret = connect(s, addr, size);
		if (ret == 0 || errno == EISCONN)
		{
			ok = true;
			break;
		}
		else
		{
			if (((start_time + (UINT64)timeout) <= Tick64()) || (errno != EAGAIN && errno != EINPROGRESS && errno != EALREADY))
			{
				// 失敗
				break;
			}
			else if (*cancel_flag)
			{
				// キャンセル
				break;
			}
			else
			{
				// 接続中
				SleepThread(50);
				UnixSelectInner(1, (UINT *)&s, 1, (UINT *)&s, 100);
			}
		}
	}

	UnixSetSocketNonBlockingMode(s, false);

	if (ok)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}
#else
// タイムアウト付き接続 (Win32 版)
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag)
{
	UINT64 start_time;
	bool ok = false;
	bool timeouted = false;
	WSAEVENT hEvent;
	UINT zero = 0;
	UINT tmp = 0;
	UINT ret_size = 0;
	bool is_nt = false;
	// 引数チェック
	if (s == INVALID_SOCKET || addr == NULL)
	{
		return -1;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	is_nt = OS_IS_WINDOWS_NT(GetOsInfo()->OsType);

	// イベントを作成
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// ソケットをイベントに関連付ける
	WSAEventSelect(s, hEvent, FD_CONNECT);

	start_time = Tick64();

	while (true)
	{
		int ret;
		
		ret = connect(s, addr, size);

		if (ret == 0)
		{
			ok = true;
			break;
		}
		else
		{
			int err = WSAGetLastError();
			//Debug("err=%u\n", err);
			//Debug("cancel_flag=%u\n", *cancel_flag);
			if (timeouted && ((err == WSAEALREADY) || (err == WSAEWOULDBLOCK && !is_nt)))
			{
				// タイムアウト
				ok = false;
				break;
			}
			if (*cancel_flag)
			{
				// キャンセル
				ok = false;
				break;
			}
			if (err == WSAEISCONN || (err == WSAEINVAL && is_nt))
			{
				ok = true;
				break;
			}
			if (((start_time + (UINT64)timeout) <= Tick64()) || (err != WSAEWOULDBLOCK && err != WSAEALREADY && (is_nt || err != WSAEINVAL)))
			{
				// 失敗 (タイムアウト)
				break;
			}
			else
			{
				SleepThread(10);
				// 接続中
				if (WaitForSingleObject(hEvent, 100) == WAIT_OBJECT_0)
				{
					timeouted = true;
				}
			}
		}
	}

	// ソケットをイベントから外す
	WSAEventSelect(s, hEvent, 0);

	// 同期ソケットに戻す
	WSAIoctl(s, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);

	// イベントを閉じる
	CloseHandle(hEvent);

	if (ok)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}
#endif	// OS_UNIX

// ソケットのパケットの優先順位を向上させる (未使用)
void SetSockPriorityHigh(SOCK *s)
{
	int value;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	value = 16;

#ifdef	IP_TOS
	//setsockopt(s->socket, IPPROTO_IP, IP_TOS, (char *)&value, sizeof(int));
#endif	// IP_TOS
}

// TCP 接続
SOCK *Connect(char *hostname, UINT port)
{
	return ConnectEx(hostname, port, 0);
}
SOCK *ConnectEx(char *hostname, UINT port, UINT timeout)
{
	return ConnectEx2(hostname, port, timeout, NULL);
}
SOCK *ConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag)
{
	SOCK *sock;
	SOCKET s;
	struct linger ling;
	struct sockaddr_in sockaddr4;
	struct in_addr addr4;
	IP ip4;
	struct sockaddr_in6 sockaddr6;
	struct in6_addr addr6;
	IP ip6;
	bool true_flag = true;
	bool false_flag = false;
	char tmp[MAX_SIZE];
	IP current_ip;
	bool is_ipv6 = false;
	bool dummy = false;
	// 引数チェック
	if (hostname == NULL || port == 0 || port >= 65536)
	{
		return NULL;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}
	if (cancel_flag == NULL)
	{
		cancel_flag = &dummy;
	}

	Zero(&current_ip, sizeof(current_ip));

	Zero(&sockaddr4, sizeof(sockaddr4));
	Zero(&addr4, sizeof(addr4));
	Zero(&ip4, sizeof(ip4));

	Zero(&sockaddr6, sizeof(sockaddr6));
	Zero(&addr6, sizeof(addr6));
	Zero(&ip6, sizeof(ip6));

	// 正引き
	if (GetIP46Ex(&ip4, &ip6, hostname, 0, cancel_flag) == false)
	{
		return NULL;
	}

	s = INVALID_SOCKET;

	// IPv4 で接続を試行する
	if (IsZeroIp(&ip4) == false)
	{
		// sockaddr_in の生成
		IPToInAddr(&addr4, &ip4);
		sockaddr4.sin_port = htons((USHORT)port);
		sockaddr4.sin_family = AF_INET;
		sockaddr4.sin_addr.s_addr = addr4.s_addr;

		// ソケット作成
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s != INVALID_SOCKET)
		{
			// 接続
			if (connect_timeout(s, (struct sockaddr *)&sockaddr4, sizeof(struct sockaddr_in), timeout, cancel_flag) != 0)
			{
				// 接続失敗
				closesocket(s);
				s = INVALID_SOCKET;
			}
			else
			{
				Copy(&current_ip, &ip4, sizeof(IP));
			}
		}
	}

	// IPv6 で接続を試行する
	if (s == INVALID_SOCKET && IsZeroIp(&ip6) == false)
	{
		// sockaddr_in6 の生成
		IPToInAddr6(&addr6, &ip6);
		sockaddr6.sin6_port = htons((USHORT)port);
		sockaddr6.sin6_family = AF_INET6;
		sockaddr6.sin6_scope_id = ip6.ipv6_scope_id;
		Copy(&sockaddr6.sin6_addr, &addr6, sizeof(addr6));

		// ソケット作成
		s = socket(AF_INET6, SOCK_STREAM, 0);
		if (s != INVALID_SOCKET)
		{
			// 接続
			if (connect_timeout(s, (struct sockaddr *)&sockaddr6, sizeof(struct sockaddr_in6), timeout, cancel_flag) != 0)
			{
				// 接続失敗
				closesocket(s);
				s = INVALID_SOCKET;
			}
			else
			{
				Copy(&current_ip, &ip6, sizeof(IP));

				is_ipv6 = true;
			}
		}
	}

	if (s == INVALID_SOCKET)
	{
		// IPv4, IPv6 の両方で接続失敗
		return NULL;
	}

	// SOCK の作成
	sock = NewSock();
	sock->socket = s;
	sock->Type = SOCK_TCP;
	sock->ServerMode = false;

	SetSockPriorityHigh(sock);

	// ホスト名解決
	if (GetHostName(tmp, sizeof(tmp), &current_ip) == false)
	{
		StrCpy(tmp, sizeof(tmp), hostname);
	}

	//Debug("PTR: %s\n", tmp);

	sock->RemoteHostname = CopyStr(tmp);

//	Debug("new socket: %u\n", s);

	Zero(&ling, sizeof(ling));
	// 強制切断フラグ
#ifdef	SO_DONTLINGER
	setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(bool));
#else	// SO_DONTLINGER
	setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(bool));
#endif	// SO_DONTLINGER
//	setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));

	// TCP オプションの設定
	setsockopt(sock->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(bool));

	// タイムアウト値の初期化
	SetTimeout(sock, TIMEOUT_INFINITE);

	// ソケット情報の取得
	QuerySocketInformation(sock);

	sock->Connected = true;
	sock->AsyncMode = false;
	sock->SecureMode = false;
	sock->IPv6 = is_ipv6;

	return sock;
}

// ソケットの送受信バッファサイズを最大にする
void SetSocketSendRecvBufferSize(int s, UINT size)
{
	int value = (int)size;
	// 引数チェック
	if (s == INVALID_SOCKET)
	{
		return;
	}

	setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&value, sizeof(int));
	setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&value, sizeof(int));
}

// ソケット情報の取得
void QuerySocketInformation(SOCK *sock)
{
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}

	Lock(sock->lock);
	{
		struct sockaddr_in6 sockaddr6;
		struct in6_addr *addr6;
		int size;

		if (sock->Type == SOCK_TCP)
		{
			// リモートホストの情報を取得
			size = sizeof(sockaddr6);
			if (getpeername(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0)
			{
				if (size >= sizeof(struct sockaddr_in6))
				{
					sock->RemotePort = (UINT)ntohs(sockaddr6.sin6_port);
					addr6 = &sockaddr6.sin6_addr;
					InAddrToIP6(&sock->RemoteIP, addr6);
					sock->RemoteIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
				}
				else
				{
					struct sockaddr_in *sockaddr;
					struct in_addr *addr;

					sockaddr = (struct sockaddr_in *)&sockaddr6;
					sock->RemotePort = (UINT)ntohs(sockaddr->sin_port);
					addr = &sockaddr->sin_addr;
					InAddrToIP(&sock->RemoteIP, addr);
				}
			}
		}

		// ローカルホストの情報を取得
		size = sizeof(sockaddr6);
		if (getsockname(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0)
		{
			if (size >= sizeof(struct sockaddr_in6))
			{
				sock->LocalPort = (UINT)ntohs(sockaddr6.sin6_port);
				addr6 = &sockaddr6.sin6_addr;
				InAddrToIP6(&sock->LocalIP, addr6);
				sock->LocalIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
			}
			else
			{
				struct sockaddr_in *sockaddr;
				struct in_addr *addr;

				sockaddr = (struct sockaddr_in *)&sockaddr6;
				sock->LocalPort = (UINT)ntohs(sockaddr->sin_port);
				addr = &sockaddr->sin_addr;
				InAddrToIP(&sock->LocalIP, addr);
			}
		}
	}
	Unlock(sock->lock);
}

// ソケットの解放
void ReleaseSock(SOCK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		if (s->ListenMode == false && s->ServerMode)
		{
			Print("");
		}
		CleanupSock(s);
	}
}

// ソケットのクリーンアップ
void CleanupSock(SOCK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

//	{Debug("CleanupSock: Disconnect() Called: %s %u\n", __FILE__, __LINE__);Disconnect(s);}
	Disconnect(s);

#ifdef	OS_WIN32
	Win32FreeAsyncSocket(s);
#else	// OS_WIN32
	UnixFreeAsyncSocket(s);
#endif	// OS_WIN32

	FreeBuf(s->SendBuf);
	if (s->socket != INVALID_SOCKET)
	{
#ifdef	OS_WIN32
		closesocket(s->socket);
#else	// OS_WIN32
		close(s->socket);
#endif	// OS_WIN32
	}
	Free(s->RemoteHostname);

	Free(s->WaitToUseCipher);
	DeleteLock(s->lock);
	DeleteLock(s->ssl_lock);
	DeleteLock(s->disconnect_lock);

	Dec(num_tcp_connections);

	Free(s);
}

// 新しいソケットの作成
SOCK *NewSock()
{
	SOCK *s = ZeroMallocFast(sizeof(SOCK));

	s->ref = NewRef();
	s->lock = NewLock();
	s->SendBuf = NewBuf();
	s->socket = INVALID_SOCKET;
	s->ssl_lock = NewLock();
	s->disconnect_lock = NewLock();

	Inc(num_tcp_connections);

	return s;
}

// IP を UINT に変換する
UINT IPToUINT(IP *ip)
{
	UCHAR *b;
	UINT i, value = 0;
	// 引数チェック
	if (ip == NULL)
	{
		return 0;
	}

	b = (UCHAR *)&value;
	for (i = 0;i < 4;i++)
	{
		b[i] = ip->addr[i];
	}

	return value;
}

// UNIT を IP に変換する
void UINTToIP(IP *ip, UINT value)
{
	UCHAR *b;
	UINT i;
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	b = (UCHAR *)&value;
	for (i = 0;i < 4;i++)
	{
		ip->addr[i] = b[i];
	}
}

// コンピュータのホスト名を取得
void GetMachineHostName(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	UINT i, len;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	GetMachineName(tmp, sizeof(tmp));

	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		if (tmp[i] == '.')
		{
			tmp[i] = 0;
		}
	}

	ConvertSafeFileName(name, size, tmp);
}

// このコンピュータの IP アドレスを取得
void GetMachineIp(IP *ip)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));
	SetIP(ip, 127, 0, 0, 1);

	GetMachineName(tmp, sizeof(tmp));
	GetIP(ip, tmp);
}

// コンピュータ名を hosts から取得
bool GetMachineNameFromHosts(char *name, UINT size)
{
	bool ret = false;
	char *s;
	BUF *b;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	b = ReadDump("/etc/hosts");
	if (b == NULL)
	{
		return false;
	}

	while (true)
	{
		s = CfgReadNextLine(b);
		if (s == NULL)
		{
			break;
		}
		else
		{
			TOKEN_LIST *t = ParseToken(s, " \t");

			if (t != NULL)
			{
				if (t->NumTokens >= 2)
				{
					if (StrCmpi(t->Token[0], "127.0.0.1") == 0)
					{
						UINT i;

						for (i = 1;i < t->NumTokens;i++)
						{
							if (StartWith(t->Token[i], "localhost") == false)
							{
								StrCpy(name, size, t->Token[i]);
								ret = true;
							}
						}
					}
				}
			}
			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ret;
}

// このコンピュータのコンピュータ名を取得
void GetMachineName(char *name, UINT size)
{
	GetMachineNameEx(name, size, false);
}
void GetMachineNameEx(char *name, UINT size, bool no_load_hosts)
{
	static char name_cache[MAX_SIZE];
	static bool name_cached = false;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	IP ip;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	Lock(machine_name_lock);
	{
		if (name_cached != false)
		{
			StrCpy(name, size, name_cache);
			Unlock(machine_name_lock);
			return;
		}
		if (gethostname(tmp, MAX_SIZE) != 0)
		{
			StrCpy(name, size, "Unknown");
			Unlock(machine_name_lock);
			return;
		}
		if (GetIP(&ip, tmp) == false)
		{
			StrCpy(name, size, tmp);
			Unlock(machine_name_lock);
			return;
		}
		if (GetHostNameInner(name, size, &ip) == false || StartWith(name, "localhost"))
		{
			StrCpy(name, size, tmp);
		}
		if (StartWith(name, "localhost"))
		{
			if (no_load_hosts == false && OS_IS_UNIX(GetOsInfo()->OsType))
			{
				if (GetMachineNameFromHosts(tmp2, sizeof(tmp2)))
				{
					StrCpy(name, sizeof(name), tmp2);
				}
			}
		}

		StrCpy(name_cache, sizeof(name_cache), name);
		name_cached = true;
	}
	Unlock(machine_name_lock);
}

// ホスト名取得スレッド
void GetHostNameThread(THREAD *t, void *p)
{
	IP *ip;
	char hostname[256];
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	ip = (IP *)p;

	AddWaitThread(t);

	NoticeThreadInit(t);

	if (GetHostNameInner(hostname, sizeof(hostname), ip))
	{
		AddHostCache(ip, hostname);
	}

	Free(ip);

	DelWaitThread(t);
}

// ホスト名の取得
bool GetHostName(char *hostname, UINT size, IP *ip)
{
	THREAD *t;
	IP *p_ip;
	bool ret;
	// 引数チェック
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	if (GetHostCache(hostname, size, ip))
	{
		if (IsEmptyStr(hostname) == false)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	p_ip = ZeroMalloc(sizeof(IP));
	Copy(p_ip, ip, sizeof(IP));

	t = NewThread(GetHostNameThread, p_ip);

	WaitThreadInit(t);

	WaitThread(t, TIMEOUT_HOSTNAME);

	ReleaseThread(t);

	ret = GetHostCache(hostname, size, ip);
	if (ret == false)
	{
		if (IsIP4(ip))
		{
			ret = GetNetBiosName(hostname, size, ip);
			if (ret)
			{
				AddHostCache(ip, hostname);
			}
		}
	}
	else
	{
		if (IsEmptyStr(hostname))
		{
			ret = false;
		}
	}
	if (ret == false)
	{
		AddHostCache(ip, "");
		StrCpy(hostname, size, "");
	}

	return ret;
}

// DNS 逆引きクエリを行う
bool GetHostNameInner(char *hostname, UINT size, IP *ip)
{
	struct in_addr addr;
	struct sockaddr_in sa;
	char tmp[MAX_SIZE];
	char ip_str[64];
	// 引数チェック
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	if (IsIP6(ip))
	{
		return GetHostNameInner6(hostname, size, ip);
	}

	// 逆引き
	IPToInAddr(&addr, ip);
	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;

#if	defined(UNIX_BSD) || defined(UNIX_MACOS)
	sa.sin_len = INET_ADDRSTRLEN;
#endif	// UNIX_BSD || UNIX_MACOS

	Copy(&sa.sin_addr, &addr, sizeof(struct in_addr));
	sa.sin_port = 0;

	if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), tmp, sizeof(tmp), NULL, 0, 0) != 0)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), ip);

	if (StrCmpi(tmp, ip_str) == 0)
	{
		return false;
	}

	if (IsEmptyStr(tmp))
	{
		return false;
	}

	StrCpy(hostname, size, tmp);

	return true;
}
bool GetHostNameInner6(char *hostname, UINT size, IP *ip)
{
	struct in6_addr addr;
	struct sockaddr_in6 sa;
	char tmp[MAX_SIZE];
	char ip_str[256];
	// 引数チェック
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	// 逆引き
	IPToInAddr6(&addr, ip);
	Zero(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;

#if	defined(UNIX_BSD) || defined(UNIX_MACOS)
	sa.sin6_len = INET6_ADDRSTRLEN;
#endif	// UNIX_BSD || UNIX_MACOS

	Copy(&sa.sin6_addr, &addr, sizeof(struct in6_addr));
	sa.sin6_port = 0;

	if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), tmp, sizeof(tmp), NULL, 0, 0) != 0)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), ip);

	if (StrCmpi(tmp, ip_str) == 0)
	{
		return false;
	}

	if (IsEmptyStr(tmp))
	{
		return false;
	}

	StrCpy(hostname, size, tmp);

	return true;
}

#define	NUM_NBT_QUERYS_SEND			3

// IP アドレスからそのマシンの NetBIOS 名を取得する
bool GetNetBiosName(char *name, UINT size, IP *ip)
{
	SOCK *s;
	UINT i, j;
	bool flag = false;
	bool ok = false;
	NBTREQUEST req;
	UCHAR buf[1024];
	USHORT tran_id[NUM_NBT_QUERYS_SEND];
	UINT64 timeout_tick;
	// 引数チェック
	if (name == NULL || ip == NULL)
	{
		return false;
	}

	IPToStr(name, size, ip);

	for (i = 0;i < NUM_NBT_QUERYS_SEND;i++)
	{
		tran_id[i] = Rand16();
	}

	s = NewUDP(0);
	if (s == NULL)
	{
		return false;
	}

	for (j = 0;j < NUM_NBT_QUERYS_SEND;j++)
	{
		Zero(&req, sizeof(req));
		req.TransactionId = Endian16(tran_id[j]);
		req.NumQuestions = Endian16(1);
		req.Query[0] = 0x20;
		req.Query[1] = 0x43;
		req.Query[2] = 0x4b;
		for (i = 3;i <= 32;i++)
		{
			req.Query[i] = 0x41;
		}
		req.Query[35] = 0x21;
		req.Query[37] = 0x01;

		if (SendTo(s, ip, 137, &req, sizeof(req)) == 0)
		{
			ReleaseSock(s);
			return false;
		}
	}

	timeout_tick = Tick() + (UINT64)TIMEOUT_NETBIOS_HOSTNAME;

	while (1)
	{
		UINT ret;
		IP src_ip;
		UINT src_port;
		SOCKSET set;
		if (Tick() >= timeout_tick)
		{
			break;
		}
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, 100, NULL, NULL);

		if (flag == false)
		{
			flag = true;
		}
		else
		{
			SleepThread(10);
		}

		ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));

		if (ret == SOCK_LATER)
		{
			continue;
		}
		else if (ret == 0)
		{
			break;
		}
		else
		{
			if (ret >= sizeof(NBTRESPONSE))
			{
				NBTRESPONSE *r = (NBTRESPONSE *)buf;
				bool b = false;
				UINT i;
				USHORT id = Endian16(r->TransactionId);
				for (i = 0;i < NUM_NBT_QUERYS_SEND;i++)
				{
					if (id == tran_id[i])
					{
						b = true;
						break;
					}
				}
				if (b)
				{
					if (r->Flags != 0 && r->NumQuestions == 0 && r->AnswerRRs >= 1)
					{
						if (r->Response[0] == 0x20 && r->Response[1] == 0x43 &&
							r->Response[2] == 0x4b)
						{
							if (r->Response[34] == 0x00 && r->Response[35] == 0x21 &&
								r->Response[36] == 0x00 && r->Response[37] == 0x01)
							{
								char *a = (char *)(&r->Response[45]);
								if (StrCheckLen(a, 15))
								{
									if (IsEmptyStr(a) == false)
									{
										StrCpy(name, size, a);
										Trim(name);
										ok = true;
									}
									else
									{
										ok = false;
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ReleaseSock(s);
	return ok;
}

// IP アドレスを設定する
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4)
{
	// 引数チェック
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));
	ip->addr[0] = a1;
	ip->addr[1] = a2;
	ip->addr[2] = a3;
	ip->addr[3] = a4;
}

// DNS 正引きを行って結果を v4 と v6 のどちらかで得る (両方の場合は IPv4 優先)
bool GetIP46Any4(IP *ip, char *hostname)
{
	IP ip4, ip6;
	bool b = false;
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (GetIP46(&ip4, &ip6, hostname) == false)
	{
		return false;
	}

	if (IsZeroIp(&ip6) == false)
	{
		Copy(ip, &ip6, sizeof(IP));

		b = true;
	}

	if (IsZeroIp(&ip4) == false)
	{
		Copy(ip, &ip4, sizeof(IP));

		b = true;
	}

	return b;
}

// DNS 正引きを行って結果を v4 と v6 のどちらかで得る (両方の場合は IPv6 優先)
bool GetIP46Any6(IP *ip, char *hostname)
{
	IP ip4, ip6;
	bool b = false;
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (GetIP46(&ip4, &ip6, hostname) == false)
	{
		return false;
	}

	if (IsZeroIp(&ip4) == false)
	{
		Copy(ip, &ip4, sizeof(IP));

		b = true;
	}

	if (IsZeroIp(&ip6) == false)
	{
		Copy(ip, &ip6, sizeof(IP));

		b = true;
	}

	return b;
}

// DNS 正引きを行って結果を v4 と v6 の両方で得る
bool GetIP46(IP *ip4, IP *ip6, char *hostname)
{
	return GetIP46Ex(ip4, ip6, hostname, 0, NULL);
}
bool GetIP46Ex(IP *ip4, IP *ip6, char *hostname, UINT timeout, bool *cancel)
{
	IP a, b;
	bool ok_a, ok_b;
	// 引数チェック
	if (ip4 == NULL || ip6 == NULL || hostname == NULL)
	{
		return false;
	}

	ZeroIP4(ip4);
	ZeroIP6(ip6);

	ok_a = ok_b = false;

	if (GetIP6Ex(&a, hostname, timeout, cancel))
	{
		ok_a = true;
	}

	if (GetIP4Ex(&b, hostname, timeout, cancel))
	{
		ok_b = true;
	}

	if (ok_a)
	{
		if (IsIP4(&a))
		{
			Copy(ip4, &a, sizeof(IP));
		}
	}
	if (ok_b)
	{
		if (IsIP4(&b))
		{
			Copy(ip4, &b, sizeof(IP));
		}

		if (IsIP6(&b))
		{
			Copy(ip6, &b, sizeof(IP));
		}
	}
	if (ok_a)
	{
		if (IsIP6(&a))
		{
			Copy(ip6, &a, sizeof(IP));
		}
	}

	if (IsZeroIp(ip4) && IsZeroIp(ip6))
	{
		return false;
	}

	return true;
}

// GetIP 用スレッドのパラメータのクリーンアップ
void CleanupGetIPThreadParam(GETIP_THREAD_PARAM *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	Free(p);
}

// GetIP 用スレッドのパラメータの解放
void ReleaseGetIPThreadParam(GETIP_THREAD_PARAM *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		CleanupGetIPThreadParam(p);
	}
}

// DNS 正引きクエリ (タイムアウト付き) を行うスレッド
void GetIP4Ex6ExThread(THREAD *t, void *param)
{
	GETIP_THREAD_PARAM *p;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	p = (GETIP_THREAD_PARAM *)param;

	AddRef(p->Ref);

	NoticeThreadInit(t);

	AddWaitThread(t);

	// 解決の実行
	if (p->IPv6 == false)
	{
		// IPv4
		p->Ok = GetIP4Inner(&p->Ip, p->HostName);
	}
	else
	{
		// IPv6
		p->Ok = GetIP6Inner(&p->Ip, p->HostName);
	}

	ReleaseGetIPThreadParam(p);

	DelWaitThread(t);
}

// DNS 正引きクエリ (タイムアウト付き) を行う
bool GetIP4Ex6Ex(IP *ip, char *hostname, UINT timeout, bool ipv6, bool *cancel)
{
	GETIP_THREAD_PARAM *p;
	THREAD *t;
	bool ret = false;
	UINT64 start_tick = 0;
	UINT64 end_tick = 0;
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_GETIP;
	}

	p = ZeroMalloc(sizeof(GETIP_THREAD_PARAM));
	p->Ref = NewRef();
	StrCpy(p->HostName, sizeof(p->HostName), hostname);
	p->IPv6 = ipv6;
	p->Timeout = timeout;
	p->Ok = false;

	t = NewThread(GetIP4Ex6ExThread, p);
	WaitThreadInit(t);

	if (cancel == NULL)
	{
		WaitThread(t, timeout);
	}
	else
	{
		start_tick = Tick64();
		end_tick = start_tick + (UINT64)timeout;

		while (true)
		{
			UINT64 now = Tick64();
			UINT64 remain;
			UINT remain32;

			if (*cancel)
			{
				break;
			}

			if (now >= end_tick)
			{
				break;
			}

			remain = end_tick - now;
			remain32 = MIN((UINT)remain, 100);

			if (WaitThread(t, remain32))
			{
				break;
			}
		}
	}

	ReleaseThread(t);

	if (p->Ok)
	{
		ret = true;
		Copy(ip, &p->Ip, sizeof(IP));
	}

	ReleaseGetIPThreadParam(p);

	return ret;
}
bool GetIP4Ex(IP *ip, char *hostname, UINT timeout, bool *cancel)
{
	return GetIP4Ex6Ex(ip, hostname, timeout, false, cancel);
}
bool GetIP6Ex(IP *ip, char *hostname, UINT timeout, bool *cancel)
{
	return GetIP4Ex6Ex(ip, hostname, timeout, true, cancel);
}
bool GetIP4(IP *ip, char *hostname)
{
	return GetIP4Ex(ip, hostname, 0, NULL);
}
bool GetIP6(IP *ip, char *hostname)
{
	return GetIP6Ex(ip, hostname, 0, NULL);
}

// DNS 正引きクエリを行う
bool GetIP(IP *ip, char *hostname)
{
	return GetIPEx(ip, hostname, false);
}
bool GetIPEx(IP *ip, char *hostname, bool ipv6)
{
	if (ipv6 == false)
	{
		return GetIP4(ip, hostname);
	}
	else
	{
		return GetIP6(ip, hostname);
	}
}
bool GetIP6Inner(IP *ip, char *hostname)
{
	struct sockaddr_in6 in;
	struct in6_addr addr;
	struct addrinfo hint;
	struct addrinfo *info;
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (IsEmptyStr(hostname))
	{
		return false;
	}

	if (StrCmpi(hostname, "localhost") == 0)
	{
		GetLocalHostIP6(ip);
		return true;
	}

	if (StrToIP6(ip, hostname) == false && StrToIP(ip, hostname) == false)
	{
		// 正引き
		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET6;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) != 0 ||
			info->ai_family != AF_INET6)
		{
			if (info)
			{
				freeaddrinfo(info);
			}
			return QueryDnsCacheEx(ip, hostname, true);
		}
		// 正引き成功
		Copy(&in, info->ai_addr, sizeof(struct sockaddr_in6));
		freeaddrinfo(info);

		Copy(&addr, &in.sin6_addr, sizeof(addr));
		InAddrToIP6(ip, &addr);
	}

	// キャッシュ保存
	NewDnsCache(hostname, ip);

	return true;
}
bool GetIP4Inner(IP *ip, char *hostname)
{
	struct sockaddr_in in;
	struct in_addr addr;
	struct addrinfo hint;
	struct addrinfo *info;
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (IsEmptyStr(hostname))
	{
		return false;
	}

	if (StrCmpi(hostname, "localhost") == 0)
	{
		SetIP(ip, 127, 0, 0, 1);
		return true;
	}

	if (StrToIP6(ip, hostname) == false && StrToIP(ip, hostname) == false)
	{
		// 正引き
		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) != 0 ||
			info->ai_family != AF_INET)
		{
			if (info)
			{
				freeaddrinfo(info);
			}
			return QueryDnsCache(ip, hostname);
		}
		// 正引き成功
		Copy(&in, info->ai_addr, sizeof(struct sockaddr_in));
		freeaddrinfo(info);
		Copy(&addr, &in.sin_addr, sizeof(addr));
		InAddrToIP(ip, &addr);
	}

	// キャッシュ保存
	NewDnsCache(hostname, ip);

	return true;
}

// DNS キャッシュを検索する
bool QueryDnsCache(IP *ip, char *hostname)
{
	return QueryDnsCacheEx(ip, hostname, false);
}
bool QueryDnsCacheEx(IP *ip, char *hostname, bool ipv6)
{
	DNSCACHE *c;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	GenDnsCacheKeyName(tmp, sizeof(tmp), hostname, ipv6);

	c = FindDnsCache(tmp);
	if (c == NULL)
	{
		return false;
	}

	Copy(ip, &c->IpAddress, sizeof(IP));

	return true;
}

// IP を文字列に変換
void IPToUniStr(wchar_t *str, UINT size, IP *ip)
{
	char tmp[128];

	IPToStr(tmp, sizeof(tmp), ip);
	StrToUni(str, size, tmp);
}

// IP を文字列に変換 (32bit UINT)
void IPToUniStr32(wchar_t *str, UINT size, UINT ip)
{
	char tmp[128];

	IPToStr32(tmp, sizeof(tmp), ip);
	StrToUni(str, size, tmp);
}

// IP を文字列に変換 (128bit byte array)
void IPToStr128(char *str, UINT size, UCHAR *ip_bytes)
{
	IP ip_st;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	SetIP6(&ip_st, ip_bytes);
	IPToStr(str, size, &ip_st);
}

// IP を文字列に変換 (32bit UINT)
void IPToStr32(char *str, UINT size, UINT ip)
{
	IP ip_st;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	UINTToIP(&ip_st, ip);
	IPToStr(str, size, &ip_st);
}

// IPv4 または IPv6 を文字列に変換
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes)
{
	IP ip4;
	IP ip6;
	IP ip;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	Zero(&ip, sizeof(ip));

	UINTToIP(&ip4, ip_4_uint);
	SetIP6(&ip6, ip_6_bytes);

	if (IsIP6(&ip4) || (IsZeroIp(&ip4) && (IsZeroIp(&ip6) == false)))
	{
		Copy(&ip, &ip6, sizeof(IP));
	}
	else
	{
		Copy(&ip, &ip4, sizeof(IP));
	}

	IPToStr(str, size, &ip);
}

// IP を文字列に変換
void IPToStr(char *str, UINT size, IP *ip)
{
	// 引数チェック
	if (str == NULL || ip == NULL)
	{
		return;
	}

	if (IsIP6(ip))
	{
		IPToStr6(str, size, ip);
	}
	else
	{
		IPToStr4(str, size, ip);
	}
}

// IPv4 を文字列に変換
void IPToStr4(char *str, UINT size, IP *ip)
{
	// 引数チェック
	if (str == NULL || ip == NULL)
	{
		return;
	}

	// 変換
	snprintf(str, size != 0 ? size : 64, "%u.%u.%u.%u", ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3]);
}

// 文字列を IP に変換
bool StrToIP(IP *ip, char *str)
{
	TOKEN_LIST *token;
	char *tmp;
	UINT i;
	// 引数チェック
	if (ip == NULL || str == NULL)
	{
		return false;
	}

	if (StrToIP6(ip, str))
	{
		return true;
	}

	Zero(ip, sizeof(IP));

	tmp = CopyStr(str);
	Trim(tmp);
	token = ParseToken(tmp, ".");
	Free(tmp);

	if (token->NumTokens != 4)
	{
		FreeToken(token);
		return false;
	}
	for (i = 0;i < 4;i++)
	{
		char *s = token->Token[i];
		if (s[0] < '0' || s[0] > '9' ||
			(ToInt(s) >= 256))
		{
			FreeToken(token);
			return false;
		}
	}
	Zero(ip, sizeof(IP));
	for (i = 0;i < 4;i++)
	{
		ip->addr[i] = (UCHAR)ToInt(token->Token[i]);
	}

	FreeToken(token);

	return true;
}
UINT StrToIP32(char *str)
{
	IP ip;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	if (StrToIP(&ip, str) == false)
	{
		return 0;
	}

	return IPToUINT(&ip);
}
bool UniStrToIP(IP *ip, wchar_t *str)
{
	char *tmp;
	bool ret;

	tmp = CopyUniToStr(str);
	ret = StrToIP(ip, tmp);
	Free(tmp);

	return ret;
}
UINT UniStrToIP32(wchar_t *str)
{
	UINT ret;
	char *tmp;

	tmp = CopyUniToStr(str);
	ret = StrToIP32(tmp);
	Free(tmp);

	return ret;
}

// IP を in_addr に変換
void IPToInAddr(struct in_addr *addr, IP *ip)
{
	UINT i;
	// 引数チェック
	if (addr == NULL || ip == NULL)
	{
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	if (IsIP6(ip) == false)
	{
		for (i = 0;i < 4;i++)
		{
			((UCHAR *)addr)[i] = ip->addr[i];
		}
	}
}

// IP を in6_addr に変換
void IPToInAddr6(struct in6_addr *addr, IP *ip)
{
	UINT i;
	// 引数チェック
	if (addr == NULL || ip == NULL)
	{
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	if (IsIP6(ip))
	{
		for (i = 0;i < 16;i++)
		{
			((UCHAR *)addr)[i] = ip->ipv6_addr[i];
		}
	}
}

// in_addr を IP に変換
void InAddrToIP(IP *ip, struct in_addr *addr)
{
	UINT i;
	// 引数チェック
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	for (i = 0;i < 4;i++)
	{
		ip->addr[i] = ((UCHAR *)addr)[i];
	}
}

// in6_addr を IP に変換
void InAddrToIP6(IP *ip, struct in6_addr *addr)
{
	UINT i;
	// 引数チェック
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	ZeroIP6(ip);
	for (i = 0;i < 16;i++)
	{
		ip->ipv6_addr[i] = ((UCHAR *)addr)[i];
	}
}

// DNS キャッシュの検索
DNSCACHE *FindDnsCache(char *hostname)
{
	return FindDnsCacheEx(hostname, false);
}
DNSCACHE *FindDnsCacheEx(char *hostname, bool ipv6)
{
	DNSCACHE *c;
	char tmp[MAX_SIZE];
	if (hostname == NULL)
	{
		return NULL;
	}

	GenDnsCacheKeyName(tmp, sizeof(tmp), hostname, ipv6);

	LockDnsCache();
	{
		DNSCACHE t;
		t.HostName = tmp;
		c = Search(DnsCache, &t);
	}
	UnlockDnsCache();

	return c;
}

// DNS キャッシュ用の IPv4 / IPv6 キー名を生成
void GenDnsCacheKeyName(char *dst, UINT size, char *src, bool ipv6)
{
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	if (ipv6 == false)
	{
		StrCpy(dst, size, src);
	}
	else
	{
		Format(dst, size, "%s@ipv6", src);
	}
}

// 新しい DNS キャッシュの登録
void NewDnsCache(char *hostname, IP *ip)
{
	NewDnsCacheEx(hostname, ip, IsIP6(ip));
}
void NewDnsCacheEx(char *hostname, IP *ip, bool ipv6)
{
	DNSCACHE *c;
	char tmp[MAX_PATH];
	// 引数チェック
	if (hostname == NULL || ip == NULL)
	{
		return;
	}

	if (IsNetworkNameCacheEnabled() == false)
	{
		return;
	}

	GenDnsCacheKeyName(tmp, sizeof(tmp), hostname, ipv6);

	LockDnsCache();
	{
		DNSCACHE t;

		// まず hostname に該当するものがあるかどうか検索してみる
		t.HostName = tmp;
		c = Search(DnsCache, &t);

		if (c == NULL)
		{
			// 新規登録
			c = ZeroMalloc(sizeof(DNSCACHE));
			c->HostName = CopyStr(tmp);

			Copy(&c->IpAddress, ip, sizeof(IP));

			Add(DnsCache, c);
		}
		else
		{
			// 更新
			Copy(&c->IpAddress, ip, sizeof(IP));
		}
	}
	UnlockDnsCache();
}

// DNS キャッシュの名前比較
int CompareDnsCache(void *p1, void *p2)
{
	DNSCACHE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(DNSCACHE **)p1;
	c2 = *(DNSCACHE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->HostName, c2->HostName);
}

// DNS キャッシュの初期化
void InitDnsCache()
{
	// リスト作成
	DnsCache = NewList(CompareDnsCache);
}

// DNS キャッシュの解放
void FreeDnsCache()
{
	LockDnsCache();
	{
		DNSCACHE *c;
		UINT i;
		for (i = 0;i < LIST_NUM(DnsCache);i++)
		{
			// エントリのメモリ解放
			c = LIST_DATA(DnsCache, i);
			Free(c->HostName);
			Free(c);
		}
	}
	UnlockDnsCache();

	// リスト解放
	ReleaseList(DnsCache);
	DnsCache = NULL;
}

// DNS キャッシュのロック
void LockDnsCache()
{
	LockList(DnsCache);
}

// DNS キャッシュのロック解除
void UnlockDnsCache()
{
	UnlockList(DnsCache);
}

// ネットワーク通信モジュールの初期化
void InitNetwork()
{
	num_tcp_connections = NewCounter();

	// クライアントリストの初期化
	InitIpClientList();

	// スレッド関係の初期化
	InitWaitThread();

	// ホスト名キャッシュの初期化
	InitHostCache();

#ifdef	OS_WIN32
	// ソケットライブラリの初期化
	Win32InitSocketLibrary();
#else
	UnixInitSocketLibrary();
#endif	// OS_WIN32

	// DNS キャッシュの初期化
	InitDnsCache();

	// OpenSSL の初期化
	ssl_ctx = SSL_CTX_new(SSLv23_method());

	// ロック初期化
	machine_name_lock = NewLock();
	disconnect_function_lock = NewLock();
	aho = NewLock();
	socket_library_lock = NewLock();
	ssl_connect_lock = NewLock();
//	ssl_accept_lock = NewLock();
	dns_lock = NewLock();
	unix_dns_server_addr_lock = NewLock();
	Zero(&unix_dns_server, sizeof(unix_dns_server));

	cipher_list_token = ParseToken(cipher_list, " ");

	disable_cache = false;
}

// ネットワーク名キャッシュの有効化
void EnableNetworkNameCache()
{
	disable_cache = false;
}

// ネットワーク名キャッシュの無効化
void DisableNetworkNameCache()
{
	disable_cache = true;
}

// ネットワーク名キャッシュが有効かどうか取得
bool IsNetworkNameCacheEnabled()
{
	return !disable_cache;
}

// 暗号化アルゴリズムリストを取得
TOKEN_LIST *GetCipherList()
{
	return cipher_list_token;
}

// TCP コネクション数カウンタを取得
COUNTER *GetNumTcpConnectionsCounter()
{
	return num_tcp_connections;
}

// ネットワーク通信モジュールの解放
void FreeNetwork()
{
	FreeToken(cipher_list_token);
	cipher_list_token = NULL;

	Zero(&unix_dns_server, sizeof(unix_dns_server));

	// ロック解放
	DeleteLock(unix_dns_server_addr_lock);
	DeleteLock(dns_lock);
	DeleteLock(ssl_accept_lock);
	DeleteLock(machine_name_lock);
	DeleteLock(disconnect_function_lock);
	DeleteLock(aho);
	DeleteLock(socket_library_lock);
	DeleteLock(ssl_connect_lock);
	machine_name_lock = NULL;
	ssl_accept_lock = machine_name_lock = disconnect_function_lock =
		aho = socket_library_lock = ssl_connect_lock = NULL;

	// OpenSSL の解放
	SSL_CTX_free(ssl_ctx);
	ssl_ctx = NULL;

	// スレッド関係の解放
	FreeWaitThread();

	// DNS キャッシュの解放
	FreeDnsCache();

	// ホスト名キャッシュの解放
	FreeHostCache();

#ifdef	OS_WIN32
	// ソケットライブラリの解放
	Win32FreeSocketLibrary();
#else
	UnixFreeSocketLibrary();
#endif	// OS_WIN32

	DeleteCounter(num_tcp_connections);
	num_tcp_connections = NULL;

	// クライアントリストの解放
	FreeIpClientList();
}

// ソケットリストにソケットを追加する
void AddSockList(SOCKLIST *sl, SOCK *s)
{
	// 引数チェック
	if (sl == NULL || s == NULL)
	{
		return;
	}

	LockList(sl->SockList);
	{
		if (IsInList(sl->SockList, s) == false)
		{
			AddRef(s->ref);

			Insert(sl->SockList, s);
		}
	}
	UnlockList(sl->SockList);
}

// ソケットリストからソケットを削除する
void DelSockList(SOCKLIST *sl, SOCK *s)
{
	// 引数チェック
	if (sl == NULL || s == NULL)
	{
		return;
	}

	LockList(sl->SockList);
	{
		if (Delete(sl->SockList, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(sl->SockList);
}

// ソケットリストのソケットをすべて停止させて削除する
void StopSockList(SOCKLIST *sl)
{
	SOCK **ss;
	UINT num, i;
	// 引数チェック
	if (sl == NULL)
	{
		return;
	}

	LockList(sl->SockList);
	{
		num = LIST_NUM(sl->SockList);
		ss = ToArray(sl->SockList);

		DeleteAll(sl->SockList);
	}
	UnlockList(sl->SockList);

	for (i = 0;i < num;i++)
	{
		SOCK *s = ss[i];

		Disconnect(s);
		ReleaseSock(s);
	}

	Free(ss);
}

// ソケットリストの削除
void FreeSockList(SOCKLIST *sl)
{
	// 引数チェック
	if (sl == NULL)
	{
		return;
	}

	StopSockList(sl);

	ReleaseList(sl->SockList);

	Free(sl);
}

// ソケットリストの作成
SOCKLIST *NewSockList()
{
	SOCKLIST *sl = ZeroMallocFast(sizeof(SOCKLIST));

	sl->SockList = NewList(NULL);

	return sl;
}

// Solarisでのソケットのタイムアウト用スレッド
void SocketTimeoutThread(THREAD *t, void *param)
{
	SOCKET_TIMEOUT_PARAM *ttparam;
	ttparam = (SOCKET_TIMEOUT_PARAM *)param;

	// タイムアウト時間だけ待つ
	Select(NULL, ttparam->sock->TimeOut, ttparam->cancel, NULL);

	// ブロック中ならディスコネクトする
	if(! ttparam->unblocked)
	{
//		Debug("Socket timeouted\n");
		closesocket(ttparam->sock->socket);
	}
	else
	{
//		Debug("Socket timeout cancelled\n");
	}
}

// タイムアウト用スレッドの初期化と開始
SOCKET_TIMEOUT_PARAM *NewSocketTimeout(SOCK *sock)
{
	SOCKET_TIMEOUT_PARAM *ttp;
	if(! sock->AsyncMode && sock->TimeOut != TIMEOUT_INFINITE)
	{
//		Debug("NewSockTimeout(%u)\n",sock->TimeOut);

		ttp = (SOCKET_TIMEOUT_PARAM*)Malloc(sizeof(SOCKET_TIMEOUT_PARAM));

		// タイムアウトスレッド用のパラメータをセット
		ttp->cancel = NewCancel();
		ttp->sock = sock;
		ttp->unblocked = false;
		ttp->thread = NewThread(SocketTimeoutThread, ttp);
		return ttp;
	}
	return NULL;
}

// タイムアウト用スレッドの停止と開放
void FreeSocketTimeout(SOCKET_TIMEOUT_PARAM *ttp)
{
	if(ttp == NULL)
	{
		return;
	}

	ttp->unblocked = true;
	Cancel(ttp->cancel);
	WaitThread(ttp->thread, INFINITE);
	ReleaseCancel(ttp->cancel);
	ReleaseThread(ttp->thread);
	Free(ttp);
//	Debug("FreeSocketTimeout succeed\n");
	return;
}

// IP アドレスとサブネット マスクのパース
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask)
{
	// 引数チェック
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		return IsSubnetMask4(mask);
	}
	else
	{
		return IsSubnetMask6(mask);
	}
}
bool ParseIpAndSubnetMask6(char *src, IP *ip, IP *mask)
{
	if (ParseIpAndSubnetMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP6(ip) == false)
	{
		return false;
	}

	return true;
}
bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip2, mask2;
	// 引数チェック
	if (src == NULL)
	{
		return false;
	}

	if (ParseIpAndSubnetMask46(src, &ip2, &mask2) == false)
	{
		return false;
	}

	if (IsIP4(&ip2) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip2);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&mask2);
	}

	return true;
}


// IP アドレスとマスクのパース
bool ParseIpAndMask46(char *src, IP *ip, IP *mask)
{
	TOKEN_LIST *t;
	char *ipstr;
	char *subnetstr;
	bool ret = false;
	IP ip2;
	IP mask2;
	// 引数チェック
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	Zero(&ip2, sizeof(IP));
	Zero(&mask2, sizeof(IP));

	t = ParseToken(src, "/");
	if (t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	ipstr = t->Token[0];
	subnetstr = t->Token[1];
	Trim(ipstr);
	Trim(subnetstr);

	if (StrToIP(&ip2, ipstr))
	{
		if (StrToIP(&mask2, subnetstr))
		{
			// IP アドレス部とマスク部が同一の種類かどうか比較する
			if (IsIP6(&ip2) && IsIP6(&mask2))
			{
				// 両方とも IPv6
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
			else if (IsIP4(&ip2) && IsIP4(&mask2))
			{
				// 両方とも IPv4
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
		}
		else
		{
			if (IsNum(subnetstr))
			{
				UINT i = ToInt(subnetstr);
				// マスク部が数値
				if (IsIP6(&ip2) && i <= 128)
				{
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask6(mask, i);
				}
				else if (i <= 32)
				{
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask4(mask, i);
				}
			}
		}
	}

	FreeToken(t);

	return ret;
}
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip_ip, ip_mask;
	if (ParseIpAndMask46(src, &ip_ip, &ip_mask) == false)
	{
		return false;
	}

	if (IsIP4(&ip_ip) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip_ip);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&ip_mask);
	}

	return true;
}
bool ParseIpAndMask6(char *src, IP *ip, IP *mask)
{
	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP6(ip) == false)
	{
		return false;
	}

	return true;
}


// IPv4 アドレスの指定が正しいかどうかチェックする
bool IsIpStr4(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP32(str) == 0 && StrCmpi(str, "0.0.0.0") != 0)
	{
		return false;
	}

	return true;
}

// IPv6 アドレスの指定が正しいかどうかチェックする
bool IsIpStr6(char *str)
{
	IP ip;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP6(&ip, str) == false)
	{
		return false;
	}

	return true;
}

// IP アドレスの指定が正しいかどうかチェックする
bool IsIpStr46(char *str)
{
	if (IsIpStr4(str) || IsIpStr6(str))
	{
		return true;
	}

	return false;
}


// 文字列を IPv4 マスクに変換
bool StrToMask4(IP *mask, char *str)
{
	// 引数チェック
	if (mask == NULL || str == NULL)
	{
		return false;
	}

	if (str[0] == '/')
	{
		str++;
	}

	if (IsNum(str))
	{
		UINT n = ToInt(str);

		if (n <= 32)
		{
			IntToSubnetMask4(mask, n);
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		if (StrToIP(mask, str) == false)
		{
			return false;
		}
		else
		{
			return IsIP4(mask);
		}
	}
}

// 文字列を IPv6 マスクに変換
bool StrToMask6(IP *mask, char *str)
{
	// 引数チェック
	if (mask == NULL || str == NULL)
	{
		return false;
	}

	if (str[0] == '/')
	{
		str++;
	}

	if (IsNum(str))
	{
		UINT n = ToInt(str);

		if (n <= 128)
		{
			IntToSubnetMask6(mask, n);
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		if (StrToIP(mask, str) == false)
		{
			return false;
		}
		else
		{
			return IsIP6(mask);
		}
	}
}
bool StrToMask6Addr(IPV6_ADDR *mask, char *str)
{
	IP ip;

	if (StrToMask6(&ip, str) == false)
	{
		return false;
	}

	if (IPToIPv6Addr(mask, &ip) == false)
	{
		return false;
	}

	return true;
}

// 文字列を IPv4 / IPv6 マスクに変換
bool StrToMask46(IP *mask, char *str, bool ipv6)
{
	if (ipv6)
	{
		return StrToMask6(mask, str);
	}
	else
	{
		return StrToMask4(mask, str);
	}
}


// IPv4 / IPv6 マスクを文字列に変換
void MaskToStr(char *str, UINT size, IP *mask)
{
	MaskToStrEx(str, size, mask, false);
}
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address)
{
	// 引数チェック
	if (str == NULL || mask == NULL)
	{
		return;
	}

	if (always_full_address == false && IsSubnetMask(mask))
	{
		ToStr(str, SubnetMaskToInt(mask));
	}
	else
	{
		IPToStr(str, size, mask);
	}
}
void MaskToStr32(char *str, UINT size, UINT mask)
{
	MaskToStr32Ex(str, size, mask, false);
}
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address)
{
	IP ip;

	UINTToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address)
{
	IP ip;

	// 引数チェック
	if (str == NULL || mask == NULL)
	{
		StrCpy(str, size, "");
		return;
	}

	IPv6AddrToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask)
{
	Mask6AddrToStrEx(str, size, mask, false);
}

