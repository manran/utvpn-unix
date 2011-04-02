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

// Network.h
// Network.c のヘッダ

#ifndef	NETWORK_H
#define	NETWORK_H

#define	TIMEOUT_GETIP				2300

#define	TIMEOUT_INFINITE			(0x7fffffff)
#define	TIMEOUT_TCP_PORT_CHECK		(10 * 1000)
#define	TIMEOUT_SSL_CONNECT			(15 * 1000)

#define	TIMEOUT_HOSTNAME			(500)
#define	TIMEOUT_NETBIOS_HOSTNAME	(100)
#define	EXPIRES_HOSTNAME			(10 * 60 * 1000)

#define	SOCKET_BUFFER_SIZE			0x10000000

#define	IPV6_DUMMY_FOR_IPV4			0xFEFFFFDF


// IP アドレス
struct IP
{
	UCHAR addr[4];					// IPv4 アドレス, ※ 223.255.255.254 = IPv6 を意味する
	UCHAR ipv6_addr[16];			// IPv6 アドレス
	UINT ipv6_scope_id;				// IPv6 スコープ ID
};

// IP 構造体をアドレス部分のみで比較する際のサイズ
#define	SIZE_OF_IP_FOR_ADDR			(sizeof(UCHAR) * 20)

// IP アドレス部を比較
#define	CmpIpAddr(ip1, ip2)			(Cmp((ip1), (ip2), SIZE_OF_IP_FOR_ADDR))

// IPv6 アドレス (異形式)
struct IPV6_ADDR
{
	UCHAR Value[16];				// 値
} GCC_PACKED;

// IPv6アドレスの種類
#define IPV6_ADDR_UNICAST						1	// ユニキャスト
#define IPV6_ADDR_LOCAL_UNICAST					2	// ローカルユニキャスト
#define IPV6_ADDR_GLOBAL_UNICAST				4	// グローバルユニキャスト
#define IPV6_ADDR_MULTICAST						8	// マルチキャスト
#define IPV6_ADDR_ALL_NODE_MULTICAST			16	// 全ノードマルチキャスト
#define IPV6_ADDR_ALL_ROUTER_MULTICAST			32	// 全ルータマルチキャスト
#define IPV6_ADDR_SOLICIATION_MULTICAST			64	// 要請ノードマルチキャスト
#define	IPV6_ADDR_ZERO							128	// オールゼロ
#define	IPV6_ADDR_LOOPBACK						256	// ループバック


// DNS キャッシュリスト
struct DNSCACHE
{
	char *HostName;
	IP IpAddress;
};

// クライアントリスト
struct IP_CLIENT
{
	IP IpAddress;					// IP アドレス
	UINT NumConnections;			// 接続個数
};

// ソケットイベント
struct SOCK_EVENT
{
	REF *ref;						// 参照カウンタ
#ifdef	OS_WIN32
	void *hEvent;					// Win32 イベントハンドルへのポインタ
#else	// OS_WIN32
	LIST *SockList;					// ソケットリスト
	int pipe_read, pipe_write;		// パイプ
#endif	// OS_WIN32
};

// ソケットの種類
#define	SOCK_TCP				1
#define	SOCK_UDP				2

// ソケット
struct SOCK
{
	REF *ref;					// 参照カウンタ
	LOCK *lock;					// ロック
	LOCK *ssl_lock;				// SSL 関係のロック
	LOCK *disconnect_lock;		// 切断用ロック
	SOCKET socket;				// ソケット番号
	SSL *ssl;					// SSL オブジェクト
	UINT Type;					// ソケットの種類
	bool Connected;				// 接続中フラグ
	bool ServerMode;			// サーバーモード
	bool AsyncMode;				// 非同期モード
	bool SecureMode;			// SSL 通信モード
	bool ListenMode;			// Listen 中
	BUF *SendBuf;				// 送信バッファ
	IP RemoteIP;				// リモートホストの IP アドレス
	IP LocalIP;					// ローカルホストの IP アドレス
	char *RemoteHostname;		// リモートホスト名
	UINT RemotePort;			// リモート側のポート番号
	UINT LocalPort;				// ローカル側のポート番号
	UINT64 SendSize;			// 送信したデータサイズの合計
	UINT64 RecvSize;			// 受信したデータサイズの合計
	UINT64 SendNum;				// 送信したデータブロック数
	UINT64 RecvNum;				// 受信したデータブロック数
	X *RemoteX;					// リモートホストの証明書
	X *LocalX;					// ローカルホストの証明書
	char *CipherName;			// 暗号化アルゴリズム名
	char *WaitToUseCipher;		// 使用したいアルゴリズム名を設定する
	bool IgnoreRecvErr;			// RecvFrom エラーを無視できるかどうか
	bool IgnoreSendErr;			// SendTo エラーを無視できるかどうか
	UINT TimeOut;				// タイムアウト値
	SOCK_EVENT *SockEvent;		// 関連付けられているソケットイベント
	bool CancelAccept;			// Accept のキャンセルフラグ
	bool WriteBlocked;			// 前回の書き込みがブロックされた
	bool Disconnecting;			// 切断しようとしている
	bool UdpBroadcast;			// UDP ブロードキャストモード
	void *Param;				// 任意のパラメータ
	bool IPv6;					// IPv6

#ifdef	OS_UNIX
	pthread_t CallingThread;	// システムコールを呼び出しているスレッド
#endif	// OS_UNIX

#ifdef	OS_WIN32
	void *hEvent;				// 非同期モードの場合のイベント
#endif	// OS_WIN32
};

// 戻り値の定数
#define	SOCK_LATER	(0xffffffff)	// ブロッキング中

// ソケットセット
#define	MAX_SOCKSET_NUM		60		// ソケットセットに格納できるソケット数
struct SOCKSET
{
	UINT NumSocket;					// ソケット数
	SOCK *Sock[MAX_SOCKSET_NUM];	// ソケットへのポインタの配列
};

// キャンセルオブジェクト
struct CANCEL
{
	REF *ref;						// 参照カウンタ
	bool SpecialFlag;				// 特殊フラグ (Win32 ドライバが生成したイベントを関連付ける)
#ifdef	OS_WIN32
	void *hEvent;					// Win32 イベントハンドルへのポインタ
#else	// OS_WIN32
	int pipe_read, pipe_write;		// パイプ
#endif	// OS_WIN32
};

// ルーティングテーブルエントリ
struct ROUTE_ENTRY
{
	IP DestIP;
	IP DestMask;
	IP GatewayIP;
	bool LocalRouting;
	bool PPPConnection;
	UINT Metric;
	UINT OldIfMetric;
	UINT InterfaceID;
};

// ルーティングテーブル
struct ROUTE_TABLE
{
	UINT NumEntry;
	UINT HashedValue;
	ROUTE_ENTRY **Entry;
};

// ホスト名キャッシュリスト
typedef struct HOSTCACHE
{
	UINT64 Expires;							// 有効期限
	IP IpAddress;							// IP アドレス
	char HostName[256];						// ホスト名
} HOSTCACHE;

// NETBIOS 名前要求
typedef struct NBTREQUEST
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Query[38];
} NBTREQUEST;

// NETBIOS 名前応答
typedef struct NBTRESPONSE
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Response[61];
} NBTRESPONSE;

// ソケットリスト
typedef struct SOCKLIST
{
	LIST *SockList;
} SOCKLIST;


// Solaris 用タイムアウトスレッドのパラメータ
typedef struct SOCKET_TIMEOUT_PARAM{
	SOCK *sock;
	CANCEL *cancel;
	THREAD *thread;
	bool unblocked;
} SOCKET_TIMEOUT_PARAM;

// GetIP 用スレッドのパラメータ
struct GETIP_THREAD_PARAM
{
	REF *Ref;
	char HostName[MAX_PATH];
	bool IPv6;
	UINT Timeout;
	IP Ip;
	bool Ok;
};

// IP アドレスリリース用スレッドのパラメータ
struct WIN32_RELEASEADDRESS_THREAD_PARAM
{
	REF *Ref;
	char Guid[MAX_SIZE];
	UINT Timeout;
	bool Ok;
	bool Renew;
};

// TCP テーブルエントリ
typedef struct TCPTABLE
{
	UINT Status;
	IP LocalIP;
	UINT LocalPort;
	IP RemoteIP;
	UINT RemotePort;
	UINT ProcessId;
} TCPTABLE;

// TCP の状態
#define	TCP_STATE_CLOSED				1
#define	TCP_STATE_LISTEN				2
#define	TCP_STATE_SYN_SENT				3
#define	TCP_STATE_SYN_RCVD				4
#define	TCP_STATE_ESTAB					5
#define	TCP_STATE_FIN_WAIT1				6
#define	TCP_STATE_FIN_WAIT2				7
#define	TCP_STATE_CLOSE_WAIT			8
#define	TCP_STATE_CLOSING				9
#define	TCP_STATE_LAST_ACK				10
#define	TCP_STATE_TIME_WAIT				11
#define	TCP_STATE_DELETE_TCB			12

// ルーティングテーブル変化通知
struct ROUTE_CHANGE
{
	ROUTE_CHANGE_DATA *Data;
};


#ifdef	OS_WIN32

// Win32 用関数プロトタイプ
void Win32InitSocketLibrary();
void Win32FreeSocketLibrary();
void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void Win32InitAsyncSocket(SOCK *sock);
void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
void Win32FreeAsyncSocket(SOCK *sock);
void Win32IpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row);
void Win32RouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry);
int Win32CompareRouteEntryByMetric(void *p1, void *p2);
ROUTE_TABLE *Win32GetRouteTable();
bool Win32AddRouteEntry(ROUTE_ENTRY *e, bool *already_exists);
void Win32DeleteRouteEntry(ROUTE_ENTRY *e);
void Win32UINTToIP(IP *ip, UINT i);
UINT Win32IPToUINT(IP *ip);
UINT Win32GetVLanInterfaceID(char *instance_name);
char **Win32EnumVLan(char *tag_name);
void Win32Cancel(CANCEL *c);
void Win32CleanupCancel(CANCEL *c);
CANCEL *Win32NewCancel();
SOCK_EVENT *Win32NewSockEvent();
void Win32SetSockEvent(SOCK_EVENT *event);
void Win32CleanupSockEvent(SOCK_EVENT *event);
bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout);
bool Win32GetDefaultDns(IP *ip, char *domain, UINT size);
void Win32RenewDhcp();
void Win32RenewDhcp9x(UINT if_id);
void Win32ReleaseDhcp9x(UINT if_id, bool wait);
int CompareIpAdapterIndexMap(void *p1, void *p2);
LIST *Win32GetTcpTableList();
LIST *Win32GetTcpTableListByGetExtendedTcpTable();
LIST *Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack();
LIST *Win32GetTcpTableListByGetTcpTable();
ROUTE_CHANGE *Win32NewRouteChange();
void Win32FreeRouteChange(ROUTE_CHANGE *r);
bool Win32IsRouteChanged(ROUTE_CHANGE *r);
bool Win32GetAdapterFromGuid(void *a, char *guid);

bool Win32ReleaseAddress(void *a);
bool Win32ReleaseAddressByGuid(char *guid);
bool Win32ReleaseAddressByGuidEx(char *guid, UINT timeout);
void Win32ReleaseAddressByGuidExThread(THREAD *t, void *param);
void ReleaseWin32ReleaseAddressByGuidThreadParam(WIN32_RELEASEADDRESS_THREAD_PARAM *p);
bool Win32ReleaseOrRenewAddressByGuidEx(char *guid, UINT timeout, bool renew);
bool Win32RenewAddress(void *a);
bool Win32RenewAddressByGuid(char *guid);
bool Win32RenewAddressByGuidEx(char *guid, UINT timeout);


#else	// OS_WIN32

// UNIX 用関数プロトタイプ
void UnixInitSocketLibrary();
void UnixFreeSocketLibrary();
void UnixSelect(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void UnixInitAsyncSocket(SOCK *sock);
void UnixJoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
void UnixFreeAsyncSocket(SOCK *sock);
void UnixIpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row);
void UnixRouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry);
int UnixCompareRouteEntryByMetric(void *p1, void *p2);
ROUTE_TABLE *UnixGetRouteTable();
bool UnixAddRouteEntry(ROUTE_ENTRY *e, bool *already_exists);
void UnixDeleteRouteEntry(ROUTE_ENTRY *e);
UINT UnixGetVLanInterfaceID(char *instance_name);
char **UnixEnumVLan(char *tag_name);
void UnixCancel(CANCEL *c);
void UnixCleanupCancel(CANCEL *c);
CANCEL *UnixNewCancel();
SOCK_EVENT *UnixNewSockEvent();
void UnixSetSockEvent(SOCK_EVENT *event);
void UnixCleanupSockEvent(SOCK_EVENT *event);
bool UnixWaitSockEvent(SOCK_EVENT *event, UINT timeout);
bool UnixGetDefaultDns(IP *ip);
void UnixRenewDhcp();
void UnixNewPipe(int *pipe_read, int *pipe_write);
void UnixWritePipe(int pipe_write);
void UnixDeletePipe(int p1, int p2);
void UnixSelectInner(UINT num_read, UINT *reads, UINT num_write, UINT *writes, UINT timeout);
void UnixSetSocketNonBlockingMode(int fd, bool nonblock);

#endif	// OS_WIN32

// 関数プロトタイプ
void InitNetwork();
void FreeNetwork();
void InitDnsCache();
void FreeDnsCache();
void LockDnsCache();
void UnlockDnsCache();
int CompareDnsCache(void *p1, void *p2);
void GenDnsCacheKeyName(char *dst, UINT size, char *src, bool ipv6);
void NewDnsCacheEx(char *hostname, IP *ip, bool ipv6);
DNSCACHE *FindDnsCacheEx(char *hostname, bool ipv6);
bool QueryDnsCacheEx(IP *ip, char *hostname, bool ipv6);
void NewDnsCache(char *hostname, IP *ip);
DNSCACHE *FindDnsCache(char *hostname);
bool QueryDnsCache(IP *ip, char *hostname);
void InAddrToIP(IP *ip, struct in_addr *addr);
void InAddrToIP6(IP *ip, struct in6_addr *addr);
void IPToInAddr(struct in_addr *addr, IP *ip);
void IPToInAddr6(struct in6_addr *addr, IP *ip);
bool StrToIP(IP *ip, char *str);
UINT StrToIP32(char *str);
bool UniStrToIP(IP *ip, wchar_t *str);
UINT UniStrToIP32(wchar_t *str);
void IPToStr(char *str, UINT size, IP *ip);
void IPToStr4(char *str, UINT size, IP *ip);
void IPToStr32(char *str, UINT size, UINT ip);
void IPToStr128(char *str, UINT size, UCHAR *ip_bytes);
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes);
void IPToUniStr(wchar_t *str, UINT size, IP *ip);
void IPToUniStr32(wchar_t *str, UINT size, UINT ip);
bool GetIPEx(IP *ip, char *hostname, bool ipv6);
bool GetIP46(IP *ip4, IP *ip6, char *hostname);
bool GetIP46Ex(IP *ip4, IP *ip6, char *hostname, UINT timeout, bool *cancel);
bool GetIP46Any4(IP *ip, char *hostname);
bool GetIP46Any6(IP *ip, char *hostname);
bool GetIP(IP *ip, char *hostname);
bool GetIP4(IP *ip, char *hostname);
bool GetIP6(IP *ip, char *hostname);
bool GetIP4Ex(IP *ip, char *hostname, UINT timeout, bool *cancel);
bool GetIP6Ex(IP *ip, char *hostname, UINT timeout, bool *cancel);
bool GetIP4Ex6Ex(IP *ip, char *hostname, UINT timeout, bool ipv6, bool *cancel);
void GetIP4Ex6ExThread(THREAD *t, void *param);
void ReleaseGetIPThreadParam(GETIP_THREAD_PARAM *p);
void CleanupGetIPThreadParam(GETIP_THREAD_PARAM *p);
bool GetIP4Inner(IP *ip, char *hostname);
bool GetIP6Inner(IP *ip, char *hostname);
bool GetHostNameInner(char *hostname, UINT size, IP *ip);
bool GetHostNameInner6(char *hostname, UINT size, IP *ip);
bool GetHostName(char *hostname, UINT size, IP *ip);
void GetHostNameThread(THREAD *t, void *p);
void GetMachineName(char *name, UINT size);
void GetMachineNameEx(char *name, UINT size, bool no_load_hosts);
bool GetMachineNameFromHosts(char *name, UINT size);
void GetMachineIp(IP *ip);
void GetMachineHostName(char *name, UINT size);
void UINTToIP(IP *ip, UINT value);
UINT IPToUINT(IP *ip);
SOCK *NewSock();
void ReleaseSock(SOCK *s);
void CleanupSock(SOCK *s);
SOCK *Connect(char *hostname, UINT port);
SOCK *ConnectEx(char *hostname, UINT port, UINT timeout);
SOCK *ConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag);
void SetSocketSendRecvBufferSize(int s, UINT size);
void QuerySocketInformation(SOCK *sock);
void Disconnect(SOCK *sock);
SOCK *Listen(UINT port);
SOCK *ListenEx(UINT port, bool local_only);
SOCK *Listen6(UINT port);
SOCK *ListenEx6(UINT port, bool local_only);
SOCK *Accept(SOCK *sock);
SOCK *Accept6(SOCK *sock);
UINT Send(SOCK *sock, void *data, UINT size, bool secure);
UINT Recv(SOCK *sock, void *data, UINT size, bool secure);
UINT SecureSend(SOCK *sock, void *data, UINT size);
UINT SecureRecv(SOCK *sock, void *data, UINT size);
bool StartSSL(SOCK *sock, X *x, K *priv);
bool StartSSLEx(SOCK *sock, X *x, K *priv, bool client_tls);
bool SendAll(SOCK *sock, void *data, UINT size, bool secure);
void SendAdd(SOCK *sock, void *data, UINT size);
bool SendNow(SOCK *sock, int secure);
bool RecvAll(SOCK *sock, void *data, UINT size, bool secure);
void InitSockSet(SOCKSET *set);
void AddSockSet(SOCKSET *set, SOCK *sock);
CANCEL *NewCancel();
CANCEL *NewCancelSpecial(void *hEvent);
void ReleaseCancel(CANCEL *c);
void CleanupCancel(CANCEL *c);
void Cancel(CANCEL *c);
void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void SetWantToUseCipher(SOCK *sock, char *name);
SOCK *NewUDP(UINT port);
SOCK *NewUDPEx(UINT port, bool ipv6);
SOCK *NewUDP4(UINT port);
SOCK *NewUDP6(UINT port);
UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size);
UINT SendTo6(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size);
UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
void SetTimeout(SOCK *sock, UINT timeout);
UINT GetTimeout(SOCK *sock);
void LockOpenSSL();
void UnlockOpenSSL();
bool CheckTCPPort(char *hostname, UINT port);
bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout);
void CheckTCPPortThread(THREAD *thread, void *param);
ROUTE_TABLE *GetRouteTable();
void FreeRouteTable(ROUTE_TABLE *t);
bool AddRouteEntryEx(ROUTE_ENTRY *e, bool *already_exists);
bool AddRouteEntry(ROUTE_ENTRY *e);
void DeleteRouteEntry(ROUTE_ENTRY *e);
char **EnumVLan(char *tag_name);
void FreeEnumVLan(char **s);
UINT GetVLanInterfaceID(char *tag_name);
ROUTE_ENTRY *GetBestRouteEntry(IP *ip);
ROUTE_ENTRY *GetBestRouteEntryEx(IP *ip, UINT exclude_if_id);
ROUTE_ENTRY *GetBestRouteEntryFromRouteTable(ROUTE_TABLE *table, IP *ip);
ROUTE_ENTRY *GetBestRouteEntryFromRouteTableEx(ROUTE_TABLE *table, IP *ip, UINT exclude_if_id);
void FreeRouteEntry(ROUTE_ENTRY *e);
void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
SOCK_EVENT *NewSockEvent();
void SetSockEvent(SOCK_EVENT *event);
void CleanupSockEvent(SOCK_EVENT *event);
bool WaitSockEvent(SOCK_EVENT *event, UINT timeout);
void ReleaseSockEvent(SOCK_EVENT *event);
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4);
bool GetDefaultDns(IP *ip);
bool GetDomainName(char *name, UINT size);
bool UnixGetDomainName(char *name, UINT size);
void RenewDhcp();
void AcceptInit(SOCK *s);
bool CheckCipherListName(char *name);
TOKEN_LIST *GetCipherList();
COUNTER *GetNumTcpConnectionsCounter();
void InitWaitThread();
void FreeWaitThread();
void AddWaitThread(THREAD *t);
void DelWaitThread(THREAD *t);
void InitHostCache();
void FreeHostCache();
int CompareHostCache(void *p1, void *p2);
void AddHostCache(IP *ip, char *hostname);
bool GetHostCache(char *hostname, UINT size, IP *ip);
bool IsSubnetMask(IP *ip);
bool IsSubnetMask4(IP *ip);
bool IsSubnetMask32(UINT ip);
bool IsNetworkAddress(IP *ip, IP *mask);
bool IsNetworkAddress4(IP *ip, IP *mask);
bool IsNetworkAddress32(UINT ip, UINT mask);
bool IsHostIPAddress4(IP *ip);
bool IsHostIPAddress32(UINT ip);
bool IsZeroIp(IP *ip);
bool IsZeroIP(IP *ip);
bool IsZeroIP6Addr(IPV6_ADDR *addr);
UINT IntToSubnetMask32(UINT i);
void IntToSubnetMask4(IP *ip, UINT i);
bool GetNetBiosName(char *name, UINT size, IP *ip);
bool NormalizeMacAddress(char *dst, UINT size, char *src);
SOCKLIST *NewSockList();
void AddSockList(SOCKLIST *sl, SOCK *s);
void DelSockList(SOCKLIST *sl, SOCK *s);
void StopSockList(SOCKLIST *sl);
void FreeSockList(SOCKLIST *sl);
bool IsIPv6Supported();
void SetSockPriorityHigh(SOCK *s);
void InitIpClientList();
void FreeIpClientList();
int CompareIpClientList(void *p1, void *p2);
void AddIpClient(IP *ip);
void DelIpClient(IP *ip);
IP_CLIENT *SearchIpClient(IP *ip);
UINT GetNumIpClient(IP *ip);
void SetLinuxArpFilter();
LIST *GetTcpTableList();
void FreeTcpTableList(LIST *o);
int CompareTcpTable(void *p1, void *p2);
void PrintTcpTableList(LIST *o);
TCPTABLE *GetTcpTableFromEndPoint(LIST *o, IP *local_ip, UINT local_port, IP *remote_ip, UINT remote_port);
UINT GetTcpProcessIdFromSocket(SOCK *s);
UINT GetTcpProcessIdFromSocketReverse(SOCK *s);
bool CanGetTcpProcessId();
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag);
void EnableNetworkNameCache();
void DisableNetworkNameCache();
bool IsNetworkNameCacheEnabled();
ROUTE_CHANGE *NewRouteChange();
void FreeRouteChange(ROUTE_CHANGE *r);
bool IsRouteChanged(ROUTE_CHANGE *r);
void RouteToStr(char *str, UINT str_size, ROUTE_ENTRY *e);
void DebugPrintRoute(ROUTE_ENTRY *e);
void DebugPrintRouteTable(ROUTE_TABLE *r);

void SocketTimeoutThread(THREAD *t, void *param);
SOCKET_TIMEOUT_PARAM *NewSocketTimeout(SOCK *sock);
void FreeSocketTimeout(SOCKET_TIMEOUT_PARAM *ttp);

bool CheckSubnetLength6(UINT i);
bool IsIP6(IP *ip);
bool IsIP4(IP *ip);
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr);
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip);
void SetIP6(IP *ip, UCHAR *value);
void GetLocalHostIP6(IP *ip);
void ZeroIP6(IP *ip);
void ZeroIP4(IP *ip);
bool CheckIPItemStr6(char *str);
void IPItemStrToChars6(UCHAR *chars, char *str);
bool StrToIP6(IP *ip, char *str);
bool StrToIP6Addr(IPV6_ADDR *ip, char *str);
void IPToStr6(char *str, UINT size, IP *ip);
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr);
void IPToStr6Array(char *str, UINT size, UCHAR *bytes);
void IPToStr6Inner(char *str, IP *ip);
void IntToSubnetMask6(IP *ip, UINT i);
void IPNot6(IP *dst, IP *a);
void IPOr6(IP *dst, IP *a, IP *b);
void IPAnd6(IP *dst, IP *a, IP *b);
void GetAllRouterMulticastAddress6(IP *ip);
void GetAllNodeMulticaseAddress6(IP *ip);
void GetLoopbackAddress6(IP *ip);
void GetAllFilledAddress6(IP *ip);
UINT GetIPAddrType6(IP *ip);
UINT GetIPv6AddrType(IPV6_ADDR *addr);
void GenerateMulticastMacAddress6(UCHAR *mac, IP *ip);
void GetSoliciationMulticastAddr6(IP *dst, IP *src);
bool CheckUnicastAddress(IP *ip);
bool IsNetworkPrefixAddress6(IP *ip, IP *subnet);
bool IsNetworkAddress6(IP *ip, IP *subnet);
void GetHostAddress6(IP *dst, IP *ip, IP *subnet);
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet);
bool IsNetworkPrefixAddress6(IP *ip, IP *subnet);
bool IsInSameNetwork6(IP *a1, IP *a2, IP *subnet);
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac);
void GenerateEui64LocalAddress(IP *a, UCHAR *mac);
void GenerateEui64GlobalAddress(IP *ip, IP *prefix, IP *subnet, UCHAR *mac);
bool IsSubnetMask6(IP *a);
UINT SubnetMaskToInt(IP *a);
UINT SubnetMaskToInt6(IP *a);
UINT SubnetMaskToInt4(IP *a);
bool IsStrIPv6Address(char *str);

bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndSubnetMask6(char *src, IP *ip, IP *mask);
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask);
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndMask6(char *src, IP *ip, IP *mask);
bool ParseIpAndMask46(char *src, IP *ip, IP *mask);
bool IsIpStr4(char *str);
bool IsIpStr6(char *str);
bool IsIpMask6(char *str);
bool IsIpStr46(char *str);
bool StrToMask4(IP *mask, char *str);
bool StrToMask6(IP *mask, char *str);
bool StrToMask6Addr(IPV6_ADDR *mask, char *str);
bool StrToMask46(IP *mask, char *str, bool ipv6);
void MaskToStr(char *str, UINT size, IP *mask);
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address);
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask);
void MaskToStr32(char *str, UINT size, UINT mask);
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address);
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address);


#endif	// NETWORK_H

