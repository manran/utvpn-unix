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

// Virtual.h
// Virtual.c のヘッダ

#ifndef	VIRTUAL_H
#define	VIRTUAL_H


// ARP エントリ
struct ARP_ENTRY
{
	UINT IpAddress;					// IP アドレス
	UCHAR MacAddress[6];			// MAC アドレス
	UCHAR Padding[2];
	UINT64 Created;					// 作成日時
	UINT64 Expire;					// 有効期限
};

// ARP 待機リスト
struct ARP_WAIT
{
	UINT IpAddress;					// 解決しようとしている IP アドレス
	UINT NextTimeoutTimeValue;		// 次にタイムアウトするまでの時間
	UINT64 TimeoutTime;				// 現在の送信のタイムアウト時刻
	UINT64 GiveupTime;				// 送信を諦める時刻
};

// IP 待機リスト
struct IP_WAIT
{
	UINT DestIP;					// 宛先 IP アドレス
	UINT SrcIP;						// 送信元 IP アドレス
	UINT64 Expire;					// 保管期限
	void *Data;						// データ
	UINT Size;						// サイズ
};

// IP 部分リスト
struct IP_PART
{
	UINT Offset;					// オフセット
	UINT Size;						// サイズ
};

// IP 復元リスト
struct IP_COMBINE
{
	UINT DestIP;					// 宛先 IP アドレス
	UINT SrcIP;						// 送信元 IP アドレス
	USHORT Id;						// IP パケット ID
	UINT64 Expire;					// 保管期限
	void *Data;						// パケットデータ
	UINT DataReserved;				// データ用に確保された領域
	UINT Size;						// パケットサイズ (トータル)
	LIST *IpParts;					// IP 部分リスト
	UCHAR Protocol;					// プロトコル番号
	bool MacBroadcast;				// MAC レベルでのブロードキャストパケット
};

#define	IP_COMBINE_INITIAL_BUF_SIZE		(MAX_IP_DATA_SIZE)		// 初期バッファサイズ

// NAT セッションテーブル
struct NAT_ENTRY
{
	// TCP | UDP 共通項目
	struct VH *v;					// 仮想マシン
	UINT Id;						// ID
	LOCK *lock;						// ロック
	UINT Protocol;					// プロトコル
	UINT SrcIp;						// 接続元 IP アドレス
	UINT SrcPort;					// 接続元ポート番号
	UINT DestIp;					// 接続先 IP アドレス
	UINT DestPort;					// 接続先ポート番号
	UINT PublicIp;					// 公衆 IP アドレス
	UINT PublicPort;				// 公衆ポート番号
	UINT64 CreatedTime;				// 接続時刻
	UINT64 LastCommTime;			// 最終通信時刻
	SOCK *Sock;						// ソケット
	bool DisconnectNow;				// すぐに停止せよフラグ
	UINT tag1;
	bool ProxyDns;					// プロキシ DNS
	UINT DestIpProxy;				// プロキシ DNS アドレス

	// DNS NAT 項目
	THREAD *DnsThread;				// DNS 問い合わせ用スレッド
	bool DnsGetIpFromHost;			// 逆引きフラグ
	char *DnsTargetHostName;		// ターゲットホスト名
	IP DnsResponseIp;				// 応答 IP アドレス
	char *DnsResponseHostName;		// 応答ホスト名
	UINT DnsTransactionId;			// DNS トランザクション ID
	bool DnsFinished;				// DNS 問い合わせ完了フラグ
	bool DnsOk;						// DNS 成功フラグ
	bool DnsPollingFlag;			// DNS ポーリング完了フラグ

	// UDP 項目
	QUEUE *UdpSendQueue;			// UDP 送信キュー
	QUEUE *UdpRecvQueue;			// UDP 受信キュー
	bool UdpSocketCreated;			// UDP のソケットが作成されたかどうか

	// TCP 項目
	FIFO *SendFifo;					// 送信 FIFO
	FIFO *RecvFifo;					// 受信 FIFO
	UINT TcpStatus;					// TCP 状態
	THREAD *NatTcpConnectThread;	// TCP ソケット接続スレッド
	bool TcpMakeConnectionFailed;	// 接続スレッドによる接続に失敗した
	bool TcpMakeConnectionSucceed;	// 接続スレッドによる接続に成功した
	UINT TcpSendMaxSegmentSize;		// 最大送信セグメントサイズ
	UINT TcpRecvMaxSegmentSize;		// 最大受信セグメントサイズ
	UINT64 LastSynAckSentTime;		// 最後に SYN + ACK を送信した時刻
	UINT SynAckSentCount;			// SYN + ACK 送信回数
	UINT TcpSendWindowSize;			// 送信ウインドウサイズ
	UINT TcpSendCWnd;				// 送信用輻輳ウインドウサイズ (/mss)
	UINT TcpRecvWindowSize;			// 受信ウインドウサイズ
	UINT TcpSendTimeoutSpan;		// 送信タイムアウト時間
	UINT64 TcpLastSentTime;			// TCP で最後に送信を行った時刻
	UINT64 LastSentKeepAliveTime;	// 最後にキープアライブ ACK を送信した時刻
	FIFO *TcpRecvWindow;			// TCP 受信ウインドウ
	LIST *TcpRecvList;				// TCP 受信リスト
	bool SendAckNext;				// 次の送信時に ACK を送信する
	UINT LastSentWindowSize;		// 最後に送信した自分のウインドウサイズ

	UINT64 SendSeqInit;				// 初期送信シーケンス番号
	UINT64 SendSeq;					// 送信シーケンス番号
	UINT64 RecvSeqInit;				// 初期受信シーケンス番号
	UINT64 RecvSeq;					// 受信シーケンス番号

	bool CurrentSendingMission;		// バースト送信実施中
	UINT SendMissionSize;			// 今回の送信サイズ
	bool RetransmissionUsedFlag;	// 再送信使用記録フラグ

	UINT CurrentRTT;				// 現在の RTT 値
	UINT64 CalcRTTStartTime;		// RTT 測定開始時刻
	UINT64 CalcRTTStartValue;		// RTT 測定開始値

	bool TcpFinished;				// TCP のデータ通信終了フラグ
	UINT64 FinSentTime;				// 最後に FIN を送信した時刻
	UINT FinSentCount;				// FIN 送信回数
};


// TCP オプション
struct TCP_OPTION
{
	UINT MaxSegmentSize;			// 最大セグメントサイズ
	UINT WindowScaling;				// ウインドウスケーリング
};

// 仮想ホスト構造体
struct VH
{
	REF *ref;						// 参照カウンタ
	LOCK *lock;						// ロック
	SESSION *Session;				// セッション
	CANCEL *Cancel;					// キャンセルオブジェクト
	QUEUE *SendQueue;				// 送信キュー
	bool Active;					// アクティブフラグ
	volatile bool HaltNat;			// NAT 停止フラグ
	LIST *ArpTable;					// ARP テーブル
	LIST *ArpWaitTable;				// ARP 待ちテーブル
	LIST *IpWaitTable;				// IP 待ちテーブル
	LIST *IpCombine;				// IP 結合テーブル
	UINT64 Now;						// 現在時刻
	UINT64 NextArpTablePolling;		// 次に ARP テーブルをポーリングする時刻
	UINT Mtu;						// MTU 値
	UINT IpMss;						// IP 最大データサイズ
	UINT TcpMss;					// TCP 最大データサイズ
	UINT UdpMss;					// UDP 最大データサイズ
	bool flag1;						// フラグ 1
	bool flag2;						// フラグ 2
	USHORT NextId;					// IP パケットの ID
	UINT CurrentIpQuota;			// IP パケットメモリクォータ
	LIST *NatTable;					// NAT テーブル
	SOCK_EVENT *SockEvent;			// ソケットイベント
	THREAD *NatThread;				// NAT 用スレッド
	void *TmpBuf;					// 一時的に使用できるバッファ
	bool NatDoCancelFlag;			// キャンセルを叩くかどうかのフラグ
	UCHAR MacAddress[6];			// MAC アドレス
	UCHAR Padding[2];
	UINT HostIP;					// ホスト IP
	UINT HostMask;					// ホストサブネットマスク
	UINT NatTcpTimeout;				// NAT TCP タイムアウト秒数
	UINT NatUdpTimeout;				// NAT UDP タイムアウト秒数
	bool UseNat;					// NAT 使用フラグ
	bool UseDhcp;					// DHCP 使用フラグ
	UINT DhcpIpStart;				// 配布開始アドレス
	UINT DhcpIpEnd;					// 配布終了アドレス
	UINT DhcpMask;					// サブネットマスク
	UINT DhcpExpire;				// アドレス配布有効期限
	UINT DhcpGateway;				// ゲートウェイアドレス
	UINT DhcpDns;					// DNS サーバーアドレス
	char DhcpDomain[MAX_HOST_NAME_LEN + 1];	// 割り当てドメイン名
	LIST *DhcpLeaseList;			// DHCP リースリスト
	UINT64 LastDhcpPolling;			// 最後に DHCP リストをポーリングした時刻
	bool SaveLog;					// ログの保存
	COUNTER *Counter;				// セッションカウンタ
	UINT DhcpId;					// DHCP ID
	UINT64 LastSendBeacon;			// 最後にビーコンを発信した時刻
	LOG *Logger;					// ロガー
	NAT *nat;						// NAT オブジェクトへの参照
};

// 仮想ホストオプション
struct VH_OPTION
{
	char HubName[MAX_HUBNAME_LEN + 1];	// 操作対象の仮想 HUB 名
	UCHAR MacAddress[6];			// MAC アドレス
	UCHAR Padding[2];
	IP Ip;							// IP アドレス
	IP Mask;						// サブネットマスク
	bool UseNat;					// NAT 機能の使用フラグ
	UINT Mtu;						// MTU 値
	UINT NatTcpTimeout;				// NAT TCP タイムアウト秒数
	UINT NatUdpTimeout;				// NAT UDP タイムアウト秒数
	bool UseDhcp;					// DHCP 機能の使用フラグ
	IP DhcpLeaseIPStart;			// DHCP 配布 IP 開始アドレス
	IP DhcpLeaseIPEnd;				// DHCP 配布 IP 終了アドレス
	IP DhcpSubnetMask;				// DHCP サブネットマスク
	UINT DhcpExpireTimeSpan;		// DHCP 有効期限
	IP DhcpGatewayAddress;			// 割り当てゲートウェイアドレス
	IP DhcpDnsServerAddress;		// 割り当て DNS サーバーアドレス
	char DhcpDomainName[MAX_HOST_NAME_LEN + 1];	// 割り当てドメイン名
	bool SaveLog;					// ログの保存
};

// DHCP オプション
struct DHCP_OPTION
{
	UINT Id;						// ID
	UINT Size;						// サイズ
	void *Data;						// データ
};

// DHCP オプションリスト
struct DHCP_OPTION_LIST
{
	// 共通項目
	UINT Opcode;					// DHCP オペコード

	// クライアント要求
	UINT RequestedIp;				// 要求された IP アドレス
	char Hostname[MAX_HOST_NAME_LEN + 1]; // ホスト名

	// サーバー応答
	UINT ServerAddress;				// DHCP サーバーアドレス
	UINT LeaseTime;					// リース時間
	char DomainName[MAX_HOST_NAME_LEN + 1];	// ドメイン名
	UINT SubnetMask;				// サブネットマスク
	UINT Gateway;					// ゲートウェイアドレス
	UINT DnsServer;					// DNS サーバーアドレス
};


// DHCP リース エントリ
struct DHCP_LEASE
{
	UINT Id;						// ID
	UINT64 LeasedTime;				// リースした時刻
	UINT64 ExpireTime;				// 有効期限
	UCHAR MacAddress[6];			// MAC アドレス
	UCHAR Padding[2];				// Padding
	UINT IpAddress;					// IP アドレス
	UINT Mask;						// サブネットマスク
	char *Hostname;					// ホスト名
};

// DNS 問い合わせ
typedef struct NAT_DNS_QUERY
{
	REF *ref;						// 参照カウンタ
	char Hostname[256];				// ホスト名
	bool Ok;						// 結果の成功フラグ
	IP Ip;							// 結果 IP アドレス
} NAT_DNS_QUERY;


// 仮想ホストの仮想 LAN カード
PACKET_ADAPTER *VirtualGetPacketAdapter();
bool VirtualPaInit(SESSION *s);
CANCEL *VirtualPaGetCancel(SESSION *s);
UINT VirtualPaGetNextPacket(SESSION *s, void **data);
bool VirtualPaPutPacket(SESSION *s, void *data, UINT size);
void VirtualPaFree(SESSION *s);

bool VirtualInit(VH *v);
UINT VirtualGetNextPacket(VH *v, void **data);
bool VirtualPutPacket(VH *v, void *data, UINT size);
void Virtual_Free(VH *v);

VH *NewVirtualHost(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option);
VH *NewVirtualHostEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option, NAT *nat);
void LockVirtual(VH *v);
void UnlockVirtual(VH *v);
void ReleaseVirtual(VH *v);
void CleanupVirtual(VH *v);
void StopVirtualHost(VH *v);
void SetVirtualHostOption(VH *v, VH_OPTION *vo);
void GenMacAddress(UCHAR *mac);
void GetVirtualHostOption(VH *v, VH_OPTION *o);

void VirtualLayer2(VH *v, PKT *packet);
bool VirtualLayer2Filter(VH *v, PKT *packet);
void VirtualArpReceived(VH *v, PKT *packet);
void VirtualArpResponseRequest(VH *v, PKT *packet);
void VirtualArpResponseReceived(VH *v, PKT *packet);
void VirtualArpSendResponse(VH *v, UCHAR *dest_mac, UINT dest_ip, UINT src_ip);
void VirtualArpSendRequest(VH *v, UINT dest_ip);
void VirtualIpSend(VH *v, UCHAR *dest_mac, void *data, UINT size);
void VirtualLayer2Send(VH *v, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size);
void VirtualPolling(VH *v);
void InitArpTable(VH *v);
void FreeArpTable(VH *v);
int CompareArpTable(void *p1, void *p2);
ARP_ENTRY *SearchArpTable(VH *v, UINT ip);
void RefreshArpTable(VH *v);
void PollingArpTable(VH *v);
void InsertArpTable(VH *v, UCHAR *mac, UINT ip);
bool IsMacBroadcast(UCHAR *mac);
bool IsMacInvalid(UCHAR *mac);
void InitArpWaitTable(VH *v);
void FreeArpWaitTable(VH *v);
int CompareArpWaitTable(void *p1, void *p2);
ARP_WAIT *SearchArpWaitTable(VH *v, UINT ip);
void DeleteArpWaitTable(VH *v, UINT ip);
void SendArp(VH *v, UINT ip);
void InsertArpWaitTable(VH *v, ARP_WAIT *w);
void PollingArpWaitTable(VH *v);
void ArpIpWasKnown(VH *v, UINT ip, UCHAR *mac);
void InitIpWaitTable(VH *v);
void FreeIpWaitTable(VH *v);
void InsertIpWaitTable(VH *v, UINT dest_ip, UINT src_ip, void *data, UINT size);
void SendFragmentedIp(VH *v, UINT dest_ip, UINT src_ip, USHORT id, USHORT total_size, USHORT offset, UCHAR protocol, void *data, UINT size, UCHAR *dest_mac);
void SendIp(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size);
void PollingIpWaitTable(VH *v);
void DeleteOldIpWaitTable(VH *v);
void SendWaitingIp(VH *v, UCHAR *mac, UINT dest_ip);
void VirtualIpReceived(VH *v, PKT *packet);
void InitIpCombineList(VH *v);
void FreeIpCombineList(VH *v);
int CompareIpCombine(void *p1, void *p2);
void CombineIp(VH *v, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet);
void IpReceived(VH *v, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size, bool mac_broadcast);
void FreeIpCombine(VH *v, IP_COMBINE *c);
void PollingIpCombine(VH *v);
IP_COMBINE *InsertIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast);
IP_COMBINE *SearchIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol);
USHORT IpChecksum(void *buf, UINT size);
bool IpCheckChecksum(IPV4_HEADER *ip);
void VirtualIcmpReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size);
void VirtualIcmpEchoRequestReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size);
void VirtualIcmpEchoSendResponse(VH *v, UINT src_ip, UINT dst_ip, USHORT id, USHORT seq_no, void *data, UINT size);
void VirtualIcmpSend(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size);
void VirtualUdpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, bool mac_broadcast);
void SendUdp(VH *v, UINT dest_ip, UINT dest_port, UINT src_ip, UINT src_port, void *data, UINT size);
UINT GetNetworkAddress(UINT addr, UINT mask);
UINT GetBroadcastAddress(UINT addr, UINT mask);
bool IsInNetwork(UINT uni_addr, UINT network_addr, UINT mask);
void UdpRecvForMe(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvForBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy);
void InitNat(VH *v);
void FreeNat(VH *v);
int CompareNat(void *p1, void *p2);
NAT_ENTRY *SearchNat(VH *v, NAT_ENTRY *target);
void SetNat(NAT_ENTRY *n, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT public_ip, UINT public_port);
void DeleteNatTcp(VH *v, NAT_ENTRY *n);
void DeleteNatUdp(VH *v, NAT_ENTRY *n);
NAT_ENTRY *CreateNatUdp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT dns_proxy_ip);
void NatThread(THREAD *t, void *param);
void NatThreadMain(VH *v);
bool NatTransactUdp(VH *v, NAT_ENTRY *n);
void PoolingNat(VH *v);
void PoolingNatUdp(VH *v, NAT_ENTRY *n);
void VirtualTcpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size);
void TcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *tcp, void *data, UINT size);
NAT_ENTRY *CreateNatTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port);
bool NatTransactTcp(VH *v, NAT_ENTRY *n);
void CreateNatTcpConnectThread(VH *v, NAT_ENTRY *n);
void NatTcpConnectThread(THREAD *t, void *p);
void PollingNatTcp(VH *v, NAT_ENTRY *n);
void ParseTcpOption(TCP_OPTION *o, void *data, UINT size);
void SendTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss, void *data, UINT size);
void DnsProxy(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
bool ParseDnsPacket(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
bool ParseDnsQuery(char *name, UINT name_size, void *data, UINT data_size);
UCHAR GetNextByte(BUF *b);
bool NatTransactDns(VH *v, NAT_ENTRY *n);
void NatDnsThread(THREAD *t, void *param);
bool NatGetIP(IP *ip, char *hostname);
void NatGetIPThread(THREAD *t, void *param);
NAT_ENTRY *CreateNatDns(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port,
				  UINT transaction_id, bool dns_get_ip_from_host, char *dns_target_host_name);
void PollingNatDns(VH *v, NAT_ENTRY *n);
void SendNatDnsResponse(VH *v, NAT_ENTRY *n);
void BuildDnsQueryPacket(BUF *b, char *hostname, bool ptr);
void BuildDnsResponsePacketA(BUF *b, IP *ip);
void BuildDnsResponsePacketPtr(BUF *b, char *hostname);
bool ArpaToIP(IP *ip, char *str);
BUF *BuildDnsHostName(char *hostname);
bool CanCreateNewNatEntry(VH *v);
void VirtualDhcpServer(VH *v, PKT *p);
LIST *ParseDhcpOptions(void *data, UINT size);
void FreeDhcpOptions(LIST *o);
DHCP_OPTION *GetDhcpOption(LIST *o, UINT id);
DHCP_OPTION_LIST *ParseDhcpOptionList(void *data, UINT size);
void InitDhcpServer(VH *v);
void FreeDhcpServer(VH *v);
void PollingDhcpServer(VH *v);
int CompareDhcpLeaseList(void *p1, void *p2);
DHCP_LEASE *NewDhcpLease(UINT expire, UCHAR *mac_address, UINT ip, UINT mask, char *hostname);
void FreeDhcpLease(DHCP_LEASE *d);
DHCP_LEASE *SearchDhcpLeaseByMac(VH *v, UCHAR *mac);
DHCP_LEASE *SearchDhcpLeaseByIp(VH *v, UINT ip);
UINT ServeDhcpDiscover(VH *v, UCHAR *mac, UINT request_ip);
UINT GetFreeDhcpIpAddress(VH *v);
UINT ServeDhcpRequest(VH *v, UCHAR *mac, UINT request_ip);
LIST *BuildDhcpOption(DHCP_OPTION_LIST *opt);
DHCP_OPTION *NewDhcpOption(UINT id, void *data, UINT size);
BUF *BuildDhcpOptionsBuf(LIST *o);
void VirtualDhcpSend(VH *v, UINT tran_id, UINT dest_ip, UINT dest_port,
					 UINT new_ip, UCHAR *client_mac, BUF *b);
void VLog(VH *v, char *str);
void SendBeacon(VH *v);
void PollingBeacon(VH *v);


#endif	// VIRTUAL_H


