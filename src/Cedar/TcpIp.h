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

// TcpIp.h
// TcpIp.c のヘッダ

#ifndef	TCPIP_H
#define	TCPIP_H

#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

// MAC ヘッダ
struct MAC_HEADER
{
	UCHAR	DestAddress[6];			// 送信元 MAC アドレス
	UCHAR	SrcAddress[6];			// 宛先 MAC アドレス
	USHORT	Protocol;				// プロトコル
} GCC_PACKED;

// MAC プロトコル
#define	MAC_PROTO_ARPV4		0x0806	// ARPv4 パケット
#define	MAC_PROTO_IPV4		0x0800	// IPv4 パケット
#define	MAC_PROTO_IPV6		0x86dd	// IPv6 パケット
#define	MAC_PROTO_TAGVLAN	0x8100	// タグ付き VLAN パケット

// LLC ヘッダ
struct LLC_HEADER
{
	UCHAR	Dsap;
	UCHAR	Ssap;
	UCHAR	Ctl;
} GCC_PACKED;

// LLC ヘッダの DSAP, SSAP の値
#define	LLC_DSAP_BPDU		0x42
#define	LLC_SSAP_BPDU		0x42

// BPDU ヘッダ
struct BPDU_HEADER
{
	USHORT	ProtocolId;				// プロトコル ID (STP == 0x0000)
	UCHAR	Version;				// バージョン
	UCHAR	Type;					// 種類
	UCHAR	Flags;					// フラグ
	USHORT	RootPriority;			// ルートブリッジのプライオリティ
	UCHAR	RootMacAddress[6];		// ルートブリッジの MAC アドレス
	UINT	RootPathCost;			// ルートブリッジまでのパスコスト
	USHORT	BridgePriority;			// 発信ブリッジのプライオリティ
	UCHAR	BridgeMacAddress[6];	// 発信ブリッジの MAC アドレス
	USHORT	BridgePortId;			// 発信ブリッジのポート ID
	USHORT	MessageAge;				// 有効期限
	USHORT	MaxAge;					// 最大有効期限
	USHORT	HelloTime;				// Hello Time
	USHORT	ForwardDelay;			// Forward Delay
} GCC_PACKED;

// ARPv4 ヘッダ
struct ARPV4_HEADER
{
	USHORT	HardwareType;			// ハードウェアタイプ
	USHORT	ProtocolType;			// プロトコルタイプ
	UCHAR	HardwareSize;			// ハードウェアサイズ
	UCHAR	ProtocolSize;			// プロトコルサイズ
	USHORT	Operation;				// オペレーション
	UCHAR	SrcAddress[6];			// 送信元 MAC アドレス
	UINT	SrcIP;					// 送信元 IP アドレス
	UCHAR	TargetAddress[6];		// ターゲット MAC アドレス
	UINT	TargetIP;				// ターゲット IP アドレス
} GCC_PACKED;

// ARP ハードウェア種類
#define	ARP_HARDWARE_TYPE_ETHERNET		0x0001

// ARP オペレーション種類
#define	ARP_OPERATION_REQUEST			1
#define	ARP_OPERATION_RESPONSE			2

// タグ付き VLAN ヘッダ
struct TAGVLAN_HEADER
{
	UCHAR Data[2];					// データ
} GCC_PACKED;

// IPv4 ヘッダ
struct IPV4_HEADER
{
	UCHAR	VersionAndHeaderLength;		// バージョンとヘッダサイズ
	UCHAR	TypeOfService;				// サービスタイプ
	USHORT	TotalLength;				// 合計サイズ
	USHORT	Identification;				// 識別子
	UCHAR	FlagsAndFlagmentOffset[2];	// フラグとフラグメントオフセット
	UCHAR	TimeToLive;					// TTL
	UCHAR	Protocol;					// プロトコル
	USHORT	Checksum;					// チェックサム
	UINT	SrcIP;						// 送信元 IP アドレス
	UINT	DstIP;						// 宛先 IP アドレス
} GCC_PACKED;

// IPv4 ヘッダ操作用マクロ
#define	IPV4_GET_VERSION(h)			(((h)->VersionAndHeaderLength >> 4 & 0x0f))
#define	IPV4_SET_VERSION(h, v)		((h)->VersionAndHeaderLength |= (((v) & 0x0f) << 4))
#define	IPV4_GET_HEADER_LEN(h)		((h)->VersionAndHeaderLength & 0x0f)
#define	IPV4_SET_HEADER_LEN(h, v)	((h)->VersionAndHeaderLength |= ((v) & 0x0f))

// IPv4 フラグメント関係操作用マクロ
#define	IPV4_GET_FLAGS(h)			(((h)->FlagsAndFlagmentOffset[0] >> 5) & 0x07)
#define	IPV4_SET_FLAGS(h, v)		((h)->FlagsAndFlagmentOffset[0] |= (((v) & 0x07) << 5))
#define	IPV4_GET_OFFSET(h)			(((h)->FlagsAndFlagmentOffset[0] & 0x1f) * 256 + ((h)->FlagsAndFlagmentOffset[1]))
#define	IPV4_SET_OFFSET(h, v)		{(h)->FlagsAndFlagmentOffset[0] |= (UCHAR)((v) / 256); (h)->FlagsAndFlagmentOffset[1] = (UCHAR)((v) % 256);}

// IPv4 プロトコル
#define	IP_PROTO_ICMPV4		0x01	// ICMPv4 プロトコル

// IPv6 プロトコル
#define	IP_PROTO_ICMPV6		0x3a	// ICMPv6 プロトコル

// IPv4 / IPv6 共通プロトコル
#define	IP_PROTO_TCP		0x06	// TCP プロトコル
#define	IP_PROTO_UDP		0x11	// UDP プロトコル


// UDP ヘッダ
struct UDP_HEADER
{
	USHORT	SrcPort;					// 送信元ポート番号
	USHORT	DstPort;					// 宛先ポート番号
	USHORT	PacketLength;			// データ長
	USHORT	Checksum;				// チェックサム
} GCC_PACKED;

// UDPv4 擬似ヘッダ
struct UDPV4_PSEUDO_HEADER
{
	UINT	SrcIP;					// 送信元 IP アドレス
	UINT	DstIP;					// 宛先 IP アドレス
	UCHAR	Reserved;				// 未使用
	UCHAR	Protocol;				// プロトコル番号
	USHORT	PacketLength1;			// UDP データ長 1
	USHORT	SrcPort;					// 送信元ポート番号
	USHORT	DstPort;					// 宛先ポート番号
	USHORT	PacketLength2;			// UDP データ長 2
	USHORT	Checksum;				// チェックサム
} GCC_PACKED;

// TCPv4 擬似ヘッダ
struct TCPV4_PSEUDO_HEADER
{
	UINT	SrcIP;					// 送信元 IP アドレス
	UINT	DstIP;					// 宛先 IP アドレス
	UCHAR	Reserved;				// 未使用
	UCHAR	Protocol;				// プロトコル番号
	USHORT	PacketLength;			// UDP データ長 1
} GCC_PACKED;

// TCP ヘッダ
struct TCP_HEADER
{
	USHORT	SrcPort;					// 送信元ポート番号
	USHORT	DstPort;					// 宛先ポート番号
	UINT	SeqNumber;				// シーケンス番号
	UINT	AckNumber;				// 確認応答番号
	UCHAR	HeaderSizeAndReserved;	// ヘッダサイズと予約領域
	UCHAR	Flag;					// フラグ
	USHORT	WindowSize;				// ウインドウサイズ
	USHORT	Checksum;				// チェックサム
	USHORT	UrgentPointer;			// 緊急ポインタ
} GCC_PACKED;

// TCP マクロ
#define	TCP_GET_HEADER_SIZE(h)	(((h)->HeaderSizeAndReserved >> 4) & 0x0f)
#define	TCP_SET_HEADER_SIZE(h, v)	((h)->HeaderSizeAndReserved = (((v) & 0x0f) << 4))

// TCP フラグ
#define	TCP_FIN						1
#define	TCP_SYN						2
#define	TCP_RST						4
#define	TCP_PSH						8
#define	TCP_ACK						16
#define	TCP_URG						32

// ICMP ヘッダ
struct ICMP_HEADER
{
	UCHAR	Type;					// タイプ
	UCHAR	Code;					// コード
	USHORT	Checksum;				// チェックサム
} GCC_PACKED;

#define	ICMP_TYPE_ECHO_REQUEST		8		// ICMP Echo 要求
#define	ICMP_TYPE_ECHO_RESPONSE		0		// ICMP Echo 応答

// ICMP Echo
struct ICMP_ECHO
{
	USHORT	Identifier;						// ID
	USHORT	SeqNo;							// シーケンス番号
} GCC_PACKED;

// DHCPv4 ヘッダ
struct DHCPV4_HEADER
{
	UCHAR	OpCode;				// オペコード
	UCHAR	HardwareType;		// ハードウェア種類
	UCHAR	HardwareAddressSize;	// ハードウェアアドレスサイズ
	UCHAR	Hops;				// ホップ数
	UINT	TransactionId;		// トランザクション ID
	USHORT	Seconds;				// 秒数
	USHORT	Flags;				// フラグ
	UINT	ClientIP;			// クライアント IP アドレス
	UINT	YourIP;				// 割り当て IP アドレス
	UINT	ServerIP;			// サーバー IP アドレス
	UINT	RelayIP;				// リレー IP アドレス
	UCHAR	ClientMacAddress[6];	// クライアント MAC アドレス
	UCHAR	Padding[10];			// Ethernet 以外のためにパディング
} GCC_PACKED;

// DNSv4 ヘッダ
struct DNSV4_HEADER
{
	USHORT	TransactionId;			// トランザクション ID
	UCHAR	Flag1;					// フラグ 1
	UCHAR	Flag2;					// フラグ 2
	USHORT	NumQuery;				// クエリ数
	USHORT	AnswerRRs;				// 回答 RR 数
	USHORT	AuthorityRRs;			// 権威 RR 数
	USHORT	AdditionalRRs;			// 追加 RR 数
} GCC_PACKED;

#define	DHCP_MAGIC_COOKIE	0x63825363	// Magic Cookie (固定)

// IPv6 ヘッダパケット情報
struct IPV6_HEADER_PACKET_INFO
{
	IPV6_HEADER *IPv6Header;					// IPv6 ヘッダ
	IPV6_OPTION_HEADER *HopHeader;				// ホップバイホップオプションヘッダ
	UINT HopHeaderSize;							// ホップバイホップオプションヘッダサイズ
	IPV6_OPTION_HEADER *EndPointHeader;			// 終点オプションヘッダ
	UINT EndPointHeaderSize;					// 終点オプションヘッダサイズ
	IPV6_OPTION_HEADER *RoutingHeader;			// ルーティングヘッダ
	UINT RoutingHeaderSize;						// ルーティングヘッダサイズ
	IPV6_FRAGMENT_HEADER *FragmentHeader;		// フラグメントヘッダ
	void *Payload;								// ペイロード
	UINT PayloadSize;							// ペイロードサイズ
	UCHAR Protocol;								// ペイロードプロトコル
	bool IsFragment;							// フラグメントパケットかどうか
};

// IPv6 ヘッダ
struct IPV6_HEADER
{
	UCHAR VersionAndTrafficClass1;		// バージョン番号 (4 bit) とトラフィッククラス 1 (4 bit)
	UCHAR TrafficClass2AndFlowLabel1;	// トラフィッククラス 2 (4 bit) とフローラベル 1 (4 bit)
	UCHAR FlowLabel2;					// フローラベル 2 (8 bit)
	UCHAR FlowLabel3;					// フローラベル 3 (8 bit)
	USHORT PayloadLength;				// ペイロードの長さ (拡張ヘッダを含む)
	UCHAR NextHeader;					// 次のヘッダ
	UCHAR HopLimit;						// ホップリミット
	IPV6_ADDR SrcAddress;				// ソースアドレス
	IPV6_ADDR DestAddress;				// 宛先アドレス
} GCC_PACKED;


// IPv6 ヘッダ操作用マクロ
#define IPV6_GET_VERSION(h)			(((h)->VersionAndTrafficClass1 >> 4) & 0x0f)
#define IPV6_SET_VERSION(h, v)		((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0x0f) | ((v) << 4) & 0xf0)
#define IPV6_GET_TRAFFIC_CLASS(h)	((((h)->VersionAndTrafficClass1 << 4) & 0xf0) | ((h)->TrafficClass2AndFlowLabel1 >> 4) & 0x0f)
#define	IPV6_SET_TRAFFIC_CLASS(h, v)	((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0xf0) | (((v) >> 4) & 0x0f),\
	(h)->TrafficClass2AndFlowLabel1 = (h)->TrafficClass2AndFlowLabel1 & 0x0f | ((v) << 4) & 0xf0)
#define	IPV6_GET_FLOW_LABEL(h)		((((h)->TrafficClass2AndFlowLabel1 << 16) & 0xf0000) | (((h)->FlowLabel2 << 8) & 0xff00) |\
	(((h)->FlowLabel3) & 0xff))
#define IPV6_SET_FLOW_LABEL(h, v)	((h)->TrafficClass2AndFlowLabel1 = ((h)->TrafficClass2AndFlowLabel1 & 0xf0 | ((v) >> 16) & 0x0f),\
	(h)->FlowLabel2 = ((v) >> 8) & 0xff,\
	(h)->FlowLabel3 = (v) & 0xff)


// IPv6 ホップ最大値 (ルーティングしない)
#define IPV6_HOP_MAX					255

// IPv6 ホップ標準数
#define IPV6_HOP_DEFAULT				127

// IPv6 ヘッダ番号
#define IPV6_HEADER_HOP					0	// ホップバイホップオプションヘッダ
#define IPV6_HEADER_ENDPOINT			60	// 終点オプションヘッダ
#define IPV6_HEADER_ROUTING				43	// ルーティングヘッダ
#define IPV6_HEADER_FRAGMENT			44	// フラグメントヘッダ
#define IPV6_HEADER_NONE				59	// 次ヘッダ無し

// IPv6 オプションヘッダ
// (ホップオプションヘッダ、終点オプションヘッダ、ルーティングヘッダで使用される)
struct IPV6_OPTION_HEADER
{
	UCHAR NextHeader;					// 次のヘッダ
	UCHAR Size;							// ヘッダサイズ (/8)
} GCC_PACKED;

// IPv6 フラグメントヘッダ
// (フラグメント不可能部分は、ルーティングヘッダがある場合はその直前まで、
//  ホップバイホップオプションヘッダがある場合はその直前まで、
//  それ以外の場合は最初の拡張ヘッダもしくはペイロードの直前まで)
struct IPV6_FRAGMENT_HEADER
{
	UCHAR NextHeader;					// 次のヘッダ
	UCHAR Reserved;						// 予約
	UCHAR FlagmentOffset1;				// フラグメントオフセット 1 (/8, 8 bit)
	UCHAR FlagmentOffset2AndFlags;		// フラグメントオフセット 2 (/8, 5 bit) + 予約 (2 bit) + More フラグ (1 bit)
	UINT Identification;				// ID
} GCC_PACKED;

// IPv6 フラグメントヘッダ操作用マクロ
#define IPV6_GET_FRAGMENT_OFFSET(h)		(((((h)->FlagmentOffset1) << 5) & 0x1fe0) | (((h)->FlagmentOffset2AndFlags >> 3) & 0x1f))
#define IPV6_SET_FRAGMENT_OFFSET(h, v)	((h)->FlagmentOffset1 = (v / 32) & 0xff,	\
	((h)->FlagmentOffset2AndFlags = ((v % 256) << 3) & 0xf8) | ((h)->FlagmentOffset2AndFlags & 0x07))
#define IPV6_GET_FLAGS(h)				((h)->FlagmentOffset2AndFlags & 0x0f)
#define IPV6_SET_FLAGS(h, v)				((h)->FlagmentOffset2AndFlags = (((h)->FlagmentOffset2AndFlags & 0xf8) | (v & 0x07)))

// フラグ
#define IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS		0x01	// 次のフラグメントがある

// IPv6 仮想ヘッダ
struct IPV6_PSEUDO_HEADER
{
	IPV6_ADDR SrcAddress;				// ソースアドレス
	IPV6_ADDR DestAddress;				// 宛先アドレス
	UINT UpperLayerPacketSize;			// 上位レイヤのパケットサイズ
	UCHAR Padding[3];					// パディング
	UCHAR NextHeader;					// 次ヘッダ (TCP / UDP)
} GCC_PACKED;

// ICMPv6 ルータ要請ヘッダ
struct ICMPV6_ROUTER_SOLICIATION_HEADER
{
	UINT Reserved;							// 予約
	// + オプション (ソースリンクレイヤアドレス[任意])
} GCC_PACKED;

// ICMPv6 ルータ広告ヘッダ
struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER
{
	UCHAR CurHopLimit;						// デフォルトのホップリミット数
	UCHAR Flags;							// フラグ (0)
	USHORT Lifetime;						// 寿命
	UINT ReachableTime;						// 0
	UINT RetransTimer;						// 0
	// + オプション (プレフィックス情報[必須], MTU[任意])
} GCC_PACKED;

// ICMPv6 近隣要請ヘッダ
struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER
{
	UINT Reserved;							// 予約
	IPV6_ADDR TargetAddress;				// ターゲットアドレス
	// + オプション (ソースリンクレイヤアドレス[必須])
} GCC_PACKED;

// ICMPv6 近隣広告ヘッダ
struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER
{
	UCHAR Flags;							// フラグ
	UCHAR Reserved[3];						// 予約
	IPV6_ADDR TargetAddress;				// ターゲットアドレス
	// + オプション (ターゲットリンクレイヤアドレス)
} GCC_PACKED;

#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER		0x80	// ルータ
#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED	0x40	// 要請フラグ
#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERWRITE	0x20	// 上書きフラグ

// ICMPv6 オプションリスト
struct ICMPV6_OPTION_LIST
{
	ICMPV6_OPTION_LINK_LAYER *SourceLinkLayer;		// ソースリンクレイヤアドレス
	ICMPV6_OPTION_LINK_LAYER *TargetLinkLayer;		// ターゲットリンクレイヤアドレス
	ICMPV6_OPTION_PREFIX *Prefix;					// プレフィックス情報
	ICMPV6_OPTION_MTU *Mtu;							// MTU
} GCC_PACKED;

// ICMPv6 オプション
struct ICMPV6_OPTION
{
	UCHAR Type;								// タイプ
	UCHAR Length;							// 長さ (/8, タイプと長さを含める)
} GCC_PACKED;

#define	ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER	1		// ソースリンクレイヤアドレス
#define ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER	2		// ターゲットリンクレイヤアドレス
#define ICMPV6_OPTION_TYPE_PREFIX				3		// プレフィックス情報
#define ICMPV6_OPTION_TYPE_MTU					5		// MTU

// ICMPv6 リンクレイヤオプション
struct ICMPV6_OPTION_LINK_LAYER
{
	ICMPV6_OPTION IcmpOptionHeader;			// オプションヘッダ
	UCHAR Address[6];						// MAC アドレス
} GCC_PACKED;

// ICMPv6 プレフィックス情報オプション
struct ICMPV6_OPTION_PREFIX
{
	ICMPV6_OPTION IcmpOptionHeader;			// オプションヘッダ
	UCHAR SubnetLength;						// サブネット長
	UCHAR Flags;							// フラグ
	UINT ValidLifetime;						// 正式な寿命
	UINT PreferredLifetime;					// 望ましい寿命
	UINT Reserved;							// 予約
	IPV6_ADDR Prefix;						// プレフィックスアドレス
} GCC_PACKED;

#define ICMPV6_OPTION_PREFIX_FLAG_ONLINK		0x80	// リンク上
#define ICMPV6_OPTION_PREFIX_FLAG_AUTO			0x40	// 自動

// ICMPv6 MTU オプション
struct ICMPV6_OPTION_MTU
{
	ICMPV6_OPTION IcmpOptionHeader;			// オプションヘッダ
	USHORT Reserved;						// 予約
	UINT Mtu;								// MTU 値
} GCC_PACKED;


// IPv6 ヘッダ情報
struct IPV6_HEADER_INFO
{
	bool IsRawIpPacket;
	USHORT Size;
	UINT Id;
	UCHAR Protocol;
	UCHAR HopLimit;
	IPV6_ADDR SrcIpAddress;
	IPV6_ADDR DestIpAddress;
	bool UnicastForMe;
	bool UnicastForRouting;
	bool UnicastForRoutingWithProxyNdp;
	bool IsBroadcast;
	UINT TypeL4;
};

// ICMPv6 ヘッダ情報
struct ICMPV6_HEADER_INFO
{
	UCHAR Type;
	UCHAR Code;
	USHORT DataSize;
	void *Data;
	ICMP_ECHO EchoHeader;
	void *EchoData;
	UINT EchoDataSize;

	union
	{
		// Type の値によって意味が決まる
		ICMPV6_ROUTER_SOLICIATION_HEADER *RouterSoliciationHeader;
		ICMPV6_ROUTER_ADVERTISEMENT_HEADER *RouterAdvertisementHeader;
		ICMPV6_NEIGHBOR_SOLICIATION_HEADER *NeighborSoliciationHeader;
		ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *NeighborAdvertisementHeader;
		void *HeaderPointer;
	} Headers;

	ICMPV6_OPTION_LIST OptionList;
};

// ICMPv6 の Type の値
#define ICMPV6_TYPE_ECHO_REQUEST				128		// ICMPv6 Echo 要求
#define ICMPV6_TYPE_ECHO_RESPONSE				129		// ICMPv6 Echo 応答
#define ICMPV6_TYPE_ROUTER_SOLICIATION			133		// ルータ要請
#define ICMPV6_TYPE_ROUTER_ADVERTISEMENT		134		// ルータ広告
#define ICMPV6_TYPE_NEIGHBOR_SOLICIATION		135		// 近隣要請
#define ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT		136		// 近隣広告

// パケット
struct PKT
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	UCHAR			*PacketData;	// パケットデータ本体
	UINT			PacketSize;		// パケットサイズ
	MAC_HEADER		*MacHeader;		// MAC ヘッダ
	UCHAR			*MacAddressSrc;	// 送信元 MAC アドレス
	UCHAR			*MacAddressDest;	// 宛先 MAC アドレス
	bool			BroadcastPacket;		// ブロードキャストパケット
	bool			InvalidSourcePacket;	// ソースアドレスが不正なパケット
	bool			AccessChecked;	// アクセスリストで通過が確認されたパケット
	UINT			VlanTypeID;		// タグ付き VLAN の TypeID (通常は 0x8100)
	UINT			VlanId;			// VLAN ID
	UINT			Delay;			// 遅延
	UINT			Jitter;			// ジッタ
	UINT			Loss;			// パケットロス
	UINT64			DelayedForwardTick;	// 遅延した場合における送信時刻
	SESSION			*DelayedSrcSession;	// 送信元のセッション
	UINT			TypeL3;			// Layer-3 パケット分類
	IPV6_HEADER_PACKET_INFO IPv6HeaderPacketInfo;	// IPv6 ヘッダパケット情報 (TypeL3 == L3_IPV6 の場合のみ)
	ICMPV6_HEADER_INFO ICMPv6HeaderPacketInfo;		// ICMPv6 ヘッダ情報 (TypeL4 == L4_ICMPV6 の場合のみ)
	union
	{
		IPV4_HEADER		*IPv4Header;	// IPv4 ヘッダ
		ARPV4_HEADER	*ARPv4Header;	// ARPv4 ヘッダ
		IPV6_HEADER		*IPv6Header;	// IPv6 ヘッダ
		TAGVLAN_HEADER	*TagVlanHeader;	// タグヘッダ
		BPDU_HEADER		*BpduHeader;	// BPDU ヘッダ
		void			*PointerL3;
	} L3;
	UINT			TypeL4;				// Layer-4 パケット分類
	union
	{
		UDP_HEADER	*UDPHeader;			// UDP ヘッダ
		TCP_HEADER	*TCPHeader;			// TCP ヘッダ
		ICMP_HEADER	*ICMPHeader;		// ICMP ヘッダ
		void		*PointerL4;
	} L4;
	UINT			TypeL7;			// Layer-7 パケット分類
	union
	{
		DHCPV4_HEADER	*DHCPv4Header;	// DHCPv4 ヘッダ
		void			*PointerL7;
	} L7;
} GCC_PACKED;

// Layer-3 パケット分類
#define	L3_UNKNOWN			0		// 不明
#define	L3_ARPV4			1		// ARPv4 パケット
#define	L3_IPV4				2		// IPv4 パケット
#define	L3_TAGVLAN			3		// タグ付き VLAN パケット
#define	L3_BPDU				4		// BPDU パケット
#define L3_IPV6				5		// IPv6 パケット

// Layer-4 パケット分類
#define	L4_UNKNOWN			0		// 不明
#define	L4_UDP				1		// UDPv4 パケット
#define	L4_TCP				2		// TCPv4 パケット
#define	L4_ICMPV4			3		// ICMPv4 パケット
#define	L4_ICMPV6			4		// ICMPv6 パケット
#define	L4_FRAGMENT			5		// フラグメントパケット

// Layer-7 パケット分類
#define	L7_UNKNOWN			0		// 不明
#define	L7_DHCPV4			1		// DHCPv4 パケット


PKT *ParsePacket(UCHAR *buf, UINT size);
PKT *ParsePacketEx(UCHAR *buf, UINT size, bool no_l3);
PKT *ParsePacketEx2(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id);
PKT *ParsePacketEx3(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address);
void FreePacket(PKT *p);
void FreePacketIPv4(PKT *p);
void FreePacketTagVlan(PKT *p);
void FreePacketARPv4(PKT *p);
void FreePacketUDPv4(PKT *p);
void FreePacketTCPv4(PKT *p);
void FreePacketICMPv4(PKT *p);
void FreePacketDHCPv4(PKT *p);
bool ParsePacketL2(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3);
bool ParsePacketARPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketBPDU(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size);
bool ParseICMPv4(PKT *p, UCHAR *buf, UINT size);
bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size);
bool ParseTCP(PKT *p, UCHAR *buf, UINT size);
bool ParseUDP(PKT *p, UCHAR *buf, UINT size);
void ParseDHCPv4(PKT *p, UCHAR *buf, UINT size);
PKT *ClonePacket(PKT *p, bool copy_data);
void FreeClonePacket(PKT *p);

bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size);
bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size);
bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size);
void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src);
void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o);
USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size);
BUF *BuildICMPv6Options(ICMPV6_OPTION_LIST *o);
void BuildICMPv6OptionValue(BUF *b, UCHAR type, void *header_pointer, UINT total_size);
BUF *BuildIPv6(IPV6_ADDR *dest_ip, IPV6_ADDR *src_ip, UINT id, UCHAR protocol, UCHAR hop_limit, void *data,
			   UINT size);
BUF *BuildIPv6PacketHeader(IPV6_HEADER_PACKET_INFO *info, UINT *bytes_before_payload);
UCHAR IPv6GetNextHeaderFromQueue(QUEUE *q);
void BuildAndAddIPv6PacketOptionHeader(BUF *b, IPV6_OPTION_HEADER *opt, UCHAR next_header, UINT size);
BUF *BuildICMPv6NeighborSoliciation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address, UINT id);
BUF *BuildICMPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR hop_limit, UCHAR type, UCHAR code, void *data, UINT size, UINT id);

bool VLanRemoveTag(void **packet_data, UINT *packet_size, UINT vlan_id);
void VLanInsertTag(void **packet_data, UINT *packet_size, UINT vlan_id);

#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32

#endif	// TCPIP_H


