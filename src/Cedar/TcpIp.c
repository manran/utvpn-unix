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

// TcpIp.c
// TCP/IP プロトコル パケットアナライザ

#include "CedarPch.h"

// パケットに VLAN タグを埋め込む
void VLanInsertTag(void **packet_data, UINT *packet_size, UINT vlan_id)
{
	UINT dest_size;
	UCHAR *dest_data;
	UINT src_size;
	UCHAR *src_data;
	USHORT vlan_ushort = Endian16(((USHORT)vlan_id) & 0xFFF);
	// 引数チェック
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
		*packet_size < 14 || vlan_id == 0)
	{
		return;
	}

	src_size = *packet_size;
	src_data = (UCHAR *)(*packet_data);

	dest_size = src_size + 4;
	dest_data = Malloc(dest_size);

	dest_data[12] = 0x81;
	dest_data[13] = 0x00;
	Copy(&dest_data[14], &vlan_ushort, sizeof(USHORT));

	Copy(&dest_data[0], &src_data[0], 12);
	Copy(&dest_data[16], &src_data[12], src_size - 12);

	*packet_size = dest_size;
	*packet_data = dest_data;

	Free(src_data);
}

// パケットから VLAN タグを取り除く
bool VLanRemoveTag(void **packet_data, UINT *packet_size, UINT vlan_id)
{
	bool has_vlan_tag = false;
	UCHAR *src_data;
	UINT src_size;
	// 引数チェック
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
		*packet_size < 14)
	{
		return false;
	}

	src_data = (UCHAR *)(*packet_data);
	src_size = *packet_size;

	if (src_data[12] == 0x81 && src_data[13] == 0x00)
	{
		if (src_size >= 18)
		{
			USHORT vlan_ushort;

			vlan_ushort = Endian16(*((USHORT *)&src_data[14]));
			vlan_ushort = vlan_ushort & 0xFFF;

			if (vlan_id == 0 || (vlan_ushort == vlan_id))
			{
				UINT dest_size = src_size - 4;
				UINT i;

				for (i = 12;i < dest_size;i++)
				{
					src_data[i] = src_data[i + 4];
				}

				*packet_size = dest_size;

				return true;
			}
		}
	}

	return false;
}

// ICMPv6 パケットの送信
BUF *BuildICMPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR hop_limit, UCHAR type, UCHAR code, void *data, UINT size, UINT id)
{
	ICMP_HEADER *icmp;
	void *data_buf;
	BUF *ret;
	// 引数チェック
	if (src_ip == NULL || dest_ip == NULL || data == NULL)
	{
		return NULL;
	}

	// ヘッダの組み立て
	icmp = ZeroMalloc(sizeof(ICMP_HEADER) + size);
	data_buf = ((UCHAR *)icmp) + sizeof(ICMP_HEADER);
	Copy(data_buf, data, size);

	icmp->Type = type;
	icmp->Code = code;
	icmp->Checksum = CalcChecksumForIPv6(src_ip, dest_ip, IP_PROTO_ICMPV6, icmp,
		sizeof(ICMP_HEADER) + size);

	ret = BuildIPv6(dest_ip, src_ip, id, IP_PROTO_ICMPV6, hop_limit, icmp,
		sizeof(ICMP_HEADER) + size);

	Free(icmp);

	return ret;
}

// ICMPv6 近隣要請パケットのビルド
BUF *BuildICMPv6NeighborSoliciation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address, UINT id)
{
	ICMPV6_OPTION_LIST opt;
	ICMPV6_OPTION_LINK_LAYER link;
	ICMPV6_NEIGHBOR_SOLICIATION_HEADER header;
	BUF *b;
	BUF *b2;
	BUF *ret;
	// 引数チェック
	if (src_ip == NULL || target_ip == NULL || my_mac_address == NULL)
	{
		return NULL;
	}

	Zero(&link, sizeof(link));
	Copy(link.Address, my_mac_address, 6);

	Zero(&opt, sizeof(opt));
	opt.SourceLinkLayer = &link;

	b = BuildICMPv6Options(&opt);

	Zero(&header, sizeof(header));
	Copy(&header.TargetAddress, target_ip, sizeof(IPV6_ADDR));

	b2 = NewBuf();

	WriteBuf(b2, &header, sizeof(header));
	WriteBufBuf(b2, b);

	ret = BuildICMPv6(src_ip, target_ip, 255,
		ICMPV6_TYPE_NEIGHBOR_SOLICIATION, 0, b2->Buf, b2->Size, id);

	FreeBuf(b);
	FreeBuf(b2);

	return ret;
}

// キューから次のヘッダ番号を取得
UCHAR IPv6GetNextHeaderFromQueue(QUEUE *q)
{
	UINT *p;
	UCHAR v;
	// 引数チェック
	if (q == NULL)
	{
		return IPV6_HEADER_NONE;
	}

	p = (UINT *)GetNext(q);
	v = (UCHAR)(*p);
	Free(p);

	return v;
}

// IPv6 拡張オプションヘッダ (可変長) の追加
void BuildAndAddIPv6PacketOptionHeader(BUF *b, IPV6_OPTION_HEADER *opt, UCHAR next_header, UINT size)
{
	IPV6_OPTION_HEADER *h;
	UINT total_size;
	// 引数チェック
	if (b == NULL || opt == NULL)
	{
		return;
	}

	total_size = size;
	if ((total_size % 8) != 0)
	{
		total_size = ((total_size / 8) + 1) * 8;
	}

	h = ZeroMalloc(total_size);
	Copy(h, opt, size);
	h->Size = (total_size / 8) - 1;
	h->NextHeader = next_header;

	WriteBuf(b, h, total_size);

	Free(h);
}

// IPv6 パケットのビルド
BUF *BuildIPv6(IPV6_ADDR *dest_ip, IPV6_ADDR *src_ip, UINT id, UCHAR protocol, UCHAR hop_limit, void *data,
			   UINT size)
{
	IPV6_HEADER_PACKET_INFO info;
	IPV6_HEADER ip_header;
	BUF *buf;
	UINT size_for_headers;
	// 引数チェック
	if (dest_ip == NULL || src_ip == NULL || data == NULL)
	{
		return NULL;
	}
	if (hop_limit == 0)
	{
		hop_limit = 255;
	}

	// IPv6 ヘッダ
	Zero(&ip_header, sizeof(ip_header));
	IPV6_SET_VERSION(&ip_header, 6);
	ip_header.HopLimit = hop_limit;
	Copy(&ip_header.SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ip_header.DestAddress, dest_ip, sizeof(IPV6_ADDR));

	// ヘッダパケット情報の整理
	Zero(&info, sizeof(info));
	info.IPv6Header = &ip_header;
	info.Protocol = protocol;
	info.Payload = data;
	info.PayloadSize = size;

	buf = BuildIPv6PacketHeader(&info, &size_for_headers);
	if (buf == NULL)
	{
		return NULL;
	}

	return buf;
}

// IPv6 パケットヘッダ部のビルド
BUF *BuildIPv6PacketHeader(IPV6_HEADER_PACKET_INFO *info, UINT *bytes_before_payload)
{
	BUF *b;
	QUEUE *q;
	UINT bbp = 0;
	// 引数チェック
	if (info == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	q = NewQueueFast();

	// オプションヘッダの一覧を作成
	if (info->HopHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_HOP);
	}
	if (info->EndPointHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_ENDPOINT);
	}
	if (info->RoutingHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_ROUTING);
	}
	if (info->FragmentHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_FRAGMENT);
	}
	InsertQueueInt(q, info->Protocol);

	// IPv6 ヘッダ
	info->IPv6Header->NextHeader = IPv6GetNextHeaderFromQueue(q);
	WriteBuf(b, info->IPv6Header, sizeof(IPV6_HEADER));

	// ホップバイホップオプションヘッダ
	if (info->HopHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->HopHeader,
			IPv6GetNextHeaderFromQueue(q), info->HopHeaderSize);
	}

	// 終点オプションヘッダ
	if (info->EndPointHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->EndPointHeader,
			IPv6GetNextHeaderFromQueue(q), info->EndPointHeaderSize);
	}

	// ルーティングヘッダ
	if (info->RoutingHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->RoutingHeader,
			IPv6GetNextHeaderFromQueue(q), info->RoutingHeaderSize);
	}

	// フラグメントヘッダ
	if (info->FragmentHeader != NULL)
	{
		info->FragmentHeader->NextHeader = IPv6GetNextHeaderFromQueue(q);
		WriteBuf(b, info->FragmentHeader, sizeof(IPV6_FRAGMENT_HEADER));
	}

	bbp = b->Size;
	if (info->FragmentHeader == NULL)
	{
		bbp += sizeof(IPV6_FRAGMENT_HEADER);
	}

	// ペイロード
	if (info->Protocol != IPV6_HEADER_NONE)
	{
		WriteBuf(b, info->Payload, info->PayloadSize);
	}

	ReleaseQueue(q);

	SeekBuf(b, 0, 0);

	// ペイロード長さ
	((IPV6_HEADER *)b->Buf)->PayloadLength = Endian16(b->Size - (USHORT)sizeof(IPV6_HEADER));

	if (bytes_before_payload != NULL)
	{
		// ペイロードの直前までの長さ (ただしフラグメントヘッダは必ず含まれると仮定)
		// を計算する
		*bytes_before_payload = bbp;
	}

	return b;
}

// ICMPv6 パケットのオプション値のビルド
void BuildICMPv6OptionValue(BUF *b, UCHAR type, void *header_pointer, UINT total_size)
{
	UINT packet_size;
	UCHAR *packet;
	ICMPV6_OPTION *opt;
	// 引数チェック
	if (b == NULL || header_pointer == NULL)
	{
		return;
	}

	packet_size = ((total_size + 7) / 8) * 8;
	packet = ZeroMalloc(packet_size);

	Copy(packet, header_pointer, total_size);
	opt = (ICMPV6_OPTION *)packet;
	opt->Length = (UCHAR)(packet_size / 8);
	opt->Type = type;

	WriteBuf(b, packet, packet_size);

	Free(packet);
}

// ICMPv6 パケットのオプションのビルド
BUF *BuildICMPv6Options(ICMPV6_OPTION_LIST *o)
{
	BUF *b;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	if (o->SourceLinkLayer != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER, o->SourceLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	}
	if (o->TargetLinkLayer != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER, o->TargetLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	}
	if (o->Prefix != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_PREFIX, o->Prefix, sizeof(ICMPV6_OPTION_PREFIX));
	}
	if (o->Mtu != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_MTU, o->Mtu, sizeof(ICMPV6_OPTION_MTU));
	}

	SeekBuf(b, 0, 0);

	return b;
}

// チェックサム計算
USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size)
{
	UCHAR *tmp;
	UINT tmp_size;
	IPV6_PSEUDO_HEADER *ph;
	USHORT ret;
	// 引数チェック
	if (data == NULL && size != 0)
	{
		return 0;
	}

	tmp_size = size + sizeof(IPV6_PSEUDO_HEADER);
	tmp = ZeroMalloc(tmp_size);

	ph = (IPV6_PSEUDO_HEADER *)tmp;
	Copy(&ph->SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ph->DestAddress, dest_ip, sizeof(IPV6_ADDR));
	ph->UpperLayerPacketSize = Endian32(size);
	ph->NextHeader = protocol;

	Copy(((UCHAR *)tmp) + sizeof(IPV6_PSEUDO_HEADER), data, size);

	ret = IpChecksum(tmp, tmp_size);

	Free(tmp);

	return ret;
}

// クローンされたパケットを解放する
void FreeClonePacket(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	Free(p->IPv6HeaderPacketInfo.IPv6Header);
	Free(p->IPv6HeaderPacketInfo.HopHeader);
	Free(p->IPv6HeaderPacketInfo.EndPointHeader);
	Free(p->IPv6HeaderPacketInfo.RoutingHeader);
	Free(p->IPv6HeaderPacketInfo.FragmentHeader);
	Free(p->IPv6HeaderPacketInfo.Payload);
	Free(p->ICMPv6HeaderPacketInfo.Data);
	Free(p->ICMPv6HeaderPacketInfo.EchoData);
	Free(p->ICMPv6HeaderPacketInfo.Headers.HeaderPointer);
	FreeCloneICMPv6Options(&p->ICMPv6HeaderPacketInfo.OptionList);
	Free(p->L3.PointerL3);
	Free(p->L4.PointerL4);
	Free(p->L7.PointerL7);
	Free(p->PacketData);
	Free(p->MacHeader);
	Free(p);
}

// パケットヘッダをコピーする
PKT *ClonePacket(PKT *p, bool copy_data)
{
	PKT *ret;
	// 引数チェック
	if (p == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocFast(sizeof(PKT));
	ret->PacketSize = p->PacketSize;

	// MAC ヘッダのコピー
	ret->MacHeader = MallocFast(sizeof(MAC_HEADER));
	Copy(ret->MacHeader, p->MacHeader, sizeof(MAC_HEADER));

	// MAC フラグのコピー
	ret->BroadcastPacket = p->BroadcastPacket;
	ret->InvalidSourcePacket = p->InvalidSourcePacket;

	// IPv6 関係構造体のコピー
	Copy(&ret->IPv6HeaderPacketInfo, &p->IPv6HeaderPacketInfo, sizeof(IPV6_HEADER_PACKET_INFO));
	Copy(&ret->ICMPv6HeaderPacketInfo, &p->ICMPv6HeaderPacketInfo, sizeof(ICMPV6_HEADER_INFO));

	// Layer 3
	ret->TypeL3 = p->TypeL3;
	switch (ret->TypeL3)
	{
	case L3_ARPV4:
		// ARP パケット
		ret->L3.ARPv4Header = MallocFast(sizeof(ARPV4_HEADER));
		Copy(ret->L3.ARPv4Header, p->L3.ARPv4Header, sizeof(ARPV4_HEADER));
		break;

	case L3_IPV4:
		// IPv4 パケット
		ret->L3.IPv4Header = MallocFast(sizeof(IPV4_HEADER));
		Copy(ret->L3.IPv4Header, p->L3.IPv4Header, sizeof(IPV4_HEADER));
		break;

	case L3_IPV6:
		// IPv6 パケット
		ret->L3.IPv6Header = MallocFast(sizeof(IPV6_HEADER));
		Copy(ret->L3.IPv6Header, p->L3.IPv6Header, sizeof(IPV6_HEADER));

		ret->IPv6HeaderPacketInfo.IPv6Header = Clone(p->IPv6HeaderPacketInfo.IPv6Header,
			sizeof(IPV6_HEADER));

		ret->IPv6HeaderPacketInfo.HopHeader = Clone(p->IPv6HeaderPacketInfo.HopHeader,
			sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.EndPointHeader = Clone(p->IPv6HeaderPacketInfo.EndPointHeader,
			sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.RoutingHeader = Clone(p->IPv6HeaderPacketInfo.RoutingHeader,
			sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.FragmentHeader = Clone(p->IPv6HeaderPacketInfo.FragmentHeader,
			sizeof(IPV6_FRAGMENT_HEADER));

		ret->IPv6HeaderPacketInfo.Payload = Clone(p->IPv6HeaderPacketInfo.Payload,
			p->IPv6HeaderPacketInfo.PayloadSize);
		break;
	}

	// Layer 4
	ret->TypeL4 = p->TypeL4;
	switch (ret->TypeL4)
	{
	case L4_ICMPV4:
		// ICMPv4 パケット
		ret->L4.ICMPHeader = MallocFast(sizeof(ICMP_HEADER));
		Copy(ret->L4.ICMPHeader, p->L4.ICMPHeader, sizeof(ICMP_HEADER));
		break;

	case L4_ICMPV6:
		// ICMPv6 パケット
		ret->L4.ICMPHeader = MallocFast(sizeof(ICMP_HEADER));
		Copy(ret->L4.ICMPHeader, p->L4.ICMPHeader, sizeof(ICMP_HEADER));

		ret->ICMPv6HeaderPacketInfo.Data = Clone(p->ICMPv6HeaderPacketInfo.Data,
			p->ICMPv6HeaderPacketInfo.DataSize);

		ret->ICMPv6HeaderPacketInfo.EchoData = Clone(p->ICMPv6HeaderPacketInfo.EchoData,
			p->ICMPv6HeaderPacketInfo.EchoDataSize);

		switch (ret->ICMPv6HeaderPacketInfo.Type)
		{
		case ICMPV6_TYPE_ECHO_REQUEST:
		case ICMPV6_TYPE_ECHO_RESPONSE:
			break;

		case ICMPV6_TYPE_ROUTER_SOLICIATION:
			ret->ICMPv6HeaderPacketInfo.Headers.RouterSoliciationHeader =
				Clone(p->ICMPv6HeaderPacketInfo.Headers.RouterSoliciationHeader,
				sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER));
			break;

		case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
			ret->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader =
				Clone(p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader,
				sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER));
			break;

		case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
			ret->ICMPv6HeaderPacketInfo.Headers.NeighborSoliciationHeader =
				Clone(p->ICMPv6HeaderPacketInfo.Headers.NeighborSoliciationHeader,
				sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER));
			break;

		case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
			ret->ICMPv6HeaderPacketInfo.Headers.NeighborAdvertisementHeader =
				Clone(p->ICMPv6HeaderPacketInfo.Headers.NeighborAdvertisementHeader,
				sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER));
			break;
		}

		CloneICMPv6Options(&ret->ICMPv6HeaderPacketInfo.OptionList,
			&p->ICMPv6HeaderPacketInfo.OptionList);
		break;

	case L4_TCP:
		// TCP パケット
		ret->L4.TCPHeader = MallocFast(sizeof(TCP_HEADER));
		Copy(ret->L4.TCPHeader, p->L4.TCPHeader, sizeof(TCP_HEADER));
		break;

	case L4_UDP:
		// UDP パケット
		ret->L4.UDPHeader = MallocFast(sizeof(UDP_HEADER));
		Copy(ret->L4.UDPHeader, p->L4.UDPHeader, sizeof(UDP_HEADER));
		break;
	}

	// Layer 7
	ret->TypeL7 = p->TypeL7;
	switch (ret->TypeL7)
	{
	case L7_DHCPV4:
		// DHCP パケット
		ret->L7.DHCPv4Header = MallocFast(sizeof(DHCPV4_HEADER));
		Copy(ret->L7.DHCPv4Header, p->L7.DHCPv4Header, sizeof(DHCPV4_HEADER));
		break;
	}

	// アドレスデータ
	ret->MacAddressSrc = ret->MacHeader->SrcAddress;
	ret->MacAddressDest = ret->MacHeader->DestAddress;

	if (copy_data)
	{
		// パケット本体もコピー
		ret->PacketData = MallocFast(p->PacketSize);
		Copy(ret->PacketData, p->PacketData, p->PacketSize);
	}

	return ret;
}

// パケットの中身をパースする
PKT *ParsePacket(UCHAR *buf, UINT size)
{
	return ParsePacketEx(buf, size, false);
}
PKT *ParsePacketEx(UCHAR *buf, UINT size, bool no_l3)
{
	return ParsePacketEx2(buf, size, no_l3, 0);
}
PKT *ParsePacketEx2(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id)
{
	return ParsePacketEx3(buf, size, no_l3, vlan_type_id, true);
}
PKT *ParsePacketEx3(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address)
{
	PKT *p;
	// 引数チェック
	if (buf == NULL || size == 0)
	{
		return NULL;
	}

	if (vlan_type_id == 0)
	{
		vlan_type_id = MAC_PROTO_TAGVLAN;
	}

	p = ZeroMallocFast(sizeof(PKT));

	p->VlanTypeID = vlan_type_id;

	// パース実行
	if (ParsePacketL2Ex(p, buf, size, no_l3) == false)
	{
		// パース失敗
		FreePacket(p);
		return NULL;
	}

	p->PacketData = buf;
	p->PacketSize = size;

	p->MacAddressSrc = p->MacHeader->SrcAddress;
	p->MacAddressDest = p->MacHeader->DestAddress;

	if (bridge_id_as_mac_address)
	{
		if (p->TypeL3 == L3_BPDU)
		{
			if (p->L3.BpduHeader != NULL)
			{
				p->MacAddressSrc = p->L3.BpduHeader->BridgeMacAddress;
			}
		}
	}

	// パース成功
	return p;
}


// Layer-2 パース
bool ParsePacketL2(PKT *p, UCHAR *buf, UINT size)
{
	return ParsePacketL2Ex(p, buf, size, false);
}
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3)
{
	UINT i;
	bool b1, b2;
	USHORT type_id_16;
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(MAC_HEADER))
	{
		return false;
	}

	// MAC ヘッダ
	p->MacHeader = (MAC_HEADER *)buf;

	buf += sizeof(MAC_HEADER);
	size -= sizeof(MAC_HEADER);

	// MAC ヘッダの解析
	p->BroadcastPacket = true;
	b1 = true;
	b2 = true;
	for (i = 0;i < 6;i++)
	{
		if (p->MacHeader->DestAddress[i] != 0xff)
		{
			p->BroadcastPacket = false;
		}
		if (p->MacHeader->SrcAddress[i] != 0xff)
		{
			b1 = false;
		}
		if (p->MacHeader->SrcAddress[i] != 0x00)
		{
			b2 = false;
		}
	}
	if (b1 || b2 || (Cmp(p->MacHeader->SrcAddress, p->MacHeader->DestAddress, 6) == 0))
	{
		p->InvalidSourcePacket = true;
	}
	else
	{
		p->InvalidSourcePacket = false;
	}

	if (p->MacHeader->DestAddress[0] & 0x01)
	{
		p->BroadcastPacket = true;
	}

	// L3 パケットのパース
	type_id_16 = Endian16(p->MacHeader->Protocol);

	if (type_id_16 > 1500)
	{
		// 通常の Ethernet フレーム
		switch (type_id_16)
		{
		case MAC_PROTO_ARPV4:	// ARPv4
			if (no_l3)
			{
				return true;
			}

			return ParsePacketARPv4(p, buf, size);

		case MAC_PROTO_IPV4:	// IPv4
			if (no_l3)
			{
				return true;
			}

			return ParsePacketIPv4(p, buf, size);

		case MAC_PROTO_IPV6:	// IPv6
			if (no_l3)
			{
				return true;
			}

			return ParsePacketIPv6(p, buf, size);

		default:				// 不明
			if (type_id_16 == p->VlanTypeID)
			{
				// VLAN
				return ParsePacketTAGVLAN(p, buf, size);
			}
			else
			{
				return true;
			}
		}
	}
	else
	{
		// IEEE 802.3 の古い (パケットのペイロード長が書いてある) フレーム
		// (BPDU 等で使われていることがある)
		UINT length = (UINT)type_id_16;
		LLC_HEADER *llc;

		// 長さが残っているかどうかチェック
		if (size < length || size < sizeof(LLC_HEADER))
		{
			return true;
		}

		// LLC ヘッダを読む
		llc = (LLC_HEADER *)buf;
		buf += sizeof(LLC_HEADER);
		size -= sizeof(LLC_HEADER);

		// DSAP, SSAP の値によってプロトコルを判定する
		if (llc->Dsap == LLC_DSAP_BPDU && llc->Ssap == LLC_SSAP_BPDU)
		{
			// BPDU (Spanning Tree) である
			return ParsePacketBPDU(p, buf, size);
		}
		else
		{
			// 不明なプロトコルである
			return true;
		}
	}
}

// TAG VLAN パース
bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size)
{
	USHORT vlan_ushort;
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(TAGVLAN_HEADER))
	{
		return false;
	}

	// TAG VLAN ヘッダ
	p->L3.TagVlanHeader = (TAGVLAN_HEADER *)buf;
	p->TypeL3 = L3_TAGVLAN;

	buf += sizeof(TAGVLAN_HEADER);
	size -= sizeof(TAGVLAN_HEADER);

	vlan_ushort = Endian16(*((USHORT *)p->L3.TagVlanHeader->Data));
	vlan_ushort = vlan_ushort & 0xFFF;

	p->VlanId = vlan_ushort;

	return true;
}

// BPDU パース
bool ParsePacketBPDU(PKT *p, UCHAR *buf, UINT size)
{
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(BPDU_HEADER))
	{
		return true;
	}

	// BPDU ヘッダ
	p->L3.BpduHeader = (BPDU_HEADER *)buf;
	p->TypeL3 = L3_BPDU;

	buf += sizeof(BPDU_HEADER);
	size -= sizeof(BPDU_HEADER);

	return true;
}

// ARPv4 パース
bool ParsePacketARPv4(PKT *p, UCHAR *buf, UINT size)
{
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(ARPV4_HEADER))
	{
		return false;
	}

	// ARPv4 ヘッダ
	p->L3.ARPv4Header = (ARPV4_HEADER *)buf;
	p->TypeL3 = L3_ARPV4;

	buf += sizeof(ARPV4_HEADER);
	size -= sizeof(ARPV4_HEADER);

	return true;
}

// IPv6 拡張ヘッダの解析
bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size)
{
	bool ret = false;
	IPV6_OPTION_HEADER *option_header;
	UINT option_header_size;
	UCHAR next_header_2 = IPV6_HEADER_NONE;
	// 引数チェック
	if (info == NULL || buf == NULL)
	{
		return false;
	}

	info->IsFragment = false;

	while (true)
	{
		if (size > 8)
		{
			next_header_2 = *((UCHAR *)buf);
		}

		switch (next_header)
		{
		case IPV6_HEADER_HOP:
		case IPV6_HEADER_ENDPOINT:
		case IPV6_HEADER_ROUTING:
			// 可変長ヘッダ
			if (size < 8)
			{
				return false;
			}

			option_header = (IPV6_OPTION_HEADER *)buf;
			option_header_size = (option_header->Size + 1) * 8;
			if (size < option_header_size)
			{
				return false;
			}

			switch (next_header)
			{
			case IPV6_HEADER_HOP:
				info->HopHeader = (IPV6_OPTION_HEADER *)buf;
				info->HopHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ENDPOINT:
				info->EndPointHeader = (IPV6_OPTION_HEADER *)buf;
				info->EndPointHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ROUTING:
				info->RoutingHeader = (IPV6_OPTION_HEADER *)buf;
				info->RoutingHeaderSize = option_header_size;
				break;
			}

			buf += option_header_size;
			size -= option_header_size;
			break;

		case IPV6_HEADER_FRAGMENT:
			// フラグメントヘッダ (固定長)
			if (size < sizeof(IPV6_FRAGMENT_HEADER))
			{
				return false;
			}

			info->FragmentHeader = (IPV6_FRAGMENT_HEADER *)buf;

			if (IPV6_GET_FRAGMENT_OFFSET(info->FragmentHeader) != 0)
			{
				info->IsFragment = true;
			}

			buf += sizeof(IPV6_FRAGMENT_HEADER);
			size -= sizeof(IPV6_FRAGMENT_HEADER);
			break;

		default:
			// 後にペイロードが続くとみなす
			if (next_header != IPV6_HEADER_NONE)
			{
				info->Payload = buf;
				info->PayloadSize = size;
			}
			else
			{
				info->Payload = NULL;
				info->PayloadSize = 0;
			}
			info->Protocol = next_header;
			return true;
		}

		next_header = next_header_2;
	}
}

// IPv6 ヘッダの解析
bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size)
{
	// 引数チェック
	if (info == NULL || buf == NULL)
	{
		return false;
	}

	Zero(info, sizeof(IPV6_HEADER_PACKET_INFO));

	// IPv6 ヘッダ
	if (size < sizeof(IPV6_HEADER))
	{
		// サイズ不正
		return false;
	}

	info->IPv6Header = (IPV6_HEADER *)buf;
	buf += sizeof(IPV6_HEADER);
	size -= sizeof(IPV6_HEADER);

	if (IPV6_GET_VERSION(info->IPv6Header) != 6)
	{
		// バージョン不正
		return false;
	}

	// 拡張ヘッダの解析
	return ParseIPv6ExtHeader(info, info->IPv6Header->NextHeader, buf, size);
}

// ICMPv6 パケットのオプションの解析
bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size)
{
	// 引数チェック
	if (o == NULL || buf == NULL)
	{
		return false;
	}

	Zero(o, sizeof(ICMPV6_OPTION_LIST));

	// ヘッダ部分の読み込み
	while (true)
	{
		ICMPV6_OPTION *option_header;
		UINT header_total_size;
		UCHAR *header_pointer;
		if (size < sizeof(ICMPV6_OPTION))
		{
			// サイズ不足
			return true;
		}

		option_header = (ICMPV6_OPTION *)buf;
		// ヘッダ全体サイズの計算
		header_total_size = option_header->Length * 8;
		if (header_total_size == 0)
		{
			// サイズがゼロ
			return true;
		}
		if (size < header_total_size)
		{
			// サイズ不足
			return true;
		}

		header_pointer = buf;
		buf += header_total_size;
		size -= header_total_size;

		switch (option_header->Type)
		{
		case ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER:
		case ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER:
			// ソース or ターゲットリンクレイヤオプション
			if (header_total_size >= sizeof(ICMPV6_OPTION_LINK_LAYER))
			{
				if (option_header->Type == ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER)
				{
					o->SourceLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
				else
				{
					o->TargetLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
			}
			else
			{
				// ICMPv6 パケット破損?
				return false;
			}
			break;

		case ICMPV6_OPTION_TYPE_PREFIX:
			// プレフィックス情報
			if (header_total_size >= sizeof(ICMPV6_OPTION_PREFIX))
			{
				o->Prefix = (ICMPV6_OPTION_PREFIX *)header_pointer;
			}
			else
			{
				// ICMPv6 パケット破損?
			}
			break;

		case ICMPV6_OPTION_TYPE_MTU:
			// MTU
			if (header_total_size >= sizeof(ICMPV6_OPTION_MTU))
			{
				o->Mtu = (ICMPV6_OPTION_MTU *)header_pointer;
			}
			else
			{
				// ICMPv6 パケット破損?
			}
			break;
		}
	}
}

// ICMPv6 パース
bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size)
{
	ICMPV6_HEADER_INFO icmp_info;
	ICMP_HEADER *icmp;
	ICMP_ECHO *echo;
	UINT msg_size;
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	Zero(&icmp_info, sizeof(icmp_info));

	if (size < sizeof(ICMP_HEADER))
	{
		return false;
	}

	icmp = (ICMP_HEADER *)buf;
	p->L4.ICMPHeader = icmp;

	msg_size = size - sizeof(ICMP_HEADER);

	icmp_info.Type = icmp->Type;
	icmp_info.Code = icmp->Code;
	icmp_info.Data = ((UCHAR *)buf) + sizeof(ICMP_HEADER);
	icmp_info.DataSize = msg_size;

	switch (icmp_info.Type)
	{
	case ICMPV6_TYPE_ECHO_REQUEST:
	case ICMPV6_TYPE_ECHO_RESPONSE:
		// ICMP Echo Request / Response
		if (icmp_info.DataSize < sizeof(ICMP_ECHO))
		{
			return false;
		}

		echo = (ICMP_ECHO *)icmp_info.Data;

		icmp_info.EchoHeader.Identifier = Endian16(echo->Identifier);
		icmp_info.EchoHeader.SeqNo = Endian16(echo->SeqNo);
		icmp_info.EchoData = (UCHAR *)echo + sizeof(ICMP_ECHO);
		icmp_info.EchoDataSize = icmp_info.DataSize - sizeof(ICMP_ECHO);

		break;

	case ICMPV6_TYPE_ROUTER_SOLICIATION:
		// ルータ要請
		if (icmp_info.DataSize < sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER))
		{
			return false;
		}

		icmp_info.Headers.RouterSoliciationHeader =
			(ICMPV6_ROUTER_SOLICIATION_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER),
			icmp_info.DataSize - sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
		// ルータ広告
		if (icmp_info.DataSize < sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER))
		{
			return false;
		}

		icmp_info.Headers.RouterAdvertisementHeader =
			(ICMPV6_ROUTER_ADVERTISEMENT_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER),
			icmp_info.DataSize - sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
		// 近隣要請
		if (icmp_info.DataSize < sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER))
		{
			return false;
		}

		icmp_info.Headers.NeighborSoliciationHeader =
			(ICMPV6_NEIGHBOR_SOLICIATION_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER),
			icmp_info.DataSize - sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
		// 近隣広告
		if (icmp_info.DataSize < sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER))
		{
			return false;
		}

		icmp_info.Headers.NeighborAdvertisementHeader =
			(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER),
			icmp_info.DataSize - sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER)) == false)
		{
			return false;
		}

		break;
	}

	p->TypeL4 = L4_ICMPV6;
	Copy(&p->ICMPv6HeaderPacketInfo, &icmp_info, sizeof(ICMPV6_HEADER_INFO));

	return true;
}

// ICMPv6 オプションの解放
void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	Free(o->SourceLinkLayer);
	Free(o->TargetLinkLayer);
	Free(o->Prefix);
	Free(o->Mtu);
}

// ICMPv6 オプションのクローン
void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src)
{
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	Zero(dst, sizeof(ICMPV6_OPTION_LIST));

	dst->SourceLinkLayer = Clone(src->SourceLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	dst->TargetLinkLayer = Clone(src->TargetLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	dst->Prefix = Clone(src->Prefix, sizeof(ICMPV6_OPTION_PREFIX));
	dst->Mtu = Clone(src->Mtu, sizeof(ICMPV6_OPTION_MTU));
}

// IPv6 パース
bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size)
{
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (ParsePacketIPv6Header(&p->IPv6HeaderPacketInfo, buf, size) == false)
	{
		return false;
	}

	p->TypeL3 = L3_IPV6;
	p->L3.IPv6Header = p->IPv6HeaderPacketInfo.IPv6Header;

	if (p->IPv6HeaderPacketInfo.Payload == NULL)
	{
		// ペイロードなし
		return true;
	}

	buf = p->IPv6HeaderPacketInfo.Payload;
	size = p->IPv6HeaderPacketInfo.PayloadSize;

	if (p->IPv6HeaderPacketInfo.IsFragment)
	{
		// フラグメントパケットであるからこれ以上解釈しない
		p->TypeL4 = L4_FRAGMENT;
		return true;
	}

	// L4 パケットのパース
	switch (p->IPv6HeaderPacketInfo.Protocol)
	{
	case IP_PROTO_ICMPV6:	// ICMPv6
		if (ParseICMPv6(p, buf, size) == false)
		{
			// ICMPv6 のパースに失敗しても true を返す
			return true;
		}
		else
		{
			return true;
		}

	case IP_PROTO_TCP:		// TCP
		return ParseTCP(p, buf, size);

	case IP_PROTO_UDP:		// UDP
		return ParseUDP(p, buf, size);

	default:				// 不明
		return true;
	}

	return true;
}

// IPv4 パース
bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size)
{
	UINT header_size;
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(IPV4_HEADER))
	{
		return false;
	}

	// IPv4 ヘッダ
	p->L3.IPv4Header = (IPV4_HEADER *)buf;
	p->TypeL3 = L3_IPV4;

	// ヘッダのチェック
	header_size = IPV4_GET_HEADER_LEN(p->L3.IPv4Header) * 4;
	if (header_size < sizeof(IPV4_HEADER) || size < header_size)
	{
		// ヘッダサイズが不正
		p->L3.IPv4Header = NULL;
		p->TypeL3= L3_UNKNOWN;
		return true;
	}

	if (IPV4_GET_OFFSET(p->L3.IPv4Header) != 0)
	{
		// フラグメント化されているからこれ以上解析しない
		p->TypeL4 = L4_FRAGMENT;
		return true;
	}

	buf += header_size;
	size -= header_size;

	// L4 パケットのパース
	switch (p->L3.IPv4Header->Protocol)
	{
	case IP_PROTO_ICMPV4:	// ICMPv4
		return ParseICMPv4(p, buf, size);

	case IP_PROTO_UDP:		// UDP
		return ParseUDP(p, buf, size);

	case IP_PROTO_TCP:		// TCP
		return ParseTCP(p, buf, size);

	default:				// 不明
		return true;
	}
}

// ICMPv4 パース
bool ParseICMPv4(PKT *p, UCHAR *buf, UINT size)
{
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(ICMP_HEADER))
	{
		// サイズが不正
		return false;
	}

	// ICMPv4 ヘッダ
	p->L4.ICMPHeader = (ICMP_HEADER *)buf;
	p->TypeL4 = L4_ICMPV4;

	buf += sizeof(ICMP_HEADER);
	size -= sizeof(ICMP_HEADER);

	return true;
}

// TCP パース
bool ParseTCP(PKT *p, UCHAR *buf, UINT size)
{
	UINT header_size;
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(TCP_HEADER))
	{
		// サイズが不正
		return false;
	}

	// TCP ヘッダ
	p->L4.TCPHeader = (TCP_HEADER *)buf;
	p->TypeL4 = L4_TCP;

	// ヘッダサイズをチェック
	header_size = TCP_GET_HEADER_SIZE(p->L4.TCPHeader) * 4;
	if (header_size < sizeof(TCP_HEADER) || size < header_size)
	{
		// ヘッダサイズが不正
		p->L4.TCPHeader = NULL;
		p->TypeL4 = L4_UNKNOWN;
		return true;
	}

	buf += header_size;
	size -= header_size;

	return true;
}

// UDP パース
bool ParseUDP(PKT *p, UCHAR *buf, UINT size)
{
	USHORT src_port, dst_port;
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// サイズをチェック
	if (size < sizeof(UDP_HEADER))
	{
		// サイズが不正
		return false;
	}

	// UDP ヘッダ
	p->L4.UDPHeader = (UDP_HEADER *)buf;
	p->TypeL4 = L4_UDP;

	buf += sizeof(UDP_HEADER);
	size -= sizeof(UDP_HEADER);

	// ポート番号をチェック
	src_port = Endian16(p->L4.UDPHeader->SrcPort);
	dst_port = Endian16(p->L4.UDPHeader->DstPort);

	if ((src_port == 67 && dst_port == 68) ||
		(src_port == 68 && dst_port == 67))
	{
		if (p->TypeL3 == L3_IPV4)
		{
			// DHCP パケットを発見
			ParseDHCPv4(p, buf, size);
		}
	}

	return true;
}

// DHCPv4 パース
void ParseDHCPv4(PKT *p, UCHAR *buf, UINT size)
{
	// 引数チェック
	if (p == NULL || buf == NULL)
	{
		return;
	}

	// サイズをチェック
	if (size < sizeof(DHCPV4_HEADER))
	{
		// サイズが不正
		return;
	}

	// DHCPv4 ヘッダ
	p->L7.DHCPv4Header = (DHCPV4_HEADER *)buf;
	p->TypeL7 = L7_DHCPV4;
}

// パケットのメモリを解放する
void FreePacket(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	if (p->MacHeader != NULL)
	{
		switch (p->TypeL3)
		{
		case L3_IPV4:
			FreePacketIPv4(p);
			break;

		case L3_ARPV4:
			FreePacketARPv4(p);
			break;

		case L3_TAGVLAN:
			FreePacketTagVlan(p);
			break;
		}
	}

	Free(p);
}

// IPv4 パケットのメモリを解放する
void FreePacketIPv4(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	switch (p->TypeL4)
	{
	case L4_ICMPV4:
		FreePacketICMPv4(p);
		break;

	case L4_TCP:
		FreePacketTCPv4(p);
		break;

	case L4_UDP:
		FreePacketUDPv4(p);
		break;
	}

	p->L3.IPv4Header = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

// タグ VLAN パケットのメモリを解放する
void FreePacketTagVlan(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	p->L3.TagVlanHeader = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

// ARPv4 パケットのメモリを解放する
void FreePacketARPv4(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	p->L3.ARPv4Header = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

// UDPv4 パケットのメモリを解放する
void FreePacketUDPv4(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	switch (p->TypeL7)
	{
	case L7_DHCPV4:
		FreePacketDHCPv4(p);
		break;
	}

	p->L4.UDPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

// TCPv4 パケットのメモリを解放する
void FreePacketTCPv4(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	p->L4.TCPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

// ICMPv4 パケットのメモリを解放する
void FreePacketICMPv4(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	p->L4.ICMPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

// DHCPv4 パケットのメモリを解放する
void FreePacketDHCPv4(PKT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	p->L7.DHCPv4Header = NULL;
	p->TypeL7 = L7_UNKNOWN;
}

