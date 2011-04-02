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

// Layer3.c
// Layer-3 スイッチ モジュール

#include "CedarPch.h"

static UCHAR broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// IP キューの処理
void L3PollingIpQueue(L3IF *f)
{
	L3PACKET *p;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	// 別のセッションから来たパケットを処理する
	while (p = GetNext(f->IpPacketQueue))
	{
		PKT *pkt = p->Packet;

		// IP パケットとして送信する
		L3SendIp(f, p);
	}
}

// IP パケットの処理
void L3RecvIp(L3IF *f, PKT *p, bool self)
{
	IPV4_HEADER *ip;
	UINT header_size;
	UINT next_hop = 0;
	L3IF *dst;
	L3PACKET *packet;
	UINT new_ttl = 0;
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	ip = p->L3.IPv4Header;
	header_size = IPV4_GET_HEADER_LEN(p->L3.IPv4Header) * 4;

	// チェックサムの計算
	if (IpCheckChecksum(ip) == false)
	{
		// チェックサムが一致しない
		goto FREE_PACKET;
	}

	// ARP テーブルに登録
	L3KnownArp(f, ip->SrcIP, p->MacAddressSrc);

	if (p->BroadcastPacket)
	{
		// ブロードキャストパケットの場合はルーティングしない
		goto FREE_PACKET;
	}

	// TTL を計算
	if (ip->TimeToLive >= 1)
	{
		new_ttl = ip->TimeToLive - 1;
	}
	else
	{
		new_ttl = 0;
	}

	if (new_ttl == 0)
	{
		if (ip->DstIP != f->IpAddress)
		{
			UINT src_packet_size = p->PacketSize - sizeof(MAC_HEADER);
			UINT icmp_packet_total_size = sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4 + header_size + 8;
			UCHAR *buf;
			IPV4_HEADER *ipv4;
			ICMP_HEADER *icmpv4;
			UCHAR *data;
			PKT *pkt;
			UINT data_size = MIN(p->PacketSize - header_size, header_size + 8);

			// TTL 切れが発生したことを知らせる ICMP メッセージを生成する
			buf = ZeroMalloc(icmp_packet_total_size);
			ipv4 = (IPV4_HEADER *)(buf + sizeof(MAC_HEADER));
			icmpv4 = (ICMP_HEADER *)(buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER));
			data = buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4;

			IPV4_SET_VERSION(ipv4, 4);
			IPV4_SET_HEADER_LEN(ipv4, sizeof(IPV4_HEADER) / 4);
			ipv4->TotalLength = Endian16((USHORT)(icmp_packet_total_size - sizeof(MAC_HEADER)));
			ipv4->TimeToLive = 0xff;
			ipv4->Protocol = IP_PROTO_ICMPV4;
			ipv4->SrcIP = f->IpAddress;
			ipv4->DstIP = ip->SrcIP;
			ipv4->Checksum = IpChecksum(ipv4, sizeof(IPV4_HEADER));

			icmpv4->Type = 11;
			Copy(data, ip, data_size);
			icmpv4->Checksum = IpChecksum(icmpv4, sizeof(ICMP_HEADER) + data_size + 4);

			buf[12] = 0x08;
			buf[13] = 0x00;

			pkt = ParsePacket(buf, icmp_packet_total_size);
			if (pkt == NULL)
			{
				Free(buf);
			}
			else
			{
				L3RecvIp(f, pkt, true);
			}

			// TTL が切れたパケット本体は破棄する
			goto FREE_PACKET;
		}
	}

	// 書き換える
	p->L3.IPv4Header->TimeToLive = (UCHAR)new_ttl;

	// 宛先 IP アドレスに対するインターフェイスを取得する
	dst = L3GetNextIf(f->Switch, ip->DstIP, &next_hop);

	if (dst == NULL && self == false)
	{
		UINT src_packet_size = p->PacketSize - sizeof(MAC_HEADER);
		UINT icmp_packet_total_size = sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4 + header_size + 8;
		UCHAR *buf;
		IPV4_HEADER *ipv4;
		ICMP_HEADER *icmpv4;
		UCHAR *data;
		PKT *pkt;
			UINT data_size = MIN(p->PacketSize - header_size, header_size + 8);

		// ルートが見つからない旨を ICMP で応答する
		buf = ZeroMalloc(icmp_packet_total_size);
		ipv4 = (IPV4_HEADER *)(buf + sizeof(MAC_HEADER));
		icmpv4 = (ICMP_HEADER *)(buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER));
		data = buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4;

		IPV4_SET_VERSION(ipv4, 4);
		IPV4_SET_HEADER_LEN(ipv4, sizeof(IPV4_HEADER) / 4);
		ipv4->TotalLength = Endian16((USHORT)(icmp_packet_total_size - sizeof(MAC_HEADER)));
		ipv4->TimeToLive = 0xff;
		ipv4->Protocol = IP_PROTO_ICMPV4;
		ipv4->SrcIP = f->IpAddress;
		ipv4->DstIP = ip->SrcIP;
		ipv4->Checksum = IpChecksum(ipv4, sizeof(IPV4_HEADER));

		icmpv4->Type = 3;
		Copy(data, ip, data_size);
		icmpv4->Checksum = IpChecksum(icmpv4, sizeof(ICMP_HEADER) + data_size + 4);

		buf[12] = 0x08;
		buf[13] = 0x00;

		pkt = ParsePacket(buf, icmp_packet_total_size);
		if (pkt == NULL)
		{
			Free(buf);
		}
		else
		{
			L3RecvIp(f, pkt, true);
		}

		// ルートが見つからないパケット本体は破棄する
		goto FREE_PACKET;
	}

	if (dst != NULL && ip->DstIP == dst->IpAddress)
	{
		bool free_packet = true;
		// 自分宛の IP パケットが届いた
		if (p->TypeL4 == L4_ICMPV4)
		{
			ICMP_HEADER *icmp = p->L4.ICMPHeader;
			if (icmp->Type == ICMP_TYPE_ECHO_REQUEST)
			{
				// この IP パケットの宛先と送信元を書き換えて返信する
				UINT src_ip, dst_ip;
				src_ip = p->L3.IPv4Header->DstIP;
				dst_ip = p->L3.IPv4Header->SrcIP;

				p->L3.IPv4Header->DstIP = dst_ip;
				p->L3.IPv4Header->SrcIP = src_ip;

				ip->TimeToLive = 0xff;

				// チェックサムを再計算する
				ip->FlagsAndFlagmentOffset[0] = ip->FlagsAndFlagmentOffset[1] = 0;
				icmp->Checksum = 0;
				icmp->Type = ICMP_TYPE_ECHO_RESPONSE;
				icmp->Checksum = IpChecksum(icmp, p->PacketSize - sizeof(MAC_HEADER) - header_size);

				dst = L3GetNextIf(f->Switch, ip->DstIP, &next_hop);

				free_packet = false;
			}
		}

		if (free_packet)
		{
			goto FREE_PACKET;
		}
	}

	if (dst == NULL)
	{
		// 宛先が存在しない
		goto FREE_PACKET;
	}

	// IP チェックサムの再計算
	ip->Checksum = 0;
	ip->Checksum = IpChecksum(ip, header_size);

	// Layer-3 パケットとして処理する
	packet = ZeroMalloc(sizeof(L3PACKET));
	packet->Expire = Tick64() + IP_WAIT_FOR_ARP_TIMEOUT;
	packet->NextHopIp = next_hop;
	packet->Packet = p;

	// 宛先セッションにストアする
	L3StoreIpPacketToIf(f, dst, packet);

	return;

FREE_PACKET:
	// パケットの解放
	Free(p->PacketData);
	FreePacket(p);
	return;
}

// レイヤ 2 パケットの処理
void L3RecvL2(L3IF *f, PKT *p)
{
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	// 自分が送信したパケットか、ユニキャストパケットで自分宛で無いパケット
	// はすべて無視する
	if (Cmp(p->MacAddressSrc, f->MacAddress, 6) == 0 ||
		(p->BroadcastPacket == false && Cmp(p->MacAddressDest, f->MacAddress, 6) != 0))
	{
		// パケット解放
		Free(p->PacketData);
		FreePacket(p);
		return;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		// ARP パケットを受信した
		L3RecvArp(f, p);

		// パケット解放
		Free(p->PacketData);
		FreePacket(p);
	}
	else if (p->TypeL3 == L3_IPV4)
	{
		// IP パケットを受信した
		L3RecvIp(f, p, false);
	}
	else
	{
		// パケット解放
		Free(p->PacketData);
		FreePacket(p);
	}
}

// IP パケットを別のインターフェイスにストアする
void L3StoreIpPacketToIf(L3IF *src_if, L3IF *dst_if, L3PACKET *p)
{
	// 引数チェック
	if (src_if == NULL || p == NULL || dst_if == NULL)
	{
		return;
	}

	// ストア先セッションのキューに追加する
	InsertQueue(dst_if->IpPacketQueue, p);

	// ストア先セッションの Cancel オブジェクトを叩くことにする
	AddCancelList(src_if->CancelList, dst_if->Session->Cancel1);
}

// パケットを書き込む (新しいパケットが届いたので処理する)
void L3PutPacket(L3IF *f, void *data, UINT size)
{
	PKT *p;
	L3SW *s;
	if (f == NULL)
	{
		return;
	}

	s = f->Switch;

	if (data != NULL)
	{
		// 次のパケットを処理する
		if (f->CancelList == NULL)
		{
			f->CancelList = NewCancelList();
		}

		// パケット解析
		p = ParsePacket(data, size);

		if (p == NULL)
		{
			// パケット解析失敗
			Free(data);
		}
		else
		{
			// パケット解析成功
			Lock(s->lock);
			{
				L3RecvL2(f, p);
			}
			Unlock(s->lock);
		}
	}
	else
	{
		// すべてのパケットの処理が終わったらキャンセルリストをキャンセル処理する
		if (f->CancelList != NULL)
		{
			CancelList(f->CancelList);
			ReleaseCancelList(f->CancelList);
			f->CancelList = NULL;
		}
	}
}

// 待機している IP パケットのうち送信先 MAC アドレスが解決したものを送信する
void L3SendWaitingIp(L3IF *f, UCHAR *mac, UINT ip, L3ARPENTRY *a)
{
	UINT i;
	LIST *o = NULL;
	// 引数チェック
	if (f == NULL || mac == NULL || a == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->IpWaitList);i++)
	{
		L3PACKET *p = LIST_DATA(f->IpWaitList, i);

		if (p->NextHopIp == ip)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, p);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3PACKET *p = LIST_DATA(o, i);

			// 送信
			L3SendIpNow(f, a, p);

			Delete(f->IpWaitList, p);
			Free(p->Packet->PacketData);
			FreePacket(p->Packet);
			Free(p);
		}

		ReleaseList(o);
	}
}

// ARP テーブルに登録する
void L3InsertArpTable(L3IF *f, UINT ip, UCHAR *mac)
{
	L3ARPENTRY *a, t;
	// 引数チェック
	if (f == NULL || ip == 0 || ip == 0xffffffff || mac == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.IpAddress = ip;

	a = Search(f->ArpTable, &t);

	if (a == NULL)
	{
		// リストに登録されていないので登録する
		a = ZeroMalloc(sizeof(L3ARPENTRY));
		a->IpAddress = ip;
		Copy(a->MacAddress, mac, 6);
		Insert(f->ArpTable, a);
	}

	// 有効期限を延長する
	a->Expire = Tick64() + ARP_ENTRY_EXPIRES;

	// 待機している IP パケットを送信させる
	L3SendWaitingIp(f, mac, ip, a);
}

// ARP テーブルを知ったときに呼ばれる関数
void L3KnownArp(L3IF *f, UINT ip, UCHAR *mac)
{
	L3ARPWAIT t, *w;
	// 引数チェック
	if (f == NULL || ip == 0 || ip == 0xffffffff || mac == NULL)
	{
		return;
	}

	// この IP アドレスへの ARP 問い合わせテーブルを削除する
	Zero(&t, sizeof(t));
	t.IpAddress = ip;
	w = Search(f->IpWaitList, &t);
	if (w != NULL)
	{
		Delete(f->IpWaitList, w);
		Free(w);
	}

	// ARP テーブルに登録する
	L3InsertArpTable(f, ip, mac);
}

// ARP を発行する
void L3SendArp(L3IF *f, UINT ip)
{
	L3ARPWAIT t, *w;
	// 引数チェック
	if (f == NULL || ip == 0 || ip == 0xffffffff)
	{
		return;
	}

	// すでに登録されていないかどうか調べる
	Zero(&t, sizeof(t));
	t.IpAddress = ip;
	w = Search(f->ArpWaitTable, &t);

	if (w != NULL)
	{
		// すでに待機リストに登録されているので何もしない
		return;
	}
	else
	{
		// 新しくリストに登録する
		w = ZeroMalloc(sizeof(L3ARPWAIT));
		w->Expire = Tick64() + ARP_REQUEST_GIVEUP;
		w->IpAddress = ip;
		Insert(f->ArpWaitTable, w);
	}
}

// ARP 要求を受信した
void L3RecvArpRequest(L3IF *f, PKT *p)
{
	ARPV4_HEADER *a;
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	a = p->L3.ARPv4Header;

	L3KnownArp(f, a->SrcIP, a->SrcAddress);

	if (a->TargetIP == f->IpAddress)
	{
		// 自分宛の ARP パケットの場合のみ応答する
		L3SendArpResponseNow(f, a->SrcAddress, a->SrcIP, f->IpAddress);
	}
}

// ARP 応答を受信した
void L3RecvArpResponse(L3IF *f, PKT *p)
{
	ARPV4_HEADER *a;
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	a = p->L3.ARPv4Header;

	L3KnownArp(f, a->SrcIP, a->SrcAddress);
}

// ARP パケットを受信した
void L3RecvArp(L3IF *f, PKT *p)
{
	ARPV4_HEADER *a;
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	a = p->L3.ARPv4Header;

	if (Endian16(a->HardwareType) != ARP_HARDWARE_TYPE_ETHERNET ||
		Endian16(a->ProtocolType) != MAC_PROTO_IPV4 ||
		a->HardwareSize != 6 || a->ProtocolSize != 4)
	{
		return;
	}
	if (Cmp(a->SrcAddress, p->MacAddressSrc, 6) != 0)
	{
		return;
	}

	switch (Endian16(a->Operation))
	{
	case ARP_OPERATION_REQUEST:
		// ARP 要求が届いた
		L3RecvArpRequest(f, p);
		break;

	case ARP_OPERATION_RESPONSE:
		// ARP 応答が届いた
		L3RecvArpResponse(f, p);
		break;
	}
}

// IP パケットを送信する
void L3SendIp(L3IF *f, L3PACKET *p)
{
	L3ARPENTRY *a = NULL;
	bool broadcast = false;
	IPV4_HEADER *ip;
	bool for_me = false;
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}
	if (p->Packet->TypeL3 != L3_IPV4)
	{
		return;
	}

	ip = p->Packet->L3.IPv4Header;

	// ブロードキャストかどうか判定
	if (p->NextHopIp == 0xffffffff ||
		((p->NextHopIp & f->SubnetMask) == (f->IpAddress & f->SubnetMask)) &&
		((p->NextHopIp & (~f->SubnetMask)) == (~f->SubnetMask)))
	{
		broadcast = true;
	}

	if (broadcast == false && ip->DstIP == f->IpAddress)
	{
		// me?
	}
	else if (broadcast == false)
	{
		// ユニキャストの場合 ARP エントリに入っているかどうか調べる
		a = L3SearchArpTable(f, p->NextHopIp);

		if (a == NULL)
		{
			// ARP エントリに入っていないので、すぐに送信せずに
			// IP 待ちリストに挿入する
			p->Expire = Tick64() + IP_WAIT_FOR_ARP_TIMEOUT;

			Insert(f->IpWaitList, p);

			// ARP を発行しておく
			L3SendArp(f, p->NextHopIp);
			return;
		}
	}

	if (for_me == false)
	{
		// IP パケットを送信する
		L3SendIpNow(f, a, p);
	}

	// パケットを解放する
	Free(p->Packet->PacketData);
	FreePacket(p->Packet);
	Free(p);
}

// IP パケットをすぐに送信する
void L3SendIpNow(L3IF *f, L3ARPENTRY *a, L3PACKET *p)
{
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	L3SendL2Now(f, a != NULL ? a->MacAddress : broadcast, f->MacAddress, Endian16(p->Packet->MacHeader->Protocol),
		p->Packet->L3.PointerL3, p->Packet->PacketSize - sizeof(MAC_HEADER));
}

// ARP テーブルを検索する
L3ARPENTRY *L3SearchArpTable(L3IF *f, UINT ip)
{
	L3ARPENTRY *e, t;
	// 引数チェック
	if (f == NULL || ip == 0 || ip == 0xffffffff)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.IpAddress = ip;

	e = Search(f->ArpTable, &t);

	return e;
}

// ARP 要求パケットを送信する
void L3SendArpRequestNow(L3IF *f, UINT dest_ip)
{
	ARPV4_HEADER arp;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	// ARP ヘッダを構築
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_REQUEST);
	Copy(arp.SrcAddress, f->MacAddress, 6);
	arp.SrcIP = f->IpAddress;
	Zero(&arp.TargetAddress, 6);
	arp.TargetIP = dest_ip;

	// 送信
	L3SendL2Now(f, broadcast, f->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// ARP 応答パケットを送信する
void L3SendArpResponseNow(L3IF *f, UCHAR *dest_mac, UINT dest_ip, UINT src_ip)
{
	ARPV4_HEADER arp;
	// 引数チェック
	if (f == NULL || dest_mac == NULL)
	{
		return;
	}

	// ヘッダ構築
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
	Copy(arp.SrcAddress, f->MacAddress, 6);
	Copy(arp.TargetAddress, dest_mac, 6);
	arp.SrcIP = src_ip;
	arp.TargetIP = dest_ip;

	// 送信
	L3SendL2Now(f, dest_mac, f->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// インターフェイスの MAC アドレスの生成
void L3GenerateMacAddress(L3IF *f)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, f->Switch->Name, StrLen(f->Switch->Name));
	WriteBuf(b, f->HubName, StrLen(f->HubName));
	WriteBuf(b, &f->IpAddress, sizeof(f->IpAddress));

	GenMacAddress(f->MacAddress);
	Hash(hash, b->Buf, b->Size, true);
	Copy(f->MacAddress + 2, hash, 4);
	f->MacAddress[1] = 0xA3;
	FreeBuf(b);
}

// L2 パケットをすぐに送信する
void L3SendL2Now(L3IF *f, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size)
{
	UCHAR *buf;
	MAC_HEADER *mac_header;
	PKT *p;
	// 引数チェック
	if (f == NULL || dest_mac == NULL || src_mac == NULL || data == NULL)
	{
		return;
	}

	// バッファ生成
	buf = Malloc(MAC_HEADER_SIZE + size);

	// MAC ヘッダ
	mac_header = (MAC_HEADER *)&buf[0];
	Copy(mac_header->DestAddress, dest_mac, 6);
	Copy(mac_header->SrcAddress, src_mac, 6);
	mac_header->Protocol = Endian16(protocol);

	// データのコピー
	Copy(&buf[sizeof(MAC_HEADER)], data, size);

	// サイズ
	size += sizeof(MAC_HEADER);

	// パケット生成
	p = ZeroMalloc(sizeof(PKT));
	p->PacketData = buf;
	p->PacketSize = size;

	// キューに追加する
	InsertQueue(f->SendQueue, p);
}

// ARP 解決待ちリストのポーリング
void L3PollingArpWaitTable(L3IF *f)
{
	UINT i;
	LIST *o = NULL;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->ArpWaitTable);i++)
	{
		L3ARPWAIT *w = LIST_DATA(f->ArpWaitTable, i);

		if (w->Expire <= Tick64())
		{
			// ARP 要求テーブルが期限切れである
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Insert(o, w);
		}
		else if ((w->LastSentTime + ARP_REQUEST_TIMEOUT) <= Tick64())
		{
			// 次の ARP 要求パケットを送信する
			w->LastSentTime = Tick64();

			L3SendArpRequestNow(f, w->IpAddress);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3ARPWAIT *w = LIST_DATA(o, i);

			Delete(f->ArpWaitTable, w);
			Free(w);
		}

		ReleaseList(o);
	}
}

// 古い ARP テーブルの清掃
void L3DeleteOldArpTable(L3IF *f)
{
	UINT i;
	LIST *o = NULL;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	if ((f->LastDeleteOldArpTable + ARP_ENTRY_POLLING_TIME) > Tick64())
	{
		return;
	}
	f->LastDeleteOldArpTable = Tick64();

	for (i = 0;i < LIST_NUM(f->ArpTable);i++)
	{
		L3ARPENTRY *a = LIST_DATA(f->ArpTable, i);

		if (a->Expire <= Tick64())
		{
			// 有効期限切れ
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Insert(o, a);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3ARPENTRY *a = LIST_DATA(o, i);

			Delete(f->ArpTable, a);
			Free(a);
		}

		ReleaseList(o);
	}
}

// IP 待ちリストの清掃
void L3DeleteOldIpWaitList(L3IF *f)
{
	UINT i;
	LIST *o = NULL;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->IpWaitList);i++)
	{
		L3PACKET *p = LIST_DATA(f->IpWaitList, i);

		if (p->Expire <= Tick64())
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Insert(o, p);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3PACKET *p = LIST_DATA(o, i);

			Delete(f->IpWaitList, p);

			Free(p->Packet->PacketData);
			FreePacket(p->Packet);
			Free(p);
		}

		ReleaseList(o);
	}
}

// ビーコン送信
void L3PollingBeacon(L3IF *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	if (f->LastBeaconSent == 0 ||
		(f->LastBeaconSent + BEACON_SEND_INTERVAL) <= Tick64())
	{
		UINT dest_ip;
		UCHAR *udp_buf;
		UINT udp_buf_size;
		ARPV4_HEADER arp;
		IPV4_HEADER *ip;
		UDP_HEADER *udp;
		static char beacon_str[] =
			"SoftEther UT-VPN Virtual Layer-3 Switch Beacon";

		// UDP を送信
		dest_ip = (f->IpAddress & f->SubnetMask) | (~f->SubnetMask);
		udp_buf_size = sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + sizeof(beacon_str);
		udp_buf = ZeroMalloc(udp_buf_size);

		ip = (IPV4_HEADER *)udp_buf;
		udp = (UDP_HEADER *)(udp_buf + sizeof(IPV4_HEADER));
		udp->DstPort = Endian16(7);
		udp->SrcPort = Endian16(7);
		udp->PacketLength = Endian16(sizeof(UDP_HEADER) + sizeof(beacon_str));

		Copy(udp_buf + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER), beacon_str, sizeof(beacon_str));

		udp->Checksum = IpChecksum(udp, sizeof(UDP_HEADER) + sizeof(beacon_str));

		ip->DstIP = dest_ip;
		IPV4_SET_VERSION(ip, 4);
		IPV4_SET_HEADER_LEN(ip, (IP_HEADER_SIZE / 4));
		ip->TypeOfService = DEFAULT_IP_TOS;
		ip->TotalLength = Endian16((USHORT)(udp_buf_size));
		ip->TimeToLive = DEFAULT_IP_TTL;
		ip->Protocol = IP_PROTO_UDP;
		ip->SrcIP = f->IpAddress;
		ip->Checksum = IpChecksum(ip, IP_HEADER_SIZE);

		L3SendL2Now(f, broadcast, f->MacAddress, MAC_PROTO_IPV4, udp_buf, udp_buf_size);

		Free(udp_buf);

		// ARP ヘッダを構築
		arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
		arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
		arp.HardwareSize = 6;
		arp.ProtocolSize = 4;
		arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
		Copy(arp.SrcAddress, f->MacAddress, 6);
		arp.SrcIP = f->IpAddress;
		arp.TargetAddress[0] =
			arp.TargetAddress[1] =
			arp.TargetAddress[2] =
			arp.TargetAddress[3] =
			arp.TargetAddress[4] =
			arp.TargetAddress[5] = 0xff;
		arp.TargetIP = dest_ip;

		// 送信
		L3SendL2Now(f, broadcast, f->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));

		f->LastBeaconSent = Tick64();
	}
}

// ポーリング処理
void L3Polling(L3IF *f)
{
	L3SW *s;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	s = f->Switch;

	// ポーリング処理の途中ではスイッチ全体にロックをかける
	Lock(s->lock);
	{
		// ビーコン送信
		L3PollingBeacon(f);

		// IP キューの処理
		L3PollingIpQueue(f);

		// 古い ARP テーブルの清掃
		L3DeleteOldArpTable(f);

		// ARP 解決待ちリストのポーリング
		L3PollingArpWaitTable(f);

		// IP 待ちリストの清掃
		L3DeleteOldIpWaitList(f);
	}
	Unlock(s->lock);
}

// 次のパケットを取得する
UINT L3GetNextPacket(L3IF *f, void **data)
{
	UINT ret = 0;
	// 引数チェック
	if (f == NULL || data == NULL)
	{
		return 0;
	}

START:
	// 送信キューを調べる
	LockQueue(f->SendQueue);
	{
		PKT *p = GetNext(f->SendQueue);

		if (p != NULL)
		{
			// パケットがあった
			ret = p->PacketSize;
			*data = p->PacketData;
			// パケット構造体は破棄して良い
			Free(p);
		}
	}
	UnlockQueue(f->SendQueue);

	if (ret == 0)
	{
		// ポーリング処理
		L3Polling(f);

        // ポーリング処理の結果、新たにパケットがキューに入っていないか
		// どうか調べる
		if (f->SendQueue->num_item != 0)
		{
			// キューに入っていたら早速そのパケットを取得させる
			goto START;
		}
	}

	return ret;
}

// 指定した IP アドレス宛のパケットをどのインターフェイスに投げれば良いか決める
L3IF *L3GetNextIf(L3SW *s, UINT ip, UINT *next_hop)
{
	UINT i;
	L3IF *f;
	UINT next_hop_ip = 0;
	// 引数チェック
	if (s == NULL || ip == 0 || ip == 0xffffffff)
	{
		return NULL;
	}

	f = NULL;

	// まず各インターフェイスの所属しているネットワークに指定した IP アドレスが
	// 含まれるものが無いかどうか調べる
	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *ff = LIST_DATA(s->IfList, i);

		if ((ff->IpAddress & ff->SubnetMask) == (ip & ff->SubnetMask))
		{
			f = ff;
			next_hop_ip = ip;
			break;
		}
	}

	if (f == NULL)
	{
		// 見つからなかったらルーティングテーブルを探す
		L3TABLE *t = L3GetBestRoute(s, ip);

		if (t == NULL)
		{
			// それでも見つからなかった
			return NULL;
		}
		else
		{
			// 見つかったルートの NextHop のルータの IP アドレスを持つ
			// インターフェイスを探す
			for (i = 0;i < LIST_NUM(s->IfList);i++)
			{
				L3IF *ff = LIST_DATA(s->IfList, i);

				if ((ff->IpAddress & ff->SubnetMask) == (t->GatewayAddress & ff->SubnetMask))
				{
					f = ff;
					next_hop_ip = t->GatewayAddress;
					break;
				}
			}
		}
	}

	if (f == NULL)
	{
		// 結局宛先インターフェイスが不明であった
		return NULL;
	}

	if (next_hop != NULL)
	{
		*next_hop = next_hop_ip;
	}

	return f;
}

// 指定した IP アドレス宛の最適なルーティングテーブルエントリを取得する
L3TABLE *L3GetBestRoute(L3SW *s, UINT ip)
{
	UINT i;
	UINT max_mask = 0;
	UINT min_metric = INFINITE;
	L3TABLE *ret = NULL;
	// 引数チェック
	if (s == NULL || ip == 0)
	{
		return NULL;
	}

	// 第一条件: サブネットマスクが最も大きいものを選択
	// 第二条件: メトリックが最も小さいものを選択
	for (i = 0;i < LIST_NUM(s->TableList);i++)
	{
		L3TABLE *t = LIST_DATA(s->TableList, i);

		if ((t->NetworkAddress & t->SubnetMask) == (ip & t->SubnetMask))
		{
			if (t->SubnetMask >= max_mask)
			{
				max_mask = t->SubnetMask;
				if (min_metric >= t->Metric)
				{
					min_metric = t->Metric;
					ret = t;
				}
			}
		}
	}

	return ret;
}

// Layer-3 インターフェイスの初期化
void L3InitInterface(L3IF *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	// MAC アドレス生成
	L3GenerateMacAddress(f);

	// リスト生成
	f->ArpTable = NewList(CmpL3ArpEntry);
	f->ArpWaitTable = NewList(CmpL3ArpWaitTable);
	f->IpPacketQueue = NewQueue();
	f->IpWaitList = NewList(NULL);
	f->SendQueue = NewQueue();
}

// Layer-3 インターフェイスの解放
void L3FreeInterface(L3IF *f)
{
	UINT i;
	L3PACKET *p;
	PKT *pkt;
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->ArpTable);i++)
	{
		L3ARPENTRY *a = LIST_DATA(f->ArpTable, i);
		Free(a);
	}
	ReleaseList(f->ArpTable);
	f->ArpTable = NULL;

	for (i = 0;i < LIST_NUM(f->ArpWaitTable);i++)
	{
		L3ARPWAIT *w = LIST_DATA(f->ArpWaitTable, i);
		Free(w);
	}
	ReleaseList(f->ArpWaitTable);
	f->ArpWaitTable = NULL;

	while (p = GetNext(f->IpPacketQueue))
	{
		Free(p->Packet->PacketData);
		FreePacket(p->Packet);
		Free(p);
	}
	ReleaseQueue(f->IpPacketQueue);
	f->IpPacketQueue = NULL;

	for (i = 0;i < LIST_NUM(f->IpWaitList);i++)
	{
		L3PACKET *p = LIST_DATA(f->IpWaitList, i);
		Free(p->Packet->PacketData);
		FreePacket(p->Packet);
		Free(p);
	}
	ReleaseList(f->IpWaitList);
	f->IpWaitList = NULL;

	while (pkt = GetNext(f->SendQueue))
	{
		Free(pkt->PacketData);
		FreePacket(pkt);
	}
	ReleaseQueue(f->SendQueue);
	f->SendQueue = NULL;
}

// Layer-3 インターフェイスのスレッド
void L3IfThread(THREAD *t, void *param)
{
	L3IF *f;
	CONNECTION *c;
	SESSION *s;
	POLICY *policy;
	char tmp[MAX_SIZE];
	char name[MAX_SIZE];
	char username[MAX_SIZE];
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	f = (L3IF *)param;

	StrCpy(username, sizeof(username), L3_USERNAME);
	if (f->Switch != NULL)
	{
		StrCat(username, sizeof(username), f->Switch->Name);
	}

	// コネクションの作成
	c = NewServerConnection(f->Switch->Cedar, NULL, t);
	c->Protocol = CONNECTION_HUB_LAYER3;

	// セッションの作成
	policy = ClonePolicy(GetDefaultPolicy());
	// ポリシーではブロードキャスト数を制限しない
	policy->NoBroadcastLimiter = true;
	s = NewServerSession(f->Switch->Cedar, c, f->Hub, username, policy);
	c->Session = s;

	ReleaseConnection(c);

	// セッション名を決定する
	GetMachineHostName(tmp, sizeof(tmp));
	if (f->Switch->Cedar->Server->ServerType == SERVER_TYPE_STANDALONE)
	{
		Format(name, sizeof(name), "SID-L3-%s-%u", f->Switch->Name, Inc(f->Hub->SessionCounter));
	}
	else
	{
		Format(name, sizeof(name), "SID-L3-%s-%s-%u", tmp, f->Switch->Name, Inc(f->Hub->SessionCounter));
	}
	ConvertSafeFileName(name, sizeof(name), name);
	StrUpper(name);

	Free(s->Name);
	s->Name = CopyStr(name);

	s->L3SwitchMode = true;
	s->L3If = f;

	if (s->Username != NULL)
	{
		Free(s->Username);
	}
	s->Username = CopyStr(username);

	StrCpy(s->UserNameReal, sizeof(s->UserNameReal), username);

	f->Session = s;
	AddRef(s->ref);

	// 初期化完了を通知
	NoticeThreadInit(t);

	// セッションメイン処理
	SessionMain(s);

	// セッションの解放
	ReleaseSession(s);
}

// すべての Layer-3 インターフェイスの初期化をする
void L3InitAllInterfaces(L3SW *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *f = LIST_DATA(s->IfList, i);
		THREAD *t;

		L3InitInterface(f);

		f->Hub = GetHub(s->Cedar, f->HubName);
		t = NewThread(L3IfThread, f);
		WaitThreadInit(t);
		ReleaseThread(t);
	}
}

// すべての Layer-3 インターフェイスの解放をする
void L3FreeAllInterfaces(L3SW *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *f = LIST_DATA(s->IfList, i);

		ReleaseHub(f->Hub);
		f->Hub = NULL;
		ReleaseSession(f->Session);
		f->Session = NULL;

		L3FreeInterface(f);
	}
}

// Layer-3 テスト
void L3Test(SERVER *s)
{
	L3SW *ss = L3AddSw(s->Cedar, "TEST");
	L3AddIf(ss, "DEFAULT", 0x0101a8c0, 0x00ffffff);
	L3AddIf(ss, "DEFAULT2", 0x0102a8c0, 0x00ffffff);
	L3SwStart(ss);
	ReleaseL3Sw(ss);
}

// Layer-3 スイッチスレッド
void L3SwThread(THREAD *t, void *param)
{
	L3SW *s;
	bool shutdown_now = false;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (L3SW *)param;

	s->Active = true;

	NoticeThreadInit(t);

	// 動作開始
	SLog(s->Cedar, "L3_SWITCH_START", s->Name);

	while (s->Halt == false)
	{
		if (s->Online == false)
		{
			// 現在 L3 スイッチはオフラインなので、一定時間ごとにオンライン化
			// を試みる
			LockList(s->Cedar->HubList);
			{
				Lock(s->lock);
				{
					UINT i;
					UINT n = 0;
					bool all_exists = true;
					if (LIST_NUM(s->IfList) == 0)
					{
						// 1 つもインターフェイスが無い場合は動作しない
						all_exists = false;
					}
					for (i = 0;i < LIST_NUM(s->IfList);i++)
					{
						L3IF *f = LIST_DATA(s->IfList, i);
						HUB *h = GetHub(s->Cedar, f->HubName);

						if (h != NULL)
						{
							if (h->Offline || h->Type == HUB_TYPE_FARM_DYNAMIC)
							{
								all_exists = false;
							}
							else
							{
								n++;
							}
							ReleaseHub(h);
						}
						else
						{
							all_exists = false;
						}
					}

					if (all_exists && n >= 1)
					{
						// すべてのインターフェイスの仮想 HUB が有効になったので
						// 動作を開始する
						SLog(s->Cedar, "L3_SWITCH_ONLINE", s->Name);
						L3InitAllInterfaces(s);
						s->Online = true;
					}
				}
				Unlock(s->lock);
			}
			UnlockList(s->Cedar->HubList);
		}
		else
		{
			// 一定時間ごとにすべてのセッションが終了していないかどうか調査する
			UINT i;
			bool any_halted = false;
			LIST *o = NULL;

SHUTDOWN:

			Lock(s->lock);
			{
				for (i = 0;i < LIST_NUM(s->IfList);i++)
				{
					L3IF *f = LIST_DATA(s->IfList, i);
					if (f->Session->Halt || f->Hub->Offline != false)
					{
						any_halted = true;
						break;
					}
				}

				if (shutdown_now)
				{
					any_halted = true;
				}

				if (any_halted)
				{
					SLog(s->Cedar, "L3_SWITCH_OFFLINE", s->Name);
					o = NewListFast(NULL);
					// 1 つでも終了したセッションがあれば、すべてのセッションを終了する
					for (i = 0;i < LIST_NUM(s->IfList);i++)
					{
						L3IF *f = LIST_DATA(s->IfList, i);
						Insert(o, f->Session);
					}

					// オフラインに戻す
					s->Online = false;
				}
			}
			Unlock(s->lock);

			if (o != NULL)
			{
				UINT i;
				for (i = 0;i < LIST_NUM(o);i++)
				{
					SESSION *s = LIST_DATA(o, i);
					StopSession(s);
				}
				L3FreeAllInterfaces(s);
				ReleaseList(o);
				o = NULL;
			}
		}

		SleepThread(50);
	}

	if (s->Online != false)
	{
		shutdown_now = true;
		goto SHUTDOWN;
	}

	// 動作停止
	SLog(s->Cedar, "L3_SWITCH_STOP", s->Name);
}

// Layer-3 スイッチを開始する
void L3SwStart(L3SW *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			// 登録されている IF 数が 1 以上でないと開始しない
			if (LIST_NUM(s->IfList) >= 1)
			{
				s->Halt = false;

				// スレッド作成
				s->Thread = NewThread(L3SwThread, s);
				WaitThreadInit(s->Thread);
			}
		}
	}
	Unlock(s->lock);
}

// Layer-3 スイッチを停止する
void L3SwStop(L3SW *s)
{
	THREAD *t = NULL;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			Unlock(s->lock);
			return;
		}

		s->Halt = true;

		t = s->Thread;

		s->Active = false;
	}
	Unlock(s->lock);

	WaitThread(t, INFINITE);
	ReleaseThread(t);
}

// Layer-3 スイッチを追加する
L3SW *L3AddSw(CEDAR *c, char *name)
{
	L3SW *s = NULL;
	// 引数チェック
	if (c == NULL || name == NULL)
	{
		return NULL;
	}

	LockList(c->L3SwList);
	{
		s = L3GetSw(c, name);

		if (s == NULL)
		{
			s = NewL3Sw(c, name);

			Insert(c->L3SwList, s);

			AddRef(s->ref);
		}
		else
		{
			ReleaseL3Sw(s);
			s = NULL;
		}
	}
	UnlockList(c->L3SwList);

	return s;
}

// Layer-3 スイッチを削除する
bool L3DelSw(CEDAR *c, char *name)
{
	L3SW *s;
	bool ret = false;
	// 引数チェック
	if (c == NULL || name == NULL)
	{
		return false;
	}

	LockList(c->L3SwList);
	{
		s = L3GetSw(c, name);

		if (s != NULL)
		{
			// 停止して削除
			L3SwStop(s);
			Delete(c->L3SwList, s);
			ReleaseL3Sw(s);
			ReleaseL3Sw(s);

			ret = true;
		}
	}
	UnlockList(c->L3SwList);

	return ret;
}


// ルーティングテーブルの削除
bool L3DelTable(L3SW *s, L3TABLE *tbl)
{
	bool ret = false;
	// 引数チェック
	if (s == NULL || tbl == NULL)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			L3TABLE *t = Search(s->TableList, tbl);

			if (t != NULL)
			{
				Delete(s->TableList, t);
				Free(t);

				ret = true;
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// ルーティングテーブルの追加
bool L3AddTable(L3SW *s, L3TABLE *tbl)
{
	bool ret = false;
	// 引数チェック
	if (s == NULL || tbl == NULL)
	{
		return false;
	}

	if (tbl->Metric == 0 || tbl->GatewayAddress == 0 || tbl->GatewayAddress == 0xffffffff)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (LIST_NUM(s->TableList) >= GetServerCapsInt(s->Cedar->Server, "i_max_l3_table"))
		{
			// 数が多すぎる
		}
		else
		{
			// 作成
			if (s->Active == false)
			{
				if (Search(s->TableList, tbl) == NULL)
				{
					L3TABLE *t = ZeroMalloc(sizeof(L3TABLE));

					Copy(t, tbl, sizeof(L3TABLE));

					Insert(s->TableList, t);

					ret = true;
				}
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// L3 スイッチを取得する
L3SW *L3GetSw(CEDAR *c, char *name)
{
	L3SW t, *s;
	// 引数チェック
	if (c == NULL || name == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Name, sizeof(t.Name), name);

	LockList(c->L3SwList);
	{
		s = Search(c->L3SwList, &t);
	}
	UnlockList(c->L3SwList);

	if (s != NULL)
	{
		AddRef(s->ref);
	}

	return s;
}

// L3 スイッチから指定した仮想 HUB に接続されているインターフェイスを取得する
L3IF *L3SearchIf(L3SW *s, char *hubname)
{
	L3IF t, *f;
	// 引数チェック
	if (s == NULL || hubname == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);

	f = Search(s->IfList, &t);

	return f;
}

// インターフェイスの削除
bool L3DelIf(L3SW *s, char *hubname)
{
	L3IF *f;
	bool ret = false;
	// 引数チェック
	if (s == NULL || hubname == NULL)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			f = L3SearchIf(s, hubname);

			if (f != NULL)
			{
				// 削除する
				Delete(s->IfList, f);
				Free(f);

				ret = true;
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// インターフェイスの追加
bool L3AddIf(L3SW *s, char *hubname, UINT ip, UINT subnet)
{
	L3IF *f;
	bool ret = false;
	// 引数チェック
	if (s == NULL || hubname == NULL || IsSafeStr(hubname) == false ||
		ip == 0 || ip == 0xffffffff)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (LIST_NUM(s->TableList) >= GetServerCapsInt(s->Cedar->Server, "i_max_l3_if"))
		{
			// 数が多すぎる
		}
		else
		{
			if (s->Active == false)
			{
				// 同じ仮想 HUB にすでにインターフェイスが入っていないかどうか調べる
				if (L3SearchIf(s, hubname) == NULL)
				{
					// 追加
					f = ZeroMalloc(sizeof(L3IF));

					f->Switch = s;
					StrCpy(f->HubName, sizeof(f->HubName), hubname);
					f->IpAddress = ip;
					f->SubnetMask = subnet;

					Insert(s->IfList, f);

					ret = true;
				}
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// L3 スイッチのクリーンアップ
void CleanupL3Sw(L3SW *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *f = LIST_DATA(s->IfList, i);
		Free(f);
	}
	ReleaseList(s->IfList);

	for (i = 0;i < LIST_NUM(s->TableList);i++)
	{
		L3TABLE *t = LIST_DATA(s->TableList, i);
		Free(t);
	}
	ReleaseList(s->TableList);

	DeleteLock(s->lock);
	Free(s);
}

// L3 スイッチの解放
void ReleaseL3Sw(L3SW *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupL3Sw(s);
	}
}

// 新しい L3 スイッチを作成する
L3SW *NewL3Sw(CEDAR *c, char *name)
{
	L3SW *o;
	// 引数チェック
	if (c == NULL || name == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(L3SW));

	StrCpy(o->Name, sizeof(o->Name), name);

	o->lock = NewLock();
	o->ref = NewRef();
	o->Cedar = c;
	o->Active = false;

	o->IfList = NewList(CmpL3If);
	o->TableList = NewList(CmpL3Table);

	return o;
}

// Cedar にあるすべての L3 スイッチを停止する
void L3FreeAllSw(CEDAR *c)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	LockList(c->L3SwList);
	{
		for (i = 0;i < LIST_NUM(c->L3SwList);i++)
		{
			L3SW *s = LIST_DATA(c->L3SwList, i);
			Insert(o, CopyStr(s->Name));
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			char *name = LIST_DATA(o, i);

			L3DelSw(c, name);

			Free(name);
		}

		ReleaseList(o);
	}
	UnlockList(c->L3SwList);
}

// Cedar の L3 スイッチ機能を停止する
void FreeCedarLayer3(CEDAR *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	ReleaseList(c->L3SwList);
	c->L3SwList = NULL;
}

// Cedar の L3 スイッチ機能を開始する
void InitCedarLayer3(CEDAR *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->L3SwList = NewList(CmpL3Sw);
}

// インターフェイス比較関数
int CmpL3If(void *p1, void *p2)
{
	L3IF *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(L3IF **)p1;
	f2 = *(L3IF **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}

	return StrCmpi(f1->HubName, f2->HubName);
}

// ルーティングテーブル比較関数
int CmpL3Table(void *p1, void *p2)
{
	L3TABLE *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(L3TABLE **)p1;
	t2 = *(L3TABLE **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	if (t1->NetworkAddress > t2->NetworkAddress)
	{
		return 1;
	}
	else if (t1->NetworkAddress < t2->NetworkAddress)
	{
		return -1;
	}
	else if (t1->SubnetMask > t2->SubnetMask)
	{
		return 1;
	}
	else if (t1->SubnetMask < t2->SubnetMask)
	{
		return -1;
	}
	else if (t1->GatewayAddress > t2->GatewayAddress)
	{
		return 1;
	}
	else if (t1->GatewayAddress < t2->GatewayAddress)
	{
		return -1;
	}
	else if (t1->Metric > t2->Metric)
	{
		return 1;
	}
	else if (t1->Metric < t2->Metric)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// L3SW 比較関数
int CmpL3Sw(void *p1, void *p2)
{
	L3SW *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(L3SW **)p1;
	s2 = *(L3SW **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	return StrCmpi(s1->Name, s2->Name);
}

// ARP 待機エントリ比較関数
int CmpL3ArpWaitTable(void *p1, void *p2)
{
	L3ARPWAIT *w1, *w2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	w1 = *(L3ARPWAIT **)p1;
	w2 = *(L3ARPWAIT **)p2;
	if (w1 == NULL || w2 == NULL)
	{
		return 0;
	}
	if (w1->IpAddress > w2->IpAddress)
	{
		return 1;
	}
	else if (w1->IpAddress < w2->IpAddress)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// ARP エントリ比較関数
int CmpL3ArpEntry(void *p1, void *p2)
{
	L3ARPENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(L3ARPENTRY **)p1;
	e2 = *(L3ARPENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	if (e1->IpAddress > e2->IpAddress)
	{
		return 1;
	}
	else if (e1->IpAddress < e2->IpAddress)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

