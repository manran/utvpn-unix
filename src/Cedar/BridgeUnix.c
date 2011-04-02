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

// BridgeUnix.c
// Ethernet ブリッジプログラム (UNIX 版)
//#define	BRIDGE_C
//#define	UNIX_LINUX

#ifdef	BRIDGE_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

#ifdef UNIX_SOLARIS
#include <sys/sockio.h>
#endif

#ifdef BRIDGE_PCAP
#include <pcap.h>
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#endif // BRIDGE_BPF

// 初期化
void InitEth()
{
}

// 解放
void FreeEth()
{
}

// Unix のデバイスの説明文字列の取得がサポートされているかどうか取得
bool EthIsInterfaceDescriptionSupportedUnix()
{
	bool ret = false;
	DIRLIST *d = EnumDir("/etc/sysconfig/networking/devices/");

	if (d == NULL)
	{
		return false;
	}

	if (d->NumFiles >= 1)
	{
		ret = true;
	}

	FreeDir(d);

	return ret;
}

// Unix のデバイスの説明文字列を取得
bool EthGetInterfaceDescriptionUnix(char *name, char *str, UINT size)
{
	char tmp[MAX_SIZE];
	bool ret = false;
	BUF *b;
	// 引数チェック
	if (name == NULL || str == NULL)
	{
		return false;
	}

	StrCpy(str, size, name);

	Format(tmp, sizeof(tmp), "/etc/sysconfig/networking/devices/ifcfg-%s", name);

	b = ReadDump(tmp);
	if (b != NULL)
	{
		char *line = CfgReadNextLine(b);

		if (IsEmptyStr(line) == false)
		{
			if (StartWith(line, "#"))
			{
				char tmp[MAX_SIZE];

				StrCpy(tmp, sizeof(tmp), line + 1);

				Trim(tmp);
				tmp[60] = 0;

				StrCpy(str, size, tmp);

				ret = true;
			}
		}

		Free(line);

		FreeBuf(b);
	}

	return ret;
}

// Raw ソケットを開く
int UnixEthOpenRawSocket()
{
#ifdef	UNIX_LINUX
	int s;

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
	{
		return INVALID_SOCKET;
	}
	else
	{
		return s;
	}
#else	// UNIX_LINUX
	return -1;
#endif	// UNIX_LINUX
}

// Ethernet 操作がサポートされているかどうか
bool IsEthSupported()
{
	bool ret = false;

#if		defined(UNIX_LINUX)
	ret = IsEthSupportedLinux();
#elif	defined(UNIX_SOLARIS)
	ret = IsEthSupportedSolaris();
#elif	defined(BRIDGE_PCAP)
	ret = true;
#elif	defined(BRIDGE_BPF)
	ret = true;
#endif
	return ret;
}

#ifdef	UNIX_LINUX
bool IsEthSupportedLinux()
{
	int s;

	// Raw ソケットを開いてみる
	s = UnixEthOpenRawSocket();
	if (s == INVALID_SOCKET)
	{
		// 失敗
		return false;
	}

	// 成功
	closesocket(s);

	return true;
}
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
bool IsEthSupportedSolaris()
{
	return true;
}
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
// アダプタ一覧を取得 (Solaris)
TOKEN_LIST *GetEthListSolaris()
{
	TOKEN_LIST *t;
	int i, s;
	LIST *o;


	o = NewListFast(CompareStr);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != INVALID_SOCKET)
	{
		struct lifnum lifn;
		lifn.lifn_family = AF_INET;
		lifn.lifn_flags = 0;
		if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) >= 0)
		{
			struct lifconf lifc;
			struct lifreq *buf;
			UINT numifs;
			UINT bufsize;
			
			numifs = lifn.lifn_count;
			Debug("NumIFs:%d\n",numifs);
			bufsize = numifs * sizeof(struct lifreq);
			buf = Malloc(bufsize);

			lifc.lifc_family = AF_INET;
			lifc.lifc_flags = 0;
			lifc.lifc_len = bufsize;
			lifc.lifc_buf = (char*) buf;
			if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) >= 0)
			{
				for (i = 0; i<numifs; i++)
				{
					if(StartWith(buf[i].lifr_name, "lo") == false){
						Add(o, CopyStr(buf[i].lifr_name));
					}
				}
			}
			Free(buf);
		}
		closesocket(s);
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *name = LIST_DATA(o, i);
		t->Token[i] = name;
	}

	ReleaseList(o);

	return t;
}
#endif	// UNIX_SOLARIS

#ifdef	UNIX_LINUX
// アダプタ一覧を取得 (Linux)
TOKEN_LIST *GetEthListLinux()
{
	struct ifreq ifr;
	TOKEN_LIST *t;
	UINT i, n;
	int s;
	LIST *o;
	char name[MAX_SIZE];

	o = NewListFast(CompareStr);

	s = UnixEthOpenRawSocket();
	if (s != INVALID_SOCKET)
	{
		n = 0;
		for (i = 0;;i++)
		{
			Zero(&ifr, sizeof(ifr));
			ifr.ifr_ifindex = i;

			if (ioctl(s, SIOCGIFNAME, &ifr) >= 0)
			{
				n = 0;
				StrCpy(name, sizeof(name), ifr.ifr_name);

				Zero(&ifr, sizeof(ifr));
				StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), name);
				if (ioctl(s, SIOCGIFHWADDR, &ifr) >= 0)
				{
					UINT type = ifr.ifr_hwaddr.sa_family;
					if (type == 1 || type == 2 || type == 6 || type == 800 || type == 801)
					{
						if (IsInListStr(o, name) == false)
						{
							if (StartWith(name, "tap_") == false)
							{
								Add(o, CopyStr(name));
							}
						}
					}
				}
			}
			else
			{
				n++;
				if (n >= 64)
				{
					break;
				}
			}
		}
		closesocket(s);
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *name = LIST_DATA(o, i);
		t->Token[i] = name;
	}

	ReleaseList(o);

	return t;
}
#endif	// UNIX_LINUX

#ifdef BRIDGE_PCAP
// アダプタ一覧を取得 (Pcap)
TOKEN_LIST *GetEthListPcap()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	LIST *o;
	TOKEN_LIST *t;
	int i;

	o = NewListFast(CompareStr);

	if( pcap_findalldevs(&alldevs,errbuf) != -1)
	{
		pcap_if_t *dev = alldevs;
		while(dev != NULL)
		{
			pcap_t *p;
			// デバイスを開いてみないとデバイスの種類が分からない？
			p = pcap_open_live(dev->name, 0, false, 0, errbuf);
			if(p != NULL)
			{
				int datalink = pcap_datalink(p);
	//			Debug("type:%s\n",pcap_datalink_val_to_name(datalink));
				pcap_close(p);
				if(datalink == DLT_EN10MB){
					// イーサネットデバイスのみ列挙する
					Add(o, CopyStr(dev->name));
				}
			}
			dev = dev->next;
		}
		pcap_freealldevs(alldevs);
	}
	
	Sort(o);
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}
	ReleaseList(o);
	return t;
}
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
// アダプタ一覧を取得 (BPF)
TOKEN_LIST *GetEthListBpf()
{
	struct ifaddrs *ifadrs;
	struct sockaddr_dl *sockadr;
	LIST *o;
	TOKEN_LIST *t;
	int i;

	o = NewListFast(CompareStr);

	// ネットワークデバイスの一覧を取得
	if(getifaddrs( &ifadrs ) == 0)
	{
		struct ifaddrs *ifadr = ifadrs;
		while(ifadr)
		{
			sockadr = (struct sockaddr_dl*)ifadr->ifa_addr;
			if(sockadr->sdl_family == AF_LINK && sockadr->sdl_type == IFT_ETHER)
			{
				// Ethernet デバイスか？
				if(!IsInListStr(o,ifadr->ifa_name))
				{
					// 既存でなければ追加（複数のMACアドレスを持つインターフェースへの対策）
					Add(o, CopyStr(ifadr->ifa_name));
				}
			}
			ifadr = ifadr -> ifa_next;
		}
		freeifaddrs(ifadrs);
	}

	Sort(o);
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}
	ReleaseList(o);
	return t;
}
#endif // BRIDGE_BPF

// アダプタ一覧を取得
TOKEN_LIST *GetEthList()
{
	TOKEN_LIST *t = NULL;

#if	defined(UNIX_LINUX)
	t = GetEthListLinux();
#elif	defined(UNIX_SOLARIS)
	t = GetEthListSolaris();
#elif	defined(BRIDGE_PCAP)
	t = GetEthListPcap();
#elif	defined(BRIDGE_BPF)
	t = GetEthListBpf();
#endif

	return t;
}

#ifdef	UNIX_LINUX
// アダプタを開く (Linux)
ETH *OpenEthLinux(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *e;
	struct ifreq ifr;
	struct sockaddr_ll addr;
	int s;
	int index;
	CANCEL *c;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	if (tapmode)
	{
#ifndef	NO_VLAN
		// tap モードの場合
		VLAN *v = NewTap(name, tapaddr);
		if (v == NULL)
		{
			return NULL;
		}

		e = ZeroMalloc(sizeof(ETH));
		e->Name = CopyStr(name);
		e->Title = CopyStr(name);
		e->Cancel = VLanGetCancel(v);
		e->IfIndex = 0;
		e->Socket = INVALID_SOCKET;
		e->Tap = v;

		return e;
#else	// NO_VLAN
		return NULL;
#endif	// NO_VLAN
	}

	s = UnixEthOpenRawSocket();
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&ifr, sizeof(ifr));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), name);

	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
	{
		closesocket(s);
		return NULL;
	}

	index = ifr.ifr_ifindex;

	Zero(&addr, sizeof(addr));
	addr.sll_family = PF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = index;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		closesocket(s);
		return NULL;
	}

	if (local == false)
	{
		// プロミスキャスモードに設定する
		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), name);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		{
			// 失敗
			closesocket(s);
			return NULL;
		}

		ifr.ifr_flags |= IFF_PROMISC;

		if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		{
			// 失敗
			closesocket(s);
			return NULL;
		}
	}

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);
	e->IfIndex = index;
	e->Socket = s;

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	UnixSetSocketNonBlockingMode(s, true);

	c->SpecialFlag = true;
	c->pipe_read = s;

	e->Cancel = c;

	// MTU の取得
	e->InitialMtu = EthGetMtu(e);

	return e;
}
#endif	// UNIX_LINUX

// MTU の値を取得
UINT EthGetMtu(ETH *e)
{
#if	defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	UINT ret = 0;
#ifdef	UNIX_SOLARIS
	struct lifreq ifr;
#else	// UNIX_SOLARIS
	struct ifreq ifr;
#endif	// UNIX_SOLARIS
	int s;
	// 引数チェック
	if (e == NULL || e->Tap != NULL)
	{
		return 0;
	}

	if (e->CurrentMtu != 0)
	{
		return e->CurrentMtu;
	}

#if	defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->SocketBsdIf;
#else	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->Socket;
#endif	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)

	Zero(&ifr, sizeof(ifr));

#ifdef	UNIX_SOLARIS
	StrCpy(ifr.lifr_name, sizeof(ifr.lifr_name), e->Name);
#else	// UNIX_SOLARIS
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), e->Name);
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
	if (ioctl(s, SIOCGLIFMTU, &ifr) < 0)
	{
		// 失敗
		return 0;
	}
#else	// UNIX_SOLARIS
	if (ioctl(s, SIOCGIFMTU, &ifr) < 0)
	{
		// 失敗
		return 0;
	}
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
	ret = ifr.lifr_mtu + 14;
#else	// UNIX_SOLARIS
	ret = ifr.ifr_mtu + 14;
#endif	// UNIX_SOLARIS

	e->CurrentMtu = ret;

	Debug("%s: GetMtu: %u\n", e->Name, ret);

	return ret;
#else	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	return 0;
#endif	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
}

// MTU の値を設定
bool EthSetMtu(ETH *e, UINT mtu)
{
#if	defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	UINT ret = 0;
#ifdef	UNIX_SOLARIS
	struct lifreq ifr;
#else	// UNIX_SOLARIS
	struct ifreq ifr;
#endif	// UNIX_SOLARIS
	int s;
	// 引数チェック
	if (e == NULL || e->Tap != NULL || (mtu > 1 && mtu < 1514))
	{
		return false;
	}
	if (mtu == 0 && e->InitialMtu == 0)
	{
		return false;
	}

	if (mtu == 0)
	{
		// mtu == 0 の場合は MTU の値を元に戻す
		mtu = e->InitialMtu;
	}

#if	defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->SocketBsdIf;
#else	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->Socket;
#endif	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)

	if (e->CurrentMtu == mtu)
	{
		// 変更の必要なし
		return true;
	}

	Zero(&ifr, sizeof(ifr));

#ifdef	UNIX_SOLARIS
	StrCpy(ifr.lifr_name, sizeof(ifr.lifr_name), e->Name);
	ifr.lifr_mtu = mtu - 14;
#else	// UNIX_SOLARIS
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), e->Name);
	ifr.ifr_mtu = mtu - 14;
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
	if (ioctl(s, SIOCSLIFMTU, &ifr) < 0)
	{
		// 失敗
		return false;
	}
#else	// UNIX_SOLARIS
	if (ioctl(s, SIOCSIFMTU, &ifr) < 0)
	{
		// 失敗
		return false;
	}
#endif	// UNIX_SOLARIS

	e->CurrentMtu = mtu;

	Debug("%s: SetMtu: %u\n", e->Name, mtu);

	return true;
#else	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	return false;
#endif	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
}

// MTU の値の変更がサポートされているかどうか取得
bool EthIsChangeMtuSupported(ETH *e)
{
#if	defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	// 引数チェック
	if (e == NULL || e->Tap != NULL)
	{
		return false;
	}

	return true;
#else	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	return false;
#endif	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
}

#ifdef	UNIX_SOLARIS
// アダプタを開く (Solaris)
ETH *OpenEthSolaris(char *name, bool local, bool tapmode, char *tapaddr)
{
	char devname[MAX_SIZE];
	UINT devid;
	int fd;
	ETH *e;
	CANCEL *c;
	struct strioctl sioc;

	// 引数チェック
	if (name == NULL || tapmode != false)
	{
		return NULL;
	}

	// デバイス名を解析
	if (ParseUnixEthDeviceName(devname, sizeof(devname), &devid, name) == false)
	{
		return NULL;
	}

	// デバイスを開く
	fd = open(devname, O_RDWR);
	if (fd == -1)
	{
		// 失敗
		return NULL;
	}

	// デバイスにアタッチする
	if (DlipAttatchRequest(fd, devid) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// 確認
	if (DlipReceiveAck(fd) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// SAPにバインドする
	if (DlipBindRequest(fd) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// 確認
	if (DlipReceiveAck(fd) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// SAPに関わらず受信するモードにセットする
	if (DlipPromiscuous(fd, DL_PROMISC_SAP) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// 確認
	if (DlipReceiveAck(fd) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// 自分の送信するパケットも受信するモードにセットする
	if (DlipPromiscuous(fd, DL_PROMISC_PHYS) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// 確認
	if (DlipReceiveAck(fd) == false)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	// Raw モードに設定
	sioc.ic_cmd = DLIOCRAW;
	sioc.ic_timout = -1;
	sioc.ic_len = 0;
	sioc.ic_dp = NULL;
	if (ioctl(fd, I_STR, &sioc) < 0)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	if (ioctl(fd, I_FLUSH, FLUSHR) < 0)
	{
		// 失敗
		close(fd);
		return NULL;
	}

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	c->SpecialFlag = true;
	c->pipe_read = fd;

	e->Cancel = c;

	e->IfIndex = -1;
	e->Socket = fd;

	UnixSetSocketNonBlockingMode(fd, true);

	// 操作用 I/F の取得
	e->SocketBsdIf = socket(AF_INET, SOCK_DGRAM, 0);

	// MTU の取得
	e->InitialMtu = EthGetMtu(e);

	return e;
}

// プロミスキャスモードにセットする
bool DlipPromiscuous(int fd, UINT level)
{
	dl_promiscon_req_t req;
	struct strbuf ctl;
	int flags;
	// 引数チェック
	if (fd == -1)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	req.dl_primitive = DL_PROMISCON_REQ;
	req.dl_level = level;

	Zero(&ctl, sizeof(ctl));
	ctl.maxlen = 0;
	ctl.len = sizeof(req);
	ctl.buf = (char *)&req;

	flags = 0;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
	{
		return false;
	}

	return true;
}

// SAPにバインドする
bool DlipBindRequest(int fd)
{
	dl_bind_req_t	req;
	struct strbuf ctl;

	if (fd == -1)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	req.dl_primitive = DL_BIND_REQ;
	req.dl_service_mode = DL_CLDLS;
	req.dl_sap = 0;

	Zero(&ctl, sizeof(ctl));
	ctl.maxlen = 0;
	ctl.len = sizeof(req);
	ctl.buf = (char *)&req;

	if (putmsg(fd, &ctl, NULL, 0) < 0)
	{
		return false;
	}
	return true;
}

// デバイスにアタッチする
bool DlipAttatchRequest(int fd, UINT devid)
{
	dl_attach_req_t req;
	struct strbuf ctl;
	int flags;
	// 引数チェック
	if (fd == -1)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	req.dl_primitive = DL_ATTACH_REQ;
	req.dl_ppa = devid;

	Zero(&ctl, sizeof(ctl));
	ctl.maxlen = 0;
	ctl.len = sizeof(req);
	ctl.buf = (char *)&req;

	flags = 0;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
	{
		return false;
	}

	return true;
}

// 確認応答を受信する
bool DlipReceiveAck(int fd)
{
	union DL_primitives *dlp;
	struct strbuf ctl;
	int flags = 0;
	char *buf;
	// 引数チェック
	if (fd == -1)
	{
		return false;
	}

	buf = MallocFast(SOLARIS_MAXDLBUF);

	Zero(&ctl, sizeof(ctl));
	ctl.maxlen = SOLARIS_MAXDLBUF;
	ctl.len = 0;
	ctl.buf = buf;

	if (getmsg(fd, &ctl, NULL, &flags) < 0)
	{
		return false;
	}

	dlp = (union DL_primitives *)ctl.buf;
	if (dlp->dl_primitive != (UINT)DL_OK_ACK && dlp->dl_primitive != (UINT)DL_BIND_ACK)
	{
		Free(buf);
		return false;
	}

	Free(buf);

	return true;
}

#endif	// UNIX_SOLARIS

// UNIX のデバイス名文字列をデバイス名と番号に分ける
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, UINT *dst_devid, char *src_name)
{
	UINT len, i, j;

	// 引数チェック
	if (dst_devname == NULL || dst_devid == NULL || src_name == NULL)
	{
		return false;
	}

	len = strlen(src_name);
	// 文字列長チェック
	if(len == 0)
	{
		return false;
	}

	for (i = len-1; i+1 != 0; i--)
	{
		// 末尾からたどって最初に数字でない文字を検出
		if (src_name[i] < '0' || '9' < src_name[i])
		{
			// 最後の文字が数字でなければエラー
			if(src_name[i+1]==0)
			{
				return false;
			}
			*dst_devid = ToInt(src_name + i + 1);
			StrCpy(dst_devname, dst_devname_size, "/dev/");
			for (j = 0; j<i+1 && j<dst_devname_size-6; j++)
			{
				dst_devname[j+5] = src_name[j];
			}
			dst_devname[j+5]=0;
			return true;
		}
	}
	// 全て数字ならエラー
	return false;
}

#if defined(BRIDGE_BPF) || defined(BRIDGE_PCAP)
// キャプチャしたパケットデータ構造体の初期化
struct CAPTUREBLOCK *NewCaptureBlock(UCHAR *data, UINT size){
	struct CAPTUREBLOCK *block = Malloc(sizeof(struct CAPTUREBLOCK));
	block->Buf = data;
	block->Size = size;
	return block;
}

// キャプチャしたパケットデータ構造体の開放
void FreeCaptureBlock(struct CAPTUREBLOCK *block){
	Free(block);
}
#endif // BRIDGE_BPF || BRIDGE_PCAP

#ifdef	BRIDGE_PCAP
// パケット到着のコールバック関数
void PcapHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	ETH *e = (ETH*) user;
	struct CAPTUREBLOCK *block;
	UCHAR *data;
	
	data = Malloc(h->caplen);
	Copy(data, bytes, h->caplen);
	block = NewCaptureBlock(data, h->caplen);
	LockQueue(e->Queue);
	// キューのサイズが限界を超えたらパケットを破棄する。
	if(e->QueueSize < BRIDGE_MAX_QUEUE_SIZE){
		InsertQueue(e->Queue, block);
		e->QueueSize += h->caplen;
	}
	UnlockQueue(e->Queue);
	Cancel(e->Cancel);
	return;
}


// Pcap でのパケットキャプチャの中継用スレッド
void PcapThread(THREAD *thread, void *param)
{
	ETH *e = (ETH*)param;
	pcap_t *p = e->Pcap;
	int ret;

	// 初期化完了を通知
	NoticeThreadInit(thread);

	// 帰り値 -1:エラー -2:外部からの終了
	ret = pcap_loop(p, -1, PcapHandler, (u_char*) e);
	if(ret == -1){
		e->Socket = INVALID_SOCKET;
		pcap_perror(p, "capture");
	}
	return;
}


// アダプタを開く (Pcap)
ETH *OpenEthPcap(char *name, bool local, bool tapmode, char *tapaddr)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	ETH *e;
	pcap_t *p;
	CANCEL *c;

	// 引数チェック
	if (name == NULL || tapmode != false)
	{
		return NULL;
	}
	
	// エラーメッセージバッファの初期化
	errbuf[0] = 0;

	// キャプチャデバイスを開く
	p = pcap_open_live(name, 65535, (local == false), 1, errbuf);
	if(p==NULL)
	{
		return NULL;
	}

	// ノンブロックモードに設定
	// BSD系OSでは、BPFのselectが正常に動作しないのでブロックさせないとビジーループになる
	/*
	if(pcap_setnonblock(p, true, errbuf) == -1)
	{
		Debug("pcap_setnonblock:%s\n",errbuf);
		pcap_close(p);
		return NULL;
	}
	*/
	
	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);
	e->Queue = NewQueue();
	e->QueueSize = 0;
	e->Cancel = NewCancel();
	e->IfIndex = -1;
	e->Socket = pcap_get_selectable_fd(p);
	e->Pcap = p;
	
	e->CaptureThread = NewThread(PcapThread, e);
	WaitThreadInit(e->CaptureThread);

	return e;
}
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
#ifdef BRIDGE_BPF_THREAD
// BPF でのパケットキャプチャの中継用スレッド
void BpfThread(THREAD *thread, void *param)
{
	ETH *e = (ETH*)param;
	int fd = e->Socket;
	int len;
	int rest;	// バッファ中の残りバイト数
	UCHAR *next;	//バッファ中の次のパケットの先頭
	struct CAPTUREBLOCK *block;	// キューに追加するデータ
	UCHAR *data;
	struct bpf_hdr *hdr;

	// バッファを確保
	UCHAR *buf = Malloc(e->BufSize);
	
	// 初期化完了を通知
	NoticeThreadInit(thread);

	while(1){
		// ループの脱出判定
		if(e->Socket == INVALID_SOCKET){
			break;
		}
		
		rest = read(fd, buf, e->BufSize);
		if(rest < 0 && errno != EAGAIN){
			// エラー
			close(fd);
			e->Socket = INVALID_SOCKET;
			Free(buf);
			Cancel(e->Cancel);
			return;
		}
		next = buf;
		LockQueue(e->Queue);
		while(rest>0){
			// パケットの切り出し
			hdr = (struct bpf_hdr*)next;

			// Queue中のパケットサイズが限界を超えたらパケットを破棄する
			if(e->QueueSize < BRIDGE_MAX_QUEUE_SIZE){
				data = Malloc(hdr->bh_caplen);
				Copy(data, next+(hdr->bh_hdrlen), hdr->bh_caplen);
				block = NewCaptureBlock(data, hdr->bh_caplen);
				InsertQueue(e->Queue, block);
				e->QueueSize += hdr->bh_caplen;
			}

			// 次のパケットの頭出し
			rest -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
			next += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
		}
		UnlockQueue(e->Queue);
		Cancel(e->Cancel);
	}
	Free(buf);
	Cancel(e->Cancel);
	return;
}
#endif // BRIDGE_BPF_THREAD

// アダプタを開く (BPF)
ETH *OpenEthBpf(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *e;
	CANCEL *c;
	char devname[MAX_SIZE];
	int n = 0;
	int fd;
	int ret;
	UINT bufsize;
	struct ifreq ifr;
	struct timeval to;
	
	// 未使用の bpf デバイスを探して開く
	do{
		Format(devname, sizeof(devname), "/dev/bpf%d", n++);
		fd = open (devname, O_RDWR);
		if(fd<0){
			perror("open");
		}
	}while(fd < 0 && errno == EBUSY);
	
	// 開くことが出来るbpfデバイスが無ければエラー
	if(fd < 0){
		Debug("BPF: No minor number are free.\n");
		return NULL;
	}
	
	// バッファサイズを拡大
	n = 524288; // なんとなく(libpcapでは32768だった)
	while(true){
		// バッファサイズを指定
		ioctl(fd, BIOCSBLEN, &n);

		// ネットワークをバインド
		StrCpy(ifr.ifr_name, IFNAMSIZ, name);
		ret = ioctl(fd, BIOCSETIF, &ifr);
		if(ret < 0){
			if(ret == ENOBUFS && n>1500){
				// バッファサイズが不適切
				// サイズを半分にしてリトライ
				// バッファサイズ1500バイト以下でエラーになるのは何かおかしい
				n /= 2;
				continue;
			}
			Debug("bpf: binding network failed.\n");
			close(fd);
			return NULL;
		}else{
			break;
		}
	}
	bufsize = n;

	// プロミスキャスモードに設定
	if(local == false){
		if (ioctl(fd, BIOCPROMISC, NULL) < 0){
			printf("bpf: promisc mode failed.\n");
			close(fd);
			return NULL;
		}
	}

	
	// 即時モードに設定（パケットを受信するとタイムアウトを待たず、すぐにreadがreturnする）
	n = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &n) < 0){
		Debug("BPF: non-block mode failed.\n");
		close(fd);
		return NULL;
	}

	// 自分が送信するパケットも受信する
	n = 1;
	if (ioctl(fd, BIOCGSEESENT, &n) < 0){
		Debug("BPF: see sent mode failed.\n");
		close(fd);
		return NULL;
	}


	// ヘッダ完全モード（送信するパケットのヘッダも自分で生成する）
	n = 1;
	if (ioctl(fd, BIOCSHDRCMPLT, &n) < 0){
		Debug("BPF: Header complete mode failed.\n");
		close(fd);
		return NULL;
	}
	
	// read のタイムアウト時間を設定（1秒）
	to.tv_sec = 1;
	to.tv_usec = 0;
	if (ioctl(fd, BIOCSRTIMEOUT, &to) < 0){
		Debug("BPF: Read timeout setting failed.\n");
		close(fd);
		return NULL;
	}
	
	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);
	e->IfIndex = -1;
	e->Socket = fd;
	e->BufSize = bufsize;

#ifdef BRIDGE_BPF_THREAD
	e->Queue = NewQueue();
	e->QueueSize = 0;
	e->Cancel = NewCancel();

	// キャプチャ用スレッドの開始
	e->CaptureThread = NewThread(BpfThread, e);
	WaitThreadInit(e->CaptureThread);

#else // BRIDGE_BPF_THREAD
	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;
	c->SpecialFlag = true;
	c->pipe_read = fd;
	e->Cancel = c;
	e->Buffer = Malloc(bufsize);
	e->Next = e->Buffer;
	e->Rest = 0;

	// ノンブロッキングモードに設定
	UnixSetSocketNonBlockingMode(fd, true);
#endif // BRIDGE_BPF_THREAD

	// FreeBSD 用インターフェイス操作用ソケットを作成
	e->SocketBsdIf = socket(AF_LOCAL, SOCK_DGRAM, 0);

	// MTU の取得
	e->InitialMtu = EthGetMtu(e);

	return e;
}
#endif // BRIDGE_BPF

// アダプタを開く
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *ret = NULL;

#if		defined(UNIX_LINUX)
	ret = OpenEthLinux(name, local, tapmode, tapaddr);
#elif	defined(UNIX_SOLARIS)
	ret = OpenEthSolaris(name, local, tapmode, tapaddr);
#elif	defined(BRIDGE_PCAP)
	ret = OpenEthPcap(name, local, tapmode, tapaddr);
#elif	defined(BRIDGE_BPF)
	ret = OpenEthBpf(name, local, tapmode, tapaddr);
#endif

	return ret;
}

typedef struct UNIXTHREAD
{
	pthread_t thread;
	bool finished;
} UNIXTHREAD;

// アダプタを閉じる
void CloseEth(ETH *e)
{
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	if (e->Tap != NULL)
	{
#ifndef	NO_VLAN
		FreeTap(e->Tap);
#endif	// NO_VLAN
	}

#ifdef BRIDGE_PCAP
	{
		struct CAPTUREBLOCK *block;
		pcap_breakloop(e->Pcap);
		WaitThread(e->CaptureThread, INFINITE);
		ReleaseThread(e->CaptureThread);
		pcap_close(e->Pcap);
		while (block = GetNext(e->Queue)){
			Free(block->Buf);
			FreeCaptureBlock(block);
		}
		ReleaseQueue(e->Queue);
	}
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
#ifdef BRIDGE_BPF_THREAD
	{
		struct CAPTUREBLOCK *block;
		int fd = e->Socket;
		e->Socket = INVALID_SOCKET;
		WaitThread(e->CaptureThread, INFINITE);
		ReleaseThread(e->CaptureThread);
		e->Socket = fd; // 後でcloseするために復帰
		while (block = GetNext(e->Queue)){
			Free(block->Buf);
			FreeCaptureBlock(block);
		}
		ReleaseQueue(e->Queue);
	}
#else // BRIDGE_BPF_THREAD
	Free(e->Buffer);
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF

	ReleaseCancel(e->Cancel);
	Free(e->Name);
	Free(e->Title);

	// MTU の値を元に戻す
	EthSetMtu(e, 0);

	if (e->Socket != INVALID_SOCKET)
	{
#if defined(BRIDGE_BPF) || defined(BRIDGE_PCAP) || defined(UNIX_SOLARIS)
		close(e->Socket);
#else // BRIDGE_PCAP
		closesocket(e->Socket);
#endif // BRIDGE_PCAP
#if defined(BRIDGE_BPF) || defined(UNIX_SOLARIS)
		if (e->SocketBsdIf != INVALID_SOCKET)
		{
			close(e->SocketBsdIf);
		}
#endif	// BRIDGE_BPF || UNIX_SOLARIS
	}

	Free(e);
}

// キャンセルオブジェクトの取得
CANCEL *EthGetCancel(ETH *e)
{
	CANCEL *c;
	// 引数チェック
	if (e == NULL)
	{
		return NULL;
	}

	c = e->Cancel;
	AddRef(c->ref);

	return c;
}

// パケットの読み込み
UINT EthGetPacket(ETH *e, void **data)
{
	UINT ret = 0;

#if		defined(UNIX_LINUX)
	ret = EthGetPacketLinux(e, data);
#elif	defined(UNIX_SOLARIS)
	ret = EthGetPacketSolaris(e, data);
#elif	defined(BRIDGE_PCAP)
	ret = EthGetPacketPcap(e, data);
#elif	defined(BRIDGE_BPF)
	ret = EthGetPacketBpf(e, data);
#endif

	return ret;
}

#ifdef	UNIX_LINUX
UINT EthGetPacketLinux(ETH *e, void **data)
{
	int s, ret;
	UCHAR tmp[UNIX_ETH_TMP_BUFFER_SIZE];
	// 引数チェック
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}

	if (e->Tap != NULL)
	{
#ifndef	NO_VLAN
		// tap モード
		void *buf;
		UINT size;

		if (VLanGetNextPacket(e->Tap, &buf, &size) == false)
		{
			return INFINITE;
		}

		*data = buf;
		return size;
#else	// NO_VLAN
		return INFINITE;
#endif
	}

	s = e->Socket;

	if (s == INVALID_SOCKET)
	{
		return INFINITE;
	}

	// 読み込み
	ret = read(s, tmp, sizeof(tmp));
	if (ret == 0 || (ret == -1 && errno == EAGAIN))
	{
		// パケット無し
		*data = NULL;
		return 0;
	}
	else if (ret == -1 || ret > sizeof(tmp))
	{
		// エラー
		*data = NULL;
		e->Socket = INVALID_SOCKET;
		return INFINITE;
	}
	else
	{
		// パケット読み込み成功
		*data = MallocFast(ret);
		Copy(*data, tmp, ret);
		return ret;
	}

	return 0;
}
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
UINT EthGetPacketSolaris(ETH *e, void **data)
{
	UCHAR tmp[UNIX_ETH_TMP_BUFFER_SIZE];
	struct strbuf buf;
	int s;
	int flags = 0;
	int ret;
	// 引数チェック
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}

	s = e->Socket;
	if (s == INVALID_SOCKET)
	{
		return INFINITE;
	}

	Zero(&buf, sizeof(buf));
	buf.buf = tmp;
	buf.maxlen = sizeof(tmp);

	ret = getmsg(s, NULL, &buf, &flags);

	if (ret < 0 || ret > sizeof(tmp))
	{
		if (errno == EAGAIN)
		{
			// パケット無し
			*data = NULL;
			return 0;
		}
		// エラー
		*data = NULL;
		return INFINITE;
	}

	ret = buf.len;

	*data = MallocFast(ret);
	Copy(*data, tmp, ret);
	return ret;
}
#endif	// UNIX_SOLARIS

#ifdef	BRIDGE_PCAP
UINT EthGetPacketPcap(ETH *e, void **data)
{
	struct CAPTUREBLOCK *block;
	UINT size;
	
	LockQueue(e->Queue);
	block = GetNext(e->Queue);
	if(block != NULL){
		e->QueueSize -= block->Size;
	}
	UnlockQueue(e->Queue);
	
	if(block == NULL){
		*data = NULL;
		if(e->Socket == INVALID_SOCKET){
			return INFINITE;
		}
		return 0;
	}
	
	*data = block->Buf;
	size = block->Size;
	FreeCaptureBlock(block);
	
	return size;
}
#endif // BRIDGE_PCAP

#ifdef	BRIDGE_BPF
#ifdef BRIDGE_BPF_THREAD
UINT EthGetPacketBpf(ETH *e, void **data)
{
	struct CAPTUREBLOCK *block;
	UINT size;
	
	LockQueue(e->Queue);
	block = GetNext(e->Queue);
	if(block != NULL){
		e->QueueSize -= block->Size;
	}
	UnlockQueue(e->Queue);
	
	if(block == NULL){
		*data = NULL;
		if(e->Socket == INVALID_SOCKET){
			return INFINITE;
		}
		return 0;
	}
	
	*data = block->Buf;
	size = block->Size;
	FreeCaptureBlock(block);
	
	return size;
}
#else // BRIDGE_BPF_THREAD
UINT EthGetPacketBpf(ETH *e, void **data)
{
	struct bpf_hdr *hdr;
	
	if(e->Rest<=0){
		e->Rest = read(e->Socket, e->Buffer, e->BufSize);
		if(e->Rest < 0){
			*data = NULL;
			if(errno != EAGAIN){
				// エラー
				return INFINITE;
			}
			// データなし
			return 0;
		}
		e->Next = e->Buffer;
	}
	// パケットの切り出し
	hdr = (struct bpf_hdr*)e->Next;
	*data = Malloc(hdr->bh_caplen);
	Copy(*data, e->Next+(hdr->bh_hdrlen), hdr->bh_caplen);

	// 次のパケットの頭出し
	e->Rest -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
	e->Next += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
	
	return hdr->bh_caplen;
}
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF


// 複数のパケットの書き込み
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes)
{
	UINT i;
	// 引数チェック
	if (e == NULL || num == 0 || datas == NULL || sizes == NULL)
	{
		return;
	}

	for (i = 0;i < num;i++)
	{
		EthPutPacket(e, datas[i], sizes[i]);
	}
}

// パケットの書き込み
void EthPutPacket(ETH *e, void *data, UINT size)
{
	int s, ret;
	// 引数チェック
	if (e == NULL || data == NULL)
	{
		return;
	}
	if (size < 14 || size > MAX_PACKET_SIZE)
	{
		Free(data);
		return;
	}

	if (e->Tap != NULL)
	{
#ifndef	NO_VLAN
		// tap モード
		VLanPutPacket(e->Tap, data, size);
#endif	// NO_VLAN
		return;
	}

	s = e->Socket;

	if (s == INVALID_SOCKET)
	{
		Free(data);
		return;
	}

	// 書き込み
#ifdef BRIDGE_PCAP
	ret = pcap_inject(e->Pcap, data, size);
	if( ret == -1 ){
#ifdef _DEBUG
		pcap_perror(e->Pcap, "inject");
#endif // _DEBUG
		Debug("EthPutPacket: ret:%d size:%d\n", ret, size);
	}
#else // BRIDGE_PCAP
	ret = write(s, data, size);
	if (ret<0)
	{
		Debug("EthPutPacket: ret:%d errno:%d  size:%d\n", ret, errno, size);
	}
#endif //BRIDGE_PCAP
	
	Free(data);
}

#endif	// BRIDGE_C


