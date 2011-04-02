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

// VLanUnix.c
// UNIX 用仮想デバイスドライバライブラリ

#ifdef	VLAN_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

#ifdef	OS_UNIX

static LIST *unix_vlan = NULL;

#ifndef	NO_VLAN

// PACKET_ADAPTER の取得
PACKET_ADAPTER *VLanGetPacketAdapter()
{
	PACKET_ADAPTER *pa;

	pa = NewPacketAdapter(VLanPaInit, VLanPaGetCancel,
		VLanPaGetNextPacket, VLanPaPutPacket, VLanPaFree);
	if (pa == NULL)
	{
		return NULL;
	}

	return pa;
}

// PA 初期化
bool VLanPaInit(SESSION *s)
{
	VLAN *v;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	// ドライバに接続
	v = NewVLan(s->ClientOption->DeviceName, NULL);
	if (v == NULL)
	{
		// 失敗
		return false;
	}

	s->PacketAdapter->Param = v;

	return true;
}

// キャンセルオブジェクトの取得
CANCEL *VLanPaGetCancel(SESSION *s)
{
	VLAN *v;
	// 引数チェック
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return NULL;
	}

	return VLanGetCancel(v);
}

// パケットアダプタの解放
void VLanPaFree(SESSION *s)
{
	VLAN *v;
	// 引数チェック
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return;
	}

	// 仮想 LAN カードの終了
	FreeVLan(v);

	s->PacketAdapter->Param = NULL;
}

// パケットの書き込み
bool VLanPaPutPacket(SESSION *s, void *data, UINT size)
{
	VLAN *v;
	// 引数チェック
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return false;
	}

	return VLanPutPacket(v, data, size);
}

// 次のパケットを取得
UINT VLanPaGetNextPacket(SESSION *s, void **data)
{
	VLAN *v;
	UINT size;
	// 引数チェック
	if (data == NULL || (s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return INFINITE;
	}

	if (VLanGetNextPacket(v, data, &size) == false)
	{
		return INFINITE;
	}

	return size;
}

// パケットを仮想 LAN カードに書き込む
bool VLanPutPacket(VLAN *v, void *buf, UINT size)
{
	UINT ret;
	// 引数チェック
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}
	if (size > MAX_PACKET_SIZE)
	{
		return false;
	}
	if (buf == NULL || size == 0)
	{
		if (buf != NULL)
		{
			Free(buf);
		}
		return true;
	}

	ret = write(v->fd, buf, size);

	if (ret >= 1)
	{
		Free(buf);
		return true;
	}

	if (errno == EAGAIN || ret == 0)
	{
		Free(buf);
		return true;
	}

	return false;
}

// 仮想 LAN カードから次のパケットを取得する
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size)
{
	UCHAR tmp[TAP_READ_BUF_SIZE];
	int ret;
	// 引数チェック
	if (v == NULL || buf == NULL || size == 0)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	// 読み込み
	ret = read(v->fd, tmp, sizeof(tmp));

	if (ret == 0 ||
		(ret == -1 && errno == EAGAIN))
	{
		// パケット無し
		*buf = NULL;
		*size = 0;
		return true;
	}
	else if (ret == -1 || ret > TAP_READ_BUF_SIZE)
	{
		// エラー
		return false;
	}
	else
	{
		// パケット読み込み成功
		*buf = Malloc(ret);
		Copy(*buf, tmp, ret);
		*size = ret;
		return true;
	}
}

// キャンセルオブジェクトの取得
CANCEL *VLanGetCancel(VLAN *v)
{
	CANCEL *c;
	int fd;
	int yes = 0;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	fd = v->fd;

#ifndef	UNIX_MACOS
	UnixSetSocketNonBlockingMode(fd, true);
#else	// UNIX_MACOS
	UnixSetSocketNonBlockingMode(fd, false);
#endif	// UNIX_MACOS

	c->SpecialFlag = true;
	c->pipe_read = fd;

	return c;
}

// 仮想 LAN カードを閉じる
void FreeVLan(VLAN *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	Free(v->InstanceName);

	Free(v);
}

// tap の作成
VLAN *NewTap(char *name, char *mac_address)
{
	int fd;
	VLAN *v;
	// 引数チェック
	if (name == NULL || mac_address == NULL)
	{
		return NULL;
	}

	fd = UnixCreateTapDeviceEx(name, "tap", mac_address);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(name);
	v->fd = fd;

	return v;
}

// tap を閉じる
void FreeTap(VLAN *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	close(v->fd);
	FreeVLan(v);
}

// 仮想 LAN カードの取得
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param)
{
	int fd;
	VLAN *v;
	// 引数チェック
	if (instance_name == NULL)
	{
		return NULL;
	}

	// tap を開く
	fd = UnixVLanGet(instance_name);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(instance_name);
	v->fd = fd;

	return v;
}

// tap デバイスの作成
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address)
{
	int fd;
	struct ifreq ifr;
	char eth_name[MAX_SIZE];
	char instance_name_lower[MAX_SIZE];
	struct sockaddr sa;
	char *tap_name = TAP_FILENAME_1;
	int s;
	// 引数チェック
	if (name == NULL)
	{
		return -1;
	}

	// デバイス名を生成
	StrCpy(instance_name_lower, sizeof(instance_name_lower), name);
	Trim(instance_name_lower);
	StrLower(instance_name_lower);
	Format(eth_name, sizeof(eth_name), "%s_%s", prefix, instance_name_lower);

	eth_name[15] = 0;

	// tun/tap を開く
#ifndef	UNIX_MACOS
	if (GetOsInfo()->OsType == OSTYPE_LINUX)
	{
		// Linux
		if (IsFile(TAP_FILENAME_1) == false)
		{
			char tmp[MAX_SIZE];

			Format(tmp, sizeof(tmp), "%s c 10 200", TAP_FILENAME_1);
			Run("mknod", tmp, true, true);

			Format(tmp, sizeof(tmp), "600 %s", TAP_FILENAME_1);
			Run("chmod", tmp, true, true);
		}
	}
	// MacOS X 以外
	fd = open(TAP_FILENAME_1, O_RDWR);
	if (fd == -1)
	{
		// 失敗
		fd = open(TAP_FILENAME_2, O_RDWR);
		if (fd == -1)
		{
			return -1;
		}
		tap_name = TAP_FILENAME_2;
	}
#else	// UNIX_MACOS
	// MacOS X
	fd = open(TAP_MACOS_FILENAME, O_RDWR);
	if (fd == -1)
	{
		return -1;
	}
	tap_name = TAP_MACOS_FILENAME;
#endif	// UNIX_MACOS

#ifdef	UNIX_LINUX
	// Linux 用 tap の作成

	// デバイス名設定
	Zero(&ifr, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
	{
		// 失敗
		close(fd);
		return -1;
	}

	// MAC アドレス設定
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);
			ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
			Copy(&ifr.ifr_hwaddr.sa_data, mac_address, 6);
			ioctl(s, SIOCSIFHWADDR, &ifr);
		}

		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);
		ioctl(s, SIOCGIFFLAGS, &ifr);

		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);

		close(s);
	}

#else	// UNIX_LINUX
#ifdef	UNIX_SOLARIS
	// Solaris 用 tap の作成
	{
		int ip_fd;
		int tun_fd;
		int ppa;

		tun_fd = open(tap_name, O_RDWR);
		if (tun_fd == -1)
		{
			// 失敗
			close(fd);
			return -1;
		}

		ip_fd = open("/dev/ip", O_RDWR);
		if (ip_fd == -1)
		{
			// 失敗
			close(tun_fd);
			close(fd);
			return -1;
		}

		ppa = -1;
		ppa = ioctl(tun_fd, TUNNEWPPA, ppa);
		if (ppa == -1)
		{
			// 失敗
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, I_PUSH, "ip") < 0)
		{
			// 失敗
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, IF_UNITSEL, (char *)&ppa) < 0)
		{
			// 失敗
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(ip_fd, I_LINK, fd) < 0)
		{
			// 失敗
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		close(tun_fd);
		close(ip_fd);
	}

#endif	// UNIX_SOLARIS
#endif	// UNIX_LINUX

	return fd;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address)
{
	return UnixCreateTapDeviceEx(name, "utvpn", mac_address);
}

// tap デバイスを閉じる
void UnixCloseTapDevice(int fd)
{
	// 引数チェック
	if (fd == -1)
	{
		return;
	}

	close(fd);
}

#else	// NO_VLAN

void UnixCloseTapDevice(int fd)
{
}

int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address)
{
	return -1;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address)
{
	return -1;
}

#endif	// NO_VLAN

// VLAN リストの比較
int UnixCompareVLan(void *p1, void *p2)
{
	UNIX_VLAN_LIST *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(UNIX_VLAN_LIST **)p1;
	v2 = *(UNIX_VLAN_LIST **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->Name, v2->Name);
}

// VLAN リストの初期化
void UnixVLanInit()
{
	unix_vlan = NewList(UnixCompareVLan);
}

// VLAN の作成
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address)
{
	// 引数チェック
	char tmp[MAX_SIZE];
	if (name == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	name = tmp;

	LockList(unix_vlan);
	{
		UNIX_VLAN_LIST *t, tt;
		int fd;

		// 同一名のデバイスが存在していないかどうかチェック
		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			// すでに存在する
			UnlockList(unix_vlan);
			return false;
		}

		// tap デバイスを作成
		fd = UnixCreateTapDeviceEx(name, prefix, mac_address);
		if (fd == -1)
		{
			// 作成失敗
			UnlockList(unix_vlan);
			return false;
		}

		t = ZeroMalloc(sizeof(UNIX_VLAN_LIST));
		t->fd = fd;
		StrCpy(t->Name, sizeof(t->Name), name);

		Insert(unix_vlan, t);
	}
	UnlockList(unix_vlan);

	return true;
}
bool UnixVLanCreate(char *name, UCHAR *mac_address)
{
	return UnixVLanCreateEx(name, "utvpn", mac_address);
}

// VLAN の列挙
TOKEN_LIST *UnixVLanEnum()
{
	TOKEN_LIST *ret;
	UINT i;
	if (unix_vlan == NULL)
	{
		return NullToken();
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));

	LockList(unix_vlan);
	{
		ret->NumTokens = LIST_NUM(unix_vlan);
		ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);

		for (i = 0;i < ret->NumTokens;i++)
		{
			UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

			ret->Token[i] = CopyStr(t->Name);
		}
	}
	UnlockList(unix_vlan);

	return ret;
}

// VLAN の削除
void UnixVLanDelete(char *name)
{
	// 引数チェック
	if (name == NULL || unix_vlan == NULL)
	{
		return;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			UnixCloseTapDevice(t->fd);
			Delete(unix_vlan, t);
			Free(t);
		}
	}
	UnlockList(unix_vlan);
}

// VLAN の取得
int UnixVLanGet(char *name)
{
	int fd = -1;
	// 引数チェック
	if (name == NULL || unix_vlan == NULL)
	{
		return -1;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			fd = t->fd;
		}
	}
	UnlockList(unix_vlan);

	return fd;
}

// VLAN リストの解放
void UnixVLanFree()
{
	UINT i;

	for (i = 0;i < LIST_NUM(unix_vlan);i++)
	{
		UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

		UnixCloseTapDevice(t->fd);
		Free(t);
	}

	ReleaseList(unix_vlan);
	unix_vlan = NULL;
}

#endif	// OS_UNIX

#endif	// VLAN_C

