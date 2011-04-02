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

// BridgeWin32.c
// Ethernet ブリッジプログラム (Win32 版)

#ifdef	BRIDGE_C

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Packet32.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>


static WP *wp = NULL;
static LIST *eth_list = NULL;

static LOCK *eth_list_lock = NULL;
static bool is_sep_mode = false;

#define	LOAD_DLL_ADDR(name)				\
	{									\
		void *addr = GetProcAddress(h, #name);	\
		Copy(&wp->name, &addr, sizeof(void *));	\
	}

// リスト比較
int CmpRpcEnumEthVLan(void *p1, void *p2)
{
	RPC_ENUM_ETH_VLAN_ITEM *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *((RPC_ENUM_ETH_VLAN_ITEM **)p1);
	v2 = *((RPC_ENUM_ETH_VLAN_ITEM **)p2);
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->DeviceName, v2->DeviceName);
}

// MTU の取得 (Windows では非サポート)
UINT EthGetMtu(ETH *e)
{
	return 0;
}

// MTU の設定 (Windows では非サポート)
bool EthSetMtu(ETH *e, UINT mtu)
{
	return false;
}

// MTU の設定がサポートされているかどうか取得 (Windows では非サポート)
bool EthIsChangeMtuSupported(ETH *e)
{
	return false;
}

// デバイスの VLAN 有効化状態を設定
bool SetVLanEnableStatus(char *title, bool enable)
{
	RPC_ENUM_ETH_VLAN t;
	RPC_ENUM_ETH_VLAN_ITEM *e;
	bool ret = false;
	char key[MAX_SIZE];
	char tcpkey[MAX_SIZE];
	char short_key[MAX_SIZE];
	// 引数チェック
	if (title == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (EnumEthVLanWin32(&t) == false)
	{
		return false;
	}

	e = FindEthVLanItem(&t, title);

	if (e != NULL)
	{
		if (GetClassRegKeyWin32(key, sizeof(key), short_key, sizeof(short_key), e->Guid))
		{
			if (StrCmpi(e->DriverType, "Intel") == 0)
			{
				if (enable)
				{
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "VlanFiltering", "0");
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "TaggingMode", "0");
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "MonitorMode", 1);
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled", 1);
				}
				else
				{
					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "TaggingMode") == 0)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "TaggingMode");
					}

					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorMode") == 1)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "MonitorMode");
					}

					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled") == 1)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "MonitorModeEnabled");
					}
				}

				ret = true;
			}
			else if (StrCmpi(e->DriverType, "Broadcom") == 0)
			{
				if (enable)
				{
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "PreserveVlanInfoInRxPacket", "1");
				}
				else
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, key, "PreserveVlanInfoInRxPacket");
				}

				ret = true;
			}
			else if (StrCmpi(e->DriverType, "Marvell") == 0)
			{
				if (enable)
				{
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "SkDisableVlanStrip", 1);
				}
				else
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, key, "SkDisableVlanStrip");
				}

				ret = true;
			}

			Format(tcpkey, sizeof(tcpkey),
				"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
				e->Guid);

			if (enable)
			{
				if (MsRegIsValue(REG_LOCAL_MACHINE, tcpkey, "MTU") == false)
				{
					MsRegWriteInt(REG_LOCAL_MACHINE, tcpkey, "MTU", 1500);
				}
			}
			else
			{
				UINT mtu = MsRegReadInt(REG_LOCAL_MACHINE, tcpkey, "MTU");
				if (mtu == 1500)
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, tcpkey, "MTU");
				}
			}
		}
	}

	FreeRpcEnumEthVLan(&t);

	return ret;
}

// デバイスを検索
RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name)
{
	UINT i;
	// 引数チェック
	if (t == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < t->NumItem;i++)
	{
		if (StrCmpi(t->Items[i].DeviceName, name) == 0)
		{
			return &t->Items[i];
		}
	}

	return NULL;
}

// デバイスの VLAN 有効化状態を取得
void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e)
{
	char key[MAX_SIZE];
	char short_key[MAX_SIZE];
	char tcpkey[MAX_SIZE];
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	e->Enabled = false;

	if (e->Support == false)
	{
		return;
	}

	if (GetClassRegKeyWin32(key, sizeof(key), short_key, sizeof(short_key), e->Guid) == false)
	{
		return;
	}

	Format(tcpkey, sizeof(tcpkey),
		"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
		e->Guid);

	if (StrCmpi(e->DriverType, "Intel") == 0)
	{
		char *VlanFiltering = MsRegReadStr(REG_LOCAL_MACHINE, key, "VlanFiltering");
		UINT MonitorMode = MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorMode");
		UINT MonitorModeEnabled = MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled");
		char *TaggingMode = MsRegReadStr(REG_LOCAL_MACHINE, key, "TaggingMode");

		if (StrCmpi(VlanFiltering, "0") == 0 &&
			MonitorMode == 1 &&
			MonitorModeEnabled == 1 &&
			StrCmpi(TaggingMode, "0") == 0)
		{
			e->Enabled = true;
		}

		Free(VlanFiltering);
		Free(TaggingMode);
	}
	else if (StrCmpi(e->DriverType, "Broadcom") == 0)
	{
		char *PreserveVlanInfoInRxPacket = MsRegReadStr(REG_LOCAL_MACHINE,
			key, "PreserveVlanInfoInRxPacket");

		if (StrCmpi(PreserveVlanInfoInRxPacket, "1") == 0)
		{
			e->Enabled = true;
		}

		Free(PreserveVlanInfoInRxPacket);
	}
	else if (StrCmpi(e->DriverType, "Marvell") == 0)
	{
		DWORD SkDisableVlanStrip = MsRegReadInt(REG_LOCAL_MACHINE,
			key, "SkDisableVlanStrip");

		if (SkDisableVlanStrip == 1)
		{
			e->Enabled = true;
		}
	}

	if (MsRegIsValue(REG_LOCAL_MACHINE, tcpkey, "MTU") == false)
	{
		e->Enabled = false;
	}
}

// デバイスの VLAN サポート状態を取得
void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e)
{
	BUF *b;
	char filename[MAX_SIZE];
	void *wow;
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	wow = MsDisableWow64FileSystemRedirection();

	// ドライバファイルを読み込む
	CombinePath(filename, sizeof(filename), MsGetSystem32Dir(), "drivers");
	CombinePath(filename, sizeof(filename), filename, e->DriverName);

	b = ReadDump(filename);

	if (b != NULL)
	{
		char intel1[] = "VlanFiltering";
		char intel2[] = "V\0l\0a\0n\0F\0i\0l\0t\0e\0r\0i\0n\0g";
		char intel3[] = "MonitorMode";
		char intel4[] = "M\0o\0n\0i\0t\0o\0r\0M\0o\0d\0e";
		char intel5[] = "TaggingMode";
		char intel6[] = "T\0a\0g\0g\0i\0n\0g\0M\0o\0d\0e";
		char broadcom1[] = "PreserveVlanInfoInRxPacket";
		char broadcom2[] = "P\0r\0e\0s\0e\0r\0v\0e\0V\0l\0a\0n\0I\0n\0f\0o\0I\0n\0R\0x\0P\0a\0c\0k\0e\0t";
		char marvell1[] = "SkDisableVlanStrip";
		char marvell2[] = "S\0k\0D\0i\0s\0a\0b\0l\0e\0V\0l\0a\0n\0S\0t\0r\0i\0p";
		char *driver_type = "";

		if (SearchBin(b->Buf, 0, b->Size, intel1, sizeof(intel1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel2, sizeof(intel2)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel3, sizeof(intel3)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel4, sizeof(intel4)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel5, sizeof(intel5)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel6, sizeof(intel6)) != INFINITE)
		{
			driver_type = "Intel";
		}
		else if (SearchBin(b->Buf, 0, b->Size, broadcom1, sizeof(broadcom1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, broadcom2, sizeof(broadcom2)) != INFINITE)
		{
			driver_type = "Broadcom";
		}
		else if (SearchBin(b->Buf, 0, b->Size, marvell1, sizeof(marvell1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, marvell2, sizeof(marvell2)) != INFINITE)
		{
			driver_type = "Marvell";
		}

		if (IsEmptyStr(driver_type) == false)
		{
			StrCpy(e->DriverType, sizeof(e->DriverType), driver_type);
			e->Support = true;
		}

		FreeBuf(b);
	}

	MsRestoreWow64FileSystemRedirection(wow);
}

// short_key からデバイスのインスタンス ID を取得する
char *SearchDeviceInstanceIdFromShortKey(char *short_key)
{
	char *ret = NULL;
	TOKEN_LIST *t1;
	// 引数チェック
	if (short_key == NULL)
	{
		return NULL;
	}

	t1 = MsRegEnumKey(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum");

	if (t1 != NULL)
	{
		TOKEN_LIST *t2;
		char tmp[MAX_SIZE];
		UINT i;

		for (i = 0;i < t1->NumTokens;i++)
		{
			Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Enum\\%s", t1->Token[i]);

			t2 = MsRegEnumKey(REG_LOCAL_MACHINE, tmp);

			if (t2 != NULL)
			{
				TOKEN_LIST *t3;
				UINT i;

				for (i = 0;i < t2->NumTokens;i++)
				{
					char tmp2[MAX_SIZE];

					Format(tmp2, sizeof(tmp2), "%s\\%s", tmp, t2->Token[i]);

					t3 = MsRegEnumKey(REG_LOCAL_MACHINE, tmp2);

					if (t3 != NULL)
					{
						UINT i;

						for (i = 0;i < t3->NumTokens;i++)
						{
							char tmp3[MAX_SIZE];
							char *s;

							Format(tmp3, sizeof(tmp3), "%s\\%s", tmp2, t3->Token[i]);

							s = MsRegReadStr(REG_LOCAL_MACHINE, tmp3, "Driver");

							if (s != NULL)
							{
								if (StrCmpi(s, short_key) == 0)
								{
									if (ret != NULL)
									{
										Free(ret);
									}

									ret = CopyStr(tmp3 + StrLen("SYSTEM\\CurrentControlSet\\Enum\\"));
								}

								Free(s);
							}
						}

						FreeToken(t3);
					}
				}

				FreeToken(t2);
			}
		}

		FreeToken(t1);
	}

	return ret;
}

// 物理 LAN カードの VLAN 対応状況の列挙
bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t)
{
	UINT i;
	LIST *o;
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}

	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	if (MsIsWin2000OrGreater() == false)
	{
		return false;
	}

	if (IsEthSupported() == false)
	{
		return false;
	}

	// アダプタ一覧の取得
	Lock(eth_list_lock);

	InitEthAdaptersList();

	o = NewListFast(CmpRpcEnumEthVLan);

	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);

		if (IsEmptyStr(a->Guid) == false)
		{
			char class_key[MAX_SIZE];
			char short_key[MAX_SIZE];

			if (GetClassRegKeyWin32(class_key, sizeof(class_key),
				short_key, sizeof(short_key), a->Guid))
			{
				char *device_instance_id = MsRegReadStr(REG_LOCAL_MACHINE, class_key, "DeviceInstanceID");

				if (IsEmptyStr(device_instance_id))
				{
					Free(device_instance_id);
					device_instance_id = SearchDeviceInstanceIdFromShortKey(short_key);
				}

				if (IsEmptyStr(device_instance_id) == false)
				{
					char device_key[MAX_SIZE];
					char *service_name;

					Format(device_key, sizeof(device_key), "SYSTEM\\CurrentControlSet\\Enum\\%s",
						device_instance_id);

					service_name = MsRegReadStr(REG_LOCAL_MACHINE, device_key, "Service");
					if (IsEmptyStr(service_name) == false)
					{
						char service_key[MAX_SIZE];
						char *sys;

						Format(service_key, sizeof(service_key),
							"SYSTEM\\CurrentControlSet\\services\\%s",
							service_name);

						sys = MsRegReadStr(REG_LOCAL_MACHINE, service_key, "ImagePath");

						if (IsEmptyStr(sys) == false)
						{
							char sysname[MAX_PATH];

							GetFileNameFromFilePath(sysname, sizeof(sysname), sys);

							Trim(sysname);

							if (EndWith(sysname, ".sys"))
							{
								// デバイス発見
								RPC_ENUM_ETH_VLAN_ITEM *e = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM));

								StrCpy(e->DeviceName, sizeof(e->DeviceName), a->Title);
								StrCpy(e->Guid, sizeof(e->Guid), a->Guid);
								StrCpy(e->DeviceInstanceId, sizeof(e->DeviceInstanceId), device_instance_id);
								StrCpy(e->DriverName, sizeof(e->DriverName), sysname);

								// デバイスの VLAN サポート状態を取得
								GetVLanSupportStatus(e);

								// 有効化状態を取得
								GetVLanEnableStatus(e);

								Insert(o, e);
							}
						}

						Free(sys);
					}

					Free(service_name);
				}

				Free(device_instance_id);
			}
		}
	}

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * i);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = LIST_DATA(o, i);

		Copy(&t->Items[i], e, sizeof(RPC_ENUM_ETH_VLAN_ITEM));

		Free(e);
	}

	ReleaseList(o);

	Unlock(eth_list_lock);

	return true;
}

// GUID からネットワーククラスデータのレジストリキーを取得
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid)
{
	TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	// 引数チェック
	if (key == NULL || short_key == NULL || guid == NULL)
	{
		return false;
	}

	t = MsRegEnumKey(REG_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
	if (t == NULL)
	{
		return false;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char keyname[MAX_SIZE];
		char *value;

		Format(keyname, sizeof(keyname),
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s",
			t->Token[i]);

		value = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "NetCfgInstanceId");

		if (StrCmpi(value, guid) == 0)
		{
			ret = true;

			StrCpy(key, key_size, keyname);

			Format(short_key, short_key_size, "{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s",
				t->Token[i]);
		}

		Free(value);
	}

	FreeToken(t);

	return ret;
}

// 複数のパケットを書き込む
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes)
{
	UINT i, total_size;
	UCHAR *buf;
	UINT write_pointer;
	// 引数チェック
	if (e == NULL || num == 0 || datas == NULL || sizes == NULL)
	{
		return;
	}

	if (IsWin32BridgeWithSep() == false)
	{
		// 古い WinPcap にはバグがあり、2 個以上の CPU が搭載されている場合に
		// ロックが不十分なところがあってカーネル内でクラッシュすることが
		// 頻繁にあった。そこで 1 個目の CPU でしか動作しないように工夫していた
		if (e->LastSetSingleCpu == 0 || (e->LastSetSingleCpu + 10000) <= Tick64())
		{
			e->LastSetSingleCpu = Tick64();
			MsSetThreadSingleCpu();
		}
	}

	// 必要なデータサイズの計算
	total_size = 0;
	for (i = 0;i < num;i++)
	{
		void *data = datas[i];
		UINT size = sizes[i];
		if (data != NULL && size >= 14 && size <= MAX_PACKET_SIZE)
		{
			total_size += size + sizeof(struct dump_bpf_hdr);
		}
	}

	// 適当やな
	buf = MallocFast(total_size * 100 / 75 + 1600);

	write_pointer = 0;
	// キューに入れる
	for (i = 0;i < num;i++)
	{
		void *data = datas[i];
		UINT size = sizes[i];
		if (data != NULL && size >= 14 && size <= MAX_PACKET_SIZE)
		{
			struct dump_bpf_hdr *h;

			h = (struct dump_bpf_hdr *)(buf + write_pointer);
			Zero(h, sizeof(struct dump_bpf_hdr));
			h->caplen = h->len = size;
			write_pointer += sizeof(struct dump_bpf_hdr);
			Copy(buf + write_pointer, data, size);
			write_pointer += size;

			PROBE_DATA2("EthPutPackets", data, size);
		}
		// 元のメモリは解放する
		Free(data);
	}

	// 送信
	if (total_size != 0)
	{
		wp->PacketSendPackets(e->Adapter, buf, total_size, true);
	}

	Free(buf);
}

// パケットを書き込む
void EthPutPacket(ETH *e, void *data, UINT size)
{
	// 引数チェック
	if (e == NULL || data == NULL || size == 0)
	{
		return;
	}
	if (size < 14 || size > MAX_PACKET_SIZE)
	{
		Free(data);
		return;
	}

	if (IsWin32BridgeWithSep() == false)
	{
		if (e->LastSetSingleCpu == 0 || (e->LastSetSingleCpu + 10000) <= Tick64())
		{
			e->LastSetSingleCpu = Tick64();
			MsSetThreadSingleCpu();
		}
	}

	wp->PacketInitPacket(e->PutPacket, data, size);
	wp->PacketSendPacket(e->Adapter, e->PutPacket, false);

	Free(data);
}

// 次のパケットを読み込む
UINT EthGetPacket(ETH *e, void **data)
{
	BLOCK *b;
	bool flag = false;
	// 引数チェック
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}

RETRY:
	// まずキューにパケットがたまっているかどうか見てみる
	b = GetNext(e->PacketQueue);
	if (b != NULL)
	{
		UINT size;
		size = b->Size;
		*data = b->Buf;
		Free(b);

		if (e->PacketQueue->num_item == 0)
		{
			e->Empty = true;
		}

		return size;
	}

	if (e->Empty)
	{
		e->Empty = false;
		return 0;
	}

	if (flag == false)
	{
		// 次のパケットの取得を試みる
		PROBE_STR("EthGetPacket: PacketInitPacket");
		wp->PacketInitPacket(e->Packet, e->Buffer, e->BufferSize);
		PROBE_STR("EthGetPacket: PacketReceivePacket");
		if (wp->PacketReceivePacket(e->Adapter, e->Packet, false) == false)
		{
			// 失敗
			return INFINITE;
		}
		else
		{
			UCHAR *buf;
			UINT total;
			UINT offset;

			buf = (UCHAR *)e->Packet->Buffer;
			total = e->Packet->ulBytesReceived;
			offset = 0;

			while (offset < total)
			{
				struct bpf_hdr *header;
				UINT packet_size;
				UCHAR *packet_data;

				header = (struct bpf_hdr *)(buf + offset);
				packet_size = header->bh_caplen;
				offset += header->bh_hdrlen;
				packet_data = buf + offset;
				offset = Packet_WORDALIGN(offset + packet_size);

				if (packet_size >= 14)
				{
					UCHAR *tmp;
					BLOCK *b;

					PROBE_DATA2("EthGetPacket: NewBlock", packet_data, packet_size);
					
					tmp = MallocFast(packet_size);

					Copy(tmp, packet_data, packet_size);
					b = NewBlock(tmp, packet_size, 0);
					InsertQueue(e->PacketQueue, b);
				}
			}

			flag = true;
			goto RETRY;
		}
	}

	// これ以上パケットを取得できない
	return 0;
}

// キャンセルオブジェクトの取得
CANCEL *EthGetCancel(ETH *e)
{
	// 引数チェック
	if (e == NULL)
	{
		return NULL;
	}

	AddRef(e->Cancel->ref);

	return e->Cancel;
}

// アダプタを閉じる
void CloseEth(ETH *e)
{
	BLOCK *b;
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	ReleaseCancel(e->Cancel);

	wp->PacketCloseAdapter(e->Adapter);
	wp->PacketFreePacket(e->Packet);
	wp->PacketFreePacket(e->PutPacket);

	while (b = GetNext(e->PacketQueue))
	{
		FreeBlock(b);
	}
	ReleaseQueue(e->PacketQueue);

	Free(e->Name);
	Free(e->Title);
	Free(e->Buffer);

	Free(e);
}

// アダプタを開く
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *ret;
	void *p;

	p = MsDisableWow64FileSystemRedirection();

	ret = OpenEthInternal(name, local, tapmode, tapaddr);

	MsRestoreWow64FileSystemRedirection(p);

	return ret;
}
ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr)
{
	WP_ADAPTER *t, tt;
	ETH *e;
	ADAPTER *a;
	HANDLE h;
	CANCEL *c;
	// 引数チェック
	if (name == NULL || IsEthSupported() == false)
	{
		return NULL;
	}

	if (tapmode)
	{
		// Win32 では tap はサポートしていない
		return NULL;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	Zero(&tt, sizeof(tt));
	StrCpy(tt.Title, sizeof(tt.Title), name);

	t = Search(eth_list, &tt);
	if (t == NULL)
	{
		Unlock(eth_list_lock);
		return NULL;
	}

	a = wp->PacketOpenAdapter(t->Name);
	if (a == NULL)
	{
		Unlock(eth_list_lock);
		return NULL;
	}

	if (IsWin32BridgeWithSep() == false)
	{
		MsSetThreadSingleCpu();
	}

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(t->Name);
	e->Title = CopyStr(t->Title);

	e->Adapter = a;

	wp->PacketSetBuff(e->Adapter, BRIDGE_WIN32_ETH_BUFFER);
	wp->PacketSetHwFilter(e->Adapter, local ? 0x0080 : 0x0020);
	wp->PacketSetMode(e->Adapter, PACKET_MODE_CAPT);
	wp->PacketSetReadTimeout(e->Adapter, -1);
	wp->PacketSetNumWrites(e->Adapter, 1);

	if (wp->PacketSetLoopbackBehavior != NULL)
	{
		if (GET_KETA(GetOsType(), 100) >= 3)
		{
			// Windows XP, Server 2003 以降
			bool ret = wp->PacketSetLoopbackBehavior(e->Adapter, 1);
			Debug("*** PacketSetLoopbackBehavior: %u\n", ret);

			e->LoopbackBlock = ret;
		}
	}

	h = wp->PacketGetReadEvent(e->Adapter);

	c = NewCancelSpecial(h);
	e->Cancel = c;

	e->Buffer = Malloc(BRIDGE_WIN32_ETH_BUFFER);
	e->BufferSize = BRIDGE_WIN32_ETH_BUFFER;
	e->Packet = wp->PacketAllocatePacket();

	e->PutPacket = wp->PacketAllocatePacket();

	e->PacketQueue = NewQueue();

	Unlock(eth_list_lock);

	return e;
}

// Ethernet アダプタリストの取得
TOKEN_LIST *GetEthList()
{
	TOKEN_LIST *ret;
	UINT i;

	if (IsEthSupported() == false)
	{
		return NULL;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = LIST_NUM(eth_list);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		ret->Token[i] = CopyStr(a->Title);
	}

	Unlock(eth_list_lock);

	return ret;
}

// WP_ADAPTER の名前比較
int CompareWpAdapter(void *p1, void *p2)
{
	int i;
	WP_ADAPTER *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(WP_ADAPTER **)p1;
	a2 = *(WP_ADAPTER **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	i = StrCmpi(a1->Title, a2->Title);
	return i;
}

// Ethernet アダプタリストの取得
LIST *GetEthAdapterList()
{
	void *p;
	LIST *o;

	p = MsDisableWow64FileSystemRedirection();

	o = GetEthAdapterListInternal();

	MsRestoreWow64FileSystemRedirection(p);

	return o;
}
LIST *GetEthAdapterListInternal()
{
	LIST *o;
	LIST *ret;
	UINT size;
	char *buf;
	UINT i, j;
	char *qos_tag = " (Microsoft's Packet Scheduler)";

	o = NewListFast(CompareWpAdapter);

	size = 200000;
	buf = ZeroMalloc(size);

	if (wp->PacketGetAdapterNames(buf, &size) == false)
	{
		Free(buf);
		return o;
	}

	i = 0;

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		// Windows NT
		if (size >= 2 && buf[0] != 0 && buf[1] != 0)
		{
			goto ANSI_STR;
		}

		while (true)
		{
			wchar_t tmp[MAX_SIZE];
			WP_ADAPTER *a;
			UniStrCpy(tmp, sizeof(tmp), L"");

			if (*((wchar_t *)(&buf[i])) == 0)
			{
				i += sizeof(wchar_t);
				break;
			}

			for (;*((wchar_t *)(&buf[i])) != 0;i += sizeof(wchar_t))
			{
				wchar_t str[2];
				str[0] = *((wchar_t *)(&buf[i]));
				str[1] = 0;
				UniStrCat(tmp, sizeof(tmp), str);
			}

			i += sizeof(wchar_t);

			a = ZeroMalloc(sizeof(WP_ADAPTER));
			UniToStr(a->Name, sizeof(a->Name), tmp);

			Add(o, a);
		}
	}
	else
	{
		// Windows 9x
ANSI_STR:
		while (true)
		{
			char tmp[MAX_SIZE];
			WP_ADAPTER *a;
			StrCpy(tmp, sizeof(tmp), "");

			if (*((char *)(&buf[i])) == 0)
			{
				i += sizeof(char);
				break;
			}

			for (;*((char *)(&buf[i])) != 0;i += sizeof(char))
			{
				char str[2];
				str[0] = *((char *)(&buf[i]));
				str[1] = 0;
				StrCat(tmp, sizeof(tmp), str);
			}

			i += sizeof(char);

			a = ZeroMalloc(sizeof(WP_ADAPTER));
			StrCpy(a->Name, sizeof(a->Name), tmp);

			Add(o, a);
		}
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		WP_ADAPTER *a = LIST_DATA(o, j);

		StrCpy(a->Title, sizeof(a->Title), &buf[i]);
		i += StrSize(a->Title);

		// Win9x で デバイスの説明が"Unknown"ならば1文字読み飛ばす。
		if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
		{
			if (StrCmp(a->Title, "Unknown") == 0)
			{
				if (buf[i] == 0)
				{
					i+=sizeof(char);
				}
			}
		}

		TrimCrlf(a->Title);
		Trim(a->Title);
		TrimCrlf(a->Title);
		Trim(a->Title);

		if (EndWith(a->Title, qos_tag))
		{
			a->Title[StrLen(a->Title) - StrLen(qos_tag)] = 0;
			TrimCrlf(a->Title);
			Trim(a->Title);
			TrimCrlf(a->Title);
			Trim(a->Title);
		}
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		// GUID の抽出
		WP_ADAPTER *a = LIST_DATA(o, j);

		StrCpy(a->Guid, sizeof(a->Guid), a->Name);
		ReplaceStr(a->Guid, sizeof(a->Guid), a->Guid, "\\Device\\SEP_", "");
		ReplaceStr(a->Guid, sizeof(a->Guid), a->Guid, "\\Device\\SEE_", "");
		ReplaceStr(a->Guid, sizeof(a->Guid), a->Guid, "\\Device\\NPF_", "");
		ReplaceStr(a->Guid, sizeof(a->Guid), a->Guid, "\\Device\\PCD_", "");
	}

	// ソート
	Sort(o);

	ret = NewListFast(CompareWpAdapter);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WP_ADAPTER *a = LIST_DATA(o, i);
		ADAPTER *ad;
		bool ok = false;

		if (SearchStrEx(a->Title, "ppp", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "wan", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "dialup", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "pptp", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "telepho", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "modem", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "ras", 0, false) != INFINITE)
		{
			Free(a);
			continue;
		}

		ad = wp->PacketOpenAdapter(a->Name);
		if (ad != NULL)
		{
			NetType type;
			if (wp->PacketGetNetType(ad, &type))
			{
				if (type.LinkType == 0)
				{
					char tmp[MAX_SIZE];
					UINT k;
					// Ethernet のみ
					StrCpy(tmp, sizeof(tmp), a->Title);

					for (k = 0;;k++)
					{
						if (k == 0)
						{
							StrCpy(tmp, sizeof(tmp), a->Title);
						}
						else
						{
							Format(tmp, sizeof(tmp), "%s (%u)", a->Title, k + 1);
						}

						ok = true;
						for (j = 0;j < LIST_NUM(ret);j++)
						{
							WP_ADAPTER *aa = LIST_DATA(ret, j);
							if (StrCmpi(aa->Title, tmp) == 0)
							{
								ok = false;
							}
						}

						if (ok)
						{
							break;
						}
					}

					StrCpy(a->Title, sizeof(a->Title), tmp);
					Add(ret, a);
				}
				else
				{
					Debug("%s: type = %u\n", a->Name, type.LinkType);
				}
			}
			else
			{
				Debug("%s: PacketGetNetType() Failed.\n", a->Name);
			}
			wp->PacketCloseAdapter(ad);
		}
		else
		{
			Debug("%s: PacketOpenAdapter() Failed.\n", a->Name);
		}

		if (ok == false)
		{
			Free(a);
		}
	}

	Free(buf);

	Sort(ret);

	ReleaseList(o);

	return ret;
}

// Ethernet アダプタのリストの初期化
void InitEthAdaptersList()
{
	if (eth_list != NULL)
	{
		FreeEthAdaptersList();
		eth_list = NULL;
	}
	eth_list = GetEthAdapterList();
}

// Ethernet アダプタのリストの解放
void FreeEthAdaptersList()
{
	UINT i;
	if (eth_list == NULL)
	{
		return;
	}
	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		Free(a);
	}
	ReleaseList(eth_list);
	eth_list = NULL;
}

// Ethernet がサポートされているかどうか
bool IsEthSupported()
{
	if (wp == NULL)
	{
		return false;
	}

	return wp->Inited;
}

// 現在の OS で PCD ドライバがサポートされているか
bool IsPcdSupported()
{
	UINT type;
	OS_INFO *info = GetOsInfo();

	type = info->OsType;

	if (OS_IS_WINDOWS_NT(type) == false)
	{
		// Windows NT 以外はダメ
		return false;
	}

	if (GET_KETA(type, 100) >= 2)
	{
		// Windows 2000 以降は良い
		return true;
	}

	// Windows NT 4.0, Longhorn はダメ

	return false;
}

// PCD ドライバのビルド番号を書き込む
void SavePcdDriverBuild(UINT build)
{
	MsRegWriteInt(REG_LOCAL_MACHINE, BRIDGE_WIN32_PCD_REGKEY, BRIDGE_WIN32_PCD_BUILDVALUE,
		build);
}

// PCD ドライバのビルド番号を読み込む
UINT LoadPcdDriverBuild()
{
	return MsRegReadInt(REG_LOCAL_MACHINE, BRIDGE_WIN32_PCD_REGKEY, BRIDGE_WIN32_PCD_BUILDVALUE);
}

// PCD ドライバのインストールを試みる
HINSTANCE InstallPcdDriver()
{
	HINSTANCE ret;
	void *p = MsDisableWow64FileSystemRedirection();

	ret = InstallPcdDriverInternal();

	MsRestoreWow64FileSystemRedirection(p);

	return ret;
}
HINSTANCE InstallPcdDriverInternal()
{
	char tmp[MAX_PATH];
	bool install_driver = true;
	HINSTANCE h;
	char *dll_filename;

	// まず sep.sys が system32\drivers ディレクトリにインストールされているかどうか確認する
	Format(tmp, sizeof(tmp), "%s\\drivers\\sep.sys", MsGetSystem32Dir());

	if (IsFileExists(tmp))
	{
		// ドライバが存在している場合は、次にレジストリからビルド番号を取得する
		if (LoadPcdDriverBuild() >= CEDAR_BUILD)
		{
			// すでに最新版のドライバがインストールされている
			install_driver = false;
		}
	}

	if (install_driver)
	{
		char *src_filename = BRIDGE_WIN32_PCD_SYS;
		// ドライバのインストールをする必要がある場合
		// まず Admin かどうかチェックする
		if (MsIsAdmin() == false)
		{
			// Admin で無い場合はドライバのインストールは不能である
			return NULL;
		}

		if (MsIsX64())
		{
			src_filename = BRIDGE_WIN32_PCD_SYS_X64;
		}

		if (MsIsIA64())
		{
			src_filename = BRIDGE_WIN32_PCD_SYS_IA64;
		}

		// sep.sys をコピーする
		if (FileCopy(src_filename, tmp) == false)
		{
			return NULL;
		}

		// ビルド番号を書き込む
		SavePcdDriverBuild(CEDAR_BUILD);
	}

	dll_filename = BRIDGE_WIN32_PCD_DLL;

	if (Is64())
	{
		if (MsIsX64())
		{
			dll_filename = BRIDGE_WIN32_PCD_DLL_X64;
		}
		else if (MsIsIA64())
		{
			dll_filename = BRIDGE_WIN32_PCD_DLL_IA64;
		}
	}

	// sep.dll を読み込んで初期化してみる
	h = MsLoadLibrary(dll_filename);
	if (h == NULL)
	{
		return NULL;
	}

	return h;
}

// Ethernet の初期化
void InitEth()
{
	HINSTANCE h;
	if (wp != NULL)
	{
		// 初期化済み
		return;
	}

	eth_list_lock = NewLock();

	wp = ZeroMalloc(sizeof(WP));

	is_sep_mode = false;

	if (IsPcdSupported())
	{
		// PCD がサポートされている OS である
		h = InstallPcdDriver();
		if (h != NULL)
		{
			// PCD を使って初期化を試みる
			if (InitWpWithLoadLibrary(wp, h) == false)
			{
				Debug("InitEth: SEP Failed.\n");
				FreeLibrary(h);
			}
			else
			{
				Debug("InitEth: SEP Loaded.\n");
				is_sep_mode = true;
			}
		}
	}

	if (wp->Inited == false)
	{
		// WinPcap の Packet.dll を使って初期化を試みる
		h = LoadLibrary(BRIDGE_WIN32_PACKET_DLL);
		if (h != NULL)
		{
			if (InitWpWithLoadLibrary(wp, h) == false)
			{
				Debug("InitEth: Packet.dll Failed.\n");
				FreeLibrary(h);
			}
			else
			{
				Debug("InitEth: Packet.dll Loaded.\n");
			}
		}
	}
}

// sep.sys を用いてブリッジを行っているかどうかを取得
bool IsWin32BridgeWithSep()
{
	return is_sep_mode;
}

// WP 構造体を DLL で初期化する
bool InitWpWithLoadLibrary(WP *wp, HINSTANCE h)
{
	TOKEN_LIST *o;
	// 引数チェック
	if (wp == NULL || h == NULL)
	{
		return false;
	}
	wp->Inited = true;
	wp->hPacketDll = h;

	LOAD_DLL_ADDR(PacketGetVersion);
	LOAD_DLL_ADDR(PacketGetDriverVersion);
	LOAD_DLL_ADDR(PacketSetMinToCopy);
	LOAD_DLL_ADDR(PacketSetNumWrites);
	LOAD_DLL_ADDR(PacketSetMode);
	LOAD_DLL_ADDR(PacketSetReadTimeout);
	LOAD_DLL_ADDR(PacketSetBpf);
	LOAD_DLL_ADDR(PacketSetSnapLen);
	LOAD_DLL_ADDR(PacketGetStats);
	LOAD_DLL_ADDR(PacketGetStatsEx);
	LOAD_DLL_ADDR(PacketSetBuff);
	LOAD_DLL_ADDR(PacketGetNetType);
	LOAD_DLL_ADDR(PacketOpenAdapter);
	LOAD_DLL_ADDR(PacketSendPacket);
	LOAD_DLL_ADDR(PacketSendPackets);
	LOAD_DLL_ADDR(PacketAllocatePacket);
	LOAD_DLL_ADDR(PacketInitPacket);
	LOAD_DLL_ADDR(PacketFreePacket);
	LOAD_DLL_ADDR(PacketReceivePacket);
	LOAD_DLL_ADDR(PacketSetHwFilter);
	LOAD_DLL_ADDR(PacketGetAdapterNames);
	LOAD_DLL_ADDR(PacketGetNetInfoEx);
	LOAD_DLL_ADDR(PacketRequest);
	LOAD_DLL_ADDR(PacketGetReadEvent);
	LOAD_DLL_ADDR(PacketSetDumpName);
	LOAD_DLL_ADDR(PacketSetDumpLimits);
	LOAD_DLL_ADDR(PacketSetDumpLimits);
	LOAD_DLL_ADDR(PacketIsDumpEnded);
	LOAD_DLL_ADDR(PacketStopDriver);
	LOAD_DLL_ADDR(PacketCloseAdapter);
	LOAD_DLL_ADDR(PacketSetLoopbackBehavior);

	if (wp->PacketSetMinToCopy == NULL ||
		wp->PacketSetNumWrites == NULL ||
		wp->PacketSetMode == NULL ||
		wp->PacketSetReadTimeout == NULL ||
		wp->PacketSetBuff == NULL ||
		wp->PacketGetNetType == NULL ||
		wp->PacketOpenAdapter == NULL ||
		wp->PacketSendPacket == NULL ||
		wp->PacketSendPackets == NULL ||
		wp->PacketAllocatePacket == NULL ||
		wp->PacketInitPacket == NULL ||
		wp->PacketFreePacket == NULL ||
		wp->PacketReceivePacket == NULL ||
		wp->PacketSetHwFilter == NULL ||
		wp->PacketGetAdapterNames == NULL ||
		wp->PacketGetNetInfoEx == NULL ||
		wp->PacketCloseAdapter == NULL)
	{
RELEASE:
		wp->Inited = false;
		wp->hPacketDll = NULL;

		return false;
	}

	o = GetEthList();
	if (o == NULL || o->NumTokens == 0)
	{
		FreeToken(o);
		goto RELEASE;
	}

	FreeToken(o);

	return true;
}

// Ethernet の解放
void FreeEth()
{
	if (wp == NULL)
	{
		// 初期化されていない
		return;
	}

	// アダプタリストの解放
	FreeEthAdaptersList();

	if (wp->Inited)
	{
		// DLL 解放
		FreeLibrary(wp->hPacketDll);
	}

	Free(wp);
	wp = NULL;

	DeleteLock(eth_list_lock);
	eth_list_lock = NULL;
}

// Ethernet デバイスに対応するネットワーク接続名を取得する
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name)
{
	WP_ADAPTER *t, tt;
	char *tmp = NULL, guid[MAX_SIZE];
	wchar_t *ncname = NULL;

	UniStrCpy(dst, size, L"");

	// 引数チェック
	if (device_name == NULL || IsEthSupported() == false || 
		IsNt() == false || MsIsWin2000OrGreater() == false)
	{
		return;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	Zero(&tt, sizeof(tt));
	StrCpy(tt.Title, sizeof(tt.Title), device_name);

	t = Search(eth_list, &tt);
	if (t == NULL)
	{
		Unlock(eth_list_lock);
		return;
	}

	tmp = Malloc(sizeof(t->Name));
	StrCpy(tmp, sizeof(t->Name), t->Name);
	Unlock(eth_list_lock);

	ReplaceStr(guid, sizeof(guid), tmp, "\\Device\\SEP_", "");
	Free(tmp);

	ReplaceStr(guid, sizeof(guid), guid, "\\Device\\SEE_", "");
	ReplaceStr(guid, sizeof(guid), guid, "\\Device\\NPF_", "");
	ReplaceStr(guid, sizeof(guid), guid, "\\Device\\PCD_", "");

	if(guid == NULL)
	{
		return;
	}

	ncname = MsGetNetworkConnectionName(guid);
	if(ncname != NULL)
	{
		UniStrCpy(dst, size, ncname);
	}
	Free(ncname);
}

#endif	// BRIDGE_C


