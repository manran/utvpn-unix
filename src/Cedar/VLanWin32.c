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

// VLanWin32.c
// Win32 用仮想デバイスドライバライブラリ

#ifdef	VLAN_C

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

#ifdef	OS_WIN32

typedef DWORD(CALLBACK* OPENVXDHANDLE)(HANDLE);

// Windows のバージョン情報の取得
void Win32GetWinVer(RPC_WINVER *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_WINVER));

	v->IsWindows = true;

	if (OS_IS_WINDOWS_NT(GetOsType()) == false)
	{
		// Windows 9x
		OSVERSIONINFO os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		GetVersionEx(&os);

		v->Build = LOWORD(os.dwBuildNumber);
		v->VerMajor = os.dwMajorVersion;
		v->VerMinor = os.dwMinorVersion;

		Format(v->Title, sizeof(v->Title), "%s %s",
			GetOsInfo()->OsProductName,
			GetOsInfo()->OsVersion);
		Trim(v->Title);
	}
	else
	{
		// Windows NT 4.0 SP6 以降
		OSVERSIONINFOEX os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		GetVersionEx((LPOSVERSIONINFOA)&os);

		v->IsNT = true;
		v->Build = os.dwBuildNumber;
		v->ServicePack = os.wServicePackMajor;

		if (os.wProductType != VER_NT_WORKSTATION)
		{
			v->IsServer = true;
		}
		v->VerMajor = os.dwMajorVersion;
		v->VerMinor = os.dwMinorVersion;

		if (GetOsInfo()->OsServicePack == 0)
		{
			StrCpy(v->Title, sizeof(v->Title), GetOsInfo()->OsProductName);
		}
		else
		{
			Format(v->Title, sizeof(v->Title), "%s Service Pack %u",
				GetOsInfo()->OsProductName,
				GetOsInfo()->OsServicePack);
		}
		Trim(v->Title);

		if (InStr(GetOsInfo()->OsVersion, "rc") ||
			InStr(GetOsInfo()->OsVersion, "beta"))
		{
			v->IsBeta = true;
		}
	}
}

// すべての仮想 LAN カードの DHCP アドレスを解放する
void Win32ReleaseAllDhcp9x(bool wait)
{
	TOKEN_LIST *t;
	UINT i;

	t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, "---dummy-string-ut--");
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		UINT id = GetInstanceId(name);
		if (id != 0)
		{
			Win32ReleaseDhcp9x(id, wait);
		}
	}

	FreeToken(t);
}

// ルーティングテーブル追跡メイン
void RouteTrackingMain(SESSION *s)
{
	ROUTE_TRACKING *t;
	UINT64 now;
	ROUTE_TABLE *table;
	ROUTE_ENTRY *rs;
	bool changed = false;
	bool check = false;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}
	if (s->ClientModeAndUseVLan == false)
	{
		return;
	}

	// 状態の取得
	t = ((VLAN *)s->PacketAdapter->Param)->RouteState;
	if (t == NULL)
	{
		return;
	}

	// 現在時刻
	PROBE_STR("RouteTrackingMain 1");
	now = Tick64();

	if (t->RouteChange != NULL)
	{
		if (t->NextRouteChangeCheckTime == 0 ||
			t->NextRouteChangeCheckTime <= now)
		{
			t->NextRouteChangeCheckTime = now + 1000ULL;

			check = IsRouteChanged(t->RouteChange);

			if (check)
			{
				Debug("*** Routing Table Changed ***\n");
				t->NextTrackingTime = 0;
			}
		}
	}
	if (t->NextTrackingTime != 0 && t->NextTrackingTime > now)
	{
		PROBE_STR("RouteTrackingMain 2");
		return;
	}
	PROBE_STR("RouteTrackingMain 3");

	// 現在のルーティングテーブルを取得
	table = GetRouteTable();
	rs = t->RouteToServer;
	if (table != NULL)
	{
		UINT i;
		bool route_to_server_erased = true;
		bool is_vlan_want_to_be_default_gateway = false;
		UINT vlan_default_gatewat_metric = 0;
		UINT other_if_default_gateway_metric_min = INFINITE;

		// ルーティングテーブルが変更されたかどうか取得
		if (t->LastRoutingTableHash != table->HashedValue)
		{
			t->LastRoutingTableHash = table->HashedValue;
			changed = true;
		}

		//DebugPrintRouteTable(table);

		// ルーティングテーブルを走査
		for (i = 0;i < table->NumEntry;i++)
		{
			ROUTE_ENTRY *e = table->Entry[i];

			if (rs != NULL)
			{
				if (CmpIpAddr(&e->DestIP, &rs->DestIP) == 0 &&
					CmpIpAddr(&e->DestMask, &rs->DestMask) == 0
//					&& CmpIpAddr(&e->GatewayIP, &rs->GatewayIP) == 0
//					&& e->InterfaceID == rs->InterfaceID &&
//					e->LocalRouting == rs->LocalRouting &&
//					e->Metric == rs->Metric
					)
				{
					// 接続時に追加したサーバーへのルーティングテーブルが見つかった
					route_to_server_erased = false;
				}
			}

			// デフォルトゲートウェイの検索
			if (IPToUINT(&e->DestIP) == 0 &&
				IPToUINT(&e->DestMask) == 0)
			{
				//Debug("e->InterfaceID = %u, t->VLanInterfaceId = %u\n",
				//	e->InterfaceID, t->VLanInterfaceId);

				if (e->InterfaceID == t->VLanInterfaceId)
				{
					// 仮想 LAN カードがデフォルトゲートウェイになりたいと思っている
					is_vlan_want_to_be_default_gateway = true;
					vlan_default_gatewat_metric = e->Metric;

					if (vlan_default_gatewat_metric >= 2 &&
						t->OldDefaultGatewayMetric == (vlan_default_gatewat_metric - 1))
					{
						// PPP サーバーが勝手に
						// ルーティングテーブルを書き換えたので戻す
						DeleteRouteEntry(e);
						e->Metric--;
						AddRouteEntry(e);
						Debug("** Restore metric destroyed by PPP.\n");
					}

					// このエントリを保存しておく
					if (t->DefaultGatewayByVLan != NULL)
					{
						// 前回追加したものがあれば削除する
						FreeRouteEntry(t->DefaultGatewayByVLan);
					}

					t->DefaultGatewayByVLan = ZeroMalloc(sizeof(ROUTE_ENTRY));
					Copy(t->DefaultGatewayByVLan, e, sizeof(ROUTE_ENTRY));

					t->OldDefaultGatewayMetric = vlan_default_gatewat_metric;
				}
				else
				{
					// 仮想 LAN カード以外にデフォルトゲートウェイが存在している
					// このデフォルトゲートウェイのメトリック値を記録しておく
					if (other_if_default_gateway_metric_min > e->Metric)
					{
						// Windows Vista の場合はすべての PPP 接続のメトリック値は無視する
						if (MsIsVista() == false || e->PPPConnection == false)
						{
							other_if_default_gateway_metric_min = e->Metric;
						}
						else
						{
							// Windows Vista を使用しており PPP を使ってネットワーク
							// に接続している
							t->VistaAndUsingPPP = true;
						}
					}
				}
			}
		}

		if (t->VistaAndUsingPPP)
		{
			if (t->DefaultGatewayByVLan != NULL)
			{
				if (is_vlan_want_to_be_default_gateway)
				{
					if (t->VistaOldDefaultGatewayByVLan == NULL || Cmp(t->VistaOldDefaultGatewayByVLan, t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY)) != 0)
					{
						ROUTE_ENTRY *e;
						// Windows Vista で PPP を使用して接続しており、かつ
						// 仮想 LAN カードがデフォルトゲートウェイになるべき場合は
						// 0.0.0.0/128.0.0.0 および 128.0.0.0/128.0.0.0 のルートを
						// システムに追加する

						if (t->VistaOldDefaultGatewayByVLan != NULL)
						{
							FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
						}

						if (t->VistaDefaultGateway1 != NULL)
						{
							DeleteRouteEntry(t->VistaDefaultGateway1);
							FreeRouteEntry(t->VistaDefaultGateway1);

							DeleteRouteEntry(t->VistaDefaultGateway2);
							FreeRouteEntry(t->VistaDefaultGateway2);
						}

						t->VistaOldDefaultGatewayByVLan = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));

						e = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));
						SetIP(&e->DestIP, 0, 0, 0, 0);
						SetIP(&e->DestMask, 128, 0, 0, 0);
						t->VistaDefaultGateway1 = e;

						e = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));
						SetIP(&e->DestIP, 128, 0, 0, 0);
						SetIP(&e->DestMask, 128, 0, 0, 0);
						t->VistaDefaultGateway2 = e;

						AddRouteEntry(t->VistaDefaultGateway1);
						AddRouteEntry(t->VistaDefaultGateway2);

						Debug("Vista PPP Fix Route Table Added.\n");
					}
				}
				else
				{
					if (t->VistaOldDefaultGatewayByVLan != NULL)
					{
						FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
						t->VistaOldDefaultGatewayByVLan = NULL;
					}

					if (t->VistaDefaultGateway1 != NULL)
					{
						Debug("Vista PPP Fix Route Table Deleted.\n");
						DeleteRouteEntry(t->VistaDefaultGateway1);
						FreeRouteEntry(t->VistaDefaultGateway1);

						DeleteRouteEntry(t->VistaDefaultGateway2);
						FreeRouteEntry(t->VistaDefaultGateway2);

						t->VistaDefaultGateway1 = t->VistaDefaultGateway2 = NULL;
					}
				}
			}
		}

		// 仮想 LAN カードがデフォルトゲートウェイになることを希望しており
		// かつ仮想 LAN カードの 0.0.0.0/0.0.0.0 のメトリック値よりも小さなメトリック値の
		// LAN カードが他に 1 枚も無い場合は、他のデフォルトゲートウェイエントリを削除して
		// 仮想 LAN カードをデフォルトゲートウェイに強制的に選出する
		if (is_vlan_want_to_be_default_gateway && (rs != NULL && route_to_server_erased == false) &&
			other_if_default_gateway_metric_min >= vlan_default_gatewat_metric)
		{
			// 再度ルーティングテーブルを走査
			for (i = 0;i < table->NumEntry;i++)
			{
				ROUTE_ENTRY *e = table->Entry[i];

				if (e->InterfaceID != t->VLanInterfaceId)
				{
					if (IPToUINT(&e->DestIP) == 0 &&
					IPToUINT(&e->DestMask) == 0)
					{
						char str[64];
						// デフォルトゲートウェイを発見
						ROUTE_ENTRY *r = ZeroMalloc(sizeof(ROUTE_ENTRY));

						Copy(r, e, sizeof(ROUTE_ENTRY));

						// キューに入れておく
						InsertQueue(t->DeletedDefaultGateway, r);

						// このゲートウェイエントリを一旦削除する
						DeleteRouteEntry(e);

						IPToStr(str, sizeof(str), &e->GatewayIP);
						Debug("Default Gateway %s Deleted.\n", str);
					}
				}
			}
		}

		if (rs != NULL && route_to_server_erased)
		{
			// サーバーへの物理的なエントリが消滅している
			Debug("Route to Server entry ERASED !!!\n");

			// 強制切断 (再接続有効)
			s->RetryFlag = true;
			s->Halt = true;
		}

		// ルーティングテーブルを解放
		FreeRouteTable(table);
	}

	// 次回トラッキングを行う時刻を設定
	if (t->NextTrackingTimeAdd == 0 || changed)
	{
		t->NextTrackingTimeAdd = TRACKING_INTERVAL_INITIAL;
	}
	else
	{
		UINT64 max_value = TRACKING_INTERVAL_MAX;
		if (t->RouteChange != NULL)
		{
			max_value = TRACKING_INTERVAL_MAX_RC;
		}

		t->NextTrackingTimeAdd += TRACKING_INTERVAL_ADD;

		if (t->NextTrackingTimeAdd >= max_value)
		{
			t->NextTrackingTimeAdd = max_value;
		}
	}
	//Debug("t->NextTrackingTimeAdd = %I64u\n", t->NextTrackingTimeAdd);
	t->NextTrackingTime = now + t->NextTrackingTimeAdd;
}

// ルーティングテーブルの追跡を開始する
void RouteTrackingStart(SESSION *s)
{
	VLAN *v;
	ROUTE_TRACKING *t;
	UINT if_id = 0;
	ROUTE_ENTRY *e;
	ROUTE_ENTRY *dns = NULL;
	char tmp[64];
	UINT exclude_if_id = 0;
	bool already_exists = false;
	bool already_exists_by_other_account = false;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	v = (VLAN *)s->PacketAdapter->Param;
	if (v->RouteState != NULL)
	{
		return;
	}

	// 仮想 LAN カードのインターフェース ID を取得する
	if_id = GetInstanceId(v->InstanceName);
	Debug("[InstanceId of %s] = 0x%x\n", v->InstanceName, if_id);

	if (MsIsVista())
	{
		// Windows Vista では明示的に仮想 LAN カード本体によるルーティングテーブル
		// を除外しなければならない
		exclude_if_id = if_id;
	}

	// サーバーまでのルートを取得する
	e = GetBestRouteEntryEx(&s->ServerIP, exclude_if_id);
	if (e == NULL)
	{
		// 取得失敗
		Debug("Failed to get GetBestRouteEntry().\n");
		return;
	}
	IPToStr(tmp, sizeof(tmp), &e->GatewayIP);
	Debug("GetBestRouteEntry() Succeed. [Gateway: %s]\n", tmp);

	// ルートを追加する
	if (MsIsVista())
	{
		e->Metric = e->OldIfMetric;
	}
	if (AddRouteEntryEx(e, &already_exists) == false)
	{
		FreeRouteEntry(e);
		e = NULL;
	}
	Debug("already_exists: %u\n", already_exists);

	if (already_exists)
	{
		if (s->Cedar->Client != NULL && s->Account != NULL)
		{
			UINT i;
			ACCOUNT *a;
			for (i = 0;i < LIST_NUM(s->Cedar->Client->AccountList);i++)
			{
				a = LIST_DATA(s->Cedar->Client->AccountList, i);
				Lock(a->lock);
				{
					SESSION *sess = a->ClientSession;
					if (sess != NULL && sess != s)
					{
						VLAN *v = sess->PacketAdapter->Param;
						if (v != NULL)
						{
							ROUTE_TRACKING *tr = v->RouteState;
							if (tr != NULL && e != NULL)
							{
								if (Cmp(tr->RouteToServer, e, sizeof(ROUTE_ENTRY)) == 0)
								{
									already_exists_by_other_account = true;
								}
							}
						}
					}
				}
				Unlock(a->lock);
			}
		}

		if (already_exists_by_other_account)
		{
			Debug("already_exists_by_other_account = %u\n", already_exists_by_other_account);
			already_exists = false;
		}
	}

	// DNS サーバーまでのルーティングテーブルを取得する
	dns = GetBestRouteEntryEx(&s->DefaultDns, exclude_if_id);
	if (dns == NULL)
	{
		// 取得失敗
		Debug("Failed to get GetBestRouteEntry DNS.\n");
	}
	else
	{
		// ルートを追加する
		if (MsIsVista())
		{
			dns->Metric = dns->OldIfMetric;

			if (AddRouteEntry(dns) == false)
			{
				FreeRouteEntry(dns);
				dns = NULL;
			}
		}
	}

	// 初期化
	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		Lock(s->Account->lock);
	}

	t = ZeroMalloc(sizeof(ROUTE_TRACKING));
	v->RouteState = t;

	t->RouteToServerAlreadyExists = already_exists;
	t->RouteToServer = e;
	t->RouteToDefaultDns = dns;
	t->VLanInterfaceId = if_id;
	t->NextTrackingTime = 0;
	t->DeletedDefaultGateway = NewQueue();
	t->OldDefaultGatewayMetric = 0x7fffffff;

	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		Unlock(s->Account->lock);
	}

	// ネットワーク変更を検出するために
	// 現在のデフォルト DNS サーバーを取得しておく
	GetDefaultDns(&t->OldDnsServer);

	// DHCP を使用する場合は IP アドレスを解放してすぐに取得する
	if (IsNt())
	{
		char tmp[MAX_SIZE];
		MS_ADAPTER *a;

		Format(tmp, sizeof(tmp), VLAN_ADAPTER_NAME_TAG, v->InstanceName);
		a = MsGetAdapter(tmp);

		if (a != NULL)
		{
			if (a->UseDhcp)
			{
				bool ret = Win32ReleaseAddressByGuidEx(a->Guid, 100);
				Debug("*** Win32ReleaseAddressByGuidEx = %u\n", ret);

				ret = Win32RenewAddressByGuidEx(a->Guid, 100);
				Debug("*** Win32RenewAddressByGuidEx = %u\n", ret);
			}

			MsFreeAdapter(a);
		}
	}
	else
	{
		// Win9x の場合
		Win32RenewDhcp9x(if_id);
	}

	// ルーティングテーブルの変更を検出 (対応 OS のみ)
	t->RouteChange = NewRouteChange();
	Debug("t->RouteChange = 0x%p\n", t->RouteChange);
}

// ルーティングテーブルの追跡を終了する
void RouteTrackingStop(SESSION *s, ROUTE_TRACKING *t)
{
	ROUTE_ENTRY *e;
	ROUTE_TABLE *table;
	IP dns_ip;
	bool network_has_changed = false;
	bool do_not_delete_routing_entry = false;
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	Zero(&dns_ip, sizeof(dns_ip));

	// 仮想 LAN カードが追加したデフォルトゲートウェイを削除する
	if (t->DefaultGatewayByVLan != NULL)
	{
		Debug("Default Gateway by VLAN was deleted.\n");
		DeleteRouteEntry(t->DefaultGatewayByVLan);
		FreeRouteEntry(t->DefaultGatewayByVLan);
		t->DefaultGatewayByVLan = NULL;
	}

	if (t->VistaOldDefaultGatewayByVLan != NULL)
	{
		FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
	}

	if (t->VistaDefaultGateway1 != NULL)
	{
		Debug("Vista PPP Fix Route Table Deleted.\n");
		DeleteRouteEntry(t->VistaDefaultGateway1);
		FreeRouteEntry(t->VistaDefaultGateway1);

		DeleteRouteEntry(t->VistaDefaultGateway2);
		FreeRouteEntry(t->VistaDefaultGateway2);
	}

	if (MsIsNt() == false)
	{
		// Windows 9x の場合のみ、仮想 LAN カードの DHCP アドレスを解放する
		Win32ReleaseDhcp9x(t->VLanInterfaceId, false);
	}

	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		UINT i;
		ACCOUNT *a;
		for (i = 0;i < LIST_NUM(s->Cedar->Client->AccountList);i++)
		{
			a = LIST_DATA(s->Cedar->Client->AccountList, i);
			Lock(a->lock);
			{
				SESSION *sess = a->ClientSession;
				if (sess != NULL && sess != s)
				{
					VLAN *v = sess->PacketAdapter->Param;
					if (v != NULL)
					{
						ROUTE_TRACKING *tr = v->RouteState;
						if (tr != NULL)
						{
							if (Cmp(tr->RouteToServer, t->RouteToServer, sizeof(ROUTE_ENTRY)) == 0)
							{
								do_not_delete_routing_entry = true;
							}
						}
					}
				}
			}
			Unlock(a->lock);
		}

		Lock(s->Account->lock);
	}

	if (do_not_delete_routing_entry == false)
	{
		// 最初に追加したルートを削除する
		if (t->RouteToServerAlreadyExists == false)
		{
			DeleteRouteEntry(t->RouteToServer);
		}

		DeleteRouteEntry(t->RouteToDefaultDns);
	}

	FreeRouteEntry(t->RouteToDefaultDns);
	FreeRouteEntry(t->RouteToServer);
	t->RouteToDefaultDns = t->RouteToServer = NULL;

	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		Unlock(s->Account->lock);
	}

#if	0
	// 現在の DNS サーバーを取得する
	if (GetDefaultDns(&dns_ip))
	{
		if (IPToUINT(&t->OldDnsServer) != 0)
		{
			if (IPToUINT(&t->OldDnsServer) != IPToUINT(&dns_ip))
			{
				char s1[MAX_SIZE], s2[MAX_SIZE];
				network_has_changed = true;
				IPToStr(s1, sizeof(s1), &t->OldDnsServer);
				IPToStr(s2, sizeof(s2), &dns_ip);
				Debug("Old Dns: %s, New Dns: %s\n",
					s1, s2);
			}
		}
	}

	if (network_has_changed == false)
	{
		Debug("Network: not changed.\n");
	}
	else
	{
		Debug("Network: Changed.\n");
	}

#endif

	// 現在のルーティングテーブルを取得する
	table = GetRouteTable();

	// これまで削除してきたルーティングテーブルを復元する
	while (e = GetNext(t->DeletedDefaultGateway))
	{
		bool restore = true;
		UINT i;
		// 復元しようとしているルーティングテーブルがデフォルトゲートウェイの場合
		// かつ既存のルーティングテーブルでそのインターフェースによるデフォルト
		// ルートが 1 つでも登録されている場合は復元しない
		if (IPToUINT(&e->DestIP) == 0 && IPToUINT(&e->DestMask) == 0)
		{
			for (i = 0;i < table->NumEntry;i++)
			{
				ROUTE_ENTRY *r = table->Entry[i];
				if (IPToUINT(&r->DestIP) == 0 && IPToUINT(&r->DestMask) == 0)
				{
					if (r->InterfaceID == e->InterfaceID)
					{
						restore = false;
					}
				}
			}
			if (network_has_changed)
			{
				restore = false;
			}
		}

		if (restore)
		{
			// ルーティングテーブル復元
			AddRouteEntry(e);
		}

		// メモリ解放
		FreeRouteEntry(e);
	}

	// 解放
	FreeRouteTable(table);
	ReleaseQueue(t->DeletedDefaultGateway);

	FreeRouteChange(t->RouteChange);

	Free(t);
}

// 仮想 LAN カードのインスタンス ID を取得する
UINT GetInstanceId(char *name)
{
	char tmp[MAX_SIZE];
	UINT id = 0;
	// 引数チェック
	if (name == NULL)
	{
		return 0;
	}

	Format(tmp, sizeof(tmp), VLAN_ADAPTER_NAME_TAG, name);

	id = GetVLanInterfaceID(tmp);
	if (id != 0)
	{
		return id;
	}

	return 0;
}

// 仮想 LAN カードのインスタンスリストを取得する
INSTANCE_LIST *GetInstanceList()
{
	INSTANCE_LIST *n = ZeroMalloc(sizeof(INSTANCE_LIST));

	// 列挙
	char **ss = EnumVLan(VLAN_ADAPTER_NAME);

	if (ss == NULL)
	{
		// 失敗
		n->NumInstance = 0;
		n->InstanceName = Malloc(0);
		return n;
	}
	else
	{
		UINT i, num;
		i = num = 0;
		while (true)
		{
			if (ss[i++] == NULL)
			{
				break;
			}
			num++;
		}
		i = 0;
		n->NumInstance = num;
		n->InstanceName = (char **)ZeroMalloc(sizeof(char *) * n->NumInstance);
		for (i = 0;i < num;i++)
		{
			char *s = ss[i] + StrLen(VLAN_ADAPTER_NAME) + StrLen(" - ");
			if (StrLen(ss[i]) > StrLen(VLAN_ADAPTER_NAME) + StrLen(" - "))
			{
				n->InstanceName[i] = CopyStr(s);
			}
		}
		FreeEnumVLan(ss);
	}

	return n;
}

// インスタンスリストを解放する
void FreeInstanceList(INSTANCE_LIST *n)
{
	UINT i;
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	for (i = 0;i < n->NumInstance;i++)
	{
		Free(n->InstanceName[i]);
	}
	Free(n->InstanceName);
	Free(n);
}

// パケットアダプタの解放
void VLanPaFree(SESSION *s)
{
	VLAN *v;
	ROUTE_TRACKING *t;
	// 引数チェック
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return;
	}

	// DHCP を使用している場合は IP アドレスを解放する
	if (IsNt())
	{
		char tmp[MAX_SIZE];
		MS_ADAPTER *a;

		Format(tmp, sizeof(tmp), VLAN_ADAPTER_NAME_TAG, v->InstanceName);
		a = MsGetAdapter(tmp);

		if (a != NULL)
		{
			if (a->UseDhcp)
			{
				bool ret = Win32ReleaseAddressByGuidEx(a->Guid, 50);
				Debug("*** Win32ReleaseAddressByGuid = %u\n", ret);
			}

			MsFreeAdapter(a);
		}
	}

	t = v->RouteState;
	// 仮想 LAN カードの終了
	FreeVLan(v);

	// ルーティングテーブル追跡終了
	if (s->ClientModeAndUseVLan)
	{
		RouteTrackingStop(s, t);
	}
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
		return 0;
	}

	RouteTrackingMain(s);

	if (VLanGetNextPacket(v, data, &size) == false)
	{
		return INFINITE;
	}

	return size;
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

// パケットアダプタ初期化
bool VLanPaInit(SESSION *s)
{
	VLAN *v;
	// 引数チェック
	if ((s == NULL)/* || (s->ServerMode != false) || (s->ClientOption == NULL)*/)
	{
		return false;
	}

	// 接続直前の DNS サーバーの IP アドレスの取得
	if (s->ClientModeAndUseVLan)
	{
		Zero(&s->DefaultDns, sizeof(IP));
		GetDefaultDns(&s->DefaultDns);
	}

	// ドライバに接続
	v = NewVLan(s->ClientOption->DeviceName, NULL);
	if (v == NULL)
	{
		// 失敗
		return false;
	}

	s->PacketAdapter->Param = v;

	// ルーティングテーブル追跡開始
	if (s->ClientModeAndUseVLan)
	{
		RouteTrackingStart(s);
	}

	return true;
}

// VLAN のパケットアダプタを取得
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


// 次の受信パケットをドライバに書き込む
bool VLanPutPacket(VLAN *v, void *buf, UINT size)
{
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

	// まず、現在のバッファが一杯になっているかどうか調べる
	if ((SEN_NUM_PACKET(v->PutBuffer) >= SEN_MAX_PACKET_EXCHANGE) ||
		(buf == NULL && SEN_NUM_PACKET(v->PutBuffer) != 0))
	{
#ifdef	USE_PROBE
		{
			char tmp[MAX_SIZE];
			snprintf(tmp, sizeof(tmp), "VLanPutPacket: SEN_NUM_PACKET(v->PutBuffer) = %u", SEN_NUM_PACKET(v->PutBuffer));
			PROBE_DATA2(tmp, NULL, 0);
		}
#endif	// USE_PROBE
		// パケットをドライバに書き出す
		if (VLanPutPacketsToDriver(v) == false)
		{
			return false;
		}
		SEN_NUM_PACKET(v->PutBuffer) = 0;
	}

	// 次のパケットをバッファに追加する
	if (buf != NULL)
	{
		UINT i = SEN_NUM_PACKET(v->PutBuffer);
		SEN_NUM_PACKET(v->PutBuffer)++;

		SEN_SIZE_OF_PACKET(v->PutBuffer, i) = size;
		Copy(SEN_ADDR_OF_PACKET(v->PutBuffer, i), buf, size);
		Free(buf);
	}

	return true;
}

// 次の送信パケットをドライバから読み出す
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size)
{
	// 引数チェック
	if (v == NULL || buf == NULL || size == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	PROBE_STR("VLanGetNextPacket");

	while (true)
	{
		if (v->CurrentPacketCount < SEN_NUM_PACKET(v->GetBuffer))
		{
			// すでに読み込まれたパケットがまだ残っている
			*size = SEN_SIZE_OF_PACKET(v->GetBuffer, v->CurrentPacketCount);
			*buf = MallocFast(*size);
			Copy(*buf, SEN_ADDR_OF_PACKET(v->GetBuffer, v->CurrentPacketCount), *size);

			// パケット番号をインクリメントする
			v->CurrentPacketCount++;

			return true;
		}
		else
		{
			// 次のパケットをドライバから読み込む
			if (VLanGetPacketsFromDriver(v) == false)
			{
				return false;
			}

			if (SEN_NUM_PACKET(v->GetBuffer) == 0)
			{
				// 現在パケットは届いていない
				*buf = NULL;
				*size = 0;
				return true;
			}

			v->CurrentPacketCount = 0;
		}
	}
}

// ドライバに現在のすべてのパケットを書き込む
bool VLanPutPacketsToDriver(VLAN *v)
{
	DWORD write_size;
	// 引数チェック
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	if (v->Win9xMode == false)
	{
		// Windows NT
		PROBE_STR("VLanPutPacketsToDriver: WriteFile");
		if (WriteFile(v->Handle, v->PutBuffer, SEN_EXCHANGE_BUFFER_SIZE, &write_size,
			NULL) == false)
		{
			v->Halt = true;
			return false;
		}
		PROBE_STR("VLanPutPacketsToDriver: WriteFile Completed.");

		if (write_size != SEN_EXCHANGE_BUFFER_SIZE)
		{
			v->Halt = true;
			return false;
		}
	}
	else
	{
		// Windows 9x
		if (DeviceIoControl(v->Handle, SEN_IOCTL_PUT_PACKET, v->PutBuffer,
			SEN_EXCHANGE_BUFFER_SIZE, NULL, 0, &write_size, NULL) == false)
		{
			v->Halt = true;
			return false;
		}
	}

	return true;
}

// ドライバから次のパケットを読み込む
bool VLanGetPacketsFromDriver(VLAN *v)
{
	DWORD read_size;
	// 引数チェック
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	if (v->Win9xMode == false)
	{
		// Windows NT
		PROBE_STR("VLanGetPacketsFromDriver: ReadFile");
		if (ReadFile(v->Handle, v->GetBuffer, SEN_EXCHANGE_BUFFER_SIZE,
			&read_size, NULL) == false)
		{
			v->Halt = true;
			return false;
		}
	}
	else
	{
		// Windows 9x
		if (DeviceIoControl(v->Handle, SEN_IOCTL_GET_PACKET, NULL, 0,
			v->GetBuffer, SEN_EXCHANGE_BUFFER_SIZE, &read_size, NULL) == false)
		{
			v->Halt = true;
			return false;
		}
	}

	if (read_size != SEN_EXCHANGE_BUFFER_SIZE)
	{
		v->Halt = true;
		return false;
	}

	return true;
}

// キャンセルオブジェクトの取得
CANCEL *VLanGetCancel(VLAN *v)
{
	CANCEL *c;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	// キャンセルオブジェクトの作成
	c = NewCancel();
	c->SpecialFlag = true;
	CloseHandle(c->hEvent);

	c->hEvent = v->Event;

	return c;
}

// VLAN オブジェクトの解放
void FreeVLan(VLAN *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// ハンドルを閉じる
	CloseHandle(v->Event);
	CloseHandle(v->Handle);

	// メモリ解放
	Free(v->InstanceName);
	Free(v->EventNameWin32);
	Free(v->DeviceNameWin32);
	Free(v->PutBuffer);
	Free(v->GetBuffer);
	Free(v);
}

// VLAN オブジェクトの作成
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param)
{
	VLAN *v;
	HANDLE h = INVALID_HANDLE_VALUE;
	HANDLE e = INVALID_HANDLE_VALUE;
	char tmp[MAX_SIZE];
	char name_upper[MAX_SIZE];
	// 引数チェック
	if (instance_name == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		v->Win9xMode = true;
	}

	// 名前の初期化
	Format(name_upper, sizeof(name_upper), "%s", instance_name);
	StrUpper(name_upper);
	v->InstanceName = CopyStr(name_upper);
	Format(tmp, sizeof(tmp), NDIS_SEN_DEVICE_FILE_NAME, v->InstanceName);
	v->DeviceNameWin32 = CopyStr(tmp);

	if (v->Win9xMode == false)
	{
		Format(tmp, sizeof(tmp), NDIS_SEN_EVENT_NAME_WIN32, v->InstanceName);
		v->EventNameWin32 = CopyStr(tmp);
	}

	// デバイスに接続
	h = CreateFile(v->DeviceNameWin32,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		// 接続失敗
		goto CLEANUP;
	}

	if (v->Win9xMode == false)
	{
		// イベントに接続
		e = OpenEvent(SYNCHRONIZE, FALSE, v->EventNameWin32);
		if (e == INVALID_HANDLE_VALUE)
		{
			// 接続失敗
			goto CLEANUP;
		}
	}
	else
	{
		OPENVXDHANDLE OpenVxDHandle;
		DWORD vxd_handle;
		UINT bytes_returned;

		OpenVxDHandle = (OPENVXDHANDLE)GetProcAddress(GetModuleHandleA("KERNEL32"),
			"OpenVxDHandle");

		// イベントを作成してドライバに渡す
		e = CreateEvent(NULL, FALSE, FALSE, NULL);
		vxd_handle = (DWORD)OpenVxDHandle(e);

		DeviceIoControl(h, SEN_IOCTL_SET_EVENT, &vxd_handle, sizeof(DWORD),
			NULL, 0, &bytes_returned, NULL);
	}

	v->Event = e;
	v->Handle = h;

	v->GetBuffer = ZeroMalloc(SEN_EXCHANGE_BUFFER_SIZE);
	v->PutBuffer = ZeroMalloc(SEN_EXCHANGE_BUFFER_SIZE);

	return v;

CLEANUP:
	if (h != INVALID_HANDLE_VALUE)
	{
		CloseHandle(h);
	}
	if (e != INVALID_HANDLE_VALUE)
	{
		CloseHandle(e);
	}

	Free(v->InstanceName);
	Free(v->EventNameWin32);
	Free(v->DeviceNameWin32);
	Free(v);

	return NULL;
}

#endif	// OS_WIN32

#endif	//VLAN_C

