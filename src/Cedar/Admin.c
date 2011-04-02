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

// Admin.c
// 管理用 RPC モジュール

#include "CedarPch.h"

// RPC 関数関係マクロ
// このあたりは急いで実装したのでコードがあまり美しくない。
// 本当は Sun RPC のプリプロセッサのようにきれいな処理方法を採用したがったが
// とりあえず今はマクロの羅列になっている。
#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type *t;													\
		t = ZeroMalloc(sizeof(data_type));								\
		in_rpc(t, p);													\
		err = function(a, t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, t);											\
		}																\
		free_rpc(t);													\
		Free(t);														\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type *t;													\
		t = ZeroMalloc(sizeof(data_type));								\
		in_rpc(t, p);													\
		err = function(a, t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, t);											\
		}																\
		Free(t);														\
		ok = true;														\
	}
#define	DECLARE_SC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)	\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		free_rpc(t);													\
		Zero(t, sizeof(data_type));										\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	DECLARE_SC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	CHECK_RIGHT														\
	if (a->ServerAdmin == false && (t->HubName == NULL || StrCmpi(a->HubName, t->HubName) != 0))	\
		return ERR_NOT_ENOUGH_RIGHT;	\
	if (IsEmptyStr(t->HubName))			\
		return ERR_INVALID_PARAMETER;
#define	SERVER_ADMIN_ONLY												\
	if (a->ServerAdmin == false)										\
		return ERR_NOT_ENOUGH_RIGHT;
#define	NO_SUPPORT_FOR_BRIDGE											\
	if (a->Server->Cedar->Bridge)										\
		return ERR_NOT_SUPPORTED;

// サーバーの Caps を取得 (取得できない場合はビルド番号から判別)
CAPSLIST *ScGetCapsEx(RPC *rpc)
{
	RPC_SERVER_INFO info;
	CAPSLIST *t;
	bool is_bridge = false;
	// 引数チェック
	if (rpc == NULL)
	{
		return NULL;
	}

	Zero(&info, sizeof(info));
	ScGetServerInfo(rpc, &info);

	t = ZeroMalloc(sizeof(CAPSLIST));

	// RPC で Caps を取得してみる
	if (ScGetCaps(rpc, t) != ERR_NO_ERROR)
	{
		UINT build;

		Free(t);
		t = NewCapsList();

		// 取得に失敗したのでビルド番号を取得する
		// (ものすごく古いバージョンの VPN Server のための対応コード)
		build = info.ServerBuildInt;

		is_bridge = (SearchStrEx(info.ServerProductName, "bridge", 0, false) == INFINITE) ? false : true;

		AddCapsInt(t, "i_max_packet_size", 1514);

		if (is_bridge == false)
		{
			AddCapsInt(t, "i_max_hubs", 4096);
			AddCapsInt(t, "i_max_sessions", 4096);

			if (info.ServerType != SERVER_TYPE_FARM_MEMBER)
			{
				AddCapsInt(t, "i_max_users_per_hub", 10000);
				AddCapsInt(t, "i_max_groups_per_hub", 10000);
				AddCapsInt(t, "i_max_access_lists", 4096);
			}
			else
			{
				AddCapsInt(t, "i_max_users_per_hub", 0);
				AddCapsInt(t, "i_max_groups_per_hub", 0);
				AddCapsInt(t, "i_max_access_lists", 0);
			}
		}
		else
		{
			AddCapsInt(t, "i_max_hubs", 0);
			AddCapsInt(t, "i_max_sessions", 0);
			AddCapsInt(t, "i_max_users_per_hub", 0);
			AddCapsInt(t, "i_max_groups_per_hub", 0);
			AddCapsInt(t, "i_max_access_lists", 0);
		}

		AddCapsInt(t, "i_max_mac_tables", 10000);
		AddCapsInt(t, "i_max_ip_tables", 10000);

		if (info.ServerType == SERVER_TYPE_STANDALONE)
		{
			AddCapsBool(t, "b_support_securenat", (build >= 3600) ? true : false);
			AddCapsInt(t, "i_max_secnat_tables", 4096);
		}
		else
		{
			AddCapsBool(t, "b_support_securenat", false);
			AddCapsInt(t, "i_max_secnat_tables", 0);
		}

		if (is_bridge)
		{
			AddCapsBool(t, "b_bridge", true);
		}
		else if (info.ServerType == SERVER_TYPE_STANDALONE)
		{
			AddCapsBool(t, "b_standalone", true);
		}
		else if (info.ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			AddCapsBool(t, "b_cluster_controller", true);
		}
		else
		{
			AddCapsBool(t, "b_cluster_member", true);
		}

		AddCapsBool(t, "b_support_config_hub", info.ServerType != SERVER_TYPE_FARM_MEMBER &&
			is_bridge == false);

		AddCapsBool(t, "b_vpn_client_connect", is_bridge == false ? true : false);

		AddCapsBool(t, "b_support_radius", info.ServerType != SERVER_TYPE_FARM_MEMBER &&
			is_bridge == false);

		if (build >= 3600)
		{
			RPC_BRIDGE_SUPPORT b;
			Zero(&b, sizeof(b));
			if (ScGetBridgeSupport(rpc, &b) == ERR_NO_ERROR)
			{
				AddCapsBool(t, "b_local_bridge", b.IsBridgeSupportedOs);
				AddCapsBool(t, "b_must_install_pcap", b.IsWinPcapNeeded);
			}
			else
			{
				AddCapsBool(t, "b_local_bridge", false);
				AddCapsBool(t, "b_must_install_pcap", false);
			}
		}
		else
		{
			AddCapsBool(t, "b_local_bridge", false);
			AddCapsBool(t, "b_must_install_pcap", false);
		}

		AddCapsBool(t, "b_tap_supported", false);

		if (info.ServerType == SERVER_TYPE_STANDALONE)
		{
			AddCapsBool(t, "b_support_cascade", true);
		}
		else
		{
			AddCapsBool(t, "b_support_cascade", false);
		}

		AddCapsBool(t, "b_support_cascade_cert", false);
		AddCapsBool(t, "b_support_config_log", info.ServerType != SERVER_TYPE_FARM_MEMBER);
		AddCapsBool(t, "b_support_autodelete", false);
	}
	else
	{
		// 成功した場合
		if (info.ServerBuildInt <= 4350)
		{
			if (is_bridge == false)
			{
				// Build 4300 以下では必ず b_support_cluster が true
				CAPS *caps = GetCaps(t, "b_support_cluster");
				if (caps == NULL)
				{
					AddCapsBool(t, "b_support_cluster", true);
				}
				else
				{
					caps->Value = 1;
				}
			}
		}
	}

	if (true)
	{
		TOKEN_LIST *names;

		// サーバー側に存在しない Caps の一覧を false として登録
		names = GetTableNameStartWith("CT_b_");
		if (names != NULL)
		{
			UINT i;
			for (i = 0;i < names->NumTokens;i++)
			{
				char *name = names->Token[i] + 3;

				if (GetCaps(t, name) == NULL)
				{
					AddCapsBool(t, name, false);
				}
			}

			FreeToken(names);
		}
	}

	FreeRpcServerInfo(&info);

	return t;
}

// 管理用 RPC 関数ディスパッチルーチン
PACK *AdminDispatch(RPC *rpc, char *name, PACK *p)
{
	ADMIN *a;
	PACK *ret;
	UINT err;
	SERVER *server = NULL;
	CEDAR *cedar = NULL;
	bool ok = false;
	// 引数チェック
	if (rpc == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;

	// 管理構造体
	a = (ADMIN *)rpc->Param;
	if (a == NULL)
	{
		FreePack(ret);
		return NULL;
	}

	server = a->Server;

	if (server != NULL)
	{
		cedar = server->Cedar;
	}

	Lock(cedar->CedarSuperLock);

	if (true)
	{
		char tmp[MAX_PATH];
		char ip[MAX_PATH];
		UINT rpc_id = 0;

		StrCpy(ip, sizeof(ip), "Unknown");

		if (rpc->Sock != NULL)
		{
			IPToStr(ip, sizeof(ip), &rpc->Sock->RemoteIP);
			rpc_id = rpc->Sock->socket;
		}

		Format(tmp, sizeof(tmp), "RPC: RPC-%u (%s): Entering RPC [%s]...",
			rpc_id, ip, name);

		SiDebugLog(a->Server, tmp);
	}

	if (0) {}

	// このあたりは急いで実装したのでコードがあまり美しくない。
	// 本当は Sun RPC のプリプロセッサのようにきれいな処理方法を採用したがったが
	// とりあえず今はマクロの羅列になっている。

	// RPC 関数定義: ここから
	DECLARE_RPC_EX("Test", RPC_TEST, StTest, InRpcTest, OutRpcTest, FreeRpcTest)
	DECLARE_RPC_EX("GetServerInfo", RPC_SERVER_INFO, StGetServerInfo, InRpcServerInfo, OutRpcServerInfo, FreeRpcServerInfo)
	DECLARE_RPC("GetServerStatus", RPC_SERVER_STATUS, StGetServerStatus, InRpcServerStatus, OutRpcServerStatus)
	DECLARE_RPC("CreateListener", RPC_LISTENER, StCreateListener, InRpcListener, OutRpcListener)
	DECLARE_RPC_EX("EnumListener", RPC_LISTENER_LIST, StEnumListener, InRpcListenerList, OutRpcListenerList, FreeRpcListenerList)
	DECLARE_RPC("DeleteListener", RPC_LISTENER, StDeleteListener, InRpcListener, OutRpcListener)
	DECLARE_RPC("EnableListener", RPC_LISTENER, StEnableListener, InRpcListener, OutRpcListener)
	DECLARE_RPC("SetServerPassword", RPC_SET_PASSWORD, StSetServerPassword, InRpcSetPassword, OutRpcSetPassword)
	DECLARE_RPC_EX("SetFarmSetting", RPC_FARM, StSetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
	DECLARE_RPC_EX("GetFarmSetting", RPC_FARM, StGetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
	DECLARE_RPC_EX("GetFarmInfo", RPC_FARM_INFO, StGetFarmInfo, InRpcFarmInfo, OutRpcFarmInfo, FreeRpcFarmInfo)
	DECLARE_RPC_EX("EnumFarmMember", RPC_ENUM_FARM, StEnumFarmMember, InRpcEnumFarm, OutRpcEnumFarm, FreeRpcEnumFarm)
	DECLARE_RPC("GetFarmConnectionStatus", RPC_FARM_CONNECTION_STATUS, StGetFarmConnectionStatus, InRpcFarmConnectionStatus, OutRpcFarmConnectionStatus)
	DECLARE_RPC_EX("SetServerCert", RPC_KEY_PAIR, StSetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
	DECLARE_RPC_EX("GetServerCert", RPC_KEY_PAIR, StGetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
	DECLARE_RPC_EX("GetServerCipher", RPC_STR, StGetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC_EX("SetServerCipher", RPC_STR, StSetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC("CreateHub", RPC_CREATE_HUB, StCreateHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC("SetHub", RPC_CREATE_HUB, StSetHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC("GetHub", RPC_CREATE_HUB, StGetHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC_EX("EnumHub", RPC_ENUM_HUB, StEnumHub, InRpcEnumHub, OutRpcEnumHub, FreeRpcEnumHub)
	DECLARE_RPC("DeleteHub", RPC_DELETE_HUB, StDeleteHub, InRpcDeleteHub, OutRpcDeleteHub)
	DECLARE_RPC("GetHubRadius", RPC_RADIUS, StGetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPC("SetHubRadius", RPC_RADIUS, StSetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPC_EX("EnumConnection", RPC_ENUM_CONNECTION, StEnumConnection, InRpcEnumConnection, OutRpcEnumConnection, FreeRpcEnumConnetion)
	DECLARE_RPC("DisconnectConnection", RPC_DISCONNECT_CONNECTION, StDisconnectConnection, InRpcDisconnectConnection, OutRpcDisconnectConnection)
	DECLARE_RPC("GetConnectionInfo", RPC_CONNECTION_INFO, StGetConnectionInfo, InRpcConnectionInfo, OutRpcConnectionInfo)
	DECLARE_RPC("SetHubOnline", RPC_SET_HUB_ONLINE, StSetHubOnline, InRpcSetHubOnline, OutRpcSetHubOnline)
	DECLARE_RPC("GetHubStatus", RPC_HUB_STATUS, StGetHubStatus, InRpcHubStatus, OutRpcHubStatus)
	DECLARE_RPC("SetHubLog", RPC_HUB_LOG, StSetHubLog, InRpcHubLog, OutRpcHubLog)
	DECLARE_RPC("GetHubLog", RPC_HUB_LOG, StGetHubLog, InRpcHubLog, OutRpcHubLog)
	DECLARE_RPC_EX("AddCa", RPC_HUB_ADD_CA, StAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
	DECLARE_RPC_EX("EnumCa", RPC_HUB_ENUM_CA, StEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
	DECLARE_RPC_EX("GetCa", RPC_HUB_GET_CA, StGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
	DECLARE_RPC("DeleteCa", RPC_HUB_DELETE_CA, StDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
	DECLARE_RPC("SetLinkOnline", RPC_LINK, StSetLinkOnline, InRpcLink, OutRpcLink)
	DECLARE_RPC("SetLinkOffline", RPC_LINK, StSetLinkOffline, InRpcLink, OutRpcLink)
	DECLARE_RPC("DeleteLink", RPC_LINK, StDeleteLink, InRpcLink, OutRpcLink)
	DECLARE_RPC("RenameLink", RPC_RENAME_LINK, StRenameLink, InRpcRenameLink, OutRpcRenameLink)
	DECLARE_RPC_EX("CreateLink", RPC_CREATE_LINK, StCreateLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("GetLink", RPC_CREATE_LINK, StGetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("SetLink", RPC_CREATE_LINK, StSetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("EnumLink", RPC_ENUM_LINK, StEnumLink, InRpcEnumLink, OutRpcEnumLink, FreeRpcEnumLink)
	DECLARE_RPC_EX("GetLinkStatus", RPC_LINK_STATUS, StGetLinkStatus, InRpcLinkStatus, OutRpcLinkStatus, FreeRpcLinkStatus)
	DECLARE_RPC("AddAccess", RPC_ADD_ACCESS, StAddAccess, InRpcAddAccess, OutRpcAddAccess)
	DECLARE_RPC("DeleteAccess", RPC_DELETE_ACCESS, StDeleteAccess, InRpcDeleteAccess, OutRpcDeleteAccess)
	DECLARE_RPC_EX("EnumAccess", RPC_ENUM_ACCESS_LIST, StEnumAccess, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
	DECLARE_RPC_EX("SetAccessList", RPC_ENUM_ACCESS_LIST, StSetAccessList, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
	DECLARE_RPC_EX("CreateUser", RPC_SET_USER, StCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC_EX("SetUser", RPC_SET_USER, StSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC_EX("GetUser", RPC_SET_USER, StGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC("DeleteUser", RPC_DELETE_USER, StDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPC_EX("EnumUser", RPC_ENUM_USER, StEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
	DECLARE_RPC_EX("CreateGroup", RPC_SET_GROUP, StCreateGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC_EX("SetGroup", RPC_SET_GROUP, StSetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC_EX("GetGroup", RPC_SET_GROUP, StGetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC("DeleteGroup", RPC_DELETE_USER, StDeleteGroup, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPC_EX("EnumGroup", RPC_ENUM_GROUP, StEnumGroup, InRpcEnumGroup, OutRpcEnumGroup, FreeRpcEnumGroup)
	DECLARE_RPC_EX("EnumSession", RPC_ENUM_SESSION, StEnumSession, InRpcEnumSession, OutRpcEnumSession, FreeRpcEnumSession)
	DECLARE_RPC_EX("GetSessionStatus", RPC_SESSION_STATUS, StGetSessionStatus, InRpcSessionStatus, OutRpcSessionStatus, FreeRpcSessionStatus)
	DECLARE_RPC("DeleteSession", RPC_DELETE_SESSION, StDeleteSession, InRpcDeleteSession, OutRpcDeleteSession)
	DECLARE_RPC_EX("EnumMacTable", RPC_ENUM_MAC_TABLE, StEnumMacTable, InRpcEnumMacTable, OutRpcEnumMacTable, FreeRpcEnumMacTable)
	DECLARE_RPC("DeleteMacTable", RPC_DELETE_TABLE, StDeleteMacTable, InRpcDeleteTable, OutRpcDeleteTable)
	DECLARE_RPC_EX("EnumIpTable", RPC_ENUM_IP_TABLE, StEnumIpTable, InRpcEnumIpTable, OutRpcEnumIpTable, FreeRpcEnumIpTable)
	DECLARE_RPC("DeleteIpTable", RPC_DELETE_TABLE, StDeleteIpTable, InRpcDeleteTable, OutRpcDeleteTable)
	DECLARE_RPC("SetKeep", RPC_KEEP, StSetKeep, InRpcKeep, OutRpcKeep)
	DECLARE_RPC("GetKeep", RPC_KEEP, StGetKeep, InRpcKeep, OutRpcKeep)
	DECLARE_RPC("EnableSecureNAT", RPC_HUB, StEnableSecureNAT, InRpcHub, OutRpcHub)
	DECLARE_RPC("DisableSecureNAT", RPC_HUB, StDisableSecureNAT, InRpcHub, OutRpcHub)
	DECLARE_RPC("SetSecureNATOption", VH_OPTION, StSetSecureNATOption, InVhOption, OutVhOption)
	DECLARE_RPC("GetSecureNATOption", VH_OPTION, StGetSecureNATOption, InVhOption, OutVhOption)
	DECLARE_RPC_EX("EnumNAT", RPC_ENUM_NAT, StEnumNAT, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
	DECLARE_RPC_EX("EnumDHCP", RPC_ENUM_DHCP, StEnumDHCP, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
	DECLARE_RPC("GetSecureNATStatus", RPC_NAT_STATUS, StGetSecureNATStatus, InRpcNatStatus, OutRpcNatStatus)
	DECLARE_RPC_EX("EnumEthernet", RPC_ENUM_ETH, StEnumEthernet, InRpcEnumEth, OutRpcEnumEth, FreeRpcEnumEth)
	DECLARE_RPC("AddLocalBridge", RPC_LOCALBRIDGE, StAddLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
	DECLARE_RPC("DeleteLocalBridge", RPC_LOCALBRIDGE, StDeleteLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
	DECLARE_RPC_EX("EnumLocalBridge", RPC_ENUM_LOCALBRIDGE, StEnumLocalBridge, InRpcEnumLocalBridge, OutRpcEnumLocalBridge, FreeRpcEnumLocalBridge)
	DECLARE_RPC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, StGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
	DECLARE_RPC("RebootServer", RPC_TEST, StRebootServer, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetCaps", CAPSLIST, StGetCaps, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
	DECLARE_RPC_EX("GetConfig", RPC_CONFIG, StGetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("SetConfig", RPC_CONFIG, StSetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("GetDefaultHubAdminOptions", RPC_ADMIN_OPTION, StGetDefaultHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("GetHubAdminOptions", RPC_ADMIN_OPTION, StGetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubAdminOptions", RPC_ADMIN_OPTION, StSetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("GetHubExtOptions", RPC_ADMIN_OPTION, StGetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubExtOptions", RPC_ADMIN_OPTION, StSetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC("AddL3Switch", RPC_L3SW, StAddL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC("DelL3Switch", RPC_L3SW, StDelL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC_EX("EnumL3Switch", RPC_ENUM_L3SW, StEnumL3Switch, InRpcEnumL3Sw, OutRpcEnumL3Sw, FreeRpcEnumL3Sw)
	DECLARE_RPC("StartL3Switch", RPC_L3SW, StStartL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC("StopL3Switch", RPC_L3SW, StStopL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC("AddL3If", RPC_L3IF, StAddL3If, InRpcL3If, OutRpcL3If)
	DECLARE_RPC("DelL3If", RPC_L3IF, StDelL3If, InRpcL3If, OutRpcL3If)
	DECLARE_RPC_EX("EnumL3If", RPC_ENUM_L3IF, StEnumL3If, InRpcEnumL3If, OutRpcEnumL3If, FreeRpcEnumL3If)
	DECLARE_RPC("AddL3Table", RPC_L3TABLE, StAddL3Table, InRpcL3Table, OutRpcL3Table)
	DECLARE_RPC("DelL3Table", RPC_L3TABLE, StDelL3Table, InRpcL3Table, OutRpcL3Table)
	DECLARE_RPC_EX("EnumL3Table", RPC_ENUM_L3TABLE, StEnumL3Table, InRpcEnumL3Table, OutRpcEnumL3Table, FreeRpcEnumL3Table)
	DECLARE_RPC_EX("EnumCrl", RPC_ENUM_CRL, StEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
	DECLARE_RPC_EX("AddCrl", RPC_CRL, StAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("DelCrl", RPC_CRL, StDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("GetCrl", RPC_CRL, StGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("SetCrl", RPC_CRL, StSetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("SetAcList", RPC_AC_LIST, StSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("GetAcList", RPC_AC_LIST, StGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("EnumLogFile", RPC_ENUM_LOG_FILE, StEnumLogFile, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
	DECLARE_RPC_EX("ReadLogFile", RPC_READ_LOG_FILE, StReadLogFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
	DECLARE_RPC("AddLicenseKey", RPC_TEST, StAddLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC("DelLicenseKey", RPC_TEST, StDelLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, StEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
	DECLARE_RPC("GetLicenseStatus", RPC_LICENSE_STATUS, StGetLicenseStatus, InRpcLicenseStatus, OutRpcLicenseStatus)
	DECLARE_RPC("SetSysLog", SYSLOG_SETTING, StSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC("GetSysLog", SYSLOG_SETTING, StGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC_EX("EnumEthVLan", RPC_ENUM_ETH_VLAN, StEnumEthVLan, InRpcEnumEthVLan, OutRpcEnumEthVLan, FreeRpcEnumEthVLan)
	DECLARE_RPC("SetEnableEthVLan", RPC_TEST, StSetEnableEthVLan, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("SetHubMsg", RPC_MSG, StSetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC_EX("GetHubMsg", RPC_MSG, StGetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Crash", RPC_TEST, StCrash, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetAdminMsg", RPC_MSG, StGetAdminMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Flush", RPC_TEST, StFlush, InRpcTest, OutRpcTest)
	DECLARE_RPC("Debug", RPC_TEST, StDebug, InRpcTest, OutRpcTest)
	// RPC 関数定義: ここまで

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	if (err != ERR_NO_ERROR)
	{
		PackAddInt(ret, "error", err);
	}

	if (true)
	{
		char tmp[MAX_PATH];
		char ip[MAX_PATH];
		UINT rpc_id = 0;

		StrCpy(ip, sizeof(ip), "Unknown");

		if (rpc->Sock != NULL)
		{
			IPToStr(ip, sizeof(ip), &rpc->Sock->RemoteIP);
			rpc_id = rpc->Sock->socket;
		}

		Format(tmp, sizeof(tmp), "RPC: RPC-%u (%s): Leaving RPC [%s] (Error: %u).",
			rpc_id, ip, name, err);

		SiDebugLog(a->Server, tmp);
	}

	Unlock(cedar->CedarSuperLock);

	return ret;
}

// このあたりは急いで実装したのでコードがあまり美しくない。
// 本当は Sun RPC のプリプロセッサのようにきれいな処理方法を採用したがったが
// とりあえず今はマクロの羅列になっている。

// RPC 呼び出し関数定義: ここから
DECLARE_SC_EX("Test", RPC_TEST, ScTest, InRpcTest, OutRpcTest, FreeRpcTest)
DECLARE_SC_EX("GetServerInfo", RPC_SERVER_INFO, ScGetServerInfo, InRpcServerInfo, OutRpcServerInfo, FreeRpcServerInfo)
DECLARE_SC("GetServerStatus", RPC_SERVER_STATUS, ScGetServerStatus, InRpcServerStatus, OutRpcServerStatus)
DECLARE_SC("CreateListener", RPC_LISTENER, ScCreateListener, InRpcListener, OutRpcListener)
DECLARE_SC_EX("EnumListener", RPC_LISTENER_LIST, ScEnumListener, InRpcListenerList, OutRpcListenerList, FreeRpcListenerList)
DECLARE_SC("DeleteListener", RPC_LISTENER, ScDeleteListener, InRpcListener, OutRpcListener)
DECLARE_SC("EnableListener", RPC_LISTENER, ScEnableListener, InRpcListener, OutRpcListener)
DECLARE_SC("SetServerPassword", RPC_SET_PASSWORD, ScSetServerPassword, InRpcSetPassword, OutRpcSetPassword)
DECLARE_SC_EX("SetFarmSetting", RPC_FARM, ScSetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
DECLARE_SC_EX("GetFarmSetting", RPC_FARM, ScGetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
DECLARE_SC_EX("GetFarmInfo", RPC_FARM_INFO, ScGetFarmInfo, InRpcFarmInfo, OutRpcFarmInfo, FreeRpcFarmInfo)
DECLARE_SC_EX("EnumFarmMember", RPC_ENUM_FARM, ScEnumFarmMember, InRpcEnumFarm, OutRpcEnumFarm, FreeRpcEnumFarm)
DECLARE_SC("GetFarmConnectionStatus", RPC_FARM_CONNECTION_STATUS, ScGetFarmConnectionStatus, InRpcFarmConnectionStatus, OutRpcFarmConnectionStatus)
DECLARE_SC_EX("SetServerCert", RPC_KEY_PAIR, ScSetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
DECLARE_SC_EX("GetServerCert", RPC_KEY_PAIR, ScGetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
DECLARE_SC_EX("GetServerCipher", RPC_STR, ScGetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC_EX("SetServerCipher", RPC_STR, ScSetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC("CreateHub", RPC_CREATE_HUB, ScCreateHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC("SetHub", RPC_CREATE_HUB, ScSetHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC("GetHub", RPC_CREATE_HUB, ScGetHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC_EX("EnumHub", RPC_ENUM_HUB, ScEnumHub, InRpcEnumHub, OutRpcEnumHub, FreeRpcEnumHub)
DECLARE_SC("DeleteHub", RPC_DELETE_HUB, ScDeleteHub, InRpcDeleteHub, OutRpcDeleteHub)
DECLARE_SC("GetHubRadius", RPC_RADIUS, ScGetHubRadius, InRpcRadius, OutRpcRadius)
DECLARE_SC("SetHubRadius", RPC_RADIUS, ScSetHubRadius, InRpcRadius, OutRpcRadius)
DECLARE_SC_EX("EnumConnection", RPC_ENUM_CONNECTION, ScEnumConnection, InRpcEnumConnection, OutRpcEnumConnection, FreeRpcEnumConnetion)
DECLARE_SC("DisconnectConnection", RPC_DISCONNECT_CONNECTION, ScDisconnectConnection, InRpcDisconnectConnection, OutRpcDisconnectConnection)
DECLARE_SC("GetConnectionInfo", RPC_CONNECTION_INFO, ScGetConnectionInfo, InRpcConnectionInfo, OutRpcConnectionInfo)
DECLARE_SC("SetHubOnline", RPC_SET_HUB_ONLINE, ScSetHubOnline, InRpcSetHubOnline, OutRpcSetHubOnline)
DECLARE_SC("GetHubStatus", RPC_HUB_STATUS, ScGetHubStatus, InRpcHubStatus, OutRpcHubStatus)
DECLARE_SC("SetHubLog", RPC_HUB_LOG, ScSetHubLog, InRpcHubLog, OutRpcHubLog)
DECLARE_SC("GetHubLog", RPC_HUB_LOG, ScGetHubLog, InRpcHubLog, OutRpcHubLog)
DECLARE_SC_EX("AddCa", RPC_HUB_ADD_CA, ScAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
DECLARE_SC_EX("EnumCa", RPC_HUB_ENUM_CA, ScEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
DECLARE_SC_EX("GetCa", RPC_HUB_GET_CA, ScGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
DECLARE_SC("DeleteCa", RPC_HUB_DELETE_CA, ScDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
DECLARE_SC_EX("CreateLink", RPC_CREATE_LINK, ScCreateLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("GetLink", RPC_CREATE_LINK, ScGetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("SetLink", RPC_CREATE_LINK, ScSetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("EnumLink", RPC_ENUM_LINK, ScEnumLink, InRpcEnumLink, OutRpcEnumLink, FreeRpcEnumLink)
DECLARE_SC_EX("GetLinkStatus", RPC_LINK_STATUS, ScGetLinkStatus, InRpcLinkStatus, OutRpcLinkStatus, FreeRpcLinkStatus)
DECLARE_SC("SetLinkOnline", RPC_LINK, ScSetLinkOnline, InRpcLink, OutRpcLink)
DECLARE_SC("SetLinkOffline", RPC_LINK, ScSetLinkOffline, InRpcLink, OutRpcLink)
DECLARE_SC("DeleteLink", RPC_LINK, ScDeleteLink, InRpcLink, OutRpcLink)
DECLARE_SC("RenameLink", RPC_RENAME_LINK, ScRenameLink, InRpcRenameLink, OutRpcRenameLink)
DECLARE_SC("AddAccess", RPC_ADD_ACCESS, ScAddAccess, InRpcAddAccess, OutRpcAddAccess)
DECLARE_SC("DeleteAccess", RPC_DELETE_ACCESS, ScDeleteAccess, InRpcDeleteAccess, OutRpcDeleteAccess)
DECLARE_SC_EX("EnumAccess", RPC_ENUM_ACCESS_LIST, ScEnumAccess, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
DECLARE_SC_EX("SetAccessList", RPC_ENUM_ACCESS_LIST, ScSetAccessList, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
DECLARE_SC_EX("CreateUser", RPC_SET_USER, ScCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC_EX("SetUser", RPC_SET_USER, ScSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC_EX("GetUser", RPC_SET_USER, ScGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC("DeleteUser", RPC_DELETE_USER, ScDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
DECLARE_SC_EX("EnumUser", RPC_ENUM_USER, ScEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
DECLARE_SC_EX("CreateGroup", RPC_SET_GROUP, ScCreateGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC_EX("SetGroup", RPC_SET_GROUP, ScSetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC_EX("GetGroup", RPC_SET_GROUP, ScGetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC("DeleteGroup", RPC_DELETE_USER, ScDeleteGroup, InRpcDeleteUser, OutRpcDeleteUser)
DECLARE_SC_EX("EnumGroup", RPC_ENUM_GROUP, ScEnumGroup, InRpcEnumGroup, OutRpcEnumGroup, FreeRpcEnumGroup)
DECLARE_SC_EX("EnumSession", RPC_ENUM_SESSION, ScEnumSession, InRpcEnumSession, OutRpcEnumSession, FreeRpcEnumSession)
DECLARE_SC_EX("GetSessionStatus", RPC_SESSION_STATUS, ScGetSessionStatus, InRpcSessionStatus, OutRpcSessionStatus, FreeRpcSessionStatus)
DECLARE_SC("DeleteSession", RPC_DELETE_SESSION, ScDeleteSession, InRpcDeleteSession, OutRpcDeleteSession)
DECLARE_SC_EX("EnumMacTable", RPC_ENUM_MAC_TABLE, ScEnumMacTable, InRpcEnumMacTable, OutRpcEnumMacTable, FreeRpcEnumMacTable)
DECLARE_SC("DeleteMacTable", RPC_DELETE_TABLE, ScDeleteMacTable, InRpcDeleteTable, OutRpcDeleteTable)
DECLARE_SC_EX("EnumIpTable", RPC_ENUM_IP_TABLE, ScEnumIpTable, InRpcEnumIpTable, OutRpcEnumIpTable, FreeRpcEnumIpTable)
DECLARE_SC("DeleteIpTable", RPC_DELETE_TABLE, ScDeleteIpTable, InRpcDeleteTable, OutRpcDeleteTable)
DECLARE_SC("SetKeep", RPC_KEEP, ScSetKeep, InRpcKeep, OutRpcKeep)
DECLARE_SC("GetKeep", RPC_KEEP, ScGetKeep, InRpcKeep, OutRpcKeep)
DECLARE_SC("EnableSecureNAT", RPC_HUB, ScEnableSecureNAT, InRpcHub, OutRpcHub)
DECLARE_SC("DisableSecureNAT", RPC_HUB, ScDisableSecureNAT, InRpcHub, OutRpcHub)
DECLARE_SC("SetSecureNATOption", VH_OPTION, ScSetSecureNATOption, InVhOption, OutVhOption)
DECLARE_SC("GetSecureNATOption", VH_OPTION, ScGetSecureNATOption, InVhOption, OutVhOption)
DECLARE_SC_EX("EnumNAT", RPC_ENUM_NAT, ScEnumNAT, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
DECLARE_SC_EX("EnumDHCP", RPC_ENUM_DHCP, ScEnumDHCP, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
DECLARE_SC("GetSecureNATStatus", RPC_NAT_STATUS, ScGetSecureNATStatus, InRpcNatStatus, OutRpcNatStatus)
DECLARE_SC_EX("EnumEthernet", RPC_ENUM_ETH, ScEnumEthernet, InRpcEnumEth, OutRpcEnumEth, FreeRpcEnumEth)
DECLARE_SC("AddLocalBridge", RPC_LOCALBRIDGE, ScAddLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
DECLARE_SC("DeleteLocalBridge", RPC_LOCALBRIDGE, ScDeleteLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
DECLARE_SC_EX("EnumLocalBridge", RPC_ENUM_LOCALBRIDGE, ScEnumLocalBridge, InRpcEnumLocalBridge, OutRpcEnumLocalBridge, FreeRpcEnumLocalBridge)
DECLARE_SC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, ScGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
DECLARE_SC("RebootServer", RPC_TEST, ScRebootServer, InRpcTest, OutRpcTest)
DECLARE_SC_EX("GetCaps", CAPSLIST, ScGetCaps, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
DECLARE_SC_EX("GetConfig", RPC_CONFIG, ScGetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
DECLARE_SC_EX("SetConfig", RPC_CONFIG, ScSetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
DECLARE_SC_EX("GetHubAdminOptions", RPC_ADMIN_OPTION, ScGetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("SetHubAdminOptions", RPC_ADMIN_OPTION, ScSetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("GetHubExtOptions", RPC_ADMIN_OPTION, ScGetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("SetHubExtOptions", RPC_ADMIN_OPTION, ScSetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("GetDefaultHubAdminOptions", RPC_ADMIN_OPTION, ScGetDefaultHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC("AddL3Switch", RPC_L3SW, ScAddL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC("DelL3Switch", RPC_L3SW, ScDelL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC_EX("EnumL3Switch", RPC_ENUM_L3SW, ScEnumL3Switch, InRpcEnumL3Sw, OutRpcEnumL3Sw, FreeRpcEnumL3Sw)
DECLARE_SC("StartL3Switch", RPC_L3SW, ScStartL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC("StopL3Switch", RPC_L3SW, ScStopL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC("AddL3If", RPC_L3IF, ScAddL3If, InRpcL3If, OutRpcL3If)
DECLARE_SC("DelL3If", RPC_L3IF, ScDelL3If, InRpcL3If, OutRpcL3If)
DECLARE_SC_EX("EnumL3If", RPC_ENUM_L3IF, ScEnumL3If, InRpcEnumL3If, OutRpcEnumL3If, FreeRpcEnumL3If)
DECLARE_SC("AddL3Table", RPC_L3TABLE, ScAddL3Table, InRpcL3Table, OutRpcL3Table)
DECLARE_SC("DelL3Table", RPC_L3TABLE, ScDelL3Table, InRpcL3Table, OutRpcL3Table)
DECLARE_SC_EX("EnumL3Table", RPC_ENUM_L3TABLE, ScEnumL3Table, InRpcEnumL3Table, OutRpcEnumL3Table, FreeRpcEnumL3Table)
DECLARE_SC_EX("EnumCrl", RPC_ENUM_CRL, ScEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
DECLARE_SC_EX("AddCrl", RPC_CRL, ScAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("DelCrl", RPC_CRL, ScDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("GetCrl", RPC_CRL, ScGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("SetCrl", RPC_CRL, ScSetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("SetAcList", RPC_AC_LIST, ScSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
DECLARE_SC_EX("GetAcList", RPC_AC_LIST, ScGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
DECLARE_SC_EX("EnumLogFile", RPC_ENUM_LOG_FILE, ScEnumLogFile, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
DECLARE_SC_EX("ReadLogFile", RPC_READ_LOG_FILE, ScReadLogFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
DECLARE_SC("AddLicenseKey", RPC_TEST, ScAddLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC("DelLicenseKey", RPC_TEST, ScDelLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, ScEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
DECLARE_SC("GetLicenseStatus", RPC_LICENSE_STATUS, ScGetLicenseStatus, InRpcLicenseStatus, OutRpcLicenseStatus)
DECLARE_SC("SetSysLog", SYSLOG_SETTING, ScSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC("GetSysLog", SYSLOG_SETTING, ScGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC_EX("EnumEthVLan", RPC_ENUM_ETH_VLAN, ScEnumEthVLan, InRpcEnumEthVLan, OutRpcEnumEthVLan, FreeRpcEnumEthVLan)
DECLARE_SC("SetEnableEthVLan", RPC_TEST, ScSetEnableEthVLan, InRpcTest, OutRpcTest)
DECLARE_SC_EX("SetHubMsg", RPC_MSG, ScSetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
DECLARE_SC_EX("GetHubMsg", RPC_MSG, ScGetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
DECLARE_SC("Crash", RPC_TEST, ScCrash, InRpcTest, OutRpcTest)
DECLARE_SC_EX("GetAdminMsg", RPC_MSG, ScGetAdminMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
DECLARE_SC("Flush", RPC_TEST, ScFlush, InRpcTest, OutRpcTest)
DECLARE_SC("Debug", RPC_TEST, ScDebug, InRpcTest, OutRpcTest)
// RPC 呼び出し関数定義: ここまで


// メッセージを設定
UINT StSetHubMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
	{
		return ERR_MEMORY_NOT_ENOUGH;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_msg") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			SetHubMsg(h, t->Msg);
		}

		ReleaseHub(h);
	}

	IncrementServerConfigRevision(s);

	return ret;
}

// メッセージを取得
UINT StGetHubMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
	{
		return ERR_MEMORY_NOT_ENOUGH;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcMsg(t);
	Zero(t, sizeof(t));

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		t->Msg = GetHubMsg(h);

		ReleaseHub(h);
	}

	return ret;
}

// デバッグ機能を実行する
UINT StDebug(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	RPC_TEST t2;

	SERVER_ADMIN_ONLY;

	Zero(&t2, sizeof(t2));

	ret = SiDebug(s, &t2, t->IntValue, t->StrValue);

	if (ret == ERR_NO_ERROR)
	{
		Copy(t, &t2, sizeof(RPC_TEST));
	}
	else
	{
		Zero(t, sizeof(RPC_TEST));
	}

	return ret;
}

// 設定ファイルをフラッシュする
UINT StFlush(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	UINT size;

	SERVER_ADMIN_ONLY;

	size = SiWriteConfigurationFile(s);

	t->IntValue = size;

	return ERR_NO_ERROR;
}

// クラッシュさせる (システム管理者だけが実行できる緊急時用コード)
UINT StCrash(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

#ifdef	OS_WIN32
	MsSetEnableMinidump(false);
#endif	// OS_WIN32

	CrashNow();

	return ERR_NO_ERROR;
}

// 管理者向けメッセージを取得する
UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	RPC_WINVER server_ver;
	RPC_WINVER client_ver;
	wchar_t winver_msg_client[3800];
	wchar_t winver_msg_server[3800];
	wchar_t *utvpn_msg;
	UINT tmpsize;
	wchar_t *tmp;

	FreeRpcMsg(t);
	Zero(t, sizeof(RPC_MSG));

	// Windows バージョンチェック
	GetWinVer(&server_ver);
	Copy(&client_ver, &a->ClientWinVer, sizeof(RPC_WINVER));

	Zero(winver_msg_client, sizeof(winver_msg_client));
	Zero(winver_msg_server, sizeof(winver_msg_server));

	utvpn_msg = _UU("UTVPN_MSG");

	if (IsSupportedWinVer(&client_ver) == false)
	{
		SYSTEMTIME st;

		LocalTime(&st);

		UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
			_UU("WINVER_ERROR_PC_LOCAL"),
			client_ver.Title,
			_UU("WINVER_ERROR_VPNSERVER"),
			SUPPORTED_WINDOWS_LIST,
			_UU("WINVER_ERROR_PC_LOCAL"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			st.wYear, st.wMonth);
	}

	if (IsSupportedWinVer(&server_ver) == false)
	{
		SYSTEMTIME st;

		LocalTime(&st);

		UniFormat(winver_msg_server, sizeof(winver_msg_server), _UU("WINVER_ERROR_FORMAT"),
			_UU("WINVER_ERROR_PC_REMOTE"),
			server_ver.Title,
			_UU("WINVER_ERROR_VPNSERVER"),
			SUPPORTED_WINDOWS_LIST,
			_UU("WINVER_ERROR_PC_REMOTE"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			st.wYear, st.wMonth);
	}

	tmpsize = UniStrSize(winver_msg_client) + UniStrSize(winver_msg_server) + UniStrSize(utvpn_msg) + 100;

	tmp = ZeroMalloc(tmpsize);
	UniStrCat(tmp, tmpsize, utvpn_msg);
	UniStrCat(tmp, tmpsize, winver_msg_client);
	UniStrCat(tmp, tmpsize, winver_msg_server);

	t->Msg = tmp;

	return ERR_NO_ERROR;
}

// VLAN 透過設定一覧の取得
UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

#ifdef	OS_WIN32
	if (GetServerCapsBool(s, "b_support_eth_vlan") == false)
	{
		ret = ERR_NOT_SUPPORTED;
	}
	else
	{
		FreeRpcEnumEthVLan(t);
		Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

		if (EnumEthVLanWin32(t) == false)
		{
			ret = ERR_INTERNAL_ERROR;
		}
	}
#else	// OS_WIN32
	ret = ERR_NOT_SUPPORTED;
#endif	// OS_WIN32

	return ret;
}

// VLAN 透過設定の設定
UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

#ifdef	OS_WIN32
	if (GetServerCapsBool(s, "b_support_eth_vlan") == false)
	{
		ret = ERR_NOT_SUPPORTED;
	}
	else if (MsIsAdmin() == false)
	{
		ret = ERR_NOT_ENOUGH_RIGHT;
	}
	else
	{
		if (SetVLanEnableStatus(t->StrValue, MAKEBOOL(t->IntValue)) == false)
		{
			ret = ERR_INTERNAL_ERROR;
		}
	}
#else	// OS_WIN32
	ret = ERR_NOT_SUPPORTED;
#endif	// OS_WIN32

	return ret;
}

// ライセンス状態の取得
// (ソフトイーサ社の製品 PacketiX VPN の管理に使えるように互換性を残している)
UINT StGetLicenseStatus(ADMIN *a, RPC_LICENSE_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	LICENSE_SYSTEM *ls = s->LicenseSystem;
	LICENSE_STATUS status;

	if (ls == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	Zero(t, sizeof(RPC_LICENSE_STATUS));

	// 現在のライセンスステータスを取得
	LiParseCurrentLicenseStatus(ls, &status);

	t->EditionId = status.Edition;
	StrCpy(t->EditionStr, sizeof(t->EditionStr), status.EditionStr);
	t->SystemId = status.SystemId;
	t->SystemExpires = status.Expires;
	t->NumClientConnectLicense = status.NumClientLicense;
	t->NumBridgeConnectLicense = status.NumBridgeLicense;
	t->NumUserCreationLicense = status.NumUserLicense;
	t->SubscriptionExpires = status.SubscriptionExpires;
	t->IsSubscriptionExpired = status.IsSubscriptionExpired;
	t->NeedSubscription = status.NeedSubscription;
	t->AllowEnterpriseFunction = status.AllowEnterpriseFunction;
	t->ReleaseDate = c->BuiltDate;

	return ret;
}

// ライセンスキーの列挙
// (ソフトイーサ社の製品 PacketiX VPN の管理に使えるように互換性を残している)
UINT StEnumLicenseKey(ADMIN *a, RPC_ENUM_LICENSE_KEY *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	LICENSE_SYSTEM *ls = s->LicenseSystem;

	if (ls == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumLicenseKey(t);
	Zero(t, sizeof(RPC_ENUM_LICENSE_KEY));

	LockList(ls->LicenseList);
	{
		UINT i;

		t->NumItem = LIST_NUM(ls->LicenseList);
		t->Items = ZeroMalloc(sizeof(RPC_ENUM_LICENSE_KEY_ITEM) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			RPC_ENUM_LICENSE_KEY_ITEM *k = &t->Items[i];
			LICENSE *e = LIST_DATA(ls->LicenseList, i);

			k->Id = e->Id;
			k->Expires = e->Expires;
			StrCpy(k->LicenseId, sizeof(k->LicenseId), e->LicenseIdStr);
			StrCpy(k->LicenseKey, sizeof(k->LicenseKey), e->LicenseKeyStr);
			StrCpy(k->LicenseName, sizeof(k->LicenseName), e->Name);
			k->Status = e->Status;
			k->ProductId = e->ProductId;
			k->SystemId = e->SystemId;
			k->SerialId = e->SerialId;
		}
	}
	UnlockList(ls->LicenseList);

	return ret;
}

// ライセンスキーの追加
// (ソフトイーサ社の製品 PacketiX VPN の管理に使えるように互換性を残している)
UINT StAddLicenseKey(ADMIN *a, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
}

// ライセンスキーの削除
// (ソフトイーサ社の製品 PacketiX VPN の管理に使えるように互換性を残している)
UINT StDelLicenseKey(ADMIN *a, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
}

// ログファイルのダウンロード
BUF *DownloadFileFromServer(RPC *r, char *server_name, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param)
{
	UINT offset;
	BUF *buf;
	// 引数チェック
	if (r == NULL || filepath == NULL)
	{
		return NULL;
	}

	if (server_name == NULL)
	{
		server_name = "";
	}

	offset = 0;

	buf = NewBuf();

	while (true)
	{
		DOWNLOAD_PROGRESS g;
		RPC_READ_LOG_FILE t;
		UINT ret;

		Zero(&t, sizeof(t));
		StrCpy(t.FilePath, sizeof(t.FilePath), filepath);
		t.Offset = offset;
		StrCpy(t.ServerName, sizeof(t.ServerName), server_name);

		ret = ScReadLogFile(r, &t);

		if (ret != ERR_NO_ERROR)
		{
			// 失敗
			FreeRpcReadLogFile(&t);
			FreeBuf(buf);
			return NULL;
		}

		if (t.Buffer == NULL)
		{
			// 最後まで読み込んだ
			break;
		}

		// 現在の状況を更新
		offset += t.Buffer->Size;
		Zero(&g, sizeof(g));
		g.Param = param;
		g.CurrentSize = offset;
		g.TotalSize = MAX(total_size, offset);
		g.ProgressPercent = (UINT)(MAKESURE((UINT64)g.CurrentSize * 100ULL / (UINT64)(MAX(g.TotalSize, 1)), 0, 100ULL));

		WriteBuf(buf, t.Buffer->Buf, t.Buffer->Size);

		FreeRpcReadLogFile(&t);

		if (proc != NULL)
		{
			if (proc(&g) == false)
			{
				// ユーザーキャンセル
				FreeBuf(buf);
				return NULL;
			}
		}
	}

	if (buf->Size == 0)
	{
		// ダウンロード失敗
		FreeBuf(buf);
		return NULL;
	}

	return buf;
}

// ログファイルの読み込み
UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	char logfilename[MAX_PATH];
	char servername[MAX_HOST_NAME_LEN + 1];
	UINT offset;
	bool local = true;

	if (IsEmptyStr(t->FilePath))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(logfilename, sizeof(logfilename), t->FilePath);
	StrCpy(servername, sizeof(servername), t->ServerName);
	offset = t->Offset;

	if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		GetMachineName(servername, sizeof(servername));
	}

	// ログファイルを読み込む権限があるかどうか検査する
	if (a->LogFileList == NULL)
	{
		// キャッシュ無し
		return ERR_OBJECT_NOT_FOUND;
	}
	if (CheckLogFileNameFromEnumList(a->LogFileList, logfilename, servername) == false)
	{
		// そのようなファイルは列挙リストに無い
		return ERR_OBJECT_NOT_FOUND;
	}

	FreeRpcReadLogFile(t);
	Zero(t, sizeof(RPC_READ_LOG_FILE));

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i;

		// 要求されたファイルのサーバー名がクラスタメンバのホスト名
		// と一致した場合はリモートサーバー上にファイルが存在するのでそれを読み込む
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				if (f->Me == false)
				{
					if (StrCmpi(f->hostname, servername) == 0)
					{
						RPC_READ_LOG_FILE tt;

						Zero(&tt, sizeof(tt));
						local = false;

						StrCpy(tt.ServerName, sizeof(tt.ServerName), servername);
						StrCpy(tt.FilePath, sizeof(tt.FilePath), logfilename);
						tt.Offset = offset;

						if (SiCallReadLogFile(s, f, &tt))
						{
							if (tt.Buffer != NULL && tt.Buffer->Size > 0)
							{
								t->Buffer = NewBuf();
								WriteBuf(t->Buffer, tt.Buffer->Buf, tt.Buffer->Size);
							}
						}

						FreeRpcReadLogFile(&tt);

						break;
					}
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	// ローカルファイルの読み込み
	if (local)
	{
		SiReadLocalLogFile(s, logfilename, offset, t);
	}

	if (offset == 0)
	{
		ALog(a, NULL, "LA_READ_LOG_FILE", servername, logfilename);
	}

	return ERR_NO_ERROR;
}

// ログファイルの列挙
UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT i;
	bool no_access = false;

	HUB *h;

	if (a->ServerAdmin == false)
	{
		h = GetHub(c, a->HubName);

		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_read_log_file") != 0)
		{
			no_access = true;
		}

		ReleaseHub(h);
	}
	else
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			// クラスタコントローラで管理者がログファイルの一覧を取得する
			// と高負荷になるため制限している
			return ERR_NOT_SUPPORTED;
		}
	}

	if (no_access)
	{
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcEnumLogFile(t);
	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	// ローカルのログファイルを列挙する
	SiEnumLocalLogFileList(s, a->ServerAdmin ? NULL : a->HubName, t);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i;
		LIST *tt_list = NewListFast(NULL);

		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				if (f->Me == false)
				{
					// 他のメンバ上のログファイルを列挙する
					RPC_ENUM_LOG_FILE *tt;
					tt = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE));

					if (SiCallEnumLogFileList(s, f, tt, a->ServerAdmin ? "" : a->HubName))
					{
						UINT i;
						for (i = 0;i < tt->NumItem;i++)
						{
							RPC_ENUM_LOG_FILE_ITEM *e = &tt->Items[i];

							StrCpy(e->ServerName, sizeof(e->ServerName), f->hostname);
						}

						Add(tt_list, tt);
					}
					else
					{
						Free(tt);
					}
				}
			}
		}
		UnlockList(s->FarmMemberList);

		for (i = 0;i < LIST_NUM(tt_list);i++)
		{
			RPC_ENUM_LOG_FILE *tt = LIST_DATA(tt_list, i);

			AdjoinRpcEnumLogFile(t, tt);
			FreeRpcEnumLogFile(tt);

			Free(tt);
		}

		ReleaseList(tt_list);
	}

	// RPC セッションに最後に列挙したログファイル一覧をキャッシュする
	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}

	a->LogFileList = NewListFast(CmpLogFile);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		f->UpdatedTime = e->UpdatedTime;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);
		StrCpy(f->ServerName, sizeof(f->ServerName), e->ServerName);

		Insert(a->LogFileList, f);
	}

	return ERR_NO_ERROR;
}


// AC リストの取得
UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	return ERR_NOT_SUPPORTED;
}

// AC リストの設定
UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	return ERR_NOT_SUPPORTED;
}

// CRL の設定
UINT StSetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_INTERNAL_ERROR;
					}
					else
					{
						CRL *new_crl = CopyCrl(t->Crl);
						if (ReplaceListPointer(h->HubDb->CrlList, crl, new_crl))
						{
							ALog(a, h, "LA_ADD_CRL");
							FreeCrl(crl);

							IncrementServerConfigRevision(s);
						}
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// CRL の取得
UINT StGetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcCrl(t);
	Zero(t, sizeof(RPC_CRL));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	t->Key = key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

				if (crl == NULL)
				{
					ret = ERR_INTERNAL_ERROR;
				}
				else
				{
					t->Crl = CopyCrl(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}

// CRL の削除
UINT StDelCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_INTERNAL_ERROR;
					}
					else
					{
						ALog(a, h, "LA_DEL_CRL");
						FreeCrl(crl);
						Delete(h->HubDb->CrlList, crl);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// CRL の追加
UINT StAddCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					if (LIST_NUM(h->HubDb->CrlList) < MAX_HUB_CRLS)
					{
						CRL *crl = CopyCrl(t->Crl);

						Insert(h->HubDb->CrlList, crl);

						ALog(a, h, "LA_SET_CRL");

						IncrementServerConfigRevision(s);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// CRL の列挙
UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumCrl(t);
	Zero(t, sizeof(RPC_ENUM_CRL));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				UINT i;

				t->NumItem = LIST_NUM(h->HubDb->CrlList);
				t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);

				for (i = 0;i < LIST_NUM(h->HubDb->CrlList);i++)
				{
					CRL *crl = LIST_DATA(h->HubDb->CrlList, i);
					wchar_t *info = GenerateCrlStr(crl);

					UniStrCpy(t->Items[i].CrlInfo, sizeof(t->Items[i].CrlInfo), info);
					Free(info);

					t->Items[i].Key = POINTER_TO_KEY(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}

// ルーティングテーブルの列挙
UINT StEnumL3Table(ADMIN *a, RPC_ENUM_L3TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;
	char name[MAX_HUBNAME_LEN + 1];

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(name, sizeof(name), t->Name);
	FreeRpcEnumL3Table(t);
	Zero(t, sizeof(RPC_ENUM_L3TABLE));
	StrCpy(t->Name, sizeof(t->Name), name);

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		UINT i;

		Lock(sw->lock);
		{
			t->NumItem = LIST_NUM(sw->TableList);
			t->Items = ZeroMalloc(sizeof(RPC_L3TABLE) * t->NumItem);

			for (i = 0;i < t->NumItem;i++)
			{
				L3TABLE *tbl = LIST_DATA(sw->TableList, i);
				RPC_L3TABLE *e = &t->Items[i];

				StrCpy(e->Name, sizeof(e->Name), name);
				e->NetworkAddress = tbl->NetworkAddress;
				e->SubnetMask = tbl->SubnetMask;
				e->GatewayAddress = tbl->GatewayAddress;
				e->Metric = tbl->Metric;
			}
		}
		Unlock(sw->lock);

		ReleaseL3Sw(sw);
	}

	return ret;
}

// ルーティングテーブルの削除
UINT StDelL3Table(ADMIN *a, RPC_L3TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	SERVER_ADMIN_ONLY;

	NO_SUPPORT_FOR_BRIDGE;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		L3TABLE tbl;

		Zero(&tbl, sizeof(tbl));
		tbl.NetworkAddress = t->NetworkAddress;
		tbl.SubnetMask = t->SubnetMask;
		tbl.GatewayAddress = t->GatewayAddress;
		tbl.Metric = t->Metric;

		if (L3DelTable(sw, &tbl) == false)
		{
			ret = ERR_LAYER3_TABLE_DEL_FAILED;
		}
		else
		{
			char tmp[MAX_SIZE];
			IPToStr32(tmp, sizeof(tmp), tbl.NetworkAddress);
			ALog(a, NULL, "LA_DEL_L3_TABLE", tmp, t->Name);

			IncrementServerConfigRevision(s);
		}

		ReleaseL3Sw(sw);
	}

	return ret;
}

// ルーティングテーブルの追加
UINT StAddL3Table(ADMIN *a, RPC_L3TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	if (IsNetworkAddress32(t->NetworkAddress, t->SubnetMask) == false ||
		IsHostIPAddress32(t->GatewayAddress) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	NO_SUPPORT_FOR_BRIDGE;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		L3TABLE tbl;

		Zero(&tbl, sizeof(tbl));
		tbl.NetworkAddress = t->NetworkAddress;
		tbl.SubnetMask = t->SubnetMask;
		tbl.GatewayAddress = t->GatewayAddress;
		tbl.Metric = t->Metric;

		if (L3AddTable(sw, &tbl) == false)
		{
			ret = ERR_LAYER3_TABLE_ADD_FAILED;
		}
		else
		{
			char tmp[MAX_SIZE];
			IPToStr32(tmp, sizeof(tmp), tbl.NetworkAddress);
			ALog(a, NULL, "LA_ADD_L3_TABLE", tmp, t->Name);

			IncrementServerConfigRevision(s);
		}

		ReleaseL3Sw(sw);
	}

	return ret;
}

// インターフェイスの列挙
UINT StEnumL3If(ADMIN *a, RPC_ENUM_L3IF *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;
	char name[MAX_HUBNAME_LEN + 1];

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(name, sizeof(name), t->Name);

	FreeRpcEnumL3If(t);
	Zero(t, sizeof(RPC_ENUM_L3IF));

	StrCpy(t->Name, sizeof(t->Name), name);

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		Lock(sw->lock);
		{
			UINT i;

			t->NumItem = LIST_NUM(sw->IfList);
			t->Items = ZeroMalloc(sizeof(RPC_L3IF) * t->NumItem);

			for (i = 0;i < t->NumItem;i++)
			{
				L3IF *f = LIST_DATA(sw->IfList, i);
				RPC_L3IF *e = &t->Items[i];

				StrCpy(e->Name, sizeof(e->Name), sw->Name);
				StrCpy(e->HubName, sizeof(e->HubName), f->HubName);
				e->IpAddress = f->IpAddress;
				e->SubnetMask = f->SubnetMask;
			}
		}
		Unlock(sw->lock);

		ReleaseL3Sw(sw);
	}

	return ret;
}

// インターフェイスの削除
UINT StDelL3If(ADMIN *a, RPC_L3IF *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		if (L3DelIf(sw, t->HubName) == false)
		{
			ret = ERR_LAYER3_IF_DEL_FAILED;
		}
		else
		{
			ALog(a, NULL, "LA_DEL_L3_IF", t->HubName, t->Name);

			IncrementServerConfigRevision(s);
		}
		ReleaseL3Sw(sw);
	}

	return ret;
}

// インターフェイスの追加
UINT StAddL3If(ADMIN *a, RPC_L3IF *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	if (IsSubnetMask32(t->SubnetMask) == false || IsHostIPAddress32(t->IpAddress) == false)
	{
		return ERR_INVALID_PARAMETER;
	}
	if ((t->IpAddress & (~t->SubnetMask)) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		Lock(sw->lock);
		{
			if (L3SearchIf(sw, t->HubName) != NULL)
			{
				// すでに存在する
				ret = ERR_LAYER3_IF_EXISTS;
			}
			else
			{
				if (L3AddIf(sw, t->HubName, t->IpAddress, t->SubnetMask) == false)
				{
					ret = ERR_LAYER3_IF_ADD_FAILED;
				}
				else
				{
					ALog(a, NULL, "LA_ADD_L3_IF", t->HubName, t->Name);

					IncrementServerConfigRevision(s);
				}
			}
		}
		Unlock(sw->lock);
		ReleaseL3Sw(sw);
	}

	return ret;
}

// Layer-3 スイッチの停止
UINT StStopL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		L3SwStop(sw);
		ALog(a, NULL, "LA_STOP_L3_SW", sw->Name);
		ReleaseL3Sw(sw);

		IncrementServerConfigRevision(s);
	}

	return ret;
}

// Layer-3 スイッチの開始
UINT StStartL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		Lock(sw->lock);
		{
			// 登録されているインターフェイス数を検査する
			if (LIST_NUM(sw->IfList) >= 1)
			{
				L3SwStart(sw);

				ALog(a, NULL, "LA_START_L3_SW", sw->Name);

				IncrementServerConfigRevision(s);
			}
			else
			{
				ret = ERR_LAYER3_CANT_START_SWITCH;
			}
		}
		Unlock(sw->lock);

		ReleaseL3Sw(sw);
	}

	return ret;
}

// Layer-3 スイッチの列挙
UINT StEnumL3Switch(ADMIN *a, RPC_ENUM_L3SW *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	NO_SUPPORT_FOR_BRIDGE;

	FreeRpcEnumL3Sw(t);
	Zero(t, sizeof(RPC_ENUM_L3SW));

	LockList(c->L3SwList);
	{
		t->NumItem = LIST_NUM(c->L3SwList);
		t->Items = ZeroMalloc(sizeof(RPC_ENUM_L3SW_ITEM) * t->NumItem);
		for (i = 0;i < LIST_NUM(c->L3SwList);i++)
		{
			L3SW *sw = LIST_DATA(c->L3SwList, i);
			RPC_ENUM_L3SW_ITEM *e = &t->Items[i];

			Lock(sw->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), sw->Name);
				e->NumInterfaces = LIST_NUM(sw->IfList);
				e->NumTables = LIST_NUM(sw->TableList);
				e->Active = sw->Active;
				e->Online = sw->Online;
			}
			Unlock(sw->lock);
		}
	}
	UnlockList(c->L3SwList);

	return ret;
}

// Layer-3 スイッチの削除
UINT StDelL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	if (L3DelSw(c, t->Name) == false)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		ALog(a, NULL, "LA_DEL_L3_SW", t->Name);

		IncrementServerConfigRevision(s);
	}

	return ret;
}

// Layer-3 スイッチの追加
UINT StAddL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	NO_SUPPORT_FOR_BRIDGE;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	// 重複チェック
	sw = L3GetSw(c, t->Name);
	if (sw != NULL)
	{
		// すでに存在する
		ReleaseL3Sw(sw);
		ret = ERR_LAYER3_SW_EXISTS;
	}
	else
	{
		LockList(c->L3SwList);
		{
			if (LIST_NUM(c->L3SwList) >= GetServerCapsInt(s, "i_max_l3_sw"))
			{
				// これ以上作成できない
				sw = NULL;
			}
			else
			{
				// 作成する
				sw = L3AddSw(c, t->Name);

				if (sw != NULL)
				{
					ALog(a, NULL, "LA_ADD_L3_SW", t->Name);

					IncrementServerConfigRevision(s);
				}
			}
		}
		UnlockList(c->L3SwList);

		if (sw == NULL)
		{
			// 失敗
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			// 成功
			ReleaseL3Sw(sw);
		}
	}

	return ret;
}

// 仮想 HUB の拡張オプションを設定する
UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;

	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (GetHubAdminOption(h, "deny_hub_admin_change_ext_option") && not_server_admin)
	{
		// 十分な管理権限が無い
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	// 設定の実行
	Lock(h->lock);
	{
		DataToHubOptionStruct(h->Option, t);
	}
	Unlock(h->lock);

	ALog(a, NULL, "LA_SET_HUB_EXT_OPTION", h->Name);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// 仮想 HUB の拡張オプションを取得する
UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	// 設定の取得
	Lock(h->lock);
	{
		HubOptionStructToData(t, h->Option, h->Name);
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// 仮想 HUB の管理オプションを設定する
UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;

	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (GetHubAdminOption(h, "allow_hub_admin_change_option") == false
		&& not_server_admin)
	{
		// 十分な管理権限が無い
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->AdminOptionList);
	{
		DeleteAllHubAdminOption(h, false);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *e = &t->Items[i];
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}

		AddHubAdminOptionsDefaults(h, false);
	}
	UnlockList(h->AdminOptionList);

	ALog(a, NULL, "LA_SET_HUB_ADMIN_OPTION", h->Name);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// 仮想 HUB の管理オプションを取得する
UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	LockList(h->AdminOptionList);
	{
		t->NumItem = LIST_NUM(h->AdminOptionList);
		t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);
			ADMIN_OPTION *e = &t->Items[i];

			StrCpy(e->Name, sizeof(e->Name), a->Name);
			e->Value = a->Value;
		}
	}
	UnlockList(h->AdminOptionList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// デフォルトの管理オプションの一覧を取得する
UINT StGetDefaultHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;

	NO_SUPPORT_FOR_BRIDGE;
	if (a->Server->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	t->NumItem = num_admin_options;
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *a = &t->Items[i];

		StrCpy(a->Name, sizeof(a->Name), admin_options[i].Name);
		a->Value = admin_options[i].Value;
	}

	return ERR_NO_ERROR;
}

// config の取得
UINT StGetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;

	SERVER_ADMIN_ONLY;

	FreeRpcConfig(t);
	Zero(t, sizeof(RPC_CONFIG));

	s = a->Server;

	ALog(a, NULL, "LA_GET_CONFIG");

	if (s->CfgRw != NULL)
	{
		FOLDER *f = SiWriteConfigurationToCfg(s);
		BUF *b = CfgFolderToBuf(f, true);

		StrCpy(t->FileName, sizeof(t->FileName), s->CfgRw->FileName + (s->CfgRw->FileName[0] == '@' ? 1 : 0));

		t->FileData = ZeroMalloc(b->Size + 1);
		Copy(t->FileData, b->Buf, b->Size);

		CfgDeleteFolder(f);
		FreeBuf(b);

		return ERR_NO_ERROR;
	}
	else
	{
		return ERR_INTERNAL_ERROR;
	}
}

// config の設定
UINT StSetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;
	IO *o;
	char filename[MAX_PATH];

	SERVER_ADMIN_ONLY;

	s = a->Server;
	if (s->CfgRw == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// 新しい Config ファイルに書き込む
	Format(filename, sizeof(filename), "%s.new", s->CfgRw->FileName);

	o = FileCreate(filename);

	FileWrite(o, t->FileData, StrLen(t->FileData));

	FileClose(o);

	IncrementServerConfigRevision(s);

	ALog(a, NULL, "LA_SET_CONFIG");

	// サーバーを再起動する
	SiRebootServer(s->Cedar->Bridge);

	return ERR_NO_ERROR;
}

// Caps の取得
UINT StGetCaps(ADMIN *a, CAPSLIST *t)
{
	FreeRpcCapsList(t);
	Zero(t, sizeof(CAPSLIST));

	GetServerCapsMain(a->Server, t);

	return ERR_NO_ERROR;
}

// サーバーの再起動
UINT StRebootServer(ADMIN *a, RPC_TEST *t)
{
	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_REBOOT_SERVER");

	SiRebootServerEx(a->Server->Cedar->Bridge, t->IntValue);

	return ERR_NO_ERROR;
}

// ローカルブリッジのサポート情報の取得
UINT StGetBridgeSupport(ADMIN *a, RPC_BRIDGE_SUPPORT *t)
{
	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = IsBridgeSupported();
	t->IsWinPcapNeeded = IsNeedWinPcap();

	return ERR_NO_ERROR;
}

// Ethernet デバイスの列挙
UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t)
{
	TOKEN_LIST *o;
	UINT i;
	char tmp[MAX_SIZE];
	bool unix_support = false;

	SERVER_ADMIN_ONLY;

#ifdef	OS_UNIX
	unix_support = EthIsInterfaceDescriptionSupportedUnix();
#endif	// OS_UNIX

	o = GetEthList();

	FreeRpcEnumEth(t);
	Zero(t, sizeof(RPC_ENUM_ETH));

	t->NumItem = o->NumTokens;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];

		StrCpy(e->DeviceName, sizeof(e->DeviceName), o->Token[i]);

		StrCpy(tmp, sizeof(tmp), e->DeviceName);

#ifdef OS_WIN32
		GetEthNetworkConnectionName(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), e->DeviceName);
#else
		if (unix_support == false)
		{
			StrCpy(tmp, sizeof(tmp), "");
		}
		else
		{
			if (EthGetInterfaceDescriptionUnix(e->DeviceName, tmp, sizeof(tmp)) == false)
			{
				StrCpy(tmp, sizeof(tmp), e->DeviceName);
			}
		}

		StrToUni(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), tmp);
#endif
	}

	FreeToken(o);

	return ERR_NO_ERROR;
}

// ローカルブリッジの追加
UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	if (IsEthSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

	ALog(a, NULL, "LA_ADD_BRIDGE", t->HubName, t->DeviceName);

	AddLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName, false, false, t->TapMode, NULL, false);

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// ローカルブリッジの削除
UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_DELETE_BRIDGE", t->HubName, t->DeviceName);

	if (DeleteLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// ローカルブリッジの列挙
UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t)
{
	UINT i;
	CEDAR *c;

	if (IsEthSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

	FreeRpcEnumLocalBridge(t);
	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));

	c = a->Server->Cedar;

	LockList(c->LocalBridgeList);
	{
		t->NumItem = LIST_NUM(c->LocalBridgeList);
		t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			RPC_LOCALBRIDGE *e = &t->Items[i];
			LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

			if (br->Bridge == false)
			{
				e->Online = e->Active = false;
			}
			else
			{
				e->Online = true;
				if (br->Bridge->Active)
				{
					e->Active = true;
				}
				else
				{
					e->Active = false;
				}
			}
			StrCpy(e->DeviceName, sizeof(e->DeviceName), br->DeviceName);
			StrCpy(e->HubName, sizeof(e->HubName), br->HubName);

			e->TapMode = br->TapMode;
		}
	}
	UnlockList(c->LocalBridgeList);

	return ERR_NO_ERROR;
}

// syslog 設定の書き込み
UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	return ERR_NOT_SUPPORTED;
}

// syslog 設定の読み込み
UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	return ERR_NOT_SUPPORTED;
}

// KEEP の設定
UINT StSetKeep(ADMIN *a, RPC_KEEP *t)
{
	SERVER *s = a->Server;

	if (t->UseKeepConnect)
	{
		if (IsEmptyStr(t->KeepConnectHost) ||
			t->KeepConnectPort == 0 ||
			t->KeepConnectPort >= 65536)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	SERVER_ADMIN_ONLY;

	Lock(s->Keep->lock);
	{
		KEEP *keep = s->Keep;
		keep->Enable = t->UseKeepConnect;
		keep->Server = true;
		StrCpy(keep->ServerName, sizeof(keep->ServerName), t->KeepConnectHost);
		keep->ServerPort = t->KeepConnectPort;
		keep->UdpMode = t->KeepConnectProtocol;
		keep->Interval = t->KeepConnectInterval * 1000;
		if (keep->Interval < 5000)
		{
			keep->Interval = 5000;
		}
		else if (keep->Interval > 600000)
		{
			keep->Interval = 600000;
		}
	}
	Unlock(s->Keep->lock);

	ALog(a, NULL, "LA_SET_KEEP");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// KEEP の取得
UINT StGetKeep(ADMIN *a, RPC_KEEP *t)
{
	SERVER *s = a->Server;

	Zero(t, sizeof(RPC_KEEP));

	Lock(s->Keep->lock);
	{
		KEEP *k = s->Keep;
		t->UseKeepConnect = k->Enable;
		StrCpy(t->KeepConnectHost, sizeof(t->KeepConnectHost), k->ServerName);
		t->KeepConnectPort = k->ServerPort;
		t->KeepConnectProtocol = k->UdpMode;
		t->KeepConnectInterval = k->Interval / 1000;
	}
	Unlock(s->Keep->lock);

	return ERR_NO_ERROR;
}

// IP テーブルの削除
UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_iptable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->IpTable);
	{
		if (IsInListKey(h->IpTable, t->Key))
		{
			IP_TABLE_ENTRY *e = ListKeyToPointer(h->IpTable, t->Key);
			Free(e);
			Delete(h->IpTable, e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->IpTable);

	if (ret == ERR_OBJECT_NOT_FOUND)
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			UINT i;
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						SiCallDeleteIpTable(s, f, t->HubName, t->Key);
						ret = ERR_NO_ERROR;
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	return ret;
}

// ローカル IP テーブルの列挙
UINT SiEnumIpTable(SERVER *s, char *hubname, RPC_ENUM_IP_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	// 引数チェック
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->IpTable);
	{
		t->NumIpTable = LIST_NUM(h->IpTable);
		t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

		for (i = 0;i < t->NumIpTable;i++)
		{
			RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];
			IP_TABLE_ENTRY *table = LIST_DATA(h->IpTable, i);

			e->Key = POINTER_TO_KEY(table);
			StrCpy(e->SessionName, sizeof(e->SessionName), table->Session->Name);
			e->Ip = IPToUINT(&table->Ip);
			Copy(&e->IpV6, &table->Ip, sizeof(IP));
			e->DhcpAllocated = table->DhcpAllocated;
			e->CreatedTime = TickToTime(table->CreatedTime);
			e->UpdatedTime = TickToTime(table->UpdatedTime);

			GetMachineName(e->RemoteHostname, sizeof(e->RemoteHostname));
		}
	}
	UnlockList(h->IpTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// IP テーブルの列挙
UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	// ローカルの列挙
	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumIpTable(t);
	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	ret = SiEnumIpTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// リモートの列挙
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me == false)
				{
					RPC_ENUM_IP_TABLE tmp;

					Zero(&tmp, sizeof(tmp));

					SiCallEnumIpTable(s, f, hubname, &tmp);

					AdjoinRpcEnumIpTable(t, &tmp);
					FreeRpcEnumIpTable(&tmp);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	return ret;
}

// MAC テーブルの削除
UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_mactable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->MacTable);
	{
		if (IsInListKey(h->MacTable, t->Key))
		{
			MAC_TABLE_ENTRY *e = ListKeyToPointer(h->MacTable, t->Key);
			Free(e);
			Delete(h->MacTable, e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->MacTable);

	if (ret == ERR_OBJECT_NOT_FOUND)
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			UINT i;
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						SiCallDeleteMacTable(s, f, t->HubName, t->Key);
						ret = ERR_NO_ERROR;
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	return ret;
}

// ローカル MAC テーブルの列挙
UINT SiEnumMacTable(SERVER *s, char *hubname, RPC_ENUM_MAC_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	// 引数チェック
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->MacTable);
	{
		t->NumMacTable = LIST_NUM(h->MacTable);
		t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

		for (i = 0;i < t->NumMacTable;i++)
		{
			RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];
			MAC_TABLE_ENTRY *mac = LIST_DATA(h->MacTable, i);

			e->Key = POINTER_TO_KEY(mac);
			StrCpy(e->SessionName, sizeof(e->SessionName), mac->Session->Name);
			Copy(e->MacAddress, mac->MacAddress, sizeof(e->MacAddress));
			e->CreatedTime = TickToTime(mac->CreatedTime);
			e->UpdatedTime = TickToTime(mac->UpdatedTime);
			e->VlanId = mac->VlanId;

			GetMachineName(e->RemoteHostname, sizeof(e->RemoteHostname));
		}
	}
	UnlockList(h->MacTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// MAC テーブルの列挙
UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	// ローカルの MAC テーブルを列挙する
	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumMacTable(t);
	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));

	ret = SiEnumMacTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// リモートの MAC テーブルを列挙する
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me == false)
				{
					RPC_ENUM_MAC_TABLE tmp;

					Zero(&tmp, sizeof(tmp));

					SiCallEnumMacTable(s, f, hubname, &tmp);

					AdjoinRpcEnumMacTable(t, &tmp);
					FreeRpcEnumMacTable(&tmp);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	return ret;
}

// セッションの削除
UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_disconnect_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	sess = GetSessionByName(h, name);

	if (sess == NULL)
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			// ファームコントローラ
			UINT i;
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						// 切断を試行
						SiCallDeleteSession(s, f, t->HubName, t->Name);
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	else
	{
		if (sess->LinkModeServer)
		{
			ret = ERR_LINK_CANT_DISCONNECT;
		}
		else if (sess->SecureNATMode)
		{
			ret = ERR_SNAT_CANT_DISCONNECT;
		}
		else if (sess->BridgeMode)
		{
			ret = ERR_BRIDGE_CANT_DISCONNECT;
		}
		else if (sess->L3SwitchMode)
		{
			ret = ERR_LAYER3_CANT_DISCONNECT;
		}
		else
		{
			StopSession(sess);
		}
		ReleaseSession(sess);
	}

	if (ret != ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_SESSION", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

// セッション状態の取得
UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_query_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcSessionStatus(t);
	Zero(t, sizeof(RPC_SESSION_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	sess = GetSessionByName(h, t->Name);

	if (sess == NULL)
	{
		if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
		{
			// セッションが見つからない
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			UINT i;
			// 自分以外のメンバのセッションも検索してみる
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_SESSION_STATUS tmp;
						Zero(&tmp, sizeof(tmp));
						StrCpy(tmp.HubName, sizeof(tmp.HubName), t->HubName);
						StrCpy(tmp.Name, sizeof(tmp.Name), t->Name);

						if (SiCallGetSessionStatus(s, f, &tmp))
						{
							if (StrLen(tmp.HubName) != 0)
							{
								// セッション情報の取得に成功した
								Copy(t, &tmp, sizeof(RPC_SESSION_STATUS));
								break;
							}
							else
							{
								FreeRpcSessionStatus(&tmp);
							}
						}
					}
				}

				if (i == LIST_NUM(s->FarmMemberList))
				{
					// 結局見つからない
					ret = ERR_OBJECT_NOT_FOUND;
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}
	else
	{
		SESSION *s = sess;

		Lock(s->lock);
		{
			StrCpy(t->Username, sizeof(t->Username), s->Username);
			StrCpy(t->RealUsername, sizeof(t->RealUsername), s->UserNameReal);
			StrCpy(t->GroupName, sizeof(t->GroupName), s->GroupName);
			Copy(&t->NodeInfo, &s->NodeInfo, sizeof(NODE_INFO));

			if (s->Connection != NULL)
			{
				t->ClientIp = IPToUINT(&s->Connection->ClientIp);
				if (IsIP6(&s->Connection->ClientIp))
				{
					Copy(&t->ClientIp6, &s->Connection->ClientIp.ipv6_addr, sizeof(t->ClientIp6));
				}

				StrCpy(t->ClientHostName, sizeof(t->ClientHostName), s->Connection->ClientHostname);
			}
		}
		Unlock(s->lock);

		CiGetSessionStatus(&t->Status, s);

		ReleaseSession(s);
	}

	ReleaseHub(h);

	return ret;
}

// セッションの列挙メイン
void SiEnumSessionMain(SERVER *s, RPC_ENUM_SESSION *t)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT ret = ERR_NO_ERROR;
	UINT num;
	UINT i;
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcEnumSession(t);
	Zero(t, sizeof(RPC_ENUM_SESSION));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	// ローカルセッションの列挙
	num = 0;
	SiEnumLocalSession(s, hubname, t);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// リモートセッションの列挙
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me == false)
				{
					RPC_ENUM_SESSION tmp;

					Zero(&tmp, sizeof(tmp));

					SiCallEnumSession(s, f, hubname, &tmp);

					AdjoinRpcEnumSession(t, &tmp);
					FreeRpcEnumSession(&tmp);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}
}

// セッションの列挙
UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_enum_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	SiEnumSessionMain(s, t);

	ReleaseHub(h);

	return ret;
}

// グループの列挙
UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		UINT i, j;

		FreeRpcEnumGroup(t);
		Zero(t, sizeof(RPC_ENUM_GROUP));
		StrCpy(t->HubName, sizeof(t->HubName), hubname);

		t->NumGroup = LIST_NUM(h->HubDb->GroupList);
		t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

		for (i = 0;i < t->NumGroup;i++)
		{
			RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];
			USERGROUP *g = LIST_DATA(h->HubDb->GroupList, i);

			Lock(g->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), g->Name);
				UniStrCpy(e->Realname, sizeof(e->Realname), g->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), g->Note);
				if (g->Policy != NULL)
				{
					if (g->Policy->Access == false)
					{
						e->DenyAccess = true;
					}
				}
			}
			Unlock(g->lock);

			e->NumUsers = 0;


			LockList(h->HubDb->UserList);
			{
				for (j = 0;j < LIST_NUM(h->HubDb->UserList);j++)
				{
					USER *u = LIST_DATA(h->HubDb->UserList, j);

					Lock(u->lock);
					{
						if (u->Group == g)
						{
							e->NumUsers++;
						}
					}
					Unlock(u->lock);
				}
			}
			UnlockList(h->HubDb->UserList);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// グループの削除
UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcDeleteGroup(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_GROUP", t->Name);
	}

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// グループの取得
UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);

		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			FreeRpcSetGroup(t);
			Zero(t, sizeof(RPC_SET_GROUP));

			StrCpy(t->HubName, sizeof(t->HubName), hubname);

			Lock(g->lock);
			{
				StrCpy(t->Name, sizeof(t->Name), g->Name);
				UniStrCpy(t->Realname, sizeof(t->Realname), g->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), g->Note);
				Copy(&t->Traffic, g->Traffic, sizeof(TRAFFIC));
			}
			Unlock(g->lock);

			t->Policy = GetGroupPolicy(g);

			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

// グループの設定
UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);
		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(g->lock);
			{
				Free(g->RealName);
				Free(g->Note);
				g->RealName = UniCopyStr(t->Realname);
				g->Note = UniCopyStr(t->Note);
			}
			Unlock(g->lock);

			SetGroupPolicy(g, t->Policy);

			ReleaseGroup(g);

			ALog(a, h, "LA_SET_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// グループの作成
UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcIsGroup(h, t->Name))
		{
			ret = ERR_GROUP_ALREADY_EXISTS;
		}
		else
		{
			USERGROUP *g = NewGroup(t->Name, t->Realname, t->Note);
			SetGroupPolicy(g, t->Policy);

			if ((LIST_NUM(h->HubDb->GroupList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
				((GetHubAdminOption(h, "max_groups") != 0) && (LIST_NUM(h->HubDb->GroupList) >= GetHubAdminOption(h, "max_groups"))))
			{
				ret = ERR_TOO_MANY_GROUP;
			}
			else
			{
				AcAddGroup(h, g);
			}

			ReleaseGroup(g);

			ALog(a, h, "LA_CREATE_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// ユーザーの列挙
UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i, num;

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcEnumUser(t);

	StrCpy(hubname, sizeof(hubname), t->HubName);

	Zero(t, sizeof(RPC_ENUM_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->HubDb->UserList);
	{
		num = LIST_NUM(h->HubDb->UserList);

		t->NumUser = num;
		t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * num);

		for (i = 0;i < num;i++)
		{
			USER *u = LIST_DATA(h->HubDb->UserList, i);

			Lock(u->lock);
			{
				RPC_ENUM_USER_ITEM *e = &t->Users[i];

				StrCpy(e->Name, sizeof(e->Name), u->Name);
				StrCpy(e->GroupName, sizeof(e->GroupName), u->GroupName);
				UniStrCpy(e->Realname, sizeof(e->Realname), u->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), u->Note);
				e->AuthType = u->AuthType;
				e->LastLoginTime = u->LastLoginTime;
				e->NumLogin = u->NumLogin;

				if (u->Policy != NULL)
				{
					e->DenyAccess = u->Policy->Access ? false : true;
				}
			}
			Unlock(u->lock);
		}
	}
	UnlockList(h->HubDb->UserList);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// ユーザーの削除
UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_DELETE_USER", t->Name);

	AcLock(h);
	{
		if (AcDeleteUser(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// ユーザーの取得
UINT StGetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;
	char name[MAX_USERNAME_LEN + 1];
	char hubname[MAX_HUBNAME_LEN + 1];
	StrCpy(name, sizeof(name), t->Name);
	StrCpy(hubname, sizeof(hubname), t->HubName);

	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcSetUser(t);
	Zero(t, sizeof(RPC_SET_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		u = AcGetUser(h, name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				StrCpy(t->GroupName, sizeof(t->GroupName), u->GroupName);
				UniStrCpy(t->Realname, sizeof(t->Realname), u->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), u->Note);
				t->CreatedTime = u->CreatedTime;
				t->UpdatedTime = u->UpdatedTime;
				t->ExpireTime = u->ExpireTime;

				t->AuthType = u->AuthType;
				t->AuthData = CopyAuthData(u->AuthData, t->AuthType);
				t->NumLogin = u->NumLogin;
				Copy(&t->Traffic, u->Traffic, sizeof(TRAFFIC));
				if (u->Policy != NULL)
				{
					t->Policy = ClonePolicy(u->Policy);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

// ユーザーの設定
UINT StSetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;

	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_RADIUS && t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (t->AuthType == AUTHTYPE_RADIUS ||
		t->AuthType == AUTHTYPE_ROOTCERT ||
		t->AuthType == AUTHTYPE_USERCERT ||
		t->AuthType == AUTHTYPE_NT)
	{
		return ERR_UTVPN_NOT_SUPPORT_THIS_AUTH;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		u = AcGetUser(h, t->Name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				if (StrLen(t->GroupName) != 0)
				{
					g = AcGetGroup(h, t->GroupName);

					if (g != NULL)
					{
						JoinUserToGroup(u, g);
						ReleaseGroup(g);
					}
					else
					{
						ret = ERR_GROUP_NOT_FOUND;
					}
				}
				else
				{
					JoinUserToGroup(u, NULL);
				}

				if (ret != ERR_GROUP_NOT_FOUND)
				{
					Free(u->RealName);
					Free(u->Note);
					u->RealName = UniCopyStr(t->Realname);
					u->Note = UniCopyStr(t->Note);
					SetUserAuthData(u, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
					u->ExpireTime = t->ExpireTime;
					u->UpdatedTime = SystemTime64();

					SetUserPolicy(u, t->Policy);
				}
			}
			Unlock(u->lock);

			IncrementServerConfigRevision(s);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_SET_USER", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

// ユーザーの作成
UINT StCreateUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u;
	USERGROUP *g = NULL;

	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (t->AuthType == AUTHTYPE_RADIUS ||
		t->AuthType == AUTHTYPE_ROOTCERT ||
		t->AuthType == AUTHTYPE_USERCERT ||
		t->AuthType == AUTHTYPE_NT)
	{
		return ERR_UTVPN_NOT_SUPPORT_THIS_AUTH;
	}

	if (IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_RADIUS && t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	u = NewUser(t->Name, t->Realname, t->Note, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
	if (u == NULL)
	{
		ReleaseHub(h);
		return ERR_INTERNAL_ERROR;
	}

	u->ExpireTime = t->ExpireTime;

	SetUserPolicy(u, t->Policy);

	AcLock(h);
	{
		if ((LIST_NUM(h->HubDb->UserList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
			((GetHubAdminOption(h, "max_users") != 0) && (LIST_NUM(h->HubDb->UserList) >= GetHubAdminOption(h, "max_users"))))
		{
			ret = ERR_TOO_MANY_USER;
		}
		else if (SiTooManyUserObjectsInServer(s, false))
		{
			ret = ERR_TOO_MANY_USERS_CREATED;
			ALog(a, h, "ERR_128");
		}
		else if (AcIsUser(h, t->Name))
		{
			ret = ERR_USER_ALREADY_EXISTS;
		}
		else
		{
			if (StrLen(t->GroupName) != 0)
			{
				g = AcGetGroup(h, t->GroupName);
				if (g == NULL)
				{
					ret = ERR_GROUP_NOT_FOUND;
				}
			}

			if (ret != ERR_GROUP_NOT_FOUND)
			{
				if (g != NULL)
				{
					JoinUserToGroup(u, g);
					ReleaseGroup(g);
				}

				AcAddUser(h, u);
				ALog(a, h, "LA_CREATE_USER", t->Name);

				IncrementServerConfigRevision(s);
			}
		}
	}
	AcUnlock(h);

	ReleaseUser(u);

	ReleaseHub(h);

	return ret;
}

// アクセスリストの列挙
UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumAccessList(t);
	Zero(t, sizeof(RPC_ENUM_ACCESS_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->AccessList);
	{
		t->NumAccess = LIST_NUM(h->AccessList);
		t->Accesses = ZeroMalloc(sizeof(ACCESS) * t->NumAccess);

		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = &t->Accesses[i];
			Copy(a, LIST_DATA(h->AccessList, i), sizeof(ACCESS));
		}
	}
	UnlockList(h->AccessList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// アクセスリストの削除
UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool exists;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	exists = false;

	LockList(h->AccessList);
	{
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *access = LIST_DATA(h->AccessList, i);

			if (access->Id == t->Id)
			{
				Free(access);
				Delete(h->AccessList, access);
				exists = true;

				break;
			}
		}
	}
	UnlockList(h->AccessList);

	if (exists == false)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_DELETE_ACCESS");

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// アクセスリストの設定
UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool no_jitter = false;
	UINT ret = ERR_NO_ERROR;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (t->NumAccess > GetServerCapsInt(a->Server, "i_max_access_lists"))
	{
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "max_accesslists") != 0 &&
		t->NumAccess > GetHubAdminOption(h, "max_accesslists"))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockList(h->AccessList);
	{
		UINT i;

		// 古いバージョンのクライアントで対応できない形式のアクセスリストがすでに
		// 存在しないかどうかチェックする
		if (a->ClientBuild < 6560)
		{
			for (i = 0;i < LIST_NUM(h->AccessList);i++)
			{
				ACCESS *access = LIST_DATA(h->AccessList, i);
				if (access->IsIPv6 ||
					access->Jitter != 0 || access->Loss != 0 || access->Delay != 0)
				{
					ret = ERR_VERSION_INVALID;
					break;
				}
			}
		}

		if (ret == ERR_NO_ERROR)
		{
			// すべて削除
			for (i = 0;i < LIST_NUM(h->AccessList);i++)
			{
				ACCESS *access = LIST_DATA(h->AccessList, i);
				Free(access);
			}

			DeleteAll(h->AccessList);
		}
	}
	UnlockList(h->AccessList);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_SET_ACCESS_LIST", t->NumAccess);

		// すべてのアクセスリストを追加
		for (i = 0;i < t->NumAccess;i++)
		{
			ACCESS *a = &t->Accesses[i];

			if (no_jitter)
			{
				a->Jitter = a->Loss = a->Delay = 0;
			}

			AddAccessList(h, a);
		}

		IncrementServerConfigRevision(s);

		h->CurrentVersion++;
		SiHubUpdateProc(h);
	}

	ReleaseHub(h);

	return ret;
}

// アクセスリストの追加
UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	bool no_jitter = false;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if ((LIST_NUM(h->AccessList) >= GetServerCapsInt(a->Server, "i_max_access_lists") ||
		(GetHubAdminOption(h, "max_accesslists") != 0) && (LIST_NUM(h->AccessList) >= GetHubAdminOption(h, "max_accesslists"))))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	ALog(a, h, "LA_ADD_ACCESS");

	if (no_jitter)
	{
		t->Access.Jitter = t->Access.Delay = t->Access.Loss = 0;
	}

	AddAccessList(h, &t->Access);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// リンクの名前を変更する
UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	LINK *k;
	bool exists = false;

	if (UniIsEmptyStr(t->OldAccountName) || UniIsEmptyStr(t->NewAccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (UniStrCmpi(t->NewAccountName, t->OldAccountName) == 0)
	{
		// 古い名前と新しい名前が同一
		return ERR_NO_ERROR;
	}

	h = GetHub(c, t->HubName);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	// リンクを検索する
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->OldAccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}

		exists = false;

		if (k != NULL)
		{
			// 新しい名前がすでに存在しているリンクの名前と重複するかどうか検査
			for (i = 0;i < LIST_NUM(h->LinkList);i++)
			{
				LINK *kk = LIST_DATA(h->LinkList, i);
				Lock(kk->lock);
				{
					if (UniStrCmpi(kk->Option->AccountName, t->NewAccountName) == 0)
					{
						// 重複した
						exists = true;
					}
				}
				Unlock(kk->lock);
			}

			if (exists)
			{
				// すでに同一の名前が存在している
				ret = ERR_LINK_ALREADY_EXISTS;
			}
			else
			{
				// 変更作業を実施する
				UniStrCpy(k->Option->AccountName, sizeof(k->Option->AccountName), t->NewAccountName);

				ALog(a, h, "LA_RENAME_LINK", t->OldAccountName, t->NewAccountName);

				IncrementServerConfigRevision(s);
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// リンクが見つからない
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ReleaseLink(k);

	ReleaseHub(h);

	return ret;
}

// リンクを削除する
UINT StDeleteLink(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	// リンクを検索する
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// リンクが見つからない
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_DELETE_LINK", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	DelLink(h, k);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// リンクをオフラインにする
UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	// リンクを検索する
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// リンクが見つからない
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_OFFLINE", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// リンクをオンラインにする
UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	// リンクを検索する
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// リンクが見つからない
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_ONLINE", t->AccountName);

	SetLinkOnline(k);

	ReleaseLink(k);
	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// リンク状態の取得
UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;
	SESSION *sess;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	FreeRpcLinkStatus(t);
	Zero(t, sizeof(RPC_LINK_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	UniStrCpy(t->AccountName, sizeof(t->AccountName), accountname);

	k = NULL;

	// リンクを検索する
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// リンクが見つからない
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	// セッションからステータス情報を取得する
	Lock(k->lock);
	{
		sess = k->ClientSession;
		if (sess != NULL)
		{
			AddRef(sess->ref);
		}
	}
	Unlock(k->lock);

	if (sess != NULL && k->Offline == false)
	{
		CiGetSessionStatus(&t->Status, sess);
	}
	else
	{
		ret = ERR_LINK_IS_OFFLINE;
	}
	ReleaseSession(sess);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// リンクの列挙
UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumLink(t);
	Zero(t, sizeof(RPC_ENUM_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->LinkList);
	{
		t->NumLink = LIST_NUM(h->LinkList);
		t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);

		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = LIST_DATA(h->LinkList, i);
			RPC_ENUM_LINK_ITEM *e = &t->Links[i];

			Lock(k->lock);
			{
				UniStrCpy(e->AccountName, sizeof(e->AccountName), k->Option->AccountName);
				StrCpy(e->Hostname, sizeof(e->Hostname), k->Option->Hostname);
				StrCpy(e->HubName, sizeof(e->HubName), k->Option->HubName);
				e->Online = k->Offline ? false : true;

				if (e->Online)
				{
					if (k->ClientSession != NULL)
					{
						e->ConnectedTime = TickToTime(k->ClientSession->CurrentConnectionEstablishTime);
						e->Connected = (k->ClientSession->ClientStatus == CLIENT_STATUS_ESTABLISHED);
						e->LastError = k->ClientSession->Err;
					}
				}
			}
			Unlock(k->lock);
		}
	}
	UnlockList(h->LinkList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// リンクの取得
UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	char hubname[MAX_SIZE];
	LINK *k;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_LINK_CANT_CREATE_ON_FARM;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	k = NULL;

	// リンクを検索する
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// 見つからなかった
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcCreateLink(t);
	Zero(t, sizeof(t));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	Lock(k->lock);
	{
		// 設定の取得
		t->Online = k->Offline ? false : true;
		t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(t->ClientOption, k->Option, sizeof(CLIENT_OPTION));
		t->ClientAuth = CopyClientAuth(k->Auth);
		Copy(&t->Policy, k->Policy, sizeof(POLICY));

		t->CheckServerCert = k->CheckServerCert;
		t->ServerCert = CloneX(k->ServerCert);
	}
	Unlock(k->lock);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// リンクの設定
UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	LINK *k;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_LINK_CANT_CREATE_ON_FARM;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	// リンクを検索する
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// 見つからなかった
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK", t->ClientOption->AccountName);

	Lock(k->lock);
	{
		// 設定の更新
		if (k->ServerCert != NULL)
		{
			FreeX(k->ServerCert);
			k->ServerCert = NULL;
		}

		Copy(k->Option, t->ClientOption, sizeof(CLIENT_OPTION));
		StrCpy(k->Option->DeviceName, sizeof(k->Option->DeviceName), LINK_DEVICE_NAME);
		k->Option->NumRetry = INFINITE;
		k->Option->RetryInterval = 10;
		k->Option->NoRoutingTracking = true;
		CiFreeClientAuth(k->Auth);
		k->Auth = CopyClientAuth(t->ClientAuth);

		if (t->Policy.Ver3 == false)
		{
			Copy(k->Policy, &t->Policy, sizeof(UINT) * NUM_POLICY_ITEM_FOR_VER2);
		}
		else
		{
			Copy(k->Policy, &t->Policy, sizeof(POLICY));
		}

		k->Option->RequireBridgeRoutingMode = true;	// ブリッジ / ルーティングモード有効
		k->Option->RequireMonitorMode = false;	// モニタモード無効

		k->CheckServerCert = t->CheckServerCert;
		k->ServerCert = CloneX(t->ServerCert);
	}
	Unlock(k->lock);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// リンクの作成
UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	LINK *k;

	CHECK_RIGHT;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_LINK_CANT_CREATE_ON_FARM;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	// 既に同じ名前のリンクが存在しないかどうか調べる
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k != NULL)
	{
		// すでに同じ名前のリンクが存在する
		ReleaseLink(k);
		ReleaseHub(h);
		return ERR_LINK_ALREADY_EXISTS;
	}

	ALog(a, h, "LA_CREATE_LINK", t->ClientOption->AccountName);

	// リンクの作成
	k = NewLink(c, h, t->ClientOption, t->ClientAuth, &t->Policy);

	if (k == NULL)
	{
		// 作成失敗
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		// サーバー証明書検証設定
		k->CheckServerCert = t->CheckServerCert;
		k->ServerCert = CloneX(t->ServerCert);

		// オフラインにしておく
		k->Offline = false;
		SetLinkOffline(k);
		ReleaseLink(k);

		IncrementServerConfigRevision(s);
	}

	ReleaseHub(h);

	return ret;
}

// HUB の CA を削除
UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_cert_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, t->Key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, t->Key);
			Delete(h->HubDb->RootCertList, x);
			FreeX(x);

			ALog(a, h, "LA_DELETE_CA");

			IncrementServerConfigRevision(s);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

// HUB の CA を取得
UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT key;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcHubGetCa(t);
	Zero(t, sizeof(RPC_HUB_GET_CA));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, key);

			t->Cert = CloneX(x);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

// HUB の CA を列挙
UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcHubEnumCa(t);
	Zero(t, sizeof(RPC_HUB_ENUM_CA));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_HUB_ENUM_CA));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	if (h->HubDb->RootCertList != NULL)
	{
		LockList(h->HubDb->RootCertList);
		{
			t->NumCa = LIST_NUM(h->HubDb->RootCertList);
			t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);

			for (i = 0;i < t->NumCa;i++)
			{
				RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];
				X *x = LIST_DATA(h->HubDb->RootCertList, i);

				e->Key = POINTER_TO_KEY(x);
				GetAllNameFromNameEx(e->SubjectName, sizeof(e->SubjectName), x->subject_name);
				GetAllNameFromNameEx(e->IssuerName, sizeof(e->IssuerName), x->issuer_name);
				e->Expires = x->notAfter;
			}
		}
		UnlockList(h->HubDb->RootCertList);
	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// HUB へ CA を追加
UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	if (t->Cert == NULL)
	{
		ERR_INVALID_PARAMETER;
	}

	if (t->Cert->is_compatible_bit == false)
	{
		return ERR_NOT_RSA_1024;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_cert_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_ADD_CA");

	AddRootCert(h, t->Cert);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// HUB ログ設定の取得
UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	GetHubLogSetting(h, &t->LogSetting);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// HUB ログ設定の設定
UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_config") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_SET_HUB_LOG");

	SetHubLogSettingEx(h, &t->LogSetting,
		(a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_switch_type") != 0));

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// HUB 状態の取得
UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_HUB_STATUS));

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->HubType = h->Type;
		t->Online = h->Offline ? false : true;
		t->NumSessions = LIST_NUM(h->SessionList);
		t->NumSessionsClient = Count(h->NumSessionsClient);
		t->NumSessionsBridge = Count(h->NumSessionsBridge);
		t->NumAccessLists = LIST_NUM(h->AccessList);

		if (h->HubDb != NULL)
		{
			t->NumUsers = LIST_NUM(h->HubDb->UserList);
			t->NumGroups = LIST_NUM(h->HubDb->GroupList);
		}

		t->NumMacTables = LIST_NUM(h->MacTable);
		t->NumIpTables = LIST_NUM(h->IpTable);

		Lock(h->TrafficLock);
		{
			Copy(&t->Traffic, h->Traffic, sizeof(TRAFFIC));
		}
		Unlock(h->TrafficLock);

		t->NumLogin = h->NumLogin;
		t->LastCommTime = h->LastCommTime;
		t->LastLoginTime = h->LastLoginTime;
		t->CreatedTime = h->CreatedTime;
	}
	Unlock(h->lock);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i;
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				UINT k;
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				if (f->Me == false)
				{
					LockList(f->HubList);
					{
						for (k = 0;k < LIST_NUM(f->HubList);k++)
						{
							HUB_LIST *h = LIST_DATA(f->HubList, k);

							if (StrCmpi(h->Name, t->HubName) == 0)
							{
								t->NumSessions += h->NumSessions;
								t->NumSessionsClient += h->NumSessionsClient;
								t->NumSessionsBridge += h->NumSessionsBridge;
								t->NumMacTables += h->NumMacTables;
								t->NumIpTables += h->NumIpTables;
							}
						}
					}
					UnlockList(f->HubList);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	if (h->Type != HUB_TYPE_FARM_STATIC)
	{
		t->SecureNATEnabled = h->EnableSecureNAT;
	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// HUB の SecureNAT を有効にする
UINT StEnableSecureNAT(ADMIN *a, RPC_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_ENABLE_SNAT");

	EnableSecureNAT(h, true);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// HUB の SecureNAT を無効にする
UINT StDisableSecureNAT(ADMIN *a, RPC_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_DISABLE_SNAT");

	EnableSecureNAT(h, false);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// NAT エントリの列挙
UINT StEnumNAT(ADMIN *a, RPC_ENUM_NAT *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT == NULL)
		{
			ret = ERR_SNAT_NOT_RUNNING;
		}
		else
		{
			NtEnumNatList(h->SecureNAT->Nat, t);
		}
	}
	Unlock(h->lock_online);

	if (h->Type == HUB_TYPE_FARM_DYNAMIC)
	{
		if (ret == ERR_SNAT_NOT_RUNNING)
		{
			// リモートの SecureNAT の状態取得
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_ENUM_NAT tmp;

						Zero(&tmp, sizeof(tmp));

						SiCallEnumNat(s, f, hubname, &tmp);

						if (tmp.NumItem >= 1)
						{
							FreeRpcEnumNat(t);
							Copy(t, &tmp, sizeof(RPC_ENUM_NAT));
							ret = ERR_NO_ERROR;
							break;
						}
						else
						{
							FreeRpcEnumNat(&tmp);
						}
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	ret = ERR_NO_ERROR;

	return ret;
}

// SecureNAT の状態の取得
UINT StGetSecureNATStatus(ADMIN *a, RPC_NAT_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT == NULL)
		{
			ret = ERR_SNAT_NOT_RUNNING;
		}
		else
		{
			NtGetStatus(h->SecureNAT->Nat, t);
		}
	}
	Unlock(h->lock_online);

	if (h->Type == HUB_TYPE_FARM_DYNAMIC)
	{
		if (ret == ERR_SNAT_NOT_RUNNING)
		{
			// リモートの SecureNAT の状態取得
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_NAT_STATUS tmp;

						Zero(&tmp, sizeof(tmp));

						SiCallGetNatStatus(s, f, hubname, &tmp);

						if (tmp.NumDhcpClients == 0 && tmp.NumTcpSessions == 0 && tmp.NumUdpSessions == 0)
						{
						}
						else
						{
							Copy(t, &tmp, sizeof(RPC_NAT_STATUS));
							ret = ERR_NO_ERROR;
							break;
						}
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	ret = ERR_NO_ERROR;

	return ret;
}

// DHCP エントリの列挙
UINT StEnumDHCP(ADMIN *a, RPC_ENUM_DHCP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT == NULL)
		{
			ret = ERR_SNAT_NOT_RUNNING;
		}
		else
		{
			NtEnumDhcpList(h->SecureNAT->Nat, t);
		}
	}
	Unlock(h->lock_online);

	if (h->Type == HUB_TYPE_FARM_DYNAMIC)
	{
		if (ret == ERR_SNAT_NOT_RUNNING)
		{
			// リモートの DHCP の状態取得
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_ENUM_DHCP tmp;

						Zero(&tmp, sizeof(tmp));

						SiCallEnumDhcp(s, f, hubname, &tmp);

						if (tmp.NumItem >= 1)
						{
							FreeRpcEnumDhcp(t);
							Copy(t, &tmp, sizeof(RPC_ENUM_DHCP));
							ret = ERR_NO_ERROR;
							break;
						}
						else
						{
							FreeRpcEnumDhcp(&tmp);
						}
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	ret = ERR_NO_ERROR;

	return ret;
}

// SecureNATOption を設定する
UINT StSetSecureNATOption(ADMIN *a, VH_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	if (IsZero(t->MacAddress, sizeof(t->MacAddress)) ||
		IsHostIPAddress4(&t->Ip) == false ||
		IsSubnetMask4(&t->Mask) == false)
	{
		return ERR_INVALID_PARAMETER;
	}
	if ((IPToUINT(&t->Ip) & (~(IPToUINT(&t->Mask)))) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (h->SecureNATOption->UseNat == false && t->UseNat)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat_enablenat") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	if (h->SecureNATOption->UseDhcp == false && t->UseDhcp)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat_enabledhcp") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	Copy(h->SecureNATOption, t, sizeof(VH_OPTION));

	if (h->Type != HUB_TYPE_STANDALONE && h->Cedar != NULL && h->Cedar->Server != NULL &&
		h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		NiClearUnsupportedVhOptionForDynamicHub(h->SecureNATOption, false);
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT != NULL)
		{
			SetVirtualHostOption(h->SecureNAT->Nat->Virtual, t);
		}
	}
	Unlock(h->lock_online);

	ALog(a, h, "LA_SET_SNAT_OPTION");

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// SecureNATOption を取得する
UINT StGetSecureNATOption(ADMIN *a, VH_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	Zero(t, sizeof(VH_OPTION));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	Copy(t, h->SecureNATOption, sizeof(VH_OPTION));

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// HUB をオンラインまたはオフラインにする
UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && t->Online && GetHubAdminOption(h, "no_online") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && t->Online == false && GetHubAdminOption(h, "no_offline") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (t->Online)
	{
		ALog(a, h, "LA_SET_HUB_ONLINE");
		SetHubOnline(h);
	}
	else
	{
		ALog(a, h, "LA_SET_HUB_OFFLINE");
		SetHubOffline(h);
	}

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// コネクション情報の取得
UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;
	char name[MAX_CONNECTION_NAME_LEN + 1];

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;
		StrCpy(name, sizeof(name), t->Name);

		connection = Search(c->ConnectionList, &tt);

		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	StrCpy(t->Name, sizeof(t->Name), name);

	Lock(connection->lock);
	{
		SOCK *s = connection->FirstSock;

		if (s != NULL)
		{
			t->Ip = IPToUINT(&s->RemoteIP);
			t->Port = s->RemotePort;
			StrCpy(t->Hostname, sizeof(t->Hostname), s->RemoteHostname);
		}

		StrCpy(t->Name, sizeof(t->Name), connection->Name);
		t->ConnectedTime = TickToTime(connection->ConnectedTick);
		t->Type = connection->Type;

		StrCpy(t->ServerStr, sizeof(t->ServerStr), connection->ServerStr);
		StrCpy(t->ClientStr, sizeof(t->ClientStr), connection->ClientStr);
		t->ServerVer = connection->ServerVer;
		t->ServerBuild = connection->ServerBuild;
		t->ClientVer = connection->ClientVer;
		t->ClientBuild = connection->ClientBuild;
	}
	Unlock(connection->lock);

	ReleaseConnection(connection);

	return ERR_NO_ERROR;
}

// コネクションの切断
UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;

		connection = Search(c->ConnectionList, &tt);
		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	StopConnection(connection, true);

	ReleaseConnection(connection);

	ALog(a, NULL, "LA_DISCONNECT_CONN", t->Name);

	return ERR_NO_ERROR;
}

// コネクションの列挙
UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumConnetion(t);
	Zero(t, sizeof(RPC_ENUM_CONNECTION));

	LockList(c->ConnectionList);
	{
		UINT i;
		t->NumConnection = LIST_NUM(c->ConnectionList);
		t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);
		
		for (i = 0;i < t->NumConnection;i++)
		{
			RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];
			CONNECTION *connection = LIST_DATA(c->ConnectionList, i);

			Lock(connection->lock);
			{
				SOCK *s = connection->FirstSock;

				if (s != NULL)
				{
					e->Ip = IPToUINT(&s->RemoteIP);
					e->Port = s->RemotePort;
					StrCpy(e->Hostname, sizeof(e->Hostname), s->RemoteHostname);
				}

				StrCpy(e->Name, sizeof(e->Name), connection->Name);
				e->ConnectedTime = TickToTime(connection->ConnectedTick);
				e->Type = connection->Type;
			}
			Unlock(connection->lock);
		}
	}
	UnlockList(c->ConnectionList);

	return ERR_NO_ERROR;
}

// HUB の Radius オプションの設定
UINT StSetHubRadius(ADMIN *a, RPC_RADIUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	NO_SUPPORT_FOR_BRIDGE;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	SetRadiusServerEx(h, t->RadiusServerName, t->RadiusPort, t->RadiusSecret, t->RadiusRetryInterval);

	ALog(a, h, "LA_SET_HUB_RADIUS");

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// HUB の Radius オプションの取得
UINT StGetHubRadius(ADMIN *a, RPC_RADIUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	CHECK_RIGHT;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(t));
	GetRadiusServerEx(h, t->RadiusServerName, sizeof(t->RadiusServerName),
		&t->RadiusPort, t->RadiusSecret, sizeof(t->RadiusSecret), &t->RadiusRetryInterval);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// HUB の削除
UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StopHub(h);

	IncrementServerConfigRevision(s);

	DelHub(c, h);
	ReleaseHub(h);

	ALog(a, NULL, "LA_DELETE_HUB", t->HubName);

	return ERR_NO_ERROR;
}

// HUB の列挙
UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	FreeRpcEnumHub(t);

	Zero(t, sizeof(RPC_ENUM_HUB));

	LockHubList(c);
	{
		UINT i, num, j;

		num = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);

			Lock(h->lock);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
				// 列挙を許可しない
			}
			else
			{
				// 列挙を許可する
				num++;
			}
		}

		t->NumHub = num;

		t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * num);

		i = 0;
		for (j = 0;j < LIST_NUM(c->HubList);j++)
		{
			HUB *h = LIST_DATA(c->HubList, j);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
				// 列挙許可しない
			}
			else
			{
				// 列挙許可
				RPC_ENUM_HUB_ITEM *e = &t->Hubs[i++];

				StrCpy(e->HubName, sizeof(e->HubName), h->Name);
				e->Online = h->Offline ? false : true;
				e->HubType = h->Type;

				e->NumSessions = LIST_NUM(h->SessionList);

				LockList(h->MacTable);
				{
					e->NumMacTables = LIST_NUM(h->MacTable);
				}
				UnlockList(h->MacTable);

				LockList(h->IpTable);
				{
					e->NumIpTables = LIST_NUM(h->IpTable);
				}
				UnlockList(h->IpTable);

				if (h->HubDb != NULL)
				{
					LockList(h->HubDb->UserList);
					{
						e->NumUsers = LIST_NUM(h->HubDb->UserList);
					}
					UnlockList(h->HubDb->UserList);

					LockList(h->HubDb->GroupList);
					{
						e->NumGroups = LIST_NUM(h->HubDb->GroupList);
					}
					UnlockList(h->HubDb->GroupList);
				}

				e->LastCommTime = h->LastCommTime;
				e->LastLoginTime = h->LastLoginTime;
				e->NumLogin = h->NumLogin;
				e->CreatedTime = h->CreatedTime;
			}

			Unlock(h->lock);
		}
	}
	UnlockHubList(c);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i, j, k;
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				LockList(f->HubList);
				{
					if (f->Me == false)
					{
						for (j = 0;j < LIST_NUM(f->HubList);j++)
						{
							HUB_LIST *o = LIST_DATA(f->HubList, j);

							for (k = 0;k < t->NumHub;k++)
							{
								RPC_ENUM_HUB_ITEM *e = &t->Hubs[k];

								if (StrCmpi(e->HubName, o->Name) == 0)
								{
									e->NumIpTables += o->NumIpTables;
									e->NumMacTables += o->NumMacTables;
									e->NumSessions += o->NumSessions;
								}
							}
						}
					}
				}
				UnlockList(f->HubList);
			}
		}
		UnlockList(s->FarmMemberList);
	}

	return ERR_NO_ERROR;
}

// HUB 設定を取得する
UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	HUB *h;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	Zero(t, sizeof(RPC_CREATE_HUB));

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->Online = h->Offline ? false : true;
		t->HubOption.MaxSession = h->Option->MaxSession;
		t->HubOption.NoEnum = h->Option->NoEnum;
		t->HubType = h->Type;
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ret;
}

// HUB 設定を更新する
UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		if (t->HubType != HUB_TYPE_STANDALONE)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (t->HubType == HUB_TYPE_STANDALONE)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type != t->HubType)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
		IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_admin_password") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	// 設定しようとしているパスワードが空白かどうか調べる
	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		HashPassword(hash1, ADMINISTRATOR_USERNAME, "");
		Hash(hash2, "", 0, true);

		if (Cmp(t->HashedPassword, hash2, SHA1_SIZE) == 0 || Cmp(t->SecurePassword, hash1, SHA1_SIZE) == 0)
		{
			if (a->ServerAdmin == false && a->Rpc->Sock->RemoteIP.addr[0] != 127)
			{
				// ローカル以外から仮想 NUB 管理者モードで接続中に
				// 仮想 HUB のパスワードを空白に設定しようとすると拒否する
				ReleaseHub(h);
				return ERR_INVALID_PARAMETER;
			}
		}
	}

	Lock(h->lock);
	{
		if (a->ServerAdmin == false && h->Type != t->HubType)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			h->Type = t->HubType;
			h->Option->MaxSession = t->HubOption.MaxSession;
			h->Option->NoEnum = t->HubOption.NoEnum;
			if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
				IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
			{
				Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
				Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);
			}
		}
	}
	Unlock(h->lock);

	if (t->Online)
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_online") == 0)
		{
			SetHubOnline(h);
		}
	}
	else
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_offline") == 0)
		{
			SetHubOffline(h);
		}
	}

	if (h->Type == HUB_TYPE_FARM_STATIC)
	{
		EnableSecureNAT(h, false);
	}

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_SET_HUB");

	ReleaseHub(h);

	return ret;
}

// HUB を作成する
UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	HUB_OPTION o;
	UINT current_hub_num;
	bool b;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	SERVER_ADMIN_ONLY;

	Trim(t->HubName);
	if (StrLen(t->HubName) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (StartWith(t->HubName, ".") || EndWith(t->HubName, "."))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		if (t->HubType != HUB_TYPE_STANDALONE)
		{
			return ERR_INVALID_PARAMETER;
		}
	}
	else if (t->HubType != HUB_TYPE_FARM_DYNAMIC && t->HubType != HUB_TYPE_FARM_STATIC)
	{
		return ERR_INVALID_PARAMETER;
	}

	// HUB の作成
	Zero(&o, sizeof(o));
	o.MaxSession = t->HubOption.MaxSession;
	o.NoEnum = t->HubOption.NoEnum;
	o.ManageOnlyPrivateIP = true;
	o.ManageOnlyLocalUnicastIPv6 = true;
	o.NoMacAddressLog = true;
	o.NoIPv6DefaultRouterInRAWhenIPv6 = true;

	LockList(c->HubList);
	{
		current_hub_num = LIST_NUM(c->HubList);
	}
	UnlockList(c->HubList);

	if (current_hub_num > GetServerCapsInt(a->Server, "i_max_hubs"))
	{
		return ERR_TOO_MANY_HUBS;
	}

	LockList(c->HubList);
	{
		b = IsHub(c, t->HubName);
	}
	UnlockList(c->HubList);

	if (b)
	{
		return ERR_HUB_ALREADY_EXISTS;
	}

	ALog(a, NULL, "LA_CREATE_HUB", t->HubName);

	h = NewHub(c, t->HubName, &o);
	Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
	Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);

	h->Type = t->HubType;

	AddHub(c, h);

	if (t->Online)
	{
		h->Offline = true;
		SetHubOnline(h);
	}
	else
	{
		h->Offline = false;
		SetHubOffline(h);
	}

	h->CreatedTime = SystemTime64();

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// 暗号化アルゴリズムを設定する
UINT StSetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	if (IsEmptyStr(t->String))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	StrUpper(t->String);

	if (CheckCipherListName(t->String) == false)
	{
		return ERR_CIPHER_NOT_SUPPORTED;
	}
	else
	{
		ALog(a, NULL, "LA_SET_SERVER_CIPHER", t->String);
	}

	Lock(c->lock);
	{
		SetCedarCipherList(c, t->String);
	}
	Unlock(c->lock);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// 暗号化アルゴリズムを取得する
UINT StGetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcStr(t);
	Zero(t, sizeof(RPC_STR));

	Lock(c->lock);
	{
		t->String = CopyStr(c->CipherList);
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

// サーバー証明書を取得する
UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	bool admin;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	admin = a->ServerAdmin;

	FreeRpcKeyPair(t);
	Zero(t, sizeof(RPC_KEY_PAIR));

	Lock(c->lock);
	{
		t->Cert = CloneX(c->ServerX);
		if (admin)
		{
			t->Key = CloneK(c->ServerK);
		}
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

// サーバー証明書を設定する
UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	if (t->Cert == NULL || t->Key == NULL)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (t->Cert->is_compatible_bit == false)
	{
		return ERR_NOT_RSA_1024;
	}

	if (CheckXandK(t->Cert, t->Key) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	SetCedarCert(c, t->Cert, t->Key);

	ALog(a, NULL, "LA_SET_SERVER_CERT");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// サーバーファームコントローラへの接続状態を取得する
UINT StGetFarmConnectionStatus(ADMIN *a, RPC_FARM_CONNECTION_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	FARM_CONTROLLER *fc;

	if (s->ServerType != SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_MEMBER;
	}

	Zero(t, sizeof(RPC_FARM_CONNECTION_STATUS));

	fc = s->FarmController;

	Lock(fc->lock);
	{
		if (fc->Sock != NULL)
		{
			t->Ip = IPToUINT(&fc->Sock->RemoteIP);
			t->Port = fc->Sock->RemotePort;
		}

		t->Online = fc->Online;
		t->LastError = ERR_NO_ERROR;

		if (t->Online == false)
		{
			t->LastError = fc->LastError;
		}
		else
		{
			t->CurrentConnectedTime = fc->CurrentConnectedTime;
		}

		t->StartedTime = fc->StartedTime;
		t->FirstConnectedTime = fc->FirstConnectedTime;

		t->NumConnected = fc->NumConnected;
		t->NumTry = fc->NumTry;
		t->NumFailed = fc->NumFailed;
	}
	Unlock(fc->lock);

	return ERR_NO_ERROR;
}

// サーバーファームメンバ列挙
UINT StEnumFarmMember(ADMIN *a, RPC_ENUM_FARM *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT i;

	FreeRpcEnumFarm(t);
	Zero(t, sizeof(RPC_ENUM_FARM));

	if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	Zero(t, sizeof(RPC_ENUM_FARM));

	LockList(s->FarmMemberList);
	{
		t->NumFarm = LIST_NUM(s->FarmMemberList);
		t->Farms = ZeroMalloc(sizeof(RPC_ENUM_FARM_ITEM) * t->NumFarm);

		for (i = 0;i < t->NumFarm;i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
			RPC_ENUM_FARM_ITEM *e = &t->Farms[i];

			e->Id = POINTER_TO_KEY(f);
			e->Controller = f->Me;

			if (e->Controller)
			{
				e->ConnectedTime = TickToTime(c->CreatedTick);
				e->Ip = 0x0100007f;
				GetMachineName(e->Hostname, sizeof(e->Hostname));
				e->Point = f->Point;
				e->NumSessions = Count(c->CurrentSessions);
				e->NumTcpConnections = Count(c->CurrentTcpConnections);

				e->AssignedBridgeLicense = Count(c->AssignedBridgeLicense);
				e->AssignedClientLicense = Count(c->AssignedClientLicense);
			}
			else
			{
				e->ConnectedTime = f->ConnectedTime;
				e->Ip = f->Ip;
				StrCpy(e->Hostname, sizeof(e->Hostname), f->hostname);
				e->Point = f->Point;
				e->NumSessions = f->NumSessions;
				e->NumTcpConnections = f->NumTcpConnections;

				e->AssignedBridgeLicense = f->AssignedBridgeLicense;
				e->AssignedClientLicense = f->AssignedClientLicense;
			}
			e->NumHubs = LIST_NUM(f->HubList);
		}
	}
	UnlockList(s->FarmMemberList);

	return ERR_NO_ERROR;
}

// サーバーファームメンバ情報の取得
UINT StGetFarmInfo(ADMIN *a, RPC_FARM_INFO *t)
{
	SERVER *s = a->Server;
	UINT id = t->Id;
	UINT i;
	UINT ret = ERR_NO_ERROR;

	FreeRpcFarmInfo(t);
	Zero(t, sizeof(RPC_FARM_INFO));

	if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	LockList(s->FarmMemberList);
	{
		if (IsInListKey(s->FarmMemberList, id))
		{
			FARM_MEMBER *f = ListKeyToPointer(s->FarmMemberList, id);

			t->Id = id;
			t->Controller = f->Me;
			t->Weight = f->Weight;

			LockList(f->HubList);
			{
				t->NumFarmHub = LIST_NUM(f->HubList);
				t->FarmHubs = ZeroMalloc(sizeof(RPC_FARM_HUB) * t->NumFarmHub);

				for (i = 0;i < t->NumFarmHub;i++)
				{
					RPC_FARM_HUB *h = &t->FarmHubs[i];
					HUB_LIST *hh = LIST_DATA(f->HubList, i);

					h->DynamicHub = hh->DynamicHub;
					StrCpy(h->HubName, sizeof(h->HubName), hh->Name);
				}
			}
			UnlockList(f->HubList);

			if (t->Controller)
			{
				t->ConnectedTime = TickToTime(s->Cedar->CreatedTick);
				t->Ip = 0x0100007f;
				GetMachineName(t->Hostname, sizeof(t->Hostname));
				t->Point = f->Point;

				LockList(s->ServerListenerList);
				{
					UINT i, n;
					t->NumPort = 0;
					for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
					{
						SERVER_LISTENER *o = LIST_DATA(s->ServerListenerList, i);
						if (o->Enabled)
						{
							t->NumPort++;
						}
					}
					t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
					n = 0;
					for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
					{
						SERVER_LISTENER *o = LIST_DATA(s->ServerListenerList, i);
						if (o->Enabled)
						{
							t->Ports[n++] = o->Port;
						}
					}
				}
				UnlockList(s->ServerListenerList);

				t->ServerCert = CloneX(s->Cedar->ServerX);
				t->NumSessions = Count(s->Cedar->CurrentSessions);
				t->NumTcpConnections = Count(s->Cedar->CurrentTcpConnections);
			}
			else
			{
				t->ConnectedTime = f->ConnectedTime;
				t->Ip = f->Ip;
				StrCpy(t->Hostname, sizeof(t->Hostname), f->hostname);
				t->Point = f->Point;
				t->NumPort = f->NumPort;
				t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
				Copy(t->Ports, f->Ports, sizeof(UINT) * t->NumPort);
				t->ServerCert = CloneX(f->ServerCert);
				t->NumSessions = f->NumSessions;
				t->NumTcpConnections = f->NumTcpConnections;
			}
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(s->FarmMemberList);

	return ret;
}

// サーバーファーム設定の取得
UINT StGetFarmSetting(ADMIN *a, RPC_FARM *t)
{
	SERVER *s;
	FreeRpcFarm(t);
	Zero(t, sizeof(RPC_FARM));

	s = a->Server;
	t->ServerType = s->ServerType;
	t->ControllerOnly = s->ControllerOnly;
	t->Weight = s->Weight;

	if (t->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		t->NumPort = s->NumPublicPort;
		t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
		Copy(t->Ports, s->PublicPorts, sizeof(UINT) * t->NumPort);
		t->PublicIp = s->PublicIp;
		StrCpy(t->ControllerName, sizeof(t->ControllerName), s->ControllerName);
		t->ControllerPort = s->ControllerPort;
	}
	else
	{
		t->NumPort = 0;
		t->Ports = ZeroMalloc(0);
	}

	return ERR_NO_ERROR;
}

// サーバーファーム設定の設定
UINT StSetFarmSetting(ADMIN *a, RPC_FARM *t)
{
	bool cluster_allowed = false;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	cluster_allowed = GetServerCapsInt(a->Server, "b_support_cluster");

	if (t->ServerType != SERVER_TYPE_STANDALONE && cluster_allowed == false)
	{
		// クラスタとして動作が許可されていないのにクラスタ化しようとすると
		// エラーを発生する
		return ERR_NOT_SUPPORTED;
	}

	ALog(a, NULL, "LA_SET_FARM_SETTING");

	IncrementServerConfigRevision(a->Server);

	SiSetServerType(a->Server, t->ServerType, t->PublicIp, t->NumPort, t->Ports,
		t->ControllerName, t->ControllerPort, t->MemberPassword, t->Weight, t->ControllerOnly);

	return ERR_NO_ERROR;
}

// パスワードの設定
UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t)
{
	SERVER_ADMIN_ONLY;

	Copy(a->Server->HashedPassword, t->HashedPassword, SHA1_SIZE);

	ALog(a, NULL, "LA_SET_SERVER_PASSWORD");

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// リスナーの有効化 / 無効化
UINT StEnableListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	LockList(a->Server->ServerListenerList);
	{
		if (t->Enable)
		{
			if (SiEnableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_ENABLE_LISTENER", t->Port);
			}
		}
		else
		{
			if (SiDisableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_DISABLE_LISTENER", t->Port);
			}
		}
	}
	UnlockList(a->Server->ServerListenerList);

	IncrementServerConfigRevision(a->Server);

	SleepThread(250);

	return ret;
}

// リスナーの削除
UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	LockList(a->Server->ServerListenerList);
	{
		if (SiDeleteListener(a->Server, t->Port) == false)
		{
			ret = ERR_LISTENER_NOT_FOUND;
		}
		else
		{
			ALog(a, NULL, "LA_DELETE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	UnlockList(a->Server->ServerListenerList);

	return ret;
}

// リスナーの列挙
UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t)
{
	CEDAR *c = a->Server->Cedar;
	UINT i;

	FreeRpcListenerList(t);
	Zero(t, sizeof(RPC_LISTENER_LIST));

	LockList(a->Server->ServerListenerList);
	{
		t->NumPort = LIST_NUM(a->Server->ServerListenerList);
		t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
		t->Enables = ZeroMalloc(sizeof(bool) * t->NumPort);
		t->Errors = ZeroMalloc(sizeof(bool) * t->NumPort);

		for (i = 0;i < t->NumPort;i++)
		{
			SERVER_LISTENER *o = LIST_DATA(a->Server->ServerListenerList, i);

			t->Ports[i] = o->Port;
			t->Enables[i] = o->Enabled;
			if (t->Enables[i])
			{
				if (o->Listener->Status == LISTENER_STATUS_TRYING)
				{
					t->Errors[i] = true;
				}
			}
		}
	}
	UnlockList(a->Server->ServerListenerList);

	return ERR_NO_ERROR;
}

// リスナーの作成
UINT StCreateListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;
	CEDAR *c = a->Server->Cedar;

	if (t->Port == 0 || t->Port > 65535)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(a->Server->ServerListenerList);
	{
		if (SiAddListener(a->Server, t->Port, t->Enable) == false)
		{
			ret = ERR_LISTENER_ALREADY_EXISTS;
		}
		else
		{
			ALog(a, NULL, "LA_CREATE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	UnlockList(a->Server->ServerListenerList);

	SleepThread(250);

	return ret;
}

// サーバー状態の取得
UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t)
{
	CEDAR *c;
	UINT i;

	c = a->Server->Cedar;

	Zero(t, sizeof(RPC_SERVER_STATUS));

	Lock(c->TrafficLock);
	{
		Copy(&t->Traffic, c->Traffic, sizeof(TRAFFIC));
	}
	Unlock(c->TrafficLock);

	GetMemInfo(&t->MemInfo);

	t->ServerType = a->Server->ServerType;
	t->NumTcpConnections = t->NumTcpConnectionsLocal = t->NumTcpConnectionsRemote = 0;
	t->NumSessionsTotal = t->NumSessionsLocal = t->NumSessionsRemote = 0;

	t->NumTcpConnectionsLocal = Count(c->CurrentTcpConnections);

	if (a->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		LockList(a->Server->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(a->Server->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(a->Server->FarmMemberList, i);

				if (f->Me == false)
				{
					t->NumTcpConnectionsRemote += f->NumTcpConnections;
					t->NumSessionsRemote += f->NumSessions;
					AddTraffic(&t->Traffic, &f->Traffic);
				}
			}
		}
		UnlockList(a->Server->FarmMemberList);
	}

	t->NumMacTables = t->NumIpTables = t->NumUsers = t->NumGroups = 0;

	// HUB 数の情報
	LockList(c->HubList);
	{
		t->NumHubTotal = LIST_NUM(c->HubList);

		t->NumHubStandalone = t->NumHubDynamic = t->NumHubStatic = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			Lock(h->lock);
			{
				switch (h->Type)
				{
				case HUB_TYPE_STANDALONE:
					t->NumHubStandalone++;
					break;

				case HUB_TYPE_FARM_STATIC:
					t->NumHubStatic++;
					break;

				case HUB_TYPE_FARM_DYNAMIC:
					t->NumHubDynamic++;
					break;
				}
			}

			t->NumMacTables += LIST_NUM(h->MacTable);
			t->NumIpTables += LIST_NUM(h->IpTable);

			if (h->HubDb != NULL)
			{
				t->NumUsers += LIST_NUM(h->HubDb->UserList);
				t->NumGroups += LIST_NUM(h->HubDb->GroupList);
			}

			Unlock(h->lock);
		}
	}
	UnlockList(c->HubList);

	// セッション数の情報
	t->NumSessionsLocal = Count(c->CurrentSessions);
	t->NumSessionsTotal = t->NumSessionsLocal + t->NumSessionsRemote;
	t->NumTcpConnections = t->NumTcpConnectionsLocal + t->NumTcpConnectionsRemote;

	t->AssignedBridgeLicenses = Count(c->AssignedBridgeLicense);
	t->AssignedClientLicenses = Count(c->AssignedClientLicense);

	t->AssignedBridgeLicensesTotal = a->Server->CurrentAssignedBridgeLicense;
	t->AssignedClientLicensesTotal = a->Server->CurrentAssignedClientLicense;

	t->CurrentTick = Tick64();
	t->CurrentTime = SystemTime64();

	t->StartTime = a->Server->StartTime;

	return ERR_NO_ERROR;
}

// サーバー情報の取得
UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t)
{
	CEDAR *c;
	OS_INFO *info;
	// 引数チェック
	if (a == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	FreeRpcServerInfo(t);
	Zero(t, sizeof(RPC_SERVER_INFO));

	c = a->Server->Cedar;

	GetServerProductName(a->Server, t->ServerProductName, sizeof(t->ServerProductName));

	StrCpy(t->ServerVersionString, sizeof(t->ServerVersionString), c->VerString);
	StrCpy(t->ServerBuildInfoString, sizeof(t->ServerBuildInfoString), c->BuildInfo);
	t->ServerVerInt = c->Version;
	t->ServerBuildInt = c->Build;
	GetMachineName(t->ServerHostName, sizeof(t->ServerHostName));
	t->ServerType = c->Server->ServerType;

	info = GetOsInfo();
	if (info != NULL)
	{
		CopyOsInfo(&t->OsInfo, info);
	}

	return ERR_NO_ERROR;
}

// OS_INFO のコピー
void CopyOsInfo(OS_INFO *dst, OS_INFO *info)
{
	// 引数チェック
	if (info == NULL || dst == NULL)
	{
		return;
	}

	dst->OsType = info->OsType;
	dst->OsServicePack = info->OsServicePack;
	dst->OsSystemName = CopyStr(info->OsSystemName);
	dst->OsProductName = CopyStr(info->OsProductName);
	dst->OsVendorName = CopyStr(info->OsVendorName);
	dst->OsVersion = CopyStr(info->OsVersion);
	dst->KernelName = CopyStr(info->KernelName);
	dst->KernelVersion = CopyStr(info->KernelVersion);
}

// RPC_WINVER
void InRpcWinVer(RPC_WINVER *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_WINVER));

	t->IsWindows = PackGetBool(p, "V_IsWindows");
	t->IsNT = PackGetBool(p, "V_IsNT");
	t->IsServer = PackGetBool(p, "V_IsServer");
	t->IsBeta = PackGetBool(p, "V_IsBeta");
	t->VerMajor = PackGetInt(p, "V_VerMajor");
	t->VerMinor = PackGetInt(p, "V_VerMinor");
	t->Build = PackGetInt(p, "V_Build");
	t->ServicePack = PackGetInt(p, "V_ServicePack");
	PackGetStr(p, "V_Title", t->Title, sizeof(t->Title));
}
void OutRpcWinVer(PACK *p, RPC_WINVER *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "V_IsWindows", t->IsWindows);
	PackAddBool(p, "V_IsNT", t->IsNT);
	PackAddBool(p, "V_IsServer", t->IsServer);
	PackAddBool(p, "V_IsBeta", t->IsBeta);
	PackAddInt(p, "V_VerMajor", t->VerMajor);
	PackAddInt(p, "V_VerMinor", t->VerMinor);
	PackAddInt(p, "V_Build", t->Build);
	PackAddInt(p, "V_ServicePack", t->ServicePack);
	PackAddStr(p, "V_Title", t->Title);
}

// RPC_MSG
void InRpcMsg(RPC_MSG *t, PACK *p)
{
	UINT size;
	char *utf8;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_MSG));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	size = PackGetDataSize(p, "Msg");
	utf8 = ZeroMalloc(size + 8);
	PackGetData(p, "Msg", utf8);
	t->Msg = CopyUtfToUni(utf8);
	Free(utf8);
}
void OutRpcMsg(PACK *p, RPC_MSG *t)
{
	UINT size;
	char *utf8;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	utf8 = CopyUniToUtf(t->Msg);
	size = StrLen(utf8);
	PackAddData(p, "Msg", utf8, size);
	Free(utf8);
}
void FreeRpcMsg(RPC_MSG *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Msg);
}

// RPC_ENUM_ETH_VLAN
void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	t->NumItem = PackGetIndexCount(p, "DeviceName");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t->Items[i];

		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetStrEx(p, "Guid", e->Guid, sizeof(e->Guid), i);
		PackGetStrEx(p, "DeviceInstanceId", e->DeviceInstanceId, sizeof(e->DeviceInstanceId), i);
		PackGetStrEx(p, "DriverName", e->DriverName, sizeof(e->DriverName), i);
		PackGetStrEx(p, "DriverType", e->DriverType, sizeof(e->DriverType), i);
		e->Support = PackGetBoolEx(p, "Support", i);
		e->Enabled = PackGetBoolEx(p, "Enabled", i);
	}
}
void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t->Items[i];

		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddStrEx(p, "Guid", e->Guid, i, t->NumItem);
		PackAddStrEx(p, "DeviceInstanceId", e->DeviceInstanceId, i, t->NumItem);
		PackAddStrEx(p, "DriverName", e->DriverName, i, t->NumItem);
		PackAddStrEx(p, "DriverType", e->DriverType, i, t->NumItem);
		PackAddBoolEx(p, "Support", e->Support, i, t->NumItem);
		PackAddBoolEx(p, "Enabled", e->Enabled, i, t->NumItem);
	}
}
void FreeRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_ENUM_LOG_FILE
void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		PackGetStrEx(p, "FilePath", e->FilePath, sizeof(e->FilePath), i);
		PackGetStrEx(p, "ServerName", e->ServerName, sizeof(e->ServerName), i);
		e->FileSize = PackGetIntEx(p, "FileSize", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
	}
}
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		PackAddStrEx(p, "FilePath", e->FilePath, i, t->NumItem);
		PackAddStrEx(p, "ServerName", e->ServerName, i, t->NumItem);
		PackAddIntEx(p, "FileSize", e->FileSize, i, t->NumItem);
		PackAddInt64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumItem);
	}
}
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}
void AdjoinRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, RPC_ENUM_LOG_FILE *src)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (t == NULL || src == NULL)
	{
		return;
	}

	o = NewListFast(CmpLogFile);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);
		StrCpy(f->ServerName, sizeof(f->ServerName), e->ServerName);
		f->UpdatedTime = e->UpdatedTime;

		Add(o, f);
	}

	for (i = 0;i < src->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &src->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);
		StrCpy(f->ServerName, sizeof(f->ServerName), e->ServerName);
		f->UpdatedTime = e->UpdatedTime;

		Add(o, f);
	}

	FreeRpcEnumLogFile(t);

	Sort(o);

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));
	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		StrCpy(e->FilePath, sizeof(e->FilePath), f->Path);
		StrCpy(e->ServerName, sizeof(e->ServerName), f->ServerName);
		e->FileSize = f->FileSize;
		e->UpdatedTime = f->UpdatedTime;
	}

	FreeEnumLogFile(o);
}

// RPC_READ_LOG_FILE
void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_READ_LOG_FILE));
	PackGetStr(p, "FilePath", t->FilePath, sizeof(t->FilePath));
	PackGetStr(p, "ServerName", t->ServerName, sizeof(t->ServerName));
	t->Offset = PackGetInt(p, "Offset");

	t->Buffer = PackGetBuf(p, "Buffer");
}
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "FilePath", t->FilePath);
	PackAddStr(p, "ServerName", t->ServerName);
	PackAddInt(p, "Offset", t->Offset);

	if (t->Buffer != NULL)
	{
		PackAddBuf(p, "Buffer", t->Buffer);
	}
}
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	if (t->Buffer != NULL)
	{
		FreeBuf(t->Buffer);
	}
}

// RPC_AC_LIST
void InRpcAcList(RPC_AC_LIST *t, PACK *p)
{
	UINT i;
	LIST *o;
	UINT num;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_AC_LIST));
	o = NewAcList();

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	num = PackGetInt(p, "NumItem");

	for (i = 0;i < num;i++)
	{
		AC *ac = ZeroMalloc(sizeof(AC));

		ac->Deny = PackGetBoolEx(p, "Deny", i);
		PackGetIpEx(p, "IpAddress", &ac->IpAddress, i);
		ac->Masked = PackGetBoolEx(p, "Masked", i);

		if (ac->Masked)
		{
			PackGetIpEx(p, "SubnetMask", &ac->SubnetMask, i);
		}

		PackGetIntEx(p, "testtest", i);

		ac->Priority = PackGetIntEx(p, "Priority", i);

		AddAc(o, ac);

		Free(ac);
	}

	t->o = o;
}
void OutRpcAcList(PACK *p, RPC_AC_LIST *t)
{
	UINT i, num;
	LIST *o;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	o = t->o;
	num = LIST_NUM(o);

	PackAddInt(p, "NumItem", num);

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < num;i++)
	{
		AC *ac = LIST_DATA(o, i);

		PackAddBoolEx(p, "Deny", ac->Deny, i, num);
		PackAddIpEx(p, "IpAddress", &ac->IpAddress, i, num);
		PackAddBoolEx(p, "Masked", ac->Masked, i, num);

		PackAddIpEx(p, "SubnetMask", &ac->SubnetMask, i, num);

		PackAddIntEx(p, "Priority", ac->Priority, i, num);
	}
}
void FreeRpcAcList(RPC_AC_LIST *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeAcList(t->o);
}

// RPC_INT
void InRpcInt(RPC_INT *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_INT));
	t->IntValue = PackGetInt(p, "IntValue");
}
void OutRpcInt(PACK *p, RPC_INT *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "IntValue", t->IntValue);
}

// RPC_ENUM_CRL
void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_CRL));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumItem = PackGetInt(p, "NumItem");

	t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t->Items[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "CrlInfo", e->CrlInfo, sizeof(e->CrlInfo), i);
	}
}
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumItem);
		PackAddUniStrEx(p, "CrlInfo", e->CrlInfo, i, t->NumItem);
	}
}
void FreeRpcEnumCrl(RPC_ENUM_CRL *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_CRL
void InRpcCrl(RPC_CRL *t, PACK *p)
{
	BUF *b;
	NAME *n;
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CRL));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
	b = PackGetBuf(p, "Serial");
	t->Crl = ZeroMalloc(sizeof(CRL));
	if (b != NULL)
	{
		t->Crl->Serial = NewXSerial(b->Buf, b->Size);
		FreeBuf(b);
	}
	t->Crl->Name = ZeroMalloc(sizeof(NAME));
	n = t->Crl->Name;
	if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
	{
		n->CommonName = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Organization", tmp, sizeof(tmp)))
	{
		n->Organization = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Unit", tmp, sizeof(tmp)))
	{
		n->Unit = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Country", tmp, sizeof(tmp)))
	{
		n->Country = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "State", tmp, sizeof(tmp)))
	{
		n->State = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Local", tmp, sizeof(tmp)))
	{
		n->Local = CopyUniStr(tmp);
	}
	if (PackGetDataSize(p, "DigestMD5") == MD5_SIZE)
	{
		PackGetData(p, "DigestMD5", t->Crl->DigestMD5);
	}
	if (PackGetDataSize(p, "DigestSHA1") == SHA1_SIZE)
	{
		PackGetData(p, "DigestSHA1", t->Crl->DigestSHA1);
	}
}
void OutRpcCrl(PACK *p, RPC_CRL *t)
{
	NAME *n;
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);

	if (t->Crl == NULL)
	{
		return;
	}

	if (t->Crl->Serial != NULL)
	{
		PackAddData(p, "Serial", t->Crl->Serial->data, t->Crl->Serial->size);
	}
	n = t->Crl->Name;
	if (n->CommonName != NULL)
	{
		PackAddUniStr(p, "CommonName", n->CommonName);
	}
	if (n->Organization != NULL)
	{
		PackAddUniStr(p, "Organization", n->Organization);
	}
	if (n->Unit != NULL)
	{
		PackAddUniStr(p, "Unit", n->Unit);
	}
	if (n->Country != NULL)
	{
		PackAddUniStr(p, "Country", n->Country);
	}
	if (n->State != NULL)
	{
		PackAddUniStr(p, "State", n->State);
	}
	if (n->Local != NULL)
	{
		PackAddUniStr(p, "Local", n->Local);
	}
	if (IsZero(t->Crl->DigestMD5, MD5_SIZE) == false)
	{
		PackAddData(p, "DigestMD5", t->Crl->DigestMD5, MD5_SIZE);
	}
	if (IsZero(t->Crl->DigestSHA1, SHA1_SIZE) == false)
	{
		PackAddData(p, "DigestSHA1", t->Crl->DigestSHA1, SHA1_SIZE);
	}
}
void FreeRpcCrl(RPC_CRL *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeCrl(t->Crl);
}

// RPC_ENUM_L3TABLE
void InRpcEnumL3Table(RPC_ENUM_L3TABLE *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_L3TABLE));
	t->NumItem = PackGetInt(p, "NumItem");
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->Items = ZeroMalloc(sizeof(RPC_L3TABLE) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3TABLE *e = &t->Items[i];

		e->NetworkAddress = PackGetIp32Ex(p, "NetworkAddress", i);
		e->SubnetMask = PackGetIp32Ex(p, "SubnetMask", i);
		e->GatewayAddress = PackGetIp32Ex(p, "GatewayAddress", i);
		e->Metric = PackGetIntEx(p, "Metric", i);
	}
}
void OutRpcEnumL3Table(PACK *p, RPC_ENUM_L3TABLE *t)
{
	UINT i;
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	PackAddStr(p, "Name", t->Name);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3TABLE *e = &t->Items[i];

		PackAddIp32Ex(p, "NetworkAddress", e->NetworkAddress, i, t->NumItem);
		PackAddIp32Ex(p, "SubnetMask", e->SubnetMask, i, t->NumItem);
		PackAddIp32Ex(p, "GatewayAddress", e->GatewayAddress, i, t->NumItem);
		PackAddIntEx(p, "Metric", e->Metric, i, t->NumItem);
	}
}
void FreeRpcEnumL3Table(RPC_ENUM_L3TABLE *t)
{
	Free(t->Items);
}

// RPC_L3TABLE
void InRpcL3Table(RPC_L3TABLE *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_L3TABLE));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->NetworkAddress = PackGetIp32(p, "NetworkAddress");
	t->SubnetMask = PackGetIp32(p, "SubnetMask");
	t->GatewayAddress = PackGetIp32(p, "GatewayAddress");
	t->Metric = PackGetInt(p, "Metric");
}
void OutRpcL3Table(PACK *p, RPC_L3TABLE *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
	PackAddIp32(p, "NetworkAddress", t->NetworkAddress);
	PackAddIp32(p, "SubnetMask", t->SubnetMask);
	PackAddIp32(p, "GatewayAddress", t->GatewayAddress);
	PackAddInt(p, "Metric", t->Metric);
}

// RPC_ENUM_L3IF
void InRpcEnumL3If(RPC_ENUM_L3IF *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_L3IF));
	t->NumItem = PackGetInt(p, "NumItem");
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->Items = ZeroMalloc(sizeof(RPC_L3IF) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3IF *f = &t->Items[i];

		PackGetStrEx(p, "HubName", f->HubName, sizeof(f->HubName), i);
		f->IpAddress = PackGetIp32Ex(p, "IpAddress", i);
		f->SubnetMask = PackGetIp32Ex(p, "SubnetMask", i);
	}
}
void OutRpcEnumL3If(PACK *p, RPC_ENUM_L3IF *t)
{
	UINT i;
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	PackAddStr(p, "Name", t->Name);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3IF *f = &t->Items[i];

		PackAddStrEx(p, "HubName", f->HubName, i, t->NumItem);
		PackAddIp32Ex(p, "IpAddress", f->IpAddress, i, t->NumItem);
		PackAddIp32Ex(p, "SubnetMask", f->SubnetMask, i, t->NumItem);
	}
}
void FreeRpcEnumL3If(RPC_ENUM_L3IF *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_L3IF
void InRpcL3If(RPC_L3IF *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_L3IF));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->IpAddress = PackGetIp32(p, "IpAddress");
	t->SubnetMask = PackGetIp32(p, "SubnetMask");
}
void OutRpcL3If(PACK *p, RPC_L3IF *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "HubName", t->HubName);
	PackAddIp32(p, "IpAddress", t->IpAddress);
	PackAddIp32(p, "SubnetMask", t->SubnetMask);
}

// RPC_L3SW
void InRpcL3Sw(RPC_L3SW *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_L3SW));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcL3Sw(PACK *p, RPC_L3SW *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
}

// RPC_ENUM_L3SW
void InRpcEnumL3Sw(RPC_ENUM_L3SW *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_L3SW));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_L3SW_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *s = &t->Items[i];

		PackGetStrEx(p, "Name", s->Name, sizeof(s->Name), i);
		s->NumInterfaces = PackGetIntEx(p, "NumInterfaces", i);
		s->NumTables = PackGetIntEx(p, "NumTables", i);
		s->Active = PackGetBoolEx(p, "Active", i);
		s->Online = PackGetBoolEx(p, "Online", i);
	}
}
void OutRpcEnumL3Sw(PACK *p, RPC_ENUM_L3SW *t)
{
	UINT i;
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *s = &t->Items[i];

		PackAddStrEx(p, "Name", s->Name, i, t->NumItem);
		PackAddIntEx(p, "NumInterfaces", s->NumInterfaces, i, t->NumItem);
		PackAddIntEx(p, "NumTables", s->NumTables, i, t->NumItem);
		PackAddBoolEx(p, "Active", s->Active, i, t->NumItem);
		PackAddBoolEx(p, "Online", s->Online, i, t->NumItem);
	}
}
void FreeRpcEnumL3Sw(RPC_ENUM_L3SW *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_ENUM_ETH
void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_ETH));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];
		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetUniStrEx(p, "NetworkConnectionName", e->NetworkConnectionName, sizeof(e->NetworkConnectionName), i);
	}
}
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t)
{
	UINT i;
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];
		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddUniStrEx(p, "NetworkConnectionName", e->NetworkConnectionName, i, t->NumItem);
	}
}
void FreeRpcEnumEth(RPC_ENUM_ETH *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_LOCALBRIDGE
void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LOCALBRIDGE));
	PackGetStr(p, "DeviceName", t->DeviceName, sizeof(t->DeviceName));
	PackGetStr(p, "HubNameLB", t->HubName, sizeof(t->HubName));
	t->TapMode = PackGetBool(p, "TapMode");
}
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", t->DeviceName);
	PackAddStr(p, "HubNameLB", t->HubName);
	PackAddBool(p, "TapMode", t->TapMode);
}

// RPC_ENUM_LOCALBRIDGE
void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t->Items[i];

		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetStrEx(p, "HubNameLB", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->Active = PackGetBoolEx(p, "Active", i);
		e->TapMode = PackGetBoolEx(p, "TapMode", i);
	}
}
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t->Items[i];

		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddStrEx(p, "HubNameLB", e->HubName, i, t->NumItem);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumItem);
		PackAddBoolEx(p, "Active", e->Active, i, t->NumItem);
		PackAddBoolEx(p, "TapMode", e->TapMode, i, t->NumItem);
	}
}
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}
	Free(t->Items);
}

// MEMINFO
void InRpcMemInfo(MEMINFO *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(MEMINFO));
	t->TotalMemory = PackGetInt64(p, "TotalMemory");
	t->UsedMemory = PackGetInt64(p, "UsedMemory");
	t->FreeMemory = PackGetInt64(p, "FreeMemory");
	t->TotalPhys = PackGetInt64(p, "TotalPhys");
	t->UsedPhys = PackGetInt64(p, "UsedPhys");
	t->FreePhys = PackGetInt64(p, "FreePhys");
}
void OutRpcMemInfo(PACK *p, MEMINFO *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt64(p, "TotalMemory", t->TotalMemory);
	PackAddInt64(p, "UsedMemory", t->UsedMemory);
	PackAddInt64(p, "FreeMemory", t->FreeMemory);
	PackAddInt64(p, "TotalPhys", t->TotalPhys);
	PackAddInt64(p, "UsedPhys", t->UsedPhys);
	PackAddInt64(p, "FreePhys", t->FreePhys);
}

// OS_INFO
void InRpcOsInfo(OS_INFO *t, PACK *p)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(OS_INFO));
	t->OsType = PackGetInt(p, "OsType");
	t->OsServicePack = PackGetInt(p, "OsServicePack");
	if (PackGetStr(p, "OsSystemName", tmp, sizeof(tmp)))
	{
		t->OsSystemName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsProductName", tmp, sizeof(tmp)))
	{
		t->OsProductName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsVendorName", tmp, sizeof(tmp)))
	{
		t->OsVendorName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsVersion", tmp, sizeof(tmp)))
	{
		t->OsVersion = CopyStr(tmp);
	}
	if (PackGetStr(p, "KernelName", tmp, sizeof(tmp)))
	{
		t->KernelName = CopyStr(tmp);
	}
	if (PackGetStr(p, "KernelVersion", tmp, sizeof(tmp)))
	{
		t->KernelVersion = CopyStr(tmp);
	}
}
void OutRpcOsInfo(PACK *p, OS_INFO *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "OsType", t->OsType);
	PackAddInt(p, "OsServicePack", t->OsServicePack);
	PackAddStr(p, "OsSystemName", t->OsSystemName);
	PackAddStr(p, "OsProductName", t->OsProductName);
	PackAddStr(p, "OsVendorName", t->OsVendorName);
	PackAddStr(p, "OsVersion", t->OsVersion);
	PackAddStr(p, "KernelName", t->KernelName);
	PackAddStr(p, "KernelVersion", t->KernelVersion);
}
void FreeRpcOsInfo(OS_INFO *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->OsSystemName);
	Free(t->OsProductName);
	Free(t->OsVendorName);
	Free(t->OsVersion);
	Free(t->KernelName);
	Free(t->KernelVersion);
}

// ローカルのログファイルを読み込む
void SiReadLocalLogFile(SERVER *s, char *filepath, UINT offset, RPC_READ_LOG_FILE *t)
{
	char exe_dir[MAX_PATH], full_path[MAX_PATH];
	IO *o;
	// 引数チェック
	if (s == NULL || t == NULL || filepath == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_READ_LOG_FILE));

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(full_path, sizeof(full_path), "%s/%s", exe_dir, filepath);

	// ファイルを読み込む
	o = FileOpenEx(full_path, false, false);
	if (o != NULL)
	{
		UINT filesize = FileSize(o);

		if (offset < filesize)
		{
			UINT readsize = MIN(filesize - offset, FTP_BLOCK_SIZE);
			void *buf = ZeroMalloc(readsize);

			FileSeek(o, FILE_BEGIN, offset);
			FileRead(o, buf, readsize);

			t->Buffer = NewBuf();
			WriteBuf(t->Buffer, buf, readsize);
			Free(buf);
		}

		FileClose(o);
	}
}

// ローカルのログファイルを列挙する
void SiEnumLocalLogFileList(SERVER *s, char *hubname, RPC_ENUM_LOG_FILE *t)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	o = EnumLogFile(hubname);

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		StrCpy(e->FilePath, sizeof(e->FilePath), f->Path);
		StrCpy(e->ServerName, sizeof(e->ServerName), f->ServerName);
		e->FileSize = f->FileSize;
		e->UpdatedTime = f->UpdatedTime;
	}

	FreeEnumLogFile(o);
}

// ローカルのセッションを列挙する
void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t)
{
	HUB *h;
	// 引数チェック
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	LockHubList(s->Cedar);
	h = GetHub(s->Cedar, hubname);
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		t->NumSession = 0;
		t->Sessions = ZeroMalloc(0);
		return;
	}

	LockList(h->SessionList);
	{
		UINT i;
		t->NumSession = LIST_NUM(h->SessionList);
		t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

		for (i = 0;i < t->NumSession;i++)
		{
			SESSION *s = LIST_DATA(h->SessionList, i);
			RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];
			Lock(s->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), s->Name);
				StrCpy(e->Username, sizeof(e->Username), s->Username);
				e->Ip = IPToUINT(&s->Connection->ClientIp);
				StrCpy(e->Hostname, sizeof(e->Hostname), s->Connection->ClientHostname);
				e->MaxNumTcp = s->MaxConnection;
				e->LinkMode = s->LinkModeServer;
				e->SecureNATMode = s->SecureNATMode;
				e->BridgeMode = s->BridgeMode;
				e->Layer3Mode = s->L3SwitchMode;
				e->VLanId = s->VLanId;
				LockList(s->Connection->Tcp->TcpSockList);
				{
					e->CurrentNumTcp = s->Connection->Tcp->TcpSockList->num_item;
				}
				UnlockList(s->Connection->Tcp->TcpSockList);
				Lock(s->TrafficLock);
				{
					e->PacketSize = GetTrafficPacketSize(s->Traffic);
					e->PacketNum = GetTrafficPacketNum(s->Traffic);
				}
				Unlock(s->TrafficLock);
				e->Client_BridgeMode = s->IsBridgeMode;
				e->Client_MonitorMode = s->IsMonitorMode;
				Copy(e->UniqueId, s->NodeInfo.UniqueId, 16);
			}
			Unlock(s->lock);
			GetMachineName(e->RemoteHostname, sizeof(e->RemoteHostname));
		}
	}
	UnlockList(h->SessionList);

	ReleaseHub(h);
}

// RPC_ENUM_LICENSE_KEY
void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LICENSE_KEY));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LICENSE_KEY_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t->Items[i];

		e->Id = PackGetIntEx(p, "Id", i);
		PackGetStrEx(p, "LicenseKey", e->LicenseKey, sizeof(e->LicenseKey), i);
		PackGetStrEx(p, "LicenseId", e->LicenseId, sizeof(e->LicenseId), i);
		PackGetStrEx(p, "LicenseName", e->LicenseName, sizeof(e->LicenseName), i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
		e->Status = PackGetIntEx(p, "Status", i);
		e->ProductId = PackGetIntEx(p, "ProductId", i);
		e->SystemId = PackGetInt64Ex(p, "SystemId", i);
		e->SerialId = PackGetIntEx(p, "SerialId", i);
	}
}
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumItem);
		PackAddStrEx(p, "LicenseKey", e->LicenseKey, i, t->NumItem);
		PackAddStrEx(p, "LicenseId", e->LicenseId, i, t->NumItem);
		PackAddStrEx(p, "LicenseName", e->LicenseName, i, t->NumItem);
		PackAddInt64Ex(p, "Expires", e->Expires, i, t->NumItem);
		PackAddIntEx(p, "Status", e->Status, i, t->NumItem);
		PackAddIntEx(p, "ProductId", e->ProductId, i, t->NumItem);
		PackAddInt64Ex(p, "SystemId", e->SystemId, i, t->NumItem);
		PackAddIntEx(p, "SerialId", e->SerialId, i, t->NumItem);
	}
}
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_LICENSE_STATUS
void InRpcLicenseStatus(RPC_LICENSE_STATUS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LICENSE_STATUS));

	t->EditionId = PackGetInt(p, "EditionId");
	PackGetStr(p, "EditionStr", t->EditionStr, sizeof(t->EditionStr) );
	t->SystemId = PackGetInt64(p, "SystemId");
	t->SystemExpires = PackGetInt64(p, "SystemExpires");
	t->NumClientConnectLicense = PackGetInt(p, "NumClientConnectLicense");
	t->NumBridgeConnectLicense = PackGetInt(p, "NumBridgeConnectLicense");

	// v3.0
	t->NeedSubscription = PackGetBool(p, "NeedSubscription");
	t->AllowEnterpriseFunction = PackGetBool(p, "AllowEnterpriseFunction");
	t->SubscriptionExpires = PackGetInt64(p, "SubscriptionExpires");
	t->IsSubscriptionExpired = PackGetBool(p, "IsSubscriptionExpired");
	t->NumUserCreationLicense = PackGetInt(p, "NumUserCreationLicense");
	t->ReleaseDate = PackGetInt64(p, "ReleaseDate");
}
void OutRpcLicenseStatus(PACK *p, RPC_LICENSE_STATUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "EditionId", t->EditionId);
	PackAddStr(p, "EditionStr", t->EditionStr);
	PackAddInt64(p, "SystemId", t->SystemId);
	PackAddInt64(p, "SystemExpires", t->SystemExpires);
	PackAddInt(p, "NumClientConnectLicense", t->NumClientConnectLicense);
	PackAddInt(p, "NumBridgeConnectLicense", t->NumBridgeConnectLicense);

	// v3.0
	PackAddBool(p, "NeedSubscription", t->NeedSubscription);
	PackAddBool(p, "AllowEnterpriseFunction", t->AllowEnterpriseFunction);
	PackAddInt64(p, "SubscriptionExpires", t->SubscriptionExpires);
	PackAddBool(p, "IsSubscriptionExpired", t->IsSubscriptionExpired);
	PackAddInt(p, "NumUserCreationLicense", t->NumUserCreationLicense);
	PackAddInt64(p, "ReleaseDate", t->ReleaseDate);
}

// RPC_ADMIN_OPTION
void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADMIN_OPTION));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *o = &t->Items[i];

		PackGetStrEx(p, "Name", o->Name, sizeof(o->Name), i);
		o->Value = PackGetIntEx(p, "Value", i);
	}
}
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *o = &t->Items[i];

		PackAddStrEx(p, "Name", o->Name, i, t->NumItem);
		PackAddIntEx(p, "Value", o->Value, i, t->NumItem);
	}
}
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_CONFIG
void InRpcConfig(RPC_CONFIG *t, PACK *p)
{
	UINT size;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CONFIG));
	PackGetStr(p, "FileName", t->FileName, sizeof(t->FileName));
	size = PackGetDataSize(p, "FileData");
	t->FileData = ZeroMalloc(size + 1);
	PackGetData(p, "FileData", t->FileData);
}
void OutRpcConfig(PACK *p, RPC_CONFIG *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "FileName", t->FileName);
	PackAddData(p, "FileData", t->FileData, StrLen(t->FileData));
}
void FreeRpcConfig(RPC_CONFIG *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->FileData);
}

// RPC_BRIDGE_SUPPORT
void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = PackGetBool(p, "IsBridgeSupportedOs");
	t->IsWinPcapNeeded = PackGetBool(p, "IsWinPcapNeeded");
}
void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddBool(p, "IsBridgeSupportedOs", t->IsBridgeSupportedOs);
	PackAddBool(p, "IsWinPcapNeeded",t->IsWinPcapNeeded);
}

// RPC_ADD_ACCESS
void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADD_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	InRpcAccess(&t->Access, p);
}
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	OutRpcAccess(p, &t->Access);
}

// RPC_DELETE_ACCESS
void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Id = PackGetInt(p, "Id");
}
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Id", t->Id);
}


// RPC_SERVER_INFO
void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SERVER_INFO));

	PackGetStr(p, "ServerProductName", t->ServerProductName, sizeof(t->ServerProductName));
	PackGetStr(p, "ServerVersionString", t->ServerVersionString, sizeof(t->ServerVersionString));
	PackGetStr(p, "ServerBuildInfoString", t->ServerBuildInfoString, sizeof(t->ServerBuildInfoString));
	t->ServerVerInt = PackGetInt(p, "ServerVerInt");
	t->ServerBuildInt = PackGetInt(p, "ServerBuildInt");
	PackGetStr(p, "ServerHostName", t->ServerHostName, sizeof(t->ServerHostName));
	t->ServerType = PackGetInt(p, "ServerType");
	InRpcOsInfo(&t->OsInfo, p);
}
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ServerProductName", t->ServerProductName);
	PackAddStr(p, "ServerVersionString", t->ServerVersionString);
	PackAddStr(p, "ServerBuildInfoString", t->ServerBuildInfoString);
	PackAddInt(p, "ServerVerInt", t->ServerVerInt);
	PackAddInt(p, "ServerBuildInt", t->ServerBuildInt);
	PackAddStr(p, "ServerHostName", t->ServerHostName);
	PackAddInt(p, "ServerType", t->ServerType);
	OutRpcOsInfo(p, &t->OsInfo);
}
void FreeRpcServerInfo(RPC_SERVER_INFO *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeRpcOsInfo(&t->OsInfo);
}

// RPC_SERVER_STATUS
void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SERVER_STATUS));
	t->ServerType = PackGetInt(p, "ServerType");
	t->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	t->NumTcpConnectionsLocal = PackGetInt(p, "NumTcpConnectionsLocal");
	t->NumTcpConnectionsRemote = PackGetInt(p, "NumTcpConnectionsRemote");
	t->NumHubTotal = PackGetInt(p, "NumHubTotal");
	t->NumHubStandalone = PackGetInt(p, "NumHubStandalone");
	t->NumHubStatic = PackGetInt(p, "NumHubStatic");
	t->NumHubDynamic = PackGetInt(p, "NumHubDynamic");
	t->NumSessionsTotal = PackGetInt(p, "NumSessionsTotal");
	t->NumSessionsLocal = PackGetInt(p, "NumSessionsLocal");
	t->NumSessionsRemote = PackGetInt(p, "NumSessionsRemote");
	t->NumMacTables = PackGetInt(p, "NumMacTables");
	t->NumIpTables = PackGetInt(p, "NumIpTables");
	t->NumUsers = PackGetInt(p, "NumUsers");
	t->NumGroups = PackGetInt(p, "NumGroups");
	t->CurrentTime = PackGetInt64(p, "CurrentTime");
	t->CurrentTick = PackGetInt64(p, "CurrentTick");
	t->AssignedBridgeLicenses = PackGetInt(p, "AssignedBridgeLicenses");
	t->AssignedClientLicenses = PackGetInt(p, "AssignedClientLicenses");
	t->AssignedBridgeLicensesTotal = PackGetInt(p, "AssignedBridgeLicensesTotal");
	t->AssignedClientLicensesTotal = PackGetInt(p, "AssignedClientLicensesTotal");
	t->StartTime = PackGetInt64(p, "StartTime");

	InRpcTraffic(&t->Traffic, p);

	InRpcMemInfo(&t->MemInfo, p);
}
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "ServerType", t->ServerType);
	PackAddInt(p, "NumTcpConnections", t->NumTcpConnections);
	PackAddInt(p, "NumHubTotal", t->NumHubTotal);
	PackAddInt(p, "NumHubStandalone", t->NumHubStandalone);
	PackAddInt(p, "NumHubStatic", t->NumHubStatic);
	PackAddInt(p, "NumHubDynamic", t->NumHubDynamic);
	PackAddInt(p, "NumSessionsTotal", t->NumSessionsTotal);
	PackAddInt(p, "NumSessionsLocal", t->NumSessionsLocal);
	PackAddInt(p, "NumSessionsRemote", t->NumSessionsRemote);
	PackAddInt(p, "NumTcpConnections", t->NumTcpConnections);
	PackAddInt(p, "NumTcpConnectionsLocal", t->NumTcpConnectionsLocal);
	PackAddInt(p, "NumTcpConnectionsRemote", t->NumTcpConnectionsRemote);
	PackAddInt(p, "NumMacTables", t->NumMacTables);
	PackAddInt(p, "NumIpTables", t->NumIpTables);
	PackAddInt(p, "NumUsers", t->NumUsers);
	PackAddInt(p, "NumGroups", t->NumGroups);
	PackAddInt64(p, "CurrentTime", t->CurrentTime);
	PackAddInt64(p, "CurrentTick", t->CurrentTick);
	PackAddInt(p, "AssignedBridgeLicenses", t->AssignedBridgeLicenses);
	PackAddInt(p, "AssignedClientLicenses", t->AssignedClientLicenses);
	PackAddInt(p, "AssignedBridgeLicensesTotal", t->AssignedBridgeLicensesTotal);
	PackAddInt(p, "AssignedClientLicensesTotal", t->AssignedClientLicensesTotal);
	PackAddInt64(p, "StartTime", t->StartTime);

	OutRpcTraffic(p, &t->Traffic);

	OutRpcMemInfo(p, &t->MemInfo);
}

// RPC_LISTENER
void InRpcListener(RPC_LISTENER *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LISTENER));
	t->Port = PackGetInt(p, "Port");
	t->Enable = PackGetBool(p, "Enable");
}
void OutRpcListener(PACK *p, RPC_LISTENER *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Port", t->Port);
	PackAddBool(p, "Enable", t->Enable);
}

// RPC_LISTENER_LIST
void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LISTENER_LIST));
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Enables = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Errors = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
		t->Enables[i] = PackGetBoolEx(p, "Enables", i);
		t->Errors[i] = PackGetBoolEx(p, "Errors", i);
	}
}
void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumPort;i++)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
		PackAddBoolEx(p, "Enables", t->Enables[i], i, t->NumPort);
		PackAddBoolEx(p, "Errors", t->Errors[i], i, t->NumPort);
	}
}
void FreeRpcListenerList(RPC_LISTENER_LIST *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
	Free(t->Enables);
	Free(t->Errors);
}

// RPC_STR
void InRpcStr(RPC_STR *t, PACK *p)
{
	UINT size = 65536;
	char *tmp = Malloc(size);
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_STR));
	if (PackGetStr(p, "String", tmp, size) == false)
	{
		t->String = CopyStr("");
	}
	else
	{
		t->String = CopyStr(tmp);
	}
	Free(tmp);
}
void OutRpcStr(PACK *p, RPC_STR *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "String", t->String);
}
void FreeRpcStr(RPC_STR *t)
{
	// 引数チェック
	if (t == NULL )
	{
		return;
	}

	Free(t->String);
}

// RPC_SET_PASSWORD
void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_PASSWORD));
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
}
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
}

// RPC_FARM
void InRpcFarm(RPC_FARM *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_FARM));
	t->ServerType = PackGetInt(p, "ServerType");
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
	}
	t->PublicIp = PackGetIp32(p, "PublicIp");
	PackGetStr(p, "ControllerName", t->ControllerName, sizeof(t->ControllerName));
	t->ControllerPort = PackGetInt(p, "ControllerPort");
	PackGetData2(p, "MemberPassword", t->MemberPassword, sizeof(t->MemberPassword));
	t->Weight = PackGetInt(p, "Weight");
	t->ControllerOnly = PackGetBool(p, "ControllerOnly");
}
void OutRpcFarm(PACK *p, RPC_FARM *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "ServerType", t->ServerType);
	for (i = 0;i < t->NumPort;i++)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
	}
	PackAddIp32(p, "PublicIp", t->PublicIp);
	PackAddStr(p, "ControllerName", t->ControllerName);
	PackAddInt(p, "ControllerPort", t->ControllerPort);
	PackAddData(p, "MemberPassword", t->MemberPassword, sizeof(t->MemberPassword));
	PackAddInt(p, "Weight", t->Weight);
	PackAddBool(p, "ControllerOnly", t->ControllerOnly);
}
void FreeRpcFarm(RPC_FARM *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
}

// RPC_FARM_HUB
void InRpcFarmHub(RPC_FARM_HUB *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_FARM_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->DynamicHub = PackGetBool(p, "DynamicHub");
}
void OutRpcFarmHub(PACK *p, RPC_FARM_HUB *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "DynamicHub", t->DynamicHub);
}

// RPC_FARM_INFO
void InRpcFarmInfo(RPC_FARM_INFO *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_FARM_INFO));
	t->Id = PackGetInt(p, "Id");
	t->Controller = PackGetBool(p, "Controller");
	t->ConnectedTime = PackGetInt64(p, "ConnectedTime");
	t->Ip = PackGetIp32(p, "Ip");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
	t->Point = PackGetInt(p, "Point");
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
	}
	t->ServerCert = PackGetX(p, "ServerCert");
	t->NumFarmHub = PackGetIndexCount(p, "HubName");
	t->FarmHubs = ZeroMalloc(sizeof(RPC_FARM_HUB) * t->NumFarmHub);
	for (i = 0;i < t->NumFarmHub;i++)
	{
		PackGetStrEx(p, "HubName", t->FarmHubs[i].HubName, sizeof(t->FarmHubs[i].HubName), i);
		t->FarmHubs[i].DynamicHub = PackGetBoolEx(p, "DynamicHub", i);
	}
	t->NumSessions = PackGetInt(p, "NumSessions");
	t->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	t->Weight = PackGetInt(p, "Weight");
}
void OutRpcFarmInfo(PACK *p, RPC_FARM_INFO *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Id", t->Id);
	PackAddBool(p, "Controller", t->Controller);
	PackAddInt64(p, "ConnectedTime", t->ConnectedTime);
	PackAddIp32(p, "Ip", t->Ip);
	PackAddStr(p, "Hostname", t->Hostname);
	PackAddInt(p, "Point", t->Point);
	for (i = 0;i < t->NumPort;i++)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
	}
	PackAddX(p, "ServerCert", t->ServerCert);
	for (i = 0;i < t->NumFarmHub;i++)
	{
		PackAddStrEx(p, "HubName", t->FarmHubs[i].HubName, i, t->NumFarmHub);
		PackAddBoolEx(p, "DynamicHub", t->FarmHubs[i].DynamicHub, i, t->NumFarmHub);
	}
	PackAddInt(p, "NumSessions", t->NumSessions);
	PackAddInt(p, "NumTcpConnections", t->NumTcpConnections);
	PackAddInt(p, "Weight", t->Weight);
}
void FreeRpcFarmInfo(RPC_FARM_INFO *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
	Free(t->FarmHubs);
	FreeX(t->ServerCert);
}

void InRpcEnumFarm(RPC_ENUM_FARM *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_FARM));
	t->NumFarm = PackGetIndexCount(p, "Id");
	t->Farms = ZeroMalloc(sizeof(RPC_ENUM_FARM_ITEM) * t->NumFarm);

	for (i = 0;i < t->NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t->Farms[i];

		e->Id = PackGetIntEx(p, "Id", i);
		e->Controller = PackGetBoolEx(p, "Controller", i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Ip = PackGetIp32Ex(p, "Ip", i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->Point = PackGetIntEx(p, "Point", i);
		e->NumSessions = PackGetIntEx(p, "NumSessions", i);
		e->NumTcpConnections = PackGetIntEx(p, "NumTcpConnections", i);
		e->NumHubs = PackGetIntEx(p, "NumHubs", i);
		e->AssignedClientLicense = PackGetIntEx(p, "AssignedClientLicense", i);
		e->AssignedBridgeLicense = PackGetIntEx(p, "AssignedBridgeLicense", i);
	}
}
void OutRpcEnumFarm(PACK *p, RPC_ENUM_FARM *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t->Farms[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumFarm);
		PackAddBoolEx(p, "Controller", e->Controller, i, t->NumFarm);
		PackAddInt64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumFarm);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumFarm);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumFarm);
		PackAddIntEx(p, "Point", e->Point, i, t->NumFarm);
		PackAddIntEx(p, "NumSessions", e->NumSessions, i, t->NumFarm);
		PackAddIntEx(p, "NumTcpConnections", e->NumTcpConnections, i, t->NumFarm);
		PackAddIntEx(p, "NumHubs", e->NumHubs, i, t->NumFarm);
		PackAddIntEx(p, "AssignedClientLicense", e->AssignedClientLicense, i, t->NumFarm);
		PackAddIntEx(p, "AssignedBridgeLicense", e->AssignedBridgeLicense, i, t->NumFarm);
	}
}
void FreeRpcEnumFarm(RPC_ENUM_FARM *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Farms);
}

// RPC_FARM_CONNECTION_STATUS
void InRpcFarmConnectionStatus(RPC_FARM_CONNECTION_STATUS *t, PACK *p)
{
	Zero(t, sizeof(RPC_FARM_CONNECTION_STATUS));
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	t->Ip = PackGetIp32(p, "Ip");
	t->Port = PackGetInt(p, "Port");
	t->Online = PackGetBool(p, "Online");
	t->LastError = PackGetInt(p, "LastError");
	t->StartedTime = PackGetInt64(p, "StartedTime");
	t->CurrentConnectedTime = PackGetInt64(p, "CurrentConnectedTime");
	t->FirstConnectedTime = PackGetInt64(p, "FirstConnectedTime");
	t->NumConnected = PackGetInt(p, "NumConnected");
	t->NumTry = PackGetInt(p, "NumTry");
	t->NumFailed = PackGetInt(p, "NumFailed");
}
void OutRpcFarmConnectionStatus(PACK *p, RPC_FARM_CONNECTION_STATUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddIp32(p, "Ip", t->Ip);
	PackAddInt(p, "Port", t->Port);
	PackAddBool(p, "Online", t->Online);
	PackAddInt(p, "LastError", t->LastError);
	PackAddInt64(p, "StartedTime", t->StartedTime);
	PackAddInt64(p, "CurrentConnectedTime", t->CurrentConnectedTime);
	PackAddInt64(p, "FirstConnectedTime", t->FirstConnectedTime);
	PackAddInt(p, "NumConnected", t->NumConnected);
	PackAddInt(p, "NumTry", t->NumTry);
	PackAddInt(p, "NumFailed", t->NumFailed);
}

// RPC_HUB_OPTION
void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_OPTION));
	t->MaxSession = PackGetInt(p, "MaxSession");
	t->NoEnum = PackGetBool(p, "NoEnum");
}
void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "MaxSession", t->MaxSession);
	PackAddBool(p, "NoEnum", t->NoEnum);
}

// RPC_RADIUS
void InRpcRadius(RPC_RADIUS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_RADIUS));
	PackGetStr(p, "RadiusServerName", t->RadiusServerName, sizeof(t->RadiusServerName));
	t->RadiusPort = PackGetInt(p, "RadiusPort");
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "RadiusSecret", t->RadiusSecret, sizeof(t->RadiusSecret));
	t->RadiusRetryInterval = PackGetInt(p, "RadiusRetryInterval");
}
void OutRpcRadius(PACK *p, RPC_RADIUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "RadiusServerName", t->RadiusServerName);
	PackAddInt(p, "RadiusPort", t->RadiusPort);
	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "RadiusSecret", t->RadiusSecret);
	PackAddInt(p, "RadiusRetryInterval", t->RadiusRetryInterval);
}

// RPC_HUB
void InRpcHub(RPC_HUB *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
void OutRpcHub(PACK *p, RPC_HUB *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
}

// RPC_CREATE_HUB
void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CREATE_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackGetData2(p, "SecurePassword", t->SecurePassword, sizeof(t->SecurePassword));
	t->Online = PackGetBool(p, "Online");
	InRpcHubOption(&t->HubOption, p);
	t->HubType = PackGetInt(p, "HubType");
}
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackAddData(p, "SecurePassword", t->SecurePassword, sizeof(t->SecurePassword));
	PackAddBool(p, "Online", t->Online);
	OutRpcHubOption(p, &t->HubOption);
	PackAddInt(p, "HubType", t->HubType);
}

// RPC_ENUM_HUB
void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_HUB));
	t->NumHub = PackGetIndexCount(p, "HubName");
	t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * t->NumHub);

	for (i = 0;i < t->NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t->Hubs[i];

		PackGetStrEx(p, "HubName", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->HubType = PackGetIntEx(p, "HubType", i);
		e->NumSessions = PackGetIntEx(p, "NumSessions", i);
		e->NumUsers = PackGetIntEx(p, "NumUsers", i);
		e->NumGroups = PackGetIntEx(p, "NumGroups", i);
		e->NumMacTables = PackGetIntEx(p, "NumMacTables", i);
		e->NumIpTables = PackGetIntEx(p, "NumIpTables", i);
		e->LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->LastLoginTime = PackGetInt64Ex(p, "LastLoginTime", i);
		e->NumLogin = PackGetIntEx(p, "NumLogin", i);
	}
}
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t->Hubs[i];

		PackAddStrEx(p, "HubName", e->HubName, i, t->NumHub);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumHub);
		PackAddIntEx(p, "HubType", e->HubType, i, t->NumHub);
		PackAddIntEx(p, "NumSessions", e->NumSessions, i, t->NumHub);
		PackAddIntEx(p, "NumUsers", e->NumUsers, i, t->NumHub);
		PackAddIntEx(p, "NumGroups", e->NumGroups, i, t->NumHub);
		PackAddIntEx(p, "NumMacTables", e->NumMacTables, i, t->NumHub);
		PackAddIntEx(p, "NumIpTables", e->NumIpTables, i, t->NumHub);
		PackAddInt64Ex(p, "LastCommTime", e->LastCommTime, i, t->NumHub);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumHub);
		PackAddInt64Ex(p, "LastLoginTime", e->LastLoginTime, i, t->NumHub);
		PackAddIntEx(p, "NumLogin", e->NumLogin, i, t->NumHub);
	}
}
void FreeRpcEnumHub(RPC_ENUM_HUB *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Hubs);
}

// RPC_DELETE_HUB
void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
}

// RPC_ENUM_CONNECTION
void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_CONNECTION));
	t->NumConnection = PackGetIndexCount(p, "Name");
	t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);

	for (i = 0;i < t->NumConnection;i++)
	{
		RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];

		e->Ip = PackGetIp32Ex(p, "Ip", i);
		e->Port = PackGetIntEx(p, "Port", i);
		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Type = PackGetIntEx(p, "Type", i);
	}
}
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumConnection;i++)
	{
		RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];

		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumConnection);
		PackAddIntEx(p, "Port", e->Port, i, t->NumConnection);
		PackAddStrEx(p, "Name", e->Name, i, t->NumConnection);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumConnection);
		PackAddInt64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumConnection);
		PackAddIntEx(p, "Type", e->Type, i, t->NumConnection);
	}
}
void FreeRpcEnumConnetion(RPC_ENUM_CONNECTION *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Connections);
}

// RPC_DISCONNECT_CONNECTION
void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DISCONNECT_CONNECTION));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
}

// RPC_CONNECTION_INFO
void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->Ip = PackGetIp32(p, "Ip");
	t->Port = PackGetInt(p, "Port");
	t->ConnectedTime = PackGetInt64(p, "ConnectedTime");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
	PackGetStr(p, "ServerStr", t->ServerStr, sizeof(t->ServerStr));
	PackGetStr(p, "ClientStr", t->ClientStr, sizeof(t->ClientStr));
	t->ServerVer = PackGetInt(p, "ServerVer");
	t->ServerBuild = PackGetInt(p, "ServerBuild");
	t->ClientVer = PackGetInt(p, "ClientVer");
	t->ClientBuild = PackGetInt(p, "ClientBuild");
	t->Type = PackGetInt(p, "Type");
}
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
	PackAddIp32(p, "Ip", t->Ip);
	PackAddInt(p, "Port", t->Port);
	PackAddInt64(p, "ConnectedTime", t->ConnectedTime);
	PackAddStr(p, "Hostname", t->Hostname);
	PackAddStr(p, "ServerStr", t->ServerStr);
	PackAddStr(p, "ClientStr", t->ClientStr);
	PackAddInt(p, "ServerVer", t->ServerVer);
	PackAddInt(p, "ServerBuild", t->ServerBuild);
	PackAddInt(p, "ClientVer", t->ClientVer);
	PackAddInt(p, "ClientBuild", t->ClientBuild);
	PackAddInt(p, "Type", t->Type);
}

// RPC_SET_HUB_ONLINE
void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_HUB_ONLINE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
}
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "Online", t->Online);
}

// RPC_HUB_STATUS
void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p)
{
	Zero(t, sizeof(RPC_HUB_STATUS));
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
	t->HubType = PackGetInt(p, "HubType");
	t->NumSessions = PackGetInt(p, "NumSessions");
	t->NumSessionsClient = PackGetInt(p, "NumSessionsClient");
	t->NumSessionsBridge = PackGetInt(p, "NumSessionsBridge");
	t->NumAccessLists = PackGetInt(p, "NumAccessLists");
	t->NumUsers = PackGetInt(p, "NumUsers");
	t->NumGroups = PackGetInt(p, "NumGroups");
	t->NumMacTables = PackGetInt(p, "NumMacTables");
	t->NumIpTables = PackGetInt(p, "NumIpTables");
	t->SecureNATEnabled = PackGetBool(p, "SecureNATEnabled");
	InRpcTraffic(&t->Traffic, p);
	t->LastCommTime = PackGetInt64(p, "LastCommTime");
	t->CreatedTime = PackGetInt64(p, "CreatedTime");
	t->LastLoginTime = PackGetInt64(p, "LastLoginTime");
	t->NumLogin = PackGetInt(p, "NumLogin");
}
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "Online", t->Online);
	PackAddInt(p, "HubType", t->HubType);
	PackAddInt(p, "NumSessions", t->NumSessions);
	PackAddInt(p, "NumSessionsClient", t->NumSessionsClient);
	PackAddInt(p, "NumSessionsBridge", t->NumSessionsBridge);
	PackAddInt(p, "NumAccessLists", t->NumAccessLists);
	PackAddInt(p, "NumUsers", t->NumUsers);
	PackAddInt(p, "NumGroups", t->NumGroups);
	PackAddInt(p, "NumMacTables", t->NumMacTables);
	PackAddInt(p, "NumIpTables", t->NumIpTables);
	PackAddBool(p, "SecureNATEnabled", t->SecureNATEnabled);
	OutRpcTraffic(p, &t->Traffic);
	PackAddInt64(p, "LastCommTime", t->LastCommTime);
	PackAddInt64(p, "CreatedTime", t->CreatedTime);
	PackAddInt64(p, "LastLoginTime", t->LastLoginTime);
	PackAddInt(p, "NumLogin", t->NumLogin);
}

// RPC_HUB_LOG
void InRpcHubLog(RPC_HUB_LOG *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_LOG));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->LogSetting.SaveSecurityLog = PackGetBool(p, "SaveSecurityLog");
	t->LogSetting.SecurityLogSwitchType = PackGetInt(p, "SecurityLogSwitchType");
	t->LogSetting.SavePacketLog = PackGetBool(p, "SavePacketLog");
	t->LogSetting.PacketLogSwitchType = PackGetInt(p, "PacketLogSwitchType");
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		t->LogSetting.PacketLogConfig[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
}
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "SaveSecurityLog", t->LogSetting.SaveSecurityLog);
	PackAddInt(p, "SecurityLogSwitchType", t->LogSetting.SecurityLogSwitchType);
	PackAddBool(p, "SavePacketLog", t->LogSetting.SavePacketLog);
	PackAddInt(p, "PacketLogSwitchType", t->LogSetting.PacketLogSwitchType);
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		PackAddIntEx(p, "PacketLogConfig", t->LogSetting.PacketLogConfig[i], i, NUM_PACKET_LOG);
	}
}

// RPC_HUB_ADD_CA
void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_ADD_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Cert = PackGetX(p, "Cert");
}
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddX(p, "Cert", t->Cert);
}
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeX(t->Cert);
}

// RPC_HUB_ENUM_CA
void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_ENUM_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumCa = PackGetIndexCount(p, "Key");
	t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);

	for (i = 0;i < t->NumCa;i++)
	{
		RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "SubjectName", e->SubjectName, sizeof(e->SubjectName), i);
		PackGetUniStrEx(p, "IssuerName", e->IssuerName, sizeof(e->IssuerName), i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
	}
}
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t)
{
	UINT i;
	PackAddStr(p, "HubName", t->HubName);
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumCa;i++)
	{
		RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumCa);
		PackAddUniStrEx(p, "SubjectName", e->SubjectName, i, t->NumCa);
		PackAddUniStrEx(p, "IssuerName", e->IssuerName, i, t->NumCa);
		PackAddInt64Ex(p, "Expires", e->Expires, i, t->NumCa);
	}
}
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Ca);
}

// RPC_HUB_GET_CA
void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_GET_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
	t->Cert = PackGetX(p, "Cert");
}
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
	PackAddX(p, "Cert", t->Cert);
}
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeX(t->Cert);
}

// RPC_HUB_DELETE_CA
void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_DELETE_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

// RPC_CREATE_LINK
void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CREATE_LINK));
	PackGetStr(p, "HubName_Ex", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
	t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	InRpcClientOption(t->ClientOption, p);
	t->ClientAuth  = ZeroMalloc(sizeof(CLIENT_AUTH));
	InRpcClientAuth(t->ClientAuth, p);
	InRpcPolicy(&t->Policy, p);

	t->CheckServerCert = PackGetBool(p, "CheckServerCert");
	b = PackGetBuf(p, "ServerCert");
	if (b != NULL)
	{
		t->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}
}
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName_Ex",t->HubName);
	PackAddBool(p, "Online", t->Online);
	OutRpcClientOption(p, t->ClientOption);
	OutRpcClientAuth(p, t->ClientAuth);
	OutRpcPolicy(p, &t->Policy);

	PackAddBool(p, "CheckServerCert", t->CheckServerCert);
	if (t->ServerCert != NULL)
	{
		BUF *b;
		b = XToBuf(t->ServerCert, false);
		PackAddBuf(p, "ServerCert", b);
		FreeBuf(b);
	}
}
void FreeRpcCreateLink(RPC_CREATE_LINK *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	if (t->ServerCert != NULL)
	{
		FreeX(t->ServerCert);
	}
	Free(t->ClientOption);
	CiFreeClientAuth(t->ClientAuth);
}

// RPC_ENUM_LINK
void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumLink = PackGetIndexCount(p, "AccountName");
	t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);

	for (i = 0;i < t->NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t->Links[i];

		PackGetUniStrEx(p, "AccountName", e->AccountName, sizeof(e->AccountName), i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		PackGetStrEx(p, "ConnectedHubName", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Connected = PackGetBoolEx(p, "Connected", i);
		e->LastError = PackGetIntEx(p, "LastError", i);
	}
}
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t->Links[i];

		PackAddUniStrEx(p, "AccountName", e->AccountName, i, t->NumLink);
		PackAddStrEx(p, "ConnectedHubName", e->HubName, i, t->NumLink);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumLink);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumLink);
		PackAddInt64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumLink);
		PackAddBoolEx(p, "Connected", e->Connected, i, t->NumLink);
		PackAddIntEx(p, "LastError", e->LastError, i, t->NumLink);
	}
}
void FreeRpcEnumLink(RPC_ENUM_LINK *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Links);
}

// RPC_LINK_STATUS
void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LINK_STATUS));
	PackGetStr(p, "HubName_Ex", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "AccountName", t->AccountName, sizeof(t->AccountName));
	InRpcClientGetConnectionStatus(&t->Status, p);
}
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName_Ex", t->HubName);
	PackAddUniStr(p, "AccountName", t->AccountName);
	OutRpcClientGetConnectionStatus(p, &t->Status);
}
void FreeRpcLinkStatus(RPC_LINK_STATUS *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	CiFreeClientGetConnectionStatus(&t->Status);
}

// RPC_LINK
void InRpcLink(RPC_LINK *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "AccountName", t->AccountName, sizeof(t->AccountName));
}
void OutRpcLink(PACK *p, RPC_LINK *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "AccountName", t->AccountName);
}

// RPC_RENAME_LINK
void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_RENAME_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "OldAccountName", t->OldAccountName, sizeof(t->OldAccountName));
	PackGetUniStr(p, "NewAccountName", t->NewAccountName, sizeof(t->NewAccountName));
}
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "OldAccountName", t->OldAccountName);
	PackAddUniStr(p, "NewAccountName", t->NewAccountName);
}

// ACCESS
void InRpcAccessEx(ACCESS *a, PACK *p, UINT index)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(ACCESS));
	a->Id = PackGetIntEx(p, "Id", index);
	PackGetUniStrEx(p, "Note", a->Note, sizeof(a->Note), index);
	a->Active = PackGetBoolEx(p, "Active", index);
	a->Priority = PackGetIntEx(p, "Priority", index);
	a->Discard = PackGetBoolEx(p, "Discard", index);
	a->SrcIpAddress = PackGetIp32Ex(p, "SrcIpAddress", index);
	a->SrcSubnetMask = PackGetIp32Ex(p, "SrcSubnetMask", index);
	a->DestIpAddress = PackGetIp32Ex(p, "DestIpAddress", index);
	a->DestSubnetMask = PackGetIp32Ex(p, "DestSubnetMask", index);
	a->Protocol = PackGetIntEx(p, "Protocol", index);
	a->SrcPortStart = PackGetIntEx(p, "SrcPortStart", index);
	a->SrcPortEnd = PackGetIntEx(p, "SrcPortEnd", index);
	a->DestPortStart = PackGetIntEx(p, "DestPortStart", index);
	a->DestPortEnd = PackGetIntEx(p, "DestPortEnd", index);
	a->SrcUsernameHash = PackGetIntEx(p, "SrcUsernameHash", index);
	PackGetStrEx(p, "SrcUsername", a->SrcUsername, sizeof(a->SrcUsername), index);
	a->DestUsernameHash = PackGetIntEx(p, "DestUsernameHash", index);
	PackGetStrEx(p, "DestUsername", a->DestUsername, sizeof(a->DestUsername), index);
	a->CheckSrcMac = PackGetBoolEx(p, "CheckSrcMac", index);
	PackGetDataEx2(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index);
	PackGetDataEx2(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index);
	a->CheckDstMac = PackGetBoolEx(p, "CheckDstMac", index);
	PackGetDataEx2(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index);
	PackGetDataEx2(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index);
	a->CheckTcpState = PackGetBoolEx(p, "CheckTcpState", index);
	a->Established = PackGetBoolEx(p, "Established", index);
	a->Delay = PackGetIntEx(p, "Delay", index);
	a->Jitter = PackGetIntEx(p, "Jitter", index);
	a->Loss = PackGetIntEx(p, "Loss", index);
	a->IsIPv6 = PackGetBoolEx(p, "IsIPv6", index);
	if (a->IsIPv6)
	{
		PackGetIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index);
		PackGetIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index);
		PackGetIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index);
		PackGetIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index);
	}
}
void InRpcAccess(ACCESS *a, PACK *p)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	InRpcAccessEx(a, p, 0);
}
void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddIntEx(p, "Id", a->Id, index, total);
	PackAddUniStrEx(p, "Note", a->Note, index, total);
	PackAddBoolEx(p, "Active", a->Active, index, total);
	PackAddIntEx(p, "Priority", a->Priority, index, total);
	PackAddBoolEx(p, "Discard", a->Discard, index, total);
	if (a->IsIPv6)
	{
		PackAddIp32Ex(p, "SrcIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", 0xFFFFFFFF, index, total);
		PackAddIp32Ex(p, "DestIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", 0xFFFFFFFF, index, total);
	}
	else
	{
		PackAddIp32Ex(p, "SrcIpAddress", a->SrcIpAddress, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", a->SrcSubnetMask, index, total);
		PackAddIp32Ex(p, "DestIpAddress", a->DestIpAddress, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", a->DestSubnetMask, index, total);
	}
	PackAddIntEx(p, "Protocol", a->Protocol, index, total);
	PackAddIntEx(p, "SrcPortStart", a->SrcPortStart, index, total);
	PackAddIntEx(p, "SrcPortEnd", a->SrcPortEnd, index, total);
	PackAddIntEx(p, "DestPortStart", a->DestPortStart, index, total);
	PackAddIntEx(p, "DestPortEnd", a->DestPortEnd, index, total);
	PackAddIntEx(p, "SrcUsernameHash", a->SrcUsernameHash, index, total);
	PackAddStrEx(p, "SrcUsername", a->SrcUsername, index, total);
	PackAddIntEx(p, "DestUsernameHash", a->DestUsernameHash, index, total);
	PackAddStrEx(p, "DestUsername", a->DestUsername, index, total);
	PackAddBoolEx(p, "CheckSrcMac", a->CheckSrcMac, index, total);
	PackAddDataEx(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index, total);
	PackAddDataEx(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index, total);
	PackAddBoolEx(p, "CheckDstMac", a->CheckDstMac, index, total);
	PackAddDataEx(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index, total);
	PackAddDataEx(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index, total);
	PackAddBoolEx(p, "CheckTcpState", a->CheckTcpState, index, total);
	PackAddBoolEx(p, "Established", a->Established, index, total);
	PackAddIntEx(p, "Delay", a->Delay, index, total);
	PackAddIntEx(p, "Jitter", a->Jitter, index, total);
	PackAddIntEx(p, "Loss", a->Loss, index, total);
	PackAddBoolEx(p, "IsIPv6", a->IsIPv6, index, total);
	if (a->IsIPv6)
	{
		PackAddIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index, total);
	}
	else
	{
		IPV6_ADDR zero;

		Zero(&zero, sizeof(zero));

		PackAddIp6AddrEx(p, "SrcIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &zero, index, total);
	}
}
void OutRpcAccess(PACK *p, ACCESS *a)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	OutRpcAccessEx(p, a, 0, 1);
}

// RPC_ENUM_ACCESS_LIST
void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p)
{
	UINT i;
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_ENUM_ACCESS_LIST));
	PackGetStr(p, "HubName", a->HubName, sizeof(a->HubName));
	a->NumAccess = PackGetIndexCount(p, "Protocol");
	a->Accesses = ZeroMalloc(sizeof(ACCESS) * a->NumAccess);

	for (i = 0;i < a->NumAccess;i++)
	{
		ACCESS *e = &a->Accesses[i];

		InRpcAccessEx(e, p, i);
	}
}
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a)
{
	UINT i;
	PackAddStr(p, "HubName", a->HubName);
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < a->NumAccess;i++)
	{
		ACCESS *e = &a->Accesses[i];

		OutRpcAccessEx(p, e, i, a->NumAccess);
	}
}
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a)
{
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	Free(a->Accesses);
}

// AUTHDATA
void *InRpcAuthData(PACK *p, UINT *authtype)
{
	wchar_t tmp[MAX_SIZE];
	AUTHPASSWORD *pw;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	AUTHRADIUS *radius;
	AUTHNT *nt;
	BUF *b;
	// 引数チェック
	if (p == NULL)
	{
		return NULL;
	}
	if (authtype == NULL)
	{
		return NULL;
	}

	*authtype = PackGetInt(p, "AuthType");

	switch (*authtype)
	{
	case AUTHTYPE_PASSWORD:
		pw = ZeroMalloc(sizeof(AUTHPASSWORD));
		PackGetData2(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		return pw;

	case AUTHTYPE_USERCERT:
		usercert = ZeroMalloc(sizeof(AUTHUSERCERT));
		usercert->UserX = PackGetX(p, "UserX");
		return usercert;

	case AUTHTYPE_ROOTCERT:
		rootcert = ZeroMalloc(sizeof(AUTHROOTCERT));
		b = PackGetBuf(p, "Serial");
		if (b != NULL)
		{
			rootcert->Serial = NewXSerial(b->Buf, b->Size);
			FreeBuf(b);
		}
		if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
		{
			rootcert->CommonName = CopyUniStr(tmp);
		}
		return rootcert;

	case AUTHTYPE_RADIUS:
		radius = ZeroMalloc(sizeof(AUTHRADIUS));
		if (PackGetUniStr(p, "RadiusUsername", tmp, sizeof(tmp)))
		{
			radius->RadiusUsername = CopyUniStr(tmp);
		}
		else
		{
			radius->RadiusUsername = CopyUniStr(L"");
		}
		return radius;

	case AUTHTYPE_NT:
		nt = ZeroMalloc(sizeof(AUTHNT));
		if (PackGetUniStr(p, "NtUsername", tmp, sizeof(tmp)))
		{
			nt->NtUsername = CopyUniStr(tmp);
		}
		else
		{
			nt->NtUsername = CopyUniStr(L"");
		}
		return nt;
	}

	return NULL;
}
void OutRpcAuthData(PACK *p, void *authdata, UINT authtype)
{
	AUTHPASSWORD *pw = authdata;
	AUTHUSERCERT *usercert = authdata;
	AUTHROOTCERT *rootcert = authdata;
	AUTHRADIUS *radius = authdata;
	AUTHNT *nt = authdata;
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	PackAddInt(p, "AuthType", authtype);

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		break;

	case AUTHTYPE_USERCERT:
		PackAddX(p, "UserX", usercert->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (rootcert->Serial != NULL)
		{
			PackAddData(p, "Serial", rootcert->Serial->data, rootcert->Serial->size);
		}
		if (rootcert->CommonName != NULL)
		{
			PackAddUniStr(p, "CommonName", rootcert->CommonName);
		}
		break;

	case AUTHTYPE_RADIUS:
		PackAddUniStr(p, "RadiusUsername", radius->RadiusUsername);
		break;

	case AUTHTYPE_NT:
		PackAddUniStr(p, "NtUsername", nt->NtUsername);
		break;
	}
}
void FreeRpcAuthData(void *authdata, UINT authtype)
{
	FreeAuthData(authtype, authdata);
}

// RPC_SET_USER
void InRpcSetUser(RPC_SET_USER *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "GroupName", t->GroupName, sizeof(t->GroupName));
	PackGetUniStr(p, "Realname", t->Realname, sizeof(t->Realname));
	PackGetUniStr(p, "Note", t->Note, sizeof(t->Note));
	t->CreatedTime = PackGetInt64(p, "CreatedTime");
	t->UpdatedTime = PackGetInt64(p, "UpdatedTime");
	t->ExpireTime = PackGetInt64(p, "ExpireTime");
	t->AuthData = InRpcAuthData(p, &t->AuthType);
	t->NumLogin = PackGetInt(p, "NumLogin");
	InRpcTraffic(&t->Traffic, p);

	if (PackGetBool(p, "UsePolicy"))
	{
		t->Policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(t->Policy, p);
	}
}

void OutRpcSetUser(PACK *p, RPC_SET_USER *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "GroupName", t->GroupName);
	PackAddUniStr(p, "Realname", t->Realname);
	PackAddUniStr(p, "Note", t->Note);
	PackAddInt64(p, "CreatedTime", t->CreatedTime);
	PackAddInt64(p, "UpdatedTime", t->UpdatedTime);
	PackAddInt64(p, "ExpireTime", t->ExpireTime);
	OutRpcAuthData(p, t->AuthData, t->AuthType);
	PackAddInt(p, "NumLogin", t->NumLogin);
	OutRpcTraffic(p, &t->Traffic);

	if (t->Policy != NULL)
	{
		PackAddBool(p, "UsePolicy", true);
		OutRpcPolicy(p, t->Policy);
	}
}
void FreeRpcSetUser(RPC_SET_USER *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeRpcAuthData(t->AuthData, t->AuthType);
	if (t->Policy)
	{
		Free(t->Policy);
	}
}

// RPC_ENUM_USER
void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumUser = PackGetIndexCount(p, "Name");
	t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * t->NumUser);

	for (i = 0;i < t->NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t->Users[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "GroupName", e->GroupName, sizeof(e->GroupName), i);
		PackGetUniStrEx(p, "Realname", e->Realname, sizeof(e->Realname), i);
		PackGetUniStrEx(p, "Note", e->Note, sizeof(e->Note), i);
		e->AuthType = PackGetIntEx(p, "AuthType", i);
		e->LastLoginTime = PackGetInt64Ex(p, "LastLoginTime", i);
		e->NumLogin = PackGetIntEx(p, "NumLogin", i);
		e->DenyAccess = PackGetBoolEx(p, "DenyAccess", i);
	}
}
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t)
{
	UINT i;
	PackAddStr(p, "HubName", t->HubName);
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t->Users[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumUser);
		PackAddStrEx(p, "GroupName", e->GroupName, i, t->NumUser);
		PackAddUniStrEx(p, "Realname", e->Realname, i, t->NumUser);
		PackAddUniStrEx(p, "Note", e->Note, i, t->NumUser);
		PackAddIntEx(p, "AuthType", e->AuthType, i, t->NumUser);
		PackAddInt64Ex(p, "LastLoginTime", e->LastLoginTime, i, t->NumUser);
		PackAddIntEx(p, "NumLogin", e->NumLogin, i, t->NumUser);
		PackAddBoolEx(p, "DenyAccess", e->DenyAccess, i, t->NumUser);
	}
}
void FreeRpcEnumUser(RPC_ENUM_USER *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Users);
}

// RPC_SET_GROUP
void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_GROUP));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetUniStr(p, "Realname", t->Realname, sizeof(t->Realname));
	PackGetUniStr(p, "Note", t->Note, sizeof(t->Note));
	InRpcTraffic(&t->Traffic, p);

	if (PackGetBool(p, "UsePolicy"))
	{
		t->Policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(t->Policy, p);
	}
}
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddUniStr(p, "Realname", t->Realname);
	PackAddUniStr(p, "Note", t->Note);
	OutRpcTraffic(p, &t->Traffic);

	if (t->Policy != NULL)
	{
		PackAddBool(p, "UsePolicy", true);
		OutRpcPolicy(p, t->Policy);
	}
}
void FreeRpcSetGroup(RPC_SET_GROUP *t)
{
	Free(t->Policy);
}

// RPC_ENUM_GROUP
void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_GROUP));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumGroup = PackGetIndexCount(p, "Name");
	t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

	for (i = 0;i < t->NumGroup;i++)
	{
		RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetUniStrEx(p, "Realname", e->Realname, sizeof(e->Realname), i);
		PackGetUniStrEx(p, "Note", e->Note, sizeof(e->Note), i);
		e->NumUsers = PackGetIntEx(p, "NumUsers", i);
		e->DenyAccess = PackGetBoolEx(p, "DenyAccess", i);
	}
}
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumGroup;i++)
	{
		RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumGroup);
		PackAddUniStrEx(p, "Realname", e->Realname, i, t->NumGroup);
		PackAddUniStrEx(p, "Note", e->Note, i, t->NumGroup);
		PackAddIntEx(p, "NumUsers", e->NumUsers, i, t->NumGroup);
		PackAddBoolEx(p, "DenyAccess", e->DenyAccess, i, t->NumGroup);
	}
}
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Groups);
}

// RPC_DELETE_USER
void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
}

// RPC_ENUM_SESSION
void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_SESSION));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumSession = PackGetIndexCount(p, "Name");
	t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

	for (i = 0;i < t->NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "Username", e->Username, sizeof(e->Username), i);
		e->Ip = PackGetIntEx(p, "Ip", i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->MaxNumTcp = PackGetIntEx(p, "MaxNumTcp", i);
		e->CurrentNumTcp = PackGetIntEx(p, "CurrentNumTcp", i);
		e->PacketSize = PackGetInt64Ex(p, "PacketSize", i);
		e->PacketNum = PackGetInt64Ex(p, "PacketNum", i);
		e->RemoteSession = PackGetBoolEx(p, "RemoteSession", i);
		e->LinkMode = PackGetBoolEx(p, "LinkMode", i);
		e->SecureNATMode = PackGetBoolEx(p, "SecureNATMode", i);
		e->BridgeMode = PackGetBoolEx(p, "BridgeMode", i);
		e->Layer3Mode = PackGetBoolEx(p, "Layer3Mode", i);
		e->Client_BridgeMode = PackGetBoolEx(p, "Client_BridgeMode", i);
		e->Client_MonitorMode = PackGetBoolEx(p, "Client_MonitorMode", i);
		PackGetStrEx(p, "RemoteHostname", e->RemoteHostname, sizeof(e->RemoteHostname), i);
		e->VLanId = PackGetIntEx(p, "VLanId", i);
		PackGetDataEx2(p, "UniqueId", e->UniqueId, sizeof(e->UniqueId), i);
	}
}
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t)
{
	UINT i;
	PackAddStr(p, "HubName", t->HubName);
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumSession);
		PackAddStrEx(p, "Username", e->Username, i, t->NumSession);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumSession);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumSession);
		PackAddIntEx(p, "MaxNumTcp", e->MaxNumTcp, i, t->NumSession);
		PackAddIntEx(p, "CurrentNumTcp", e->CurrentNumTcp, i, t->NumSession);
		PackAddInt64Ex(p, "PacketSize", e->PacketSize, i, t->NumSession);
		PackAddInt64Ex(p, "PacketNum", e->PacketNum, i, t->NumSession);
		PackAddBoolEx(p, "RemoteSession", e->RemoteSession, i, t->NumSession);
		PackAddStrEx(p, "RemoteHostname", e->RemoteHostname, i, t->NumSession);
		PackAddBoolEx(p, "LinkMode", e->LinkMode, i, t->NumSession);
		PackAddBoolEx(p, "SecureNATMode", e->SecureNATMode, i, t->NumSession);
		PackAddBoolEx(p, "BridgeMode", e->BridgeMode, i, t->NumSession);
		PackAddBoolEx(p, "Layer3Mode", e->Layer3Mode, i, t->NumSession);
		PackAddBoolEx(p, "Client_BridgeMode", e->Client_BridgeMode, i, t->NumSession);
		PackAddBoolEx(p, "Client_MonitorMode", e->Client_MonitorMode, i, t->NumSession);
		PackAddIntEx(p, "VLanId", e->VLanId, i, t->NumSession);
		PackAddDataEx(p, "UniqueId", e->UniqueId, sizeof(e->UniqueId), i, t->NumSession);
	}
}
void FreeRpcEnumSession(RPC_ENUM_SESSION *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Sessions);
}

// RPC_KEY_PAIR
void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	t->Cert = PackGetX(p, "Cert");
	t->Key = PackGetK(p, "Key");
}
void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddX(p, "Cert", t->Cert);
	PackAddK(p, "Key", t->Key);
}
void FreeRpcKeyPair(RPC_KEY_PAIR *t)
{
	FreeX(t->Cert);
	FreeK(t->Key);
}

// NODE_INFO
void InRpcNodeInfo(NODE_INFO *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(NODE_INFO));
	PackGetStr(p, "ClientProductName", t->ClientProductName, sizeof(t->ClientProductName));
	PackGetStr(p, "ServerProductName", t->ServerProductName, sizeof(t->ServerProductName));
	PackGetStr(p, "ClientOsName", t->ClientOsName, sizeof(t->ClientOsName));
	PackGetStr(p, "ClientOsVer", t->ClientOsVer, sizeof(t->ClientOsVer));
	PackGetStr(p, "ClientOsProductId", t->ClientOsProductId, sizeof(t->ClientOsProductId));
	PackGetStr(p, "ClientHostname", t->ClientHostname, sizeof(t->ClientHostname));
	PackGetStr(p, "ServerHostname", t->ServerHostname, sizeof(t->ServerHostname));
	PackGetStr(p, "ProxyHostname", t->ProxyHostname, sizeof(t->ProxyHostname));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetData2(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	t->ClientProductVer = PackGetInt(p, "ClientProductVer");
	t->ClientProductBuild = PackGetInt(p, "ClientProductBuild");
	t->ServerProductVer = PackGetInt(p, "ServerProductVer");
	t->ServerProductBuild = PackGetInt(p, "ServerProductBuild");
	t->ClientIpAddress = PackGetIp32(p, "ClientIpAddress");
	PackGetData2(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	t->ClientPort = PackGetInt(p, "ClientPort");
	t->ServerIpAddress = PackGetIp32(p, "ServerIpAddress");
	PackGetData2(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	t->ServerPort = PackGetInt(p, "ServerPort2");
	t->ProxyIpAddress = PackGetIp32(p, "ProxyIpAddress");
	PackGetData2(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	t->ProxyPort = PackGetInt(p, "ProxyPort");
}
void OutRpcNodeInfo(PACK *p, NODE_INFO *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ClientProductName", t->ClientProductName);
	PackAddStr(p, "ServerProductName", t->ServerProductName);
	PackAddStr(p, "ClientOsName", t->ClientOsName);
	PackAddStr(p, "ClientOsVer", t->ClientOsVer);
	PackAddStr(p, "ClientOsProductId", t->ClientOsProductId);
	PackAddStr(p, "ClientHostname", t->ClientHostname);
	PackAddStr(p, "ServerHostname", t->ServerHostname);
	PackAddStr(p, "ProxyHostname", t->ProxyHostname);
	PackAddStr(p, "HubName", t->HubName);
	PackAddData(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	PackAddInt(p, "ClientProductVer", t->ClientProductVer);
	PackAddInt(p, "ClientProductBuild", t->ClientProductBuild);
	PackAddInt(p, "ServerProductVer", t->ServerProductVer);
	PackAddInt(p, "ServerProductBuild", t->ServerProductBuild);
	PackAddIp32(p, "ClientIpAddress", t->ClientIpAddress);
	PackAddData(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	PackAddInt(p, "ClientPort", t->ClientPort);
	PackAddIp32(p, "ServerIpAddress", t->ServerIpAddress);
	PackAddData(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	PackAddInt(p, "ServerPort2", t->ServerPort);
	PackAddIp32(p, "ProxyIpAddress", t->ProxyIpAddress);
	PackAddData(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	PackAddInt(p, "ProxyPort", t->ProxyPort);
}

// RPC_SESSION_STATUS
void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SESSION_STATUS));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "Username", t->Username, sizeof(t->Username));
	PackGetStr(p, "GroupName", t->GroupName, sizeof(t->GroupName));
	PackGetStr(p, "RealUsername", t->RealUsername, sizeof(t->RealUsername));
	t->ClientIp = PackGetIp32(p, "SessionStatus_ClientIp");
	PackGetData2(p, "SessionStatus_ClientIp6", t->ClientIp6, sizeof(t->ClientIp6));
	PackGetStr(p, "SessionStatus_ClientHostName", t->ClientHostName, sizeof(t->ClientHostName));

	InRpcClientGetConnectionStatus(&t->Status, p);
	InRpcNodeInfo(&t->NodeInfo, p);
}
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "Username", t->Username);
	PackAddStr(p, "GroupName", t->GroupName);
	PackAddStr(p, "RealUsername", t->RealUsername);
	PackAddIp32(p, "SessionStatus_ClientIp", t->ClientIp);
	PackAddData(p, "SessionStatus_ClientIp6", t->ClientIp6, sizeof(t->ClientIp6));
	PackAddStr(p, "SessionStatus_ClientHostName", t->ClientHostName);

	OutRpcClientGetConnectionStatus(p, &t->Status);
	OutRpcNodeInfo(p, &t->NodeInfo);
}
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	CiFreeClientGetConnectionStatus(&t->Status);
}

// RPC_DELETE_SESSION
void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_SESSION));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
}

// RPC_ENUM_MAC_TABLE
void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumMacTable = PackGetIndexCount(p, "SessionName");
	t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

	for (i = 0;i < t->NumMacTable;i++)
	{
		RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetStrEx(p, "SessionName", e->SessionName, sizeof(e->SessionName), i);
		PackGetDataEx2(p, "MacAddress", e->MacAddress, sizeof(e->MacAddress), i);
		e->VlanId = PackGetIntEx(p, "VlanId", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
		e->RemoteItem = PackGetBoolEx(p, "RemoteItem", i);
		PackGetStrEx(p, "RemoteHostname", e->RemoteHostname, sizeof(e->RemoteHostname), i);
	}
}
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumMacTable;i++)
	{
		RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumMacTable);
		PackAddStrEx(p, "SessionName", e->SessionName, i, t->NumMacTable);
		PackAddDataEx(p, "MacAddress", e->MacAddress, sizeof(e->MacAddress), i, t->NumMacTable);
		PackAddIntEx(p, "VlanId", e->VlanId, i, t->NumMacTable);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumMacTable);
		PackAddInt64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumMacTable);
		PackAddBoolEx(p, "RemoteItem", e->RemoteItem, i, t->NumMacTable);
		PackAddStrEx(p, "RemoteHostname", e->RemoteHostname, i, t->NumMacTable);
	}
}
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->MacTables);
}

// RPC_ENUM_IP_TABLE
void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumIpTable = PackGetIndexCount(p, "SessionName");
	t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

	for (i = 0;i < t->NumIpTable;i++)
	{
		RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetStrEx(p, "SessionName", e->SessionName, sizeof(e->SessionName), i);
		e->Ip = PackGetIp32Ex(p, "Ip", i);
		if (PackGetIpEx(p, "IpV6", &e->IpV6, i) == false)
		{
			UINTToIP(&e->IpV6, e->Ip);
		}
		e->DhcpAllocated = PackGetBoolEx(p, "DhcpAllocated", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
		e->RemoteItem = PackGetBoolEx(p, "RemoteItem", i);
		PackGetStrEx(p, "RemoteHostname", e->RemoteHostname, sizeof(e->RemoteHostname), i);
	}
}
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumIpTable;i++)
	{
		RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumIpTable);
		PackAddStrEx(p, "SessionName", e->SessionName, i, t->NumIpTable);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumIpTable);
		PackAddIpEx(p, "IpV6", &e->IpV6, i, t->NumIpTable);
		PackAddBoolEx(p, "DhcpAllocated", e->DhcpAllocated, i, t->NumIpTable);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumIpTable);
		PackAddInt64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumIpTable);
		PackAddBoolEx(p, "RemoteItem", e->RemoteItem, i, t->NumIpTable);
		PackAddStrEx(p, "RemoteHostname", e->RemoteHostname, i, t->NumIpTable);
	}
}
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->IpTables);
}

// RPC_DELETE_TABLE
void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

// RPC_ENUM_IP_TABLE の結合
void AdjoinRpcEnumIpTable(RPC_ENUM_IP_TABLE *dest, RPC_ENUM_IP_TABLE *src)
{
	UINT old_num;
	UINT i, n;
	if (dest == NULL || src == NULL)
	{
		return;
	}

	if (src->NumIpTable == 0)
	{
		return;
	}

	old_num = dest->NumIpTable;
	dest->NumIpTable += src->NumIpTable;
	dest->IpTables = ReAlloc(dest->IpTables, sizeof(RPC_ENUM_IP_TABLE_ITEM) * dest->NumIpTable);

	n = 0;
	for (i = old_num;i < dest->NumIpTable;i++)
	{
		Copy(&dest->IpTables[i], &src->IpTables[n++], sizeof(RPC_ENUM_IP_TABLE_ITEM));
	}
}

// RPC_ENUM_MAC_TABLE の結合
void AdjoinRpcEnumMacTable(RPC_ENUM_MAC_TABLE *dest, RPC_ENUM_MAC_TABLE *src)
{
	UINT old_num;
	UINT i, n;
	if (dest == NULL || src == NULL)
	{
		return;
	}

	if (src->NumMacTable == 0)
	{
		return;
	}

	old_num = dest->NumMacTable;
	dest->NumMacTable += src->NumMacTable;
	dest->MacTables = ReAlloc(dest->MacTables, sizeof(RPC_ENUM_MAC_TABLE_ITEM) * dest->NumMacTable);

	n = 0;
	for (i = old_num;i < dest->NumMacTable;i++)
	{
		Copy(&dest->MacTables[i], &src->MacTables[n++], sizeof(RPC_ENUM_MAC_TABLE_ITEM));
	}
}

// RPC_ENUM_SESSION の結合
void AdjoinRpcEnumSession(RPC_ENUM_SESSION *dest, RPC_ENUM_SESSION *src)
{
	UINT old_num;
	UINT i, n;
	if (dest == NULL || src == NULL)
	{
		return;
	}

	if (src->NumSession == 0)
	{
		return;
	}

	old_num = dest->NumSession;
	dest->NumSession += src->NumSession;
	dest->Sessions = ReAlloc(dest->Sessions, sizeof(RPC_ENUM_SESSION_ITEM) * dest->NumSession);

	n = 0;
	for (i = old_num;i < dest->NumSession;i++)
	{
		Copy(&dest->Sessions[i], &src->Sessions[n++], sizeof(RPC_ENUM_SESSION_ITEM));
	}
}

// RPC_KEEP
void InRpcKeep(RPC_KEEP *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_KEEP));
	t->UseKeepConnect = PackGetBool(p, "UseKeepConnect");
	PackGetStr(p, "KeepConnectHost", t->KeepConnectHost, sizeof(t->KeepConnectHost));
	t->KeepConnectPort = PackGetInt(p, "KeepConnectPort");
	t->KeepConnectProtocol = PackGetInt(p, "KeepConnectProtocol");
	t->KeepConnectInterval = PackGetInt(p, "KeepConnectInterval");
}
void OutRpcKeep(PACK *p, RPC_KEEP *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "UseKeepConnect", t->UseKeepConnect);
	PackAddStr(p, "KeepConnectHost", t->KeepConnectHost);
	PackAddInt(p, "KeepConnectPort", t->KeepConnectPort);
	PackAddInt(p, "KeepConnectProtocol", t->KeepConnectProtocol);
	PackAddInt(p, "KeepConnectInterval", t->KeepConnectInterval);
}

// テスト RPC 関数
UINT StTest(ADMIN *a, RPC_TEST *t)
{
	Format(t->StrValue, sizeof(t->StrValue), "%u", t->IntValue);

	return ERR_NO_ERROR;
}

// RPC_TEST
void InRpcTest(RPC_TEST *t, PACK *p)
{
	Zero(t, sizeof(RPC_TEST));
	t->IntValue = PackGetInt(p, "IntValue");
	PackGetStr(p, "StrValue", t->StrValue, sizeof(t->StrValue));
}
void OutRpcTest(PACK *p, RPC_TEST *t)
{
	PackAddInt(p, "IntValue", t->IntValue);
	PackAddStr(p, "StrValue", t->StrValue);
}
void FreeRpcTest(RPC_TEST *t)
{
}

// 管理用呼び出し
PACK *AdminCall(RPC *rpc, char *function_name, PACK *p)
{
	// 引数チェック
	if (rpc == NULL || function_name == NULL)
	{
		return NULL;
	}
	if (p == NULL)
	{
		p = NewPack();
	}

	return RpcCall(rpc, function_name, p);
}

// 管理用コネクションのソースアドレスが許可されているかどうか調べる
bool CheckAdminSourceAddress(SOCK *sock, char *hubname)
{
	BUF *b;
	char *s;
	bool ok = false;
	// 引数チェック
	if (sock == NULL)
	{
		return false;
	}

	b = ReadDump(ADMINIP_TXT);
	if (b == NULL)
	{
		return true;
	}

	while (true)
	{
		UINT i;
		TOKEN_LIST *t;
		IP ip;
		s = CfgReadNextLine(b);

		if (s == NULL)
		{
			break;
		}

		Trim(s);

		i = SearchStrEx(s, "//", 0, false);
		if (i != INFINITE)
		{
			s[i] = 0;
		}

		i = SearchStrEx(s, "#", 0, false);
		if (i != INFINITE)
		{
			s[i] = 0;
		}

		Trim(s);

		t = ParseToken(s, " \t");
		if (t != NULL)
		{
			if (t->NumTokens >= 1)
			{
				if (t->NumTokens == 1 || StrCmpi(hubname, t->Token[1]) == 0)
				{
					if (StrToIP(&ip, t->Token[0]))
					{
						if (CmpIpAddr(&sock->RemoteIP, &ip) == 0)
						{
							ok = true;
						}
					}

					if (StrCmpi(t->Token[0], "*") == 0)
					{
						ok = true;
					}
				}
			}

			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ok;
}

// 管理用コネクション受け入れ
UINT AdminAccept(CONNECTION *c, PACK *p)
{
	ADMIN *a;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR null_password[SHA1_SIZE];
	UCHAR secure_null_password[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	CEDAR *cedar;
	SOCK *sock;
	RPC *rpc;
	UINT err;
	RPC_WINVER ver;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	cedar = c->Cedar;
	sock = c->FirstSock;

	// クライアント OS を取得
	InRpcWinVer(&ver, p);

	// HUB 名を取得
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false)
	{
		// HUB 名無し
		StrCpy(hubname, sizeof(hubname), "");
	}

	// IP アドレスを見て許可するかどうか決める
	if (CheckAdminSourceAddress(sock, hubname) == false)
	{
		SLog(c->Cedar, "LA_IP_DENIED", c->Name);
		return ERR_IP_ADDRESS_DENIED;
	}

	// パスワードを取得
	if (PackGetDataSize(p, "secure_password") != SHA1_SIZE)
	{
		// プロトコルエラー
		return ERR_PROTOCOL_ERROR;
	}
	PackGetData(p, "secure_password", secure_password);

	if (StrLen(hubname) == 0)
	{
		// サーバー管理モード接続
		SLog(c->Cedar, "LA_CONNECTED_1", c->Name);
	}
	else
	{
		// 仮想 HUB 管理モード接続
		if (cedar->Server != NULL && cedar->Server->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			// クラスタ メンバには仮想 HUB 管理モードで接続することはできない
			return ERR_NOT_ENOUGH_RIGHT;
		}
		SLog(c->Cedar, "LA_CONNECTED_2", c->Name, hubname);
	}

	// パスワードチェック
	err = AdminCheckPassword(cedar, c->Random, secure_password,
		StrLen(hubname) != 0 ? hubname : NULL);

	if (err != ERR_NO_ERROR)
	{
		// エラー発生
		SLog(c->Cedar, "LA_ERROR", c->Name, GetUniErrorStr(err), err);
		return err;
	}

	SLog(c->Cedar, "LA_OK", c->Name);

	HashAdminPassword(null_password, "");
	SecurePassword(secure_null_password, null_password, c->Random);

	if (Cmp(secure_null_password, secure_password, SHA1_SIZE) == 0)
	{
		if (sock->RemoteIP.addr[0] != 127)
		{
			// パスワードが空であるがリモート接続しようとした
			// (仮想 HUB 管理モードのみ)
			if (StrLen(hubname) != 0)
			{
				return ERR_NULL_PASSWORD_LOCAL_ONLY;
			}
		}
	}

	// 成功結果を送信
	p = NewPack();
	HttpServerSend(sock, p);
	FreePack(p);

	// ADMIN 構造体を作成
	a = ZeroMalloc(sizeof(ADMIN));
	a->ServerAdmin = ((StrLen(hubname) == 0) ? true : false);
	a->HubName = (StrLen(hubname) != 0 ? hubname : NULL);
	a->Server = c->Cedar->Server;
	a->ClientBuild = c->ClientBuild;

	Copy(&a->ClientWinVer, &ver, sizeof(RPC_WINVER));

	// タイムアウト設定
	SetTimeout(sock, INFINITE);

	// RPC サーバー
	rpc = StartRpcServer(sock, AdminDispatch, a);

	a->Rpc = rpc;

	SLog(c->Cedar, "LA_RPC_START", c->Name, rpc->Name);

	RpcServer(rpc);
	RpcFree(rpc);

	if (a->LogFileList != NULL)
	{
		// キャッシュされたログファイル列挙リストがあれば解放する
		FreeEnumLogFile(a->LogFileList);
	}

	// ADMIN 構造体を解放
	Free(a);

	return ERR_NO_ERROR;
}

// 管理者パスワードのチェック
UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname)
{
	UCHAR check[SHA1_SIZE];
	// 引数チェック
	if (c == NULL || random == NULL || secure_password == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	if (hubname == NULL || StrLen(hubname) == 0)
	{
		// サーバー全体の管理モード
		Lock(c->lock);
		{
			SecurePassword(check, c->Server->HashedPassword, random);
		}
		Unlock(c->lock);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
		{
			// パスワード相違
			return ERR_ACCESS_DENIED;
		}
	}
	else
	{
		HUB *h;

#if	0
		if (c->Server->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			// ファームメンバの場合は HUB 管理モードで接続できない
			return ERR_FARM_MEMBER_HUB_ADMIN;
		}
#endif

		// HUB 管理モード
		LockHubList(c);
		{
			h = GetHub(c, hubname);
		}
		UnlockHubList(c);

		if (h == NULL)
		{
			// HUB が見つからない
			return ERR_HUB_NOT_FOUND;
		}

		Lock(h->lock);
		{
			SecurePassword(check, h->HashedPassword, random);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
		{
			// パスワード相違
			return ERR_ACCESS_DENIED;
		}
	}

	return ERR_NO_ERROR;
}

// 管理者パスワードのハッシュ
void HashAdminPassword(void *hash, char *password)
{
	// 引数チェック
	if (hash == NULL || password == NULL)
	{
		return;
	}

	Hash(hash, password, StrLen(password), true);
}

// 管理用コネクション切断
void AdminDisconnect(RPC *rpc)
{
	SESSION *s;
	SOCK *sock;
	// 引数チェック
	if (rpc == NULL)
	{
		return;
	}

	s = (SESSION *)rpc->Param;
	sock = rpc->Sock;

	EndRpc(rpc);

	Disconnect(sock);
	ReleaseSession(s);
}

// 管理接続メイン
SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd)
{
	UCHAR secure_password[SHA1_SIZE];
	SESSION *s;
	SOCK *sock;
	PACK *p;
	RPC_WINVER ver;
	// 接続
	s = NewRpcSessionEx2(cedar, o, err, client_name, hWnd);
	if (s == NULL)
	{
		return NULL;
	}

	// ソケット取得
	sock = s->Connection->FirstSock;

	// 接続メソッド作成
	p = NewPack();

	PackAddClientVersion(p, s->Connection);

	PackAddStr(p, "method", "admin");

	// クライアント Windows バージョン
	GetWinVer(&ver);
	OutRpcWinVer(p, &ver);

	// セキュアパスワード
	SecurePassword(secure_password, hashed_password, s->Connection->Random);

	PackAddData(p, "secure_password", secure_password, sizeof(secure_password));

	// HUB 名
	if (hubname != NULL)
	{
		PackAddStr(p, "hubname", hubname);
	}

	if (HttpClientSend(sock, p) == false)
	{
		// 切断
		FreePack(p);
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		// 切断
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	if (GetErrorFromPack(p) != 0)
	{
		// エラー
		ReleaseSession(s);
		*err = GetErrorFromPack(p);
		FreePack(p);
		return NULL;
	}

	FreePack(p);

	return s;
}

// 管理用コネクション接続
RPC *AdminConnect(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err)
{
	return AdminConnectEx(cedar, o, hubname, hashed_password, err, NULL);
}
RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name)
{
	return AdminConnectEx2(cedar, o, hubname, hashed_password, err, client_name, NULL);
}
RPC *AdminConnectEx2(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd)
{
	SESSION *s;
	SOCK *sock;
	RPC *rpc;
	// 引数チェック
	if (cedar == NULL || o == NULL || hashed_password == NULL || err == NULL)
	{
		return NULL;
	}

	if (client_name == NULL)
	{
		client_name = CEDAR_MANAGER_STR;
	}

	s = AdminConnectMain(cedar, o, hubname, hashed_password, err, client_name, hWnd);

	if (s == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;

	// RPC 開始
	rpc = StartRpcClient(sock, s);

	rpc->IsVpnServer = true;
	Copy(&rpc->VpnServerClientOption, o, sizeof(CLIENT_OPTION));
	StrCpy(rpc->VpnServerHubName, sizeof(rpc->VpnServerHubName), hubname);
	Copy(rpc->VpnServerHashedPassword, hashed_password, SHA1_SIZE);
	StrCpy(rpc->VpnServerClientName, sizeof(rpc->VpnServerClientName), client_name);

	// タイムアウト設定
	SetTimeout(sock, INFINITE);

	return rpc;
}

// 再接続
UINT AdminReconnect(RPC *rpc)
{
	SESSION *s;
	SOCK *sock;
	CEDAR *cedar;
	UINT err;
	// 引数チェック
	if (rpc == NULL || rpc->IsVpnServer == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	s = (SESSION *)rpc->Param;
	cedar = s->Cedar;
	AddRef(cedar->ref);

	sock = rpc->Sock;
	Disconnect(sock);
	ReleaseSock(sock);
	ReleaseSession(s);
	rpc->Param = NULL;

	rpc->Sock = NULL;

	s = AdminConnectMain(cedar, &rpc->VpnServerClientOption,
		rpc->VpnServerHubName,
		rpc->VpnServerHashedPassword,
		&err,
		rpc->VpnServerClientName, NULL);

	ReleaseCedar(cedar);

	if (s == NULL)
	{
		return err;
	}

	rpc->Param = s;
	rpc->Sock = s->Connection->FirstSock;
	AddRef(rpc->Sock->ref);

	return ERR_NO_ERROR;
}

