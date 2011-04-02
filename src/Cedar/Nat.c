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

// Nat.c
// User-mode Router

#include "CedarPch.h"

static LOCK *nat_lock = NULL;
static NAT *nat = NULL;


// NAT 管理者用接続を切断
void NatAdminDisconnect(RPC *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	EndRpc(r);
}

// NAT 管理者用接続
RPC *NatAdminConnect(CEDAR *cedar, char *hostname, UINT port, void *hashed_password, UINT *err)
{
	UCHAR secure_password[SHA1_SIZE];
	UCHAR random[SHA1_SIZE];
	SOCK *sock;
	RPC *rpc;
	PACK *p;
	UINT error;
	// 引数チェック
	if (cedar == NULL || hostname == NULL || port == 0 || hashed_password == NULL || err == NULL)
	{
		if (err != NULL)
		{
			*err = ERR_INTERNAL_ERROR;
		}
		return NULL;
	}

	// 接続
	sock = Connect(hostname, port);
	if (sock == NULL)
	{
		*err = ERR_CONNECT_FAILED;
		return NULL;
	}

	if (StartSSL(sock, NULL, NULL) == false)
	{
		*err = ERR_PROTOCOL_ERROR;
		ReleaseSock(sock);
		return NULL;
	}

	SetTimeout(sock, 5000);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		*err = ERR_DISCONNECTED;
		ReleaseSock(sock);
		return NULL;
	}

	if (PackGetData2(p, "auth_random", random, SHA1_SIZE) == false)
	{
		FreePack(p);
		*err = ERR_PROTOCOL_ERROR;
		ReleaseSock(sock);
		return NULL;
	}

	FreePack(p);

	SecurePassword(secure_password, hashed_password, random);

	p = NewPack();
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	if (HttpClientSend(sock, p) == false)
	{
		FreePack(p);
		*err = ERR_DISCONNECTED;
		ReleaseSock(sock);
		return NULL;
	}

	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		*err = ERR_DISCONNECTED;
		ReleaseSock(sock);
		return NULL;
	}

	error = GetErrorFromPack(p);

	FreePack(p);

	if (error != ERR_NO_ERROR)
	{
		*err = error;
		ReleaseSock(sock);
		return NULL;
	}

	SetTimeout(sock, TIMEOUT_INFINITE);

	rpc = StartRpcClient(sock, NULL);
	ReleaseSock(sock);

	return rpc;
}

// RPC 関数関係マクロ
#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type t;													\
		Zero(&t, sizeof(t));											\
		in_rpc(&t, p);													\
		err = function(n, &t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, &t);											\
		}																\
		free_rpc(&t);													\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type t;													\
		Zero(&t, sizeof(t));											\
		in_rpc(&t, p);													\
		err = function(n, &t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, &t);											\
		}																\
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

// RPC サーバー関数
PACK *NiRpcServer(RPC *r, char *name, PACK *p)
{
	NAT *n = (NAT *)r->Param;
	PACK *ret;
	UINT err;
	bool ok;
	// 引数チェック
	if (r == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;
	ok = false;

	if (0) {}

	// RPC 関数定義: ここから

//	DECLARE_RPC("Online", RPC_DUMMY, NtOnline, InRpcDummy, OutRpcDummy)
//	DECLARE_RPC("Offline", RPC_DUMMY, NtOffline, InRpcDummy, OutRpcDummy)
	DECLARE_RPC("SetHostOption", VH_OPTION, NtSetHostOption, InVhOption, OutVhOption)
	DECLARE_RPC("GetHostOption", VH_OPTION, NtGetHostOption, InVhOption, OutVhOption)
//	DECLARE_RPC_EX("SetClientConfig", RPC_CREATE_LINK, NtSetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
//	DECLARE_RPC_EX("GetClientConfig", RPC_CREATE_LINK, NtGetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("GetStatus", RPC_NAT_STATUS, NtGetStatus, InRpcNatStatus, OutRpcNatStatus, FreeRpcNatStatus)
//	DECLARE_RPC_EX("GetInfo", RPC_NAT_INFO, NtGetInfo, InRpcNatInfo, OutRpcNatInfo, FreeRpcNatInfo)
	DECLARE_RPC_EX("EnumNatList", RPC_ENUM_NAT, NtEnumNatList, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
	DECLARE_RPC_EX("EnumDhcpList", RPC_ENUM_DHCP, NtEnumDhcpList, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
//	DECLARE_RPC("SetPassword", RPC_SET_PASSWORD, NtSetPassword, InRpcSetPassword, OutRpcSetPassword)

	// RPC 関数定義: ここまで

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	PackAddInt(ret, "error", err);

	return ret;
}




// RPC 呼び出し定義ここから

DECLARE_SC("Online", RPC_DUMMY, NcOnline, InRpcDummy, OutRpcDummy)
DECLARE_SC("Offline", RPC_DUMMY, NcOffline, InRpcDummy, OutRpcDummy)
DECLARE_SC("SetHostOption", VH_OPTION, NcSetHostOption, InVhOption, OutVhOption)
DECLARE_SC("GetHostOption", VH_OPTION, NcGetHostOption, InVhOption, OutVhOption)
DECLARE_SC_EX("SetClientConfig", RPC_CREATE_LINK, NcSetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("GetClientConfig", RPC_CREATE_LINK, NcGetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("GetStatus", RPC_NAT_STATUS, NcGetStatus, InRpcNatStatus, OutRpcNatStatus, FreeRpcNatStatus)
DECLARE_SC_EX("GetInfo", RPC_NAT_INFO, NcGetInfo, InRpcNatInfo, OutRpcNatInfo, FreeRpcNatInfo)
DECLARE_SC_EX("EnumNatList", RPC_ENUM_NAT, NcEnumNatList, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
DECLARE_SC_EX("EnumDhcpList", RPC_ENUM_DHCP, NcEnumDhcpList, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
DECLARE_SC("SetPassword", RPC_SET_PASSWORD, NcSetPassword, InRpcSetPassword, OutRpcSetPassword)

// RPC 呼び出し定義ここまで



// パスワードを設定する
UINT NtSetPassword(NAT *n, RPC_SET_PASSWORD *t)
{
	Copy(n->HashedPassword, t->HashedPassword, SHA1_SIZE);

	NiWriteConfig(n);

	return ERR_NO_ERROR;
}

// オンラインにする
UINT NtOnline(NAT *n, RPC_DUMMY *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		if (n->Online)
		{
			// すでにオンラインである
			ret = ERR_ALREADY_ONLINE;
		}
		else
		{
			if (n->ClientOption == NULL || n->ClientAuth == NULL)
			{
				// 設定がまだ
				ret = ERR_ACCOUNT_NOT_PRESENT;
			}
			else
			{
				// OK
				n->Online = true;

				// 接続開始
				n->Virtual = NewVirtualHostEx(n->Cedar, n->ClientOption, n->ClientAuth,
					&n->Option, n);
			}
		}
	}
	Unlock(n->lock);

	NiWriteConfig(n);

	return ret;
}

// オフラインにする
UINT NtOffline(NAT *n, RPC_DUMMY *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		if (n->Online == false)
		{
			// オフラインである
			ret = ERR_OFFLINE;
		}
		else
		{
			// オフラインにする
			StopVirtualHost(n->Virtual);
			ReleaseVirtual(n->Virtual);
			n->Virtual = NULL;

			n->Online = false;
		}
	}
	Unlock(n->lock);

	NiWriteConfig(n);

	return ret;
}

// ホストオプションの設定
UINT NtSetHostOption(NAT *n, VH_OPTION *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		Copy(&n->Option, t, sizeof(VH_OPTION));
	}
	Unlock(n->lock);

	SetVirtualHostOption(n->Virtual, t);

	NiWriteConfig(n);

	return ret;
}

// ホストオプションの取得
UINT NtGetHostOption(NAT *n, VH_OPTION *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		Copy(t, &n->Option, sizeof(VH_OPTION));
	}
	Unlock(n->lock);

	return ret;
}

// 接続設定の設定
UINT NtSetClientConfig(NAT *n, RPC_CREATE_LINK *t)
{
	Lock(n->lock);
	{
		if (n->ClientOption != NULL || n->ClientAuth != NULL)
		{
			Free(n->ClientOption);
			CiFreeClientAuth(n->ClientAuth);
		}

		n->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(n->ClientOption, t->ClientOption, sizeof(CLIENT_OPTION));
		n->ClientAuth = CopyClientAuth(t->ClientAuth);
	}
	Unlock(n->lock);

	NiWriteConfig(n);

	if (n->Online)
	{
		NtOffline(n, NULL);
		NtOnline(n, NULL);
	}

	return ERR_NO_ERROR;
}

// 接続設定の取得
UINT NtGetClientConfig(NAT *n, RPC_CREATE_LINK *t)
{
	UINT err = ERR_NO_ERROR;

	Lock(n->lock);
	{
		if (n->ClientOption == NULL || n->ClientAuth == NULL)
		{
			err = ERR_ACCOUNT_NOT_PRESENT;
		}
		else
		{
			FreeRpcCreateLink(t);

			Zero(t, sizeof(RPC_CREATE_LINK));
			t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(t->ClientOption, n->ClientOption, sizeof(CLIENT_OPTION));
			t->ClientAuth = CopyClientAuth(n->ClientAuth);
		}
	}
	Unlock(n->lock);

	return err;
}

// 状態の取得
UINT NtGetStatus(NAT *n, RPC_NAT_STATUS *t)
{
	Lock(n->lock);
	{
		VH *v = n->Virtual;
		FreeRpcNatStatus(t);
		Zero(t, sizeof(RPC_NAT_STATUS));

		LockVirtual(v);
		{
			UINT i;

			LockList(v->NatTable);
			{
				for (i = 0;i < LIST_NUM(v->NatTable);i++)
				{
					NAT_ENTRY *e = LIST_DATA(v->NatTable, i);

					switch (e->Protocol)
					{
					case NAT_TCP:
						t->NumTcpSessions++;
						break;

					case NAT_UDP:
						t->NumUdpSessions++;
						break;
					}
				}
			}
			UnlockList(v->NatTable);

			t->NumDhcpClients = LIST_NUM(v->DhcpLeaseList);
		}
		UnlockVirtual(v);
	}
	Unlock(n->lock);

	return ERR_NO_ERROR;
}

// 情報の取得
UINT NtGetInfo(NAT *n, RPC_NAT_INFO *t)
{
	OS_INFO *info;
	FreeRpcNatInfo(t);
	Zero(t, sizeof(RPC_NAT_INFO));

	StrCpy(t->NatProductName, sizeof(t->NatProductName), CEDAR_ROUTER_STR);
	StrCpy(t->NatVersionString, sizeof(t->NatVersionString), n->Cedar->VerString);
	StrCpy(t->NatBuildInfoString, sizeof(t->NatBuildInfoString), n->Cedar->BuildInfo);
	t->NatVerInt = n->Cedar->Build;
	t->NatBuildInt = n->Cedar->Build;

	GetMachineName(t->NatHostName, sizeof(t->NatHostName));

	info = GetOsInfo();

	CopyOsInfo(&t->OsInfo, info);

	GetMemInfo(&t->MemInfo);

	return ERR_NO_ERROR;
}

// NAT リストの取得
UINT NtEnumNatList(NAT *n, RPC_ENUM_NAT *t)
{
	UINT ret = ERR_NO_ERROR;
	VH *v = NULL;

	Lock(n->lock);
	{
		v = n->Virtual;

		if (n->Online == false || v == NULL)
		{
			ret = ERR_OFFLINE;
		}
		else
		{
			LockVirtual(v);
			{
				if (v->Active == false)
				{
					ret = ERR_OFFLINE;
				}
				else
				{
					FreeRpcEnumNat(t);
					Zero(t, sizeof(RPC_ENUM_NAT));

					LockList(v->NatTable);
					{
						UINT i;
						t->NumItem = LIST_NUM(v->NatTable);
						t->Items = ZeroMalloc(sizeof(RPC_ENUM_NAT_ITEM) * t->NumItem);

						for (i = 0;i < t->NumItem;i++)
						{
							NAT_ENTRY *nat = LIST_DATA(v->NatTable, i);
							RPC_ENUM_NAT_ITEM *e = &t->Items[i];

							e->Id = nat->Id;
							e->Protocol = nat->Protocol;
							e->SrcIp = nat->SrcIp;
							e->DestIp = nat->DestIp;
							e->SrcPort = nat->SrcPort;
							e->DestPort = nat->DestPort;

							e->CreatedTime = TickToTime(nat->CreatedTime);
							e->LastCommTime = TickToTime(nat->LastCommTime);

							IPToStr32(e->SrcHost, sizeof(e->SrcHost), e->SrcIp);
							IPToStr32(e->DestHost, sizeof(e->DestHost), e->DestIp);

							if (nat->Sock != NULL)
							{
								e->SendSize = nat->Sock->SendSize;
								e->RecvSize = nat->Sock->RecvSize;

								if (nat->Sock->Type == SOCK_TCP)
								{
									StrCpy(e->DestHost, sizeof(e->DestHost), nat->Sock->RemoteHostname);
								}
							}

							e->TcpStatus = nat->TcpStatus;
						}
					}
					UnlockList(v->NatTable);
				}
			}
			UnlockVirtual(v);
		}
	}
	Unlock(n->lock);

	return ret;
}

UINT NtEnumDhcpList(NAT *n, RPC_ENUM_DHCP *t)
{
	UINT ret = ERR_NO_ERROR;
	VH *v = NULL;

	Lock(n->lock);
	{
		v = n->Virtual;

		if (n->Online == false || v == NULL)
		{
			ret = ERR_OFFLINE;
		}
		else
		{
			LockVirtual(v);
			{
				if (v->Active == false)
				{
					ret = ERR_OFFLINE;
				}
				else
				{
					FreeRpcEnumDhcp(t);
					Zero(t, sizeof(RPC_ENUM_DHCP));

					LockList(v->DhcpLeaseList);
					{
						UINT i;
						t->NumItem = LIST_NUM(v->DhcpLeaseList);
						t->Items = ZeroMalloc(sizeof(RPC_ENUM_DHCP_ITEM) * t->NumItem);

						for (i = 0;i < t->NumItem;i++)
						{
							DHCP_LEASE *dhcp = LIST_DATA(v->DhcpLeaseList, i);
							RPC_ENUM_DHCP_ITEM *e = &t->Items[i];

							e->Id = dhcp->Id;
							e->LeasedTime = TickToTime(dhcp->LeasedTime);
							e->ExpireTime = TickToTime(dhcp->ExpireTime);
							Copy(e->MacAddress, dhcp->MacAddress, 6);
							e->IpAddress = dhcp->IpAddress;
							e->Mask = dhcp->Mask;
							StrCpy(e->Hostname, sizeof(e->Hostname), dhcp->Hostname);
						}
					}
					UnlockList(v->DhcpLeaseList);
				}
			}
			UnlockVirtual(v);
		}
	}
	Unlock(n->lock);

	return ret;
}

// VH_OPTION
void InVhOption(VH_OPTION *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(VH_OPTION));
	PackGetData2(p, "MacAddress", t->MacAddress, 6);
	PackGetIp(p, "Ip", &t->Ip);
	PackGetIp(p, "Mask", &t->Mask);
	t->UseNat = PackGetBool(p, "UseNat");
	t->Mtu = PackGetInt(p, "Mtu");
	t->NatTcpTimeout = PackGetInt(p, "NatTcpTimeout");
	t->NatUdpTimeout = PackGetInt(p, "NatUdpTimeout");
	t->UseDhcp = PackGetBool(p, "UseDhcp");
	PackGetIp(p, "DhcpLeaseIPStart", &t->DhcpLeaseIPStart);
	PackGetIp(p, "DhcpLeaseIPEnd", &t->DhcpLeaseIPEnd);
	PackGetIp(p, "DhcpSubnetMask", &t->DhcpSubnetMask);
	t->DhcpExpireTimeSpan = PackGetInt(p, "DhcpExpireTimeSpan");
	PackGetIp(p, "DhcpGatewayAddress", &t->DhcpGatewayAddress);
	PackGetIp(p, "DhcpDnsServerAddress", &t->DhcpDnsServerAddress);
	PackGetStr(p, "DhcpDomainName", t->DhcpDomainName, sizeof(t->DhcpDomainName));
	t->SaveLog = PackGetBool(p, "SaveLog");
	PackGetStr(p, "RpcHubName", t->HubName, sizeof(t->HubName));
}
void OutVhOption(PACK *p, VH_OPTION *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddData(p, "MacAddress", t->MacAddress, 6);
	PackAddIp(p, "Ip", &t->Ip);
	PackAddIp(p, "Mask", &t->Mask);
	PackAddBool(p, "UseNat", t->UseNat);
	PackAddInt(p, "Mtu", t->Mtu);
	PackAddInt(p, "NatTcpTimeout", t->NatTcpTimeout);
	PackAddInt(p, "NatUdpTimeout", t->NatUdpTimeout);
	PackAddBool(p, "UseDhcp", t->UseDhcp);
	PackAddIp(p, "DhcpLeaseIPStart", &t->DhcpLeaseIPStart);
	PackAddIp(p, "DhcpLeaseIPEnd", &t->DhcpLeaseIPEnd);
	PackAddIp(p, "DhcpSubnetMask", &t->DhcpSubnetMask);
	PackAddInt(p, "DhcpExpireTimeSpan", t->DhcpExpireTimeSpan);
	PackAddIp(p, "DhcpGatewayAddress", &t->DhcpGatewayAddress);
	PackAddIp(p, "DhcpDnsServerAddress", &t->DhcpDnsServerAddress);
	PackAddStr(p, "DhcpDomainName", t->DhcpDomainName);
	PackAddBool(p, "SaveLog", t->SaveLog);
	PackAddStr(p, "RpcHubName", t->HubName);
}

// RPC_ENUM_DHCP
void InRpcEnumDhcp(RPC_ENUM_DHCP *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_DHCP));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_DHCP_ITEM) * t->NumItem);
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_DHCP_ITEM *e = &t->Items[i];

		e->Id = PackGetIntEx(p, "Id", i);
		e->LeasedTime = PackGetInt64Ex(p, "LeasedTime", i);
		e->ExpireTime = PackGetInt64Ex(p, "ExpireTime", i);
		PackGetDataEx2(p, "MacAddress", e->MacAddress, 6, i);
		e->IpAddress = PackGetIp32Ex(p, "IpAddress", i);
		e->Mask = PackGetIntEx(p, "Mask", i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
	}
}
void OutRpcEnumDhcp(PACK *p, RPC_ENUM_DHCP *t)
{
	UINT i;
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_DHCP_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumItem);
		PackAddInt64Ex(p, "LeasedTime", e->LeasedTime, i, t->NumItem);
		PackAddInt64Ex(p, "ExpireTime", e->ExpireTime, i, t->NumItem);
		PackAddDataEx(p, "MacAddress", e->MacAddress, 6, i, t->NumItem);
		PackAddIp32Ex(p, "IpAddress", e->IpAddress, i, t->NumItem);
		PackAddIntEx(p, "Mask", e->Mask, i, t->NumItem);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumItem);
	}
}
void FreeRpcEnumDhcp(RPC_ENUM_DHCP *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_ENUM_NAT
void InRpcEnumNat(RPC_ENUM_NAT *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_NAT));
	t->NumItem = PackGetInt(p, "NumItem");
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_NAT_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_NAT_ITEM *e = &t->Items[i];

		e->Id = PackGetIntEx(p, "Id", i);
		e->Protocol = PackGetIntEx(p, "Protocol", i);
		e->SrcIp = PackGetIntEx(p, "SrcIp", i);
		PackGetStrEx(p, "SrcHost", e->SrcHost, sizeof(e->SrcHost), i);
		e->SrcPort = PackGetIntEx(p, "SrcPort", i);
		e->DestIp = PackGetIntEx(p, "DestIp", i);
		PackGetStrEx(p, "DestHost", e->DestHost, sizeof(e->DestHost), i);
		e->DestPort = PackGetIntEx(p, "DestPort", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
		e->SendSize = PackGetInt64Ex(p, "SendSize", i);
		e->RecvSize = PackGetInt64Ex(p, "RecvSize", i);
		e->TcpStatus = PackGetIntEx(p, "TcpStatus", i);
	}
}
void OutRpcEnumNat(PACK *p, RPC_ENUM_NAT *t)
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
		RPC_ENUM_NAT_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumItem);
		PackAddIntEx(p, "Protocol", e->Protocol, i, t->NumItem);
		PackAddIp32Ex(p, "SrcIp", e->SrcIp, i, t->NumItem);
		PackAddStrEx(p, "SrcHost", e->SrcHost, i, t->NumItem);
		PackAddIntEx(p, "SrcPort", e->SrcPort, i, t->NumItem);
		PackAddIp32Ex(p, "DestIp", e->DestIp, i, t->NumItem);
		PackAddStrEx(p, "DestHost", e->DestHost, i, t->NumItem);
		PackAddIntEx(p, "DestPort", e->DestPort, i, t->NumItem);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumItem);
		PackAddInt64Ex(p, "LastCommTime", e->LastCommTime, i, t->NumItem);
		PackAddInt64Ex(p, "SendSize", e->SendSize, i, t->NumItem);
		PackAddInt64Ex(p, "RecvSize", e->RecvSize, i, t->NumItem);
		PackAddIntEx(p, "TcpStatus", e->TcpStatus, i, t->NumItem);
	}
}
void FreeRpcEnumNat(RPC_ENUM_NAT *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_NAT_INFO
void InRpcNatInfo(RPC_NAT_INFO *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_NAT_INFO));
	PackGetStr(p, "NatProductName", t->NatProductName, sizeof(t->NatProductName));
	PackGetStr(p, "NatVersionString", t->NatVersionString, sizeof(t->NatVersionString));
	PackGetStr(p, "NatBuildInfoString", t->NatBuildInfoString, sizeof(t->NatBuildInfoString));
	t->NatVerInt = PackGetInt(p, "NatVerInt");
	t->NatBuildInt = PackGetInt(p, "NatBuildInt");
	PackGetStr(p, "NatHostName", t->NatHostName, sizeof(t->NatHostName));
	InRpcOsInfo(&t->OsInfo, p);
	InRpcMemInfo(&t->MemInfo, p);
}
void OutRpcNatInfo(PACK *p, RPC_NAT_INFO *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "NatProductName", t->NatProductName);
	PackAddStr(p, "NatVersionString", t->NatVersionString);
	PackAddStr(p, "NatBuildInfoString", t->NatBuildInfoString);
	PackAddInt(p, "NatVerInt", t->NatVerInt);
	PackAddInt(p, "NatBuildInt", t->NatBuildInt);
	PackAddStr(p, "NatHostName", t->NatHostName);
	OutRpcOsInfo(p, &t->OsInfo);
	OutRpcMemInfo(p, &t->MemInfo);
}
void FreeRpcNatInfo(RPC_NAT_INFO *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeRpcOsInfo(&t->OsInfo);
}

// RPC_NAT_STATUS
void InRpcNatStatus(RPC_NAT_STATUS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_NAT_STATUS));
	t->NumTcpSessions = PackGetInt(p, "NumTcpSessions");
	t->NumUdpSessions = PackGetInt(p, "NumUdpSessions");
	t->NumDhcpClients = PackGetInt(p, "NumDhcpClients");
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
void OutRpcNatStatus(PACK *p, RPC_NAT_STATUS *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "NumTcpSessions", t->NumTcpSessions);
	PackAddInt(p, "NumUdpSessions", t->NumUdpSessions);
	PackAddInt(p, "NumDhcpClients", t->NumDhcpClients);
}
void FreeRpcNatStatus(RPC_NAT_STATUS *t)
{
}

// RPC_DUMMY
void InRpcDummy(RPC_DUMMY *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DUMMY));
	t->DummyValue = PackGetInt(p, "DummyValue");
}
void OutRpcDummy(PACK *p, RPC_DUMMY *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "DummyValue", t->DummyValue);
}

// 管理用メインプロシージャ
void NiAdminMain(NAT *n, SOCK *s)
{
	RPC *r;
	PACK *p;
	// 引数チェック
	if (n == NULL || s == NULL)
	{
		return;
	}

	p = NewPack();
	HttpServerSend(s, p);
	FreePack(p);

	r = StartRpcServer(s, NiRpcServer, n);

	RpcServer(r);

	RpcFree(r);
}

// 管理スレッド
void NiAdminThread(THREAD *thread, void *param)
{
	NAT_ADMIN *a = (NAT_ADMIN *)param;
	NAT *n;
	SOCK *s;
	UCHAR random[SHA1_SIZE];
	UINT err;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// 乱数生成
	Rand(random, sizeof(random));

	a->Thread = thread;
	AddRef(a->Thread->ref);
	s = a->Sock;
	AddRef(s->ref);

	n = a->Nat;

	LockList(n->AdminList);
	{
		Add(n->AdminList, a);
	}
	UnlockList(n->AdminList);

	NoticeThreadInit(thread);

	err = ERR_AUTH_FAILED;

	if (StartSSL(s, n->AdminX, n->AdminK))
	{
		PACK *p;

		// 乱数を送信する
		p = NewPack();
		PackAddData(p, "auth_random", random, sizeof(random));

		if (HttpServerSend(s, p))
		{
			PACK *p;
			// パスワードを受け取る
			p = HttpServerRecv(s);
			if (p != NULL)
			{
				UCHAR secure_password[SHA1_SIZE];
				UCHAR secure_check[SHA1_SIZE];

				if (PackGetData2(p, "secure_password", secure_password, sizeof(secure_password)))
				{
					SecurePassword(secure_check, n->HashedPassword, random);

					if (Cmp(secure_check, secure_password, SHA1_SIZE) == 0)
					{
						UCHAR test[SHA1_SIZE];
						// パスワード一致
						Hash(test, "", 0, true);
						SecurePassword(test, test, random);

#if	0
						if (Cmp(test, secure_check, SHA1_SIZE) == 0 && s->RemoteIP.addr[0] != 127)
						{
							// 空白パスワードは外部から接続できない
							err = ERR_NULL_PASSWORD_LOCAL_ONLY;
						}
						else
#endif

						{
							// 接続成功
							err = ERR_NO_ERROR;
							NiAdminMain(n, s);
						}
					}
				}

				FreePack(p);
			}
		}

		FreePack(p);

		if (err != ERR_NO_ERROR)
		{
			p = PackError(err);
			HttpServerSend(s, p);
			FreePack(p);
		}
	}

	Disconnect(s);
	ReleaseSock(s);
}

// 管理ポート Listen スレッド
void NiListenThread(THREAD *thread, void *param)
{
	NAT *n = (NAT *)param;
	SOCK *a;
	UINT i;
	bool b = false;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// 管理リストの初期化
	n->AdminList = NewList(NULL);

	while (true)
	{
		a = Listen(DEFAULT_NAT_ADMIN_PORT);
		if (b == false)
		{
			b = true;
			NoticeThreadInit(thread);
		}
		if (a != NULL)
		{
			break;
		}

		Wait(n->HaltEvent, NAT_ADMIN_PORT_LISTEN_INTERVAL);
		if (n->Halt)
		{
			return;
		}
	}

	n->AdminListenSock = a;
	AddRef(a->ref);

	// 待ち受け
	while (true)
	{
		SOCK *s = Accept(a);
		THREAD *t;
		NAT_ADMIN *admin;
		if (s == NULL)
		{
			break;
		}
		if (n->Halt)
		{
			ReleaseSock(s);
			break;
		}

		admin = ZeroMalloc(sizeof(NAT_ADMIN));
		admin->Nat = n;
		admin->Sock = s;
		t = NewThread(NiAdminThread, admin);
		WaitThreadInit(t);
		ReleaseThread(t);
	}

	// すべての管理コネクションを切断
	LockList(n->AdminList);
	{
		for (i = 0;i < LIST_NUM(n->AdminList);i++)
		{
			NAT_ADMIN *a = LIST_DATA(n->AdminList, i);
			Disconnect(a->Sock);
			WaitThread(a->Thread, INFINITE);
			ReleaseThread(a->Thread);
			ReleaseSock(a->Sock);
			Free(a);
		}
	}
	UnlockList(n->AdminList);

	ReleaseList(n->AdminList);

	ReleaseSock(a);
}

// 管理コマンド受付初期化
void NiInitAdminAccept(NAT *n)
{
	THREAD *t;
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	t = NewThread(NiListenThread, n);
	WaitThreadInit(t);
	n->AdminAcceptThread = t;
}

// 管理コマンド受付終了
void NiFreeAdminAccept(NAT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	n->Halt = true;
	Disconnect(n->AdminListenSock);
	Set(n->HaltEvent);

	while (true)
	{
		if (WaitThread(n->AdminAcceptThread, 1000) == false)
		{
			Disconnect(n->AdminListenSock);
		}
		else
		{
			break;
		}
	}
	ReleaseThread(n->AdminAcceptThread);

	ReleaseSock(n->AdminListenSock);
}

// ダイナミック仮想 HUB でサポートされていない DHCP オプションをクリアする
void NiClearUnsupportedVhOptionForDynamicHub(VH_OPTION *o, bool initial)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	o->UseNat = false;

	if (initial)
	{
		Zero(&o->DhcpGatewayAddress, sizeof(IP));
		Zero(&o->DhcpDnsServerAddress, sizeof(IP));
		StrCpy(o->DhcpDomainName, sizeof(o->DhcpDomainName), "");
	}
}

// 仮想ホストのオプションを初期化する
void NiSetDefaultVhOption(NAT *n, VH_OPTION *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	Zero(o, sizeof(VH_OPTION));
	GenMacAddress(o->MacAddress);

	// 仮想 IP を 192.168.30.1/24 にする
	SetIP(&o->Ip, 192, 168, 30, 1);
	SetIP(&o->Mask, 255, 255, 255, 0);
	o->UseNat = true;
	o->Mtu = 1500;
	o->NatTcpTimeout = 7200;
	o->NatUdpTimeout = 60;
	o->UseDhcp = true;
	SetIP(&o->DhcpLeaseIPStart, 192, 168, 30, 10);
	SetIP(&o->DhcpLeaseIPEnd, 192, 168, 30, 200);
	SetIP(&o->DhcpSubnetMask, 255, 255, 255, 0);
	o->DhcpExpireTimeSpan = 7200;
	o->SaveLog = true;

	SetIP(&o->DhcpGatewayAddress, 192, 168, 30, 1);
	SetIP(&o->DhcpDnsServerAddress, 192, 168, 30, 1);

	GetDomainName(o->DhcpDomainName, sizeof(o->DhcpDomainName));
}

// NAT の設定を初期状態にする
void NiInitDefaultConfig(NAT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	// 仮想ホストオプション初期化
	NiSetDefaultVhOption(n, &n->Option);

	// 管理用ポート初期化
	n->AdminPort = DEFAULT_NAT_ADMIN_PORT;

	// オフライン
	n->Online = false;

	// ログを保存
	n->Option.SaveLog = true;
}

// NAT の設定の初期化
void NiInitConfig(NAT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	// 初期状態
	NiInitDefaultConfig(n);
}

// 仮想ホストオプションの読み込み (拡張)
void NiLoadVhOptionEx(VH_OPTION *o, FOLDER *root)
{
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// 引数チェック
	if (o == NULL || root == NULL)
	{
		return;
	}

	host = CfgGetFolder(root, "VirtualHost");
	nat = CfgGetFolder(root, "VirtualRouter");
	dhcp = CfgGetFolder(root, "VirtualDhcpServer");

	Zero(o, sizeof(VH_OPTION));

	GenMacAddress(o->MacAddress);
	if (CfgGetStr(host, "VirtualHostMacAddress", mac_address, sizeof(mac_address)))
	{
		BUF *b = StrToBin(mac_address);
		if (b != NULL)
		{
			if (b->Size == 6)
			{
				Copy(o->MacAddress, b->Buf, 6);
			}
		}
		FreeBuf(b);
	}
	CfgGetIp(host, "VirtualHostIp", &o->Ip);
	CfgGetIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	o->UseNat = CfgGetBool(nat, "NatEnabled");
	o->Mtu = CfgGetInt(nat, "NatMtu");
	o->NatTcpTimeout = CfgGetInt(nat, "NatTcpTimeout");
	o->NatUdpTimeout = CfgGetInt(nat, "NatUdpTimeout");

	o->UseDhcp = CfgGetBool(dhcp, "DhcpEnabled");
	CfgGetIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgGetIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgGetIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	o->DhcpExpireTimeSpan = CfgGetInt(dhcp, "DhcpExpireTimeSpan");
	CfgGetIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgGetIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgGetStr(dhcp, "DhcpDomainName", o->DhcpDomainName, sizeof(o->DhcpDomainName));

	Trim(o->DhcpDomainName);
	if (StrLen(o->DhcpDomainName) == 0)
	{
		//GetDomainName(o->DhcpDomainName, sizeof(o->DhcpDomainName));
	}

	o->SaveLog = CfgGetBool(root, "SaveLog");
}

// 仮想ホストオプションの読み込み
void NiLoadVhOption(NAT *n, FOLDER *root)
{
	VH_OPTION *o;
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// 引数チェック
	if (n == NULL || root == NULL)
	{
		return;
	}

	host = CfgGetFolder(root, "VirtualHost");
	nat = CfgGetFolder(root, "VirtualRouter");
	dhcp = CfgGetFolder(root, "VirtualDhcpServer");

	o = &n->Option;
	Zero(o, sizeof(VH_OPTION));

	GenMacAddress(o->MacAddress);
	if (CfgGetStr(host, "VirtualHostMacAddress", mac_address, sizeof(mac_address)))
	{
		BUF *b = StrToBin(mac_address);
		if (b != NULL)
		{
			if (b->Size == 6)
			{
				Copy(o->MacAddress, b->Buf, 6);
			}
		}
		FreeBuf(b);
	}
	CfgGetIp(host, "VirtualHostIp", &o->Ip);
	CfgGetIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	o->UseNat = CfgGetBool(nat, "NatEnabled");
	o->Mtu = CfgGetInt(nat, "NatMtu");
	o->NatTcpTimeout = CfgGetInt(nat, "NatTcpTimeout");
	o->NatUdpTimeout = CfgGetInt(nat, "NatUdpTimeout");

	o->UseDhcp = CfgGetBool(dhcp, "DhcpEnabled");
	CfgGetIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgGetIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgGetIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	o->DhcpExpireTimeSpan = CfgGetInt(dhcp, "DhcpExpireTimeSpan");
	CfgGetIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgGetIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgGetStr(dhcp, "DhcpDomainName", o->DhcpDomainName, sizeof(o->DhcpDomainName));

	o->SaveLog = CfgGetBool(root, "SaveLog");
}

// VPN サーバーからの接続オプションの読み込み
void NiLoadClientData(NAT *n, FOLDER *root)
{
	FOLDER *co, *ca;
	// 引数チェック
	if (n == NULL || root == NULL)
	{
		return;
	}

	co = CfgGetFolder(root, "VpnClientOption");
	ca = CfgGetFolder(root, "VpnClientAuth");
	if (co == NULL || ca == NULL)
	{
		return;
	}

	n->ClientOption = CiLoadClientOption(co);
	n->ClientAuth = CiLoadClientAuth(ca);
}

// VPN サーバーへの接続オプションの書き込み
void NiWriteClientData(NAT *n, FOLDER *root)
{
	// 引数チェック
	if (n == NULL || root == NULL || n->ClientOption == NULL || n->ClientAuth == NULL)
	{
		return;
	}

	CiWriteClientOption(CfgCreateFolder(root, "VpnClientOption"), n->ClientOption);
	CiWriteClientAuth(CfgCreateFolder(root, "VpnClientAuth"), n->ClientAuth);
}

// 仮想ホストオプションの書き込み (拡張)
void NiWriteVhOptionEx(VH_OPTION *o, FOLDER *root)
{
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// 引数チェック
	if (o == NULL || root == NULL)
	{
		return;
	}

	host = CfgCreateFolder(root, "VirtualHost");
	nat = CfgCreateFolder(root, "VirtualRouter");
	dhcp = CfgCreateFolder(root, "VirtualDhcpServer");

	MacToStr(mac_address, sizeof(mac_address), o->MacAddress);
	CfgAddStr(host, "VirtualHostMacAddress", mac_address);
	CfgAddIp(host, "VirtualHostIp", &o->Ip);
	CfgAddIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	CfgAddBool(nat, "NatEnabled", o->UseNat);
	CfgAddInt(nat, "NatMtu", o->Mtu);
	CfgAddInt(nat, "NatTcpTimeout", o->NatTcpTimeout);
	CfgAddInt(nat, "NatUdpTimeout", o->NatUdpTimeout);

	CfgAddBool(dhcp, "DhcpEnabled", o->UseDhcp);
	CfgAddIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgAddIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgAddIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	CfgAddInt(dhcp, "DhcpExpireTimeSpan", o->DhcpExpireTimeSpan);
	CfgAddIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgAddIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgAddStr(dhcp, "DhcpDomainName", o->DhcpDomainName);

	CfgAddBool(root, "SaveLog", o->SaveLog);
}

// 仮想ホストオプションの書き込み
void NiWriteVhOption(NAT *n, FOLDER *root)
{
	VH_OPTION *o;
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// 引数チェック
	if (n == NULL || root == NULL)
	{
		return;
	}

	host = CfgCreateFolder(root, "VirtualHost");
	nat = CfgCreateFolder(root, "VirtualRouter");
	dhcp = CfgCreateFolder(root, "VirtualDhcpServer");

	o = &n->Option;

	MacToStr(mac_address, sizeof(mac_address), o->MacAddress);
	CfgAddStr(host, "VirtualHostMacAddress", mac_address);
	CfgAddIp(host, "VirtualHostIp", &o->Ip);
	CfgAddIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	CfgAddBool(nat, "NatEnabled", o->UseNat);
	CfgAddInt(nat, "NatMtu", o->Mtu);
	CfgAddInt(nat, "NatTcpTimeout", o->NatTcpTimeout);
	CfgAddInt(nat, "NatUdpTimeout", o->NatUdpTimeout);

	CfgAddBool(dhcp, "DhcpEnabled", o->UseDhcp);
	CfgAddIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgAddIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgAddIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	CfgAddInt(dhcp, "DhcpExpireTimeSpan", o->DhcpExpireTimeSpan);
	CfgAddIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgAddIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgAddStr(dhcp, "DhcpDomainName", o->DhcpDomainName);

	CfgAddBool(root, "SaveLog", o->SaveLog);
}

// 設定ファイルを読み込む
bool NiLoadConfig(NAT *n, FOLDER *root)
{
	FOLDER *host;
	BUF *b;
	// 引数チェック
	if (n == NULL || root == NULL)
	{
		return false;
	}

	host = CfgGetFolder(root, "VirtualHost");
	if (host == NULL)
	{
		return false;
	}

	CfgGetByte(root, "HashedPassword", n->HashedPassword, sizeof(n->HashedPassword));
	n->AdminPort = CfgGetInt(root, "AdminPort");
	n->Online = CfgGetBool(root, "Online");

	b = CfgGetBuf(root, "AdminCert");
	if (b != NULL)
	{
		n->AdminX = BufToX(b, false);
		FreeBuf(b);
	}

	b = CfgGetBuf(root, "AdminKey");
	if (b != NULL)
	{
		n->AdminK = BufToK(b, true, false, NULL);
		FreeBuf(b);
	}

	NiLoadVhOption(n, root);

	NiLoadClientData(n, root);

	return true;
}

// 設定をファイルに書き込む
void NiWriteConfig(NAT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	Lock(n->lock);
	{
		FOLDER *root = CfgCreateFolder(NULL, TAG_ROOT);
		BUF *b;

		// 証明書
		b = XToBuf(n->AdminX, false);
		CfgAddBuf(root, "AdminCert", b);
		FreeBuf(b);

		// 秘密鍵
		b = KToBuf(n->AdminK, false, NULL);
		CfgAddBuf(root, "AdminKey", b);
		FreeBuf(b);

		// パスワード
		CfgAddByte(root, "HashedPassword", n->HashedPassword, sizeof(n->HashedPassword));
		CfgAddInt(root, "AdminPort", n->AdminPort);
		CfgAddBool(root, "Online", n->Online);

		// 仮想ホストオプション
		NiWriteVhOption(n, root);

		// 接続オプション
		if (n->ClientOption != NULL && n->ClientAuth != NULL)
		{
			NiWriteClientData(n, root);
		}

		SaveCfgRw(n->CfgRw, root);
		CfgDeleteFolder(root);
	}
	Unlock(n->lock);
}

// NAT の設定の解放
void NiFreeConfig(NAT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	// 最新の設定の書き込み
	NiWriteConfig(n);

	// 設定 R/W の解放
	FreeCfgRw(n->CfgRw);
	n->CfgRw = NULL;

	Free(n->ClientOption);
	CiFreeClientAuth(n->ClientAuth);

	FreeX(n->AdminX);
	FreeK(n->AdminK);
}

// NAT の作成
NAT *NiNewNatEx(SNAT *snat, VH_OPTION *o)
{
	NAT *n = ZeroMalloc(sizeof(NAT));

	n->lock = NewLock();
	Hash(n->HashedPassword, "", 0, true);
	n->HaltEvent = NewEvent();

	//n->Cedar = NewCedar(NULL, NULL);

	n->SecureNAT = snat;

	// 優先順位を上げる
	//OSSetHighPriority();

	// 設定の初期化
	NiInitConfig(n);

#if	0
	// 仮想ホストの動作を開始
	if (n->Online && n->ClientOption != NULL)
	{
		n->Virtual = NewVirtualHostEx(n->Cedar, n->ClientOption, n->ClientAuth, &n->Option, n);
	}
	else
	{
		n->Online = false;
		n->Virtual = NULL;
	}
#else
	n->Virtual = NewVirtualHostEx(n->Cedar, NULL, NULL, o, n);
	n->Online = true;
#endif

	// 管理コマンド開始
	//NiInitAdminAccept(n);

	return n;
}
NAT *NiNewNat()
{
	return NiNewNatEx(NULL, NULL);
}

// NAT の解放
void NiFreeNat(NAT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	// 管理コマンド終了
	//NiFreeAdminAccept(n);

	// 仮想ホストが動作中の場合は停止
	Lock(n->lock);
	{
		if (n->Virtual != NULL)
		{
			StopVirtualHost(n->Virtual);
			ReleaseVirtual(n->Virtual);
			n->Virtual = NULL;
		}
	}
	Unlock(n->lock);

	// 設定の解放
	NiFreeConfig(n);

	// オブジェクトの削除
	ReleaseCedar(n->Cedar);
	ReleaseEvent(n->HaltEvent);
	DeleteLock(n->lock);

	Free(n);
}

// NAT の停止
void NtStopNat()
{
	Lock(nat_lock);
	{
		if (nat != NULL)
		{
			NiFreeNat(nat);
			nat = NULL;
		}
	}
	Unlock(nat_lock);
}

// NAT の開始
void NtStartNat()
{
	Lock(nat_lock);
	{
		if (nat == NULL)
		{
			nat = NiNewNat();
		}
	}
	Unlock(nat_lock);
}

// NtXxx 関数の初期化
void NtInit()
{
	if (nat_lock != NULL)
	{
		return;
	}

	nat_lock = NewLock();
}

// NtXxx 関数の解放
void NtFree()
{
	if (nat_lock == NULL)
	{
		return;
	}

	DeleteLock(nat_lock);
	nat_lock = NULL;
}

