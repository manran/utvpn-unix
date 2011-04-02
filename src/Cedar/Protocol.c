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

// Protocol.c
// SoftEther プロトコル関係のルーチン

#include "CedarPch.h"

static char http_404_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>404 Not Found</TITLE>\r\n</HEAD><BODY>\r\n<H1>Not Found</H1>\r\nThe requested URL $TARGET$ was not found on this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_403_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access $TARGET$\r\non this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_501_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>501 Method Not Implemented</TITLE>\r\n</HEAD><BODY>\r\n<H1>Method Not Implemented</H1>\r\n$METHOD$ to $TARGET$ not supported.<P>\r\nInvalid method in request $METHOD$ $TARGET$ $VERSION$<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";

// マシンごとにユニークな ID を生成する
void GenerateMachineUniqueHash(void *data)
{
	BUF *b;
	char name[64];
	char ip_str[64];
	IP ip;
	OS_INFO *osinfo;
	// 引数チェック
	if (data == NULL)
	{
		return;
	}

	b = NewBuf();
	GetMachineName(name, sizeof(name));
	GetMachineIp(&ip);
	IPToStr(ip_str, sizeof(ip_str), &ip);

	osinfo = GetOsInfo();

	WriteBuf(b, name, StrLen(name));
	WriteBuf(b, ip_str, StrLen(ip_str));

	WriteBuf(b, &osinfo->OsType, sizeof(osinfo->OsType));
	WriteBuf(b, osinfo->KernelName, StrLen(osinfo->KernelName));
	WriteBuf(b, osinfo->KernelVersion, StrLen(osinfo->KernelVersion));
	WriteBuf(b, osinfo->OsProductName, StrLen(osinfo->OsProductName));
	WriteBuf(b, &osinfo->OsServicePack, sizeof(osinfo->OsServicePack));
	WriteBuf(b, osinfo->OsSystemName, StrLen(osinfo->OsSystemName));
	WriteBuf(b, osinfo->OsVendorName, StrLen(osinfo->OsVendorName));
	WriteBuf(b, osinfo->OsVersion, StrLen(osinfo->OsVersion));

	Hash(data, b->Buf, b->Size, true);

	FreeBuf(b);
}

// ノード情報を文字列に変換する
void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info)
{
	char client_ip[128], server_ip[128], proxy_ip[128], unique_id[128];
	// 引数チェック
	if (str == NULL || info == NULL)
	{
		return;
	}

	IPToStr4or6(client_ip, sizeof(client_ip), info->ClientIpAddress, info->ClientIpAddress6);
	IPToStr4or6(server_ip, sizeof(server_ip), info->ServerIpAddress, info->ServerIpAddress6);
	IPToStr4or6(proxy_ip, sizeof(proxy_ip), info->ProxyIpAddress, info->ProxyIpAddress6);
	BinToStr(unique_id, sizeof(unique_id), info->UniqueId, sizeof(info->UniqueId));

	UniFormat(str, size, _UU("LS_NODE_INFO_TAG"), info->ClientProductName,
		Endian32(info->ClientProductVer), Endian32(info->ClientProductBuild),
		info->ServerProductName, Endian32(info->ServerProductVer), Endian32(info->ServerProductBuild),
		info->ClientOsName, info->ClientOsVer, info->ClientOsProductId,
		info->ClientHostname, client_ip, Endian32(info->ClientPort),
		info->ServerHostname, server_ip, Endian32(info->ServerPort),
		info->ProxyHostname, proxy_ip, Endian32(info->ProxyPort),
		info->HubName, unique_id);
}

// ノード情報の比較
bool CompareNodeInfo(NODE_INFO *a, NODE_INFO *b)
{
	// 引数チェック
	if (a == NULL || b == NULL)
	{
		return false;
	}

	// このあたりは急いで実装したのでコードがあまり美しくない。
	if (StrCmp(a->ClientProductName, b->ClientProductName) != 0)
	{
		return false;
	}
	if (a->ClientProductVer != b->ClientProductVer)
	{
		return false;
	}
	if (a->ClientProductBuild != b->ClientProductBuild)
	{
		return false;
	}
	if (StrCmp(a->ServerProductName, b->ServerProductName) != 0)
	{
		return false;
	}
	if (a->ServerProductVer != b->ServerProductVer)
	{
		return false;
	}
	if (a->ServerProductBuild != b->ServerProductBuild)
	{
		return false;
	}
	if (StrCmp(a->ClientOsName, b->ClientOsName) != 0)
	{
		return false;
	}
	if (StrCmp(a->ClientOsVer, b->ClientOsVer) != 0)
	{
		return false;
	}
	if (StrCmp(a->ClientOsProductId, b->ClientOsProductId) != 0)
	{
		return false;
	}
	if (StrCmp(a->ClientHostname, b->ClientHostname) != 0)
	{
		return false;
	}
	if (a->ClientIpAddress != b->ClientIpAddress)
	{
		return false;
	}
	if (StrCmp(a->ServerHostname, b->ServerHostname) != 0)
	{
		return false;
	}
	if (a->ServerIpAddress != b->ServerIpAddress)
	{
		return false;
	}
	if (a->ServerPort != b->ServerPort)
	{
		return false;
	}
	if (StrCmp(a->ProxyHostname, b->ProxyHostname) != 0)
	{
		return false;
	}
	if (a->ProxyIpAddress != b->ProxyIpAddress)
	{
		return false;
	}
	if (a->ProxyPort != b->ProxyPort)
	{
		return false;
	}
	if (StrCmp(a->HubName, b->HubName) != 0)
	{
		return false;
	}
	if (Cmp(a->UniqueId, b->UniqueId, 16) != 0)
	{
		return false;
	}

	return true;
}

// パスワード変更受付
UINT ChangePasswordAccept(CONNECTION *c, PACK *p)
{
	CEDAR *cedar;
	UCHAR random[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	char username[MAX_USERNAME_LEN + 1];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password[SHA1_SIZE];
	UCHAR check_secure_old_password[SHA1_SIZE];
	UINT ret = ERR_NO_ERROR;
	HUB *hub;
	bool save = false;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Copy(random, c->Random, SHA1_SIZE);
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false ||
		PackGetStr(p, "username", username, sizeof(username)) == false ||
		PackGetData2(p, "secure_old_password", secure_old_password, sizeof(secure_old_password)) == false ||
		PackGetData2(p, "new_password", new_password, sizeof(new_password)) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	cedar = c->Cedar;

	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		char tmp[MAX_SIZE];

		if (GetHubAdminOption(hub, "deny_change_user_password") != 0)
		{
			ReleaseHub(hub);
			return ERR_NOT_ENOUGH_RIGHT;
		}

		IPToStr(tmp, sizeof(tmp), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_CHANGE_PASSWORD_1", c->Name, tmp);

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u == NULL)
			{
				HLog(hub, "LH_CHANGE_PASSWORD_2", c->Name, username);
				ret = ERR_OLD_PASSWORD_WRONG;
			}
			else
			{
				Lock(u->lock);
				{
					if (u->AuthType	!= AUTHTYPE_PASSWORD)
					{
						// パスワード認証ではない
						HLog(hub, "LH_CHANGE_PASSWORD_3", c->Name, username);
						ret = ERR_USER_AUTHTYPE_NOT_PASSWORD;
					}
					else
					{
						bool fix_password = false;
						if (u->Policy != NULL)
						{
							fix_password = u->Policy->FixPassword;
						}
						else
						{
							if (u->Group != NULL)
							{
								if (u->Group->Policy != NULL)
								{
									fix_password = u->Group->Policy->FixPassword;
								}
							}
						}
						if (fix_password == false)
						{
							// 古いパスワードの確認
							AUTHPASSWORD *pw = (AUTHPASSWORD *)u->AuthData;

							SecurePassword(check_secure_old_password, pw->HashedKey, random);
							if (Cmp(check_secure_old_password, secure_old_password, SHA1_SIZE) != 0)
							{
								// 古いパスワードが間違っている
								ret = ERR_OLD_PASSWORD_WRONG;
								HLog(hub, "LH_CHANGE_PASSWORD_4", c->Name, username);
							}
							else
							{
								// 新しいパスワードの書き込み
								Copy(pw->HashedKey, new_password, SHA1_SIZE);
								HLog(hub, "LH_CHANGE_PASSWORD_5", c->Name, username);
								save = true;
							}
						}
						else
						{
							// パスワード変更は禁止
							ret = ERR_NOT_ENOUGH_RIGHT;
						}
					}
				}
				Unlock(u->lock);

				ReleaseUser(u);
			}
		}
		AcUnlock(hub);
		ReleaseHub(hub);
	}

	return ret;
}

// パスワードを変更する
UINT ChangePassword(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, char *username, char *old_pass, char *new_pass)
{
	UINT ret = ERR_NO_ERROR;
	UCHAR old_password[SHA1_SIZE];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password[SHA1_SIZE];
	SOCK *sock;
	SESSION *s;
	// 引数チェック
	if (cedar == NULL || o == NULL || hubname == NULL || username == NULL || old_pass == NULL || new_pass == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}


	// セッション作成
	s = NewRpcSessionEx(cedar, o, &ret, NULL);

	if (s != NULL)
	{
		PACK *p = NewPack();

		sock = s->Connection->FirstSock;

		HashPassword(old_password, username, old_pass);
		SecurePassword(secure_old_password, old_password, s->Connection->Random);
		HashPassword(new_password, username, new_pass);

		PackAddClientVersion(p, s->Connection);

		PackAddStr(p, "method", "password");
		PackAddStr(p, "hubname", hubname);
		PackAddStr(p, "username", username);
		PackAddData(p, "secure_old_password", secure_old_password, SHA1_SIZE);
		PackAddData(p, "new_password", new_password, SHA1_SIZE);

		if (HttpClientSend(sock, p))
		{
			PACK *p = HttpClientRecv(sock);
			if (p == NULL)
			{
				ret = ERR_DISCONNECTED;
			}
			else
			{
				ret = GetErrorFromPack(p);
			}
			FreePack(p);
		}
		else
		{
			ret = ERR_DISCONNECTED;
		}
		FreePack(p);

		ReleaseSession(s);
	}

	return ret;
}

// HUB を列挙する
TOKEN_LIST *EnumHub(SESSION *s)
{
	SOCK *sock;
	TOKEN_LIST *ret;
	PACK *p;
	UINT num;
	UINT i;
	// 引数チェック
	if (s == NULL || s->Connection == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;
	if (sock == NULL)
	{
		return NULL;
	}

	// タイムアウトの設定
	SetTimeout(sock, 10000);

	p = NewPack();
	PackAddStr(p, "method", "enum_hub");

	PackAddClientVersion(p, s->Connection);

	if (HttpClientSend(sock, p) == false)
	{
		FreePack(p);
		return NULL;
	}
	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		return NULL;
	}

	num = PackGetInt(p, "NumHub");
	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = num;
	ret->Token = ZeroMalloc(sizeof(char *) * num);
	for (i = 0;i < num;i++)
	{
		char tmp[MAX_SIZE];
		if (PackGetStrEx(p, "HubName", tmp, sizeof(tmp), i))
		{
			ret->Token[i] = CopyStr(tmp);
		}
	}
	FreePack(p);

	return ret;
}

// サーバーがクライアントからの接続を受け付ける
bool ServerAccept(CONNECTION *c)
{
	bool ret = false;
	UINT err;
	PACK *p;
	char username_real[MAX_SIZE];
	char method[MAX_SIZE];
	char hubname[MAX_SIZE];
	char username[MAX_SIZE];
	char groupname[MAX_SIZE];
	UCHAR session_key[SHA1_SIZE];
	UCHAR ticket[SHA1_SIZE];
	RC4_KEY_PAIR key_pair;
	UINT authtype;
	POLICY *policy;
	HUB *hub;
	SESSION *s;
	UINT64 user_expires = 0;
	bool use_encrypt;
	bool use_compress;
	bool half_connection;
	bool use_fast_rc4;
	bool admin_mode = false;
	UINT direction;
	UINT max_connection;
	UINT timeout;
	bool farm_controller = false;
	bool farm_member = false;
	bool farm_mode = false;
	bool require_bridge_routing_mode;
	bool require_monitor_mode;
	bool use_client_license = false, use_bridge_license = false;
	bool local_host_session = false;
	char sessionname[MAX_SESSION_NAME_LEN + 1];
	bool is_server_or_bridge = false;
	bool qos = false;
	bool cluster_dynamic_secure_nat = false;
	bool no_save_password = false;
	NODE_INFO node;
	wchar_t *msg = NULL;
	USER *loggedin_user_object = NULL;
	FARM_MEMBER *f = NULL;
	SERVER *server = NULL;
	POLICY ticketed_policy;
	UINT64 timestamp;
	UCHAR unique[SHA1_SIZE], unique2[SHA1_SIZE];
	LICENSE_STATUS license;
	CEDAR *cedar;
	RPC_WINVER winver;
	UINT client_id;
	bool no_more_users_in_server = false;

	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	Zero(&winver, sizeof(winver));

	StrCpy(groupname, sizeof(groupname), "");
	StrCpy(sessionname, sizeof(sessionname), "");

	cedar = c->Cedar;

	// ライセンス状況の取得
	Zero(&license, sizeof(license));
	if (c->Cedar->Server != NULL)
	{
		LiParseCurrentLicenseStatus(c->Cedar->Server->LicenseSystem, &license);
	}

	no_more_users_in_server = SiTooManyUserObjectsInServer(cedar->Server, true);

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	if (c->Cedar->Server != NULL)
	{
		SERVER *s = c->Cedar->Server;
		server = s;

		if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			farm_member = true;
			farm_mode = true;
		}

		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			farm_controller = true;
			farm_mode = true;
		}
	}

	// シグネチャを受信
	Debug("Downloading Signature...\n");
	if (ServerDownloadSignature(c) == false)
	{
		goto CLEANUP;
	}

	// Hello パケットを送信
	Debug("Uploading Hello...\n");
	if (ServerUploadHello(c) == false)
	{
		goto CLEANUP;
	}

	// 認証データを受信
	Debug("Auth...\n");

	p = HttpServerRecv(c->FirstSock);
	if (p == NULL)
	{
		// 通信切断
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p))
	{
		// エラー発生
		FreePack(p);
		c->Err = err;
		goto CLEANUP;
	}

	// メソッド取得
	if (GetMethodFromPack(p, method, sizeof(method)) == false)
	{
		// プロトコルエラー
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	// 時刻検査
	timestamp = PackGetInt64(p, "timestamp");
	if (timestamp != 0)
	{
		UINT64 now = SystemTime64();
		UINT64 abs;
		if (now >= timestamp)
		{
			abs = now - timestamp;
		}
		else
		{
			abs = timestamp - now;
		}

		if (abs > ALLOW_TIMESTAMP_DIFF)
		{
			// 時差が大きすぎる
			FreePack(p);
			c->Err = ERR_BAD_CLOCK;
			goto CLEANUP;
		}
	}

	// クライアントバージョン取得
	PackGetStr(p, "client_str", c->ClientStr, sizeof(c->ClientStr));
	c->ClientVer = PackGetInt(p, "client_ver");
	c->ClientBuild = PackGetInt(p, "client_build");

	if (SearchStrEx(c->ClientStr, "server", 0, false) != INFINITE ||
		SearchStrEx(c->ClientStr, "bridge", 0, false) != INFINITE)
	{
		is_server_or_bridge = true;
	}

	// クライアント Windows バージョンの取得
	InRpcWinVer(&winver, p);

	DecrementNoSsl(c->Cedar, &c->FirstSock->RemoteIP, 2);

	if (StrCmpi(method, "login") == 0)
	{
		bool auth_ret = false;

		Debug("Login...\n");
		c->Status = CONNECTION_STATUS_USERAUTH;

		c->Type = CONNECTION_TYPE_LOGIN;

		if (no_more_users_in_server)
		{
			// VPN Server に許可されているよりも多くのユーザーが存在する
			FreePack(p);
			c->Err = ERR_TOO_MANY_USER;
			goto CLEANUP;
		}

		// クライアント名など
		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");
		}
		c->ServerVer = CEDAR_VER;
		c->ServerBuild = CEDAR_BUILD;

		// NODE_INFO を取得する
		Zero(&node, sizeof(node));
		InRpcNodeInfo(&node, p);

		// プロトコル
		c->Protocol = GetProtocolFromPack(p);
		if (c->Protocol == CONNECTION_UDP)
		{
			// TCP 関係の構造体を解放する
			if (c->Tcp)
			{
				ReleaseList(c->Tcp->TcpSockList);
				Free(c->Tcp);
			}
		}

		if (GetServerCapsBool(c->Cedar->Server, "b_vpn_client_connect") == false)
		{
			// VPN クライアントが接続不可能である
			FreePack(p);
			c->Err = ERR_NOT_SUPPORTED;
			goto CLEANUP;
		}

		// ログイン
		if (GetHubnameAndUsernameFromPack(p, username, sizeof(username), hubname, sizeof(hubname)) == false)
		{
			// プロトコルエラー
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		if (farm_member)
		{
			bool ok = false;
			UINT authtype;

			authtype = GetAuthTypeFromPack(p);
			if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 &&
				authtype == AUTHTYPE_PASSWORD)
			{
				ok = true;
			}

			if (authtype == AUTHTYPE_TICKET)
			{
				ok = true;
			}

			if (ok == false)
			{
				// サーバーファームメンバへの Administrators 以外の直接ログオンは
				// 禁止されている
				FreePack(p);
				SLog(c->Cedar, "LS_FARMMEMBER_NOT_ADMIN", c->Name, hubname, ADMINISTRATOR_USERNAME, username);
				c->Err = ERR_ACCESS_DENIED;
				goto CLEANUP;
			}
		}

		Debug("Username = %s, HubName = %s\n", username, hubname);
		LockHubList(c->Cedar);
		{
			hub = GetHub(c->Cedar, hubname);
		}
		UnlockHubList(c->Cedar);
		if (hub == NULL)
		{
			// HUB が存在しない
			FreePack(p);
			c->Err = ERR_HUB_NOT_FOUND;
			SLog(c->Cedar, "LS_HUB_NOT_FOUND", c->Name, hubname);
			goto CLEANUP;
		}

		Lock(hub->lock);
		{
			USER *user;
			USERGROUP *group;
			if (hub->Halt || hub->Offline)
			{
				// HUB は停止中
				FreePack(p);
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_HUB_STOPPING;
				goto CLEANUP;
			}

			// 各種フラグの取得
			use_encrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
			use_compress = PackGetInt(p, "use_compress") == 0 ? false : true;
			max_connection = PackGetInt(p, "max_connection");
			half_connection = PackGetInt(p, "half_connection") == 0 ? false : true;
			use_fast_rc4 = PackGetInt(p, "use_fast_rc4") == 0 ? false : true;
			qos = PackGetInt(p, "qos") ? true : false;
			client_id = PackGetInt(p, "client_id");

			// 要求モード
			require_bridge_routing_mode = PackGetBool(p, "require_bridge_routing_mode");
			require_monitor_mode = PackGetBool(p, "require_monitor_mode");
			if (require_monitor_mode)
			{
				qos = false;
			}

			if (is_server_or_bridge)
			{
				require_bridge_routing_mode = true;
			}

			// クライアントユニーク ID
			Zero(unique, sizeof(unique));
			if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
			{
				PackGetData(p, "unique_id", unique);
			}

			// 認証方法の取得
			authtype = GetAuthTypeFromPack(p);

			if (1)
			{
				// ログ
				char ip1[64], ip2[64], verstr[64];
				wchar_t *authtype_str = _UU("LH_AUTH_UNKNOWN");
				switch (authtype)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					authtype_str = _UU("LH_AUTH_ANONYMOUS");
					break;
				case CLIENT_AUTHTYPE_PASSWORD:
					authtype_str = _UU("LH_AUTH_PASSWORD");
					break;
				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					authtype_str = _UU("LH_AUTH_PLAIN_PASSWORD");
					break;
				case CLIENT_AUTHTYPE_CERT:
					authtype_str = _UU("LH_AUTH_CERT");
					break;
				case AUTHTYPE_TICKET:
					authtype_str = _UU("LH_AUTH_TICKET");
					break;
				}
				IPToStr(ip1, sizeof(ip1), &c->FirstSock->RemoteIP);
				IPToStr(ip2, sizeof(ip2), &c->FirstSock->LocalIP);

				Format(verstr, sizeof(verstr), "%u.%02u", c->ClientVer / 100, c->ClientVer % 100);

				HLog(hub, "LH_CONNECT_CLIENT", c->Name, ip1, c->FirstSock->RemoteHostname, c->FirstSock->RemotePort,
					c->ClientStr, verstr, c->ClientBuild, authtype_str, username);
			}

			// まず匿名認証を試行する
			auth_ret = SamAuthUserByAnonymous(hub, username);

			if (auth_ret)
			{
				// ユーザー認証成功
				HLog(hub, "LH_AUTH_OK", c->Name, username);
			}

			if (auth_ret == false)
			{
				// 匿名認証に失敗した場合は他の認証方法を試行する
				switch (authtype)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					// 匿名認証 (すでに試行している)
					break;

				case AUTHTYPE_TICKET:
					// チケット認証
					if (PackGetDataSize(p, "ticket") == SHA1_SIZE)
					{
						PackGetData(p, "ticket", ticket);

						auth_ret = SiCheckTicket(hub, ticket, username, sizeof(username), username_real, sizeof(username_real),
							&ticketed_policy, sessionname, sizeof(sessionname), groupname, sizeof(groupname));
					}
					break;

				case CLIENT_AUTHTYPE_PASSWORD:
					// パスワード認証
					if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
					{
						POLICY *pol = NULL;
						UCHAR secure_password[SHA1_SIZE];
						Zero(secure_password, sizeof(secure_password));
						if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
						{
							PackGetData(p, "secure_password", secure_password);
						}
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password);

						pol = SamGetUserPolicy(hub, username);
						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}
					}
					break;

				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					// 外部サーバーによる認証はサポートされていない
					HLog(hub, "LH_AUTH_RADIUS_NOT_SUPPORT", c->Name, username);
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					goto CLEANUP;

				case CLIENT_AUTHTYPE_CERT:
					// 証明書認証はサポートされていない
					HLog(hub, "LH_AUTH_CERT_NOT_SUPPORT", c->Name, username);
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					goto CLEANUP;

				default:
					// 不明な認証方法
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					goto CLEANUP;
				}

				if (auth_ret == false)
				{
					// 認証失敗
					HLog(hub, "LH_AUTH_NG", c->Name, username);
				}
				else
				{
					// 認証成功
					HLog(hub, "LH_AUTH_OK", c->Name, username);
				}
			}

			if (auth_ret == false)
			{
				// 認証失敗
				Unlock(hub->lock);
				ReleaseHub(hub);
				FreePack(p);
				c->Err = ERR_AUTH_FAILED;
				goto CLEANUP;
			}
			else
			{
				if (authtype == CLIENT_AUTHTYPE_PASSWORD)
				{
					UCHAR test[SHA1_SIZE];
					HashPassword(test, username, "");
					if (Cmp(test, hub->SecurePassword, SHA1_SIZE) == 0)
					{
						SOCK *s = c->FirstSock;
						if (s != NULL)
						{
							if (GetHubAdminOption(hub, "deny_empty_password") != 0 ||
								(StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 && s->RemoteIP.addr[0] != 127))
							{
								// パスワードが空のとき、リモートから接続してはいけない
								HLog(hub, "LH_LOCAL_ONLY", c->Name, username);

								Unlock(hub->lock);
								ReleaseHub(hub);
								FreePack(p);
								c->Err = ERR_NULL_PASSWORD_LOCAL_ONLY;
								goto CLEANUP;
							}
						}
					}
				}
			}

			policy = NULL;

			// 認証成功
			FreePack(p);

			if (StrCmpi(username, ADMINISTRATOR_USERNAME) != 0)
			{
				// ポリシーを取得
				if (farm_member == false)
				{
					// ファームメンバ以外の場合
					user = AcGetUser(hub, username);
					if (user == NULL)
					{
						user = AcGetUser(hub, "*");
						if (user == NULL)
						{
							// ユーザー取得失敗
							Unlock(hub->lock);
							ReleaseHub(hub);
							c->Err = ERR_ACCESS_DENIED;
							goto CLEANUP;
						}
					}

					policy = NULL;

					Lock(user->lock);
					{
						// 有効期限を取得
						user_expires = user->ExpireTime;

						StrCpy(username_real, sizeof(username_real), user->Name);
						group = user->Group;
						if (group != NULL)
						{
							AddRef(group->ref);

							Lock(group->lock);
							{
								// グループ名を取得
								StrCpy(groupname, sizeof(groupname), group->Name);
							}
							Unlock(group->lock);
						}

						if (user->Policy != NULL)
						{
							policy = ClonePolicy(user->Policy);
						}
						else
						{
							if (group)
							{
								Lock(group->lock);
								{
									if (group->Policy != NULL)
									{
										policy = ClonePolicy(group->Policy);
									}
								}
								Unlock(group->lock);
							}
						}

						if (group != NULL)
						{
							ReleaseGroup(group);
						}
					}
					Unlock(user->lock);
					loggedin_user_object = user;
				}
				else
				{
					// ファームメンバの場合
					policy = ClonePolicy(&ticketed_policy);
				}
			}
			else
			{
				// 管理者モード
				admin_mode = true;
				StrCpy(username_real, sizeof(username_real), ADMINISTRATOR_USERNAME);

				policy = ClonePolicy(GetDefaultPolicy());
				policy->NoBroadcastLimiter = true;
				policy->MonitorPort = true;
			}

			if (policy == NULL)
			{
				// デフォルトのポリシーを使用する
				policy = ClonePolicy(GetDefaultPolicy());
			}

			if (policy->MaxConnection == 0)
			{
				policy->MaxConnection = MAX_TCP_CONNECTION;
			}

			if (policy->TimeOut == 0)
			{
				policy->TimeOut = 20;
			}

			if (qos)
			{
				// VoIP / QoS
				if (policy->NoQoS)
				{
					// ポリシーが許可していない
					qos = false;
				}
				if (GetServerCapsBool(c->Cedar->Server, "b_support_qos") == false)
				{
					// サーバーがサポートしていない
					qos = false;
					policy->NoQoS = true;
				}
				if (GetHubAdminOption(hub, "deny_qos") != 0)
				{
					// 管理オプションで禁止されている
					qos = false;
					policy->NoQoS = true;
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_download") != 0)
			{
				if (policy->MaxDownload == 0)
				{
					policy->MaxDownload = GetHubAdminOption(hub, "max_bitrates_download");
				}
				else
				{
					policy->MaxDownload = MIN(policy->MaxDownload, GetHubAdminOption(hub, "max_bitrates_download"));
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_upload") != 0)
			{
				if (policy->MaxUpload == 0)
				{
					policy->MaxUpload = GetHubAdminOption(hub, "max_bitrates_upload");
				}
				else
				{
					policy->MaxUpload = MIN(policy->MaxUpload, GetHubAdminOption(hub, "max_bitrates_upload"));
				}
			}

			if (GetHubAdminOption(hub, "deny_bridge") != 0)
			{
				policy->NoBridge = true;
			}

			if (GetHubAdminOption(hub, "deny_routing") != 0)
			{
				policy->NoRouting = true;
			}

			if (hub->Option->ClientMinimumRequiredBuild > c->ClientBuild &&
				 InStrEx(c->ClientStr, "client", false))
			{
				// クライアントのビルド番号が小さすぎる
				HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, hub->Option->ClientMinimumRequiredBuild);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_VERSION_INVALID;
				Free(policy);
				goto CLEANUP;
			}

			if (hub->Option->RequiredClientId != 0 &&
				hub->Option->RequiredClientId != client_id && 
				InStrEx(c->ClientStr, "client", false))
			{
				// クライアントのビルド番号が小さすぎる
				HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, client_id, hub->Option->RequiredClientId);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_CLIENT_ID_REQUIRED;
				Free(policy);
				goto CLEANUP;
			}

			if ((policy->NoSavePassword) || (policy->AutoDisconnect != 0))
			{
				if (c->ClientBuild < 6560 && InStrEx(c->ClientStr, "client", false))
				{
					// NoSavePassword ポリシーが指定されている場合は対応クライアント
					// でなければ接続できない
					HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, 6560);

					Unlock(hub->lock);
					ReleaseHub(hub);
					c->Err = ERR_VERSION_INVALID;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (user_expires != 0 && user_expires <= SystemTime64())
			{
				// 有効期限が切れている
				// アクセスが拒否されている
				HLog(hub, "LH_USER_EXPIRES", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_ACCESS_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (policy->Access == false)
			{
				// アクセスが拒否されている
				HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_ACCESS_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			// ポリシーの内容をクライアントが要求したオプションと比較して
			// 決定するか接続を拒否する
			// 最初にモニタポートモードで接続できるかどうか確認する
			if (require_monitor_mode && policy->MonitorPort == false)
			{
				// モニタポートモードで接続できない
				HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_MONITOR_MODE_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (policy->MonitorPort)
			{
				if (require_monitor_mode == false)
				{
					policy->MonitorPort = false;
				}
			}

			if (policy->MonitorPort)
			{
				qos = false;
			}

			// 次にブリッジ / ルーティングモードで接続できるか確認する
			if (require_bridge_routing_mode &&
				(policy->NoBridge && policy->NoRouting))
			{
				// ブリッジ / ルーティングモードで接続できない
				HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_BRIDGE_MODE_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (require_bridge_routing_mode == false)
			{
				policy->NoBridge = true;
				policy->NoRouting = true;
			}

			// ライセンスが必要かどうかチェック
			GenerateMachineUniqueHash(unique2);

			if (Cmp(unique, unique2, SHA1_SIZE) == 0)
			{
				// ローカルホストセッションである
				local_host_session = true;
			}
			else
			{
				if (license.NumUserLicense != INFINITE)
				{
					// ユーザー作成数が制限されているエディションでは多重ログイン禁止
					policy->MultiLogins = 1;
				}

				if (policy->NoBridge == false || policy->NoRouting == false)
				{
					// ブリッジライセンスを消費
					use_bridge_license = true;
				}
				else
				{
					// クライアントライセンスを消費
					use_client_license = true;
				}
			}

			if (server != NULL && server->ServerType != SERVER_TYPE_FARM_MEMBER &&
				(use_bridge_license || use_client_license))
			{
				// クラスタコントローラまたはスタンドアロンサーバーの場合で
				// クライアントにライセンスが必要になった場合、ここでライセンス数が
				// 足りているかどうかを計算する

				if (use_client_license)
				{
					if (server->CurrentAssignedClientLicense >= license.NumClientLicense)
					{
						// クライアント接続ライセンスが足りない
						Unlock(hub->lock);

						// 詳細エラーログを吐く
						HLog(hub, "LH_NOT_ENOUGH_CLIENT_LICENSE", c->Name,
							license.NumClientLicense,
							server->CurrentAssignedClientLicense + 1);

						ReleaseHub(hub);
						c->Err = ERR_CLIENT_LICENSE_NOT_ENOUGH;
						Free(policy);
						goto CLEANUP;
					}
				}
				if (use_bridge_license)
				{
					if (server->CurrentAssignedBridgeLicense >= license.NumBridgeLicense)
					{
						// ブリッジ接続ライセンス数が足りない
						Unlock(hub->lock);

						// 詳細エラーログを吐く
						HLog(hub, "LH_NOT_ENOUGH_BRIDGE_LICENSE", c->Name,
							license.NumBridgeLicense,
							server->CurrentAssignedBridgeLicense + 1);

						ReleaseHub(hub);
						c->Err = ERR_BRIDGE_LICENSE_NOT_ENOUGH;
						Free(policy);
						goto CLEANUP;
					}
				}
			}

			if (server != NULL && server->ServerType != SERVER_TYPE_FARM_MEMBER &&
				policy != NULL)
			{
				if (GetServerCapsBool(hub->Cedar->Server, "b_support_limit_multilogin"))
				{
					// ポリシーで多重ログイン制限数が指定されている場合は確認する
					RPC_ENUM_SESSION t;
					UINT i, num;
					UINT max_logins = policy->MultiLogins;
					UINT ao = GetHubAdminOption(hub, "max_multilogins_per_user");

					if (ao != 0)
					{
						if (max_logins != 0)
						{
							max_logins = MIN(max_logins, ao);
						}
						else
						{
							max_logins = ao;
						}
					}

					if (max_logins != 0)
					{
						Zero(&t, sizeof(t));
						StrCpy(t.HubName, sizeof(t.HubName), hub->Name);

						Unlock(hub->lock);

						SiEnumSessionMain(server, &t);

						Lock(hub->lock);

						num = 0;

						for (i = 0;i < t.NumSession;i++)
						{
							RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];

							if (e->BridgeMode == false && e->Layer3Mode == false && e->LinkMode == false && e->CurrentNumTcp != 0)
							{
								if (StrCmpi(e->Username, username) == 0 &&
									(IsZero(e->UniqueId, 16) || Cmp(e->UniqueId, node.UniqueId, 16) != 0))
								{
									num++;
								}
							}
						}

						FreeRpcEnumSession(&t);

						if (num >= max_logins)
						{
							// これ以上接続できない
							Unlock(hub->lock);

							// 詳細エラーログを吐く
							HLog(hub, license.NumUserLicense == INFINITE ? "LH_TOO_MANY_MULTILOGINS" : "LH_TOO_MANY_MULTILOGINS2",
								c->Name,
								username, max_logins, num);

							ReleaseHub(hub);
							c->Err = ERR_TOO_MANY_USER_SESSION;
							Free(policy);
							goto CLEANUP;
						}
					}
				}
			}

			if (loggedin_user_object != NULL)
			{
				// ユーザー情報の更新
				Lock(loggedin_user_object->lock);
				{
					loggedin_user_object->NumLogin++;
					loggedin_user_object->LastLoginTime = SystemTime64();
				}
				Unlock(loggedin_user_object->lock);
			}

			// ログイン回数を更新する
			hub->NumLogin++;
			hub->LastCommTime = hub->LastLoginTime = SystemTime64();

			if (farm_controller)
			{
				wchar_t *msg = GetHubMsg(hub);

				Unlock(hub->lock);

				Lock(cedar->CedarSuperLock);

				// ファームコントローラの場合、この HUB をホスティングする
				// ファームメンバを選定する
				LockList(server->FarmMemberList);
				{
					HLog(hub, "LH_FARM_SELECT_1", c->Name);
					f = SiGetHubHostingMember(server, hub, admin_mode);

					if (f == NULL)
					{
						// 選定に失敗した
						HLog(hub, "LH_FARM_SELECT_2", c->Name);
						UnlockList(server->FarmMemberList);
						Unlock(cedar->CedarSuperLock);
						ReleaseHub(hub);
						c->Err = ERR_COULD_NOT_HOST_HUB_ON_FARM;
						Free(policy);
						Free(msg);
						goto CLEANUP;
					}
					else
					{
						if (f->Me == false)
						{
							UCHAR ticket[SHA1_SIZE];
							PACK *p;
							BUF *b;
							UINT i;

							SLog(c->Cedar, "LH_FARM_SELECT_4", c->Name, f->hostname);

							// 選定したサーバーファームメンバにセッションを作成する
							Rand(ticket, sizeof(ticket));
							SiCallCreateTicket(server, f, hub->Name,
								username, username_real, policy, ticket, Inc(hub->SessionCounter), groupname);

							p = NewPack();
							PackAddInt(p, "Redirect", 1);
							PackAddIp32(p, "Ip", f->Ip);
							for (i = 0;i < f->NumPort;i++)
							{
								PackAddIntEx(p, "Port", f->Ports[i], i, f->NumPort);
							}
							PackAddData(p, "Ticket", ticket, sizeof(ticket));

							if (true)
							{
								char *utf = CopyUniToUtf(msg);

								PackAddData(p, "Msg", utf, StrLen(utf));

								Free(utf);
							}

							b = XToBuf(f->ServerCert, false);
							PackAddBuf(p, "Cert", b);
							FreeBuf(b);

							UnlockList(server->FarmMemberList);
							Unlock(cedar->CedarSuperLock);
							ReleaseHub(hub);

							HttpServerSend(c->FirstSock, p);
							FreePack(p);

							c->Err = 0;
							Free(policy);

							FreePack(HttpServerRecv(c->FirstSock));
							Free(msg);
							goto CLEANUP;
						}
						else
						{
							HLog(hub, "LH_FARM_SELECT_3", c->Name);
							// 自分自身が選定されたのでこのまま続ける
							UnlockList(server->FarmMemberList);
							Unlock(cedar->CedarSuperLock);
							f->Point = SiGetPoint(server);
							Lock(hub->lock);
							Free(msg);
						}
					}
				}
			}

			if (admin_mode == false)
			{
				// HUB の最大接続数をチェック
				if (hub->Option->MaxSession != 0 &&
					hub->Option->MaxSession <= Count(hub->NumSessions))
				{
					// これ以上接続できない
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_client_license || use_bridge_license)
			{
				// 仮想 HUB 管理オプションで規定された同時接続セッション数
				// の制限に抵触しないかどうか調べる
				if (
					(GetHubAdminOption(hub, "max_sessions") != 0 &&
					(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= GetHubAdminOption(hub, "max_sessions"))
					||
					(hub->Option->MaxSession != 0 &&
					(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= hub->Option->MaxSession))
				{
					// これ以上接続できない
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, GetHubAdminOption(hub, "max_sessions"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_client_license)
			{
				// 仮想 HUB 管理オプションで規定された同時接続セッション数 (クライアント)
				// の制限に抵触しないかどうか調べる
				if (((GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 || license.CarrierEdition) &&
					Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client") && hub->Cedar->Server != NULL && hub->Cedar->Server->ServerType != SERVER_TYPE_FARM_MEMBER)
					||
					(hub->FarmMember_MaxSessionClientBridgeApply &&
					Count(hub->NumSessionsClient) >= hub->FarmMember_MaxSessionClient))
				{
					// これ以上接続できない
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_bridge_license)
			{
				// 仮想 HUB 管理オプションで規定された同時接続セッション数 (ブリッジ)
				// の制限に抵触しないかどうか調べる
				if (((GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 || license.CarrierEdition) &&
					Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge") && hub->Cedar->Server != NULL && hub->Cedar->Server->ServerType != SERVER_TYPE_FARM_MEMBER)
					||
					(hub->FarmMember_MaxSessionClientBridgeApply &&
					Count(hub->NumSessionsBridge) >= hub->FarmMember_MaxSessionBridge))
				{
					// これ以上接続できない
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (Count(hub->Cedar->CurrentSessions) >= GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"))
			{
				// これ以上接続できない
				Unlock(hub->lock);

				HLog(hub, "LH_MAX_SESSION_2", c->Name, GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"));

				ReleaseHub(hub);
				c->Err = ERR_HUB_IS_BUSY;
				Free(policy);
				goto CLEANUP;
			}

			// 現在の接続数をインクリメント
			Inc(hub->NumSessions);
			if (use_bridge_license)
			{
				Inc(hub->NumSessionsBridge);
			}

			if (use_client_license)
			{
				Inc(hub->NumSessionsClient);
			}
			Inc(hub->Cedar->CurrentSessions);

			// タイムアウト時間を計算
			timeout = policy->TimeOut * 1000;	// ミリ秒 → 秒 に変換
			if (timeout == 0)
			{
				timeout = TIMEOUT_DEFAULT;
			}
			timeout = MIN(timeout, TIMEOUT_MAX);
			timeout = MAX(timeout, TIMEOUT_MIN);

			// ポリシーに応じて max_connection を更新
			max_connection = MIN(max_connection, policy->MaxConnection);
			max_connection = MIN(max_connection, MAX_TCP_CONNECTION);
			max_connection = MAX(max_connection, 1);
			if (half_connection)
			{
				// Half Connection 時にはコネクション数は 2 以上とする
				max_connection = MAX(max_connection, 2);
			}

			if (qos)
			{
				// VoIP / QoS 使用時にはコネクション数は 2 以上とする
				max_connection = MAX(max_connection, 2);
				if (half_connection)
				{
					max_connection = MAX(max_connection, 4);
				}
			}

			c->Status = CONNECTION_STATUS_ESTABLISHED;

			// コネクションを Cedar から削除
			DelConnection(c->Cedar, c);

			// セッションの作成
			StrLower(username);
			s = NewServerSession(c->Cedar, c, hub, username, policy);

			if (server != NULL)
			{
				s->NoSendSignature = server->NoSendSignature;
			}

			s->UseClientLicense = use_client_license;
			s->UseBridgeLicense = use_bridge_license;

			s->IsBridgeMode = (policy->NoBridge == false) || (policy->NoRouting == false);
			s->IsMonitorMode = policy->MonitorPort;

			// IPv6 セッションかどうかの判定
			s->IPv6Session = false;

			if (node.ClientIpAddress == 0)
			{
				s->IPv6Session = true;
			}

			if (use_bridge_license)
			{
				Inc(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Inc(s->Cedar->AssignedClientLicense);
			}

			if (server != NULL)
			{
				// Server 構造体の合計割り当て済みライセンス数の更新
				if (server->ServerType == SERVER_TYPE_STANDALONE)
				{
					// スタンドアロンモードのみ更新
					// (クラスタコントローラモードでは定期的にポーリングしている)
					server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
					server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
				}
			}

			if (StrLen(sessionname) != 0)
			{
				// セッション名の指定
				Free(s->Name);
				s->Name = CopyStr(sessionname);
			}

			{
				char ip[128];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_NEW_SESSION", c->Name, s->Name, ip, c->FirstSock->RemotePort);
			}

			c->Session = s;
			s->AdministratorMode = admin_mode;
			StrCpy(s->UserNameReal, sizeof(s->UserNameReal), username_real);
			StrCpy(s->GroupName, sizeof(s->GroupName), groupname);

			// セッションキーの取得
			Copy(session_key, s->SessionKey, SHA1_SIZE);

			// パラメータをセット
			s->MaxConnection = max_connection;
			s->UseEncrypt = use_encrypt;
			if (s->UseEncrypt && use_fast_rc4)
			{
				s->UseFastRC4 = use_fast_rc4;
			}
			s->UseCompress = use_compress;
			s->HalfConnection = half_connection;
			s->Timeout = timeout;
			s->QoS = qos;

			if (policy != NULL)
			{
				s->VLanId = policy->VLanId;
			}

			// ユーザー名
			s->Username = CopyStr(username);

			HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
				s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
				s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
				s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
				s->Timeout / 1000);

			msg = GetHubMsg(hub);
		}
		Unlock(hub->lock);

		// クライアントに Welcome パケットを送信
		p = PackWelcome(s);

		if (true)
		{
			// VPN Client に表示するメッセージ
			char *utf;
			wchar_t winver_msg_client[3800];
			wchar_t winver_msg_server[3800];
			wchar_t *utvpn_msg;
			UINT tmpsize;
			wchar_t *tmp;
			RPC_WINVER server_winver;

			GetWinVer(&server_winver);

			Zero(winver_msg_client, sizeof(winver_msg_client));
			Zero(winver_msg_server, sizeof(winver_msg_server));

			utvpn_msg = _UU("UTVPN_MSG");

			if (IsSupportedWinVer(&winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_LOCAL"),
					winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_LOCAL"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			if (IsSupportedWinVer(&server_winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_server, sizeof(winver_msg_server), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_REMOTE"),
					server_winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_REMOTE"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			tmpsize = UniStrSize(winver_msg_client) + UniStrSize(winver_msg_server) + UniStrSize(utvpn_msg) + UniStrSize(msg) * 100;

			tmp = ZeroMalloc(tmpsize);

			if (IsURLMsg(msg, NULL, 0) == false)
			{
				UniStrCat(tmp, tmpsize, utvpn_msg);
				UniStrCat(tmp, tmpsize, winver_msg_client);
				UniStrCat(tmp, tmpsize, winver_msg_server);
			}
			UniStrCat(tmp, tmpsize, msg);
			
			utf = CopyUniToUtf(tmp);

			PackAddData(p, "Msg", utf, StrLen(utf));

			Free(tmp);
			Free(utf);
		}

		Free(msg);

		if (s->UseFastRC4)
		{
			// RC4 キーペアを生成
			GenerateRC4KeyPair(&key_pair);

			// Welcome パケットに追加
			PackAddData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey, sizeof(key_pair.ClientToServerKey));
			PackAddData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey, sizeof(key_pair.ServerToClientKey));
			{
				char key1[64], key2[64];
				BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
				BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
				Debug(
					"Client to Server Key: %s\n"
					"Server to Client Key: %s\n",
					key1, key2);
			}
		}
		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		Copy(&c->Session->NodeInfo, &node, sizeof(NODE_INFO));
		{
			wchar_t tmp[MAX_SIZE * 2];
			NodeInfoToStr(tmp, sizeof(tmp), &s->NodeInfo);

			HLog(hub, "LH_NODE_INFO", s->Name, tmp);
		}

		// コネクションをトンネリングモードに移行
		StartTunnelingMode(c);

		// ハーフコネクションモード時の処理
		if (s->HalfConnection)
		{
			// 1 つ目のソケットはクライアント→サーバー 方向 とする
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			ts->Direction = TCP_CLIENT_TO_SERVER;
		}

		if (s->UseFastRC4)
		{
			// 1 つ目の TCP コネクションに RC4 キー情報をセットする
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			Copy(&ts->Rc4KeyPair, &key_pair, sizeof(RC4_KEY_PAIR));

			InitTcpSockRc4Key(ts, true);
		}

		if (s->UseEncrypt && s->UseFastRC4 == false)
		{
			s->UseSSLDataEncryption = true;
		}
		else
		{
			s->UseSSLDataEncryption = false;
		}

		if (s->Hub->Type == HUB_TYPE_FARM_DYNAMIC && s->Cedar->Server != NULL && s->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			if (s->Hub->BeingOffline == false)
			{
				// ダイナミック仮想 HUB で SecureNAT を開始
				EnableSecureNATEx(s->Hub, false, true);

				cluster_dynamic_secure_nat = true;
			}
		}

		// セッションのメインルーチン
		SessionMain(s);

		// 現在の接続数をデクリメント
		Lock(s->Hub->lock);
		{
			if (use_bridge_license)
			{
				Dec(hub->NumSessionsBridge);
			}

			if (use_client_license)
			{
				Dec(hub->NumSessionsClient);
			}

			Dec(s->Hub->NumSessions);
			Dec(s->Hub->Cedar->CurrentSessions);

			// ライセンス数のデクリメント
			if (use_bridge_license)
			{
				Dec(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Dec(s->Cedar->AssignedClientLicense);
			}

			if (server != NULL)
			{
				// Server 構造体の合計割り当て済みライセンス数の更新
				if (server->ServerType == SERVER_TYPE_STANDALONE)
				{
					// スタンドアロンモードのみ更新
					// (クラスタコントローラモードでは定期的にポーリングしている)
					server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
					server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
				}
			}
		}
		Unlock(s->Hub->lock);

		PrintSessionTotalDataSize(s);

		HLog(s->Hub, "LH_END_SESSION", s->Name, s->TotalSendSizeReal, s->TotalRecvSizeReal);

		if (cluster_dynamic_secure_nat && s->Hub->BeingOffline == false)
		{
			// ダイナミック仮想 HUB で SecureNAT を停止
			EnableSecureNATEx(s->Hub, false, true);
		}

		ReleaseSession(s);

		ret = true;
		c->Err = ERR_SESSION_REMOVED;

		ReleaseHub(hub);

		goto CLEANUP;
	}
	else if (StrCmpi(method, "additional_connect") == 0)
	{
		SOCK *sock;
		TCPSOCK *ts;
		UINT dummy;

		c->Type = CONNECTION_TYPE_ADDITIONAL;

		// 追加接続
		// セッションキーを読み出し
		if (GetSessionKeyFromPack(p, session_key, &dummy) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		FreePack(p);

		// セッションキーからセッションを取得
		s = GetSessionFromKey(c->Cedar, session_key);
		if (s == NULL || s->Halt)
		{
			// セッションが発見できない
			Debug("Session Not Found.\n");
			c->Err = ERR_SESSION_TIMEOUT;
			goto CLEANUP;
		}

		// セッションが見つかった
		Debug("Session Found: %s\n", s->Name);
		// セッションのプロトコルを確認
		c->Err = 0;
		Lock(s->lock);
		{
			if (s->Connection->Protocol != CONNECTION_TCP)
			{
				c->Err = ERR_INVALID_PROTOCOL;
			}
		}
		Unlock(s->lock);
		// セッションの現在のコネクション数を調べる
		Lock(s->Connection->lock);
		if (c->Err == 0)
		{
			if (Count(s->Connection->CurrentNumConnection) > s->MaxConnection)
			{
				c->Err = ERR_TOO_MANY_CONNECTION;
			}
		}
		if (c->Err != 0)
		{
			Unlock(s->Connection->lock);
			if (c->Err == ERR_TOO_MANY_CONNECTION)
			{
				Debug("Session TOO MANY CONNECTIONS !!: %u\n",
					Count(s->Connection->CurrentNumConnection));
			}
			else
			{
				Debug("Session Invalid Protocol.\n");
			}
			ReleaseSession(s);
			goto CLEANUP;
		}

		// RC4 高速暗号化鍵の生成
		if (s->UseFastRC4)
		{
			GenerateRC4KeyPair(&key_pair);
		}

		// セッションのコネクションリスト (TCP) にこのコネクションのソケットを追加する
		sock = c->FirstSock;
		ts = NewTcpSock(sock);
		SetTimeout(sock, CONNECTING_TIMEOUT);
		direction = TCP_BOTH;
		LockList(s->Connection->Tcp->TcpSockList);
		{
			if (s->HalfConnection)
			{
				// ハーフコネクション時、現在のすべての TCP コネクションの方向を
				// 調べて自動的に調整する
				UINT i, c2s, s2c;
				c2s = s2c = 0;
				for (i = 0;i < LIST_NUM(s->Connection->Tcp->TcpSockList);i++)
				{
					TCPSOCK *ts = (TCPSOCK *)LIST_DATA(s->Connection->Tcp->TcpSockList, i);
					if (ts->Direction == TCP_SERVER_TO_CLIENT)
					{
						s2c++;
					}
					else
					{
						c2s++;
					}
				}
				if (s2c > c2s)
				{
					direction = TCP_CLIENT_TO_SERVER;
				}
				else
				{
					direction = TCP_SERVER_TO_CLIENT;
				}
				Debug("%u/%u\n", s2c, c2s);
				ts->Direction = direction;
			}
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		if (s->UseFastRC4)
		{
			// RC4 鍵情報の設定
			Copy(&ts->Rc4KeyPair, &key_pair, sizeof(RC4_KEY_PAIR));

			InitTcpSockRc4Key(ts, true);
		}

		// 成功結果を返す
		p = PackError(ERR_NO_ERROR);
		PackAddInt(p, "direction", direction);

		if (s->UseFastRC4)
		{
			// RC4 鍵情報の追加
			PackAddData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey, sizeof(key_pair.ClientToServerKey));
			PackAddData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey, sizeof(key_pair.ServerToClientKey));
			{
				char key1[64], key2[64];
				BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
				BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
				Debug(
					"Client to Server Key: %s\n"
					"Server to Client Key: %s\n",
					key1, key2);
			}
		}

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		SetTimeout(sock, INFINITE);

		LockList(s->Connection->Tcp->TcpSockList);
		{
			Add(s->Connection->Tcp->TcpSockList, ts);
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		// コネクション数をインクリメントする
		Inc(s->Connection->CurrentNumConnection);
		Debug("TCP Connection Incremented: %u\n", Count(s->Connection->CurrentNumConnection));

		// セッションの Cancel を発行する
		Cancel(s->Cancel1);

		Unlock(s->Connection->lock);

		c->flag1 = true;

		ReleaseSession(s);

		return true;
	}
	else if (StrCmpi(method, "enum_hub") == 0)
	{
		// 仮想 HUB の列挙
		UINT i, num;
		LIST *o;
		o = NewListFast(NULL);

		c->Type = CONNECTION_TYPE_ENUM_HUB;

		FreePack(p);
		p = NewPack();
		LockList(c->Cedar->HubList);
		{
			num = LIST_NUM(c->Cedar->HubList);
			for (i = 0;i < num;i++)
			{
				HUB *h = LIST_DATA(c->Cedar->HubList, i);
				if (h->Option != NULL && h->Option->NoEnum == false)
				{
					Insert(o, CopyStr(h->Name));
				}
			}
		}
		UnlockList(c->Cedar->HubList);

		num = LIST_NUM(o);
		for (i = 0;i < num;i++)
		{
			char *name = LIST_DATA(o, i);
			PackAddStrEx(p, "HubName", name, i, num);
			Free(name);
		}
		ReleaseList(o);
		PackAddInt(p, "NumHub", num);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);
		FreePack(HttpServerRecv(c->FirstSock));
		c->Err = 0;

		SLog(c->Cedar, "LS_ENUM_HUB", c->Name, num);

		goto CLEANUP;
	}
	else if (StrCmpi(method, "farm_connect") == 0)
	{
		// サーバーファーム接続要求
		CEDAR *cedar = c->Cedar;
		c->Type = CONNECTION_TYPE_FARM_RPC;
		c->Err = 0;
		if (c->Cedar->Server == NULL)
		{
			// サポートされていない
			c->Err = ERR_NOT_FARM_CONTROLLER;
		}
		else
		{
			SERVER *s = c->Cedar->Server;
			if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER || s->FarmControllerInited == false)
			{
				// ファームコントローラではない
				SLog(c->Cedar, "LS_FARM_ACCEPT_1", c->Name);
				c->Err = ERR_NOT_FARM_CONTROLLER;
			}
			else
			{
				UCHAR check_secure_password[SHA1_SIZE];
				UCHAR secure_password[SHA1_SIZE];
				// ユーザー認証
				SecurePassword(check_secure_password, s->HashedPassword, c->Random);
				if (PackGetDataSize(p, "SecurePassword") == sizeof(secure_password))
				{
					PackGetData(p, "SecurePassword", secure_password);
				}
				else
				{
					Zero(secure_password, sizeof(secure_password));
				}

				if (Cmp(secure_password, check_secure_password, SHA1_SIZE) != 0)
				{
					// パスワードが違う
					SLog(c->Cedar, "LS_FARM_ACCEPT_2", c->Name);
					c->Err = ERR_ACCESS_DENIED;
				}
				else
				{
					// 証明書を取得する
					BUF *b;
					X *server_x;

					SLog(c->Cedar, "LS_FARM_ACCEPT_3", c->Name);
					b = PackGetBuf(p, "ServerCert");
					if (b == NULL)
					{
						c->Err = ERR_PROTOCOL_ERROR;
					}
					else
					{
						server_x = BufToX(b, false);
						FreeBuf(b);
						if (server_x == NULL)
						{
							c->Err = ERR_PROTOCOL_ERROR;
						}
						else
						{
							UINT ip;
							UINT point;
							char hostname[MAX_SIZE];

#ifdef	OS_WIN32
							MsSetThreadPriorityRealtime();
#endif	// OS_WIN32

							SetTimeout(c->FirstSock, SERVER_CONTROL_TCP_TIMEOUT);

							ip = PackGetIp32(p, "PublicIp");
							point = PackGetInt(p, "Point");
							if (PackGetStr(p, "HostName", hostname, sizeof(hostname)))
							{
								UINT num_port = PackGetIndexCount(p, "PublicPort");
								if (num_port >= 1 && num_port <= MAX_PUBLIC_PORT_NUM)
								{
									UINT *ports = ZeroMalloc(sizeof(UINT) * num_port);
									UINT i;

									for (i = 0;i < num_port;i++)
									{
										ports[i] = PackGetIntEx(p, "PublicPort", i);
									}

									SiFarmServ(s, c->FirstSock, server_x, ip, num_port, ports, hostname, point,
										PackGetInt(p, "Weight"), PackGetInt(p, "MaxSessions"));

									Free(ports);
								}
							}

							FreeX(server_x);
						}
					}
				}
			}
		}
		FreePack(p);
		goto CLEANUP;
	}
	else if (StrCmpi(method, "admin") == 0 && c->Cedar->Server != NULL)
	{
		UINT err;
		// 管理用 RPC 接続要求
		c->Type = CONNECTION_TYPE_ADMIN_RPC;
		err = AdminAccept(c, p);
		FreePack(p);
		if (err != ERR_NO_ERROR)
		{
			PACK *p = PackError(err);
			HttpServerSend(c->FirstSock, p);
			FreePack(p);
		}
		goto CLEANUP;
	}
	else if (StrCmpi(method, "password") == 0)
	{
		UINT err;
		// パスワード変更要求
		c->Type = CONNECTION_TYPE_PASSWORD;
		err = ChangePasswordAccept(c, p);
		FreePack(p);

		p = PackError(err);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);
		goto CLEANUP;
	}
	else
	{
		// 不明なメソッド
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

CLEANUP:
	// ユーザーオブジェクトの解放
	if (loggedin_user_object != NULL)
	{
		ReleaseUser(loggedin_user_object);
	}

	// エラーパケット送信
	p = PackError(c->Err);
	PackAddBool(p, "no_save_password", no_save_password);
	HttpServerSend(c->FirstSock, p);
	FreePack(p);

	SLog(c->Cedar, "LS_CONNECTION_ERROR", c->Name, GetUniErrorStr(c->Err), c->Err);

	return ret;
}
// シグネチャの送信 (TCP パケット) 用スレッド
void SendSignatureByTcpThread(THREAD *thread, void *param)
{
	BUF *buf;
	SEND_SIGNATURE_PARAM *p;
	SOCK *s;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	p = (SEND_SIGNATURE_PARAM *)param;

	AddWaitThread(thread);
	NoticeThreadInit(thread);

	buf = p->Buffer;

	s = Connect(p->Hostname, p->Port);

	if (s != NULL)
	{
		SendAll(s, buf->Buf, buf->Size, false);

		Disconnect(s);
		ReleaseSock(s);
	}

	DelWaitThread(thread);

	FreeBuf(buf);
	Free(p);
}

// シグネチャの送信 (TCP パケット)
void SendSignatureByTcp(CONNECTION *c, IP *ip)
{
	NODE_INFO info;
	BUF *b;
	SEND_SIGNATURE_PARAM *param;
	THREAD *t;
	// 引数チェック
	if (c == NULL || ip == NULL)
	{
		return;
	}

	if (c->Session == NULL || c->Session->ClientOption == NULL)
	{
		return;
	}

	CreateNodeInfo(&info, c);

	b = NewBuf();
	WriteBuf(b, CEDAR_SIGNATURE_STR, StrLen(CEDAR_SIGNATURE_STR));
	SeekBuf(b, 0, 0);

	param = ZeroMalloc(sizeof(SEND_SIGNATURE_PARAM));
	param->Buffer = b;

	if (c->Session != NULL && c->Session->ClientOption != NULL)
	{
		CLIENT_OPTION *o = c->Session->ClientOption;

		if (o->ProxyType == PROXY_DIRECT)
		{
			IPToStr(param->Hostname, sizeof(param->Hostname), ip);
			param->Port = o->Port;
		}
		else
		{
			StrCpy(param->Hostname, sizeof(param->Hostname), o->ProxyName);
			param->Port = o->ProxyPort;
		}
	}

	t = NewThread(SendSignatureByTcpThread, param);
	WaitThreadInit(t);
	ReleaseThread(t);
}

// ノード情報の作成
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c)
{
	SESSION *s;
	OS_INFO *os;
	char *product_id;
	IP ip;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	os = GetOsInfo();

	Zero(info, sizeof(NODE_INFO));

	// クライアント製品名
	StrCpy(info->ClientProductName, sizeof(info->ClientProductName), c->ClientStr);
	// クライアントバージョン
	info->ClientProductVer = Endian32(c->ClientVer);
	// クライアントビルド番号
	info->ClientProductBuild = Endian32(c->ClientBuild);

	// サーバー製品名
	StrCpy(info->ServerProductName, sizeof(info->ServerProductName), c->ServerStr);
	// サーバーバージョン
	info->ServerProductVer = Endian32(c->ServerVer);
	// サーバービルド番号
	info->ServerProductBuild = Endian32(c->ServerBuild);

	// クライアント OS 名
	StrCpy(info->ClientOsName, sizeof(info->ClientOsName), os->OsProductName);
	// クライアント OS バージョン
	StrCpy(info->ClientOsVer, sizeof(info->ClientOsVer), os->OsVersion);
	// クライアント OS プロダクト ID
	product_id = OSGetProductId();
	StrCpy(info->ClientOsProductId, sizeof(info->ClientOsProductId), product_id);
	Free(product_id);

	// クライアントホスト名
	GetMachineName(info->ClientHostname, sizeof(info->ClientHostname));
	// クライアント IP アドレス
	if (IsIP6(&c->FirstSock->LocalIP) == false)
	{
		info->ClientIpAddress = IPToUINT(&c->FirstSock->LocalIP);
	}
	else
	{
		Copy(info->ClientIpAddress6, c->FirstSock->LocalIP.ipv6_addr, sizeof(info->ClientIpAddress6));
	}
	// クライアントポート番号
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	// サーバーホスト名
	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	// サーバー IP アドレス
	if (GetIP(&ip, info->ServerHostname))
	{
		if (IsIP6(&ip) == false)
		{
			info->ServerIpAddress = IPToUINT(&ip);
		}
		else
		{
			Copy(info->ServerIpAddress6, ip.ipv6_addr, sizeof(info->ServerIpAddress6));
		}
	}
	// サーバーポート番号
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP)
	{
		// プロキシホスト名
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		// プロキシ IP アドレス
		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ProxyIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(&info->ProxyIpAddress6, c->FirstSock->RemoteIP.ipv6_addr, sizeof(info->ProxyIpAddress6));
		}

		info->ProxyPort = Endian32(c->FirstSock->RemotePort);
	}

	// HUB 名
	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	// ユニーク ID
	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

// ソケットを追加接続する
SOCK *ClientAdditionalConnectToServer(CONNECTION *c)
{
	SOCK *s;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	// ソケット接続
	s = ClientConnectGetSocket(c, true);
	if (s == NULL)
	{
		// 接続失敗
		return NULL;
	}

	// ソケットをリストに追加する
	LockList(c->ConnectingSocks);
	{
		Add(c->ConnectingSocks, s);
		AddRef(s->ref);
	}
	UnlockList(c->ConnectingSocks);

	if (c->Session->Halt)
	{
		// 停止
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	// タイムアウト
	SetTimeout(s, CONNECTING_TIMEOUT);

	// SSL 通信開始
	if (StartSSLEx(s, NULL, NULL, (c->DontUseTls1 ? false : true)) == false)
	{
		// SSL 通信失敗
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	// 証明書のチェック
	if (CompareX(s->RemoteX, c->ServerX) == false)
	{
		// 証明書が不正
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
	}

	return s;
}

// セキュアデバイス内の証明書と鍵を削除する
UINT SecureDelete(UINT device_id, char *pin, char *cert_name, char *key_name)
{
	SECURE *sec;
	// 引数チェック
	if (pin == NULL || device_id == 0)
	{
		return ERR_INTERNAL_ERROR;
	}

	// デバイスを開く
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// セッションを開く
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// ログイン
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// 証明書削除
	if (cert_name != NULL)
	{
		DeleteSecCert(sec, cert_name);
	}

	// 秘密鍵削除
	if (key_name != NULL)
	{
		DeleteSecKey(sec, key_name);
	}

	// ログアウト
	LogoutSec(sec);

	// セッションを閉じる
	CloseSecSession(sec);

	// デバイスを閉じる
	CloseSec(sec);

	return ERR_NO_ERROR;
}

// セキュアデバイス内の証明書と鍵を列挙する
UINT SecureEnum(UINT device_id, char *pin, TOKEN_LIST **cert_list, TOKEN_LIST **key_list)
{
	SECURE *sec;
	LIST *o;
	LIST *cert_name_list, *key_name_list;
	// 引数チェック
	if (pin == NULL || device_id == 0 || cert_list == NULL || key_list == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// デバイスを開く
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// セッションを開く
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// ログイン
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// オブジェクトの列挙
	if ((o = EnumSecObject(sec)) != NULL)
	{
		UINT i;

		cert_name_list = NewList(CompareStr);
		key_name_list = NewList(CompareStr);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SEC_OBJ *obj = LIST_DATA(o, i);

			if (obj->Type == SEC_X)
			{
				Add(cert_name_list, CopyStr(obj->Name));
			}
			else if (obj->Type == SEC_K)
			{
				Add(key_name_list, CopyStr(obj->Name));
			}
		}

		Sort(cert_name_list);
		Sort(key_name_list);

		*cert_list = ListToTokenList(cert_name_list);
		*key_list = ListToTokenList(key_name_list);

		// メモリ解放
		FreeStrList(cert_name_list);
		FreeStrList(key_name_list);
		FreeEnumSecObject(o);
	}
	else
	{
		*cert_list = NullToken();
		*key_list = NullToken();
	}

	// ログアウト
	LogoutSec(sec);

	// セッションを閉じる
	CloseSecSession(sec);

	// デバイスを閉じる
	CloseSec(sec);

	return ERR_NO_ERROR;
}

// セキュアデバイスに証明書と鍵を記録する
UINT SecureWrite(UINT device_id, char *cert_name, X *x, char *key_name, K *k, char *pin)
{
	SECURE *sec;
	bool failed;
	// 引数チェック
	if (pin == NULL || device_id == 0 || cert_name == NULL || x == NULL || key_name == NULL || k == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// デバイスを開く
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// セッションを開く
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// ログイン
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// 登録
	failed = false;

	// 証明書の登録
	if (WriteSecCert(sec, true, cert_name, x) == false)
	{
		failed = true;
	}

	// 秘密鍵の登録
	if (WriteSecKey(sec, true, key_name, k) == false)
	{
		failed = true;
	}

	// ログアウト
	LogoutSec(sec);

	// セッションを閉じる
	CloseSecSession(sec);

	// デバイスを閉じる
	CloseSec(sec);

	if (failed == false)
	{
		// 成功
		return ERR_NO_ERROR;
	}
	else
	{
		// 失敗
		return ERR_SECURE_CANT_WRITE;
	}
}

// セキュアデバイスによる署名を試行する
UINT SecureSign(SECURE_SIGN *sign, UINT device_id, char *pin)
{
	SECURE *sec;
	X *x;
	// 引数チェック
	if (sign == false || pin == NULL || device_id == 0)
	{
		return ERR_INTERNAL_ERROR;
	}

	// デバイスを開く
	sec = OpenSec(device_id);
	if (sec == NULL)
	{
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// セッションを開く
	if (OpenSecSession(sec, 0) == false)
	{
		CloseSec(sec);
		return ERR_SECURE_DEVICE_OPEN_FAILED;
	}

	// ログイン
	if (LoginSec(sec, pin) == false)
	{
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_PIN_LOGIN_FAILED;
	}

	// 証明書の読み込み
	x = ReadSecCert(sec, sign->SecurePublicCertName);
	if (x == NULL)
	{
		LogoutSec(sec);
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_NO_CERT;
	}

	// 秘密鍵による署名
	if (SignSec(sec, sign->SecurePrivateKeyName, sign->Signature, sign->Random, SHA1_SIZE) == false)
	{
		// 署名失敗
		FreeX(x);
		LogoutSec(sec);
		CloseSecSession(sec);
		CloseSec(sec);
		return ERR_SECURE_NO_PRIVATE_KEY;
	}

	// 証明書をバッファに変換
	sign->ClientCert = x;

	// ログアウト
	LogoutSec(sec);

	// セッションを閉じる
	CloseSecSession(sec);

	// デバイスを閉じる
	CloseSec(sec);

	// 成功
	return ERR_NO_ERROR;
}

// クライアントがサーバーに追加接続する
bool ClientAdditionalConnect(CONNECTION *c, THREAD *t)
{
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;
	RC4_KEY_PAIR key_pair;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	// サーバーにソケット接続
	s = ClientAdditionalConnectToServer(c);
	if (s == NULL)
	{
		// ソケット接続に失敗
		return false;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	// シグネチャを送信
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// 停止
		goto CLEANUP;
	}

	// Hello パケットを受信
	Debug("Downloading Hello...\n");
	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// 停止
		goto CLEANUP;
	}

	// 追加接続用の認証データを送信
	if (ClientUploadAuth2(c, s) == false)
	{
		// 切断された
		goto CLEANUP;
	}

	// 応答を受信
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// 切断された
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	if (c->Session->UseFastRC4)
	{
		// RC4 鍵情報の取得
		if (PackGetDataSize(p, "rc4_key_client_to_server") == 16)
		{
			PackGetData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey);
		}
		if (PackGetDataSize(p, "rc4_key_server_to_client") == 16)
		{
			PackGetData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey);
		}
		{
			char key1[64], key2[64];
			BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
			BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
			Debug(
				"Client to Server Key: %s\n"
				"Server to Client Key: %s\n",
				key1, key2);
		}
	}

	FreePack(p);
	p = NULL;

	if (err != 0)
	{
		// エラーが発生した
		Debug("Additional Connect Error: %u\n", err);
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL)
		{
			// 致命的なエラーなので再接続しなおすことにする
			c->Session->SessionTimeOuted = true;
		}
		goto CLEANUP;
	}

	Debug("Additional Connect Succeed!\n");

	// 追加接続成功
	// コネクションの TcpSockList に追加する
	ts = NewTcpSock(s);

	if (c->ServerMode == false)
	{
		if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
		{
			ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
		}
	}

	LockList(c->Tcp->TcpSockList);
	{
		ts->Direction = direction;
		Add(c->Tcp->TcpSockList, ts);
	}
	UnlockList(c->Tcp->TcpSockList);
	Debug("TCP Connection Incremented: %u\n", Count(c->CurrentNumConnection));

	if (c->Session->HalfConnection)
	{
		Debug("New Half Connection: %s\n",
			direction == TCP_SERVER_TO_CLIENT ? "TCP_SERVER_TO_CLIENT" : "TCP_CLIENT_TO_SERVER"
			);
	}

	if (c->Session->UseFastRC4)
	{
		// RC4 暗号化鍵のセット
		Copy(&ts->Rc4KeyPair, &key_pair, sizeof(RC4_KEY_PAIR));

		InitTcpSockRc4Key(ts, false);
	}

	// セッションに Cancel を発行する
	Cancel(c->Session->Cancel1);

	// 接続中のソケット一覧からこのソケットを削除
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return true;

CLEANUP:
	// 切断処理
	Disconnect(s);
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);

		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return false;
}

// セキュアデバイス署名スレッド
void ClientSecureSignThread(THREAD *thread, void *param)
{
	SECURE_SIGN_THREAD_PROC *p = (SECURE_SIGN_THREAD_PROC *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	NoticeThreadInit(thread);

	p->Ok = p->SecureSignProc(p->Connection->Session, p->Connection, p->SecureSign);
	p->UserFinished = true;
}

// セキュアデバイスを使用した署名
bool ClientSecureSign(CONNECTION *c, UCHAR *sign, UCHAR *random, X **x)
{
	SECURE_SIGN_THREAD_PROC *p;
	SECURE_SIGN *ss;
	SESSION *s;
	CLIENT_OPTION *o;
	CLIENT_AUTH *a;
	THREAD *thread;
	UINT64 start;
	bool ret;
	// 引数チェック
	if (c == NULL || sign == NULL || random == NULL || x == NULL)
	{
		return false;
	}

	s = c->Session;
	o = s->ClientOption;
	a = s->ClientAuth;

	p = ZeroMalloc(sizeof(SECURE_SIGN_THREAD_PROC));
	p->Connection = c;
	ss = p->SecureSign = ZeroMallocEx(sizeof(SECURE_SIGN), true);
	StrCpy(ss->SecurePrivateKeyName, sizeof(ss->SecurePrivateKeyName),
		a->SecurePrivateKeyName);
	StrCpy(ss->SecurePublicCertName, sizeof(ss->SecurePublicCertName),
		a->SecurePublicCertName);
	ss->UseSecureDeviceId = c->Cedar->Client->UseSecureDeviceId;
	Copy(ss->Random, random, SHA1_SIZE);

#ifdef	OS_WIN32
	ss->BitmapId = CmGetSecureBitmapId(c->ServerName);
#endif	// OS_WIN32

	p->SecureSignProc = a->SecureSignProc;

	// スレッド作成
	thread = NewThread(ClientSecureSignThread, p);
	WaitThreadInit(thread);

	// 署名が完了するかキャンセルするまで 0.5 秒ごとにポーリングする
	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			// 切断防止のため一定期間ごとに NOOP を送信する
			start = Tick64();
			ClientUploadNoop(c);
		}
		if (p->UserFinished)
		{
			// ユーザーが選択した
			break;
		}
		WaitThread(thread, 500);
	}
	ReleaseThread(thread);

	ret = p->Ok;

	if (ret)
	{
		Copy(sign, ss->Signature, 128);
		*x = ss->ClientCert;
	}

	Free(p->SecureSign);
	Free(p);

	return ret;
}

// サーバー証明書確認用スレッド
void ClientCheckServerCertThread(THREAD *thread, void *param)
{
	CHECK_CERT_THREAD_PROC *p = (CHECK_CERT_THREAD_PROC *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// 初期化完了を通知する
	NoticeThreadInit(thread);

	// ユーザーに選択を問い合わせる
	p->Ok = p->CheckCertProc(p->Connection->Session, p->Connection, p->ServerX, &p->Exipred);
	p->UserSelected = true;
}

// クライアントがサーバーの証明書を確認する
bool ClientCheckServerCert(CONNECTION *c, bool *expired)
{
	CLIENT_AUTH *auth;
	X *x;
	CHECK_CERT_THREAD_PROC *p;
	THREAD *thread;
	CEDAR *cedar;
	bool ret;
	UINT64 start;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	auth = c->Session->ClientAuth;
	cedar = c->Cedar;

	if (auth->CheckCertProc == NULL && c->Session->LinkModeClient == false)
	{
		// チェック関数無し
		return true;
	}

	if (c->Session->LinkModeClient && c->Session->Link->CheckServerCert == false)
	{
		// カスケード接続モードだがサーバー証明書はチェックしない
		return true;
	}

	if (c->UseTicket)
	{
		// リダイレクト先 VPN サーバーの証明書を確認する
		if (CompareX(c->FirstSock->RemoteX, c->ServerX) == false)
		{
			return false;
		}
		else
		{
			return true;
		}
	}

	x = CloneX(c->FirstSock->RemoteX);
	if (x == NULL)
	{
		// 変なエラーが発生した
		return false;
	}

	if (CheckXDateNow(x))
	{
		// 信頼するルート証明書によって署名されているかどうか確認する
		if (c->Session->LinkModeClient == false)
		{
			// 通常の VPN Client モード
			if (CheckSignatureByCa(cedar, x))
			{
				// 署名されているのでこの証明書は信頼できる
				FreeX(x);
				return true;
			}
		}
		else
		{
			// カスケード接続モード
			if (CheckSignatureByCaLinkMode(c->Session, x))
			{
				// 署名されているのでこの証明書は信頼できる
				FreeX(x);
				return true;
			}
		}
	}

	if (c->Session->LinkModeClient)
	{
		if (CheckXDateNow(x))
		{
			Lock(c->Session->Link->lock);
			{
				if (c->Session->Link->ServerCert != NULL)
				{
					if (CompareX(c->Session->Link->ServerCert, x))
					{
						Unlock(c->Session->Link->lock);
						// カスケード接続設定に登録されている証明書と完全一致
						FreeX(x);
						return true;
					}
				}
			}
			Unlock(c->Session->Link->lock);
		}
		else
		{
			if (expired != NULL)
			{
				*expired = true;
			}
		}

		// カスケード接続モードの場合はこの時点で検証失敗
		FreeX(x);
		return false;
	}

	p = ZeroMalloc(sizeof(CHECK_CERT_THREAD_PROC));
	p->ServerX = x;
	p->CheckCertProc = auth->CheckCertProc;
	p->Connection = c;

	// スレッドを作成する
	thread = NewThread(ClientCheckServerCertThread, p);
	WaitThreadInit(thread);

	// ユーザーが接続の可否を選択するまで 0.5 秒間隔でポーリングする
	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			// 切断防止のため一定期間ごとに NOOP を送信する
			start = Tick64();
			ClientUploadNoop(c);
		}
		if (p->UserSelected)
		{
			// ユーザーが選択した
			break;
		}
		WaitThread(thread, 500);
	}

	if (expired != NULL)
	{
		*expired = p->Exipred;
	}

	ret = p->Ok;
	FreeX(p->ServerX);
	Free(p);
	ReleaseThread(thread);

	return ret;
}

// クライアントがサーバーに接続する
bool ClientConnect(CONNECTION *c)
{
	bool ret = false;
	bool ok = false;
	UINT err;
	SOCK *s;
	PACK *p = NULL;
	UINT session_key_32;
	SESSION *sess;
	char session_name[MAX_SESSION_NAME_LEN + 1];
	char connection_name[MAX_CONNECTION_NAME_LEN + 1];
	UCHAR session_key[SHA1_SIZE];
	RC4_KEY_PAIR key_pair;
	POLICY *policy;
	bool expired = false;
	IP server_ip;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	sess = c->Session;

	PrintStatus(sess, L"init");
	PrintStatus(sess, _UU("STATUS_1"));

REDIRECTED:

	// [接続中]
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Session->ClientStatus = CLIENT_STATUS_CONNECTING;

	s = ClientConnectToServer(c);
	if (s == NULL)
	{
		PrintStatus(sess, L"free");
		return false;
	}

	Copy(&server_ip, &s->RemoteIP, sizeof(IP));

	if (c->Halt)
	{
		// 停止
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// [ネゴシエーション中]
	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	// シグネチャを送信
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// 停止
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	PrintStatus(sess, _UU("STATUS_5"));

	// Hello パケットを受信
	Debug("Downloading Hello...\n");
	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Session->ClientOption != NULL && c->Session->ClientOption->FromAdminPack)
	{
		if (IsAdminPackSupportedServerProduct(c->ServerStr) == false)
		{
			c->Err = ERR_NOT_ADMINPACK_SERVER;
			goto CLEANUP;
		}
	}

	if (c->Halt)
	{
		// 停止
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	Debug("Server Version : %u\n"
		"Server String  : %s\n"
		"Server Build   : %u\n"
		"Client Version : %u\n"
		"Client String  : %s\n"
		"Client Build   : %u\n",
		c->ServerVer, c->ServerStr, c->ServerBuild,
		c->ClientVer, c->ClientStr, c->ClientBuild);

	// ユーザー認証中
	c->Session->ClientStatus = CLIENT_STATUS_AUTH;

	// クライアントによるサーバー証明書の確認
	if (ClientCheckServerCert(c, &expired) == false)
	{
		if (expired == false)
		{
			c->Err = ERR_CERT_NOT_TRUSTED;
		}
		else
		{
			c->Err = ERR_SERVER_CERT_EXPIRES;
		}

		if (c->Session->LinkModeClient == false && c->Err == ERR_CERT_NOT_TRUSTED)
		{
			c->Session->ForceStopFlag = true;
		}

		goto CLEANUP;
	}

	PrintStatus(sess, _UU("STATUS_6"));

	// 認証データを送信
	if (ClientUploadAuth(c) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// 停止
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// Welcome パケットを受信
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	// エラーチェック
	err = GetErrorFromPack(p);
	if (err != 0)
	{
		// エラー発生
		c->Err = err;
		c->ClientConnectError_NoSavePassword = PackGetBool(p, "no_save_password");
		goto CLEANUP;
	}

	// 接続制限のためのブランド化文字列チェック
	{
		char tmp[20];
		char *branded_cfroms = _SS("BRANDED_C_FROM_S");
		PackGetStr(p, "branded_cfroms", tmp, sizeof(tmp));

		if(StrLen(branded_cfroms) > 0 && StrCmpi(branded_cfroms, tmp) != 0)
		{
			c->Err = ERR_BRANDED_C_FROM_S;
			goto CLEANUP;
		}
	}

	if (true)
	{
		// メッセージ取得
		UINT utf_size;
		char *utf;
		wchar_t *msg;

		utf_size = PackGetDataSize(p, "Msg");
		utf = ZeroMalloc(utf_size + 8);
		PackGetData(p, "Msg", utf);

		msg = CopyUtfToUni(utf);

		if (IsEmptyUniStr(msg) == false)
		{
			if (c->Session->Client_Message != NULL)
			{
				Free(c->Session->Client_Message);
			}

			c->Session->Client_Message = msg;
		}
		else
		{
			Free(msg);
		}

		Free(utf);
	}

	if (PackGetInt(p, "Redirect") != 0)
	{
		UINT i;
		UINT ip;
		UINT num_port;
		UINT *ports;
		UINT use_port = 0;
		UINT current_port = c->ServerPort;
		UCHAR ticket[SHA1_SIZE];
		X *server_cert;
		BUF *b;

		// リダイレクトモード
		PrintStatus(sess, _UU("STATUS_8"));

		ip = PackGetIp32(p, "Ip");
		num_port = MAX(MIN(PackGetIndexCount(p, "Port"), MAX_PUBLIC_PORT_NUM), 1);
		ports = ZeroMalloc(sizeof(UINT) * num_port);
		for (i = 0;i < num_port;i++)
		{
			ports[i] = PackGetIntEx(p, "Port", i);
		}

		// ポート番号を選定する
		for (i = 0;i < num_port;i++)
		{
			if (ports[i] == current_port)
			{
				use_port = current_port;
			}
		}
		if (use_port == 0)
		{
			use_port = ports[0];
		}

		Free(ports);

		if (PackGetDataSize(p, "Ticket") == SHA1_SIZE)
		{
			PackGetData(p, "Ticket", ticket);
		}

		b = PackGetBuf(p, "Cert");
		if (b != NULL)
		{
			server_cert = BufToX(b, false);
			FreeBuf(b);
		}

		if (c->ServerX != NULL)
		{
			FreeX(c->ServerX);
		}
		c->ServerX = server_cert;

		IPToStr32(c->ServerName, sizeof(c->ServerName), ip);
		c->ServerPort = use_port;

		c->UseTicket = true;
		Copy(c->Ticket, ticket, SHA1_SIZE);

		FreePack(p);

		p = NewPack();
		HttpClientSend(s, p);
		FreePack(p);

		p = NULL;

		c->FirstSock = NULL;
		Disconnect(s);
		ReleaseSock(s);
		s = NULL;

		goto REDIRECTED;
	}

	PrintStatus(sess, _UU("STATUS_7"));

	// Welcome パケットをパース
	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
		connection_name, sizeof(connection_name), &policy) == false)
	{
		// パース失敗
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	// セッションキーを取得
	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false)
	{
		// 取得失敗
		Free(policy);
		policy = NULL;
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	Copy(c->Session->SessionKey, session_key, SHA1_SIZE);
	c->Session->SessionKey32 = session_key_32;

	// Welcome パケットの内容を保存
	Debug("session_name: %s, connection_name: %s\n",
		session_name, connection_name);

	Lock(c->Session->lock);
	{
		// 接続パラメータの展開と更新
		c->Session->MaxConnection = PackGetInt(p, "max_connection");
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, c->Session->ClientOption->MaxConnection);
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, MAX_TCP_CONNECTION);
		c->Session->MaxConnection = MAX(c->Session->MaxConnection, 1);
		c->Session->UseCompress = PackGetInt(p, "use_compress") == 0 ? false : true;
		c->Session->UseEncrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
		c->Session->NoSendSignature = PackGetBool(p, "no_send_signature");
		if (c->Session->UseEncrypt)
		{
			c->Session->UseFastRC4 = PackGetInt(p, "use_fast_rc4") == 0 ? false : true;
		}
		c->Session->HalfConnection = PackGetInt(p, "half_connection") == 0 ? false : true;
		c->Session->Timeout = PackGetInt(p, "timeout");
		c->Session->QoS = PackGetInt(p, "qos") == 0 ? false : true;
		if (c->Session->QoS)
		{
			c->Session->MaxConnection = MAX(c->Session->MaxConnection, (UINT)(c->Session->HalfConnection ? 4 : 2));
		}
		c->Session->VLanId = PackGetInt(p, "vlan_id");

		if (c->Protocol == CONNECTION_UDP)
		{
			// UDP プロトコルの場合、サーバーから鍵を受け取る
			if (PackGetDataSize(p, "udp_send_key") == sizeof(c->Session->UdpSendKey))
			{
				PackGetData(p, "udp_send_key", c->Session->UdpSendKey);
			}

			if (PackGetDataSize(p, "udp_recv_key") == sizeof(c->Session->UdpRecvKey))
			{
				PackGetData(p, "udp_recv_key", c->Session->UdpRecvKey);
			}
		}

		if (c->Session->UseFastRC4)
		{
			// RC4 鍵情報の取得
			if (PackGetDataSize(p, "rc4_key_client_to_server") == 16)
			{
				PackGetData(p, "rc4_key_client_to_server", key_pair.ClientToServerKey);
			}
			if (PackGetDataSize(p, "rc4_key_server_to_client") == 16)
			{
				PackGetData(p, "rc4_key_server_to_client", key_pair.ServerToClientKey);
			}
			{
				char key1[64], key2[64];
				BinToStr(key1, sizeof(key1), key_pair.ClientToServerKey, 16);
				BinToStr(key2, sizeof(key2), key_pair.ServerToClientKey, 16);
				Debug(
					"Client to Server Key: %s\n"
					"Server to Client Key: %s\n",
					key1, key2);
			}
		}
	}
	Unlock(c->Session->lock);

	Lock(c->lock);
	{
		if (c->Name != NULL)
		{
			Free(c->Name);
		}
		c->Name = CopyStr(connection_name);

		// 暗号化アルゴリズム名の保存
		if (c->CipherName != NULL)
		{
			Free(c->CipherName);
		}

		c->CipherName = CopyStr(c->FirstSock->CipherName);
	}
	Unlock(c->lock);

	Lock(c->Session->lock);
	{
		if (c->Session->Name != NULL)
		{
			Free(c->Session->Name);
		}
		c->Session->Name = CopyStr(session_name);

		c->Session->Policy = policy;
	}
	Unlock(c->Session->lock);

	// Welcome パケットを破棄
	FreePack(p);
	p = NULL;

	// server_ip に対して TCP でシグネチャを送信
	if (c->Session->NoSendSignature == false)
	{
		SendSignatureByTcp(c, &server_ip);
	}

	// コネクション確立
	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	// サーバー証明書の保存
	if (c->ServerX == NULL)
	{
		c->ServerX = CloneX(c->FirstSock->RemoteX);
	}

	PrintStatus(sess, _UU("STATUS_9"));

	// コネクションをトンネリングモードに移行
	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection)
	{
		// ハーフコネクション時の処理
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	if (c->Session->UseFastRC4)
	{
		// RC4 高速暗号化鍵のセット
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		Copy(&ts->Rc4KeyPair, &key_pair, sizeof(key_pair));

		InitTcpSockRc4Key(ts, false);
	}

	// SSL 暗号化フラグ
	if (c->Session->UseEncrypt && c->Session->UseFastRC4 == false)
	{
		c->Session->UseSSLDataEncryption = true;
	}
	else
	{
		c->Session->UseSSLDataEncryption = false;
	}

	PrintStatus(sess, L"free");

	CLog(c->Cedar->Client, "LC_CONNECT_2", c->Session->ClientOption->AccountName,
		session_name);

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
	{
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);
	}

	// セッションのメインルーチン
	SessionMain(c->Session);

	ok = true;

	if (c->Err == ERR_USER_CANCEL)
	{
		ret = true;
	}

CLEANUP:
	c->FirstSock = NULL;

	if (p != NULL)
	{
		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);

	Debug("Error: %u\n", c->Err);

	if (ok == false)
	{
		PrintStatus(sess, L"free");
	}

	return ret;
}

// Welcome パケットのパース
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy)
{
	// 引数チェック
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
	{
		return false;
	}

	// セッション名
	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
	{
		return false;
	}

	// コネクション名
	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
	{
		return false;
	}

	// ポリシー
	*policy = PackGetPolicy(p);
	if (*policy == NULL)
	{
		return false;
	}

	return true;
}

// Welcome パケットの生成
PACK *PackWelcome(SESSION *s)
{
	PACK *p;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();

	// セッション名
	PackAddStr(p, "session_name", s->Name);

	// コネクション名
	PackAddStr(p, "connection_name", s->Connection->Name);

	// パラメータ
	PackAddInt(p, "max_connection", s->MaxConnection);
	PackAddInt(p, "use_encrypt", s->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_fast_rc4", s->UseFastRC4 == false ? 0 : 1);
	PackAddInt(p, "use_compress", s->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", s->HalfConnection == false ? 0 : 1);
	PackAddInt(p, "timeout", s->Timeout);
	PackAddInt(p, "qos", s->QoS ? 1 : 0);

	// セッションキー
	PackAddData(p, "session_key", s->SessionKey, SHA1_SIZE);
	PackAddInt(p, "session_key_32", s->SessionKey32);

	// ポリシー
	PackAddPolicy(p, s->Policy);

	// VLAN ID
	PackAddInt(p, "vlan_id", s->VLanId);

	if (s->Connection->Protocol == CONNECTION_UDP)
	{
		// UDP プロトコルの場合、2 組のキーを生成する
		Rand(s->UdpSendKey, sizeof(s->UdpSendKey));
		Rand(s->UdpRecvKey, sizeof(s->UdpRecvKey));

		// クライアントには鍵を反転して送る
		PackAddData(p, "udp_send_key", s->UdpRecvKey, sizeof(s->UdpRecvKey));
		PackAddData(p, "udp_recv_key", s->UdpSendKey, sizeof(s->UdpSendKey));
	}

	// no_send_signature
	if (s->NoSendSignature)
	{
		PackAddBool(p, "no_send_signature", true);
	}

	return p;
}

#define	PACK_ADD_POLICY_BOOL(name, value)	\
	PackAddInt(p, "policy:" name, y->value == false ? 0 : 1)
#define	PACK_ADD_POLICY_UINT(name, value)	\
	PackAddInt(p, "policy:" name, y->value)
#define	PACK_GET_POLICY_BOOL(name, value)	\
	y->value = (PackGetInt(p, "policy:" name) == 0 ? false : true)
#define	PACK_GET_POLICY_UINT(name, value)	\
	y->value = PackGetInt(p, "policy:" name)

// セッションキーを PACK から取得
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32)
{
	// 引数チェック
	if (p == NULL || session_key == NULL || session_key_32 == NULL)
	{
		return false;
	}

	if (PackGetDataSize(p, "session_key") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "session_key", session_key) == false)
	{
		return false;
	}
	*session_key_32 = PackGetInt(p, "session_key_32");

	return true;
}

// ポリシーを PACK から取得
POLICY *PackGetPolicy(PACK *p)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	POLICY *y;
	// 引数チェック
	if (p == NULL)
	{
		return NULL;
	}

	y = ZeroMalloc(sizeof(POLICY));

	// bool 値
	// Ver 2
	PACK_GET_POLICY_BOOL("Access", Access);
	PACK_GET_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_GET_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_GET_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_GET_POLICY_BOOL("NoBridge", NoBridge);
	PACK_GET_POLICY_BOOL("NoRouting", NoRouting);
	PACK_GET_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_GET_POLICY_BOOL("NoServer", NoServer);
	PACK_GET_POLICY_BOOL("CheckMac", CheckMac);
	PACK_GET_POLICY_BOOL("CheckIP", CheckIP);
	PACK_GET_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_GET_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_GET_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_GET_POLICY_BOOL("FixPassword", FixPassword);
	PACK_GET_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_GET_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_GET_POLICY_BOOL("RAFilter", RAFilter);
	PACK_GET_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_GET_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_GET_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_GET_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_GET_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_GET_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_GET_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_GET_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_GET_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// UINT 値
	// Ver 2
	PACK_GET_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_GET_POLICY_UINT("TimeOut", TimeOut);
	PACK_GET_POLICY_UINT("MaxMac", MaxMac);
	PACK_GET_POLICY_UINT("MaxIP", MaxIP);
	PACK_GET_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_GET_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_GET_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_GET_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_GET_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_GET_POLICY_UINT("VLanId", VLanId);

	// Ver 3 フラグ
	PACK_GET_POLICY_BOOL("Ver3", Ver3);

	return y;
}

// ポリシーを PACK に挿入
void PackAddPolicy(PACK *p, POLICY *y)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	// 引数チェック
	if (p == NULL || y == NULL)
	{
		return;
	}

	// bool 値
	// Ver 2
	PACK_ADD_POLICY_BOOL("Access", Access);
	PACK_ADD_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_ADD_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_ADD_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_ADD_POLICY_BOOL("NoBridge", NoBridge);
	PACK_ADD_POLICY_BOOL("NoRouting", NoRouting);
	PACK_ADD_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_ADD_POLICY_BOOL("NoServer", NoServer);
	PACK_ADD_POLICY_BOOL("CheckMac", CheckMac);
	PACK_ADD_POLICY_BOOL("CheckIP", CheckIP);
	PACK_ADD_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_ADD_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_ADD_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_ADD_POLICY_BOOL("FixPassword", FixPassword);
	PACK_ADD_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_ADD_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_ADD_POLICY_BOOL("RAFilter", RAFilter);
	PACK_ADD_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_ADD_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_ADD_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_ADD_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_ADD_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_ADD_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_ADD_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_ADD_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_ADD_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// UINT 値
	// Ver 2
	PACK_ADD_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_ADD_POLICY_UINT("TimeOut", TimeOut);
	PACK_ADD_POLICY_UINT("MaxMac", MaxMac);
	PACK_ADD_POLICY_UINT("MaxIP", MaxIP);
	PACK_ADD_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_ADD_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_ADD_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_ADD_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_ADD_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_ADD_POLICY_UINT("VLanId", VLanId);

	// Ver 3 フラグ
	PackAddBool(p, "policy:Ver3", true);
}

// 追加接続用の認証データをアップロードする
bool ClientUploadAuth2(CONNECTION *c, SOCK *s)
{
	PACK *p = NULL;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	p = PackAdditionalConnect(c->Session->SessionKey);

	PackAddClientVersion(p, c);

	if (HttpClientSend(s, p) == false)
	{
		FreePack(p);
		return false;
	}
	FreePack(p);

	return true;
}

// NOOP を送信する
void ClientUploadNoop(CONNECTION *c)
{
	PACK *p;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	p = PackError(0);
	PackAddInt(p, "noop", 1);
	HttpClientSend(c->FirstSock, p);
	FreePack(p);

	p = HttpClientRecv(c->FirstSock);
	if (p != NULL)
	{
		FreePack(p);
	}
}

// クライアントのバージョン情報を PACK に追加する
void PackAddClientVersion(PACK *p, CONNECTION *c)
{
	// 引数チェック
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

// 新規接続用の認証データをアップロードする
bool ClientUploadAuth(CONNECTION *c)
{
	PACK *p = NULL;
	CLIENT_AUTH *a;
	CLIENT_OPTION *o;
	X *x;
	bool ret;
	NODE_INFO info;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR sign[4096 / 8];
	UCHAR unique[SHA1_SIZE];
	RPC_WINVER v;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	Zero(sign, sizeof(sign));

	a = c->Session->ClientAuth;
	o = c->Session->ClientOption;

	if (c->UseTicket == false)
	{
		switch (a->AuthType)
		{
		case CLIENT_AUTHTYPE_ANONYMOUS:
			// 匿名認証
			p = PackLoginWithAnonymous(o->HubName, a->Username);
			break;

		case CLIENT_AUTHTYPE_PASSWORD:
			// パスワード認証
			SecurePassword(secure_password, a->HashedPassword, c->Random);
			p = PackLoginWithPassword(o->HubName, a->Username, secure_password);
			break;

		case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
			// 平文パスワード認証
			p = PackLoginWithPlainPassword(o->HubName, a->Username, a->PlainPassword);
			break;

		case CLIENT_AUTHTYPE_CERT:
			// 証明書認証
			if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
				a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign))
			{
				if (RsaSignEx(sign, c->Random, SHA1_SIZE, a->ClientK, a->ClientX->bits))
				{
					p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
					c->ClientX = CloneX(a->ClientX);
				}
			}
			break;

		case CLIENT_AUTHTYPE_SECURE:
			// セキュアデバイスによる認証
			if (ClientSecureSign(c, sign, c->Random, &x))
			{
				p = PackLoginWithCert(o->HubName, a->Username, x, sign, 128);
				c->ClientX = CloneX(x);
				FreeX(x);
			}
			else
			{
				c->Err = ERR_SECURE_DEVICE_OPEN_FAILED;
				c->Session->ForceStopFlag = true;
			}
			break;
		}
	}
	else
	{
		// チケット
		p = NewPack();
		PackAddStr(p, "method", "login");
		PackAddStr(p, "hubname", o->HubName);
		PackAddStr(p, "username", a->Username);
		PackAddInt(p, "authtype", AUTHTYPE_TICKET);
		PackAddData(p, "ticket", c->Ticket, SHA1_SIZE);
	}

	// 現在時刻
	PackAddInt64(p, "timestamp", SystemTime64());

	if (p == NULL)
	{
		// エラー
		if (c->Err != ERR_SECURE_DEVICE_OPEN_FAILED)
		{
			c->Err = ERR_PROTOCOL_ERROR;
		}
		return false;
	}

	PackAddClientVersion(p, c);

	// プロトコル
	PackAddInt(p, "protocol", c->Protocol);

	// バージョン等
	PackAddStr(p, "hello", c->ClientStr);
	PackAddInt(p, "version", c->ClientVer);
	PackAddInt(p, "build", c->ClientBuild);
	PackAddInt(p, "client_id", c->Cedar->ClientId);

	// 最大コネクション数
	PackAddInt(p, "max_connection", o->MaxConnection);
	// 暗号化使用フラグ
	PackAddInt(p, "use_encrypt", o->UseEncrypt == false ? 0 : 1);
	// 高速暗号化使用フラグ
	//	PackAddInt(p, "use_fast_rc4", o->UseFastRC4 == false ? 0 : 1);
	// データ圧縮使用フラグ
	PackAddInt(p, "use_compress", o->UseCompress == false ? 0 : 1);
	// ハーフコネクションフラグ
	PackAddInt(p, "half_connection", o->HalfConnection == false ? 0 : 1);

	// ブリッジ / ルーティングモードフラグ
	PackAddBool(p, "require_bridge_routing_mode", o->RequireBridgeRoutingMode);

	// モニタモードフラグ
	PackAddBool(p, "require_monitor_mode", o->RequireMonitorMode);

	// VoIP / QoS フラグ
	PackAddBool(p, "qos", o->DisableQoS ? false : true);

	// ユニーク ID
	GenerateMachineUniqueHash(unique);
	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	// ノード情報
	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	// OS 情報
	GetWinVer(&v);
	OutRpcWinVer(p, &v);

	ret = HttpClientSend(c->FirstSock, p);
	if (ret == false)
	{
		c->Err = ERR_DISCONNECTED;
	}

	FreePack(p);

	return ret;
}

// Hello パケットをアップロードする
bool ServerUploadHello(CONNECTION *c)
{
	PACK *p;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	// 乱数生成
	Rand(c->Random, SHA1_SIZE);

	p = PackHello(c->Random, c->ServerVer, c->ServerBuild, c->ServerStr);
	if (HttpServerSend(c->FirstSock, p) == false)
	{
		FreePack(p);
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	FreePack(p);

	return true;
}

// Hello パケットをダウンロードする
bool ClientDownloadHello(CONNECTION *c, SOCK *s)
{
	PACK *p;
	UINT err;
	UCHAR random[SHA1_SIZE];
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	// データ受信
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p))
	{
		// エラー発生
		c->Err = err;
		FreePack(p);
		return false;
	}

	// パケット解釈
	if (GetHello(p, random, &c->ServerVer, &c->ServerBuild, c->ServerStr, sizeof(c->ServerStr)) == false)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		FreePack(p);
		return false;
	}

	if (c->FirstSock == s)
	{
		Copy(c->Random, random, SHA1_SIZE);
	}

	FreePack(p);

	return true;
}

// シグネチャをダウンロードする
bool ServerDownloadSignature(CONNECTION *c)
{
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	SOCK *s;
	UINT num = 0, max = 19;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	s = c->FirstSock;

	while (true)
	{
		num++;
		if (num > max)
		{
			// 切断
			Disconnect(s);
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			return false;
		}
		// ヘッダを受信する
		h = RecvHttpHeader(s);
		if (h == NULL)
		{
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			return false;
		}

		// 解釈する
		if (StrCmpi(h->Method, "POST") == 0)
		{
			// POST なのでデータを受信する
			data_size = GetContentLength(h);
			if ((data_size > 3411 || data_size < 1411) && (data_size != StrLen(HTTP_VPN_TARGET_POSTDATA)))
			{
				// データが大きすぎる
				HttpSendForbidden(s, h->Target, NULL);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				return false;
			}
			data = Malloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false)
			{
				// データ受信失敗
				Free(data);
				FreeHttpHeader(h);
				c->Err = ERR_DISCONNECTED;
				return false;
			}
			// Target を確認する
			if (StrCmpi(h->Target, HTTP_VPN_TARGET2) != 0)
			{
				// ターゲットが不正
				HttpSendNotFound(s, h->Target);
				Free(data);
				FreeHttpHeader(h);
			}
			else
			{
				if (((data_size == StrLen(HTTP_VPN_TARGET_POSTDATA)) && (Cmp(data, HTTP_VPN_TARGET_POSTDATA, data_size) == 0)) || (data_size >= 1411))
				{
					// VPN Client が接続してきた
					Free(data);
					FreeHttpHeader(h);
					return true;
				}
				else
				{
					// VPN Client 以外のソフトウェアが接続してきた
					HttpSendForbidden(s, h->Target, NULL);
					FreeHttpHeader(h);
				}
			}
		}
		else
		{
			// これ以上解釈しても VPN クライアントで無い可能性が高いが
			// 一応する
			if (StrCmpi(h->Method, "GET") != 0)
			{
				// サポートされていないメソッド呼び出し
				HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
			}
			else
			{
				if (StrCmpi(h->Target, "/") == 0)
				{
					// ルートディレクトリ
					HttpSendForbidden(c->FirstSock, h->Target, "");
				}
				else
				{
					// Not Found
					HttpSendNotFound(s, h->Target);
				}
			}
			FreeHttpHeader(h);
		}
	}
}

// シグネチャをアップロードする
bool ClientUploadSignature(SOCK *s)
{
	HTTP_HEADER *h;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	h = NewHttpHeader("POST", HTTP_VPN_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));

	if (PostHttp(s, h, HTTP_VPN_TARGET_POSTDATA, StrLen(HTTP_VPN_TARGET_POSTDATA)) == false)
	{
		FreeHttpHeader(h);
		return false;
	}

	FreeHttpHeader(h);

	return true;
}

// サーバーへの接続を確立する
SOCK *ClientConnectToServer(CONNECTION *c)
{
	SOCK *s = NULL;
	X *x = NULL;
	K *k = NULL;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// 接続してソケットを取得
	s = ClientConnectGetSocket(c, false);
	if (s == NULL)
	{
		// 接続失敗
		return NULL;
	}

	c->FirstSock = s;

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		ReleaseSock(s);
		c->FirstSock = NULL;
		return NULL;
	}

	// タイムアウト
	SetTimeout(s, CONNECTING_TIMEOUT);

	// SSL 通信の開始
	if (StartSSLEx(s, x, k, (c->DontUseTls1 ? false : true)) == false)
	{
		// SSL 通信開始失敗
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	if (s->RemoteX == NULL)
	{
		// SSL 通信開始失敗
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	return s;
}

// サーバーに接続しソケットを返す
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect)
{
	SOCK *s = NULL;
	CLIENT_OPTION *o;
	char *host_for_direct_connection;
	UINT port_for_direct_connection;
	wchar_t tmp[MAX_SIZE];
	SESSION *sess;
	volatile bool *cancel_flag = NULL;
	void *hWnd;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	sess = c->Session;

	if (sess != NULL)
	{
		cancel_flag = &sess->CancelConnect;
	}

	hWnd = c->hWndForUI;

	o = c->Session->ClientOption;

	if (c->RestoreServerNameAndPort && additional_connect)
	{
		// サーバー名とポート番号を元に戻す
		c->RestoreServerNameAndPort = false;

		StrCpy(c->ServerName, sizeof(c->ServerName), o->Hostname);
		c->ServerPort = o->Port;
	}

	host_for_direct_connection = c->ServerName;
	port_for_direct_connection = c->ServerPort;

	if (o->PortUDP != 0)
	{
		// UDP Connection
		goto UDP_CONNECTION;
	}

	switch (o->ProxyType)
	{
	case PROXY_DIRECT:	// TCP/IP
UDP_CONNECTION:
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_4"), c->ServerName);
		PrintStatus(sess, tmp);
		// 本番
		s = TcpIpConnectEx(host_for_direct_connection, port_for_direct_connection,
			(bool *)cancel_flag, hWnd);
		if (s == NULL)
		{
			// 接続失敗
			c->Err = ERR_CONNECT_FAILED;
			return NULL;
		}
		break;

	case PROXY_HTTP:	// HTTP Proxy
		host_for_direct_connection = o->ProxyName;
		port_for_direct_connection = o->ProxyPort;

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), c->ServerName, o->ProxyName);
		PrintStatus(sess, tmp);
		// プロキシ接続
		s = ProxyConnectEx(c, host_for_direct_connection, port_for_direct_connection,
			c->ServerName, c->ServerPort, o->ProxyUsername, o->ProxyPassword,
			additional_connect, (bool *)cancel_flag, hWnd);
		if (s == NULL)
		{
			// 接続失敗
			return NULL;
		}
		break;

	case PROXY_SOCKS:	// SOCKS Proxy
		host_for_direct_connection = o->ProxyName;

		port_for_direct_connection = o->ProxyPort;

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), c->ServerName, o->ProxyName);
		PrintStatus(sess, tmp);
		// SOCKS 接続
		s = SocksConnectEx(c, host_for_direct_connection, port_for_direct_connection,
			c->ServerName, c->ServerPort, o->ProxyUsername,
			additional_connect, (bool *)cancel_flag, hWnd);
		if (s == NULL)
		{
			// 接続失敗
			return NULL;
		}
		break;
	}

	if (s == NULL)
	{
		// 接続失敗
		c->Err = ERR_CONNECT_FAILED;
	}
	else
	{
		// 接続成功
		// IP アドレスを控えておく
		if (GetIP(&c->Session->ServerIP, host_for_direct_connection) == false)
		{
			Copy(&c->Session->ServerIP, &s->RemoteIP, sizeof(IP));
		}
	}

	return s;
}

// SOCKS 経由で接続する
SOCK *SocksConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, bool additional_connect)
{
	return SocksConnectEx(c, proxy_host_name, proxy_port,
		server_host_name, server_port, username, additional_connect, NULL, NULL);
}
SOCK *SocksConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, bool additional_connect,
				   bool *cancel_flag, void *hWnd)
{
	SOCK *s = NULL;
	IP ip;
	// 引数チェック
	if (c == NULL || proxy_host_name == NULL || proxy_port == 0 || server_host_name == NULL
		|| server_port == 0)
	{
		c->Err = ERR_PROXY_CONNECT_FAILED;
		return NULL;
	}

	// 接続先サーバーの IP アドレスを取得す
	if (GetIP(&ip, server_host_name) == false)
	{
		// 失敗
		c->Err = ERR_CONNECT_FAILED;
		return NULL;
	}

	if (c->Halt)
	{
		// 停止
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// 接続
	s = TcpConnectEx2(proxy_host_name, proxy_port, 0, cancel_flag, hWnd);
	if (s == NULL)
	{
		// 失敗
		c->Err = ERR_PROXY_CONNECT_FAILED;
		return NULL;
	}

	// タイムアウト設定
	SetTimeout(s, CONNECTING_TIMEOUT_PROXY);

	if (additional_connect == false)
	{
		c->FirstSock = s;
	}

	// リクエストパケット送信
	if (SocksSendRequestPacket(c, s, server_port, &ip, username) == false)
	{
		// 失敗
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		return NULL;
	}

	// 応答パケット受信
	if (SocksRecvResponsePacket(c, s) == false)
	{
		// 失敗
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, INFINITE);

	return s;
}

// SOCKS 応答パケットを受信する
bool SocksRecvResponsePacket(CONNECTION *c, SOCK *s)
{
	BUF *b;
	UINT size = 8;
	UCHAR tmp[8];
	UCHAR vn, cd;
	// 引数チェック
	if (c == NULL || s == NULL)
	{
		return false;
	}

	if (RecvAll(s, tmp, sizeof(tmp), false) == false)
	{
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	b = NewBuf();
	WriteBuf(b, tmp, sizeof(tmp));
	SeekBuf(b, 0, 0);

	ReadBuf(b, &vn, 1);
	ReadBuf(b, &cd, 1);

	FreeBuf(b);

	if (vn != 0)
	{
		c->Err = ERR_PROXY_ERROR;
		return false;
	}

	switch (cd)
	{
	case 90:
		// 成功
		return true;

	case 93:
		// 認証失敗
		c->Err = ERR_PROXY_AUTH_FAILED;
		return false;

	default:
		// サーバーへの接続失敗
		c->Err = ERR_CONNECT_FAILED;
		return false;
	}
}

// SOCKS リクエストパケットを送信する
bool SocksSendRequestPacket(CONNECTION *c, SOCK *s, UINT dest_port, IP *dest_ip, char *userid)
{
	BUF *b;
	UCHAR vn, cd;
	USHORT port;
	UINT ip;
	bool ret;
	// 引数チェック
	if (s == NULL || dest_port == 0 || dest_ip == NULL || c == NULL)
	{
		return false;
	}
	if (userid == NULL)
	{
		userid = "";
	}

	b = NewBuf();
	vn = 4;
	cd = 1;
	WriteBuf(b, &vn, 1);
	WriteBuf(b, &cd, 1);
	port = Endian16((USHORT)dest_port);
	ip = IPToUINT(dest_ip);
	WriteBuf(b, &port, 2);
	WriteBuf(b, &ip, 4);
	WriteBuf(b, userid, StrLen(userid) + 1);

	ret = SendAll(s, b->Buf, b->Size, false);
	if (ret == false)
	{
		c->Err = ERR_DISCONNECTED;
	}

	FreeBuf(b);

	return ret;
}

// プロキシ経由で接続する
SOCK *ProxyConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, char *password, bool additional_connect)
{
	return ProxyConnectEx(c, proxy_host_name, proxy_port,
		server_host_name, server_port, username, password, additional_connect, NULL, NULL);
}
SOCK *ProxyConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, char *password, bool additional_connect,
				   bool *cancel_flag, void *hWnd)
{
	SOCK *s = NULL;
	bool use_auth = false;
	char tmp[MAX_SIZE];
	char auth_tmp_str[MAX_SIZE], auth_b64_str[MAX_SIZE * 2];
	char basic_str[MAX_SIZE * 2];
	UINT http_error_code;
	HTTP_HEADER *h;
	// 引数チェック
	if (c == NULL || proxy_host_name == NULL || proxy_port == 0 || server_host_name == NULL ||
		server_port == 0)
	{
		c->Err = ERR_PROXY_CONNECT_FAILED;
		return NULL;
	}
	if (username != NULL && password != NULL &&
		(StrLen(username) != 0 || StrLen(password) != 0))
	{
		use_auth = true;
	}

	if (c->Halt)
	{
		// 停止
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// 接続
	s = TcpConnectEx2(proxy_host_name, proxy_port, 0, cancel_flag, hWnd);
	if (s == NULL)
	{
		// 失敗
		c->Err = ERR_PROXY_CONNECT_FAILED;
		return NULL;
	}

	// タイムアウト設定
	SetTimeout(s, CONNECTING_TIMEOUT_PROXY);

	if (additional_connect == false)
	{
		c->FirstSock = s;
	}

	// HTTP ヘッダ生成
	if (IsStrIPv6Address(server_host_name))
	{
		IP ip;
		char iptmp[MAX_PATH];

		StrToIP(&ip, server_host_name);
		IPToStr(iptmp, sizeof(iptmp), &ip);

		Format(tmp, sizeof(tmp), "[%s]:%u", iptmp, server_port);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s:%u", server_host_name, server_port);
	}

	h = NewHttpHeader("CONNECT", tmp, "HTTP/1.0");
	AddHttpValue(h, NewHttpValue("User-Agent", c->Cedar->HttpUserAgent));
	Debug("proxy user agent = %s\n", c->Cedar->HttpUserAgent);
	AddHttpValue(h, NewHttpValue("Host", server_host_name));
	AddHttpValue(h, NewHttpValue("Content-Length", "0"));
	AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));

	if (use_auth)
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_3"), server_host_name);
		// 認証文字列の生成
		Format(auth_tmp_str, sizeof(auth_tmp_str), "%s:%s",
			username, password);

		// Base64 エンコード
		Zero(auth_b64_str, sizeof(auth_b64_str));
		Encode64(auth_b64_str, auth_tmp_str);
		Format(basic_str, sizeof(basic_str), "Basic %s", auth_b64_str);

		AddHttpValue(h, NewHttpValue("Proxy-Authorization", basic_str));
	}

	// 送信
	if (SendHttpHeader(s, h) == false)
	{
		// 失敗
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		FreeHttpHeader(h);
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_PROXY_ERROR;
		return NULL;
	}

	FreeHttpHeader(h);

	if (c->Halt)
	{
		// 停止
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// 結果を受信
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		// 失敗
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		FreeHttpHeader(h);
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_PROXY_ERROR;
		return NULL;
	}

	http_error_code = 0;
	if (StrLen(h->Method) == 8)
	{
		if (Cmp(h->Method, "HTTP/1.", 7) == 0)
		{
			http_error_code = ToInt(h->Target);
		}
	}
	FreeHttpHeader(h);

	// コードを確認
	switch (http_error_code)
	{
	case 401:
	case 403:
	case 407:
		// 認証失敗
		if (additional_connect == false)
		{
			c->FirstSock = NULL;
		}
		Disconnect(s);
		ReleaseSock(s);
		c->Err = ERR_PROXY_AUTH_FAILED;
		return NULL;

	default:
		if ((http_error_code / 100) == 2)
		{
			// 成功
			SetTimeout(s, INFINITE);
			return s;
		}
		else
		{
			// 不明な結果を受信
			if (additional_connect == false)
			{
				c->FirstSock = NULL;
			}
			Disconnect(s);
			ReleaseSock(s);
			c->Err = ERR_PROXY_ERROR;
			return NULL;
		}
	}
}

// TCP 接続関数
SOCK *TcpConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd)
{
#ifdef	OS_WIN32
	if (hWnd == NULL)
	{
		return ConnectEx2(hostname, port, timeout, cancel_flag);
	}
	else
	{
		return WinConnectEx2((HWND)hWnd, hostname, port, timeout, 0, NULL, NULL);
	}
#else	// OS_WIN32
	return ConnectEx2(hostname, port, timeout, cancel_flag);
#endif	// OS_WIN32
}

// TCP/IP で接続する
SOCK *TcpIpConnect(char *hostname, UINT port)
{
	return TcpIpConnectEx(hostname, port, NULL, NULL);
}
SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd)
{
	SOCK *s = NULL;
	// 引数チェック
	if (hostname == NULL || port == 0)
	{
		return NULL;
	}

	s = TcpConnectEx2(hostname, port, 0, cancel_flag, hWnd);
	if (s == NULL)
	{
		return NULL;
	}

	return s;
}

// PACK にダミーのエントリを作成する
// Q. なぜランダムなサイズのランダムデータをここで挿入するのか?
// A. ネットワーク経路中の盗聴者によってこの SSL 通信が VPN 通信であること
//    を検出しにくいようにするためである。
void CreateDummyValue(PACK *p)
{
	UINT size;
	UCHAR *buf;
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	size = Rand32() % HTTP_PACK_RAND_SIZE_MAX;
	buf = Malloc(size);
	Rand(buf, size);

	PackAddData(p, "pencore", buf, size);

	Free(buf);
}

// サーバーがクライアントから PACK を受信する
PACK *HttpServerRecv(SOCK *s)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

START:

	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		goto BAD_REQUEST;
	}

	if (StrCmpi(h->Method, "POST") != 0 ||
		StrCmpi(h->Target, HTTP_VPN_TARGET) != 0 ||
		StrCmpi(h->Version, "HTTP/1.1") != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	size = GetContentLength(h);
	if (size == 0 || size > MAX_PACK_SIZE)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

	// NOOP かどうか判断
	if (PackGetInt(p, "noop") != 0)
	{
		Debug("recv: noop\n");
		FreePack(p);

		p = PackError(0);
		PackAddInt(p, "noop", 1);
		if (HttpServerSend(s, p) == false)
		{
			FreePack(p);
			return NULL;
		}

		FreePack(p);

		goto START;
	}

	return p;

BAD_REQUEST:
	// エラーを返す


	return NULL;
}

// クライアントがサーバーから PACK を受信する
PACK *HttpClientRecv(SOCK *s)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		return NULL;
	}

	if (StrCmpi(h->Method, "HTTP/1.1") != 0 ||
		StrCmpi(h->Target, "200") != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	size = GetContentLength(h);
	if (size == 0 || size > MAX_PACK_SIZE)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

	return p;
}

// クライアントからサーバーに PACK を送信する
bool HttpClientSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return false;
	}

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("POST", HTTP_VPN_TARGET, "HTTP/1.1");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

// サーバーからクライアントに PACK を送信する
bool HttpServerSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return false;
	}

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("HTTP/1.1", "200", "OK");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

// 501 Not Implemented エラーの送信
bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// 引数チェック
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// ホスト名の取得
	GetMachineName(host, MAX_SIZE);
	// ポート番号の取得
	port = s->LocalPort;

	// ヘッダの作成
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "501", "Method Not Implemented");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// データの作成
	str_size = sizeof(http_501_str) * 2 + StrLen(target) + StrLen(host) + StrLen(method) + StrLen(version);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_501_str);

	// TARGET
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// METHOD
	ReplaceStri(str, str_size, str, "$METHOD$", method);

	// VERSION
	ReplaceStri(str, str_size, str, "$VERSION$", version);

	// 送信
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// 404 Not Found エラーの送信
bool HttpSendNotFound(SOCK *s, char *target)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// 引数チェック
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// ホスト名の取得
	GetMachineName(host, MAX_SIZE);
	// ポート番号の取得
	port = s->LocalPort;

	// ヘッダの作成
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "404", "Not Found");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// データの作成
	str_size = sizeof(http_404_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_404_str);

	// TARGET
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// 送信
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// 403 Forbidden エラーの送信
bool HttpSendForbidden(SOCK *s, char *target, char *server_id)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// 引数チェック
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// ホスト名の取得
	GetMachineName(host, MAX_SIZE);
	// ポート番号の取得
	port = s->LocalPort;

	// ヘッダの作成
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "403", "Forbidden");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// データの作成
	str_size = sizeof(http_403_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_403_str);

	// TARGET
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// 送信
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// HTTP ヘッダ用の日時文字列を取得
void GetHttpDateStr(char *str, UINT size, UINT64 t)
{
	SYSTEMTIME s;
	static char *wday[] =
	{
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
	};
	static char *month[] =
	{
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
		"Nov", "Dec",
	};
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	UINT64ToSystem(&s, t);

	Format(str, size, "%s, %02u %s %04u %02u:%02u:%02u GMT",
		wday[s.wDayOfWeek], s.wDay, month[s.wMonth - 1], s.wYear,
		s.wHour, s.wMinute, s.wSecond);
}

// HTTP ヘッダからコンテンツ長を取得する
UINT GetContentLength(HTTP_HEADER *header)
{
	UINT ret;
	HTTP_VALUE *v;
	// 引数チェック
	if (header == NULL)
	{
		return 0;
	}

	v = GetHttpValue(header, "Content-Length");
	if (v == NULL)
	{
		return 0;
	}

	ret = ToInt(v->Data);

	return ret;
}

// HTTP でデータを送信する
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size)
{
	char *header_str;
	BUF *b;
	bool ret;
	// 引数チェック
	if (s == NULL || header == NULL || post_data == NULL)
	{
		return false;
	}

	// Content-Lentgh が存在するかどうかチェック
	if (GetHttpValue(header, "Content-Length") == NULL)
	{
		char tmp[MAX_SIZE];
		// 存在しないので付加する
		ToStr(tmp, post_size);
		AddHttpValue(header, NewHttpValue("Content-Length", tmp));
	}

	// ヘッダを文字列にする
	header_str = HttpHeaderToStr(header);
	if (header_str == NULL)
	{
		return false;
	}
	b = NewBuf();
	WriteBuf(b, header_str, StrLen(header_str));
	Free(header_str);

	// データを追記する
	WriteBuf(b, post_data, post_size);

	// 送信する
	ret = SendAll(s, b->Buf, b->Size, s->SecureMode);

	FreeBuf(b);

	return ret;
}

// HTTP ヘッダを文字列に変換
char *HttpHeaderToStr(HTTP_HEADER *header)
{
	BUF *b;
	char *tmp;
	UINT i;
	char *s;
	// 引数チェック
	if (header == NULL)
	{
		return NULL;
	}

	tmp = Malloc(HTTP_HEADER_LINE_MAX_SIZE);
	b = NewBuf();

	// ヘッダ
	Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
		"%s %s %s\r\n", header->Method, header->Target, header->Version);
	WriteBuf(b, tmp, StrLen(tmp));

	// 値
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		HTTP_VALUE *v = (HTTP_VALUE *)LIST_DATA(header->ValueList, i);
		Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
			"%s: %s\r\n", v->Name, v->Data);
		WriteBuf(b, tmp, StrLen(tmp));
	}

	// 最後の改行
	WriteBuf(b, "\r\n", 2);
	s = Malloc(b->Size + 1);
	Copy(s, b->Buf, b->Size);
	s[b->Size] = 0;

	FreeBuf(b);
	Free(tmp);

	return s;
}

// HTTP ヘッダを送信
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header)
{
	char *str;
	bool ret;
	// 引数チェック
	if (s == NULL || header == NULL)
	{
		return false;
	}

	// 文字列に変換
	str = HttpHeaderToStr(header);

	// 送信
	ret = SendAll(s, str, StrLen(str), s->SecureMode);

	Free(str);

	return ret;
}

// HTTP ヘッダを受信
HTTP_HEADER *RecvHttpHeader(SOCK *s)
{
	TOKEN_LIST *token = NULL;
	char *str = NULL;
	HTTP_HEADER *header = NULL;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	// 1 行目を取得する
	str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
	if (str == NULL)
	{
		goto ERROR;
	}

	// トークンに分割する
	token = ParseToken(str, " ");
	if (token->NumTokens < 3)
	{
		goto ERROR;
	}

	Free(str);
	str = NULL;

	// ヘッダの作成
	header = NewHttpHeader(token->Token[0], token->Token[1], token->Token[2]);

	if (!StrCmpi(header->Version, "HTTP/1.0") || !StrCmpi(header->Version, "HTTP/0.9"))
	{
		// この行で終わり
		return header;
	}

	// 2 行目以降を取得する
	while (true)
	{
		UINT pos;
		HTTP_VALUE *v;
		char *value_name, *value_data;
		str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
		if (str == NULL)
		{
			goto ERROR;
		}
		Trim(str);

		if (StrLen(str) == 0)
		{
			// ヘッダの終了
			Free(str);
			str = NULL;
			break;
		}

		// コロンの位置を取得する
		pos = SearchStr(str, ":", 0);
		if (pos == INFINITE)
		{
			// コロンが存在しない
			goto ERROR;
		}
		if ((pos + 1) >= StrLen(str))
		{
			// データが存在しない
			goto ERROR;
		}

		// 名前とデータの 2 つに分ける
		value_name = Malloc(pos + 1);
		Copy(value_name, str, pos);
		value_name[pos] = 0;
		value_data = &str[pos + 1];

		v = NewHttpValue(value_name, value_data);
		if (v == NULL)
		{
			Free(value_name);
			goto ERROR;
		}

		Free(value_name);

		AddHttpValue(header, v);
		Free(str);
	}

	FreeToken(token);

	return header;

ERROR:
	// メモリ解放
	if (token)
	{
		FreeToken(token);
	}
	if (str)
	{
		Free(str);
	}
	if (header)
	{
		FreeHttpHeader(header);
	}
	return NULL;
}

// 1 行を受信する
char *RecvLine(SOCK *s, UINT max_size)
{
	BUF *b;
	char c;
	char *str;
	// 引数チェック
	if (s == NULL || max_size == 0)
	{
		return NULL;
	}

	b = NewBuf();
	while (true)
	{
		UCHAR *buf;
		if (RecvAll(s, &c, sizeof(c), s->SecureMode) == false)
		{
			FreeBuf(b);
			return NULL;
		}
		WriteBuf(b, &c, sizeof(c));
		buf = (UCHAR *)b->Buf;
		if (b->Size > max_size)
		{
			FreeBuf(b);
			return NULL;
		}
		if (b->Size >= 1)
		{
			if (buf[b->Size - 1] == '\n')
			{
				b->Size--;
				if (b->Size >= 1)
				{
					if (buf[b->Size - 1] == '\r')
					{
						b->Size--;
					}
				}
				str = Malloc(b->Size + 1);
				Copy(str, b->Buf, b->Size);
				str[b->Size] = 0;
				FreeBuf(b);

				return str;
			}
		}
	}
}

// 新しい HTTP 値の作成
HTTP_VALUE *NewHttpValue(char *name, char *data)
{
	HTTP_VALUE *v;
	// 引数チェック
	if (name == NULL || data == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(HTTP_VALUE));

	v->Name = CopyStr(name);
	v->Data = CopyStr(data);

	Trim(v->Name);
	Trim(v->Data);

	return v;
}

// プロトコルルーチンの初期化
void InitProtocol()
{
}

// プロトコルルーチンの解放
void FreeProtocol()
{
}

// HTTP ヘッダから HTTP 値を探す
HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name)
{
	HTTP_VALUE *v, t;
	// 引数チェック
	if (header == NULL || name == NULL)
	{
		return NULL;
	}

	t.Name = name;
	v = Search(header->ValueList, &t);
	if (v == NULL)
	{
		return NULL;
	}

	return v;
}

// HTTP ヘッダに HTTP 値を追加
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value)
{
	// 引数チェック
	if (header == NULL || value == NULL)
	{
		return;
	}

	Insert(header->ValueList, value);
}

// HTTP ヘッダを作成
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version)
{
	HTTP_HEADER *header;
	// 引数チェック
	if (method == NULL || target == NULL || version == NULL)
	{
		return NULL;
	}

	header = ZeroMalloc(sizeof(HTTP_HEADER));

	header->Method = CopyStr(method);
	header->Target = CopyStr(target);
	header->Version = CopyStr(version);
	header->ValueList = NewListFast(CompareHttpValue);

	return header;
}

// HTTP 値の比較関数
int CompareHttpValue(void *p1, void *p2)
{
	HTTP_VALUE *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(HTTP_VALUE **)p1;
	v2 = *(HTTP_VALUE **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}
	return StrCmpi(v1->Name, v2->Name);
}

// HTTP 値を解放
void FreeHttpValue(HTTP_VALUE *value)
{
	// 引数チェック
	if (value == NULL)
	{
		return;
	}

	Free(value->Data);
	Free(value->Name);

	Free(value);
}

// HTTP ヘッダを解放
void FreeHttpHeader(HTTP_HEADER *header)
{
	UINT i;
	HTTP_VALUE **values;
	// 引数チェック
	if (header == NULL)
	{
		return;
	}

	Free(header->Method);
	Free(header->Target);
	Free(header->Version);

	values = ToArray(header->ValueList);
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		FreeHttpValue(values[i]);
	}
	Free(values);

	ReleaseList(header->ValueList);

	Free(header);
}

// パケットを受信
PACK *RecvPack(SOCK *s)
{
	PACK *p;
	BUF *b;
	void *data;
	UINT sz;
	// 引数チェック
	if (s == NULL || s->Type != SOCK_TCP)
	{
		return false;
	}

	if (RecvAll(s, &sz, sizeof(UINT), s->SecureMode) == false)
	{
		return false;
	}
	sz = Endian32(sz);
	if (sz > MAX_PACK_SIZE)
	{
		return false;
	}
	data = MallocEx(sz, true);
	if (RecvAll(s, data, sz, s->SecureMode) == false)
	{
		Free(data);
		return false;
	}

	b = NewBuf();
	WriteBuf(b, data, sz);
	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);
	Free(data);

	return p;
}

// パケットを送信
bool SendPack(SOCK *s, PACK *p)
{
	BUF *b;
	UINT sz;
	// 引数チェック
	if (s == NULL || p == NULL || s->Type != SOCK_TCP)
	{
		return false;
	}

	b = PackToBuf(p);
	sz = Endian32(b->Size);

	SendAdd(s, &sz, sizeof(UINT));
	SendAdd(s, b->Buf, b->Size);
	FreeBuf(b);

	return SendNow(s, s->SecureMode);
}

// Hello パケットを作成
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str)
{
	PACK *p;
	// 引数チェック
	if (random == NULL || server_str == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "hello", server_str);
	PackAddInt(p, "version", ver);
	PackAddInt(p, "build", build);
	PackAddData(p, "random", random, SHA1_SIZE);

	return p;
}

// Hello パケットを解釈
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size)
{
	// 引数チェック
	if (p == NULL || random == NULL || ver == NULL || server_str == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "hello", server_str, server_str_size) == false)
	{
		return false;
	}
	*ver = PackGetInt(p, "version");
	*build = PackGetInt(p, "build");
	if (PackGetDataSize(p, "random") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "random", random) == false)
	{
		return false;
	}

	return true;
}

// エラー値を PACK に格納
PACK *PackError(UINT error)
{
	PACK *p;

	p = NewPack();
	PackAddInt(p, "error", error);

	return p;
}

// エラー値を PACK から取得
UINT GetErrorFromPack(PACK *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "error");
}

// 認証方法を PACK から取得
UINT GetAuthTypeFromPack(PACK *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "authtype");
}

// ユーザー名と HUB 名を PACK から取得
bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
								   char *hubname, UINT hubname_size)
{
	// 引数チェック
	if (p == NULL || username == NULL || hubname == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "username", username, username_size) == false)
	{
		return false;
	}
	if (PackGetStr(p, "hubname", hubname, hubname_size) == false)
	{
		return false;
	}
	return true;
}

// プロトコルを PACK から取得
UINT GetProtocolFromPack(PACK *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return 0;
	}

#if	0
	return PackGetInt(p, "protocol");
#else
	// 現バージョンでは TCP プロトコルに限定する
	return CONNECTION_TCP;
#endif
}

// メソッドを PACK から取得
bool GetMethodFromPack(PACK *p, char *method, UINT size)
{
	// 引数チェック
	if (p == NULL || method == NULL || size == 0)
	{
		return false;
	}

	return PackGetStr(p, "method", method, size);
}

// 証明書認証ログイン用のパケットを生成
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size)
{
	PACK *p;
	BUF *b;
	// 引数チェック
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_CERT);

	// 証明書
	b = XToBuf(x, false);
	PackAddData(p, "cert", b->Buf, b->Size);
	FreeBuf(b);

	// 署名データ
	PackAddData(p, "sign", sign, sign_size);

	return p;
}

// 平文パスワード認証ログイン用のパケットを生成
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password)
{
	PACK *p;
	// 引数チェック
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PLAIN_PASSWORD);
	PackAddStr(p, "plain_password", plain_password);

	return p;
}

// パスワード認証ログイン用のパケットを作成
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password)
{
	PACK *p;
	// 引数チェック
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PASSWORD);
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	return p;
}

// 匿名ログイン用のパケットを作成
PACK *PackLoginWithAnonymous(char *hubname, char *username)
{
	PACK *p;
	// 引数チェック
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_ANONYMOUS);

	return p;
}

// 追加接続用のパケットを作成
PACK *PackAdditionalConnect(UCHAR *session_key)
{
	PACK *p;
	// 引数チェック
	if (session_key == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}

// PACK から K を取得
K *PackGetK(PACK *p, char *name)
{
	K *k;
	BUF *b;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	b = PackGetBuf(p, name);
	if (b == NULL)
	{
		return NULL;
	}

	k = BufToK(b, true, false, NULL);
	FreeBuf(b);

	return k;
}

// PACK から X を取得
X *PackGetX(PACK *p, char *name)
{
	X *x;
	BUF *b;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	b = PackGetBuf(p, name);
	if (b == NULL)
	{
		return NULL;
	}

	x = BufToX(b, false);
	FreeBuf(b);

	return x;
}

// PACK に K を追加
void PackAddK(PACK *p, char *name, K *k)
{
	BUF *b;
	// 引数チェック
	if (p == NULL || name == NULL || k == NULL)
	{
		return;
	}

	b = KToBuf(k, false, NULL);
	if (b == NULL)
	{
		return;
	}

	PackAddBuf(p, name, b);
	FreeBuf(b);
}

// PACK に X を追加
void PackAddX(PACK *p, char *name, X *x)
{
	BUF *b;
	// 引数チェック
	if (p == NULL || name == NULL || x == NULL)
	{
		return;
	}

	b = XToBuf(x, false);
	if (b == NULL)
	{
		return;
	}

	PackAddBuf(p, name, b);
	FreeBuf(b);
}

// PACK からバッファを取得
BUF *PackGetBuf(PACK *p, char *name)
{
	return PackGetBufEx(p, name, 0);
}
BUF *PackGetBufEx(PACK *p, char *name, UINT index)
{
	UINT size;
	void *tmp;
	BUF *b;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	size = PackGetDataSizeEx(p, name, index);
	tmp = MallocEx(size, true);
	if (PackGetDataEx(p, name, tmp, index) == false)
	{
		Free(tmp);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);

	Free(tmp);

	return b;
}

// PACK からデータを取得
bool PackGetData(PACK *p, char *name, void *data)
{
	return PackGetDataEx(p, name, data, 0);
}
bool PackGetDataEx(PACK *p, char *name, void *data, UINT index)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return false;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return false;
	}
	Copy(data, GetDataValue(e, index), GetDataValueSize(e, index));
	return true;
}
bool PackGetData2(PACK *p, char *name, void *data, UINT size)
{
	return PackGetDataEx2(p, name, data, size, 0);
}
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return false;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return false;
	}
	if (GetDataValueSize(e, index) != size)
	{
		return false;
	}
	Copy(data, GetDataValue(e, index), GetDataValueSize(e, index));
	return true;
}

// PACK からデータサイズを取得
UINT PackGetDataSize(PACK *p, char *name)
{
	return PackGetDataSizeEx(p, name, 0);
}
UINT PackGetDataSizeEx(PACK *p, char *name, UINT index)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return 0;
	}
	return GetDataValueSize(e, index);
}

// PACK から整数を取得
UINT64 PackGetInt64(PACK *p, char *name)
{
	return PackGetInt64Ex(p, name, 0);
}
UINT64 PackGetInt64Ex(PACK *p, char *name, UINT index)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, VALUE_INT64);
	if (e == NULL)
	{
		return 0;
	}
	return GetInt64Value(e, index);
}

// PACK からインデックス数を取得
UINT PackGetIndexCount(PACK *p, char *name)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, INFINITE);
	if (e == NULL)
	{
		return 0;
	}

	return e->num_value;
}

// PACK から個数を取得
UINT PackGetNum(PACK *p, char *name)
{
	return MIN(PackGetInt(p, name), 65536);
}

// PACK から bool 型を取得
bool PackGetBool(PACK *p, char *name)
{
	return PackGetInt(p, name) == 0 ? false : true;
}
bool PackGetBoolEx(PACK *p, char *name, UINT index)
{
	return PackGetIntEx(p, name, index) == 0 ? false : true;
}

// PACK に bool 型を追加
void PackAddBool(PACK *p, char *name, bool b)
{
	PackAddInt(p, name, b ? 1 : 0);
}
void PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total)
{
	PackAddIntEx(p, name, b ? 1 : 0, index, total);
}

// PACK に IPV6_ADDR を追加
void PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total)
{
	// 引数チェック
	if (p == NULL || name == NULL || addr == NULL)
	{
		return;
	}

	PackAddDataEx(p, name, addr, sizeof(IPV6_ADDR), index, total);
}
void PackAddIp6Addr(PACK *p, char *name, IPV6_ADDR *addr)
{
	PackAddIp6AddrEx(p, name, addr, 0, 1);
}

// PACK から IPV6_ADDR を取得
bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index)
{
	// 引数チェック
	if (p == NULL || name == NULL || addr == NULL)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	return PackGetDataEx2(p, name, addr, sizeof(IPV6_ADDR), index);
}
bool PackGetIp6Addr(PACK *p, char *name, IPV6_ADDR *addr)
{
	return PackGetIp6AddrEx(p, name, addr, 0);
}

// PACK に IP を追加
void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total)
{
	IP ip;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return;
	}

	UINTToIP(&ip, ip32);

	PackAddIpEx(p, name, &ip, index, total);
}
void PackAddIp32(PACK *p, char *name, UINT ip32)
{
	PackAddIp32Ex(p, name, ip32, 0, 1);
}
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total)
{
	UINT i;
	bool b = false;
	char tmp[MAX_PATH];
	// 引数チェック
	if (p == NULL || name == NULL || ip == NULL)
	{
		return;
	}

	b = IsIP6(ip);

	Format(tmp, sizeof(tmp), "%s@ipv6_bool", name);
	PackAddBoolEx(p, tmp, b, index, total);

	Format(tmp, sizeof(tmp), "%s@ipv6_array", name);
	if (b)
	{
		PackAddDataEx(p, tmp, ip->ipv6_addr, sizeof(ip->ipv6_addr), index, total);
	}
	else
	{
		UCHAR dummy[16];

		Zero(dummy, sizeof(dummy));

		PackAddDataEx(p, tmp, dummy, sizeof(dummy), index, total);
	}

	Format(tmp, sizeof(tmp), "%s@ipv6_scope_id", name);
	if (b)
	{
		PackAddIntEx(p, tmp, ip->ipv6_scope_id, index, total);
	}
	else
	{
		PackAddIntEx(p, tmp, 0, index, total);
	}

	i = IPToUINT(ip);

	if (IsBigEndian())
	{
		i = Swap32(i);
	}

	PackAddIntEx(p, name, i, index, total);
}
void PackAddIp(PACK *p, char *name, IP *ip)
{
	PackAddIpEx(p, name, ip, 0, 1);
}

// PACK から IP を取得
UINT PackGetIp32Ex(PACK *p, char *name, UINT index)
{
	IP ip;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	if (PackGetIpEx(p, name, &ip, index) == false)
	{
		return 0;
	}

	return IPToUINT(&ip);
}
UINT PackGetIp32(PACK *p, char *name)
{
	return PackGetIp32Ex(p, name, 0);
}
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index)
{
	UINT i;
	char tmp[MAX_PATH];
	// 引数チェック
	if (p == NULL || ip == NULL || name == NULL)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), "%s@ipv6_bool", name);
	if (PackGetBoolEx(p, tmp, index))
	{
		UCHAR data[16];
		UINT scope_id;

		Zero(data, sizeof(data));

		Format(tmp, sizeof(tmp), "%s@ipv6_array", name);
		PackGetDataEx2(p, tmp, data, sizeof(data), index);

		Format(tmp, sizeof(tmp), "%s@ipv6_scope_id", name);
		scope_id = PackGetIntEx(p, tmp, index);

		SetIP6(ip, data);
		ip->ipv6_scope_id = scope_id;
	}
	else
	{
		if (GetElement(p, name, VALUE_INT) == NULL)
		{
			Zero(ip, sizeof(IP));
			return false;
		}

		i = PackGetIntEx(p, name, index);

		if (IsBigEndian())
		{
			i = Swap32(i);
		}

		UINTToIP(ip, i);
	}

	return true;
}
bool PackGetIp(PACK *p, char *name, IP *ip)
{
	return PackGetIpEx(p, name, ip, 0);
}

// PACK から整数を取得
UINT PackGetInt(PACK *p, char *name)
{
	return PackGetIntEx(p, name, 0);
}
UINT PackGetIntEx(PACK *p, char *name, UINT index)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, VALUE_INT);
	if (e == NULL)
	{
		return 0;
	}
	return GetIntValue(e, index);
}

// PACK から Unicode 文字列を取得
bool PackGetUniStr(PACK *p, char *name, wchar_t *unistr, UINT size)
{
	return PackGetUniStrEx(p, name, unistr, size, 0);
}
bool PackGetUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT size, UINT index)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL || unistr == NULL || size == 0)
	{
		return false;
	}

	unistr[0] = 0;

	e = GetElement(p, name, VALUE_UNISTR);
	if (e == NULL)
	{
		return false;
	}
	UniStrCpy(unistr, size, GetUniStrValue(e, index));
	return true;
}

// PACK から文字列を取得
bool PackGetStr(PACK *p, char *name, char *str, UINT size)
{
	return PackGetStrEx(p, name, str, size, 0);
}
bool PackGetStrEx(PACK *p, char *name, char *str, UINT size, UINT index)
{
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL || str == NULL || size == 0)
	{
		return false;
	}

	str[0] = 0;

	e = GetElement(p, name, VALUE_STR);
	if (e == NULL)
	{
		return false;
	}

	StrCpy(str, size, GetStrValue(e, index));
	return true;
}

// バッファを PACK に追加 (配列)
void PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total)
{
	// 引数チェック
	if (p == NULL || name == NULL || b == NULL || total == 0)
	{
		return;
	}

	PackAddDataEx(p, name, b->Buf, b->Size, index, total);
}

// データを PACK に追加 (配列)
void PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || data == NULL || name == NULL || total == 0)
	{
		return;
	}

	v = NewDataValue(data, size);
	e = GetElement(p, name, VALUE_DATA);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_DATA);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_DATA;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		AddElement(p, e);
	}
}

// バッファを PACK に追加
void PackAddBuf(PACK *p, char *name, BUF *b)
{
	// 引数チェック
	if (p == NULL || name == NULL || b == NULL)
	{
		return;
	}

	PackAddData(p, name, b->Buf, b->Size);
}

// データを PACK に追加
void PackAddData(PACK *p, char *name, void *data, UINT size)
{
	VALUE *v;
	// 引数チェック
	if (p == NULL || data == NULL || name == NULL)
	{
		return;
	}

	v = NewDataValue(data, size);
	AddElement(p, NewElement(name, VALUE_DATA, 1, &v));
}

// 64 bit 整数を PACK に追加 (配列)
void PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL || total == 0)
	{
		return;
	}

	v = NewInt64Value(i);
	e = GetElement(p, name, VALUE_INT64);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_INT64);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_INT64;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		AddElement(p, e);
	}
}

// 整数を PACK に追加 (配列)
void PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL || total == 0)
	{
		return;
	}

	v = NewIntValue(i);
	e = GetElement(p, name, VALUE_INT);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_INT);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_INT;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		AddElement(p, e);
	}
}

// 64 bit 整数を PACK に追加
void PackAddInt64(PACK *p, char *name, UINT64 i)
{
	VALUE *v;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return;
	}

	v = NewInt64Value(i);
	AddElement(p, NewElement(name, VALUE_INT64, 1, &v));
}

// 個数を PACK に追加
void PackAddNum(PACK *p, char *name, UINT num)
{
	PackAddInt(p, name, num);
}

// 整数を PACK に追加
void PackAddInt(PACK *p, char *name, UINT i)
{
	VALUE *v;
	// 引数チェック
	if (p == NULL || name == NULL)
	{
		return;
	}

	v = NewIntValue(i);
	AddElement(p, NewElement(name, VALUE_INT, 1, &v));
}

// Unicode 文字列を PACK に追加 (配列)
void PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL || unistr == NULL || total == 0)
	{
		return;
	}

	v = NewUniStrValue(unistr);
	e = GetElement(p, name, VALUE_UNISTR);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_UNISTR);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_UNISTR;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		AddElement(p, e);
	}
}

// Unicode 文字列を PACK に追加
void PackAddUniStr(PACK *p, char *name, wchar_t *unistr)
{
	VALUE *v;
	// 引数チェック
	if (p == NULL || name == NULL || unistr == NULL)
	{
		return;
	}

	v = NewUniStrValue(unistr);
	AddElement(p, NewElement(name, VALUE_UNISTR, 1, &v));
}

// 文字列を PACK に追加 (配列)
void PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// 引数チェック
	if (p == NULL || name == NULL || str == NULL || total == 0)
	{
		return;
	}

	v = NewStrValue(str);
	e = GetElement(p, name, VALUE_STR);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_STR);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_STR;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		AddElement(p, e);
	}
}

// 文字列を PACK に追加
void PackAddStr(PACK *p, char *name, char *str)
{
	VALUE *v;
	// 引数チェック
	if (p == NULL || name == NULL || str == NULL)
	{
		return;
	}

	v = NewStrValue(str);
	AddElement(p, NewElement(name, VALUE_STR, 1, &v));
}

// RC4 キーペアを生成
void GenerateRC4KeyPair(RC4_KEY_PAIR *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	Rand(k->ClientToServerKey, sizeof(k->ClientToServerKey));
	Rand(k->ServerToClientKey, sizeof(k->ServerToClientKey));
}

