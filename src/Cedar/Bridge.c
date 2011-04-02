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

// Bridge.c
// Ethernet ブリッジプログラム

#define	BRIDGE_C

#ifdef	WIN32
#define	OS_WIN32
#endif

#ifdef	OS_WIN32

// Win32 用
#include "BridgeWin32.c"

#else

// Unix 用
#include "BridgeUnix.c"

#endif	// OS_WIN32

// 現在の Ethernet デバイス一覧をハッシュする
UINT GetEthDeviceHash()
{
#ifdef	OS_UNIX
	// UNIX 版
	UINT num;
	UINT i;
	char tmp[4096];
	UCHAR hash[SHA1_SIZE];
	TOKEN_LIST *t = GetEthList();

	num = t->NumTokens;
	tmp[0] = 0;
	for (i = 0;i < t->NumTokens;i++)
	{
		StrCat(tmp, sizeof(tmp), t->Token[i]);
	}
	FreeToken(t);

	Hash(hash, tmp, StrLen(tmp), true);

	Copy(&num, hash, sizeof(UINT));

	return num;
#else	// OS_UNIX
	// Win32 版
	UINT ret = 0;
	MS_ADAPTER_LIST *a = MsCreateAdapterListEx(true);
	UINT num;
	UINT i;
	char tmp[4096];
	UCHAR hash[SHA1_SIZE];

	tmp[0] = 0;
	if (a != NULL)
	{
		for (i = 0;i < a->Num;i++)
		{
			StrCat(tmp, sizeof(tmp), a->Adapters[i]->Title);
		}
	}
	MsFreeAdapterList(a);

	Hash(hash, tmp, StrLen(tmp), true);

	Copy(&num, hash, sizeof(UINT));

	return num;
#endif	// OS_UNIU
}

// WinPcap が必要かどうか取得する
bool IsNeedWinPcap()
{
	if (IsBridgeSupported() == false)
	{
		// Windows 以外
		return false;
	}
	else
	{
		// Windows
		if (IsEthSupported())
		{
			// すでに Ethernet デバイスへのアクセスに成功している
			return false;
		}
		else
		{
			// Ethernet デバイスへのアクセスに失敗している
			return true;
		}
	}
}

// 現在の OS でブリッジがサポートされているかどうか取得する
bool IsBridgeSupported()
{
	UINT type = GetOsInfo()->OsType;

	if (OS_IS_WINDOWS(type))
	{
		return true;
	}
	else
	{
		return IsEthSupported();
	}
}

// ローカルブリッジの削除
bool DeleteLocalBridge(CEDAR *c, char *hubname, char *devicename)
{
	bool ret = false;
	// 引数チェック
	if (c == NULL || hubname == NULL || devicename == NULL)
	{
		return false;
	}

	LockList(c->HubList);
	{
		LockList(c->LocalBridgeList);
		{
			UINT i;

			for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

				if (StrCmpi(br->HubName, hubname) == 0)
				{
					if (StrCmpi(br->DeviceName, devicename) == 0)
					{
						if (br->Bridge != NULL)
						{
							BrFreeBridge(br->Bridge);
							br->Bridge = NULL;
						}

						Delete(c->LocalBridgeList, br);
						Free(br);

						ret = true;
						break;
					}
				}
			}
		}
		UnlockList(c->LocalBridgeList);
	}
	UnlockList(c->HubList);

	return ret;
}

// ローカルブリッジの追加
void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool fullbcast)
{
	UINT i;
	HUB *h = NULL;
	LOCALBRIDGE *br = NULL;
	// 引数チェック
	if (c == NULL || hubname == NULL || devicename == NULL)
	{
		return;
	}

	if (OS_IS_UNIX(GetOsInfo()->OsType) == false)
	{
		tapmode = false;
	}

	LockList(c->HubList);
	{
		LockList(c->LocalBridgeList);
		{
			bool exists = false;

			// 全く同一のブリッジ設定が無いかどうか調べる
			for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);
				if (StrCmpi(br->DeviceName, devicename) == 0)
				{
					if (StrCmpi(br->HubName, hubname) == 0)
					{
						if (br->TapMode == tapmode)
						{
							exists = true;
						}
					}
				}
			}

			if (exists == false)
			{
				// 設定を追加する
				br = ZeroMalloc(sizeof(LOCALBRIDGE));
				StrCpy(br->HubName, sizeof(br->HubName), hubname);
				StrCpy(br->DeviceName, sizeof(br->DeviceName), devicename);
				br->Bridge = NULL;
				br->Local = local;
				br->TapMode = tapmode;
				br->FullBroadcast = fullbcast;
				br->Monitor = monitor;
				if (br->TapMode)
				{
					if (tapaddr != NULL && IsZero(tapaddr, 6) == false)
					{
						Copy(br->TapMacAddress, tapaddr, 6);
					}
					else
					{
						GenMacAddress(br->TapMacAddress);
					}
				}

				Add(c->LocalBridgeList, br);

				// HUB を検索する
				for (i = 0;i < LIST_NUM(c->HubList);i++)
				{
					HUB *hub = LIST_DATA(c->HubList, i);
					if (StrCmpi(hub->Name, br->HubName) == 0)
					{
						h = hub;
						AddRef(h->ref);
						break;
					}
				}
			}
		}
		UnlockList(c->LocalBridgeList);
	}
	UnlockList(c->HubList);

	// 早速ブリッジを開始する
	if (h != NULL && br != NULL && h->Type != HUB_TYPE_FARM_DYNAMIC)
	{
		Lock(h->lock_online);
		{
			if (h->Offline == false)
			{
				LockList(c->LocalBridgeList);
				{
					if (IsInList(c->LocalBridgeList, br))
					{
						if (br->Bridge == NULL)
						{
							br->Bridge = BrNewBridge(h, br->DeviceName, NULL, br->Local, br->Monitor, br->TapMode, br->TapMacAddress, br->FullBroadcast);
						}
					}
				}
				UnlockList(c->LocalBridgeList);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);
}

// ローカルブリッジリストの初期化
void InitLocalBridgeList(CEDAR *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->LocalBridgeList = NewList(NULL);
}

// ローカルブリッジリストの解放
void FreeLocalBridgeList(CEDAR *c)
{
	UINT i;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
	{
		LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);
		Free(br);
	}

	ReleaseList(c->LocalBridgeList);
	c->LocalBridgeList = NULL;
}

// ブリッジ用スレッド
void BrBridgeThread(THREAD *thread, void *param)
{
	BRIDGE *b;
	CONNECTION *c;
	SESSION *s;
	HUB *h;
	char name[MAX_SIZE];
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	b = (BRIDGE *)param;

	// コネクションの作成
	c = NewServerConnection(b->Cedar, NULL, thread);
	c->Protocol = CONNECTION_HUB_BRIDGE;

	// セッションの作成
	s = NewServerSession(b->Cedar, c, b->Hub, BRIDGE_USER_NAME, b->Policy);
	HLog(b->Hub, "LH_START_BRIDGE", b->Name, s->Name);
	StrCpy(name, sizeof(name), b->Name);
	h = b->Hub;
	AddRef(h->ref);
	s->BridgeMode = true;
	s->Bridge = b;
	c->Session = s;
	ReleaseConnection(c);

	// ユーザー名
	s->Username = CopyStr(BRIDGE_USER_NAME_PRINT);

	b->Session = s;
	AddRef(s->ref);

	// 初期化完了を通知
	NoticeThreadInit(thread);

	// セッションのメイン関数
	Debug("Bridge %s Start.\n", b->Name);
	SessionMain(s);
	Debug("Bridge %s Stop.\n", b->Name);

	HLog(h, "LH_STOP_BRIDGE", name);

	ReleaseHub(h);

	ReleaseSession(s);
}

// ブリッジの解放
void BrFreeBridge(BRIDGE *b)
{
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	// セッション停止
	StopSession(b->Session);
	ReleaseSession(b->Session);
	Free(b->Name);

	Free(b);
}

// 新しいブリッジの作成
BRIDGE *BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool fullbcast)
{
	BRIDGE *b;
	POLICY *policy;
	THREAD *t;
	// 引数チェック
	if (h == NULL || name == NULL)
	{
		return NULL;
	}

	if (p == NULL)
	{
		policy = ClonePolicy(GetDefaultPolicy());
	}
	else
	{
		policy = ClonePolicy(p);
	}

	policy->CheckMac = true;

#ifdef	UNIX_LINUX
	policy->CheckMac = false;
#endif	// UNIX_LINUX

	policy->NoBroadcastLimiter = true;

	b = ZeroMalloc(sizeof(BRIDGE));
	b->Cedar = h->Cedar;
	b->Hub = h;
	b->Name = CopyStr(name);
	b->Policy = policy;
	b->Local = local;
	b->Monitor = monitor;
	b->TapMode = tapmode;
	b->FullBroadcast = fullbcast;

	if (b->TapMode)
	{
		if (tapaddr != NULL && IsZero(tapaddr, 6) == false)
		{
			Copy(b->TapMacAddress, tapaddr, 6);
		}
		else
		{
			GenMacAddress(b->TapMacAddress);
		}
	}

	if (monitor)
	{
		// モニタリングモード
		policy->MonitorPort = true;
	}

	if (b->FullBroadcast)
	{
		// ブロードキャストを制限しない
		policy->NoBroadcastLimiter = true;
	}

	// スレッド作成
	t = NewThread(BrBridgeThread, b);
	WaitThreadInit(t);
	ReleaseThread(t);

	return b;
}

