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

// Link.c
// HUB 間リンク接続

#include "CedarPch.h"

// リンクサーバースレッド
void LinkServerSessionThread(THREAD *t, void *param)
{
	LINK *k = (LINK *)param;
	CONNECTION *c;
	SESSION *s;
	POLICY *policy;
	wchar_t name[MAX_SIZE];
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	// サーバーコネクションの作成
	c = NewServerConnection(k->Cedar, NULL, t);
	c->Protocol = CONNECTION_HUB_LINK_SERVER;

	// ポリシーの作成
	policy = ZeroMalloc(sizeof(POLICY));
	Copy(policy, k->Policy, sizeof(POLICY));

	// サーバーセッションの作成
	s = NewServerSession(k->Cedar, c, k->Hub, LINK_USER_NAME, policy);
	s->LinkModeServer = true;
	s->Link = k;
	c->Session = s;
	ReleaseConnection(c);

	// ユーザー名
	s->Username = CopyStr(LINK_USER_NAME_PRINT);

	k->ServerSession = s;
	AddRef(k->ServerSession->ref);

	// 初期化完了を通知
	NoticeThreadInit(t);

	UniStrCpy(name, sizeof(name), k->Option->AccountName);
	HLog(s->Hub, "LH_LINK_START", name, s->Name);

	// セッションのメイン関数
	SessionMain(s);

	HLog(s->Hub, "LH_LINK_STOP", name);

	ReleaseSession(s);
}

// パケットアダプタ初期化
bool LinkPaInit(SESSION *s)
{
	LINK *k;
	THREAD *t;
	// 引数チェック
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	// 送信パケットキューの作成
	k->SendPacketQueue = NewQueue();

	// リンクサーバースレッドの作成
	t = NewThread(LinkServerSessionThread, (void *)k);
	WaitThreadInit(t);

	ReleaseThread(t);

	return true;
}

// キャンセルオブジェクトの取得
CANCEL *LinkPaGetCancel(SESSION *s)
{
	LINK *k;
	// 引数チェック
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return NULL;
	}

	return NULL;
}

// 次のパケットを取得
UINT LinkPaGetNextPacket(SESSION *s, void **data)
{
	LINK *k;
	UINT ret = 0;
	// 引数チェック
	if (s == NULL || data == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return INFINITE;
	}

	// キューにパケットが溜まっているかどうか調べる
	LockQueue(k->SendPacketQueue);
	{
		BLOCK *block = GetNext(k->SendPacketQueue);

		if (block != NULL)
		{
			// パケットがあった
			*data = block->Buf;
			ret = block->Size;
			// 構造体のメモリは破棄する
			Free(block);
		}
	}
	UnlockQueue(k->SendPacketQueue);

	return ret;
}

// 受信したパケットを書き込み
bool LinkPaPutPacket(SESSION *s, void *data, UINT size)
{
	LINK *k;
	BLOCK *block;
	SESSION *server_session;
	CONNECTION *server_connection;
	// 引数チェック
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	server_session = k->ServerSession;
	server_connection = server_session->Connection;

	// ここにはリンク接続先の HUB から届いたパケットが来るので
	// サーバーセッションの ReceivedBlocks に届けてあげる
	if (data != NULL)
	{
		block = NewBlock(data, size, 0);

		LockQueue(server_connection->ReceivedBlocks);
		{
			InsertQueue(server_connection->ReceivedBlocks, block);
		}
		UnlockQueue(server_connection->ReceivedBlocks);
	}
	else
	{
		// data == NULL のとき、すべてのパケットを格納し終わったので
		// Cancel を発行する
		Cancel(server_session->Cancel1);

		if (k->Hub != NULL && k->Hub->Option != NULL && k->Hub->Option->YieldAfterStorePacket)
		{
			YieldCpu();
		}
	}

	return true;
}

// パケットアダプタの解放
void LinkPaFree(SESSION *s)
{
	LINK *k;
	// 引数チェック
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return;
	}

	// サーバーセッションの停止
	StopSession(k->ServerSession);
	ReleaseSession(k->ServerSession);

	// 送信パケットキューの解放
	LockQueue(k->SendPacketQueue);
	{
		BLOCK *block;
		while (block = GetNext(k->SendPacketQueue))
		{
			FreeBlock(block);
		}
	}
	UnlockQueue(k->SendPacketQueue);

	ReleaseQueue(k->SendPacketQueue);
}

// パケットアダプタ
PACKET_ADAPTER *LinkGetPacketAdapter()
{
	return NewPacketAdapter(LinkPaInit, LinkPaGetCancel, LinkPaGetNextPacket,
		LinkPaPutPacket, LinkPaFree);
}

// すべてのリンクの解放
void ReleaseAllLink(HUB *h)
{
	LINK **kk;
	UINT num, i;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		num = LIST_NUM(h->LinkList);
		kk = ToArray(h->LinkList);
		DeleteAll(h->LinkList);
	}
	UnlockList(h->LinkList);

	for (i = 0;i < num;i++)
	{
		LINK *k = kk[i];

		ReleaseLink(k);
	}

	Free(kk);
}

// リンクの解放
void ReleaseLink(LINK *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	if (Release(k->ref) == 0)
	{
		CleanupLink(k);
	}
}

// リンクのクリーンアップ
void CleanupLink(LINK *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	DeleteLock(k->lock);
	if (k->ClientSession)
	{
		ReleaseSession(k->ClientSession);
	}
	Free(k->Option);
	CiFreeClientAuth(k->Auth);
	Free(k->Policy);

	if (k->ServerCert != NULL)
	{
		FreeX(k->ServerCert);
	}

	Free(k);
}

// リンクをオンラインにする
void SetLinkOnline(LINK *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	if (k->Offline == false)
	{
		return;
	}

	k->Offline = false;
	StartLink(k);
}

// リンクをオフラインにする
void SetLinkOffline(LINK *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	if (k->Offline)
	{
		return;
	}

	StopLink(k);
	k->Offline = true;
}

// リンクの削除
void DelLink(HUB *hub, LINK *k)
{
	// 引数チェック
	if (hub == NULL || k == NULL)
	{
		return;
	}

	LockList(hub->LinkList);
	{
		if (Delete(hub->LinkList, k))
		{
			ReleaseLink(k);
		}
	}
	UnlockList(hub->LinkList);
}

// すべてのリンクの開始
void StartAllLink(HUB *h)
{
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = (LINK *)LIST_DATA(h->LinkList, i);

			if (k->Offline == false)
			{
				StartLink(k);
			}
		}
	}
	UnlockList(h->LinkList);
}

// すべてのリンクの停止
void StopAllLink(HUB *h)
{
	LINK **link_list;
	UINT num_link;
	UINT i;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		link_list = ToArray(h->LinkList);
		num_link = LIST_NUM(h->LinkList);
		for (i = 0;i < num_link;i++)
		{
			AddRef(link_list[i]->ref);
		}
	}
	UnlockList(h->LinkList);

	for (i = 0;i < num_link;i++)
	{
		StopLink(link_list[i]);
		ReleaseLink(link_list[i]);
	}

	Free(link_list);
}

// リンクの開始
void StartLink(LINK *k)
{
	PACKET_ADAPTER *pa;
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	LockLink(k);
	{
		if (k->Started || k->Halting)
		{
			UnlockLink(k);
			return;
		}
		k->Started = true;
	}
	UnlockLink(k);

	// クライアントセッション接続
	pa = LinkGetPacketAdapter();
	pa->Param = (void *)k;
	LockLink(k);
	{
		k->ClientSession = NewClientSession(k->Cedar, k->Option, k->Auth, pa);
	}
	UnlockLink(k);
}

// リンクの停止
void StopLink(LINK *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	LockLink(k);
	{
		if (k->Started == false)
		{
			UnlockLink(k);
			return;
		}
		k->Started = false;
		k->Halting = true;
	}
	UnlockLink(k);

	if (k->ClientSession != NULL)
	{
		// クライアントセッション切断
		StopSession(k->ClientSession);

		LockLink(k);
		{
			ReleaseSession(k->ClientSession);
			k->ClientSession = NULL;
		}
		UnlockLink(k);
	}

	LockLink(k);
	{
		k->Halting = false;
	}
	UnlockLink(k);
}

// リンクのロック
void LockLink(LINK *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	Lock(k->lock);
}

// ロックのリンク解除
void UnlockLink(LINK *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	Unlock(k->lock);
}

// リンク用ポリシーの正規化
void NormalizeLinkPolicy(POLICY *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	p->Access = true;
	p->NoBridge = p->NoRouting = p->PrivacyFilter =
		p->MonitorPort = false;
	p->MaxConnection = 32;
	p->TimeOut = 20;
	p->FixPassword = false;
}

// リンクの作成
LINK *NewLink(CEDAR *cedar, HUB *hub, CLIENT_OPTION *option, CLIENT_AUTH *auth, POLICY *policy)
{
	CLIENT_OPTION *o;
	LINK *k;
	CLIENT_AUTH *a;
	// 引数チェック
	if (cedar == NULL || hub == NULL || option == NULL || auth == NULL || policy == NULL)
	{
		return NULL;
	}
	if (hub->Halt)
	{
		return NULL;
	}

	if (LIST_NUM(hub->LinkList) >= MAX_HUB_LINKS)
	{
		return NULL;
	}

	if (UniIsEmptyStr(option->AccountName))
	{
		return NULL;
	}

	// 認証方法の制限
	if (auth->AuthType != CLIENT_AUTHTYPE_ANONYMOUS && auth->AuthType != CLIENT_AUTHTYPE_PASSWORD &&
		auth->AuthType != CLIENT_AUTHTYPE_PLAIN_PASSWORD && auth->AuthType != CLIENT_AUTHTYPE_CERT)
	{
		// 匿名認証、パスワード認証、プレーンパスワード、証明書認証以外の認証方法は使用できない
		return NULL;
	}

	// クライアントオプションのコピー (改変用)
	o = ZeroMalloc(sizeof(CLIENT_OPTION));
	Copy(o, option, sizeof(CLIENT_OPTION));
	StrCpy(o->DeviceName, sizeof(o->DeviceName), LINK_DEVICE_NAME);

	o->RequireBridgeRoutingMode = true;	// ブリッジモードを要求する
	o->RequireMonitorMode = false;	// モニタモードは要求しない

	o->NumRetry = INFINITE;			// 接続の再試行は無限に行う
	o->RetryInterval = 10;			// 再試行間隔は 10 秒
	o->NoRoutingTracking = true;	// ルーティング追跡停止

	// 認証データのコピー
	a = CopyClientAuth(auth);
	a->SecureSignProc = NULL;
	a->CheckCertProc = NULL;

	// リンク オブジェクト
	k = ZeroMalloc(sizeof(LINK));
	k->lock = NewLock();
	k->ref = NewRef();

	k->Cedar = cedar;
	k->Option = o;
	k->Auth = a;
	k->Hub = hub;

	// ポリシーのコピー
	k->Policy = ZeroMalloc(sizeof(POLICY));
	Copy(k->Policy, policy, sizeof(POLICY));

	// ポリシーの正規化
	NormalizeLinkPolicy(k->Policy);

	// HUB のリンクリストに登録する
	LockList(hub->LinkList);
	{
		Add(hub->LinkList, k);
		AddRef(k->ref);
	}
	UnlockList(hub->LinkList);

	return k;
}

