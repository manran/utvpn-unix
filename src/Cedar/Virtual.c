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

// Virtual.c
// ユーザーモード仮想ホストプログラム

// Q. このプログラムには大変多くの TCP/IP 関係の奥の深い処理が入っていて
//    さらに TCP スタックの簡易的な実装まで完結しているように見えるが
//    なぜこのように気合の入ったコードを書いたのか?
// A. 作者の所属していた筑波大学第三学群情報学類という学科では、
//    「情報特別演習」という授業がある。なんとこれは専門基礎単位を取得
//    することができる貴重なコマである。専門基礎単位を取得するための他の
//    方法としては、解析学Ⅲなどという授業等がある。しかし、作者は受験勉強
//    のような数学のテスト勉強は嫌いであるし、また、SoftEther に関する打ち合わせ
//    のために大学の某所に駐車したときにその解析学Ⅲの当時の担当教員の車のミラー
//    をこすってしまって少し怒られたのでその単位の取得は難しくなった (?) のである。
//    だが、専門基礎の単位を取得しなければ、卒業することができない。
//    そこで代わりに「情報特別演習」で単位をとることにしたのだが、この授業は、
//    何か面白いコンピュータの作品を作ってプレゼンテーションすれば 2 単位がくる
//    という名目なのであった。しかし、実際のところ、ろくな作品を 1 年間で
//    作ってプレゼンする人はとても少なく、たいていが「無線 LAN の実験」とか
//    そういうほとんどクリエイティブな作業を必要とせずにできるいいかげんな
//    「実習」を行ったと言って結果を報告すれば 2 単位来るという程度の難易度
//    であることが後になって分かった。
//    作者は大変真面目なので、部類としてはかなり難しい難易度に入る TCP/IP
//    スタックの開発を実習としてやってみようと思い、数週間かけていろいろ
//    プログラムを書いた。その成果の一部がこの Virtual.c というコードである。
//    逆にいうと、大学の授業の実習程度で開発することができるくらいの簡単な
//    プログラムなので、実装は簡易的であり、効率が悪く、メンテナンス性にも欠け
//    ている。結構場当たり的なプログラミングを行ったためである。
//    それでも 2004 年末に本プログラムをインターネットで配布してから今まで
//    一応は深刻な不具合は発生していない。ただし探せば深刻な障害が潜んでいる
//    かも知れない。


#include "CedarPch.h"

static UCHAR broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// Virtual Host のログをとる
void VLog(VH *v, char *str)
{
	// とらん！！
	return;
}

// NAT が使用可能かどうかチェック
bool CanCreateNewNatEntry(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return false;
	}

	if (v->UseNat == false)
	{
		// NAT 停止中
		return false;
	}

	if (v->NatTable->num_item > NAT_MAX_SESSIONS)
	{
		// セッション数超過
		return false;
	}

	return true;
}

// NAT 処理スレッドのメイン関数
void NatThreadMain(VH *v)
{
	bool halt_flag;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	v->TmpBuf = Malloc(NAT_TMPBUF_SIZE);

	while (true)
	{
		// 次のイベントがセットされるまで待機する
		WaitSockEvent(v->SockEvent, SELECT_TIME);

		halt_flag = false;

		LockVirtual(v);
		{
			// すべての NAT セッションに対して処理を行う
			UINT i, num;

			v->Now = Tick64();
			v->NatDoCancelFlag = false;

LIST_ELEMENT_DELETED:
			num = LIST_NUM(v->NatTable);
			for (i = 0;i < num;i++)
			{
				NAT_ENTRY *n = LIST_DATA(v->NatTable, i);

				switch (n->Protocol)
				{
				case NAT_TCP:		// TCP
					if (NatTransactTcp(v, n) == false)
					{
						goto LIST_ELEMENT_DELETED;
					}
					break;

				case NAT_UDP:		// UDP
					if (NatTransactUdp(v, n) == false)
					{
						goto LIST_ELEMENT_DELETED;
					}
					break;

				case NAT_DNS:		// DNS
					if (NatTransactDns(v, n) == false)
					{
						goto LIST_ELEMENT_DELETED;
					}
					break;
				}
			}

			if (v->NatDoCancelFlag)
			{
				// 親スレッドの Cancel を叩く
				Cancel(v->Cancel);
			}

			// 停止フラグチェック
			if (v->HaltNat)
			{
				halt_flag = true;
			}
		}
		UnlockVirtual(v);

		if (halt_flag)
		{
			// すべてのエントリを強制切断してからスレッドを終了する
			LockVirtual(v);
			{
				UINT num = LIST_NUM(v->NatTable);
				NAT_ENTRY **nn = ToArray(v->NatTable);
				UINT i;

				for (i = 0;i < num;i++)
				{
					NAT_ENTRY *n = nn[i];
					n->DisconnectNow = true;

					switch (n->Protocol)
					{
					case NAT_TCP:		// TCP
						NatTransactTcp(v, n);
						break;

					case NAT_UDP:		// UDP
						NatTransactUdp(v, n);
						break;

					case NAT_DNS:		// DNS
						NatTransactDns(v, n);
						break;
					}
				}

				Free(nn);
			}
			UnlockVirtual(v);
			break;
		}
	}

	Free(v->TmpBuf);
}

// DNS: IP アドレスを取得するスレッド
void NatGetIPThread(THREAD *t, void *param)
{
	NAT_DNS_QUERY *q;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	q = (NAT_DNS_QUERY *)param;
	AddWaitThread(t);

	q->Ok = GetIP(&q->Ip, q->Hostname);

	DelWaitThread(t);

	if (Release(q->ref) == 0)
	{
		Free(q);
	}
}

// DNS: ホスト名から IP アドレスを取得する
bool NatGetIP(IP *ip, char *hostname)
{
	TOKEN_LIST *t;
	bool ret = false;
	// 引数チェック
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	t = ParseToken(hostname, ".");
	if (t == NULL)
	{
		return false;
	}
	if (t->NumTokens == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens == 1)
	{
		ret = GetIP(ip, hostname);
	}
	else
	{
		char *hostname2 = t->Token[0];
		NAT_DNS_QUERY *q1, *q2;
		THREAD *t1, *t2;

		q1 = ZeroMalloc(sizeof(NAT_DNS_QUERY));
		q2 = ZeroMalloc(sizeof(NAT_DNS_QUERY));
		q1->ref = NewRef();
		q2->ref = NewRef();
		AddRef(q1->ref);
		AddRef(q2->ref);
		StrCpy(q1->Hostname, sizeof(q1->Hostname), hostname);
		StrCpy(q2->Hostname, sizeof(q2->Hostname), hostname2);

		t1 = NewThread(NatGetIPThread, q1);
		t2 = NewThread(NatGetIPThread, q2);

		WaitThread(t1, NAT_DNS_QUERY_TIMEOUT);

		if (q1->Ok)
		{
			ret = true;
			Copy(ip, &q1->Ip, sizeof(IP));
		}
		else
		{
			WaitThread(t2, NAT_DNS_QUERY_TIMEOUT);
			if (q1->Ok)
			{
				ret = true;
				Copy(ip, &q1->Ip, sizeof(IP));
			}
			else if (q2->Ok)
			{
				ret = true;
				Copy(ip, &q2->Ip, sizeof(IP));
			}
		}

		ReleaseThread(t1);
		ReleaseThread(t2);

		if (Release(q1->ref) == 0)
		{
			Free(q1);
		}
		if (Release(q2->ref) == 0)
		{
			Free(q2);
		}
	}

	FreeToken(t);

	return ret;
}

// DNS 問い合わせ関数
void NatDnsThread(THREAD *t, void *param)
{
	NAT_ENTRY *n;
	IP ip;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}
	n = (NAT_ENTRY *)param;

	// 初期化完了を通知
	NoticeThreadInit(t);

	// 処理を実行
	if (EndWith(n->DnsTargetHostName, ".in-addr.arpa") == false)
	{
		// 正引き
		if (NatGetIP(&ip, n->DnsTargetHostName))
		{
			// 正引き成功
			Copy(&n->DnsResponseIp, &ip, sizeof(IP));
			n->DnsOk = true;
		}
	}
	else
	{
		// 逆引き
		IP ip;
		n->DnsGetIpFromHost = true;		// 逆引きフラグを設定
		// *.in-addr.arpa 文字列を IP アドレスに変換してもらう
		if (ArpaToIP(&ip, n->DnsTargetHostName))
		{
			// 逆引き処理
			char tmp[256];
			if (GetHostName(tmp, sizeof(tmp), &ip))
			{
				// 逆引き成功
				n->DnsResponseHostName = CopyStr(tmp);
				n->DnsOk = true;
			}
		}
	}

	// 結果を通知
	n->DnsFinished = true;

	SetSockEvent(n->v->SockEvent);
}

// 逆引き用アドレスを IP アドレスに変換する
bool ArpaToIP(IP *ip, char *str)
{
	TOKEN_LIST *token;
	bool ret = false;
	// 引数チェック
	if (ip == NULL || str == NULL)
	{
		return false;
	}

	// トークン変換
	token = ParseToken(str, ".");
	if (token->NumTokens == 6)
	{
		// token[0, 1, 2, 3] を IP に変換
		UINT i;
		Zero(ip, sizeof(IP));
		for (i = 0;i < 4;i++)
		{
			ip->addr[i] = (UCHAR)ToInt(token->Token[3 - i]);
		}
		ret = true;
	}

	FreeToken(token);

	if (IPToUINT(ip) == 0)
	{
		ret = false;
	}

	return ret;
}

// DNS エントリを処理する
bool NatTransactDns(VH *v, NAT_ENTRY *n)
{
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return true;
	}

	if (n->DisconnectNow)
	{
		goto DISCONNECT;
	}

	if (n->DnsThread == NULL && n->DnsFinished == false)
	{
		// スレッドを作成する
		THREAD *t = NewThread(NatDnsThread, (void *)n);
		WaitThreadInit(t);
		n->DnsThread = t;
	}
	else
	{
		// 結果を待機する
		if (n->DnsFinished)
		{
			// 結果が届いている
			WaitThread(n->DnsThread, INFINITE);
			ReleaseThread(n->DnsThread);
			n->DnsThread = NULL;
			// メインスレッドに通知
			v->NatDoCancelFlag = true;
		}
	}

	return true;

DISCONNECT:

	// 解放処理
	if (n->DnsThread != NULL)
	{
		WaitThread(n->DnsThread, INFINITE);
		ReleaseThread(n->DnsThread);
		n->DnsThread = NULL;
	}

	if (n->DnsTargetHostName != NULL)
	{
		Free(n->DnsTargetHostName);
		n->DnsTargetHostName = NULL;
	}

	if (n->DnsResponseHostName != NULL)
	{
		Free(n->DnsResponseHostName);
		n->DnsResponseHostName = NULL;
	}

	DeleteLock(n->lock);
	Delete(v->NatTable, n);
	Free(n);

	return false;
}

// UDP エントリを処理する
bool NatTransactUdp(VH *v, NAT_ENTRY *n)
{
	void *buf;
	UINT recv_size;
	BLOCK *block;
	UINT dest_port = n->DestPort;
	IP dest_ip;
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return true;
	}

	if (n->DisconnectNow)
	{
		goto DISCONNECT;
	}

	if (n->UdpSocketCreated == false)
	{
		// UDP ソケットを作成する
		n->Sock = NewUDP(0);
		if (n->Sock == NULL)
		{
			// ソケット作成失敗
			goto DISCONNECT;
		}
		else
		{
			n->PublicIp = IPToUINT(&n->Sock->LocalIP);
			n->PublicPort = n->Sock->LocalPort;

			JoinSockToSockEvent(n->Sock, v->SockEvent);
			n->UdpSocketCreated = true;
		}
	}

	buf = v->TmpBuf;
	if (n->ProxyDns == false)
	{
		UINTToIP(&dest_ip, n->DestIp);
	}
	else
	{
		UINTToIP(&dest_ip, n->DestIpProxy);
	}

	// UDP ソケットからデータを受信してみる
	while (true)
	{
		IP src_ip;
		UINT src_port;
		recv_size = RecvFrom(n->Sock, &src_ip, &src_port, buf, 65536);

		if (recv_size == SOCK_LATER)
		{
			// パケットが届いていない
			break;
		}
		else if (recv_size == 0)
		{
			// エラー?
			if (n->Sock->IgnoreRecvErr == false)
			{
				// 致命的なエラーが発生した
				goto DISCONNECT;
			}
		}
		else
		{
			// パケットが届いた。送信元 IP をチェック
			if (IPToUINT(&src_ip) == n->DestIp || (IPToUINT(&src_ip) == n->DestIpProxy && n->ProxyDns) && src_port == n->DestPort)
			{
				// キューに挿入
				void *data = Malloc(recv_size);
				Copy(data, buf, recv_size);
				block = NewBlock(data, recv_size, 0);
				InsertQueue(n->UdpRecvQueue, block);
				v->NatDoCancelFlag = true;
				n->LastCommTime = v->Now;
			}
		}
	}

	// UDP ソケットにデータを送信してみる
	while (block = GetNext(n->UdpSendQueue))
	{
		UINT send_size = SendTo(n->Sock, &dest_ip, dest_port, block->Buf, block->Size);

		FreeBlock(block);
		if (send_size == 0)
		{
			// 致命的なエラーかどうか判定
			if (n->Sock->IgnoreSendErr == false)
			{
				// 致命的なエラーが発生した
				goto DISCONNECT;
			}
		}
		else
		{
			n->LastCommTime = v->Now;
		}
	}

	// このセッションがタイムアウトになっていないかどうか調べる
	if ((n->LastCommTime + (UINT64)v->NatUdpTimeout) < v->Now || n->LastCommTime > v->Now)
	{
		// タイムアウトである
		goto DISCONNECT;
	}

	return true;

DISCONNECT:
	// このセッションを切断
	if (n->UdpSocketCreated)
	{
		// ソケットを閉じる
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	// エントリを削除
	DeleteNatUdp(v, n);

	return false;
}

// TCP ホストへの接続処理を行うためのスレッド
void NatTcpConnectThread(THREAD *t, void *p)
{
	NAT_ENTRY *n = (NAT_ENTRY *)p;
	IP ip;
	char hostname[MAX_SIZE];
	UINT port_number;
	SOCK *sock;
	SOCK_EVENT *e;
	// 引数チェック
	if (n == NULL || t == NULL)
	{
		return;
	}

	UINTToIP(&ip, n->DestIp);
	IPToStr(hostname, sizeof(hostname), &ip);
	port_number = n->DestPort;
	e = n->v->SockEvent;
	AddRef(e->ref);

	// 初期化完了を通知
	NoticeThreadInit(t);

	// TCP ホストへの接続を試行
	Debug("NatTcpConnect Connecting to %s:%u\n", hostname, port_number);
	sock = Connect(hostname, port_number);
	if (sock == NULL)
	{
		// 接続失敗
		n->TcpMakeConnectionFailed = true;
	}
	else
	{
		// 接続成功
		n->TcpMakeConnectionSucceed = true;
	}
	n->Sock = sock;
	JoinSockToSockEvent(sock, e);
	SetSockEvent(e);

	ReleaseSockEvent(e);
}

// TCP ホストに接続するためのスレッドを作成する
void CreateNatTcpConnectThread(VH *v, NAT_ENTRY *n)
{
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return;
	}

	// スレッド作成
	n->NatTcpConnectThread = NewThread(NatTcpConnectThread, (void *)n);

	// スレッド初期化完了を待機
	WaitThreadInit(n->NatTcpConnectThread);
}

// TCP エントリを処理する
bool NatTransactTcp(VH *v, NAT_ENTRY *n)
{
	char str[MAX_SIZE];
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return false;
	}

	if (n->DisconnectNow)
	{
		goto DISCONNECT;
	}

	// TCP の状態別に処理を行う
	switch (n->TcpStatus)
	{
	case NAT_TCP_CONNECTING:		// 接続待機中
		if (n->NatTcpConnectThread == NULL)
		{
			// 接続スレッドを作成し接続を開始する
			CreateNatTcpConnectThread(v, n);
		}
		else
		{
			// すでに開始されている接続スレッドの結果を待機
			if (n->TcpMakeConnectionFailed || n->TcpMakeConnectionSucceed)
			{
				// スレッドの動作はすでに完了しているので結果を使用する
				WaitThread(n->NatTcpConnectThread, INFINITE);
				ReleaseThread(n->NatTcpConnectThread);
				n->NatTcpConnectThread = NULL;

				if (n->TcpMakeConnectionSucceed)
				{
					// 接続は成功し Sock が作成された
					n->TcpStatus = NAT_TCP_CONNECTED;
					IPToStr32(str, sizeof(str), n->DestIp);
					NLog(v, "LH_NAT_TCP_SUCCEED", n->Id, n->Sock->RemoteHostname, str, n->DestPort);
				}
				else
				{
					// 接続に失敗した
					n->TcpStatus = NAT_TCP_SEND_RESET;
					IPToStr32(str, sizeof(str), n->DestIp);
					NLog(v, "LH_NAT_TCP_FAILED", n->Id, str, n->DestPort);
				}
				v->NatDoCancelFlag = true;
			}
		}
		break;

	case NAT_TCP_CONNECTED:			// TCP ソケット接続完了 クライアントホストとの間で交渉中
		break;

	case NAT_TCP_SEND_RESET:		// TCP 通信切断 クライアントホストへ RST を送信
		break;

	case NAT_TCP_ESTABLISHED:		// TCP 接続確立済み
		{
			// 受信バッファにデータがあればソケットに対して送信する
			while (n->RecvFifo->size > 0)
			{
				UINT sent_size = Send(n->Sock, ((UCHAR *)n->RecvFifo->p) + n->RecvFifo->pos,
					n->RecvFifo->size, false);
				if (sent_size == 0)
				{
					// 通信が切断された
					n->TcpFinished = true;
					v->NatDoCancelFlag = true;
					break;
				}
				else if (sent_size == SOCK_LATER)
				{
					// ブロッキング
					break;
				}
				else
				{
					// 送信成功
					ReadFifo(n->RecvFifo, NULL, sent_size);
					n->SendAckNext = true;
				}
			}
			// ソケットからデータを取得して送信バッファに書き込む
			while (true)
			{
				void *buf = (void *)v->TmpBuf;
				UINT want_to_recv_size = 0;
				UINT recv_size;
				// 受信したいサイズを計算する
				if (n->SendFifo->size < NAT_SEND_BUF_SIZE)
				{
					// まだ受信できる
					want_to_recv_size = MIN(NAT_SEND_BUF_SIZE - n->SendFifo->size, NAT_TMPBUF_SIZE);
				}
				if (want_to_recv_size == 0)
				{
					break;
				}
				recv_size = Recv(n->Sock, buf, want_to_recv_size, false);
				if (recv_size == 0)
				{
					// 通信が切断された
					n->TcpFinished = true;
					v->NatDoCancelFlag = true;
					break;
				}
				else if (recv_size == SOCK_LATER)
				{
					// ブロッキング
					break;
				}
				else
				{
					// 受信成功
					WriteFifo(n->SendFifo, buf, recv_size);
					v->NatDoCancelFlag = true;
				}
			}
		}
		break;

	}

	// タイムアウトの検出
	if ((n->LastCommTime + (UINT64)v->NatTcpTimeout) < v->Now || n->LastCommTime > v->Now)
	{
		// タイムアウトが発生、セッション切断
		n->TcpStatus = NAT_TCP_SEND_RESET;
		v->NatDoCancelFlag = true;
	}

	return true;

DISCONNECT:		// 切断とセッション廃棄処理
	DeleteNatTcp(v, n);

	return false;
}

// TCP NAT エントリの削除
void DeleteNatTcp(VH *v, NAT_ENTRY *n)
{
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return;
	}

	NLog(v, "LH_NAT_TCP_DELETED", n->Id);

	// 接続スレッドのシャットダウン
	if (n->NatTcpConnectThread != NULL)
	{
		WaitThread(n->NatTcpConnectThread, INFINITE);
		ReleaseThread(n->NatTcpConnectThread);
		n->NatTcpConnectThread = NULL;
	}
	if (n->Sock != NULL)
	{
		// ソケット切断
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	// ウインドウメモリ解放
	if (n->TcpRecvWindow != NULL)
	{
		ReleaseFifo(n->TcpRecvWindow);
		n->TcpRecvWindow = NULL;
	}

	// ウインドウ受信リスト解放
	if (n->TcpRecvList != NULL)
	{
		UINT i;
		for (i = 0;i < LIST_NUM(n->TcpRecvList);i++)
		{
			IP_PART *p = LIST_DATA(n->TcpRecvList, i);
			Free(p);
		}
		ReleaseList(n->TcpRecvList);
		n->TcpRecvList = NULL;
	}

	// FIFO 解放
	ReleaseFifo(n->SendFifo);
	ReleaseFifo(n->RecvFifo);

	// NAT エントリから削除
	Delete(v->NatTable, n);

	DeleteLock(n->lock);

	// メモリ解放
	Free(n);

	Debug("NAT_ENTRY: DeleteNatTcp\n");
}

// NAT 処理スレッド
void NatThread(THREAD *t, void *param)
{
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	// 初期化完了を通知
	NoticeThreadInit(t);

	NatThreadMain((VH *)param);
}

// ビーコンパケットの送信
void SendBeacon(VH *v)
{
	UINT dest_ip;
	ARPV4_HEADER arp;
	static char beacon_str[] =
		"SecureNAT Virtual TCP/IP Stack Beacon";
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// UDP を送信
	dest_ip = (v->HostIP & v->HostMask) | (~v->HostMask);
	SendUdp(v, dest_ip, 7, v->HostIP, 7, beacon_str, sizeof(beacon_str));

	// ARP ヘッダを構築
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
	Copy(arp.SrcAddress, v->MacAddress, 6);
	arp.SrcIP = v->HostIP;
	arp.TargetAddress[0] =
		arp.TargetAddress[1] =
		arp.TargetAddress[2] =
		arp.TargetAddress[3] =
		arp.TargetAddress[4] =
		arp.TargetAddress[5] = 0xff;
	arp.TargetIP = dest_ip;

	// 送信
	VirtualLayer2Send(v, broadcast, v->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// TCP パケットの送信
void SendTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss, void *data, UINT size)
{
	static UCHAR tcp_mss_option[] = {0x02, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00};
	TCPV4_PSEUDO_HEADER *vh;
	TCP_HEADER *tcp;
	UINT header_size = TCP_HEADER_SIZE;
	UINT total_size;
	// 引数チェック
	if (v == NULL || (size != 0 && data == NULL))
	{
		return;
	}

	// メモリ確保
	vh = Malloc(sizeof(TCPV4_PSEUDO_HEADER) + TCP_HEADER_SIZE + size + 32);
	tcp = (TCP_HEADER *)(((UCHAR *)vh) + sizeof(TCPV4_PSEUDO_HEADER));

	if (mss != 0)
	{
		USHORT *mss_size;
		mss_size = (USHORT *)(&tcp_mss_option[2]);
		*mss_size = Endian16((USHORT)mss);
		header_size += sizeof(tcp_mss_option);
	}

	total_size = header_size + size;
	if (total_size > 65536)
	{
		// パケットが長すぎる
		Free(vh);
		return;
	}

	// 擬似ヘッダ生成
	vh->SrcIP = src_ip;
	vh->DstIP = dest_ip;
	vh->Reserved = 0;
	vh->Protocol = IP_PROTO_TCP;
	vh->PacketLength = Endian16((USHORT)total_size);

	// TCP ヘッダ生成
	tcp->SrcPort = Endian16((USHORT)src_port);
	tcp->DstPort = Endian16((USHORT)dest_port);
	tcp->SeqNumber = Endian32(seq);
	tcp->AckNumber = Endian32(ack);
	tcp->HeaderSizeAndReserved = 0;
	TCP_SET_HEADER_SIZE(tcp, (UCHAR)(header_size / 4));
	tcp->Flag = (UCHAR)flag;
	tcp->WindowSize = Endian16((USHORT)window_size);
	tcp->Checksum = 0;
	tcp->UrgentPointer = 0;

	// オプション値コピー
	if (mss != 0)
	{
		Copy(((UCHAR *)tcp) + TCP_HEADER_SIZE, tcp_mss_option, sizeof(tcp_mss_option));
	}

	// データコピー
	Copy(((UCHAR *)tcp) + header_size, data, size);

	// チェックサム計算
	tcp->Checksum = IpChecksum(vh, total_size + 12);

	// IP パケットとして送信
	SendIp(v, dest_ip, src_ip, IP_PROTO_TCP, tcp, total_size);

	// メモリ解放
	Free(vh);
}

// TCP のポーリング処理
void PollingNatTcp(VH *v, NAT_ENTRY *n)
{
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return;
	}

	switch (n->TcpStatus)
	{
	case NAT_TCP_CONNECTING:		// ソケット接続中: 何もしない
		break;

	case NAT_TCP_CONNECTED:			// ソケット接続が完了した SYN+ACK, ACK 処理
		if ((n->LastSynAckSentTime > v->Now) || n->LastSynAckSentTime == 0 || ((n->LastSynAckSentTime + (UINT64)(NAT_TCP_SYNACK_SEND_TIMEOUT * (UINT64)(n->SynAckSentCount + 1)) <= v->Now)))
		{
			n->LastSynAckSentTime = v->Now;
			// SYN+ACK を送信する
			SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
				(UINT)(n->SendSeqInit + n->SendSeq),
				(UINT)(n->RecvSeqInit + n->RecvSeq),
				TCP_SYN | TCP_ACK, n->TcpRecvWindowSize,
				v->TcpMss, NULL, 0);
			n->SynAckSentCount++;
		}
		break;

	case NAT_TCP_SEND_RESET:		// コネクションのリセット
		// RST を送信する
		if (n->TcpFinished == false)
		{
			SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
				(UINT)(n->SendSeq + n->SendSeqInit),
				(UINT)(n->SendSeq + n->SendSeqInit),
				TCP_RST, 0,
				0, NULL, 0);
			// 切断する
			n->TcpStatus = NAT_TCP_WAIT_DISCONNECT;
			n->DisconnectNow = true;
		}
		else
		{
			// 合計 NAT_FIN_SEND_MAX_COUNT 回の FIN を送信する
			if (n->FinSentTime == 0 || (n->FinSentTime > v->Now) || (n->FinSentTime + NAT_FIN_SEND_INTERVAL * (n->FinSentCount + 1)) < v->Now)
			{
				SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
					(UINT)(n->SendSeq + n->SendSeqInit),
					(UINT)(n->RecvSeq + n->RecvSeqInit),
					TCP_ACK | TCP_FIN, 0,
					0, NULL, 0);
				n->FinSentTime = v->Now;
				n->FinSentCount++;
				if (n->FinSentCount >= NAT_FIN_SEND_MAX_COUNT)
				{
					n->TcpFinished = false;
				}
			}
		}
		break;

	case NAT_TCP_ESTABLISHED:		// 接続確立済み
		{
			UINT send_data_size;
			UINT current_pointer;
			UINT notice_window_size_value = 0;
			UINT buf_free_bytes = 0;
			// 通知するウインドウサイズの値を決定する
			if (FifoSize(n->RecvFifo) < NAT_RECV_BUF_SIZE)
			{
				buf_free_bytes = NAT_RECV_BUF_SIZE - FifoSize(n->RecvFifo);
			}
			notice_window_size_value = MIN(n->TcpRecvWindowSize, buf_free_bytes);
			if (n->LastSentKeepAliveTime == 0 ||
				(n->LastSentKeepAliveTime + (UINT64)NAT_ACK_KEEPALIVE_SPAN) < v->Now ||
				(n->LastSentKeepAliveTime > v->Now))
			{
				if (n->LastSentKeepAliveTime != 0)
				{
					// Keep-Alive 用 ACK パケットの送信
					SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
							(UINT)(n->SendSeqInit + n->SendSeq),
							(UINT)(n->RecvSeqInit + n->RecvSeq) - 1,
							TCP_ACK,
							notice_window_size_value,
							0,
							NULL,
							0);
				}
				n->LastSentKeepAliveTime = v->Now;
			}
			if (n->TcpLastSentTime == 0 ||
				(n->TcpLastSentTime > v->Now) ||
				((n->TcpLastSentTime + (UINT64)n->TcpSendTimeoutSpan) < v->Now) ||
				n->SendAckNext)
			{
				// 送信すべきデータがある場合は送信する
				// 送信すべきセグメントサイズを計算する
				send_data_size = n->TcpSendWindowSize;
				if (send_data_size > (n->TcpSendCWnd * n->TcpSendMaxSegmentSize))
				{
					// cwnd 値を適用する
					send_data_size = n->TcpSendCWnd * n->TcpSendMaxSegmentSize;
				}
				if (send_data_size > n->SendFifo->size)
				{
					// 現在保有しているデータ以上は送れない
					send_data_size = n->SendFifo->size;
				}
				if (send_data_size >= 1)
				{
					// セグメントに分割して送信する
					current_pointer = 0;
					while (send_data_size > 0)
					{
						UINT send_segment_size = MIN(n->TcpSendMaxSegmentSize, send_data_size);
						void *send_segment = (void *)(((UCHAR *)n->SendFifo->p) + n->SendFifo->pos + current_pointer);
						SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
							(UINT)(n->SendSeqInit + n->SendSeq + (UINT64)current_pointer),
							(UINT)(n->RecvSeqInit + n->RecvSeq),
							TCP_ACK | TCP_PSH,
							notice_window_size_value,
							0,
							send_segment,
							send_segment_size);
						current_pointer += send_segment_size;
						send_data_size -= send_segment_size;
					}
					// 送信時刻を記録する
					n->TcpLastSentTime = v->Now;
					// 今回送信するストリームサイズを記録する
					n->SendMissionSize = current_pointer;
					n->CurrentSendingMission = true;
					// RTT 測定
					if (n->CalcRTTStartTime == 0)
					{
						n->CalcRTTStartTime = v->Now;
						n->CalcRTTStartValue = n->SendSeq + current_pointer - 1;
					}
					if (n->RetransmissionUsedFlag == false)
					{
						n->RetransmissionUsedFlag = true;
					}
					else
					{
						// 輻輳発生を検出
						if (n->TcpSendCWnd > 2)
						{
							n->TcpSendCWnd--;
						}
					}
				}
				else if (n->SendAckNext)
				{
					// ACK のみ送信する
					SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
							(UINT)(n->SendSeqInit + n->SendSeq),
							(UINT)(n->RecvSeqInit + n->RecvSeq),
							TCP_ACK,
							notice_window_size_value,
							0,
							NULL,
							0);
				}
				n->SendAckNext = false;
			}
			if (n->TcpFinished)
			{
				// すべてのデータ送信が完了していたら切断する
				if (n->SendFifo->size == 0)
				{
					n->TcpStatus = NAT_TCP_SEND_RESET;
				}
			}
		}
		break;
	}
}

// インターネットへ向かう TCP パケットの受信処理
void TcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *tcp, void *data, UINT size)
{
	NAT_ENTRY *n, t;
	UINT seq, ack;
	UINT64 seq64 = 0, ack64 = 0;
	// 引数チェック
	if (v == NULL || tcp == NULL || data == NULL)
	{
		return;
	}

	// このパケットに関するセッションを NAT テーブルから検索
	SetNat(&t, NAT_TCP, src_ip, src_port, dest_ip, dest_port, 0, 0);
	n = SearchNat(v, &t);

	if (n == NULL)
	{
		// 既存のセッションが存在しない
		// SYN パケットのみ通過を許可する
		if ((tcp->Flag & TCP_SYN) && ((tcp->Flag & TCP_ACK) == false))
		{
			TCP_OPTION o;
			// 新しいセッションを作成する
			n = CreateNatTcp(v, src_ip, src_port, dest_ip, dest_port);
			if (n == NULL)
			{
				return;
			}

			// オプションの取得
			ParseTcpOption(&o, ((UCHAR *)tcp) + TCP_HEADER_SIZE, TCP_GET_HEADER_SIZE(tcp) * 4 - TCP_HEADER_SIZE);
			if (o.MaxSegmentSize == 0)
			{
				o.MaxSegmentSize = v->TcpMss;
			}

			Debug("TCP SYN: MSS=%u, WS=%u\n", o.MaxSegmentSize, o.WindowScaling);

			// 初期シーケンス番号
			n->RecvSeqInit = (UINT64)Endian32(tcp->SeqNumber);
			n->RecvSeq = 1;

			n->TcpSendMaxSegmentSize = o.MaxSegmentSize;
			n->TcpRecvWindowSize = NAT_TCP_RECV_WINDOW_SIZE;
			n->TcpSendWindowSize = (UINT)Endian16(tcp->WindowSize);
			if (o.WindowScaling != 0)
			{
				if (o.WindowScaling > 14)
				{
					o.WindowScaling = 14;
				}
				n->TcpSendWindowSize = (n->TcpSendWindowSize << o.WindowScaling);
			}
		}
	}

	seq = Endian32(tcp->SeqNumber);
	ack = Endian32(tcp->AckNumber);

	if (n == NULL)
	{
		// NAT エントリに登録されていないパケットが届いたので RST を返す
		SendTcp(v, dest_ip, dest_port, src_ip, src_port,
			ack, ack, TCP_RST, 0, 0, NULL, 0);
		return;
	}

	switch (n->TcpStatus)
	{
	case NAT_TCP_SEND_RESET:		// リセットを送信してコネクションを切断
		break;

	case NAT_TCP_CONNECTED:			// ソケット接続完了 SYN+ACK, ACK 処理
		if ((tcp->Flag & TCP_ACK) && ((tcp->Flag & TCP_SYN) == false))
		{
			if (seq == (UINT)(n->RecvSeqInit + n->RecvSeq) &&
				ack == (UINT)(n->SendSeqInit + n->SendSeq + 1))
			{
				// ACK パケットが戻ってきたのでハンドシェイク完了
				n->SendSeq++;		// SYN パケットは seq を 1 消費する
				Debug("TCP Connection Established.\n");
				n->TcpStatus = NAT_TCP_ESTABLISHED;
				// 輻輳ウインドウサイズを初期化
				n->TcpSendCWnd = 1;
				n->LastCommTime = v->Now;
			}
			else
			{
				goto TCP_RESET;
			}
		}
		else if (tcp->Flag & TCP_RST)
		{
TCP_RESET:
			// RST を受信
			Debug("TCP Connection Reseted.\n");
			n->TcpStatus = NAT_TCP_SEND_RESET;
		}
		break;

	case NAT_TCP_ESTABLISHED:		// 接続確立済み
		if (tcp->Flag & TCP_FIN)
		{
			// 接続を完了させる
			n->TcpFinished = true;
		}
		if (tcp->Flag & TCP_RST)
		{
			// RST を受信
			goto TCP_RESET;
		}
		else if (tcp->Flag & TCP_ACK)
		{
			TCP_OPTION opt;
			n->LastCommTime = v->Now;
			// ウインドウサイズなどのオプションの取得
			n->TcpSendWindowSize = Endian16(tcp->WindowSize);
			ParseTcpOption(&opt, ((UCHAR *)tcp) + TCP_HEADER_SIZE, TCP_GET_HEADER_SIZE(tcp) * 4 - TCP_HEADER_SIZE);
			if (opt.WindowScaling != 0)
			{
				if (opt.WindowScaling > 14)
				{
					opt.WindowScaling = 14;
				}
				n->TcpSendWindowSize = (n->TcpSendWindowSize << opt.WindowScaling);
			}
			// まず受信した ACK の処理を行う
			// ack64 に応答確認を受けたストリームの終端位置を格納する
			ack64 = n->SendSeq + (UINT64)ack - (n->SendSeqInit + n->SendSeq) % X32;
			if ((n->SendSeqInit + n->SendSeq) % X32 > ack)
			{
				if (((n->SendSeqInit + n->SendSeq) % X32 - ack) >= 0x80000000)
				{
					ack64 = n->SendSeq + (UINT64)ack + X32 - (n->SendSeqInit + n->SendSeq) % X32;
				}
			}
			if (ack64 > n->SendSeq)
			{
				// クライアントによって 1 バイト以上の受信が完了したらしい
				UINT slide_offset = (UINT)(ack64 - n->SendSeq);	// ウインドウのスライド量
				if (slide_offset == 0 || slide_offset > n->TcpSendWindowSize || slide_offset > n->SendFifo->size)
				{
					// 確認応答のオフセット値がこれまでに送信したはずのサイズ
					// よりも大きいので無視する
				}
				else
				{
					// RTT 測定
					if (n->CalcRTTStartTime != 0)
					{
						if (n->CalcRTTStartValue < ack64)
						{
							UINT time_span;
							if (v->Now > n->CalcRTTStartTime)
							{
								time_span = (UINT)(v->Now - n->CalcRTTStartTime);
							}
							else
							{
								time_span = 100;
							}
							n->CalcRTTStartTime = 0;

							// 平滑化
							n->CurrentRTT =
								(UINT)
								(
									((UINT64)n->CurrentRTT * (UINT64)9 +
									(UINT64)time_span * (UINT64)1) / (UINT64)10
								);
							n->TcpSendTimeoutSpan = n->CurrentRTT * 2;
						}
					}
					// 送信サイズを減少させる
					n->SendMissionSize -= slide_offset;
					if (n->SendMissionSize == 0)
					{
						// 今回送信する予定であったすべてのセグメントの送受信が完了した
						// より送信セグメントサイズを大きくしてみる
						if (n->TcpSendCWnd < 65536)
						{
							n->TcpSendCWnd++;
						}
						n->CurrentSendingMission = false;
						n->TcpLastSentTime = 0;
						n->RetransmissionUsedFlag = false;
					}
					// バッファをスライディングする
					n->SendSeq += slide_offset;
					ReadFifo(n->SendFifo, NULL, slide_offset);
					// 今回 ACK によって送信完了が確認できたサイズだけ、さらに送信を実行する
					if (n->SendMissionSize != 0 && false)
					{
						UINT notice_window_size_value = 0;
						UINT send_data_size;
						UINT buf_free_bytes;
						UINT send_offset = n->SendMissionSize;
						// 通知するウインドウサイズの値を決定する
						if (FifoSize(n->RecvFifo) < NAT_RECV_BUF_SIZE)
						{
							buf_free_bytes = NAT_RECV_BUF_SIZE - FifoSize(n->RecvFifo);
						}
						notice_window_size_value = MIN(n->TcpRecvWindowSize, buf_free_bytes);
						// 送信すべきセグメントサイズを計算する
						send_data_size = n->TcpSendWindowSize;
						if (send_data_size > (n->TcpSendCWnd * n->TcpSendMaxSegmentSize))
						{
							// cwnd 値を適用する
							send_data_size = n->TcpSendCWnd * n->TcpSendMaxSegmentSize;
						}
						if (n->SendFifo->size > send_offset)
						{
							send_data_size = MIN(send_data_size, n->SendFifo->size - send_offset);
							send_data_size = MIN(send_data_size, slide_offset);
						}
						else
						{
							send_data_size = 0;
						}
						if (send_data_size >= 1)
						{
							// セグメントに分割して送信する
							UINT current_pointer = 0;
							while (send_data_size > 0)
							{
								UINT send_segment_size = MIN(n->TcpSendMaxSegmentSize, send_data_size);
								void *send_segment = (void *)((
									(UCHAR *)n->SendFifo->p) + n->SendFifo->pos +
									current_pointer + send_offset);

								SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
									(UINT)(n->SendSeqInit + n->SendSeq + (UINT64)current_pointer
									+ (UINT)send_offset),
									(UINT)(n->RecvSeqInit + n->RecvSeq),
									TCP_ACK | TCP_PSH,
									notice_window_size_value,
									0,
									send_segment,
									send_segment_size);
								current_pointer += send_segment_size;
								send_data_size -= send_segment_size;
							}
							n->SendMissionSize += current_pointer;
							n->CurrentSendingMission = true;
							n->TcpLastSentTime = v->Now;
							// RTT 測定
							if (n->CalcRTTStartTime == 0)
							{
								n->CalcRTTStartTime = v->Now;
								n->CalcRTTStartValue = n->SendSeq + current_pointer - 1;
							}
						}
					}
					// イベント発生
					SetSockEvent(v->SockEvent);
				}
			}
			// 次にデータの受信処理を行う
			seq64 = n->RecvSeq + (UINT64)seq - (n->RecvSeqInit + n->RecvSeq) % X32;
			if ((n->RecvSeqInit + n->RecvSeq) % X32 > seq)
			{
				if (((n->RecvSeqInit + n->RecvSeq) % X32 - ack) >= 0x80000000)
				{
					seq64 = n->RecvSeq + (UINT64)seq + X32 - (n->RecvSeqInit + n->RecvSeq) % X32;
				}
			}
			// この時点で seq64 にはクライアントからのデータ開始点の位置が入っている
			if (seq64 >= n->RecvSeq && (seq64 + size) <= (n->RecvSeq + n->TcpRecvWindowSize))
			{
				if (size >= 1)
				{
					// 受信ウインドウの範囲内に 1 バイト以上のデータが届いた
					UINT offset = (UINT)(seq64 - n->RecvSeq);
					UINT i;
					IP_PART *me;
					if (n->TcpRecvWindow == NULL)
					{
						n->TcpRecvWindow = NewFifo();
					}
					if (n->TcpRecvList == NULL)
					{
						n->TcpRecvList = NewListFast(NULL);
					}
					// 届いたパケットをバッファに上書きしリストに追加する
					if (FifoSize(n->TcpRecvWindow) < (offset + size))
					{
						// バッファサイズ拡張
						WriteFifo(n->TcpRecvWindow, NULL, offset + size - FifoSize(n->TcpRecvWindow));
					}
					Copy(((UCHAR *)n->TcpRecvWindow->p) + n->TcpRecvWindow->pos +
						offset, data, size);
					me = ZeroMalloc(sizeof(IP_PART));
					me->Offset = offset;
					me->Size = size;
					for (i = 0;i < LIST_NUM(n->TcpRecvList);i++)
					{
						IP_PART *p = LIST_DATA(n->TcpRecvList, i);
						// 重なる領域があれば重なっている部分があれば除去する
						if (p->Size != 0)
						{
							if (me->Offset <= p->Offset && (me->Offset + me->Size) >= (p->Offset + p->Size))
							{
								// このパケットが既存パケットを完全に上書きする
								p->Size = 0;
							}
							else if (me->Offset >= p->Offset && (me->Offset + me->Size) <= (p->Offset + p->Size))
							{
								// 既存パケットがこのパケットを完全に上書きする
								me->Size = 0;
							}
							else if (me->Offset > p->Offset && me->Offset < (p->Offset + p->Size) &&
								(me->Offset + me->Size) > (p->Offset + p->Size))
							{
								// 一部重なっている
								p->Size -= p->Offset + p->Size - me->Offset;
							}
							else if (me->Offset < p->Offset && (me->Offset + size) > p->Offset && (me->Offset + size) < (p->Offset + p->Size))
							{
								// 一部重なっている
								me->Size -= me->Offset + me->Size - p->Offset;
							}
						}
					}
					if (me->Size == 0)
					{
						Free(me);
					}
					else
					{
						Add(n->TcpRecvList, me);
					}
KILL_NULL_FIRST:
					// 受信リストから中身が空白のものをすべて削除する
					for (i = 0;i < LIST_NUM(n->TcpRecvList);i++)
					{
						IP_PART *p = LIST_DATA(n->TcpRecvList, i);
						if (p->Size == 0)
						{
							Delete(n->TcpRecvList, p);
							Free(p);
							goto KILL_NULL_FIRST;
						}
					}
SCAN_FIRST:
					// 受信リストのうちオフセット 0 から始まるものがあれば抽出する
					for (i = 0;i < LIST_NUM(n->TcpRecvList);i++)
					{
						IP_PART *p = LIST_DATA(n->TcpRecvList, i);
						UINT sz;
						if (p->Offset == 0)
						{
							// 0 から始まるデータブロックを発見したので
							// この分だけ左側にスライドさせてデータを抜き出す
							// バッファを FIFO に書き出す
							sz = p->Size;
							WriteFifo(n->RecvFifo, ((UCHAR *)n->TcpRecvWindow->p) + n->TcpRecvWindow->pos, sz);
							// リストから解放する
							Delete(n->TcpRecvList, p);
							Free(p);
							ReadFifo(n->TcpRecvWindow, NULL, sz);
							// すべての項目を左側にスライドする
							for (i = 0;i < LIST_NUM(n->TcpRecvList);i++)
							{
								p = LIST_DATA(n->TcpRecvList, i);
								p->Offset -= sz;
							}
							// TCB のパラメータを更新
							n->RecvSeq += (UINT64)sz;
							SetSockEvent(v->SockEvent);
							n->SendAckNext = true;
							// 最初からスキャンし直す
							goto SCAN_FIRST;
						}
					}
				}
			}
		}
		break;
	}

	SetSockEvent(v->SockEvent);
}

// TCP オプションのパース
void ParseTcpOption(TCP_OPTION *o, void *data, UINT size)
{
	UCHAR *buf = (UCHAR *)data;
	UINT i;
	UINT value_size = 0;
	UINT value_id = 0;
	UCHAR value[128];
	// 引数チェック
	if (o == NULL || data == NULL)
	{
		return;
	}

	Zero(o, sizeof(TCP_OPTION));

	for (i = 0;i < size;i++)
	{
		if (buf[i] == 0)
		{
			return;
		}
		if (buf[i] != 1)
		{
			value_id = buf[i];
			i++;
			if (i >= size)
			{
				return;
			}
			value_size = buf[i];
			if (value_size <= 1 || value_size > sizeof(value))
			{
				return;
			}
			i++;
			if (i >= size)
			{
				return;
			}
			value_size -= 2;
			Copy(value, &buf[i], value_size);
			i += value_size;
			if (i >= size)
			{
				return;
			}
			switch (value_id)
			{
			case 2:	// MSS
				if (value_size == 2)
				{
					USHORT *mss = (USHORT *)value;
					o->MaxSegmentSize = Endian16(*mss);
				}
				break;

			case 3: // WSS
				if (value_size == 1)
				{
					UCHAR *wss = (UCHAR *)value;
					o->WindowScaling = Endian16(*wss);
				}
				break;

			}
		}
	}

}

// 新しい NAT TCP セッションの作成
NAT_ENTRY *CreateNatTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port)
{
	NAT_ENTRY *n;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	if (CanCreateNewNatEntry(v) == false)
	{
		return NULL;
	}

	// NAT エントリの作成
	n = ZeroMalloc(sizeof(NAT_ENTRY));
	n->Id = Inc(v->Counter);
	n->v = v;
	n->lock = NewLock();
	n->Protocol = NAT_TCP;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;
	n->CreatedTime = n->LastCommTime = v->Now;
	n->Sock = NULL;
	n->DisconnectNow = false;
	n->TcpSendMaxSegmentSize = n->TcpRecvMaxSegmentSize = v->TcpMss;

	n->SendFifo = NewFifo();
	n->RecvFifo = NewFifo();

	n->TcpStatus = NAT_TCP_CONNECTING;

	n->SendSeqInit = Rand32();
	n->CurrentRTT = NAT_INITIAL_RTT_VALUE;
	n->TcpSendTimeoutSpan = n->CurrentRTT * 2;

	// NAT テーブルに追加
	Add(v->NatTable, n);


#if	1
	{
		IP ip1, ip2;
		char s1[MAX_SIZE], s2[MAX_SIZE];
		UINTToIP(&ip1, src_ip);
		UINTToIP(&ip2, dest_ip);
		IPToStr(s1, 0, &ip1);
		IPToStr(s2, 0, &ip2);
		Debug("NAT_ENTRY: CreateNatTcp %s %u -> %s %u\n", s1, src_port, s2, dest_port);

		NLog(v, "LH_NAT_TCP_CREATED", n->Id, s1, src_port, s2, dest_port);
	}
#endif

	return n;
}

// TCP パケットを仮想ネットワークから受信した
void VirtualTcpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size)
{
	TCP_HEADER *tcp;
	UINT src_port, dest_port;
	UINT header_size, buf_size;
	void *buf;
	IP ip1, ip2;
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}

	// ヘッダを取得
	if (size < TCP_HEADER_SIZE)
	{
		// サイズが小さすぎる
		return;
	}
	tcp = (TCP_HEADER *)data;
	src_port = Endian16(tcp->SrcPort);
	dest_port = Endian16(tcp->DstPort);
	if (src_port == 0 || dest_port == 0)
	{
		// ポート番号が不正
		return;
	}
	if (src_ip == dest_ip || src_ip == 0 || src_ip == 0xffffffff || dest_ip == 0 || dest_ip == 0xffffffff)
	{
		// IP アドレスが不正
		return;
	}
	UINTToIP(&ip1, src_ip);
	UINTToIP(&ip2, dest_ip);
	if (ip1.addr[0] == 127 || ip2.addr[0] == 127)
	{
		// ループバック IP アドレスは指定できない
		return;
	}
	if (IsInNetwork(dest_ip, v->HostIP, v->HostMask))
	{
		// 仮想 LAN 側のネットワーク向けのパケットは無視する
		return;
	}
	// ヘッダサイズを取得
	header_size = TCP_GET_HEADER_SIZE(tcp) * 4;
	if (size < header_size)
	{
		// ヘッダサイズが不正
		return;
	}
	// バッファのサイズとアドレスを取得
	buf_size = size - header_size;
	buf = (void *)(((UCHAR *)data) + header_size);

	TcpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, tcp, buf, buf_size);
}

// NAT UDP ポーリング
void PoolingNatUdp(VH *v, NAT_ENTRY *n)
{
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return;
	}

	// 受信キューにパケットが 1 つ以上あれば処理する
	if (n->UdpRecvQueue->num_item != 0)
	{
		BLOCK *block;

		// すべての UDP パケットを仮想ネットワークに送信する
		while (block = GetNext(n->UdpRecvQueue))
		{
			SendUdp(v, n->SrcIp, n->SrcPort, n->DestIp, n->DestPort,
				block->Buf, block->Size);

			FreeBlock(block);
		}
	}
}

// NAT ポーリング
void PoolingNat(VH *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// すべての NAT エントリを走査し処理を行う
	for (i = 0;i < LIST_NUM(v->NatTable);i++)
	{
		NAT_ENTRY *n = LIST_DATA(v->NatTable, i);

		switch (n->Protocol)
		{
		case NAT_TCP:
			PollingNatTcp(v, n);
			break;

		case NAT_UDP:
			PoolingNatUdp(v, n);
			break;

		case NAT_DNS:
			PollingNatDns(v, n);
			break;
		}
	}
}

// NAT テーブルの比較関数
int CompareNat(void *p1, void *p2)
{
	NAT_ENTRY *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NAT_ENTRY **)p1;
	n2 = *(NAT_ENTRY **)p2;
	if (n1 == n2)
	{
		return 0;
	}

	if (n1->SrcIp > n2->SrcIp) return 1;
	else if (n1->SrcIp < n2->SrcIp) return -1;
	else if (n1->DestIp > n2->DestIp) return 1;
	else if (n1->DestIp < n2->DestIp) return -1;
	else if (n1->SrcPort > n2->SrcPort) return 1;
	else if (n1->SrcPort < n2->SrcPort) return -1;
	else if (n1->DestPort > n2->DestPort) return 1;
	else if (n1->DestPort < n2->DestPort) return -1;
	else if (n1->Protocol > n2->Protocol) return 1;
	else if (n1->Protocol < n2->Protocol) return -1;
	else return 0;
}

// NAT 構造体の設定
void SetNat(NAT_ENTRY *n, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT public_ip, UINT public_port)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	n->Protocol = protocol;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;
	n->PublicIp = public_ip;
	n->PublicPort = public_port;
}

// NAT の初期化
void InitNat(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// NAT テーブルの作成
	v->NatTable = NewList(CompareNat);

	// ソケットイベントの作成
	v->SockEvent = NewSockEvent();

	// NAT 用スレッドの作成
	v->HaltNat = false;
	v->NatThread = NewThread(NatThread, (void *)v);
	WaitThreadInit(v->NatThread);
}

// NAT の解放
void FreeNat(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// NAT 用スレッドの停止
	v->HaltNat = true;
	SetSockEvent(v->SockEvent);
	WaitThread(v->NatThread, INFINITE);
	ReleaseThread(v->NatThread);
	v->NatThread = NULL;
	ReleaseSockEvent(v->SockEvent);
	v->SockEvent = NULL;

	// NAT テーブルの解放
	ReleaseList(v->NatTable);
}

// NAT テーブルの検索
NAT_ENTRY *SearchNat(VH *v, NAT_ENTRY *target)
{
	NAT_ENTRY *n;
	// 引数チェック
	if (v == NULL || target == NULL)
	{
		return NULL;
	}

	// バイナリサーチ
	n = (NAT_ENTRY *)Search(v->NatTable, target);

	return n;
}

// UDP NAT エントリの削除
void DeleteNatUdp(VH *v, NAT_ENTRY *n)
{
	BLOCK *block;
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return;
	}

	NLog(v, "LH_NAT_UDP_DELETED", n->Id);

	// すべてのキューを解放
	while (block = GetNext(n->UdpRecvQueue))
	{
		FreeBlock(block);
	}
	ReleaseQueue(n->UdpRecvQueue);
	while (block = GetNext(n->UdpSendQueue))
	{
		FreeBlock(block);
	}
	ReleaseQueue(n->UdpSendQueue);

	// ソケットを解放
	if (n->Sock != NULL)
	{
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	DeleteLock(n->lock);

	// テーブルから削除
	Delete(v->NatTable, n);

	// メモリ解放
	Free(n);

	Debug("NAT: DeleteNatUdp\n");

}

// NAT UDP エントリを作成
NAT_ENTRY *CreateNatUdp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT dns_proxy_ip)
{
	NAT_ENTRY *n;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	if (CanCreateNewNatEntry(v) == false)
	{
		return NULL;
	}

	n = ZeroMalloc(sizeof(NAT_ENTRY));
	n->Id = Inc(v->Counter);
	n->v = v;
	n->lock = NewLock();
	n->Protocol = NAT_UDP;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;

	if (dns_proxy_ip != 0)
	{
		n->ProxyDns = true;
		n->DestIpProxy = dns_proxy_ip;
	}

	n->CreatedTime = n->LastCommTime = v->Now;

	n->UdpSendQueue = NewQueue();
	n->UdpRecvQueue = NewQueue();

	n->UdpSocketCreated = false;

	SetSockEvent(v->SockEvent);

#if	1
	{
		IP ip1, ip2;
		char s1[MAX_SIZE], s2[MAX_SIZE];
		UINTToIP(&ip1, src_ip);
		UINTToIP(&ip2, dest_ip);
		IPToStr(s1, 0, &ip1);
		IPToStr(s2, 0, &ip2);
		Debug("NAT_ENTRY: CreateNatUdp %s %u -> %s %u\n", s1, src_port, s2, dest_port);

		NLog(v, "LH_NAT_UDP_CREATED", n->Id, s1, src_port, s2, dest_port);
	}
#endif

	Add(v->NatTable, n);

	return n;
}

// インターネットへの UDP パケットの処理
void UdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy)
{
	NAT_ENTRY *n, t;
	BLOCK *block;
	void *buf;
	UINT dns_ip = 0;
	// 引数チェック
	if (data == NULL || v == NULL)
	{
		return;
	}

	if (dns_proxy)
	{
		// プロキシ接続先の DNS サーバーを取得する
		IP ip;
		char tmp[MAX_SIZE];
		if (GetDefaultDns(&ip) == false)
		{
			// 失敗
			Debug("Failed to GetDefaultDns()\n");
			return;
		}
		dns_ip = IPToUINT(&ip);
		IPToStr(tmp, sizeof(tmp), &ip);
		Debug("Redirect to DNS Server %s\n", tmp);
	}

	// このパケットに関する NAT エントリがすでに作成されているかどうかを調べる
	SetNat(&t, NAT_UDP, src_ip, src_port, dest_ip, dest_port, 0, 0);
	n = SearchNat(v, &t);

	if (n == NULL)
	{
		// 最初のパケットなので NAT エントリを作成する
		n = CreateNatUdp(v, src_ip, src_port, dest_ip, dest_port, dns_proxy ? dns_ip : 0);
		if (n == NULL)
		{
			// エントリ作成失敗
			return;
		}

		if (dns_proxy)
		{
			n->ProxyDns = true;
			n->DestIpProxy = dns_ip;
		}
	}

	// キューにパケットを挿入してイベントを呼び出す
	buf = Malloc(size);
	Copy(buf, data, size);
	block = NewBlock(buf, size, 0);
	InsertQueue(n->UdpSendQueue, block);

	SetSockEvent(v->SockEvent);
}

// DNS パケットの解釈を試行する
bool ParseDnsPacket(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	DNSV4_HEADER *dns;
	NAT_ENTRY *nat;
	UINT transaction_id;
	void *query_data;
	UINT query_data_size;
	char hostname[256];
	// 引数チェック
	if (v == NULL || data == NULL || size == 0)
	{
		return false;
	}

	// ヘッダサイズのチェック
	if (size < sizeof(DNSV4_HEADER))
	{
		// サイズ不足
		return false;
	}

	// DNS ヘッダ取得
	dns = (DNSV4_HEADER *)data;
	transaction_id = Endian16(dns->TransactionId);
	if ((dns->Flag1 & 78) != 0 || (dns->Flag1 & 0x80) != 0)
	{
		// オペコード不正
		return false;
	}
	if (Endian16(dns->NumQuery) != 1)
	{
		// クエリ数不正
		return false;
	}

	query_data = ((UCHAR *)dns) + sizeof(DNSV4_HEADER);
	query_data_size = size - sizeof(DNSV4_HEADER);

	// クエリの解釈
	if (ParseDnsQuery(hostname, sizeof(hostname), query_data, query_data_size) == false)
	{
		// 解釈失敗
		return false;
	}

	// DNS エントリの作成
	nat = CreateNatDns(v, src_ip, src_port, dest_ip, dest_port, transaction_id,
		false, hostname);

	if (nat == false)
	{
		return false;
	}

	return true;
}

// NAT DNS 応答パケットの送信
void SendNatDnsResponse(VH *v, NAT_ENTRY *n)
{
	BUF *b;
	UINT dns_header_size;
	DNSV4_HEADER *dns;
	// 引数チェック
	if (n == NULL || v == NULL)
	{
		return;
	}

	// データの生成
	b = NewBuf();

	// Query の追加
	if (n->DnsGetIpFromHost == false)
	{
		BuildDnsQueryPacket(b, n->DnsTargetHostName, false);
	}
	else
	{
		BuildDnsQueryPacket(b, n->DnsTargetHostName, true);
	}

	// Response の追加
	if (n->DnsOk)
	{
		if (n->DnsGetIpFromHost == false)
		{
			BuildDnsResponsePacketA(b, &n->DnsResponseIp);
		}
		else
		{
			BuildDnsResponsePacketPtr(b, n->DnsResponseHostName);
		}
	}

	// DNS ヘッダの生成
	dns_header_size = sizeof(DNSV4_HEADER) + b->Size;

	dns = ZeroMalloc(dns_header_size);
	dns->TransactionId = Endian16((USHORT)n->DnsTransactionId);

	// 応答フラグの生成
	if (n->DnsOk)
	{
		dns->Flag1 = 0x85;
		dns->Flag2 = 0x80;
	}
	else
	{
		dns->Flag1 = 0x85;
		dns->Flag2 = 0x83;
	}

	dns->NumQuery = Endian16(1);
	dns->AnswerRRs = Endian16(n->DnsOk != false ? 1 : 0);
	dns->AuthorityRRs = 0;
	dns->AdditionalRRs = 0;

	// データのコピー
	Copy(((UCHAR *)dns) + sizeof(DNSV4_HEADER), b->Buf, b->Size);

	// このパケットを送信
	SendUdp(v, n->SrcIp, n->SrcPort, n->DestIp, n->DestPort, dns, dns_header_size);

	// メモリ解放
	Free(dns);
	FreeBuf(b);
}

// DNS 応答パケット (ホスト名) の生成
void BuildDnsResponsePacketPtr(BUF *b, char *hostname)
{
	USHORT magic;
	USHORT type, clas;
	UINT ttl;
	USHORT len;
	BUF *c;
	// 引数チェック
	if (b == NULL || hostname == NULL)
	{
		return;
	}

	magic = Endian16(0xc00c);
	type = Endian16(0x000c);
	clas = Endian16(0x0001);
	ttl = Endian32(NAT_DNS_RESPONSE_TTL);

	c = BuildDnsHostName(hostname);
	if (c == NULL)
	{
		return;
	}
	len = Endian16((USHORT)c->Size);

	WriteBuf(b, &magic, 2);
	WriteBuf(b, &type, 2);
	WriteBuf(b, &clas, 2);
	WriteBuf(b, &ttl, 4);
	WriteBuf(b, &len, 2);
	WriteBuf(b, c->Buf, c->Size);
	FreeBuf(c);
}

// DNS 応答パケット (ホスト IP アドレス) の生成
void BuildDnsResponsePacketA(BUF *b, IP *ip)
{
	UINT ip_addr;
	USHORT magic;
	USHORT type, clas;
	UINT ttl;
	USHORT len;
	// 引数チェック
	if (b == NULL || ip == NULL)
	{
		return;
	}

	ip_addr = IPToUINT(ip);
	magic = Endian16(0xc00c);
	type = Endian16(0x0001);
	clas = Endian16(0x0001);
	ttl = Endian32(NAT_DNS_RESPONSE_TTL);
	len = Endian16((USHORT)sizeof(ttl));

	WriteBuf(b, &magic, sizeof(magic));
	WriteBuf(b, &type, sizeof(type));
	WriteBuf(b, &clas, sizeof(clas));
	WriteBuf(b, &ttl, sizeof(ttl));
	WriteBuf(b, &len, sizeof(len));
	WriteBuf(b, &ip_addr, sizeof(ip_addr));
}

// DNS クエリデータパケットの生成
void BuildDnsQueryPacket(BUF *b, char *hostname, bool ptr)
{
	USHORT val;
	BUF *c;
	// 引数チェック
	if (b == NULL || hostname == NULL)
	{
		return;
	}

	// ホスト名をバッファに変換
	c = BuildDnsHostName(hostname);
	if (c == NULL)
	{
		return;
	}

	WriteBuf(b, c->Buf, c->Size);
	FreeBuf(c);

	// 種類とクラス
	if (ptr == false)
	{
		val = Endian16(0x0001);
	}
	else
	{
		val = Endian16(0x000c);
	}
	WriteBuf(b, &val, 2);

	val = Endian16(0x0001);
	WriteBuf(b, &val, 2);
}

// DNS ホスト名バッファの生成
BUF *BuildDnsHostName(char *hostname)
{
	UINT i;
	UCHAR size;
	TOKEN_LIST *token;
	BUF *b;
	// 引数チェック
	if (hostname == NULL)
	{
		return NULL;
	}

	// ホスト名をトークンに分割
	token = ParseToken(hostname, ".");
	if (token == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// ホスト文字列を追加
	for (i = 0;i < token->NumTokens;i++)
	{
		size = (UCHAR)StrLen(token->Token[i]);
		WriteBuf(b, &size, 1);
		WriteBuf(b, token->Token[i], size);
	}

	// NULL 文字
	size = 0;
	WriteBuf(b, &size, 1);

	SeekBuf(b, 0, 0);

	FreeToken(token);

	return b;
}

// NAT DNS エントリの処理
void PollingNatDns(VH *v, NAT_ENTRY *n)
{
	// 引数チェック
	if (v == NULL || n == NULL)
	{
		return;
	}

	if (n->DnsFinished)
	{
		if (n->DnsPollingFlag == false)
		{
			n->DnsPollingFlag = true;
			// 処理が完了した
			SendNatDnsResponse(v, n);

			// 終了処理
			n->DisconnectNow = true;
		}
	}
}

// NAT DNS エントリの作成
NAT_ENTRY *CreateNatDns(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port,
				  UINT transaction_id, bool dns_get_ip_from_host, char *dns_target_host_name)
{
	NAT_ENTRY *n;
	// 引数チェック
	if (v == NULL || dns_target_host_name == NULL)
	{
		return NULL;
	}

	if (CanCreateNewNatEntry(v) == false)
	{
		return NULL;
	}

	n = ZeroMalloc(sizeof(NAT_ENTRY));
	n->Id = Inc(v->Counter);
	n->v = v;
	n->lock = NewLock();
	n->Protocol = NAT_DNS;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;
	n->DnsTransactionId = transaction_id;
	n->CreatedTime = n->LastCommTime = v->Now;
	n->DisconnectNow = false;

	n->DnsGetIpFromHost = false;
	n->DnsTargetHostName = CopyStr(dns_target_host_name);

	Add(v->NatTable, n);

#if	1
	{
		IP ip1, ip2;
		char s1[MAX_SIZE], s2[MAX_SIZE];
		UINTToIP(&ip1, src_ip);
		UINTToIP(&ip2, dest_ip);
		IPToStr(s1, 0, &ip1);
		IPToStr(s2, 0, &ip2);
		Debug("NAT_ENTRY: CreateNatDns %s %u -> %s %u\n", s1, src_port, s2, dest_port);
	}
#endif


	return n;
}

// 次のバイトを取得
UCHAR GetNextByte(BUF *b)
{
	UCHAR c = 0;
	// 引数チェック
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &c, 1) != 1)
	{
		return 0;
	}

	return c;
}

// DNS クエリの解釈
bool ParseDnsQuery(char *name, UINT name_size, void *data, UINT data_size)
{
	BUF *b;
	char tmp[257];
	bool ok = true;
	USHORT val;
	// 引数チェック
	if (name == NULL || data == NULL || data_size == 0)
	{
		return false;
	}
	StrCpy(name, name_size, "");

	b = NewBuf();
	WriteBuf(b, data, data_size);
	SeekBuf(b, 0, 0);

	while (true)
	{
		UINT next_len = (UINT)GetNextByte(b);
		if (next_len > 0)
		{
			// 指定した文字だけ読む
			Zero(tmp, sizeof(tmp));
			if (ReadBuf(b, tmp, next_len) != next_len)
			{
				ok = false;
				break;
			}
			// 追記
			if (StrLen(name) != 0)
			{
				StrCat(name, name_size, ".");
			}
			StrCat(name, name_size, tmp);
		}
		else
		{
			// すべて読み終えた
			break;
		}
	}

	if (ReadBuf(b, &val, sizeof(val)) != sizeof(val))
	{
		ok = false;
	}
	else
	{
		if (Endian16(val) != 0x01 && Endian16(val) != 0x0c)
		{
			ok = false;
		}
	}

	if (ReadBuf(b, &val, sizeof(val)) != sizeof(val))
	{
		ok = false;
	}
	else
	{
		if (Endian16(val) != 0x01)
		{
			ok = false;
		}
	}

	FreeBuf(b);

	if (ok == false || StrLen(name) == 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// DNS プロキシとして動作する
void DnsProxy(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	// 引数チェック
	if (v == NULL || data == NULL || size == 0)
	{
		return;
	}

	// まず DNS クエリを解釈することができるかどうか試してみる
	//if (ParseDnsPacket(v, src_ip, src_port, dest_ip, dest_port, data, size) == false)
	{
		// うまくいかない場合は要求をそのまま投げる
		UdpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, data, size, true);
	}
}

// 仮想ホストへの UDP パケットの処理
void UdpRecvForMe(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	// 引数チェック
	if (data == NULL || v == NULL)
	{
		return;
	}

	if (dest_port == NAT_DNS_PROXY_PORT)
	{
		// DNS プロキシ起動
		DnsProxy(v, src_ip, src_port, dest_ip, dest_port, data, size);
	}
}

// ブロードキャスト UDP パケットの処理
void UdpRecvForBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	// 引数チェック
	if (data == NULL || v == NULL)
	{
		return;
	}
}

// UDP パケットを受信した
void VirtualUdpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, bool mac_broadcast)
{
	UDP_HEADER *udp;
	UINT packet_length;
	void *buf;
	UINT buf_size;
	UINT src_port, dest_port;
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}

	// ヘッダのチェック
	udp = (UDP_HEADER *)data;
	if (size < UDP_HEADER_SIZE)
	{
		return;
	}
	packet_length = Endian16(udp->PacketLength);
	if (packet_length != size)
	{
		return;
	}
	buf = ((UCHAR *)data) + UDP_HEADER_SIZE;
	buf_size = size - UDP_HEADER_SIZE;
	src_port = Endian16(udp->SrcPort);
	dest_port = Endian16(udp->DstPort);
	// ポート番号をチェック
	if (dest_port == 0)
	{
		// ポート番号が不正
		return;
	}

	// 自分宛のパケットまたはブロードキャストパケットかどうか判別する
	if (dest_ip == v->HostIP)
	{
		// 自分宛のパケットが届いた
		UdpRecvForMe(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size);
	}
	else if (mac_broadcast || dest_ip == 0xffffffff || dest_ip == GetBroadcastAddress(v->HostIP, v->HostMask))
	{
		// ブロードキャストパケットが届いた
		UdpRecvForBroadcast(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size);
	}
	else if (IsInNetwork(dest_ip, v->HostIP, v->HostMask) == false)
	{
		// ローカルアドレス以外 (つまりインターネット上) へのパケットが届いた
		UdpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size, false);
	}
	else
	{
		// ローカルアドレスが届いた。無視
	}
}

// 指定した IP アドレスの属するサブネットのネットワークアドレスを求める
UINT GetNetworkAddress(UINT addr, UINT mask)
{
	return (addr & mask);
}

// 指定した IP アドレスの属するサブネットのブロードキャストアドレスを求める
UINT GetBroadcastAddress(UINT addr, UINT mask)
{
	return ((addr & mask) | (~mask));
}

// 指定した IP アドレスが別の指定したアドレスとサブネットマスクによって表現される
// サブネットワークに所属しているかどうか判別する
bool IsInNetwork(UINT uni_addr, UINT network_addr, UINT mask)
{
	if (GetNetworkAddress(uni_addr, mask) == GetNetworkAddress(network_addr, mask))
	{
		return true;
	}
	return false;
}

// UDP パケットの送信
void SendUdp(VH *v, UINT dest_ip, UINT dest_port, UINT src_ip, UINT src_port, void *data, UINT size)
{
	UDPV4_PSEUDO_HEADER *vh;
	UDP_HEADER *udp;
	UINT udp_packet_length = UDP_HEADER_SIZE + size;
	USHORT checksum;
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}
	if (udp_packet_length > 65536)
	{
		return;
	}

	// 仮想ヘッダを生成
	vh = Malloc(sizeof(UDPV4_PSEUDO_HEADER) + size);
	udp = (UDP_HEADER *)(((UCHAR *)vh) + 12);

	vh->SrcIP = src_ip;
	vh->DstIP = dest_ip;
	vh->Reserved = 0;
	vh->Protocol = IP_PROTO_UDP;
	vh->PacketLength1 = Endian16((USHORT)udp_packet_length);
	udp->SrcPort = Endian16((USHORT)src_port);
	udp->DstPort = Endian16((USHORT)dest_port);
	udp->PacketLength = Endian16((USHORT)udp_packet_length);
	udp->Checksum = 0;

	// データをコピー
	Copy(((UCHAR *)udp) + UDP_HEADER_SIZE, data, size);

	// チェックサムを計算
	checksum = IpChecksum(vh, udp_packet_length + 12);
	if (checksum == 0x0000)
	{
		checksum = 0xffff;
	}
	udp->Checksum = checksum;

	// パケットを送信
	SendIp(v, dest_ip, src_ip, IP_PROTO_UDP, udp, udp_packet_length);

	// メモリ解放
	Free(vh);
}

// IP 結合オブジェクトのポーリング
void PollingIpCombine(VH *v)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// 古い結合オブジェクトを破棄する
	o = NULL;
	for (i = 0;i < LIST_NUM(v->IpCombine);i++)
	{
		IP_COMBINE *c = LIST_DATA(v->IpCombine, i);

		if (c->Expire < v->Now)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, c);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP_COMBINE *c = LIST_DATA(o, i);

			// リストから削除
			Delete(v->IpCombine, c);

			// メモリ解放
			FreeIpCombine(v, c);
		}
		ReleaseList(o);
	}
}

// ICMP パケットを送信する
void VirtualIcmpSend(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size)
{
	ICMP_HEADER *icmp;
	void *data_buf;
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}

	// ヘッダ組み立て
	icmp = ZeroMalloc(sizeof(ICMP_HEADER) + size);
	// データコピー
	data_buf = ((UCHAR *)icmp) + sizeof(ICMP_HEADER);
	Copy(data_buf, data, size);
	// その他
	icmp->Checksum = 0;
	icmp->Code = 0;
	icmp->Type = ICMP_TYPE_ECHO_RESPONSE;
	// チェックサム
	icmp->Checksum = IpChecksum(icmp, sizeof(ICMP_HEADER) + size);

	// IP パケット送信
	SendIp(v, dst_ip, src_ip, IP_PROTO_ICMPV4, icmp, sizeof(ICMP_HEADER) + size);

	// メモリ解放
	Free(icmp);
}

// ICMP Echo Response パケットを送信する
void VirtualIcmpEchoSendResponse(VH *v, UINT src_ip, UINT dst_ip, USHORT id, USHORT seq_no, void *data, UINT size)
{
	ICMP_ECHO *e;
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}

	// ヘッダ組み立て
	e = ZeroMalloc(sizeof(ICMP_ECHO) + size);
	e->Identifier = Endian16(id);
	e->SeqNo = Endian16(seq_no);

	// データコピー
	Copy(((UCHAR *)e) + sizeof(ICMP_ECHO), data, size);

	// ICMP 送信
	VirtualIcmpSend(v, src_ip, dst_ip, e, sizeof(ICMP_ECHO) + size);

	// メモリ解放
	Free(e);
}

// ICMP Echo Request パケットを受信した
void VirtualIcmpEchoRequestReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size)
{
	ICMP_ECHO *echo;
	UINT data_size;
	void *data_buf;
	USHORT id, seq_no;
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}

	echo = (ICMP_ECHO *)data;

	// エコーサイズチェック
	if (size < sizeof(ICMP_ECHO))
	{
		// データが足らない
		return;
	}

	id = Endian16(echo->Identifier);
	seq_no = Endian16(echo->SeqNo);

	// データサイズ
	data_size = size - sizeof(ICMP_ECHO);

	// データ本体
	data_buf = ((UCHAR *)data) + sizeof(ICMP_ECHO);

	// ICMP Echo Response を返す
	VirtualIcmpEchoSendResponse(v, dst_ip, src_ip, id, seq_no, data_buf, data_size);
}

// ICMP パケットを受信した
void VirtualIcmpReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size)
{
	ICMP_HEADER *icmp;
	UINT msg_size;
	USHORT checksum_calc, checksum_original;
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}

	// サイズチェック
	if (size < sizeof(ICMP_HEADER))
	{
		return;
	}

	// ICMP ヘッダ
	icmp = (ICMP_HEADER *)data;

	// ICMP メッセージサイズの取得
	msg_size = size - sizeof(ICMP_HEADER);

	// ICMP ヘッダのチェックサムをチェックする
	checksum_original = icmp->Checksum;
	icmp->Checksum = 0;
	checksum_calc = IpChecksum(data, size);
	icmp->Checksum = checksum_original;

	if (checksum_calc != checksum_original)
	{
		// チェックサムが不正
		Debug("ICMP CheckSum Failed.\n");
		return;
	}

	// オペコードによって識別
	switch (icmp->Type)
	{
	case ICMP_TYPE_ECHO_REQUEST:	// ICMP Echo 要求
		VirtualIcmpEchoRequestReceived(v, src_ip, dst_ip, ((UCHAR *)data) + sizeof(ICMP_HEADER), msg_size);
		break;

	case ICMP_TYPE_ECHO_RESPONSE:	// ICMP Echo 応答
		// 何もしない
		break;
	}
}

// IP パケットを受信した
void IpReceived(VH *v, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size, bool mac_broadcast)
{
	// 引数チェック
	if (v == NULL || data == NULL)
	{
		return;
	}

	// サポートされている上位プロトコルにデータを渡す
	switch (protocol)
	{
	case IP_PROTO_ICMPV4:	// ICMPv4
		VirtualIcmpReceived(v, src_ip, dest_ip, data, size);
		break;

	case IP_PROTO_TCP:		// TCP
		if (mac_broadcast == false)
		{
			VirtualTcpReceived(v, src_ip, dest_ip, data, size);
		}
		break;

	case IP_PROTO_UDP:		// UDP
		VirtualUdpReceived(v, src_ip, dest_ip, data, size, mac_broadcast);
		break;
	}
}

// IP ヘッダのチェックサムを確認する
bool IpCheckChecksum(IPV4_HEADER *ip)
{
	UINT header_size;
	USHORT checksum_original, checksum_calc;
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	header_size = IPV4_GET_HEADER_LEN(ip) * 4;
	checksum_original = ip->Checksum;
	ip->Checksum = 0;
	checksum_calc = IpChecksum(ip, header_size);
	ip->Checksum = checksum_original;

	if (checksum_original == checksum_calc)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// チェックサムを計算する
USHORT IpChecksum(void *buf, UINT size)
{
	int sum = 0;
	USHORT *addr = (USHORT *)buf;
	int len = (int)size;
	USHORT *w = addr;
	int nleft = len;
	USHORT answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(UCHAR *)(&answer) = *(UCHAR *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	answer = ~sum;
	
	return answer;
}

// IP 結合オブジェクトに新しく受信した IP パケットを結合する
void CombineIp(VH *v, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet)
{
	UINT i;
	IP_PART *p;
	UINT need_size;
	UINT data_size_delta;
	// 引数チェック
	if (c == NULL || data == NULL)
	{
		return;
	}

	// オフセットとサイズをチェック
	if ((offset + size) > 65535)
	{
		// 64Kbytes を超えるパケットは処理しない
		return;
	}

	if (last_packet == false && c->Size != 0)
	{
		if ((offset + size) > c->Size)
		{
			// パケットサイズより大きいパケットは処理しない
			return;
		}
	}

	need_size = offset + size;
	data_size_delta = c->DataReserved;
	// バッファが不足している場合は十分確保する
	while (c->DataReserved < need_size)
	{
		c->DataReserved = c->DataReserved * 4;
		c->Data = ReAlloc(c->Data, c->DataReserved);
	}
	data_size_delta = c->DataReserved - data_size_delta;
	v->CurrentIpQuota += data_size_delta;

	// データをバッファに上書きする
	Copy(((UCHAR *)c->Data) + offset, data, size);

	if (last_packet)
	{
		// No More Flagment パケットが届いた場合、このデータグラムのサイズが確定する
		c->Size = offset + size;
	}

	// オフセットとサイズによって表現されている領域と既存の受信済みリストの
	// オフセットとサイズによって表現されている領域との間の重複をチェックする
	for (i = 0;i < LIST_NUM(c->IpParts);i++)
	{
		UINT moving_size;
		IP_PART *p = LIST_DATA(c->IpParts, i);

		// 先頭領域と既存領域との重複をチェック
		if ((p->Offset <= offset) && ((p->Offset + p->Size) > offset))
		{
			// このパケットと既存パケットとの間で先頭部分に重複が見つかったので
			// このパケットのオフセットを後方に圧縮する

			if ((offset + size) <= (p->Offset + p->Size))
			{
				// このパケットは既存のパケットの中に埋もれている
				size = 0;
			}
			else
			{
				// 後方領域は重なっていない
				moving_size = p->Offset + p->Size - offset;
				offset += moving_size;
				size -= moving_size;
			}
		}
		if ((p->Offset < (offset + size)) && ((p->Offset + p->Size) >= (offset + size)))
		{
			// このパケットと既存パケットとの間で後方部分に重複が見つかったので
			// このパケットのサイズを前方に圧縮する

			moving_size = p->Offset + p->Size - offset - size;
			size -= moving_size;
		}

		if ((p->Offset >= offset) && ((p->Offset + p->Size) <= (offset + size)))
		{
			// このパケットが既存のパケットを完全に覆いかぶさるように上書きされた
			p->Size = 0;
		}
	}

	if (size != 0)
	{
		// このパケットを登録する
		p = ZeroMalloc(sizeof(IP_PART));

		p->Offset = offset;
		p->Size = size;

		Add(c->IpParts, p);
	}

	if (c->Size != 0)
	{
		// すでに受信したデータ部分リストの合計サイズを取得する
		UINT total_size = 0;
		UINT i;

		for (i = 0;i < LIST_NUM(c->IpParts);i++)
		{
			IP_PART *p = LIST_DATA(c->IpParts, i);

			total_size += p->Size;
		}

		if (total_size == c->Size)
		{
			// IP パケットをすべて受信した
			IpReceived(v, c->SrcIP, c->DestIP, c->Protocol, c->Data, c->Size, c->MacBroadcast);

			// 結合オブジェクトの解放
			FreeIpCombine(v, c);

			// 結合オブジェクトをリストから削除
			Delete(v->IpCombine, c);
		}
	}
}

// IP 結合オブジェクトの解放
void FreeIpCombine(VH *v, IP_COMBINE *c)
{
	UINT i;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// データ解放
	v->CurrentIpQuota -= c->DataReserved;
	Free(c->Data);

	// 部分リスト解放
	for (i = 0;i < LIST_NUM(c->IpParts);i++)
	{
		IP_PART *p = LIST_DATA(c->IpParts, i);

		Free(p);
	}

	ReleaseList(c->IpParts);
	Free(c);
}

// IP 結合リストを検索
IP_COMBINE *SearchIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol)
{
	IP_COMBINE *c, t;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	t.DestIP = dest_ip;
	t.SrcIP = src_ip;
	t.Id = id;
	t.Protocol = protocol;

	c = Search(v->IpCombine, &t);

	return c;
}

// IP 結合リストに新しいオブジェクトを作成して挿入
IP_COMBINE *InsertIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast)
{
	IP_COMBINE *c;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	// クォータを調べる
	if ((v->CurrentIpQuota + IP_COMBINE_INITIAL_BUF_SIZE) > IP_COMBINE_WAIT_QUEUE_SIZE_QUOTA)
	{
		// これ以上 IP パケットを格納できない
		return NULL;
	}

	c = ZeroMalloc(sizeof(IP_COMBINE));
	c->DestIP = dest_ip;
	c->SrcIP = src_ip;
	c->Id = id;
	c->Expire = v->Now + (UINT64)IP_COMBINE_TIMEOUT;
	c->Size = 0;
	c->IpParts = NewList(NULL);
	c->Protocol = protocol;
	c->MacBroadcast = mac_broadcast;

	// メモリを確保
	c->DataReserved = IP_COMBINE_INITIAL_BUF_SIZE;
	c->Data = Malloc(c->DataReserved);
	v->CurrentIpQuota += c->DataReserved;

	Insert(v->IpCombine, c);

	return c;
}

// IP 結合リストの初期化
void InitIpCombineList(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	v->IpCombine = NewList(CompareIpCombine);
}

// IP 結合リストの解放
void FreeIpCombineList(VH *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(v->IpCombine);i++)
	{
		IP_COMBINE *c = LIST_DATA(v->IpCombine, i);

		FreeIpCombine(v, c);
	}

	ReleaseList(v->IpCombine);
}

// IP 結合リストの比較
int CompareIpCombine(void *p1, void *p2)
{
	IP_COMBINE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IP_COMBINE **)p1;
	c2 = *(IP_COMBINE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}
	if (c1->Id > c2->Id)
	{
		return 1;
	}
	else if (c1->Id < c2->Id)
	{
		return -1;
	}
	else if (c1->DestIP > c2->DestIP)
	{
		return 1;
	}
	else if (c1->DestIP < c2->DestIP)
	{
		return -1;
	}
	else if (c1->SrcIP > c2->SrcIP)
	{
		return 1;
	}
	else if (c1->SrcIP < c2->SrcIP)
	{
		return -1;
	}
	else if (c1->Protocol > c2->Protocol)
	{
		return 1;
	}
	else if (c1->Protocol < c2->Protocol)
	{
		return -1;
	}
	return 0;
}

// IP パケットを受信した
void VirtualIpReceived(VH *v, PKT *packet)
{
	IPV4_HEADER *ip;
	void *data;
	UINT data_size_recved;
	UINT size;
	UINT ipv4_header_size;
	bool last_packet;
	// 引数チェック
	if (v == NULL || packet == NULL)
	{
		return;
	}

	ip = packet->L3.IPv4Header;

	// IPv4 ヘッダのサイズを取得する
	ipv4_header_size = IPV4_GET_HEADER_LEN(packet->L3.IPv4Header) * 4;

	// IPv4 ヘッダのチェックサムを計算する
	if (IpCheckChecksum(ip) == false)
	{
		return;
	}

	// データへのポインタを取得する
	data = ((UCHAR *)packet->L3.PointerL3) + ipv4_header_size;

	// ARP テーブルに登録しておく
	ArpIpWasKnown(v, packet->L3.IPv4Header->SrcIP, packet->MacAddressSrc);

	// データサイズを取得する
	size = Endian16(ip->TotalLength);
	if (size <= ipv4_header_size)
	{
		// データが無い
		return;
	}
	size -= ipv4_header_size;

	// 実際に受信したデータサイズを取得する
	data_size_recved = packet->PacketSize - (ipv4_header_size + MAC_HEADER_SIZE);
	if (data_size_recved < size)
	{
		// データが足りない (途中で欠落しているかも知れない)
		return;
	}

	if (IPV4_GET_OFFSET(ip) == 0 && (IPV4_GET_FLAGS(ip) & 0x01) == 0)
	{
		// このパケットは分割されていないので直ちに上位層に渡すことができる
		IpReceived(v, ip->SrcIP, ip->DstIP, ip->Protocol, data, size, packet->BroadcastPacket);
	}
	else
	{
		// このパケットは分割されているので結合する必要がある

		UINT offset = IPV4_GET_OFFSET(ip) * 8;
		IP_COMBINE *c = SearchIpCombine(v, ip->SrcIP, ip->DstIP, Endian16(ip->Identification), ip->Protocol);

		last_packet = ((IPV4_GET_FLAGS(ip) & 0x01) == 0 ? true : false);

		if (c != NULL)
		{
			// 2 個目移行のパケットである
			CombineIp(v, c, offset, data, size, last_packet);
		}
		else
		{
			// 最初のパケットなので結合オブジェクトを作成する
			c = InsertIpCombine(
				v, ip->SrcIP, ip->DstIP, Endian16(ip->Identification), ip->Protocol, packet->BroadcastPacket);
			if (c != NULL)
			{
				CombineIp(v, c, offset, data, size, last_packet);
			}
		}
	}
}

// 待機している IP パケットのうち指定した IP アドレスからのものを送信する
void SendWaitingIp(VH *v, UCHAR *mac, UINT dest_ip)
{
	UINT i;
	LIST *o = NULL;
	// 引数チェック
	if (v == NULL || mac == NULL)
	{
		return;
	}

	// 対象リストを取得する
	for (i = 0;i < LIST_NUM(v->IpWaitTable);i++)
	{
		IP_WAIT *w = LIST_DATA(v->IpWaitTable, i);

		if (w->DestIP == dest_ip)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, w);
		}
	}

	// 対象となったパケットを一気に送信する
	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP_WAIT *w = LIST_DATA(o, i);

			// 送信処理
			VirtualIpSend(v, mac, w->Data, w->Size);

			// リストから削除
			Delete(v->IpWaitTable, w);

			// メモリ解放
			Free(w->Data);
			Free(w);
		}

		ReleaseList(o);
	}
}

// 古い IP 待ちテーブルを削除する
void DeleteOldIpWaitTable(VH *v)
{
	UINT i;
	LIST *o = NULL;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// 削除対象リストを取得する
	for (i = 0;i < LIST_NUM(v->IpWaitTable);i++)
	{
		IP_WAIT *w = LIST_DATA(v->IpWaitTable, i);

		if (w->Expire < v->Now)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, w);
		}
	}

	// 一気に削除する
	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP_WAIT *w = LIST_DATA(o, i);

			// リストから削除
			Delete(v->IpWaitTable, w);

			// メモリ解放
			Free(w->Data);
			Free(w);
		}
		ReleaseList(o);
	}
}

// IP 待ちテーブルのポーリング
void PollingIpWaitTable(VH *v)
{
	// 古いテーブルの削除
	DeleteOldIpWaitTable(v);
}

// IP 待ちテーブルに IP パケットを挿入する
void InsertIpWaitTable(VH *v, UINT dest_ip, UINT src_ip, void *data, UINT size)
{
	IP_WAIT *w;
	// 引数チェック
	if (v == NULL || data == NULL || size == 0)
	{
		return;
	}

	w = ZeroMalloc(sizeof(IP_WAIT));
	w->Data = data;
	w->Size = size;
	w->SrcIP = src_ip;
	w->DestIP = dest_ip;
	w->Expire = v->Now + (UINT64)IP_WAIT_FOR_ARP_TIMEOUT;

	Add(v->IpWaitTable, w);
}

// IP 待ちテーブルを初期化する
void InitIpWaitTable(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	v->IpWaitTable = NewList(NULL);
}

// IP 待ちテーブルを解放する
void FreeIpWaitTable(VH *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(v->IpWaitTable);i++)
	{
		IP_WAIT *w = LIST_DATA(v->IpWaitTable, i);

		Free(w->Data);
		Free(w);
	}

	ReleaseList(v->IpWaitTable);
}

// ARP Response が到着するなどして IP アドレスに対する MAC アドレスが判明した
void ArpIpWasKnown(VH *v, UINT ip, UCHAR *mac)
{
	// 引数チェック
	if (v == NULL || mac == NULL)
	{
		return;
	}

	// ARP 待ち行列にこの IP アドレスに対する問い合わせがあった場合は削除する
	DeleteArpWaitTable(v, ip);

	// ARP テーブルに登録または更新する
	InsertArpTable(v, mac, ip);

	// IP 待機リストで待機している IP パケットを送信する
	SendWaitingIp(v, mac, ip);
}

// ARP 待ちリストをチェックし適時 ARP を再発行する
void PollingArpWaitTable(VH *v)
{
	UINT i;
	LIST *o;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// 削除リストの初期化
	o = NULL;

	// すべての ARP 待ちリストを走査
	for (i = 0;i < LIST_NUM(v->ArpWaitTable);i++)
	{
		ARP_WAIT *w = LIST_DATA(v->ArpWaitTable, i);

		if (w->GiveupTime < v->Now || (w->GiveupTime - 100 * 1000) > v->Now)
		{
			// ARP の送信を諦める
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, w);
		}
		else
		{
			if (w->TimeoutTime < v->Now)
			{
				// ARP を再度送信する
				VirtualArpSendRequest(v, w->IpAddress);

				// 次のタイムアウト時刻をセット
				w->TimeoutTime = v->Now + (UINT64)w->NextTimeoutTimeValue;
				// 2 回目以降の ARP 送信間隔は増やしていく
				w->NextTimeoutTimeValue = w->NextTimeoutTimeValue + ARP_REQUEST_TIMEOUT;
			}
		}
	}

	// 削除対象の ARP 待ちレコードがある場合は削除する
	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			ARP_WAIT *w = LIST_DATA(o, i);

			DeleteArpWaitTable(v, w->IpAddress);
		}
		ReleaseList(o);
	}
}

// ARP を発行する
void SendArp(VH *v, UINT ip)
{
	ARP_WAIT *w;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// まず ARP 待ちリストに宛先 IP アドレスが登録されているかどうか調べる
	w = SearchArpWaitTable(v, ip);
	if (w != NULL)
	{
		// すでに登録されているので何もしない
		return;
	}

	// まず ARP パケットを送信する
	VirtualArpSendRequest(v, ip);

	// ARP 待ちリストに登録する
	w = ZeroMalloc(sizeof(ARP_WAIT));
	w->GiveupTime = v->Now + (UINT64)ARP_REQUEST_GIVEUP;
	w->TimeoutTime = v->Now + (UINT64)ARP_REQUEST_TIMEOUT;
	w->NextTimeoutTimeValue = ARP_REQUEST_TIMEOUT;
	w->IpAddress = ip;

	InsertArpWaitTable(v, w);
}

// ARP 待ちテーブルの削除
void DeleteArpWaitTable(VH *v, UINT ip)
{
	ARP_WAIT *w;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	w = SearchArpWaitTable(v, ip);
	if (w == NULL)
	{
		return;
	}
	Delete(v->ArpWaitTable, w);

	Free(w);
}

// ARP 待ちテーブルの検索
ARP_WAIT *SearchArpWaitTable(VH *v, UINT ip)
{
	ARP_WAIT *w, t;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	t.IpAddress = ip;
	w = Search(v->ArpWaitTable, &t);

	return w;
}

// ARP 待ちテーブルに登録
void InsertArpWaitTable(VH *v, ARP_WAIT *w)
{
	// 引数チェック
	if (v == NULL || w == NULL)
	{
		return;
	}

	Add(v->ArpWaitTable, w);
}

// ARP 待ちテーブルの初期化
void InitArpWaitTable(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	v->ArpWaitTable = NewList(CompareArpWaitTable);
}

// ARP 待ちテーブルの解放
void FreeArpWaitTable(VH *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(v->ArpWaitTable);i++)
	{
		ARP_WAIT *w = LIST_DATA(v->ArpWaitTable, i);

		Free(w);
	}

	ReleaseList(v->ArpWaitTable);
}

// MAC アドレスが不正かどうかチェック
bool IsMacInvalid(UCHAR *mac)
{
	UINT i;
	// 引数チェック
	if (mac == NULL)
	{
		return false;
	}

	for (i = 0;i < 6;i++)
	{
		if (mac[i] != 0x00)
		{
			return false;
		}
	}
	return true;
}

// MAC アドレスがブロードキャストアドレスかどうかチェック
bool IsMacBroadcast(UCHAR *mac)
{
	UINT i;
	// 引数チェック
	if (mac == NULL)
	{
		return false;
	}

	for (i = 0;i < 6;i++)
	{
		if (mac[i] != 0xff)
		{
			return false;
		}
	}
	return true;
}

// ARP テーブルにエントリを挿入する
void InsertArpTable(VH *v, UCHAR *mac, UINT ip)
{
	ARP_ENTRY *e, t;
	// 引数チェック
	if (v == NULL || mac == NULL || ip == 0 || ip == 0xffffffff || IsMacBroadcast(mac) || IsMacInvalid(mac))
	{
		return;
	}

	// すでに同じ IP アドレスが登録されていないかどうかチェック
	t.IpAddress = ip;
	e = Search(v->ArpTable, &t);
	if (e != NULL)
	{
		// 登録されていたのでこれを上書きするだけ
		if (Cmp(e->MacAddress, mac, 6) != 0)
		{
			e->Created = v->Now;
			Copy(e->MacAddress, mac, 6);
		}
		e->Expire = v->Now + (UINT64)ARP_ENTRY_EXPIRES;
	}
	else
	{
		// 新しくエントリを作成する
		e = ZeroMalloc(sizeof(ARP_ENTRY));

		e->Created = v->Now;
		e->Expire = v->Now + (UINT64)ARP_ENTRY_EXPIRES;
		Copy(e->MacAddress, mac, 6);
		e->IpAddress = ip;

		Add(v->ArpTable, e);
	}
}

// ARP テーブルのポーリング
void PollingArpTable(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	if (v->Now > v->NextArpTablePolling)
	{
		v->NextArpTablePolling = v->Now + (UINT64)ARP_ENTRY_POLLING_TIME;
		RefreshArpTable(v);
	}
}

// 古い ARP エントリを削除する
void RefreshArpTable(VH *v)
{
	UINT i;
	LIST *o;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	o = NewListFast(NULL);
	for (i = 0;i < LIST_NUM(v->ArpTable);i++)
	{
		ARP_ENTRY *e = LIST_DATA(v->ArpTable, i);

		// 有効期限が切れたものを調べる
		if (e->Expire < v->Now)
		{
			// 有効期限が切れている
			Add(o, e);
		}
	}

	// 有効期限が切れているものを一括して削除する
	for (i = 0;i < LIST_NUM(o);i++)
	{
		ARP_ENTRY *e = LIST_DATA(o, i);

		Delete(v->ArpTable, e);
		Free(e);
	}

	ReleaseList(o);
}

// ARP テーブルの検索
ARP_ENTRY *SearchArpTable(VH *v, UINT ip)
{
	ARP_ENTRY *e, t;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	t.IpAddress = ip;
	e = Search(v->ArpTable, &t);

	return e;
}

// ARP テーブルの初期化
void InitArpTable(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	v->ArpTable = NewList(CompareArpTable);
}

// ARP テーブルの解放
void FreeArpTable(VH *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// すべてのエントリを削除する
	for (i = 0;i < LIST_NUM(v->ArpTable);i++)
	{
		ARP_ENTRY *e = LIST_DATA(v->ArpTable, i);
		Free(e);
	}
	ReleaseList(v->ArpTable);
}

// ARP 待ちテーブルの比較
int CompareArpWaitTable(void *p1, void *p2)
{
	ARP_WAIT *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(ARP_WAIT **)p1;
	e2 = *(ARP_WAIT **)p2;
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
	return 0;
}

// ARP テーブルの比較
int CompareArpTable(void *p1, void *p2)
{
	ARP_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(ARP_ENTRY **)p1;
	e2 = *(ARP_ENTRY **)p2;
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
	return 0;
}

// 仮想ホストの初期化
bool VirtualInit(VH *v)
{
	// ログ初期化
	v->Logger = NULL;

	LockVirtual(v);
	{
		// 初期化
		v->Cancel = NewCancel();
		v->SendQueue = NewQueue();
	}
	UnlockVirtual(v);

	// カウンタリセット
	v->Counter->c = 0;
	v->DhcpId = 0;

	// ARP テーブルの初期化
	InitArpTable(v);

	// ARP 待ちテーブルの初期化
	InitArpWaitTable(v);

	// IP 待ちテーブルの初期化
	InitIpWaitTable(v);

	// IP 結合リストの初期化
	InitIpCombineList(v);

	// NAT の初期化
	InitNat(v);

	// DHCP サーバーの初期化
	InitDhcpServer(v);

	// その他初期化
	v->flag1 = false;
	v->NextArpTablePolling = Tick64() + (UINT64)ARP_ENTRY_POLLING_TIME;
	v->CurrentIpQuota = 0;
	v->Active = true;

	return true;
}
bool VirtualPaInit(SESSION *s)
{
	VH *v;
	// 引数チェック
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	return VirtualInit(v);
}

// 仮想ホストのキャンセルオブジェクトを取得
CANCEL *VirtualPaGetCancel(SESSION *s)
{
	VH *v;
	// 引数チェック
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return NULL;
	}

	AddRef(v->Cancel->ref);
	return v->Cancel;
}

// 仮想ホストから次のパケットを取得
UINT VirtualGetNextPacket(VH *v, void **data)
{
	UINT ret = 0;

START:
	// 送信キューを調べる
	LockQueue(v->SendQueue);
	{
		BLOCK *block = GetNext(v->SendQueue);

		if (block != NULL)
		{
			// パケットがあった
			ret = block->Size;
			*data = block->Buf;
			// 構造体は破棄する
			Free(block);
		}
	}
	UnlockQueue(v->SendQueue);

	if (ret == 0)
	{
		LockVirtual(v);
		{
			v->Now = Tick64();
			// ポーリング処理
			VirtualPolling(v);
		}
		UnlockVirtual(v);
		if (v->SendQueue->num_item != 0)
		{
			goto START;
		}
	}

	return ret;
}
UINT VirtualPaGetNextPacket(SESSION *s, void **data)
{
	VH *v;
	// 引数チェック
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return INFINITE;
	}

	return VirtualGetNextPacket(v, data);
}

// ポーリング処理 (SessionMain ループ中に 1 回必ず呼ばれる)
void VirtualPolling(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// DHCP ポーリング
	PollingDhcpServer(v);

	// NAT ポーリング
	PoolingNat(v);

	// 古い ARP テーブルの清掃
	PollingArpTable(v);

	// ARP 待ちリストのポーリング
	PollingArpWaitTable(v);

	// IP 待ちリストのポーリング
	PollingIpWaitTable(v);

	// IP 結合リストのポーリング
	PollingIpCombine(v);

	// ビーコン送信プロシージャ
	PollingBeacon(v);
}

// ビーコン送信プロシージャ
void PollingBeacon(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	if (v->LastSendBeacon == 0 ||
		((v->LastSendBeacon + BEACON_SEND_INTERVAL) <= Tick64()))
	{
		v->LastSendBeacon = Tick64();

		SendBeacon(v);
	}
}

// Layer-2 パケットを送信する
void VirtualLayer2Send(VH *v, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size)
{
	MAC_HEADER *mac_header;
	UCHAR *buf;
	BLOCK *block;
	// 引数チェック
	if (v == NULL || dest_mac == NULL || src_mac == NULL || data == NULL || size > (MAX_PACKET_SIZE - sizeof(MAC_HEADER)))
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
	block = NewBlock(buf, size, 0);

	// キューに挿入する
	LockQueue(v->SendQueue);
	{
		InsertQueue(v->SendQueue, block);
	}
	UnlockQueue(v->SendQueue);

	// キャンセル
	Cancel(v->Cancel);
}

// IP パケットを送信する (自動的に分割処理を行う)
void SendIp(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size)
{
	UINT mss;
	UCHAR *buf;
	USHORT offset;
	USHORT id;
	USHORT total_size;
	UINT size_of_this_packet;
	// 引数チェック
	if (v == NULL || data == NULL || size == 0 || size > MAX_IP_DATA_SIZE_TOTAL)
	{
		return;
	}

	// 最大セグメントサイズ
	mss = v->IpMss;

	// バッファ
	buf = (UCHAR *)data;

	// ID
	id = (v->NextId++);

	// 合計サイズ
	total_size = (USHORT)size;

	// 分割作業を開始
	offset = 0;

	while (true)
	{
		bool last_packet = false;
		// このパケットのサイズを取得
		size_of_this_packet = MIN((USHORT)mss, (total_size - offset));
		if ((offset + (USHORT)size_of_this_packet) == total_size)
		{
			last_packet = true;
		}

		// 分割されたパケットの送信処理
		SendFragmentedIp(v, dest_ip, src_ip, id,
			total_size, offset, protocol, buf + offset, size_of_this_packet, NULL);
		if (last_packet)
		{
			break;
		}

		offset += (USHORT)size_of_this_packet;
	}
}

// 分割済みの IP パケットを送信予約する
void SendFragmentedIp(VH *v, UINT dest_ip, UINT src_ip, USHORT id, USHORT total_size, USHORT offset, UCHAR protocol, void *data, UINT size, UCHAR *dest_mac)
{
	UCHAR *buf;
	IPV4_HEADER *ip;
	ARP_ENTRY *arp;
	// 引数チェック
	if (v == NULL || data == NULL || size == 0)
	{
		return;
	}

	// メモリ確保
	buf = Malloc(size + IP_HEADER_SIZE);
	ip = (IPV4_HEADER *)&buf[0];

	// IP ヘッダ構築
	ip->VersionAndHeaderLength = 0;
	IPV4_SET_VERSION(ip, 4);
	IPV4_SET_HEADER_LEN(ip, (IP_HEADER_SIZE / 4));
	ip->TypeOfService = DEFAULT_IP_TOS;
	ip->TotalLength = Endian16((USHORT)(size + IP_HEADER_SIZE));
	ip->Identification = Endian16(id);
	ip->FlagsAndFlagmentOffset[0] = ip->FlagsAndFlagmentOffset[1] = 0;
	IPV4_SET_OFFSET(ip, (offset / 8));
	if ((offset + size) >= total_size)
	{
		IPV4_SET_FLAGS(ip, 0x00);
	}
	else
	{
		IPV4_SET_FLAGS(ip, 0x01);
	}
	ip->TimeToLive = DEFAULT_IP_TTL;
	ip->Protocol = protocol;
	ip->Checksum = 0;
	ip->SrcIP = src_ip;
	ip->DstIP = dest_ip;

	// チェックサム計算
	ip->Checksum = IpChecksum(ip, IP_HEADER_SIZE);

	// データコピー
	Copy(buf + IP_HEADER_SIZE, data, size);

	if (dest_mac == NULL)
	{
		if (ip->DstIP == 0xffffffff ||
			(IsInNetwork(ip->DstIP, v->HostIP, v->HostMask) && (ip->DstIP & (~v->HostMask)) == (~v->HostMask)))
		{
			// ブロードキャストアドレス
			dest_mac = broadcast;
		}
		else
		{
			// 宛先 MAC アドレスが不明な場合は ARP 問い合わせ
			arp = SearchArpTable(v, dest_ip);
			if (arp != NULL)
			{
				dest_mac = arp->MacAddress;
			}
		}
	}
	if (dest_mac != NULL)
	{
		// 直ちにパケットを送信する
		VirtualIpSend(v, dest_mac, buf, size + IP_HEADER_SIZE);

		// パケットデータは解放して良い
		Free(buf);
	}
	else
	{
		// このパケットはまだ転送できないので IP 待ちテーブルに追加する
		InsertIpWaitTable(v, dest_ip, src_ip, buf, size + IP_HEADER_SIZE);

		// ARP を発行する
		SendArp(v, dest_ip);
	}
}

// IP パケット (分割済み) を送信する
void VirtualIpSend(VH *v, UCHAR *dest_mac, void *data, UINT size)
{
	// 引数チェック
	if (v == NULL || dest_mac == NULL || data == NULL || size == 0)
	{
		return;
	}

	// 送信
	VirtualLayer2Send(v, dest_mac, v->MacAddress, MAC_PROTO_IPV4, data, size);
}

// ARP リクエストパケットを送信する
void VirtualArpSendRequest(VH *v, UINT dest_ip)
{
	ARPV4_HEADER arp;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// ARP ヘッダを構築
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_REQUEST);
	Copy(arp.SrcAddress, v->MacAddress, 6);
	arp.SrcIP = v->HostIP;
	Zero(&arp.TargetAddress, 6);
	arp.TargetIP = dest_ip;

	// 送信
	VirtualLayer2Send(v, broadcast, v->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// ARP レスポンスパケットを送信する
void VirtualArpSendResponse(VH *v, UCHAR *dest_mac, UINT dest_ip, UINT src_ip)
{
	ARPV4_HEADER arp;
	// 引数チェック
	if (v == NULL || dest_mac == NULL)
	{
		return;
	}

	// ARP ヘッダを構築
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
	Copy(arp.SrcAddress, v->MacAddress, 6);
	Copy(arp.TargetAddress, dest_mac, 6);
	arp.SrcIP = src_ip;
	arp.TargetIP = dest_ip;

	// 送信
	VirtualLayer2Send(v, dest_mac, v->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(ARPV4_HEADER));
}

// ARP リクエストパケットを受信した
void VirtualArpResponseRequest(VH *v, PKT *packet)
{
	ARPV4_HEADER *arp;
	// 引数チェック
	if (v == NULL || packet == NULL)
	{
		return;
	}

	arp = packet->L3.ARPv4Header;

	// 相手のホスト IP アドレスと MAC アドレスを既知の情報とする
	ArpIpWasKnown(v, arp->SrcIP, arp->SrcAddress);

	// 自分のホスト IP アドレスと一致するかどうか検索
	if (v->HostIP == arp->TargetIP)
	{
		// 一致したので応答する
		VirtualArpSendResponse(v, arp->SrcAddress, arp->SrcIP, v->HostIP);
		return;
	}
	// 一致しない場合は何もしない
}

// ARP レスポンスパケットを受信した
void VirtualArpResponseReceived(VH *v, PKT *packet)
{
	ARPV4_HEADER *arp;
	// 引数チェック
	if (v == NULL || packet == NULL)
	{
		return;
	}

	arp = packet->L3.ARPv4Header;

	// この情報を既知の情報とする
	ArpIpWasKnown(v, arp->SrcIP, arp->SrcAddress);
}

// ARP パケットを受信した
void VirtualArpReceived(VH *v, PKT *packet)
{
	ARPV4_HEADER *arp;
	// 引数チェック
	if (v == NULL || packet == NULL)
	{
		return;
	}

	arp = packet->L3.ARPv4Header;

	if (Endian16(arp->HardwareType) != ARP_HARDWARE_TYPE_ETHERNET)
	{
		// ハードウェア種類が Ethernet 以外の場合は無視
		return;
	}
	if (Endian16(arp->ProtocolType) != MAC_PROTO_IPV4)
	{
		// プロトコル種類が IPv4 以外の場合は無視
		return;
	}
	if (arp->HardwareSize != 6 || arp->ProtocolSize != 4)
	{
		// ハードウェアアドレスまたはプロトコルアドレスのサイズが不正なので無視
		return;
	}
	// 送信元 MAC アドレスをチェック
	if (Cmp(arp->SrcAddress, packet->MacAddressSrc, 6) != 0)
	{
		// ARP パケットの MAC アドレスと MAC ヘッダの MAC アドレスが異なる
		return;
	}

	switch (Endian16(arp->Operation))
	{
	case ARP_OPERATION_REQUEST:		// ARP リクエスト
		VirtualArpResponseRequest(v, packet);
		break;

	case ARP_OPERATION_RESPONSE:	// ARP レスポンス
		VirtualArpResponseReceived(v, packet);
		break;
	}
}

// DHCP サーバーの解放
void FreeDhcpServer(VH *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// すべてのリースエントリを削除する
	for (i = 0;i < LIST_NUM(v->DhcpLeaseList);i++)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpLeaseList, i);
		FreeDhcpLease(d);
	}

	ReleaseList(v->DhcpLeaseList);
	v->DhcpLeaseList = NULL;
}

// DHCP サーバーの初期化
void InitDhcpServer(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// リスト作成
	v->DhcpLeaseList = NewList(CompareDhcpLeaseList);
}

// DHCP リース項目を IP アドレスで検索
DHCP_LEASE *SearchDhcpLeaseByIp(VH *v, UINT ip)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(v->DhcpLeaseList);i++)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpLeaseList, i);
		if (d->IpAddress == ip)
		{
			return d;
		}
	}

	return NULL;
}

// DHCP リース項目を MAC アドレスで検索
DHCP_LEASE *SearchDhcpLeaseByMac(VH *v, UCHAR *mac)
{
	DHCP_LEASE *d, t;
	// 引数チェック
	if (v == NULL || mac == NULL)
	{
		return NULL;
	}

	Copy(&t.MacAddress, mac, 6);
	d = Search(v->DhcpLeaseList, &t);

	return d;
}

// DHCP リース項目の解放
void FreeDhcpLease(DHCP_LEASE *d)
{
	// 引数チェック
	if (d == NULL)
	{
		return;
	}

	Free(d->Hostname);
	Free(d);
}

// DHCP リース項目の作成
DHCP_LEASE *NewDhcpLease(UINT expire, UCHAR *mac_address, UINT ip, UINT mask, char *hostname)
{
	DHCP_LEASE *d;
	// 引数チェック
	if (mac_address == NULL || hostname == NULL)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(DHCP_LEASE));
	d->LeasedTime = (UINT64)Tick64();
	if (expire == INFINITE)
	{
		d->ExpireTime = INFINITE;
	}
	else
	{
		d->ExpireTime = d->LeasedTime + (UINT64)expire;
	}
	d->IpAddress = ip;
	d->Mask = mask;
	d->Hostname = CopyStr(hostname);
	Copy(d->MacAddress, mac_address, 6);


	return d;
}

// DHCP リストの項目の比較
int CompareDhcpLeaseList(void *p1, void *p2)
{
	DHCP_LEASE *d1, *d2;
	// 引数チェック
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	d1 = *(DHCP_LEASE **)p1;
	d2 = *(DHCP_LEASE **)p2;
	if (d1 == NULL || d2 == NULL)
	{
		return 0;
	}

	return Cmp(d1->MacAddress, d2->MacAddress, 6);
}

// DHCP サーバーのポーリング
void PollingDhcpServer(VH *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	if (v->LastDhcpPolling != 0)
	{
		if ((v->LastDhcpPolling + (UINT64)DHCP_POLLING_INTERVAL) < v->Now ||
			v->LastDhcpPolling > v->Now)
		{
			return;
		}
	}
	v->LastDhcpPolling = v->Now;

	// 有効期限の切れたエントリを削除
FIRST_LIST:
	for (i = 0;i < LIST_NUM(v->DhcpLeaseList);i++)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpLeaseList, i);

		if (d->ExpireTime < v->Now)
		{
			FreeDhcpLease(d);
			Delete(v->DhcpLeaseList, d);
			goto FIRST_LIST;
		}
	}
}

// DHCP REQUEST に対応する
UINT ServeDhcpRequest(VH *v, UCHAR *mac, UINT request_ip)
{
	UINT ret;
	// 引数チェック
	if (v == NULL || mac == NULL)
	{
		return 0;
	}

	ret = ServeDhcpDiscover(v, mac, request_ip);
	if (ret != request_ip)
	{
		if (request_ip != 0)
		{
			// 要求されている IP アドレスを割り当てることができない場合はエラー
			return 0;
		}
	}

	return ret;
}

// DHCP DISCOVER に対応する
UINT ServeDhcpDiscover(VH *v, UCHAR *mac, UINT request_ip)
{
	UINT ret = 0;
	// 引数チェック
	if (v == NULL || mac == NULL)
	{
		return 0;
	}

	if (request_ip != 0)
	{
		// IP アドレスが指定されている
		DHCP_LEASE *d = SearchDhcpLeaseByIp(v, request_ip);
		if (d != NULL)
		{
			// 同じ IP アドレスのエントリがすでに存在している場合は
			// 同じ MAC アドレスからの要求であることを調べる
			if (Cmp(mac, d->MacAddress, 6) == 0)
			{
				// 指定された IP アドレスが割り当て範囲内にあるかどうか調べる
				if (Endian32(v->DhcpIpStart) <= Endian32(request_ip) &&
					Endian32(request_ip) <= Endian32(v->DhcpIpEnd))
				{
					// 範囲内にあるなら承諾する
					ret = request_ip;
				}
			}
		}
		else
		{
			// 指定された IP アドレスが割り当て範囲内にあるかどうか調べる
			if (Endian32(v->DhcpIpStart) <= Endian32(request_ip) &&
				Endian32(request_ip) <= Endian32(v->DhcpIpEnd))
			{
				// 範囲内にあるなら承諾する
				ret = request_ip;
			}
			else
			{
				// 範囲外であるが Discover なので範囲内の IP を 1 つ提案する
			}
		}
	}

	if (ret == 0)
	{
		// すでに登録されているエントリで同じ MAC アドレスのものがあれば
		// それを優先して使用する
		DHCP_LEASE *d = SearchDhcpLeaseByMac(v, mac);
		if (d != NULL)
		{
			// 見つかった IP アドレスが割り当て範囲内にあるかどうか調べる
			if (Endian32(v->DhcpIpStart) <= Endian32(d->IpAddress) &&
				Endian32(d->IpAddress) <= Endian32(v->DhcpIpEnd))
			{
				// 範囲内にあるなら見つかったIPアドレスを使用する
				ret = d->IpAddress;
			}
		}
	}

	if (ret == 0)
	{
		// 新しく割り当てることが可能な IP アドレスを適当に取る
		ret = GetFreeDhcpIpAddress(v);
	}

	return ret;
}

// 新しく割り当てることが可能な IP アドレスを適当に 1 つ取る
UINT GetFreeDhcpIpAddress(VH *v)
{
	UINT ip_start, ip_end;
	UINT i;
	// 引数チェック
	if (v == NULL)
	{
		return 0;
	}

	ip_start = Endian32(v->DhcpIpStart);
	ip_end = Endian32(v->DhcpIpEnd);

	for (i = ip_start; i <= ip_end;i++)
	{
		UINT ip = Endian32(i);
		if (SearchDhcpLeaseByIp(v, ip) == NULL)
		{
			// 空き IP アドレスを発見した
			return ip;
		}
	}

	// 空きが無い
	return 0;
}

// 仮想 DHCP サーバー
void VirtualDhcpServer(VH *v, PKT *p)
{
	DHCPV4_HEADER *dhcp;
	UCHAR *data;
	UINT size;
	UINT dhcp_header_size;
	UINT dhcp_data_offset;
	UINT tran_id;
	UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
	bool ok;
	DHCP_OPTION_LIST *opt;
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	dhcp = p->L7.DHCPv4Header;

	tran_id = Endian32(dhcp->TransactionId);

	// DHCP データとサイズを取得する
	dhcp_header_size = sizeof(DHCPV4_HEADER);
	dhcp_data_offset = (UINT)(((UCHAR *)p->L7.DHCPv4Header) - ((UCHAR *)p->MacHeader) + dhcp_header_size);
	data = ((UCHAR *)dhcp) + dhcp_header_size;
	size = p->PacketSize - dhcp_data_offset;
	if (dhcp_header_size < 5)
	{
		// データサイズが不正
		return;
	}

	// Magic Cookie を検索する
	ok = false;
	while (size >= 5)
	{
		if (Cmp(data, &magic_cookie, sizeof(magic_cookie)) == 0)
		{
			// 発見
			data += 4;
			size -= 4;
			ok = true;
			break;
		}
		data++;
		size--;
	}

	if (ok == false)
	{
		// パケット不正
		return;
	}

	// DHCP オプションリストのパース
	opt = ParseDhcpOptionList(data, size);
	if (opt == NULL)
	{
		// パケット不正
		return;
	}

	if (dhcp->OpCode == 1 && (opt->Opcode == DHCP_DISCOVER || opt->Opcode == DHCP_REQUEST))
	{
		// サーバーとしての動作を行う
		UINT ip;
		if (opt->RequestedIp == 0)
		{
			opt->RequestedIp = p->L3.IPv4Header->SrcIP;
		}
		if (opt->Opcode == DHCP_DISCOVER)
		{
			// 利用できる IP アドレスを 1 つ返す
			ip = ServeDhcpDiscover(v, p->MacAddressSrc, opt->RequestedIp);
		}
		else
		{
			// IP アドレスを確定する
			ip = ServeDhcpRequest(v, p->MacAddressSrc, opt->RequestedIp);
		}
		if (ip != 0)
		{
			// 提供可能な IP アドレスがある場合は応答してやる

			if (opt->Opcode == DHCP_REQUEST)
			{
				DHCP_LEASE *d;
				char mac[MAX_SIZE];
				char str[MAX_SIZE];
				// 同じ IP アドレスで古いレコードがあれば削除する
				d = SearchDhcpLeaseByIp(v, ip);
				if (d != NULL)
				{
					FreeDhcpLease(d);
					Delete(v->DhcpLeaseList, d);
				}

				// 新しいエントリを作成する
				d = NewDhcpLease(v->DhcpExpire, p->MacAddressSrc,
					ip, v->DhcpMask,
					opt->Hostname);
				d->Id = ++v->DhcpId;
				Add(v->DhcpLeaseList, d);
				MacToStr(mac, sizeof(mac), d->MacAddress);

				IPToStr32(str, sizeof(str), d->IpAddress);

				NLog(v, "LH_NAT_DHCP_CREATED", d->Id, mac, str, d->Hostname, v->DhcpExpire / 1000);
			}

			// 応答する
			if (ip != 0)
			{
				DHCP_OPTION_LIST ret;
				LIST *o;
				Zero(&ret, sizeof(ret));

				ret.Opcode = (opt->Opcode == DHCP_DISCOVER ? DHCP_OFFER : DHCP_ACK);
				ret.ServerAddress = v->HostIP;
				if (v->DhcpExpire == INFINITE)
				{
					ret.LeaseTime = INFINITE;
				}
				else
				{
					ret.LeaseTime = Endian32(v->DhcpExpire / 1000);
				}
				StrCpy(ret.DomainName, sizeof(ret.DomainName), v->DhcpDomain);
				ret.SubnetMask = v->DhcpMask;
				ret.DnsServer = v->DhcpDns;
				ret.Gateway = v->DhcpGateway;

				if (1)
				{
					char client_mac[MAX_SIZE];
					char client_ip[64];
					IP ips;
					BinToStr(client_mac, sizeof(client_mac), p->MacAddressSrc, 6);
					UINTToIP(&ips, ip);
					IPToStr(client_ip, sizeof(client_ip), &ips);
					Debug("DHCP %s : %s given %s\n",
						ret.Opcode == DHCP_OFFER ? "DHCP_OFFER" : "DHCP_ACK",
						client_mac, client_ip);
				}

				// DHCP オプションのビルド
				o = BuildDhcpOption(&ret);
				if (o != NULL)
				{
					BUF *b = BuildDhcpOptionsBuf(o);
					if (b != NULL)
					{
						UINT dest_ip = p->L3.IPv4Header->SrcIP;
						if (dest_ip == 0)
						{
							dest_ip = 0xffffffff;
						}
						// 送信
						VirtualDhcpSend(v, tran_id, dest_ip, Endian16(p->L4.UDPHeader->SrcPort),
							ip, dhcp->ClientMacAddress, b);

						// メモリ解放
						FreeBuf(b);
					}
					FreeDhcpOptions(o);
				}
			}
		}
		else
		{
			// 提供できる IP アドレスが無い
			DHCP_OPTION_LIST ret;
			LIST *o;
			Zero(&ret, sizeof(ret));

			ret.Opcode = DHCP_NACK;
			ret.ServerAddress = v->HostIP;
			StrCpy(ret.DomainName, sizeof(ret.DomainName), v->DhcpDomain);
			ret.SubnetMask = v->DhcpMask;

			// DHCP オプションのビルド
			o = BuildDhcpOption(&ret);
			if (o != NULL)
			{
				BUF *b = BuildDhcpOptionsBuf(o);
				if (b != NULL)
				{
					UINT dest_ip = p->L3.IPv4Header->SrcIP;
					if (dest_ip == 0)
					{
						dest_ip = 0xffffffff;
					}
					// 送信
					VirtualDhcpSend(v, tran_id, dest_ip, Endian16(p->L4.UDPHeader->SrcPort),
						ip, dhcp->ClientMacAddress, b);

					// メモリ解放
					FreeBuf(b);
				}
				FreeDhcpOptions(o);
			}
		}
	}

	// メモリ解放
	Free(opt);
}

// DHCP 応答パケットの送信
void VirtualDhcpSend(VH *v, UINT tran_id, UINT dest_ip, UINT dest_port,
					 UINT new_ip, UCHAR *client_mac, BUF *b)
{
	UINT blank_size = 128 + 64;
	UINT dhcp_packet_size;
	UINT magic = Endian32(DHCP_MAGIC_COOKIE);
	DHCPV4_HEADER *dhcp;
	void *magic_cookie_addr;
	void *buffer_addr;
	// 引数チェック
	if (v == NULL || b == NULL)
	{
		return;
	}

	// DHCP パケットサイズを求める
	dhcp_packet_size = blank_size + sizeof(DHCPV4_HEADER) + sizeof(magic) + b->Size;

	// ヘッダ作成
	dhcp = ZeroMalloc(dhcp_packet_size);

	dhcp->OpCode = 2;
	dhcp->HardwareType = 1;
	dhcp->HardwareAddressSize = 6;
	dhcp->Hops = 0;
	dhcp->TransactionId = Endian32(tran_id);
	dhcp->Seconds = 0;
	dhcp->Flags = 0;
	dhcp->YourIP = new_ip;
	dhcp->ServerIP = v->HostIP;
	Copy(dhcp->ClientMacAddress, client_mac, 6);

	// アドレスを求める
	magic_cookie_addr = (((UCHAR *)dhcp) + sizeof(DHCPV4_HEADER) + blank_size);
	buffer_addr = ((UCHAR *)magic_cookie_addr) + sizeof(magic);

	// Magic Cookie
	Copy(magic_cookie_addr, &magic, sizeof(magic));

	// Buffer
	Copy(buffer_addr, b->Buf, b->Size);

	// 送信
	SendUdp(v, dest_ip, dest_port, v->HostIP, NAT_DHCP_SERVER_PORT, dhcp, dhcp_packet_size);

	Free(dhcp);
}

// DHCP オプション リストをバッファに変換する
BUF *BuildDhcpOptionsBuf(LIST *o)
{
	BUF *b;
	UINT i;
	UCHAR id;
	UCHAR sz;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	for (i = 0;i < LIST_NUM(o);i++)
	{
		DHCP_OPTION *d = LIST_DATA(o, i);
		id = (UCHAR)d->Id;
		sz = (UCHAR)d->Size;
		WriteBuf(b, &id, 1);
		WriteBuf(b, &sz, 1);
		WriteBuf(b, d->Data, d->Size);
	}

	id = 0xff;
	WriteBuf(b, &id, 1);

	return b;
}

// DHCP オプション リストを DHCP オプションに変換する
LIST *BuildDhcpOption(DHCP_OPTION_LIST *opt)
{
	LIST *o;
	UCHAR opcode;
	// 引数チェック
	if (opt == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	// オペコード
	opcode = (UCHAR)opt->Opcode;
	Add(o, NewDhcpOption(DHCP_ID_MESSAGE_TYPE, &opcode, sizeof(opcode)));
	Add(o, NewDhcpOption(DHCP_ID_SERVER_ADDRESS, &opt->ServerAddress, sizeof(opt->ServerAddress)));
	Add(o, NewDhcpOption(DHCP_ID_LEASE_TIME, &opt->LeaseTime, sizeof(opt->LeaseTime)));
	if (StrLen(opt->DomainName) != 0 && opt->DnsServer != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_DOMAIN_NAME, opt->DomainName, StrLen(opt->DomainName)));
	}
	if (opt->SubnetMask != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_SUBNET_MASK, &opt->SubnetMask, sizeof(opt->SubnetMask)));
	}
	if (opt->Gateway != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_GATEWAY_ADDR, &opt->Gateway, sizeof(opt->Gateway)));
	}
	if (opt->DnsServer != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_DNS_ADDR, &opt->DnsServer, sizeof(opt->DnsServer)));
	}

	return o;
}

// 新しい DHCP オプション項目の作成
DHCP_OPTION *NewDhcpOption(UINT id, void *data, UINT size)
{
	DHCP_OPTION *ret;
	if (size != 0 && data == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(DHCP_OPTION));
	ret->Data = ZeroMalloc(size);
	Copy(ret->Data, data, size);
	ret->Size = (UCHAR)size;
	ret->Id = (UCHAR)id;

	return ret;
}

// DHCP オプションリストのパース
DHCP_OPTION_LIST *ParseDhcpOptionList(void *data, UINT size)
{
	DHCP_OPTION_LIST *ret;
	LIST *o;
	DHCP_OPTION *a;
	// 引数チェック
	if (data == NULL)
	{
		return NULL;
	}

	// リストのパース
	o = ParseDhcpOptions(data, size);
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(DHCP_OPTION_LIST));

	// オペコードの取得
	a = GetDhcpOption(o, DHCP_ID_MESSAGE_TYPE);
	if (a != NULL)
	{
		if (a->Size == 1)
		{
			ret->Opcode = *((UCHAR *)a->Data);
		}
	}

	switch (ret->Opcode)
	{
	case DHCP_DISCOVER:
	case DHCP_REQUEST:
		// クライアント要求なのでより細かくパースする
		// 要求された IP アドレス
		a = GetDhcpOption(o, DHCP_ID_REQUEST_IP_ADDRESS);
		if (a != NULL && a->Size == 4)
		{
			Copy(&ret->RequestedIp, a->Data, 4);
		}
		// ホスト名
		a = GetDhcpOption(o, DHCP_ID_HOST_NAME);
		if (a != NULL)
		{
			if (a->Size > 1)
			{
				Copy(ret->Hostname, a->Data, MIN(a->Size, sizeof(ret->Hostname) - 1));
			}
		}
		break;

	case DHCP_OFFER:
	case DHCP_ACK:
		// 今のところこの 2 つのオプションをパースする必要は無い
		break;
	}

	// リストの解放
	FreeDhcpOptions(o);

	return ret;
}

// DHCP オプションの検索
DHCP_OPTION *GetDhcpOption(LIST *o, UINT id)
{
	UINT i;
	DHCP_OPTION *ret = NULL;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		DHCP_OPTION *opt = LIST_DATA(o, i);
		if (opt->Id == id)
		{
			ret = opt;
		}
	}

	return ret;
}

// DHCP オプションの解放
void FreeDhcpOptions(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		DHCP_OPTION *opt = LIST_DATA(o, i);
		Free(opt->Data);
		Free(opt);
	}

	ReleaseList(o);
}

// DHCP オプションのパース
LIST *ParseDhcpOptions(void *data, UINT size)
{
	BUF *b;
	LIST *o;
	// 引数チェック
	if (data == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	o = NewListFast(NULL);

	while (true)
	{
		UCHAR c = 0;
		UCHAR sz = 0;
		DHCP_OPTION *opt;
		if (ReadBuf(b, &c, 1) != 1)
		{
			break;
		}
		if (c == 0xff)
		{
			break;
		}
		if (ReadBuf(b, &sz, 1) != 1)
		{
			break;
		}

		opt = ZeroMalloc(sizeof(DHCP_OPTION));
		opt->Id = (UINT)c;
		opt->Size = (UINT)sz;
		opt->Data = ZeroMalloc((UINT)sz);
		ReadBuf(b, opt->Data, sz);
		Add(o, opt);
	}

	FreeBuf(b);

	return o;
}

// 仮想ホスト - Layer2 の処理
void VirtualLayer2(VH *v, PKT *packet)
{
	bool ok;
	// 引数チェック
	if (packet == NULL || v == NULL)
	{
		return;
	}

	// パケットフィルタ
	if (VirtualLayer2Filter(v, packet) == false)
	{
		// パケットは無視された
		return;
	}

	ok = false;
	if (packet->TypeL3 == L3_IPV4 && packet->TypeL4 == L4_UDP && packet->TypeL7 == L7_DHCPV4)
	{
		if (v->UseDhcp)
		{
			// DHCP パケットに関する特殊な処理
			if (packet->BroadcastPacket || Cmp(packet->MacAddressDest, v->MacAddress, 6) == 0)
			{
				// 仮想 DHCP サーバー処理
				VirtualDhcpServer(v, packet);
				ok = true;
			}
		}
	}

	if (ok == false)
	{
		// サポートしているプロトコルごとに処理
		switch (packet->TypeL3)
		{
		case L3_ARPV4:	// ARPv4
			VirtualArpReceived(v, packet);
			break;

		case L3_IPV4:	// IPv4
			VirtualIpReceived(v, packet);
			break;
		}
	}
}

// パケットフィルタ (自分以外へのパケットを遮断)
bool VirtualLayer2Filter(VH *v, PKT *packet)
{
	// 引数チェック
	if (v == NULL || packet == NULL)
	{
		return false;
	}

	// ブロードキャストパケットなら通過
	if (packet->BroadcastPacket)
	{
		return true;
	}

	// 送信元が自分のパケットなら無視
	if (Cmp(packet->MacAddressSrc, v->MacAddress, 6) == 0)
	{
		return false;
	}
	// 自分宛のパケットなら通過
	if (Cmp(packet->MacAddressDest, v->MacAddress, 6) == 0)
	{
		return true;
	}

	// それ以外のパケットなら破棄
	return false;
}

// 仮想ホストにパケットを受信させる
bool VirtualPutPacket(VH *v, void *data, UINT size)
{
	if (data == NULL)
	{
		// フラッシュ
		v->flag1 = false;
	}
	else
	{
		// 受信したパケットを解釈する
		PKT *packet = ParsePacket(data, size);

		if (v->flag1 == false)
		{
			v->flag1 = true;
			v->Now = Tick64();
		}

		// ここの中は仮想マシン全体をロックする
		LockVirtual(v);
		{
			if (packet != NULL)
			{
				// Layer-2 の処理を行う
				VirtualLayer2(v, packet);

				// パケット構造体の解放
				FreePacket(packet);
			}
		}
		UnlockVirtual(v);

		Free(data);
	}

	return true;
}
bool VirtualPaPutPacket(SESSION *s, void *data, UINT size)
{
	VH *v;
	// 引数チェック
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	return VirtualPutPacket(v, data, size);
}

// 仮想ホストのオプションを取得する
void GetVirtualHostOption(VH *v, VH_OPTION *o)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	LockVirtual(v);
	{
		Zero(o, sizeof(VH_OPTION));

		// MAC アドレス
		Copy(o->MacAddress, v->MacAddress, 6);

		// ホスト情報
		UINTToIP(&o->Ip, v->HostIP);
		UINTToIP(&o->Mask, v->HostMask);

		o->Mtu = v->Mtu;

		// NAT タイムアウト情報
		o->NatTcpTimeout = v->NatTcpTimeout / 1000;
		o->NatUdpTimeout = v->NatUdpTimeout / 1000;

		// NAT 使用フラグ
		o->UseNat = v->UseNat;

		// DHCP 使用フラグ
		o->UseDhcp = v->UseDhcp;

		// DHCP 配布 IP アドレス範囲
		UINTToIP(&o->DhcpLeaseIPStart, v->DhcpIpStart);
		UINTToIP(&o->DhcpLeaseIPEnd, v->DhcpIpEnd);

		// サブネットマスク
		UINTToIP(&o->DhcpSubnetMask, v->DhcpMask);

		// 有効期限
		if (v->DhcpExpire != INFINITE)
		{
			o->DhcpExpireTimeSpan = v->DhcpExpire / 1000;
		}
		else
		{
			o->DhcpExpireTimeSpan = INFINITE;
		}

		// ゲートウェイアドレス
		UINTToIP(&o->DhcpGatewayAddress, v->DhcpGateway);

		// DNS サーバーアドレス
		UINTToIP(&o->DhcpDnsServerAddress, v->DhcpDns);

		// ドメイン名
		StrCpy(o->DhcpDomainName, sizeof(o->DhcpDomainName), v->DhcpDomain);

		// ログの保存
		o->SaveLog = v->SaveLog;
	}
	UnlockVirtual(v);
}

// 仮想ホストにオプションを設定する
void SetVirtualHostOption(VH *v, VH_OPTION *vo)
{
	UINT i;
	// 引数チェック
	if (v == NULL || vo == NULL)
	{
		return;
	}

	LockVirtual(v);
	{
		// MAC アドレスを設定する
		for (i = 0;i < 6;i++)
		{
			if (vo->MacAddress[i] != 0)
			{
				Copy(v->MacAddress, vo->MacAddress, 6);
				break;
			}
		}

		// ホスト情報リストを設定する
		v->HostIP = IPToUINT(&vo->Ip);
		v->HostMask = IPToUINT(&vo->Mask);

		// MTU, MMS を設定する
		v->Mtu = MIN(vo->Mtu, MAX_L3_DATA_SIZE);
		if (v->Mtu == 0)
		{
			v->Mtu = MAX_L3_DATA_SIZE;
		}
		v->Mtu = MAX(v->Mtu, TCP_HEADER_SIZE + IP_HEADER_SIZE + MAC_HEADER_SIZE + 8);
		v->IpMss = ((v->Mtu - IP_HEADER_SIZE) / 8) * 8;
		v->TcpMss = ((v->IpMss - TCP_HEADER_SIZE) / 8) * 8;
		v->UdpMss = ((v->IpMss - UDP_HEADER_SIZE) / 8) * 8;

		if (vo->NatTcpTimeout != 0)
		{
			v->NatTcpTimeout = MIN(vo->NatTcpTimeout, 4000000) * 1000;
		}
		if (vo->NatUdpTimeout != 0)
		{
			v->NatUdpTimeout = MIN(vo->NatUdpTimeout, 4000000) * 1000;
		}
		v->NatTcpTimeout = MAKESURE(v->NatTcpTimeout, NAT_TCP_MIN_TIMEOUT, NAT_TCP_MAX_TIMEOUT);
		v->NatUdpTimeout = MAKESURE(v->NatUdpTimeout, NAT_UDP_MIN_TIMEOUT, NAT_UDP_MAX_TIMEOUT);
		Debug("Timeout: %d , %d\n", v->NatTcpTimeout, v->NatUdpTimeout);

		// NAT 使用フラグ
		v->UseNat = vo->UseNat;

		// DHCP 使用フラグ
		v->UseDhcp = vo->UseDhcp;

		// 有効期限
		if (vo->DhcpExpireTimeSpan == 0 || vo->DhcpExpireTimeSpan == INFINITE)
		{
			v->DhcpExpire = INFINITE;
		}
		else
		{
			v->DhcpExpire = MAKESURE(DHCP_MIN_EXPIRE_TIMESPAN,
				MIN(vo->DhcpExpireTimeSpan * 1000, 2000000000),
				INFINITE);
		}

		// 配布するアドレス範囲
		v->DhcpIpStart = IPToUINT(&vo->DhcpLeaseIPStart);
		v->DhcpIpEnd = IPToUINT(&vo->DhcpLeaseIPEnd);
		if (Endian32(v->DhcpIpEnd) < Endian32(v->DhcpIpStart))
		{
			v->DhcpIpEnd = v->DhcpIpStart;
		}

		// サブネットマスク
		v->DhcpMask = IPToUINT(&vo->DhcpSubnetMask);

		// ゲートウェイアドレス
		v->DhcpGateway = IPToUINT(&vo->DhcpGatewayAddress);

		// DNS サーバーアドレス
		v->DhcpDns = IPToUINT(&vo->DhcpDnsServerAddress);

		// ドメイン名
		StrCpy(v->DhcpDomain, sizeof(v->DhcpDomain), vo->DhcpDomainName);

		// ログの保存
		v->SaveLog = vo->SaveLog;
	}
	UnlockVirtual(v);
}

// 仮想ホストの解放
void Virtual_Free(VH *v)
{
	// DHCP サーバー解放
	FreeDhcpServer(v);

	// NAT 解放
	FreeNat(v);

	LockVirtual(v);
	{
		// IP 結合リスト解放
		FreeIpCombineList(v);

		// IP 待ちテーブル解放
		FreeIpWaitTable(v);

		// ARP 待ちテーブル解放
		FreeArpWaitTable(v);

		// ARP テーブル解放
		FreeArpTable(v);

		// 送信キュー解放
		LockQueue(v->SendQueue);
		{
			BLOCK *block;

			// すべてのキューを解放する
			while (block = GetNext(v->SendQueue))
			{
				FreeBlock(block);
			}
		}
		UnlockQueue(v->SendQueue);
		ReleaseQueue(v->SendQueue);
		v->SendQueue = NULL;

		// キャンセルオブジェクト解放
		ReleaseCancel(v->Cancel);

		v->Active = false;
	}
	UnlockVirtual(v);

	// ロガー解放
	FreeLog(v->Logger);
}
void VirtualPaFree(SESSION *s)
{
	VH *v;
	// 引数チェック
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return;
	}

	Virtual_Free(v);
}

// 仮想ホストの解放
void ReleaseVirtual(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	if (Release(v->ref) == 0)
	{
		CleanupVirtual(v);
	}
}

// 仮想ホストのロック
void LockVirtual(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	Lock(v->lock);
}

// 仮想ホストのロック解除
void UnlockVirtual(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	Unlock(v->lock);
}

// 仮想ホストのクリーンアップ
void CleanupVirtual(VH *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	if (v->Session != NULL)
	{
		ReleaseSession(v->Session);
	}

	DeleteCounter(v->Counter);
	DeleteLock(v->lock);

	Free(v);
}

// 仮想ホストの停止
void StopVirtualHost(VH *v)
{
	SESSION *s;
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

	// 仮想ホストに対応したセッションの取得
	LockVirtual(v);
	{
		s = v->Session;
		if (s != NULL)
		{
			AddRef(s->ref);
		}
	}
	UnlockVirtual(v);

	if (s == NULL)
	{
		// すでにこのセッションは停止している
		return;
	}

	// セッションの停止
	StopSession(s);

	ReleaseSession(s);
}

// 新しい仮想ホストの作成
VH *NewVirtualHost(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option)
{
	return NewVirtualHostEx(cedar, option, auth, vh_option, NULL);
}
VH *NewVirtualHostEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option, NAT *nat)
{
	VH *v;
	// 引数チェック
	if (vh_option == NULL)
	{
		return NULL;
	}

	// VH の作成
	v = ZeroMalloc(sizeof(VH));
	v->ref = NewRef();
	v->lock = NewLock();
	v->Counter = NewCounter();

	v->nat = nat;

	// オプションの設定
	SetVirtualHostOption(v, vh_option);

	return v;
}

// ランダムな MAC アドレスを生成する
void GenMacAddress(UCHAR *mac)
{
	UCHAR rand_data[32];
	UINT64 now;
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (mac == NULL)
	{
		return;
	}

	// 現在時刻を取得
	now = SystemTime64();

	// 乱数を生成
	Rand(rand_data, sizeof(rand_data));

	// バッファに追加
	b = NewBuf();
	WriteBuf(b, &now, sizeof(now));
	WriteBuf(b, rand_data, sizeof(rand_data));

	// ハッシュ
	Hash(hash, b->Buf, b->Size, true);

	// MAC アドレスを生成
	mac[0] = 0x00;
	mac[1] = 0xAC;		// AC 万歳
	mac[2] = hash[0];
	mac[3] = hash[1];
	mac[4] = hash[2];
	mac[5] = hash[3];

	FreeBuf(b);
}

// 仮想ホストのパケットアダプタを取得
PACKET_ADAPTER *VirtualGetPacketAdapter()
{
	return NewPacketAdapter(VirtualPaInit, VirtualPaGetCancel,
		VirtualPaGetNextPacket, VirtualPaPutPacket, VirtualPaFree);
}


