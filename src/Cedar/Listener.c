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

// Listener.c
// リスナー モジュール

#include "CedarPch.h"

// UDP パケットを 1 つ受信した
void UDPReceivedPacket(CEDAR *cedar, SOCK *s, IP *ip, UINT port, void *data, UINT size)
{
	SESSION *session;
	UINT *key32;
	UCHAR *buf;
	CONNECTION *c;
	// 引数チェック
	if (s == NULL || ip == NULL || data == NULL || size == 0 || cedar == NULL)
	{
		return;
	}

	if (size < 16)
	{
		// パケットサイズが足らないので無視
		return;
	}
	buf = (UCHAR *)data;
	key32 = (UINT *)(buf + 4);


	// Key32 の値からセッションを取得
	session = GetSessionFromUDPEntry(cedar, Endian32(*key32));
	if (session == NULL)
	{
		Debug("Invalid UDP Session Key 32: 0x%X\n", *key32);
		return;
	}

	c = session->Connection;

	// データを書き込む
	PutUDPPacketData(c, buf, size);

	// コネクションに関連付けられている UDP ソケットを書き換える
	Lock(c->lock);
	{
		if (c->Protocol == CONNECTION_UDP)
		{
			if (c->Udp->s != s)
			{
				if (c->Udp->s != NULL)
				{
					ReleaseSock(c->Udp->s);
				}
				AddRef(s->ref);
				c->Udp->s = s;
			}
			Copy(&c->Udp->ip, ip, sizeof(UINT));
			c->Udp->port = port;
		}
	}
	Unlock(c->lock);

	// キャンセル発動
	Cancel(session->Cancel1);

	// セッションを解放
	ReleaseSession(session);
}

// Accept された TCP コネクションを処理するスレッド
void TCPAcceptedThread(THREAD *t, void *param)
{
	TCP_ACCEPTED_PARAM *data;
	LISTENER *r;
	SOCK *s;
	CONNECTION *c;
	bool flag1;
	char tmp[128];
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	// 初期化
	data = (TCP_ACCEPTED_PARAM *)param;
	r = data->r;
	s = data->s;
	AddRef(r->ref);
	AddRef(s->ref);

	// コネクションの作成
	c = NewServerConnection(r->Cedar, s, t);

	// Cedar に一時コネクションとして登録する
	AddConnection(c->Cedar, c);

	NoticeThreadInit(t);

	AcceptInit(s);
	StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	SLog(r->Cedar, "LS_LISTENER_ACCEPT", r->Port, tmp, s->RemoteHostname, s->RemotePort);

	// 受付
	ConnectionAccept(c);
	flag1 = c->flag1;

	// 解放
	SLog(r->Cedar, "LS_CONNECTION_END_1", c->Name);
	ReleaseConnection(c);

	// 解放
	if (flag1 == false)
	{
		Debug("%s %u flag1 == false\n", __FILE__, __LINE__);
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		SLog(r->Cedar, "LS_LISTENER_DISCONNECT", tmp, s->RemotePort);
		Disconnect(s);
	}
	ReleaseSock(s);
	ReleaseListener(r);
}

// TCP で Accept されたコネクションがある場合はここに飛ぶ
void TCPAccepted(LISTENER *r, SOCK *s)
{
	TCP_ACCEPTED_PARAM *data;
	THREAD *t;
	char tmp[MAX_SIZE];
	UINT num_clients_from_this_ip = 0;
	CEDAR *cedar;
	// 引数チェック
	if (r == NULL || s == NULL)
	{
		return;
	}

	cedar = r->Cedar;

	num_clients_from_this_ip = GetNumIpClient(&s->RemoteIP);

	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

	data = ZeroMalloc(sizeof(TCP_ACCEPTED_PARAM));
	data->r = r;
	data->s = s;

	if (r->ThreadProc == TCPAcceptedThread)
	{
		Inc(cedar->AcceptingSockets);
	}

	t = NewThread(r->ThreadProc, data);
	WaitThreadInit(t);
	Free(data);
	ReleaseThread(t);
}

// UDP リスナーメインループ
void ListenerUDPMainLoop(LISTENER *r)
{
	UCHAR *data;
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	Debug("ListenerUDPMainLoop Starts.\n");
	r->Status = LISTENER_STATUS_TRYING;

	while (true)
	{
		// UDP ポートでの待機を試みる
		while (true)
		{
			// 停止フラグ検査
			if (r->Halt)
			{
				// 停止
				return;
			}

			Debug("NewUDP()\n");
			r->Sock = NewUDP(r->Port);
			if (r->Sock != NULL)
			{
				// 待機成功
				break;
			}

			// 待機失敗
			Debug("Failed to NewUDP.\n");
			Wait(r->Event, LISTEN_RETRY_TIME);

			// 停止フラグ検査
			if (r->Halt)
			{
				Debug("UDP Halt.\n");
				return;
			}
		}

		r->Status = LISTENER_STATUS_LISTENING;
		Debug("Start Listening at UDP Port %u.\n", r->Sock->LocalPort);

		// 停止フラグ検査
		if (r->Halt)
		{
			// 停止
			goto STOP;
		}

		// バッファ領域の確保
		data = Malloc(UDP_PACKET_SIZE);

		// 次のパケットを読み込む
		while (true)
		{
			IP src_ip;
			UINT src_port;
			UINT size;
			SOCKSET set;

			InitSockSet(&set);
			AddSockSet(&set, r->Sock);
			Select(&set, SELECT_TIME, NULL, NULL);

			size = RecvFrom(r->Sock, &src_ip, &src_port, data, UDP_PACKET_SIZE);
			if (((size == 0) && (r->Sock->IgnoreRecvErr == false)) || r->Halt)
			{
				// エラーが発生した
STOP:
				Disconnect(r->Sock);
				ReleaseSock(r->Sock);
				r->Sock = NULL;
				Debug("UDP Listen Stopped.\n");
				Free(data);
				break;
			}

			// UDP パケットを 1 つ受信した
			if (size != SOCK_LATER)
			{
				UDPReceivedPacket(r->Cedar, r->Sock, &src_ip, src_port, data, size);
			}
		}
	}
}

// TCP リスナーメインループ
void ListenerTCPMainLoop(LISTENER *r)
{
	SOCK *new_sock;
	SOCK *s;
	UINT num_failed;
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	Debug("ListenerTCPMainLoop Starts.\n");
	r->Status = LISTENER_STATUS_TRYING;

	while (true)
	{
		bool first_failed = true;
		Debug("Status = LISTENER_STATUS_TRYING\n");
		r->Status = LISTENER_STATUS_TRYING;

		// Listen を試みる
		while (true)
		{
			UINT interval;
			// 停止フラグ検査
			if (r->Halt)
			{
				// 停止
				return;
			}

			if (r->ShadowIPv6 == false)
			{
				s = ListenEx(r->Port, r->LocalOnly);
			}
			else
			{
				s = ListenEx6(r->Port, r->LocalOnly);
			}

			if (s != NULL)
			{
				// Listen 成功
				AddRef(s->ref);
				r->Sock = s;
				if (r->ShadowIPv6 == false)
				{
					SLog(r->Cedar, "LS_LISTENER_START_2", r->Port);
				}
				break;
			}

			// Listen 失敗
			if (first_failed)
			{
				first_failed = false;
				if (r->ShadowIPv6 == false)
				{
					SLog(r->Cedar, "LS_LISTENER_START_3", r->Port, LISTEN_RETRY_TIME / 1000);
				}
			}

			interval = LISTEN_RETRY_TIME;

			if (r->ShadowIPv6)
			{
				if (IsIPv6Supported() == false)
				{
					interval = LISTEN_RETRY_TIME_NOIPV6;

					Debug("IPv6 is not supported.\n");
				}
			}

			Wait(r->Event, interval);

			// 停止フラグ検査
			if (r->Halt)
			{
				// 停止
				Debug("Listener Halt.\n");
				return;
			}
		}

		r->Status = LISTENER_STATUS_LISTENING;
		Debug("Status = LISTENER_STATUS_LISTENING\n");

		// 停止フラグ検査
		if (r->Halt)
		{
			// 停止
			goto STOP;
		}

		num_failed = 0;

		// Accpet ループ
		while (true)
		{
			// Accept を行う
			Debug("Accept()\n");
			new_sock = Accept(r->Sock);
			if (new_sock != NULL)
			{
				// Accept 成功
				Debug("Accepted.\n");
				TCPAccepted(r, new_sock);
				ReleaseSock(new_sock);
			}
			else
			{
				if (r->Halt == false)
				{
					if ((++num_failed) <= 5)
					{
						continue;
					}
				}
STOP:
				Debug("Accept Canceled.\n");
				// Accept に失敗した (ソケットが破壊された)
				// Listen しているソケットを閉じる
				Disconnect(s);
				ReleaseSock(s);
				break;
			}
		}

		// 停止フラグ検査
		if (r->Halt)
		{
			// 停止
			Debug("Listener Halt.\n");
			return;
		}
	}
}

// リスナーのスレッド
void ListenerThread(THREAD *thread, void *param)
{
	LISTENER *r;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// 初期化
	r = (LISTENER *)param;
	AddRef(r->ref);
	r->Thread = thread;
	AddRef(thread->ref);
	NoticeThreadInit(thread);

	// メインループ
	switch (r->Protocol)
	{
	case LISTENER_TCP:
		// TCP プロトコル
		ListenerTCPMainLoop(r);
		break;

	case LISTENER_UDP:
		// UDP プロトコル
		ListenerUDPMainLoop(r);
		break;
	}

	// 解放
	ReleaseListener(r);
}

// リスナーの停止
void StopListener(LISTENER *r)
{
	UINT port;
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	if (r->Halt)
	{
		return;
	}

	port = r->Port;

	// 停止フラグセット
	r->Halt = true;

	if (r->ShadowIPv6 == false)
	{
		SLog(r->Cedar, "LS_LISTENER_STOP_1", port);
	}

	// ソケットを閉じる
	Disconnect(r->Sock);

	// イベントのセット
	Set(r->Event);

	// スレッドが停止するまで待機
	WaitThread(r->Thread, INFINITE);

	// 影のリスナーを停止させる
	if (r->ShadowIPv6 == false)
	{
		if (r->ShadowListener != NULL)
		{
			StopListener(r->ShadowListener);

			ReleaseListener(r->ShadowListener);

			r->ShadowListener = NULL;
		}
	}

	if (r->ShadowIPv6 == false)
	{
		SLog(r->Cedar, "LS_LISTENER_STOP_2", port);
	}
}

// リスナーのクリーンアップ
void CleanupListener(LISTENER *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	if (r->Sock != NULL)
	{
		ReleaseSock(r->Sock);
	}

	DeleteLock(r->lock);
	ReleaseThread(r->Thread);
	ReleaseEvent(r->Event);

	ReleaseCedar(r->Cedar);

	Free(r);
}

// リスナーの解放
void ReleaseListener(LISTENER *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	if (Release(r->ref) == 0)
	{
		CleanupListener(r);
	}
}

// UDP エントリリストの比較関数
int CompareUDPEntry(void *p1, void *p2)
{
	UDP_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(UDP_ENTRY **)p1;
	e2 = *(UDP_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->SessionKey32 > e2->SessionKey32)
	{
		return 1;
	}
	else if (e1->SessionKey32 == e2->SessionKey32)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

// リスナーの比較関数
int CompareListener(void *p1, void *p2)
{
	LISTENER *r1, *r2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	r1 = *(LISTENER **)p1;
	r2 = *(LISTENER **)p2;
	if (r1 == NULL || r2 == NULL)
	{
		return 0;
	}

	if (r1->Protocol > r2->Protocol)
	{
		return 1;
	}
	else if (r1->Protocol < r2->Protocol)
	{
		return -1;
	}
	else if (r1->Port > r2->Port)
	{
		return 1;
	}
	else if (r1->Port < r2->Port)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// 新しいリスナーの作成
LISTENER *NewListener(CEDAR *cedar, UINT proto, UINT port)
{
	return NewListenerEx(cedar, proto, port, TCPAcceptedThread, NULL);
}
LISTENER *NewListenerEx(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param)
{
	return NewListenerEx2(cedar, proto, port, proc, thread_param, false);
}
LISTENER *NewListenerEx2(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only)
{
	return NewListenerEx3(cedar, proto, port, proc, thread_param, local_only, false);
}
LISTENER *NewListenerEx3(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6)
{
	LISTENER *r;
	THREAD *t;
	// 引数チェック
	if (port == 0 || cedar == NULL)
	{
		return NULL;
	}
	// プロトコル番号のチェック
	if (proto != LISTENER_TCP && proto != LISTENER_UDP)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(LISTENER));

	r->ThreadProc = proc;
	r->ThreadParam = thread_param;
	r->Cedar = cedar;
	AddRef(r->Cedar->ref);
	r->lock = NewLock();
	r->ref = NewRef();
	r->Protocol = proto;
	r->Port = port;
	r->Event = NewEvent();
	r->LocalOnly = local_only;
	r->ShadowIPv6 = shadow_ipv6;

	if (r->ShadowIPv6 == false)
	{
		SLog(cedar, "LS_LISTENER_START_1", port);
	}

	// スレッドの作成
	t = NewThread(ListenerThread, r);
	WaitThreadInit(t);
	ReleaseThread(t);

	if (r->ShadowIPv6 == false)
	{
		if (r->Cedar->DisableIPv6Listener == false)
		{
			// 影のリスナーを追加する
			r->ShadowListener = NewListenerEx3(cedar, proto, port, proc, thread_param,
				local_only, true);
		}
	}

	if (r->ShadowIPv6 == false)
	{
		// Cedar に追加
		AddListener(cedar, r);
	}

	return r;
}

// セッションキーからセッションを取得する
SESSION *GetSessionFromUDPEntry(CEDAR *cedar, UINT key32)
{
	UDP_ENTRY *e, t;
	SESSION *s;
	// 引数チェック
	if (cedar == NULL)
	{
		return NULL;
	}

	t.SessionKey32 = key32;

	LockList(cedar->UDPEntryList);
	{
		e = Search(cedar->UDPEntryList, &t);
		if (e == NULL)
		{
			UnlockList(cedar->UDPEntryList);
			return NULL;
		}
		s = e->Session;
		AddRef(s->ref);
	}
	UnlockList(cedar->UDPEntryList);

	return s;
}

// UDP セッションを UDP エントリから削除する
void DelUDPEntry(CEDAR *cedar, SESSION *session)
{
	UINT num, i;
	// 引数チェック
	if (cedar == NULL || session == NULL)
	{
		return;
	}

	LockList(cedar->UDPEntryList);
	{
		num = LIST_NUM(cedar->UDPEntryList);
		for (i = 0;i < num;i++)
		{
			UDP_ENTRY *e = LIST_DATA(cedar->UDPEntryList, i);
			if (e->Session == session)
			{
				ReleaseSession(e->Session);
				Delete(cedar->UDPEntryList, e);
				Free(e);
				UnlockList(cedar->UDPEntryList);
				Debug("UDP_Entry Deleted.\n");
				return;
			}
		}
	}
	UnlockList(cedar->UDPEntryList);
}

// UDP セッションを UDP エントリに追加する
void AddUDPEntry(CEDAR *cedar, SESSION *session)
{
	UDP_ENTRY *e;
	// 引数チェック
	if (cedar == NULL || session == NULL)
	{
		return;
	}

	e = ZeroMalloc(sizeof(UDP_ENTRY));
	e->Session = session;
	e->SessionKey32 = session->SessionKey32;
	AddRef(session->ref);

	LockList(cedar->UDPEntryList);
	{
		Add(cedar->UDPEntryList, e);
	}
	UnlockList(cedar->UDPEntryList);

	Debug("UDP_Entry Added.\n");
}

// UDP エントリのクリア
void CleanupUDPEntry(CEDAR *cedar)
{
	// 引数チェック
	if (cedar == NULL)
	{
		return;
	}
}


