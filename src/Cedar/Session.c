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

// Session.c
// セッションマネージャ

#include "CedarPch.h"

// セッションのメインルーチン
void SessionMain(SESSION *s)
{
	CONNECTION *c;
	POLICY *policy;
	UINT64 now;
	UINT i = 0;
	PACKET_ADAPTER *pa;
	bool pa_inited = false;
	UINT packet_size;
	void *packet;
	bool packet_put;
	bool pa_fail = false;
	UINT test = 0;
	bool update_hub_last_comm = false;
	UINT err = ERR_SESSION_TIMEOUT;
	UINT64 next_update_hub_last_comm = 0;
	UINT64 auto_disconnect_tick = 0;
	TRAFFIC t;
	SOCK *msgdlg_sock = NULL;
	SOCK *nicinfo_sock = NULL;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}
	Debug("SessionMain: %s\n", s->Name);

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	// リトライ回数のリセット
	s->CurrentRetryCount = 0;
	s->ConnectSucceed = true;
	s->SessionTimeOuted = false;

	c = s->Connection;
	policy = s->Policy;

	// パケットアダプタの初期化
	pa = s->PacketAdapter;
	if (pa->Init(s) == false)
	{
		// 初期化失敗
		if (s->VLanDeviceErrorCount >= 2)
		{
			s->ForceStopFlag = true;
		}
		else
		{
			s->VLanDeviceErrorCount++;
		}
		err = ERR_DEVICE_DRIVER_ERROR;
		goto CLEANUP;
	}
	pa_inited = true;

	if (s->BridgeMode == false)
	{
		s->Cancel2 = pa->GetCancel(s);
	}
	else
	{
		CANCEL *c = pa->GetCancel(s);
		CANCEL *old = s->Cancel1;
		s->Cancel1 = c;
		ReleaseCancel(old);
	}

	s->RetryFlag = false;

	s->LastCommTime = Tick64();
	if (s->ServerMode == false)
	{
		s->NextConnectionTime = Tick64() + (UINT64)(s->ClientOption->AdditionalConnectionInterval * 1000);
	}

	s->NumConnectionsEatablished++;
	s->CurrentConnectionEstablishTime = Tick64();
	if (s->FirstConnectionEstablisiedTime == 0)
	{
		s->FirstConnectionEstablisiedTime = Tick64();
	}

	if (s->ServerMode == false && s->Cedar->Client != NULL)
	{
		if (s->Policy != NULL)
		{
			if (s->Policy->AutoDisconnect)
			{
				auto_disconnect_tick = s->CurrentConnectionEstablishTime +
					(UINT64)s->Policy->AutoDisconnect * 1000ULL;
			}
		}
	}

	s->LastIncrementTraffic = Tick64();

	c->Err = ERR_SESSION_TIMEOUT;
	s->VLanDeviceErrorCount = 0;

	s->LastTryAddConnectTime = Tick64();

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	if (policy != NULL)
	{
		// ポリシーの内容を見てモードを決定する
		if (policy->MonitorPort)
		{
			s->IsMonitorMode = true;
		}

		if (policy->NoRouting == false || policy->NoBridge == false)
		{
			s->IsBridgeMode = true;
		}
	}

	if (s->ServerMode == false && s->Cedar->Client != NULL)
	{
		if (IsEmptyUniStr(s->Client_Message) == false)
		{
			UI_MSG_DLG dlg;

			Zero(&dlg, sizeof(dlg));
			if (s->ClientOption != NULL)
			{
				StrCpy(dlg.HubName, sizeof(dlg.HubName), s->ClientOption->HubName);
				StrCpy(dlg.ServerName, sizeof(dlg.ServerName), s->ClientOption->Hostname);
			}

			dlg.Msg = s->Client_Message;

			msgdlg_sock = CncMsgDlg(&dlg);
		}

		if (s->Win32HideNicInfoWindow == false)
		{
			UI_NICINFO info;

			Zero(&info, sizeof(info));
			if (s->ClientOption != NULL)
			{
				StrCpy(info.NicName, sizeof(info.NicName), s->ClientOption->DeviceName);
				UniStrCpy(info.AccountName, sizeof(info.AccountName), s->ClientOption->AccountName);
			}

			nicinfo_sock = CncNicInfo(&info);
		}
	}

	while (true)
	{
		Zero(&t, sizeof(t));

		if (next_update_hub_last_comm == 0 ||
			(next_update_hub_last_comm <= Tick64()))
		{
			next_update_hub_last_comm = Tick64() + 1000;

			if (s->Hub != NULL)
			{
				if (update_hub_last_comm)
				{
					Lock(s->Hub->lock);
					{
						s->Hub->LastCommTime = SystemTime64();
					}
					Unlock(s->Hub->lock);

					update_hub_last_comm = false;
				}
			}
		}

		// 追加接続のチャンス
		ClientAdditionalConnectChance(s);

		// ブロックを受信
		ConnectionReceive(c, s->Cancel1, s->Cancel2);

		// 受信したブロックを PacketAdapter に渡す
		LockQueue(c->ReceivedBlocks);
		{
			BLOCK *b;
			packet_put = false;
			while (true)
			{
				b = GetNext(c->ReceivedBlocks);
				if (b == NULL)
				{
					break;
				}

				PROBE_DATA2("GetNext", b->Buf, b->Size);

				update_hub_last_comm = true;

				if (s->ServerMode == false && b->Size >= 14)
				{
					if (b->Buf[0] & 0x40)
					{
						t.Recv.BroadcastCount++;
						t.Recv.BroadcastBytes += (UINT64)b->Size;
					}
					else
					{
						t.Recv.UnicastCount++;
						t.Recv.UnicastBytes += (UINT64)b->Size;
					}
				}

				packet_put = true;
				PROBE_DATA2("pa->PutPacket", b->Buf, b->Size);
				if (pa->PutPacket(s, b->Buf, b->Size) == false)
				{
					pa_fail = true;
					err = ERR_DEVICE_DRIVER_ERROR;
					Free(b->Buf);
					Debug("  Error: pa->PutPacket(Packet) Failed.\n");
				}
				Free(b);
			}

			if (packet_put || s->ServerMode)
			{
				PROBE_DATA2("pa->PutPacket", NULL, 0);
				if (pa->PutPacket(s, NULL, 0) == false)
				{
					Debug("  Error: pa->PutPacket(NULL) Failed.\n");
					pa_fail = true;
					err = ERR_DEVICE_DRIVER_ERROR;
				}
			}
		}
		UnlockQueue(c->ReceivedBlocks);

		// 送信するべきパケットを PacketAdapter から取得して SendBlocks に追加
		LockQueue(c->SendBlocks);
		{
			UINT i, max_num = MAX_SEND_SOCKET_QUEUE_NUM;
			i = 0;
			while (packet_size = pa->GetNextPacket(s, &packet))
			{
				BLOCK *b;
				if (packet_size == INFINITE)
				{
					err = ERR_DEVICE_DRIVER_ERROR;
					pa_fail = true;
					Debug("  Error: pa->GetNextPacket() Failed.\n");
					break;
				}

				update_hub_last_comm = true;

				if ((c->CurrentSendQueueSize > MAX_BUFFERING_PACKET_SIZE))
				{
//					WHERE;
					// バッファリングサイズ制限値を超過しているので破棄
					Free(packet);
				}
				else
				{
					bool priority;
					// バッファリングする
					if (s->ServerMode == false && packet_size >= 14)
					{
						UCHAR *buf = (UCHAR *)packet;
						if (buf[0] & 0x01)
						{
							t.Send.BroadcastCount++;
							t.Send.BroadcastBytes += (UINT64)packet_size;
						}
						else
						{
							t.Send.UnicastCount++;
							t.Send.UnicastBytes += (UINT64)packet_size;
						}
					}
					priority = IsPriorityHighestPacketForQoS(packet, packet_size);
					b = NewBlock(packet, packet_size, s->UseCompress ? 1 : 0);
					b->PriorityQoS = priority;
					c->CurrentSendQueueSize += b->Size;

					if (b->PriorityQoS && c->Protocol == CONNECTION_TCP && s->QoS)
					{
						InsertQueue(c->SendBlocks2, b);
					}
					else
					{
						InsertQueue(c->SendBlocks, b);
					}
				}
				i++;
				if (i >= max_num)
				{
					break;
				}
			}
		}
		UnlockQueue(c->SendBlocks);

		AddTrafficForSession(s, &t);

		// ブロックを送信
		ConnectionSend(c);

		// 自動切断判定
		if (auto_disconnect_tick != 0 && auto_disconnect_tick <= Tick64())
		{
			err = ERR_AUTO_DISCONNECTED;
			s->CurrentRetryCount = INFINITE;
			break;
		}

		// 停止判定
		if (s->Halt)
		{
			if (s->ForceStopFlag)
			{
				err = ERR_USER_CANCEL;
			}
			break;
		}

		// 現在時刻を取得
		now = Tick64();

		if (s->ServerMode)
		{
			HUB *hub;

			// ユーザーのトラフィックデータの更新
			if ((s->LastIncrementTraffic + INCREMENT_TRAFFIC_INTERVAL) <= now)
			{
				IncrementUserTraffic(s->Hub, s->UserNameReal, s);
				s->LastIncrementTraffic = now;
			}

			hub = s->Hub;

			if (hub != NULL)
			{
				Lock(hub->lock);
				{
					if ((hub->LastIncrementTraffic + INCREMENT_TRAFFIC_INTERVAL) <= now)
					{
						IncrementHubTraffic(s->Hub);
						hub->LastIncrementTraffic = now;
					}
				}
				Unlock(hub->lock);
			}
		}

		// リンクモードサーバーセッションの場合はタイムアウトしない
		// それ以外のセッションの場合はタイムアウトを判定する
		if (s->LinkModeServer == false && s->SecureNATMode == false && s->BridgeMode == false && s->L3SwitchMode == false)
		{
			bool timeouted = false;

			if ((now > s->LastCommTime) && ((now - s->LastCommTime) >= ((UINT64)s->Timeout)))
			{
				// 一定時間通信ができていない場合
				timeouted = true;
			}

			if (s->ServerMode == false && s->ClientOption != NULL && s->ClientOption->ConnectionDisconnectSpan == 0)
			{
				if (LIST_NUM(s->Connection->Tcp->TcpSockList) < s->MaxConnection)
				{
					if ((s->LastTryAddConnectTime +
						(UINT64)(s->ClientOption->AdditionalConnectionInterval * 1000 * 2 + CONNECTING_TIMEOUT * 2))
						<= Tick64())
					{
						timeouted = true;
					}
				}
			}

			if (timeouted)
			{
				// タイムアウトが発生した
				Debug("** Session Timeouted.\n");
				s->SessionTimeOuted = true;
				err = ERR_SESSION_TIMEOUT;
			}
		}

		// タイムアウト判定
		if (pa_fail || s->SessionTimeOuted)
		{
			s->Halt = true;
			s->RetryFlag = true;	// リトライフラグ
			break;
		}
	}

CLEANUP:
	Debug("Session %s Finishing...\n", s->Name);

	// HUB のセッション一覧から削除する
	if (s->ServerMode)
	{
		// ユーザー情報を更新する
		IncrementUserTraffic(s->Hub, s->UserNameReal, s);

		DelSession(s->Hub, s);
	}

	s->ConnectSucceed = false;
	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	if (s->Connection)
	{
		s->Connection->Halt = true;
	}

	// パケットアダプタの解放
	if (pa_inited)
	{
		pa->Free(s);
	}

	if (s->ServerMode == false)
	{
		// すべての追加コネクションの作成をキャンセルする
		StopAllAdditionalConnectThread(s->Connection);
	}

	if (s->BridgeMode)
	{
		// ブリッジの終了
		if (s->Bridge->Active)
		{
			CloseEth(s->Bridge->Eth);
			s->Bridge->Eth = NULL;
		}
	}

	if (s->Cancel2 != NULL)
	{
		// キャンセル2 の解放
		ReleaseCancel(s->Cancel2);
		s->Cancel2 = NULL;
	}

	// コネクションの終了
	EndTunnelingMode(c);

	if (nicinfo_sock != NULL)
	{
		CncNicInfoFree(nicinfo_sock);
	}

	if (msgdlg_sock != NULL)
	{
		CndMsgDlgFree(msgdlg_sock);
	}

	c->Err = err;
}

// 次の遅延パケットまでの時間を取得する
UINT GetNextDelayedPacketTickDiff(SESSION *s)
{
	UINT i;
	UINT ret = 0x7fffffff;
	UINT64 now;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	if (LIST_NUM(s->DelayedPacketList) >= 1)
	{
		now = TickHighres64();

		LockList(s->DelayedPacketList);
		{
			for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
			{
				PKT *p = LIST_DATA(s->DelayedPacketList, i);
				UINT64 t = p->DelayedForwardTick;
				UINT d = 0x7fffffff;

				if (now >= t)
				{
					d = 0;
				}
				else
				{
					d = (UINT)(t - now);
				}

				ret = MIN(ret, d);
			}
		}
		UnlockList(s->DelayedPacketList);
	}

	return ret;
}

// VoIP / QoS 機能で優先すべきパケットかどうか判定する
bool IsPriorityHighestPacketForQoS(void *data, UINT size)
{
	UCHAR *buf;
	// 引数チェック
	if (data == NULL)
	{
		return false;
	}

	buf = (UCHAR *)data;
	if (size >= 16)
	{
		if (buf[12] == 0x08 && buf[13] == 0x00 && buf[15] != 0x00 && buf[15] != 0x08)
		{
			// IPv4 パケットかつ ToS != 0
			return true;
		}

		if (size >= 34 && size <= 128)
		{
			if (buf[12] == 0x08 && buf[13] == 0x00 && buf[23] == 0x01)
			{
				// IMCPv4 パケット
				return true;
			}
		}
	}

	return false;
}

// ユーザーのトラフィック情報を更新する
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s)
{
	TRAFFIC report_traffic;
	// 引数チェック
	if (hub == NULL || username == NULL || s == NULL)
	{
		return;
	}

	Lock(s->TrafficLock);
	{
		// 報告するトラフィック情報 (前回との差分) を計算する
		Zero(&report_traffic, sizeof(report_traffic));
		report_traffic.Send.BroadcastBytes =
			s->Traffic->Send.BroadcastBytes - s->OldTraffic->Send.BroadcastBytes;
		report_traffic.Send.BroadcastCount =
			s->Traffic->Send.BroadcastCount - s->OldTraffic->Send.BroadcastCount;
		report_traffic.Send.UnicastBytes =
			s->Traffic->Send.UnicastBytes - s->OldTraffic->Send.UnicastBytes;
		report_traffic.Send.UnicastCount =
			s->Traffic->Send.UnicastCount - s->OldTraffic->Send.UnicastCount;
		report_traffic.Recv.BroadcastBytes =
			s->Traffic->Recv.BroadcastBytes - s->OldTraffic->Recv.BroadcastBytes;
		report_traffic.Recv.BroadcastCount =
			s->Traffic->Recv.BroadcastCount - s->OldTraffic->Recv.BroadcastCount;
		report_traffic.Recv.UnicastBytes =
			s->Traffic->Recv.UnicastBytes - s->OldTraffic->Recv.UnicastBytes;
		report_traffic.Recv.UnicastCount =
			s->Traffic->Recv.UnicastCount - s->OldTraffic->Recv.UnicastCount;
		Copy(s->OldTraffic, s->Traffic, sizeof(TRAFFIC));

		if (hub->FarmMember == false)
		{
			// ファームメンバーでない場合はローカルデータベースのユーザー情報を更新する
			AcLock(hub);
			{
				USER *u = AcGetUser(hub, username);
				if (u != NULL)
				{
					Lock(u->lock);
					{
						AddTraffic(u->Traffic, &report_traffic);
					}
					Unlock(u->lock);
					if (u->Group != NULL)
					{
						Lock(u->Group->lock);
						{
							AddTraffic(u->Group->Traffic, &report_traffic);
						}
						Unlock(u->Group->lock);
					}
					ReleaseUser(u);
				}
			}
			AcUnlock(hub);
		}
		else
		{
			// ファームメンバの場合はトラフィック差分報告リストを更新する
			AddTrafficDiff(hub, username, TRAFFIC_DIFF_USER, &report_traffic);
		}
	}
	Unlock(s->TrafficLock);
}

// コネクションのトラフィック情報を加算
void AddTrafficForSession(SESSION *s, TRAFFIC *t)
{
	HUB *h;
	TRAFFIC t2;
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	Lock(s->TrafficLock);
	{
		AddTraffic(s->Traffic, t);
	}
	Unlock(s->TrafficLock);

	if (s->ServerMode)
	{
		Zero(&t2, sizeof(t2));
		Copy(&t2.Recv, &t->Send, sizeof(TRAFFIC_ENTRY));
		Copy(&t2.Send, &t->Recv, sizeof(TRAFFIC_ENTRY));
		Lock(s->Cedar->TrafficLock);
		{
			AddTraffic(s->Cedar->Traffic, &t2);
		}
		Unlock(s->Cedar->TrafficLock);

		h = s->Hub;
		Lock(h->TrafficLock);
		{
			AddTraffic(h->Traffic, &t2);
		}
		Unlock(h->TrafficLock);
	}
}

// クライアントの追加コネクション確立のチャンス
void ClientAdditionalConnectChance(SESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (s->ServerMode)
	{
		// サーバーモードの場合は追加接続しない
		return;
	}
	if (s->Connection->Protocol != CONNECTION_TCP)
	{
		// TCP プロトコル以外の場合は追加接続しない
		return;
	}

	while (true)
	{
		if (s->Halt)
		{
			return;
		}
		// 追加コネクションを張る必要があるかどうかを
		// 現在張っている または 張ろうとしているコネクション数と
		// MaxConnection プロパティを見て検討する。
		if (Count(s->Connection->CurrentNumConnection) < s->MaxConnection)
		{
			// 現在時刻を取得
			UINT64 now = Tick64();

			// NextConnectionTime を調べてその時刻を過ぎていればコネクションを
			// 張ろうとする
			if (s->NextConnectionTime == 0 ||
				s->ClientOption->AdditionalConnectionInterval == 0 ||
				(s->NextConnectionTime <= now))
			{
				// 追加コネクションを張る作業を開始する
				s->NextConnectionTime = now + (UINT64)(s->ClientOption->AdditionalConnectionInterval * 1000);
				SessionAdditionalConnect(s);
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
}

// パケットアダプタの解放
void FreePacketAdapter(PACKET_ADAPTER *pa)
{
	// 引数チェック
	if (pa == NULL)
	{
		return;
	}

	Free(pa);
}

// 新しいパケットアダプタの作成
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
								 PA_PUTPACKET *put, PA_FREE *free)
{
	PACKET_ADAPTER *pa;
	// 引数チェック
	if (init == NULL || getcancel == NULL || getnext == NULL || put == NULL || free == NULL)
	{
		return NULL;
	}

	pa = ZeroMalloc(sizeof(PACKET_ADAPTER));

	pa->Init = init;
	pa->Free = free;
	pa->GetCancel = getcancel;
	pa->GetNextPacket = getnext;
	pa->PutPacket = put;

	return pa;
}

// 追加コネクションを張るためのスレッド
void ClientAdditionalThread(THREAD *t, void *param)
{
	SESSION *s;
	CONNECTION *c;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (SESSION *)param;

	// s->LastTryAddConnectTime = Tick64();

	c = s->Connection;
	// 接続中カウンタのインクリメント
	Inc(c->CurrentNumConnection);
	LockList(c->ConnectingThreads);
	{
		// 処理中スレッドに追加
		Add(c->ConnectingThreads, t);
		AddRef(t->ref);
	}
	UnlockList(c->ConnectingThreads);

	// 初期化の完了を通知
	NoticeThreadInit(t);

	Debug("Additional Connection #%u\n", Count(c->CurrentNumConnection));

	// 追加コネクションを張る
	if (ClientAdditionalConnect(c, t) == false)
	{
		// 現在処理中のカウンタをデクリメントする
		Dec(c->CurrentNumConnection);
	}
	else
	{
		s->LastTryAddConnectTime = Tick64();
	}

	// 処理中スレッドから削除
	LockList(c->ConnectingThreads);
	{
		// 処理中スレッドから削除
		if (Delete(c->ConnectingThreads, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(c->ConnectingThreads);
	ReleaseSession(s);
}

// クライアントからサーバーに追加コネクションを張る
void SessionAdditionalConnect(SESSION *s)
{
	THREAD *t;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// s->LastTryAddConnectTime = Tick64();

	AddRef(s->ref);
	t = NewThread(ClientAdditionalThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);
}

// クライアントセッションをサーバーに接続する
bool SessionConnect(SESSION *s)
{
	CONNECTION *c;
	bool ret = false;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	s->ClientStatus = CLIENT_STATUS_CONNECTING;

	Debug("SessionConnect() Started.\n");

	// セッションの初期化
	Lock(s->lock);
	{
		s->Err = ERR_NO_ERROR;
		if (s->Policy != NULL)
		{
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	s->CancelConnect = false;

	// クライアントコネクションの作成
	c = NewClientConnection(s);
	s->Connection = c;

	// クライアントをサーバーに接続する
	ret = ClientConnect(c);
	s->Err = c->Err;

	s->CancelConnect = false;

	if (s->Cedar->Client != NULL)
	{
		if (s->Policy != NULL)
		{
			if (s->Policy->NoSavePassword)
			{
				s->Client_NoSavePassword = true;

				if (s->Account != NULL)
				{
					Lock(s->Account->lock);
					{
						if (s->Account->ClientAuth != NULL)
						{
							if (s->Account->ClientAuth->AuthType == AUTHTYPE_PASSWORD ||
								s->Account->ClientAuth->AuthType == AUTHTYPE_RADIUS)
							{
								Zero(s->Account->ClientAuth->HashedPassword, sizeof(s->Account->ClientAuth->HashedPassword));
								Zero(s->Account->ClientAuth->PlainPassword, sizeof(s->Account->ClientAuth->PlainPassword));
							}
						}
					}
					Unlock(s->Account->lock);

					CiSaveConfigurationFile(s->Cedar->Client);
				}
			}
		}
	}

	if (c->ClientConnectError_NoSavePassword)
	{
		s->Client_NoSavePassword = true;
	}

	// クライアントコネクションの解放
	s->Connection = NULL;
	ReleaseConnection(c);

	Lock(s->lock);
	{
		if (s->Policy != NULL)
		{
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	return ret;
}

// セッションの停止
void StopSession(SESSION *s)
{
	StopSessionEx(s, false);
}
void StopSessionEx(SESSION *s, bool no_wait)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// 停止フラグ
	s->UserCanceled = true;
	s->CancelConnect = true;
	s->Halt = true;

	Debug("Stop Session %s\n", s->Name);

	// キャンセル
	Cancel(s->Cancel1);

	// イベント
	Set(s->HaltEvent);

	if (s->ServerMode == false)
	{
		// クライアントモード
		if (s->Connection)
		{
			StopConnection(s->Connection, no_wait);
		}
	}
	else
	{
		// サーバーモード
		if (s->Connection)
		{
			StopConnection(s->Connection, no_wait);
		}
	}

	// 停止まで待機
	if (no_wait == false)
	{
		while (true)
		{
			s->ForceStopFlag = true;
			s->Halt = true;
			if (WaitThread(s->Thread, 20))
			{
				break;
			}
		}
	}
	else
	{
		s->ForceStopFlag = true;
		s->Halt = true;
	}
}

// セッションのクリーンアップ
void CleanupSession(SESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// 遅延パケットリストの解放
	if (s->DelayedPacketList != NULL)
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
		{
			PKT *p = LIST_DATA(s->DelayedPacketList, i);

			Free(p->PacketData);
			FreePacket(p);
		}

		ReleaseList(s->DelayedPacketList);
	}

	// クライアント接続オプションの解放
	if (s->ClientOption != NULL)
	{
		Free(s->ClientOption);
	}

	// クライアント認証データの解放
	if (s->ClientAuth != NULL)
	{
		if (s->ClientAuth->ClientX != NULL)
		{
			FreeX(s->ClientAuth->ClientX);
		}
		if (s->ClientAuth->ClientX != NULL)
		{
			FreeK(s->ClientAuth->ClientK);
		}
		Free(s->ClientAuth);
	}

	FreeTraffic(s->Traffic);
	Free(s->Name);

	if (s->Thread != NULL)
	{
		ReleaseThread(s->Thread);
	}

	DeleteLock(s->lock);

	ReleaseEvent(s->HaltEvent);

	if (s->Cancel1)
	{
		ReleaseCancel(s->Cancel1);
	}

	if (s->Cancel2)
	{
		ReleaseCancel(s->Cancel2);
	}

	if (s->Policy)
	{
		Free(s->Policy);
	}

	if (s->Connection)
	{
		ReleaseConnection(s->Connection);
	}

	Free(s->Username);

	if (s->PacketAdapter)
	{
		FreePacketAdapter(s->PacketAdapter);
	}

	if (s->OldTraffic != NULL)
	{
		FreeTraffic(s->OldTraffic);
	}

	DeleteLock(s->TrafficLock);

	if (s->CancelList != NULL)
	{
		ReleaseCancelList(s->CancelList);
	}

	if (s->Client_Message != NULL)
	{
		Free(s->Client_Message);
	}

	DeleteCounter(s->LoggingRecordCount);

	Free(s);
}

// セッションの解放
void ReleaseSession(SESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSession(s);
	}
}

// セッションの転送データサイズ合計を表示する
void PrintSessionTotalDataSize(SESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Debug(
		"-- SESSION TOTAL PKT INFORMATION --\n\n"
		"      TotalSendSize: %I64u\n"
		"  TotalSendSizeReal: %I64u\n"
		"      TotalRecvSize: %I64u\n"
		"  TotalRecvSizeReal: %I64u\n"
		"   Compression Rate: %.2f%% (Send)\n"
		"                     %.2f%% (Recv)\n",
		s->TotalSendSize, s->TotalSendSizeReal,
		s->TotalRecvSize, s->TotalRecvSizeReal,
		(float)((double)s->TotalSendSizeReal / (double)s->TotalSendSize * 100.0f),
		(float)((double)s->TotalRecvSizeReal / (double)s->TotalRecvSize * 100.0f)
		);

}

// クライアントスレッド
void ClientThread(THREAD *t, void *param)
{
	SESSION *s;
	bool use_password_dlg;
	bool no_save_password = false;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	Debug("ClientThread 0x%x Started.\n", t);

	s = (SESSION *)param;
	AddRef(s->ref);
	s->Thread = t;
	AddRef(t->ref);
	NoticeThreadInit(t);

	s->ClientStatus = CLIENT_STATUS_CONNECTING;
	s->RetryFlag = true;
	s->CurrentRetryCount = 0;

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	if (s->Cedar->Client != NULL)
	{
		no_save_password = s->Cedar->Client->DontSavePassword;
	}

	s->Win32HideConnectWindow = s->ClientOption->HideStatusWindow;
	s->Win32HideNicInfoWindow = s->ClientOption->HideNicInfoWindow;

	while (true)
	{
		CLog(s->Cedar->Client, "LC_CONNECT_1", s->ClientOption->AccountName, s->CurrentRetryCount + 1);
		if (s->LinkModeClient && s->Link != NULL)
		{
			HLog(s->Link->Hub, "LH_CONNECT_1", s->ClientOption->AccountName, s->CurrentRetryCount + 1);
		}

		Debug("Trying to Connect to Server... (%u / %u)\n", s->CurrentRetryCount + 0,
			s->ClientOption->NumRetry);

		// 初期化
//		s->TotalRecvSize = s->TotalRecvSizeReal = 
//			s->TotalSendSize = s->TotalSendSizeReal = 0;
		s->NextConnectionTime = 0;

		// 接続を行う
		s->ClientStatus = CLIENT_STATUS_CONNECTING;
		s->Halt = false;
		SessionConnect(s);
		if (s->UserCanceled)
		{
			s->Err = ERR_USER_CANCEL;
		}
		Debug("Disconnected. Err = %u : %S\n", s->Err, _E(s->Err));

		PrintSessionTotalDataSize(s);

		CLog(s->Cedar->Client, "LC_CONNECT_ERROR", s->ClientOption->AccountName,
			GetUniErrorStr(s->Err), s->Err);

		if (s->LinkModeClient && s->Link != NULL)
		{
			HLog(s->Link->Hub, "LH_CONNECT_ERROR", s->ClientOption->AccountName,
				GetUniErrorStr(s->Err), s->Err);
		}

		s->ClientStatus = CLIENT_STATUS_RETRY;

		if (s->Link != NULL)
		{
			((LINK *)s->Link)->LastError = s->Err;
		}

		if (s->Halt && (s->RetryFlag == false) || s->ForceStopFlag)
		{
			// 中断しなければならない
			if (s->Err == ERR_DEVICE_DRIVER_ERROR)
			{
#ifdef	OS_WIN32
				wchar_t tmp[MAX_SIZE];
				if (s->Account != NULL && s->Cedar->Client != NULL)
				{
					UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_DEVICE_ERROR"), s->ClientOption->DeviceName,
						s->Err, _E(s->Err));
					MsgBox(NULL, 0x10000 | 0x40000 | 0x200000 | 0x30, tmp);
				}
#endif	// OS_WIN32
			}
			break;
		}
		// パスワード再入力ダイアログを表示するかどうか判断する
		use_password_dlg = false;

		if (s->Account != NULL && s->Cedar->Client != NULL)
		{
#ifdef	OS_WIN32
			if (s->ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD || s->ClientAuth->AuthType == CLIENT_AUTHTYPE_PLAIN_PASSWORD)
			{
				if (s->Err == ERR_AUTH_FAILED || s->Err == ERR_PROXY_AUTH_FAILED)
				{
					use_password_dlg = true;
				}
			}
#endif	// OS_WIN32
		}

		// 接続に失敗した または接続が切断された
		// リトライ間隔の間待機する

		if (use_password_dlg == false)
		{
			UINT retry_interval = s->RetryInterval;

			if (s->Err == ERR_HUB_IS_BUSY || s->Err == ERR_LICENSE_ERROR ||
				s->Err == ERR_HUB_STOPPING || s->Err == ERR_TOO_MANY_USER_SESSION)
			{
				retry_interval = RETRY_INTERVAL_SPECIAL;
			}

			if (s->CurrentRetryCount >= s->ClientOption->NumRetry)
			{
				// リトライ回数超過

#ifndef	OS_WIN32

				break;

#else	// OS_WIN32

				if (s->Win32HideConnectWindow == false &&
					s->Cedar->Client != NULL && s->Account != NULL)
				{
					// 再接続ダイアログを出す
					UI_CONNECTERROR_DLG p;
					Zero(&p, sizeof(p));
					UniStrCpy(p.AccountName, sizeof(p.AccountName), s->ClientOption->AccountName);
					StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->Hostname);
					p.Err = s->Err;
					p.CurrentRetryCount = s->CurrentRetryCount + 1;
					s->Halt = false;
					p.RetryLimit = 0;
					p.RetryIntervalSec = 0;
					p.CancelEvent = s->HaltEvent;
					p.HideWindow = s->Win32HideConnectWindow;
					if (CncConnectErrorDlg(s, &p) == false)
					{
						// 中断
						break;
					}
					else
					{
						s->Win32HideConnectWindow = p.HideWindow;
						goto SKIP;
					}
				}
				else
				{
					break;
				}

#endif
			}

#ifndef	OS_WIN32

			// 単純な待機
			Wait(s->HaltEvent, retry_interval);

#else	// OS_WIN32

			if (s->Win32HideConnectWindow == false &&
				s->Cedar->Client != NULL && s->Account != NULL)
			{
				// 再接続ダイアログを出す
				UI_CONNECTERROR_DLG p;
				Zero(&p, sizeof(p));
				UniStrCpy(p.AccountName, sizeof(p.AccountName), s->ClientOption->AccountName);
				StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->Hostname);
				p.Err = s->Err;
				p.CurrentRetryCount = s->CurrentRetryCount + 1;
				p.RetryLimit = s->ClientOption->NumRetry;
				p.RetryIntervalSec = retry_interval;
				p.CancelEvent = s->HaltEvent;
				s->Halt = false;
				p.HideWindow = s->Win32HideConnectWindow;
				if (CncConnectErrorDlg(s, &p) == false)
				{
					// 中断
					break;
				}
				s->Win32HideConnectWindow = p.HideWindow;
			}
			else
			{
				// 単純な待機
				Wait(s->HaltEvent, s->RetryInterval);
			}

#endif	// OS_WIN32
		}
		else
		{
#ifdef	OS_WIN32
			// パスワードの再入力を求めて待機
			UI_PASSWORD_DLG p;
			Zero(&p, sizeof(p));
			if (s->Client_NoSavePassword == false)
			{
				p.ShowNoSavePassword = true;
			}
			p.NoSavePassword = no_save_password;
			p.CancelEvent = s->HaltEvent;
			if (s->Err == ERR_PROXY_AUTH_FAILED)
			{
				p.ProxyServer = true;
			}

			if (p.ProxyServer)
			{
				StrCpy(p.Username, sizeof(p.Username), s->ClientOption->ProxyUsername);
				StrCpy(p.Password, sizeof(p.Password), s->ClientOption->ProxyPassword);
				StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->ProxyName);
			}
			else
			{
				bool empty = false;

				StrCpy(p.Username, sizeof(p.Username), s->ClientAuth->Username);
				if (s->ClientAuth->AuthType == AUTHTYPE_RADIUS)
				{
					if (StrLen(s->ClientAuth->PlainPassword) == 0)
					{
						empty = true;
					}
				}
				else if (s->ClientAuth->AuthType == AUTHTYPE_PASSWORD)
				{
					if (IsZero(s->ClientAuth->HashedPassword, sizeof(s->ClientAuth->HashedPassword)))
					{
						empty = true;
					}
				}

				StrCpy(p.Password, sizeof(p.Password), empty ? "" : HIDDEN_PASSWORD);
				StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->Hostname);
			}

			p.RetryIntervalSec = s->RetryInterval / 1000;
			p.Type = s->ClientAuth->AuthType;

			// パスワード再入力ダイアログを表示する
			if (CncPasswordDlg(s, &p) == false)
			{
				// 接続を中断する
				break;
			}
			else
			{
				// ユーザー名を上書きする
				if (p.ProxyServer)
				{
					// プロキシのユーザー名
					StrCpy(s->ClientOption->ProxyUsername, sizeof(s->ClientOption->ProxyUsername), p.Username);
				}
				else
				{
					// Server への接続のためのユーザー名
					StrCpy(s->ClientAuth->Username, sizeof(s->ClientAuth->Username), p.Username);
					s->ClientAuth->AuthType = p.Type;
				}

				if (StrCmp(p.Password, HIDDEN_PASSWORD) != 0)
				{
					// パスワードを再入力した
					if (p.ProxyServer)
					{
						// プロキシサーバーのパスワード
						StrCpy(s->ClientOption->ProxyPassword, sizeof(s->ClientOption->ProxyPassword), p.Password);
					}
					else
					{
						if (s->ClientAuth->AuthType == CLIENT_AUTHTYPE_PLAIN_PASSWORD)
						{
							// 平文パスワード認証
							StrCpy(s->ClientAuth->PlainPassword, sizeof(s->ClientAuth->PlainPassword), p.Password);
						}
						else
						{
							// 暗号化パスワード認証
							HashPassword(s->ClientAuth->HashedPassword, s->ClientAuth->Username, p.Password);
						}
					}
				}

				no_save_password = p.NoSavePassword;

				if (s->Account != NULL && s->Cedar->Client != NULL)
				{
					s->Cedar->Client->DontSavePassword = no_save_password;
					if (p.NoSavePassword == false)
					{
						// クライアントのアカウントデータベースを更新する
						if (p.ProxyServer == false)
						{
							// Server 接続情報の更新
							ACCOUNT *a = s->Account;
							Lock(a->lock);
							{
								CiFreeClientAuth(a->ClientAuth);
								a->ClientAuth = CopyClientAuth(s->ClientAuth);
							}
							Unlock(a->lock);
							CiSaveConfigurationFile(s->Cedar->Client);
						}
						else
						{
							// Proxy 接続情報の更新
							ACCOUNT *a = s->Account;
							Lock(a->lock);
							{
								Copy(a->ClientOption, s->ClientOption, sizeof(CLIENT_OPTION));
							}
							Unlock(a->lock);
							CiSaveConfigurationFile(s->Cedar->Client);
						}
					}
				}
			}
#endif	// OS_WIN32
		}

SKIP:
		// リトライ回数増加
		if (s->ConnectSucceed == false)
		{
			s->CurrentRetryCount++;
		}

		if (s->ForceStopFlag)
		{
			break;
		}
	}

	Debug("Session Halt.\n");

	s->ClientStatus = CLIENT_STATUS_IDLE;

	// ここでセッションは終了したとみなす
	if (s->Account != NULL)
	{
		s->Account->ClientSession = NULL;
		ReleaseSession(s);
	}

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	ReleaseSession(s);
}

// セッションの名前比較
int CompareSession(void *p1, void *p2)
{
	SESSION *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(SESSION **)p1;
	s2 = *(SESSION **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}
	return StrCmpi(s1->Name, s2->Name);
}

// RPC セッションの作成
SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option)
{
	return NewRpcSessionEx(cedar, option, NULL, NULL);
}
SESSION *NewRpcSessionEx(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str)
{
	return NewRpcSessionEx2(cedar, option, err, client_str, NULL);
}
SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd)
{
	SESSION *s;
	CONNECTION *c;
	SOCK *sock;
	// 引数チェック
	if (cedar == NULL || option == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();
	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = false;
	s->Name = CopyStr("CLIENT_RPC_SESSION");
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->TrafficLock = NewLock();
	s->Cancel1 = NewCancel();

	// クライアント接続オプションのコピー
	s->ClientOption = Malloc(sizeof(CLIENT_OPTION));
	Copy(s->ClientOption, option, sizeof(CLIENT_OPTION));

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	// コネクションの作成
	c = s->Connection = NewClientConnectionEx(s, client_str, cedar->Version, cedar->Build);
	c->hWndForUI = hWnd;

	// サーバーへ接続
	sock = ClientConnectToServer(c);
	if (sock == NULL)
	{
		// 接続失敗
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	// シグネチャの送信
	if (ClientUploadSignature(sock) == false)
	{
		// 失敗
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	// Hello パケットの受信
	if (ClientDownloadHello(c, sock) == false)
	{
		// 失敗
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	return s;
}

// クライアントセッションの作成
SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, ACCOUNT *account)
{
	SESSION *s;
	THREAD *t;
	// 引数チェック
	if (cedar == NULL || option == NULL || auth == NULL || pa == NULL ||
		(auth->AuthType == CLIENT_AUTHTYPE_SECURE && auth->SecureSignProc == NULL))
	{
		return NULL;
	}

	// SESSION オブジェクトの初期化
	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();

	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = false;
	s->Name = CopyStr("CLIENT_SESSION");
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->PacketAdapter = pa;
	s->TrafficLock = NewLock();
	s->OldTraffic = NewTraffic();
	s->Cancel1 = NewCancel();
	s->CancelList = NewCancelList();

	// クライアント接続オプションのコピー
	s->ClientOption = Malloc(sizeof(CLIENT_OPTION));
	Copy(s->ClientOption, option, sizeof(CLIENT_OPTION));

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	// リトライ間隔の設定
	s->RetryInterval = MAKESURE(option->RetryInterval, 0, 4000000) * 1000;
	s->RetryInterval = MAKESURE(s->RetryInterval, MIN_RETRY_INTERVAL, MAX_RETRY_INTERVAL);

	// 追加コネクション作成間隔は最低 1 秒
	s->ClientOption->AdditionalConnectionInterval = MAX(s->ClientOption->AdditionalConnectionInterval, 1);

	// クライアントモードで仮想 LAN カードを使用しているかどうか保持
	s->ClientModeAndUseVLan = (StrLen(s->ClientOption->DeviceName) == 0) ? false : true;
	if (s->ClientOption->NoRoutingTracking)
	{
		s->ClientModeAndUseVLan = false;
	}

	if (StrLen(option->DeviceName) == 0)
	{
		// NAT モード
		s->ClientModeAndUseVLan = false;
		s->VirtualHost = true;
	}

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		// Win9x の場合は半二重モードを禁止する
		s->ClientOption->HalfConnection = false;
	}

	// クライアント認証データのコピー
	s->ClientAuth = Malloc(sizeof(CLIENT_AUTH));
	Copy(s->ClientAuth, auth, sizeof(CLIENT_AUTH));

	// 証明書と秘密鍵のクローン
	if (s->ClientAuth->ClientX != NULL)
	{
		s->ClientAuth->ClientX = CloneX(s->ClientAuth->ClientX);
	}
	if (s->ClientAuth->ClientK != NULL)
	{
		s->ClientAuth->ClientK = CloneK(s->ClientAuth->ClientK);
	}

	if (StrCmpi(s->ClientOption->DeviceName, LINK_DEVICE_NAME) == 0)
	{
		// リンククライアントモード
		s->LinkModeClient = true;
		s->Link = (LINK *)s->PacketAdapter->Param;
	}

	if (StrCmpi(s->ClientOption->DeviceName, SNAT_DEVICE_NAME) == 0)
	{
		// SecureNAT モード
		s->SecureNATMode = true;
	}

	if (StrCmpi(s->ClientOption->DeviceName, BRIDGE_DEVICE_NAME) == 0)
	{
		// Bridge モード
		s->BridgeMode = true;
	}

	if (s->VirtualHost)
	{
		VH *v = (VH *)s->PacketAdapter->Param;

		// セッションオブジェクトを VH に追加
		v->Session = s;
		AddRef(s->ref);
	}

	s->Account = account;

	if (s->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE)
	{
		// スマートカード認証の場合はリトライしない
		s->ClientOption->NumRetry = 0;
	}

	// クライアントスレッドの作成
	t = NewThread(ClientThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);

	return s;
}
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa)
{
	return NewClientSessionEx(cedar, option, auth, pa, NULL);
}

// 32bit のセッションキーからセッションを取得
SESSION *GetSessionFromKey32(CEDAR *cedar, UINT key32)
{
	HUB *h;
	UINT i, j;
	// 引数チェック
	if (cedar == NULL)
	{
		return NULL;
	}

	LockList(cedar->HubList);
	{
		for (i = 0;i < LIST_NUM(cedar->HubList);i++)
		{
			h = LIST_DATA(cedar->HubList, i);
			LockList(h->SessionList);
			{
				for (j = 0;j < LIST_NUM(h->SessionList);j++)
				{
					SESSION *s = LIST_DATA(h->SessionList, j);
					Lock(s->lock);
					{
						if (s->SessionKey32 == key32)
						{
							// セッション発見
							AddRef(s->ref);

							// ロック解除
							Unlock(s->lock);
							UnlockList(h->SessionList);
							UnlockList(cedar->HubList);
							return s;
						}
					}
					Unlock(s->lock);
				}
			}
			UnlockList(h->SessionList);
		}
	}
	UnlockList(cedar->HubList);

	return NULL;
}

// セッションキーからセッションを取得
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key)
{
	HUB *h;
	UINT i, j;
	// 引数チェック
	if (cedar == NULL || session_key == NULL)
	{
		return NULL;
	}

	LockList(cedar->HubList);
	{
		for (i = 0;i < LIST_NUM(cedar->HubList);i++)
		{
			h = LIST_DATA(cedar->HubList, i);
			LockList(h->SessionList);
			{
				for (j = 0;j < LIST_NUM(h->SessionList);j++)
				{
					SESSION *s = LIST_DATA(h->SessionList, j);
					Lock(s->lock);
					{
						if (Cmp(s->SessionKey, session_key, SHA1_SIZE) == 0)
						{
							// セッション発見
							AddRef(s->ref);

							// ロック解除
							Unlock(s->lock);
							UnlockList(h->SessionList);
							UnlockList(cedar->HubList);
							return s;
						}
					}
					Unlock(s->lock);
				}
			}
			UnlockList(h->SessionList);
		}
	}
	UnlockList(cedar->HubList);

	return NULL;
}

// 新しいセッションキーを作成
void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32)
{
	// 引数チェック
	if (cedar == NULL || session_key == NULL || session_key_32 == NULL)
	{
		return;
	}

	Rand(session_key, SHA1_SIZE);
	*session_key_32 = Rand32();
}

bool if_init(SESSION *s);
CANCEL *if_getcancel(SESSION *s);
UINT if_getnext(SESSION *s, void **data);
bool if_putpacket(SESSION *s, void *data, UINT size);
void if_free(SESSION *s);


// サーバーセッションの作成
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy)
{
	SESSION *s;
	char name[MAX_SIZE];
	char hub_name_upper[MAX_SIZE];
	char user_name_upper[MAX_USERNAME_LEN + 1];
	// 引数チェック
	if (cedar == NULL || c == NULL || h == NULL || username == NULL || policy == NULL)
	{
		return NULL;
	}

	// SESSION オブジェクトの初期化
	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();
	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = true;
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->Cancel1 = NewCancel();
	s->CancelList = NewCancelList();
	s->Thread = c->Thread;
	s->TrafficLock = NewLock();
	s->OldTraffic = NewTraffic();
	s->QoS = GetServerCapsBool(cedar->Server, "b_support_qos");
	AddRef(s->Thread->ref);
	s->Hub = h;
	s->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	// 遅延パケットリスト
	s->DelayedPacketList = NewList(NULL);

	// HUB 用のパケットアダプタ
	s->PacketAdapter = GetHubPacketAdapter();

	s->Connection = c;
	AddRef(c->ref);

	// 新しいセッション名の決定
	StrCpy(hub_name_upper, sizeof(hub_name_upper), h->Name);
	StrUpper(hub_name_upper);
	StrCpy(user_name_upper, sizeof(user_name_upper), username);
	StrUpper(user_name_upper);

	if ((StrCmpi(username, ADMINISTRATOR_USERNAME) != 0) && (StrCmpi(username, BRIDGE_USER_NAME) != 0) || (cedar->Server == NULL || cedar->Server->ServerType == SERVER_TYPE_STANDALONE))
	{
		Format(name, sizeof(name), "SID-%s-%u", user_name_upper, Inc(h->SessionCounter));
	}
	else
	{
		UCHAR rand[SHA1_SIZE];
		char tmp[MAX_SIZE];
		Rand(rand, sizeof(rand));
		BinToStr(tmp, sizeof(tmp), rand, 3);

		if (StrCmpi(username, BRIDGE_USER_NAME) != 0)
		{
			Format(name, sizeof(name), "SID-%s-%s", user_name_upper,
				tmp);
		}
		else
		{
			char pc_name[MAX_SIZE];
			TOKEN_LIST *t;

			GetMachineName(tmp, sizeof(tmp));
			t = ParseToken(tmp, ".");
			if (t->NumTokens >= 1)
			{
				StrCpy(pc_name, sizeof(pc_name), t->Token[0]);
			}
			else
			{
				StrCpy(pc_name, sizeof(pc_name), "pc");
			}
			FreeToken(t);

			StrUpper(pc_name);

			Format(name, sizeof(name), "SID-%s-%s-%u", user_name_upper, pc_name,
				Inc(h->SessionCounter));
		}
	}

	s->Name = CopyStr(name);
	s->Policy = policy;

	// HUB に SESSION を追加
	AddSession(h, s);

	// キーを作成
	NewSessionKey(cedar, s->SessionKey, &s->SessionKey32);

	return s;
}

// セッションキーをデバッグ用に表示
void DebugPrintSessionKey(UCHAR *session_key)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (session_key == NULL)
	{
		return;
	}

	Bit160ToStr(tmp, session_key);
	Debug("SessionKey: %s\n", tmp);
}

// クライアントにステータスを表示する
void PrintStatus(SESSION *s, wchar_t *str)
{
	// 引数チェック
	if (s == NULL || str == NULL || s->Account == NULL || s->Cedar->Client == NULL
		|| s->Account->StatusPrinter == NULL)
	{
		return;
	}

	// コールバック関数に対してステータスを通知する
	s->Account->StatusPrinter(s, str);
}

// キャンセルリストの作成
LIST *NewCancelList()
{
	return NewList(NULL);
}

// キャンセルリストにキャンセルを追加
void AddCancelList(LIST *o, CANCEL *c)
{
	UINT i;
	// 引数チェック
	if (o == NULL || c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *t = LIST_DATA(o, i);
		if (t == c)
		{
			return;
		}
	}

	AddRef(c->ref);
	Add(o, c);
}

// キャンセルリスト内の全キャンセルの発行
void CancelList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *c = LIST_DATA(o, i);
		Cancel(c);
		ReleaseCancel(c);
	}

	DeleteAll(o);
}

// キャンセルリストの解放
void ReleaseCancelList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *c = LIST_DATA(o, i);
		ReleaseCancel(c);
	}

	ReleaseList(o);
}

// クライアントに通知
void Notify(SESSION *s, UINT code)
{
	// 引数チェック
	if (s == NULL || s->Account == NULL || s->Cedar->Client == NULL)
	{
		return;
	}

	CiNotify(s->Cedar->Client);
}


