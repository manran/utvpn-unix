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

// Connection.c
// コネクションマネージャ

#include "CedarPch.h"

// 送信に使用するかどうかの判別
#define	IS_SEND_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode == false)))

// 受信に使用するかどうかの判別
#define	IS_RECV_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode == false)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode)))

// SECURE_SIGN の変換
void InRpcSecureSign(SECURE_SIGN *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(SECURE_SIGN));
	PackGetStr(p, "SecurePublicCertName", t->SecurePublicCertName, sizeof(t->SecurePublicCertName));
	PackGetStr(p, "SecurePrivateKeyName", t->SecurePrivateKeyName, sizeof(t->SecurePrivateKeyName));
	t->ClientCert = PackGetX(p, "ClientCert");
	PackGetData2(p, "Random", t->Random, sizeof(t->Random));
	PackGetData2(p, "Signature", t->Signature, sizeof(t->Signature));
	t->UseSecureDeviceId = PackGetInt(p, "UseSecureDeviceId");
	t->BitmapId = PackGetInt(p, "BitmapId");
}
void OutRpcSecureSign(PACK *p, SECURE_SIGN *t)
{
	// 引数チェック
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "SecurePublicCertName", t->SecurePublicCertName);
	PackAddStr(p, "SecurePrivateKeyName", t->SecurePrivateKeyName);
	PackAddX(p, "ClientCert", t->ClientCert);
	PackAddData(p, "Random", t->Random, sizeof(t->Random));
	PackAddData(p, "Signature", t->Signature, sizeof(t->Signature));
	PackAddInt(p, "UseSecureDeviceId", t->UseSecureDeviceId);
	PackAddInt(p, "BitmapId", t->BitmapId);
}
void FreeRpcSecureSign(SECURE_SIGN *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FreeX(t->ClientCert);
}

// 次のパケットを生成する
BUF *NewKeepPacket(bool server_mode)
{
	BUF *b = NewBuf();
	char *string = KEEP_ALIVE_STRING;

	WriteBuf(b, string, StrLen(string));

	SeekBuf(b, 0, 0);

	return b;
}

// KEEP スレッド
void KeepThread(THREAD *thread, void *param)
{
	KEEP *k = (KEEP *)param;
	SOCK *s;
	char server_name[MAX_HOST_NAME_LEN + 1];
	UINT server_port;
	bool udp_mode;
	bool enabled;
	// 引数チェック
	if (thread == NULL || k == NULL)
	{
		return;
	}

WAIT_FOR_ENABLE:
	Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);

	// 有効になるまで待機する
	while (true)
	{
		enabled = false;
		Lock(k->lock);
		{
			if (k->Enable)
			{
				if (StrLen(k->ServerName) != 0 && k->ServerPort != 0 && k->Interval != 0)
				{
					StrCpy(server_name, sizeof(server_name), k->ServerName);
					server_port = k->ServerPort;
					udp_mode = k->UdpMode;
					enabled = true;
				}
			}
		}
		Unlock(k->lock);
		if (enabled)
		{
			break;
		}
		if (k->Halt)
		{
			return;
		}
		Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
	}

	if (udp_mode == false)
	{
		// TCP モード
		// 接続に成功するまで試行する
		while (true)
		{
			UINT64 connect_started_tick;
			bool changed = false;
			Lock(k->lock);
			{
				if (StrCmpi(k->ServerName, server_name) != 0 ||
					k->ServerPort != server_port || k->Enable == false ||
					k->UdpMode)
				{
					changed = true;
				}
			}
			Unlock(k->lock);
			if (changed)
			{
				// 設定が変更された
				goto WAIT_FOR_ENABLE;
			}

			if (k->Halt)
			{
				// 停止
				return;
			}

			// サーバーへ接続を試行
			connect_started_tick = Tick64();
			s = ConnectEx2(server_name, server_port, KEEP_TCP_TIMEOUT, (bool *)&k->Halt);
			if (s != NULL)
			{
				// 接続成功
				break;
			}

			// 接続失敗 設定が変更されるかタイムアウトするまで待機する
			while (true)
			{
				changed = false;
				if (k->Halt)
				{
					// 停止
					return;
				}
				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed)
				{
					// 設定が変更された
					goto WAIT_FOR_ENABLE;
				}

				if ((Tick64() - connect_started_tick) >= KEEP_RETRY_INTERVAL)
				{
					break;
				}

				Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
			}
		}

		// サーバーへの接続に成功した
		// 一定時間ごとにパケットデータを送受信する
		if (s != NULL)
		{
			UINT64 last_packet_sent_time = 0;
			while (true)
			{
				SOCKSET set;
				UINT ret;
				UCHAR buf[MAX_SIZE];
				bool changed;

				InitSockSet(&set);
				AddSockSet(&set, s);

				Select(&set, KEEP_POLLING_INTERVAL, k->Cancel, NULL);

				ret = Recv(s, buf, sizeof(buf), false);
				if (ret == 0)
				{
					// 切断された
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
				}

				if (s != NULL)
				{
					if ((Tick64() - last_packet_sent_time) >= (UINT64)k->Interval)
					{
						BUF *b;

						// 次のパケットを送出する
						last_packet_sent_time = Tick64();

						b = NewKeepPacket(k->Server);

						ret = Send(s, b->Buf, b->Size, false);
						FreeBuf(b);

						if (ret == 0)
						{
							// 切断された
							Disconnect(s);
							ReleaseSock(s);
							s = NULL;
						}
					}
				}

				changed = false;

				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed || s == NULL)
				{
					// 設定が変更された または 切断された
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
					goto WAIT_FOR_ENABLE;
				}
				else
				{
					if (k->Halt)
					{
						// 停止
						Disconnect(s);
						ReleaseSock(s);
						return;
					}
				}
			}
		}
	}
	else
	{
		IP dest_ip;
		// UDP モード
		// ソケット作成が成功するまで試行する
		while (true)
		{
			UINT64 connect_started_tick;
			bool changed = false;
			Lock(k->lock);
			{
				if (StrCmpi(k->ServerName, server_name) != 0 ||
					k->ServerPort != server_port || k->Enable == false ||
					k->UdpMode == false)
				{
					changed = true;
				}
			}
			Unlock(k->lock);
			if (changed)
			{
				// 設定が変更された
				goto WAIT_FOR_ENABLE;
			}

			if (k->Halt)
			{
				// 停止
				return;
			}

			// ソケット作成を試行
			connect_started_tick = Tick64();

			// まず名前解決を試行
			if (GetIP(&dest_ip, server_name))
			{
				// 名前解決に成功したら、次にソケットを作成
				s = NewUDP(0);
				if (s != NULL)
				{
					// 作成成功
					break;
				}
			}

			// 作成失敗 設定が変更されるかタイムアウトするまで待機する
			while (true)
			{
				changed = false;
				if (k->Halt)
				{
					// 停止
					return;
				}
				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed)
				{
					// 設定が変更された
					goto WAIT_FOR_ENABLE;
				}

				if ((Tick64() - connect_started_tick) >= KEEP_RETRY_INTERVAL)
				{
					break;
				}

				Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
			}
		}

		// 一定時間ごとにパケットデータを送信する
		if (s != NULL)
		{
			UINT64 last_packet_sent_time = 0;
			while (true)
			{
				SOCKSET set;
				UINT ret;
				UCHAR buf[MAX_SIZE];
				bool changed;
				IP src_ip;
				UINT src_port;

				InitSockSet(&set);
				AddSockSet(&set, s);

				Select(&set, KEEP_POLLING_INTERVAL, k->Cancel, NULL);

				// 受信
				ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));
				if (ret == 0 && s->IgnoreRecvErr == false)
				{
					// 切断された
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
				}

				if (s != NULL)
				{
					if ((Tick64() - last_packet_sent_time) >= (UINT64)k->Interval)
					{
						BUF *b;

						// 次のパケットを送出する
						last_packet_sent_time = Tick64();

						b = NewKeepPacket(k->Server);

						ret = SendTo(s, &dest_ip, server_port, b->Buf, b->Size);
						FreeBuf(b);

						if (ret == 0 && s->IgnoreSendErr == false)
						{
							// 切断された
							Disconnect(s);
							ReleaseSock(s);
							s = NULL;
						}
					}
				}

				changed = false;

				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode == false)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed || s == NULL)
				{
					// 設定が変更された または 切断された
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
					goto WAIT_FOR_ENABLE;
				}
				else
				{
					if (k->Halt)
					{
						// 停止
						Disconnect(s);
						ReleaseSock(s);
						return;
					}
				}
			}
		}
	}
}

// KEEP 停止
void StopKeep(KEEP *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	k->Halt = true;
	Set(k->HaltEvent);
	Cancel(k->Cancel);

	WaitThread(k->Thread, INFINITE);
	ReleaseThread(k->Thread);
	DeleteLock(k->lock);

	ReleaseCancel(k->Cancel);
	ReleaseEvent(k->HaltEvent);

	Free(k);
}

// KEEP 開始
KEEP *StartKeep()
{
	KEEP *k = ZeroMalloc(sizeof(KEEP));

	k->lock = NewLock();
	k->HaltEvent = NewEvent();
	k->Cancel = NewCancel();

	// スレッド開始
	k->Thread = NewThread(KeepThread, k);

	return k;
}

// クライアント認証データのコピー
CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a)
{
	CLIENT_AUTH *ret;
	// 引数チェック
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocEx(sizeof(CLIENT_AUTH), true);

	ret->AuthType = a->AuthType;
	StrCpy(ret->Username, sizeof(ret->Username), a->Username);

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		// 匿名認証
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		// パスワード認証
		Copy(ret->HashedPassword, a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		// 平文パスワード認証
		StrCpy(ret->PlainPassword, sizeof(ret->PlainPassword), a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		// 証明書認証
		ret->ClientX = CloneX(a->ClientX);
		ret->ClientK = CloneK(a->ClientK);
		break;

	case CLIENT_AUTHTYPE_SECURE:
		// セキュアデバイス認証
		StrCpy(ret->SecurePublicCertName, sizeof(ret->SecurePublicCertName), a->SecurePublicCertName);
		StrCpy(ret->SecurePrivateKeyName, sizeof(ret->SecurePrivateKeyName), a->SecurePrivateKeyName);
		break;
	}

	return ret;
}

// 送信 FIFO にデータを書き込む (自動暗号化)
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// 引数チェック
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	if (s->UseFastRC4)
	{
		Encrypt(ts->SendKey, data, data, size);
	}

	WriteFifo(ts->SendFifo, data, size);
}

// 受信 FIFO にデータを書き込む (自動解読)
void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// 引数チェック
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	if (s->UseFastRC4)
	{
		Encrypt(ts->RecvKey, data, data, size);
	}

	WriteFifo(ts->RecvFifo, data, size);
}

// TCP ソケット受信
UINT TcpSockRecv(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// 受信
	return Recv(ts->Sock, data, size, s->UseSSLDataEncryption);
}

// TCP ソケット送信
UINT TcpSockSend(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// 送信
	return Send(ts->Sock, data, size, s->UseSSLDataEncryption);
}

// データを UDP パケットとして送信する
void SendDataWithUDP(SOCK *s, CONNECTION *c)
{
	UCHAR *buf;
	BUF *b;
	UINT64 dummy_64 = 0;
	UCHAR dummy_buf[16];
	UINT64 now = Tick64();
	UINT ret;
	bool force_flag = false;
	bool packet_sent = false;
	// 引数チェック
	if (s == NULL || c == NULL)
	{
		return;
	}

	// 一時バッファをヒープから確保しておく
	if (c->RecvBuf == NULL)
	{
		c->RecvBuf = Malloc(RECV_BUF_SIZE);
	}
	buf = c->RecvBuf;

	if (c->Udp->NextKeepAliveTime == 0 || c->Udp->NextKeepAliveTime <= now)
	{
		force_flag = true;
	}

	// バッファの作成
	while ((c->SendBlocks->num_item > 0) || force_flag)
	{
		UINT *key32;
		UINT64 *seq;
		char *sign;

		force_flag = false;

		// 現在のキューからバッファを組み立てる
		b = NewBuf();

		// パケットヘッダ (16バイト) 分の領域を確保
		WriteBuf(b, dummy_buf, sizeof(dummy_buf));

		// 送信キューのパケットを詰め込む
		LockQueue(c->SendBlocks);
		{
			while (true)
			{
				BLOCK *block;

				if (b->Size > UDP_BUF_SIZE)
				{
					break;
				}
				block = GetNext(c->SendBlocks);
				if (block == NULL)
				{
					break;
				}

				if (block->Size != 0)
				{
					WriteBufInt(b, block->Size);
					WriteBuf(b, block->Buf, block->Size);

					c->Session->TotalSendSize += (UINT64)block->SizeofData;
					c->Session->TotalSendSizeReal += (UINT64)block->Size;
				}

				FreeBlock(block);
				break;
			}
		}
		UnlockQueue(c->SendBlocks);

		// セッションキーとシーケンス番号の書き込み
		sign = (char *)(((UCHAR *)b->Buf));
		key32 = (UINT *)(((UCHAR *)b->Buf + 4));
		seq = (UINT64 *)(((UCHAR *)b->Buf + 8));
		Copy(sign, SE_UDP_SIGN, 4);
		*key32 = Endian32(c->Session->SessionKey32);
		*seq = Endian64(c->Udp->Seq++); // シーケンス番号をインクリメントする

//		InsertQueue(c->Udp->BufferQueue, b);

		packet_sent = true;
/*	}

	// バッファの送信
	while (c->Udp->BufferQueue->num_item != 0)
	{
		FIFO *f = c->Udp->BufferQueue->fifo;
		BUF **pb = (BUF**)(((UCHAR *)f->p) + f->pos);
		BUF *b = *pb;

*/		ret = SendTo(s, &c->Udp->ip, c->Udp->port, b->Buf, b->Size);
		if (ret == SOCK_LATER)
		{
			// ブロッキング
			Debug(".");
//			break;
		}
		if (ret != b->Size)
		{
			if (s->IgnoreSendErr == false)
			{
				// エラー
				Debug("******* SendTo Error !!!\n");
			}
		}

		// メモリ解放
		FreeBuf(b);
//		GetNext(c->Udp->BufferQueue);
	}

	if (packet_sent)
	{
		// KeepAlive 時刻更新
		c->Udp->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
	}
}

// UDP パケットのデータをコネクションに書き込む
void PutUDPPacketData(CONNECTION *c, void *data, UINT size)
{
	BUF *b;
	char sign[4];
	// 引数チェック
	if (c == NULL || data == NULL)
	{
		return;
	}

	// プロトコルを調べる
	if (c->Protocol != CONNECTION_UDP)
	{
		// UDP プロトコルは利用されていない
		return;
	}

	// バッファ構成
	b = NewBuf();
	WriteBuf(b, data, size);

	SeekBuf(b, 0, 0);
	ReadBuf(b, sign, 4);

	// サイン確認
	if (Cmp(sign, SE_UDP_SIGN, 4) == 0)
	{
		UINT key32;

		// セッションキー番号
		key32 = ReadBufInt(b);

		if (c->Session->SessionKey32 == key32)
		{
			UINT64 seq;

			// シーケンス番号読み込み
			ReadBuf(b, &seq, sizeof(seq));
			seq = Endian64(seq);

			if ((UINT)(seq - c->Udp->RecvSeq - (UINT64)1))
			{
				//Debug("** UDP Seq Lost %u\n", (UINT)(seq - c->Udp->RecvSeq - (UINT64)1));
			}
			c->Udp->RecvSeq = seq;

			//Debug("SEQ: %I32u\n", seq);

			while (true)
			{
				UINT size;

				size = ReadBufInt(b);
				if (size == 0)
				{
					break;
				}
				else if (size <= MAX_PACKET_SIZE)
				{
					void *tmp;
					BLOCK *block;

					tmp = Malloc(size);
					if (ReadBuf(b, tmp, size) != size)
					{
						Free(tmp);
						break;
					}

					// ブロック構成
					block = NewBlock(tmp, size, 0);

					// ブロック挿入
					InsertReveicedBlockToQueue(c, block);
				}
			}

			// 最終通信時刻を更新
			c->Session->LastCommTime = Tick64();
		}
		else
		{
			Debug("Invalid SessionKey: 0x%X\n", key32);
		}
	}

	FreeBuf(b);
}

// 受信キューにブロックを追加する
void InsertReveicedBlockToQueue(CONNECTION *c, BLOCK *block)
{
	SESSION *s;
	// 引数チェック
	if (c == NULL || block == NULL)
	{
		return;
	}

	s = c->Session;
	
	if (c->Protocol == CONNECTION_TCP)
	{
		s->TotalRecvSizeReal += block->SizeofData;
		s->TotalRecvSize += block->Size;
	}

	LockQueue(c->ReceivedBlocks);
	{
		InsertQueue(c->ReceivedBlocks, block);
	}
	UnlockQueue(c->ReceivedBlocks);
}

// 次の Keep-Alive パケットまでの間隔を生成 (ネットワーク負荷減少のため乱数にする)
UINT GenNextKeepAliveSpan(CONNECTION *c)
{
	UINT a, b;
	// 引数チェック
	if (c == NULL)
	{
		return INFINITE;
	}

	a = c->Session->Timeout;
	b = rand() % (a / 2);
	b = MAX(b, a / 5);

	return b;
}

// Keep-Alive パケットを送信する
void SendKeepAlive(CONNECTION *c, TCPSOCK *ts)
{
	UINT size, i, num;
	UINT size_be;
	UCHAR *buf;
	// 引数チェック
	if (c == NULL || ts == NULL)
	{
		return;
	}

	size = rand() % MAX_KEEPALIVE_SIZE;
	num = KEEP_ALIVE_MAGIC;
	buf = MallocFast(size);

	for (i = 0;i < size;i++)
	{
		buf[i] = rand();
	}

	num = Endian32(num);
	size_be = Endian32(size);
	WriteSendFifo(c->Session, ts, &num, sizeof(UINT));
	WriteSendFifo(c->Session, ts, &size_be, sizeof(UINT));
	WriteSendFifo(c->Session, ts, buf, size);

	c->Session->TotalSendSize += sizeof(UINT) * 2 + size;
	c->Session->TotalSendSizeReal += sizeof(UINT) * 2 + size;

	Free(buf);
}

// ブロックの送信
void ConnectionSend(CONNECTION *c)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	UINT i, num;
	UINT64 now;
	UINT min_count;
	TCPSOCK **tcpsocks;
	UINT size;
	SESSION *s;
	bool use_qos;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	use_qos = s->QoS;

	now = Tick64();

	// プロトコル
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		TCP *tcp = c->Tcp;
		TCPSOCK *ts;
		TCPSOCK *ts_hp;
		UINT num_available;
		LockList(tcp->TcpSockList);
		{
			num = LIST_NUM(tcp->TcpSockList);
			tcpsocks = ToArrayEx(tcp->TcpSockList, true);
		}
		UnlockList(tcp->TcpSockList);

		// 送信に使用するソケットを選択する
		// 遅延回数が最も少ないソケットを選出
		min_count = INFINITE;
		ts = NULL;
		ts_hp = NULL;

		num_available = 0;

		for (i = 0;i < num;i++)
		{
			TCPSOCK *tcpsock = tcpsocks[i];
			if (tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
				IS_SEND_TCP_SOCK(tcpsock))
			{
				// KeepAlive の処理
				if (now >= tcpsock->NextKeepAliveTime || tcpsock->NextKeepAliveTime == 0)
				{
					// KeepAlive を打つ
					SendKeepAlive(c, tcpsock);
					tcpsock->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
				}

				// 送信に利用可能なソケット数を計測する
				num_available++;

				ts_hp = tcpsock;
			}
		}

		for (i = 0;i < num;i++)
		{
			TCPSOCK *tcpsock = tcpsocks[i];
			if (tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
				IS_SEND_TCP_SOCK(tcpsock))
			{
				// ソケットの選出
				bool b = false;

				if (use_qos == false)
				{
					b = true;
				}
				else if (num_available < 2)
				{
					b = true;
				}
				else if (tcpsock != ts_hp)
				{
					b = true;
				}

				if (b)
				{
					if (tcpsock->LateCount <= min_count)
					{
						min_count = tcpsock->LateCount;
						ts = tcpsock;
					}
				}
			}
		}

		if (use_qos == false)
		{
			ts_hp = ts;
		}

		if (ts == NULL || ts_hp == NULL)
		{
			// 現在 送信可能なソケットが存在しない
		}
		else
		{
			TCPSOCK *tss;
			UINT j;
			QUEUE *q;

			for (j = 0;j < 2;j++)
			{
				if (j == 0)
				{
					q = c->SendBlocks2;
					tss = ts_hp;
				}
				else
				{
					q = c->SendBlocks;
					tss = ts;
				}
				// 選択されたソケット ts に対して送信データを予約する
				LockQueue(c->SendBlocks);
				if (q->num_item != 0)
				{
					UINT num_data;
					BLOCK *b;

					if (tss->SendFifo->size >= MAX((MAX_SEND_SOCKET_QUEUE_SIZE / s->MaxConnection), MIN_SEND_SOCKET_QUEUE_SIZE))
					{
						// 送信ソケットキューのサイズが超過
						// 送信できない
						while (b = GetNext(q))
						{
							if (b != NULL)
							{
								c->CurrentSendQueueSize -= b->Size;
								FreeBlock(b);
							}
						}
					}
					else
					{
						bool update_keepalive_timer = false;
						// 個数データ
						num_data = Endian32(q->num_item);
						PROBE_DATA2("WriteSendFifo num", &num_data, sizeof(UINT));
						WriteSendFifo(s, tss, &num_data, sizeof(UINT));

						s->TotalSendSize += sizeof(UINT);
						s->TotalSendSizeReal += sizeof(UINT);

						while (b = GetNext(q))
						{
							// サイズデータ
							UINT size_data;
							size_data = Endian32(b->Size);
							PROBE_DATA2("WriteSendFifo size", &size_data, sizeof(UINT));
							WriteSendFifo(s, tss, &size_data, sizeof(UINT));

							c->CurrentSendQueueSize -= b->Size;

							s->TotalSendSize += sizeof(UINT);
							s->TotalSendSizeReal += sizeof(UINT);

							// データ本体
							PROBE_DATA2("WriteSendFifo data", b->Buf, b->Size);
							WriteSendFifo(s, tss, b->Buf, b->Size);

							s->TotalSendSize += b->SizeofData;
							s->TotalSendSizeReal += b->Size;

							update_keepalive_timer = true;

							// ブロック解放
							FreeBlock(b);
						}

						if (update_keepalive_timer)
						{
							// KeepAlive タイマを増加させる
							tss->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
						}
					}
				}
				UnlockQueue(c->SendBlocks);
			}
		}

		// 現在各ソケットに登録されている送信予約データを送信する
		for (i = 0;i < num;i++)
		{
			ts = tcpsocks[i];

SEND_START:
			if (ts->Sock->Connected == false)
			{
				s->LastTryAddConnectTime = Tick64();
				// 通信が切断された
				LockList(tcp->TcpSockList);
				{
					// ソケットリストからこのソケットを削除する
					Delete(tcp->TcpSockList, ts);
					// TCPSOCK の解放
					FreeTcpSock(ts);
					// 個数のデクリメント
					Dec(c->CurrentNumConnection);
					Debug("--- TCP Connection Decremented: %u (%s Line %u)\n", Count(c->CurrentNumConnection), __FILE__, __LINE__);
					Debug("LIST_NUM(tcp->TcpSockList): %u\n", LIST_NUM(tcp->TcpSockList));
				}
				UnlockList(tcp->TcpSockList);

				continue;
			}

			// Fifo サイズを取得
			if (ts->SendFifo->size != 0)
			{
				UCHAR *buf;
				UINT want_send_size;
				// 1 バイト以上送信予定データが存在する場合のみ送信する
				// バッファへのポインタを取得
				buf = (UCHAR *)ts->SendFifo->p + ts->SendFifo->pos;
				want_send_size = ts->SendFifo->size;

				PROBE_DATA2("TcpSockSend", buf, want_send_size);
				size = TcpSockSend(s, ts, buf, want_send_size);
				if (size == 0)
				{
					// 切断された
					continue;
				}
				else if (size == SOCK_LATER)
				{
					// パケットが詰まっている
					ts->LateCount++; // 遅延カウンタのインクリメント
					PROBE_STR("ts->LateCount++;");
				}
				else
				{
					// パケットが size だけ送信された
					// FIFO を進める
					ReadFifo(ts->SendFifo, NULL, size);
					if (size < want_send_size)
					{
						// 予定されたデータのすべてを送信することができなかった
#ifdef	USE_PROBE
						{
							char tmp[MAX_SIZE];

							snprintf(tmp, sizeof(tmp), "size < want_send_size: %u < %u",
								size, want_send_size);

							PROBE_STR(tmp);
						}
#endif	// USE_PROBE
					}
					else
					{
						// すべてのパケットの送信が完了した (キューが無くなった)
						// ので、遅延カウンタをリセットする
						ts->LateCount = 0;

						PROBE_STR("TcpSockSend All Completed");
					}
					// 最終通信日時を更新
					c->Session->LastCommTime = now;

					goto SEND_START;
				}
			}
		}

		Free(tcpsocks);
	}
	else if (c->Protocol == CONNECTION_UDP)
	{
		// UDP
		UDP *udp = c->Udp;
		SOCK *sock = NULL;

		Lock(c->lock);
		{
			sock = udp->s;
			if (sock != NULL)
			{
				AddRef(sock->ref);
			}
		}
		Unlock(c->lock);

		if (sock != NULL)
		{
			// UDP で送信する

			// KeepAlive 送信
			if ((udp->NextKeepAliveTime == 0 || udp->NextKeepAliveTime <= now) ||
				(c->SendBlocks->num_item != 0) || (udp->BufferQueue->num_item != 0))
			{
				// 現在のキューを UDP で送信
				SendDataWithUDP(sock, c);
			}
		}

		if (sock != NULL)
		{
			ReleaseSock(sock);
		}
	}
	else if (c->Protocol == CONNECTION_HUB_SECURE_NAT)
	{
		// SecureNAT セッション
		SNAT *snat = s->SecureNAT;
		VH *v = snat->Nat->Virtual;

		LockQueue(c->SendBlocks);
		{
			BLOCK *block;
			UINT num_packet = 0;

			while (block = GetNext(c->SendBlocks))
			{
				num_packet++;
				c->CurrentSendQueueSize -= block->Size;
				VirtualPutPacket(v, block->Buf, block->Size);
				Free(block);
			}

			if (num_packet != 0)
			{
				VirtualPutPacket(v, NULL, 0);
			}
		}
		UnlockQueue(c->SendBlocks);
	}
	else if (c->Protocol == CONNECTION_HUB_LAYER3)
	{
		// Layer-3 セッション
		L3IF *f = s->L3If;

		LockQueue(c->SendBlocks);
		{
			BLOCK *block;
			UINT num_packet = 0;

			while (block = GetNext(c->SendBlocks))
			{
				num_packet++;
				c->CurrentSendQueueSize -= block->Size;
				L3PutPacket(f, block->Buf, block->Size);
				Free(block);
			}

			if (num_packet != 0)
			{
				L3PutPacket(f, NULL, 0);
			}
		}
		UnlockQueue(c->SendBlocks);
	}
	else if (c->Protocol == CONNECTION_HUB_LINK_SERVER)
	{
		// HUB リンク
		LINK *k = (LINK *)s->Link;

		if (k != NULL)
		{
			LockQueue(c->SendBlocks);
			{
				UINT num_blocks = 0;
				LockQueue(k->SendPacketQueue);
				{
					BLOCK *block;

					// パケットキューをクライアントスレッドに転送する
					while (block = GetNext(c->SendBlocks))
					{
						num_blocks++;
						c->CurrentSendQueueSize -= block->Size;
						InsertQueue(k->SendPacketQueue, block);
					}
				}
				UnlockQueue(k->SendPacketQueue);

				if (num_blocks != 0)
				{
					// キャンセルの発行
					Cancel(k->ClientSession->Cancel1);
				}
			}
			UnlockQueue(c->SendBlocks);
		}
	}
	else if (c->Protocol == CONNECTION_HUB_BRIDGE)
	{
		// ローカルブリッジ
		BRIDGE *b = s->Bridge;

		if (b != NULL)
		{
			if (b->Active)
			{
				LockQueue(c->SendBlocks);
				{
					BLOCK *block;
					UINT num_packet = c->SendBlocks->num_item; // パケット数

					if (num_packet != 0)
					{
						// パケットデータ配列
						void **datas = MallocFast(sizeof(void *) * num_packet);
						UINT *sizes = MallocFast(sizeof(UINT *) * num_packet);
						UINT i;

						i = 0;
						while (block = GetNext(c->SendBlocks))
						{
							datas[i] = block->Buf;
							sizes[i] = block->Size;

							if (block->Size > 1514)
							{
								NormalizeEthMtu(b, c, block->Size);
							}

							c->CurrentSendQueueSize -= block->Size;
							Free(block);
							i++;
						}

						// パケットを書き込む
						EthPutPackets(b->Eth, num_packet, datas, sizes);

						Free(datas);
						Free(sizes);
					}
				}
				UnlockQueue(c->SendBlocks);
			}
		}
	}
}

// ブロックの受信
void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	UINT i, num;
	SOCKSET set;
	SESSION *s;
	TCPSOCK **tcpsocks;
	UCHAR *buf;
	UINT size;
	UINT64 now;
	UINT time;
	UINT num_delayed = 0;
	bool no_spinlock_for_delay = false;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	PROBE_STR("ConnectionReceive");

	s = c->Session;

	if (s->Hub != NULL)
	{
		no_spinlock_for_delay = s->Hub->Option->NoSpinLockForPacketDelay;
	}

	now = Tick64();

	if (c->RecvBuf == NULL)
	{
		c->RecvBuf = Malloc(RECV_BUF_SIZE);
	}
	buf = c->RecvBuf;

	// プロトコル
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		TCP *tcp = c->Tcp;

		// コネクション切断間隔が指定されている場合はコネクションの切断を行う
		if (s->ServerMode == false)
		{
			if (s->ClientOption->ConnectionDisconnectSpan != 0)
			{
				LockList(tcp->TcpSockList);
				{
					UINT i;
					for (i = 0;i < LIST_NUM(tcp->TcpSockList);i++)
					{
						TCPSOCK *ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->DisconnectTick != 0 &&
							ts->DisconnectTick <= now)
						{
							Debug("ts->DisconnectTick <= now\n");
							Disconnect(ts->Sock);
						}
					}
				}
				UnlockList(tcp->TcpSockList);
			}
		}

		if (s->HalfConnection && (s->ServerMode == false))
		{
			// 現在の TCP コネクションの方向を調べ、
			// 一方向しか無く かつコネクション数が限界の場合は
			// 1 つ切断する
			LockList(tcp->TcpSockList);
			{
				UINT i, num;
				UINT c2s, s2c;
				c2s = s2c = 0;
				num = LIST_NUM(tcp->TcpSockList);
				if (num >= s->MaxConnection)
				{
					TCPSOCK *ts;
					for (i = 0;i < num;i++)
					{
						ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->Direction == TCP_SERVER_TO_CLIENT)
						{
							s2c++;
						}
						else
						{
							c2s++;
						}
					}
					if (s2c == 0 || c2s == 0)
					{
						// 最後のソケットを切断する
						Disconnect(ts->Sock);
						Debug("Disconnect (s2c=%u, c2s=%u)\n", s2c, c2s);
					}
				}
			}
			UnlockList(tcp->TcpSockList);
		}

		// ソケットセットの初期化
		InitSockSet(&set);
		LockList(tcp->TcpSockList);
		{
			num = LIST_NUM(tcp->TcpSockList);
			tcpsocks = ToArrayEx(tcp->TcpSockList, true);
		}
		UnlockList(tcp->TcpSockList);

		for (i = 0;i < num;i++)
		{
			AddSockSet(&set, tcpsocks[i]->Sock);
		}

		// Select
		time = SELECT_TIME;
		if (s->VirtualHost)
		{
			time = MIN(time, SELECT_TIME_FOR_NAT);
		}
		time = MIN(time, GetNextDelayedPacketTickDiff(s));
		num_delayed = LIST_NUM(s->DelayedPacketList);

		PROBE_STR("ConnectionReceive: Select 0");

		if (s->Flag1 != set.NumSocket)
		{
			Select(&set, (num_delayed == 0 ? time : 1), c1, c2);
			s->Flag1 = set.NumSocket;
		}
		else
		{
			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(&set, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
				s->Flag1 = set.NumSocket;
			}
			else
			{
				YieldCpu();
			}
		}

		PROBE_STR("ConnectionReceive: Select 1");

		// TCP ソケットに到着しているデータをすべて読み込む
		for (i = 0;i < num;i++)
		{
			TCPSOCK *ts = tcpsocks[i];
			if (ts->WantSize == 0)
			{
				// 最初に必ず sizeof(UINT) だけ読み込む
				ts->WantSize = sizeof(UINT);
			}

RECV_START:
			// 受信
			size = TcpSockRecv(s, ts, buf, RECV_BUF_SIZE);
			if (size == 0)
			{
DISCONNECT_THIS_TCP:
				s->LastTryAddConnectTime = Tick64();
				// 通信が切断された
				LockList(tcp->TcpSockList);
				{
					// ソケットリストからこのソケットを削除する
					Delete(tcp->TcpSockList, ts);
					// TCPSOCK の解放
					FreeTcpSock(ts);
					// デクリメント
					Dec(c->CurrentNumConnection);
					Debug("--- TCP Connection Decremented: %u (%s Line %u)\n", Count(c->CurrentNumConnection), __FILE__, __LINE__);
					Debug("LIST_NUM(tcp->TcpSockList): %u\n", LIST_NUM(tcp->TcpSockList));
				}
				UnlockList(tcp->TcpSockList);

				continue;
			}
			else if (size == SOCK_LATER)
			{
				// 受信待ち状態: 何もしない
				if (IS_RECV_TCP_SOCK(ts))
				{
					if ((now > ts->LastCommTime) && ((now - ts->LastCommTime) >= ((UINT64)s->Timeout)))
					{
						// このコネクションはタイムアウトした
						Debug("Connection %u Timeouted.\n", i);
						goto DISCONNECT_THIS_TCP;
					}
				}
			}
			else
			{
				// 最終通信時刻を更新
				ts->LastCommTime = now;
				c->Session->LastCommTime = now;

				// データが受信できたので FIFO に書き込む
				PROBE_DATA2("WriteRecvFifo", buf, size);
				WriteRecvFifo(s, ts, buf, size);

				// 受信バッファがいっぱいになったら受信をやめる
				if (ts->RecvFifo->size < MAX_SEND_SOCKET_QUEUE_SIZE)
				{
					goto RECV_START;
				}
			}

			// FIFO に書き込まれたデータを処理する
			while (ts->RecvFifo->size >= ts->WantSize)
			{
				UCHAR *buf;
				void *data;
				BLOCK *block;
				UINT sz;
				// すでに十分な量のデータが格納されている
				// データのポインタを取得
				buf = (UCHAR *)ts->RecvFifo->p + ts->RecvFifo->pos;

				switch (ts->Mode)
				{
				case 0:
					// データブロック個数
					ts->WantSize = sizeof(UINT);
					Copy(&sz, buf, sizeof(UINT));
					PROBE_DATA2("ReadFifo 0", buf, sizeof(UINT));
					sz = Endian32(sz);
					ts->NextBlockNum = sz;
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->CurrentPacketNum = 0;
					if (ts->NextBlockNum != 0)
					{
						if (ts->NextBlockNum == KEEP_ALIVE_MAGIC)
						{
							ts->Mode = 3;
						}
						else
						{
							ts->Mode = 1;
						}
					}
					break;

				case 1:
					// データブロックサイズ
					Copy(&sz, buf, sizeof(UINT));
					sz = Endian32(sz);
					PROBE_DATA2("ReadFifo 1", buf, sizeof(UINT));
					if (sz > (MAX_PACKET_SIZE * 2))
					{
						// おかしなデータサイズを受信した
						// TCP/IP 通信エラー?
						Debug("%s %u sz > (MAX_PACKET_SIZE * 2)\n", __FILE__, __LINE__);
						Disconnect(ts->Sock);
					}
					ts->NextBlockSize = MIN(sz, MAX_PACKET_SIZE * 2);
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->WantSize = ts->NextBlockSize;
					if (ts->WantSize != 0)
					{
						ts->Mode = 2;
					}
					else
					{
						ts->Mode = 1;
						ts->WantSize = sizeof(UINT);
						ts->CurrentPacketNum++;
						if (ts->CurrentPacketNum >= ts->NextBlockNum)
						{
							ts->Mode = 0;
						}
					}
					break;

				case 2:
					// データブロック本体
					ts->WantSize = sizeof(UINT);
					ts->CurrentPacketNum++;
					data = MallocFast(ts->NextBlockSize);
					Copy(data, buf, ts->NextBlockSize);
					PROBE_DATA2("ReadFifo 2", buf, ts->NextBlockSize);
					ReadFifo(ts->RecvFifo, NULL, ts->NextBlockSize);
					block = NewBlock(data, ts->NextBlockSize, s->UseCompress ? -1 : 0);

					if (block->Size > MAX_PACKET_SIZE)
					{
						// パケットサイズ超過
						FreeBlock(block);
					}
					else
					{
						// データブロックをキューに追加
						InsertReveicedBlockToQueue(c, block);
					}

					if (ts->CurrentPacketNum >= ts->NextBlockNum)
					{
						// すべてのデータブロックの受信が完了
						ts->Mode = 0;
					}
					else
					{
						// 次のデータブロックサイズを受信
						ts->Mode = 1;
					}
					break;

				case 3:
					// Keep-Alive パケットサイズ
					ts->Mode = 4;
					Copy(&sz, buf, sizeof(UINT));
					PROBE_DATA2("ReadFifo 3", buf, sizeof(UINT));
					sz = Endian32(sz);
					if (sz > MAX_KEEPALIVE_SIZE)
					{
						// おかしなデータサイズを受信した
						// TCP/IP 通信エラー?
						Debug("%s %u sz > MAX_KEEPALIVE_SIZE\n", __FILE__, __LINE__);
						Disconnect(ts->Sock);
					}
					ts->NextBlockSize = MIN(sz, MAX_KEEPALIVE_SIZE);
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->WantSize = sz;
					break;

				case 4:
					// Keep-Alive パケット本体
					//Debug("KeepAlive Recved.\n");
					ts->Mode = 0;
					sz = ts->NextBlockSize;
					PROBE_DATA2("ReadFifo 4", NULL, 0);
					ReadFifo(ts->RecvFifo, NULL, sz);

					s->TotalRecvSize += sz;
					s->TotalRecvSizeReal += sz;

					ts->WantSize = sizeof(UINT);
					break;
				}
			}
		}

		Free(tcpsocks);
	}
	else if (c->Protocol == CONNECTION_UDP)
	{
		// UDP
		UDP *udp = c->Udp;
		SOCK *sock = NULL;

		if (s->ServerMode == false)
		{
			Lock(c->lock);
			{
				if (c->Udp->s != NULL)
				{
					sock = c->Udp->s;
					if (sock != NULL)
					{
						AddRef(sock->ref);
					}
				}
			}
			Unlock(c->lock);

			InitSockSet(&set);

			if (sock != NULL)
			{
				AddSockSet(&set, sock);
			}

			Select(&set, SELECT_TIME, c1, c2);

			if (sock != NULL)
			{
				IP ip;
				UINT port;
				UCHAR *buf;
				UINT size;

				while (true)
				{
					buf = c->RecvBuf;
					size = RecvFrom(sock, &ip, &port, buf, RECV_BUF_SIZE);
					if (size == 0 && sock->IgnoreRecvErr == false)
					{
						Debug("UDP Socket Disconnected.\n");
						Lock(c->lock);
						{
							ReleaseSock(udp->s);
							udp->s = NULL;
						}
						Unlock(c->lock);
						break;
					}
					else if (size == SOCK_LATER)
					{
						break;
					}
					else
					{
						if (size)
						{
							PutUDPPacketData(c, buf, size);
						}
					}
				}
			}

			if (sock != NULL)
			{
				Release(sock->ref);
			}
		}
		else
		{
			Select(NULL, SELECT_TIME, c1, c2);
		}
	}
	else if (c->Protocol == CONNECTION_HUB_SECURE_NAT)
	{
		SNAT *snat = c->Session->SecureNAT;
		VH *v = snat->Nat->Virtual;
		UINT size;
		void *data;
		UINT num;
		UINT select_wait_time = SELECT_TIME_FOR_NAT;

		if (snat->Nat != NULL && snat->Nat->Option.UseNat == false)
		{
			select_wait_time = SELECT_TIME;
		}
		else
		{
			if (snat->Nat != NULL)
			{
				LockList(v->NatTable);
				{
					if (LIST_NUM(v->NatTable) == 0 && LIST_NUM(v->ArpWaitTable) == 0)
					{
						select_wait_time = SELECT_TIME;
					}
				}
				UnlockList(v->NatTable);
			}
		}

		select_wait_time = MIN(select_wait_time, GetNextDelayedPacketTickDiff(s));
		num_delayed = LIST_NUM(s->DelayedPacketList);

		if (no_spinlock_for_delay || select_wait_time >= 50 || num_delayed == false)
		{
			Select(NULL, (num_delayed == 0 ? select_wait_time :
				(select_wait_time > 100 ? (select_wait_time - 100) : 1)), c1, c2);
		}
		else
		{
			YieldCpu();
		}

		num = 0;

		// 仮想マシンからパケットを受信する
		while (size = VirtualGetNextPacket(v, &data))
		{
			BLOCK *block;

			// パケットブロックを生成
			block = NewBlock(data, size, 0);
			if (block->Size > MAX_PACKET_SIZE)
			{
				// パケットサイズ超過
				FreeBlock(block);
			}
			else
			{
				// データブロックをキューに追加
				InsertReveicedBlockToQueue(c, block);
			}
			num++;
			if (num >= MAX_SEND_SOCKET_QUEUE_NUM)
			{
//				WHERE;
				break;
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_LINK_SERVER)
	{
		// HUB リンク
		// 単純に Cancel を待つだけ
		if (c->SendBlocks->num_item == 0)
		{
			UINT time = SELECT_TIME;

			time = MIN(time, GetNextDelayedPacketTickDiff(s));
			num_delayed = LIST_NUM(s->DelayedPacketList);

			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_LAYER3)
	{
		// Layer-3 スイッチ セッション
		L3IF *f = s->L3If;
		UINT size, num = 0;
		void *data;

		if (f->SendQueue->num_item == 0)
		{
			UINT time = SELECT_TIME_FOR_NAT;

			if (f->ArpWaitTable != NULL)
			{
				LockList(f->ArpWaitTable);
				{
					if (LIST_NUM(f->ArpWaitTable) == 0)
					{
						time = SELECT_TIME;
					}
				}
				UnlockList(f->ArpWaitTable);
			}

			time = MIN(time, GetNextDelayedPacketTickDiff(s));
			num_delayed = LIST_NUM(s->DelayedPacketList);

			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}
		}

		// 次のパケットを取得する
		while (size = L3GetNextPacket(f, &data))
		{
			BLOCK *block = NewBlock(data, size, 0);
			if (block->Size > MAX_PACKET_SIZE)
			{
				FreeBlock(block);
			}
			else
			{
				InsertReveicedBlockToQueue(c, block);
			}

			num++;
			if (num >= MAX_SEND_SOCKET_QUEUE_NUM)
			{
				break;
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_BRIDGE)
	{
		BRIDGE *b = c->Session->Bridge;

		// Bridge セッション
		if (b->Active)
		{
			void *data;
			UINT ret;
			UINT num = 0;
			bool check_device_num = false;
			UINT time = SELECT_TIME;

			time = MIN(time, GetNextDelayedPacketTickDiff(s));
			num_delayed = LIST_NUM(s->DelayedPacketList);

			// ブリッジ動作中
			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}

			if ((b->LastNumDeviceCheck + BRIDGE_NUM_DEVICE_CHECK_SPAN) <= Tick64())
			{
				check_device_num = true;
				b->LastNumDeviceCheck = Tick64();
			}

			// ブリッジから次のパケットを取得する
			while (true)
			{
				if (check_device_num && b->LastNumDevice != GetEthDeviceHash())
				{
					ret = INFINITE;
				}
				else
				{
					ret = EthGetPacket(b->Eth, &data);
				}

#ifdef	OS_WIN32
				if (b->Eth != NULL && b->Eth->LoopbackBlock)
				{
					// ブリッジにおける eth デバイスがループバックパケットを遮断
					// する能力がある場合は CheckMac ポリシーを無効にする
					if (c->Session != NULL && c->Session->Policy != NULL)
					{
						c->Session->Policy->CheckMac = false;
					}
				}
#endif	// OS_WIN32

				if (ret == INFINITE)
				{
					// エラー発生 ブリッジを停止させる
					CloseEth(b->Eth);
					b->Eth = NULL;
					b->Active = false;
					ReleaseCancel(s->Cancel2);
					s->Cancel2 = NULL;

					HLog(s->Hub, "LH_BRIDGE_2", s->Name, b->Name);
					Debug("Bridge Device Error.\n");

					break;
				}
				else if (ret == 0)
				{
					// これ以上パケットが無い
					break;
				}
				else
				{
					// パケットをキューに追加
					BLOCK *block = NewBlock(data, ret, 0);

					PROBE_DATA2("ConnectionReceive: NewBlock", data, ret);

					if (ret > 1514)
					{
						NormalizeEthMtu(b, c, ret);
					}

					if (block->Size > MAX_PACKET_SIZE)
					{
						// パケットサイズ超過
						FreeBlock(block);
					}
					else
					{
						InsertReveicedBlockToQueue(c, block);
					}
					num++;
					if (num >= MAX_SEND_SOCKET_QUEUE_NUM)
					{
//						WHERE;
						break;
					}
				}
			}
		}
		else
		{
			ETH *e;
			// 現在ブリッジは停止している
			Select(NULL, SELECT_TIME, c1, NULL);

			if (b->LastBridgeTry == 0 || (b->LastBridgeTry + BRIDGE_TRY_SPAN) <= Tick64())
			{
				b->LastBridgeTry = Tick64();

				// Ethernet デバイスを開こうとしてみる
				e = OpenEth(b->Name, b->Local, b->TapMode, b->TapMacAddress);
				if (e != NULL)
				{
					// 成功
					b->Eth = e;
					b->Active = true;
					b->LastNumDeviceCheck = Tick64();
					b->LastNumDevice = GetEthDeviceHash();

					Debug("Bridge Open Succeed.\n");

					HLog(c->Session->Hub, "LH_BRIDGE_1", c->Session->Name, b->Name);

					s->Cancel2 = EthGetCancel(b->Eth);
				}
			}
		}
	}
}

// Ethernet デバイスの MTU を正規化する
void NormalizeEthMtu(BRIDGE *b, CONNECTION *c, UINT packet_size)
{
	// 引数チェック
	if (packet_size == 0 || b == NULL || c == NULL)
	{
		return;
	}

	// 現在の MTU を超えるパケットの場合は MTU を引き上げる
	if (EthIsChangeMtuSupported(b->Eth))
	{
		UINT currentMtu = EthGetMtu(b->Eth);
		if (currentMtu != 0)
		{
			if (packet_size > currentMtu)
			{
				bool ok = EthSetMtu(b->Eth, packet_size);

				if (ok)
				{
					HLog(c->Session->Hub, "LH_SET_MTU", c->Session->Name,
						b->Name, currentMtu, packet_size, packet_size);
				}
				else
				{
					UINT64 now = Tick64();

					if (b->LastChangeMtuError == 0 ||
						now >= (b->LastChangeMtuError + 60000ULL))
					{
						HLog(c->Session->Hub, "LH_SET_MTU_ERROR", c->Session->Name,
							b->Name, currentMtu, packet_size, packet_size);

						b->LastChangeMtuError = now;
					}
				}
			}
		}
	}
}

// ブロックの解放
void FreeBlock(BLOCK *b)
{
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	Free(b->Buf);
	Free(b);
}

// 新しいブロック作成
BLOCK *NewBlock(void *data, UINT size, int compress)
{
	BLOCK *b;
	// 引数チェック
	if (data == NULL)
	{
		return NULL;
	}

	b = ZeroMallocFast(sizeof(BLOCK));

	if (compress == 0)
	{
		// 非圧縮
		b->Compressed = FALSE;
		b->Buf = data;
		b->Size = size;
		b->SizeofData = size;
	}
	else if (compress == 1)
	{
		UINT max_size;

		// 圧縮
		b->Compressed = TRUE;
		max_size = CalcCompress(size);
		b->Buf = MallocFast(max_size);
		b->Size = Compress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		// 古いデータブロックを破棄
		Free(data);
	}
	else
	{
		// 展開
		UINT max_size;

		max_size = MAX_PACKET_SIZE;
		b->Buf = MallocFast(max_size);
		b->Size = Uncompress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		// 古いデータを破棄
		Free(data);
	}

	return b;
}

// TCP ソケットの作成
TCPSOCK *NewTcpSock(SOCK *s)
{
	TCPSOCK *ts;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	ts = ZeroMalloc(sizeof(TCPSOCK));

	ts->Sock = s;
	AddRef(s->ref);

	ts->RecvFifo = NewFifo();
	ts->SendFifo = NewFifo();
	ts->LastCommTime = Tick64();

	// タイムアウト値の解消
	SetTimeout(s, TIMEOUT_INFINITE);

	return ts;
}

// TCP ソケット用暗号化鍵の設定
void InitTcpSockRc4Key(TCPSOCK *ts, bool server_mode)
{
	RC4_KEY_PAIR *pair;
	CRYPT *c1, *c2;
	// 引数チェック
	if (ts == NULL)
	{
		return;
	}

	pair = &ts->Rc4KeyPair;

	c1 = NewCrypt(pair->ClientToServerKey, sizeof(pair->ClientToServerKey));
	c2 = NewCrypt(pair->ServerToClientKey, sizeof(pair->ServerToClientKey));

	if (server_mode)
	{
		ts->RecvKey = c1;
		ts->SendKey = c2;
	}
	else
	{
		ts->SendKey = c1;
		ts->RecvKey = c2;
	}
}

// TCP ソケットの解放
void FreeTcpSock(TCPSOCK *ts)
{
	// 引数チェック
	if (ts == NULL)
	{
		return;
	}

	Disconnect(ts->Sock);
	ReleaseSock(ts->Sock);
	ReleaseFifo(ts->RecvFifo);
	ReleaseFifo(ts->SendFifo);

	if (ts->SendKey)
	{
		FreeCrypt(ts->SendKey);
	}
	if (ts->RecvKey)
	{
		FreeCrypt(ts->RecvKey);
	}

	Free(ts);
}

// コネクションのトンネリングモードを終了する
void EndTunnelingMode(CONNECTION *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// プロトコル
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		DisconnectTcpSockets(c);
	}
	else
	{
		// UDP
		DisconnectUDPSockets(c);
	}
}

// コネクションをトンネリングモードに移行させる
void StartTunnelingMode(CONNECTION *c)
{
	SOCK *s;
	TCP *tcp;
	TCPSOCK *ts;
	IP ip;
	UINT port;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	tcp = c->Tcp;

	// プロトコル
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		s = c->FirstSock;

		ts = NewTcpSock(s);

		if (c->ServerMode == false)
		{
			if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
			{
				ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
			}
		}

		LockList(tcp->TcpSockList);
		{
			Add(tcp->TcpSockList, ts);
		}
		UnlockList(tcp->TcpSockList);
		ReleaseSock(s);
		c->FirstSock = NULL;
	}
	else
	{
		// UDP
		s = c->FirstSock;
		Copy(&ip, &s->RemoteIP, sizeof(IP));
		// この時点で TCP コネクションは切断してよい
		c->FirstSock = NULL;
		Disconnect(s);
		ReleaseSock(s);

		// UDP 構造体の初期化
		c->Udp = ZeroMalloc(sizeof(UDP));

		if (c->ServerMode)
		{
			// サーバーモード
			// エントリの追加
			AddUDPEntry(c->Cedar, c->Session);
			c->Udp->s = NULL;
		}
		else
		{
			port = c->Session->ClientOption->PortUDP;
			// クライアントモード
			c->Udp->s = NewUDP(0);
			// IP アドレスとポート番号を書く
			Copy(&c->Udp->ip, &ip, sizeof(IP));
			c->Udp->port = port;
		}

		// キュー
		c->Udp->BufferQueue = NewQueue();
	}
}

// 新しいコネクションを受け付ける関数
void ConnectionAccept(CONNECTION *c)
{
	SOCK *s;
	X *x;
	K *k;
	char tmp[128];
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	Debug("ConnectionAccept()\n");

	// ソケットを取得する
	s = c->FirstSock;
	AddRef(s->ref);

	Dec(c->Cedar->AcceptingSockets);

	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	SLog(c->Cedar, "LS_CONNECTION_START_1", tmp, s->RemoteHostname, s->RemotePort, c->Name);

	// タイムアウト設定
	SetTimeout(s, CONNECTING_TIMEOUT);

	// 暗号化アルゴリズムを指定する
	Lock(c->lock);
	{
		if (c->Cedar->CipherList != NULL)
		{
			SetWantToUseCipher(s, c->Cedar->CipherList);
		}

		x = CloneX(c->Cedar->ServerX);
		k = CloneK(c->Cedar->ServerK);
	}
	Unlock(c->lock);

	// SSL 通信を開始する
	Debug("StartSSL()\n");
	if (StartSSL(s, x, k) == false)
	{
		// 失敗
		Debug("Failed to StartSSL.\n");
		FreeX(x);
		FreeK(k);
		goto ERROR;
	}

	FreeX(x);
	FreeK(k);

	SLog(c->Cedar, "LS_SSL_START", c->Name, s->CipherName);

	// 接続を受諾する
	if (ServerAccept(c) == false)
	{
		// 失敗
		Debug("ServerAccept Failed. Err = %u\n", c->Err);
		goto ERROR;
	}

	if (c->flag1 == false)
	{
		Debug("%s %u c->flag1 == false\n", __FILE__, __LINE__);
		Disconnect(s);
	}
	DelConnection(c->Cedar, c);
	ReleaseSock(s);
	return;

ERROR:
	Debug("ConnectionAccept() Error.\n");
	Disconnect(s);
	DelConnection(c->Cedar, c);
	ReleaseSock(s);
}

// 現在動作しているすべての追加コネクションを張るスレッドを中断する
void StopAllAdditionalConnectThread(CONNECTION *c)
{
	UINT i, num;
	SOCK **socks;
	THREAD **threads;
	// 引数チェック
	if (c == NULL || c->ServerMode != false)
	{
		return;
	}

	// まずソケットを切断する
	LockList(c->ConnectingSocks);
	{
		num = LIST_NUM(c->ConnectingSocks);
		socks = ToArray(c->ConnectingSocks);
		DeleteAll(c->ConnectingSocks);
	}
	UnlockList(c->ConnectingSocks);
	for (i = 0;i < num;i++)
	{
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}
	Free(socks);

	// 次にスレッドの停止を待つ
	LockList(c->ConnectingThreads);
	{
		num = LIST_NUM(c->ConnectingThreads);
		Debug("c->ConnectingThreads: %u\n", num);
		threads = ToArray(c->ConnectingThreads);
		DeleteAll(c->ConnectingThreads);
	}
	UnlockList(c->ConnectingThreads);
	for (i = 0;i < num;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}
	Free(threads);
}

// コネクションの停止
void StopConnection(CONNECTION *c, bool no_wait)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	Debug("Stop Connection: %s\n", c->Name);

	// 停止フラグ
	c->Halt = true;
	Disconnect(c->FirstSock);

	if (no_wait == false)
	{
		// スレッド停止まで待機
		WaitThread(c->Thread, INFINITE);
	}
}

// UDP ソケットをすべて閉じる
void DisconnectUDPSockets(CONNECTION *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}
	if (c->Protocol != CONNECTION_UDP)
	{
		return;
	}

	// エントリの削除
	if (c->ServerMode)
	{
		DelUDPEntry(c->Cedar, c->Session);
	}

	// UDP 構造体の削除
	if (c->Udp != NULL)
	{
		if (c->Udp->s != NULL)
		{
			ReleaseSock(c->Udp->s);
		}
		if (c->Udp->BufferQueue != NULL)
		{
			// キューの解放
			BUF *b;
			while (b = GetNext(c->Udp->BufferQueue))
			{
				FreeBuf(b);
			}
			ReleaseQueue(c->Udp->BufferQueue);
		}
		Free(c->Udp);
		c->Udp = NULL;
	}

	if (c->FirstSock != NULL)
	{
		Disconnect(c->FirstSock);
		ReleaseSock(c->FirstSock);
		c->FirstSock = NULL;
	}
}

// TCP コネクションをすべて閉じる
void DisconnectTcpSockets(CONNECTION *c)
{
	UINT i, num;
	TCP *tcp;
	TCPSOCK **tcpsocks;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}
	if (c->Protocol != CONNECTION_TCP)
	{
		return;
	}

	tcp = c->Tcp;
	LockList(tcp->TcpSockList);
	{
		tcpsocks = ToArray(tcp->TcpSockList);
		num = LIST_NUM(tcp->TcpSockList);
		DeleteAll(tcp->TcpSockList);
	}
	UnlockList(tcp->TcpSockList);

	if (num != 0)
	{
		Debug("--- SOCKET STATUS ---\n");
		for (i = 0;i < num;i++)
		{
			TCPSOCK *ts = tcpsocks[i];
			Debug(" SOCK %2u: %u\n", i, ts->Sock->SendSize);
			FreeTcpSock(ts);
		}
	}

	Free(tcpsocks);
}

// コネクションのクリーンアップ
void CleanupConnection(CONNECTION *c)
{
	UINT i, num;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	DeleteLock(c->lock);
	ReleaseCedar(c->Cedar);

	switch (c->Protocol)
	{
	case CONNECTION_TCP:
		// TCP コネクションリストの解放
		DisconnectTcpSockets(c);
		break;

	case CONNECTION_UDP:
		break;
	}

	ReleaseList(c->Tcp->TcpSockList);
	Free(c->Tcp);

	ReleaseSock(c->FirstSock);
	c->FirstSock = NULL;

	ReleaseThread(c->Thread);
	Free(c->Name);

	// すべての送信ブロックと受信ブロックを解放
	if (c->SendBlocks)
	{
		LockQueue(c->SendBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks);
	}
	if (c->SendBlocks2)
	{
		LockQueue(c->SendBlocks2);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks2))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks2);
	}
	if (c->ReceivedBlocks)
	{
		LockQueue(c->ReceivedBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->ReceivedBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->ReceivedBlocks);
	}

	if (c->ConnectingThreads)
	{
		THREAD **threads;
		LockList(c->ConnectingThreads);
		{
			num = LIST_NUM(c->ConnectingThreads);
			threads = ToArray(c->ConnectingThreads);
			for (i = 0;i < num;i++)
			{
				ReleaseThread(threads[i]);
			}
			Free(threads);
		}
		UnlockList(c->ConnectingThreads);
		ReleaseList(c->ConnectingThreads);
	}

	if (c->ConnectingSocks)
	{
		SOCK **socks;
		LockList(c->ConnectingSocks);
		{
			num = LIST_NUM(c->ConnectingSocks);
			socks = ToArray(c->ConnectingSocks);
			for (i = 0;i < num;i++)
			{
				Disconnect(socks[i]);
				ReleaseSock(socks[i]);
			}
			Free(socks);
		}
		UnlockList(c->ConnectingSocks);
		ReleaseList(c->ConnectingSocks);
	}

	if (c->RecvBuf)
	{
		Free(c->RecvBuf);
	}

	if (c->ServerX != NULL)
	{
		FreeX(c->ServerX);
	}

	if (c->ClientX != NULL)
	{
		FreeX(c->ClientX);
	}

	ReleaseQueue(c->ReceivedBlocks);
	ReleaseQueue(c->SendBlocks);
	ReleaseQueue(c->SendBlocks2);

	DeleteCounter(c->CurrentNumConnection);

	if (c->CipherName != NULL)
	{
		Free(c->CipherName);
	}

	Free(c);
}

// コネクションの解放
void ReleaseConnection(CONNECTION *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupConnection(c);
	}
}

// コネクションの比較
int CompareConnection(void *p1, void *p2)
{
	CONNECTION *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CONNECTION **)p1;
	c2 = *(CONNECTION **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

// サーバーコネクションの作成
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t)
{
	CONNECTION *c;
	// 引数チェック
	if (cedar == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->Type = CONNECTION_TYPE_INIT;
	c->FirstSock = s;
	if (s != NULL)
	{
		AddRef(c->FirstSock->ref);
		Copy(&c->ClientIp, &s->RemoteIP, sizeof(IP));
		StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	}
	c->Tcp = ZeroMalloc(sizeof(TCP));
	c->Tcp->TcpSockList = NewList(NULL);
	c->ServerMode = true;
	c->Status = CONNECTION_STATUS_ACCEPTED;
	c->Name = CopyStr("INITING");
	c->Thread = t;
	AddRef(t->ref);
	c->CurrentNumConnection = NewCounter();
	Inc(c->CurrentNumConnection);

	c->ServerVer = cedar->Version;
	c->ServerBuild = cedar->Build;
	StrCpy(c->ServerStr, sizeof(c->ServerStr), cedar->ServerStr);
	GetServerProductName(cedar->Server, c->ServerStr, sizeof(c->ServerStr));

	if (s != NULL && s->RemoteX != NULL)
	{
		c->ServerX = CloneX(s->RemoteX);
	}

	// キューの作成
	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}

// クライアントコネクションの作成
CONNECTION *NewClientConnection(SESSION *s)
{
	return NewClientConnectionEx(s, NULL, 0, 0);
}
CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build)
{
	CONNECTION *c;

	// CONNECTION オブジェクトの初期化
	c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = s->Cedar;
	AddRef(c->Cedar->ref);
	if (s->ClientOption->PortUDP == 0)
	{
		// TCP
		c->Protocol = CONNECTION_TCP;
		c->Tcp = ZeroMalloc(sizeof(TCP));
		c->Tcp->TcpSockList = NewList(NULL);
	}
	else
	{
		// UDP
		c->Protocol = CONNECTION_UDP;
	}
	c->ServerMode = false;
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Name = CopyStr("CLIENT_CONNECTION");
	c->Session = s;
	c->CurrentNumConnection = NewCounter();
	Inc(c->CurrentNumConnection);

	c->ConnectingThreads = NewList(NULL);
	c->ConnectingSocks = NewList(NULL);

	if (client_str == NULL)
	{
		c->ClientVer = s->Cedar->Version;
		c->ClientBuild = s->Cedar->Build;

		if (c->Session->VirtualHost == false)
		{
			if (c->Session->LinkModeClient == false)
			{
				StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_CLIENT_STR);
			}
			else
			{
				StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_SERVER_LINK_STR);
			}
		}
		else
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_ROUTER_STR);
		}
	}
	else
	{
		c->ClientVer = client_ver;
		c->ClientBuild = client_build;
		StrCpy(c->ClientStr, sizeof(c->ClientStr), client_str);
	}

	// サーバー名とポート番号
	StrCpy(c->ServerName, sizeof(c->ServerName), s->ClientOption->Hostname);
	c->ServerPort = s->ClientOption->Port;

	// TLS 1.0 使用フラグ
	c->DontUseTls1 = s->ClientOption->NoTls1;

	// キューの作成
	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}


