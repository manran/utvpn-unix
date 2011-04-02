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

// Connection.h
// Connection.c のヘッダ

#ifndef	CONNECTION_H
#define	CONNECTION_H

#define	KEEP_ALIVE_STRING				"Internet Connection Keep Alive Packet"

// KEEP CONNECT 構造体
struct KEEP
{
	LOCK *lock;										// ロック
	bool Server;									// サーバーモード
	volatile bool Halt;								// 停止フラグ
	bool Enable;									// 有効フラグ
	char ServerName[MAX_HOST_NAME_LEN + 1];			// サーバー名
	UINT ServerPort;								// サーバーポート番号
	bool UdpMode;									// UDP モード
	UINT Interval;									// パケット送出間隔
	THREAD *Thread;									// 接続スレッド
	EVENT *HaltEvent;								// 停止イベント
	CANCEL *Cancel;									// キャンセル
};

// 構造体
struct SECURE_SIGN
{
	char SecurePublicCertName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// セキュアデバイス証明書名
	char SecurePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// セキュアデバイス秘密鍵名
	X *ClientCert;					// クライアント証明書
	UCHAR Random[SHA1_SIZE];		// 署名元乱数値
	UCHAR Signature[128];			// 署名済データ
	UINT UseSecureDeviceId;
	UINT BitmapId;					// ビットマップ ID
};

// 関数型宣言
typedef bool (CHECK_CERT_PROC)(SESSION *s, CONNECTION *c, X *server_x, bool *expired);
typedef bool (SECURE_SIGN_PROC)(SESSION *s, CONNECTION *c, SECURE_SIGN *sign);

// RC4 鍵ペア
struct RC4_KEY_PAIR
{
	UCHAR ServerToClientKey[16];
	UCHAR ClientToServerKey[16];
};

// クライアントオプション
struct CLIENT_OPTION
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// 接続設定名
	char Hostname[MAX_HOST_NAME_LEN + 1];			// ホスト名
	UINT Port;										// ポート番号
	UINT PortUDP;									// UDP ポート番号 (0…TCPのみ使用)
	UINT ProxyType;									// プロキシの種類
	char ProxyName[MAX_HOST_NAME_LEN + 1];			// プロキシサーバー名
	UINT ProxyPort;									// プロキシサーバーのポート番号
	char ProxyUsername[MAX_PROXY_USERNAME_LEN + 1];	// 最大ユーザー名長
	char ProxyPassword[MAX_PROXY_PASSWORD_LEN + 1];	// 最大パスワード長
	UINT NumRetry;									// 自動リトライ回数
	UINT RetryInterval;								// リトライ間隔
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT MaxConnection;								// 最大同時接続 TCP コネクション数
	bool UseEncrypt;								// 暗号化通信を使用
	bool UseCompress;								// データ圧縮を使用
	bool HalfConnection;							// TCP でハーフコネクションを利用する
	bool NoRoutingTracking;							// ルーティング追跡を無効にする
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];		// VLAN デバイス名
	UINT AdditionalConnectionInterval;				// 追加コネクション確立時の接続試行間隔
	UINT ConnectionDisconnectSpan;					// コネクション切断間隔
	bool HideStatusWindow;							// 状況ウインドウを非表示にする
	bool HideNicInfoWindow;							// NIC 状態ウインドウを非表示にする
	bool RequireMonitorMode;						// モニタポートモード
	bool RequireBridgeRoutingMode;					// ブリッジまたはルーティングモード
	bool DisableQoS;								// VoIP / QoS 機能を無効化する
	bool FromAdminPack;								// Administration Pack 用
	bool NoTls1;									// TLS 1.0 を使用しない
};

// クライアント認証データ
struct CLIENT_AUTH
{
	UINT AuthType;									// 認証の種類
	char Username[MAX_USERNAME_LEN + 1];			// ユーザー名
	UCHAR HashedPassword[SHA1_SIZE];				// ハッシュされたパスワード
	char PlainPassword[MAX_PASSWORD_LEN + 1];		// パスワード
	X *ClientX;										// クライアント証明書
	K *ClientK;										// クライアント秘密鍵
	char SecurePublicCertName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// セキュアデバイス証明書名
	char SecurePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// セキュアデバイス秘密鍵名
	CHECK_CERT_PROC *CheckCertProc;					// サーバー証明書確認用プロシージャ
	SECURE_SIGN_PROC *SecureSignProc;				// セキュリティ署名用プロシージャ
};

// TCP ソケットデータ構造体
struct TCPSOCK
{
	SOCK *Sock;						// ソケット
	FIFO *RecvFifo;					// 受信バッファ
	FIFO *SendFifo;					// 送信バッファ
	UINT Mode;						// 読み取りモード
	UINT WantSize;					// 要求しているデータサイズ
	UINT NextBlockNum;				// 次に読み取れるブロック数の合計
	UINT NextBlockSize;				// 次に読み取る予定のブロックサイズ
	UINT CurrentPacketNum;			// 現在のパケット番号
	UINT64 LastCommTime;			// 最後に通信を行った時刻
	UINT LateCount;					// 遅延回数
	UINT Direction;					// 方向
	UINT64 NextKeepAliveTime;		// 次に KeepAlive パケットを送信する時刻
	RC4_KEY_PAIR Rc4KeyPair;		// RC4 キーペア
	CRYPT *SendKey;					// 送信鍵
	CRYPT *RecvKey;					// 受信鍵
	UINT64 DisconnectTick;			// このコネクションを切断する予定の時刻
};

// TCP 通信データ構造体
struct TCP
{
	LIST *TcpSockList;				// TCP ソケットリスト
};

// UDP 通信データ構造体
struct UDP
{
	SOCK *s;						// UDP ソケット (送信用)
	IP ip;							// 送信先 IP アドレス
	UINT port;						// 送信先ポート番号
	UINT64 NextKeepAliveTime;		// 次に KeepAlive パケットを送信する時刻
	UINT64 Seq;						// パケットシーケンス番号
	UINT64 RecvSeq;
	QUEUE *BufferQueue;				// 送信予定バッファのキュー
};

// データブロック
struct BLOCK
{
	BOOL Compressed;				// 圧縮フラグ
	UINT Size;						// ブロックサイズ
	UINT SizeofData;				// データサイズ
	UCHAR *Buf;						// バッファ
	bool PriorityQoS;				// VoIP / QoS 機能用優先パケット
};

// コネクション構造体
struct CONNECTION
{
	LOCK *lock;						// ロック
	REF *ref;						// 参照カウンタ
	CEDAR *Cedar;					// Cedar
	struct SESSION *Session;		// セッション
	UINT Protocol;					// プロトコル
	SOCK *FirstSock;				// ネゴシエーション用のソケット
	TCP *Tcp;						// TCP 通信データ構造体
	UDP *Udp;						// UDP 通信データ構造体
	bool ServerMode;				// サーバーモード
	UINT Status;					// 状態
	char *Name;						// コネクション名
	THREAD *Thread;					// スレッド
	volatile bool Halt;				// 停止フラグ
	UCHAR Random[SHA1_SIZE];		// 認証用乱数
	UINT ServerVer;					// サーバーバージョン
	UINT ServerBuild;				// サーバービルド番号
	UINT ClientVer;					// クライアントバージョン
	UINT ClientBuild;				// クライアントビルド番号
	char ServerStr[MAX_SERVER_STR_LEN + 1];	// サーバー文字列
	char ClientStr[MAX_CLIENT_STR_LEN + 1];	// クライアント文字列
	UINT Err;						// エラー値
	bool ClientConnectError_NoSavePassword;	// 指定されたユーザー名に関してパスワードを保存しない
	QUEUE *ReceivedBlocks;			// 受信したブロック キュー
	QUEUE *SendBlocks;				// 送信する予定のブロック キュー
	QUEUE *SendBlocks2;				// 送信キュー (優先度高)
	COUNTER *CurrentNumConnection;	// 現在のコネクション数のカウンタ
	LIST *ConnectingThreads;		// 接続中のスレッドのリスト
	LIST *ConnectingSocks;			// 接続中のソケットのリスト
	bool flag1;						// フラグ 1
	UCHAR *RecvBuf;					// 受信バッファ
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	UINT ServerPort;				// ポート番号
	bool RestoreServerNameAndPort;	// サーバー名とポート番号を元に戻すフラグ
	bool UseTicket;					// チケット使用フラグ
	UCHAR Ticket[SHA1_SIZE];		// チケット
	UINT CurrentSendQueueSize;		// 送信キューの合計サイズ
	X *ServerX;						// サーバー証明書
	X *ClientX;						// クライアント証明書
	char *CipherName;				// 暗号化アルゴリズム名
	UINT64 ConnectedTick;			// 接続された時刻
	IP ClientIp;					// クライアント IP アドレス
	char ClientHostname[MAX_HOST_NAME_LEN + 1];	// クライアントホスト名
	UINT Type;						// 種類
	bool DontUseTls1;				// TLS 1.0 を使用しない
	void *hWndForUI;				// 親ウインドウ
};



// 関数プロトタイプ

CONNECTION *NewClientConnection(SESSION *s);
CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build);
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t);
void ReleaseConnection(CONNECTION *c);
void CleanupConnection(CONNECTION *c);
int CompareConnection(void *p1, void *p2);
void StopConnection(CONNECTION *c, bool no_wait);
void ConnectionAccept(CONNECTION *c);
void StartTunnelingMode(CONNECTION *c);
void EndTunnelingMode(CONNECTION *c);
void DisconnectTcpSockets(CONNECTION *c);
void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2);
void ConnectionSend(CONNECTION *c);
TCPSOCK *NewTcpSock(SOCK *s);
void FreeTcpSock(TCPSOCK *ts);
BLOCK *NewBlock(void *data, UINT size, int compress);
void FreeBlock(BLOCK *b);
void StopAllAdditionalConnectThread(CONNECTION *c);
UINT GenNextKeepAliveSpan(CONNECTION *c);
void SendKeepAlive(CONNECTION *c, TCPSOCK *ts);
void DisconnectUDPSockets(CONNECTION *c);
void PutUDPPacketData(CONNECTION *c, void *data, UINT size);
void SendDataWithUDP(SOCK *s, CONNECTION *c);
void InsertReveicedBlockToQueue(CONNECTION *c, BLOCK *block);
void InitTcpSockRc4Key(TCPSOCK *ts, bool server_mode);
UINT TcpSockRecv(SESSION *s, TCPSOCK *ts, void *data, UINT size);
UINT TcpSockSend(SESSION *s, TCPSOCK *ts, void *data, UINT size);
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a);
BUF *NewKeepPacket(bool server_mode);
void KeepThread(THREAD *thread, void *param);
KEEP *StartKeep();
void StopKeep(KEEP *k);
void InRpcSecureSign(SECURE_SIGN *t, PACK *p);
void OutRpcSecureSign(PACK *p, SECURE_SIGN *t);
void FreeRpcSecureSign(SECURE_SIGN *t);
void NormalizeEthMtu(BRIDGE *b, CONNECTION *c, UINT packet_size);



#endif	// CONNECTION_H

