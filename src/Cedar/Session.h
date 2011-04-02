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

// Session.h
// Session.c のヘッダ

#ifndef	SESSION_H
#define	SESSION_H



// パケットアダプタ関数
typedef bool (PA_INIT)(SESSION *s);
typedef CANCEL *(PA_GETCANCEL)(SESSION *s);
typedef UINT (PA_GETNEXTPACKET)(SESSION *s, void **data);
typedef bool (PA_PUTPACKET)(SESSION *s, void *data, UINT size);
typedef void (PA_FREE)(SESSION *s);

// クライアント関係関数
typedef void (CLIENT_STATUS_PRINTER)(SESSION *s, wchar_t *status);

// ノード情報
struct NODE_INFO
{
	char ClientProductName[64];		// クライアント製品名
	UINT ClientProductVer;			// クライアントバージョン
	UINT ClientProductBuild;		// クライアントビルド番号
	char ServerProductName[64];		// サーバー製品名
	UINT ServerProductVer;			// サーバーバージョン
	UINT ServerProductBuild;		// サーバービルド番号
	char ClientOsName[64];			// クライアント OS 名
	char ClientOsVer[128];			// クライアント OS バージョン
	char ClientOsProductId[64];		// クライアント OS プロダクト ID
	char ClientHostname[64];		// クライアントホスト名
	UINT ClientIpAddress;			// クライアント IP アドレス
	UINT ClientPort;				// クライアントポート番号
	char ServerHostname[64];		// サーバーホスト名
	UINT ServerIpAddress;			// サーバー IP アドレス
	UINT ServerPort;				// サーバーポート番号
	char ProxyHostname[64];			// プロキシホスト名
	UINT ProxyIpAddress;			// プロキシ IP アドレス
	UINT ProxyPort;					// プロキシポート番号
	char HubName[64];				// HUB 名
	UCHAR UniqueId[16];				// ユニーク ID
	// 以下は IPv6 対応用
	UCHAR ClientIpAddress6[16];		// クライアント IPv6 アドレス
	UCHAR ServerIpAddress6[16];		// サーバー IP アドレス
	UCHAR ProxyIpAddress6[16];		// プロキシ IP アドレス
	char Padding[304 - (16 * 3)];	// パディング
};

// パケットアダプタ
struct PACKET_ADAPTER
{
	PA_INIT *Init;
	PA_GETCANCEL *GetCancel;
	PA_GETNEXTPACKET *GetNextPacket;
	PA_PUTPACKET *PutPacket;
	PA_FREE *Free;
	void *Param;
};

// セッション構造体
struct SESSION
{
	LOCK *lock;						// ロック
	REF *ref;						// 参照カウンタ
	CEDAR *Cedar;					// Cedar
	bool LocalHostSession;			// ローカルホストセッション
	bool ServerMode;				// サーバーモードセッション
	bool LinkModeClient;			// リンクモードクライアント
	bool LinkModeServer;			// リンクモードサーバー
	bool SecureNATMode;				// SecureNAT セッション
	bool BridgeMode;				// Bridge セッション
	bool VirtualHost;				// 仮想ホストモード
	bool L3SwitchMode;				// Layer-3 スイッチモード
	THREAD *Thread;					// 管理スレッド
	CONNECTION *Connection;			// コネクション
	CLIENT_OPTION *ClientOption;	// クライアント接続オプション
	CLIENT_AUTH *ClientAuth;		// クライアント認証データ
	volatile bool Halt;				// 停止フラグ
	volatile bool CancelConnect;	// 接続のキャンセル
	EVENT *HaltEvent;				// 停止イベント
	UINT Err;						// エラー値
	HUB *Hub;						// HUB
	CANCEL *Cancel1;				// キャンセルオブジェクト 1
	CANCEL *Cancel2;				// キャンセルオブジェクト 2
	PACKET_ADAPTER *PacketAdapter;	// パケットアダプタ
	UCHAR UdpSendKey[16];			// UDP 送信用暗号化鍵
	UCHAR UdpRecvKey[16];			// UDP 受信用暗号化鍵
	UINT ClientStatus;				// クライアントステータス
	bool RetryFlag;					// リトライフラグ (クライアント)
	bool ForceStopFlag;				// 強制停止フラグ (クライアント)
	UINT CurrentRetryCount;			// 現在のリトライカウンタ (クライアント)
	UINT RetryInterval;				// リトライ間隔 (クライアント)
	bool ConnectSucceed;			// 接続成功フラグ (クライアント)
	bool SessionTimeOuted;			// セッションがタイムアウトした
	UINT Timeout;					// タイムアウト時間
	UINT64 NextConnectionTime;		// 次に追加コネクションを張る時刻
	IP ServerIP;					// サーバーの IP アドレス
	bool ClientModeAndUseVLan;		// クライアントモードで仮想 LAN カードを使用
	bool UseSSLDataEncryption;		// SSL データ暗号化を使用する
	LOCK *TrafficLock;				// トラフィックデータロック
	LINK *Link;						// リンクオブジェクトへの参照
	SNAT *SecureNAT;				// SecureNAT オブジェクトへの参照
	BRIDGE *Bridge;					// Bridge オブジェクトへの参照
	NODE_INFO NodeInfo;				// ノード情報
	UINT64 LastIncrementTraffic;	// 最後にユーザーのトラフィックデータを更新した時刻
	bool AdministratorMode;			// 管理者モード
	LIST *CancelList;				// キャンセルリスト
	L3IF *L3If;						// Layer-3 インターフェイス
	IP DefaultDns;					// デフォルトの DNS サーバーの IP アドレス
	bool IPv6Session;				// IPv6 セッション (物理的な通信が IPv6 である)
	UINT VLanId;					// VLAN ID

	UINT64 CreatedTime;				// 作成日時
	UINT64 LastCommTime;			// 最終通信日時
	TRAFFIC *Traffic;				// トラフィックデータ
	TRAFFIC *OldTraffic;			// 古いトラフィックデータ
	UINT64 TotalSendSize;			// 合計送信データサイズ
	UINT64 TotalRecvSize;			// 合計受信データサイズ
	UINT64 TotalSendSizeReal;		// 合計送信データサイズ (無圧縮)
	UINT64 TotalRecvSizeReal;		// 合計受信データサイズ (無圧縮)
	char *Name;						// セッション名
	char *Username;					// ユーザー名
	char UserNameReal[MAX_USERNAME_LEN + 1];	// ユーザー名 (本物)
	char GroupName[MAX_USERNAME_LEN + 1];	// グループ名
	POLICY *Policy;					// ポリシー
	UCHAR SessionKey[SHA1_SIZE];	// セッションキー
	UINT SessionKey32;				// 32bit のセッションキー
	UINT MaxConnection;				// 最大同時接続 TCP コネクション数
	bool UseEncrypt;				// 暗号化通信を使用
	bool UseFastRC4;				// 高速 RC4 暗号化を使用
	bool UseCompress;				// データ圧縮を使用
	bool HalfConnection;			// ハーフコネクションモード
	bool QoS;						// VoIP / QoS
	bool NoSendSignature;			// シグネチャを送信しない
	UINT64 FirstConnectionEstablisiedTime;	// 最初のコネクションの接続完了時刻
	UINT64 CurrentConnectionEstablishTime;	// このコネクションの接続完了時刻
	UINT NumConnectionsEatablished;	// これまでに確立したコネクション数

	ACCOUNT *Account;				// クライアント アカウント
	UINT VLanDeviceErrorCount;		// 仮想 LAN カードでエラーが発生した回数
	bool Win32HideConnectWindow;	// 接続ウインドウを非表示にする
	bool Win32HideNicInfoWindow;	// NIC 情報ウインドウを非表示にする
	bool UserCanceled;				// ユーザーによってキャンセルされた
	UINT64 LastTryAddConnectTime;	// 最後にコネクションの追加を試行しようとした時刻

	bool IsMonitorMode;				// モニタモードか否か
	bool IsBridgeMode;				// ブリッジモードか否か
	bool UseClientLicense;			// 割り当てられたクライアントライセンス数
	bool UseBridgeLicense;			// 割り当てられたブリッジライセンス数

	COUNTER *LoggingRecordCount;	// ロギング中のレコード数のカウンタ

	bool Client_NoSavePassword;		// パスワードの保存を禁止
	wchar_t *Client_Message;		// サーバーから送信されてきたメッセージ

	LIST *DelayedPacketList;		// 遅延パケットリスト
	UINT Flag1;

	// D-Link バグ対策
	UINT64 LastDLinkSTPPacketSendTick;	// 最後の D-Link STP パケット送出時刻
	UCHAR LastDLinkSTPPacketDataHash[MD5_SIZE];	// 最後の D-Link STP パケットハッシュ
};

// パスワードダイアログ
struct UI_PASSWORD_DLG
{
	UINT Type;						// パスワードの種類
	char Username[MAX_USERNAME_LEN + 1];	// ユーザー名
	char Password[MAX_PASSWORD_LEN + 1];	// パスワード
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	UINT RetryIntervalSec;			// リトライまでの時間
	EVENT *CancelEvent;				// ダイアログ表示をキャンセルするイベント
	bool ProxyServer;				// プロキシサーバーに関する認証
	UINT64 StartTick;				// 開始時刻
	bool AdminMode;					// 管理モード
	bool ShowNoSavePassword;		// パスワードを保存しないチェックボックスを表示するかどうか
	bool NoSavePassword;			// パスワードを保存しないモード
	SOCK *Sock;						// ソケット
};

// メッセージダイアログ
struct UI_MSG_DLG
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	char HubName[MAX_HUBNAME_LEN + 1];	// 仮想 HUB 名
	wchar_t *Msg;					// 本文
	SOCK *Sock;						// ソケット
	bool Halt;						// 閉じるフラグ
};

// NIC 情報
struct UI_NICINFO
{
	wchar_t AccountName[MAX_SIZE];	// 接続設定名
	char NicName[MAX_SIZE];			// 仮想 NIC 名

	SOCK *Sock;						// ソケット
	bool Halt;						// 閉じるフラグ
	ROUTE_CHANGE *RouteChange;		// ルーティングテーブル変更通知
	UINT CurrentIcon;				// 現在のアイコン
	UINT64 CloseAfterTime;			// 自動で閉じる
};

// 接続エラーダイアログ
struct UI_CONNECTERROR_DLG
{
	EVENT *CancelEvent;				// ダイアログ表示をキャンセルするイベント
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	UINT Err;						// エラーコード
	UINT CurrentRetryCount;			// 現在のリトライ回数
	UINT RetryLimit;				// リトライ回数のリミット
	UINT64 StartTick;				// 開始時刻
	UINT RetryIntervalSec;			// リトライまでの時間
	bool HideWindow;				// ウインドウを非表示にする
	SOCK *Sock;						// ソケット
};

// サーバー証明書チェックダイアログ
struct UI_CHECKCERT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	X *x;							// サーバー証明書
	X *parent_x;					// 親証明書
	X *old_x;						// 前回の証明書
	bool DiffWarning;				// 証明書変造の警告を表示する
	bool Ok;						// 接続許可フラグ
	bool SaveServerCert;			// サーバー証明書を保存する
	SESSION *Session;				// セッション
	volatile bool Halt;				// 停止フラグ
	SOCK *Sock;						// ソケット
};


// 関数プロトタイプ
SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, struct ACCOUNT *account);
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa);
SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option);
SESSION *NewRpcSessionEx(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str);
SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd);
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy);
void ClientThread(THREAD *t, void *param);
void ReleaseSession(SESSION *s);
void CleanupSession(SESSION *s);
void StopSession(SESSION *s);
void StopSessionEx(SESSION *s, bool no_wait);
bool SessionConnect(SESSION *s);
bool ClientConnect(CONNECTION *c);
int CompareSession(void *p1, void *p2);
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
								 PA_PUTPACKET *put, PA_FREE *free);
void FreePacketAdapter(PACKET_ADAPTER *pa);
void SessionMain(SESSION *s);
void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32);
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key);
SESSION *GetSessionFromKey32(CEDAR *cedar, UINT key32);
void DebugPrintSessionKey(UCHAR *session_key);
void ClientAdditionalConnectChance(SESSION *s);
void SessionAdditionalConnect(SESSION *s);
void ClientAdditionalThread(THREAD *t, void *param);
void PrintSessionTotalDataSize(SESSION *s);
void AddTrafficForSession(SESSION *s, TRAFFIC *t);
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s);
void Notify(SESSION *s, UINT code);
void PrintStatus(SESSION *s, wchar_t *str);
LIST *NewCancelList();
void ReleaseCancelList(LIST *o);
void AddCancelList(LIST *o, CANCEL *c);
void CancelList(LIST *o);
bool CompareNodeInfo(NODE_INFO *a, NODE_INFO *b);
bool IsPriorityHighestPacketForQoS(void *data, UINT size);
UINT GetNextDelayedPacketTickDiff(SESSION *s);

#endif	// SESSION_H



