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

// Server.h
// Server.c のヘッダ

#ifndef	SERVER_H
#define	SERVER_H

extern char *SERVER_CONFIG_FILE_NAME;
#define	SERVER_DEFAULT_CIPHER_NAME		"RC4-MD5"
#define	SERVER_DEFAULT_CERT_DAYS		(365 * 10)
#define	SERVER_DEFAULT_HUB_NAME			"DEFAULT"
#define	SERVER_DEFAULT_BRIDGE_NAME		"BRIDGE"
#define	SERVER_CONTROL_TCP_TIMEOUT		(60 * 1000)
#define	SERVER_FARM_CONTROL_INTERVAL	(10 * 1000)

#define	SERVER_FILE_SAVE_INTERVAL_DEFAULT	(5 * 60 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MIN		(5 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MAX		(3600 * 1000)

#define	SERVER_LICENSE_VIOLATION_SPAN	(SERVER_FARM_CONTROL_INTERVAL * 2)


#define SERVER_DEADLOCK_CHECK_SPAN		(2 * 60 * 1000)
#define SERVER_DEADLOCK_CHECK_TIMEOUT	(3 * 60 * 1000)


#define	RETRY_CONNECT_TO_CONTROLLER_INTERVAL	(1 * 1000)

#define	MAX_PUBLIC_PORT_NUM				128

// 各ファームメンバによってホストされている仮想 HUB リスト
struct HUB_LIST
{
	struct FARM_MEMBER *FarmMember;		// ファームメンバ
	bool DynamicHub;					// ダイナミック HUB
	char Name[MAX_HUBNAME_LEN + 1];		// HUB 名
	UINT NumSessions;					// セッション数
	UINT NumSessionsClient;				// クライアントセッション数
	UINT NumSessionsBridge;				// ブリッジセッション数
	UINT NumMacTables;					// MAC テーブル数
	UINT NumIpTables;					// IP テーブル数
};

// タスク
struct FARM_TASK
{
	EVENT *CompleteEvent;				// 完了通知
	PACK *Request;						// 要求
	PACK *Response;						// 応答
};

// ファームメンバ
struct FARM_MEMBER
{
	CEDAR *Cedar;						// Cedar
	UINT64 ConnectedTime;				// 接続日時
	UINT Me;							// 自分自身
	UINT Ip;							// IP アドレス
	UINT NumPort;						// ポート番号数
	UINT *Ports;						// ポート番号
	char hostname[MAX_HOST_NAME_LEN + 1];	// ホスト名
	X *ServerCert;						// サーバー証明書
	LIST *HubList;						// 仮想 HUB リスト
	QUEUE *TaskQueue;					// タスクキュー
	EVENT *TaskPostEvent;				// タスク投入イベント
	UINT Point;							// 点数
	volatile bool Halting;				// 停止中
	UINT NumSessions;					// セッション数
	UINT MaxSessions;					// 最大セッション数
	UINT NumTcpConnections;				// TCP コネクション数
	TRAFFIC Traffic;					// トラフィック情報
	UINT AssignedClientLicense;			// 割り当て済みクライアントライセンス数
	UINT AssignedBridgeLicense;			// 割り当て済みブリッジライセンス数
	UINT Weight;						// 性能基準比
	UCHAR RandomKey[SHA1_SIZE];			// 乱数キー (ライセンスチェック)
	UINT64 SystemId;					// システム ID (ライセンスチェック)
};

// ファームコントローラへの接続
struct FARM_CONTROLLER
{
	LOCK *lock;							// ロック
	struct SERVER *Server;				// サーバー
	THREAD *Thread;						// スレッド
	SOCK *Sock;							// ソケット
	SESSION *Session;					// セッション
	volatile bool Halt;					// 停止フラグ
	EVENT *HaltEvent;					// 停止イベント
	UINT LastError;						// 最終エラー
	bool Online;						// オンライン フラグ
	UINT64 StartedTime;					// 接続開始時刻
	UINT64 CurrentConnectedTime;		// 今回の接続時刻
	UINT64 FirstConnectedTime;			// 最初の接続時刻
	UINT NumConnected;					// 接続回数
	UINT NumTry;						// 試行回数
	UINT NumFailed;						// 接続失敗回数
};

// サーバーリスナー
struct SERVER_LISTENER
{
	UINT Port;							// ポート番号
	bool Enabled;						// 有効フラグ
	LISTENER *Listener;					// リスナーオブジェクト
};

// syslog 設定
struct SYSLOG_SETTING
{
	UINT SaveType;							// 保存種類
	char Hostname[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT Port;								// ポート番号
};

// サーバー オブジェクト
struct SERVER
{
	UINT ServerType;					// サーバーの種類
	UINT UpdatedServerType;				// 更新されたサーバーの種類
	LIST *ServerListenerList;			// サーバーリスナーリスト
	UCHAR HashedPassword[SHA1_SIZE];	// パスワード
	char ControllerName[MAX_HOST_NAME_LEN + 1];		// コントローラ名
	UINT ControllerPort;				// コントローラポート
	UINT Weight;						// 性能基準比
	bool ControllerOnly;				// コントローラ機能のみ
	UCHAR MemberPassword[SHA1_SIZE];	// ファームメンバ用パスワード
	UINT PublicIp;						// 公開 IP 
	UINT NumPublicPort;					// 公開ポート数
	UINT *PublicPorts;					// 公開ポート配列
	UINT64 StartTime;					// 起動時刻
	UINT AutoSaveConfigSpan;			// 自動保存間隔
	UINT ConfigRevision;				// 設定ファイルリビジョン
	UCHAR MyRandomKey[SHA1_SIZE];		// 自分のランダムキー
	bool FarmControllerInited;			// ファームコントローラの初期化が完了した
	bool DisableDeadLockCheck;			// デッドロックチェックを無効化する
	bool NoSendSignature;				// クライアントにシグネチャを送信させない
	bool SaveDebugLog;					// デバッグログを保存する
	bool NoLinuxArpFilter;				// Linux における arp_filter を設定しない
	bool NoHighPriorityProcess;			// プロセスの優先順位を上げない
	bool NoDebugDump;					// デバッグダンプを出力しない

	volatile bool Halt;					// 停止フラグ
	LOCK *lock;							// ロック
	REF *ref;							// 参照カウンタ
	CEDAR *Cedar;						// Cedar
	CFG_RW *CfgRw;						// 設定ファイル R/W
	LOCK *SaveCfgLock;					// 設定保存ロック
	EVENT *SaveHaltEvent;				// 保存スレッド停止イベント
	THREAD *SaveThread;					// 設定保存スレッド
	FARM_CONTROLLER *FarmController;	// ファームコントローラ
	LOCK *TasksFromFarmControllerLock;	// ファームコントローラからのタスクを処理中にかけるロック
	LIST *FarmMemberList;				// ファームメンバーリスト
	FARM_MEMBER *Me;					// 自分自身のファームメンバ登録
	THREAD *FarmControlThread;			// ファームコントロールスレッド
	EVENT *FarmControlThreadHaltEvent;	// ファームコントロールスレッド停止イベント
	LIST *HubCreateHistoryList;			// 仮想 HUB 作成履歴リスト

	KEEP *Keep;							// コネクション維持
	LOG *Logger;						// サーバー ロガー
	ERASER *Eraser;						// 自動ファイル削除器

	UINT CurrentTotalNumSessionsOnFarm;	// サーバー ファーム全体での合計のセッション数
	UINT CurrentAssignedClientLicense;	// 現在のクライアントライセンス割り当て数
	UINT CurrentAssignedBridgeLicense;	// 現在のブリッジライセンス割り当て数
	LICENSE_SYSTEM *LicenseSystem;		// ライセンスシステム

	LOCK *CapsCacheLock;				// Caps キャッシュ用ロック
	CAPSLIST *CapsListCache;			// Caps キャッシュ
	UINT LicenseHash;					// ライセンスリストのハッシュ値

	bool SnapshotInited;
	EVENT *SnapshotHaltEvent;			// スナップショット停止イベント
	volatile bool HaltSnapshot;			// スナップショット停止フラグ
	THREAD *SnapshotThread;				// スナップショットスレッド
	LOG *SnapshotLogger;				// スナップショットロガー
	UINT64 LastSnapshotTime;			// 最後にスナップショットを作成した時刻

	THREAD *DeadLockCheckThread;		// デッドロックチェックスレッド
	volatile bool HaltDeadLockThread;	// 停止フラグ
	EVENT *DeadLockWaitEvent;			// 待機イベント

	TINY_LOG *DebugLog;					// デバッグログ
};


// セッションの列挙*
struct RPC_ENUM_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT NumSession;								// セッション数
	struct RPC_ENUM_SESSION_ITEM *Sessions;			// セッションリスト
};

// セッション状態*
struct RPC_SESSION_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	char Name[MAX_SESSION_NAME_LEN + 1];			// セッション名
	char Username[MAX_USERNAME_LEN + 1];			// ユーザー名
	char RealUsername[MAX_USERNAME_LEN + 1];		// 本当のユーザー名
	char GroupName[MAX_USERNAME_LEN + 1];			// グループ名
	bool LinkMode;									// リンクモード
	RPC_CLIENT_GET_CONNECTION_STATUS Status;		// ステータス
	UINT ClientIp;									// クライアント IP アドレス
	UCHAR ClientIp6[16];							// クライアント IPv6 アドレス
	char ClientHostName[MAX_HOST_NAME_LEN + 1];		// クライアントホスト名
	NODE_INFO NodeInfo;								// ノード情報
};


// サーバーの種類
#define	SERVER_TYPE_STANDALONE			0		// スタンドアロン サーバー
#define	SERVER_TYPE_FARM_CONTROLLER		1		// ファームコントローラ サーバー
#define	SERVER_TYPE_FARM_MEMBER			2		// ファームメンバ サーバー


// Caps 関係
struct CAPS
{
	char *Name;							// 名前
	UINT Value;							// 値
};
struct CAPSLIST
{
	LIST *CapsList;						// Caps リスト
};

// ログファイル
struct LOG_FILE
{
	char Path[MAX_PATH];				// パス名
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	UINT FileSize;						// ファイルサイズ
	UINT64 UpdatedTime;					// 更新日時
};

// 仮想 HUB のスナップショット
struct HUB_SNAPSHOT
{
	char HubName[MAX_HUBNAME_LEN + 1];
	bool HubStatus;
	UINT HubMaxSessionsClient;
	UINT HubMaxSessionsBridge;
};

// Server のスナップショット
struct SERVER_SNAPSHOT
{
	UINT64 DateTime;
	IP ServerIp;
	char ServerHostname[MAX_HOST_NAME_LEN + 1];
	char ServerProduct[MAX_SIZE];
	char ServerVersion[MAX_SIZE];
	char ServerBuild[MAX_SIZE];
	char ServerOs[MAX_SIZE];
	UINT64 ServerLicenseId;
	UINT64 ServerLicenseExpires;
	UINT ServerType;
	UINT64 ServerStartupDatetime;
	UINT NumClusterNodes;
	LIST *HubList;
};

// 仮想 HUB 作成履歴
struct SERVER_HUB_CREATE_HISTORY
{
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT64 CreatedTime;
};

// 関数プロトタイプ宣言
SERVER *SiNewServer(bool bridge);
void SiReleaseServer(SERVER *s);
void SiCleanupServer(SERVER *s);
void StStartServer(bool bridge);
void StStopServer();
void SiInitConfiguration(SERVER *s);
void SiFreeConfiguration(SERVER *s);
UINT SiWriteConfigurationFile(SERVER *s);
void SiLoadInitialConfiguration(SERVER *s);
bool SiLoadConfigurationFile(SERVER *s);
bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root);
void SiInitDefaultServerCert(SERVER *s);
void SiInitCipherName(SERVER *s);
void SiGenerateDefualtCert(X **server_x, K **server_k);
void SiInitListenerList(SERVER *s);
void SiLockListenerList(SERVER *s);
void SiUnlockListenerList(SERVER *s);
bool SiAddListener(SERVER *s, UINT port, bool enabled);
bool SiEnableListener(SERVER *s, UINT port);
bool SiDisableListener(SERVER *s, UINT port);
bool SiDeleteListener(SERVER *s, UINT port);
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port);
int CompareServerListener(void *p1, void *p2);
void SiStopAllListener(SERVER *s);
void SiInitDefaultHubList(SERVER *s);
void SiInitBridge(SERVER *s);
void SiTest(SERVER *s);
FOLDER *SiWriteConfigurationToCfg(SERVER *s);
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root);
void SiWriteLocalBridges(FOLDER *f, SERVER *s);
void SiLoadLocalBridges(SERVER *s, FOLDER *f);
void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br);
void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f);
void SiWriteListeners(FOLDER *f, SERVER *s);
void SiLoadListeners(SERVER *s, FOLDER *f);
void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r);
void SiLoadListenerCfg(SERVER *s, FOLDER *f);
void SiWriteServerCfg(FOLDER *f, SERVER *s);
void SiLoadServerCfg(SERVER *s, FOLDER *f);
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiSaverThread(THREAD *thread, void *param);
void SiLoadLicenseManager(SERVER *s, FOLDER *f);
void SiWriteLicenseManager(FOLDER *f, SERVER *s);
void SiLoadL3Switchs(SERVER *s, FOLDER *f);
void SiLoadL3SwitchCfg(L3SW *sw, FOLDER *f);
void SiWriteL3Switchs(FOLDER *f, SERVER *s);
void SiWriteL3SwitchCfg(FOLDER *f, L3SW *sw);
void SiWriteHubs(FOLDER *f, SERVER *s);
void SiLoadHubs(SERVER *s, FOLDER *f);
void SiWriteHubCfg(FOLDER *f, HUB *h);
void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name);
void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f);
void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLogCfg(FOLDER *f, HUB_LOG *g);
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode);
void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLinks(FOLDER *f, HUB *h);
void SiLoadHubLinks(HUB *h, FOLDER *f);
void SiWriteHubAdminOptions(FOLDER *f, HUB *h);
void SiLoadHubAdminOptions(HUB *h, FOLDER *f);
void SiWriteHubLinkCfg(FOLDER *f, LINK *k);
void SiLoadHubLinkCfg(FOLDER *f, HUB *h);
void SiWriteHubAccessLists(FOLDER *f, HUB *h);
void SiLoadHubAccessLists(HUB *h, FOLDER *f);
void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a);
void SiLoadHubAccessCfg(HUB *h, FOLDER *f);
void SiWriteHubDb(FOLDER *f, HUBDB *db);
void SiLoadHubDb(HUB *h, FOLDER *f);
void SiWriteUserList(FOLDER *f, LIST *o);
void SiLoadUserList(HUB *h, FOLDER *f);
void SiWriteUserCfg(FOLDER *f, USER *u);
void SiLoadUserCfg(HUB *h, FOLDER *f);
void SiWriteGroupList(FOLDER *f, LIST *o);
void SiLoadGroupList(HUB *h, FOLDER *f);
void SiWriteGroupCfg(FOLDER *f, USERGROUP *g);
void SiLoadGroupCfg(HUB *h, FOLDER *f);
void SiWriteCertList(FOLDER *f, LIST *o);
void SiLoadCertList(LIST *o, FOLDER *f);
void SiWriteCrlList(FOLDER *f, LIST *o);
void SiLoadCrlList(LIST *o, FOLDER *f);
void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode);
void SiLoadPolicyCfg(POLICY *p, FOLDER *f);
void SiLoadSecureNAT(HUB *h, FOLDER *f);
void SiWriteSecureNAT(HUB *h, FOLDER *f);
void SiRebootServerEx(bool bridge, bool reset_setting);
void SiRebootServer(bool bridge);
void SiRebootServerThread(THREAD *thread, void *param);
void StInit();
void StFree();
SERVER *StGetServer();
void SiSetServerType(SERVER *s, UINT type,
					 UINT ip, UINT num_port, UINT *ports,
					 char *controller_name, UINT controller_port, UCHAR *password, UINT weight, bool controller_only);
FARM_CONTROLLER *SiStartConnectToController(SERVER *s);
void SiStopConnectToController(FARM_CONTROLLER *f);
void SiFarmServ(SERVER *server, SOCK *sock, X *cert, UINT ip, UINT num_port, UINT *ports, char *hostname, UINT point, UINT weight, UINT max_sessions);
int CompareHubList(void *p1, void *p2);
void SiFarmServMain(SERVER *server, SOCK *sock, FARM_MEMBER *f);
FARM_TASK *SiFarmServPostTask(FARM_MEMBER *f, PACK *request);
PACK *SiFarmServWaitTask(FARM_TASK *t);
PACK *SiExecTask(FARM_MEMBER *f, PACK *p);
PACK *SiCallTask(FARM_MEMBER *f, PACK *p, char *taskname);
void SiAcceptTasksFromController(FARM_CONTROLLER *f, SOCK *sock);
void SiAcceptTasksFromControllerMain(FARM_CONTROLLER *f, SOCK *sock);
PACK *SiCalledTask(FARM_CONTROLLER *f, PACK *p, char *taskname);
void SiHubOnlineProc(HUB *h);
void SiHubOfflineProc(HUB *h);
FARM_MEMBER *SiGetNextFarmMember(SERVER *s);
void SiCallCreateHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallUpdateHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallDeleteHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallEnumSession(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_SESSION *t);
void SiCallEnumNat(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_NAT *t);
void SiCallEnumDhcp(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_DHCP *t);
void SiCallGetNatStatus(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_NAT_STATUS *t);
void SiCallEnumMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_MAC_TABLE *t);
void SiCallEnumIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_IP_TABLE *t);
void SiCallDeleteSession(SERVER *s, FARM_MEMBER *f, char *hubname, char *session_name);
void SiCallCreateTicket(SERVER *s, FARM_MEMBER *f, char *hubname, char *username, char *realusername, POLICY *policy, UCHAR *ticket, UINT counter, char *groupname);
void SiCallDeleteMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key);
void SiCallDeleteIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key);
void SiCalledCreateHub(SERVER *s, PACK *p);
void SiCalledUpdateHub(SERVER *s, PACK *p);
void SiCalledDeleteHub(SERVER *s, PACK *p);
void SiCalledDeleteSession(SERVER *s, PACK *p);
void SiCalledDeleteMacTable(SERVER *s, PACK *p);
void SiCalledDeleteIpTable(SERVER *s, PACK *p);
PACK *SiCalledCreateTicket(SERVER *s, PACK *p);
PACK *SiCalledEnumSession(SERVER *s, PACK *p);
PACK *SiCalledEnumNat(SERVER *s, PACK *p);
PACK *SiCalledEnumDhcp(SERVER *s, PACK *p);
PACK *SiCalledGetNatStatus(SERVER *s, PACK *p);
PACK *SiCalledEnumMacTable(SERVER *s, PACK *p);
PACK *SiCalledEnumIpTable(SERVER *s, PACK *p);
void SiCalledEnumHub(SERVER *s, PACK *p, PACK *req);
void SiPackAddCreateHub(PACK *p, HUB *h);
FARM_MEMBER *SiGetHubHostingMember(SERVER *s, HUB *h, bool admin_mode);
void SiCallEnumHub(SERVER *s, FARM_MEMBER *f);
void SiStartFarmControl(SERVER *s);
void SiStopFarmControl(SERVER *s);
void SiFarmControlThread(THREAD *thread, void *param);
void SiAccessListToPack(PACK *p, LIST *o);
void SiAccessToPack(PACK *p, ACCESS *a, UINT i, UINT total);
ACCESS *SiPackToAccess(PACK *p, UINT i);
UINT SiNumAccessFromPack(PACK *p);
void SiHubUpdateProc(HUB *h);
bool SiCheckTicket(HUB *h, UCHAR *ticket, char *username, UINT username_size, char *usernamereal, UINT usernamereal_size, POLICY *policy, char *sessionname, UINT sessionname_size, char *groupname, UINT groupname_size);
UINT SiGetPoint(SERVER *s);
UINT SiCalcPoint(SERVER *s, UINT num, UINT weight);
bool SiCallGetSessionStatus(SERVER *s, FARM_MEMBER *f, RPC_SESSION_STATUS *t);
PACK *SiCalledGetSessionStatus(SERVER *s, PACK *p);
bool SiCallEnumLogFileList(SERVER *s, FARM_MEMBER *f, RPC_ENUM_LOG_FILE *t, char *hubname);
PACK *SiCalledEnumLogFileList(SERVER *s, PACK *p);
bool SiCallReadLogFile(SERVER *s, FARM_MEMBER *f, RPC_READ_LOG_FILE *t);
PACK *SiCalledReadLogFile(SERVER *s, PACK *p);
int CmpLogFile(void *p1, void *p2);
LIST *EnumLogFile(char *hubname);
void EnumLogFileDir(LIST *o, char *dirname);
void FreeEnumLogFile(LIST *o);
bool CheckLogFileNameFromEnumList(LIST *o, char *name, char *server_name);
void AdjoinEnumLogFile(LIST *o, LIST *src);
void IncrementServerConfigRevision(SERVER *s);
void GetServerProductName(SERVER *s, char *name, UINT size);
void GetServerProductNameInternal(SERVER *s, char *name, UINT size);
void SiGetServerLicenseStatus(SERVER *s, LICENSE_STATUS *st);
void SiInitDeadLockCheck(SERVER *s);
void SiFreeDeadLockCheck(SERVER *s);
void SiDeadLockCheckThread(THREAD *t, void *param);
void SiCheckDeadLockMain(SERVER *s, UINT timeout);
void SiDebugLog(SERVER *s, char *msg);
UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str);
UINT SiDebugProcHelloWorld(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

typedef UINT (SI_DEBUG_PROC)(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

CAPS *NewCaps(char *name, UINT value);
void FreeCaps(CAPS *c);
CAPSLIST *NewCapsList();
int CompareCaps(void *p1, void *p2);
void AddCaps(CAPSLIST *caps, CAPS *c);
CAPS *GetCaps(CAPSLIST *caps, char *name);
void FreeCapsList(CAPSLIST *caps);
bool GetCapsBool(CAPSLIST *caps, char *name);
UINT GetCapsInt(CAPSLIST *caps, char *name);
void AddCapsBool(CAPSLIST *caps, char *name, bool b);
void AddCapsInt(CAPSLIST *caps, char *name, UINT i);
void InRpcCapsList(CAPSLIST *t, PACK *p);
void OutRpcCapsList(PACK *p, CAPSLIST *t);
void FreeRpcCapsList(CAPSLIST *t);
void InitCapsList(CAPSLIST *t);
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p);
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t);

void GetServerCaps(SERVER *s, CAPSLIST *t);
bool GetServerCapsBool(SERVER *s, char *name);
UINT GetServerCapsInt(SERVER *s, char *name);
void GetServerCapsMain(SERVER *s, CAPSLIST *t);
void InitServerCapsCache(SERVER *s);
void FreeServerCapsCache(SERVER *s);
void DestroyServerCapsCache(SERVER *s);

bool MakeServerSnapshot(SERVER *s, UINT64 now, SERVER_SNAPSHOT *t);
void FreeSnapshot(SERVER_SNAPSHOT *t);
void InitServerSnapshot(SERVER *s);
void FreeServerSnapshot(SERVER *s);
void ServerSnapshotThread(THREAD *t, void *param);
void WriteServerSnapshotLog(SERVER *s, SERVER_SNAPSHOT *t);
BUF *ServerSnapshotToBuf(SERVER_SNAPSHOT *t);
bool IsAdminPackSupportedServerProduct(char *name);

void SiInitHubCreateHistory(SERVER *s);
void SiFreeHubCreateHistory(SERVER *s);
void SiDeleteOldHubCreateHistory(SERVER *s);
void SiAddHubCreateHistory(SERVER *s, char *name);
void SiDelHubCreateHistory(SERVER *s, char *name);
bool SiIsHubRegistedOnCreateHistory(SERVER *s, char *name);

UINT SiGetServerNumUserObjects(SERVER *s);
bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore);

#endif	// SERVER_H



