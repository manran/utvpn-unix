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

// Hub.h
// Hub.c のヘッダ

#ifndef	HUB_H
#define	HUB_H



// SoftEther リンク制御パケット
struct SE_LINK
{
	UCHAR DestMacAddress[6];			// 宛先 MAC アドレス
	UCHAR SrcMacAddress[6];				// 送信元 MAC アドレス
	UCHAR SignatureS;					// 'S'
	UCHAR SignatureE;					// 'E'
	UCHAR Padding[2];					// パディング
	UINT Type;							// 種類
	UCHAR HubSignature[16];				// HUB シグネチャ
	UINT TransactionId;					// トランザクション ID
	UINT Data;							// データ
	UCHAR Dummy[20];					// ダミー
	UCHAR Checksum[SHA1_SIZE];			// チェックサム
};


// テストパケット受信記録
struct TEST_HISTORY
{
	SESSION *s1;
	SESSION *s2;
};

// リンクテスト用状態マシン
struct SE_TEST
{
	LOCK *lock;							// ロック
	UINT64 LastTestPacketSentTime;		// 最後にテストパケットを送信した時刻
	UINT NextTestPacketSendInterval;	// 次のテストパケット送信間隔
	bool CurrentTesting;				// 現在テストパケットを送信してテスト中
	UINT TransactionId;					// トランザクション ID
	LIST *TestHistory;					// 受信履歴
};

// マクロ
#define	NO_ACCOUNT_DB(h)		((h)->FarmMember)

// スタンドアロンまたはファームマスタ HUB の場合のデータベース
struct HUBDB
{
	LIST *UserList;						// ユーザーリスト
	LIST *GroupList;					// グループリスト
	LIST *RootCertList;					// 信頼する証明書リスト
	LIST *CrlList;						// CRL リスト
};

// トラフィック リミッタ
struct TRAFFIC_LIMITER
{
	UINT64 LastTime;					// 最後に測定した時刻
	UINT64 Value;						// 現在の値
};

// エンドポイントごとのブロードキャスト数記録
struct STORM
{
	UCHAR MacAddress[6];				// MAC アドレス
	UCHAR Padding[2];					// パディング
	IP SrcIp;							// 送信元 IP アドレス
	IP DestIp;							// 宛先 IP アドレス
	UINT64 CheckStartTick;				// チェックを開始した時刻
	UINT CurrentBroadcastNum;			// 現在のブロードキャスト個数
	UINT DiscardValue;					// ブロードキャストパケットを破棄する割合
};

// HUB 用パケットアダプタ情報構造体
struct HUB_PA
{
	CANCEL *Cancel;						// キャンセルオブジェクト
	QUEUE *PacketQueue;					// パケットキュー
	bool MonitorPort;					// モニタポート
	UINT64 Now;							// 現在時刻
	TRAFFIC_LIMITER UploadLimiter;		// アップロード帯域幅制限
	TRAFFIC_LIMITER DownloadLimiter;	// ダウンロード帯域幅制限
	SESSION *Session;					// セッション
	LIST *StormList;					// ブロードキャスト嵐記録用リスト
	UINT UsernameHash;					// ユーザー名ハッシュ
	UINT GroupnameHash;					// グループ名ハッシュ
};

// HUB オプション
struct HUB_OPTION
{
	// 標準オプション
	UINT MaxSession;					// 最大同時接続数
	bool NoEnum;						// 列挙の対象外
	// 拡張オプション
	bool NoArpPolling;					// ARP ポーリングしない
	bool NoIPv6AddrPolling;				// IPv6 アドレスポーリングしない
	bool NoIpTable;						// IP アドレステーブルを生成しない
	bool NoMacAddressLog;				// MAC アドレスの登録ログを書き込まない
	bool ManageOnlyPrivateIP;			// プライベート IP のみを管理対象にする
	bool ManageOnlyLocalUnicastIPv6;	// ローカルユニキャスト IPv6 アドレスのみを管理対象にする
	bool DisableIPParsing;				// IP 解釈を禁止する
	bool YieldAfterStorePacket;			// パケットをストアした後イールドする
	bool NoSpinLockForPacketDelay;		// スピンロックを使用しない
	UINT BroadcastStormDetectionThreshold;	// ブロードキャスト数制限閾値
	bool FilterPPPoE;					// PPPoE をフィルタリングする (0x8863, 0x8864)
	bool FilterOSPF;					// OSPF をフィルタリングする (ip_proto=89)
	bool FilterIPv4;					// IPv4 パケットをフィルタリングする
	bool FilterIPv6;					// IPv6 パケットをフィルタリングする
	bool FilterNonIP;					// 非 IP パケットをすべてフィルタリング
	bool FilterBPDU;					// BPDU パケットをフィルタリングする
	UINT ClientMinimumRequiredBuild;	// クライアントのビルド番号が一定以下であれば拒否
	bool NoIPv6DefaultRouterInRAWhenIPv6;	// IPv6 ルータ広告からデフォルトルータ指定を削除 (IPv6 物理接続時のみ)
	bool NoIPv4PacketLog;				// IPv4 パケットのパケットログを保存しない
	bool NoIPv6PacketLog;				// IPv6 パケットのパケットログを保存しない
	bool NoLookBPDUBridgeId;			// スイッチングのために BPDU ブリッジ ID を見ない
	bool NoManageVlanId;				// VLAN ID を管理しない
	UINT VlanTypeId;					// VLAN パケットの Type ID (通常は 0x8100)
	bool FixForDLinkBPDU;				// D-Link の変な挙動をする BPDU のための fix を適用する
	UINT RequiredClientId;				// クライアント ID
};

// MAC テーブルエントリ
struct MAC_TABLE_ENTRY
{
	UCHAR MacAddress[6];				// MAC アドレス
	UCHAR Padding[2];
	UINT VlanId;						// VLAN ID
	SESSION *Session;					// セッション
	HUB_PA *HubPa;						// HUB パケットアダプタ
	UINT64 CreatedTime;					// 作成日時
	UINT64 UpdatedTime;					// 更新日時
};

// IP テーブルエントリ
struct IP_TABLE_ENTRY
{
	IP Ip;								// IP アドレス
	SESSION *Session;					// セッション
	bool DhcpAllocated;					// DHCP によって割り当て済み
	UINT64 CreatedTime;					// 作成日時
	UINT64 UpdatedTime;					// 更新日時
	UCHAR MacAddress[6];				// MAC アドレス
};

// ループリスト
struct LOOP_LIST
{
	UINT NumSessions;
	SESSION **Session;
};

// アクセスリスト
struct ACCESS
{
	// IPv4
	UINT Id;							// ID
	wchar_t Note[MAX_ACCESSLIST_NOTE_LEN + 1];	// メモ
	bool Active;						// 有効フラグ
	UINT Priority;						// 優先順位
	bool Discard;						// 破棄フラグ
	UINT SrcIpAddress;					// 送信元 IP アドレス
	UINT SrcSubnetMask;					// 送信元サブネットマスク
	UINT DestIpAddress;					// 宛先 IP アドレス
	UINT DestSubnetMask;				// 宛先サブネットマスク
	UINT Protocol;						// プロトコル
	UINT SrcPortStart;					// 送信元ポート番号開始点
	UINT SrcPortEnd;					// 送信元ポート番号終了点
	UINT DestPortStart;					// 宛先ポート番号開始点
	UINT DestPortEnd;					// 宛先ポート番号終了点
	UINT SrcUsernameHash;				// 送信元ユーザー名ハッシュ
	char SrcUsername[MAX_USERNAME_LEN + 1];
	UINT DestUsernameHash;				// 宛先ユーザー名ハッシュ
	char DestUsername[MAX_USERNAME_LEN + 1];
	bool CheckSrcMac;					// 送信元 MAC アドレスの設定の有無
	UCHAR SrcMacAddress[6];				// 送信元 MAC アドレス
	UCHAR SrcMacMask[6];				// 送信元 MAC アドレスマスク
	bool CheckDstMac;					// 宛先 MAC アドレスの設定の有無
	UCHAR DstMacAddress[6];				// 宛先 MAC アドレス
	UCHAR DstMacMask[6];				// 宛先 MAC アドレスマスク
	bool CheckTcpState;					// TCP コネクションの状態
	bool Established;					// Establieshed(TCP)
	UINT Delay;							// 遅延
	UINT Jitter;						// ジッタ
	UINT Loss;							// パケットロス

	// IPv6
	bool IsIPv6;						// IPv6 かどうか
	IPV6_ADDR SrcIpAddress6;			// 送信元 IP アドレス (IPv6)
	IPV6_ADDR SrcSubnetMask6;			// 送信元サブネットマスク (IPv6)
	IPV6_ADDR DestIpAddress6;			// 宛先 IP アドレス (IPv6)
	IPV6_ADDR DestSubnetMask6;			// 宛先サブネットマスク (IPv6)
};

// チケット
struct TICKET
{
	UINT64 CreatedTick;						// 作成日時
	UCHAR Ticket[SHA1_SIZE];				// チケット
	char Username[MAX_USERNAME_LEN + 1];	// ユーザー名
	char UsernameReal[MAX_USERNAME_LEN + 1];	// 本当のユーザー名
	char GroupName[MAX_USERNAME_LEN + 1];	// グループ名
	char SessionName[MAX_SESSION_NAME_LEN + 1];	// セッション名
	POLICY Policy;							// ポリシー
};

// トラフィック差分
struct TRAFFIC_DIFF
{
	UINT Type;							// 種別
	TRAFFIC Traffic;					// トラフィック
	char *HubName;						// HUB 名
	char *Name;							// 名前
};

// 管理オプション
struct ADMIN_OPTION
{
	char Name[MAX_ADMIN_OPTION_NAME_LEN + 1];	// 名前
	UINT Value;									// データ
};

// 証明書無効エントリ
struct CRL
{
	X_SERIAL *Serial;					// シリアル番号
	NAME *Name;							// 名前情報
	UCHAR DigestMD5[MD5_SIZE];			// MD5 ハッシュ
	UCHAR DigestSHA1[SHA1_SIZE];		// SHA-1 ハッシュ
};

// アクセスコントロール
struct AC
{
	UINT Id;							// ID
	UINT Priority;						// 優先順位
	bool Deny;							// アクセスを拒否
	bool Masked;						// マスクされているかどうか
	IP IpAddress;						// IP アドレス
	IP SubnetMask;						// サブネットマスク
};

// HUB 構造体
struct HUB
{
	LOCK *lock;							// ロック
	LOCK *lock_online;					// オンライン用ロック
	REF *ref;							// 参照カウンタ
	CEDAR *Cedar;						// Cedar
	UINT Type;							// 種類
	HUBDB *HubDb;						// データベース
	char *Name;							// HUB の名前
	LOCK *RadiusOptionLock;				// Radius オプション用ロック
	char *RadiusServerName;				// Radius サーバー名
	UINT RadiusServerPort;				// Radius サーバーポート番号
	UINT RadiusRetryInterval;			// Radius 再試行間隔
	BUF *RadiusSecret;					// Radius 共有鍵
	volatile bool Halt;					// 停止フラグ
	bool Offline;						// オフライン
	bool BeingOffline;					// オフライン化中
	LIST *SessionList;					// セッションリスト
	COUNTER *SessionCounter;			// セッション番号生成カウンタ
	TRAFFIC *Traffic;					// トラフィック情報
	TRAFFIC *OldTraffic;				// 古いトラフィック情報
	LOCK *TrafficLock;					// トラフィックロック
	COUNTER *NumSessions;				// 現在のセッション数
	COUNTER *NumSessionsClient;			// 現在のセッション数 (クライアント)
	COUNTER *NumSessionsBridge;			// 現在のセッション数 (ブリッジ)
	HUB_OPTION *Option;					// HUB オプション
	LIST *MacTable;						// MAC アドレステーブル
	LIST *IpTable;						// IP アドレステーブル
	LIST *MonitorList;					// モニタポートセッションリスト
	LIST *LinkList;						// リンクリスト
	UCHAR HubSignature[16];				// HUB シグネチャ
	UCHAR HubMacAddr[6];				// HUB の MAC アドレス
	IP HubIp;							// HUB の IP アドレス (IPv4)
	IPV6_ADDR HubIpV6;					// HUB の IP アドレス (IPv6)
	UINT HubIP6Id;						// HUB の IPv6 パケット ID
	UCHAR Padding[2];					// パディング
	LOCK *LoopListLock;					// ループリスト用ロック
	UINT NumLoopList;					// ループリスト数
	LOOP_LIST **LoopLists;				// ループリスト
	LIST *AccessList;					// アクセスリスト
	HUB_LOG LogSetting;					// ログ設定
	LOG *PacketLogger;					// パケットロガー
	LOG *SecurityLogger;				// セキュリティロガー
	UCHAR HashedPassword[SHA1_SIZE];	// パスワード
	UCHAR SecurePassword[SHA1_SIZE];	// セキュアパスワード
	LIST *TicketList;					// チケットリスト
	bool FarmMember;					// ファームメンバー
	UINT64 LastIncrementTraffic;		// トラフィック報告時刻
	UINT64 LastSendArpTick;				// 最後の ARP 送信時刻
	SNAT *SecureNAT;					// SecureNAT
	bool EnableSecureNAT;				// SecureNAT 有効/無効フラグ
	VH_OPTION *SecureNATOption;			// SecureNAT のオプション
	THREAD *WatchDogThread;				// 番犬スレッド
	EVENT *WatchDogEvent;				// 番犬イベント
	bool WatchDogStarted;				// 番犬スレッドが使用されているかどうか
	volatile bool HaltWatchDog;			// 番犬スレッドの停止
	LIST *AdminOptionList;				// 管理オプションリスト
	UINT64 CreatedTime;					// 作成日時
	UINT64 LastCommTime;				// 最終通信日時
	UINT64 LastLoginTime;				// 最終ログイン日時
	UINT NumLogin;						// ログイン回数
	bool HubIsOnlineButHalting;			// 仮想 HUB は本当はオンラインだが停止のためにオフライン化してある
	UINT FarmMember_MaxSessionClient;	// クラスタメンバ用 最大クライアント接続セッション数
	UINT FarmMember_MaxSessionBridge;	// クラスタメンバ用 最大ブリッジ接続セッション数
	bool FarmMember_MaxSessionClientBridgeApply;	// FarmMember_MaxSession* を適用する
	UINT CurrentVersion;				// 現在のバージョン
	UINT LastVersion;					// 最後に更新通知を発行したときのバージョン
	wchar_t *Msg;						// クライアントが接続してきたときに表示するメッセージ
};


// グローバル変数
extern ADMIN_OPTION admin_options[];
extern UINT num_admin_options;


// 関数プロトタイプ
HUBDB *NewHubDb();
void DeleteHubDb(HUBDB *d);
HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option);
void SetHubMsg(HUB *h, wchar_t *msg);
wchar_t *GetHubMsg(HUB *h);
void GenHubMacAddress(UCHAR *mac, char *name);
void GenHubIpAddress(IP *ip, char *name);
bool IsHubIpAddress(IP *ip);
bool IsHubIpAddress32(UINT ip32);
bool IsHubIpAddress64(IPV6_ADDR *addr);
bool IsHubMacAddress(UCHAR *mac);
void ReleaseHub(HUB *h);
void CleanupHub(HUB *h);
int CompareHub(void *p1, void *p2);
void LockHubList(CEDAR *cedar);
void UnlockHubList(CEDAR *cedar);
HUB *GetHub(CEDAR *cedar, char *name);
bool IsHub(CEDAR *cedar, char *name);
void StopHub(HUB *h);
void AddSession(HUB *h, SESSION *s);
void DelSession(HUB *h, SESSION *s);
void StopAllSession(HUB *h);
bool HubPaInit(SESSION *s);
void HubPaFree(SESSION *s);
CANCEL *HubPaGetCancel(SESSION *s);
UINT HubPaGetNextPacket(SESSION *s, void **data);
bool HubPaPutPacket(SESSION *s, void *data, UINT size);
PACKET_ADAPTER *GetHubPacketAdapter();
int CompareMacTable(void *p1, void *p2);
void StorePacket(HUB *hub, SESSION *s, PKT *packet);
bool StorePacketFilter(SESSION *s, PKT *packet);
void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet);
void SetHubOnline(HUB *h);
void SetHubOffline(HUB *h);
SESSION *GetSessionByPtr(HUB *hub, void *ptr);
SESSION *GetSessionByName(HUB *hub, char *name);
int CompareIpTable(void *p1, void *p2);
bool StorePacketFilterByPolicy(SESSION *s, PKT *p);
bool DeleteIPv6DefaultRouterInRA(PKT *p);
bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p);
void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p);
bool IsMostHighestPriorityPacket(SESSION *s, PKT *p);
bool IsPriorityPacketForQoS(PKT *p);
int CompareStormList(void *p1, void *p2);
STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip);
STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip);
bool CheckBroadcastStorm(SESSION *s, PKT *p);
void AddRootCert(HUB *hub, X *x);
int CmpAccessList(void *p1, void *p2);
void InitAccessList(HUB *hub);
void FreeAccessList(HUB *hub);
void AddAccessList(HUB *hub, ACCESS *a);
UINT UsernameToInt(char *name);
bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p);
bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p);
bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT dest_username, UINT dest_groupname);
void GetAccessListStr(char *str, UINT size, ACCESS *a);
void DeleteOldIpTableEntry(LIST *o);
void SetRadiusServer(HUB *hub, char *name, UINT port, char *secret);
void SetRadiusServerEx(HUB *hub, char *name, UINT port, char *secret, UINT interval);
bool GetRadiusServer(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size);
bool GetRadiusServerEx(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval);
int CompareCert(void *p1, void *p2);
void GetHubLogSetting(HUB *h, HUB_LOG *setting);
void SetHubLogSetting(HUB *h, HUB_LOG *setting);
void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type);
void DeleteExpiredIpTableEntry(LIST *o);
void DeleteExpiredMacTableEntry(LIST *o);
void AddTrafficDiff(HUB *h, char *name, UINT type, TRAFFIC *traffic);
void IncrementHubTraffic(HUB *h);
void EnableSecureNAT(HUB *h, bool enable);
void EnableSecureNATEx(HUB *h, bool enable, bool no_change);
void StartHubWatchDog(HUB *h);
void StopHubWatchDog(HUB *h);
void HubWatchDogThread(THREAD *t, void *param);
int CompareAdminOption(void *p1, void *p2);
UINT GetHubAdminOptionEx(HUB *h, char *name, UINT default_value);
UINT GetHubAdminOption(HUB *h, char *name);
void DeleteAllHubAdminOption(HUB *h, bool lock);
void AddHubAdminOptionsDefaults(HUB *h, bool lock);
bool IsCertMatchCrl(X *x, CRL *crl);
bool IsCertMatchCrlList(X *x, LIST *o);
wchar_t *GenerateCrlStr(CRL *crl);
bool IsValidCertInHub(HUB *h, X *x);
void FreeCrl(CRL *crl);
CRL *CopyCrl(CRL *crl);
int CmpAc(void *p1, void *p2);
LIST *NewAcList();
void AddAc(LIST *o, AC *ac);
bool DelAc(LIST *o, UINT id);
AC *GetAc(LIST *o, UINT id);
void SetAc(LIST *o, UINT id, AC *ac);
void DelAllAc(LIST *o);
void SetAcList(LIST *o, LIST *src);
void NormalizeAcList(LIST *o);
char *GenerateAcStr(AC *ac);
void FreeAcList(LIST *o);
LIST *CloneAcList(LIST *o);
bool IsIPPrivate(IP *ip);
bool IsIPManagementTargetForHUB(IP *ip, HUB *hub);
wchar_t *GetHubAdminOptionHelpString(char *name);
void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name);
ADMIN_OPTION *NewAdminOption(char *name, UINT value);
void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao);
UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name);
void GetHubAdminOptionDataAndSet(RPC_ADMIN_OPTION *ao, char *name, UINT *dest);
bool IsURLMsg(wchar_t *str, char *url, UINT url_size);


#endif	// HUB_H


