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

// Admin.h
// Admin.c のヘッダ

#ifndef	ADMIN_H
#define	ADMIN_H

// Windows のバージョン
struct RPC_WINVER
{
	bool IsWindows;
	bool IsNT;
	bool IsServer;
	bool IsBeta;
	UINT VerMajor;
	UINT VerMinor;
	UINT Build;
	UINT ServicePack;
	char Title[128];
};

// サーバー側構造体
struct ADMIN
{
	SERVER *Server;				// サーバー
	bool ServerAdmin;			// サーバー Administrator
	char *HubName;				// 管理することができる HUB 名
	RPC *Rpc;					// RPC
	LIST *LogFileList;			// アクセス可能なログファイルリスト
	UINT ClientBuild;			// クライアントのビルド番号
	RPC_WINVER ClientWinVer;	// クライアントの Windows のバージョン
};

// テスト
struct RPC_TEST
{
	UINT IntValue;
	char StrValue[1024];
};

// サーバー情報 *
struct RPC_SERVER_INFO
{
	char ServerProductName[128];		// サーバー製品名
	char ServerVersionString[128];		// サーバーバージョン文字列
	char ServerBuildInfoString[128];	// サーバービルド情報文字列
	UINT ServerVerInt;					// サーバーバージョン整数値
	UINT ServerBuildInt;				// サーバービルド番号整数値
	char ServerHostName[MAX_HOST_NAME_LEN + 1];	// サーバーホスト名
	UINT ServerType;					// サーバーの種類
	OS_INFO OsInfo;						// OS 情報
};

// サーバー状態
struct RPC_SERVER_STATUS
{
	UINT ServerType;					// サーバーの種類
	UINT NumTcpConnections;				// 合計 TCP コネクション数
	UINT NumTcpConnectionsLocal;		// ローカル TCP コネクション数
	UINT NumTcpConnectionsRemote;		// リモート TCP コネクション数
	UINT NumHubTotal;					// 合計 HUB 数
	UINT NumHubStandalone;				// スタンドアロン HUB 数
	UINT NumHubStatic;					// スタティック HUB 数
	UINT NumHubDynamic;					// ダイナミック HUB 数
	UINT NumSessionsTotal;				// 合計セッション数
	UINT NumSessionsLocal;				// ローカルセッション数 (コントローラのみ)
	UINT NumSessionsRemote;				// リモートセッション数 (コントローラ以外)
	UINT NumMacTables;					// MAC テーブル数
	UINT NumIpTables;					// IP テーブル数
	UINT NumUsers;						// ユーザー数
	UINT NumGroups;						// グループ数
	UINT AssignedBridgeLicenses;		// 割り当て済みブリッジライセンス数
	UINT AssignedClientLicenses;		// 割り当て済みクライアントライセンス数
	UINT AssignedBridgeLicensesTotal;	// 割り当て済みブリッジライセンス数 (クラスタ全体)
	UINT AssignedClientLicensesTotal;	// 割り当て済みクライアントライセンス数 (クラスタ全体)
	TRAFFIC Traffic;					// トラフィック情報
	UINT64 CurrentTime;					// 現在時刻
	UINT64 CurrentTick;					// 現在 Tick
	UINT64 StartTime;					// 起動時刻
	MEMINFO MemInfo;					// メモリ情報
};

// リスナー
struct RPC_LISTENER
{
	UINT Port;							// ポート番号
	bool Enable;						// 有効状態
};

// リスナーのリスト*
struct RPC_LISTENER_LIST
{
	UINT NumPort;						// ポート数
	UINT *Ports;						// ポート一覧
	bool *Enables;						// 有効状態
	bool *Errors;						// エラー発生
};

// 文字列*
struct RPC_STR
{
	char *String;						// 文字列
};

// 整数
struct RPC_INT
{
	UINT IntValue;						// 整数
};

// パスワードの設定
struct RPC_SET_PASSWORD
{
	UCHAR HashedPassword[SHA1_SIZE];	// ハッシュされたパスワード
};

// サーバーファーム設定*
struct RPC_FARM
{
	UINT ServerType;					// サーバーの種類
	UINT NumPort;						// 公開ポート数
	UINT *Ports;						// 公開ポート一覧
	UINT PublicIp;						// 公開 IP
	char ControllerName[MAX_HOST_NAME_LEN + 1];	// コントローラ名
	UINT ControllerPort;				// コントローラポート
	UCHAR MemberPassword[SHA1_SIZE];	// メンバパスワード
	UINT Weight;						// 性能基準比
	bool ControllerOnly;				// コントローラ機能のみ
};

// ファームメンバごとの HUB アイテム
struct RPC_FARM_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	bool DynamicHub;					// ダイナミック HUB
};

// サーバーファームメンバ情報取得*
struct RPC_FARM_INFO
{
	UINT Id;							// ID
	bool Controller;					// コントローラ
	UINT64 ConnectedTime;				// 接続時刻
	UINT Ip;							// IP アドレス
	char Hostname[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT Point;							// ポイント
	UINT NumPort;						// ポート数
	UINT *Ports;						// ポート
	X *ServerCert;						// サーバー証明書
	UINT NumFarmHub;					// ファーム HUB 数
	RPC_FARM_HUB *FarmHubs;				// ファーム HUB
	UINT NumSessions;					// セッション数
	UINT NumTcpConnections;				// TCP コネクション数
	UINT Weight;						// 性能基準比
};

// サーバーファームメンバ列挙項目
struct RPC_ENUM_FARM_ITEM
{
	UINT Id;							// ID
	bool Controller;					// コントローラ
	UINT64 ConnectedTime;				// 接続時刻
	UINT Ip;							// IP アドレス
	char Hostname[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT Point;							// ポイント
	UINT NumSessions;					// セッション数
	UINT NumTcpConnections;				// TCP コネクション数
	UINT NumHubs;						// HUB 数
	UINT AssignedClientLicense;			// 割り当て済みクライアントライセンス数
	UINT AssignedBridgeLicense;			// 割り当て済みブリッジライセンス数
};

// サーバーファームメンバ列挙*
struct RPC_ENUM_FARM
{
	UINT NumFarm;						// ファーム数
	RPC_ENUM_FARM_ITEM *Farms;			// ファーム一覧
};

// コントローラへの接続状態
struct RPC_FARM_CONNECTION_STATUS
{
	UINT Ip;							// IP アドレス
	UINT Port;							// ポート番号
	bool Online;						// オンライン状態
	UINT LastError;						// 最終エラー
	UINT64 StartedTime;					// 接続開始時刻
	UINT64 FirstConnectedTime;			// 最初の接続時刻
	UINT64 CurrentConnectedTime;		// 今回の接続時刻
	UINT NumTry;						// 試行回数
	UINT NumConnected;					// 接続回数
	UINT NumFailed;						// 接続失敗回数
};

// キーペア
struct RPC_KEY_PAIR
{
	X *Cert;							// 証明書
	K *Key;								// 秘密鍵
};

// HUB オプション
struct RPC_HUB_OPTION
{
	UINT MaxSession;					// 最大セッション数
	bool NoEnum;						// 列挙しない
};

// Radius サーバーオプション
struct RPC_RADIUS
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	char RadiusServerName[MAX_HOST_NAME_LEN + 1];	// Radius サーバー名
	UINT RadiusPort;					// Radius ポート番号
	char RadiusSecret[MAX_PASSWORD_LEN + 1];	// 秘密鍵
	UINT RadiusRetryInterval;			// Radius 再試行間隔
};

// HUB の指定
struct RPC_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
};

// HUB の作成
struct RPC_CREATE_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	UCHAR HashedPassword[SHA1_SIZE];	// 管理用パスワード
	UCHAR SecurePassword[SHA1_SIZE];	// Administrator パスワード
	bool Online;						// オンラインフラグ
	RPC_HUB_OPTION HubOption;			// HUB オプション
	UINT HubType;						// HUB の種類
};

// HUB の列挙項目
struct RPC_ENUM_HUB_ITEM
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	bool Online;						// オンライン
	UINT HubType;						// HUB の種類
	UINT NumUsers;						// ユーザー数
	UINT NumGroups;						// グループ数
	UINT NumSessions;					// セッション数
	UINT NumMacTables;					// MAC テーブル数
	UINT NumIpTables;					// IP テーブル数
	UINT64 LastCommTime;				// 最終通信日時
	UINT64 LastLoginTime;				// 最終ログイン日時
	UINT64 CreatedTime;					// 作成日時
	UINT NumLogin;						// ログイン回数
};

// HUB の列挙*
struct RPC_ENUM_HUB
{
	UINT NumHub;						// HUB 数
	RPC_ENUM_HUB_ITEM *Hubs;			// HUB
};

// HUB の削除
struct RPC_DELETE_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
};

// コネクション列挙項目
struct RPC_ENUM_CONNECTION_ITEM
{
	char Name[MAX_SIZE];				// コネクション名
	char Hostname[MAX_SIZE];			// ホスト名
	UINT Ip;							// IP アドレス
	UINT Port;							// ポート番号
	UINT64 ConnectedTime;				// 接続された時刻
	UINT Type;							// 種類
};

// コネクション列挙
struct RPC_ENUM_CONNECTION
{
	UINT NumConnection;					// コネクション数
	RPC_ENUM_CONNECTION_ITEM *Connections;	// コネクション一覧
};

// コネクション切断
struct RPC_DISCONNECT_CONNECTION
{
	char Name[MAX_SIZE];				// コネクション名
};

// コネクション情報
struct RPC_CONNECTION_INFO
{
	char Name[MAX_SIZE];				// コネクション名
	UINT Type;							// 種類
	char Hostname[MAX_SIZE];			// ホスト名
	UINT Ip;							// IP アドレス
	UINT Port;							// ポート番号
	UINT64 ConnectedTime;				// 接続された時刻
	char ServerStr[MAX_SERVER_STR_LEN + 1];	// サーバー文字列
	UINT ServerVer;						// サーバーバージョン
	UINT ServerBuild;					// サーバービルド番号
	char ClientStr[MAX_CLIENT_STR_LEN + 1];	// クライアント文字列
	UINT ClientVer;						// クライアントバージョン
	UINT ClientBuild;					// クライアントビルド番号
};

// HUB をオンラインまたはオフラインにする
struct RPC_SET_HUB_ONLINE
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	bool Online;						// オンライン・オフラインフラグ
};

// HUB 状態の取得
struct RPC_HUB_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	bool Online;						// オンライン
	UINT HubType;						// HUB の種類
	UINT NumSessions;					// セッション数
	UINT NumSessionsClient;				// セッション数 (クライアント)
	UINT NumSessionsBridge;				// セッション数 (ブリッジ)
	UINT NumAccessLists;				// アクセスリスト数
	UINT NumUsers;						// ユーザー数
	UINT NumGroups;						// グループ数
	UINT NumMacTables;					// MAC テーブル数
	UINT NumIpTables;					// IP テーブル数
	TRAFFIC Traffic;					// トラフィック
	bool SecureNATEnabled;				// SecureNAT が有効かどうか
	UINT64 LastCommTime;				// 最終通信日時
	UINT64 LastLoginTime;				// 最終ログイン日時
	UINT64 CreatedTime;					// 作成日時
	UINT NumLogin;						// ログイン回数
};

// HUB ログ設定
struct RPC_HUB_LOG
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	HUB_LOG LogSetting;					// ログ設定
};

// HUB への CA 追加*
struct RPC_HUB_ADD_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	X *Cert;							// 証明書
};

// HUB の CA 列挙項目
struct RPC_HUB_ENUM_CA_ITEM
{
	UINT Key;								// 証明書キー
	wchar_t SubjectName[MAX_SIZE];			// 発行先
	wchar_t IssuerName[MAX_SIZE];			// 発行者
	UINT64 Expires;							// 有効期限
};

// HUB の CA 列挙*
struct RPC_HUB_ENUM_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	UINT NumCa;								// CA 数
	RPC_HUB_ENUM_CA_ITEM *Ca;				// CA
};

// HUB の CA の取得*
struct RPC_HUB_GET_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	UINT Key;							// 証明書キー
	X *Cert;							// 証明書
};

// HUB の CA の削除
struct RPC_HUB_DELETE_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	UINT Key;							// 削除する証明書キー
};

// リンクの作成・設定*
struct RPC_CREATE_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB 名
	bool Online;						// オンラインフラグ
	CLIENT_OPTION *ClientOption;		// クライアントオプション
	CLIENT_AUTH *ClientAuth;			// クライアント認証データ
	POLICY Policy;						// ポリシー
	bool CheckServerCert;				// サーバー証明書を検証する
	X *ServerCert;						// サーバー証明書
};

// リンクの列挙項目
struct RPC_ENUM_LINK_ITEM
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
	bool Online;									// オンラインフラグ
	bool Connected;									// 接続完了フラグ
	UINT LastError;									// 最後に発生したエラー
	UINT64 ConnectedTime;							// 接続完了時刻
	char Hostname[MAX_HOST_NAME_LEN + 1];			// ホスト名
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
};

// リンクの列挙*
struct RPC_ENUM_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT NumLink;									// リンク数
	RPC_ENUM_LINK_ITEM *Links;						// リンク一覧
};

// リンク状態の取得*
struct RPC_LINK_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
	RPC_CLIENT_GET_CONNECTION_STATUS Status;		// ステータス
};

// リンクの指定
struct RPC_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// アカウント名
};

// リンクの名前変更
struct RPC_RENAME_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	wchar_t OldAccountName[MAX_ACCOUNT_NAME_LEN + 1];	// 古いアカウント名
	wchar_t NewAccountName[MAX_ACCOUNT_NAME_LEN + 1];	// 新しいアカウント名
};

// アクセスリストの列挙*
struct RPC_ENUM_ACCESS_LIST
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT NumAccess;									// アクセスリスト数
	ACCESS *Accesses;								// アクセスリスト
};

// アクセスリストの追加
struct RPC_ADD_ACCESS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	ACCESS Access;									// アクセスリスト
};

// アクセスリストの削除
struct RPC_DELETE_ACCESS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT Id;										// ID
};

// ユーザーの作成・設定・取得*
struct RPC_SET_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	char Name[MAX_USERNAME_LEN + 1];				// ユーザー名
	char GroupName[MAX_USERNAME_LEN + 1];			// グループ名
	wchar_t Realname[MAX_SIZE];						// 本名
	wchar_t Note[MAX_SIZE];							// メモ
	UINT64 CreatedTime;								// 作成日時
	UINT64 UpdatedTime;								// 更新日時
	UINT64 ExpireTime;								// 有効期限
	UINT AuthType;									// 認証方法
	void *AuthData;									// 認証データ
	UINT NumLogin;									// ログイン回数
	TRAFFIC Traffic;								// トラフィックデータ
	POLICY *Policy;									// ポリシー
};

// ユーザーの列挙項目
struct RPC_ENUM_USER_ITEM
{
	char Name[MAX_USERNAME_LEN + 1];				// ユーザー名
	char GroupName[MAX_USERNAME_LEN + 1];			// グループ名
	wchar_t Realname[MAX_SIZE];						// 本名
	wchar_t Note[MAX_SIZE];							// メモ
	UINT AuthType;									// 認証方法
	UINT NumLogin;									// ログイン回数
	UINT64 LastLoginTime;							// 最終ログイン日時
	bool DenyAccess;								// アクセス拒否
};

// ユーザーの列挙
struct RPC_ENUM_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT NumUser;									// ユーザー数
	RPC_ENUM_USER_ITEM *Users;						// ユーザー
};

// グループの作成・設定・取得*
struct RPC_SET_GROUP
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	char Name[MAX_USERNAME_LEN + 1];				// ユーザー名
	wchar_t Realname[MAX_SIZE];						// 本名
	wchar_t Note[MAX_SIZE];							// メモ
	TRAFFIC Traffic;								// トラフィックデータ
	POLICY *Policy;									// ポリシー
};

// グループの列挙項目
struct RPC_ENUM_GROUP_ITEM
{
	char Name[MAX_USERNAME_LEN + 1];				// ユーザー名
	wchar_t Realname[MAX_SIZE];						// 本名
	wchar_t Note[MAX_SIZE];							// メモ
	UINT NumUsers;									// ユーザー数
	bool DenyAccess;								// アクセス拒否
};

// グループの列挙
struct RPC_ENUM_GROUP
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT NumGroup;									// グループ数
	RPC_ENUM_GROUP_ITEM *Groups;					// グループ
};

// ユーザーまたはグループの削除
struct RPC_DELETE_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	char Name[MAX_USERNAME_LEN + 1];				// ユーザー名またはグループ名
};

// セッションの列挙項目
struct RPC_ENUM_SESSION_ITEM
{
	char Name[MAX_SESSION_NAME_LEN + 1];			// セッション名
	bool RemoteSession;								// リモートセッション
	char RemoteHostname[MAX_HOST_NAME_LEN + 1];		// リモートサーバー名
	char Username[MAX_USERNAME_LEN + 1];			// ユーザー名
	UINT Ip;										// IP アドレス (IPv4)
	char Hostname[MAX_HOST_NAME_LEN	+ 1];			// ホスト名
	UINT MaxNumTcp;									// TCP コネクション数最大
	UINT CurrentNumTcp;								// TCP コネクション数現在
	UINT64 PacketSize;								// パケットサイズ
	UINT64 PacketNum;								// パケット数
	bool LinkMode;									// リンクモード
	bool SecureNATMode;								// SecureNAT モード
	bool BridgeMode;								// ブリッジモード
	bool Layer3Mode;								// レイヤ 3 モード
	bool Client_BridgeMode;							// クライアントがブリッジモード
	bool Client_MonitorMode;						// クライアントがモニタリングモード
	UINT VLanId;									// VLAN ID
	UCHAR UniqueId[16];								// Unique ID
};

// セッションの切断
struct RPC_DELETE_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	char Name[MAX_SESSION_NAME_LEN + 1];			// セッション名
};

// MAC テーブルの列挙項目
struct RPC_ENUM_MAC_TABLE_ITEM
{
	UINT Key;										// キー
	char SessionName[MAX_SESSION_NAME_LEN + 1];		// セッション名
	UCHAR MacAddress[6];							// MAC アドレス
	UCHAR Padding[2];
	UINT64 CreatedTime;								// 作成日時
	UINT64 UpdatedTime;								// 更新日時
	bool RemoteItem;								// リモートアイテム
	char RemoteHostname[MAX_HOST_NAME_LEN + 1];		// リモートホスト名
	UINT VlanId;									// VLAN ID
};

// MAC テーブルの列挙
struct RPC_ENUM_MAC_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT NumMacTable;								// テーブル数
	RPC_ENUM_MAC_TABLE_ITEM *MacTables;				// MAC テーブル
};

// IP テーブルの列挙項目
struct RPC_ENUM_IP_TABLE_ITEM
{
	UINT Key;										// キー
	char SessionName[MAX_SESSION_NAME_LEN + 1];		// セッション名
	UINT Ip;										// IP アドレス
	IP IpV6;										// IPv6 アドレス
	bool DhcpAllocated;								// DHCP によって割り当て済み
	UINT64 CreatedTime;								// 作成日時
	UINT64 UpdatedTime;								// 更新日時
	bool RemoteItem;								// リモートアイテム
	char RemoteHostname[MAX_HOST_NAME_LEN + 1];		// リモートホスト名
};

// IP テーブルの列挙
struct RPC_ENUM_IP_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT NumIpTable;								// テーブル数
	RPC_ENUM_IP_TABLE_ITEM *IpTables;				// MAC テーブル
};

// テーブルの削除
struct RPC_DELETE_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB 名
	UINT Key;										// キー
};

// KEEP 設定
struct RPC_KEEP
{
	bool UseKeepConnect;					// インターネットへの接続を維持
	char KeepConnectHost[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT KeepConnectPort;					// ポート番号
	UINT KeepConnectProtocol;				// プロトコル
	UINT KeepConnectInterval;				// 間隔
};

// Ethernet 列挙アイテム
struct RPC_ENUM_ETH_ITEM
{
	char DeviceName[MAX_SIZE];				// デバイス名
	wchar_t NetworkConnectionName[MAX_SIZE];// ネットワーク接続名
};

// Ethernet 列挙
struct RPC_ENUM_ETH
{
	UINT NumItem;							// アイテム数
	RPC_ENUM_ETH_ITEM *Items;				// アイテム
};

// ブリッジ項目
struct RPC_LOCALBRIDGE
{
	char DeviceName[MAX_SIZE];				// デバイス名
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB 名
	bool Online;							// オンラインフラグ
	bool Active;							// 動作フラグ
	bool TapMode;							// tap モード
};

// ブリッジ列挙
struct RPC_ENUM_LOCALBRIDGE
{
	UINT NumItem;							// アイテム数
	RPC_LOCALBRIDGE *Items;					// アイテム
};

// ブリッジサポート情報
struct RPC_BRIDGE_SUPPORT
{
	bool IsBridgeSupportedOs;				// ブリッジがサポートされている OS か
	bool IsWinPcapNeeded;					// WinPcap が必要とされているか
};

// config 操作
struct RPC_CONFIG
{
	char FileName[MAX_PATH];				// ファイル名
	char *FileData;							// ファイルデータ
};

// 管理オプションリスト
struct RPC_ADMIN_OPTION
{
	char HubName[MAX_HUBNAME_LEN + 1];		// 仮想 HUB 名
	UINT NumItem;							// 個数
	ADMIN_OPTION *Items;					// データ
};

// Layer-3 スイッチ
struct RPC_L3SW
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 スイッチ名
};

// Layer-3 スイッチ列挙
struct RPC_ENUM_L3SW_ITEM
{
	char Name[MAX_HUBNAME_LEN + 1];			// 名前
	UINT NumInterfaces;						// インターフェイス数
	UINT NumTables;							// ルーティングテーブル数
	bool Active;							// 動作中
	bool Online;							// オンライン
};
struct RPC_ENUM_L3SW
{
	UINT NumItem;
	RPC_ENUM_L3SW_ITEM *Items;
};

// Layer-3 インターフェイス
struct RPC_L3IF
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 スイッチ名
	char HubName[MAX_HUBNAME_LEN + 1];		// 仮想 HUB 名
	UINT IpAddress;							// IP アドレス
	UINT SubnetMask;						// サブネットマスク
};

// Layer-3 インターフェイス列挙
struct RPC_ENUM_L3IF
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 スイッチ名
	UINT NumItem;
	RPC_L3IF *Items;
};

// ルーティングテーブル
struct RPC_L3TABLE
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 スイッチ名
	UINT NetworkAddress;					// ネットワークアドレス
	UINT SubnetMask;						// サブネットマスク
	UINT GatewayAddress;					// ゲートウェイアドレス
	UINT Metric;							// メトリック
};

// ルーティングテーブル列挙
struct RPC_ENUM_L3TABLE
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 スイッチ名
	UINT NumItem;
	RPC_L3TABLE *Items;
};

// CRL エントリ
struct RPC_CRL
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB 名
	UINT Key;								// キー
	CRL *Crl;								// CRL 本体
};

// CRL 列挙
struct RPC_ENUM_CRL_ITEM
{
	UINT Key;								// キー
	wchar_t CrlInfo[MAX_SIZE];				// 情報
};
struct RPC_ENUM_CRL
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB 名
	UINT NumItem;							// アイテム数
	RPC_ENUM_CRL_ITEM *Items;				// リスト
};

// AC リスト
struct RPC_AC_LIST
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB 名
	LIST *o;								// リスト本体
};

// ログファイル列挙
struct RPC_ENUM_LOG_FILE_ITEM
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	char FilePath[MAX_PATH];				// ファイルパス
	UINT FileSize;							// ファイルサイズ
	UINT64 UpdatedTime;						// 更新日時
};
struct RPC_ENUM_LOG_FILE
{
	UINT NumItem;							// アイテム数
	RPC_ENUM_LOG_FILE_ITEM *Items;			// リスト
};

// ログファイル読み込み
struct RPC_READ_LOG_FILE
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// サーバー名
	char FilePath[MAX_PATH];				// ファイルパス
	UINT Offset;							// オフセット
	BUF *Buffer;							// バッファ
};

// ダウンロード情報
struct DOWNLOAD_PROGRESS
{
	void *Param;							// ユーザー定義データ
	UINT TotalSize;							// 合計ファイルサイズ
	UINT CurrentSize;						// 読み込みが完了したサイズ
	UINT ProgressPercent;					// 完了パーセント
};

// ライセンスキーの列挙
struct RPC_ENUM_LICENSE_KEY_ITEM
{
	UINT Id;								// ID
	char LicenseKey[LICENSE_KEYSTR_LEN + 1];	// ライセンスキー
	char LicenseId[LICENSE_LICENSEID_STR_LEN + 1];	// ライセンス ID
	char LicenseName[LICENSE_MAX_PRODUCT_NAME_LEN + 1];	// ライセンス名
	UINT64 Expires;							// 有効期限
	UINT Status;							// 状況
	UINT ProductId;							// 製品 ID
	UINT64 SystemId;						// システム ID
	UINT SerialId;							// シリアル ID
};
struct RPC_ENUM_LICENSE_KEY
{
	UINT NumItem;							// アイテム数
	RPC_ENUM_LICENSE_KEY_ITEM *Items;		// リスト
};

// サーバーのライセンスの状態
struct RPC_LICENSE_STATUS
{
	UINT EditionId;							// エディション ID
	char EditionStr[LICENSE_MAX_PRODUCT_NAME_LEN + 1];	// エディション名
	UINT64 SystemId;						// システム ID
	UINT64 SystemExpires;					// システム有効期限
	UINT NumClientConnectLicense;			// クライアント同時接続可能数
	UINT NumBridgeConnectLicense;			// ブリッジ同時接続可能数

	// v3.0
	bool NeedSubscription;					// サブスクリプション制度が有効かどうか
	UINT64 SubscriptionExpires;				// サブスクリプション有効期限
	bool IsSubscriptionExpired;				// サブスクリプション有効期限が切れているかどうか
	UINT NumUserCreationLicense;			// ユーザー作成可能数
	bool AllowEnterpriseFunction;			// エンタープライズ機能の動作
	UINT64 ReleaseDate;						// リリース日付
};

// 物理 LAN カードの VLAN 対応状況の列挙
struct RPC_ENUM_ETH_VLAN_ITEM
{
	char DeviceName[MAX_SIZE];				// デバイス名
	char Guid[MAX_SIZE];					// GUID
	char DeviceInstanceId[MAX_SIZE];		// デバイスインスタンス ID
	char DriverName[MAX_SIZE];				// ドライバファイル名
	char DriverType[MAX_SIZE];				// ドライバの種類
	bool Support;							// サポートしているかどうか
	bool Enabled;							// 有効化されているかどうか
};
struct RPC_ENUM_ETH_VLAN
{
	UINT NumItem;							// アイテム数
	RPC_ENUM_ETH_VLAN_ITEM *Items;			// リスト
};

// メッセージ
struct RPC_MSG
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB 名
	wchar_t *Msg;							// メッセージ
};


// 関数プロトタイプ
UINT AdminAccept(CONNECTION *c, PACK *p);
void HashAdminPassword(void *hash, char *password);
SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd);
RPC *AdminConnect(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err);
RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name);
RPC *AdminConnectEx2(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd);
void AdminDisconnect(RPC *rpc);
UINT AdminReconnect(RPC *rpc);
UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname);
PACK *AdminDispatch(RPC *rpc, char *name, PACK *p);
PACK *AdminCall(RPC *rpc, char *function_name, PACK *p);
void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t);
void CopyOsInfo(OS_INFO *dst, OS_INFO *info);
CAPSLIST *ScGetCapsEx(RPC *rpc);
UINT SiEnumMacTable(SERVER *s, char *hubname, RPC_ENUM_MAC_TABLE *t);
UINT SiEnumIpTable(SERVER *s, char *hubname, RPC_ENUM_IP_TABLE *t);
void SiEnumLocalLogFileList(SERVER *s, char *hubname, RPC_ENUM_LOG_FILE *t);
void SiReadLocalLogFile(SERVER *s, char *filepath, UINT offset, RPC_READ_LOG_FILE *t);
typedef bool (DOWNLOAD_PROC)(DOWNLOAD_PROGRESS *progress);
BUF *DownloadFileFromServer(RPC *r, char *server_name, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param);
bool CheckAdminSourceAddress(SOCK *sock, char *hubname);
void SiEnumSessionMain(SERVER *s, RPC_ENUM_SESSION *t);

UINT StTest(ADMIN *a, RPC_TEST *t);
UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t);
UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t);
UINT StCreateListener(ADMIN *a, RPC_LISTENER *t);
UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t);
UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t);
UINT StEnableListener(ADMIN *a, RPC_LISTENER *t);
UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t);
UINT StSetFarmSetting(ADMIN *a, RPC_FARM *t);
UINT StGetFarmSetting(ADMIN *a, RPC_FARM *t);
UINT StGetFarmInfo(ADMIN *a, RPC_FARM_INFO *t);
UINT StEnumFarmMember(ADMIN *a, RPC_ENUM_FARM *t);
UINT StGetFarmConnectionStatus(ADMIN *a, RPC_FARM_CONNECTION_STATUS *t);
UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
UINT StGetServerCipher(ADMIN *a, RPC_STR *t);
UINT StSetServerCipher(ADMIN *a, RPC_STR *t);
UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t);
UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t);
UINT StGetHubRadius(ADMIN *a, RPC_RADIUS *t);
UINT StSetHubRadius(ADMIN *a, RPC_RADIUS *t);
UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t);
UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t);
UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t);
UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t);
UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t);
UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t);
UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t);
UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t);
UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t);
UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t);
UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t);
UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t);
UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t);
UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t);
UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t);
UINT StDeleteLink(ADMIN *a, RPC_LINK *t);
UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t);
UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t);
UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t);
UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
UINT StCreateUser(ADMIN *a, RPC_SET_USER *t);
UINT StSetUser(ADMIN *a, RPC_SET_USER *t);
UINT StGetUser(ADMIN *a, RPC_SET_USER *t);
UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t);
UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t);
UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t);
UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t);
UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t);
UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t);
UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t);
UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t);
UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t);
UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t);
UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t);
UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
UINT StSetKeep(ADMIN *a, RPC_KEEP *t);
UINT StGetKeep(ADMIN *a, RPC_KEEP *t);
UINT StEnableSecureNAT(ADMIN *a, RPC_HUB *t);
UINT StDisableSecureNAT(ADMIN *a, RPC_HUB *t);
UINT StSetSecureNATOption(ADMIN *a, VH_OPTION *t);
UINT StGetSecureNATOption(ADMIN *a, VH_OPTION *t);
UINT StEnumNAT(ADMIN *a, RPC_ENUM_NAT *t);
UINT StEnumDHCP(ADMIN *a, RPC_ENUM_DHCP *t);
UINT StGetSecureNATStatus(ADMIN *a, RPC_NAT_STATUS *t);
UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t);
UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t);
UINT StGetBridgeSupport(ADMIN *a, RPC_BRIDGE_SUPPORT *t);
UINT StRebootServer(ADMIN *a, RPC_TEST *t);
UINT StGetCaps(ADMIN *a, CAPSLIST *t);
UINT StGetConfig(ADMIN *a, RPC_CONFIG *t);
UINT StSetConfig(ADMIN *a, RPC_CONFIG *t);
UINT StGetDefaultHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StAddL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StDelL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StEnumL3Switch(ADMIN *a, RPC_ENUM_L3SW *t);
UINT StStartL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StStopL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StAddL3If(ADMIN *a, RPC_L3IF *t);
UINT StDelL3If(ADMIN *a, RPC_L3IF *t);
UINT StEnumL3If(ADMIN *a, RPC_ENUM_L3IF *t);
UINT StAddL3Table(ADMIN *a, RPC_L3TABLE *t);
UINT StDelL3Table(ADMIN *a, RPC_L3TABLE *t);
UINT StEnumL3Table(ADMIN *a, RPC_ENUM_L3TABLE *t);
UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t);
UINT StAddCrl(ADMIN *a, RPC_CRL *t);
UINT StDelCrl(ADMIN *a, RPC_CRL *t);
UINT StGetCrl(ADMIN *a, RPC_CRL *t);
UINT StSetCrl(ADMIN *a, RPC_CRL *t);
UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t);
UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t);
UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t);
UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t);
UINT StAddLicenseKey(ADMIN *a, RPC_TEST *t);
UINT StDelLicenseKey(ADMIN *a, RPC_TEST *t);
UINT StEnumLicenseKey(ADMIN *a, RPC_ENUM_LICENSE_KEY *t);
UINT StGetLicenseStatus(ADMIN *a, RPC_LICENSE_STATUS *t);
UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t);
UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t);
UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t);
UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t);
UINT StSetHubMsg(ADMIN *a, RPC_MSG *t);
UINT StGetHubMsg(ADMIN *a, RPC_MSG *t);
UINT StCrash(ADMIN *a, RPC_TEST *t);
UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t);
UINT StFlush(ADMIN *a, RPC_TEST *t);
UINT StDebug(ADMIN *a, RPC_TEST *t);

UINT ScTest(RPC *r, RPC_TEST *t);
UINT ScGetServerInfo(RPC *r, RPC_SERVER_INFO *t);
UINT ScGetServerStatus(RPC *r, RPC_SERVER_STATUS *t);
UINT ScCreateListener(RPC *r, RPC_LISTENER *t);
UINT ScEnumListener(RPC *r, RPC_LISTENER_LIST *t);
UINT ScDeleteListener(RPC *r, RPC_LISTENER *t);
UINT ScEnableListener(RPC *r, RPC_LISTENER *t);
UINT ScSetServerPassword(RPC *r, RPC_SET_PASSWORD *t);
UINT ScSetFarmSetting(RPC *r, RPC_FARM *t);
UINT ScGetFarmSetting(RPC *r, RPC_FARM *t);
UINT ScGetFarmInfo(RPC *r, RPC_FARM_INFO *t);
UINT ScEnumFarmMember(RPC *r, RPC_ENUM_FARM *t);
UINT ScGetFarmConnectionStatus(RPC *r, RPC_FARM_CONNECTION_STATUS *t);
UINT ScSetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCipher(RPC *r, RPC_STR *t);
UINT ScSetServerCipher(RPC *r, RPC_STR *t);
UINT ScCreateHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScSetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScGetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScEnumHub(RPC *r, RPC_ENUM_HUB *t);
UINT ScDeleteHub(RPC *r, RPC_DELETE_HUB *t);
UINT ScGetHubRadius(RPC *r, RPC_RADIUS *t);
UINT ScSetHubRadius(RPC *r, RPC_RADIUS *t);
UINT ScEnumConnection(RPC *r, RPC_ENUM_CONNECTION *t);
UINT ScDisconnectConnection(RPC *r, RPC_DISCONNECT_CONNECTION *t);
UINT ScGetConnectionInfo(RPC *r, RPC_CONNECTION_INFO *t);
UINT ScSetHubOnline(RPC *r, RPC_SET_HUB_ONLINE *t);
UINT ScGetHubStatus(RPC *r, RPC_HUB_STATUS *t);
UINT ScSetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScGetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScAddCa(RPC *r, RPC_HUB_ADD_CA *t);
UINT ScEnumCa(RPC *r, RPC_HUB_ENUM_CA *t);
UINT ScGetCa(RPC *r, RPC_HUB_GET_CA *t);
UINT ScDeleteCa(RPC *r, RPC_HUB_DELETE_CA *t);
UINT ScCreateLink(RPC *r, RPC_CREATE_LINK *t);
UINT ScEnumLink(RPC *r, RPC_ENUM_LINK *t);
UINT ScGetLinkStatus(RPC *r, RPC_LINK_STATUS *t);
UINT ScSetLinkOnline(RPC *r, RPC_LINK *t);
UINT ScSetLinkOffline(RPC *r, RPC_LINK *t);
UINT ScDeleteLink(RPC *r, RPC_LINK *t);
UINT ScRenameLink(RPC *r, RPC_RENAME_LINK *t);
UINT ScAddAccess(RPC *r, RPC_ADD_ACCESS *t);
UINT ScDeleteAccess(RPC *r, RPC_DELETE_ACCESS *t);
UINT ScEnumAccess(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScCreateUser(RPC *r, RPC_SET_USER *t);
UINT ScSetUser(RPC *r, RPC_SET_USER *t);
UINT ScGetUser(RPC *r, RPC_SET_USER *t);
UINT ScDeleteUser(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumUser(RPC *r, RPC_ENUM_USER *t);
UINT ScCreateGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScSetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScGetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScDeleteGroup(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumGroup(RPC *r, RPC_ENUM_GROUP *t);
UINT ScEnumSession(RPC *r, RPC_ENUM_SESSION *t);
UINT ScGetSessionStatus(RPC *r, RPC_SESSION_STATUS *t);
UINT ScDeleteSession(RPC *r, RPC_DELETE_SESSION *t);
UINT ScEnumMacTable(RPC *r, RPC_ENUM_MAC_TABLE *t);
UINT ScDeleteMacTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScEnumIpTable(RPC *r, RPC_ENUM_IP_TABLE *t);
UINT ScDeleteIpTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScGetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetAccessList(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScSetKeep(RPC *r, RPC_KEEP *t);
UINT ScGetKeep(RPC *r, RPC_KEEP *t);
UINT ScEnableSecureNAT(RPC *r, RPC_HUB *t);
UINT ScDisableSecureNAT(RPC *r, RPC_HUB *t);
UINT ScSetSecureNATOption(RPC *r, VH_OPTION *t);
UINT ScGetSecureNATOption(RPC *r, VH_OPTION *t);
UINT ScEnumNAT(RPC *r, RPC_ENUM_NAT *t);
UINT ScEnumDHCP(RPC *r, RPC_ENUM_DHCP *t);
UINT ScGetSecureNATStatus(RPC *r, RPC_NAT_STATUS *t);
UINT ScEnumEthernet(RPC *r, RPC_ENUM_ETH *t);
UINT ScAddLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScDeleteLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScEnumLocalBridge(RPC *r, RPC_ENUM_LOCALBRIDGE *t);
UINT ScGetBridgeSupport(RPC *r, RPC_BRIDGE_SUPPORT *t);
UINT ScRebootServer(RPC *r, RPC_TEST *t);
UINT ScGetCaps(RPC *r, CAPSLIST *t);
UINT ScGetConfig(RPC *r, RPC_CONFIG *t);
UINT ScSetConfig(RPC *r, RPC_CONFIG *t);
UINT ScGetDefaultHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScGetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScGetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScAddL3Switch(RPC *r, RPC_L3SW *t);
UINT ScDelL3Switch(RPC *r, RPC_L3SW *t);
UINT ScEnumL3Switch(RPC *r, RPC_ENUM_L3SW *t);
UINT ScStartL3Switch(RPC *r, RPC_L3SW *t);
UINT ScStopL3Switch(RPC *r, RPC_L3SW *t);
UINT ScAddL3If(RPC *r, RPC_L3IF *t);
UINT ScDelL3If(RPC *r, RPC_L3IF *t);
UINT ScEnumL3If(RPC *r, RPC_ENUM_L3IF *t);
UINT ScAddL3Table(RPC *r, RPC_L3TABLE *t);
UINT ScDelL3Table(RPC *r, RPC_L3TABLE *t);
UINT ScEnumL3Table(RPC *r, RPC_ENUM_L3TABLE *t);
UINT ScEnumCrl(RPC *r, RPC_ENUM_CRL *t);
UINT ScAddCrl(RPC *r, RPC_CRL *t);
UINT ScDelCrl(RPC *r, RPC_CRL *t);
UINT ScGetCrl(RPC *r, RPC_CRL *t);
UINT ScSetCrl(RPC *r, RPC_CRL *t);
UINT ScSetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScGetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScEnumLogFile(RPC *r, RPC_ENUM_LOG_FILE *t);
UINT ScReadLogFile(RPC *r, RPC_READ_LOG_FILE *t);
UINT ScAddLicenseKey(RPC *r, RPC_TEST *t);
UINT ScDelLicenseKey(RPC *r, RPC_TEST *t);
UINT ScEnumLicenseKey(RPC *r, RPC_ENUM_LICENSE_KEY *t);
UINT ScGetLicenseStatus(RPC *r, RPC_LICENSE_STATUS *t);
UINT ScSetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScGetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScEnumEthVLan(RPC *r, RPC_ENUM_ETH_VLAN *t);
UINT ScSetEnableEthVLan(RPC *r, RPC_TEST *t);
UINT ScSetHubMsg(RPC *r, RPC_MSG *t);
UINT ScGetHubMsg(RPC *r, RPC_MSG *t);
UINT ScCrash(RPC *r, RPC_TEST *t);
UINT ScGetAdminMsg(RPC *r, RPC_MSG *t);
UINT ScFlush(RPC *r, RPC_TEST *t);
UINT ScDebug(RPC *r, RPC_TEST *t);

void InRpcTest(RPC_TEST *t, PACK *p);
void OutRpcTest(PACK *p, RPC_TEST *t);
void FreeRpcTest(RPC_TEST *t);
void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p);
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t);
void FreeRpcServerInfo(RPC_SERVER_INFO *t);
void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p);
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t);
void InRpcListener(RPC_LISTENER *t, PACK *p);
void OutRpcListener(PACK *p, RPC_LISTENER *t);
void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p);
void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t);
void FreeRpcListenerList(RPC_LISTENER_LIST *t);
void InRpcStr(RPC_STR *t, PACK *p);
void OutRpcStr(PACK *p, RPC_STR *t);
void FreeRpcStr(RPC_STR *t);
void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p);
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t);
void InRpcFarm(RPC_FARM *t, PACK *p);
void OutRpcFarm(PACK *p, RPC_FARM *t);
void FreeRpcFarm(RPC_FARM *t);
void InRpcFarmHub(RPC_FARM_HUB *t, PACK *p);
void OutRpcFarmHub(PACK *p, RPC_FARM_HUB *t);
void InRpcFarmInfo(RPC_FARM_INFO *t, PACK *p);
void OutRpcFarmInfo(PACK *p, RPC_FARM_INFO *t);
void FreeRpcFarmInfo(RPC_FARM_INFO *t);
void InRpcEnumFarm(RPC_ENUM_FARM *t, PACK *p);
void OutRpcEnumFarm(PACK *p, RPC_ENUM_FARM *t);
void FreeRpcEnumFarm(RPC_ENUM_FARM *t);
void InRpcFarmConnectionStatus(RPC_FARM_CONNECTION_STATUS *t, PACK *p);
void OutRpcFarmConnectionStatus(PACK *p, RPC_FARM_CONNECTION_STATUS *t);
void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p);
void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t);
void InRpcRadius(RPC_RADIUS *t, PACK *p);
void OutRpcRadius(PACK *p, RPC_RADIUS *t);
void InRpcHub(RPC_HUB *t, PACK *p);
void OutRpcHub(PACK *p, RPC_HUB *t);
void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p);
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t);
void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p);
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t);
void FreeRpcEnumHub(RPC_ENUM_HUB *t);
void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p);
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t);
void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p);
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t);
void FreeRpcEnumConnetion(RPC_ENUM_CONNECTION *t);
void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p);
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t);
void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p);
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t);
void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p);
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t);
void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p);
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t);
void InRpcHubLog(RPC_HUB_LOG *t, PACK *p);
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t);
void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p);
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t);
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t);
void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p);
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t);
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t);
void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p);
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t);
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t);
void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p);
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t);
void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p);
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t);
void FreeRpcCreateLink(RPC_CREATE_LINK *t);
void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p);
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t);
void FreeRpcEnumLink(RPC_ENUM_LINK *t);
void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p);
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t);
void FreeRpcLinkStatus(RPC_LINK_STATUS *t);
void InRpcLink(RPC_LINK *t, PACK *p);
void OutRpcLink(PACK *p, RPC_LINK *t);
void InRpcAccessEx(ACCESS *a, PACK *p, UINT index);
void InRpcAccess(ACCESS *a, PACK *p);
void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total);
void OutRpcAccess(PACK *p, ACCESS *a);
void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p);
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a);
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a);
void *InRpcAuthData(PACK *p, UINT *authtype);
void OutRpcAuthData(PACK *p, void *authdata, UINT authtype);
void FreeRpcAuthData(void *authdata, UINT authtype);
void InRpcSetUser(RPC_SET_USER *t, PACK *p);
void OutRpcSetUser(PACK *p, RPC_SET_USER *t);
void FreeRpcSetUser(RPC_SET_USER *t);
void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p);
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t);
void FreeRpcEnumUser(RPC_ENUM_USER *t);
void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p);
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t);
void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p);
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t);
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t);
void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p);
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t);
void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p);
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t);
void FreeRpcEnumSession(RPC_ENUM_SESSION *t);
void InRpcNodeInfo(NODE_INFO *t, PACK *p);
void OutRpcNodeInfo(PACK *p, NODE_INFO *t);
void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p);
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t);
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t);
void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p);
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t);
void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p);
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t);
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t);
void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p);
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t);
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t);
void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p);
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t);
void InRpcMemInfo(MEMINFO *t, PACK *p);
void OutRpcMemInfo(PACK *p, MEMINFO *t);
void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p);
void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t);
void FreeRpcKeyPair(RPC_KEY_PAIR *t);
void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p);
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t);
void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p);
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t);
void FreeRpcSetGroup(RPC_SET_GROUP *t);
void AdjoinRpcEnumSession(RPC_ENUM_SESSION *dest, RPC_ENUM_SESSION *src);
void AdjoinRpcEnumMacTable(RPC_ENUM_MAC_TABLE *dest, RPC_ENUM_MAC_TABLE *src);
void AdjoinRpcEnumIpTable(RPC_ENUM_IP_TABLE *dest, RPC_ENUM_IP_TABLE *src);
void InRpcKeep(RPC_KEEP *t, PACK *p);
void OutRpcKeep(PACK *p, RPC_KEEP *t);
void InRpcOsInfo(OS_INFO *t, PACK *p);
void OutRpcOsInfo(PACK *p, OS_INFO *t);
void FreeRpcOsInfo(OS_INFO *t);
void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p);
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t);
void FreeRpcEnumEth(RPC_ENUM_ETH *t);
void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p);
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t);
void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p);
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t);
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t);
void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p);
void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t);
void InRpcConfig(RPC_CONFIG *t, PACK *p);
void OutRpcConfig(PACK *p, RPC_CONFIG *t);
void FreeRpcConfig(RPC_CONFIG *t);
void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p);
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t);
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t);
void InRpcEnumL3Table(RPC_ENUM_L3TABLE *t, PACK *p);
void OutRpcEnumL3Table(PACK *p, RPC_ENUM_L3TABLE *t);
void FreeRpcEnumL3Table(RPC_ENUM_L3TABLE *t);
void InRpcL3Table(RPC_L3TABLE *t, PACK *p);
void OutRpcL3Table(PACK *p, RPC_L3TABLE *t);
void InRpcEnumL3If(RPC_ENUM_L3IF *t, PACK *p);
void OutRpcEnumL3If(PACK *p, RPC_ENUM_L3IF *t);
void FreeRpcEnumL3If(RPC_ENUM_L3IF *t);
void InRpcL3If(RPC_L3IF *t, PACK *p);
void OutRpcL3If(PACK *p, RPC_L3IF *t);
void InRpcL3Sw(RPC_L3SW *t, PACK *p);
void OutRpcL3Sw(PACK *p, RPC_L3SW *t);
void InRpcEnumL3Sw(RPC_ENUM_L3SW *t, PACK *p);
void OutRpcEnumL3Sw(PACK *p, RPC_ENUM_L3SW *t);
void FreeRpcEnumL3Sw(RPC_ENUM_L3SW *t);
void InRpcCrl(RPC_CRL *t, PACK *p);
void OutRpcCrl(PACK *p, RPC_CRL *t);
void FreeRpcCrl(RPC_CRL *t);
void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p);
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t);
void FreeRpcEnumCrl(RPC_ENUM_CRL *t);
void InRpcInt(RPC_INT *t, PACK *p);
void OutRpcInt(PACK *p, RPC_INT *t);
void InRpcAcList(RPC_AC_LIST *t, PACK *p);
void OutRpcAcList(PACK *p, RPC_AC_LIST *t);
void FreeRpcAcList(RPC_AC_LIST *t);
void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p);
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t);
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t);
void AdjoinRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, RPC_ENUM_LOG_FILE *src);
void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p);
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t);
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t);
void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p);
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t);
void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p);
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t);
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t);
void InRpcLicenseStatus(RPC_LICENSE_STATUS *t, PACK *p);
void OutRpcLicenseStatus(PACK *p, RPC_LICENSE_STATUS *t);
void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p);
void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t);
void FreeRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t);
void InRpcMsg(RPC_MSG *t, PACK *p);
void OutRpcMsg(PACK *p, RPC_MSG *t);
void FreeRpcMsg(RPC_MSG *t);
void InRpcWinVer(RPC_WINVER *t, PACK *p);
void OutRpcWinVer(PACK *p, RPC_WINVER *t);



#endif	// ADMIN_H


