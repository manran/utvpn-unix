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

// Nat.h
// Nat.c のヘッダ

#ifndef	NAT_H
#define	NAT_H

// 定数
#define	NAT_CONFIG_FILE_NAME			"@vpn_router.config"	// NAT 設定ファイル
#define	DEFAULT_NAT_ADMIN_PORT			2828		// デフォルトの管理用ポート番号
#define	NAT_ADMIN_PORT_LISTEN_INTERVAL	1000		// 管理用ポートを開こうとする間隔
#define	NAT_FILE_SAVE_INTERVAL			(30 * 1000)	// 保存間隔


// NAT オブジェクト
struct NAT
{
	LOCK *lock;							// ロック
	UCHAR HashedPassword[SHA1_SIZE];	// 管理用パスワード
	VH_OPTION Option;					// オプション
	CEDAR *Cedar;						// Cedar
	UINT AdminPort;						// 管理用ポート番号
	bool Online;						// オンライン フラグ
	VH *Virtual;						// 仮想ホストオブジェクト
	CLIENT_OPTION *ClientOption;		// クライアントオプション
	CLIENT_AUTH *ClientAuth;			// クライアント認証データ
	CFG_RW *CfgRw;						// Config ファイル R/W
	THREAD *AdminAcceptThread;			// 管理用コネクション受付スレッド
	SOCK *AdminListenSock;				// 管理ポートソケット
	EVENT *HaltEvent;					// 停止イベント
	volatile bool Halt;					// 停止フラグ
	LIST *AdminList;					// 管理スレッドリスト
	X *AdminX;							// 管理用サーバー証明書
	K *AdminK;							// 管理用サーバー秘密鍵
	SNAT *SecureNAT;					// SecureNAT オブジェクト
};

// NAT 管理コネクション
struct NAT_ADMIN
{
	NAT *Nat;							// NAT
	SOCK *Sock;							// ソケット
	THREAD *Thread;						// スレッド
};

// RPC_DUMMY
struct RPC_DUMMY
{
	UINT DummyValue;
};

// RPC_NAT_STATUS
struct RPC_NAT_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB 名
	UINT NumTcpSessions;						// TCP セッション数
	UINT NumUdpSessions;						// UDP セッション数
	UINT NumDhcpClients;						// DHCP クライアント数
};

// RPC_NAT_INFO *
struct RPC_NAT_INFO
{
	char NatProductName[128];					// サーバー製品名
	char NatVersionString[128];					// サーバーバージョン文字列
	char NatBuildInfoString[128];				// サーバービルド情報文字列
	UINT NatVerInt;								// サーバーバージョン整数値
	UINT NatBuildInt;							// サーバービルド番号整数値
	char NatHostName[MAX_HOST_NAME_LEN + 1];	// サーバーホスト名
	OS_INFO OsInfo;								// OS 情報
	MEMINFO MemInfo;							// メモリ情報
};

// RPC_ENUM_NAT_ITEM
struct RPC_ENUM_NAT_ITEM
{
	UINT Id;									// ID
	UINT Protocol;								// プロトコル
	UINT SrcIp;									// 接続元 IP アドレス
	char SrcHost[MAX_HOST_NAME_LEN + 1];		// 接続元ホスト名
	UINT SrcPort;								// 接続元ポート番号
	UINT DestIp;								// 接続先 IP アドレス
	char DestHost[MAX_HOST_NAME_LEN + 1];		// 接続先ホスト名
	UINT DestPort;								// 接続先ポート番号
	UINT64 CreatedTime;							// 接続時刻
	UINT64 LastCommTime;						// 最終通信時刻
	UINT64 SendSize;							// 送信サイズ
	UINT64 RecvSize;							// 受信サイズ
	UINT TcpStatus;								// TCP 状態
};

// RPC_ENUM_NAT *
struct RPC_ENUM_NAT
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB 名
	UINT NumItem;								// アイテム数
	RPC_ENUM_NAT_ITEM *Items;					// アイテム
};

// RPC_ENUM_DHCP_ITEM
struct RPC_ENUM_DHCP_ITEM
{
	UINT Id;									// ID
	UINT64 LeasedTime;							// リース時刻
	UINT64 ExpireTime;							// 有効期限
	UCHAR MacAddress[6];						// MAC アドレス
	UCHAR Padding[2];							// パディング
	UINT IpAddress;								// IP アドレス
	UINT Mask;									// サブネットマスク
	char Hostname[MAX_HOST_NAME_LEN + 1];		// ホスト名
};

// RPC_ENUM_DHCP *
struct RPC_ENUM_DHCP
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB 名
	UINT NumItem;								// アイテム数
	RPC_ENUM_DHCP_ITEM *Items;					// アイテム
};


// 関数プロトタイプ
NAT *NiNewNat();
NAT *NiNewNatEx(SNAT *snat, VH_OPTION *o);
void NiFreeNat(NAT *n);
void NiInitConfig(NAT *n);
void NiFreeConfig(NAT *n);
void NiInitDefaultConfig(NAT *n);
void NiSetDefaultVhOption(NAT *n, VH_OPTION *o);
void NiClearUnsupportedVhOptionForDynamicHub(VH_OPTION *o, bool initial);
void NiWriteConfig(NAT *n);
void NiWriteVhOption(NAT *n, FOLDER *root);
void NiWriteVhOptionEx(VH_OPTION *o, FOLDER *root);
void NiWriteClientData(NAT *n, FOLDER *root);
void NiLoadVhOption(NAT *n, FOLDER *root);
void NiLoadVhOptionEx(VH_OPTION *o, FOLDER *root);
bool NiLoadConfig(NAT *n, FOLDER *root);
void NiLoadClientData(NAT *n, FOLDER *root);
void NiInitAdminAccept(NAT *n);
void NiFreeAdminAccept(NAT *n);
void NiListenThread(THREAD *thread, void *param);
void NiAdminThread(THREAD *thread, void *param);
void NiAdminMain(NAT *n, SOCK *s);
PACK *NiRpcServer(RPC *r, char *name, PACK *p);

RPC *NatAdminConnect(CEDAR *cedar, char *hostname, UINT port, void *hashed_password, UINT *err);
void NatAdminDisconnect(RPC *r);

void NtStartNat();
void NtStopNat();
void NtInit();
void NtFree();


UINT NtOnline(NAT *n, RPC_DUMMY *t);
UINT NtOffline(NAT *n, RPC_DUMMY *t);
UINT NtSetHostOption(NAT *n, VH_OPTION *t);
UINT NtGetHostOption(NAT *n, VH_OPTION *t);
UINT NtSetClientConfig(NAT *n, RPC_CREATE_LINK *t);
UINT NtGetClientConfig(NAT *n, RPC_CREATE_LINK *t);
UINT NtGetStatus(NAT *n, RPC_NAT_STATUS *t);
UINT NtGetInfo(NAT *n, RPC_NAT_INFO *t);
UINT NtEnumNatList(NAT *n, RPC_ENUM_NAT *t);
UINT NtEnumDhcpList(NAT *n, RPC_ENUM_DHCP *t);
UINT NtSetPassword(NAT *n, RPC_SET_PASSWORD *t);


UINT NcOnline(RPC *r, RPC_DUMMY *t);
UINT NcOffline(RPC *r, RPC_DUMMY *t);
UINT NcSetHostOption(RPC *r, VH_OPTION *t);
UINT NcGetHostOption(RPC *r, VH_OPTION *t);
UINT NcSetClientConfig(RPC *r, RPC_CREATE_LINK *t);
UINT NcGetClientConfig(RPC *r, RPC_CREATE_LINK *t);
UINT NcGetStatus(RPC *r, RPC_NAT_STATUS *t);
UINT NcGetInfo(RPC *r, RPC_NAT_INFO *t);
UINT NcEnumNatList(RPC *r, RPC_ENUM_NAT *t);
UINT NcEnumDhcpList(RPC *r, RPC_ENUM_DHCP *t);
UINT NcSetPassword(RPC *r, RPC_SET_PASSWORD *t);




void InRpcEnumDhcp(RPC_ENUM_DHCP *t, PACK *p);
void OutRpcEnumDhcp(PACK *p, RPC_ENUM_DHCP *t);
void FreeRpcEnumDhcp(RPC_ENUM_DHCP *t);
void InRpcEnumNat(RPC_ENUM_NAT *t, PACK *p);
void OutRpcEnumNat(PACK *p, RPC_ENUM_NAT *t);
void FreeRpcEnumNat(RPC_ENUM_NAT *t);
void InRpcNatInfo(RPC_NAT_INFO *t, PACK *p);
void OutRpcNatInfo(PACK *p, RPC_NAT_INFO *t);
void FreeRpcNatInfo(RPC_NAT_INFO *t);
void InRpcNatStatus(RPC_NAT_STATUS *t, PACK *p);
void OutRpcNatStatus(PACK *p, RPC_NAT_STATUS *t);
void FreeRpcNatStatus(RPC_NAT_STATUS *t);
void InVhOption(VH_OPTION *t, PACK *p);
void OutVhOption(PACK *p, VH_OPTION *t);
void InRpcDummy(RPC_DUMMY *t, PACK *p);
void OutRpcDummy(PACK *p, RPC_DUMMY *t);




#endif	// NAT_H


