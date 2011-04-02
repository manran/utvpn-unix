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

// Cedar.h
// Cedar.c のヘッダ

#ifndef	CEDAR_H
#define	CEDAR_H


//////////////////////////////////////////////////////////////////////
// 
// 製品情報関連定数
// 
//////////////////////////////////////////////////////////////////////

#define	bool	UINT
#define	BOOL	UINT

// バージョン番号
#define	CEDAR_VER					101

// ビルド番号
#define	CEDAR_BUILD					7101

// ベータ番号
//#define	BETA_NUMBER					2

// ビルド担当者の名前を指定
#ifndef	BUILDER_NAME
#define	BUILDER_NAME		"yagi"
#endif	// BUILDER_NAME

// ビルドした場所を指定
#ifndef	BUILD_PLACE
#define	BUILD_PLACE			"pc25"
#endif	// BUILD_PLACE

// ビルド日時を指定
#define	BUILD_DATE_Y		2010
#define	BUILD_DATE_M		6
#define	BUILD_DATE_D		27
#define	BUILD_DATE_HO		18
#define	BUILD_DATE_MI		40
#define	BUILD_DATE_SE		28

// 許容する時差
#define	ALLOW_TIMESTAMP_DIFF		(UINT64)(3 * 24 * 60 * 60 * 1000)

// SoftEther UT-VPN シリーズ製品名
#define	CEDAR_PRODUCT_STR			"UT-VPN"

// Server 製品名
#define	CEDAR_SERVER_STR			"UT-VPN Server"

// Bridge 製品名
#define	CEDAR_BRIDGE_STR			"UT-VPN Bridge"

// Server 製品名 (ベータ)
#define	CEDAR_BETA_SERVER			"UT-VPN Server Pre Release"

// VPN Server Manager 製品名
#define	CEDAR_MANAGER_STR			"UT-VPN Server Manager"

// VPN Command-Line Admin Tool 製品名
#define	CEDAR_CUI_STR				"UT-VPN Command-Line Admin Tool"

// VPN User-mode Router 製品名
#define	CEDAR_ROUTER_STR			"UT-VPN User-mode Router"

// VPN Client 製品名
#define	CEDAR_CLIENT_STR			"UT-VPN Client"

// VPN Client Manager 製品名
#define CEDAR_CLIENT_MANAGER_STR	"UT-VPN Client Connection Manager"

// VPN Server のカスケード接続時の製品名
#define	CEDAR_SERVER_LINK_STR		"UT-VPN Server (Cascade Mode)"

// VPN Server のサーバーファーム RPC 接続時の製品名
#define	CEDAR_SERVER_FARM_STR		"UT-VPN Server (Cluster RPC Mode)"


// IDS 検出用シグネチャの指定
#define	CEDAR_SIGNATURE_STR			"SE-UTVPN-PROTOCOL"

// スマートカードのデフォルトの RSA 証明書名
#define	SECURE_DEFAULT_CERT_NAME	"VPN_RSA_CERT"

// スマートカードのデフォルトの RSA 秘密鍵名
#define	SECURE_DEFAULT_KEY_NAME		"VPN_RSA_KEY"

// 8 文字の非表示パスワード文字列
#define	HIDDEN_PASSWORD				"********"



//////////////////////////////////////////////////////////////////////
// 
// 各種文字列の最大長の定義
// 
//////////////////////////////////////////////////////////////////////

#define	MAX_ACCOUNT_NAME_LEN		255		// 最大アカウント名長
#define	MAX_USERNAME_LEN			255		// ユーザー名最大長
#define	MAX_PASSWORD_LEN			255		// パスワード名最大長
#define	MAX_HOST_NAME_LEN			255		// ホスト名最大長
#define	MAX_PROXY_USERNAME_LEN		255		// プロキシユーザー名最大長
#define	MAX_PROXY_PASSWORD_LEN		255		// プロキシパスワード最大長
#define	MAX_SERVER_STR_LEN			255		// サーバー文字列最大長
#define	MAX_CLIENT_STR_LEN			255		// クライアント文字列最大長
#define	MAX_HUBNAME_LEN				255		// HUB 名最大長
#define	MAX_SESSION_NAME_LEN		255		// セッション名最大長
#define	MAX_CONNECTION_NAME_LEN		255		// コネクション名最大長
#define	MAX_DEVICE_NAME_LEN			31		// デバイス名最大長
#define	MAX_DEVICE_NAME_LEN_9X		4		// Win9x での仮想 LAN カード名最大長
#define	MAX_ACCESSLIST_NOTE_LEN		255		// アクセスリストのメモ最大長
#define	MAX_SECURE_DEVICE_FILE_LEN	255		// セキュアデバイス内ファイル名最大長
#define	MAX_ADMIN_OPTION_NAME_LEN	63		// 管理オプション名


//////////////////////////////////////////////////////////////////////
// 
// サーバーおよびセッション管理関連定数
// 
//////////////////////////////////////////////////////////////////////

#define	SERVER_MAX_SESSIONS			4096	// サーバーがサポートする最大セッション数
#define SERVER_MAX_SESSIONS_FOR_64BIT	100000	// サーバーがサポートする最大セッション数 (64 bit)
#define	NAT_MAX_SESSIONS			4096	// NAT がサポートする最大セッション数
#define	MAX_HUBS					4096	// 仮想 HUB の最大数 (32 bit)
#define MAX_HUBS_FOR_64BIT			100000	// 仮想 HUB の最大数 (64 bit)
#define	MAX_ACCESSLISTS				4096	// アクセスリストの最大数
#define	MAX_USERS					10000	// 最大ユーザー数
#define	MAX_GROUPS					10000	// 最大グループ数
#define	MAX_MAC_TABLES				65536	// 最大 MAC アドレステーブル数
#define	MAX_IP_TABLES				65536	// 最大 IP アドレステーブル数
#define	MAX_HUB_CERTS				4096	// 登録できるルート CA 最大数
#define	MAX_HUB_CRLS				4096	// 登録できる CRL 最大数
#define	MAX_HUB_ACS					4096	// 登録できる AC 最大数
#define	MAX_HUB_LINKS				128		// 登録できるカスケード接続最大数
#define	MAX_HUB_ADMIN_OPTIONS		4096	// 登録できる仮想 HUB 管理オプション最大数

#define	MAX_PACKET_SIZE				1560	// 最大パケットサイズ
#define	UDP_BUF_SIZE				(32 * 1024) // UDP パケットサイズの目安

#define	MAX_SEND_SOCKET_QUEUE_SIZE	(1600 * 1600 * 1)	// 最大送信キューサイズ
#define	MIN_SEND_SOCKET_QUEUE_SIZE	(1600 * 200 * 1)
#define	MAX_SEND_SOCKET_QUEUE_NUM	128		// 最大送信キュー数
#define	MAX_TCP_CONNECTION			32		// 最大 TCP コネクション数
#define	SELECT_TIME					256
#define	SELECT_TIME_FOR_NAT			30
#define	SELECT_TIME_FOR_DELAYED_PKT	1		// 遅延パケットがある場合
#define	MAX_STORED_QUEUE_NUM		1024		// セッションごとにストアできるキューの数
#define	MAX_BUFFERING_PACKET_SIZE	(1600 * 1600)	// バッファリング可能なパケットサイズの最大値

#define	TIMEOUT_MIN					(5 * 1000)	// 最小タイムアウト秒数
#define	TIMEOUT_MAX					(60 * 1000)	// 最大タイムアウト秒数
#define	TIMEOUT_DEFAULT				(30 * 1000) // デフォルトのタイムアウト秒数
#define	CONNECTING_TIMEOUT			(15 * 1000)	// 接続中のタイムアウト秒数
#define	CONNECTING_TIMEOUT_PROXY	(4 * 1000)	// 接続中のタイムアウト秒数 (Proxy)
#define	CONNECTING_POOLING_SPAN		(3 * 1000) // 接続中のポーリング間隔
#define	MIN_RETRY_INTERVAL			(5 * 1000)		// 最小リトライ間隔
#define	MAX_RETRY_INTERVAL			(300 * 1000)	// 最大リトライ間隔
#define	RETRY_INTERVAL_SPECIAL		(60 * 1000)		// 特別な場合の再接続間隔

#define	MAC_MIN_LIMIT_COUNT			3		// 最小 MAC アドレス数制限値
#define	IP_MIN_LIMIT_COUNT			4		// 最小 IPv4 アドレス数制限値
#define	IP_MIN_LIMIT_COUNT_V6		5		// 最小 IPv6 アドレス数制限値
#define	IP_LIMIT_WHEN_NO_ROUTING_V6	15		// NoRouting ポリシーが有効な場合の IPv6 アドレス数制限値

#define	MAC_TABLE_EXCLUSIVE_TIME	(13 * 1000)			// MAC アドレスを占有することができる期間
#define	IP_TABLE_EXCLUSIVE_TIME		(13 * 1000)			// IP アドレスを占有することができる期間
#define	MAC_TABLE_EXPIRE_TIME		(600 * 1000)			// MAC アドレステーブル有効期限
#define	IP_TABLE_EXPIRE_TIME		(60 * 1000)			// IP アドレステーブル有効期限
#define	IP_TABLE_EXPIRE_TIME_DHCP	(5 * 60 * 1000)		// IP アドレステーブル有効期限 (DHCP の場合)
#define	HUB_ARP_SEND_INTERVAL		(5 * 1000)			// ARP パケット送信間隔 (生存チェック)

#define	LIMITER_SAMPLING_SPAN		1000	// トラフィック制限装置のサンプリング間隔

#define	STORM_CHECK_SPAN			500		// ブロードキャストストームチェック間隔
#define	STORM_DISCARD_VALUE_START	3		// ブロードキャストパケット破棄値開始値
#define	STORM_DISCARD_VALUE_END		1024	// ブロードキャストパケット破棄値終了値

#define	KEEP_INTERVAL_MIN			5		// パケット送出間隔最小値
#define	KEEP_INTERVAL_DEFAULT		50		// パケット送出間隔デフォルト値
#define	KEEP_INTERVAL_MAX			600		// パケット送出間隔最大値
#define KEEP_TCP_TIMEOUT			1000	// TCP タイムアウト値

#define	TICKET_EXPIRES				(60 * 1000)	// チケットの有効期限


#define	FARM_BASE_POINT				100000		// クラスタ得点の基準値
#define	FARM_DEFAULT_WEIGHT			100			// 標準の性能基準比


// HTTPS サーバー / クライアント関連文字列定数
#define	DEFAULT_USER_AGENT	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)"
#define	DEFAULT_ACCEPT		"image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/msword, application/vnd.ms-powerpoint, application/vnd.ms-excel, */*"
#define	DEFAULT_ENCODING	"gzip, deflate"
#define	HTTP_CONTENT_TYPE	"text/html; charset=iso-8859-1"
#define	HTTP_CONTENT_TYPE2	"application/octet-stream"
#define	HTTP_CONTENT_TYPE3	"image/jpeg"
#define	HTTP_CONTENT_TYPE4	"text/html"
#define	HTTP_CONTENT_TYPE5	"message/rfc822"
#define	HTTP_KEEP_ALIVE		"timeout=15; max=19"
#define	HTTP_VPN_TARGET		"/vpnsvc/vpn.cgi"
#define	HTTP_VPN_TARGET2	"/vpnsvc/connect.cgi"
#define HTTP_VPN_TARGET_POSTDATA	"VPNCONNECT"
#define	HTTP_SAITAMA		"/saitama.jpg"
#define	HTTP_PICTURES		"/picture"

#define	SE_UDP_SIGN			"SE2P"		// 未使用 (旧 UDP モードのみ)

// トラフィック情報更新間隔
#define	INCREMENT_TRAFFIC_INTERVAL		(10 * 1000)

// クライアント セッションの状態
#define	CLIENT_STATUS_CONNECTING	0		// 接続中
#define	CLIENT_STATUS_NEGOTIATION	1		// ネゴシエーション中
#define	CLIENT_STATUS_AUTH			2		// ユーザー認証中
#define	CLIENT_STATUS_ESTABLISHED	3		// 接続完了
#define	CLIENT_STATUS_RETRY			4		// リトライまで待機中
#define	CLIENT_STATUS_IDLE			5		// アイドル状態

// ファイル転送時に一度に転送するブロック
#define	FTP_BLOCK_SIZE				(640 * 1024)

// syslog 設定
#define SYSLOG_NONE							0		// syslog を使わない
#define SYSLOG_SERVER_LOG					1		// サーバーログのみ
#define SYSLOG_SERVER_AND_HUB_SECURITY_LOG	2		// サーバーと仮想 HUB セキュリティログ
#define SYSLOG_SERVER_AND_HUB_ALL_LOG		3		// サーバー、仮想 HUB セキュリティおよびパケットログ

#define SYSLOG_PORT					514			// syslog ポート番号
#define SYSLOG_POLL_IP_INTERVAL		(UINT64)(3600 * 1000)	// IP アドレスを調べる間隔
#define	SYSLOG_POLL_IP_INTERVAL_NG	(UINT64)(60 * 1000)	// IP アドレスを調べる間隔 (前回失敗時)

//////////////////////////////////////////////////////////////////////
// 
// コネクション関連の定数
// 
//////////////////////////////////////////////////////////////////////

// インターネット接続維持機能 (KeepAlive)

#define	KEEP_RETRY_INTERVAL		(60 * 1000)			// 接続失敗時の再接続間隔
#define	KEEP_MIN_PACKET_SIZE	1					// 最小パケットサイズ
#define	KEEP_MAX_PACKET_SIZE	128					// 最大パケットサイズ
#define	KEEP_POLLING_INTERVAL	250					// KEEP ポーリング間隔

// 定数
#define	RECV_BUF_SIZE				65536			// 一度に受信するバッファサイズ

// プロキシの種類
#define	PROXY_DIRECT			0	// 直接 TCP 接続
#define	PROXY_HTTP				1	// HTTP プロキシサーバー経由接続
#define	PROXY_SOCKS				2	// SOCKS プロキシサーバー経由接続

// データの流れる方向
#define	TCP_BOTH				0	// 双方向
#define	TCP_SERVER_TO_CLIENT	1	// サーバー -> クライアント方向のみ
#define	TCP_CLIENT_TO_SERVER	2	// クライアント -> サーバー方向のみ

// コネクションの種類
#define	CONNECTION_TYPE_CLIENT			0	// クライアント
#define	CONNECTION_TYPE_INIT			1	// 初期化中
#define	CONNECTION_TYPE_LOGIN			2	// ログインコネクション
#define	CONNECTION_TYPE_ADDITIONAL		3	// 追加接続コネクション
#define	CONNECTION_TYPE_FARM_RPC		4	// サーバーファーム用 RPC
#define	CONNECTION_TYPE_ADMIN_RPC		5	// 管理用 RPC
#define	CONNECTION_TYPE_ENUM_HUB		6	// HUB 列挙
#define	CONNECTION_TYPE_PASSWORD		7	// パスワード変更

// プロトコル
#define	CONNECTION_TCP					0	// TCP プロトコル
#define	CONNECTION_UDP					1	// UDP プロトコル
#define	CONNECTION_HUB_LAYER3			6	// Layer-3 スイッチ セッション
#define	CONNECTION_HUB_BRIDGE			7	// Bridge セッション
#define	CONNECTION_HUB_SECURE_NAT		8	// Secure NAT セッション
#define	CONNECTION_HUB_LINK_SERVER		9	// HUB リンクセッション


// 状態
#define	CONNECTION_STATUS_ACCEPTED		0	// 接続を受け付けた (クライアント側)
#define	CONNECTION_STATUS_NEGOTIATION	1	// ネゴシエーション中
#define	CONNECTION_STATUS_USERAUTH		2	// ユーザー認証中
#define	CONNECTION_STATUS_ESTABLISHED	3	// コネクション確立済み
#define	CONNECTION_STATUS_CONNECTING	0	// 接続中 (クライアント側)

// KeepAlive パケットのマジックナンバー
#define	KEEP_ALIVE_MAGIC				0xffffffff
#define	MAX_KEEPALIVE_SIZE				512



//////////////////////////////////////////////////////////////////////
// 
// 仮想 HUB 関連の定数
// 
//////////////////////////////////////////////////////////////////////

#define	SE_HUB_MAC_ADDR_SIGN				0xAE					// 仮想 HUB MAC アドレスのサイン

// トラフィック差分値
#define	TRAFFIC_DIFF_USER		0		// ユーザー
#define	TRAFFIC_DIFF_HUB		1		// 仮想 HUB
#define	MAX_TRAFFIC_DIFF		30000	// 最大件数

// HUB の種類
#define	HUB_TYPE_STANDALONE			0	// スタンドアロン HUB
#define	HUB_TYPE_FARM_STATIC		1	// スタティック HUB
#define	HUB_TYPE_FARM_DYNAMIC		2	// ダイナミック HUB

// アクセスリストにおける遅延、ジッタ、パケットロス関係
#define	HUB_ACCESSLIST_DELAY_MAX	10000		// 最大遅延
#define	HUB_ACCESSLIST_JITTER_MAX	100			// 最大ジッタ
#define	HUB_ACCESSLIST_LOSS_MAX		100			// 最大パケットロス

// メッセージ関係
#define	HUB_MAXMSG_LEN				20000		// 最大メッセージ文字数



//////////////////////////////////////////////////////////////////////
// 
// ユーザー認証の種類
// 
//////////////////////////////////////////////////////////////////////

// サーバー側における定数
#define	AUTHTYPE_ANONYMOUS				0			// 匿名認証
#define	AUTHTYPE_PASSWORD				1			// パスワード認証
#define	AUTHTYPE_USERCERT				2			// ユーザー証明書認証
#define	AUTHTYPE_ROOTCERT				3			// 信頼するルート証明期間が発行する証明書
#define	AUTHTYPE_RADIUS					4			// Radius 認証
#define	AUTHTYPE_NT						5			// Windows NT 認証
#define	AUTHTYPE_TICKET					99			// チケット認証

// クライアント側における定数
#define	CLIENT_AUTHTYPE_ANONYMOUS		0			// 匿名認証
#define	CLIENT_AUTHTYPE_PASSWORD		1			// パスワード認証
#define	CLIENT_AUTHTYPE_PLAIN_PASSWORD	2			// プレーンパスワード認証
#define	CLIENT_AUTHTYPE_CERT			3			// 証明書認証
#define	CLIENT_AUTHTYPE_SECURE			4			// セキュアデバイス認証

// Radius 関係
#define	RADIUS_DEFAULT_PORT		1812			// デフォルトのポート番号
#define	RADIUS_RETRY_INTERVAL	500				// 再送間隔
#define	RADIUS_RETRY_TIMEOUT	(10 * 1000)		// タイムアウト時間



//////////////////////////////////////////////////////////////////////
// 
// TCP リスナー関係の定数
// 
//////////////////////////////////////////////////////////////////////

// Listen に失敗した場合の再試行回数
#define	LISTEN_RETRY_TIME			(2 * 1000)		// 普通に Listen に失敗した場合
#define LISTEN_RETRY_TIME_NOIPV6	(60 * 1000)		// IPv6 サポートが無効な場合


// リスナーの使用するプロトコル
#define	LISTENER_TCP				0		// TCP/IP
#define	LISTENER_UDP				1		// UDP/IP

// リスナーの状態
#define	LISTENER_STATUS_TRYING		0		// 試行中
#define	LISTENER_STATUS_LISTENING	1		// Listen 中

// 最大の UDP パケットサイズ
#define	UDP_PACKET_SIZE				65536

// 標準の IP アドレスごとのコネクション数
#define DEFAULT_MAX_CONNECTIONS_PER_IP	256
#define MIN_MAX_CONNECTIONS_PER_IP	10		// 最小値

// 許容される未処理のコネクション数
#define	DEFAULT_MAX_UNESTABLISHED_CONNECTIONS	1000
#define	MIN_MAX_UNESTABLISHED_CONNECTIONS	30	// 最小値


//////////////////////////////////////////////////////////////////////
// 
// ログ関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define	LOG_ENGINE_SAVE_START_CACHE_COUNT	100000		// 強制的に保存を開始する数
#define	LOG_ENGINE_BUFFER_CACHE_SIZE_MAX	(10 * 1024 * 1024)	// 書き込みキャッシュサイズ

// ファイル名などの定数
#define	SERVER_LOG_DIR_NAME			"@server_log"
#define	BRIDGE_LOG_DIR_NAME			SERVER_LOG_DIR_NAME
#define	SERVER_LOG_PERFIX			"vpn"

#define	HUB_SECURITY_LOG_DIR_NAME	"@security_log"
#define	HUB_SECURITY_LOG_FILE_NAME	"@security_log/%s"
#define	HUB_SECURITY_LOG_PREFIX		"sec"
#define	HUB_PACKET_LOG_DIR_NAME		"@packet_log"
#define	HUB_PACKET_LOG_FILE_NAME	"@packet_log/%s"
#define	HUB_PACKET_LOG_PREFIX		"pkt"

#define	NAT_LOG_DIR_NAME			"@secure_nat_log"
#define	NAT_LOG_FILE_NAME			"@secure_nat_log/%s"
#define	NAT_LOG_PREFIX				"snat"

#define	CLIENT_LOG_DIR_NAME			"@client_log"
#define	CLIENT_LOG_PREFIX			"client"

// パケットログ設定
#define	NUM_PACKET_LOG				16
#define	PACKET_LOG_TCP_CONN			0		// TCP コネクションログ
#define	PACKET_LOG_TCP				1		// TCP パケットログ
#define	PACKET_LOG_DHCP				2		// DHCP ログ
#define	PACKET_LOG_UDP				3		// UDP ログ
#define	PACKET_LOG_ICMP				4		// ICMP ログ
#define	PACKET_LOG_IP				5		// IP ログ
#define	PACKET_LOG_ARP				6		// ARP ログ
#define	PACKET_LOG_ETHERNET			7		// Ethernet ログ

#define	PACKET_LOG_NONE				0		// 保存しない
#define	PACKET_LOG_HEADER			1		// ヘッダのみ
#define	PACKET_LOG_ALL				2		// データも保存する

// ログ切り替えのタイミング
#define	LOG_SWITCH_NO				0		// 切り替え無し
#define	LOG_SWITCH_SECOND			1		// 1 秒単位
#define	LOG_SWITCH_MINUTE			2		// 1 分単位
#define	LOG_SWITCH_HOUR				3		// 1 時間単位
#define	LOG_SWITCH_DAY				4		// 1 日単位
#define	LOG_SWITCH_MONTH			5		// 1 ヶ月単位

// ディスクの空き容量の最小サイズ
#define	DISK_FREE_SPACE_MIN			1048576	// 1 MBytes
#define	DISK_FREE_SPACE_DEFAULT		(DISK_FREE_SPACE_MIN * 100)	// 100 Mbytes

// 空き容量をチェックする間隔
#define	DISK_FREE_CHECK_INTERVAL	(5 * 60 * 1000)

// 簡易ログ
#define TINY_LOG_DIRNAME			"@tiny_log"
#define TINY_LOG_FILENAME			"@tiny_log/%04u%02u%02u_%02u%02u%02u.log"


//////////////////////////////////////////////////////////////////////
// 
// Carrier Edition 関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define CE_SNAPSHOT_INTERVAL		((UINT64)(3600 * 1000))
//#define CE_SNAPSHOT_INTERVAL		((UINT64)(3000))
#define CE_SNAPSHOT_POLLING_INTERVAL	(1 * 1000)
#define CE_SNAPSHOT_POLLING_INTERVAL_LICENSE	(30 * 1000)
#define CE_SNAPSHOT_DIR_NAME		"@carrier_log"
#define CE_SNAPSHOT_PREFIX			"carrier"


//////////////////////////////////////////////////////////////////////
// 
// 通信プロトコル関係の定数
// 
//////////////////////////////////////////////////////////////////////

// 管理者ユーザー名
#define	ADMINISTRATOR_USERNAME		"administrator"
// HTTP ヘッダの 1 行のサイズの最大値
#define	HTTP_HEADER_LINE_MAX_SIZE	4096
// PACK に含める乱数サイズの最大値
#define	HTTP_PACK_RAND_SIZE_MAX		1000
// ランダムサイズの最大値
#define	RAND_SIZE_MAX				4096
// ランダムサイズキャッシュの有効期限
#define	RAND_SIZE_CACHE_EXPIRE		(24 * 60 * 60 * 1000)
// 管理許可 IP アドレスリストファイル名
#define	ADMINIP_TXT					"@adminip.txt"

#define NON_SSL_MIN_COUNT			60
#define NON_SSL_ENTRY_EXPIRES		(60 * 60 * 1000)

//////////////////////////////////////////////////////////////////////
// 
// カスケード接続関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define	LINK_DEVICE_NAME		"_SEHUBLINKCLI_"
#define	LINK_USER_NAME			"link"
#define	LINK_USER_NAME_PRINT	"Cascade"



//////////////////////////////////////////////////////////////////////
// 
// SecureNAT 接続関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define	SNAT_DEVICE_NAME		"_SEHUBSECURENAT_"
#define	SNAT_USER_NAME			"securenat"
#define	SNAT_USER_NAME_PRINT	"SecureNAT"



//////////////////////////////////////////////////////////////////////
// 
// Bridge 接続関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define	BRIDGE_DEVICE_NAME				"_SEHUBBRIDGE_"
#define	BRIDGE_USER_NAME				"localbridge"
#define	BRIDGE_USER_NAME_PRINT			"Local Bridge"
#define	BRIDGE_TRY_SPAN					1000
#define	BRIDGE_NUM_DEVICE_CHECK_SPAN	(5 * 60 * 1000)
#define BRIDGE_NETWORK_CONNECTION_STR	L"%s [%S]"



//////////////////////////////////////////////////////////////////////
// 
// EtherLogger 関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define	EL_ADMIN_PORT			22888
#define	EL_CONFIG_FILENAME		"@etherlogger.config"
#define	EL_PACKET_LOG_DIR_NAME	"@etherlogger_log"
#define	EL_PACKET_LOG_FILE_NAME	"@etherlogger_log/%s"
#define	EL_PACKET_LOG_PREFIX	"pkt"
#define	EL_LICENSE_CHECK_SPAN	(10 * 1000)



//////////////////////////////////////////////////////////////////////
// 
// Layer-3 Switch 関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define	MAX_NUM_L3_SWITCH		4096
#define	MAX_NUM_L3_IF			4096
#define	MAX_NUM_L3_TABLE		4096



//////////////////////////////////////////////////////////////////////
// 
// User-mode Router 関係の定数
// 
//////////////////////////////////////////////////////////////////////

#define	ARP_ENTRY_EXPIRES			(30 * 1000)		// ARP テーブル有効期限
#define	ARP_ENTRY_POLLING_TIME		(1 * 1000)		// ARP テーブル清掃タイマ
#define	ARP_REQUEST_TIMEOUT			(200)			// ARP リクエストタイムアウト時間
#define	ARP_REQUEST_GIVEUP			(5 * 1000)		// ARP リクエストの送信を諦める時刻
#define	IP_WAIT_FOR_ARP_TIMEOUT		(5 * 1000)		// IP パケットが ARP テーブルを待つ合計時間
#define	IP_COMBINE_TIMEOUT			(10 * 1000)		// IP パケットの結合タイムアウト
#define	NAT_TCP_MAX_TIMEOUT			(2000000 * 1000)	// 最大 TCP セッションタイムアウト秒数
#define	NAT_UDP_MAX_TIMEOUT			(2000000 * 1000)	// 最大 UDP セッションタイムアウト秒数
#define	NAT_TCP_MIN_TIMEOUT			(5 * 60 * 1000)		// 最小 TCP セッションタイムアウト秒数
#define	NAT_UDP_MIN_TIMEOUT			(10 * 1000)			// 最小 UDP セッションタイムアウト秒数
#define	NAT_TCP_RECV_WINDOW_SIZE	64512				// TCP 受信ウインドウサイズ
#define	NAT_TCP_SYNACK_SEND_TIMEOUT	250					// TCP SYN+ACK 送信間隔
#define	NAT_SEND_BUF_SIZE			(64 * 1024)			// TCP 送信バッファサイズ
#define	NAT_RECV_BUF_SIZE			(64 * 1024)			// TCP 受信バッファサイズ
#define	NAT_TMPBUF_SIZE				(128 * 1024)		// TCP 一時メモリ領域サイズ
#define	NAT_ACK_KEEPALIVE_SPAN		(5 * 1000)			// TCP キープアライブ用 ACK 送信間隔
#define	NAT_INITIAL_RTT_VALUE		500					// 初期 RTT 値
#define	NAT_FIN_SEND_INTERVAL		1000				// FIN 送信間隔
#define	NAT_FIN_SEND_MAX_COUNT		5					// 合計 FIN 送信数
#define	NAT_DNS_PROXY_PORT			53					// DNS プロキシポート番号
#define	NAT_DNS_RESPONSE_TTL		(20 * 60)			// DNS 応答の TTL
#define	NAT_DHCP_SERVER_PORT		67					// DHCP サーバーポート番号
#define	DHCP_MIN_EXPIRE_TIMESPAN	(15 * 1000)			// DHCP 最小有効期限
#define	DHCP_POLLING_INTERVAL		1000				// DHCP ポーリング間隔
#define	X32							((UINT64)4294967296ULL)	// 32bit + 1
#define	NAT_DNS_QUERY_TIMEOUT		(512)				// DNS クエリのタイムアウト値

// ビーコン送信間隔
#define	BEACON_SEND_INTERVAL		(5 * 1000)

// IP パケットの結合用のキューで許容される合計サイズ クォータ
#define	IP_COMBINE_WAIT_QUEUE_SIZE_QUOTA	(50 * 1024 * 1024)

// ヘッダサイズ定数
#define	MAC_HEADER_SIZE				(sizeof(MAC_HEADER))
#define	ARP_HEADER_SIZE				(sizeof(ARPV4_HEADER))
#define	IP_HEADER_SIZE				(sizeof(IPV4_HEADER))
#define	TCP_HEADER_SIZE				(sizeof(TCP_HEADER))
#define	UDP_HEADER_SIZE				(sizeof(UDP_HEADER))

// データ最大サイズ定数
#define	MAX_L3_DATA_SIZE			(1500)
#define	MAX_IP_DATA_SIZE			(MAX_L3_DATA_SIZE - IP_HEADER_SIZE)
#define	MAX_TCP_DATA_SIZE			(MAX_IP_DATA_SIZE - TCP_HEADER_SIZE)
#define	MAX_UDP_DATA_SIZE			(MAX_IP_DATA_SIZE - UDP_HEADER_SIZE)
#define	MAX_IP_DATA_SIZE_TOTAL		(65535)

// IP パケットオプション定数
#define	DEFAULT_IP_TOS				0				// IP ヘッダの TOS
#define	DEFAULT_IP_TTL				128				// IP ヘッダの TTL

// NAT セッションの種類
#define	NAT_TCP						0		// TCP NAT
#define	NAT_UDP						1		// UDP NAT
#define	NAT_DNS						2		// DNS NAT

// NAT セッションの状態
#define	NAT_TCP_CONNECTING			0		// 接続中
#define	NAT_TCP_SEND_RESET			1		// RST を送信する (接続失敗または切断)
#define	NAT_TCP_CONNECTED			2		// 接続完了
#define	NAT_TCP_ESTABLISHED			3		// 接続確立済み
#define	NAT_TCP_WAIT_DISCONNECT		4		// ソケット切断を待機

// DHCP クライアント動作
#define	DHCP_DISCOVER		1
#define	DHCP_REQUEST		3

// DHCP サーバー動作
#define	DHCP_OFFER			2
#define	DHCP_ACK			5
#define	DHCP_NACK			6

// DHCP 関係の定数
#define	DHCP_ID_MESSAGE_TYPE		0x35
#define	DHCP_ID_REQUEST_IP_ADDRESS	0x32
#define	DHCP_ID_HOST_NAME			0x0c
#define	DHCP_ID_SERVER_ADDRESS		0x36
#define	DHCP_ID_LEASE_TIME			0x33
#define	DHCP_ID_DOMAIN_NAME			0x0f
#define	DHCP_ID_SUBNET_MASK			0x01
#define	DHCP_ID_GATEWAY_ADDR		0x03
#define	DHCP_ID_DNS_ADDR			0x06




//////////////////////////////////////////////////////////////////////
// 
// UNIX 用仮想 LAN カード関係定数
// 
//////////////////////////////////////////////////////////////////////

#define	TAP_FILENAME_1				"/dev/net/tun"
#define	TAP_FILENAME_2				"/dev/tun"
#define	TAP_MACOS_FILENAME			"/dev/tap0"




//////////////////////////////////////////////////////////////////////
// 
// ライセンスデータベース関係
// 
//////////////////////////////////////////////////////////////////////

#define	LICENSE_MAX_PRODUCT_NAME_LEN	255				// ライセンス製品名の最大長
#define	LICENSE_KEYSTR_LEN				41				// ライセンスキーの長さ
#define	LICENSE_LICENSEID_STR_LEN		33				// ライセンス ID の長さ


// ライセンスされている製品エディション
#define	LICENSE_EDITION_VPN3_NO_LICENSE					0		// ライセンス無し
#define	LICENSE_EDITION_UTVPN_GPL						201		// UT-VPN (GPL)

// ライセンスステータス
#define	LICENSE_STATUS_OK				0		// 有効
#define	LICENSE_STATUS_EXPIRED			1		// 無効 (有効期限切れ)
#define	LICENSE_STATUS_ID_DIFF			2		// 無効 (システム ID 不一致)
#define	LICENSE_STATUS_DUP				3		// 無効 (重複)
#define	LICENSE_STATUS_INSUFFICIENT		4		// 無効 (必要な他のライセンスが不足)
#define	LICENSE_STATUS_COMPETITION		5		// 無効 (他のライセンスと競合)
#define	LICENSE_STATUS_NONSENSE			6		// 無効 (現在のエディションでは無意味)
#define	LICENSE_STATUS_CPU				7		// 無効 (CPU の種類が不一致)


#define	BIT_TO_BYTE(x)					(((x) + 7) / 8)
#define	BYTE_TO_BIT(x)					((x) * 8)


//////////////////////////////////////////////////////////////////////
// 
// エラーコード
// 
//////////////////////////////////////////////////////////////////////

#define	ERR_NO_ERROR					0	// エラー無し
#define	ERR_CONNECT_FAILED				1	// サーバーへの接続が失敗した
#define	ERR_SERVER_IS_NOT_VPN			2	// 接続先サーバーは VPN サーバーではない
#define	ERR_DISCONNECTED				3	// 接続が切断された
#define	ERR_PROTOCOL_ERROR				4	// プロトコルエラー
#define	ERR_CLIENT_IS_NOT_VPN			5	// 接続元クライアントは VPN クライアントではない
#define	ERR_USER_CANCEL					6	// ユーザーキャンセル
#define	ERR_AUTHTYPE_NOT_SUPPORTED		7	// 指定された認証方法はサポートされていない
#define	ERR_HUB_NOT_FOUND				8	// HUB が存在しない
#define	ERR_AUTH_FAILED					9	// 認証失敗
#define	ERR_HUB_STOPPING				10	// HUB が停止中
#define	ERR_SESSION_REMOVED				11	// セッションが削除された
#define	ERR_ACCESS_DENIED				12	// アクセス拒否
#define	ERR_SESSION_TIMEOUT				13	// セッションがタイムアウトした
#define	ERR_INVALID_PROTOCOL			14	// プロトコルが不正
#define	ERR_TOO_MANY_CONNECTION			15	// コネクション数が多すぎる
#define	ERR_HUB_IS_BUSY					16	// HUB のセッション数が多すぎる
#define	ERR_PROXY_CONNECT_FAILED		17	// プロキシサーバーへの接続が失敗した
#define	ERR_PROXY_ERROR					18	// プロキシエラーが発生
#define	ERR_PROXY_AUTH_FAILED			19	// プロキシサーバーでの認証に失敗
#define	ERR_TOO_MANY_USER_SESSION		20	// 同一ユーザーのセッション数が多すぎる
#define	ERR_LICENSE_ERROR				21	// ライセンスエラー
#define	ERR_DEVICE_DRIVER_ERROR			22	// デバイスドライバエラー
#define	ERR_INTERNAL_ERROR				23	// 内部エラー
#define	ERR_SECURE_DEVICE_OPEN_FAILED	24	// セキュアデバイスを開けなかった
#define	ERR_SECURE_PIN_LOGIN_FAILED		25	// PIN コードが違う
#define	ERR_SECURE_NO_CERT				26	// 指定された証明書が格納されていない
#define	ERR_SECURE_NO_PRIVATE_KEY		27	// 指定された秘密鍵が格納されていない
#define	ERR_SECURE_CANT_WRITE			28	// 書き込み失敗
#define	ERR_OBJECT_NOT_FOUND			29	// 指定されたオブジェクトが見つからない
#define	ERR_VLAN_ALREADY_EXISTS			30	// 指定された名前の仮想 LAN カードは存在する
#define	ERR_VLAN_INSTALL_ERROR			31	// 指定された仮想 LAN カードを生成できない
#define	ERR_VLAN_INVALID_NAME			32	// 指定された仮想 LAN カードの名前は不正
#define	ERR_NOT_SUPPORTED				33	// サポートされていない
#define	ERR_ACCOUNT_ALREADY_EXISTS		34	// アカウントはすでに存在する
#define	ERR_ACCOUNT_ACTIVE				35	// アカウントは動作中
#define	ERR_ACCOUNT_NOT_FOUND			36	// 指定されたアカウントは無い
#define	ERR_ACCOUNT_INACTIVE			37	// アカウントは停止中
#define	ERR_INVALID_PARAMETER			38	// パラメータが不正
#define	ERR_SECURE_DEVICE_ERROR			39	// セキュアデバイスの操作でエラーが発生した
#define	ERR_NO_SECURE_DEVICE_SPECIFIED	40	// セキュアデバイスが指定されていない
#define	ERR_VLAN_IS_USED				41	// 仮想 LAN カードはアカウントによって使用中
#define	ERR_VLAN_FOR_ACCOUNT_NOT_FOUND	42	// アカウントの仮想 LAN カードが見つからない
#define	ERR_VLAN_FOR_ACCOUNT_USED		43	// アカウントの仮想 LAN カードはすでに使用中
#define	ERR_VLAN_FOR_ACCOUNT_DISABLED	44	// アカウントの仮想 LAN カードは無効化されている
#define	ERR_INVALID_VALUE				45	// 値が不正
#define	ERR_NOT_FARM_CONTROLLER			46	// ファームコントローラではない
#define	ERR_TRYING_TO_CONNECT			47	// 接続を試行中
#define	ERR_CONNECT_TO_FARM_CONTROLLER	48	// ファームコントローラへの接続に失敗
#define	ERR_COULD_NOT_HOST_HUB_ON_FARM	49	// ファーム上に仮想 HUB を作成できなかった
#define	ERR_FARM_MEMBER_HUB_ADMIN		50	// ファームメンバで HUB を管理することはできない
#define	ERR_NULL_PASSWORD_LOCAL_ONLY	51	// 空文字のパスワードのためローカル接続のみ受付中
#define	ERR_NOT_ENOUGH_RIGHT			52	// 権利が不足している
#define	ERR_LISTENER_NOT_FOUND			53	// リスナーが見つからない
#define	ERR_LISTENER_ALREADY_EXISTS		54	// すでにリスナーが存在している
#define	ERR_NOT_FARM_MEMBER				55	// ファームメンバではない
#define	ERR_CIPHER_NOT_SUPPORTED		56	// 暗号化アルゴリズムがサポートされていない
#define	ERR_HUB_ALREADY_EXISTS			57	// HUB はすでに存在する
#define	ERR_TOO_MANY_HUBS				58	// HUB が多すぎる
#define	ERR_LINK_ALREADY_EXISTS			59	// リンクはすでに存在する
#define	ERR_LINK_CANT_CREATE_ON_FARM	60	// リンクはサーバーファーム上に作成できない
#define	ERR_LINK_IS_OFFLINE				61	// リンクはオフラインである
#define	ERR_TOO_MANY_ACCESS_LIST		62	// アクセスリストが多すぎる
#define	ERR_TOO_MANY_USER				63	// ユーザーが多すぎる
#define	ERR_TOO_MANY_GROUP				64	// グループが多すぎる
#define	ERR_GROUP_NOT_FOUND				65	// グループが見つからない
#define	ERR_USER_ALREADY_EXISTS			66	// ユーザーがすでに存在する
#define	ERR_GROUP_ALREADY_EXISTS		67	// グループがすでに存在する
#define	ERR_USER_AUTHTYPE_NOT_PASSWORD	68	// ユーザーの認証方法はパスワード認証ではない
#define	ERR_OLD_PASSWORD_WRONG			69	// 古いパスワードが間違っているかユーザーが存在しない
#define	ERR_LINK_CANT_DISCONNECT		73	// カスケード セッションは切断できない
#define	ERR_ACCOUNT_NOT_PRESENT			74	// VPN サーバーへの接続設定が未完了である
#define	ERR_ALREADY_ONLINE				75	// すでにオンラインである
#define	ERR_OFFLINE						76	// オフラインである
#define	ERR_NOT_RSA_1024				77	// RSA 1024bit 以外の証明書である
#define	ERR_SNAT_CANT_DISCONNECT		78	// SecureNAT セッションは切断できない
#define	ERR_SNAT_NEED_STANDALONE		79	// SecureNAT はスタンドアロン HUB でしか動作しない
#define	ERR_SNAT_NOT_RUNNING			80	// SecureNAT 機能が動作していない
#define	ERR_SE_VPN_BLOCK				81	// システム管理者向けブロックツールで停止された (廃止)
#define	ERR_BRIDGE_CANT_DISCONNECT		82	// Bridge セッションは切断できない
#define	ERR_LOCAL_BRIDGE_STOPPING		83	// Bridge 機能は停止している
#define	ERR_LOCAL_BRIDGE_UNSUPPORTED	84	// Bridge 機能がサポートされていない
#define	ERR_CERT_NOT_TRUSTED			85	// 接続先サーバーの証明書が信頼できない
#define	ERR_PRODUCT_CODE_INVALID		86	// 製品コードが違う
#define	ERR_VERSION_INVALID				87	// バージョンが違う
#define	ERR_CAPTURE_DEVICE_ADD_ERROR	88	// キャプチャデバイス追加失敗
#define	ERR_VPN_CODE_INVALID			89	// VPN コードが違う
#define	ERR_CAPTURE_NOT_FOUND			90	// キャプチャデバイスが見つからない
#define	ERR_LAYER3_CANT_DISCONNECT		91	// Layer-3 セッションは切断できない
#define	ERR_LAYER3_SW_EXISTS			92	// すでに同一の L3 スイッチが存在する
#define	ERR_LAYER3_SW_NOT_FOUND			93	// Layer-3 スイッチが見つからない
#define	ERR_INVALID_NAME				94	// 名前が不正
#define	ERR_LAYER3_IF_ADD_FAILED		95	// インターフェイスの追加に失敗した
#define	ERR_LAYER3_IF_DEL_FAILED		96	// インターフェイスの削除に失敗した
#define	ERR_LAYER3_IF_EXISTS			97	// 指定したインターフェイスはすでに存在する
#define	ERR_LAYER3_TABLE_ADD_FAILED		98	// ルーティングテーブルの追加に失敗した
#define	ERR_LAYER3_TABLE_DEL_FAILED		99	// ルーティングテーブルの削除に失敗した
#define	ERR_LAYER3_TABLE_EXISTS			100	// 指定したルーティングテーブルはすでに存在する
#define	ERR_BAD_CLOCK					101	// 時刻がおかしい
#define	ERR_LAYER3_CANT_START_SWITCH	102	// 仮想レイヤ 3 スイッチを開始できない
#define	ERR_CLIENT_LICENSE_NOT_ENOUGH	103	// クライアント接続ライセンス数不足
#define	ERR_BRIDGE_LICENSE_NOT_ENOUGH	104 // ブリッジ接続ライセンス数不足
#define	ERR_SERVER_CANT_ACCEPT			105	// 技術的な問題で Accept していない
#define	ERR_SERVER_CERT_EXPIRES			106	// 接続先 VPN サーバーの有効期限が切れている
#define	ERR_MONITOR_MODE_DENIED			107	// モニタポートモードは拒否された
#define	ERR_BRIDGE_MODE_DENIED			108	// ブリッジまたはルーティングモードは拒否された
#define	ERR_IP_ADDRESS_DENIED			109	// クライアント IP アドレスが拒否された
#define	ERR_TOO_MANT_ITEMS				110	// 項目数が多すぎる
#define	ERR_MEMORY_NOT_ENOUGH			111	// メモリ不足
#define	ERR_OBJECT_EXISTS				112	// オブジェクトはすでに存在している
#define	ERR_FATAL						113	// 致命的なエラーが発生した
#define	ERR_SERVER_LICENSE_FAILED		114	// サーバー側でライセンス違反が発生した
#define	ERR_SERVER_INTERNET_FAILED		115	// サーバー側がインターネットに接続されていない
#define	ERR_CLIENT_LICENSE_FAILED		116	// クライアント側でライセンス違反が発生した
#define	ERR_BAD_COMMAND_OR_PARAM		117	// コマンドまたはパラメータが不正
#define	ERR_INVALID_LICENSE_KEY			118	// ライセンスキー不正
#define	ERR_NO_VPN_SERVER_LICENSE		119	// VPN Server の有効なライセンスが無い
#define	ERR_NO_VPN_CLUSTER_LICENSE		120	// クラスタライセンスが無い
#define ERR_NOT_ADMINPACK_SERVER		121	// Administrator Pack ライセンスを持ったサーバーに接続しようとしていない
#define ERR_NOT_ADMINPACK_SERVER_NET	122	// Administrator Pack ライセンスを持ったサーバーに接続しようとしていない (.NET 用)
#define ERR_BETA_EXPIRES				123	// 接続先 VPN Server のベータ版の有効期限が切れている
#define ERR_BRANDED_C_TO_S				124 // 接続制限用のブランド化文字列が異なる(サーバ側での認証用)
#define ERR_BRANDED_C_FROM_S			125	// 接続制限用のブランド化文字列が異なる(クライアント側での認証用)
#define	ERR_AUTO_DISCONNECTED			126	// 一定時間が経過したため VPN セッションが切断された
#define	ERR_CLIENT_ID_REQUIRED			127	// クライアント ID が一致していない
#define	ERR_TOO_MANY_USERS_CREATED		128	// 作成されているユーザー数が多すぎる
#define	ERR_SUBSCRIPTION_IS_OLDER		129	// サブスクリプションの期限が VPN Server のビルド日時よりも前である
#define	ERR_UTVPN_NOT_SUPPORT_THIS_AUTH	130	// UT-VPN はこの認証方法を実装していない
#define	ERR_UTVPN_NOT_SUPPORT_THIS_FUNC	131	// UT-VPN はこの機能を実装していない


////////////////////////////
// 全般的に使用される構造体

// ネットワーク サービス
typedef struct NETSVC
{
	bool Udp;						// false=TCP, true=UDP
	UINT Port;						// ポート番号
	char *Name;						// 名称
} NETSVC;

// トラフィックデータエントリ
typedef struct TRAFFIC_ENTRY
{
	UINT64 BroadcastCount;			// ブロードキャストパケット数
	UINT64 BroadcastBytes;			// ブロードキャストバイト数
	UINT64 UnicastCount;			// ユニキャストカウント数
	UINT64 UnicastBytes;			// ユニキャストバイト数
} TRAFFIC_ENTRY;

// トラフィックデータ
typedef struct TRAFFIC
{
	TRAFFIC_ENTRY Send;				// 送信データ
	TRAFFIC_ENTRY Recv;				// 受信データ
} TRAFFIC;

// 非 SSL 接続元
typedef struct NON_SSL
{
	IP IpAddress;					// IP アドレス
	UINT64 EntryExpires;			// エントリの有効期限
	UINT Count;						// 接続回数
} NON_SSL;

// 簡易ログ保存
typedef struct TINY_LOG
{
	char FileName[MAX_PATH];		// ファイル名
	IO *io;							// ファイル
	LOCK *Lock;						// ロック
} TINY_LOG;

// CEDAR 構造体
typedef struct CEDAR
{
	LOCK *lock;						// ロック
	REF *ref;						// 参照カウンタ
	COUNTER *AcceptingSockets;		// Accept 中のソケット数
	UINT Type;						// 種類
	LIST *ListenerList;				// リスナーリスト
	LIST *HubList;					// HUB リスト
	LIST *ConnectionList;			// ネゴシエーション中のコネクションリスト
	LIST *CaList;					// CA のリスト
	volatile bool Halt;				// 停止フラグ
	COUNTER *ConnectionIncrement;	// コネクションインクリメントカウンタ
	X *ServerX;						// サーバー証明書
	K *ServerK;						// サーバー証明書の秘密鍵
	char *CipherList;				// 暗号化アルゴリズムのリスト
	UINT Version;					// バージョン情報
	UINT Build;						// ビルド番号
	char *ServerStr;				// サーバー文字列
	char *MachineName;				// コンピュータ名
	char *HttpUserAgent;			// HTTP ユーザーエージェント
	char *HttpAccept;				// HTTP Accept
	char *HttpAcceptLanguage;		// HTTP Accept Language
	char *HttpAcceptEncoding;		// HTTP Accept Encoding
	TRAFFIC *Traffic;				// トラフィック情報
	LOCK *TrafficLock;				// トラフィック情報ロック
	LIST *UDPEntryList;				// UDP エントリリスト
	COUNTER *CurrentSessions;		// 現在のセッション数
	COUNTER *CurrentTcpConnections;	// 現在の TCP コネクション数
	LIST *NetSvcList;				// ネットワークサービスリスト
	char *VerString;				// バージョン文字列
	char *BuildInfo;				// ビルド情報
	struct CLIENT *Client;			// クライアント
	struct SERVER *Server;			// サーバー
	UINT64 CreatedTick;				// 生成日時
	bool CheckExpires;				// 有効期限をチェックする
	LIST *TrafficDiffList;			// トラフィック差分リスト
	struct LOG *DebugLog;			// デバッグログ
	UCHAR UniqueId[16];				// ユニーク ID
	LIST *LocalBridgeList;			// ローカルブリッジリスト
	bool Bridge;					// ブリッジ版
	LIST *L3SwList;					// Layer-3 スイッチリスト
	COUNTER *AssignedClientLicense;	// 割り当て済みクライアントライセンス数
	COUNTER *AssignedBridgeLicense;	// 割り当て済みブリッジライセンス数
	UINT64 LicenseViolationTick;	// ライセンス違反発生
	LIST *NonSslList;				// 非 SSL 接続リスト
	struct WEBUI *WebUI;			// WebUI サービス用データ
	UINT Beta;						// ベータ番号
	LOCK *CedarSuperLock;			// シーダー スーパー ロック！
	bool DisableIPv6Listener;		// IPv6 リスナーを無効にする
	UINT ClientId;					// クライアント ID
	UINT64 BuiltDate;				// ビルドされた日付
} CEDAR;

// CEDAR の種類
#define	CEDAR_CLIENT				0	// クライアント
#define	CEDAR_STANDALONE_SERVER		1	// スタンドアロンサーバー
#define	CEDAR_FARM_CONTROLLER		2	// サーバーファーム コントローラ
#define	CEDAR_FARM_MEMBER			3	// サーバーファーム メンバー


////////////////////////////
// ヘッダファイルの読み込み

// 型
#include <Cedar/CedarType.h>
// アカウントマネージャ
#include <Cedar/Account.h>
// リスナー モジュール
#include <Cedar/Listener.h>
// TCP/IP
#include <Cedar/TcpIp.h>
// ログ保存モジュール
#include <Cedar/Logging.h>
// コネクション管理
#include <Cedar/Connection.h>
// セッション管理
#include <Cedar/Session.h>
// RPC
#include <Cedar/Remote.h>
// HUB 管理
#include <Cedar/Hub.h>
// セキュリティアカウントマネージャ
#include <Cedar/Sam.h>
// プロトコル
#include <Cedar/Protocol.h>
// HUB 間リンク
#include <Cedar/Link.h>
// ユーザーモード仮想ホスト
#include <Cedar/Virtual.h>
// SecureNAT
#include <Cedar/SecureNAT.h>
// コンソール サービス
#include <Cedar/Console.h>
// vpncmd ユーティリティ
#include <Cedar/Command.h>

#ifdef	OS_WIN32
// Sen デバイスドライバ
#include <Sen/Sen.h>
#endif	// OS_WIN32

// Sen デバイスドライバ操作用ライブラリ
#include <Cedar/VLan.h>
// ブリッジ
#include <Cedar/Bridge.h>
// Layer-3 スイッチ
#include <Cedar/Layer3.h>
// テスト用仮想 LAN カード
#include <Cedar/NullLan.h>
// クライアント
#include <Cedar/Client.h>
/// サーバー
#include <Cedar/Server.h>
// ライセンスデータベース
#include <Cedar/Database.h>
// 管理 RPC
#include <Cedar/Admin.h>
// User-mode Router
#include <Cedar/Nat.h>

#ifdef	OS_WIN32

// Win32 ユーザーインターフェイス
#include <Cedar/WinUi.h>
// Win32 クライアント接続マネージャ
#include <Cedar/CM.h>
// Win32 Server Manager
#include <Cedar/SM.h>
// Win32 User-mode Router Manager
#include <Cedar/NM.h>
// Win32 Network Utility
#include <Cedar/UT.h>
// Win32 HTML 表示モジュール
#include <Cedar/Win32Html.h>

#endif




////////////////////////////
// 関数プロトタイプ

TRAFFIC *NewTraffic();
void FreeTraffic(TRAFFIC *t);
CEDAR *NewCedar(X *server_x, K *server_k);
void SetCedarVpnBridge(CEDAR *c);
void SetCedarCert(CEDAR *c, X *server_x, K *server_k);
void ReleaseCedar(CEDAR *c);
void CleanupCedar(CEDAR *c);
void StopCedar(CEDAR *c);
void AddListener(CEDAR *c, LISTENER *r);
void StopAllListener(CEDAR *c);
void AddTraffic(TRAFFIC *dst, TRAFFIC *diff);
void AddHub(CEDAR *c, HUB *h);
void DelHub(CEDAR *c, HUB *h);
void DelHubEx(CEDAR *c, HUB *h, bool no_lock);
void StopAllHub(CEDAR *c);
void StopAllConnection(CEDAR *c);
void AddConnection(CEDAR *cedar, CONNECTION *c);
UINT GetUnestablishedConnections(CEDAR *cedar);
void DelConnection(CEDAR *cedar, CONNECTION *c);
void SetCedarCipherList(CEDAR *cedar, char *name);
void InitCedar();
void FreeCedar();
void AddCa(CEDAR *cedar, X *x);
bool DeleteCa(CEDAR *cedar, UINT ptr);
bool CheckSignatureByCa(CEDAR *cedar, X *x);
bool CheckSignatureByCaLinkMode(SESSION *s, X *x);
X *FindCaSignedX(LIST *o, X *x);
void InitNetSvcList(CEDAR *cedar);
void FreeNetSvcList(CEDAR *cedar);
int CompareNetSvc(void *p1, void *p2);
char *GetSvcName(CEDAR *cedar, bool udp, UINT port);
void InitHiddenPassword(char *str, UINT size);
bool IsHiddenPasswordChanged(char *str);
UINT64 GetTrafficPacketSize(TRAFFIC *t);
UINT64 GetTrafficPacketNum(TRAFFIC *t);
void EnableDebugLog(CEDAR *c);
void StartCedarLog();
void StopCedarLog();
void CedarLog(char *str);
int CompareNoSslList(void *p1, void *p2);
void InitNoSslList(CEDAR *c);
void FreeNoSslList(CEDAR *c);
bool AddNoSsl(CEDAR *c, IP *ip);
void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec);
void DeleteOldNoSsl(CEDAR *c);
NON_SSL *SearchNoSslList(CEDAR *c, IP *ip);
bool IsInNoSsl(CEDAR *c, IP *ip);
void FreeTinyLog(TINY_LOG *t);
void WriteTinyLog(TINY_LOG *t, char *str);
TINY_LOG *NewTinyLog();
void GetWinVer(RPC_WINVER *v);
bool IsSupportedWinVer(RPC_WINVER *v);
bool IsLaterBuild(CEDAR *c, UINT64 t);


#endif	// CEDAR_H

