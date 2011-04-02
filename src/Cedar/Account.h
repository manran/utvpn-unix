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

// Account.h
// Account.c のヘッダ

#ifndef	ACCOUNT_H
#define	ACCOUNT_H

// ポリシー項目
struct POLICY_ITEM
{
	UINT Index;
	bool TypeInt;
	bool AllowZero;
	UINT MinValue;
	UINT MaxValue;
	UINT DefaultValue;
	char *FormatStr;
};

// ポリシー
struct POLICY
{
	// ポリシー Ver 2.0
	bool Access;					// アクセスを許可
	bool DHCPFilter;				// DHCP パケットをフィルタリング (IPv4)
	bool DHCPNoServer;				// DHCP サーバーの動作を禁止 (IPv4)
	bool DHCPForce;					// DHCP が割り当てた IP アドレスを強制 (IPv4)
	bool NoBridge;					// ブリッジを禁止
	bool NoRouting;					// ルータ動作を禁止 (IPv4)
	bool CheckMac;					// MAC アドレスの重複を禁止
	bool CheckIP;					// IP アドレスの重複を禁止 (IPv4)
	bool ArpDhcpOnly;				// ARP・DHCP・ICMPv6 以外のブロードキャストを禁止
	bool PrivacyFilter;				// プライバシーフィルタモード
	bool NoServer;					// TCP/IP サーバーとしての動作を禁止 (IPv4)
	bool NoBroadcastLimiter;		// ブロードキャスト数を制限しない
	bool MonitorPort;				// モニタリングモードを許可
	UINT MaxConnection;				// TCP コネクション数の最大値
	UINT TimeOut;					// 通信タイムアウト時間
	UINT MaxMac;					// MAC アドレスの上限数
	UINT MaxIP;						// IP アドレスの上限数 (IPv4)
	UINT MaxUpload;					// アップロード帯域幅
	UINT MaxDownload;				// ダウンロード帯域幅
	bool FixPassword;				// ユーザーはパスワードを変更できない
	UINT MultiLogins;				// 多重ログイン制限数
	bool NoQoS;						// VoIP / QoS 対応機能の使用を禁止

	// ポリシー Ver 3.0
	bool RSandRAFilter;				// ルータ要請/広告パケットをフィルタリング (IPv6)
	bool RAFilter;					// ルータ広告パケットをフィルタリング (IPv6)
	bool DHCPv6Filter;				// DHCP パケットをフィルタリング (IPv6)
	bool DHCPv6NoServer;			// DHCP サーバーの動作を禁止 (IPv6)
	bool NoRoutingV6;				// ルータ動作を禁止 (IPv6)
	bool CheckIPv6;					// IP アドレスの重複を禁止 (IPv6)
	bool NoServerV6;				// TCP/IP サーバーとしての動作を禁止 (IPv6)
	UINT MaxIPv6;					// IP アドレスの上限数 (IPv6)
	bool NoSavePassword;			// VPN Client でパスワードの保存を禁止
	UINT AutoDisconnect;			// VPN Client を一定時間で自動切断
	bool FilterIPv4;				// IPv4 パケットをすべてフィルタリング
	bool FilterIPv6;				// IPv6 パケットをすべてフィルタリング
	bool FilterNonIP;				// 非 IP パケットをすべてフィルタリング
	bool NoIPv6DefaultRouterInRA;	// IPv6 ルータ広告からデフォルトルータ指定を削除
	bool NoIPv6DefaultRouterInRAWhenIPv6;	// IPv6 ルータ広告からデフォルトルータ指定を削除 (IPv6 接続時有効化)
	UINT VLanId;					// VLAN ID を指定

	bool Ver3;						// ポリシーのバージョンが 3.0 以降かどうか
};

// グループ
struct USERGROUP
{
	LOCK *lock;						// ロック
	REF *ref;						// 参照カウンタ
	char *Name;						// グループ名
	wchar_t *RealName;				// 表示名
	wchar_t *Note;					// メモ
	POLICY *Policy;					// ポリシー
	TRAFFIC *Traffic;				// トラフィックデータ
};

// ユーザー
struct USER
{
	LOCK *lock;						// ロック
	REF *ref;						// 参照カウンタ
	char *Name;						// ユーザー名
	wchar_t *RealName;				// 本名
	wchar_t *Note;					// メモ
	char *GroupName;				// グループ名
	USERGROUP *Group;				// グループ
	UINT AuthType;					// 認証の種類
	void *AuthData;					// 認証データ
	UINT64 CreatedTime;				// 作成日時
	UINT64 UpdatedTime;				// 更新日時
	UINT64 ExpireTime;				// 有効期限
	UINT64 LastLoginTime;			// 最終ログイン時刻
	UINT NumLogin;					// ログイン回数の合計
	POLICY *Policy;					// ポリシー
	TRAFFIC *Traffic;				// トラフィックデータ
};

// パスワード認証データ
struct AUTHPASSWORD
{
	UCHAR HashedKey[SHA1_SIZE];		// ハッシュされたパスワード
};

// ユーザー証明書認証データ
struct AUTHUSERCERT
{
	X *UserX;						// ユーザーの X509 証明書
};

// ルート証明機関認証データ
struct AUTHROOTCERT
{
	X_SERIAL *Serial;				// シリアル番号
	wchar_t *CommonName;			// CommonName
};

// Radius 認証データ
struct AUTHRADIUS
{
	wchar_t *RadiusUsername;		// Radius 上でのユーザー名
};

// Windows NT 認証データ
struct AUTHNT
{
	wchar_t *NtUsername;			// NT 上でのユーザー名
};



// マクロ
#define	POLICY_CURRENT_VERSION		3
#define	NUM_POLICY_ITEM		((sizeof(POLICY) / sizeof(UINT)) - 1)
#define	NUM_POLICY_ITEM_FOR_VER2	22
#define	NUM_POLICY_ITEM_FOR_VER3	38

#define	IS_POLICY_FOR_VER2(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER2))
#define	IS_POLICY_FOR_VER3(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER3))

#define	IS_POLICY_FOR_CURRENT_VER(index, ver)	((ver) >= 3 ? IS_POLICY_FOR_VER3(index) : IS_POLICY_FOR_VER2(index))

#define	POLICY_BOOL(p, i)	(((bool *)(p))[(i)])
#define	POLICY_INT(p, i)	(((UINT *)(p))[(i)])

extern POLICY_ITEM policy_item[];




// 関数プロトタイプ
int CompareUserName(void *p1, void *p2);
int CompareGroupName(void *p1, void *p2);
void AcLock(HUB *h);
void AcUnlock(HUB *h);
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note);
void ReleaseGroup(USERGROUP *g);
void CleanupGroup(USERGROUP *g);
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata);
void ReleaseUser(USER *u);
void CleanupUser(USER *u);
void FreeAuthData(UINT authtype, void *authdata);
bool AcAddUser(HUB *h, USER *u);
bool AcAddGroup(HUB *h, USERGROUP *g);
USER *AcGetUser(HUB *h, char *name);
USERGROUP *AcGetGroup(HUB *h, char *name);
bool AcIsUser(HUB *h, char *name);
bool AcIsGroup(HUB *h, char *name);
bool AcDeleteUser(HUB *h, char *name);
bool AcDeleteGroup(HUB *h, char *name);
void JoinUserToGroup(USER *u, USERGROUP *g);
void SetUserTraffic(USER *u, TRAFFIC *t);
void SetGroupTraffic(USERGROUP *g, TRAFFIC *t);
void AddUserTraffic(USER *u, TRAFFIC *diff);
void AddGroupTraffic(USERGROUP *g, TRAFFIC *diff);
void SetUserAuthData(USER *u, UINT authtype, void *authdata);
void *NewPasswordAuthData(char *username, char *password);
void *NewPasswordAuthDataRaw(UCHAR *hashed_password);
void *NewUserCertAuthData(X *x);
void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name);
void *NewRadiusAuthData(wchar_t *username);
void *NewNTAuthData(wchar_t *username);
void HashPassword(void *dst, char *username, char *password);
POLICY *GetDefaultPolicy();
POLICY *ClonePolicy(POLICY *policy);
void SetUserPolicy(USER *u, POLICY *policy);
void OverwritePolicy(POLICY **target, POLICY *p);
POLICY *GetUserPolicy(USER *u);
void SetGroupPolicy(USERGROUP *g, POLICY *policy);
POLICY *GetGroupPolicy(USERGROUP *g);
wchar_t *GetPolicyTitle(UINT id);
wchar_t *GetPolicyDescription(UINT id);
bool IsUserName(char *name);
void *CopyAuthData(void *authdata, UINT authtype);
UINT PolicyNum();
bool PolicyIsSupportedForCascade(UINT i);
UINT PolicyStrToId(char *name);
char *PolicyIdToStr(UINT i);
POLICY_ITEM *GetPolicyItem(UINT id);
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id);
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value);
char *NormalizePolicyName(char *name);


#endif	// ACCOUNT_H


