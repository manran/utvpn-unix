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

// Account.c
// アカウントマネージャ

#include "CedarPch.h"

// ポリシー項目
POLICY_ITEM policy_item[] =
{
//  番号,   数値,   省略可能, 最小, 最大, デフォルト, 単位文字列
// Ver 2.0
	{0,		false,	false,	0,	0,	0,		NULL},			// Access
	{1,		false,	false,	0,	0,	0,		NULL},			// DHCPFilter
	{2,		false,	false,	0,	0,	0,		NULL},			// DHCPNoServer
	{3,		false,	false,	0,	0,	0,		NULL},			// DHCPForce
	{4,		false,	false,	0,	0,	0,		NULL},			// NoBridge
	{5,		false,	false,	0,	0,	0,		NULL},			// NoRouting
	{6,		false,	false,	0,	0,	0,		NULL},			// CheckMac
	{7,		false,	false,	0,	0,	0,		NULL},			// CheckIP
	{8,		false,	false,	0,	0,	0,		NULL},			// ArpDhcpOnly
	{9,		false,	false,	0,	0,	0,		NULL},			// PrivacyFilter
	{10,	false,	false,	0,	0,	0,		NULL},			// NoServer
	{11,	false,	false,	0,	0,	0,		NULL},			// NoBroadcastLimiter
	{12,	false,	false,	0,	0,	0,		NULL},			// MonitorPort
	{13,	true,	false,	1,	32,	32,		"POL_INT_COUNT"},	// MaxConnection
	{14,	true,	false,	5,	60,	20,		"POL_INT_SEC"},	// TimeOut
	{15,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MaxMac
	{16,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MaxIP
	{17,	true,	true,	1,	4294967295UL,	0,	"POL_INT_BPS"},	// MaxUpload
	{18,	true,	true,	1,	4294967295UL,	0,	"POL_INT_BPS"},	// MaxDownload
	{19,	false,	false,	0,	0,	0,		NULL},			// FixPassword
	{20,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MultiLogins
	{21,	false,	false,	0,	0,	0,		NULL},			// NoQoS
// Ver 3.0
	{22,	false,	false,	0,	0,	0,		NULL},			// RSandRAFilter
	{23,	false,	false,	0,	0,	0,		NULL},			// RAFilter
	{24,	false,	false,	0,	0,	0,		NULL},			// DHCPv6Filter
	{25,	false,	false,	0,	0,	0,		NULL},			// DHCPv6NoServer
	{26,	false,	false,	0,	0,	0,		NULL},			// NoRoutingV6
	{27,	false,	false,	0,	0,	0,		NULL},			// CheckIPv6
	{28,	false,	false,	0,	0,	0,		NULL},			// NoServerV6
	{29,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MaxIPv6
	{30,	false,	false,	0,	0,	0,		NULL},			// NoSavePassword
	{31,	true,	true,	1,	4294967295UL,	0,	"POL_INT_SEC"},	// AutoDisconnect
	{32,	false,	false,	0,	0,	0,		NULL},			// FilterIPv4
	{33,	false,	false,	0,	0,	0,		NULL},			// FilterIPv6
	{34,	false,	false,	0,	0,	0,		NULL},			// FilterNonIP
	{35,	false,	false,	0,	0,	0,		NULL},			// NoIPv6DefaultRouterInRA
	{36,	false,	false,	0,	0,	0,		NULL},			// NoIPv6DefaultRouterInRAWhenIPv6
	{37,	true,	true,	1,	4095,	0,	"POL_INT_VLAN"},	// VLanId
};

// ポリシー名を正規化する
char *NormalizePolicyName(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	return PolicyIdToStr(PolicyStrToId(name));
}

// ポリシーの値をフォーマット
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value)
{
	POLICY_ITEM *p;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false)
	{
		// bool 型
		if (value == 0)
		{
			UniStrCpy(str, size, L"No");
		}
		else
		{
			UniStrCpy(str, size, L"Yes");
		}
	}
	else
	{
		// int 型
		if (value == 0 && p->AllowZero)
		{
			UniStrCpy(str, size, _UU("CMD_NO_SETTINGS"));
		}
		else
		{
			UniFormat(str, size, _UU(p->FormatStr), value);
		}
	}
}

// ポリシーとして設定可能な値の範囲を説明する文字列を取得
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id)
{
	POLICY_ITEM *p;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false)
	{
		// bool 型
		UniStrCpy(str, size, _UU("CMD_PolicyList_Range_Bool"));
	}
	else
	{
		wchar_t *tag;
		wchar_t tmp1[256], tmp2[256];

		// int 型
		if (p->AllowZero)
		{
			tag = _UU("CMD_PolicyList_Range_Int_2");
		}
		else
		{
			tag = _UU("CMD_PolicyList_Range_Int_1");
		}

		UniFormat(tmp1, sizeof(tmp1), _UU(p->FormatStr), p->MinValue);
		UniFormat(tmp2, sizeof(tmp2), _UU(p->FormatStr), p->MaxValue);

		UniFormat(str, size, tag, tmp1, tmp2);
	}
}

// ポリシーアイテムの取得
POLICY_ITEM *GetPolicyItem(UINT id)
{
	return &policy_item[id];
}

// 指定されたポリシーがカスケード接続でサポートされているかどうか
bool PolicyIsSupportedForCascade(UINT i)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	if (i == 0 || i == 4 || i == 5 || i == 9 || i == 12 || i == 13 ||
		i == 14 || i == 19 || i == 20 || i == 21 || i == 26 || i == 30 || i == 31 || i == 36)
	{
		// これらの項目はカスケード接続でサポートされていない
		return false;
	}

	return true;
}

// ID をポリシーの名前に変換
char *PolicyIdToStr(UINT i)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	switch (i)
	{
	// Ver 2.0
	case 0:		return "Access";
	case 1:		return "DHCPFilter";
	case 2:		return "DHCPNoServer";
	case 3:		return "DHCPForce";
	case 4:		return "NoBridge";
	case 5:		return "NoRouting";
	case 6:		return "CheckMac";
	case 7:		return "CheckIP";
	case 8:		return "ArpDhcpOnly";
	case 9:		return "PrivacyFilter";
	case 10:	return "NoServer";
	case 11:	return "NoBroadcastLimiter";
	case 12:	return "MonitorPort";
	case 13:	return "MaxConnection";
	case 14:	return "TimeOut";
	case 15:	return "MaxMac";
	case 16:	return "MaxIP";
	case 17:	return "MaxUpload";
	case 18:	return "MaxDownload";
	case 19:	return "FixPassword";
	case 20:	return "MultiLogins";
	case 21:	return "NoQoS";

	// Ver 3.0
	case 22:	return "RSandRAFilter";
	case 23:	return "RAFilter";
	case 24:	return "DHCPv6Filter";
	case 25:	return "DHCPv6NoServer";
	case 26:	return "NoRoutingV6";
	case 27:	return "CheckIPv6";
	case 28:	return "NoServerV6";
	case 29:	return "MaxIPv6";
	case 30:	return "NoSavePassword";
	case 31:	return "AutoDisconnect";
	case 32:	return "FilterIPv4";
	case 33:	return "FilterIPv6";
	case 34:	return "FilterNonIP";
	case 35:	return "NoIPv6DefaultRouterInRA";
	case 36:	return "NoIPv6DefaultRouterInRAWhenIPv6";
	case 37:	return "VLanId";
	}

	return NULL;
}

// ポリシーの名前を ID に変換
UINT PolicyStrToId(char *name)
{
	UINT i;
	// 引数チェック
	if (name == NULL)
	{
		return INFINITE;
	}

	for (i = 0;i < NUM_POLICY_ITEM;i++)
	{
		if (StartWith(PolicyIdToStr(i), name))
		{
			return i;
		}
	}

	return INFINITE;
}

// ポリシーの総数を取得
UINT PolicyNum()
{
	return NUM_POLICY_ITEM;
}

// 指定した名前をアカウント名として使用できるかどうか確認する
bool IsUserName(char *name)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	char tmp[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	name = tmp;

	Trim(name);

	if (StrLen(name) == 0)
	{
		return false;
	}

	if (StrCmpi(name, "*") == 0)
	{
		return true;
	}

	if (IsSafeStr(name) == false)
	{
		return false;
	}

	if (StrCmpi(name, LINK_USER_NAME) == 0)
	{
		return false;
	}

	if (StartWith(name, L3_USERNAME))
	{
		return false;
	}

	if (StrCmpi(name, LINK_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, SNAT_USER_NAME) == 0)
	{
		return false;
	}

	if (StrCmpi(name, SNAT_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME) == 0)
	{
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, ADMINISTRATOR_USERNAME) == 0)
	{
		return false;
	}

	return true;
}

// ポリシーのタイトルを取得する
wchar_t *GetPolicyTitle(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "POL_%u", id);

	return _UU(tmp);
}

// ポリシーの説明を取得する
wchar_t *GetPolicyDescription(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "POL_EX_%u", id);

	return _UU(tmp);
}

// ポリシーデータのクローン
POLICY *ClonePolicy(POLICY *policy)
{
	POLICY *ret;
	// 引数チェック
	if (policy == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(POLICY));
	Copy(ret, policy, sizeof(POLICY));

	return ret;
}

// ポリシーを上書きする (古いバージョンを上書きする場合は新しいバージョンのデータは残す)
void OverwritePolicy(POLICY **target, POLICY *p)
{
	// 引数チェック
	if (target == NULL)
	{
		return;
	}

	if (p == NULL)
	{
		// ポリシー消去
		if (*target != NULL)
		{
			Free(*target);
			*target = NULL;
		}
	}
	else
	{
		if (p->Ver3)
		{
			// Ver 3
			if (*target != NULL)
			{
				Free(*target);
				*target = NULL;
			}

			*target = ClonePolicy(p);
		}
		else
		{
			// Ver 2
			if (*target == NULL)
			{
				*target = ClonePolicy(p);
			}
			else
			{
				Copy(*target, p, NUM_POLICY_ITEM_FOR_VER2 * sizeof(UINT));
			}
		}
	}
}

// ユーザーポリシーの設定
void SetUserPolicy(USER *u, POLICY *policy)
{
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		OverwritePolicy(&u->Policy, policy);
	}
	Unlock(u->lock);
}

// ユーザーポリシーの取得
POLICY *GetUserPolicy(USER *u)
{
	POLICY *ret;
	// 引数チェック
	if (u == NULL)
	{
		return NULL;
	}

	Lock(u->lock);
	{
		if (u->Policy == NULL)
		{
			ret = NULL;
		}
		else
		{
			ret = ClonePolicy(u->Policy);
		}
	}
	Unlock(u->lock);

	return ret;
}

// グループポリシーの設定
void SetGroupPolicy(USERGROUP *g, POLICY *policy)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		OverwritePolicy(&g->Policy, policy);
	}
	Unlock(g->lock);
}

// グループポリシーの取得
POLICY *GetGroupPolicy(USERGROUP *g)
{
	POLICY *ret;
	// 引数チェック
	if (g == NULL)
	{
		return NULL;
	}

	Lock(g->lock);
	{
		if (g->Policy == NULL)
		{
			ret = NULL;
		}
		else
		{
			ret = ClonePolicy(g->Policy);
		}
	}
	Unlock(g->lock);

	return ret;
}

// デフォルトのポリシーを返す
POLICY *GetDefaultPolicy()
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	static POLICY def_policy =
	{
		true,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		32,
		20,
		0,
		0,
		0,
		0,
		false,
		0,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		0,
		false,
		0,
		false,
		false,
		false,
		false,
		false,
	};

	return &def_policy;
}

// NT 認証データの作成
void *NewNTAuthData(wchar_t *username)
{
	AUTHNT *a;
	// 引数チェック
	a = ZeroMallocEx(sizeof(AUTHNT), true);
	a->NtUsername = CopyUniStr(username);

	return a;
}

// Radius 認証データの作成
void *NewRadiusAuthData(wchar_t *username)
{
	AUTHRADIUS *a;
	// 引数チェック
	a = ZeroMallocEx(sizeof(AUTHRADIUS), true);
	a->RadiusUsername = CopyUniStr(username);

	return a;
}

// ルート証明書による認証データの作成
void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name)
{
	AUTHROOTCERT *a;

	a = ZeroMallocEx(sizeof(AUTHROOTCERT), true);
	if (common_name != NULL && UniIsEmptyStr(common_name) == false)
	{
		a->CommonName = CopyUniStr(common_name);
	}
	if (serial != NULL && serial->size >= 1)
	{
		a->Serial = CloneXSerial(serial);
	}

	return a;
}

// ユーザー証明書認証データの作成
void *NewUserCertAuthData(X *x)
{
	AUTHUSERCERT *a;

	a = ZeroMalloc(sizeof(AUTHUSERCERT));
	a->UserX = CloneX(x);

	return a;
}

// パスワードのハッシュ
void HashPassword(void *dst, char *username, char *password)
{
	BUF *b;
	char *username_upper;
	// 引数チェック
	if (dst == NULL || username == NULL || password == NULL)
	{
		return;
	}

	b = NewBuf();
	username_upper = CopyStr(username);
	StrUpper(username_upper);
	WriteBuf(b, password, StrLen(password));
	WriteBuf(b, username_upper, StrLen(username_upper));
	Hash(dst, b->Buf, b->Size, true);

	FreeBuf(b);
	Free(username_upper);
}

// パスワード認証データの作成
void *NewPasswordAuthData(char *username, char *password)
{
	AUTHPASSWORD *pw;
	// 引数チェック
	if (username == NULL || password == NULL)
	{
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	HashPassword(pw->HashedKey, username, password);

	return pw;
}
void *NewPasswordAuthDataRaw(UCHAR *hashed_password)
{
	AUTHPASSWORD *pw;
	// 引数チェック
	if (hashed_password == NULL)
	{
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	Copy(pw->HashedKey, hashed_password, SHA1_SIZE);

	return pw;
}

// ユーザーの認証データのコピー
void *CopyAuthData(void *authdata, UINT authtype)
{
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *usercert = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rootcert = (AUTHROOTCERT *)authdata;
	AUTHRADIUS *radius = (AUTHRADIUS *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	// 引数チェック
	if (authdata == NULL || authtype == AUTHTYPE_ANONYMOUS)
	{
		return NULL;
	}

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		{
			AUTHPASSWORD *ret = ZeroMalloc(sizeof(AUTHPASSWORD));
			Copy(ret, pw, sizeof(AUTHPASSWORD));
			return ret;
		}
		break;

	case AUTHTYPE_USERCERT:
		{
			AUTHUSERCERT *ret = ZeroMalloc(sizeof(AUTHUSERCERT));
			ret->UserX = CloneX(usercert->UserX);
			return ret;
		}
		break;

	case AUTHTYPE_ROOTCERT:
		{
			AUTHROOTCERT *ret = ZeroMalloc(sizeof(AUTHROOTCERT));
			ret->CommonName = CopyUniStr(rootcert->CommonName);
			ret->Serial = CloneXSerial(rootcert->Serial);
			return ret;
		}
		break;

	case AUTHTYPE_RADIUS:
		{
			AUTHRADIUS *ret = ZeroMalloc(sizeof(AUTHRADIUS));
			ret->RadiusUsername = UniCopyStr(radius->RadiusUsername);
			return ret;
		}
		break;

	case AUTHTYPE_NT:
		{
			AUTHNT *ret = ZeroMalloc(sizeof(AUTHNT));
			ret->NtUsername = UniCopyStr(nt->NtUsername);
			return ret;
		}
		break;
	}

	return NULL;
}

// ユーザーの認証データのセット
void SetUserAuthData(USER *u, UINT authtype, void *authdata)
{
	// 引数チェック
	if (u == NULL)
	{
		return;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		if (u->AuthType != AUTHTYPE_ANONYMOUS)
		{
			// 現在の認証データの解放
			FreeAuthData(u->AuthType, u->AuthData);
		}
		// 新しい認証データの設定
		u->AuthType = authtype;
		u->AuthData = authdata;
	}
	Unlock(u->lock);
}

// グループのトラフィックデータを加算
void AddGroupTraffic(USERGROUP *g, TRAFFIC *diff)
{
	// 引数チェック
	if (g == NULL || diff == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		AddTraffic(g->Traffic, diff);
	}
	Unlock(g->lock);
}

// ユーザーのトラフィックデータを加算
void AddUserTraffic(USER *u, TRAFFIC *diff)
{
	// 引数チェック
	if (u == NULL || diff == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		AddTraffic(u->Traffic, diff);
	}
	Unlock(u->lock);
}

// グループのトラフィック情報をセット
void SetGroupTraffic(USERGROUP *g, TRAFFIC *t)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		if (t != NULL)
		{
			Copy(g->Traffic, t, sizeof(TRAFFIC));
		}
		else
		{
			Zero(g->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(g->lock);
}

// ユーザーのトラフィック情報をセット
void SetUserTraffic(USER *u, TRAFFIC *t)
{
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		if (t != NULL)
		{
			Copy(u->Traffic, t, sizeof(TRAFFIC));
		}
		else
		{
			Zero(u->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(u->lock);
}

// ユーザーをグループに所属させる
void JoinUserToGroup(USER *u, USERGROUP *g)
{
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	if (g != NULL)
	{
		// 参加
		Lock(u->lock);
		{
			Lock(g->lock);
			{
				if (u->Group != NULL)
				{
					// まずユーザーをグループから外す
					ReleaseGroup(u->Group);
					u->Group = NULL;
					Free(u->GroupName);
					u->GroupName = NULL;
				}
				// ユーザーをグループに追加する
				u->GroupName = CopyStr(g->Name);
				u->Group = g;
				AddRef(g->ref);
			}
			Unlock(g->lock);
		}
		Unlock(u->lock);
	}
	else
	{
		// 脱退
		Lock(u->lock);
		{
			if (u->Group != NULL)
			{
				// ユーザーをグループから外す
				ReleaseGroup(u->Group);
				u->Group = NULL;
				Free(u->GroupName);
				u->GroupName = NULL;
			}
		}
		Unlock(u->lock);
	}
}

// グループ名チェック
bool AcIsGroup(HUB *h, char *name)
{
	USERGROUP *g;
	// 引数チェック
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL)
	{
		return false;
	}
	ReleaseGroup(g);

	return true;
}

// ユーザー名チェック
bool AcIsUser(HUB *h, char *name)
{
	USER *u;
	// 引数チェック
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL)
	{
		return false;
	}
	ReleaseUser(u);

	return true;
}

// グループの取得
USERGROUP *AcGetGroup(HUB *h, char *name)
{
	USERGROUP *g, t;
	// 引数チェック
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return NULL;
	}

	t.Name = name;
	g = Search(h->HubDb->GroupList, &t);
	if (g == NULL)
	{
		return NULL;
	}
	AddRef(g->ref);

	return g;
}

// ユーザーの取得
USER *AcGetUser(HUB *h, char *name)
{
	USER *u, t;
	// 引数チェック
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return NULL;
	}

	t.Name = name;
	u = Search(h->HubDb->UserList, &t);
	if (u == NULL)
	{
		return NULL;
	}
	AddRef(u->ref);

	return u;
}

// ユーザーの削除
bool AcDeleteUser(HUB *h, char *name)
{
	USER *u;
	// 引数チェック
	if (h == NULL || name == NULL)
	{
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL)
	{
		return false;
	}

	if (Delete(h->HubDb->UserList, u))
	{
		ReleaseUser(u);
	}

	ReleaseUser(u);

	return true;
}

// グループの削除
bool AcDeleteGroup(HUB *h, char *name)
{
	USERGROUP *g;
	UINT i;
	// 引数チェック
	if (h == NULL || name == NULL)
	{
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL)
	{
		return false;
	}

	if (Delete(h->HubDb->GroupList, g))
	{
		ReleaseGroup(g);
	}

	for (i = 0;i < LIST_NUM(h->HubDb->UserList);i++)
	{
		USER *u = LIST_DATA(h->HubDb->UserList, i);
		Lock(u->lock);
		{
			if (u->Group == g)
			{
				JoinUserToGroup(u, NULL);
			}
		}
		Unlock(u->lock);
	}

	ReleaseGroup(g);

	return true;
}

// グループの追加
bool AcAddGroup(HUB *h, USERGROUP *g)
{
	// 引数チェック
	if (h == NULL || g == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	if (LIST_NUM(h->HubDb->GroupList) >= MAX_GROUPS)
	{
		return false;
	}

	if (AcIsGroup(h, g->Name) != false)
	{
		return false;
	}

	Insert(h->HubDb->GroupList, g);
	AddRef(g->ref);

	return true;
}

// ユーザーの追加
bool AcAddUser(HUB *h, USER *u)
{
	// 引数チェック
	if (h == NULL || u == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	if (LIST_NUM(h->HubDb->UserList) >= MAX_USERS)
	{
		return false;
	}

	if (AcIsUser(h, u->Name) != false)
	{
		return false;
	}

	Insert(h->HubDb->UserList, u);
	AddRef(u->ref);

	return true;
}

// ユーザーの解放
void ReleaseUser(USER *u)
{
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	if (Release(u->ref) == 0)
	{
		CleanupUser(u);
	}
}

// ユーザーのクリーンアップ
void CleanupUser(USER *u)
{
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	DeleteLock(u->lock);
	Free(u->Name);
	Free(u->RealName);
	Free(u->Note);
	Free(u->GroupName);
	if (u->Group != NULL)
	{
		ReleaseGroup(u->Group);
	}

	// 認証データの解放
	FreeAuthData(u->AuthType, u->AuthData);

	if (u->Policy)
	{
		// ポリシー解放
		Free(u->Policy);
	}

	FreeTraffic(u->Traffic);

	Free(u);
}

// 認証データの解放
void FreeAuthData(UINT authtype, void *authdata)
{
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *uc = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rc = (AUTHROOTCERT *)authdata;
	AUTHRADIUS *rd = (AUTHRADIUS *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	// 引数チェック
	if (authtype == AUTHTYPE_ANONYMOUS || authdata == NULL)
	{
		return;
	}

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		// パスワード認証
		// 何も解放しない
		break;

	case AUTHTYPE_USERCERT:
		// ユーザー証明書
		FreeX(uc->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		// ルート証明書
		if (rc->Serial != NULL)
		{
			FreeXSerial(rc->Serial);
		}
		if (rc->CommonName != NULL)
		{
			Free(rc->CommonName);
		}
		break;

	case AUTHTYPE_RADIUS:
		// Radius 認証
		Free(rd->RadiusUsername);
		break;

	case AUTHTYPE_NT:
		// Windows NT 認証
		Free(nt->NtUsername);
		break;
	}

	Free(authdata);
}

// ユーザーの作成
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata)
{
	USER *u;
	// 引数チェック
	if (name == NULL || realname == NULL || note == NULL)
	{
		return NULL;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
	{
		return NULL;
	}

	u = ZeroMalloc(sizeof(USER));
	u->lock = NewLock();
	u->ref = NewRef();
	u->Name = CopyStr(name);
	u->RealName = CopyUniStr(realname);
	u->Note = CopyUniStr(note);
	u->GroupName = NULL;
	u->Group = NULL;
	u->AuthType = authtype;
	u->AuthData = authdata;
	u->CreatedTime = SystemTime64();
	u->UpdatedTime = SystemTime64();

	u->Policy = NULL;
	u->Traffic = NewTraffic();

	return u;
}

// グループの解放
void ReleaseGroup(USERGROUP *g)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	if (Release(g->ref) == 0)
	{
		CleanupGroup(g);
	}
}

// グループのクリーンアップ
void CleanupGroup(USERGROUP *g)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	Free(g->Name);
	Free(g->RealName);
	Free(g->Note);

	if (g->Policy)
	{
		// ポリシー解放
		Free(g->Policy);
	}


	FreeTraffic(g->Traffic);

	DeleteLock(g->lock);
	Free(g);
}

// 新しいグループを作成
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note)
{
	USERGROUP *g;
	// 引数チェック
	if (name == NULL || realname == NULL || note == NULL)
	{
		return NULL;
	}

	g = ZeroMalloc(sizeof(USERGROUP));
	g->lock = NewLock();
	g->ref = NewRef();
	g->Name = CopyStr(name);
	g->RealName = CopyUniStr(realname);
	g->Note = CopyUniStr(note);
	g->Policy = NULL;
	g->Traffic = NewTraffic();

	return g;
}

// HUB のアカウントデータベースのロック
void AcLock(HUB *h)
{
	// 引数チェック
	if (h == NULL)
	{
		return;
	}
	if (NO_ACCOUNT_DB(h))
	{
		return;
	}

	// グループとユーザーをロック
	LockList(h->HubDb->GroupList);
	LockList(h->HubDb->UserList);
}

// HUB のアカウントデータベースのロック解除
void AcUnlock(HUB *h)
{
	// 引数チェック
	if (h == NULL)
	{
		return;
	}
	if (NO_ACCOUNT_DB(h))
	{
		return;
	}

	// グループとユーザーをロック解除
	UnlockList(h->HubDb->UserList);
	UnlockList(h->HubDb->GroupList);
}

// グループ名比較関数
int CompareGroupName(void *p1, void *p2)
{
	USERGROUP *g1, *g2;
	// 引数チェック
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	g1 = *(USERGROUP **)p1;
	g2 = *(USERGROUP **)p2;
	if (g1 == NULL || g2 == NULL)
	{
		return 0;
	}

	return StrCmpi(g1->Name, g2->Name);
}

// ユーザー名比較関数
int CompareUserName(void *p1, void *p2)
{
	USER *u1, *u2;
	// 引数チェック
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	u1 = *(USER **)p1;
	u2 = *(USER **)p2;
	if (u1 == NULL || u2 == NULL)
	{
		return 0;
	}

	return StrCmpi(u1->Name, u2->Name);
}

