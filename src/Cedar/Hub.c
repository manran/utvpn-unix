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

// Hub.c
// 仮想 HUB モジュール

#include "CedarPch.h"

static UCHAR broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// 現在サポートされている管理オプションの一覧とデフォルト値
// 名前は 63 文字以内にすること
ADMIN_OPTION admin_options[] =
{
	{"allow_hub_admin_change_option", 0},
	{"max_users", 0},
	{"max_multilogins_per_user", 0},
	{"max_groups", 0},
	{"max_accesslists", 0},
	{"max_sessions_client_bridge_apply", 0},
	{"max_sessions", 0},
	{"max_sessions_client", 0},
	{"max_sessions_bridge", 0},
	{"max_bitrates_download", 0},
	{"max_bitrates_upload", 0},
	{"deny_empty_password", 0},
	{"deny_bridge", 0},
	{"deny_routing", 0},
	{"deny_qos", 0},
	{"deny_change_user_password", 0},
	{"no_change_users", 0},
	{"no_change_groups", 0},
	{"no_securenat", 0},
	{"no_securenat_enablenat", 0},
	{"no_securenat_enabledhcp", 0},
	{"no_cascade", 0},
	{"no_online", 0},
	{"no_offline", 0},
	{"no_change_log_config", 0},
	{"no_disconnect_session", 0},
	{"no_delete_iptable", 0},
	{"no_delete_mactable", 0},
	{"no_enum_session", 0},
	{"no_query_session", 0},
	{"no_change_admin_password", 0},
	{"no_change_log_switch_type", 0},
	{"no_change_access_list", 0},
	{"no_change_access_control_list", 0},
	{"no_change_cert_list", 0},
	{"no_change_crl_list", 0},
	{"no_read_log_file", 0},
	{"deny_hub_admin_change_ext_option", 0},
	{"no_delay_jitter_packet_loss", 0},
	{"no_change_msg", 0},
};

UINT num_admin_options = sizeof(admin_options) / sizeof(ADMIN_OPTION);

// 指定されたメッセージが URL 文字列かどうか取得
bool IsURLMsg(wchar_t *str, char *url, UINT url_size)
{
	UNI_TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	UINT n = 0;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	t = UniParseToken(str, L"\r\n");

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *str = t->Token[i];

		if (IsEmptyUniStr(str) == false)
		{
			n++;

			UniTrim(str);

			if (n == 1)
			{
				if (UniStartWith(str, L"http://") ||
					UniStartWith(str, L"https://") ||
					UniStartWith(str, L"ftp://"))
				{
					ret = true;

					UniToStr(url, url_size, str);
				}
			}
		}
	}

	if (n != 1)
	{
		ret = false;
	}

	UniFreeToken(t);

	return ret;
}

// RPC_ADMIN_OPTION からデータを取得
UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name)
{
	UINT i;
	// 引数チェック
	if (ao == NULL || name == NULL)
	{
		return INFINITE;
	}

	for (i = 0;i < ao->NumItem;i++)
	{
		ADMIN_OPTION *a = &ao->Items[i];

		if (StrCmpi(a->Name, name) == 0)
		{
			return a->Value;
		}
	}

	return INFINITE;
}
void GetHubAdminOptionDataAndSet(RPC_ADMIN_OPTION *ao, char *name, UINT *dest)
{
	UINT value;
	// 引数チェック
	if (ao == NULL || name == NULL || dest == NULL)
	{
		return;
	}

	value = GetHubAdminOptionData(ao, name);
	if (value == INFINITE)
	{
		return;
	}

	*dest = value;
}

// データをもとに HUB_OPTION の内容を設定
void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao)
{
	// 引数チェック
	if (o == NULL || ao == NULL)
	{
		return;
	}

	GetHubAdminOptionDataAndSet(ao, "NoAddressPollingIPv4", &o->NoArpPolling);
	GetHubAdminOptionDataAndSet(ao, "NoAddressPollingIPv6", &o->NoIPv6AddrPolling);
	GetHubAdminOptionDataAndSet(ao, "NoIpTable", &o->NoIpTable);
	GetHubAdminOptionDataAndSet(ao, "NoMacAddressLog", &o->NoMacAddressLog);
	GetHubAdminOptionDataAndSet(ao, "ManageOnlyPrivateIP", &o->ManageOnlyPrivateIP);
	GetHubAdminOptionDataAndSet(ao, "ManageOnlyLocalUnicastIPv6", &o->ManageOnlyLocalUnicastIPv6);
	GetHubAdminOptionDataAndSet(ao, "DisableIPParsing", &o->DisableIPParsing);
	GetHubAdminOptionDataAndSet(ao, "YieldAfterStorePacket", &o->YieldAfterStorePacket);
	GetHubAdminOptionDataAndSet(ao, "NoSpinLockForPacketDelay", &o->NoSpinLockForPacketDelay);
	GetHubAdminOptionDataAndSet(ao, "BroadcastStormDetectionThreshold", &o->BroadcastStormDetectionThreshold);
	GetHubAdminOptionDataAndSet(ao, "ClientMinimumRequiredBuild", &o->ClientMinimumRequiredBuild);
	GetHubAdminOptionDataAndSet(ao, "FilterPPPoE", &o->FilterPPPoE);
	GetHubAdminOptionDataAndSet(ao, "FilterOSPF", &o->FilterOSPF);
	GetHubAdminOptionDataAndSet(ao, "FilterIPv4", &o->FilterIPv4);
	GetHubAdminOptionDataAndSet(ao, "FilterIPv6", &o->FilterIPv6);
	GetHubAdminOptionDataAndSet(ao, "FilterNonIP", &o->FilterNonIP);
	GetHubAdminOptionDataAndSet(ao, "NoIPv4PacketLog", &o->NoIPv4PacketLog);
	GetHubAdminOptionDataAndSet(ao, "NoIPv6PacketLog", &o->NoIPv6PacketLog);
	GetHubAdminOptionDataAndSet(ao, "FilterBPDU", &o->FilterBPDU);
	GetHubAdminOptionDataAndSet(ao, "NoIPv6DefaultRouterInRAWhenIPv6", &o->NoIPv6DefaultRouterInRAWhenIPv6);
	GetHubAdminOptionDataAndSet(ao, "NoLookBPDUBridgeId", &o->NoLookBPDUBridgeId);
	GetHubAdminOptionDataAndSet(ao, "NoManageVlanId", &o->NoManageVlanId);
	GetHubAdminOptionDataAndSet(ao, "VlanTypeId", &o->VlanTypeId);
	GetHubAdminOptionDataAndSet(ao, "FixForDLinkBPDU", &o->FixForDLinkBPDU);
	GetHubAdminOptionDataAndSet(ao, "RequiredClientId", &o->RequiredClientId);
}

// HUB_OPTION の内容をデータに変換
void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name)
{
	LIST *aol;
	UINT i;
	// 引数チェック
	if (ao == NULL || o == NULL || hub_name == NULL)
	{
		return;
	}

	aol = NewListFast(NULL);

	Add(aol, NewAdminOption("NoAddressPollingIPv4", o->NoArpPolling));
	Add(aol, NewAdminOption("NoAddressPollingIPv6", o->NoIPv6AddrPolling));
	Add(aol, NewAdminOption("NoIpTable", o->NoIpTable));
	Add(aol, NewAdminOption("NoMacAddressLog", o->NoMacAddressLog));
	Add(aol, NewAdminOption("ManageOnlyPrivateIP", o->ManageOnlyPrivateIP));
	Add(aol, NewAdminOption("ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6));
	Add(aol, NewAdminOption("DisableIPParsing", o->DisableIPParsing));
	Add(aol, NewAdminOption("YieldAfterStorePacket", o->YieldAfterStorePacket));
	Add(aol, NewAdminOption("NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay));
	Add(aol, NewAdminOption("BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold));
	Add(aol, NewAdminOption("ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild));
	Add(aol, NewAdminOption("FilterPPPoE", o->FilterPPPoE));
	Add(aol, NewAdminOption("FilterOSPF", o->FilterOSPF));
	Add(aol, NewAdminOption("FilterIPv4", o->FilterIPv4));
	Add(aol, NewAdminOption("FilterIPv6", o->FilterIPv6));
	Add(aol, NewAdminOption("FilterNonIP", o->FilterNonIP));
	Add(aol, NewAdminOption("NoIPv4PacketLog", o->NoIPv4PacketLog));
	Add(aol, NewAdminOption("NoIPv6PacketLog", o->NoIPv6PacketLog));
	Add(aol, NewAdminOption("FilterBPDU", o->FilterBPDU));
	Add(aol, NewAdminOption("NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6));
	Add(aol, NewAdminOption("NoLookBPDUBridgeId", o->NoLookBPDUBridgeId));
	Add(aol, NewAdminOption("NoManageVlanId", o->NoManageVlanId));
	Add(aol, NewAdminOption("VlanTypeId", o->VlanTypeId));
	Add(aol, NewAdminOption("FixForDLinkBPDU", o->FixForDLinkBPDU));
	Add(aol, NewAdminOption("RequiredClientId", o->RequiredClientId));

	Zero(ao, sizeof(RPC_ADMIN_OPTION));

	StrCpy(ao->HubName, sizeof(ao->HubName), hub_name);

	ao->NumItem = LIST_NUM(aol);
	ao->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * ao->NumItem);

	for (i = 0;i < LIST_NUM(aol);i++)
	{
		ADMIN_OPTION *a = LIST_DATA(aol, i);

		Copy(&ao->Items[i], a, sizeof(ADMIN_OPTION));

		Free(a);
	}

	ReleaseList(aol);
}

// 新しい ADMIN OPTION の作成
ADMIN_OPTION *NewAdminOption(char *name, UINT value)
{
	ADMIN_OPTION *a;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(ADMIN_OPTION));
	StrCpy(a->Name, sizeof(a->Name), name);
	a->Value = value;

	return a;
}

// AC リストのクローン
LIST *CloneAcList(LIST *o)
{
	LIST *ret;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewAcList();
	SetAcList(ret, o);

	return ret;
}

// AC リストをすべてセットする
void SetAcList(LIST *o, LIST *src)
{
	UINT i;
	// 引数チェック
	if (o == NULL || src == NULL)
	{
		return;
	}

	DelAllAc(o);

	for (i = 0;i < LIST_NUM(src);i++)
	{
		AC *ac = LIST_DATA(src, i);

		AddAc(o, ac);
	}
}

// AC リストからすべての AC を削除する
void DelAllAc(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	DeleteAll(o);
}

// AC リストを解放する
void FreeAcList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	ReleaseList(o);
}

// AC の内容を示す文字列を生成する
char *GenerateAcStr(AC *ac)
{
	char tmp[MAX_SIZE];
	char ip[64], mask[64];

	if (ac == NULL)
	{
		return NULL;
	}

	IPToStr(ip, sizeof(ip), &ac->IpAddress);
	MaskToStr(mask, sizeof(mask), &ac->SubnetMask);

	if (ac->Masked == false)
	{
		Format(tmp, sizeof(tmp), "%s", ip);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s/%s", ip, mask);
	}

	return CopyStr(tmp);
}

// AC の設定
void SetAc(LIST *o, UINT id, AC *ac)
{
	// 引数チェック
	if (o == NULL || id == 0 || ac == NULL)
	{
		return;
	}

	if (DelAc(o, id))
	{
		AddAc(o, ac);
	}
}

// AC の取得
AC *GetAc(LIST *o, UINT id)
{
	UINT i;
	// 引数チェック
	if (o == NULL || id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (ac->Id == id)
		{
			return Clone(ac, sizeof(AC));
		}
	}

	return NULL;
}

// AC の削除
bool DelAc(LIST *o, UINT id)
{
	UINT i;
	// 引数チェック
	if (o == NULL || id == 0)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (ac->Id == id)
		{
			if (Delete(o, ac))
			{
				Free(ac);

				NormalizeAcList(o);

				return true;
			}
		}
	}

	return false;
}

// AC の追加
void AddAc(LIST *o, AC *ac)
{
	// 引数チェック
	if (o == NULL || ac == NULL)
	{
		return;
	}

	if (LIST_NUM(o) < MAX_HUB_ACS)
	{
		Insert(o, Clone(ac, sizeof(AC)));

		NormalizeAcList(o);
	}
}

// AC リストを正規化する
void NormalizeAcList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (IsIP6(&ac->IpAddress))
		{
			ac->IpAddress.ipv6_scope_id = 0;
		}

		ac->Id = (i + 1);
	}
}

// 新しい AC リストの作成
LIST *NewAcList()
{
	return NewList(CmpAc);
}

// AC 比較
int CmpAc(void *p1, void *p2)
{
	AC *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(AC **)p1;
	a2 = *(AC **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Deny > a2->Deny)
	{
		return 1;
	}
	else if (a1->Deny < a2->Deny)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// CRL のコピー
CRL *CopyCrl(CRL *crl)
{
	CRL *ret;
	// 引数チェック
	if (crl == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CRL));

	if (crl->Serial != NULL)
	{
		ret->Serial = NewXSerial(crl->Serial->data, crl->Serial->size);
	}

	ret->Name = CopyName(crl->Name);

	Copy(ret->DigestMD5, crl->DigestMD5, MD5_SIZE);
	Copy(ret->DigestSHA1, crl->DigestSHA1, SHA1_SIZE);

	return ret;
}

// CRL の解放
void FreeCrl(CRL *crl)
{
	// 引数チェック
	if (crl == NULL)
	{
		return;
	}

	if (crl->Serial != NULL)
	{
		FreeXSerial(crl->Serial);
	}

	if (crl->Name != NULL)
	{
		FreeName(crl->Name);
	}

	Free(crl);
}

// 仮想 HUB の CRL リストを検索して証明書が無効化されていないかどうか調べる
bool IsValidCertInHub(HUB *h, X *x)
{
	bool ret;
	// 引数チェック
	if (h == NULL || x == NULL)
	{
		return false;
	}

	if (h->HubDb == NULL)
	{
		return false;
	}

	if (IsXRevoked(x))
	{
		// ファイルに保存されている CRL によって無効化されている
		return false;
	}

	LockList(h->HubDb->CrlList);
	{
		ret = IsCertMatchCrlList(x, h->HubDb->CrlList);
	}
	UnlockList(h->HubDb->CrlList);

	if (ret)
	{
		// 一致するので無効である
		return false;
	}

	// 一致しなかったので有効である
	return true;
}

// CRL リストに証明書が一致するかどうか検索
bool IsCertMatchCrlList(X *x, LIST *o)
{
	UINT i;
	// 引数チェック
	if (x == NULL || o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CRL *crl = LIST_DATA(o, i);

		if (IsCertMatchCrl(x, crl))
		{
			return true;
		}
	}

	return false;
}

// CRL を示す文字列に変換する
wchar_t *GenerateCrlStr(CRL *crl)
{
	wchar_t tmp[2048];
	// 引数チェック
	if (crl == NULL)
	{
		return NULL;
	}

	UniStrCpy(tmp, sizeof(tmp), L"");

	if (crl->Name != NULL)
	{
		// 名前情報
		wchar_t name[MAX_SIZE];

		UniStrCat(tmp, sizeof(tmp), L"Subject=\"");

		GetAllNameFromName(name, sizeof(name), crl->Name);
		UniStrCat(tmp, sizeof(tmp), name);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (crl->Serial != NULL)
	{
		// シリアル情報
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"Serial=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
	{
		// MD5
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"MD5=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
	{
		// MD5
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"SHA1=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (UniEndWith(tmp, L", "))
	{
		tmp[UniStrLen(tmp) - 2] = 0;
	}

	return CopyUniStr(tmp);
}

// 証明書無効リストエントリに一致するかどうか検査する
bool IsCertMatchCrl(X *x, CRL *crl)
{
	// このあたりは急いで実装したのでコードがあまり美しくない。
	bool b = true;
	// 引数チェック
	if (x == NULL || crl == NULL)
	{
		return false;
	}

	if (crl->Serial != NULL)
	{
		// CRL にシリアル番号が定義されている場合
		if (x->serial == NULL || CompareXSerial(x->serial, crl->Serial) == false)
		{
			// シリアル番号不一致
			b = false;
		}
	}

	if (IsZero(crl->DigestMD5, sizeof(crl->DigestMD5)) == false)
	{
		UCHAR test[MD5_SIZE];
		// CRL に DigestMD5 が定義されている場合
		GetXDigest(x, test, false);

		if (Cmp(test, crl->DigestMD5, MD5_SIZE) != 0)
		{
			b = false;
		}
	}

	if (IsZero(crl->DigestSHA1, sizeof(crl->DigestSHA1)) == false)
	{
		UCHAR test[SHA1_SIZE];
		// CRL に DigestSHA1 が定義されている場合
		GetXDigest(x, test, true);

		if (Cmp(test, crl->DigestSHA1, SHA1_SIZE) != 0)
		{
			b = false;
		}
	}

	if (crl->Name != NULL)
	{
		// CRL に名前が定義されている場合
		NAME *xn, *cn;
		xn = x->subject_name;
		cn = crl->Name;

		if (cn->CommonName != NULL && (UniIsEmptyStr(cn->CommonName) == false))
		{
			if (xn->CommonName == NULL || UniSoftStrCmp(xn->CommonName, cn->CommonName) != 0)
			{
				// CommonName 不一致
				b = false;
			}
		}

		if (cn->Organization != NULL && (UniIsEmptyStr(cn->Organization) == false))
		{
			if (xn->Organization == NULL || UniSoftStrCmp(xn->Organization, cn->Organization) != 0)
			{
				// Organization 不一致
				b = false;
			}
		}

		if (cn->Unit != NULL && (UniIsEmptyStr(cn->Unit) == false))
		{
			if (xn->Unit == NULL || UniSoftStrCmp(xn->Unit, cn->Unit) != 0)
			{
				// Unit不一致
				b = false;
			}
		}

		if (cn->Country != NULL && (UniIsEmptyStr(cn->Country) == false))
		{
			if (xn->Country == NULL || UniSoftStrCmp(xn->Country, cn->Country) != 0)
			{
				// Country 不一致
				b = false;
			}
		}

		if (cn->State != NULL && (UniIsEmptyStr(cn->State) == false))
		{
			if (xn->State == NULL || UniSoftStrCmp(xn->State, cn->State) != 0)
			{
				// State 不一致
				b = false;
			}
		}

		if (cn->Local != NULL && (UniIsEmptyStr(cn->Local) == false))
		{
			if (xn->Local == NULL || UniSoftStrCmp(xn->Local, cn->Local) != 0)
			{
				// Local 不一致
				b = false;
			}
		}
	}

	return b;
}

// 管理オプションのヘルプ文字列を取得する
wchar_t *GetHubAdminOptionHelpString(char *name)
{
	char tmp[MAX_SIZE];
	wchar_t *ret;
	// 引数チェック
	if (name == NULL)
	{
		return L"";
	}

	Format(tmp, sizeof(tmp), "HUB_AO_%s", name);

	ret = _UU(tmp);
	if (UniIsEmptyStr(ret))
	{
		ret = _UU("HUB_AO_UNKNOWN");
	}

	return ret;
}

// 仮想 HUB にデフォルトの管理オプションを追加する
void AddHubAdminOptionsDefaults(HUB *h, bool lock)
{
	UINT i;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	if (lock)
	{
		LockList(h->AdminOptionList);
	}

	for (i = 0;i < num_admin_options;i++)
	{
		ADMIN_OPTION *e = &admin_options[i];
		ADMIN_OPTION t, *r;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), e->Name);

		r = Search(h->AdminOptionList, &t);
		if (r == NULL)
		{
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}
	}

	if (lock)
	{
		UnlockList(h->AdminOptionList);
	}
}

// 仮想 HUB のすべての管理オプションの削除
void DeleteAllHubAdminOption(HUB *h, bool lock)
{
	UINT i;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	if (lock)
	{
		LockList(h->AdminOptionList);
	}

	for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
	{
		Free(LIST_DATA(h->AdminOptionList, i));
	}

	DeleteAll(h->AdminOptionList);

	if (lock)
	{
		UnlockList(h->AdminOptionList);
	}
}

// 仮想 HUB の管理オプションの取得
UINT GetHubAdminOptionEx(HUB *h, char *name, UINT default_value)
{
	UINT ret = default_value;
	// 引数チェック
	if (h == NULL || name == NULL)
	{
		return 0;
	}

	LockList(h->AdminOptionList);
	{
		ADMIN_OPTION *a, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), name);
		Trim(t.Name);

		a = Search(h->AdminOptionList, &t);

		if (a != NULL)
		{
			ret = a->Value;
		}
	}
	UnlockList(h->AdminOptionList);

	return ret;
}
UINT GetHubAdminOption(HUB *h, char *name)
{
	return GetHubAdminOptionEx(h, name, 0);
}

// 管理オプション
int CompareAdminOption(void *p1, void *p2)
{
	ADMIN_OPTION *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ADMIN_OPTION **)p1;
	a2 = *(ADMIN_OPTION **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	return StrCmpi(a1->Name, a2->Name);
}

// 番犬開始
void StartHubWatchDog(HUB *h)
{
	THREAD *t;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = false;
	h->WatchDogEvent = NewEvent();

	t = NewThread(HubWatchDogThread, h);
	WaitThreadInit(t);
	ReleaseThread(t);
}

// 番犬停止
void StopHubWatchDog(HUB *h)
{
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = true;
	Set(h->WatchDogEvent);

	WaitThread(h->WatchDogThread, INFINITE);
	ReleaseThread(h->WatchDogThread);
	h->WatchDogThread = NULL;
	h->HaltWatchDog = false;

	ReleaseEvent(h->WatchDogEvent);
	h->WatchDogEvent = NULL;
}

// 番犬スレッド
void HubWatchDogThread(THREAD *t, void *param)
{
	UINT num_packets_v4 = 0;
	UINT num_packets_v6 = 0;
	HUB *hub;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	hub = (HUB *)param;

	hub->WatchDogThread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	while (true)
	{
		LIST *o;
		LIST *o2;
		UINT i, num;
		UINT interval;
		UINT wait_time = 100;
		if (hub->HaltWatchDog)
		{
			break;
		}

		o = NewListFast(NULL);
		o2 = NewListFast(NULL);

		// ARP パケットの送信
		LockList(hub->IpTable);
		{
			num = LIST_NUM(hub->IpTable);
			for (i = 0;i < LIST_NUM(hub->IpTable);i++)
			{
				IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

				if ((e->UpdatedTime + (UINT64)(IP_TABLE_EXPIRE_TIME)) > Tick64())
				{
					if (e->MacAddress[0] != 0xff || e->MacAddress[1] != 0xff || e->MacAddress[2] != 0xff ||
						e->MacAddress[3] != 0xff || e->MacAddress[4] != 0xff || e->MacAddress[5] != 0xff)
					{
						if (hub->Option != NULL && hub->Option->NoArpPolling == false)
						{
							if (IsIP4(&e->Ip))
							{
								// IPv4
								MAC_HEADER *mac = ZeroMalloc(sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
								ARPV4_HEADER *p = (ARPV4_HEADER *)(((UCHAR *)mac) + sizeof(MAC_HEADER));

								Copy(mac->DestAddress, e->MacAddress, 6);
								Copy(mac->SrcAddress, hub->HubMacAddr, 6);
								mac->Protocol = Endian16(MAC_PROTO_ARPV4);

								p->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
								p->ProtocolType = Endian16(MAC_PROTO_IPV4);
								p->HardwareSize = 6;
								p->ProtocolSize = 4;
								p->Operation = Endian16(ARP_OPERATION_REQUEST);
								Copy(p->SrcAddress, hub->HubMacAddr, 6);
								p->SrcIP = IPToUINT(&hub->HubIp);
								p->TargetAddress[0] =
									p->TargetAddress[1] =
									p->TargetAddress[2] =
									p->TargetAddress[3] =
									p->TargetAddress[4] =
									p->TargetAddress[5] = 0x00;
								p->TargetIP = IPToUINT(&e->Ip);
								Insert(o, mac);
							}
						}

						if (hub->Option != NULL && hub->Option->NoIPv6AddrPolling == false)
						{
							if (IsIP6(&e->Ip))
							{
								// IPv6
								BUF *buf;
								IPV6_ADDR ip6addr;

								if (IPToIPv6Addr(&ip6addr, &e->Ip))
								{
									buf = BuildICMPv6NeighborSoliciation(&hub->HubIpV6,
										&ip6addr,
										hub->HubMacAddr, ++hub->HubIP6Id);

									if (buf != NULL)
									{
										BUF *buf2 = NewBuf();
										MAC_HEADER mac;

										Zero(&mac, sizeof(mac));

										Copy(mac.DestAddress, e->MacAddress, 6);
										Copy(mac.SrcAddress, hub->HubMacAddr, 6);
										mac.Protocol = Endian16(MAC_PROTO_IPV6);

										WriteBuf(buf2, &mac, sizeof(MAC_HEADER));

										WriteBuf(buf2, buf->Buf, buf->Size);

										FreeBuf(buf);

										Insert(o2, buf2);
									}
								}
							}
						}
					}
				}
			}
		}
		UnlockList(hub->IpTable);

		if ((LIST_NUM(o) + LIST_NUM(o2)) != 0)
		{
			interval = HUB_ARP_SEND_INTERVAL / (LIST_NUM(o) + LIST_NUM(o2));
		}
		else
		{
			interval = HUB_ARP_SEND_INTERVAL;
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			PKT *packet;
			void *p = LIST_DATA(o, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				for (;i < LIST_NUM(o);i++)
				{
					Free(LIST_DATA(o, i));
				}
				ReleaseList(o);

				for (i = 0;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket((UCHAR *)p, sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v4++;
			}
			else
			{
				Free(p);
			}
		}

		for (i = 0;i < LIST_NUM(o2);i++)
		{
			PKT *packet;
			BUF *buf = LIST_DATA(o2, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				ReleaseList(o);

				for (;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket(buf->Buf, buf->Size);
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v6++;
			}
			else
			{
				Free(buf->Buf);
			}

			Free(buf);
		}

		ReleaseList(o);
		ReleaseList(o2);

		if (num == 0)
		{
			wait_time = HUB_ARP_SEND_INTERVAL;
		}

		Wait(hub->WatchDogEvent, wait_time);
	}
ESCAPE:
	return;
}

// SecureNAT を有効/無効に設定する
void EnableSecureNAT(HUB *h, bool enable)
{
	EnableSecureNATEx(h, enable, false);
}
void EnableSecureNATEx(HUB *h, bool enable, bool no_change)
{
	bool for_cluster = false;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (h->Type == HUB_TYPE_FARM_DYNAMIC)
		{
			for_cluster = true;
		}
	}

	Lock(h->lock_online);
	{
		if (no_change == false)
		{
			h->EnableSecureNAT = enable;
		}

		if (h->EnableSecureNAT == false)
		{
STOP:
			// すでに開始している場合は停止する
			if (h->SecureNAT != NULL)
			{
				SnFreeSecureNAT(h->SecureNAT);
				h->SecureNAT = NULL;
			}
		}
		else
		{
			if (for_cluster)
			{
				if ((h->SecureNAT != NULL && LIST_NUM(h->SessionList) <= 1) ||
					(h->SecureNAT == NULL && LIST_NUM(h->SessionList) == 0))
				{
					// 開始モードだが、ダイナミック仮想 HUB で他にセッションが無い場合
					// は停止する
					goto STOP;
				}
			}

			// まだ開始していない場合で HUB がオンラインの場合は開始する
			if (h->SecureNAT == NULL && h->Offline == false)
			{
				h->SecureNAT = SnNewSecureNAT(h, h->SecureNATOption);
			}
		}
	}
	Unlock(h->lock_online);
}

// アクセスリストを文字列に変換する
void GetAccessListStr(char *str, UINT size, ACCESS *a)
{
	char tmp[MAX_SIZE];
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool l3 = false;
	bool asterisk = false;
	// 引数チェック
	if (str == NULL || a == NULL)
	{
		return;
	}

	StrCpy(str, size, "");

	if (a->IsIPv6 == false)
	{
		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->SrcIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->SrcSubnetMask);
			Format(tmp, sizeof(tmp), "SrcIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->DestIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->DestSubnetMask);
			Format(tmp, sizeof(tmp), "DstIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}
	else
	{
		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false || IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->SrcIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->SrcSubnetMask6);
			Format(tmp, sizeof(tmp), "SrcIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false || IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->DestIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->DestSubnetMask6);
			Format(tmp, sizeof(tmp), "DstIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}

	if (a->Protocol != 0)
	{
		StrCpy(tmp1, sizeof(tmp1), "");
		switch (a->Protocol)
		{
		case 1:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv4");
			break;
		case 3:
			StrCpy(tmp1, sizeof(tmp1), "GGP");
			break;
		case 6:
			StrCpy(tmp1, sizeof(tmp1), "TCP");
			break;
		case 8:
			StrCpy(tmp1, sizeof(tmp1), "EGP");
			break;
		case 12:
			StrCpy(tmp1, sizeof(tmp1), "PUP");
			break;
		case 17:
			StrCpy(tmp1, sizeof(tmp1), "UDP");
			break;
		case 20:
			StrCpy(tmp1, sizeof(tmp1), "HMP");
			break;
		case 22:
			StrCpy(tmp1, sizeof(tmp1), "XNS-IDP");
			break;
		case 27:
			StrCpy(tmp1, sizeof(tmp1), "RDP");
			break;
		case 58:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv6");
			break;
		case 66:
			StrCpy(tmp1, sizeof(tmp1), "RVD");
			break;
		}
		Format(tmp, sizeof(tmp), "Protocol=%s(%u), ", tmp1, a->Protocol);
		StrCat(str, size, tmp);

		l3 = true;
	}

	if (a->SrcPortStart != 0)
	{
		if (a->SrcPortEnd == a->SrcPortStart)
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u, ", a->SrcPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u-%u, ", a->SrcPortStart, a->SrcPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (a->DestPortStart != 0)
	{
		if (a->DestPortEnd == a->DestPortStart)
		{
			Format(tmp, sizeof(tmp), "DstPort=%u, ", a->DestPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "DstPort=%u-%u, ", a->DestPortStart, a->DestPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (StrLen(a->SrcUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "SrcUser=%s, ", a->SrcUsername);
		StrCat(str, size, tmp);
	}

	if (StrLen(a->DestUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "DstUser=%s, ", a->DestUsername);
		StrCat(str, size, tmp);
	}

	if (a->CheckSrcMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->SrcMacAddress);
		MacToStr(mask, sizeof(mask), a->SrcMacMask);
		Format(tmp, sizeof(tmp), "SrcMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}
	if (a->CheckDstMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->DstMacAddress);
		MacToStr(mask, sizeof(mask), a->DstMacMask);
		Format(tmp, sizeof(tmp), "DstMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}

	if (a->CheckTcpState)
	{
		if(a->Established)
		{
			StrCat(str, size, "Established, ");
		}
		else
		{
			StrCat(str, size, "Unestablished, ");
		}

		l3 = true;
	}

	if (a->Discard == false)
	{
		if (a->Delay >= 1)
		{
			Format(tmp, sizeof(tmp), "Delay=%u, ", a->Delay);
			StrCat(str, size, tmp);
		}

		if (a->Jitter >= 1)
		{
			Format(tmp, sizeof(tmp), "Jitter=%u, ", a->Jitter);
			StrCat(str, size, tmp);
		}

		if (a->Loss >= 1)
		{
			Format(tmp, sizeof(tmp), "Loss=%u, " , a->Loss);
			StrCat(str, size, tmp);
		}
	}

	if (StrLen(str) == 0)
	{
		asterisk = true;
	}

	if (l3)
	{
		if (a->IsIPv6)
		{
			StrCatLeft(str, size, "(ipv6) ");
		}
		else
		{
			StrCatLeft(str, size, "(ipv4) ");
		}
	}
	else
	{
		StrCatLeft(str, size, "(ether) ");
	}

	if (EndWith(str, ", "))
	{
		str[StrLen(str) - 2] = 0;
	}

	if (asterisk)
	{
		StrCat(str, size, "*");
	}
}

// パケットをアクセスリストによってマスクすることができるかどうか判定する
bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT dest_username, UINT dest_groupname)
{
	UINT src_username;
	UINT src_groupname;
	HUB_PA *pa;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	bool is_ipv4_packet = false;
	bool is_ipv6_packet = false;
	// 引数チェック
	if (s == NULL || p == NULL || a == NULL)
	{
		return false;
	}
	if (a->Active == false)
	{
		// アクセスリストは無効
		return false;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;

	// 送信元のユーザー名ハッシュ
	src_username = pa->UsernameHash;
	src_groupname = pa->GroupnameHash;

	// 送信元・宛先 MAC アドレスの判定
	if (a->CheckSrcMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if((a->SrcMacAddress[i] & a->SrcMacMask[i]) != (a->SrcMacMask[i] & p->MacAddressSrc[i]))
			{
				return false;
			}
		}
	}

	if (a->CheckDstMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if ((a->DstMacAddress[i] & a->DstMacMask[i]) != (a->DstMacMask[i] & p->MacAddressDest[i]))
			{
				return false;
			}
		}
	}

	// 送信元ユーザー名 / グループ名のチェック
	if (a->SrcUsernameHash != 0)
	{
		if ((a->SrcUsernameHash != src_username) && (a->SrcUsernameHash != src_groupname))
		{
			return false;
		}
	}

	// 宛先ユーザー名 / グループ名のチェック
	if (a->DestUsernameHash != 0)
	{
		if ((a->DestUsernameHash != dest_username) && (a->DestUsernameHash != dest_groupname))
		{
			return false;
		}
	}

	// IP パケットの判定
	if (p->TypeL3 != L3_IPV4)
	{
		is_ipv4_packet = false;
	}
	else
	{
		is_ipv4_packet = true;
	}

	if (p->TypeL3 != L3_IPV6)
	{
		is_ipv6_packet = false;
	}
	else
	{
		is_ipv6_packet = true;
	}

	if (is_ipv4_packet)
	{
		ip = p->L3.IPv4Header;
	}

	if (is_ipv6_packet)
	{
		ip6 = p->L3.IPv6Header;
	}

	if (a->IsIPv6 == false)
	{
		// IPv4

		// 送信元 IP アドレスのチェック
		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (p->TypeL3 == L3_ARPV4)
				{
					bool arp_match = false;
					if (p->L3.ARPv4Header->HardwareSize == 6 &&
						Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
						p->L3.ARPv4Header->ProtocolSize == 4 &&
						Endian16(p->L3.ARPv4Header->ProtocolType) == 0x0800)
					{
						UINT uint_ip = p->L3.ARPv4Header->SrcIP;

						if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
						{
							if ((uint_ip & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
							{
							}
							else
							{
								arp_match = true;
							}
						}
					}

					if (arp_match == false)
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				if ((ip->SrcIP & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
				{
					return false;
				}
			}
		}

		// 宛先 IP アドレスのチェック
		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (p->TypeL3 == L3_ARPV4)
				{
					bool arp_match = false;
					if (p->L3.ARPv4Header->HardwareSize == 6 &&
						Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
						p->L3.ARPv4Header->ProtocolSize == 4 &&
						Endian16(p->L3.ARPv4Header->ProtocolType) == 0x0800)
					{
						UINT uint_ip = p->L3.ARPv4Header->TargetIP;

						if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
						{
							if ((uint_ip & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
							{
							}
							else
							{
								arp_match = true;
							}
						}
					}

					if (arp_match == false)
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				if ((ip->DstIP & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
				{
					return false;
				}
			}
		}
	}
	else
	{
		// IPv6

		// 送信元 IP アドレスのチェック
		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false ||
			IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->SrcIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->SrcSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->SrcAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}

		// 宛先 IP アドレスのチェック
		if (IsZeroIP6Addr(&a->DestIpAddress6) == false ||
			IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->DestIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->DestSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->DestAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}
	}

	// IPv4 でも IPv6 でもないパケットはマッチさせない。
	if(is_ipv4_packet == false && is_ipv6_packet==false){
		return false;
	}

	// プロトコル番号のチェック
	if (a->Protocol != 0)
	{
		if (a->IsIPv6 == false)
		{
			if (is_ipv4_packet == false)
			{
				return false;
			}
			else
			{
				if (ip->Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
		else
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				if (p->IPv6HeaderPacketInfo.Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
	}

	// ポート番号のチェック
	if (a->SrcPortStart != 0 || a->DestPortStart != 0 ||
		a->SrcPortEnd != 0 || a->DestPortEnd != 0)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			if (p->TypeL4 == L4_TCP)
			{
				TCP_HEADER *tcp = p->L4.TCPHeader;
				// 送信元ポートのチェック
				if (a->SrcPortStart != 0 || a->SrcPortEnd != 0)
				{
					UINT src_port = Endian16(tcp->SrcPort);
					if (src_port < a->SrcPortStart || src_port > a->SrcPortEnd)
					{
						return false;
					}
				}

				// 宛先ポート番号のチェック
				if (a->DestPortStart != 0 || a->DestPortEnd != 0)
				{
					UINT dest_port = Endian16(tcp->DstPort);
					if (dest_port < a->DestPortStart || dest_port > a->DestPortEnd)
					{
						return false;
					}
				}
			}
			else if (p->TypeL4 == L4_UDP)
			{
				UDP_HEADER *udp = p->L4.UDPHeader;
				// 送信元ポートのチェック
				if (a->SrcPortStart != 0 || a->SrcPortEnd != 0)
				{
					UINT src_port = Endian16(udp->SrcPort);
					if (src_port < a->SrcPortStart || src_port > a->SrcPortEnd)
					{
						return false;
					}
				}

				// 宛先ポート番号のチェック
				if (a->DestPortStart != 0 || a->DestPortEnd != 0)
				{
					UINT dest_port = Endian16(udp->DstPort);
					if (dest_port < a->DestPortStart || dest_port > a->DestPortEnd)
					{
						return false;
					}
				}
			}
			else
			{
				// アクセスリストにポート番号が指定されているときは
				// TCP か UDP 以外のパケットは適用されない
				return false;
			}
		}
	}

	// TCP コネクションの状態チェック
	if (a->CheckTcpState != false)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			if(p->TypeL4 == L4_TCP)
			{
				// by shimizu
				TCP_HEADER *tcp = p->L4.TCPHeader;
				bool est = true;

				if (tcp->Flag & TCP_SYN)
				{
					est = false;
				}

				if((MAKEBOOL(a->Established) ^ MAKEBOOL(est)))
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
	}

	return true;
}

// フォワードするパケットに対してアクセスリストを適用する
bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p)
{
	UINT i;
	bool pass = true;	// デフォルトでは通過させる
	bool skip = true;
	// 引数チェック
	if (hub == NULL || src_session == NULL || p == NULL || dest_session == NULL)
	{
		return false;
	}

	// 既にチェックされたパケットはアクセスリストを再適用しない。
	if (p->AccessChecked)
	{
		return true;
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			// あて先ユーザー名が指定されているエントリ以降のみを走査する。
			if (a->DestUsernameHash != 0)
			{
				skip = false;
			}

			if (skip == false)
			{
				if (IsPacketMaskedByAccessList(src_session, p, a,
					((HUB_PA *)dest_session->PacketAdapter->Param)->UsernameHash,
					((HUB_PA *)dest_session->PacketAdapter->Param)->GroupnameHash))
				{
					// パケットの通過または破棄を決定する
					pass = a->Discard ? false : true;

					// リストの走査をここで完了する
					break;
				}
			}
		}
	}
	UnlockList(hub->AccessList);

	return pass;
}

// ストアされたパケットに対してアクセスリストを適用する
bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p)
{
	UINT i;
	bool pass = true;	// デフォルトでは通過させる
	// 引数チェック
	if (hub == NULL || s == NULL || p == NULL)
	{
		return false;
	}

	if (hub->Option != NULL && hub->Option->FilterPPPoE)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x8863 || proto == 0x8864)
			{
				// PPPoE Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterOSPF)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->L3.IPv4Header != NULL)
			{
				if (p->L3.IPv4Header->Protocol == 89)
				{
					// OSPF Filter
					return false;
				}
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterIPv4)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x0800 || proto == 0x0806)
			{
				// IPv4 Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterIPv6)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x86dd)
			{
				// IPv6 Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterNonIP)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (!(proto == 0x86dd || proto == 0x0800 || proto == 0x0806))
			{
				// Non-IP Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterBPDU)
	{
		if (p->MacHeader != NULL)
		{
			if (p->TypeL3 == L3_BPDU)
			{
				// BPDU Filter
				return false;
			}
		}
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
			{
				// あて先ユーザー名が指定されていたら、そこでリストの走査を中断する。
				break;
			}

			if (IsPacketMaskedByAccessList(s, p, a, 0, 0))
			{
				// パケットの通過または破棄を決定する
				pass = a->Discard ? false : true;

				// ここで処理が決定したパケットはHUBを出るときに走査しない。
				p->AccessChecked = true;

				// 遅延・ジッタ・パケットロスのパラメータのコピー
				p->Delay = a->Delay;
				p->Jitter = a->Jitter;
				p->Loss = a->Loss;

				// リストの走査をここで完了する
				break;
			}
		}
	}
	UnlockList(hub->AccessList);

	return pass;
}

// アクセスリストの追加
void AddAccessList(HUB *hub, ACCESS *a)
{
	// 引数チェック
	if (hub == NULL || a == NULL)
	{
		return;
	}

	LockList(hub->AccessList);
	{
		ACCESS *access;
		UINT i;

		// 個数のチェック
		if (LIST_NUM(hub->AccessList) >= MAX_ACCESSLISTS)
		{
			UnlockList(hub->AccessList);
			return;
		}

		access = Malloc(sizeof(ACCESS));
		Copy(access, a, sizeof(ACCESS));
		access->SrcUsernameHash = UsernameToInt(access->SrcUsername);
		access->DestUsernameHash = UsernameToInt(access->DestUsername);

		// ポート番号補正
		if (access->SrcPortStart != 0)
		{
			access->SrcPortEnd = MAX(access->SrcPortEnd, access->SrcPortStart);
		}
		if (access->DestPortStart != 0)
		{
			access->DestPortEnd = MAX(access->DestPortEnd, access->DestPortStart);
		}

		// 遅延、ジッタ、パケットロスの補正
		access->Delay = MAKESURE(access->Delay, 0, HUB_ACCESSLIST_DELAY_MAX);
		access->Jitter = MAKESURE(access->Jitter, 0, HUB_ACCESSLIST_JITTER_MAX);
		access->Loss = MAKESURE(access->Loss, 0, HUB_ACCESSLIST_LOSS_MAX);

		Insert(hub->AccessList, access);

		// ID を振り直す
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);
			a->Id = (i + 1);
		}
	}
	UnlockList(hub->AccessList);
}

// アクセスリストの初期化
void InitAccessList(HUB *hub)
{
	// 引数チェック
	if (hub == NULL)
	{
		return;
	}

	hub->AccessList = NewList(CmpAccessList);
}

// アクセスリストの解放
void FreeAccessList(HUB *hub)
{
	UINT i;
	// 引数チェック
	if (hub == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(hub->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(hub->AccessList, i);
		Free(a);
	}

	ReleaseList(hub->AccessList);
	hub->AccessList = NULL;
}

// アクセスリストの比較
int CmpAccessList(void *p1, void *p2)
{
	ACCESS *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ACCESS **)p1;
	a2 = *(ACCESS **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	// 優先順位別にソートする
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Discard > a2->Discard)
	{
		return 1;
	}
	else if (a1->Discard < a2->Discard)
	{
		return -1;
	}
	else
	{
		return Cmp(&a1->Active, &a2->Active, sizeof(ACCESS) - 4);
	}
}

// ユーザー名を UINT に変換
UINT UsernameToInt(char *name)
{
	UCHAR hash[SHA1_SIZE];
	UINT ret;
	char tmp[MAX_USERNAME_LEN + 1];
	// 引数チェック
	if (name == 0 || StrLen(name) == 0)
	{
		return 0;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	if (StrLen(tmp) == 0)
	{
		return 0;
	}

	Hash(hash, tmp, StrLen(tmp), true);
	Copy(&ret, hash, sizeof(ret));

	return ret;
}

// セッションポインタからセッションを検索
SESSION *GetSessionByPtr(HUB *hub, void *ptr)
{
	// 引数チェック
	if (hub == NULL || ptr == NULL)
	{
		return NULL;
	}

	LockList(hub->SessionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(hub->SessionList);i++)
		{
			SESSION *s = LIST_DATA(hub->SessionList, i);
			if (s == (SESSION *)ptr)
			{
				// 発見
				AddRef(s->ref);
				UnlockList(hub->SessionList);
				return s;
			}
		}
	}
	UnlockList(hub->SessionList);

	return NULL;
}

// セッション名からセッションを検索
SESSION *GetSessionByName(HUB *hub, char *name)
{
	// 引数チェック
	if (hub == NULL || name == NULL)
	{
		return NULL;
	}

	LockList(hub->SessionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(hub->SessionList);i++)
		{
			SESSION *s = LIST_DATA(hub->SessionList, i);
			if (StrCmpi(s->Name, name) == 0)
			{
				// 発見
				AddRef(s->ref);
				UnlockList(hub->SessionList);
				return s;
			}
		}
	}
	UnlockList(hub->SessionList);

	return NULL;
}

// STORM リストのソート
int CompareStormList(void *p1, void *p2)
{
	STORM *s1, *s2;
	UINT r;
	// 引数チェック
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(STORM **)p1;
	s2 = *(STORM **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}
	r = CmpIpAddr(&s1->DestIp, &s2->DestIp);
	if (r != 0)
	{
		return r;
	}
	r = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
	if (r != 0)
	{
		return r;
	}
	r = Cmp(s1->MacAddress, s2->MacAddress, 6);
	return r;
}

// パケットアダプタ初期化
bool HubPaInit(SESSION *s)
{
	// パケットアダプタ情報の初期化
	HUB_PA *pa = ZeroMalloc(sizeof(HUB_PA));
	pa->Cancel = NewCancel();
	pa->PacketQueue = NewQueue();
	pa->Now = Tick64();
	pa->Session = s;
	pa->StormList = NewList(CompareStormList);
	pa->UsernameHash = UsernameToInt(s->Username);
	pa->GroupnameHash = UsernameToInt(s->GroupName);

	s->PacketAdapter->Param = pa;

	if (s->Policy->MonitorPort)
	{
		// このポートをモニタリングポートとしてマークする
		pa->MonitorPort = true;

		// HUB のモニタリングポート一覧にこのセッションを追加する
		LockList(s->Hub->MonitorList);
		{
			Insert(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	return true;
}

// パケットアダプタ解放
void HubPaFree(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	HUB *hub = s->Hub;

	if (pa->MonitorPort)
	{
		// HUB のモニタポート一覧からこのセッションを削除する
		LockList(s->Hub->MonitorList);
		{
			Delete(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	// このセッションに関連付けられている MAC アドレステーブルを消去
	LockList(hub->MacTable);
	{
		UINT i, num = LIST_NUM(hub->MacTable);
		LIST *o = NewListFast(NULL);
		for (i = 0;i < num;i++)
		{
			MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)LIST_DATA(hub->MacTable, i);
			if (e->Session == s)
			{
				Add(o, e);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)LIST_DATA(o, i);
			Delete(hub->MacTable, e);
			Free(e);
		}
		ReleaseList(o);
	}
	{
		UINT i, num = LIST_NUM(hub->IpTable);
		LIST *o = NewListFast(NULL);
		for (i = 0;i < num;i++)
		{
			IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);
			if (e->Session == s)
			{
				Add(o, e);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP_TABLE_ENTRY *e = LIST_DATA(o, i);
			Delete(hub->IpTable, e);
			Free(e);
		}
		ReleaseList(o);
	}
	UnlockList(hub->MacTable);

	// STORM リストを解放
	LockList(pa->StormList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(pa->StormList);i++)
		{
			STORM *s = (STORM *)LIST_DATA(pa->StormList, i);
			Free(s);
		}
		DeleteAll(pa->StormList);
	}
	UnlockList(pa->StormList);

	ReleaseList(pa->StormList);

	// キューに残っているパケットを解放
	LockQueue(pa->PacketQueue);
	{
		BLOCK *b;

		while (b = GetNext(pa->PacketQueue))
		{
			// ブロックの解放
			FreeBlock(b);
		}
	}
	UnlockQueue(pa->PacketQueue);

	// キューを解放
	ReleaseQueue(pa->PacketQueue);

	// キャンセルオブジェクトの解放
	ReleaseCancel(pa->Cancel);

	// パケットアダプタ情報の解放
	Free(pa);
	s->PacketAdapter->Param = NULL;
}

// キャンセルオブジェクトの取得
CANCEL *HubPaGetCancel(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	AddRef(pa->Cancel->ref);
	return pa->Cancel;
}

// 次の送信予定パケットの取得
UINT HubPaGetNextPacket(SESSION *s, void **data)
{
	UINT ret = 0;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	// キューの先頭から 1 つ取得する
	LockQueue(pa->PacketQueue);
	{
		BLOCK *block = GetNext(pa->PacketQueue);
		if (block == NULL)
		{
			// キュー無し
			ret = 0;
		}
		else
		{
			// あった
			*data = block->Buf;
			ret = block->Size;
			// ブロックの構造体のメモリは解放する
			Free(block);
		}
	}
	UnlockQueue(pa->PacketQueue);

	return ret;
}

// パケットの受信
bool HubPaPutPacket(SESSION *s, void *data, UINT size)
{
	PKT *packet;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	bool b = false;
	HUB *hub;
	bool no_l3 = false;
	LIST *o = NULL;
	UINT i;
	UINT vlan_type_id = 0;
	bool no_look_bpdu_bridge_id = false;

	hub = s->Hub;

	pa->Now = Tick64();

	if (data == NULL)
	{
		// 遅延パケットのチェック
		o = NULL;
		LockList(s->DelayedPacketList);
		{
			UINT i;
			if (LIST_NUM(s->DelayedPacketList) >= 1)
			{
				UINT64 now = TickHighres64();
				for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
				{
					PKT *p = LIST_DATA(s->DelayedPacketList, i);

					if (now >= p->DelayedForwardTick)
					{
						if (o == NULL)
						{
							o = NewListFast(NULL);
						}

						Add(o, p);
					}
				}
			}

			if (o != NULL)
			{
				for (i = 0;i < LIST_NUM(o);i++)
				{
					PKT *p = LIST_DATA(o, i);

					Delete(s->DelayedPacketList, p);
				}
			}
		}
		UnlockList(s->DelayedPacketList);

		// 遅延パケットがある場合はストアする
		if (o != NULL)
		{
			for (i = 0;i < LIST_NUM(o);i++)
			{
				PKT *p = LIST_DATA(o, i);

				StorePacket(s->Hub, s, p);
			}

			ReleaseList(o);
		}

		// このセッションからのすべてのパケットの受信が完了した
		CancelList(s->CancelList);

		// イールドする
		if (hub->Option != NULL && hub->Option->YieldAfterStorePacket)
		{
			YieldCpu();
		}

		return true;
	}

	if (hub != NULL && hub->Option != NULL && hub->Option->DisableIPParsing)
	{
		no_l3 = true;
	}

	if (hub != NULL && hub->Option != NULL)
	{
		vlan_type_id = hub->Option->VlanTypeId;
		no_look_bpdu_bridge_id = hub->Option->NoLookBPDUBridgeId;
	}

	// VLAN タグを挿入する
	if (s->VLanId != 0)
	{
		VLanInsertTag(&data, &size, s->VLanId);
	}

	// パケットをパースする
	packet = ParsePacketEx3(data, size, no_l3, vlan_type_id, !no_look_bpdu_bridge_id);

	if (packet != NULL)
	{
		if (packet->InvalidSourcePacket)
		{
			// 不正な送信元のパケット
			FreePacket(packet);
			packet = NULL;
		}
	}

	if (packet != NULL)
	{
		// パケットのストア
		StorePacket(s->Hub, s, packet);
	}
	else
	{
		// 不良パケット (正しい MAC フレームではない)
		// であるのでパケットデータを解放する
		Free(data);
	}

	return true;
}

// ブロードキャストストームが発生しないようにチェックするアルゴリズム
// 特定のエンドポイントからのブロードキャストが頻繁に来た場合はフィルタリングする
bool CheckBroadcastStorm(SESSION *s, PKT *p)
{
	IP src_ip, dest_ip;
	HUB_PA *pa;
	UINT64 now = Tick64();
	UINT limit_start_count;
	SESSION *sess = s;
	bool ret = true;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (s->Policy->NoBroadcastLimiter)
	{
		// ブロードキャスト数の制限無し
		return true;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;

	if (p->TypeL3 == L3_IPV4)
	{
		UINTToIP(&src_ip, p->L3.IPv4Header->SrcIP);
		UINTToIP(&dest_ip, p->L3.IPv4Header->DstIP);
	}
	else if (p->TypeL3 == L3_ARPV4)
	{
		UINTToIP(&src_ip, p->L3.ARPv4Header->SrcIP);
		Zero(&dest_ip, sizeof(IP));
	}
	else if (p->TypeL3 == L3_IPV6)
	{
		IPv6AddrToIP(&src_ip, &p->L3.IPv6Header->SrcAddress);
		IPv6AddrToIP(&dest_ip, &p->L3.IPv6Header->DestAddress);
	}
	else
	{
		Zero(&src_ip, sizeof(IP));
		Zero(&dest_ip, sizeof(IP));
	}

	// 1 間隔ごとに制限を開始する個数
	limit_start_count = 32;

	if (s->Hub != NULL && s->Hub->Option->BroadcastStormDetectionThreshold != 0)
	{
		limit_start_count = s->Hub->Option->BroadcastStormDetectionThreshold;
	}

	LockList(pa->StormList);
	{
		STORM *s;
		UINT num;
		s = SearchStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip);
		if (s == NULL)
		{
			s = AddStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip);
		}

		s->CurrentBroadcastNum++;

		if ((s->CheckStartTick + STORM_CHECK_SPAN) < now ||
			s->CheckStartTick == 0 || s->CheckStartTick > now)
		{
			// 一定期間ごとにブロードキャスト数を計測する
			UINT64 diff_time;
			if (s->CheckStartTick < now)
			{
				diff_time = now - s->CheckStartTick;
			}
			else
			{
				diff_time = 0;
			}
			s->CheckStartTick = now;
			num = (UINT)((UINT64)s->CurrentBroadcastNum * (UINT64)1000 / (UINT64)STORM_CHECK_SPAN);
			s->CurrentBroadcastNum = 0;
			if (num >= limit_start_count)
			{
				char ip1[64];
				char ip2[64];
				char mac[MAX_SIZE];
				IPToStr(ip1, sizeof(ip1), &src_ip);
				IPToStr(ip2, sizeof(ip2), &dest_ip);
				ret = false;
				if (s->DiscardValue < STORM_DISCARD_VALUE_END)
				{
					s->DiscardValue = MAX(s->DiscardValue, 1) * 2;
				}
				Debug("s->DiscardValue: %u  (%u)\n", s->DiscardValue, num);

				MacToStr(mac, sizeof(mac), p->MacAddressSrc);

				HLog(sess->Hub, "LH_BCAST_STORM", sess->Name, mac, ip1, ip2, num);
			}
			else
			{
				if (s->DiscardValue >= 1)
				{
					s->DiscardValue = (UINT)((UINT64)s->DiscardValue / MAX((UINT64)2, (UINT64)diff_time / (UINT64)STORM_CHECK_SPAN));
				}
			}
		}

		if (s->DiscardValue >= STORM_DISCARD_VALUE_START)
		{
			if (s->DiscardValue >= 128)
			{
				ret = false;
			}
			else if ((rand() % s->DiscardValue) != 0)
			{
				ret = false;
			}
		}

	}
	UnlockList(pa->StormList);

	return ret;
}

// パケットのストア
void StorePacket(HUB *hub, SESSION *s, PKT *packet)
{
	MAC_TABLE_ENTRY *entry = NULL;
	MAC_TABLE_ENTRY t;
	void *data;
	UINT size;
	bool broadcast_mode;
	HUB_PA *dest_pa;
	SESSION *dest_session;
	TRAFFIC traffic;
	UINT64 now = Tick64();
	// 引数チェック
	if (hub == NULL || packet == NULL)
	{
		return;
	}

	if (s != NULL)
	{
		if (((HUB_PA *)s->PacketAdapter->Param)->MonitorPort)
		{
			// モニタポートからもらったパケットはフォワードしてはならない
			Free(packet->PacketData);
			FreePacket(packet);
			return;
		}
	}

	// MAC アドレステーブル全体をロック
	LockList(hub->MacTable);
	{
		// フィルタリング
		if (s != NULL && (packet->DelayedForwardTick == 0 && StorePacketFilter(s, packet) == false))
		{
DISCARD_PACKET:
			// 通過が不許可となったのでパケットを解放する
			Free(packet->PacketData);
			FreePacket(packet);
		}
		else // 通過が許可された
		{
			bool forward_now = true;

			if (packet->Loss >= 1)
			{
				// パケットロスを発生させる
				UINT r = rand() % 100;
				if ((packet->Loss >= 100) || (r < packet->Loss))
				{
					// パケットロス
					goto DISCARD_PACKET;
				}
			}

			if (packet->Delay >= 1)
			{
				float delay = (float)packet->Delay;
				float jitter;
				UINT delay_uint;
				bool f = Rand1();
				if (packet->Jitter == 0)
				{
					jitter = 0;
				}
				else
				{
					jitter = (float)(Rand32() % (int)((float)packet->Jitter * delay / 100.0f));
				}

				delay += jitter * (f ? 1 : -1);
				delay_uint = (UINT)delay;

				if (delay_uint >= 1)
				{
					// 遅延を発生させる
					forward_now = false;
					packet->Loss = packet->Jitter = packet->Delay = 0;
					packet->DelayedForwardTick = TickHighres64() + (UINT64)delay_uint;
					packet->DelayedSrcSession = s;

					LockList(s->DelayedPacketList);
					{
						Add(s->DelayedPacketList, packet);
					}
					UnlockList(s->DelayedPacketList);
				}
			}

			if (forward_now)
			{
				if (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) == 0)
				{
					if (s != NULL)
					{
						// この HUB 自身が発信しようとしたパケットが外部から入力された
						goto DISCARD_PACKET;
					}
				}
				if (s != NULL && (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) != 0))
				{
					// 送信元 MAC アドレスがテーブルに登録されているかどうか調べる
					Copy(t.MacAddress, packet->MacAddressSrc, 6);
					if (hub->Option->NoManageVlanId == false)
					{
						t.VlanId = packet->VlanId;
					}
					else
					{
						t.VlanId = 0;
					}
					entry = Search(hub->MacTable, &t);

					if (entry == NULL)
					{
						// 古いエントリを削除する
						DeleteExpiredMacTableEntry(hub->MacTable);

						// 登録されていないので登録する
						if (s->Policy->MaxMac != 0 || s->Policy->NoBridge)
						{
							UINT i, num_mac_for_me = 0;
							UINT limited_count;

							// 現在このセッションで登録されている MAC アドレス数を調べる
							for (i = 0;i < LIST_NUM(hub->MacTable);i++)
							{
								MAC_TABLE_ENTRY *e = LIST_DATA(hub->MacTable, i);
								if (e->Session == s)
								{
									num_mac_for_me++;
								}
							}

							limited_count = 0xffffffff;
							if (s->Policy->NoBridge)
							{
								limited_count = MIN(limited_count, MAC_MIN_LIMIT_COUNT);
							}
							if (s->Policy->MaxMac != 0)
							{
								limited_count = MIN(limited_count, s->Policy->MaxMac);
							}
							limited_count = MAX(limited_count, MAC_MIN_LIMIT_COUNT);

							if (num_mac_for_me >= limited_count)
							{
								// すでに登録されている MAC アドレス数が上限を超えている
								char mac_str[64];

								if (s != NULL)
								{
									MacToStr(mac_str, sizeof(mac_str), packet->MacAddressSrc);
									if (s->Policy->NoBridge)
									{
										HLog(hub, "LH_BRIDGE_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
									}
									else
									{
										HLog(hub, "LH_MAC_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
									}
								}

								goto DISCARD_PACKET;	// パケット破棄
							}
						}

						if (LIST_NUM(hub->MacTable) >= MAX_MAC_TABLES)
						{
							// MAC テーブルデータベースが最大件数を超えたので
							// 最も古いテーブルを削除する
							UINT i;
							UINT64 old_time = 0xffffffffffffffffULL;
							MAC_TABLE_ENTRY *old_entry = NULL;
							for (i = 0;i < LIST_NUM(hub->MacTable);i++)
							{
								MAC_TABLE_ENTRY *e = LIST_DATA(hub->MacTable, i);
								if (e->UpdatedTime <= old_time)
								{
									old_time = e->CreatedTime;
									old_entry = e;
								}
							}
							if (old_entry != NULL)
							{
								Delete(hub->MacTable, old_entry);
								Free(old_entry);
							}
						}

						entry = ZeroMalloc(sizeof(MAC_TABLE_ENTRY));
						entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
						Copy(entry->MacAddress, packet->MacAddressSrc, 6);
						if (hub->Option->NoManageVlanId == false)
						{
							entry->VlanId = packet->VlanId;
						}
						else
						{
							entry->VlanId = 0;
						}
						entry->Session = s;
						entry->UpdatedTime = entry->CreatedTime = now;

						Insert(hub->MacTable, entry);

						if (hub->Option->NoMacAddressLog == false)
						{
							// デバッグ表示
							char mac_address[32];

							if (s != NULL)
							{
								MacToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc);
//								Debug("Register MAC Address %s to Session %X.\n", mac_address, s);

								if (packet->VlanId == 0)
								{
									HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
								}
								else
								{
									HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, packet->VlanId);
								}
							}
						}
					}
					else
					{
						if (entry->Session == s)
						{
							// 既に登録されているので何もしない
							entry->UpdatedTime = now;
						}
						else
						{
							// 既に登録されていて自分のセッション以外である
							if (s->Policy->CheckMac && (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) != 0) &&
								((entry->UpdatedTime + MAC_TABLE_EXCLUSIVE_TIME) >= now))
							{
								UCHAR *mac = packet->MacAddressSrc;
								if (hub->Option != NULL && hub->Option->FixForDLinkBPDU &&
									(mac[0] == 0x00 && mac[1] == 0x80 && mac[2] == 0xc8 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00) ||
									(mac[0] == 0x00 && mac[1] == 0x0d && mac[2] == 0x88 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00))
								{
									// D-Link 用バグ対策。D-Link のスパニングツリーパケットは上記アドレスから送出される。
									// ローカルブリッジ時の CheckMac オプションが悪影響を与えることがある。
									// そこで例外的に処理。
									UCHAR hash[MD5_SIZE];
									UINT64 tick_diff = Tick64() - s->LastDLinkSTPPacketSendTick;

									Hash(hash, packet->PacketData, packet->PacketSize, false);

									if ((s->LastDLinkSTPPacketSendTick != 0) &&
										(tick_diff < 750ULL) &&
										(Cmp(hash, s->LastDLinkSTPPacketDataHash, MD5_SIZE) == 0))
									{
										// 750ms より前に同一パケットを送信した場合は破棄
										Debug("D-Link Discard %u\n", (UINT)tick_diff);
										goto DISCARD_PACKET;	// パケット破棄
									}
									else
									{
										goto UPDATE_FDB;
									}
								}
								else
								{
									if (0)
									{
										// CheckMac ポリシーが有効な場合
										// 別のセッションが同じ MAC アドレスを持っていることは禁止されている
										// (2 バイト目が 0xAE の場合はこのチェックを行わない)
										char mac_address[32];
										BinToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc, 6);
									}
								}

								goto DISCARD_PACKET;	// パケット破棄
							}
							else
							{
								// MAC アドレステーブルのセッションと HUB_PA を書き換える
								char mac_address[32];
UPDATE_FDB:
								BinToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc, 6);

								entry->Session = s;
								entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
								entry->UpdatedTime = entry->CreatedTime = now;

								if (1)
								{
									// デバッグ表示
									char mac_address[32];

									if (s != NULL)
									{
										MacToStr(mac_address, sizeof(mac_address), packet->MacHeader->SrcAddress);
										Debug("Register MAC Address %s to Session %X.\n", mac_address, s);
										if (packet->VlanId == 0)
										{
											HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
										}
										else
										{
											HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, packet->VlanId);
										}
									}
								}
							}
						}
					}
				}

				broadcast_mode = false;
				dest_pa = NULL;
				dest_session = NULL;

				if (packet->BroadcastPacket)
				{
					// ブロードキャストパケット
					broadcast_mode = true;
				}
				else
				{
					// 宛先 MAC アドレスがテーブルに登録されているかどうか調べる
					Copy(t.MacAddress, packet->MacAddressDest, 6);
					if (hub->Option->NoManageVlanId == false)
					{
						t.VlanId = packet->VlanId;
					}
					else
					{
						t.VlanId = 0;
					}
					entry = Search(hub->MacTable, &t);

					if (entry == NULL)
					{
						// 宛先が見つからないのでブロードキャストする
						broadcast_mode = true;
					}
					else
					{
						if (entry->Session != s)
						{
							// 宛先が見つかった
							dest_pa = entry->HubPa;
							dest_session = entry->Session;
						}
						else
						{
							// 宛先が自分自身である不正なパケット
							goto DISCARD_PACKET;
						}
					}
				}

				if (s != NULL && hub->Option->NoIpTable == false)
				{
					if (packet->TypeL3 == L3_IPV6)
					{
						// IPv6 パケット
						IP ip;
						bool b = true;
						UINT ip_type;
						bool dhcp_or_ra = false;

						IPv6AddrToIP(&ip, &packet->L3.IPv6Header->SrcAddress);
						ip_type = GetIPv6AddrType(&packet->L3.IPv6Header->SrcAddress);

						if (!(ip_type & IPV6_ADDR_UNICAST))
						{
							// マルチキャストアドレス
							b = false;
						}
						else if ((ip_type & IPV6_ADDR_LOOPBACK) || (ip_type & IPV6_ADDR_ZERO))
						{
							// ループバックアドレスまたは All-Zero アドレス
							b = false;
						}

						if (packet->TypeL4 == L4_ICMPV6)
						{
							if (packet->ICMPv6HeaderPacketInfo.Type == 133 ||
								packet->ICMPv6HeaderPacketInfo.Type == 134)
							{
								// ICMPv6 RS/RA
								dhcp_or_ra = true;
							}
						}
						else if (packet->TypeL4 == L4_UDP)
						{
							if (Endian16(packet->L4.UDPHeader->DstPort) == 546 ||
								Endian16(packet->L4.UDPHeader->DstPort) == 547)
							{
								// DHCPv6
								dhcp_or_ra = true;
							}
						}

						if (IsHubMacAddress(packet->MacAddressSrc) &&
							IsHubIpAddress64(&packet->L3.IPv6Header->SrcAddress))
						{
							// 仮想 HUB のポーリング用送信元アドレス
							b = false;
						}

						if (b)
						{
							// ICMPv6 RS/RA および DHCPv6 以外のパケット
							IP_TABLE_ENTRY t, *e;

							Copy(&t.Ip, &ip, sizeof(IP));

							// 既存のテーブルに登録されているかどうかチェック
							e = Search(hub->IpTable, &t);

							if (e == NULL)
							{
								// 登録されていないので登録する
								if (s->Policy->NoRoutingV6 || s->Policy->MaxIPv6 != 0)
								{
									UINT i, num_ip_for_me = 0;
									UINT limited_count = 0xffffffff;

									for (i = 0;i < LIST_NUM(hub->IpTable);i++)
									{
										IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

										if (e->Session == s)
										{
											if (IsIP6(&e->Ip))
											{
												num_ip_for_me++;
											}
										}
									}

									if (s->Policy->NoRoutingV6)
									{
										limited_count = MIN(limited_count, IP_LIMIT_WHEN_NO_ROUTING_V6);
									}
									if (s->Policy->MaxIPv6 != 0)
									{
										limited_count = MIN(limited_count, s->Policy->MaxIPv6);
									}
									limited_count = MAX(limited_count, IP_MIN_LIMIT_COUNT_V6);

									if (dhcp_or_ra)
									{
										limited_count = 0xffffffff;
									}

									if (num_ip_for_me >= limited_count)
									{
										// 使用できる IP アドレスの上限を超えているので
										// このパケットを破棄する
										char tmp[64];
										IPToStr(tmp, sizeof(tmp), &ip);
										if (s->Policy->NoRoutingV6 == false)
										{
											HLog(hub, "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
										}
										else
										{
											HLog(hub, "LH_ROUTING_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
										}
										goto DISCARD_PACKET;
									}
								}

								if (IsIPManagementTargetForHUB(&ip, hub))
								{
									// エントリ作成
									e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
									e->CreatedTime = e->UpdatedTime = now;
									e->DhcpAllocated = false;
									Copy(&e->Ip, &ip, sizeof(IP));
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
									e->Session = s;

									DeleteExpiredIpTableEntry(hub->IpTable);

									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										// 古い IP テーブルエントリを削除する
										DeleteOldIpTableEntry(hub->IpTable);
									}

									Insert(hub->IpTable, e);

									if (0)
									{
										char ip_address[64];
										IPToStr(ip_address, sizeof(ip_address), &ip);
										Debug("Registered IP Address %s to Session %X.\n",
											ip_address, s);
									}
								}
							}
							else
							{
								if (e->Session == s)
								{
									// 自分のセッションであるので何もしない
									// 更新日時を上書きする
									e->UpdatedTime = now;
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
								}
								else
								{
									// 別のセッションが以前この IP アドレスを使っていた
									if ((s->Policy->CheckIPv6) &&
										((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
									{
										// 他のセッションがこの IP アドレスを使っているので
										// パケットを破棄する
										char ip_address[32];
										IPToStr(ip_address, sizeof(ip_address), &ip);

										Debug("IP Address %s is Already used by Session %X.\n",
											ip_address, s);

										HLog(hub, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name);

										goto DISCARD_PACKET;
									}
								}
							}
						}
					}
				}

				if (
					(s != NULL) &&
					(hub->Option->NoIpTable == false) &&
					(
						(packet->TypeL3 == L3_IPV4 ||
							(packet->TypeL3 == L3_ARPV4 && packet->L3.ARPv4Header->HardwareSize == 6 &&
							Endian16(packet->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
							packet->L3.ARPv4Header->ProtocolSize == 4 &&
							Endian16(packet->L3.ARPv4Header->ProtocolType) == 0x0800)
						) &&
						(packet->TypeL7 != L7_DHCPV4)
					)
					) // DHCP パケット以外
				{
					// IP パケットまたは ARP 応答パケットの場合は IP アドレステーブルを検索する
					IP_TABLE_ENTRY t, *e;
					IP ip;
					UINT uint_ip = 0;

					if (packet->TypeL3 == L3_IPV4)
					{
						uint_ip = packet->L3.IPv4Header->SrcIP;
					}
					else if (packet->TypeL3 == L3_ARPV4)
					{
						uint_ip = packet->L3.ARPv4Header->SrcIP;
					}

					if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(packet->MacAddressSrc)))
					{
						UINTToIP(&ip, uint_ip);
						Copy(&t.Ip, &ip, sizeof(IP));

						// 既存のテーブルに登録されているかどうかチェック
						e = Search(hub->IpTable, &t);

						if (e == NULL)
						{
							// 登録されていないので登録する
							if (s->Policy->DHCPForce)
							{
								char ipstr[MAX_SIZE];

								// DHCP サーバーによって割り当てられた IP アドレスではない
								// のでこのパケットを破棄する
								IPToStr32(ipstr, sizeof(ipstr), uint_ip);
								HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
								goto DISCARD_PACKET;
							}

	//						if (packet->TypeL3 == L3_ARPV4)
							{
								// すでにこのセッションで登録されている個数を調べる
								if (s->Policy->NoRouting || s->Policy->MaxIP != 0)
								{
									UINT i, num_ip_for_me = 0;
									UINT limited_count = 0xffffffff;

									for (i = 0;i < LIST_NUM(hub->IpTable);i++)
									{
										IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

										if (e->Session == s)
										{
											if (IsIP4(&e->Ip))
											{
												num_ip_for_me++;
											}
										}
									}

									if (s->Policy->NoRouting)
									{
										limited_count = MIN(limited_count, IP_MIN_LIMIT_COUNT);
									}
									if (s->Policy->MaxIP != 0)
									{
										limited_count = MIN(limited_count, s->Policy->MaxIP);
									}
									limited_count = MAX(limited_count, IP_MIN_LIMIT_COUNT);

									if (num_ip_for_me >= limited_count)
									{
										// 使用できる IP アドレスの上限を超えているので
										// このパケットを破棄する
										char tmp[64];
										IPToStr32(tmp, sizeof(tmp), uint_ip);
										if (s->Policy->NoRouting == false)
										{
											HLog(hub, "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
										}
										else
										{
											HLog(hub, "LH_ROUTING_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
										}
										goto DISCARD_PACKET;
									}
								}

								if (IsIPManagementTargetForHUB(&ip, hub))
								{
									// エントリ作成
									e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
									e->CreatedTime = e->UpdatedTime = now;
									e->DhcpAllocated = false;
									Copy(&e->Ip, &ip, sizeof(IP));
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
									e->Session = s;

									DeleteExpiredIpTableEntry(hub->IpTable);

									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										// 古い IP テーブルエントリを削除する
										DeleteOldIpTableEntry(hub->IpTable);
									}

									Insert(hub->IpTable, e);

									if (0)
									{
										char ip_address[64];
										IPToStr(ip_address, sizeof(ip_address), &ip);
										Debug("Registered IP Address %s to Session %X.\n",
											ip_address, s);
									}
								}
							}
						}
						else
						{
							if (e->Session == s)
							{
								// 自分のセッションであるので何もしない
								// 更新日時を上書きする
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
							else
							{
								// 別のセッションが以前この IP アドレスを使っていた
								if ((s->Policy->CheckIP || s->Policy->DHCPForce) &&
									((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
								{
									// 他のセッションがこの IP アドレスを使っているので
									// パケットを破棄する
									char ip_address[32];
									IPToStr(ip_address, sizeof(ip_address), &ip);

									Debug("IP Address %s is Already used by Session %X.\n",
										ip_address, s);

									HLog(hub, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name);

									goto DISCARD_PACKET;
								}

								if (s->Policy->DHCPForce)
								{
									if (e->DhcpAllocated == false)
									{
										char ipstr[MAX_SIZE];

										// DHCP サーバーによって割り当てられた IP アドレスではない
										// のでこのパケットを破棄する
										IPToStr32(ipstr, sizeof(ipstr), uint_ip);
										HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
										goto DISCARD_PACKET;
									}
								}

								// エントリを上書きする
								e->Session = s;
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
						}
					}
				}

				if (s != NULL && broadcast_mode)
				{
					// ブロードキャストパケットのループや
					// 大量のブロードキャストの発生を防止するため
					// Broadcast Storm 回避アルゴリズムを呼び出す
					if (CheckBroadcastStorm(s, packet) == false)
					{
						goto DISCARD_PACKET;
					}
				}

				// トラフィック加算
				Zero(&traffic, sizeof(traffic));
				if (packet->BroadcastPacket)
				{
					// ブロードキャスト
					traffic.Send.BroadcastBytes = packet->PacketSize;
					traffic.Send.BroadcastCount = 1;
				}
				else
				{
					// ユニキャスト
					traffic.Send.UnicastBytes = packet->PacketSize;
					traffic.Send.UnicastCount = 1;
				}

				if (s != NULL)
				{
					AddTrafficForSession(s, &traffic);
				}

				// トラフィック情報の Send と Recv を反転
				Copy(&traffic.Recv, &traffic.Send, sizeof(TRAFFIC_ENTRY));
				Zero(&traffic.Send, sizeof(TRAFFIC_ENTRY));

				// HUB のモニタポートにこのパケットをブロードキャストする
				if (hub->MonitorList->num_item != 0)
				{
					LockList(hub->MonitorList);
					{
						UINT i;
						void *data;
						UINT size = packet->PacketSize;
						for (i = 0;i < LIST_NUM(hub->MonitorList);i++)
						{
							SESSION *monitor_session = (SESSION *)LIST_DATA(hub->MonitorList, i);

							// パケットをフラッディング
							if (monitor_session->PacketAdapter->Param != NULL)
							{
								data = MallocFast(size);
								Copy(data, packet->PacketData, size);
								StorePacketToHubPa((HUB_PA *)monitor_session->PacketAdapter->Param,
									s, data, size, packet);
							}
						}
					}
					UnlockList(hub->MonitorList);
				}

				if (broadcast_mode == false)
				{
					if (dest_pa != NULL)
					{
						if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
							(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
							(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
						{
							DeleteIPv6DefaultRouterInRA(packet);
						}
						if (dest_session->Policy->RSandRAFilter)
						{
							if (packet->TypeL3 == L3_IPV6 &&
								packet->TypeL4 == L4_ICMPV6 &&
								(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
								 packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->DHCPFilter)
						{
							if (packet->TypeL3 == L3_IPV4 &&
								packet->TypeL4 == L4_UDP &&
								packet->TypeL7 == L7_DHCPV4)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->DHCPv6Filter)
						{
							if (packet->TypeL3 == L3_IPV6 &&
								packet->TypeL4 == L4_UDP &&
								(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->ArpDhcpOnly)
						{
							if (packet->BroadcastPacket)
							{
								bool b = true;

								if (packet->TypeL3 == L3_IPV4 &&
									packet->TypeL4 == L4_UDP &&
									packet->TypeL7 == L7_DHCPV4)
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_ARPV4)
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_IPV6 &&
									packet->TypeL4 == L4_UDP &&
									(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_IPV6 &&
									packet->TypeL4 == L4_ICMPV6)
								{
									b = false;
								}

								if (b)
								{
									goto DISCARD_UNICAST_PACKET;
								}
							}
						}
						if (dest_session->Policy->FilterIPv4)
						{
							if (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->FilterIPv6)
						{
							if (packet->TypeL3 == L3_IPV6)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->FilterNonIP)
						{
							if (packet->TypeL3 != L3_IPV4 && packet->TypeL3 != L3_ARPV4 && packet->TypeL3 != L3_IPV6)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						if (s != NULL &&
							(packet->BroadcastPacket == false &&
							s->Policy->PrivacyFilter &&
							dest_session->Policy->PrivacyFilter)
							)
						{
							// プライバシーフィルタ
							if (packet->TypeL3 != L3_ARPV4)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						if (s != NULL)
						{
							if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
								Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						// パケットログをとる
						if (s != NULL)
						{
							PacketLog(s->Hub, s, dest_session, packet);
						}

						// 宛先 HUB_PA にストアする
						StorePacketToHubPa(dest_pa, s, packet->PacketData, packet->PacketSize, packet);

						// トラフィック加算
						AddTrafficForSession(dest_session, &traffic);
					}
					else
					{
DISCARD_UNICAST_PACKET:
						Free(packet->PacketData);
					}
				}
				else
				{
					// すべてのセッションにストアする
					LockList(hub->SessionList);
					{
						UINT i, num = LIST_NUM(hub->SessionList);
						for (i = 0;i < num;i++)
						{
							SESSION *dest_session = LIST_DATA(hub->SessionList, i);
							HUB_PA *dest_pa = (HUB_PA *)dest_session->PacketAdapter->Param;
							bool discard = false;

							if (dest_session != s)
							{
								bool delete_default_router_in_ra = false;

								if (dest_session->VLanId != 0 && packet->TypeL3 == L3_TAGVLAN &&
									packet->VlanId != dest_session->VLanId)
								{
									discard = true;
								}

								if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
									(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
									(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
								{
									if (packet->TypeL3 == L3_IPV6 && packet->TypeL4 == L4_ICMPV6 &&
										(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
									{
										if (packet->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
										{
											delete_default_router_in_ra = true;
										}
									}
								}
								if (dest_session->Policy->RSandRAFilter)
								{
									if (packet->TypeL3 == L3_IPV6 &&
										packet->TypeL4 == L4_ICMPV6 &&
										(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
										 packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
									{
										discard = true;
									}
								}

								if (dest_session->Policy->DHCPFilter)
								{
									if (packet->TypeL3 == L3_IPV4 &&
										packet->TypeL4 == L4_UDP &&
										packet->TypeL7 == L7_DHCPV4)
									{
										discard = true;
									}
								}

								if (dest_session->Policy->DHCPv6Filter)
								{
									if (packet->TypeL3 == L3_IPV6 &&
										packet->TypeL4 == L4_UDP &&
										(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
									{
										discard = true;
									}
								}

								if (dest_session->Policy->ArpDhcpOnly)
								{
									if (packet->BroadcastPacket)
									{
										bool b = true;

										if (packet->TypeL3 == L3_IPV4 &&
											packet->TypeL4 == L4_UDP &&
											packet->TypeL7 == L7_DHCPV4)
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_ARPV4)
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_IPV6 &&
											packet->TypeL4 == L4_UDP &&
											(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_IPV6 &&
											packet->TypeL4 == L4_ICMPV6)
										{
											b = false;
										}

										if (discard == false)
										{
											discard = b;
										}
									}
								}

								if (dest_session->Policy->FilterIPv4)
								{
									if (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4)
									{
										discard = true;
									}
								}
								if (dest_session->Policy->FilterIPv6)
								{
									if (packet->TypeL3 == L3_IPV6)
									{
										discard = true;
									}
								}
								if (dest_session->Policy->FilterNonIP)
								{
									if (packet->TypeL3 != L3_IPV4 && packet->TypeL3 != L3_ARPV4 && packet->TypeL3 != L3_IPV6)
									{
										discard = true;
									}
								}

								if (s != NULL &&
									(packet->BroadcastPacket == false &&
									s->Policy->PrivacyFilter &&
									dest_session->Policy->PrivacyFilter)
									)
								{
									// プライバシーフィルタ
									if (packet->TypeL3 != L3_ARPV4)
									{
										discard = true;
									}
								}

								if (s != NULL)
								{
									if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
										Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
									{
										discard = true;
									}
								}

								if (discard == false && dest_pa != NULL)
								{
									// 自分以外のセッションにストア
									data = MallocFast(packet->PacketSize);
									Copy(data, packet->PacketData, packet->PacketSize);
									size = packet->PacketSize;

									if (delete_default_router_in_ra)
									{
										PKT *pkt2 = ParsePacket(data, size);

										DeleteIPv6DefaultRouterInRA(pkt2);

										FreePacket(pkt2);
									}

									StorePacketToHubPa(dest_pa, s, data, size, packet);

									// トラフィック加算
									AddTrafficForSession(dest_session, &traffic);
								}
							}
						}
					}
					UnlockList(hub->SessionList);

					// パケットログをとる
					if (s != NULL)
					{
						PacketLog(s->Hub, s, NULL, packet);
					}

					Free(packet->PacketData);
				}
				FreePacket(packet);
			}
		}
	}
	UnlockList(hub->MacTable);
}

// 指定された IP アドレスがプライベート IP アドレスかどうかチェックする
bool IsIPPrivate(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	if (ip->addr[0] == 10)
	{
		return true;
	}

	if (ip->addr[0] == 172)
	{
		if (ip->addr[1] >= 16 && ip->addr[1] <= 31)
		{
			return true;
		}
	}

	if (ip->addr[0] == 192 && ip->addr[1] == 168)
	{
		return true;
	}

	if (ip->addr[0] == 2)
	{
		// Special !!
		return true;
	}

	if (ip->addr[0] == 169 && ip->addr[1] == 254)
	{
		return true;
	}

	return false;
}

// 指定された IP アドレスが仮想 HUB による管理対象かどうか確認する
bool IsIPManagementTargetForHUB(IP *ip, HUB *hub)
{
	// 引数チェック
	if (ip == NULL || hub == NULL)
	{
		return false;
	}

	if (hub->Option == NULL)
	{
		return true;
	}

	if (IsIP4(ip))
	{
		if (hub->Option->ManageOnlyPrivateIP)
		{
			if (IsIPPrivate(ip) == false)
			{
				return false;
			}
		}
	}
	else
	{
		if (hub->Option->ManageOnlyLocalUnicastIPv6)
		{
			UINT ip_type = GetIPAddrType6(ip);

			if (!(ip_type & IPV6_ADDR_LOCAL_UNICAST))
			{
				return false;
			}
		}
	}

	return true;
}

// 古い IP テーブルエントリを削除する
void DeleteOldIpTableEntry(LIST *o)
{
	UINT i;
	UINT64 oldest_time = 0xffffffffffffffffULL;
	IP_TABLE_ENTRY *old = NULL;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);

		if (e->UpdatedTime <= oldest_time)
		{
			old = e;
		}
	}

	if (old != NULL)
	{
		Delete(o, old);
		Free(old);
	}
}

// ストームリストの追加
STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip)
{
	STORM *s;
	// 引数チェック
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(STORM));
	if (src_ip != NULL)
	{
		Copy(&s->SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&s->DestIp, dest_ip, sizeof(IP));
	}
	Copy(s->MacAddress, mac_address, 6);

	Insert(pa->StormList, s);

	return s;
}

// ストームリストのサーチ
STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip)
{
	STORM t, *s;
	// 引数チェック
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	if (src_ip != NULL)
	{
		Copy(&t.SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&t.DestIp, dest_ip, sizeof(IP));
	}
	Copy(t.MacAddress, mac_address, 6);

	s = Search(pa->StormList, &t);

	return s;
}

// パケットを宛先の HUB_PA にストアする
void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet)
{
	BLOCK *b;
	// 引数チェック
	if (dest == NULL || data == NULL)
	{
		return;
	}

	if (size < 14)
	{
		Free(data);
		return;
	}

	if (src != NULL)
	{
		// フォワード用のアクセスリスト適用
		if (ApplyAccessListToForwardPacket(src->Hub, src, dest->Session, packet) == false)
		{
			Free(data);
			return;
		}
	}

	if (src != NULL)
	{
		if (dest->Session->Policy->MaxDownload != 0)
		{
			// トラフィック制限
			if (packet != NULL && IsMostHighestPriorityPacket(dest->Session, packet) == false)
			{
				TRAFFIC_LIMITER *tr = &dest->DownloadLimiter;
				IntoTrafficLimiter(tr, packet);

				if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > dest->Session->Policy->MaxDownload)
				{
					// 制限する
					Free(data);
					return;
				}
			}
		}
	}

	if (src != NULL && src->Hub != NULL && src->Hub->Option != NULL && src->Hub->Option->FixForDLinkBPDU)
	{
		// D-Link バグ対策
		UCHAR *mac = packet->MacAddressSrc;
		if ((mac[0] == 0x00 && mac[1] == 0x80 && mac[2] == 0xc8 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00) ||
			(mac[0] == 0x00 && mac[1] == 0x0d && mac[2] == 0x88 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00))
		{
			SESSION *session = dest->Session;

			if (session != NULL)
			{
				if (session->Policy != NULL && session->Policy->CheckMac)
				{
					UCHAR hash[MD5_SIZE];
					Hash(hash, packet->PacketData, packet->PacketSize, false);

					Copy(session->LastDLinkSTPPacketDataHash, hash, MD5_SIZE);
					session->LastDLinkSTPPacketSendTick = Tick64();
				}
			}
		}
	}

	// VLAN タグを除去
	if (dest->Session != NULL && dest->Session->VLanId != 0)
	{
		if (VLanRemoveTag(&data, &size, dest->Session->VLanId) == false)
		{
			Free(data);
			return;
		}
	}

	// ブロック作成
	b = NewBlock(data, size, 0);

	LockQueue(dest->PacketQueue);
	{
		// キューの数を測定
		if ((dest->PacketQueue->num_item < MAX_STORED_QUEUE_NUM) ||
			(((UCHAR *)data)[12] == 'S' && ((UCHAR *)data)[13] == 'E'))
		{
			// ストア
			InsertQueue(dest->PacketQueue, b);
		}
		else
		{
			// パケット破棄
			FreeBlock(b);
		}
	}
	UnlockQueue(dest->PacketQueue);

	// キャンセルの発行
	if (src != NULL)
	{
		AddCancelList(src->CancelList, dest->Cancel);
	}
	else
	{
		Cancel(dest->Cancel);
	}
}

// IPv6 ルータ広告からデフォルトルータ指定を削除
bool DeleteIPv6DefaultRouterInRA(PKT *p)
{
	if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
		(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
	{
		if (p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
		{
			p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime = 0;

			p->L4.ICMPHeader->Checksum = 0;
			p->L4.ICMPHeader->Checksum =
				CalcChecksumForIPv6(&p->L3.IPv6Header->SrcAddress,
					&p->L3.IPv6Header->DestAddress, IP_PROTO_ICMPV6,
					p->L4.ICMPHeader, p->IPv6HeaderPacketInfo.PayloadSize);
		}
	}

	return false;
}

// ポリシーによるパケットフィルタ
bool StorePacketFilterByPolicy(SESSION *s, PKT *p)
{
	POLICY *pol;
	HUB *hub;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return false;
	}

	hub = s->Hub;

	// ポリシー
	pol = s->Policy;

	// サーバーとしての動作を禁止する
	if (pol->NoServer)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[64], ip2[64];
					// SYN + ACK パケットを送信させない
					Debug("pol->NoServer: Discard SYN+ACK Packet.\n");

					IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
					IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

					HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, p->L4.TCPHeader->DstPort,
						ip1, p->L4.TCPHeader->SrcPort);

					return false;
				}
			}
		}
	}

	// サーバーとしての動作を禁止する (IPv6)
	if (pol->NoServerV6)
	{
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[128], ip2[128];
					// SYN + ACK パケットを送信させない
					Debug("pol->NoServerV6: Discard SYN+ACK Packet.\n");

					IP6AddrToStr(ip1, sizeof(ip1), &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress);
					IP6AddrToStr(ip2, sizeof(ip2), &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress);

					HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, p->L4.TCPHeader->DstPort,
						ip1, p->L4.TCPHeader->SrcPort);

					return false;
				}
			}
		}
	}

	// ブロードキャストは ARP と DHCP のみ許可
	if (pol->ArpDhcpOnly && p->BroadcastPacket)
	{
		bool ok = false;

		if (p->TypeL3 == L3_ARPV4)
		{
			ok = true;
		}
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->TypeL4 == L4_UDP)
			{
				if (p->TypeL7 == L7_DHCPV4)
				{
					ok = true;
				}
			}
		}
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_ICMPV6)
			{
				ok = true;
			}
		}

		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP &&
			(Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->DstPort) == 547))
		{
			ok = true;
		}

		if (ok == false)
		{
			return false;
		}
	}

	// IPv4 パケットのフィルタリング
	if (pol->FilterIPv4)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x0800 || proto == 0x0806)
			{
				return false;
			}
		}
	}

	// IPv6 パケットのフィルタリング
	if (pol->FilterIPv6)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x86dd)
			{
				return false;
			}
		}
	}

	// 非 IP パケットのフィルタリング
	if (pol->FilterNonIP)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (!(proto == 0x86dd || proto == 0x0800 || proto == 0x0806))
			{
				return false;
			}
		}
	}

	// DHCP パケットのフィルタリング
	if (pol->DHCPFilter)
	{
		if (p->TypeL3 == L3_IPV4 &&
			p->TypeL4 == L4_UDP &&
			p->TypeL7 == L7_DHCPV4)
		{
			// DHCP パケットを破棄する
			Debug("pol->DHCPFilter: Discard DHCP Packet.\n");

			return false;
		}
	}

	// DHCPv6 パケットのフィルタリング
	if (pol->DHCPv6Filter)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP)
		{
			if (Endian16(p->L4.UDPHeader->DstPort) == 546 ||
				Endian16(p->L4.UDPHeader->DstPort) == 547)
			{
				// DHCPv6 パケットを破棄する
				Debug("pol->DHCPv6Filter: Discard DHCPv6 Packet.\n");

				return false;
			}
		}
	}

	// DHCP サーバーとしての動作を禁止
	if (pol->DHCPNoServer)
	{
		if (p->TypeL3 == L3_IPV4 &&
			p->TypeL4 == L4_UDP &&
			p->TypeL7 == L7_DHCPV4)
		{
			DHCPV4_HEADER *h = p->L7.DHCPv4Header;
			if (h->OpCode == 2)
			{
				char ip1[64], ip2[64];

				// DHCP パケットを破棄する
				IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
				IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

				HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);

				// DHCP 応答パケットを破棄する
				Debug("pol->DHCPNoServer: Discard DHCP Response Packet.\n");
				return false;
			}
		}
	}

	// DHCPv6 サーバーとしての動作を禁止
	if (pol->DHCPv6NoServer)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP &&
			(Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->SrcPort) == 547))
		{
			char ip1[128], ip2[128];

			// DHCP パケットを破棄する
			IP6AddrToStr(ip1, sizeof(ip1), &p->L3.IPv6Header->SrcAddress);
			IP6AddrToStr(ip2, sizeof(ip2), &p->L3.IPv6Header->DestAddress);

			HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);

			// DHCP 応答パケットを破棄する
			Debug("pol->DHCPv6NoServer: Discard DHCPv6 Response Packet.\n");
			return false;
		}
	}

	// ルータ要請/広告パケットをフィルタリング (IPv6)
	if (pol->RSandRAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
			 p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
		{
			return false;
		}
	}

	// ルータ広告パケットをフィルタリング (IPv6)
	if (pol->RAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT)
		{
			return false;
		}
	}

	// DHCP 応答パケットを記録して IP テーブルに登録
	if (p->TypeL3 == L3_IPV4 &&
		p->TypeL4 == L4_UDP &&
		p->TypeL7 == L7_DHCPV4 &&
		(s->Hub != NULL && s->Hub->Option->NoIpTable == false))
	{
		DHCPV4_HEADER *h = p->L7.DHCPv4Header;
		if (h->OpCode == 2)
		{
			// DHCP 応答パケットの中身を見て IP テーブルに登録する
			if (h->HardwareType == ARP_HARDWARE_TYPE_ETHERNET)
			{
				if (h->HardwareAddressSize == 6)
				{
					if (h->YourIP != 0 && h->YourIP != 0xffffffff)
					{
						UINT ip_uint = h->YourIP;
						IP ip;
						IP_TABLE_ENTRY *e, t;
						MAC_TABLE_ENTRY *mac_table, mt;
						mt.VlanId = 0;
						Copy(&mt.MacAddress, &h->ClientMacAddress, 6);
						mac_table = Search(hub->MacTable, &mt);

						if (mac_table != NULL)
						{
							bool new_entry = true;
							UINTToIP(&ip, ip_uint);
							Copy(&t.Ip, &ip, sizeof(IP));

							e = Search(hub->IpTable, &t);
							if (e == NULL)
							{
								// 新しく登録
								e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
UPDATE_DHCP_ALLOC_ENTRY:
								e->CreatedTime = e->UpdatedTime = Tick64();
								e->DhcpAllocated = true;
								Copy(&e->Ip, &ip, sizeof(IP));
								e->Session = mac_table->Session;
								Copy(e->MacAddress, p->MacAddressDest, 6);

								if (new_entry)
								{
									// 有効期限の切れた IP テーブルエントリを削除する
									DeleteExpiredIpTableEntry(hub->IpTable);
									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										// 古いエントリを削除する
										DeleteOldIpTableEntry(hub->IpTable);
									}
									Insert(hub->IpTable, e);
								}

								if (new_entry)
								{
									char dhcp_mac_addr[64];
									char dest_mac_addr[64];
									char dest_ip_addr[64];
									char server_ip_addr[64];
									MacToStr(dhcp_mac_addr, sizeof(dhcp_mac_addr), p->MacAddressSrc);
									MacToStr(dest_mac_addr, sizeof(dest_mac_addr), h->ClientMacAddress);
									IPToStr(dest_ip_addr, sizeof(dest_ip_addr), &ip);
									IPToStr32(server_ip_addr, sizeof(server_ip_addr), p->L3.IPv4Header->SrcIP);
									Debug("DHCP Allocated; dhcp server: %s, client: %s, new_ip: %s\n",
										dhcp_mac_addr, dest_mac_addr, dest_ip_addr);

									HLog(s->Hub, "LH_REGIST_DHCP", s->Name, dhcp_mac_addr, server_ip_addr,
										mac_table->Session->Name, dest_mac_addr, dest_ip_addr);
								}
							}
							else
							{
								// 更新
								new_entry = false;
								goto UPDATE_DHCP_ALLOC_ENTRY;
							}
						}
					}
				}
			}
		}
	}

	return true;
}

// 有効期限の切れた MAC テーブルエントリを削除する
void DeleteExpiredMacTableEntry(LIST *o)
{
	LIST *o2;
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MAC_TABLE_ENTRY *e = LIST_DATA(o, i);
		if ((e->UpdatedTime + (UINT64)MAC_TABLE_EXPIRE_TIME) <= Tick64())
		{
			Add(o2, e);
		}
	}

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		MAC_TABLE_ENTRY *e = LIST_DATA(o2, i);
		Delete(o, e);
		Free(e);
	}

	ReleaseList(o2);
}

// 有効期限の切れた IP テーブルエントリを削除する
void DeleteExpiredIpTableEntry(LIST *o)
{
	LIST *o2;
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);
		if ((e->UpdatedTime + (UINT64)(e->DhcpAllocated ? IP_TABLE_EXPIRE_TIME_DHCP : IP_TABLE_EXPIRE_TIME)) <= Tick64())
		{
			Add(o2, e);
		}
	}

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o2, i);
		Delete(o, e);
		Free(e);
	}

	ReleaseList(o2);
}

// 優先して取り扱うべきパケットかどうかを判断
bool IsMostHighestPriorityPacket(SESSION *s, PKT *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		// ARP パケット
		return true;
	}

	if (p->TypeL3 == L3_IPV4)
	{
		if (p->TypeL4 == L4_ICMPV4)
		{
			// ICMP パケット
			return true;
		}

		if (p->TypeL4 == L4_TCP)
		{
			if ((p->L4.TCPHeader->Flag & TCP_SYN) || (p->L4.TCPHeader->Flag & TCP_FIN)
				|| (p->L4.TCPHeader->Flag & TCP_RST))
			{
				// SYN, FIN, RST パケット
				return true;
			}
		}

		if (p->TypeL4 == L4_UDP)
		{
			if (p->TypeL7 == L7_DHCPV4)
			{
				// DHCP パケット
				return true;
			}
		}
	}

	return false;
}

// トラフィック リミッターへのパケット追加
void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p)
{
	UINT64 now = Tick64();
	// 引数チェック
	if (tr == NULL || p == NULL)
	{
		return;
	}

	if (tr->LastTime == 0 || tr->LastTime > now ||
		(tr->LastTime + LIMITER_SAMPLING_SPAN) < now)
	{
		// サンプリング初期化
		tr->Value = 0;
		tr->LastTime = now;
	}

	// 値増加
	tr->Value += (UINT64)(p->PacketSize * 8);
}

// トラフィック リミッターによる帯域幅削減
bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p)
{
	HUB_PA *pa;
	TRAFFIC_LIMITER *tr;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (s->Policy->MaxUpload == 0)
	{
		// 制限無し
		return true;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;
	tr = &pa->UploadLimiter;

	// 優先パケットは制限を適用しない
	if (IsMostHighestPriorityPacket(s, p))
	{
		return true;
	}

	// リミッターへパケットを投入
	IntoTrafficLimiter(tr, p);

	// 現在の帯域幅と制限値を比較
	if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > s->Policy->MaxUpload)
	{
		// パケットを破棄
		return false;
	}

	return true;
}

// ストアするパケットのフィルタリング
bool StorePacketFilter(SESSION *s, PKT *packet)
{
	// 引数チェック
	if (s == NULL || packet == NULL)
	{
		return false;
	}

	// トラフィック リミッターによる帯域幅削減
	if (StorePacketFilterByTrafficLimiter(s, packet) == false)
	{
		return false;
	}

	// ポリシーによるパケットフィルタ
	if (StorePacketFilterByPolicy(s, packet) == false)
	{
		return false;
	}

	// アクセスリストによるパケットフィルタ
	if (ApplyAccessListToStoredPacket(s->Hub, s, packet) == false)
	{
		return false;
	}

	return true;
}

// HUB 用のパケットアダプタの取得
PACKET_ADAPTER *GetHubPacketAdapter()
{
	// 関数リストを生成して引き渡す
	PACKET_ADAPTER *pa = NewPacketAdapter(HubPaInit,
		HubPaGetCancel, HubPaGetNextPacket, HubPaPutPacket, HubPaFree);

	return pa;
}

// HUB のすべての SESSION を停止させる
void StopAllSession(HUB *h)
{
	SESSION **s;
	UINT i, num;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		num = LIST_NUM(h->SessionList);
		s = ToArray(h->SessionList);
		DeleteAll(h->SessionList);
	}
	UnlockList(h->SessionList);

	for (i = 0;i < num;i++)
	{
		StopSession(s[i]);
		ReleaseSession(s[i]);
	}

	Free(s);
}

// HUB から SESSION を削除
void DelSession(HUB *h, SESSION *s)
{
	// 引数チェック
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		if (Delete(h->SessionList, s))
		{
			Debug("Session %s was Deleted from %s.\n", s->Name, h->Name);
			ReleaseSession(s);
		}
	}
	UnlockList(h->SessionList);
}

// HUB に SESSION を追加
void AddSession(HUB *h, SESSION *s)
{
	// 引数チェック
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		Insert(h->SessionList, s);
		AddRef(s->ref);
		Debug("Session %s Inserted to %s.\n", s->Name, h->Name);
	}
	UnlockList(h->SessionList);
}

// HUB の動作を停止する
void StopHub(HUB *h)
{
	bool old_status = false;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	old_status = h->Offline;
	h->HubIsOnlineButHalting = true;

	SetHubOffline(h);

	if (h->Halt == false)
	{
		SLog(h->Cedar, "LS_HUB_STOP", h->Name);
		h->Halt = true;
	}

	h->Offline = old_status;
	h->HubIsOnlineButHalting = false;
}

// HUB をオンラインにする
void SetHubOnline(HUB *h)
{
	bool for_cluster = false;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (h->Type == HUB_TYPE_FARM_DYNAMIC)
		{
			for_cluster = true;
		}
	}

	Lock(h->lock_online);
	{
		if (h->Offline == false)
		{
			Unlock(h->lock_online);
			return;
		}
		HLog(h, "LH_ONLINE");

		// すべてのリンクを開始
		StartAllLink(h);

		// SecureNAT を開始
		if (h->EnableSecureNAT)
		{
			if (h->SecureNAT == NULL)
			{
				if (for_cluster == false)
				{
					h->SecureNAT = SnNewSecureNAT(h, h->SecureNATOption);
				}
			}
		}

		// この HUB に関連付けられているローカルブリッジをすべて開始する
		if (h->Type != HUB_TYPE_FARM_DYNAMIC)
		{
			LockList(h->Cedar->LocalBridgeList);
			{
				UINT i;
				for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
				{
					LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

					if (StrCmpi(br->HubName, h->Name) == 0)
					{
						if (br->Bridge == NULL)
						{
							br->Bridge = BrNewBridge(h, br->DeviceName, NULL, br->Local, br->Monitor,
								br->TapMode, br->TapMacAddress, br->FullBroadcast);
						}
					}
				}
			}
			UnlockList(h->Cedar->LocalBridgeList);
		}

		h->Offline = false;
	}
	Unlock(h->lock_online);

	if (h->Cedar->Server != NULL)
	{
		SiHubOnlineProc(h);
	}
}

// HUB をオフラインにする
void SetHubOffline(HUB *h)
{
	UINT i;
	bool for_cluster = false;
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (h->Type == HUB_TYPE_FARM_DYNAMIC)
		{
			for_cluster = true;
		}
	}

	h->BeingOffline = true;

	Lock(h->lock_online);
	{
		if (h->Offline || h->Halt)
		{
			Unlock(h->lock_online);
			h->BeingOffline = false;
			return;
		}

		HLog(h, "LH_OFFLINE");

		// すべてのリンクを停止
		StopAllLink(h);

		// SecureNAT を停止
		SnFreeSecureNAT(h->SecureNAT);
		h->SecureNAT = NULL;

		// この HUB に関連付けられているローカルブリッジをすべて停止する
		LockList(h->Cedar->LocalBridgeList);
		{
			for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0)
				{
					BrFreeBridge(br->Bridge);
					br->Bridge = NULL;
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		// オフラインにする
		h->Offline = true;

		// すべてのセッションを切断する
		StopAllSession(h);
	}
	Unlock(h->lock_online);

	h->BeingOffline = false;

	if (h->Cedar->Server != NULL)
	{
		SiHubOfflineProc(h);
	}
}

// 指定された名前の HUB が存在するかどうか取得
bool IsHub(CEDAR *cedar, char *name)
{
	HUB *h;
	// 引数チェック
	if (cedar == NULL || name == NULL)
	{
		return false;
	}

	h = GetHub(cedar, name);
	if (h == NULL)
	{
		return false;
	}

	ReleaseHub(h);

	return true;
}

// HUB の取得
HUB *GetHub(CEDAR *cedar, char *name)
{
	HUB *h, t;
	// 引数チェック
	if (cedar == NULL || name == NULL)
	{
		return NULL;
	}

	LockHubList(cedar);

	t.Name = name;
	h = Search(cedar->HubList, &t);
	if (h == NULL)
	{
		UnlockHubList(cedar);
		return NULL;
	}

	AddRef(h->ref);

	UnlockHubList(cedar);

	return h;
}

// HUB リストのロック
void LockHubList(CEDAR *cedar)
{
	// 引数チェック
	if (cedar == NULL)
	{
		return;
	}

	LockList(cedar->HubList);
}

// HUB リストのロック解除
void UnlockHubList(CEDAR *cedar)
{
	// 引数チェック
	if (cedar == NULL)
	{
		return;
	}

	UnlockList(cedar->HubList);
}

// HUB の解放
void ReleaseHub(HUB *h)
{
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	if (Release(h->ref) == 0)
	{
		CleanupHub(h);
	}
}

// Radius サーバー情報を取得
bool GetRadiusServer(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size)
{
	UINT interval;
	return GetRadiusServerEx(hub, name, size, port, secret, secret_size, &interval);
}
bool GetRadiusServerEx(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval)
{
	bool ret = false;
	// 引数チェック
	if (hub == NULL || name == NULL || port == NULL || secret == NULL || interval == NULL)
	{
		return false;
	}

	Lock(hub->RadiusOptionLock);
	{
		if (hub->RadiusServerName != NULL)
		{
			char *tmp;
			UINT tmp_size;
			StrCpy(name, size, hub->RadiusServerName);
			*port = hub->RadiusServerPort;
			*interval = hub->RadiusRetryInterval;

			tmp_size = hub->RadiusSecret->Size + 1;
			tmp = ZeroMalloc(tmp_size);
			Copy(tmp, hub->RadiusSecret->Buf, hub->RadiusSecret->Size);
			StrCpy(secret, secret_size, tmp);
			Free(tmp);

			ret = true;
		}
	}
	Unlock(hub->RadiusOptionLock);

	return ret;
}

// Radius サーバー情報を設定
void SetRadiusServer(HUB *hub, char *name, UINT port, char *secret)
{
	SetRadiusServerEx(hub, name, port, secret, RADIUS_RETRY_INTERVAL);
}
void SetRadiusServerEx(HUB *hub, char *name, UINT port, char *secret, UINT interval)
{
	// 引数チェック
	if (hub == NULL)
	{
		return;
	}

	Lock(hub->RadiusOptionLock);
	{
		if (hub->RadiusServerName != NULL)
		{
			Free(hub->RadiusServerName);
		}

		if (name == NULL)
		{
			hub->RadiusServerName = NULL;
			hub->RadiusServerPort = 0;
			hub->RadiusRetryInterval = RADIUS_RETRY_INTERVAL;
			FreeBuf(hub->RadiusSecret);
		}
		else
		{
			hub->RadiusServerName = CopyStr(name);
			hub->RadiusServerPort = port;
			if (interval == 0)
			{
				hub->RadiusRetryInterval = RADIUS_RETRY_INTERVAL;
			}
			else if (interval > RADIUS_RETRY_TIMEOUT)
			{
				hub->RadiusRetryInterval = RADIUS_RETRY_TIMEOUT;
			}
			else
			{
				hub->RadiusRetryInterval = interval;
			}
			FreeBuf(hub->RadiusSecret);

			if (secret == NULL)
			{
				hub->RadiusSecret = NewBuf();
			}
			else
			{
				hub->RadiusSecret = NewBuf();
				WriteBuf(hub->RadiusSecret, secret, StrLen(secret));
				SeekBuf(hub->RadiusSecret, 0, 0);
			}
		}
	}
	Unlock(hub->RadiusOptionLock);
}

// 仮想 HUB のトラフィック情報の追加
void IncrementHubTraffic(HUB *h)
{
	TRAFFIC t;
	// 引数チェック
	if (h == NULL || h->FarmMember == false)
	{
		return;
	}

	Zero(&t, sizeof(t));

	Lock(h->TrafficLock);
	{
		t.Send.BroadcastBytes =
			h->Traffic->Send.BroadcastBytes - h->OldTraffic->Send.BroadcastBytes;
		t.Send.BroadcastCount =
			h->Traffic->Send.BroadcastCount - h->OldTraffic->Send.BroadcastCount;
		t.Send.UnicastBytes =
			h->Traffic->Send.UnicastBytes - h->OldTraffic->Send.UnicastBytes;
		t.Send.UnicastCount =
			h->Traffic->Send.UnicastCount - h->OldTraffic->Send.UnicastCount;
		t.Recv.BroadcastBytes =
			h->Traffic->Recv.BroadcastBytes - h->OldTraffic->Recv.BroadcastBytes;
		t.Recv.BroadcastCount =
			h->Traffic->Recv.BroadcastCount - h->OldTraffic->Recv.BroadcastCount;
		t.Recv.UnicastBytes =
			h->Traffic->Recv.UnicastBytes - h->OldTraffic->Recv.UnicastBytes;
		t.Recv.UnicastCount =
			h->Traffic->Recv.UnicastCount - h->OldTraffic->Recv.UnicastCount;
		Copy(h->OldTraffic, h->Traffic, sizeof(TRAFFIC));
	}
	Unlock(h->TrafficLock);

	if (IsZero(&t, sizeof(TRAFFIC)))
	{
		return;
	}

	AddTrafficDiff(h, h->Name, TRAFFIC_DIFF_HUB, &t);
}

// トラフィック情報の追加
void AddTrafficDiff(HUB *h, char *name, UINT type, TRAFFIC *traffic)
{
	TRAFFIC_DIFF *d;
	// 引数チェック
	if (h == NULL || h->FarmMember == false || name == NULL || traffic == NULL)
	{
		return;
	}

	if (LIST_NUM(h->Cedar->TrafficDiffList) > MAX_TRAFFIC_DIFF)
	{
		return;
	}

	d = ZeroMallocFast(sizeof(TRAFFIC_DIFF));
	d->HubName = CopyStr(h->Name);
	d->Name = CopyStr(name);
	d->Type = type;
	Copy(&d->Traffic, traffic, sizeof(TRAFFIC));

	LockList(h->Cedar->TrafficDiffList);
	{
		Insert(h->Cedar->TrafficDiffList, d);
	}
	UnlockList(h->Cedar->TrafficDiffList);
}

// HUB のクリーンアップ
void CleanupHub(HUB *h)
{
	UINT i;
	char name[MAX_SIZE];
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	StrCpy(name, sizeof(name), h->Name);

	if (h->WatchDogStarted)
	{
		StopHubWatchDog(h);
	}

	FreeAccessList(h);

	if (h->RadiusServerName != NULL)
	{
		Free(h->RadiusServerName);
		FreeBuf(h->RadiusSecret);
	}
	ReleaseAllLink(h);
	DeleteHubDb(h->HubDb);
	ReleaseCedar(h->Cedar);
	DeleteLock(h->lock);
	DeleteLock(h->lock_online);
	Free(h->Name);
	ReleaseList(h->SessionList);
	ReleaseList(h->MacTable);
	ReleaseList(h->IpTable);
	ReleaseList(h->MonitorList);
	ReleaseList(h->LinkList);
	DeleteCounter(h->NumSessions);
	DeleteCounter(h->NumSessionsClient);
	DeleteCounter(h->NumSessionsBridge);
	DeleteCounter(h->SessionCounter);
	FreeTraffic(h->Traffic);
	FreeTraffic(h->OldTraffic);
	Free(h->Option);

	Free(h->SecureNATOption);

	DeleteLock(h->TrafficLock);

	for (i = 0;i < LIST_NUM(h->TicketList);i++)
	{
		Free(LIST_DATA(h->TicketList, i));
	}

	ReleaseList(h->TicketList);

	DeleteLock(h->RadiusOptionLock);

	FreeLog(h->PacketLogger);
	FreeLog(h->SecurityLogger);

	for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
	{
		Free(LIST_DATA(h->AdminOptionList, i));
	}
	ReleaseList(h->AdminOptionList);

	if (h->Msg != NULL)
	{
		Free(h->Msg);
	}

	Free(h);
}

// IP テーブルの比較関数
int CompareIpTable(void *p1, void *p2)
{
	IP_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(IP_TABLE_ENTRY **)p1;
	e2 = *(IP_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	return CmpIpAddr(&e1->Ip, &e2->Ip);
}

// MAC テーブルの比較関数
int CompareMacTable(void *p1, void *p2)
{
	int r;
	MAC_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MAC_TABLE_ENTRY **)p1;
	e2 = *(MAC_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	r = Cmp(e1->MacAddress, e2->MacAddress, 6);
	if (r != 0)
	{
		return r;
	}
	if (e1->VlanId > e2->VlanId)
	{
		return 1;
	}
	else if (e1->VlanId < e2->VlanId)
	{
		return -1;
	}
	return 0;
}

// HUB の比較関数
int CompareHub(void *p1, void *p2)
{
	HUB *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HUB **)p1;
	h2 = *(HUB **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}
	return StrCmpi(h1->Name, h2->Name);
}

// MAC アドレスが仮想 HUB の ARP ポーリング用の MAC アドレスかどうか調べる
bool IsHubMacAddress(UCHAR *mac)
{
	// 引数チェック
	if (mac == NULL)
	{
		return false;
	}

	if (mac[0] == 0x00 && mac[1] == SE_HUB_MAC_ADDR_SIGN)
	{
		return true;
	}

	return false;
}

// IP アドレスが仮想 HUB の ARP ポーリング用の IP アドレスかどうか調べる
bool IsHubIpAddress32(UINT ip32)
{
	IP ip;

	UINTToIP(&ip, ip32);

	return IsHubIpAddress(&ip);
}
bool IsHubIpAddress(IP *ip)
{
	// 引数チェック
	if (ip == NULL)
	{
		return false;
	}

	if (ip->addr[0] == 172 && ip->addr[1] == 31)
	{
		if (ip->addr[2] >= 1 && ip->addr[2] <= 254)
		{
			if (ip->addr[3] >= 1 && ip->addr[3] <= 254)
			{
				return true;
			}
		}
	}

	return false;
}
bool IsHubIpAddress64(IPV6_ADDR *addr)
{
	// 引数チェック
	if (addr == NULL)
	{
		return false;
	}

	if (addr->Value[0] == 0xfe && addr->Value[1] == 0x80 &&
		addr->Value[2] == 0 &&
		addr->Value[3] == 0 &&
		addr->Value[4] == 0 &&
		addr->Value[5] == 0 &&
		addr->Value[6] == 0 &&
		addr->Value[7] == 0 &&
		addr->Value[8] == 0x02 && addr->Value[9] == 0xae && 
		addr->Value[11] == 0xff && addr->Value[12] == 0xfe)
	{
		return true;
	}

	return false;
}

// 仮想 HUB 用 IP アドレスの生成
void GenHubIpAddress(IP *ip, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (ip == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	GenerateMachineUniqueHash(hash);
	BinToStr(tmp2, sizeof(tmp2), hash, sizeof(hash));
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Hash(hash, tmp2, StrLen(tmp2), true);

	Zero(ip, sizeof(IP));
	ip->addr[0] = 172;
	ip->addr[1] = 31;
	ip->addr[2] = hash[0] % 254 + 1;
	ip->addr[3] = hash[1] % 254 + 1;
}

// 仮想 HUB 用 MAC アドレスの生成
void GenHubMacAddress(UCHAR *mac, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (mac == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	GenerateMachineUniqueHash(hash);
	BinToStr(tmp2, sizeof(tmp2), hash, sizeof(hash));
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Hash(hash, tmp2, StrLen(tmp2), true);

	mac[0] = 0x00;
	mac[1] = SE_HUB_MAC_ADDR_SIGN;
	mac[2] = hash[0];
	mac[3] = hash[1];
	mac[4] = hash[2];
	mac[5] = hash[3];
}

// HUB からメッセージを取得
wchar_t *GetHubMsg(HUB *h)
{
	wchar_t *ret = NULL;
	// 引数チェック
	if (h == NULL)
	{
		return NULL;
	}

	Lock(h->lock);
	{
		if (h->Msg != NULL)
		{
			ret = CopyUniStr(h->Msg);
		}
	}
	Unlock(h->lock);

	return ret;
}

// HUB にメッセージを設定
void SetHubMsg(HUB *h, wchar_t *msg)
{
	// 引数チェック
	if (h == NULL)
	{
		return;
	}

	Lock(h->lock);
	{
		if (h->Msg != NULL)
		{
			Free(h->Msg);
			h->Msg = NULL;
		}

		if (UniIsEmptyStr(msg) == false)
		{
			h->Msg = UniCopyStr(msg);
		}
	}
	Unlock(h->lock);
}

// 新しい HUB の作成
HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option)
{
	HUB *h;
	char packet_logger_name[MAX_SIZE];
	char tmp[MAX_SIZE];
	char safe_hub_name[MAX_HUBNAME_LEN + 1];
	UCHAR hash[SHA1_SIZE];
	IP ip6;
	// 引数チェック
	if (cedar == NULL || option == NULL || HubName == NULL)
	{
		return NULL;
	}

	h = ZeroMalloc(sizeof(HUB));
	Hash(h->HashedPassword, "", 0, true);
	HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
	h->lock = NewLock();
	h->lock_online = NewLock();
	h->ref = NewRef();
	h->Cedar = cedar;
	AddRef(h->Cedar->ref);
	h->Type = HUB_TYPE_STANDALONE;

	ConvertSafeFileName(safe_hub_name, sizeof(safe_hub_name), HubName);
	h->Name = CopyStr(safe_hub_name);

	h->AdminOptionList = NewList(CompareAdminOption);
	AddHubAdminOptionsDefaults(h, true);

	h->LastCommTime = SystemTime64();
	h->LastLoginTime = SystemTime64();
	h->NumLogin = 0;

	h->TrafficLock = NewLock();

	h->HubDb = NewHubDb();

	h->SessionList = NewList(NULL);
	h->SessionCounter = NewCounter();
	h->NumSessions = NewCounter();
	h->NumSessionsClient = NewCounter();
	h->NumSessionsBridge = NewCounter();
	h->MacTable = NewList(CompareMacTable);
	h->IpTable = NewList(CompareIpTable);
	h->MonitorList = NewList(NULL);
	h->LinkList = NewList(NULL);

	h->Traffic = NewTraffic();
	h->OldTraffic = NewTraffic();

	h->Option = ZeroMalloc(sizeof(HUB_OPTION));
	Copy(h->Option, option, sizeof(HUB_OPTION));

	if (h->Option->VlanTypeId == 0)
	{
		h->Option->VlanTypeId = MAC_PROTO_TAGVLAN;
	}

	Rand(h->HubSignature, sizeof(h->HubSignature));

	// SecureNAT 関係
	h->EnableSecureNAT = false;
	h->SecureNAT = NULL;
	h->SecureNATOption = ZeroMalloc(sizeof(VH_OPTION));
	NiSetDefaultVhOption(NULL, h->SecureNATOption);

	if (h->Cedar != NULL && h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		NiClearUnsupportedVhOptionForDynamicHub(h->SecureNATOption, true);
	}

	// HUB 用の一時的な MAC アドレスを生成する
	GenerateMachineUniqueHash(hash);
	GenHubMacAddress(h->HubMacAddr, h->Name);
	GenHubIpAddress(&h->HubIp, h->Name);

	// HUB 用 IPv6 アドレス
	GenerateEui64LocalAddress(&ip6, h->HubMacAddr);
	IPToIPv6Addr(&h->HubIpV6, &ip6);

	h->RadiusOptionLock = NewLock();
	h->RadiusServerPort = RADIUS_DEFAULT_PORT;

	h->TicketList = NewList(NULL);

	InitAccessList(h);

	// デフォルトのログ設定
	h->LogSetting.SaveSecurityLog = true;
	h->LogSetting.SavePacketLog = false;
	h->LogSetting.PacketLogConfig[PACKET_LOG_TCP_CONN] =
		h->LogSetting.PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
	h->LogSetting.SecurityLogSwitchType = LOG_SWITCH_DAY;
	h->LogSetting.PacketLogSwitchType = LOG_SWITCH_DAY;

	MakeDir(HUB_SECURITY_LOG_DIR_NAME);
	MakeDir(HUB_PACKET_LOG_DIR_NAME);

	// パケットロガーの開始
	Format(packet_logger_name, sizeof(packet_logger_name), HUB_PACKET_LOG_FILE_NAME, h->Name);
	h->PacketLogger = NewLog(packet_logger_name, HUB_PACKET_LOG_PREFIX, h->LogSetting.PacketLogSwitchType);

	// セキュリティロガーの開始
	Format(tmp, sizeof(tmp), HUB_SECURITY_LOG_FILE_NAME, h->Name);
	h->SecurityLogger = NewLog(tmp, HUB_SECURITY_LOG_PREFIX, h->LogSetting.SecurityLogSwitchType);

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		h->FarmMember = true;
	}

	// HUB の開始
	SetHubOnline(h);

	if (h->Cedar->Bridge)
	{
		h->Option->NoArpPolling = true;
	}

	if (h->Option->NoArpPolling == false && h->Option->NoIpTable == false)
	{
		StartHubWatchDog(h);
		h->WatchDogStarted = true;
	}

	SLog(h->Cedar, "LS_HUB_START", h->Name);

	MacToStr(tmp, sizeof(tmp), h->HubMacAddr);
	SLog(h->Cedar, "LS_HUB_MAC", h->Name, tmp);

	return h;
}

// HUBDB の削除
void DeleteHubDb(HUBDB *d)
{
	// 引数チェック
	if (d == NULL)
	{
		return;
	}

	LockList(d->UserList);
	{
		LockList(d->GroupList);
		{
			// すべてのユーザーとグループを解放
			UINT i;
			USER **users;
			USERGROUP **groups;

			users = ToArray(d->UserList);
			groups = ToArray(d->GroupList);

			for (i = 0;i < LIST_NUM(d->UserList);i++)
			{
				ReleaseUser(users[i]);
			}
			for (i = 0;i < LIST_NUM(d->GroupList);i++)
			{
				ReleaseGroup(groups[i]);
			}

			Free(users);
			Free(groups);
		}
		UnlockList(d->GroupList);
	}
	UnlockList(d->UserList);

	// ルート証明書一覧を解放
	LockList(d->RootCertList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->RootCertList);i++)
		{
			X *x = LIST_DATA(d->RootCertList, i);
			FreeX(x);
		}
	}
	UnlockList(d->RootCertList);

	// CRL を解放
	LockList(d->CrlList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->CrlList);i++)
		{
			CRL *crl = LIST_DATA(d->CrlList, i);
			FreeCrl(crl);
		}
	}
	UnlockList(d->CrlList);

	ReleaseList(d->GroupList);
	ReleaseList(d->UserList);
	ReleaseList(d->RootCertList);
	ReleaseList(d->CrlList);
	Free(d);
}

// HUB のログ設定を取得する
void GetHubLogSetting(HUB *h, HUB_LOG *setting)
{
	// 引数チェック
	if (setting == NULL || h == NULL)
	{
		return;
	}

	Copy(setting, &h->LogSetting, sizeof(HUB_LOG));
}

// HUB のログ設定を更新する
void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type)
{
	UINT i1, i2;
	// 引数チェック
	if (setting == NULL || h == NULL)
	{
		return;
	}

	i1 = h->LogSetting.PacketLogSwitchType;
	i2 = h->LogSetting.SecurityLogSwitchType;

	Copy(&h->LogSetting, setting, sizeof(HUB_LOG));

	if (no_change_switch_type)
	{
		h->LogSetting.PacketLogSwitchType = i1;
		h->LogSetting.SecurityLogSwitchType = i2;
	}

	// パケットロガー設定
	SetLogSwitchType(h->PacketLogger, setting->PacketLogSwitchType);
	SetLogSwitchType(h->SecurityLogger, setting->SecurityLogSwitchType);
}
void SetHubLogSetting(HUB *h, HUB_LOG *setting)
{
	SetHubLogSettingEx(h, setting, false);
}

// HUB に信頼するルート証明書を追加する
void AddRootCert(HUB *hub, X *x)
{
	HUBDB *db;
	// 引数チェック
	if (hub == NULL || x == NULL)
	{
		return;
	}

	db = hub->HubDb;
	if (db != NULL)
	{
		LockList(db->RootCertList);
		{
			if (LIST_NUM(db->RootCertList) < MAX_HUB_CERTS)
			{
				UINT i;
				bool ok = true;

				for (i = 0;i < LIST_NUM(db->RootCertList);i++)
				{
					X *exist_x = LIST_DATA(db->RootCertList, i);
					if (CompareX(exist_x, x))
					{
						ok = false;
						break;
					}
				}

				if (ok)
				{
					Insert(db->RootCertList, CloneX(x));
				}
			}
		}
		UnlockList(db->RootCertList);
	}
}

// 証明書リストの比較
int CompareCert(void *p1, void *p2)
{
	X *x1, *x2;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	x1 = *(X **)p1;
	x2 = *(X **)p2;
	if (x1 == NULL || x2 == NULL)
	{
		return 0;
	}

	GetPrintNameFromX(tmp1, sizeof(tmp1), x1);
	GetPrintNameFromX(tmp2, sizeof(tmp2), x2);

	return UniStrCmpi(tmp1, tmp2);
}

// 新しい HUBDB の作成
HUBDB *NewHubDb()
{
	HUBDB *d = ZeroMalloc(sizeof(HUBDB));

	d->GroupList = NewList(CompareGroupName);
	d->UserList = NewList(CompareUserName);
	d->RootCertList = NewList(CompareCert);
	d->CrlList = NewList(NULL);

	return d;
}


