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

// SM.c
// Win32 用 SoftEther UT-VPN Server Manager


#ifdef	WIN32

#define	SM_C
#define	CM_C
#define	NM_C

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "CMInner.h"
#include "SMInner.h"
#include "NMInner.h"
#include "../PenCore/resource.h"

// グローバル変数
static SM *sm = NULL;
static bool link_create_now = false;

// メッセージ設定
void SmHubMsg(HWND hWnd, SM_EDIT_HUB *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_MSG, SmHubMsgDlg, s);
}

// メッセージダイアログプロシージャ
UINT SmHubMsgDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_HUB *s = (SM_EDIT_HUB *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmHubMsgDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_TEXT:
			SmHubMsgDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmHubMsgDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case C_USEMSG:
			SmHubMsgDlgUpdate(hWnd, s);

			if (IsChecked(hWnd, C_USEMSG))
			{
				FocusEx(hWnd, E_TEXT);
			}
			break;
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// メッセージダイアログ初期化
void SmHubMsgDlgInit(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_MSG t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (MsIsVista())
	{
		SetFont(hWnd, E_TEXT, GetMeiryoFont());
	}
	else
	{
		DlgFont(hWnd, E_TEXT, 11, false);
	}

	FormatText(hWnd, S_MSG_2, s->HubName);

	LimitText(hWnd, E_TEXT, HUB_MAXMSG_LEN);

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScGetHubMsg(s->p->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	if (UniIsEmptyStr(t.Msg) == false)
	{
		SetText(hWnd, E_TEXT, t.Msg);

		Check(hWnd, C_USEMSG, true);
	}
	else
	{
		Check(hWnd, C_USEMSG, false);
	}

	FreeRpcMsg(&t);

	SmHubMsgDlgUpdate(hWnd, s);
}

// OK ボタン
void SmHubMsgDlgOnOk(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_MSG t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (IsChecked(hWnd, C_USEMSG) == false)
	{
		t.Msg = CopyUniStr(L"");
	}
	else
	{
		t.Msg = GetText(hWnd, E_TEXT);
	}

	if (CALL(hWnd, ScSetHubMsg(s->p->Rpc, &t)) == false)
	{
		return;
	}

	FreeRpcMsg(&t);

	EndDialog(hWnd, 1);
}

// メッセージダイアログ更新
void SmHubMsgDlgUpdate(HWND hWnd, SM_EDIT_HUB *s)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetEnable(hWnd, E_TEXT, IsChecked(hWnd, C_USEMSG));

	if (IsChecked(hWnd, C_USEMSG))
	{
		wchar_t *s = GetText(hWnd, E_TEXT);

		b = !IsEmptyUniStr(s);

		Free(s);
	}

	SetEnable(hWnd, IDOK, b);
}

// VLAN ユーティリティ
void SmVLan(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_VLAN, SmVLanDlg, s);
}

// VLAN ダイアログ
UINT SmVLanDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	NMHDR *n;

	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmVLanDlgInit(hWnd, s);

		if (LvNum(hWnd, L_LIST) == 0)
		{
			Disable(hWnd, L_LIST);
			SetTimer(hWnd, 1, 100, NULL);
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_VLAN_NOTHING"),
				s->CurrentSetting->ClientOption.Hostname);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;

		case B_ENABLE:
		case B_DISABLE:
			{
				UINT i = LvGetSelected(hWnd, L_LIST);
				if (i != INFINITE)
				{
					char *name = LvGetStrA(hWnd, L_LIST, i, 0);

					if (IsEmptyStr(name) == false)
					{
						RPC_TEST t;

						Zero(&t, sizeof(t));

						StrCpy(t.StrValue, sizeof(t.StrValue), name);
						t.IntValue = BOOL_TO_INT(wParam == B_ENABLE);

						if (CALL(hWnd, ScSetEnableEthVLan(s->Rpc, &t)))
						{
							SmVLanDlgRefresh(hWnd, s);

							if (wParam == B_ENABLE)
							{
								MsgBoxEx(hWnd, MB_ICONINFORMATION,
									_UU("SM_VLAN_MSG_1"),
									name, name, name);
							}
							else
							{
								MsgBoxEx(hWnd, MB_ICONINFORMATION,
									_UU("SM_VLAN_MSG_2"),
									name);
							}
						}
					}

					Free(name);
				}
				break;
			}
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmVLanDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// VLAN ダイアログ初期化
void SmVLanDlgInit(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_VLAN_COLUMN_0"), 245);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_VLAN_COLUMN_1"), 75);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_VLAN_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_VLAN_COLUMN_3"), 100);
	LvInsertColumn(hWnd, L_LIST, 4, _UU("SM_VLAN_COLUMN_4"), 290);
	LvInsertColumn(hWnd, L_LIST, 5, _UU("SM_VLAN_COLUMN_5"), 430);

	SmVLanDlgRefresh(hWnd, s);
}

// VLAN ダイアログ内容更新
void SmVLanDlgRefresh(HWND hWnd, SM_SERVER *s)
{
	LVB *b;
	RPC_ENUM_ETH_VLAN t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumEthVLan(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t.Items[i];

		if (e->Support)
		{
			wchar_t tmp0[MAX_SIZE];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t *tmp3;
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];

			StrToUni(tmp0, sizeof(tmp0), e->DeviceName);
			StrToUni(tmp1, sizeof(tmp1), e->DriverType);
			StrToUni(tmp2, sizeof(tmp2), e->DriverName);
			tmp3 = (e->Enabled ? _UU("SM_VLAN_YES") : _UU("SM_VLAN_NO"));
			StrToUni(tmp4, sizeof(tmp4), e->Guid);
			StrToUni(tmp5, sizeof(tmp5), e->DeviceInstanceId);

			LvInsertAdd(b,
				e->Enabled ? ICO_NIC_ONLINE : ICO_NIC_OFFLINE, 0, 6,
				tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
		}
	}

	LvInsertEnd(b, hWnd, L_LIST);

	FreeRpcEnumEthVLan(&t);

	SmVLanDlgUpdate(hWnd, s);
}

// VLAN ダイアログコントロール更新
void SmVLanDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSingleSelected(hWnd, L_LIST) == false)
	{
		Disable(hWnd, B_ENABLE);
		Disable(hWnd, B_DISABLE);
	}
	else
	{
		UINT i = LvGetSelected(hWnd, L_LIST);
		if (i != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_LIST, i, 3);

			if (UniStrCmpi(s, _UU("SM_VLAN_YES")) != 0)
			{
				Enable(hWnd, B_ENABLE);
				Disable(hWnd, B_DISABLE);
			}
			else
			{
				Enable(hWnd, B_DISABLE);
				Disable(hWnd, B_ENABLE);
			}

			Free(s);
		}
	}
}

// 現在の VPN Server / VPN Bridge の状態が初期状態かどうか調べる
bool SmSetupIsNew(SM_SERVER *s)
{
	RPC *rpc;
	bool is_bridge;
	char hubname[MAX_HUBNAME_LEN + 1];
	bool check_hub = false;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	if (s->ServerAdminMode == false)
	{
		return false;
	}

	rpc = s->Rpc;
	is_bridge =s->Bridge;

	// ローカルブリッジのサポート
	if (true)
	{
		RPC_BRIDGE_SUPPORT t;

		Zero(&t, sizeof(t));

		if (ScGetBridgeSupport(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.IsBridgeSupportedOs == false ||
				t.IsWinPcapNeeded)
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	// サーバー種類
	if (is_bridge == false)
	{
		bool b = false;
		RPC_SERVER_INFO t;

		Zero(&t, sizeof(t));
		if (ScGetServerInfo(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.ServerType != SERVER_TYPE_STANDALONE)
			{
				b = true;
			}

			FreeRpcServerInfo(&t);
		}
		else
		{
			return false;
		}

		if (b)
		{
			return false;
		}
	}

	// ローカルブリッジ
	if (true)
	{
		RPC_ENUM_LOCALBRIDGE t;
		bool b = false;

		Zero(&t, sizeof(t));
		if (ScEnumLocalBridge(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.NumItem != 0)
			{
				b = true;
			}
			FreeRpcEnumLocalBridge(&t);
		}

		if (b)
		{
			return false;
		}
	}

	// 仮想 HUB

	check_hub = false;

	if (is_bridge == false)
	{
		RPC_ENUM_HUB t;
		bool b = false;

		Zero(&t, sizeof(t));
		if (ScEnumHub(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.NumHub >= 2)
			{
				b = true;
			}
			else if (t.NumHub == 1)
			{
				if (StrCmpi(t.Hubs[0].HubName, SERVER_DEFAULT_HUB_NAME) != 0)
				{
					b = true;
				}
				else
				{
					check_hub = true;
				}
			}

			FreeRpcEnumHub(&t);
		}

		if (b)
		{
			return false;
		}
	}
	else
	{
		check_hub = true;
	}

	// 仮想 HUB の状態
	if (is_bridge == false)
	{
		StrCpy(hubname, sizeof(hubname), SERVER_DEFAULT_HUB_NAME);
	}
	else
	{
		StrCpy(hubname, sizeof(hubname), SERVER_DEFAULT_BRIDGE_NAME);
	}

	if (check_hub)
	{
		if (true)
		{
			// 仮想 HUB 内のオブジェクト数
			RPC_HUB_STATUS t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHubStatus(rpc, &t) == ERR_NO_ERROR)
			{
				if (t.NumSessions != 0 || t.NumAccessLists != 0 ||
					t.NumUsers != 0 || t.NumGroups != 0 ||
					t.NumMacTables != 0 || t.NumIpTables != 0 ||
					t.SecureNATEnabled)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (true)
		{
			// カスケード接続
			RPC_ENUM_LINK t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScEnumLink(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;

				if (t.NumLink != 0)
				{
					b = true;
				}

				FreeRpcEnumLink(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// 信頼する証明書一覧
			RPC_HUB_ENUM_CA t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScEnumCa(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;

				if (t.NumCa != 0)
				{
					b = true;
				}

				FreeRpcHubEnumCa(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// 無効な証明書一覧
			RPC_ENUM_CRL t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScEnumCrl(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;

				if (t.NumItem != 0)
				{
					b = true;
				}

				FreeRpcEnumCrl(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// 認証サーバーの設定
			RPC_RADIUS t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHubRadius(rpc, &t) == ERR_NO_ERROR)
			{
				if (IsEmptyStr(t.RadiusServerName) == false)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// 仮想 HUB の設定
			RPC_CREATE_HUB t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHub(rpc, &t) == ERR_NO_ERROR)
			{
				if (t.HubOption.NoEnum || t.HubOption.MaxSession != 0 ||
					t.Online == false)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// IP アクセス制御リスト
			RPC_AC_LIST t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetAcList(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;
				if (LIST_NUM(t.o) != 0)
				{
					b = true;
				}
				FreeRpcAcList(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// AO
			RPC_ADMIN_OPTION t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHubAdminOptions(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;
				UINT i;

				for (i = 0;i < t.NumItem;i++)
				{
					if (t.Items[i].Value != 0)
					{
						b = true;
					}
				}

				FreeRpcAdminOption(&t);

				if (b)
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

	// 仮想レイヤ 3 スイッチ
	if (is_bridge == false)
	{
		RPC_ENUM_L3SW t;
		bool b = false;

		Zero(&t, sizeof(t));
		if (ScEnumL3Switch(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.NumItem != 0)
			{
				b = true;
			}

			FreeRpcEnumL3Sw(&t);
		}
		else
		{
			return false;
		}

		if (b)
		{
			return false;
		}
	}

	return true;
}

// セットアップ手順ダイアログ初期化
void SmSetupStepDlgInit(HWND hWnd, SM_SETUP *s)
{
	bool b;
	RPC_ENUM_ETH t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SETUP);

	DlgFont(hWnd, S_1_1, 0, true);
	DlgFont(hWnd, S_2_1, 0, true);
	DlgFont(hWnd, S_3_1, 0, true);

	b = false;
	if (s->UseRemote)
	{
		b = true;
	}
	if (s->UseSite && s->UseSiteEdge == false)
	{
		b = true;
	}

	SetEnable(hWnd, S_1_1, b);
	SetEnable(hWnd, S_1_2, b);
	SetEnable(hWnd, B_USER, b);

	b = false;
	if (s->UseSiteEdge)
	{
		b = true;
	}

	SetEnable(hWnd, S_2_1, b);
	SetEnable(hWnd, S_2_2, b);
	SetEnable(hWnd, B_CASCADE, b);

	CbReset(hWnd, C_DEVICE);
	CbSetHeight(hWnd, C_DEVICE, 18);

	Zero(&t, sizeof(t));

	CbAddStr(hWnd, C_DEVICE, _UU("SM_SETUP_SELECT"), 0);

	if (CALL(hWnd, ScEnumEthernet(s->Rpc, &t)) == false)
	{
		return;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		wchar_t tmp[MAX_PATH];
		RPC_ENUM_ETH_ITEM *e = &t.Items[i];

		StrToUni(tmp, sizeof(tmp), e->DeviceName);

		CbAddStr(hWnd, C_DEVICE, tmp, 1);
	}

	FreeRpcEnumEth(&t);

	s->Flag1 = false;
	s->Flag2 = false;
}

// 閉じる
void SmSetupOnClose(HWND hWnd, SM_SETUP *s)
{
	wchar_t *tmp;
	char name[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	tmp = CbGetStr(hWnd, C_DEVICE);

	if (tmp != NULL)
	{
		UniToStr(name, sizeof(name), tmp);

		if (CbGetSelect(hWnd, C_DEVICE) != 0)
		{
			RPC_LOCALBRIDGE t;

			Zero(&t, sizeof(t));
			t.Active = true;
			StrCpy(t.DeviceName, sizeof(t.DeviceName), name);
			StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
			t.Online = true;
			t.TapMode = false;

			if (CALL(hWnd, ScAddLocalBridge(s->Rpc, &t)) == false)
			{
				Free(tmp);
				return;
			}
		}
		Free(tmp);
	}

	EndDialog(hWnd, 0);
}

// セットアップ手順ダイアログプロシージャ
UINT SmSetupStepDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SETUP *s = (SM_SETUP *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmSetupStepDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_USER:
			// ユーザー作成
			if (true)
			{
				SM_HUB h;

				Zero(&h, sizeof(h));
				h.HubName = s->HubName;
				h.p = s->s;
				h.Rpc = s->Rpc;

				SmUserListDlgEx(hWnd, &h, NULL, s->Flag1 ? false : true);

				s->Flag1 = true;
			}
			break;

		case B_CASCADE:
			// カスケード接続作成
			if (true)
			{
				SM_HUB h;

				Zero(&h, sizeof(h));
				h.HubName = s->HubName;
				h.p = s->s;
				h.Rpc = s->Rpc;

				SmLinkDlgEx(hWnd, &h, s->Flag2 ? false : true);
				s->Flag2 = true;
			}
			break;

		case IDCANCEL:
			// 閉じるボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		// 終了
		SmSetupOnClose(hWnd, s);
		break;
	}

	return 0;
}

// セットアップ手順ダイアログ
void SmSetupStep(HWND hWnd, SM_SETUP *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_SETUP_STEP, SmSetupStepDlg, s);
}

// セットアップによる初期化を行う
bool SmSetupInit(HWND hWnd, SM_SETUP *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	if (s->IsBridge == false)
	{
		if (SmSetupDeleteAllLayer3(hWnd, s) == false)
		{
			return false;
		}

		if (SmSetupDeleteAllHub(hWnd, s) == false)
		{
			return false;
		}
	}
	else
	{
		if (SmSetupDeleteAllObjectInBridgeHub(hWnd, s) == false)
		{
			return false;
		}
	}

	if (SmSetupDeleteAllLocalBridge(hWnd, s) == false)
	{
		return false;
	}

	if (s->IsBridge == false)
	{
		// 仮想 HUB の作成
		RPC_CREATE_HUB t;
		char *password = "";

		Zero(&t, sizeof(t));
		Hash(t.HashedPassword, password, StrLen(password), true);
		HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, password);
		StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
		t.HubType = HUB_TYPE_STANDALONE;
		t.Online = true;

		if (CALL(hWnd, ScCreateHub(s->Rpc, &t)) == false)
		{
			return false;
		}
	}

	return true;
}

// すべての VPN Bridge 用の仮想 HUB 内のオブジェクトを削除
bool SmSetupDeleteAllObjectInBridgeHub(HWND hWnd, SM_SETUP *s)
{
	char *hubname = SERVER_DEFAULT_BRIDGE_NAME;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	if (true)
	{
		RPC_ENUM_LINK t;
		UINT i;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		if (CALL(hWnd, ScEnumLink(s->Rpc, &t)) == false)
		{
			return false;
		}

		for (i = 0;i < t.NumLink;i++)
		{
			RPC_ENUM_LINK_ITEM *e = &t.Links[i];
			RPC_LINK a;

			Zero(&a, sizeof(a));
			StrCpy(a.HubName, sizeof(a.HubName), hubname);
			UniStrCpy(a.AccountName, sizeof(a.AccountName), e->AccountName);

			if (CALL(hWnd, ScDeleteLink(s->Rpc, &a)) == false)
			{
				FreeRpcEnumLink(&t);
				return false;
			}
		}

		FreeRpcEnumLink(&t);
	}

	if (true)
	{
		RPC_HUB t;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		if (CALL(hWnd, ScDisableSecureNAT(s->Rpc, &t)) == false)
		{
			return false;
		}
	}

	return true;
}

// すべての仮想レイヤ 3 スイッチの削除
bool SmSetupDeleteAllLayer3(HWND hWnd, SM_SETUP *s)
{
	RPC_ENUM_L3SW t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if(CALL(hWnd, ScEnumL3Switch(s->Rpc, &t)) == false)
	{
		return false;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *e = &t.Items[i];
		RPC_L3SW tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), e->Name);

		if (CALL(hWnd, ScDelL3Switch(s->Rpc, &tt)) == false)
		{
			FreeRpcEnumL3Sw(&t);
			return false;
		}
	}

	FreeRpcEnumL3Sw(&t);

	return true;
}

// すべてのローカルブリッジの削除
bool SmSetupDeleteAllLocalBridge(HWND hWnd, SM_SETUP *s)
{
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumLocalBridge(s->Rpc, &t)) == false)
	{
		return false;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t.Items[i];

		if (CALL(hWnd, ScDeleteLocalBridge(s->Rpc, e)) == false)
		{
			FreeRpcEnumLocalBridge(&t);
			return false;
		}
	}

	FreeRpcEnumLocalBridge(&t);

	return true;
}

// すべての仮想 HUB の削除
bool SmSetupDeleteAllHub(HWND hWnd, SM_SETUP *s)
{
	RPC_ENUM_HUB t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumHub(s->Rpc, &t)) == false)
	{
		return false;
	}

	for (i = 0;i < t.NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
		RPC_DELETE_HUB tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.HubName, sizeof(tt.HubName), e->HubName);

		if (CALL(hWnd, ScDeleteHub(s->Rpc, &tt)) == false)
		{
			FreeRpcEnumHub(&t);
			return false;
		}
	}

	FreeRpcEnumHub(&t);

	return true;
}

// 仮想 HUB のコントロール更新
void SmSetupHubDlgUpdate(HWND hWnd, SM_SETUP *s)
{
	bool ok = true;
	char tmp[MAX_HUBNAME_LEN + 1];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_HUBNAME, tmp, sizeof(tmp));

	if (IsEmptyStr(tmp) || IsSafeStr(tmp) == false)
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// 仮想 HUB 作成ダイアログ
UINT SmSetupHubDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SETUP *s = (SM_SETUP *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetTextA(hWnd, E_HUBNAME, "VPN");
		FocusEx(hWnd, E_HUBNAME);
		SmSetupHubDlgUpdate(hWnd, s);
		break;

	case WM_COMMAND:
		SmSetupHubDlgUpdate(hWnd, s);

		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_HUBNAME, s->HubName, sizeof(s->HubName));
			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// セットアップダイアログの [次へ] ボタン
void SmSetupDlgOnOk(HWND hWnd, SM_SETUP *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (MsgBox(hWnd, MB_YESNO | MB_ICONEXCLAMATION, _UU("SM_SETUP_WARNING")) == IDNO)
	{
		return;
	}

	s->UseRemote = IsChecked(hWnd, C_REMOTE);
	s->UseSite = IsChecked(hWnd, C_SITE);
	s->UseSiteEdge = IsChecked(hWnd, C_EDGE);

	if (s->IsBridge)
	{
		StrCpy(s->HubName, sizeof(s->HubName), SERVER_DEFAULT_BRIDGE_NAME);
	}
	else
	{
		if (Dialog(hWnd, D_SM_SETUP_HUB, SmSetupHubDlg, s) == false)
		{
			return;
		}
	}

	// 初期化 (既存オブジェクトの抹消)
	if (SmSetupInit(hWnd, s) == false)
	{
		return;
	}

	// 手順の実行
	SmSetupStep(hWnd, s);

	// ダイアログを閉じる
	EndDialog(hWnd, true);
}

// セットアップダイアログ初期化
void SmSetupDlgInit(HWND hWnd, SM_SETUP *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SETUP);
	DlgFont(hWnd, S_TITLE, 14, true);
	DlgFont(hWnd, C_REMOTE, 0, true);
	DlgFont(hWnd, C_SITE, 0, true);
	DlgFont(hWnd, C_OTHER, 0, true);

	if (s->IsBridge)
	{
		SetText(hWnd, B_BOLD, _UU("SM_SETUP_BRIDGE_ONLY"));
		SetText(hWnd, C_EDGE, _UU("SM_SETUP_BRIDGE_EDGE"));

		Check(hWnd, C_SITE, true);
		Check(hWnd, C_EDGE, true);
		Focus(hWnd, C_SITE);
	}

	SmSetupDlgUpdate(hWnd, s);
}

// セットアップダイアログ更新
void SmSetupDlgUpdate(HWND hWnd, SM_SETUP *s)
{
	bool enable_remote = true;
	bool enable_site = true;
	bool enable_site_center = true;
	bool enable_detail = true;
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->IsBridge)
	{
		enable_remote = false;
		enable_site_center = false;
		enable_detail = false;
	}

	if (IsChecked(hWnd, C_OTHER))
	{
		ok = false;
	}

	SetEnable(hWnd, C_REMOTE, enable_remote && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, S_REMOTE_1, enable_remote && IsChecked(hWnd, C_OTHER) == false);

	SetEnable(hWnd, C_SITE, enable_site && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, S_SITE_1, enable_site && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, S_SITE_2, enable_site && IsChecked(hWnd, C_SITE) && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, C_CENTER, enable_site && enable_site_center && IsChecked(hWnd, C_SITE) && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, C_EDGE, enable_site && IsChecked(hWnd, C_SITE) && IsChecked(hWnd, C_OTHER) == false);

	SetEnable(hWnd, C_OTHER, enable_detail);
	SetEnable(hWnd, S_OTHER, enable_detail);

	if (IsChecked(hWnd, C_REMOTE) == false && IsChecked(hWnd, C_SITE) == false)
	{
		ok = false;
	}

	if (IsChecked(hWnd, C_SITE))
	{
		if (IsChecked(hWnd, C_CENTER) == false && IsChecked(hWnd, C_EDGE) == false)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);

	SetText(hWnd, S_INFO,
		IsChecked(hWnd, C_OTHER) ? _UU("SM_SETUP_INFO_2") : _UU("SM_SETUP_INFO_1"));
}

// セットアップダイアログ
UINT SmSetupDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SETUP *s = (SM_SETUP *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmSetupDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		SmSetupDlgUpdate(hWnd, s);

		switch (wParam)
		{
		case IDOK:
			SmSetupDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// セットアップ
bool SmSetup(HWND hWnd, SM_SERVER *s)
{
	SM_SETUP ss;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	Zero(&ss, sizeof(ss));
	ss.s = s;
	ss.IsBridge = ss.s->Bridge;
	ss.Rpc = s->Rpc;

	if (Dialog(hWnd, D_SM_SETUP, SmSetupDlg, &ss) == false)
	{
		return false;
	}

	return true;
}

// ライセンス登録処理
void SmLicenseAddDlgOnOk(HWND hWnd, SM_SERVER *s)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmLicenseAddDlgGetText(hWnd, tmp, sizeof(tmp));

	if (true)
	{
		RPC_TEST t;

		Disable(hWnd, IDOK);
		Disable(hWnd, IDCANCEL);

		Zero(&t, sizeof(t));
		StrCpy(t.StrValue, sizeof(t.StrValue), tmp);

		if (CALL(hWnd, ScAddLicenseKey(s->Rpc, &t)) == false)
		{
			FocusEx(hWnd, B_KEY6);
		}
		else
		{
			EndDialog(hWnd, true);
		}

		Enable(hWnd, IDOK);
		Enable(hWnd, IDCANCEL);
	}
}

// テキスト入力のシフト処理
void SmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus)
{
	char *s;
	// 引数チェック
	if (hWnd == NULL || next_focus == NULL)
	{
		return;
	}

	s = GetTextA(hWnd, id1);
	if (StrLen(s) >= 6)
	{
		char *s2 = CopyStr(s);
		char tmp[MAX_SIZE];
		s2[6] = 0;
		SetTextA(hWnd, id1, s2);
		Free(s2);

		if (id2 != 0)
		{
			GetTxtA(hWnd, id2, tmp, sizeof(tmp));

			StrCat(tmp, sizeof(tmp), s + 6);
			ReplaceStrEx(tmp, sizeof(tmp), tmp, "-", "", false);

			SetTextA(hWnd, id2, tmp);

			*next_focus = id2;
		}
		else
		{
			*next_focus = IDOK;
		}
	}

	Free(s);
}

// 入力データをテキスト化
void SmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size)
{
	char *k1, *k2, *k3, *k4, *k5, *k6;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	k1 = GetTextA(hWnd, B_KEY1);
	k2 = GetTextA(hWnd, B_KEY2);
	k3 = GetTextA(hWnd, B_KEY3);
	k4 = GetTextA(hWnd, B_KEY4);
	k5 = GetTextA(hWnd, B_KEY5);
	k6 = GetTextA(hWnd, B_KEY6);

	Format(str, size, "%s-%s-%s-%s-%s-%s", k1, k2, k3, k4, k5, k6);

	Free(k1);
	Free(k2);
	Free(k3);
	Free(k4);
	Free(k5);
	Free(k6);
}

// ライセンス追加ダイアログ更新
void SmLicenseAddDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	UINT next_focus = 0;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (s == NULL || hWnd == NULL)
	{
		return;
	}

	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY1, B_KEY2, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY2, B_KEY3, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY3, B_KEY4, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY4, B_KEY5, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY5, B_KEY6, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY6, 0, &next_focus);

	if ((IsFocus(hWnd, B_KEY1) && GetTextLen(hWnd, B_KEY1, true) <= 5) ||
		(IsFocus(hWnd, B_KEY2) && GetTextLen(hWnd, B_KEY2, true) <= 5) ||
		(IsFocus(hWnd, B_KEY3) && GetTextLen(hWnd, B_KEY3, true) <= 5) ||
		(IsFocus(hWnd, B_KEY4) && GetTextLen(hWnd, B_KEY4, true) <= 5) ||
		(IsFocus(hWnd, B_KEY5) && GetTextLen(hWnd, B_KEY5, true) <= 5) ||
		(IsFocus(hWnd, B_KEY6) && GetTextLen(hWnd, B_KEY6, true) <= 5))
	{
		next_focus = 0;
	}

	if (next_focus != 0)
	{
		Focus(hWnd, next_focus);
	}

	SmLicenseAddDlgGetText(hWnd, tmp, sizeof(tmp));

	SetEnable(hWnd, IDOK, true);
}

// ライセンス追加ダイアログ初期化
void SmLicenseAddDlgInit(HWND hWnd, SM_SERVER *s)
{
	HFONT h;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	h = GetFont("Arial", 10, true, false, false, false);
	SetFont(hWnd, B_KEY1, h);
	SetFont(hWnd, B_KEY2, h);
	SetFont(hWnd, B_KEY3, h);
	SetFont(hWnd, B_KEY4, h);
	SetFont(hWnd, B_KEY5, h);
	SetFont(hWnd, B_KEY6, h);

	DlgFont(hWnd, S_INFO, 10, true);

	SmLicenseAddDlgUpdate(hWnd, s);
}

// ライセンスの追加ダイアログ
UINT SmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmLicenseAddDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case B_KEY1:
		case B_KEY2:
		case B_KEY3:
		case B_KEY4:
		case B_KEY5:
		case B_KEY6:
			switch (HIWORD(wParam))
			{
			case EN_CHANGE:
				SmLicenseAddDlgUpdate(hWnd, s);

				switch (LOWORD(wParam))
				{
				case B_KEY2:
					if (GetTextLen(hWnd, B_KEY2, true) == 0)
					{
						FocusEx(hWnd, B_KEY1);
					}
					break;
				case B_KEY3:
					if (GetTextLen(hWnd, B_KEY3, true) == 0)
					{
						FocusEx(hWnd, B_KEY2);
					}
					break;
				case B_KEY4:
					if (GetTextLen(hWnd, B_KEY4, true) == 0)
					{
						FocusEx(hWnd, B_KEY3);
					}
					break;
				case B_KEY5:
					if (GetTextLen(hWnd, B_KEY5, true) == 0)
					{
						FocusEx(hWnd, B_KEY4);
					}
					break;
				case B_KEY6:
					if (GetTextLen(hWnd, B_KEY6, true) == 0)
					{
						FocusEx(hWnd, B_KEY5);
					}
					break;
				}
				break;
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmLicenseAddDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// ライセンスの追加
bool SmLicenseAdd(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_SM_LICENSE_ADD, SmLicenseAddDlg, s);
}

// ライセンスダイアログ初期化
void SmLicenseDlgInit(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_CERT);

	DlgFont(hWnd, S_BOLD, 0, true);
	DlgFont(hWnd, S_BOLD2, 0, true);

	LvInit(hWnd, L_LIST);
	LvSetStyle(hWnd, L_LIST, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_LICENSE_COLUMN_1"), 50);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_LICENSE_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_LICENSE_COLUMN_3"), 290);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_LICENSE_COLUMN_4"), 150);
	LvInsertColumn(hWnd, L_LIST, 4, _UU("SM_LICENSE_COLUMN_5"), 120);
	LvInsertColumn(hWnd, L_LIST, 5, _UU("SM_LICENSE_COLUMN_6"), 250);
	LvInsertColumn(hWnd, L_LIST, 6, _UU("SM_LICENSE_COLUMN_7"), 100);
	LvInsertColumn(hWnd, L_LIST, 7, _UU("SM_LICENSE_COLUMN_8"), 100);
	LvInsertColumn(hWnd, L_LIST, 8, _UU("SM_LICENSE_COLUMN_9"), 100);

	LvInitEx(hWnd, L_STATUS, true);
	LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 100);
	LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 100);

	SmLicenseDlgRefresh(hWnd, s);
}

// ライセンスダイアログ更新
void SmLicenseDlgRefresh(HWND hWnd, SM_SERVER *s)
{
	RPC_ENUM_LICENSE_KEY t;
	RPC_LICENSE_STATUS st;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	LVB *b;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	if (CALL(hWnd, ScEnumLicenseKey(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		wchar_t tmp1[32], tmp2[LICENSE_KEYSTR_LEN + 1], tmp3[LICENSE_MAX_PRODUCT_NAME_LEN + 1],
			*tmp4, tmp5[128], tmp6[LICENSE_LICENSEID_STR_LEN + 1], tmp7[64],
			tmp8[64], tmp9[64];
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t.Items[i];

		UniToStru(tmp1, e->Id);
		StrToUni(tmp2, sizeof(tmp2), e->LicenseKey);
		StrToUni(tmp3, sizeof(tmp3), e->LicenseName);
		tmp4 = LiGetLicenseStatusStr(e->Status);
		if (e->Expires == 0)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp5, sizeof(tmp5), e->Expires, NULL);
		}
		StrToUni(tmp6, sizeof(tmp6), e->LicenseId);
		UniToStru(tmp7, e->ProductId);
		UniFormat(tmp8, sizeof(tmp8), L"%I64u", e->SystemId);
		UniToStru(tmp9, e->SerialId);

		LvInsertAdd(b,
			e->Status == LICENSE_STATUS_OK ? ICO_PASS : ICO_DISCARD,
			(void *)e->Id, 9,
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
	}

	LvInsertEnd(b, hWnd, L_LIST);

	FreeRpcEnumLicenseKey(&t);

	Zero(&st, sizeof(st));

	if (CALL(hWnd, ScGetLicenseStatus(s->Rpc, &st)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();

	if (st.EditionId == LICENSE_EDITION_VPN3_NO_LICENSE)
	{
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NO_LICENSE_COLUMN"), _UU("SM_NO_LICENSE"));
	}
	else
	{
		// 製品エディション名
		StrToUni(tmp, sizeof(tmp), st.EditionStr);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_EDITION"), tmp);

		// リリース日付
		if (st.ReleaseDate != 0)
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.ReleaseDate, NULL);
			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_RELEASE"), tmp);
		}

		// 現在のシステム ID
		UniFormat(tmp, sizeof(tmp), L"%I64u", st.SystemId);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SYSTEM_ID"), tmp);

		// 現在の製品ライセンスの有効期限
		if (st.SystemExpires == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.SystemExpires, NULL);
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_EXPIRES"), tmp);

		// サブスクリプション (サポート) 契約
		if (st.NeedSubscription == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONEED"));
		}
		else
		{
			if (st.SubscriptionExpires == 0)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONE"));
			}
			else
			{
				wchar_t dtstr[MAX_PATH];

				GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

				UniFormat(tmp, sizeof(tmp),
					st.IsSubscriptionExpired ? _UU("SM_LICENSE_STATUS_SUBSCRIPTION_EXPIRED") :  _UU("SM_LICENSE_STATUS_SUBSCRIPTION_VALID"),
					dtstr);
			}
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SUBSCRIPTION"), tmp);

		if (st.NeedSubscription == false && st.SubscriptionExpires != 0)
		{
			wchar_t dtstr[MAX_PATH];

			GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD_STR"), tmp);
		}

		if (st.NeedSubscription && st.SubscriptionExpires != 0)
		{
			wchar_t dtstr[MAX_PATH];

			GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

			UniFormat(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD_STR"), dtstr);

			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD"), tmp);
		}

		if (GetCapsBool(s->CapsList, "b_vpn3"))
		{
			// ユーザー作成可能数
			if (st.NumUserCreationLicense == INFINITE)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
			}
			else
			{
				UniToStru(tmp, st.NumUserCreationLicense);
			}
			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_NUM_USER"), tmp);
		}

		// クライアント同時接続可能数
		if (st.NumClientConnectLicense == INFINITE)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
		}
		else
		{
			UniToStru(tmp, st.NumClientConnectLicense);
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_NUM_CLIENT"), tmp);

		// ブリッジ同時接続可能数
		if (st.NumBridgeConnectLicense == INFINITE)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
		}
		else
		{
			UniToStru(tmp, st.NumBridgeConnectLicense);
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_NUM_BRIDGE"), tmp);

		// エンタープライズ機能の利用可否
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_ENTERPRISE"),
			st.AllowEnterpriseFunction ? _UU("SM_LICENSE_STATUS_ENTERPRISE_YES") : _UU("SM_LICENSE_STATUS_ENTERPRISE_NO"));
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	if (LvNum(hWnd, L_STATUS) >= 1)
	{
		LvAutoSize(hWnd, L_STATUS);
	}

	SmLicenseDlgUpdate(hWnd, s);
}

// ライセンスダイアログコントロール更新
void SmLicenseDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	bool b = false;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b = LvIsSingleSelected(hWnd, L_LIST);

	SetEnable(hWnd, B_DEL, b);
	SetEnable(hWnd, IDOK, b);
}

// ライセンスダイアログ
UINT SmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	NMHDR *n;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmLicenseDlgInit(hWnd, s);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
			case L_STATUS:
				SmLicenseDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				UINT i = LvGetSelected(hWnd, L_LIST);

				if (i != INFINITE)
				{
					char *s = LvGetStrA(hWnd, L_LIST, i, 1);
					char tmp[MAX_SIZE];

					Format(tmp, sizeof(tmp), _SS("LICENSE_SUPPORT_URL"), s);
					ShellExecute(hWnd, "open", tmp, NULL, NULL, SW_SHOW);

					Free(s);
				}
			}
			break;

		case B_OBTAIN:
			ShellExecute(hWnd, "open", _SS("LICENSE_INFO_URL"), NULL, NULL, SW_SHOW);
			break;

		case B_ADD:
			if (SmLicenseAdd(hWnd, s))
			{
				SmLicenseDlgRefresh(hWnd, s);
			}
			break;

		case B_DEL:
			if (IsEnable(hWnd, B_DEL))
			{
				UINT id = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (id != 0)
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_LICENSE_DELETE_MSG")) == IDYES)
					{
						RPC_TEST t;

						Zero(&t, sizeof(t));
						t.IntValue = id;

						if (CALL(hWnd, ScDelLicenseKey(s->Rpc, &t)))
						{
							SmLicenseDlgRefresh(hWnd, s);
						}
					}
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// ライセンスの追加と削除
void SmLicense(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_LICENSE, SmLicenseDlg, s);

	FreeCapsList(s->CapsList);
	s->CapsList = ScGetCapsEx(s->Rpc);
}

// ログ保存プロシージャ
UINT SmSaveLogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_READ_LOG_FILE *p = (SM_READ_LOG_FILE *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, S_INFO, p->filepath);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case B_SAVE:
			if (p->Buffer != NULL)
			{
				char filename[MAX_PATH];

				Format(filename, sizeof(filename), "%s_%s", p->server_name, p->filepath);
				ConvertSafeFileName(filename, sizeof(filename), filename);

				if (wParam == IDOK)
				{
					// エディタで開く
					char fullpath[MAX_PATH];

					Format(fullpath, sizeof(fullpath), "%s\\%s",
						MsGetMyTempDir(), filename);

					if (DumpBuf(p->Buffer, fullpath) == false)
					{
						MsgBoxEx(hWnd, MB_ICONSTOP, _UU("SM_READ_SAVE_TMP_FAILED"),
							fullpath);
					}
					else
					{
						if (((UINT)ShellExecute(hWnd, "open", fullpath, NULL, NULL, SW_SHOWNORMAL)) > 32)
						{
							EndDialog(hWnd, true);
						}
						else
						{
							MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_READ_SAVE_OPEN_ERROR"), fullpath);
						}
					}
				}
				else
				{
					// ファイルに保存する
					wchar_t def[MAX_PATH];
					wchar_t *uni_path;

					StrToUni(def, sizeof(def), filename);
					
					uni_path = SaveDlg(hWnd, _UU("SM_READ_SAVE_DLG_FILTER"), _UU("SM_READ_SAVE_DLG_TITLE"),
						def, L".log");

					if (uni_path != NULL)
					{
						char path[MAX_PATH];

						UniToStr(path, sizeof(path), uni_path);
						Free(uni_path);

						if (DumpBuf(p->Buffer, path) == false)
						{
							MsgBox(hWnd, MB_ICONSTOP, _UU("SM_READ_SAVE_FAILED"));
						}
						else
						{
							EndDialog(hWnd, true);
						}
					}
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// ダウンロードコールバックプロシージャ
bool SmReadLogFileProc(DOWNLOAD_PROGRESS *g)
{
	wchar_t tmp[MAX_SIZE];
	char size1[64], size2[64];
	SM_READ_LOG_FILE *p;
	HWND hWnd;
	// 引数チェック
	if (g == NULL)
	{
		return false;
	}

	p = (SM_READ_LOG_FILE *)g->Param;
	hWnd = p->hWnd;

	SetPos(hWnd, P_PROGRESS, g->ProgressPercent);

	ToStrByte(size1, sizeof(size1), g->CurrentSize);
	ToStrByte(size2, sizeof(size2), g->TotalSize);
	UniFormat(tmp, sizeof(tmp), _UU("SM_READ_LOG_FILE_INFO_2"), size2, size1);

	SetText(hWnd, S_INFO, tmp);

	DoEvents(hWnd);

	return p->cancel_flag ? false : true;
}

// ログファイルダウンロードダイアログプロシージャ
UINT SmReadLogFile(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_READ_LOG_FILE *p = (SM_READ_LOG_FILE *)param;
	BUF *buf;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		p->hWnd = hWnd;
		SetFont(hWnd, S_INFO, Font(11, true));
		SetText(hWnd, S_INFO, _UU("SM_READ_LOG_FILE_INFO_1"));
		DisableClose(hWnd);
		FormatText(hWnd, S_INFO2, p->filepath);
		SetRange(hWnd, P_PROGRESS, 0, 100);

		SetTimer(hWnd, 1, 100, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			buf = DownloadFileFromServer(p->s->Rpc, p->server_name, p->filepath, p->totalsize, SmReadLogFileProc, p);
			if (buf == NULL)
			{
				if (p->cancel_flag == false)
				{
					// ダウンロード失敗
					MsgBox(hWnd, MB_ICONSTOP, _UU("SM_READ_LOG_FILE_ERROR"));
				}
				EndDialog(hWnd, false);
			}
			else
			{
				// ダウンロード成功
				p->Buffer = buf;
				Dialog(hWnd, D_SM_SAVE_LOG, SmSaveLogProc, p);
				FreeBuf(buf);
				EndDialog(hWnd, true);
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			p->cancel_flag = true;
			break;
		}
		break;
	}

	return 0;
}

// ログファイルのダウンロードを開始する
void SmLogFileStartDownload(HWND hWnd, SM_SERVER *s, char *server_name, char *filepath, UINT totalsize)
{
	SM_READ_LOG_FILE p;
	// 引数チェック
	if (hWnd == NULL || server_name == NULL || filepath == NULL || totalsize == 0)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.filepath = filepath;
	p.s = s;
	p.server_name = server_name;
	p.totalsize = totalsize;

	Dialog(hWnd, D_SM_READ_LOG_FILE, SmReadLogFile, &p);
}

// ダイアログ初期化
void SmLogFileDlgInit(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_LOG2);

	LvInit(hWnd, L_LIST);

	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_LOG_FILE_COLUMN_1"), 250);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_LOG_FILE_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_LOG_FILE_COLUMN_3"), 130);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_LOG_FILE_COLUMN_4"), 110);

	SmLogFileDlgRefresh(hWnd, p);
}

// ダイアログ内容更新
void SmLogFileDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	UINT i;
	LVB *v;
	RPC_ENUM_LOG_FILE t;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumLogFile(p->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t.Items[i];
		wchar_t tmp1[MAX_PATH], tmp2[128], tmp3[128], tmp4[MAX_HOST_NAME_LEN + 1];
		char tmp[MAX_SIZE];

		StrToUni(tmp1, sizeof(tmp1), e->FilePath);

		ToStrByte(tmp, sizeof(tmp), e->FileSize);
		StrToUni(tmp2, sizeof(tmp2), tmp);

		GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->UpdatedTime));

		StrToUni(tmp4, sizeof(tmp4), e->ServerName);

		LvInsertAdd(v, ICO_LOG2, (void *)e->FileSize, 4, tmp1, tmp2, tmp3, tmp4);
	}

	LvInsertEndEx(v, hWnd, L_LIST, true);

	if (t.NumItem != 0)
	{
		LvAutoSize(hWnd, L_LIST);
	}

	FreeRpcEnumLogFile(&t);

	SmLogFileDlgUpdate(hWnd, p);
}

// ダイアログコントロール更新
void SmLogFileDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsSingleSelected(hWnd, L_LIST));
}

// ログファイルダイアログプロシージャ
UINT SmLogFileDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SERVER *p = (SM_SERVER *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmLogFileDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				UINT i = LvGetSelected(hWnd, L_LIST);
				if (i != INFINITE)
				{
					UINT size = (UINT)LvGetParam(hWnd, L_LIST, i);
					char *server_name;
					char *filepath;

					server_name = LvGetStrA(hWnd, L_LIST, i, 3);
					filepath = LvGetStrA(hWnd, L_LIST, i, 0);
					SmLogFileStartDownload(hWnd, p, server_name, filepath, size);
					Free(filepath);
					Free(server_name);
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_REFRESH:
			SmLogFileDlgRefresh(hWnd, p);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmLogFileDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// ダイアログ初期化
void SmHubEditAcDlgInit(HWND hWnd, SM_EDIT_AC *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetEnable(hWnd, R_IPV6, GetCapsBool(p->e->s->p->CapsList, "b_support_ipv6_ac"));

	if (p->id == 0)
	{
		UINT i, v;

		Check(hWnd, R_SINGLE, true);
		Check(hWnd, R_PASS, true);
		Check(hWnd, R_IPV4, true);

		v = 0;

		for (i = 0;i < LIST_NUM(p->e->AcList);i++)
		{
			AC *ac = LIST_DATA(p->e->AcList, i);

			v = MAX(v, ac->Priority);
		}

		v += 100;

		SetInt(hWnd, E_PRIORITY, v);
	}
	else
	{
		AC *ac = GetAc(p->e->AcList, p->id);

		if (ac == NULL)
		{
			EndDialog(hWnd, false);
			return;
		}

		Check(hWnd, R_SINGLE, ac->Masked == false);
		Check(hWnd, R_MASKED, ac->Masked);
		Check(hWnd, R_IPV4, IsIP4(&ac->IpAddress));
		Check(hWnd, R_IPV6, IsIP6(&ac->IpAddress));

		if (IsIP4(&ac->IpAddress))
		{
			IpSet(hWnd, E_IP, IPToUINT(&ac->IpAddress));
		}
		else
		{
			char tmp[MAX_SIZE];

			IPToStr(tmp, sizeof(tmp), &ac->IpAddress);
			SetTextA(hWnd, E_IPV6, tmp);
		}

		if (ac->Masked)
		{
			if (IsIP4(&ac->IpAddress))
			{
				IpSet(hWnd, E_MASK, IPToUINT(&ac->SubnetMask));
			}
			else
			{
				char tmp[MAX_SIZE];

				MaskToStrEx(tmp, sizeof(tmp), &ac->SubnetMask, false);

				if (IsNum(tmp))
				{
					StrCatLeft(tmp, sizeof(tmp), "/");
				}

				SetTextA(hWnd, E_MASKV6, tmp);
			}
		}

		Check(hWnd, R_PASS, ac->Deny == false);
		Check(hWnd, R_DENY, ac->Deny);
		SetInt(hWnd, E_PRIORITY, ac->Priority);

		Free(ac);
	}

	Focus(hWnd, E_IP);

	SmHubEditAcDlgUpdate(hWnd, p);
}

// ダイアログ更新
void SmHubEditAcDlgUpdate(HWND hWnd, SM_EDIT_AC *p)
{
	bool b = true;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, R_SINGLE))
	{
		if (IsChecked(hWnd, R_IPV6) == false)
		{
			Show(hWnd, E_IP);
			Hide(hWnd, E_IPV6);

			if (IpIsFilled(hWnd, E_IP) == false)
			{
				b = false;
			}

			if (IpGet(hWnd, E_IP) == 0 || IpGet(hWnd, E_IP) == 0xffffffff)
			{
				b = false;
			}
		}
		else
		{
			Show(hWnd, E_IPV6);
			Hide(hWnd, E_IP);

			GetTxtA(hWnd, E_IPV6, tmp, sizeof(tmp));

			if (IsStrIPv6Address(tmp) == false)
			{
				b = false;
			}
		}

		Hide(hWnd, S_MASK);
		Hide(hWnd, E_MASK);
		Hide(hWnd, E_MASKV6);
	}
	else
	{
		if (IsChecked(hWnd, R_IPV6) == false)
		{
			Show(hWnd, E_IP);
			Hide(hWnd, E_IPV6);

			if (IpIsFilled(hWnd, E_IP) == false || IpIsFilled(hWnd, E_MASK) == false)
			{
				b = false;
			}

			if (IpGet(hWnd, E_IP) == 0xffffffff)
			{
				b = false;
			}
		}
		else
		{
			char tmp1[MAX_SIZE], tmp2[MAX_SIZE];

			Show(hWnd, E_IPV6);
			Hide(hWnd, E_IP);

			GetTxtA(hWnd, E_IPV6, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_MASKV6, tmp2, sizeof(tmp2));

			if (!(IsIpStr6(tmp1) && IsIpMask6(tmp2)))
			{
				b = false;
			}
		}

		Show(hWnd, S_MASK);
		SetShow(hWnd, E_MASK, !IsChecked(hWnd, R_IPV6));
		SetShow(hWnd, E_MASKV6, IsChecked(hWnd, R_IPV6));
	}

	if (GetInt(hWnd, E_PRIORITY) == 0)
	{
		b = false;
	}

	SetIcon(hWnd, S_ICON, IsChecked(hWnd, R_PASS) ? ICO_INTERNET : ICO_INTERNET_X);

	SetEnable(hWnd, IDOK, b);
}

// ダイアログで OK ボタンがクリックされた
void SmHubEditAcDlgOnOk(HWND hWnd, SM_EDIT_AC *p)
{
	AC ac;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&ac, sizeof(ac));
	ac.Deny = IsChecked(hWnd, R_DENY);
	ac.Priority = GetInt(hWnd, E_PRIORITY);

	if (IsChecked(hWnd, R_IPV6) == false)
	{
		UINTToIP(&ac.IpAddress, IpGet(hWnd, E_IP));
	}
	else
	{
		GetTxtA(hWnd, E_IPV6, tmp, sizeof(tmp));

		StrToIP6(&ac.IpAddress, tmp);
	}

	ac.Masked = IsChecked(hWnd, R_MASKED);

	if (ac.Masked)
	{
		if (IsChecked(hWnd, R_IPV6) == false)
		{
			UINTToIP(&ac.SubnetMask, IpGet(hWnd, E_MASK));
		}
		else
		{
			GetTxtA(hWnd, E_MASKV6, tmp, sizeof(tmp));

			StrToMask6(&ac.SubnetMask, tmp);
		}
	}

	if (p->id != 0)
	{
		SetAc(p->e->AcList, p->id, &ac);
	}
	else
	{
		AddAc(p->e->AcList, &ac);
	}

	EndDialog(hWnd, true);
}

// AC 編集ダイアログ
UINT SmHubEditAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_AC *p = (SM_EDIT_AC *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmHubEditAcDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_SINGLE:
		case R_MASKED:
		case E_IP:
		case E_MASK:
		case R_PASS:
		case R_DENY:
		case E_PRIORITY:
		case R_IPV4:
		case R_IPV6:
		case E_IPV6:
		case E_MASKV6:
			SmHubEditAcDlgUpdate(hWnd, p);
			break;
		}

		switch (wParam)
		{
		case R_IPV4:
		case R_IPV6:
		case R_SINGLE:
		case R_MASKED:
			if (IsChecked(hWnd, R_IPV6) == false)
			{
				if (IpIsFilled(hWnd, E_IP))
				{
					Focus(hWnd, E_MASK);
				}
				else
				{
					Focus(hWnd, E_IP);
				}
			}
			else
			{
				char tmp[MAX_SIZE];

				GetTxtA(hWnd, E_IPV6, tmp, sizeof(tmp));

				if (IsStrIPv6Address(tmp))
				{
					FocusEx(hWnd, E_MASKV6);
				}
				else
				{
					FocusEx(hWnd, E_IPV6);
				}
			}
			break;

		case IDOK:
			SmHubEditAcDlgOnOk(hWnd, p);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// ダイアログ初期化
void SmHubAcDlgInit(HWND hWnd, SM_EDIT_AC_LIST *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_INTERNET);

	FormatText(hWnd, S_TITLE, p->s->HubName);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_AC_COLUMN_1"), 40);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_AC_COLUMN_2"), 80);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_AC_COLUMN_3"), 90);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_AC_COLUMN_4"), 170);

	SmHubAcDlgRefresh(hWnd, p);
}

// ダイアログコントロール更新
void SmHubAcDlgUpdate(HWND hWnd, SM_EDIT_AC_LIST *p)
{
	bool b;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	b = LvIsSingleSelected(hWnd, L_LIST);

	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, B_DELETE, b);
}

// ダイアログ内容更新
void SmHubAcDlgRefresh(HWND hWnd, SM_EDIT_AC_LIST *p)
{
	UINT i;
	LVB *v;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < LIST_NUM(p->AcList);i++)
	{
		wchar_t tmp1[32], *tmp2, tmp3[MAX_SIZE], tmp4[32];
		char *tmp_str;
		AC *ac = LIST_DATA(p->AcList, i);

		UniToStru(tmp1, ac->Id);
		tmp2 = ac->Deny ? _UU("SM_AC_DENY") : _UU("SM_AC_PASS");
		tmp_str = GenerateAcStr(ac);
		StrToUni(tmp3, sizeof(tmp3), tmp_str);

		Free(tmp_str);

		UniToStru(tmp4, ac->Priority);

		LvInsertAdd(v, ac->Deny ? ICO_INTERNET_X : ICO_INTERNET,
			(void *)ac->Id, 4, tmp1, tmp4, tmp2, tmp3);
	}

	LvInsertEnd(v, hWnd, L_LIST);
	LvSortEx(hWnd, L_LIST, 0, false, true);


	SmHubAcDlgUpdate(hWnd, p);
}

// アクセス制御リスト編集ダイアログ
UINT SmHubAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_EDIT_AC_LIST *p = (SM_EDIT_AC_LIST *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmHubAcDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				SM_EDIT_AC s;
				Zero(&s, sizeof(s));

				s.e = p;
				s.id = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (Dialog(hWnd, D_SM_AC, SmHubEditAcDlgProc, &s))
				{
					SmHubAcDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_ADD:
			if (IsEnable(hWnd, B_ADD))
			{
				SM_EDIT_AC s;
				Zero(&s, sizeof(s));

				s.e = p;

				if (Dialog(hWnd, D_SM_AC, SmHubEditAcDlgProc, &s))
				{
					SmHubAcDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_DELETE:
			if (IsEnable(hWnd, B_DELETE))
			{
				UINT id = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (DelAc(p->AcList, id))
				{
					SmHubAcDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_SAVE:
			if (IsEnable(hWnd, B_SAVE))
			{
				RPC_AC_LIST t;

				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), p->s->HubName);
				t.o = CloneAcList(p->AcList);

				if (CALL(hWnd, ScSetAcList(p->s->p->Rpc, &t)))
				{
					EndDialog(hWnd, true);
				}

				FreeRpcAcList(&t);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmHubAcDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// アクセス制御リスト編集
void SmHubAc(HWND hWnd, SM_EDIT_HUB *s)
{
	SM_EDIT_AC_LIST p;
	RPC_AC_LIST t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScGetAcList(s->p->Rpc, &t)) == false)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.s = s;
	p.AcList = CloneAcList(t.o);

	FreeRpcAcList(&t);

	Dialog(hWnd, D_SM_AC_LIST, SmHubAcDlgProc, &p);

	FreeAcList(p.AcList);
}

// ダイアログ初期化
void SmEditCrlDlgInit(HWND hWnd, SM_EDIT_CRL *c)
{
	// 引数チェック
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	if (c->NewCrl == false)
	{
		RPC_CRL t;
		CRL *crl;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), c->s->HubName);
		t.Key = c->Key;

		if (CALL(hWnd, ScGetCrl(c->s->Rpc, &t)) == false)
		{
			EndDialog(hWnd, false);
			return;
		}

		crl = t.Crl;

		SmEditCrlDlgSetName(hWnd, crl->Name);
		SmEditCrlDlgSetSerial(hWnd, crl->Serial);
		SmEditCrlDlgSetHash(hWnd, crl->DigestMD5, crl->DigestSHA1);

		FreeRpcCrl(&t);
	}

	SmEditCrlDlgUpdate(hWnd, c);
}

// コントロール更新
void SmEditCrlDlgUpdate(HWND hWnd, SM_EDIT_CRL *c)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	SetEnable(hWnd, E_CN, IsChecked(hWnd, R_CN));
	SetEnable(hWnd, E_O, IsChecked(hWnd, R_O));
	SetEnable(hWnd, E_OU, IsChecked(hWnd, R_OU));
	SetEnable(hWnd, E_C, IsChecked(hWnd, R_C));
	SetEnable(hWnd, E_ST, IsChecked(hWnd, R_ST));
	SetEnable(hWnd, E_L, IsChecked(hWnd, R_L));
	SetEnable(hWnd, E_SERI, IsChecked(hWnd, R_SERI));
	SetEnable(hWnd, E_MD5_HASH, IsChecked(hWnd, R_MD5_HASH));
	SetEnable(hWnd, E_SHA1_HASH, IsChecked(hWnd, R_SHA1_HASH));

	if (IsChecked(hWnd, R_CN))
	{
		if (IsEmpty(hWnd, E_CN))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_O))
	{
		if (IsEmpty(hWnd, E_O))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_OU))
	{
		if (IsEmpty(hWnd, E_OU))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_C))
	{
		if (IsEmpty(hWnd, E_C))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_ST))
	{
		if (IsEmpty(hWnd, E_ST))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_L))
	{
		if (IsEmpty(hWnd, E_L))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_SERI))
	{
		char tmp[MAX_SIZE];
		BUF *buf;

		GetTxtA(hWnd, E_SERI, tmp, sizeof(tmp));
		buf = StrToBin(tmp);

		if (buf->Size == 0)
		{
			b = false;
		}

		FreeBuf(buf);
	}

	if (IsChecked(hWnd, R_MD5_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *buf;

		GetTxtA(hWnd, E_MD5_HASH, tmp, sizeof(tmp));
		buf = StrToBin(tmp);

		if (buf->Size != MD5_SIZE)
		{
			b = false;
		}

		FreeBuf(buf);
	}

	if (IsChecked(hWnd, R_SHA1_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *buf;

		GetTxtA(hWnd, E_SHA1_HASH, tmp, sizeof(tmp));
		buf = StrToBin(tmp);

		if (buf->Size != SHA1_SIZE)
		{
			b = false;
		}

		FreeBuf(buf);
	}

	SetEnable(hWnd, IDOK, b);
}

// OK ボタンクリック
void SmEditCrlDlgOnOk(HWND hWnd, SM_EDIT_CRL *c)
{
	CRL *crl;
	NAME *n;
	RPC_CRL t;
	bool empty = true;
	// 引数チェック
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	crl = ZeroMalloc(sizeof(CRL));
	crl->Name = ZeroMalloc(sizeof(NAME));
	n = crl->Name;

	if (IsChecked(hWnd, R_CN))
	{
		n->CommonName = GetText(hWnd, E_CN);
		empty = false;
	}

	if (IsChecked(hWnd, R_O))
	{
		n->Organization = GetText(hWnd, E_O);
		empty = false;
	}

	if (IsChecked(hWnd, R_OU))
	{
		n->Unit = GetText(hWnd, E_OU);
		empty = false;
	}

	if (IsChecked(hWnd, R_C))
	{
		n->Country = GetText(hWnd, E_C);
		empty = false;
	}

	if (IsChecked(hWnd, R_ST))
	{
		n->State = GetText(hWnd, E_ST);
		empty = false;
	}

	if (IsChecked(hWnd, R_L))
	{
		n->Local = GetText(hWnd, E_L);
		empty = false;
	}

	if (IsChecked(hWnd, R_SERI))
	{
		char tmp[MAX_SIZE];
		BUF *b;

		GetTxtA(hWnd, E_SERI, tmp, sizeof(tmp));
		b = StrToBin(tmp);

		if (b != NULL && b->Size >= 1)
		{
			crl->Serial = NewXSerial(b->Buf, b->Size);
		}

		FreeBuf(b);

		empty = false;
	}

	if (IsChecked(hWnd, R_MD5_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *b;

		GetTxtA(hWnd, E_MD5_HASH, tmp, sizeof(tmp));
		b = StrToBin(tmp);

		if (b != NULL && b->Size == MD5_SIZE)
		{
			Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
		}

		FreeBuf(b);

		empty = false;
	}

	if (IsChecked(hWnd, R_SHA1_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *b;

		GetTxtA(hWnd, E_SHA1_HASH, tmp, sizeof(tmp));
		b = StrToBin(tmp);

		if (b != NULL && b->Size == SHA1_SIZE)
		{
			Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
		}

		FreeBuf(b);

		empty = false;
	}

	if (empty)
	{
		if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_CRL_EMPTY_MSG")) == IDNO)
		{
			return;
		}
	}

	if (c->NewCrl)
	{
		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), c->s->HubName);
		t.Crl = crl;

		if (CALL(hWnd, ScAddCrl(c->s->Rpc, &t)))
		{
			EndDialog(hWnd, true);
		}

		FreeRpcCrl(&t);
	}
	else
	{
		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), c->s->HubName);
		t.Crl = crl;
		t.Key = c->Key;

		if (CALL(hWnd, ScSetCrl(c->s->Rpc, &t)))
		{
			EndDialog(hWnd, true);
		}

		FreeRpcCrl(&t);
	}
}

// 証明書の読み込み
void SmEditCrlDlgOnLoad(HWND hWnd, SM_EDIT_CRL *c)
{
	X *x;
	// 引数チェック
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	if (CmLoadXFromFileOrSecureCard(hWnd, &x))
	{
		UCHAR md5[MD5_SIZE], sha1[SHA1_SIZE];

		SmEditCrlDlgSetName(hWnd, x->subject_name);
		SmEditCrlDlgSetSerial(hWnd, x->serial);
		GetXDigest(x, md5, false);
		GetXDigest(x, sha1, true);
		SmEditCrlDlgSetHash(hWnd, md5, sha1);

		FreeX(x);

		SmEditCrlDlgUpdate(hWnd, c);
	}
}

// ダイアログにハッシュ情報を設定する
void SmEditCrlDlgSetHash(HWND hWnd, UCHAR *hash_md5, UCHAR *hash_sha1)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (hash_md5 != NULL && IsZero(hash_md5, MD5_SIZE) == false)
	{
		Check(hWnd, R_MD5_HASH, true);
		BinToStrEx(tmp, sizeof(tmp), hash_md5, MD5_SIZE);
		SetTextA(hWnd, E_MD5_HASH, tmp);
	}
	else
	{
		Check(hWnd, R_MD5_HASH, false);
	}

	if (hash_sha1 != NULL && IsZero(hash_sha1, SHA1_SIZE) == false)
	{
		Check(hWnd, R_SHA1_HASH, true);
		BinToStrEx(tmp, sizeof(tmp), hash_sha1, SHA1_SIZE);
		SetTextA(hWnd, E_SHA1_HASH, tmp);
	}
	else
	{
		Check(hWnd, R_SHA1_HASH, false);
	}
}

// ダイアログにシリアル番号を設定する
void SmEditCrlDlgSetSerial(HWND hWnd, X_SERIAL *serial)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || serial == NULL)
	{
		return;
	}

	BinToStrEx(tmp, sizeof(tmp), serial->data, serial->size);

	Check(hWnd, R_SERI, true);

	SetTextA(hWnd, E_SERI, tmp);
}

// ダイアログに名前状況を設定する
void SmEditCrlDlgSetName(HWND hWnd, NAME *name)
{
	// 引数チェック
	if (hWnd == NULL || name == NULL)
	{
		return;
	}

	// CN
	if (UniIsEmptyStr(name->CommonName))
	{
		Check(hWnd, R_CN, false);
	}
	else
	{
		Check(hWnd, R_CN, true);
		SetText(hWnd, E_CN, name->CommonName);
	}

	// O
	if (UniIsEmptyStr(name->Organization))
	{
		Check(hWnd, R_O, false);
	}
	else
	{
		Check(hWnd, R_O, true);
		SetText(hWnd, E_O, name->Organization);
	}

	// OU
	if (UniIsEmptyStr(name->Unit))
	{
		Check(hWnd, R_OU, false);
	}
	else
	{
		Check(hWnd, R_OU, true);
		SetText(hWnd, E_OU, name->Unit);
	}

	// C
	if (UniIsEmptyStr(name->Country))
	{
		Check(hWnd, R_C, false);
	}
	else
	{
		Check(hWnd, R_C, true);
		SetText(hWnd, E_C, name->Country);
	}

	// ST
	if (UniIsEmptyStr(name->State))
	{
		Check(hWnd, R_ST, false);
	}
	else
	{
		Check(hWnd, R_ST, true);
		SetText(hWnd, E_ST, name->State);
	}

	// L
	if (UniIsEmptyStr(name->Local))
	{
		Check(hWnd, R_L, false);
	}
	else
	{
		Check(hWnd, R_L, true);
		SetText(hWnd, E_L, name->Local);
	}
}

// CRL 編集ダイアログプロシージャ
UINT SmEditCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_CRL *c = (SM_EDIT_CRL *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEditCrlDlgInit(hWnd, c);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_CN:
		case E_CN:
		case R_O:
		case E_O:
		case R_OU:
		case E_OU:
		case R_C:
		case E_C:
		case R_ST:
		case E_ST:
		case R_L:
		case E_L:
		case R_SERI:
		case E_SERI:
		case R_MD5_HASH:
		case E_MD5_HASH:
		case R_SHA1_HASH:
		case E_SHA1_HASH:
			SmEditCrlDlgUpdate(hWnd, c);
			break;
		}

		switch (wParam)
		{
		case B_LOAD:
			SmEditCrlDlgOnLoad(hWnd, c);
			break;

		case IDOK:
			SmEditCrlDlgOnOk(hWnd, c);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_CN:
			FocusEx(hWnd, E_CN);
			break;

		case R_O:
			FocusEx(hWnd, E_O);
			break;

		case R_OU:
			FocusEx(hWnd, E_OU);
			break;

		case R_C:
			FocusEx(hWnd, E_C);
			break;

		case R_ST:
			FocusEx(hWnd, E_ST);
			break;

		case R_L:
			FocusEx(hWnd, E_L);
			break;

		case R_SERI:
			FocusEx(hWnd, E_SERI);
			break;

		case R_MD5_HASH:
			FocusEx(hWnd, E_MD5_HASH);
			break;

		case R_SHA1_HASH:
			FocusEx(hWnd, E_SHA1_HASH);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// ダイアログ初期化
void SmCrlDlgInit(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_CERT_X);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_CRL_COLUMN_1"), 555);

	SmCrlDlgRefresh(hWnd, s);
}

// コントロール更新
void SmCrlDlgUpdate(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsSingleSelected(hWnd, L_LIST));
	SetEnable(hWnd, B_DELETE, LvIsSingleSelected(hWnd, L_LIST));
}

// 内容更新
void SmCrlDlgRefresh(HWND hWnd, SM_HUB *s)
{
	UINT i;
	RPC_ENUM_CRL t;
	LVB *v;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScEnumCrl(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t.Items[i];
		LvInsertAdd(v, ICO_CERT_X, (void *)e->Key, 1, e->CrlInfo);
	}

	LvInsertEndEx(v, hWnd, L_LIST, true);

	if (t.NumItem >= 1)
	{
		LvAutoSize(hWnd, L_LIST);
	}

	FreeRpcEnumCrl(&t);

	SmCrlDlgUpdate(hWnd, s);
}

// 無効な証明書一覧ダイアログプロシージャ
UINT SmCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_CRL c;
	SM_HUB *s = (SM_HUB *)param;
	NMHDR *n;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmCrlDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			Zero(&c, sizeof(c));
			c.NewCrl = true;
			c.s = s;

			if (Dialog(hWnd, D_SM_EDIT_CRL, SmEditCrlDlgProc, &c))
			{
				SmCrlDlgRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			if (IsEnable(hWnd, B_DELETE))
			{
				if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_CRL_DELETE_MSG")) == IDYES)
				{
					RPC_CRL t;

					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
					t.Key = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

					if (CALL(hWnd, ScDelCrl(s->Rpc, &t)))
					{
						SmCrlDlgRefresh(hWnd, s);
					}

					FreeRpcCrl(&t);
				}
			}
			break;

		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				SM_EDIT_CRL c;

				Zero(&c, sizeof(c));
				c.NewCrl = false;
				c.s = s;
				c.Key = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (Dialog(hWnd, D_SM_EDIT_CRL, SmEditCrlDlgProc, &c))
				{
					SmCrlDlgRefresh(hWnd, s);
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmCrlDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// スマートカードマネージャ
void SmSecureManager(HWND hWnd)
{
	UINT id = SmGetCurrentSecureIdFromReg();

	if (id == 0)
	{
		id = SmSelectSecureId(hWnd);
	}

	if (id == 0)
	{
		return;
	}

	CmSecureManager(hWnd, id);
}

// ダイアログ初期化
void SmSelectKeyPairDlgInit(HWND hWnd, SM_SECURE_KEYPAIR *k)
{
	SECURE_DEVICE *dev;
	// 引数チェック
	if (hWnd == NULL || k == NULL)
	{
		return;
	}

	dev = GetSecureDevice(k->Id);
	if (dev != NULL)
	{
		FormatText(hWnd, S_INFO, dev->DeviceName);
	}

	LvInit(hWnd, L_CERT);
	LvInsertColumn(hWnd, L_CERT, 0, _UU("SEC_MGR_COLUMN1"), 200);
	LvInsertColumn(hWnd, L_CERT, 1, _UU("SEC_MGR_COLUMN2"), 110);

	LvInit(hWnd, L_KEY);
	LvInsertColumn(hWnd, L_KEY, 0, _UU("SEC_MGR_COLUMN1"), 200);
	LvInsertColumn(hWnd, L_KEY, 1, _UU("SEC_MGR_COLUMN2"), 110);

	SetEnable(hWnd, L_CERT, k->UseCert);
	SetEnable(hWnd, B_BOLD1, k->UseCert);
	SetEnable(hWnd, L_KEY, k->UseKey);
	SetEnable(hWnd, B_BOLD2, k->UseKey);

	SetFont(hWnd, B_BOLD1, Font(0, true));
	SetFont(hWnd, B_BOLD2, Font(0, true));

	SmSelectKeyPairDlgUpdate(hWnd, k);
}

// ダイアログコントロール更新
void SmSelectKeyPairDlgUpdate(HWND hWnd, SM_SECURE_KEYPAIR *k)
{
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL || k == NULL)
	{
		return;
	}

	if (k->UseCert)
	{
		if (LvIsSingleSelected(hWnd, L_CERT) == false)
		{
			ok = false;
		}
		else
		{
			char *name = LvGetSelectedStrA(hWnd, L_CERT, 0);
			if (name != NULL)
			{
				if (LvIsSingleSelected(hWnd, L_KEY) == false)
				{
					if ((k->Flag++) == 0)
					{
						LvSelect(hWnd, L_KEY, LvSearchStrA(hWnd, L_KEY, 0, name));
					}
				}
				Free(name);
			}
		}
	}

	if (k->UseKey)
	{
		if (LvIsSingleSelected(hWnd, L_KEY) == false)
		{
			ok = false;
		}
		else
		{
			char *name = LvGetSelectedStrA(hWnd, L_KEY, 0);
			if (name != NULL)
			{
				if (LvIsSingleSelected(hWnd, L_CERT) == false)
				{
					if ((k->Flag++) == 0)
					{
						LvSelect(hWnd, L_CERT, LvSearchStrA(hWnd, L_CERT, 0, name));
					}
				}
				Free(name);
			}
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// コンテンツ更新
void SmSelectKeyPairDlgRefresh(HWND hWnd, SM_SECURE_KEYPAIR *k)
{
	bool ret;
	LIST *o;
	WINUI_SECURE_BATCH batch[] =
	{
		{WINUI_SECURE_ENUM_OBJECTS, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL},
	};
	// 引数チェック
	if (hWnd == NULL || k == NULL)
	{
		return;
	}

	ret = SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), k->Id, k->BitmapId);

	if (ret == false)
	{
		Close(hWnd);
		return;
	}

	o = batch[0].EnumList;
	if (o != NULL)
	{
		if (k->UseCert)
		{
			CmSecureManagerDlgPrintListEx(hWnd, L_CERT, o, SEC_X);
		}

		if (k->UseKey)
		{
			CmSecureManagerDlgPrintListEx(hWnd, L_KEY, o, SEC_K);
		}

		FreeEnumSecObject(o);
	}

	// コントロール更新
	SmSelectKeyPairDlgUpdate(hWnd, k);
}

// キーペア読み込みダイアログプロシージャ
UINT SmSelectKeyPairDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SECURE_KEYPAIR *k = (SM_SECURE_KEYPAIR *)param;
	char *s1, *s2;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmSelectKeyPairDlgInit(hWnd, k);

		SetTimer(hWnd, 1, 1, NULL);
		SetTimer(hWnd, 2, 100, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			SmSelectKeyPairDlgRefresh(hWnd, k);
			break;

		case 2:
			SmSelectKeyPairDlgUpdate(hWnd, k);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			s1 = LvGetSelectedStrA(hWnd, L_CERT, 0);
			s2 = LvGetSelectedStrA(hWnd, L_KEY, 0);
			if (k->UseCert)
			{
				StrCpy(k->CertName, sizeof(k->CertName), s1);
			}
			if (k->UseKey)
			{
				StrCpy(k->KeyName, sizeof(k->KeyName), s2);
			}
			Free(s1);
			Free(s2);
			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_CERT:
		case L_KEY:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmSelectKeyPairDlgUpdate(hWnd, k);
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// キーペアをスマートカードから読み込む
bool SmSelectKeyPair(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size)
{
	return SmSelectKeyPairEx(hWnd, cert_name, cert_name_size, key_name, key_name_size, 0);
}
bool SmSelectKeyPairEx(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size, UINT bitmap_id)
{
	SM_SECURE_KEYPAIR p;
	// 引数チェック
	if (hWnd == NULL || (cert_name == NULL && key_name == NULL))
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.Id = SmGetCurrentSecureId(hWnd);
	if (p.Id == 0)
	{
		return false;
	}

	p.UseCert = (cert_name == NULL) ? false : true;
	p.UseKey = (key_name == NULL) ? false : true;
	p.BitmapId = bitmap_id;

	if (Dialog(hWnd, D_SM_SELECT_KEYPAIR, SmSelectKeyPairDlg, &p) == false)
	{
		return false;
	}

	if (p.UseCert)
	{
		StrCpy(cert_name, cert_name_size, p.CertName);
	}
	if (p.UseKey)
	{
		StrCpy(key_name, key_name_size, p.KeyName);
	}

	return true;
}

// スマートカード番号をユーザーに選択させる
UINT SmSelectSecureId(HWND hWnd)
{
	UINT id = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId");
	UINT ret;

	if (id != 0 && CheckSecureDeviceId(id) == false)
	{
		id = 0;
	}

	ret = CmSelectSecure(hWnd, id);
	if (ret == 0)
	{
		return 0;
	}

	SmWriteSelectSecureIdReg(ret);

	return ret;
}

// 現在のスマートカード番号をレジストリに書き込む
void SmWriteSelectSecureIdReg(UINT id)
{
	MsRegWriteInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId", id);
}

// 現在のスマートカード番号を取得する
UINT SmGetCurrentSecureId(HWND hWnd)
{
	// 現在の設定をロード
	UINT id = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId");

	// 正常かどうかチェック
	if (id == 0 || CheckSecureDeviceId(id) == false)
	{
		// 不正な場合はスマートカードデバイス番号を選択させる
		id = SmSelectSecureId(hWnd);
	}

	return id;
}

// レジストリから現在のスマートカード番号を取得する
UINT SmGetCurrentSecureIdFromReg()
{
	// 現在の設定をロード
	UINT id = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId");

	// 正常かどうかチェック
	if (id == 0 || CheckSecureDeviceId(id) == false)
	{
		id = 0;
	}

	return id;
}

// 指定した名前の L3 スイッチが開始されているかどうか取得する
bool SmL3IsSwActive(SM_SERVER *s, char *name)
{
	bool ret = false;
	UINT i;
	RPC_ENUM_L3SW t;
	// 引数チェック
	if (s == NULL || name == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (ScEnumL3Switch(s->Rpc, &t) == ERR_NO_ERROR)
	{
		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_L3SW_ITEM *e = &t.Items[i];
			if (StrCmpi(e->Name, name) == 0)
			{
				if (e->Active)
				{
					ret = true;
					break;
				}
			}
		}
		FreeRpcEnumL3Sw(&t);
	}

	return ret;
}

// ダイアログ初期化
void SmL3SwTableDlgInit(HWND hWnd, SM_L3SW *w)
{
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	SmL3SwTableDlgUpdate(hWnd, w);
}

// コントロール更新
void SmL3SwTableDlgUpdate(HWND hWnd, SM_L3SW *w)
{
	bool b = true;
	UINT ip;
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	if (IpIsFilled(hWnd, E_NETWORK) == false ||
		IpIsFilled(hWnd, E_MASK) == false ||
		IpIsFilled(hWnd, E_GATEWAY) == false)
	{
		b = false;
	}

	ip = IpGet(hWnd, E_GATEWAY);
	if (ip == 0 || ip == 0xffffffff)
	{
		b = false;
	}

	if (GetInt(hWnd, E_METRIC) == 0)
	{
		b = false;
	}

	if (IsNetworkAddress32(IpGet(hWnd, E_NETWORK), IpGet(hWnd, E_MASK)) == false)
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);
}

UINT SmL3SwTableDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_L3SW *w = (SM_L3SW *)param;
	RPC_L3TABLE t;

	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3SwTableDlgInit(hWnd, w);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_NETWORK:
		case E_MASK:
		case E_GATEWAY:
		case E_METRIC:
			SmL3SwTableDlgUpdate(hWnd, w);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			Zero(&t, sizeof(t));
			StrCpy(t.Name, sizeof(t.Name), w->SwitchName);
			t.NetworkAddress = IpGet(hWnd, E_NETWORK);
			t.SubnetMask = IpGet(hWnd, E_MASK);
			t.GatewayAddress = IpGet(hWnd, E_GATEWAY);
			t.Metric = GetInt(hWnd, E_METRIC);

			if (CALL(hWnd, ScAddL3Table(w->s->Rpc, &t)))
			{
				EndDialog(hWnd, 1);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// ダイアログ初期化
void SmL3SwIfDlgInit(HWND hWnd, SM_L3SW *w)
{
	RPC_ENUM_HUB t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	if (CALL(hWnd, ScEnumHub(w->s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	CbReset(hWnd, E_HUBNAME);
	CbSetHeight(hWnd, E_HUBNAME, 18);

	for (i = 0;i < t.NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];

		if (e->HubType != HUB_TYPE_FARM_DYNAMIC)
		{
			CbAddStrA(hWnd, E_HUBNAME, e->HubName, 0);
		}
	}

	FreeRpcEnumHub(&t);

	SetTextA(hWnd, E_HUBNAME, "");

	SmL3SwIfDlgUpdate(hWnd, w);
}

// コントロール更新
void SmL3SwIfDlgUpdate(HWND hWnd, SM_L3SW *w)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	if (IsEmpty(hWnd, E_HUBNAME))
	{
		b = false;
	}

	if (IpIsFilled(hWnd, E_IP) == false || IpIsFilled(hWnd, E_MASK) == false)
	{
		b = false;
	}

	if (IpGet(hWnd, E_IP) == 0 || IpGet(hWnd, E_IP) == 0xffffffff)
	{
		b = false;
	}

	if (IsSubnetMask32(IpGet(hWnd, E_MASK)) == false)
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);
}

// 仮想インターフェイスの追加ダイアログ
UINT SmL3SwIfDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_L3SW *w = (SM_L3SW *)param;
	char *hubname;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3SwIfDlgInit(hWnd, w);

		SetTimer(hWnd, 1, 250, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			SmL3SwIfDlgUpdate(hWnd, w);
			break;
		}
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_HUBNAME:
		case E_IP:
		case E_MASK:
			SmL3SwIfDlgUpdate(hWnd, w);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			hubname = GetTextA(hWnd, E_HUBNAME);
			if (hubname != NULL)
			{
				RPC_L3IF t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), hubname);
				t.IpAddress = IpGet(hWnd, E_IP);
				t.SubnetMask = IpGet(hWnd, E_MASK);
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

				if (CALL(hWnd, ScAddL3If(w->s->Rpc, &t)))
				{
					EndDialog(hWnd, 1);
				}

				Free(hubname);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// 初期化
void SmL3SwDlgInit(HWND hWnd, SM_L3SW *w)
{
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SWITCH_OFFLINE);

	FormatText(hWnd, 0, w->SwitchName);

	SetFont(hWnd, S_BOLD1, Font(0, true));
	SetFont(hWnd, S_BOLD2, Font(0, true));

	LvInit(hWnd, L_IF);
	LvInsertColumn(hWnd, L_IF, 0, _UU("SM_L3_SW_IF_COLUMN1"), 150);
	LvInsertColumn(hWnd, L_IF, 1, _UU("SM_L3_SW_IF_COLUMN2"), 150);
	LvInsertColumn(hWnd, L_IF, 2, _UU("SM_L3_SW_IF_COLUMN3"), 180);

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, 0, _UU("SM_L3_SW_TABLE_COLUMN1"), 130);
	LvInsertColumn(hWnd, L_TABLE, 1, _UU("SM_L3_SW_TABLE_COLUMN2"), 130);
	LvInsertColumn(hWnd, L_TABLE, 2, _UU("SM_L3_SW_TABLE_COLUMN3"), 130);
	LvInsertColumn(hWnd, L_TABLE, 3, _UU("SM_L3_SW_TABLE_COLUMN4"), 100);

	w->Enable = SmL3IsSwActive(w->s, w->SwitchName) ? false : true;

	SmL3SwDlgRefresh(hWnd, w);
}

// コントロール更新
void SmL3SwDlgUpdate(HWND hWnd, SM_L3SW *w)
{
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	SetEnable(hWnd, B_ADD_IF, w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_ADD_TABLE, w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_DEL_IF, LvIsSingleSelected(hWnd, L_IF) && w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_DEL_TABLE, LvIsSingleSelected(hWnd, L_TABLE) && w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_START, w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_STOP, w->s->ServerAdminMode && (w->Enable == false));
}

// 内容更新
void SmL3SwDlgRefresh(HWND hWnd, SM_L3SW *w)
{
	UINT i;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t tmp3[MAX_SIZE];
	wchar_t tmp4[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	// 仮想インターフェイス一覧
	{
		RPC_ENUM_L3IF t;
		LVB *v;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

		if (CALL(hWnd, ScEnumL3If(w->s->Rpc, &t)) == false)
		{
			Close(hWnd);
			return;
		}

		v = LvInsertStart();

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3IF *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->IpAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			StrToUni(tmp3, sizeof(tmp3), e->HubName);

			LvInsertAdd(v, ICO_NIC_ONLINE, NULL, 3, tmp1, tmp2, tmp3);
		}

		LvReset(hWnd, L_IF);

		LvInsertEnd(v, hWnd, L_IF);

		FreeRpcEnumL3If(&t);
	}

	// ルーティングテーブル一覧
	{
		RPC_ENUM_L3TABLE t;
		LVB *v;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

		if (CALL(hWnd, ScEnumL3Table(w->s->Rpc, &t)) == false)
		{
			Close(hWnd);
			return;
		}

		v = LvInsertStart();

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3TABLE *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->NetworkAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			IPToUniStr32(tmp3, sizeof(tmp3), e->GatewayAddress);
			UniToStru(tmp4, e->Metric);

			LvInsertAdd(v, ICO_PROTOCOL, NULL, 4, tmp1, tmp2, tmp3, tmp4);
		}

		LvReset(hWnd, L_TABLE);

		LvInsertEnd(v, hWnd, L_TABLE);

		FreeRpcEnumL3Table(&t);
	}

	SmL3SwDlgUpdate(hWnd, w);
}

// L3 スイッチの編集ダイアログ
UINT SmL3SwDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_L3SW *w = (SM_L3SW *)param;
	NMHDR *n;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3SwDlgInit(hWnd, w);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			w->Enable = SmL3IsSwActive(w->s, w->SwitchName) ? false : true;
			SmL3SwDlgUpdate(hWnd, w);
			SetTimer(hWnd, 1, 1000, NULL);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_START:
			if (IsEnable(hWnd, B_START))
			{
				RPC_L3SW t;

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

				if (CALL(hWnd, ScStartL3Switch(w->s->Rpc, &t)))
				{
					SmL3SwDlgUpdate(hWnd, w);
				}
			}
			break;

		case B_STOP:
			if (IsEnable(hWnd, B_STOP))
			{
				RPC_L3SW t;

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

				if (CALL(hWnd, ScStopL3Switch(w->s->Rpc, &t)))
				{
					SmL3SwDlgUpdate(hWnd, w);
				}
			}
			break;

		case B_ADD_IF:
			if (Dialog(hWnd, D_SM_L3_SW_IF, SmL3SwIfDlg, w))
			{
				SmL3SwDlgRefresh(hWnd, w);
			}
			break;

		case B_DEL_IF:
			if (LvIsSingleSelected(hWnd, L_IF))
			{
				RPC_L3IF t;
				char *tmp1, *tmp2, *tmp3;

				tmp1 = LvGetSelectedStrA(hWnd, L_IF, 0);
				tmp2 = LvGetSelectedStrA(hWnd, L_IF, 1);
				tmp3 = LvGetSelectedStrA(hWnd, L_IF, 2);

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);
				t.IpAddress = StrToIP32(tmp1);
				t.SubnetMask = StrToIP32(tmp2);
				StrCpy(t.HubName, sizeof(t.HubName), tmp3);

				if (CALL(hWnd, ScDelL3If(w->s->Rpc, &t)))
				{
					SmL3SwDlgRefresh(hWnd, w);
				}

				Free(tmp1);
				Free(tmp2);
				Free(tmp3);
			}
			break;

		case B_ADD_TABLE:
			if (Dialog(hWnd, D_SM_L3_SW_TABLE, SmL3SwTableDlg, w))
			{
				SmL3SwDlgRefresh(hWnd, w);
			}
			break;

		case B_DEL_TABLE:
			if (LvIsSingleSelected(hWnd, L_TABLE))
			{
				RPC_L3TABLE t;
				char *tmp1, *tmp2, *tmp3, *tmp4;

				tmp1 = LvGetSelectedStrA(hWnd, L_TABLE, 0);
				tmp2 = LvGetSelectedStrA(hWnd, L_TABLE, 1);
				tmp3 = LvGetSelectedStrA(hWnd, L_TABLE, 2);
				tmp4 = LvGetSelectedStrA(hWnd, L_TABLE, 3);

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);
				t.NetworkAddress = StrToIP32(tmp1);
				t.SubnetMask = StrToIP32(tmp2);
				t.GatewayAddress = StrToIP32(tmp3);
				t.Metric = ToInt(tmp4);

				if (CALL(hWnd, ScDelL3Table(w->s->Rpc, &t)))
				{
					SmL3SwDlgRefresh(hWnd, w);
				}

				Free(tmp1);
				Free(tmp2);
				Free(tmp3);
				Free(tmp4);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_IF:
		case L_TABLE:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmL3SwDlgUpdate(hWnd, w);
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// コントロール更新
void SmL3AddDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	char *tmp;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	tmp = GetTextA(hWnd, E_NAME);

	SetEnable(hWnd, IDOK, IsEmptyStr(tmp) == false && IsSafeStr(tmp));

	Free(tmp);
}

// 新しい L3 スイッチの作成ダイアログ
UINT SmL3AddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	RPC_L3SW t;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		LimitText(hWnd, E_NAME, MAX_HUBNAME_LEN);
		SmL3AddDlgUpdate(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_NAME:
			SmL3AddDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			Zero(&t, sizeof(t));
			GetTxtA(hWnd, E_NAME, t.Name, sizeof(t.Name));
			if (CALL(hWnd, ScAddL3Switch(s->Rpc, &t)))
			{
				EndDialog(hWnd, 1);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// ダイアログ初期化
void SmL3DlgInit(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetFont(hWnd, S_BOLD, Font(0, true));

	SetIcon(hWnd, 0, ICO_SWITCH);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_L3_SW_COLUMN1"), 150);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_L3_SW_COLUMN2"), 120);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_L3_SW_COLUMN3"), 100);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_L3_SW_COLUMN4"), 100);

	SmL3DlgRefresh(hWnd, s);
}

// ダイアログコントロール更新
void SmL3DlgUpdate(HWND hWnd, SM_SERVER *s)
{
	bool b = false;
	bool active = false;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSingleSelected(hWnd, L_LIST))
	{
		wchar_t *tmp;
		UINT i;
		b = true;
		i = LvGetSelected(hWnd, L_LIST);
		if (i != INFINITE)
		{
			tmp = LvGetStr(hWnd, L_LIST, i, 1);
			if (UniStrCmpi(tmp, _UU("SM_L3_SW_ST_F_F")) != 0)
			{
				active = true;
			}
			Free(tmp);
		}
	}

	SetEnable(hWnd, B_START, b && (active == false));
	SetEnable(hWnd, B_STOP, b && (active != false));
	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, B_DELETE, b);
}

// ダイアログ内容更新
void SmL3DlgRefresh(HWND hWnd, SM_SERVER *s)
{
	RPC_ENUM_L3SW t;
	UINT i;
	LVB *v;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumL3Switch(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *e = &t.Items[i];
		wchar_t tmp1[MAX_SIZE], *tmp2, tmp3[64], tmp4[64];

		StrToUni(tmp1, sizeof(tmp1), e->Name);
		if (e->Active == false)
		{
			tmp2 = _UU("SM_L3_SW_ST_F_F");
		}
		else if (e->Online == false)
		{
			tmp2 = _UU("SM_L3_SW_ST_T_F");
		}
		else
		{
			tmp2 = _UU("SM_L3_SW_ST_T_T");
		}
		UniToStru(tmp3, e->NumInterfaces);
		UniToStru(tmp4, e->NumTables);

		LvInsertAdd(v, e->Active ? ICO_SWITCH : ICO_SWITCH_OFFLINE, NULL,
			4, tmp1, tmp2, tmp3, tmp4);
	}

	LvInsertEnd(v, hWnd, L_LIST);

	FreeRpcEnumL3Sw(&t);

	SmL3DlgUpdate(hWnd, s);
}

// L3 ダイアログプロシージャ
UINT SmL3Dlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SERVER *s = (SM_SERVER *)param;
	RPC_L3SW t;
	char *name;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3DlgInit(hWnd, s);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		KillTimer(hWnd, 1);
		SmL3DlgRefresh(hWnd, s);
		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			// 追加
			if (Dialog(hWnd, D_SM_L3_ADD, SmL3AddDlg, s))
			{
				SmL3DlgRefresh(hWnd, s);
			}
			break;

		case B_START:
			// 動作開始
			name = LvGetSelectedStrA(hWnd, L_LIST, 0);
			if (name != NULL)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), name);

				if (CALL(hWnd, ScStartL3Switch(s->Rpc, &t)))
				{
					SmL3DlgRefresh(hWnd, s);
				}

				Free(name);
			}
			break;

		case B_STOP:
			// 動作停止
			name = LvGetSelectedStrA(hWnd, L_LIST, 0);
			if (name != NULL)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), name);

				if (CALL(hWnd, ScStopL3Switch(s->Rpc, &t)))
				{
					SmL3DlgRefresh(hWnd, s);
				}

				Free(name);
			}
			break;

		case IDOK:
			// 編集
			if (IsEnable(hWnd, IDOK))
			{
				name = LvGetSelectedStrA(hWnd, L_LIST, 0);
				if (name != NULL)
				{
					SM_L3SW w;
					Zero(&w, sizeof(w));
					w.s = s;
					w.SwitchName = name;

					Dialog(hWnd, D_SM_L3_SW, SmL3SwDlg, &w);

					Free(name);
				}
			}
			break;

		case B_DELETE:
			// 削除
			name = LvGetSelectedStrA(hWnd, L_LIST, 0);
			if (name != NULL)
			{
				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_L3_SW_DEL_MSG"), name) == IDYES)
				{
					Zero(&t, sizeof(t));
					StrCpy(t.Name, sizeof(t.Name), name);

					if (CALL(hWnd, ScDelL3Switch(s->Rpc, &t)))
					{
						SmL3DlgRefresh(hWnd, s);
					}
				}

				Free(name);
			}
			break;

		case IDCANCEL:
			// 閉じる
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmL3DlgUpdate(hWnd, s);
				break;

			case NM_DBLCLK:
				Command(hWnd, IDOK);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// L3 ダイアログ
void SmL3(HWND hWnd, SM_SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_L3, SmL3Dlg, s);
}

// 管理オプション値用ダイアログ
UINT SmHubAdminOptionValueDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_AO *a = (SM_EDIT_AO *)param;
	UINT i;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CbReset(hWnd, C_NAME);
		for (i = 0;i < a->DefaultOptions.NumItem;i++)
		{
			wchar_t tmp[MAX_PATH];
			StrToUni(tmp, sizeof(tmp), a->DefaultOptions.Items[i].Name);
			CbAddStr(hWnd, C_NAME, tmp, 0);
		}
		if (a->NewMode == false)
		{
			char tmp[MAX_SIZE];

			SetTextA(hWnd, C_NAME, a->Name);
			ToStr(tmp, a->Value);

			SetTextA(hWnd, E_VALUE, tmp);
		}
		else
		{
			SetTextA(hWnd, C_NAME, "");
		}
		SmHubAdminOptionValueDlgUpdate(hWnd, a);
		if (a->NewMode == false)
		{
			FocusEx(hWnd, E_VALUE);
			Disable(hWnd, C_NAME);
		}
		else
		{
			FocusEx(hWnd, C_NAME);
		}

		SetTimer(hWnd, 1, 100, NULL);
		break;

	case WM_TIMER:
		SmHubAdminOptionValueDlgUpdate(hWnd, a);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (a->NewMode)
			{
				GetTxtA(hWnd, C_NAME, a->Name, sizeof(a->Name));
			}

			GetTxtA(hWnd, E_VALUE, tmp, sizeof(tmp));
			a->Value = ToInt(tmp);

			Trim(a->Name);

			if (StartWith(a->Name, "no") || StartWith(a->Name, "allow") || StartWith(a->Name, "deny")
				 || StartWith(a->Name, "filter") || StartWith(a->Name, "fix") || StartWith(a->Name, "force")
				 || StartWith(a->Name, "use") || StartWith(a->Name, "b_") || StartWith(a->Name, "is")
				 || StartWith(a->Name, "manage") || StartWith(a->Name, "yield")
				 || StartWith(a->Name, "permit") || StartWith(a->Name, "yes") || StartWith(a->Name, "ok")
				 || StartWith(a->Name, "do") || StartWith(a->Name, "only") || StartWith(a->Name, "disable"))
			{
				if (StrCmpi(tmp, "0") != 0 && StrCmpi(tmp, "1") != 0)
				{
					MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SM_TRUE_OR_FALSE"));
					FocusEx(hWnd, E_VALUE);
					break;
				}
			}

			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}

		SmHubAdminOptionValueDlgUpdate(hWnd, a);

		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 管理オプション値用ダイアログ コントロール更新
void SmHubAdminOptionValueDlgUpdate(HWND hWnd, SM_EDIT_AO *a)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	GetTxtA(hWnd, C_NAME, tmp, sizeof(tmp));

	SetEnable(hWnd, IDOK, IsEmpty(hWnd, C_NAME) == false && IsEmpty(hWnd, E_VALUE) == false &&
		IsSafeStr(tmp));
}

// 初期化
void SmHubAdminOptionDlgInit(HWND hWnd, SM_EDIT_AO *a)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_USER_ADMIN);

	if (a->e->p->ServerAdminMode)
	{
		a->CanChange = true;
	}
	else
	{
		if (a->ExtOption == false)
		{
			for (i = 0;i < a->CurrentOptions.NumItem;i++)
			{
				if (StrCmpi(a->CurrentOptions.Items[i].Name, "allow_hub_admin_change_option") == 0)
				{
					if (a->CurrentOptions.Items[i].Value != 0)
					{
						a->CanChange = true;
					}
				}
			}
		}
		else
		{
			a->CanChange = true;
		}
	}

	FormatText(hWnd, S_INFO, a->e->HubName);

	DlgFont(hWnd, S_BOLD, 0, true);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_AO_COLUMN_1"), 260);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_AO_COLUMN_2"), 100);

	for (i = 0;i < a->CurrentOptions.NumItem;i++)
	{
		ADMIN_OPTION *e = &a->CurrentOptions.Items[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];

		StrToUni(tmp1, sizeof(tmp1), e->Name);
		UniToStru(tmp2, e->Value);

		LvInsert(hWnd, L_LIST, ICO_LOG, NULL, 2, tmp1, tmp2);
			
	}

	if (a->ExtOption)
	{
		SetIcon(hWnd, S_ICON, ICO_LINK2);
		SetIcon(hWnd, 0, ICO_LINK2);

		SetText(hWnd, 0, _UU("SM_HUBEXT_OPTION_TITLE"));
		SetText(hWnd, S_STATIC1, _UU("SM_HUBEXT_OPTION_STATIC1"));
		SetText(hWnd, S_STATIC2, _UU("SM_HUBEXT_OPTION_STATIC2"));
	}

	// コントロール更新
	SmHubAdminOptionDlgUpdate(hWnd, a);
}

// コントロール更新
void SmHubAdminOptionDlgUpdate(HWND hWnd, SM_EDIT_AO *a)
{
	bool b = false;
	wchar_t *helpstr;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	helpstr = _UU("HUB_AO_CLICK");

	SetEnable(hWnd, IDOK, a->CanChange);
	SetEnable(hWnd, B_ADD, a->CanChange);
	SetEnable(hWnd, B_EDIT, a->CanChange && (LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false));

	if (LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false)
	{
		UINT i;
		i = LvGetSelected(hWnd, L_LIST);

		if (a->CanChange)
		{

			b = true;

			if (i != INFINITE)
			{
				char *name = LvGetStrA(hWnd, L_LIST, i, 0);
				if (name != NULL)
				{
					UINT j;

					for (j = 0;j < a->DefaultOptions.NumItem;j++)
					{
						if (StrCmpi(a->DefaultOptions.Items[j].Name, name) == 0)
						{
							b = false;
						}
					}
					Free(name);
				}
			}
		}

		if (i != INFINITE)
		{
			char *name = LvGetStrA(hWnd, L_LIST, i, 0);
			if (name != NULL)
			{
				helpstr = GetHubAdminOptionHelpString(name);
			}
			Free(name);
		}
	}
	SetEnable(hWnd, B_DELETE, b);

	SetText(hWnd, E_HELP, helpstr);
}

// 保存
void SmHubAdminOptionDlgOk(HWND hWnd, SM_EDIT_AO *a)
{
	UINT i, num;
	RPC_ADMIN_OPTION t;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	num = LvNum(hWnd, L_LIST);

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), a->e->HubName);
	t.NumItem = num;
	t.Items = ZeroMalloc(sizeof(ADMIN_OPTION) * num);

	for (i = 0;i < num;i++)
	{
		char *name = LvGetStrA(hWnd, L_LIST, i, 0);
		char *s_value = LvGetStrA(hWnd, L_LIST, i, 1);
		ADMIN_OPTION *a = &t.Items[i];

		StrCpy(a->Name, sizeof(a->Name), name);
		a->Value = ToInt(s_value);

		Free(name);
		Free(s_value);
	}

	if (a->ExtOption == false)
	{
		if (CALL(hWnd, ScSetHubAdminOptions(a->e->p->Rpc, &t)))
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_AO_SET_OK"));
			EndDialog(hWnd, true);
		}
	}
	else
	{
		if (CALL(hWnd, ScSetHubExtOptions(a->e->p->Rpc, &t)))
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_EXT_OPTION_SET_OK"));
			EndDialog(hWnd, true);
		}
	}

	FreeRpcAdminOption(&t);
}

// 仮想 HUB 管理オプションダイアログ
UINT SmHubAdminOptionDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_AO *a = (SM_EDIT_AO *)param;
	NMHDR *n;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmHubAdminOptionDlgInit(hWnd, a);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			a->NewMode = true;
			StrCpy(a->Name, sizeof(a->Name), "");
			a->Value = 0;
			if (Dialog(hWnd, D_SM_AO_VALUE, SmHubAdminOptionValueDlg,
				a))
			{
				wchar_t tmp1[MAX_SIZE];
				wchar_t tmp2[MAX_SIZE];
				StrToUni(tmp1, sizeof(tmp1), a->Name);
				UniToStru(tmp2, a->Value);

				LvInsert(hWnd, L_LIST, ICO_LOG, NULL, 2, tmp1, tmp2);
			}
			break;

		case B_EDIT:
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE && a->CanChange)
			{
				char *name, *value;
				name = LvGetStrA(hWnd, L_LIST, i, 0);
				value = LvGetStrA(hWnd, L_LIST, i, 1);
				a->NewMode = false;
				StrCpy(a->Name, sizeof(a->Name), name);
				a->Value = ToInt(value);

				if (Dialog(hWnd, D_SM_AO_VALUE, SmHubAdminOptionValueDlg,
					a))
				{
					char tmp[MAX_PATH];
					ToStr(tmp, a->Value);
					LvSetItemA(hWnd, L_LIST, i, 1, tmp);
				}

				Free(name);
				Free(value);
			}
			break;

		case B_DELETE:
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE)
			{
				LvDeleteItem(hWnd, L_LIST, i);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case IDOK:
			SmHubAdminOptionDlgOk(hWnd, a);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmHubAdminOptionDlgUpdate(hWnd, a);
				break;

			case NM_DBLCLK:
				Command(hWnd, B_EDIT);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// 仮想 HUB 拡張オプション
void SmHubExtOption(HWND hWnd, SM_EDIT_HUB *e)
{
	SM_EDIT_AO a;
	// 引数チェック
	if (hWnd == NULL || e == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.e = e;
	a.ExtOption = true;

	StrCpy(a.CurrentOptions.HubName, sizeof(a.CurrentOptions.HubName), e->HubName);

	// 現在のサーバー上のオプションを取得する
	if (CALL(hWnd, ScGetHubExtOptions(e->p->Rpc, &a.CurrentOptions)) == false)
	{
		return;
	}

	Dialog(hWnd, D_SM_ADMIN_OPTION, SmHubAdminOptionDlg, &a);

	FreeRpcAdminOption(&a.CurrentOptions);
	FreeRpcAdminOption(&a.DefaultOptions);
}

// 仮想 HUB 管理オプション
void SmHubAdminOption(HWND hWnd, SM_EDIT_HUB *e)
{
	SM_EDIT_AO a;
	// 引数チェック
	if (hWnd == NULL || e == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.e = e;

	StrCpy(a.CurrentOptions.HubName, sizeof(a.CurrentOptions.HubName), e->HubName);

	// 現在のサーバー上のオプションを取得する
	if (CALL(hWnd, ScGetHubAdminOptions(e->p->Rpc, &a.CurrentOptions)) == false)
	{
		return;
	}

	ScGetDefaultHubAdminOptions(e->p->Rpc, &a.DefaultOptions);

	Dialog(hWnd, D_SM_ADMIN_OPTION, SmHubAdminOptionDlg, &a);

	FreeRpcAdminOption(&a.CurrentOptions);
	FreeRpcAdminOption(&a.DefaultOptions);
}

// 初期化
void SmConfigDlgInit(HWND hWnd, SM_CONFIG *c)
{
	wchar_t *tmp;
	UINT tmp_size;
	// 引数チェック
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	Focus(hWnd, IDCANCEL);

	SetIcon(hWnd, 0, ICO_MACHINE);

	SetFont(hWnd, E_CONFIG, GetFont(_SS("DEFAULT_FONT_2"), 0, false, false,
		false, false));

	FormatText(hWnd, IDC_INFO, c->s->ServerName);

	// UTF-8 から Unicode に変換
	tmp_size = CalcUtf8ToUni(c->Config.FileData, StrLen(c->Config.FileData)) + 1;
	tmp = ZeroMalloc(tmp_size);
	Utf8ToUni(tmp, tmp_size, c->Config.FileData, StrLen(c->Config.FileData));

	SetText(hWnd, E_CONFIG, tmp);

	Free(tmp);
}

// config 編集ダイアログ
UINT SmConfigDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_CONFIG *c = (SM_CONFIG *)param;
	char *filename;
	wchar_t *filename_unicode;
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmConfigDlgInit(hWnd, c);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_EXPORT:
			StrToUni(tmp, sizeof(tmp), c->Config.FileName);
			filename_unicode = SaveDlg(hWnd, _UU("DLG_CONFIG_FILES"), _UU("DLG_SAVE_CONFIG"), tmp, L".config");
			if (filename_unicode != NULL)
			{
				BUF *b = NewBuf();
				filename = CopyUniToStr(filename_unicode);
				WriteBuf(b, c->Config.FileData, StrLen(c->Config.FileData));
				if (DumpBuf(b, filename))
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_CONFIG_SAVED"));
				}
				else
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("SM_CONFIG_SAVE_FAILED"));
				}
				FreeBuf(b);
				Free(filename);
				Free(filename_unicode);
			}
			break;

		case B_IMPORT:
			filename_unicode = OpenDlg(hWnd, _UU("DLG_CONFIG_FILES"), _UU("DLG_OPEN_CONFIG"));
			if (filename_unicode != NULL)
			{
				BUF *b;
				filename = CopyUniToStr(filename_unicode);
				b = ReadDump(filename);
				if (b != NULL)
				{
					RPC_CONFIG t;

					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_CONFIG_CONFIRM")) == IDYES)
					{
						Zero(&t, sizeof(t));
						t.FileData = ZeroMalloc(b->Size + 1);
						Copy(t.FileData, b->Buf, b->Size);

						if (CALL(hWnd, ScSetConfig(c->s->Rpc, &t)))
						{
							// 成功
							MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_CONFIG_WRITE_OK"));
							_exit(0);
						}

						FreeRpcConfig(&t);

						FreeRpcConfig(&t);
						FreeBuf(b);
					}
				}
				else
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("SM_CONFIG_OPEN_FAILED"));
				}
				Free(filename);
				Free(filename_unicode);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// config 編集ダイアログを表示する
void SmConfig(HWND hWnd, SM_SERVER *s)
{
	SM_CONFIG c;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));

	c.s = s;

	// 現在の config をサーバーから取得
	if (CALL(hWnd, ScGetConfig(s->Rpc, &c.Config)) == false)
	{
		return;
	}

	// ダイアログ表示
	Dialog(hWnd, D_SM_CONFIG, SmConfigDlg, &c);

	// 解放
	FreeRpcConfig(&c.Config);
}

// ブリッジダイアログ初期化
void SmBridgeDlgInit(HWND hWnd, SM_SERVER *s)
{
	UINT i;
	RPC_ENUM_ETH t;
	RPC_SERVER_INFO si;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_BRIDGE_COLUMN_1"), 50);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_BRIDGE_COLUMN_2"), 145);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_BRIDGE_COLUMN_3"), 300);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_BRIDGE_COLUMN_4"), 100);

	SmBridgeDlgRefresh(hWnd, s);

	SetShow(hWnd, B_VLAN, GetCapsBool(s->CapsList, "b_support_eth_vlan"));

	SetIcon(hWnd, 0, ICO_BRIDGE);

	// サーバー情報を取得
	Zero(&si, sizeof(si));
	ScGetServerInfo(s->Rpc, &si);
	if (GetCapsBool(s->CapsList, "b_tap_supported") == false)
	{
		// tap はサポートしていない
		Hide(hWnd, R_TAP);
		Hide(hWnd, S_TAP_1);
		Hide(hWnd, E_TAPNAME);
		Hide(hWnd, S_TAP_2);
		Hide(hWnd, R_BRIDGE);
		Hide(hWnd, S_STATIC5);
	}
	Check(hWnd, R_BRIDGE, true);
	FreeRpcServerInfo(&si);

	// Ethernet 列挙
	Zero(&t, sizeof(t));
	ScEnumEthernet(s->Rpc, &t);

	CbReset(hWnd, E_NICNAME);
	CbSetHeight(hWnd, E_NICNAME, 18);

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t.Items[i];
		if(UniIsEmptyStr(e->NetworkConnectionName) == false)
		{
			wchar_t ncname[MAX_SIZE * 2];
			UniFormat(ncname, sizeof(ncname), BRIDGE_NETWORK_CONNECTION_STR, e->NetworkConnectionName, e->DeviceName);
			CbAddStr(hWnd, E_NICNAME, ncname, 0);
		}
		else
		{
			wchar_t *s = CopyStrToUni(e->DeviceName);
			CbAddStr(hWnd, E_NICNAME, s, 0);
			Free(s);
		}
	}

	FreeRpcEnumEth(&t);

	// 仮想 HUB 列挙
	{
		RPC_ENUM_HUB t;
		Zero(&t, sizeof(t));

		ScEnumHub(s->Rpc, &t);

		CbReset(hWnd, E_HUBNAME);
		CbSetHeight(hWnd, E_HUBNAME, 18);

		for (i = 0;i < t.NumHub;i++)
		{
			RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
			wchar_t *s = CopyStrToUni(e->HubName);

			if (e->HubType != HUB_TYPE_FARM_DYNAMIC)
			{
				CbAddStr(hWnd, E_HUBNAME, s, 0);
			}
			Free(s);
		}

		SetText(hWnd, E_HUBNAME, L"");

		FreeRpcEnumHub(&t);
	}

	if (s->Bridge)
	{
		SetTextA(hWnd, E_HUBNAME, "BRIDGE");
	}

	Focus(hWnd, E_HUBNAME);
	
	SmBridgeDlgUpdate(hWnd, s);

	SetTimer(hWnd, 1, 1000, NULL);
}

// ブリッジダイアログコントロール更新
void SmBridgeDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false)
	{
		Enable(hWnd, B_DELETE);
	}
	else
	{
		Disable(hWnd, B_DELETE);
	}

	if (IsEmpty(hWnd, E_HUBNAME))
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_TAP) == false)
	{
		// ブリッジモード
		Enable(hWnd, S_ETH_1);
		Enable(hWnd, E_NICNAME);
		Disable(hWnd, S_TAP_1);
		Disable(hWnd, S_TAP_2);
		Disable(hWnd, E_TAPNAME);
		SetText(hWnd, S_INFO, _UU("SM_BRIDGE_INFO_1"));
		SetIcon(hWnd, S_ICON, ICO_NIC_ONLINE);
		if (IsEmpty(hWnd, E_NICNAME))
		{
			ok = false;
		}
	}
	else
	{
		char tmp[MAX_SIZE];
		// tap モード
		Disable(hWnd, S_ETH_1);
		Disable(hWnd, E_NICNAME);
		Enable(hWnd, S_TAP_1);
		Enable(hWnd, S_TAP_2);
		Enable(hWnd, E_TAPNAME);
		SetText(hWnd, S_INFO, _UU("SM_BRIDGE_INFO_2"));
		SetIcon(hWnd, S_ICON, ICO_PROTOCOL);
		GetTxtA(hWnd, E_TAPNAME, tmp, sizeof(tmp));
		if (IsEmptyStr(tmp))
		{
			ok = false;
		}
		else
		{
			if (IsSafeStr(tmp) == false)
			{
				ok = false;
			}
			if (StrLen(tmp) >= 12)
			{
				ok = false;
			}
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// ブリッジダイアログ更新
void SmBridgeDlgRefresh(HWND hWnd, SM_SERVER *s)
{
	LVB *lvb;
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	lvb = LvInsertStart();

	Zero(&t, sizeof(t));

	ScEnumLocalBridge(s->Rpc, &t);

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t.Items[i];
		wchar_t name[MAX_SIZE];
		wchar_t nic[MAX_SIZE];
		wchar_t hub[MAX_SIZE];
		wchar_t *status = _UU("SM_BRIDGE_OFFLINE");

		UniToStru(name, i + 1);
		StrToUni(nic, sizeof(nic), e->DeviceName);
		StrToUni(hub, sizeof(hub), e->HubName);

		if (e->Online)
		{
			status = e->Active ? _UU("SM_BRIDGE_ONLINE") : _UU("SM_BRIDGE_ERROR");
		}

		LvInsertAdd(lvb, e->TapMode == false ? (e->Active ? ICO_NIC_ONLINE : ICO_NIC_OFFLINE) : ICO_PROTOCOL,
			NULL, 4, name, hub, nic, status);
	}

	FreeRpcEnumLocalBridge(&t);

	LvInsertEnd(lvb, hWnd, L_LIST);

	SmBridgeDlgUpdate(hWnd, s);
}

// ローカルブリッジの追加
void SmBridgeDlgOnOk(HWND hWnd, SM_SERVER *s)
{
	char nic[MAX_SIZE];
	char hub[MAX_SIZE];
	RPC_LOCALBRIDGE t;
	bool tapmode = false;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_HUBNAME, hub, sizeof(hub));

	Zero(nic, sizeof(nic));

	if (IsChecked(hWnd, R_TAP) == false)
	{
		wchar_t nctmp[MAX_SIZE * 2];
		if(GetCapsBool(s->CapsList, "b_support_network_connection_name") && GetTxt(hWnd, E_NICNAME, nctmp, sizeof(nctmp)))
		{
			RPC_ENUM_ETH et;
			UINT i;
			Zero(&et, sizeof(et));
			ScEnumEthernet(s->Rpc, &et);
			for(i = 0; i < et.NumItem; i++)
			{
				RPC_ENUM_ETH_ITEM *e = &et.Items[i];
				if(UniIsEmptyStr(e->NetworkConnectionName) == false)
				{
					wchar_t ncname[MAX_SIZE * 2];
					UniFormat(ncname, sizeof(ncname), BRIDGE_NETWORK_CONNECTION_STR, e->NetworkConnectionName, e->DeviceName);
					if(UniStrCmp(ncname, nctmp) == 0)
					{
						StrCpy(nic, sizeof(nic), e->DeviceName);
						break;
					}
				}		
			}
			FreeRpcEnumEth(&et);

			if (IsEmptyStr(nic))
			{
				GetTxtA(hWnd, E_NICNAME, nic, sizeof(nic));
			}
		}
		else
		{
			GetTxtA(hWnd, E_NICNAME, nic, sizeof(nic));
		}
	}
	else
	{
		tapmode = true;
		GetTxtA(hWnd, E_TAPNAME, nic, sizeof(nic));
	}

	Trim(hub);
	Trim(nic);

	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), nic);
	StrCpy(t.HubName, sizeof(t.HubName), hub);
	t.TapMode = tapmode;

	if (InStrEx(t.DeviceName, "vpn", false) || InStrEx(t.DeviceName, "tun", false)
		|| InStrEx(t.DeviceName, "tap", false))
	{
		// VPN デバイスにローカルブリッジしようとしている
		if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
			_UU("SM_BRIDGE_VPN"),
			t.DeviceName) == IDNO)
		{
			return;
		}
	}

	// Intel 製 LAN カードなどに関する警告
	if (tapmode == false)
	{
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_INTEL"));
	}

	if (CALL(hWnd, ScAddLocalBridge(s->Rpc, &t)) == false)
	{
		Focus(hWnd, E_HUBNAME);
		return;
	}

	SetText(hWnd, E_HUBNAME, L"");
	Focus(hWnd, E_HUBNAME);

	if (tapmode)
	{
		SetTextA(hWnd, E_TAPNAME, "");
	}

	SmBridgeDlgRefresh(hWnd, s);

	MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_OK"));
}

// ブリッジダイアログプロシージャ
UINT SmBridgeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SERVER *s = (SM_SERVER *)param;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmBridgeDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_HUBNAME:
		case E_NICNAME:
		case R_BRIDGE:
		case R_TAP:
		case E_TAPNAME:
			SmBridgeDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case R_BRIDGE:
			Focus(hWnd, E_NICNAME);
			break;

		case R_TAP:
			FocusEx(hWnd, E_TAPNAME);
			break;

		case IDOK:
			// 追加
			SmBridgeDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// 閉じる
			Close(hWnd);
			break;

		case B_VLAN:
			// VLAN ユーティリティ
			SmVLan(hWnd, s);
			break;

		case B_DELETE:
			// 削除
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE)
			{
				wchar_t *nic, *hub;
				wchar_t tmp[MAX_SIZE];
				RPC_LOCALBRIDGE t;

				hub = LvGetStr(hWnd, L_LIST, i, 1);
				nic = LvGetStr(hWnd, L_LIST, i, 2);

				UniFormat(tmp, sizeof(tmp), _UU("SM_BRIDGE_DELETE"),
					hub, nic);

				if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, tmp) == IDYES)
				{
					Zero(&t, sizeof(t));
					UniToStr(t.DeviceName, sizeof(t.DeviceName), nic);
					UniToStr(t.HubName, sizeof(t.HubName), hub);

					if (CALL(hWnd, ScDeleteLocalBridge(s->Rpc, &t)))
					{
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_DELETE_OK"));
						SmBridgeDlgRefresh(hWnd, s);
					}
				}

				Free(hub);
				Free(nic);
			}
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			SmBridgeDlgRefresh(hWnd, s);
			SetTimer(hWnd, 1, 1000, NULL);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmBridgeDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// WinPcap のインストール作業
void SmInstallWinPcap(HWND hWnd, SM_SERVER *s)
{
	wchar_t temp_name[MAX_SIZE];
	IO *io;
	BUF *buf;

	// インストールを開始するかどうか質問する
	if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_BRIDGE_WPCAP_INSTALL")) == IDNO)
	{
		return;
	}

	// 一時ファイル名を生成
	UniFormat(temp_name, sizeof(temp_name), L"%s\\winpcap_installer.exe", MsGetTempDirW());

	// hamcore から読み込む
	buf = ReadDump(MsIsNt() ? "|winpcap_installer.exe" : "|winpcap_installer_win9x.exe");
	if (buf == NULL)
	{
RES_ERROR:
		MsgBox(hWnd, MB_ICONSTOP, _UU("SM_BRIDGE_RESOURCE"));
		return;
	}

	// 一時ファイルに書き出す
	io = FileCreateW(temp_name);
	if (io == NULL)
	{
		FreeBuf(buf);
		goto RES_ERROR;
	}

	FileWrite(io, buf->Buf, buf->Size);
	FileClose(io);

	FreeBuf(buf);

	// 実行する
	if (RunW(temp_name, NULL, false, true) == false)
	{
		// 失敗
		FileDeleteW(temp_name);
		goto RES_ERROR;
	}

	FileDeleteW(temp_name);

	if (s == NULL)
	{
		return;
	}

	// 終了後のメッセージ
	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) == false)
	{
		// コンピュータの再起動が必要
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_WPCAP_REBOOT1"));
	}
	else
	{
		// サービスの再起動が必要
		if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_BRIDGE_WPCAP_REBOOT2")) == IDNO)
		{
			// 再起動しない
		}
		else
		{
			// 再起動する
			RPC_TEST t;
			Zero(&t, sizeof(t));
			ScRebootServer(s->Rpc, &t);

			SleepThread(500);

			Zero(&t, sizeof(t));
			CALL(hWnd, ScTest(s->Rpc, &t));
		}
	}
}

// ブリッジダイアログ
void SmBridgeDlg(HWND hWnd, SM_SERVER *s)
{
	RPC_BRIDGE_SUPPORT t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	// まずサーバー側のブリッジ対応状況を調べる
	Zero(&t, sizeof(t));
	if (CALLEX(hWnd, ScGetBridgeSupport(s->Rpc, &t)) != ERR_NO_ERROR)
	{
		// 古いバージョンなので未対応
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SM_BRIDGE_TOO_OLD_VER"));
		return;
	}

	if (t.IsBridgeSupportedOs == false)
	{
		// OS がブリッジに対応していない
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SM_BRIDGE_UNSUPPORTED"));
		return;
	}

	if (t.IsWinPcapNeeded)
	{
		if (s->Rpc->Sock->RemoteIP.addr[0] != 127)
		{
			// WinPcap が必要だがリモート管理モードなので何も出来ない
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_WPCAP_REMOTE"));
			return;
		}
		else
		{
			// WinPcap が必要でローカル管理モードである
			if (MsIsAdmin())
			{
				// Administrators である
				SmInstallWinPcap(hWnd, s);
				return;
			}
			else
			{
				// Administrators でない
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_WPCAP_ROOT"));
				return;
			}
		}
	}

	Dialog(hWnd, D_SM_BRIDGE, SmBridgeDlgProc, s);
}

// SecureNAT 画面更新
void SmSNATDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool b;
	RPC_HUB_STATUS t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScGetHubStatus(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	b = t.SecureNATEnabled;

	if (b)
	{
		Disable(hWnd, B_ENABLE);
		Enable(hWnd, B_DISABLE);
		Enable(hWnd, B_NAT);
		Enable(hWnd, B_DHCP);
		Enable(hWnd, B_STATUS);
	}
	else
	{
		Enable(hWnd, B_ENABLE);
		Disable(hWnd, B_DISABLE);
		Disable(hWnd, B_NAT);
		Disable(hWnd, B_DHCP);
		Disable(hWnd, B_STATUS);
	}
}

// SecureNAT 設定画面
UINT SmSNATDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	RPC_HUB t;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_ROUTER);
		DlgFont(hWnd, S_WARNING, (_GETLANG() == 0 || _GETLANG() == 2) ? 13 : 10, true);
		FormatText(hWnd, S_TITLE, s->HubName);
		SmSNATDlgUpdate(hWnd, s);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		if (wParam == 1)
		{
			KillTimer(hWnd, 1);

			SmSNATDlgUpdate(hWnd, s);

			SetTimer(hWnd, 1, 1000, NULL);
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;

		case B_ENABLE:
			if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_OKCANCEL | MB_DEFBUTTON2,
				_UU("SM_SECURE_NAT_MSG")) == IDOK)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
				CALL(hWnd, ScEnableSecureNAT(s->Rpc, &t));
				SmSNATDlgUpdate(hWnd, s);
			}
			break;

		case B_DISABLE:
			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
			CALL(hWnd, ScDisableSecureNAT(s->Rpc, &t));
			SmSNATDlgUpdate(hWnd, s);
			break;

		case B_CONFIG:
			NmEditVhOption(hWnd, s);
			break;

		case B_NAT:
			NmNat(hWnd, s);
			break;

		case B_DHCP:
			NmDhcp(hWnd, s);
			break;

		case B_STATUS:
			SmStatusDlg(hWnd, s->p, s, false, true, _UU("SM_SNAT_STATUS"), ICO_ROUTER,
				NULL, NmStatus);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// 初期化
void SmCreateCertDlgInit(HWND hWnd, SM_CERT *s)
{
	UINT cert_sign;
	UINT cert_days;
	char *reg_o, *reg_ou, *reg_c, *reg_st, *reg_l;
	UINT bits[] = {1024, 1536, 2048, 3072, 4096 };
	UINT i;
	UINT last_bit;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetTextA(hWnd, E_CN, s->default_cn);

	last_bit = MsRegReadInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Bits");
	if (last_bit == 0)
	{
		last_bit = 1024;
	}

	CbReset(hWnd, C_BITS);
	for (i = 0;i < sizeof(bits) / sizeof(bits[0]);i++)
	{
		char tmp[MAX_PATH];
		UINT index;

		ToStr(tmp, bits[i]);

		index = CbAddStrA(hWnd, C_BITS, tmp, bits[i]);
	}

	CbSelect(hWnd, C_BITS, 1024);
	CbSelect(hWnd, C_BITS, last_bit);

	reg_o = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "O");
	reg_ou = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "OU");
	reg_c = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "C");
	reg_st = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "ST");
	reg_l = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "L");
	SetTextA(hWnd, E_O, reg_o);
	SetTextA(hWnd, E_OU, reg_ou);
	SetTextA(hWnd, E_C, reg_c);
	SetTextA(hWnd, E_ST, reg_st);
	SetTextA(hWnd, E_L, reg_l);
	Free(reg_o);
	Free(reg_ou);
	Free(reg_c);
	Free(reg_st);
	Free(reg_l);

	LimitText(hWnd, E_C, 2);

	cert_sign = MsRegReadInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Sign");
	cert_days = MsRegReadInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Days");

	Check(hWnd, R_ROOT_CERT, cert_sign ? false : true);
	Check(hWnd, R_SIGNED_CERT, cert_sign ? true : false);

	if (cert_days == 0)
	{
		cert_days = 3650;
	}

	SetIntEx(hWnd, E_EXPIRE, cert_days);

	SmCreateCertDlgUpdate(hWnd, s);

	FocusEx(hWnd, E_CN);
}

// 更新
void SmCreateCertDlgUpdate(HWND hWnd, SM_CERT *s)
{
	bool ok = true;
	bool b;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (IsEmpty(hWnd, E_CN) && IsEmpty(hWnd, E_O) && IsEmpty(hWnd, E_OU) &&
		IsEmpty(hWnd, E_ST) && IsEmpty(hWnd, E_L))
	{
		ok = false;
	}

	i = GetInt(hWnd, E_EXPIRE);
	if (i == 0 || i >= (365 * 30))
	{
		ok = false;
	}

	b = IsChecked(hWnd, R_SIGNED_CERT);

	SetEnable(hWnd, S_LOAD_1, b);
	SetEnable(hWnd, B_LOAD, b);
	SetEnable(hWnd, S_LOAD_2, b);

	if (b && (s->root_k == NULL || s->root_x == NULL))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// OK ボタン
void SmCreateCertDlgOnOk(HWND hWnd, SM_CERT *s)
{
	wchar_t cn[MAX_SIZE], o[MAX_SIZE], ou[MAX_SIZE], c[MAX_SIZE], st[MAX_SIZE], l[MAX_SIZE];
	char *reg_o, *reg_ou, *reg_c, *reg_st, *reg_l;
	UINT days;
	bool sign;
	char serial[MAX_SIZE * 2];
	X *x;
	K *pub;
	K *pri;
	NAME *n;
	X_SERIAL *x_serial;
	BUF *buf;
	UINT bits;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	GetTxt(hWnd, E_CN, cn, sizeof(cn));
	GetTxt(hWnd, E_O, o, sizeof(o));
	GetTxt(hWnd, E_OU, ou, sizeof(ou));
	GetTxt(hWnd, E_C, c, sizeof(c));
	GetTxt(hWnd, E_ST, st, sizeof(st));
	GetTxt(hWnd, E_L, l, sizeof(l));
	GetTxtA(hWnd, E_SERIAL, serial, sizeof(serial));

	bits = CbGetSelect(hWnd, C_BITS);
	if (bits == INFINITE)
	{
		bits = 1024;
	}

	buf = StrToBin(serial);
	if (buf == NULL)
	{
		return;
	}

	if (buf->Size > 1)
	{
		x_serial = NewXSerial(buf->Buf, buf->Size);
	}
	else
	{
		x_serial = NULL;
	}

	FreeBuf(buf);

	n = NewName(UniStrLen(cn) ? cn : NULL,
		UniStrLen(o) ? o : NULL,
		UniStrLen(ou) ? ou : NULL,
		UniStrLen(c) ? c : NULL,
		UniStrLen(st) ? st : NULL,
		UniStrLen(l) ? l : NULL);

	days = GetInt(hWnd, E_EXPIRE);

	sign = IsChecked(hWnd, R_SIGNED_CERT);

	MsRegWriteInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Sign", sign);
	MsRegWriteInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Days", days);
	MsRegWriteInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Bits", bits);

	RsaGen(&pri, &pub, bits);

	if (sign == false)
	{
		x = NewRootX(pub, pri, n, days, x_serial);
	}
	else
	{
		x = NewX(pub, s->root_k, s->root_x, n, days, x_serial);
	}

	FreeName(n);

	FreeXSerial(x_serial);

	if (x == NULL)
	{
		FreeX(x);
		FreeK(pub);
		FreeK(pri);
		return;
	}

	if (s->do_not_save == false)
	{
		if (SmSaveKeyPairDlg(hWnd, x, pri) == false)
		{
			FreeX(x);
			FreeK(pub);
			FreeK(pri);
			return;
		}
	}

	s->x = x;
	s->k = pri;
	FreeK(pub);

	reg_o = GetTextA(hWnd, E_O);
	reg_ou = GetTextA(hWnd, E_OU);
	reg_c = GetTextA(hWnd, E_C);
	reg_st = GetTextA(hWnd, E_ST);
	reg_l = GetTextA(hWnd, E_L);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "O", reg_o);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "OU", reg_ou);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "C", reg_c);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "ST", reg_st);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "L", reg_l);
	Free(reg_o);
	Free(reg_ou);
	Free(reg_c);
	Free(reg_st);
	Free(reg_l);

	EndDialog(hWnd, true);
}

// 証明書作成画面
UINT SmCreateCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_CERT *s = (SM_CERT *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmCreateCertDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_ROOT_CERT:
		case R_SIGNED_CERT:
		case B_LOAD:
		case E_CN:
		case E_O:
		case E_OU:
		case E_C:
		case E_ST:
		case E_L:
		case E_EXPIRE:
			SmCreateCertDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmCreateCertDlgOnOk(hWnd, s);
			break;

		case R_ROOT_CERT:
			if (IsChecked(hWnd, R_ROOT_CERT))
			{
				FocusEx(hWnd, E_CN);
			}
			break;

		case B_LOAD:
			// 証明書読み込み
			if (1)
			{
				X *x;
				K *k;
				if (CmLoadXAndK(hWnd, &x, &k))
				{
					wchar_t tmp[MAX_SIZE];
					FreeX(s->root_x);
					FreeK(s->root_k);
					s->root_x = x;
					s->root_k = k;

					SmGetCertInfoStr(tmp, sizeof(tmp), x);
					SetText(hWnd, S_LOAD_2, tmp);
					SmCreateCertDlgUpdate(hWnd, s);
				}
			}
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 証明書ツール
bool SmCreateCert(HWND hWnd, X **x, K **k, bool do_not_save, char *default_cn)
{
	bool ret;
	SM_CERT s;
	Zero(&s, sizeof(s));

	if (default_cn == NULL)
	{
		default_cn = "";
	}

	s.default_cn = default_cn;

	s.do_not_save = do_not_save;

	ret = Dialog(hWnd, D_SM_CREATE_CERT, SmCreateCertDlgProc, &s);

	if (ret)
	{
		if (x != NULL)
		{
			*x = CloneX(s.x);
		}

		if (k != NULL)
		{
			*k = CloneK(s.k);
		}
	}

	FreeX(s.x);
	FreeK(s.k);
	FreeX(s.root_x);
	FreeK(s.root_k);

	return ret;
}

// 初期化
void SmIpTableDlgInit(HWND hWnd, SM_TABLE *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PROTOCOL);
	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	if (s->SessionName != NULL)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		GetTxt(hWnd, S_TITLE, tmp, sizeof(tmp));
		UniFormat(tmp2, sizeof(tmp2), _UU("SM_SESSION_FILTER"), s->SessionName);
		UniStrCat(tmp, sizeof(tmp), tmp2);
		SetText(hWnd, S_TITLE, tmp);
	}

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, 0, _UU("SM_IP_COLUMN_1"), 190);
	LvInsertColumn(hWnd, L_TABLE, 1, _UU("SM_IP_COLUMN_2"), 140);
	LvInsertColumn(hWnd, L_TABLE, 2, _UU("SM_IP_COLUMN_3"), 133);
	LvInsertColumn(hWnd, L_TABLE, 3, _UU("SM_IP_COLUMN_4"), 133);
	LvInsertColumn(hWnd, L_TABLE, 4, _UU("SM_IP_COLUMN_5"), 133);
	LvSetStyle(hWnd, L_TABLE, LVS_EX_GRIDLINES);

	SmIpTableDlgRefresh(hWnd, s);
}

// コントロール更新
void SmIpTableDlgUpdate(HWND hWnd, SM_TABLE *s)
{
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_TABLE) == false || LvIsMultiMasked(hWnd, L_TABLE))
	{
		ok = false;
	}

	SetEnable(hWnd, B_DELETE, ok);
}

// 内容更新
void SmIpTableDlgRefresh(HWND hWnd, SM_TABLE *s)
{
	UINT i;
	RPC_ENUM_IP_TABLE t;
	UINT old_selected = 0;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);

	if (CALL(hWnd, ScEnumIpTable(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	i = LvGetSelected(hWnd, L_TABLE);
	if (i != INFINITE)
	{
		old_selected = (UINT)LvGetParam(hWnd, L_TABLE, i);
	}

	LvReset(hWnd, L_TABLE);

	for (i = 0;i < t.NumIpTable;i++)
	{
		char str[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

		if (s->SessionName == NULL || StrCmpi(e->SessionName, s->SessionName) == 0)
		{
			StrToUni(tmp1, sizeof(tmp1), e->SessionName);

			if (e->DhcpAllocated == false)
			{
				IPToStr(str, sizeof(str), &e->IpV6);
				StrToUni(tmp2, sizeof(tmp2), str);
			}
			else
			{
				IPToStr(str, sizeof(str), &e->IpV6);
				UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
			}

			GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

			GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

			if (StrLen(e->RemoteHostname) == 0)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
			}
			else
			{
				UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
			}

			LvInsert(hWnd, L_TABLE, e->DhcpAllocated ? ICO_PROTOCOL_DHCP : ICO_PROTOCOL, (void *)e->Key, 5,
				tmp1, tmp2, tmp3, tmp4, tmp5);
		}
	}

	FreeRpcEnumIpTable(&t);

	if (old_selected != 0)
	{
		LvSelect(hWnd, L_TABLE, LvSearchParam(hWnd, L_TABLE, (void *)old_selected));
	}

	SmIpTableDlgUpdate(hWnd, s);
}

// IP アドレステーブルダイアログプロシージャ
UINT SmIpTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_TABLE *s = (SM_TABLE *)param;
	NMHDR *n;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmIpTableDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_DELETE:
			// 削除
			i = LvGetSelected(hWnd, L_TABLE);
			if (i != INFINITE)
			{
				RPC_DELETE_TABLE t;
				UINT key = (UINT)LvGetParam(hWnd, L_TABLE, i);

				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
				t.Key = key;
				if (CALL(hWnd, ScDeleteIpTable(s->Rpc, &t)))
				{
					LvDeleteItem(hWnd, L_TABLE, i);
				}
			}
			break;

		case B_REFRESH:
			// 更新
			SmIpTableDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_TABLE:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmIpTableDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_TABLE);

	return 0;
}

// IP アドレステーブルダイアログ
void SmIpTableDlg(HWND hWnd, SM_HUB *s, char *session_name)
{
	SM_TABLE t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Hub = s;
	t.Rpc = s->Rpc;
	t.SessionName = session_name;

	Dialog(hWnd, D_SM_IP, SmIpTableDlgProc, &t);
}


// 初期化
void SmMacTableDlgInit(HWND hWnd, SM_TABLE *s)
{
	UINT i = 0;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_NIC_ONLINE);
	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	if (s->SessionName != NULL)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		GetTxt(hWnd, S_TITLE, tmp, sizeof(tmp));
		UniFormat(tmp2, sizeof(tmp2), _UU("SM_SESSION_FILTER"), s->SessionName);
		UniStrCat(tmp, sizeof(tmp), tmp2);
		SetText(hWnd, S_TITLE, tmp);
	}

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_1"), 190);
	if (GetCapsBool(s->Hub->p->CapsList, "b_support_vlan"))
	{
		LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_1A"), 65);
	}
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_2"), 140);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_3"), 133);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_4"), 133);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_5"), 133);
	LvSetStyle(hWnd, L_TABLE, LVS_EX_GRIDLINES);

	SmMacTableDlgRefresh(hWnd, s);
}

// コントロール更新
void SmMacTableDlgUpdate(HWND hWnd, SM_TABLE *s)
{
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_TABLE) == false || LvIsMultiMasked(hWnd, L_TABLE))
	{
		ok = false;
	}

	SetEnable(hWnd, B_DELETE, ok);
}

// 内容更新
void SmMacTableDlgRefresh(HWND hWnd, SM_TABLE *s)
{
	UINT i;
	RPC_ENUM_MAC_TABLE t;
	UINT old_selected = 0;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);

	if (CALL(hWnd, ScEnumMacTable(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	i = LvGetSelected(hWnd, L_TABLE);
	if (i != INFINITE)
	{
		old_selected = (UINT)LvGetParam(hWnd, L_TABLE, i);
	}

	LvReset(hWnd, L_TABLE);

	for (i = 0;i < t.NumMacTable;i++)
	{
		char str[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		wchar_t tmp6[MAX_SIZE];
		RPC_ENUM_MAC_TABLE_ITEM *e = &t.MacTables[i];

		if (s->SessionName == NULL || StrCmpi(e->SessionName, s->SessionName) == 0)
		{
			StrToUni(tmp1, sizeof(tmp1), e->SessionName);

			MacToStr(str, sizeof(str), e->MacAddress);
			StrToUni(tmp2, sizeof(tmp2), str);

			GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

			GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

			if (StrLen(e->RemoteHostname) == 0)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
			}
			else
			{
				UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
			}

			UniToStru(tmp6, e->VlanId);
			if (e->VlanId == 0)
			{
				UniStrCpy(tmp6, sizeof(tmp6), _UU("CM_ST_NONE"));
			}

			if (GetCapsBool(s->Hub->p->CapsList, "b_support_vlan"))
			{
				LvInsert(hWnd, L_TABLE, ICO_NIC_ONLINE, (void *)e->Key, 6,
					tmp1, tmp6, tmp2, tmp3, tmp4, tmp5);
			}
			else
			{
				LvInsert(hWnd, L_TABLE, ICO_NIC_ONLINE, (void *)e->Key, 5,
					tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}
	}

	FreeRpcEnumMacTable(&t);

	if (old_selected != 0)
	{
		LvSelect(hWnd, L_TABLE, LvSearchParam(hWnd, L_TABLE, (void *)old_selected));
	}

	SmMacTableDlgUpdate(hWnd, s);
}

// MAC アドレステーブルダイアログプロシージャ
UINT SmMacTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_TABLE *s = (SM_TABLE *)param;
	NMHDR *n;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmMacTableDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_DELETE:
			// 削除
			i = LvGetSelected(hWnd, L_TABLE);
			if (i != INFINITE)
			{
				RPC_DELETE_TABLE t;
				UINT key = (UINT)LvGetParam(hWnd, L_TABLE, i);

				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
				t.Key = key;
				if (CALL(hWnd, ScDeleteMacTable(s->Rpc, &t)))
				{
					LvDeleteItem(hWnd, L_TABLE, i);
				}
			}
			break;

		case B_REFRESH:
			// 更新
			SmMacTableDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_TABLE:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmMacTableDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_TABLE);

	return 0;
}

// MAC アドレステーブルダイアログ
void SmMacTableDlg(HWND hWnd, SM_HUB *s, char *session_name)
{
	SM_TABLE t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Hub = s;
	t.Rpc = s->Rpc;
	t.SessionName = session_name;

	Dialog(hWnd, D_SM_MAC, SmMacTableDlgProc, &t);
}

// 初期化
void SmSessionDlgInit(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_VPN);
	FormatText(hWnd, 0, s->HubName);
	FormatText(hWnd, S_TITLE, s->HubName);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_SESS_COLUMN_1"), 176);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_SESS_COLUMN_8"), 58);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_SESS_COLUMN_2"), 62);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_SESS_COLUMN_3"), 78);
	LvInsertColumn(hWnd, L_LIST, 4, _UU("SM_SESS_COLUMN_4"), 122);
	LvInsertColumn(hWnd, L_LIST, 5, _UU("SM_SESS_COLUMN_5"), 68);
	LvInsertColumn(hWnd, L_LIST, 6, _UU("SM_SESS_COLUMN_6"), 100);
	LvInsertColumn(hWnd, L_LIST, 7, _UU("SM_SESS_COLUMN_7"), 100);
	LvSetStyle(hWnd, L_LIST, LVS_EX_GRIDLINES);

	if (s->p->ServerType == SERVER_TYPE_FARM_CONTROLLER && GetCapsBool(s->p->CapsList, "b_support_cluster_admin") == false)
	{
		Show(hWnd, S_FARM_INFO_1);
		Show(hWnd, S_FARM_INFO_2);
	}

	SmSessionDlgRefresh(hWnd, s);
}

// コントロールを更新する
void SmSessionDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool ok = true;
	bool ok2 = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_LIST) == false || LvIsMultiMasked(hWnd, L_LIST))
	{
		ok = false;
		ok2 = false;
	}
	else
	{
		UINT i = LvGetSelected(hWnd, L_LIST);
		if (i != INFINITE)
		{
			void *p = LvGetParam(hWnd, L_LIST, i);
			if (((bool)p) != false)
			{
				if (GetCapsBool(s->p->CapsList, "b_support_cluster_admin") == false)
				{
					ok = false;
				}
			}
		}
	}

	if (s->p->ServerInfo.ServerBuildInt < 2844)
	{
		// セッションのリモート管理非対応 Ver
		ok2 = ok;
	}

	SetEnable(hWnd, IDOK, ok2);
	SetEnable(hWnd, B_DISCONNECT, ok2);
	SetEnable(hWnd, B_SESSION_IP_TABLE, ok);
	SetEnable(hWnd, B_SESSION_MAC_TABLE, ok);
}

// リストを更新する
void SmSessionDlgRefresh(HWND hWnd, SM_HUB *s)
{
	LVB *b;
	UINT i;
	wchar_t *old_select;
	RPC_ENUM_SESSION t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScEnumSession(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	old_select = LvGetSelectedStr(hWnd, L_LIST, 0);

	LvReset(hWnd, L_LIST);

	b = LvInsertStart();

	for (i = 0;i < t.NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t *tmp2;
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		wchar_t tmp6[MAX_SIZE];
		wchar_t tmp7[MAX_SIZE];
		wchar_t tmp8[MAX_SIZE];
		bool free_tmp2 = false;
		UINT icon;

		StrToUni(tmp1, sizeof(tmp1), e->Name);

		tmp2 = _UU("SM_SESS_NORMAL");
		icon = ICO_VPN;
		if (s->p->ServerType != SERVER_TYPE_STANDALONE)
		{
			if (e->RemoteSession)
			{
				tmp2 = ZeroMalloc(MAX_SIZE);
				UniFormat(tmp2, MAX_SIZE, _UU("SM_SESS_REMOTE"), e->RemoteHostname);
				icon = ICO_VPN;
				free_tmp2 = true;
			}
			else
			{
				if (StrLen(e->RemoteHostname) == 0)
				{
					tmp2 = _UU("SM_SESS_LOCAL");
				}
				else
				{
					tmp2 = ZeroMalloc(MAX_SIZE);
					UniFormat(tmp2, MAX_SIZE, _UU("SM_SESS_LOCAL_2"), e->RemoteHostname);
					free_tmp2 = true;
				}
			}
		}
		if (e->LinkMode)
		{
			if (free_tmp2)
			{
				Free(tmp2);
				free_tmp2 = false;
			}
			tmp2 = _UU("SM_SESS_LINK");
			icon = ICO_CASCADE;
		}
		else if (e->SecureNATMode)
		{
			/*if (free_tmp2)
			{
				Free(tmp2);
				free_tmp2 = false;
			}
			tmp2 = _UU("SM_SESS_SNAT");*/
			icon = ICO_ROUTER;
		}
		else if (e->BridgeMode)
		{
			icon = ICO_BRIDGE;
		}
		else if (e->Layer3Mode)
		{
			icon = ICO_SWITCH;
		}

		StrToUni(tmp3, sizeof(tmp3), e->Username);

		StrToUni(tmp4, sizeof(tmp4), e->Hostname);
		if (e->LinkMode)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_LINK_HOSTNAME"));
		}
		else if (e->SecureNATMode)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_SNAT_HOSTNAME"));
		}
		else if (e->BridgeMode)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_BRIDGE_HOSTNAME"));
		}
		else if (StartWith(e->Username, L3_USERNAME))
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_LAYER3_HOSTNAME"));
		}

		UniFormat(tmp5, sizeof(tmp5), L"%u / %u", e->CurrentNumTcp, e->MaxNumTcp);
		if (e->LinkMode)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_LINK_TCP"));
		}
		else if (e->SecureNATMode)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_SNAT_TCP"));
		}
		else if (e->BridgeMode)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_BRIDGE_TCP"));
		}

		if (e->VLanId == 0)
		{
			UniStrCpy(tmp8, sizeof(tmp8), _UU("CM_ST_NO_VLAN"));
		}
		else
		{
			UniToStru(tmp8, e->VLanId);
		}

		UniToStr3(tmp6, sizeof(tmp6), e->PacketSize);
		UniToStr3(tmp7, sizeof(tmp7), e->PacketNum);

		if (icon == ICO_VPN)
		{
			if (e->Client_BridgeMode)
			{
				icon = ICO_SESSION_BRIDGE;
			}
			else if (e->Client_MonitorMode)
			{
				icon = ICO_SESSION_MONITOR;
			}
		}

		LvInsertAdd(b, icon, (void *)(e->RemoteSession), 8, tmp1, tmp8, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7);

		if (free_tmp2)
		{
			Free(tmp2);
		}
	}

	LvInsertEnd(b, hWnd, L_LIST);

	if (old_select != NULL && UniStrLen(old_select) != 0)
	{
		UINT i = LvSearchStr(hWnd, L_LIST, 0, old_select);
		if (i != INFINITE)
		{
			LvSelect(hWnd, L_LIST, i);
		}
	}

	Free(old_select);

	FreeRpcEnumSession(&t);

	SmSessionDlgUpdate(hWnd, s);
}

// NODE_INFO の表示
void SmPrintNodeInfo(LVB *b, NODE_INFO *info)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// 引数チェック
	if (b == NULL || info == NULL)
	{
		return;
	}

	StrToUni(tmp, sizeof(tmp), info->ClientProductName);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_NAME"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%u.%02u", Endian32(info->ClientProductVer) / 100, Endian32(info->ClientProductVer) % 100);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_VER"), tmp);

	UniFormat(tmp, sizeof(tmp), L"Build %u", Endian32(info->ClientProductBuild));
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_BUILD"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsName);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_OS_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsVer);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_OS_VER"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsProductId);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_OS_PID"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientHostname);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ClientIpAddress, info->ClientIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_IP"), tmp);

	UniToStru(tmp, Endian32(info->ClientPort));
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_PORT"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ServerHostname);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_SERVER_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ServerIpAddress, info->ServerIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_SERVER_IP"), tmp);

	UniToStru(tmp, Endian32(info->ServerPort));
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_SERVER_PORT"), tmp);

	if (StrLen(info->ProxyHostname) != 0)
	{
		StrToUni(tmp, sizeof(tmp), info->ProxyHostname);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_PROXY_HOSTNAME"), tmp);

		IPToStr4or6(str, sizeof(str), info->ProxyIpAddress, info->ProxyIpAddress6);
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_PROXY_IP"), tmp);

		UniToStru(tmp, Endian32(info->ProxyPort));
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_PROXY_PORT"), tmp);
	}
}

// セッション ステータスの更新
bool SmRefreshSessionStatus(HWND hWnd, SM_SERVER *s, void *param)
{
	LVB *b;
	SM_SESSION_STATUS *status = (SM_SESSION_STATUS *)param;
	RPC_SESSION_STATUS t;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || s == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), status->Hub->HubName);
	StrCpy(t.Name, sizeof(t.Name), status->SessionName);

	if (CALL(hWnd, ScGetSessionStatus(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	if (t.ClientIp != 0)
	{
		IPToStr4or6(str, sizeof(str), t.ClientIp, t.ClientIp6);
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_CLIENT_IP"), tmp);
	}

	if (StrLen(t.ClientHostName) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.ClientHostName);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_CLIENT_HOSTNAME"), tmp);
	}

	StrToUni(tmp, sizeof(tmp), t.Username);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_SESS_STATUS_USERNAME"), tmp);

	if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.RealUsername);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_SESS_STATUS_REALUSER"), tmp);
	}

	if (IsEmptyStr(t.GroupName) == false)
	{
		StrToUni(tmp, sizeof(tmp), t.GroupName);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_SESS_STATUS_GROUPNAME"), tmp);
	}

	CmPrintStatusToListViewEx(b, &t.Status, true);

	if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0 &&
		StartWith(t.Username, L3_USERNAME) == false)
	{
		SmPrintNodeInfo(b, &t.NodeInfo);
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcSessionStatus(&t);

	return true;
}

// セッション管理ダイアログプロシージャ
UINT SmSessionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	wchar_t *tmp;
	wchar_t tmp2[MAX_SIZE];
	char name[MAX_SIZE];
	NMHDR *n;
	SM_SESSION_STATUS status;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	tmp = LvGetSelectedStr(hWnd, L_LIST, 0);
	UniToStr(name, sizeof(name), tmp);

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmSessionDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				// セッション状態表示
				UniFormat(tmp2, sizeof(tmp2), _UU("SM_SESS_STATUS_CAPTION"), name);
				Zero(&status, sizeof(status));
				status.Hub = s;
				status.SessionName = name;
				SmStatusDlg(hWnd, s->p, &status, true, true, tmp2, ICO_VPN,
					NULL, SmRefreshSessionStatus);
			}
			break;

		case B_DISCONNECT:
			// 切断
			if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
				_UU("SM_SESS_DISCONNECT_MSG"), name) == IDYES)
			{
				RPC_DELETE_SESSION t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
				StrCpy(t.Name, sizeof(t.Name), name);

				if (CALL(hWnd, ScDeleteSession(s->Rpc, &t)))
				{
					SmSessionDlgRefresh(hWnd, s);
				}
			}
			break;

		case B_REFRESH:
			// 更新
			SmSessionDlgRefresh(hWnd, s);
			break;

		case B_SESSION_IP_TABLE:
			// IP テーブル
			SmIpTableDlg(hWnd, s, name);
			break;

		case B_SESSION_MAC_TABLE:
			// MAC テーブル
			SmMacTableDlg(hWnd, s, name);
			break;

		case B_MAC_TABLE:
			// MAC テーブル一覧
			SmMacTableDlg(hWnd, s, NULL);
			break;

		case B_IP_TABLE:
			// IP テーブル一覧
			SmIpTableDlg(hWnd, s, NULL);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmSessionDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	Free(tmp);

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// セッション管理ダイアログ
void SmSessionDlg(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_SESSION, SmSessionDlgProc, s);
}

// 証明書一覧更新
void SmCaDlgRefresh(HWND hWnd, SM_HUB *s)
{
	LVB *b;
	UINT i;
	RPC_HUB_ENUM_CA t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScEnumCa(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumCa;i++)
	{
		wchar_t tmp[MAX_SIZE];
		RPC_HUB_ENUM_CA_ITEM *e = &t.Ca[i];

		GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

		LvInsertAdd(b, ICO_SERVER_CERT, (void *)e->Key, 3,
			e->SubjectName, e->IssuerName, tmp);
	}

	LvInsertEnd(b, hWnd, L_CERT);

	FreeRpcHubEnumCa(&t);

	SmCaDlgUpdate(hWnd, s);
}

// 初期化
void SmCaDlgInit(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SERVER_CERT);

	LvInit(hWnd, L_CERT);
	LvInsertColumn(hWnd, L_CERT, 0, _UU("CM_CERT_COLUMN_1"), 190);
	LvInsertColumn(hWnd, L_CERT, 1, _UU("CM_CERT_COLUMN_2"), 190);
	LvInsertColumn(hWnd, L_CERT, 2, _UU("CM_CERT_COLUMN_3"), 160);

	SmCaDlgRefresh(hWnd, s);
}

// コントロール更新
void SmCaDlgUpdate(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetEnable(hWnd, B_DELETE, LvIsSelected(hWnd, L_CERT));
	SetEnable(hWnd, IDOK, LvIsSelected(hWnd, L_CERT));
}

// OK
void SmCaDlgOnOk(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}
}

// CA 追加ダイアログ
bool SmCaDlgAdd(HWND hWnd, SM_HUB *s)
{
	X *x;
	RPC_HUB_ADD_CA t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	if (CmLoadXFromFileOrSecureCard(hWnd, &x) == false)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	t.Cert = x;

	if (CALL(hWnd, ScAddCa(s->Rpc, &t)) == false)
	{
		return false;
	}

	FreeRpcHubAddCa(&t);

	return true;
}

// CA 一覧ダイアログプロシージャ
UINT SmCaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_HUB *s = (SM_HUB *)param;
	UINT i, key;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmCaDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_IMPORT:
			// 追加
			if (SmCaDlgAdd(hWnd, s))
			{
				SmCaDlgRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			// 削除
			i = LvGetSelected(hWnd, L_CERT);
			if (i != INFINITE)
			{
				key = (UINT)LvGetParam(hWnd, L_CERT, i);
				if (key != 0)
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
						_UU("CM_CERT_DELETE_MSG")) == IDYES)
					{
						RPC_HUB_DELETE_CA t;
						Zero(&t, sizeof(t));
						StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
						t.Key = key;

						if (CALL(hWnd, ScDeleteCa(s->Rpc, &t)))
						{
							SmCaDlgRefresh(hWnd, s);
						}
					}
				}
			}
			break;

		case IDOK:
			// 表示
			i = LvGetSelected(hWnd, L_CERT);
			if (i != INFINITE)
			{
				key = (UINT)LvGetParam(hWnd, L_CERT, i);
				if (key != 0)
				{
					RPC_HUB_GET_CA t;
					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
					t.Key = key;

					if (CALL(hWnd, ScGetCa(s->Rpc, &t)))
					{
						CertDlg(hWnd, t.Cert, NULL, true);
						FreeRpcHubGetCa(&t);
					}
				}
			}
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_CERT:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmCaDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_CERT);

	return 0;
}

// CA 一覧ダイアログ
void SmCaDlg(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_CA, SmCaDlgProc, s);
}

// 初期化
void SmLogDlgInit(HWND hWnd, SM_HUB *s)
{
	RPC_HUB_LOG t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_LOG2);

	FormatText(hWnd, S_TITLE, s->HubName);

	CbSetHeight(hWnd, C_SEC_SWITCH, 18);
	CbSetHeight(hWnd, C_PACKET_SWITCH, 18);

	// コントロール初期化
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_0"), 0);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_1"), 1);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_2"), 2);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_3"), 3);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_4"), 4);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_5"), 5);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_0"), 0);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_1"), 1);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_2"), 2);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_3"), 3);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_4"), 4);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_5"), 5);

	// ログ設定を取得
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScGetHubLog(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	Check(hWnd, B_SEC, t.LogSetting.SaveSecurityLog);
	CbSelect(hWnd, C_SEC_SWITCH, t.LogSetting.SecurityLogSwitchType);

	Check(hWnd, B_PACKET, t.LogSetting.SavePacketLog);
	CbSelect(hWnd, C_PACKET_SWITCH, t.LogSetting.PacketLogSwitchType);

	Check(hWnd, B_PACKET_0_0, t.LogSetting.PacketLogConfig[0] == 0);
	Check(hWnd, B_PACKET_0_1, t.LogSetting.PacketLogConfig[0] == 1);
	Check(hWnd, B_PACKET_0_2, t.LogSetting.PacketLogConfig[0] == 2);

	Check(hWnd, B_PACKET_1_0, t.LogSetting.PacketLogConfig[1] == 0);
	Check(hWnd, B_PACKET_1_1, t.LogSetting.PacketLogConfig[1] == 1);
	Check(hWnd, B_PACKET_1_2, t.LogSetting.PacketLogConfig[1] == 2);

	Check(hWnd, B_PACKET_2_0, t.LogSetting.PacketLogConfig[2] == 0);
	Check(hWnd, B_PACKET_2_1, t.LogSetting.PacketLogConfig[2] == 1);
	Check(hWnd, B_PACKET_2_2, t.LogSetting.PacketLogConfig[2] == 2);

	Check(hWnd, B_PACKET_3_0, t.LogSetting.PacketLogConfig[3] == 0);
	Check(hWnd, B_PACKET_3_1, t.LogSetting.PacketLogConfig[3] == 1);
	Check(hWnd, B_PACKET_3_2, t.LogSetting.PacketLogConfig[3] == 2);

	Check(hWnd, B_PACKET_4_0, t.LogSetting.PacketLogConfig[4] == 0);
	Check(hWnd, B_PACKET_4_1, t.LogSetting.PacketLogConfig[4] == 1);
	Check(hWnd, B_PACKET_4_2, t.LogSetting.PacketLogConfig[4] == 2);

	Check(hWnd, B_PACKET_5_0, t.LogSetting.PacketLogConfig[5] == 0);
	Check(hWnd, B_PACKET_5_1, t.LogSetting.PacketLogConfig[5] == 1);
	Check(hWnd, B_PACKET_5_2, t.LogSetting.PacketLogConfig[5] == 2);

	Check(hWnd, B_PACKET_6_0, t.LogSetting.PacketLogConfig[6] == 0);
	Check(hWnd, B_PACKET_6_1, t.LogSetting.PacketLogConfig[6] == 1);
	Check(hWnd, B_PACKET_6_2, t.LogSetting.PacketLogConfig[6] == 2);

	Check(hWnd, B_PACKET_7_0, t.LogSetting.PacketLogConfig[7] == 0);
	Check(hWnd, B_PACKET_7_1, t.LogSetting.PacketLogConfig[7] == 1);
	Check(hWnd, B_PACKET_7_2, t.LogSetting.PacketLogConfig[7] == 2);

	SmLogDlgUpdate(hWnd, s);
}

// コントロール更新
void SmLogDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool b;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b = IsChecked(hWnd, B_SEC);
	SetEnable(hWnd, S_SEC, b);
	SetEnable(hWnd, C_SEC_SWITCH, b);

	b = IsChecked(hWnd, B_PACKET);
	SetEnable(hWnd, S_PACKET, b);
	SetEnable(hWnd, C_PACKET_SWITCH, b);
	SetEnable(hWnd, S_PACKET_0, b);
	SetEnable(hWnd, S_PACKET_1, b);
	SetEnable(hWnd, S_PACKET_2, b);
	SetEnable(hWnd, S_PACKET_3, b);
	SetEnable(hWnd, S_PACKET_4, b);
	SetEnable(hWnd, S_PACKET_5, b);
	SetEnable(hWnd, S_PACKET_6, b);
	SetEnable(hWnd, S_PACKET_7, b);
	SetEnable(hWnd, B_PACKET_0_0, b); SetEnable(hWnd, B_PACKET_0_1, b); SetEnable(hWnd, B_PACKET_0_2, b);
	SetEnable(hWnd, B_PACKET_1_0, b); SetEnable(hWnd, B_PACKET_1_1, b); SetEnable(hWnd, B_PACKET_1_2, b);
	SetEnable(hWnd, B_PACKET_2_0, b); SetEnable(hWnd, B_PACKET_2_1, b); SetEnable(hWnd, B_PACKET_2_2, b);
	SetEnable(hWnd, B_PACKET_3_0, b); SetEnable(hWnd, B_PACKET_3_1, b); SetEnable(hWnd, B_PACKET_3_2, b);
	SetEnable(hWnd, B_PACKET_4_0, b); SetEnable(hWnd, B_PACKET_4_1, b); SetEnable(hWnd, B_PACKET_4_2, b);
	SetEnable(hWnd, B_PACKET_5_0, b); SetEnable(hWnd, B_PACKET_5_1, b); SetEnable(hWnd, B_PACKET_5_2, b);
	SetEnable(hWnd, B_PACKET_6_0, b); SetEnable(hWnd, B_PACKET_6_1, b); SetEnable(hWnd, B_PACKET_6_2, b);
	SetEnable(hWnd, B_PACKET_7_0, b); SetEnable(hWnd, B_PACKET_7_1, b); SetEnable(hWnd, B_PACKET_7_2, b);
}

// OK
void SmLogDlgOnOk(HWND hWnd, SM_HUB *s)
{
	HUB_LOG g;
	RPC_HUB_LOG t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&g, sizeof(g));
	g.SaveSecurityLog = IsChecked(hWnd, B_SEC);
	g.SavePacketLog = IsChecked(hWnd, B_PACKET);
	g.SecurityLogSwitchType = CbGetSelect(hWnd, C_SEC_SWITCH);
	g.PacketLogSwitchType = CbGetSelect(hWnd, C_PACKET_SWITCH);

	g.PacketLogConfig[0] = IsChecked(hWnd, B_PACKET_0_0) ? 0 : IsChecked(hWnd, B_PACKET_0_1) ? 1 : 2;
	g.PacketLogConfig[1] = IsChecked(hWnd, B_PACKET_1_0) ? 0 : IsChecked(hWnd, B_PACKET_1_1) ? 1 : 2;
	g.PacketLogConfig[2] = IsChecked(hWnd, B_PACKET_2_0) ? 0 : IsChecked(hWnd, B_PACKET_2_1) ? 1 : 2;
	g.PacketLogConfig[3] = IsChecked(hWnd, B_PACKET_3_0) ? 0 : IsChecked(hWnd, B_PACKET_3_1) ? 1 : 2;
	g.PacketLogConfig[4] = IsChecked(hWnd, B_PACKET_4_0) ? 0 : IsChecked(hWnd, B_PACKET_4_1) ? 1 : 2;
	g.PacketLogConfig[5] = IsChecked(hWnd, B_PACKET_5_0) ? 0 : IsChecked(hWnd, B_PACKET_5_1) ? 1 : 2;
	g.PacketLogConfig[6] = IsChecked(hWnd, B_PACKET_6_0) ? 0 : IsChecked(hWnd, B_PACKET_6_1) ? 1 : 2;
	g.PacketLogConfig[7] = IsChecked(hWnd, B_PACKET_7_0) ? 0 : IsChecked(hWnd, B_PACKET_7_1) ? 1 : 2;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	Copy(&t.LogSetting, &g, sizeof(HUB_LOG));

	if (CALL(hWnd, ScSetHubLog(s->Rpc, &t)) == false)
	{
		return;
	}

	EndDialog(hWnd, true);
}

// ログ保存設定ダイアログ
UINT SmLogDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmLogDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case B_SEC:
		case B_PACKET:
			SmLogDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmLogDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// カスケード接続のステータスの表示
bool SmRefreshLinkStatus(HWND hWnd, SM_SERVER *s, void *param)
{
	SM_LINK *k = (SM_LINK *)param;
	RPC_LINK_STATUS t;
	LVB *b;
	// 引数チェック
	if (hWnd == NULL || s == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), k->Hub->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), k->AccountName);

	if (CALL(hWnd, ScGetLinkStatus(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	CmPrintStatusToListView(b, &t.Status);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcLinkStatus(&t);

	return true;
}

// リンクの編集
bool SmLinkEdit(HWND hWnd, SM_HUB *s, wchar_t *name)
{
	CM_ACCOUNT a;
	RPC_CREATE_LINK t;
	bool ret = false;
	// 引数チェック
	if (hWnd == NULL || s == NULL || name == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));
	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), name);

	if (CALL(hWnd, ScGetLink(s->Rpc, &t)) == false)
	{
		return false;
	}

	a.Hub = s;
	a.EditMode = true;
	a.LinkMode = true;
	a.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	a.OnlineFlag = t.Online;
	Copy(a.ClientOption, t.ClientOption, sizeof(CLIENT_OPTION));
	a.ClientAuth = CopyClientAuth(t.ClientAuth);
	Copy(&a.Policy, &t.Policy, sizeof(POLICY));
	a.CheckServerCert = t.CheckServerCert;
	a.ServerCert = CloneX(t.ServerCert);
	a.HideTrustCert = GetCapsBool(s->p->CapsList, "b_support_config_hub");
	FreeRpcCreateLink(&t);

	a.PolicyVer = s->p->PolicyVer;

	if (GetCapsBool(s->p->CapsList, "b_support_cascade_client_cert") == false)
	{
		a.HideClientCertAuth = true;
	}

	a.HideSecureAuth = true;

	ret = CmEditAccountDlg(hWnd, &a);

	FreeX(a.ServerCert);
	Free(a.ClientOption);
	CiFreeClientAuth(a.ClientAuth);

	return ret;
}

// 新しいリンクの作成
bool SmLinkCreate(HWND hWnd, SM_HUB *s)
{
	return SmLinkCreateEx(hWnd, s, false);
}
bool SmLinkCreateEx(HWND hWnd, SM_HUB *s, bool connectNow)
{
	CM_ACCOUNT a;
	bool ret = false;;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));

	a.Hub = s;
	a.EditMode = false;
	a.LinkMode = true;
	a.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	a.OnlineFlag = false;
	a.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	a.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
	Copy(&a.Policy, GetDefaultPolicy(), sizeof(POLICY));
	a.ClientOption->Port = 443;	// デフォルトポート番号
	a.ClientOption->NumRetry = INFINITE;
	a.ClientOption->RetryInterval = 15;
	a.ClientOption->MaxConnection = 8;
	a.ClientOption->UseEncrypt = true;
	a.ClientOption->HalfConnection = false;
	a.ClientOption->AdditionalConnectionInterval = 1;
	a.ClientOption->RequireBridgeRoutingMode = true;
	a.Link_ConnectNow = connectNow;

	a.PolicyVer = s->p->PolicyVer;

	if (GetCapsBool(s->p->CapsList, "b_support_cascade_client_cert") == false)
	{
		a.HideClientCertAuth = true;
	}

	a.HideSecureAuth = true;

	ret = CmEditAccountDlg(hWnd, &a);

	FreeX(a.ServerCert);
	Free(a.ClientOption);
	CiFreeClientAuth(a.ClientAuth);

	return ret;
}

// 初期化
void SmLinkDlgInit(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_LINK);

	FormatText(hWnd, 0, s->HubName);

	LvInit(hWnd, L_LINK);

	LvInsertColumn(hWnd, L_LINK, 0, _UU("SM_LINK_COLUMN_1"), 120);
	LvInsertColumn(hWnd, L_LINK, 1, _UU("SM_LINK_COLUMN_2"), 150);
	LvInsertColumn(hWnd, L_LINK, 2, _UU("SM_LINK_COLUMN_3"), 180);
	LvInsertColumn(hWnd, L_LINK, 3, _UU("SM_LINK_COLUMN_4"), 130);
	LvInsertColumn(hWnd, L_LINK, 4, _UU("SM_LINK_COLUMN_5"), 130);

	LvSetStyle(hWnd, L_LINK, LVS_EX_GRIDLINES);

	SmLinkDlgRefresh(hWnd, s);
}

// コントロール更新
void SmLinkDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool ok = true;
	bool online = false;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_LINK) == false || LvIsMultiMasked(hWnd, L_LINK))
	{
		ok = false;
	}
	else
	{
		online = (bool)LvGetParam(hWnd, L_LINK, LvGetSelected(hWnd, L_LINK));
	}

	SetEnable(hWnd, B_EDIT, ok);
	SetEnable(hWnd, B_ONLINE, ok && (online == false));
	SetEnable(hWnd, B_OFFLINE, ok && online);
	SetEnable(hWnd, IDOK, ok && online);
	SetEnable(hWnd, B_DELETE, ok);
	SetEnable(hWnd, B_RENAME, ok);
}

// 内容更新
void SmLinkDlgRefresh(HWND hWnd, SM_HUB *s)
{
	LVB *b;
	RPC_ENUM_LINK t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScEnumLink(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t.Links[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		UINT icon = ICO_CASCADE;

		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
		StrToUni(tmp2, sizeof(tmp2), e->Hostname);
		StrToUni(tmp3, sizeof(tmp3), e->HubName);

		if (e->Online == false)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_OFFLINE"));
		}
		else
		{
			if (e->Connected)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ONLINE"));
			}
			else
			{
				if (e->LastError != 0)
				{
					UniFormat(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ERROR"), e->LastError, _E(e->LastError));
				}
				else
				{
					UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_CONNECTING"));
				}
			}
		}

		if (e->Online == false)
		{
			icon = ICO_CASCADE_OFFLINE;
		}
		else
		{
			if (e->Connected == false && e->LastError != 0)
			{
				icon = ICO_CASCADE_ERROR;
			}
			else
			{
				icon = ICO_CASCADE;
			}
		}

		LvInsertAdd(b,
			icon, (void *)e->Online, 5,
			e->AccountName, tmp4, tmp1, tmp2, tmp3);
	}

	LvInsertEnd(b, hWnd, L_LINK);

	FreeRpcEnumLink(&t);

	SmLinkDlgUpdate(hWnd, s);
}


// リンク一覧ダイアログプロシージャ
UINT SmLinkDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	wchar_t *str;
	NMHDR *n;
	NMLVDISPINFOW *disp_info;
	NMLVKEYDOWN *key;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	str = LvGetSelectedStr(hWnd, L_LINK, 0);

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmLinkDlgInit(hWnd, s);

		if (link_create_now)
		{
			if (SmLinkCreateEx(hWnd, s, true))
			{
				SmLinkDlgRefresh(hWnd, s);
			}
		}

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			SmLinkDlgRefresh(hWnd, s);
			SetTimer(hWnd, 1, 1000, NULL);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_CREATE:
			// 新規作成
			if (SmLinkCreate(hWnd, s))
			{
				SmLinkDlgRefresh(hWnd, s);
			}
			break;

		case B_EDIT:
			// 編集
			if (str != NULL)
			{
				if (SmLinkEdit(hWnd, s, str))
				{
					SmLinkDlgRefresh(hWnd, s);
				}
			}
			break;

		case B_ONLINE:
			// オンライン
			if (str != NULL)
			{
				RPC_LINK t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), str);
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

				if (CALL(hWnd, ScSetLinkOnline(s->Rpc, &t)))
				{
					SmLinkDlgRefresh(hWnd, s);
				}
			}
			break;

		case B_OFFLINE:
			// オフライン
			if (str != NULL)
			{
				RPC_LINK t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), str);
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_LINK_OFFLINE_MSG"), t.AccountName) == IDYES)
				{
					if (CALL(hWnd, ScSetLinkOffline(s->Rpc, &t)))
					{
						SmLinkDlgRefresh(hWnd, s);
					}
				}
			}
			break;

		case IDOK:
			// 状態
			if (str != NULL)
			{
				wchar_t tmp[MAX_SIZE];
				SM_LINK t;
				Zero(&t, sizeof(t));
				t.Hub = s;
				t.AccountName = str;
				UniFormat(tmp, sizeof(tmp), _UU("SM_LINK_STATUS_CAPTION"), str);
				SmStatusDlg(hWnd, s->p, &t, true, true, tmp,
					ICO_CASCADE, NULL, SmRefreshLinkStatus);
			}
			break;

		case B_DELETE:
			// 削除
			if (str != NULL)
			{
				RPC_LINK t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), str);
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_LINK_DELETE_MSG"), t.AccountName) == IDYES)
				{
					if (CALL(hWnd, ScDeleteLink(s->Rpc, &t)))
					{
						SmLinkDlgRefresh(hWnd, s);
					}
				}
			}
			break;

		case B_REFRESH:
			// 更新
			SmLinkDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case B_RENAME:
			// 名前の変更
			Focus(hWnd, L_LINK);
			LvRename(hWnd, L_LINK, LvGetSelected(hWnd, L_LINK));
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LINK:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				// 選択状態の変更
				SmLinkDlgUpdate(hWnd, s);
				break;

			case LVN_ENDLABELEDITW:
				// 名前の変更
				disp_info = (NMLVDISPINFOW *)n;
				if (disp_info->item.pszText != NULL)
				{
					wchar_t *new_name = disp_info->item.pszText;
					wchar_t *old_name = LvGetStr(hWnd, L_LINK, disp_info->item.iItem, 0);

					if (old_name != NULL)
					{
						if (UniStrCmp(new_name, old_name) != 0 && UniIsEmptyStr(new_name) == false)
						{
							RPC_RENAME_LINK t;
							Zero(&t, sizeof(t));
							StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
							UniStrCpy(t.OldAccountName, sizeof(t.OldAccountName), old_name);
							UniStrCpy(t.NewAccountName, sizeof(t.NewAccountName), new_name);
							if (CALL(hWnd, ScRenameLink(s->Rpc, &t)))
							{
								SmLinkDlgRefresh(hWnd, s);
							}
						}

						Free(old_name);
					}
				}
				break;

			case LVN_KEYDOWN:
				// キー押下
				key = (NMLVKEYDOWN *)n;
				if (key != NULL)
				{
					bool ctrl, alt;
					UINT code = key->wVKey;
					ctrl = (GetKeyState(VK_CONTROL) & 0x8000) == 0 ? false : true;
					alt = (GetKeyState(VK_MENU) & 0x8000) == 0 ? false : true;

					if (code == VK_F2)
					{
						Command(hWnd, B_RENAME);
					}
				}
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	Free(str);

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LINK);

	return 0;
}

// リンク一覧ダイアログ
void SmLinkDlg(HWND hWnd, SM_HUB *s)
{
	SmLinkDlgEx(hWnd, s, false);
}
void SmLinkDlgEx(HWND hWnd, SM_HUB *s, bool createNow)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	link_create_now = createNow;

	Dialog(hWnd, D_SM_LINK, SmLinkDlgProc, s);
}

// 初期化
void SmRadiusDlgInit(HWND hWnd, SM_HUB *s)
{
	RPC_RADIUS t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_TOWER);

	FormatText(hWnd, S_TITLE, s->HubName);
	FormatText(hWnd, S_RADIUS_7, RADIUS_RETRY_INTERVAL, RADIUS_RETRY_TIMEOUT);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScGetHubRadius(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	Check(hWnd, R_USE_RADIUS, StrLen(t.RadiusServerName) != 0);

	if (StrLen(t.RadiusServerName) != 0)
	{
		SetTextA(hWnd, E_HOSTNAME, t.RadiusServerName);
		SetIntEx(hWnd, E_PORT, t.RadiusPort);
		SetTextA(hWnd, E_SECRET1, t.RadiusSecret);
		SetTextA(hWnd, E_SECRET2, t.RadiusSecret);
		SetIntEx(hWnd, E_RADIUS_RETRY_INTERVAL, t.RadiusRetryInterval);
		FocusEx(hWnd, E_HOSTNAME);
	}
	else
	{
		SetInt(hWnd, E_PORT, RADIUS_DEFAULT_PORT);
		SetInt(hWnd, E_RADIUS_RETRY_INTERVAL, RADIUS_RETRY_INTERVAL);
	}

	SmRadiusDlgUpdate(hWnd, s);
}

// コントロール更新
void SmRadiusDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool ok = true;
	bool b, b1;
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b1 = GetCapsBool(s->p->CapsList, "b_support_radius_retry_interval_and_several_servers");
	if(b1 == false)
	{
		Hide(hWnd, S_RADIUS_7);
		Hide(hWnd, S_RADIUS_8);
		Hide(hWnd, S_RADIUS_9);
		Hide(hWnd, E_RADIUS_RETRY_INTERVAL);
	}

	b = IsChecked(hWnd, R_USE_RADIUS);

	SetEnable(hWnd, S_RADIUS_1, b);
	SetEnable(hWnd, S_RADIUS_2, b);
	SetEnable(hWnd, S_RADIUS_3, b);
	SetEnable(hWnd, S_RADIUS3, b);
	SetEnable(hWnd, S_RADIUS_4, b);
	SetEnable(hWnd, S_RADIUS_5, b);
	SetEnable(hWnd, S_RADIUS_6, b);
	SetEnable(hWnd, S_RADIUS_7, b);
	SetEnable(hWnd, S_RADIUS_8, b);
	SetEnable(hWnd, S_RADIUS_9, b);
	SetEnable(hWnd, E_HOSTNAME, b);
	SetEnable(hWnd, E_PORT, b);
	SetEnable(hWnd, E_SECRET1, b);
	SetEnable(hWnd, E_SECRET2, b);
	SetEnable(hWnd, E_RADIUS_RETRY_INTERVAL, b);

	if (b)
	{
		UINT p, m;
		GetTxtA(hWnd, E_SECRET1, tmp1, sizeof(tmp1));
		GetTxtA(hWnd, E_SECRET2, tmp2, sizeof(tmp2));

		if (StrCmp(tmp1, tmp2) != 0)
		{
			ok = false;
		}

		if (IsEmpty(hWnd, E_HOSTNAME))
		{
			ok = false;
		}

		p = GetInt(hWnd, E_PORT);

		if (p == 0 || p >= 65536)
		{
			ok = false;
		}

		m = GetInt(hWnd, E_RADIUS_RETRY_INTERVAL);
		if (m > RADIUS_RETRY_TIMEOUT || m < RADIUS_RETRY_INTERVAL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// OK ボタン
void SmRadiusDlgOnOk(HWND hWnd, SM_HUB *s)
{
	RPC_RADIUS t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (IsChecked(hWnd, R_USE_RADIUS))
	{
		GetTxtA(hWnd, E_HOSTNAME, t.RadiusServerName, sizeof(t.RadiusServerName));
		t.RadiusPort = GetInt(hWnd, E_PORT);
		GetTxtA(hWnd, E_SECRET1,t.RadiusSecret, sizeof(t.RadiusSecret));
		t.RadiusRetryInterval = GetInt(hWnd, E_RADIUS_RETRY_INTERVAL);
	}

	if (CALL(hWnd, ScSetHubRadius(s->Rpc, &t)) == false)
	{
		return;
	}

	EndDialog(hWnd, true);
}


// Radius ダイアログ プロシージャ
UINT SmRadiusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmRadiusDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_HOSTNAME:
		case E_PORT:
		case E_SECRET1:
		case E_SECRET2:
		case E_RADIUS_RETRY_INTERVAL:
		case R_USE_RADIUS:
			SmRadiusDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmRadiusDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case R_USE_RADIUS:
			if (IsChecked(hWnd, R_USE_RADIUS))
			{
				FocusEx(hWnd, E_HOSTNAME);
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Radius 設定ダイアログ
void SmRadiusDlg(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_RADIUS, SmRadiusDlgProc, s);
}


// 初期化
void SmEditAccessInit(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PASS);

	GetTxt(hWnd, 0, tmp, sizeof(tmp));

	UniStrCat(tmp, sizeof(tmp), s->Access->IsIPv6 ? L" (IPv6)" : L" (IPv4)");

	SetText(hWnd, 0, tmp);

	s->Inited = false;
	a = s->Access;

	SetText(hWnd, E_NOTE, a->Note);

	Check(hWnd, R_DISCARD, a->Discard);
	Check(hWnd, R_PASS, a->Discard == false);
	SetIntEx(hWnd, E_PRIORITY, a->Priority);

	if (a->IsIPv6 == false)
	{
		// IPv4
		if (a->SrcIpAddress == 0 && a->SrcSubnetMask == 0)
		{
			Check(hWnd, R_SRC_ALL, true);
		}
		else
		{
			IpSet(hWnd, E_SRC_IP, a->SrcIpAddress);
			IpSet(hWnd, E_SRC_MASK, a->SrcSubnetMask);
		}

		if (a->DestIpAddress == 0 && a->DestSubnetMask == 0)
		{
			Check(hWnd, R_DST_ALL, true);
		}
		else
		{
			IpSet(hWnd, E_DST_IP, a->DestIpAddress);
			IpSet(hWnd, E_DST_MASK, a->DestSubnetMask);
		}
	}
	else
	{
		// IPv6
		if (IsZeroIP6Addr(&a->SrcIpAddress6) && IsZeroIP6Addr(&a->SrcSubnetMask6))
		{
			Check(hWnd, R_SRC_ALL, true);
		}
		else
		{
			char tmp[MAX_SIZE];

			IP6AddrToStr(tmp, sizeof(tmp), &a->SrcIpAddress6);
			SetTextA(hWnd, E_SRC_IP_V6, tmp);

			Mask6AddrToStrEx(tmp, sizeof(tmp), &a->SrcSubnetMask6, false);

			if (IsNum(tmp))
			{
				StrCatLeft(tmp, sizeof(tmp), "/");
			}

			SetTextA(hWnd, E_SRC_MASK_V6, tmp);
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) && IsZeroIP6Addr(&a->DestSubnetMask6))
		{
			Check(hWnd, R_DST_ALL, true);
		}
		else
		{
			char tmp[MAX_SIZE];

			IP6AddrToStr(tmp, sizeof(tmp), &a->DestIpAddress6);
			SetTextA(hWnd, E_DST_IP_V6, tmp);

			Mask6AddrToStrEx(tmp, sizeof(tmp), &a->DestSubnetMask6, false);

			if (IsNum(tmp))
			{
				StrCatLeft(tmp, sizeof(tmp), "/");
			}

			SetTextA(hWnd, E_DST_MASK_V6, tmp);
		}
	}

	CbSetHeight(hWnd, C_PROTOCOL, 18);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_1"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_2"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_3"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_4"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_5"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_6"), 0);

	switch (a->Protocol)
	{
	case 0:
		CbSelectIndex(hWnd, C_PROTOCOL, 0);
		break;
	case 6:
		CbSelectIndex(hWnd, C_PROTOCOL, 1);
		break;
	case 17:
		CbSelectIndex(hWnd, C_PROTOCOL, 2);
		break;
	case 1:
		CbSelectIndex(hWnd, C_PROTOCOL, 3);
		break;
	case 58:
		CbSelectIndex(hWnd, C_PROTOCOL, 4);
		break;
	default:
		CbSelectIndex(hWnd, C_PROTOCOL, 5);
		break;
	}

	Check(hWnd, R_DISABLE, a->Active ? false : true);

	SetIntEx(hWnd, E_IP_PROTO, a->Protocol);

	SetIntEx(hWnd, E_SRC_PORT_1, a->SrcPortStart);
	SetIntEx(hWnd, E_SRC_PORT_2, a->SrcPortEnd);
	SetIntEx(hWnd, E_DST_PORT_1, a->DestPortStart);
	SetIntEx(hWnd, E_DST_PORT_2, a->DestPortEnd);

	SetTextA(hWnd, E_USERNAME1, a->SrcUsername);
	SetTextA(hWnd, E_USERNAME2, a->DestUsername);

	if(a->CheckSrcMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->SrcMacAddress);
		MacToStr(mask, sizeof(mask), a->SrcMacMask);
		SetTextA(hWnd, E_SRC_MAC, mac); 
		SetTextA(hWnd, E_SRC_MAC_MASK, mask);
	}
	if(a->CheckDstMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->DstMacAddress);
		MacToStr(mask, sizeof(mask), a->DstMacMask);
		SetTextA(hWnd, E_DST_MAC, mac); 
		SetTextA(hWnd, E_DST_MAC_MASK, mask);
	}
	Check(hWnd, R_CHECK_SRC_MAC, !a->CheckSrcMac);
	Check(hWnd, R_CHECK_DST_MAC, !a->CheckDstMac);

	Check(hWnd, R_CHECK_TCP_STATE, a->CheckTcpState);
	if(a->CheckTcpState != false)
	{
		Check(hWnd, R_ESTABLISHED, a->Established);
		Check(hWnd, R_UNESTABLISHED, !a->Established);
	}

	if (GetCapsBool(s->Hub->p->CapsList, "b_support_acl_group") == false)
	{
		SetText(hWnd, S_STATIC11, _UU("D_SM_EDIT_ACCESS@STATIC11_OLD"));
		SetText(hWnd, S_STATIC12, _UU("D_SM_EDIT_ACCESS@STATIC12_OLD"));
		SetText(hWnd, S_STATIC15, _UU("D_SM_EDIT_ACCESS@STATIC15_OLD"));
	}

	s->Inited = true;

	SmEditAccessUpdate(hWnd, s);
}

// コントロール更新
void SmEditAccessUpdate(HWND hWnd, SM_EDIT_ACCESS *s)
{
	bool ok = true;
	bool tcp;
	bool b;
	bool check_srcmac, check_dstmac, support_mac;
	bool check_state, support_check_state;
	char srcmac[MAX_SIZE], srcmac_mask[MAX_SIZE], dstmac[MAX_SIZE], dstmac_mask[MAX_SIZE];
	char tmp[MAX_SIZE];
	wchar_t unitmp[MAX_SIZE];
	ACCESS *a;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->Inited == false)
	{
		return;
	}

	a = s->Access;

	GetTxt(hWnd, E_NOTE, a->Note, sizeof(a->Note));

	a->Discard = IsChecked(hWnd, R_DISCARD);

	a->Priority = GetInt(hWnd, E_PRIORITY);
	if (a->Priority == 0)
	{
		ok = false;
	}


	b = IsChecked(hWnd, R_SRC_ALL) ? false : true;
	if (b == false)
	{
		if (a->IsIPv6 == false)
		{
			a->SrcIpAddress = 0;
			a->SrcSubnetMask = 0;
		}
		else
		{
			Zero(&a->SrcIpAddress6, sizeof(IPV6_ADDR));
			Zero(&a->SrcSubnetMask6, sizeof(IPV6_ADDR));
		}
	}
	else
	{
		if (a->IsIPv6 == false)
		{
			if (IpIsFilled(hWnd, E_SRC_IP) == false || IpIsFilled(hWnd, E_SRC_MASK) == false)
			{
				ok = false;
			}
			else
			{
				a->SrcIpAddress = IpGet(hWnd, E_SRC_IP);
				a->SrcSubnetMask = IpGet(hWnd, E_SRC_MASK);
			}
		}
		else
		{
			char tmp1[MAX_SIZE];
			char tmp2[MAX_SIZE];

			GetTxtA(hWnd, E_SRC_IP_V6, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_SRC_MASK_V6, tmp2, sizeof(tmp2));

			if (StrToIP6Addr(&a->SrcIpAddress6, tmp1) == false ||
				StrToMask6Addr(&a->SrcSubnetMask6, tmp2) == false)
			{
				ok = false;
			}
		}
	}
	SetEnable(hWnd, S_SRC_IP_1, b);
	SetEnable(hWnd, S_SRC_IP_2, b);
	SetEnable(hWnd, S_SRC_IP_3, b);
	SetEnable(hWnd, E_SRC_IP, b);
	SetEnable(hWnd, E_SRC_MASK, b);
	SetEnable(hWnd, E_SRC_IP_V6, b);
	SetEnable(hWnd, E_SRC_MASK_V6, b);

	b = IsChecked(hWnd, R_DST_ALL) ? false : true;
	if (b == false)
	{
		if (a->IsIPv6 == false)
		{
			a->DestIpAddress = 0;
			a->DestSubnetMask = 0;
		}
		else
		{
			Zero(&a->DestIpAddress6, sizeof(IPV6_ADDR));
			Zero(&a->DestSubnetMask6, sizeof(IPV6_ADDR));
		}
	}
	else
	{
		if (a->IsIPv6 == false)
		{
			if (IpIsFilled(hWnd, E_DST_IP) == false || IpIsFilled(hWnd, E_DST_MASK) == false)
			{
				ok = false;
			}
			else
			{
				a->DestIpAddress = IpGet(hWnd, E_DST_IP);
				a->DestSubnetMask = IpGet(hWnd, E_DST_MASK);
			}
		}
		else
		{
			char tmp1[MAX_SIZE];
			char tmp2[MAX_SIZE];

			GetTxtA(hWnd, E_DST_IP_V6, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_DST_MASK_V6, tmp2, sizeof(tmp2));

			if (StrToIP6Addr(&a->DestIpAddress6, tmp1) == false ||
				StrToMask6Addr(&a->DestSubnetMask6, tmp2) == false)
			{
				ok = false;
			}
		}
	}
	SetEnable(hWnd, S_IP_DST_1, b);
	SetEnable(hWnd, S_IP_DST_2, b);
	SetEnable(hWnd, S_IP_DST_3, b);
	SetEnable(hWnd, E_DST_IP, b);
	SetEnable(hWnd, E_DST_MASK, b);
	SetEnable(hWnd, E_DST_IP_V6, b);
	SetEnable(hWnd, E_DST_MASK_V6, b);

	a->Protocol = GetInt(hWnd, C_PROTOCOL);

	GetTxtA(hWnd, C_PROTOCOL, tmp, sizeof(tmp));
	GetTxt(hWnd, C_PROTOCOL, unitmp, sizeof(unitmp));

	if (UniStrCmpi(unitmp, _UU("SM_ACCESS_PROTO_6")) == 0 || StrCmpi(tmp, _SS("SM_ACCESS_PROTO_6")) == 0)
	{
		a->Protocol = GetInt(hWnd, E_IP_PROTO);

		if (IsEmpty(hWnd, E_IP_PROTO))
		{
			ok = false;
		}

		Enable(hWnd, S_PROTOID);
		Enable(hWnd, E_IP_PROTO);
	}
	else
	{
		Disable(hWnd, E_IP_PROTO);
		Disable(hWnd, S_PROTOID);
	}

	tcp = false;
	if (a->Protocol == 17 || a->Protocol == 6)
	{
		tcp = true;
	}

	SetEnable(hWnd, S_TCP_1, tcp);
	SetEnable(hWnd, S_TCP_2, tcp);
	SetEnable(hWnd, S_TCP_3, tcp);
	SetEnable(hWnd, S_TCP_4, tcp);
	SetEnable(hWnd, S_TCP_5, tcp);
	SetEnable(hWnd, S_TCP_6, tcp);
	SetEnable(hWnd, S_TCP_7, tcp);
	SetEnable(hWnd, E_SRC_PORT_1, tcp);
	SetEnable(hWnd, E_SRC_PORT_2, tcp);
	SetEnable(hWnd, E_DST_PORT_1, tcp);
	SetEnable(hWnd, E_DST_PORT_2, tcp);

	if (tcp == false)
	{
		a->SrcPortEnd = a->SrcPortStart = a->DestPortEnd = a->DestPortStart = 0;
	}
	else
	{
		a->SrcPortStart = GetInt(hWnd, E_SRC_PORT_1);
		a->SrcPortEnd = GetInt(hWnd, E_SRC_PORT_2);
		a->DestPortStart = GetInt(hWnd, E_DST_PORT_1);
		a->DestPortEnd = GetInt(hWnd, E_DST_PORT_2);

		if (a->SrcPortStart != 0)
		{
			if (a->SrcPortEnd != 0)
			{
				if (a->SrcPortStart > a->SrcPortEnd)
				{
					ok = false;
				}
			}
		}
		else
		{
			if (a->SrcPortEnd != 0)
			{
				ok = false;
			}
		}

		if (a->DestPortStart != 0)
		{
			if (a->DestPortEnd != 0)
			{
				if (a->DestPortStart > a->DestPortEnd)
				{
					ok = false;
				}
			}
		}
		else
		{
			if (a->DestPortEnd != 0)
			{
				ok = false;
			}
		}

		if (a->DestPortEnd < a->DestPortStart)
		{
			a->DestPortEnd = a->DestPortStart;
		}

		if (a->SrcPortEnd < a->SrcPortStart)
		{
			a->SrcPortEnd = a->SrcPortStart;
		}
	}

	a->SrcUsernameHash = a->DestUsernameHash = 0;
	GetTxtA(hWnd, E_USERNAME1, a->SrcUsername, sizeof(a->SrcUsername));
	GetTxtA(hWnd, E_USERNAME2, a->DestUsername, sizeof(a->DestUsername));

	Trim(a->SrcUsername);
	/*
	if (StrLen(a->SrcUsername) != 0)
	{
		if (IsUserName(a->SrcUsername) == false)
		{
			ok = false;
		}
	}*/

	Trim(a->DestUsername);
	/*
	if (StrLen(a->DestUsername) != 0)
	{
		if (IsUserName(a->DestUsername) == false)
		{
			ok = false;
		}
	}*/

	support_mac = GetCapsBool(s->Hub->p->CapsList, "b_support_check_mac");

	// 送信元 MAC アドレスの設定
	check_srcmac = a->CheckSrcMac = support_mac && (IsChecked(hWnd, R_CHECK_SRC_MAC) ? false : true);
	if(check_srcmac == false)
	{
		Zero(a->SrcMacAddress, sizeof(a->SrcMacAddress));
		Zero(a->SrcMacMask, sizeof(a->SrcMacMask));
	}
	else
	{
		GetTxtA(hWnd, E_SRC_MAC, srcmac, sizeof(srcmac));
		GetTxtA(hWnd, E_SRC_MAC_MASK, srcmac_mask, sizeof(srcmac_mask));
		Trim(srcmac);
		Trim(srcmac_mask);
		if(StrLen(srcmac) != 0 && StrLen(srcmac_mask) != 0)
		{
			UCHAR mac[6], mask[6];
			if(StrToMac(mac, srcmac) && StrToMac(mask, srcmac_mask))
			{
				Copy(a->SrcMacAddress, mac, 6);
				Copy(a->SrcMacMask, mask, 6);
			}
			else
			{
				ok = false;
			}
		}
		else
		{
			ok = false;
		}
	}
	SetEnable(hWnd, S_CHECK_SRC_MAC, support_mac);
	SetEnable(hWnd, R_CHECK_SRC_MAC, support_mac);
	SetEnable(hWnd, S_SRC_MAC, check_srcmac);
	SetEnable(hWnd, S_SRC_MAC_MASK, check_srcmac);
	SetEnable(hWnd, E_SRC_MAC, check_srcmac);
	SetEnable(hWnd, E_SRC_MAC_MASK, check_srcmac);

	// 宛先 MAC アドレスの設定
	check_dstmac = a->CheckDstMac = support_mac && (IsChecked(hWnd, R_CHECK_DST_MAC) ? false : true);
	if(check_dstmac == false)
	{
		Zero(a->DstMacAddress, sizeof(a->DstMacAddress));
		Zero(a->DstMacMask, sizeof(a->DstMacMask));
	}
	else
	{
		GetTxtA(hWnd, E_DST_MAC, dstmac, sizeof(dstmac));
		GetTxtA(hWnd, E_DST_MAC_MASK, dstmac_mask, sizeof(dstmac_mask));
		Trim(dstmac);
		Trim(dstmac_mask);
		if(StrLen(dstmac) != 0 && StrLen(dstmac_mask) != 0)
		{
			UCHAR mac[6], mask[6];
			if(StrToMac(mac, dstmac) && StrToMac(mask, dstmac_mask))
			{
				Copy(a->DstMacAddress, mac, 6);
				Copy(a->DstMacMask, mask, 6);
			}
			else
			{
				ok = false;
			}
		}
		else
		{
			ok = false;
		}
	}
	SetEnable(hWnd, S_CHECK_DST_MAC, support_mac);
	SetEnable(hWnd, R_CHECK_DST_MAC, support_mac);
	SetEnable(hWnd, S_DST_MAC, check_dstmac);
	SetEnable(hWnd, S_DST_MAC_MASK, check_dstmac);
	SetEnable(hWnd, E_DST_MAC, check_dstmac);
	SetEnable(hWnd, E_DST_MAC_MASK, check_dstmac);

	SetEnable(hWnd, S_MAC_NOTE, check_srcmac || check_dstmac);

	// TCP コネクションの状態
	support_check_state = GetCapsBool(s->Hub->p->CapsList, "b_support_check_tcp_state") && a->Protocol == 6;
	SetEnable(hWnd, R_CHECK_TCP_STATE, support_check_state);
	check_state = a->CheckTcpState = support_check_state && IsChecked(hWnd, R_CHECK_TCP_STATE);

	a->Established = IsChecked(hWnd, R_ESTABLISHED) && check_state;
	SetEnable(hWnd, R_ESTABLISHED, check_state);
	SetEnable(hWnd, R_UNESTABLISHED, check_state);
	if(check_state != false && IsChecked(hWnd, R_ESTABLISHED) == false && IsChecked(hWnd, R_UNESTABLISHED) == false)
	{
		ok = false;
	}

	a->Active = IsChecked(hWnd, R_DISABLE) ? false : true;

	SetEnable(hWnd, B_SIMULATION, a->Discard == false && GetCapsBool(s->Hub->p->CapsList, "b_support_ex_acl"));

	SetEnable(hWnd, IDOK, ok);
}

// OK クリック
void SmEditAccessOnOk(HWND hWnd, SM_EDIT_ACCESS *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmEditAccessUpdate(hWnd, s);

	EndDialog(hWnd, true);
}


// アクセスリスト編集ダイアログ
UINT SmEditAccessDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_ACCESS *s = (SM_EDIT_ACCESS *)param;
	UINT ico;
	ACCESS *a;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmEditAccessInit(hWnd, s);

		goto REFRESH_ICON;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_PASS:
		case R_DISCARD:
		case E_PRIORITY:
		case R_SRC_ALL:
		case E_SRC_IP:
		case E_SRC_MASK:
		case R_DST_ALL:
		case E_DST_MASK:
		case E_SRC_IP_V6:
		case E_SRC_MASK_V6:
		case E_DST_MASK_V6:
		case E_DST_IP_V6:
		case C_PROTOCOL:
		case E_SRC_PORT_1:
		case E_SRC_PORT_2:
		case E_DST_PORT_1:
		case E_DST_PORT_2:
		case E_USERNAME1:
		case E_USERNAME2:
		case R_DISABLE:
		case E_IP_PROTO:
		case R_CHECK_SRC_MAC:
		case E_SRC_MAC:
		case E_SRC_MAC_MASK:
		case R_CHECK_DST_MAC:
		case E_DST_MAC:
		case E_DST_MAC_MASK:
		case R_CHECK_TCP_STATE:
		case R_ESTABLISHED:
		case R_UNESTABLISHED:
			SmEditAccessUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case B_USER1:
			if (GetTxtA(hWnd, E_USERNAME1, tmp, sizeof(tmp)))
			{
				char *ret = SmSelectUserDlgEx(hWnd, s->Hub, tmp, GetCapsBool(s->Hub->p->CapsList, "b_support_acl_group"));
				if (ret == NULL)
				{
					SetTextA(hWnd, E_USERNAME1, "");
				}
				else
				{
					SetTextA(hWnd, E_USERNAME1, ret);
					Free(ret);
				}
				FocusEx(hWnd, E_USERNAME1);
			}
			break;

		case B_USER2:
			if (GetTxtA(hWnd, E_USERNAME2, tmp, sizeof(tmp)))
			{
				char *ret = SmSelectUserDlgEx(hWnd, s->Hub, tmp, GetCapsBool(s->Hub->p->CapsList, "b_support_acl_group"));
				if (ret == NULL)
				{
					SetTextA(hWnd, E_USERNAME2, "");
				}
				else
				{
					SetTextA(hWnd, E_USERNAME2, ret);
					Free(ret);
				}
				FocusEx(hWnd, E_USERNAME2);
			}
			break;

		case IDOK:
			// OK ボタン
			SmEditAccessOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case R_SRC_ALL:
			if (IsChecked(hWnd, R_SRC_ALL) == false)
			{
				if (s->Access->IsIPv6)
				{
					FocusEx(hWnd, E_SRC_IP_V6);
				}
				else
				{
					Focus(hWnd, E_SRC_IP);
				}
			}
			break;

		case R_DST_ALL:
			if (IsChecked(hWnd, R_DST_ALL) == false)
			{
				if (s->Access->IsIPv6)
				{
					FocusEx(hWnd, E_DST_IP_V6);
				}
				else
				{
					Focus(hWnd, E_DST_IP);
				}
			}
			break;
		case R_CHECK_SRC_MAC:
			if(IsChecked(hWnd, R_CHECK_SRC_MAC) == false)
			{
				Focus(hWnd, E_SRC_MAC);
			}
			break;
		case R_CHECK_DST_MAC:
			if(IsChecked(hWnd, R_CHECK_DST_MAC) == false)
			{
				Focus(hWnd, E_DST_MAC);
			}
			break;

		case R_PASS:
		case R_DISCARD:
		case R_DISABLE:
REFRESH_ICON:
			a = s->Access;
			if (a->Discard == false && a->Active == false)
			{
				ico = ICO_PASS_DISABLE;
			}
			else if (a->Discard == false && a->Active)
			{
				ico = ICO_PASS;
			}
			else if (a->Discard && a->Active == false)
			{
				ico = ICO_DISCARD_DISABLE;
			}
			else
			{
				ico = ICO_DISCARD;
			}

			SetIcon(hWnd, S_ICON, ico);
			break;

		case B_SIMULATION:
			// シミュレーション
			Dialog(hWnd, D_SM_SIMULATION, SmSimulationDlg, s);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 遅延・ジッタ・パケットロスダイアログ
UINT SmSimulationDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_ACCESS *s = (SM_EDIT_ACCESS *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmSimulationInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_DELAY:
		case E_JITTER:
		case E_LOSS:
			SmSimulationUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmSimulationOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case C_DELAY:
			SmSimulationUpdate(hWnd, s);
			if (IsChecked(hWnd, C_DELAY))
			{
				FocusEx(hWnd, E_DELAY);
			}
			break;

		case C_JITTER:
			SmSimulationUpdate(hWnd, s);
			if (IsChecked(hWnd, C_JITTER))
			{
				FocusEx(hWnd, E_JITTER);
			}
			break;

		case C_LOSS:
			SmSimulationUpdate(hWnd, s);
			if (IsChecked(hWnd, C_LOSS))
			{
				FocusEx(hWnd, E_LOSS);
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 遅延・ジッタ・パケットロスダイアログの更新
void SmSimulationUpdate(HWND hWnd, SM_EDIT_ACCESS *s)
{
	bool b1, b2, b3;
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b1 = IsChecked(hWnd, C_DELAY);
	b2 = IsChecked(hWnd, C_JITTER);
	b3 = IsChecked(hWnd, C_LOSS);

	SetEnable(hWnd, S_DELAY, b1);
	SetEnable(hWnd, S_DELAY2, b1);
	SetEnable(hWnd, E_DELAY, b1);

	SetEnable(hWnd, C_JITTER, b1);

	if (b1 == false)
	{
		b2 = false;
	}

	SetEnable(hWnd, S_JITTER, b2);
	SetEnable(hWnd, S_JITTER2, b2);
	SetEnable(hWnd, E_JITTER, b2);

	SetEnable(hWnd, S_LOSS, b3);
	SetEnable(hWnd, S_LOSS2, b3);
	SetEnable(hWnd, E_LOSS, b3);

	if (b1)
	{
		UINT i = GetInt(hWnd, E_DELAY);
		if (i == 0 || i > HUB_ACCESSLIST_DELAY_MAX)
		{
			ok = false;
		}
	}

	if (b2)
	{
		UINT i = GetInt(hWnd, E_JITTER);
		if (i == 0 || i > HUB_ACCESSLIST_JITTER_MAX)
		{
			ok = false;
		}
	}

	if (b3)
	{
		UINT i = GetInt(hWnd, E_LOSS);
		if (i == 0 || i > HUB_ACCESSLIST_LOSS_MAX)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// 遅延・ジッタ・パケットロスダイアログの初期化
void SmSimulationInit(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	a = s->Access;

	Check(hWnd, C_DELAY, a->Delay != 0);
	Check(hWnd, C_JITTER, a->Jitter != 0);
	Check(hWnd, C_LOSS, a->Loss != 0);

	SetIntEx(hWnd, E_DELAY, a->Delay);
	if (a->Delay != 0)
	{
		SetIntEx(hWnd, E_JITTER, a->Jitter);
	}
	SetIntEx(hWnd, E_LOSS, a->Loss);

	SmSimulationUpdate(hWnd, s);

	if (a->Delay != 0)
	{
		FocusEx(hWnd, E_DELAY);
	}
	else
	{
		Focus(hWnd, C_DELAY);
	}
}

// 遅延・ジッタ・パケットロスダイアログの保存
void SmSimulationOnOk(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	a = s->Access;

	a->Jitter = a->Loss = a->Delay = 0;

	if (IsChecked(hWnd, C_DELAY))
	{
		a->Delay = GetInt(hWnd, E_DELAY);
	}

	if (IsChecked(hWnd, C_JITTER))
	{
		a->Jitter = GetInt(hWnd, E_JITTER);
	}

	if (IsChecked(hWnd, C_LOSS))
	{
		a->Loss = GetInt(hWnd, E_LOSS);
	}

	EndDialog(hWnd, 1);
}

// アクセスリストの編集
bool SmEditAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *a)
{
	SM_EDIT_ACCESS edit;
	bool ret;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&edit, sizeof(edit));
	edit.AccessList = s;
	edit.EditMode = true;
	edit.Access = ZeroMalloc(sizeof(ACCESS));
	edit.Hub = s->Hub;
	Copy(edit.Access, a, sizeof(ACCESS));

	if (edit.Access->IsIPv6 == false)
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS, SmEditAccessDlg, &edit);
	}
	else
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS_V6, SmEditAccessDlg, &edit);
	}

	if (ret)
	{
		Copy(a, edit.Access, sizeof(ACCESS));
		Free(edit.Access);
		Sort(s->AccessList);

		// ID を振り直す
		for (i = 0;i < LIST_NUM(s->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(s->AccessList, i);
			a->Id = (i + 1);
		}
	}
	else
	{
		Free(edit.Access);
	}

	return ret;
}

// アクセスリストの追加
bool SmAddAccess(HWND hWnd, SM_ACCESS_LIST *s, bool ipv6)
{
	SM_EDIT_ACCESS edit;
	bool ret;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&edit, sizeof(edit));
	edit.AccessList = s;
	edit.Access = ZeroMalloc(sizeof(ACCESS));
	edit.Access->Active = true;
	edit.Access->Priority = 0;
	edit.Access->IsIPv6 = ipv6;
	edit.Hub = s->Hub;

	// 新しい優先順位の取得
	for (i = 0;i < LIST_NUM(s->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(s->AccessList, i);
		edit.Access->Priority = MAX(edit.Access->Priority, a->Priority);
	}

	if (edit.Access->Priority == 0)
	{
		edit.Access->Priority = 900;
	}

	edit.Access->Priority += 100;

	if (edit.Access->IsIPv6 == false)
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS, SmEditAccessDlg, &edit);
	}
	else
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS_V6, SmEditAccessDlg, &edit);
	}

	if (ret)
	{
		Insert(s->AccessList, edit.Access);

		// ID を振り直す
		for (i = 0;i < LIST_NUM(s->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(s->AccessList, i);
			a->Id = (i + 1);
		}
	}
	else
	{
		Free(edit.Access);
	}

	return ret;
}

// 初期化
void SmAccessListInit(HWND hWnd, SM_ACCESS_LIST *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PASS);
	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	LvInit(hWnd, L_ACCESS_LIST);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 0, _UU("SM_ACCESS_COLUMN_0"), 60);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 1, _UU("SM_ACCESS_COLUMN_1"), 60);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 2, _UU("SM_ACCESS_COLUMN_2"), 60);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 3, _UU("SM_ACCESS_COLUMN_3"), 70);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 4, _UU("SM_ACCESS_COLUMN_4"), 150);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 5, _UU("SM_ACCESS_COLUMN_5"), 600);

	LvSetStyle(hWnd, L_ACCESS_LIST, LVS_EX_GRIDLINES);

	SetEnable(hWnd, B_ADD_V6, GetCapsBool(s->Hub->p->CapsList, "b_support_ipv6_acl"));

	SmAccessListRefresh(hWnd, s);
}

// コントロール更新
void SmAccessListUpdate(HWND hWnd, SM_ACCESS_LIST *s)
{
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_ACCESS_LIST) == false || LvIsMultiMasked(hWnd, L_ACCESS_LIST))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, B_DELETE, ok);

	SetEnable(hWnd, B_CREATE, LIST_NUM(s->AccessList) < MAX_ACCESSLISTS);
}

// 内容更新
void SmAccessListRefresh(HWND hWnd, SM_ACCESS_LIST *s)
{
	LVB *b;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b = LvInsertStart();

	Sort(s->AccessList);

	for (i = 0;i < LIST_NUM(s->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(s->AccessList, i);
		char tmp[MAX_SIZE];
		UINT ico = ICO_PASS;
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		GetAccessListStr(tmp, sizeof(tmp), a);
		UniToStru(tmp1, a->Priority);
		StrToUni(tmp2, sizeof(tmp2), tmp);

		if (a->Discard == false && a->Active == false)
		{
			ico = ICO_PASS_DISABLE;
		}
		else if (a->Discard == false && a->Active)
		{
			ico = ICO_PASS;
		}
		else if (a->Discard && a->Active == false)
		{
			ico = ICO_DISCARD_DISABLE;
		}
		else
		{
			ico = ICO_DISCARD;
		}

		UniToStru(tmp3, a->Id);

		LvInsertAdd(b, ico, (void *)a, 6,
			tmp3,
			a->Discard ? _UU("SM_ACCESS_DISCARD") : _UU("SM_ACCESS_PASS"),
			a->Active ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"),
			tmp1,
			a->Note,
			tmp2);
	}

	LvInsertEnd(b, hWnd, L_ACCESS_LIST);
	LvSortEx(hWnd, L_ACCESS_LIST, 0, false, true);

	SmAccessListUpdate(hWnd, s);
}

// アクセスリストダイアログプロシージャ
UINT SmAccessListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_ACCESS_LIST *s = (SM_ACCESS_LIST *)param;
	NMHDR *n;
	ACCESS *a;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmAccessListInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			// 追加 (IPv4)
			if (SmAddAccess(hWnd, s, false))
			{
				SmAccessListRefresh(hWnd, s);
			}
			break;

		case B_ADD_V6:
			// 追加 (IPv6)
			if (SmAddAccess(hWnd, s, true))
			{
				SmAccessListRefresh(hWnd, s);
			}
			break;

		case IDOK:
			// 編集
			a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));
			if (a != NULL)
			{
				if (SmEditAccess(hWnd, s, a))
				{
					SmAccessListRefresh(hWnd, s);
				}
			}
			break;

		case B_DELETE:
			// 削除
			a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));
			if (a != NULL)
			{
				UINT i;
				if (IsInList(s->AccessList, a))
				{
					Delete(s->AccessList, a);
					Free(a);
					// ID を振り直す
					for (i = 0;i < LIST_NUM(s->AccessList);i++)
					{
						ACCESS *a = LIST_DATA(s->AccessList, i);
						a->Id = (i + 1);
					}
					SmAccessListRefresh(hWnd, s);
				}
			}
			break;

		case B_SAVE:
			// 保存
			{
				UINT i;
				bool ok;
				// アクセスリストを保存する
				RPC_ENUM_ACCESS_LIST t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
				t.NumAccess = LIST_NUM(s->AccessList);
				t.Accesses = ZeroMalloc(sizeof(ACCESS) * t.NumAccess);
				for (i = 0;i < LIST_NUM(s->AccessList);i++)
				{
					ACCESS *access = LIST_DATA(s->AccessList, i);
					Copy(&t.Accesses[i], access, sizeof(ACCESS));
				}

				ok = CALL(hWnd, ScSetAccessList(s->Rpc, &t));
				FreeRpcEnumAccessList(&t);
				if (ok)
				{
					EndDialog(hWnd, true);
				}
			}
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_ACCESS_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmAccessListUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_ACCESS_LIST);

	return 0;
}


// アクセスリストダイアログ
void SmAccessListDlg(HWND hWnd, SM_HUB *s)
{
	SM_ACCESS_LIST a;
	UINT i;
	RPC_ENUM_ACCESS_LIST t;
	bool ret;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.Hub = s;
	a.Rpc = s->Rpc;

	// アクセスリストの取得
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScEnumAccess(s->Rpc, &t)) == false)
	{
		return;
	}

	a.AccessList = NewListFast(CmpAccessList);
	// リストに追加
	for (i = 0;i < t.NumAccess;i++)
	{
		ACCESS *access = ZeroMalloc(sizeof(ACCESS));
		Copy(access, &t.Accesses[i], sizeof(ACCESS));

		Add(a.AccessList, access);
	}

	// ソート
	Sort(a.AccessList);
	FreeRpcEnumAccessList(&t);

	// ダイアログ表示
	ret = Dialog(hWnd, D_SM_ACCESS_LIST, SmAccessListProc, &a);

	for (i = 0;i < LIST_NUM(a.AccessList);i++)
	{
		ACCESS *access = LIST_DATA(a.AccessList, i);
		Free(access);
	}
	ReleaseList(a.AccessList);
}

// 初期化
void SmEditGroupDlgInit(HWND hWnd, SM_EDIT_GROUP *g)
{
	RPC_SET_GROUP *group;
	LVB *b;
	// 引数チェック
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_GROUP);

	group = &g->SetGroup;

	if (g->EditMode == false)
	{
		SetText(hWnd, 0, _UU("SM_EDIT_GROUP_CAPTION_1"));
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_GROUP_CAPTION_2"), group->Name);
		SetText(hWnd, 0, tmp);
	}

	SetTextA(hWnd, E_GROUPNAME, group->Name);
	SetText(hWnd, E_REALNAME, group->Realname);
	SetText(hWnd, E_NOTE, group->Note);

	g->Inited = true;

	if (g->EditMode == false)
	{
		Disable(hWnd, L_STATUS);
	}
	else
	{
		LvInit(hWnd, L_STATUS);
		LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 0);
		LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 0);
		LvSetStyle(hWnd, L_STATUS, LVS_EX_GRIDLINES);

		b = LvInsertStart();

		SmInsertTrafficInfo(b, &group->Traffic);

		LvInsertEnd(b, hWnd, L_STATUS);

		LvAutoSize(hWnd, L_STATUS);
	}

	Check(hWnd, R_POLICY, group->Policy != NULL);

	if (g->EditMode)
	{
		Disable(hWnd, E_GROUPNAME);
		FocusEx(hWnd, E_REALNAME);
	}

	SmEditGroupDlgUpdate(hWnd, g);
}

// 更新
void SmEditGroupDlgUpdate(HWND hWnd, SM_EDIT_GROUP *g)
{
	bool ok = true;
	RPC_SET_GROUP *group;
	// 引数チェック
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	if (g->Inited == false)
	{
		return;
	}

	group = &g->SetGroup;

	GetTxtA(hWnd, E_GROUPNAME, group->Name, sizeof(group->Name));
	Trim(group->Name);

	if (IsUserName(group->Name) == false)
	{
		ok = false;
	}

	GetTxt(hWnd, E_REALNAME, group->Realname, sizeof(group->Realname));
	UniTrim(group->Realname);

	GetTxt(hWnd, E_NOTE, group->Note, sizeof(group->Note));
	UniTrim(group->Note);

	SetEnable(hWnd, B_POLICY, IsChecked(hWnd, R_POLICY));

	if (IsChecked(hWnd, R_POLICY))
	{
		if (group->Policy == NULL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// OK
void SmEditGroupDlgOnOk(HWND hWnd, SM_EDIT_GROUP *g)
{
	RPC_SET_GROUP *group;
	RPC_SET_GROUP t;
	// 引数チェック
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	SmEditGroupDlgUpdate(hWnd, g);

	group = &g->SetGroup;

	if (IsChecked(hWnd, R_POLICY) == false)
	{
		if (group->Policy != NULL)
		{
			Free(group->Policy);
			group->Policy = NULL;
		}
	}

	Zero(&t, sizeof(t));
	Copy(&t, group, sizeof(RPC_SET_GROUP));

	t.Policy = ClonePolicy(group->Policy);

	if (g->EditMode == false)
	{
		if (CALL(hWnd, ScCreateGroup(g->Rpc, &t)) == false)
		{
			FocusEx(hWnd, E_GROUPNAME);
			return;
		}
	}
	else
	{
		if (CALL(hWnd, ScSetGroup(g->Rpc, &t)) == false)
		{
			return;
		}
	}

	FreeRpcSetGroup(&t);

	if (g->EditMode == false)
	{
		MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_GROUP_CREATED"), group->Name);
	}

	EndDialog(hWnd, true);
}

// グループ編集ダイアログプロシージャ
UINT SmEditGroupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_GROUP *g = (SM_EDIT_GROUP *)param;
	wchar_t tmp[MAX_SIZE];
	NMHDR *n;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmEditGroupDlgInit(hWnd, g);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_GROUPNAME:
		case E_REALNAME:
		case E_NOTE:
		case R_POLICY:
			SmEditGroupDlgUpdate(hWnd, g);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmEditGroupDlgOnOk(hWnd, g);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case R_POLICY:
			if (IsChecked(hWnd, R_POLICY))
			{
				Focus(hWnd, B_POLICY);
			}
			break;

		case B_POLICY:
			// セキュリティ ポリシー
			UniFormat(tmp, sizeof(tmp), _UU("SM_GROUP_POLICY_CAPTION"), g->SetGroup.Name);
			if (g->SetGroup.Policy == NULL)
			{
				POLICY *p = ClonePolicy(GetDefaultPolicy());
				if (SmPolicyDlgEx2(hWnd, p, tmp, false, g->p->PolicyVer))
				{
					g->SetGroup.Policy = p;
					SmEditGroupDlgUpdate(hWnd, g);
				}
				else
				{
					Free(p);
				}
			}
			else
			{
				SmPolicyDlgEx2(hWnd, g->SetGroup.Policy, tmp, false, g->p->PolicyVer);
			}
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_STATUS:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmEditGroupDlgUpdate(hWnd, g);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// グループ編集ダイアログ
bool SmEditGroupDlg(HWND hWnd, SM_GROUP *s, char *name)
{
	SM_EDIT_GROUP g;
	RPC_SET_GROUP *group;
	bool ret;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&g, sizeof(g));
	g.EditMode = true;
	g.Hub = s->Hub;
	g.p = s->p;
	g.Rpc = s->Rpc;

	group = &g.SetGroup;

	StrCpy(group->Name, sizeof(group->Name), name);
	StrCpy(group->HubName, sizeof(group->HubName), s->Hub->HubName);

	if (CALL(hWnd, ScGetGroup(s->Rpc, group)) == false)
	{
		return false;
	}

	ret = Dialog(hWnd, D_SM_EDIT_GROUP, SmEditGroupDlgProc, &g);

	FreeRpcSetGroup(group);

	return ret;
}

// グループ作成ダイアログ
bool SmCreateGroupDlg(HWND hWnd, SM_GROUP *s)
{
	SM_EDIT_GROUP g;
	RPC_SET_GROUP *group;
	bool ret;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&g, sizeof(g));
	g.EditMode = false;
	g.Hub = s->Hub;
	g.p = s->p;
	g.Rpc = s->Rpc;

	group = &g.SetGroup;

	StrCpy(group->HubName, sizeof(group->HubName), s->Hub->HubName);

	ret = Dialog(hWnd, D_SM_EDIT_GROUP, SmEditGroupDlgProc, &g);

	FreeRpcSetGroup(group);

	return ret;
}

// 初期化
void SmGroupListDlgInit(HWND hWnd, SM_GROUP *s)
{
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_GROUP);

	// カラム初期化
	LvInit(hWnd, L_GROUP);
	LvInsertColumn(hWnd, L_GROUP, 0, _UU("SM_GROUPLIST_NAME"), 130);
	LvInsertColumn(hWnd, L_GROUP, 1, _UU("SM_GROUPLIST_REALNAME"), 130);
	LvInsertColumn(hWnd, L_GROUP, 2, _UU("SM_GROUPLIST_NOTE"), 170);
	LvInsertColumn(hWnd, L_GROUP, 3, _UU("SM_GROUPLIST_NUMUSERS"), 80);
	LvSetStyle(hWnd, L_GROUP, LVS_EX_GRIDLINES);

	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	SmGroupListDlgRefresh(hWnd, s);

	if (s->SelectMode)
	{
		SetStyle(hWnd, L_GROUP, LVS_SINGLESEL);
	}

	if (s->SelectMode)
	{
		wchar_t tmp[MAX_SIZE];
		SetText(hWnd, IDOK, _UU("SM_SELECT_GROUP"));

		if (s->SelectedGroupName != NULL)
		{
			UINT i;
			StrToUni(tmp, sizeof(tmp), s->SelectedGroupName);
			i = LvSearchStr(hWnd, L_GROUP, 0, tmp);
			if (i != INFINITE)
			{
				LvSelect(hWnd, L_GROUP, i);
			}
		}
	}
}

// コントロール更新
void SmGroupListDlgUpdate(HWND hWnd, SM_GROUP *s)
{
	bool ok = true;
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_GROUP) == false || LvIsMultiMasked(hWnd, L_GROUP))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, B_USER, ok);
	SetEnable(hWnd, B_STATUS, ok);

	if (s->SelectMode == false)
	{
		SetEnable(hWnd, B_DELETE, ok);
	}
	else
	{
		SetEnable(hWnd, B_DELETE, false);
		SetEnable(hWnd, B_USER, false);
		SetText(hWnd, IDCANCEL, _UU("SM_SELECT_NO_GROUP"));
	}
}

// 内容更新
void SmGroupListDlgRefresh(HWND hWnd, SM_GROUP *s)
{
	RPC_ENUM_GROUP t;
	UINT i;
	LVB *b;
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);

	if (CALL(hWnd, ScEnumGroup(s->Rpc, &t)) == false)
	{
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumGroup;i++)
	{
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		RPC_ENUM_GROUP_ITEM *e = &t.Groups[i];

		StrToUni(tmp1, sizeof(tmp1), e->Name);
		UniToStru(tmp2, e->NumUsers);

		LvInsertAdd(b, e->DenyAccess == false ? ICO_GROUP : ICO_GROUP_DENY,
			NULL, 4, tmp1, e->Realname, e->Note, tmp2);
	}

	LvInsertEnd(b, hWnd, L_GROUP);

	SmGroupListDlgUpdate(hWnd, s);

	FreeRpcEnumGroup(&t);
}

// グループリストダイアログプロシージャ
UINT SmGroupListDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_GROUP *s = (SM_GROUP *)param;
	NMHDR *n;
	wchar_t *tmp;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmGroupListDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_CREATE:
			// 新規作成
			if (SmCreateGroupDlg(hWnd, s))
			{
				SmGroupListDlgRefresh(hWnd, s);
			}
			break;

		case IDOK:
			// 編集
			tmp = LvGetSelectedStr(hWnd, L_GROUP, 0);
			if (tmp != NULL)
			{
				char name[MAX_SIZE];
				UniToStr(name, sizeof(name), tmp);

				if (s->SelectMode == false)
				{
					if (SmEditGroupDlg(hWnd, s, name))
					{
						SmGroupListDlgRefresh(hWnd, s);
					}
				}
				else
				{
					s->SelectedGroupName = CopyStr(name);
					EndDialog(hWnd, true);
				}
				Free(tmp);
			}
			break;

		case B_DELETE:
			// 削除
			tmp = LvGetSelectedStr(hWnd, L_GROUP, 0);
			if (tmp != NULL)
			{
				char name[MAX_SIZE];
				RPC_DELETE_USER t;
				UniToStr(name, sizeof(name), tmp);

				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_GROUP_DELETE_MSG"), name) == IDYES)
				{
					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
					StrCpy(t.Name, sizeof(t.Name), name);

					if (CALL(hWnd, ScDeleteGroup(s->Rpc, &t)))
					{
						SmGroupListDlgRefresh(hWnd, s);
					}
				}

				Free(tmp);
			}
			break;

		case B_USER:
			// メンバ一覧
			tmp = LvGetSelectedStr(hWnd, L_GROUP, 0);
			if (tmp != NULL)
			{
				char name[MAX_SIZE];
				UniToStr(name, sizeof(name), tmp);
				SmUserListDlgEx(hWnd, s->Hub, name, false);
				Free(tmp);
			}
			break;

		case B_REFRESH:
			// 最新情報に更新
			SmGroupListDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_GROUP:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmGroupListDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_GROUP);

	return 0;
}

// グループリストダイアログ (選択モード)
char *SmSelectGroupDlg(HWND hWnd, SM_HUB *s, char *default_name)
{
	SM_GROUP g;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return NULL;
	}

	Zero(&g, sizeof(g));
	g.Hub = s;
	g.p = s->p;
	g.Rpc = s->Rpc;
	g.SelectMode = true;
	g.SelectedGroupName = default_name;

	if (Dialog(hWnd, D_SM_GROUP, SmGroupListDlgProc, &g) == false)
	{
		return NULL;
	}

	return g.SelectedGroupName;
}

// グループリストダイアログ
void SmGroupListDlg(HWND hWnd, SM_HUB *s)
{
	SM_GROUP g;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&g, sizeof(g));
	g.Hub = s;
	g.p = s->p;
	g.Rpc = s->Rpc;
	g.SelectMode = false;

	Dialog(hWnd, D_SM_GROUP, SmGroupListDlgProc, &g);
}

// ユーザー情報の更新
bool SmRefreshUserInfo(HWND hWnd, SM_SERVER *s, void *param)
{
	RPC_SET_USER t;
	SM_USER_INFO *p = (SM_USER_INFO *)param;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	char *username;

	// 引数チェック
	if (hWnd == NULL || s == NULL || param == NULL)
	{
		return false;
	}

	username = p->Username;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), p->Hub->HubName);
	StrCpy(t.Name, sizeof(t.Name), username);

	if (CALL(hWnd, ScGetUser(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	StrToUni(tmp, sizeof(tmp), t.Name);
	LvInsertAdd(b, ICO_USER, NULL, 2, _UU("SM_USERINFO_NAME"), tmp);

	if (StrLen(t.GroupName) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.GroupName);
		LvInsertAdd(b, ICO_GROUP, NULL, 2, _UU("SM_USERINFO_GROUP"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime), NULL);
	LvInsertAdd(b, ICO_USER_ADMIN, NULL, 2, _UU("SM_USERINFO_CREATE"), tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.UpdatedTime), NULL);
	LvInsertAdd(b, ICO_USER_ADMIN, NULL, 2, _UU("SM_USERINFO_UPDATE"), tmp);

	if (t.ExpireTime != 0)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ExpireTime), NULL);
		LvInsertAdd(b, ICO_WARNING, NULL, 2, _UU("SM_USERINFO_EXPIRE"), tmp);
	}

	SmInsertTrafficInfo(b, &t.Traffic);

	UniToStru(tmp, t.NumLogin);
	LvInsertAdd(b, ICO_LINK, NULL, 2, _UU("SM_USERINFO_NUMLOGIN"), tmp);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcSetUser(&t);

	return true;
}

// 初期化
void SmPolicyDlgInit(HWND hWnd, SM_POLICY *s)
{
	CM_POLICY cp;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_MACHINE);
	SetText(hWnd, 0, s->Caption);
	SetText(hWnd, S_TITLE, s->Caption);
	DlgFont(hWnd, S_BOLD, 10, true);
	DlgFont(hWnd, S_BOLD2, 10, true);

	DlgFont(hWnd, S_POLICY_TITLE, 11, false);
	DlgFont(hWnd, E_POLICY_DESCRIPTION, 10, false);

	Zero(&cp, sizeof(cp));
	cp.Policy = s->Policy;
	cp.Extension = true;

	LvInit(hWnd, L_POLICY);
	LvInsertColumn(hWnd, L_POLICY, 0, _UU("POL_TITLE_STR"), 250);
	LvInsertColumn(hWnd, L_POLICY, 1, _UU("POL_VALUE_STR"), 150);
	LvSetStyle(hWnd, L_POLICY, LVS_EX_GRIDLINES);

	CmPolicyDlgPrintEx2(hWnd, &cp, s->CascadeMode, s->Ver);

	LvSelect(hWnd, L_POLICY, 0);

	s->Inited = true;
	SmPolicyDlgUpdate(hWnd, s);
}

// 更新
void SmPolicyDlgUpdate(HWND hWnd, SM_POLICY *s)
{
	bool ok = true;
	bool value_changed = false;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->Inited == false)
	{
		return;
	}

	i = LvGetSelected(hWnd, L_POLICY);
	if (i != INFINITE)
	{
		i = (UINT)LvGetParam(hWnd, L_POLICY, i);
	}
	if (i == INFINITE || i >= NUM_POLICY_ITEM)
	{
		SetText(hWnd, S_POLICY_TITLE, _UU("SM_POLICY_INIT_TITLE"));
		SetText(hWnd, E_POLICY_DESCRIPTION, L"");
		Disable(hWnd, S_POLICY_TITLE);
		Disable(hWnd, S_BOLD);
		Hide(hWnd, S_BOLD2);
		Hide(hWnd, R_ENABLE);
		Hide(hWnd, R_DISABLE);
		Hide(hWnd, R_DEFINE);
		Hide(hWnd, E_VALUE);
		Hide(hWnd, S_TANI);
		Hide(hWnd, S_LIMIT);
	}
	else
	{
		POLICY_ITEM *item = &policy_item[i];
		bool changed = false;
		wchar_t *tmp = GetText(hWnd, S_POLICY_TITLE);
		if (UniStrCmp(tmp, GetPolicyTitle(i)) != 0)
		{
			changed = true;
		}
		Free(tmp);
		SetText(hWnd, S_POLICY_TITLE, GetPolicyTitle(i));
		SetText(hWnd, E_POLICY_DESCRIPTION, GetPolicyDescription(i));
		Enable(hWnd, S_POLICY_TITLE);
		Enable(hWnd, S_BOLD);
		Show(hWnd, S_BOLD2);

		if (item->TypeInt == false)
		{
			Show(hWnd, R_ENABLE);
			Show(hWnd, R_DISABLE);
			Hide(hWnd, R_DEFINE);
			Hide(hWnd, E_VALUE);
			Hide(hWnd, S_TANI);
			Hide(hWnd, S_LIMIT);

			if (changed)
			{
				if (POLICY_BOOL(s->Policy, i))
				{
					Check(hWnd, R_ENABLE, true);
					Check(hWnd, R_DISABLE, false);
				}
				else
				{
					Check(hWnd, R_ENABLE, false);
					Check(hWnd, R_DISABLE, true);
				}
			}

			if ((!(POLICY_BOOL(s->Policy, i))) != (!(IsChecked(hWnd, R_ENABLE))))
			{
				POLICY_BOOL(s->Policy, i) = IsChecked(hWnd, R_ENABLE);
				value_changed = true;
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			UINT value;
			if (item->AllowZero)
			{
				if (changed)
				{
					Check(hWnd, R_DEFINE, POLICY_INT(s->Policy, i) != 0);
					Enable(hWnd, R_DEFINE);
					SetIntEx(hWnd, E_VALUE, POLICY_INT(s->Policy, i));
				}

				SetEnable(hWnd, E_VALUE, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_TANI, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_LIMIT, IsChecked(hWnd, R_DEFINE));
			}
			else
			{
				if (changed)
				{
					Check(hWnd, R_DEFINE, true);
					Disable(hWnd, R_DEFINE);
					SetInt(hWnd, E_VALUE, POLICY_INT(s->Policy, i));
				}

				SetEnable(hWnd, E_VALUE, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_TANI, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_LIMIT, IsChecked(hWnd, R_DEFINE));
			}

			UniReplaceStrEx(tmp, sizeof(tmp), _UU(policy_item[i].FormatStr),
				L"%u ", L"", false);
			UniReplaceStrEx(tmp, sizeof(tmp), tmp,
				L"%u", L"", false);

			SetText(hWnd, S_TANI, tmp);

			UniFormat(tmp, sizeof(tmp), _UU("SM_LIMIT_STR"), policy_item[i].MinValue, policy_item[i].MaxValue);
			SetText(hWnd, S_LIMIT, tmp);

			Hide(hWnd, R_ENABLE);
			Hide(hWnd, R_DISABLE);
			Show(hWnd, E_VALUE);
			Show(hWnd, R_DEFINE);
			Show(hWnd, S_TANI);
			Show(hWnd, S_LIMIT);

			value = GetInt(hWnd, E_VALUE);

			if (item->AllowZero && (IsChecked(hWnd, R_DEFINE) == false))
			{
				value = 0;
			}
			else
			{
				if (value < policy_item[i].MinValue || value > policy_item[i].MaxValue)
				{
					ok = false;
				}
			}

			if (ok)
			{
				if (POLICY_INT(s->Policy, i) != value)
				{
					POLICY_INT(s->Policy, i) = value;
					value_changed = true;
				}
			}
		}
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, L_POLICY, ok);

	if (value_changed)
	{
		CM_POLICY cp;
		Zero(&cp, sizeof(cp));
		cp.Policy = s->Policy;
		cp.Extension = true;

		CmPolicyDlgPrintEx(hWnd, &cp, s->CascadeMode);
	}
}

// 確定
void SmPolicyDlgOk(HWND hWnd, SM_POLICY *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	EndDialog(hWnd, true);
}

// ポリシー ダイアログ ボックス プロシージャ
UINT SmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_POLICY *s = (SM_POLICY *)param;
	NMHDR *n;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmPolicyDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_DEFINE:
		case R_ENABLE:
		case R_DISABLE:
		case E_VALUE:
			SmPolicyDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmPolicyDlgOk(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case R_DEFINE:
			if (IsChecked(hWnd, R_DEFINE))
			{
				FocusEx(hWnd, E_VALUE);
			}
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_POLICY:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmPolicyDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// ポリシー ダイアログ ボックスの表示
bool SmPolicyDlg(HWND hWnd, POLICY *p, wchar_t *caption)
{
	return SmPolicyDlgEx(hWnd, p, caption, false);
}
bool SmPolicyDlgEx(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode)
{
	return SmPolicyDlgEx2(hWnd, p, caption, cascade_mode, POLICY_CURRENT_VERSION);
}
bool SmPolicyDlgEx2(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode, UINT ver)
{
	SM_POLICY s;
	bool ret;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	if (caption == NULL)
	{
		caption = _UU("SM_POLICY_DEF_CAPTION");
	}

	Zero(&s, sizeof(s));
	s.Caption = caption;
	s.Policy = ClonePolicy(p);
	s.CascadeMode = cascade_mode;
	s.Ver = ver;

	ret = Dialog(hWnd, D_SM_POLICY, SmPolicyDlgProc, &s);

	if (ret)
	{
		Copy(p, s.Policy, sizeof(POLICY));
	}

	Free(s.Policy);

	return ret;
}

// ユーザー編集確定
void SmEditUserDlgOk(HWND hWnd, SM_EDIT_USER *s)
{
	RPC_SET_USER t;
	RPC_SET_USER *u;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmEditUserDlgUpdate(hWnd, s);

	Zero(&t, sizeof(t));
	u = &s->SetUser;

	StrCpy(t.HubName, sizeof(t.HubName), u->HubName);
	StrCpy(t.Name, sizeof(t.Name), u->Name);
	StrCpy(t.GroupName, sizeof(t.GroupName), u->GroupName);
	UniStrCpy(t.Realname, sizeof(t.Realname), u->Realname);
	UniStrCpy(t.Note, sizeof(t.Note), u->Note);
	t.ExpireTime = u->ExpireTime;
	t.AuthType = u->AuthType;
	t.AuthData = CopyAuthData(u->AuthData, t.AuthType);

	if (IsChecked(hWnd, R_POLICY))
	{
		t.Policy = ClonePolicy(u->Policy);
	}
	else
	{
		t.Policy = NULL;
	}

	if (s->EditMode == false)
	{
		if (CALL(hWnd, ScCreateUser(s->Rpc, &t)) == false)
		{
			FocusEx(hWnd, E_USERNAME);
			return;
		}
		FreeRpcSetUser(&t);

		MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_USER_CREEATE_OK"), u->Name);
	}
	else
	{
		if (CALL(hWnd, ScSetUser(s->Rpc, &t)) == false)
		{
			FocusEx(hWnd, E_REALNAME);
			return;
		}
		FreeRpcSetUser(&t);
	}

	EndDialog(hWnd, true);
}

// ユーザー編集初期化
void SmEditUserDlgInit(HWND hWnd, SM_EDIT_USER *s)
{
	RPC_SET_USER *u;
	wchar_t tmp[MAX_SIZE];
	UINT i;
	UINT icons[6] = {ICO_PASS, ICO_KEY, ICO_CERT, ICO_SERVER_CERT,
		ICO_TOWER, ICO_LINK};
	RECT rect;

	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_USER);

	u = &s->SetUser;

	// カラム初期化
	LvInit(hWnd, L_AUTH);
	LvSetStyle(hWnd, L_AUTH, LVS_EX_GRIDLINES);

	GetClientRect(DlgItem(hWnd, L_AUTH), &rect);
	LvInsertColumn(hWnd, L_AUTH, 0, L"Name", rect.right - rect.left);

	for (i = 0;i < 6;i++)
	{
		LvInsert(hWnd, L_AUTH, icons[i], (void *)i, 1, SmGetAuthTypeStr(i));
	}

	// ユーザー名など
	SetTextA(hWnd, E_USERNAME, u->Name);
	SetText(hWnd, E_REALNAME, u->Realname);
	SetText(hWnd, E_NOTE, u->Note);


	// 有効期限
	if (u->ExpireTime == 0)
	{
		SYSTEMTIME st;
		Check(hWnd, R_EXPIRES, false);
		GetLocalTime(&st);
		UINT64ToSystem(&st, SystemToUINT64(&st) + (60 * 60 * 24 * 1000));
		st.wHour = st.wMinute = st.wSecond = st.wMilliseconds = 0;
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_DATE), GDT_VALID, &st);
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_TIME), GDT_VALID, &st);
	}
	else
	{
		SYSTEMTIME st;
		UINT64ToSystem(&st, SystemToLocal64(u->ExpireTime));
		Check(hWnd, R_EXPIRES, true);
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_DATE), GDT_VALID, &st);
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_TIME), GDT_VALID, &st);
	}

	SetStyle(hWnd, E_EXPIRES_DATE, DTS_LONGDATEFORMAT);
	SetWindowLong(DlgItem(hWnd, E_EXPIRES_TIME), GWL_STYLE, WS_CHILDWINDOW | WS_VISIBLE | WS_TABSTOP | DTS_RIGHTALIGN | DTS_TIMEFORMAT | DTS_UPDOWN);

	// グループ名
	SetTextA(hWnd, E_GROUP, u->GroupName);

	// 認証方法
	LvSelect(hWnd, L_AUTH, u->AuthType);

	SetText(hWnd, S_CERT_INFO, _UU("SM_EDIT_USER_CERT_INFO"));

	switch (u->AuthType)
	{
	case AUTHTYPE_PASSWORD:
		if (s->EditMode)
		{
			SetTextA(hWnd, E_PASSWORD1, HIDDEN_PASSWORD);
			SetTextA(hWnd, E_PASSWORD2, HIDDEN_PASSWORD);
		}
		break;

	case AUTHTYPE_USERCERT:
		SmGetCertInfoStr(tmp, sizeof(tmp), ((AUTHUSERCERT *)u->AuthData)->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (u->AuthData != NULL)
		{
			AUTHROOTCERT *c = (AUTHROOTCERT *)u->AuthData;
			if (c->CommonName != NULL && UniStrLen(c->CommonName) != 0)
			{
				Check(hWnd, R_CN, true);
				SetText(hWnd, E_CN, c->CommonName);
			}
			else
			{
				Check(hWnd, R_CN, false);
			}
			if (c->Serial != NULL && c->Serial->size != 0)
			{
				X_SERIAL *s = c->Serial;
				char *tmp;
				UINT tmp_size = s->size * 3 + 1;
				tmp = ZeroMalloc(tmp_size);
				BinToStrEx(tmp, tmp_size, s->data, s->size);
				SetTextA(hWnd, E_SERIAL, tmp);
				Free(tmp);
				Check(hWnd, R_SERIAL, true);
			}
			else
			{
				Check(hWnd, R_SERIAL, false);
			}
		}
		break;

	case AUTHTYPE_RADIUS:
		if (u->AuthData != NULL)
		{
			AUTHRADIUS *r = (AUTHRADIUS *)u->AuthData;
			if (UniStrLen(r->RadiusUsername) != 0)
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, true);
				SetText(hWnd, E_RADIUS_USERNAME, r->RadiusUsername);
			}
			else
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, false);
			}
		}
		break;

	case AUTHTYPE_NT:
		if (u->AuthData != NULL)
		{
			AUTHNT *n = (AUTHNT *)u->AuthData;
			if (UniStrLen(n->NtUsername) != 0)
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, true);
				SetText(hWnd, E_RADIUS_USERNAME, n->NtUsername);
			}
			else
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, false);
			}
		}
		break;
	}

	if (u->Policy != NULL)
	{
		Check(hWnd, R_POLICY, true);
	}

	s->Inited = true;

	SmEditUserDlgUpdate(hWnd, s);

	if (s->EditMode == false)
	{
		Focus(hWnd, E_USERNAME);
		SetText(hWnd, 0, _UU("SM_EDIT_USER_CAPTION_1"));
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_USER_CAPTION_2"), s->SetUser.Name);
		SetText(hWnd, 0, tmp);

		Disable(hWnd, E_USERNAME);
		FocusEx(hWnd, E_REALNAME);
	}
}

// ユーザー編集コントロール更新
void SmEditUserDlgUpdate(HWND hWnd, SM_EDIT_USER *s)
{
	RPC_SET_USER *u;
	bool ok = true;
	UINT old_authtype;
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool authtype_changed = false;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->Inited == false)
	{
		return;
	}

	u = &s->SetUser;

	// ユーザー名
	GetTxtA(hWnd, E_USERNAME, u->Name, sizeof(u->Name));
	Trim(u->Name);
	if (StrLen(u->Name) == 0 || IsUserName(u->Name) == false)
	{
		ok = false;
	}

	// 本名
	GetTxt(hWnd, E_REALNAME, u->Realname, sizeof(u->Realname));
	UniTrim(u->Realname);

	// メモ
	GetTxt(hWnd, E_NOTE, u->Note, sizeof(u->Note));
	UniTrim(u->Realname);

	// グループ
	GetTxtA(hWnd, E_GROUP, u->GroupName, sizeof(u->GroupName));
	Trim(u->GroupName);

	// 有効期限
	if (IsChecked(hWnd, R_EXPIRES) == false)
	{
		u->ExpireTime = 0;
		Disable(hWnd, E_EXPIRES_DATE);
		Disable(hWnd, E_EXPIRES_TIME);
	}
	else
	{
		SYSTEMTIME st1, st2;
		Enable(hWnd, E_EXPIRES_DATE);
		Enable(hWnd, E_EXPIRES_TIME);
		DateTime_GetSystemtime(DlgItem(hWnd, E_EXPIRES_DATE), &st1);
		DateTime_GetSystemtime(DlgItem(hWnd, E_EXPIRES_TIME), &st2);
		st1.wHour = st2.wHour;
		st1.wMinute = st2.wMinute;
		st1.wSecond = st2.wSecond;
		st1.wMilliseconds = st2.wMilliseconds;
		u->ExpireTime = LocalToSystem64(SystemToUINT64(&st1));
	}

	// 認証方法
	old_authtype = u->AuthType;
	u->AuthType = LvGetSelected(hWnd, L_AUTH);

	if (StrCmpi(u->Name, "*") == 0)
	{
		if (u->AuthType != AUTHTYPE_RADIUS && u->AuthType != AUTHTYPE_NT)
		{
			ok = false;
		}
	}

	if (u->AuthType == INFINITE)
	{
		ok = false;
		u->AuthType = 0;
	}
	if (old_authtype != u->AuthType)
	{
		authtype_changed = true;
	}

	if (authtype_changed)
	{
		FreeAuthData(old_authtype, u->AuthData);
		u->AuthData = NULL;
		switch (u->AuthType)
		{
		case AUTHTYPE_ANONYMOUS:
			u->AuthData = NULL;
			break;

		case AUTHTYPE_PASSWORD:
			u->AuthData = NewPasswordAuthData("", "");
			GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
			if (StrCmp(tmp1, HIDDEN_PASSWORD) == 0)
			{
				SetTextA(hWnd, E_PASSWORD1, "");
			}
			GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
			if (StrCmp(tmp2, HIDDEN_PASSWORD) == 0)
			{
				SetTextA(hWnd, E_PASSWORD2, "");
			}
			break;

		case AUTHTYPE_USERCERT:
			u->AuthData = NewUserCertAuthData(NULL);
			SetText(hWnd, S_CERT_INFO, _UU("SM_EDIT_USER_CERT_INFO"));
			break;

		case AUTHTYPE_ROOTCERT:
			u->AuthData = NewRootCertAuthData(NULL, NULL);
			break;

		case AUTHTYPE_NT:
			u->AuthData = NewNTAuthData(L"");
			break;

		case AUTHTYPE_RADIUS:
			u->AuthData = NewRadiusAuthData(L"");
			break;
		}
	}

	SetEnable(hWnd, S_RADIUS_3, (u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT));
	SetEnable(hWnd, R_SET_RADIUS_USERNAME, (u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT));
	SetEnable(hWnd, S_RADIUS_1, (u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT));

	if (StrCmp(u->Name, "*") == 0)
	{
		Check(hWnd, R_SET_RADIUS_USERNAME, false);
		Disable(hWnd, R_SET_RADIUS_USERNAME);
	}

	if ((u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT))
	{
		SetEnable(hWnd, E_RADIUS_USERNAME, IsChecked(hWnd, R_SET_RADIUS_USERNAME));
		SetEnable(hWnd, S_RADIUS_2, IsChecked(hWnd, R_SET_RADIUS_USERNAME));
	}
	else
	{
		SetEnable(hWnd, E_RADIUS_USERNAME, false);
		SetEnable(hWnd, S_RADIUS_2, false);
	}

	SetEnable(hWnd, S_PASSWORD_1, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, S_PASSWORD_2, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, S_PASSWORD_3, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, E_PASSWORD1, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, E_PASSWORD2, u->AuthType == AUTHTYPE_PASSWORD);

	SetEnable(hWnd, S_USER_CERT_1, u->AuthType == AUTHTYPE_USERCERT);
	SetEnable(hWnd, S_CERT_INFO, u->AuthType == AUTHTYPE_USERCERT);
	SetEnable(hWnd, B_LOAD_CERT, u->AuthType == AUTHTYPE_USERCERT);

	if (u->AuthType == AUTHTYPE_USERCERT)
	{
		SetEnable(hWnd, B_VIEW_CERT, ((AUTHUSERCERT *)u->AuthData)->UserX != NULL);
	}
	else
	{
		SetEnable(hWnd, B_VIEW_CERT, false);
	}

	SetEnable(hWnd, S_ROOT_CERT_1, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, S_ROOT_CERT_2, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, S_ROOT_CERT_3, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, R_CN, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, R_SERIAL, u->AuthType == AUTHTYPE_ROOTCERT);

	if (u->AuthType == AUTHTYPE_ROOTCERT)
	{
		SetEnable(hWnd, E_CN, IsChecked(hWnd, R_CN));
		SetEnable(hWnd, E_SERIAL, IsChecked(hWnd, R_SERIAL));
	}
	else
	{
		Disable(hWnd, E_CN);
		Disable(hWnd, E_SERIAL);
	}

	switch (u->AuthType)
	{
	case AUTHTYPE_PASSWORD:
		GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
		GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
		if (StrCmp(tmp1, tmp2) != 0)
		{
			ok = false;
		}
		else
		{
			if (StrCmp(tmp1, HIDDEN_PASSWORD) != 0)
			{
				HashPassword(((AUTHPASSWORD *)u->AuthData)->HashedKey, u->Name, tmp1);
			}
		}
		break;

	case AUTHTYPE_USERCERT:
		if (((AUTHUSERCERT *)u->AuthData)->UserX == NULL)
		{
			ok = false;
		}
		break;

	case AUTHTYPE_ROOTCERT:
		Free(((AUTHROOTCERT *)u->AuthData)->CommonName);
		((AUTHROOTCERT *)u->AuthData)->CommonName = NULL;
		if (IsChecked(hWnd, R_CN) && (IsEmpty(hWnd, E_CN) == false))
		{
			((AUTHROOTCERT *)u->AuthData)->CommonName = GetText(hWnd, E_CN);
			UniTrim(((AUTHROOTCERT *)u->AuthData)->CommonName);
		}
		if (IsChecked(hWnd, R_CN) && ((AUTHROOTCERT *)u->AuthData)->CommonName == NULL)
		{
			ok = false;
		}
		FreeXSerial(((AUTHROOTCERT *)u->AuthData)->Serial);
		((AUTHROOTCERT *)u->AuthData)->Serial = NULL;
		if (IsChecked(hWnd, R_SERIAL))
		{
			char *serial_str = GetTextA(hWnd, E_SERIAL);
			if (serial_str != NULL)
			{
				BUF *b = StrToBin(serial_str);
				if (b->Size >= 1)
				{
					((AUTHROOTCERT *)u->AuthData)->Serial = NewXSerial(b->Buf, b->Size);
				}
				FreeBuf(b);
				Free(serial_str);
			}
		}
		if (IsChecked(hWnd, R_SERIAL) && ((AUTHROOTCERT *)u->AuthData)->Serial == NULL)
		{
			ok = false;
		}
		break;

	case AUTHTYPE_RADIUS:
		Free(((AUTHRADIUS *)u->AuthData)->RadiusUsername);
		((AUTHRADIUS *)u->AuthData)->RadiusUsername = NULL;
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && (IsEmpty(hWnd, E_RADIUS_USERNAME) == false))
		{
			((AUTHRADIUS *)u->AuthData)->RadiusUsername = GetText(hWnd, E_RADIUS_USERNAME);
		}
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && ((AUTHRADIUS *)u->AuthData)->RadiusUsername == NULL)
		{
			ok = false;
		}
		break;

	case AUTHTYPE_NT:
		Free(((AUTHNT *)u->AuthData)->NtUsername);
		((AUTHNT *)u->AuthData)->NtUsername = NULL;
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && (IsEmpty(hWnd, E_RADIUS_USERNAME) == false))
		{
			((AUTHNT *)u->AuthData)->NtUsername = GetText(hWnd, E_RADIUS_USERNAME);
		}
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && ((AUTHNT *)u->AuthData)->NtUsername == NULL)
		{
			ok = false;
		}
		break;
	}

	SetEnable(hWnd, B_POLICY, IsChecked(hWnd, R_POLICY));
	if (IsChecked(hWnd, R_POLICY))
	{
		if (u->Policy == NULL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// ユーザー編集ダイアログプロシージャ
UINT SmEditUserDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_USER *s = (SM_EDIT_USER *)param;
	NMHDR *n;
	POLICY *policy;
	X *x = NULL;
	wchar_t tmp[MAX_SIZE];
	char name[MAX_SIZE];
	char *ret;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmEditUserDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_USERNAME:
		case E_REALNAME:
		case E_NOTE:
		case R_EXPIRES:
		case E_EXPIRES_DATE:
		case E_EXPIRES_TIME:
		case E_GROUP:
		case L_AUTH:
		case R_SET_RADIUS_USERNAME:
		case E_RADIUS_USERNAME:
		case R_POLICY:
		case E_PASSWORD1:
		case E_PASSWORD2:
		case R_CN:
		case E_CN:
		case R_SERIAL:
		case E_SERIAL:
			SmEditUserDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmEditUserDlgOk(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case B_POLICY:
			UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_USER_POL_DLG"), s->SetUser.Name);
			// ポリシー
			if (s->SetUser.Policy == NULL)
			{
				policy = ClonePolicy(GetDefaultPolicy());
				if (SmPolicyDlgEx2(hWnd, policy, tmp, false, s->p->PolicyVer))
				{
					s->SetUser.Policy = policy;
					SmEditUserDlgUpdate(hWnd, s);
				}
				else
				{
					Free(policy);
				}
			}
			else
			{
				SmPolicyDlgEx2(hWnd, s->SetUser.Policy, tmp, false, s->p->PolicyVer);
			}
			break;

		case B_GROUP:
			// グループの参照
			GetTxtA(hWnd, E_GROUP, name, sizeof(name));
			Trim(name);
			ret = SmSelectGroupDlg(hWnd, s->Hub, StrLen(name) == 0 ? NULL : name);
			if (ret != NULL)
			{
				SetTextA(hWnd, E_GROUP, ret);
				Free(ret);
			}
			else
			{
				SetTextA(hWnd, E_GROUP, "");
			}
			FocusEx(hWnd, E_GROUP);
			break;

		case B_LOAD_CERT:
			// 証明書の指定
			if (CmLoadXFromFileOrSecureCard(hWnd, &x))
			{
UPDATE_CERT:
				if (s->SetUser.AuthType == AUTHTYPE_USERCERT)
				{
					wchar_t tmp[MAX_SIZE];
					FreeX(((AUTHUSERCERT *)s->SetUser.AuthData)->UserX);
					((AUTHUSERCERT *)s->SetUser.AuthData)->UserX = x;
					SmGetCertInfoStr(tmp, sizeof(tmp), x);
					SetText(hWnd, S_CERT_INFO, tmp);
					SmEditUserDlgUpdate(hWnd, s);
				}
				else
				{
					if (x != NULL)
					{
						FreeX(x);
						x = NULL;
					}
				}
			}
			break;

		case B_VIEW_CERT:
			// 証明書の表示
			if (s->SetUser.AuthType == AUTHTYPE_USERCERT)
			{
				CertDlg(hWnd, ((AUTHUSERCERT *)s->SetUser.AuthData)->UserX, NULL, true);
			}
			break;

		case B_CREATE:
			// 作成
			GetTxtA(hWnd, E_USERNAME, name, sizeof(name));
			Trim(name);
			if (SmCreateCert(hWnd, &x, NULL, false, name))
			{
				if (s->SetUser.AuthType != AUTHTYPE_USERCERT)
				{
					LvSelect(hWnd, L_AUTH, 2);
				}
				goto UPDATE_CERT;
			}
			break;

		case R_SET_RADIUS_USERNAME:
			if (IsChecked(hWnd, R_SET_RADIUS_USERNAME))
			{
				FocusEx(hWnd, E_RADIUS_USERNAME);
			}
			break;

		case R_EXPIRES:
			if (IsChecked(hWnd, R_EXPIRES))
			{
				Focus(hWnd, E_EXPIRES_DATE);
			}
			break;

		case R_POLICY:
			if (IsChecked(hWnd, R_POLICY))
			{
				Focus(hWnd, B_POLICY);
			}
			break;

		case R_CN:
			if (IsChecked(hWnd, R_CN))
			{
				Focus(hWnd, E_CN);
			}
			break;

		case R_SERIAL:
			if (IsChecked(hWnd, R_SERIAL))
			{
				Focus(hWnd, E_SERIAL);
			}
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_AUTH:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmEditUserDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// ユーザーの編集ダイアログ
bool SmEditUserDlg(HWND hWnd, SM_HUB *s, char *username)
{
	SM_EDIT_USER e;
	bool ret;
	// 引数チェック
	if (hWnd == NULL || s == NULL || username == NULL)
	{
		return false;
	}

	Zero(&e, sizeof(e));
	e.p = s->p;
	e.Rpc = s->Rpc;
	e.Hub = s;

	// ユーザーの取得
	StrCpy(e.SetUser.HubName, sizeof(e.SetUser.HubName), e.Hub->HubName);
	StrCpy(e.SetUser.Name, sizeof(e.SetUser.Name), username);

	if (CALL(hWnd, ScGetUser(s->Rpc, &e.SetUser)) == false)
	{
		return false;
	}

	e.EditMode = true;

	ret = Dialog(hWnd, D_SM_EDIT_USER, SmEditUserDlgProc, &e);

	FreeRpcSetUser(&e.SetUser);

	return ret;
}

// ユーザーの新規作成ダイアログ
bool SmCreateUserDlg(HWND hWnd, SM_HUB *s)
{
	SM_EDIT_USER e;
	bool ret;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&e, sizeof(e));
	e.EditMode = false;
	e.p = s->p;
	e.Rpc = s->Rpc;
	e.Hub = s;

	// 新しいユーザーの設定
	StrCpy(e.SetUser.HubName, sizeof(e.SetUser.HubName), e.Hub->HubName);
	e.SetUser.AuthType = CLIENT_AUTHTYPE_PASSWORD;
	e.SetUser.AuthData = NewPasswordAuthData("", "");

	ret = Dialog(hWnd, D_SM_EDIT_USER, SmEditUserDlgProc, &e);

	FreeRpcSetUser(&e.SetUser);

	return ret;
}

// ユーザー認証方法の文字列の取得
wchar_t *SmGetAuthTypeStr(UINT id)
{
	return GetAuthTypeStr(id);
}

// ユーザーリスト初期化
void SmUserListInit(HWND hWnd, SM_USER *s)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_USER);

	// カラム初期化
	LvInit(hWnd, L_USER);
	LvSetStyle(hWnd, L_USER, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_USER, 0, _UU("SM_USER_COLUMN_1"), 120);
	LvInsertColumn(hWnd, L_USER, 1, _UU("SM_USER_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_USER, 2, _UU("SM_USER_COLUMN_3"), 100);
	LvInsertColumn(hWnd, L_USER, 3, _UU("SM_USER_COLUMN_4"), 130);
	LvInsertColumn(hWnd, L_USER, 4, _UU("SM_USER_COLUMN_5"), 100);
	LvInsertColumn(hWnd, L_USER, 5, _UU("SM_USER_COLUMN_6"), 90);
	LvInsertColumn(hWnd, L_USER, 6, _UU("SM_USER_COLUMN_7"), 120);

	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	if (s->GroupName != NULL)
	{
		GetTxt(hWnd, 0, tmp1, sizeof(tmp1));
		UniFormat(tmp2, sizeof(tmp2), _UU("SM_GROUP_MEMBER_STR"), s->GroupName);
		UniStrCat(tmp1, sizeof(tmp1), tmp2);
		SetText(hWnd, S_TITLE, tmp1);
		Disable(hWnd, B_CREATE);
	}

	if (s->SelectMode)
	{
		SetStyle(hWnd, L_USER, LVS_SINGLESEL);
	}

	SmUserListRefresh(hWnd, s);

	if (s->SelectMode)
	{
		wchar_t tmp[MAX_SIZE];
		UINT i;
		StrToUni(tmp, sizeof(tmp), s->SelectedName);
		i = LvSearchStr(hWnd, L_USER, 0, tmp);
		if (i != INFINITE)
		{
			LvSelect(hWnd, L_USER, i);
		}

		if (s->AllowGroup)
		{
			SetText(hWnd, B_DELETE, _UU("SM_SELECT_ALT_GROUP"));
		}
	}
}

// ユーザーリスト更新
void SmUserListRefresh(HWND hWnd, SM_USER *s)
{
	LVB *b;
	RPC_ENUM_USER t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
	if (CALL(hWnd, ScEnumUser(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t.Users[i];
		wchar_t name[MAX_SIZE];
		wchar_t group[MAX_SIZE];
		wchar_t num[MAX_SIZE];
		wchar_t time[MAX_SIZE];

		if (s->GroupName != NULL)
		{
			if (StrCmpi(s->GroupName, e->GroupName) != 0)
			{
				continue;
			}
		}

		StrToUni(name, sizeof(name), e->Name);

		if (StrLen(e->GroupName) != 0)
		{
			StrToUni(group, sizeof(group), e->GroupName);
		}
		else
		{
			UniStrCpy(group, sizeof(group), _UU("SM_NO_GROUP"));
		}

		UniToStru(num, e->NumLogin);

		GetDateTimeStrEx64(time, sizeof(time), SystemToLocal64(e->LastLoginTime), NULL);

		LvInsertAdd(b, e->DenyAccess ? ICO_USER_DENY : ICO_USER, NULL, 7,
			name, e->Realname, group, e->Note, SmGetAuthTypeStr(e->AuthType),
			num, time);
	}

	LvInsertEnd(b, hWnd, L_USER);

	FreeRpcEnumUser(&t);

	SmUserListUpdate(hWnd, s);
}

// ユーザーリストコントロール更新
void SmUserListUpdate(HWND hWnd, SM_USER *s)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_USER) == false || LvIsMultiMasked(hWnd, L_USER))
	{
		b = false;
	}

	if (s->SelectMode)
	{
		SetText(hWnd, IDOK, _UU("SM_SELECT_USER"));
		SetText(hWnd, IDCANCEL, _UU("SM_SELECT_NO"));
		SetText(hWnd, S_TITLE, _UU("SM_PLEASE_SELECT"));
	}

	SetEnable(hWnd, IDOK, b);

	SetEnable(hWnd, B_STATUS, b);
	SetEnable(hWnd, B_DELETE, (b && s->SelectedName == false) || s->AllowGroup);
	SetEnable(hWnd, B_CREATE, s->SelectedName == false);
}

// ユーザーリストダイアログプロシージャ
UINT SmUserListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_USER *s = (SM_USER *)param;
	NMHDR *n;
	wchar_t *str;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmUserListInit(hWnd, s);

		if (s->CreateNow)
		{
			// すぐに作成
			if (IsEnable(hWnd, B_CREATE))
			{
				Command(hWnd, B_CREATE);
			}
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (s->SelectMode == false)
			{
				// プロパティ
				str = LvGetSelectedStr(hWnd, L_USER, 0);
				if (str != NULL)
				{
					char name[MAX_SIZE];
					UniToStr(name, sizeof(name), str);

					if (SmEditUserDlg(hWnd, s->Hub, name))
					{
						SmUserListRefresh(hWnd, s);
					}

					Free(str);
				}
			}
			else
			{
				// ユーザーを選択した
				str = LvGetSelectedStr(hWnd, L_USER, 0);
				if (str != NULL)
				{
					char name[MAX_SIZE];
					UniToStr(name, sizeof(name), str);

					s->SelectedName = CopyStr(name);

					EndDialog(hWnd, true);

					Free(str);
				}
			}
			break;

		case B_CREATE:
			// 新規作成
			if (SmCreateUserDlg(hWnd, s->Hub))
			{
				SmUserListRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			if (s->AllowGroup)
			{
				// グループ選択
				EndDialog(hWnd, INFINITE);
			}
			else
			{
				// 削除
				str = LvGetSelectedStr(hWnd, L_USER, 0);
				if (str != NULL)
				{
					RPC_DELETE_USER t;
					char name[MAX_SIZE];
					UniToStr(name, sizeof(name), str);

					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
					StrCpy(t.Name, sizeof(t.Name), name);

					if (MsgBoxEx(hWnd, MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
						_UU("SM_USER_DELETE_MSG"), str) == IDYES)
					{
						if (CALL(hWnd, ScDeleteUser(s->Rpc, &t)))
						{
							SmUserListRefresh(hWnd, s);
						}
					}

					Free(str);
				}
			}
			break;

		case B_STATUS:
			// ユーザー情報表示
			str = LvGetSelectedStr(hWnd, L_USER, 0);
			if (str != NULL)
			{
				char name[MAX_SIZE];
				wchar_t tmp[MAX_SIZE];
				SM_USER_INFO info;
				UniToStr(name, sizeof(name), str);

				UniFormat(tmp, sizeof(tmp), _UU("SM_USERINFO_CAPTION"), name);

				Zero(&info, sizeof(info));
				info.p = s->p;
				info.Rpc = s->Rpc;
				info.Hub = s->Hub;
				info.Username = name;

				SmStatusDlg(hWnd, s->p, &info, false, true, tmp, ICO_USER, NULL, SmRefreshUserInfo);

				Free(str);
			}
			break;
			break;

		case B_REFRESH:
			// 更新
			SmUserListRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_USER:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				// コントロール更新
				SmUserListUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_USER);

	return 0;
}

// ユーザーリストダイアログ (選択)
char *SmSelectUserDlg(HWND hWnd, SM_HUB *s, char *default_name)
{
	return SmSelectUserDlgEx(hWnd, s, default_name, false);
}
char *SmSelectUserDlgEx(HWND hWnd, SM_HUB *s, char *default_name, bool allow_group)
{
	UINT ret;
	SM_USER user;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return NULL;
	}

	Zero(&user, sizeof(user));
	user.Hub = s;
	user.p = s->p;
	user.Rpc = s->Rpc;
	user.GroupName = NULL;
	user.SelectedName = default_name;
	user.SelectMode = true;
	user.AllowGroup = allow_group;

	ret = Dialog(hWnd, D_SM_USER, SmUserListProc, &user);

	if (ret == 0)
	{
		return NULL;
	}
	else if (ret == INFINITE)
	{
		// グループの選択
		return SmSelectGroupDlg(hWnd, s, default_name);
	}
	else
	{
		return user.SelectedName;
	}
}

// ユーザーリストダイアログ (グループ名でフィルタ)
void SmUserListDlgEx(HWND hWnd, SM_HUB *s, char *groupname, bool create)
{
	SM_USER user;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&user, sizeof(user));
	user.Hub = s;
	user.p = s->p;
	user.Rpc = s->Rpc;
	user.GroupName = groupname;
	user.CreateNow = create;

	Dialog(hWnd, D_SM_USER, SmUserListProc, &user);
}

// ユーザーリストダイアログ
void SmUserListDlg(HWND hWnd, SM_HUB *s)
{
	SmUserListDlgEx(hWnd, s, NULL, false);
}

// 初期化
void SmHubDlgInit(HWND hWnd, SM_HUB *s)
{
	CAPSLIST *caps;
	bool support_user, support_group, support_accesslist, support_cascade,
		support_log, support_config_hub, support_secure_nat, support_config_radius;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	FormatText(hWnd, 0, s->HubName);
	FormatText(hWnd, S_TITLE, s->HubName);
	SetIcon(hWnd, 0, ICO_HUB);
	DlgFont(hWnd, S_TITLE, 15, true);

	LvInit(hWnd, L_STATUS);
	LvSetStyle(hWnd, L_STATUS, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 0);
	LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 0);

	caps = s->p->CapsList;

	support_user = GetCapsInt(caps, "i_max_users_per_hub") == 0 ? false : true;
	support_group = GetCapsInt(caps, "i_max_groups_per_hub") == 0 ? false : true;
	support_accesslist = GetCapsInt(caps, "i_max_access_lists") == 0 ? false : true;
	support_cascade = GetCapsBool(caps, "b_support_cascade");
	support_log = GetCapsBool(caps, "b_support_config_log");
	support_config_hub = GetCapsBool(caps, "b_support_config_hub");
	support_secure_nat = GetCapsBool(caps, "b_support_securenat");
	support_config_radius = GetCapsBool(caps, "b_support_radius");

	SetEnable(hWnd, B_USER, support_user);
	SetEnable(hWnd, S_USER, support_user);

	SetEnable(hWnd, B_GROUP, support_group);
	SetEnable(hWnd, S_GROUP, support_group);

	SetEnable(hWnd, B_ACCESS, support_accesslist);
	SetEnable(hWnd, S_ACCESS, support_accesslist);

	SetEnable(hWnd, B_PROPERTY, s->p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, S_PROPERTY, s->p->ServerType != SERVER_TYPE_FARM_MEMBER);

	SetEnable(hWnd, B_RADIUS, support_config_radius);
	SetEnable(hWnd, S_RADIUS, support_config_radius);

	SetEnable(hWnd, B_LINK, support_cascade);
	SetEnable(hWnd, S_LINK, support_cascade);

	SetEnable(hWnd, B_LOG, support_log);
	SetEnable(hWnd, S_LOG, support_log);

	SetEnable(hWnd, B_CA, support_config_hub);
	SetEnable(hWnd, S_CA, support_config_hub);

	SetEnable(hWnd, B_SNAT, support_secure_nat);
	SetEnable(hWnd, S_SNAT, support_secure_nat);

	SetEnable(hWnd, B_CRL, GetCapsBool(caps, "b_support_crl"));

	SetEnable(hWnd, B_LOG_FILE, GetCapsBool(caps, "b_support_read_log"));

	SmHubDlgRefresh(hWnd, s);
}

// コントロール更新
void SmHubDlgUpdate(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}
}

// 内容更新
void SmHubDlgRefresh(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmRefreshHubStatus(hWnd, s->p, (void *)s->HubName);
	LvAutoSize(hWnd, L_STATUS);

	SmHubDlgUpdate(hWnd, s);
}

// HUB 管理ダイアログ
UINT SmHubDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmHubDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_USER:
			// ユーザー
			SmUserListDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_GROUP:
			// グループ
			SmGroupListDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_ACCESS:
			// アクセスリスト
			SmAccessListDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_PROPERTY:
			// プロパティ
			if (SmEditHubDlg(hWnd, s->p, s->HubName))
			{
				SmHubDlgRefresh(hWnd, s);
			}
			break;

		case B_RADIUS:
			// Radius
			SmRadiusDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_LINK:
			// カスケード
			SmLinkDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_SESSION:
			// セッション
			SmSessionDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_LOG:
			// ログ
			Dialog(hWnd, D_SM_LOG, SmLogDlg, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_CA:
			// CA
			SmCaDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case B_REFRESH:
			// 更新
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_SNAT:
			// SecureNAT
			Dialog(hWnd, D_SM_SNAT, SmSNATDlgProc, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_CRL:
			// 無効な証明書の一覧
			Dialog(hWnd, D_SM_CRL, SmCrlDlgProc, s);
			break;

		case B_LOG_FILE:
			// ログファイル
			Dialog(hWnd, D_SM_LOG_FILE, SmLogFileDlgProc, s->p);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// HUB の管理
void SmHubDlg(HWND hWnd, SM_HUB *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_HUB, SmHubDlgProc, s);
}

// サーバー パスワードの変更
UINT SmChangeServerPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	RPC_SET_PASSWORD t;
	SETTING *setting;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SetIcon(hWnd, 0, ICO_USER_ADMIN);
		FormatText(hWnd, 0, p->ServerName);
		FormatText(hWnd, S_TITLE, p->ServerName);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
			if (StrCmp(tmp1, tmp2) != 0)
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_CHANGE_PASSWORD_1"));
				FocusEx(hWnd, E_PASSWORD2);
				break;
			}
			if (StrLen(tmp1) == 0)
			{
				if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_CHANGE_PASSWORD_2")) == IDNO)
				{
					Focus(hWnd, E_PASSWORD1);
					break;
				}
			}
			Zero(&t, sizeof(t));
			Hash(t.HashedPassword, tmp1, StrLen(tmp1), true);
			Copy(hash, t.HashedPassword, sizeof(hash));
			if (CALL(hWnd, ScSetServerPassword(p->Rpc, &t)) == false)
			{
				break;
			}
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_CHANGE_PASSWORD_3"));

			// 接続設定のパスワードを変更する
			setting = SmGetSetting(p->CurrentSetting->Title);
			if (setting != NULL && sm->TempSetting == NULL)
			{
				if (IsZero(setting->HashedPassword, SHA1_SIZE) == false)
				{
					Copy(setting->HashedPassword, hash, SHA1_SIZE);
					SmWriteSettingList();
				}
			}

			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// サーバー ファーム コントローラへの接続状況更新
bool SmRefreshFarmConnectionInfo(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_FARM_CONNECTION_STATUS t;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetFarmConnectionStatus(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	if (t.Online == false)
	{
		LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_FC_IP"), _UU("SM_FC_NOT_CONNECTED"));

		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_PORT"), _UU("SM_FC_NOT_CONNECTED"));
	}
	else
	{
		IPToStr32(str, sizeof(str), t.Ip);
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_FC_IP"), tmp);

		UniToStru(tmp, t.Port);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_PORT"), tmp);
	}

	LvInsertAdd(b,
		t.Online ? ICO_SERVER_ONLINE_EX : ICO_PROTOCOL_X, NULL, 2,
		_UU("SM_FC_STATUS"),
		t.Online ? _UU("SM_FC_ONLINE") : _UU("SM_FC_OFFLINE"));

	if (t.Online == false)
	{
		UniFormat(tmp, sizeof(tmp), _UU("SM_FC_ERROR_TAG"), _E(t.LastError), t.LastError);
		LvInsertAdd(b, ICO_STOP, NULL, 2,
			_UU("SM_FC_LAST_ERROR"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FC_START_TIME"), tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.FirstConnectedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FC_FIRST_TIME"), tmp);

	//if (t.Online == false)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CurrentConnectedTime), NULL);
		LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FC_CURRENT_TIME"), tmp);
	}

	UniToStru(tmp, t.NumTry);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_NUM_TRY"), tmp);

	UniToStru(tmp, t.NumConnected);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_NUM_CONNECTED"), tmp);

	UniToStru(tmp, t.NumFailed);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_NUM_FAILED"), tmp);

	LvInsertEnd(b, hWnd, L_STATUS);

	return true;
}

// 初期化
void SmFarmMemberDlgInit(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_FARM);

	FormatText(hWnd, S_TITLE, p->ServerName);

	// カラム初期化
	LvInit(hWnd, L_FARM_MEMBER);
	LvSetStyle(hWnd, L_FARM_MEMBER, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 0, _UU("SM_FM_COLUMN_1"), 90);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 1, _UU("SM_FM_COLUMN_2"), 150);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 2, _UU("SM_FM_COLUMN_3"), 140);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 3, _UU("SM_FM_COLUMN_4"), 60);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 4, _UU("SM_FM_COLUMN_5"), 80);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 5, _UU("SM_FM_COLUMN_6"), 80);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 6, _UU("SM_FM_COLUMN_7"), 80);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 7, _UU("SM_FM_COLUMN_8"), 160);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 8, _UU("SM_FM_COLUMN_9"), 160);

	SmFarmMemberDlgRefresh(hWnd, p);
}

// 更新
void SmFarmMemberDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsSelected(hWnd, L_FARM_MEMBER) && (LvIsMultiMasked(hWnd, L_FARM_MEMBER) == false));
	SetEnable(hWnd, B_CERT, LvIsSelected(hWnd, L_FARM_MEMBER) && (LvIsMultiMasked(hWnd, L_FARM_MEMBER) == false));
}

// 内容更新
void SmFarmMemberDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	RPC_ENUM_FARM t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumFarmMember(p->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	LvReset(hWnd, L_FARM_MEMBER);

	for (i = 0;i < t.NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t.Farms[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[64];
		wchar_t tmp4[64];
		wchar_t tmp5[64];
		wchar_t tmp6[64];
		wchar_t tmp7[64];
		wchar_t tmp8[64];

		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
		StrToUni(tmp2, sizeof(tmp2), e->Hostname);
		UniToStru(tmp3, e->Point);
		UniToStru(tmp4, e->NumSessions);
		UniToStru(tmp5, e->NumTcpConnections);
		UniToStru(tmp6, e->NumHubs);
		UniToStru(tmp7, e->AssignedClientLicense);
		UniToStru(tmp8, e->AssignedBridgeLicense);

		LvInsert(hWnd, L_FARM_MEMBER, e->Controller ? ICO_FARM : ICO_TOWER, (void *)e->Id, 9,
			e->Controller ? _UU("SM_FM_CONTROLLER") : _UU("SM_FM_MEMBER"),
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8);
	}

	FreeRpcEnumFarm(&t);

	SmFarmMemberDlgUpdate(hWnd, p);
}

// OK ボタン
void SmFarmMemberDlgOnOk(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

}

// ファーム メンバ証明書の表示
void SmFarmMemberCert(HWND hWnd, SM_SERVER *p, UINT id)
{
	RPC_FARM_INFO t;
	// 引数チェック
	if (hWnd == NULL || p == NULL || id == 0)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Id = id;

	if (CALL(hWnd, ScGetFarmInfo(p->Rpc, &t)) == false)
	{
		return;
	}

	CertDlg(hWnd, t.ServerCert, NULL, true);

	FreeRpcFarmInfo(&t);
}

// ファームメンバ情報の更新
bool SmRefreshFarmMemberInfo(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_FARM_INFO t;
	UINT id = (UINT)param;
	LVB *b;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL || id == 0)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	t.Id = id;

	if (CALL(hWnd, ScGetFarmInfo(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_FMINFO_TYPE"),
		t.Controller ? _UU("SM_FARM_CONTROLLER") : _UU("SM_FARM_MEMBER"));

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FMINFO_CONNECT_TIME"), tmp);

	IPToStr32(str, sizeof(str), t.Ip);
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FMINFO_IP"), tmp);

	StrToUni(tmp, sizeof(tmp), t.Hostname);
	LvInsertAdd(b, ICO_TOWER, NULL, 2, _UU("SM_FMINFO_HOSTNAME"), tmp);

	UniToStru(tmp, t.Point);
	LvInsertAdd(b, ICO_TEST, NULL, 2, _UU("SM_FMINFO_POINT"), tmp);

	UniToStru(tmp, t.Weight);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_FMINFO_WEIGHT"), tmp);

	UniToStru(tmp, t.NumPort);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FMINFO_NUM_PORT"), tmp);

	for (i = 0;i < t.NumPort;i++)
	{
		wchar_t tmp2[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_PORT"), i + 1);
		UniToStru(tmp2, t.Ports[i]);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, tmp, tmp2);
	}

	UniToStru(tmp, t.NumFarmHub);
	LvInsertAdd(b, ICO_HUB_OFFLINE, NULL, 2, _UU("SM_FMINFO_NUM_HUB"), tmp);

	for (i = 0;i < t.NumFarmHub;i++)
	{
		wchar_t tmp2[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_HUB"), i + 1);
		UniFormat(tmp2, sizeof(tmp2),
			t.FarmHubs[i].DynamicHub ? _UU("SM_FMINFO_HUB_TAG_2") : _UU("SM_FMINFO_HUB_TAG_1"),
			t.FarmHubs[i].HubName);
		LvInsertAdd(b, ICO_HUB, NULL, 2, tmp, tmp2);
	}

	UniToStru(tmp, t.NumSessions);
	LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_FMINFO_NUM_SESSION"), tmp);

	UniToStru(tmp, t.NumTcpConnections);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FMINFO_NUN_CONNECTION"), tmp);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcFarmInfo(&t);

	return true;
}

// ファームメンバ一覧ダイアログ
UINT SmFarmMemberDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	NMHDR *n;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmFarmMemberDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// ファーム メンバの情報を表示
			i = LvGetSelected(hWnd, L_FARM_MEMBER);
			if (i != INFINITE)
			{
				SmStatusDlg(hWnd, p, LvGetParam(hWnd, L_FARM_MEMBER, i), false, true,
					_UU("SM_FMINFO_CAPTION"), ICO_FARM, NULL, SmRefreshFarmMemberInfo);
			}
			break;

		case B_CERT:
			// サーバー証明書の表示
			i = LvGetSelected(hWnd, L_FARM_MEMBER);
			if (i != INFINITE)
			{
				SmFarmMemberCert(hWnd, p, (UINT)LvGetParam(hWnd, L_FARM_MEMBER, i));
			}
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case B_REFRESH:
			// 更新
			SmFarmMemberDlgRefresh(hWnd, p);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_FARM_MEMBER:
				SmFarmMemberDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_FARM_MEMBER);

	return 0;
}

// 文字列をポートリストに変換
LIST *SmStrToPortList(char *str)
{
	return StrToPortList(str);
}

// ダイアログ初期化
void SmFarmDlgInit(HWND hWnd, SM_SERVER *p)
{
	RPC_FARM t;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_FARM);

	// 現在の設定を取得
	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetFarmSetting(p->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	if (t.Weight == 0)
	{
		t.Weight = FARM_DEFAULT_WEIGHT;
	}

	FormatText(hWnd, S_TITLE, p->ServerName);
	DlgFont(hWnd, S_CURRENT, 11, true);

	SetText(hWnd, S_CURRENT, GetServerTypeStr(t.ServerType));

	switch (t.ServerType)
	{
	case SERVER_TYPE_FARM_CONTROLLER:
		Check(hWnd, R_CONTROLLER, true);
		break;

	case SERVER_TYPE_FARM_MEMBER:
		Check(hWnd, R_MEMBER, true);
		break;

	default:
		Check(hWnd, R_STANDALONE, true);
		break;
	}

	SetInt(hWnd, E_WEIGHT, t.Weight);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		Check(hWnd, R_CONTROLLER_ONLY, t.ControllerOnly);
	}

	if (t.ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		char tmp[MAX_PUBLIC_PORT_NUM * 8];
		UINT i;
		if (t.PublicIp != 0)
		{
			IpSet(hWnd, E_IP, t.PublicIp);
		}
		StrCpy(tmp, sizeof(tmp), "");
		if (t.NumPort != 0)
		{
			for (i = 0;i < t.NumPort;i++)
			{
				Format(tmp, sizeof(tmp), "%s%u", tmp, t.Ports[i]);
				if (i != (t.NumPort - 1))
				{
					StrCat(tmp, sizeof(tmp), ", ");
				}
			}
			SetTextA(hWnd, E_PORT, tmp);
		}
		SetTextA(hWnd, E_CONTROLLER, t.ControllerName);
		SetIntEx(hWnd, E_CONTROLLER_PORT, t.ControllerPort);
		SetTextA(hWnd, E_PASSWORD, HIDDEN_PASSWORD);
	}
	else
	{
		// ポート一覧を書き込む
		RPC_LISTENER_LIST t;
		char tmp[MAX_PUBLIC_PORT_NUM * 8];
		Zero(&t, sizeof(t));
		StrCpy(tmp, sizeof(tmp), "");
		if (CALL(hWnd, ScEnumListener(p->Rpc, &t)))
		{
			UINT i;
			if (t.NumPort != 0)
			{
				for (i = 0;i < t.NumPort;i++)
				{
					Format(tmp, sizeof(tmp), "%s%u", tmp, t.Ports[i]);
					if (i != (t.NumPort - 1))
					{
						StrCat(tmp, sizeof(tmp), ", ");
					}
				}
				SetTextA(hWnd, E_PORT, tmp);
			}
			FreeRpcListenerList(&t);
		}
	}

	SmFarmDlgUpdate(hWnd, p);

	FreeRpcFarm(&t);

	Focus(hWnd, IDOK);
}

// ダイアログ更新
void SmFarmDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	bool ok = true;
	bool farm_member_control = false;
	char *s;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, R_MEMBER))
	{
		LIST *o;
		UINT i = IpGetFilledNum(hWnd, E_IP);
		if (i != 0 && i != 4)
		{
			ok = false;
		}

		s = GetTextA(hWnd, E_PORT);
		o = SmStrToPortList(s);
		if (o == NULL)
		{
			ok = false;
		}
		else
		{
			ReleaseList(o);
		}
		Free(s);

		if (IsEmpty(hWnd, E_CONTROLLER))
		{
			ok = false;
		}

		i = GetInt(hWnd, E_CONTROLLER_PORT);
		if (i == 0 || i >= 65536)
		{
			ok = false;
		}

		farm_member_control = true;
	}

	if (IsChecked(hWnd, R_STANDALONE))
	{
		Disable(hWnd, S_1);
		Disable(hWnd, S_2);
		Disable(hWnd, E_WEIGHT);
	}
	else
	{
		Enable(hWnd, S_1);
		Enable(hWnd, S_2);
		Enable(hWnd, E_WEIGHT);
	}

	if (IsChecked(hWnd, R_CONTROLLER))
	{
		Enable(hWnd, R_CONTROLLER_ONLY);
	}
	else
	{
		Disable(hWnd, R_CONTROLLER_ONLY);
	}

	if (IsChecked(hWnd, R_CONTROLLER) || IsChecked(hWnd, R_MEMBER))
	{
		if (GetInt(hWnd, E_WEIGHT) == 0)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, S_IP_1, farm_member_control);
	SetEnable(hWnd, E_IP, farm_member_control);
	SetEnable(hWnd, S_IP_2, farm_member_control);
	SetEnable(hWnd, S_PORT_1, farm_member_control);
	SetEnable(hWnd, E_PORT, farm_member_control);
	SetEnable(hWnd, S_PORT_2, farm_member_control);
	SetEnable(hWnd, S_PORT_3, farm_member_control);
	SetEnable(hWnd, E_CONTROLLER, farm_member_control);
	SetEnable(hWnd, S_CONTROLLER, farm_member_control);
	SetEnable(hWnd, E_CONTROLLER_PORT, farm_member_control);
	SetEnable(hWnd, S_CONTROLLER_PORT, farm_member_control);
	SetEnable(hWnd, S_PASSWORD, farm_member_control);
	SetEnable(hWnd, E_PASSWORD, farm_member_control);
	SetEnable(hWnd, IDOK, ok);
}

// OK ボタン
void SmFarmDlgOnOk(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// メッセージ表示
	if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_OKCANCEL | MB_DEFBUTTON2,
		_UU("SM_FARM_REBOOT_MSG")) == IDOK)
	{
		RPC_FARM t;
		Zero(&t, sizeof(t));
		t.ServerType = SERVER_TYPE_STANDALONE;
		if (IsChecked(hWnd, R_CONTROLLER))
		{
			t.ServerType = SERVER_TYPE_FARM_CONTROLLER;
		}
		if (IsChecked(hWnd, R_MEMBER))
		{
			t.ServerType = SERVER_TYPE_FARM_MEMBER;
		}

		t.ControllerOnly = IsChecked(hWnd, R_CONTROLLER_ONLY);
		t.Weight = GetInt(hWnd, E_WEIGHT);

		if (t.ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			char *s;
			char pass[MAX_SIZE];
			t.PublicIp = IpGet(hWnd, E_IP);
			s = GetTextA(hWnd, E_PORT);
			if (s != NULL)
			{
				LIST *o = SmStrToPortList(s);
				if (o != NULL)
				{
					UINT i;
					t.NumPort = LIST_NUM(o);
					t.Ports = ZeroMalloc(sizeof(UINT) * t.NumPort);
					for (i = 0;i < t.NumPort;i++)
					{
						t.Ports[i] = (UINT)LIST_DATA(o, i);
					}
					ReleaseList(o);
				}
				Free(s);
			}
			GetTxtA(hWnd, E_CONTROLLER, t.ControllerName, sizeof(t.ControllerName));
			t.ControllerPort = GetInt(hWnd, E_CONTROLLER_PORT);
			GetTxtA(hWnd, E_PASSWORD, pass, sizeof(pass));
			if (StrCmp(pass, HIDDEN_PASSWORD) != 0)
			{
				Hash(t.MemberPassword, pass, StrLen(pass), true);
			}
		}

		// 設定更新
		if (CALL(hWnd, ScSetFarmSetting(p->Rpc, &t)) == false)
		{
			return;
		}

		FreeRpcFarm(&t);

		EndDialog(hWnd, true);
	}
}

// サーバー ファーム ダイアログ プロシージャ
UINT SmFarmDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmFarmDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_STANDALONE:
		case R_CONTROLLER:
		case R_MEMBER:
		case E_IP:
		case E_PORT:
		case E_CONTROLLER:
		case E_CONTROLLER_PORT:
		case E_PASSWORD:
		case R_CONTROLLER_ONLY:
		case E_WEIGHT:
			SmFarmDlgUpdate(hWnd, p);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmFarmDlgOnOk(hWnd, p);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case R_MEMBER:
			if (IsChecked(hWnd, R_MEMBER))
			{
				Focus(hWnd, E_IP);
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// サーバー ファーム構成
bool SmFarmDlg(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_SM_FARM, SmFarmDlgProc, p);
}

// コネクション情報の更新
bool SmRefreshConnectionStatus(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_CONNECTION_INFO t;
	SM_CONNECTION_INFO *info = (SM_CONNECTION_INFO *)param;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Name, sizeof(t.Name), info->ConnectionName);
	if (CALL(hWnd, ScGetConnectionInfo(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	StrToUni(tmp, sizeof(tmp), t.Name);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_CONNINFO_NAME"), tmp);

	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_TYPE"), SmGetConnectionTypeStr(t.Type));

	StrToUni(tmp, sizeof(tmp), t.Hostname);
	LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_CONNINFO_HOSTNAME"), tmp);

	UniToStru(tmp, t.Port);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_CONNINFO_PORT"), tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_CONNINFO_TIME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.ServerStr);
	LvInsertAdd(b, ICO_VPNSERVER, NULL, 2, _UU("SM_CONNINFO_SERVER_STR"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ServerVer / 100, t.ServerVer % 100);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_SERVER_VER"), tmp);

	UniToStru(tmp, t.ServerBuild);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_SERVER_BUILD"), tmp);

	if (StrLen(t.ClientStr) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.ClientStr);
		LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_CONNINFO_CLIENT_STR"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ClientVer / 100, t.ClientVer % 100);
		LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_CLIENT_VER"), tmp);

		UniToStru(tmp, t.ClientBuild);
		LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_CLIENT_BUILD"), tmp);
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	return true;
}

// 初期化
void SmConnectionDlgInit(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PROTOCOL);
	FormatText(hWnd, S_TITLE, p->ServerName);

	// カラム初期化
	LvInit(hWnd, L_LIST);
	LvSetStyle(hWnd, L_LIST, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_CONN_COLUMN_1"), 90);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_CONN_COLUMN_2"), 150);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_CONN_COLUMN_3"), 200);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_CONN_COLUMN_4"), 80);

	SmConnectionDlgRefresh(hWnd, p);
	SmConnectionDlgUpdate(hWnd, p);
}

// 更新
void SmConnectionDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	LVB *b;
	UINT i;
	RPC_ENUM_CONNECTION t;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumConnection(p->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumConnection;i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t name[MAX_SIZE];
		wchar_t datetime[MAX_SIZE];
		RPC_ENUM_CONNECTION_ITEM *e = &t.Connections[i];

		StrToUni(name, sizeof(name), e->Name);
		UniFormat(tmp, sizeof(tmp), _UU("SM_HOSTNAME_AND_PORT"), e->Hostname, e->Port);
		GetDateTimeStrEx64(datetime, sizeof(datetime), SystemToLocal64(e->ConnectedTime), NULL);

		LvInsertAdd(b, ICO_PROTOCOL, NULL, 4, name, tmp, datetime,
			SmGetConnectionTypeStr(e->Type));
	}

	LvInsertEnd(b, hWnd, L_LIST);

	FreeRpcEnumConnetion(&t);
}

// コントロール更新
void SmConnectionDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	bool b = false;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_LIST) && (LvIsMultiMasked(hWnd, L_LIST) == false))
	{
		b = true;
	}

	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, B_DISCONNECT, b && p->ServerAdminMode);
}

// コネクション一覧プロシージャ
UINT SmConnectionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	NMHDR *n;
	wchar_t *s;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmConnectionDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// コネクション情報を表示
			s = LvGetSelectedStr(hWnd, L_LIST, 0);
			if (s != NULL)
			{
				wchar_t caption[MAX_SIZE];
				SM_CONNECTION_INFO info;
				UniFormat(caption, sizeof(caption), _UU("SM_CONNINFO_CAPTION"),
					s);
				Zero(&info, sizeof(info));
				info.ConnectionName = CopyUniToStr(s);
				info.p = p;
				SmStatusDlg(hWnd, p, &info, false, false, caption, ICO_PROTOCOL,
					NULL, SmRefreshConnectionStatus);
				Free(info.ConnectionName);
				Free(s);
			}
			break;

		case B_DISCONNECT:
			// 切断
			s = LvGetSelectedStr(hWnd, L_LIST, 0);
			if (s != NULL)
			{
				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_CONN_DISCONNECT_MSG"), s) == IDYES)
				{
					char tmp[MAX_SIZE];
					RPC_DISCONNECT_CONNECTION t;

					UniToStr(tmp, sizeof(tmp), s);
					Zero(&t, sizeof(t));
					StrCpy(t.Name, sizeof(t.Name), tmp);

					if (CALL(hWnd, ScDisconnectConnection(p->Rpc, &t)))
					{
						SmConnectionDlgRefresh(hWnd, p);
					}
				}
				Free(s);
			}
			break;

		case B_REFRESH:
			// 最新の状態に更新
			SmConnectionDlgRefresh(hWnd, p);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmConnectionDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// コネクション一覧の表示
void SmConnectionDlg(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_CONNECTION, SmConnectionDlgProc, p);
}

// コネクション種類文字列の取得
wchar_t *SmGetConnectionTypeStr(UINT type)
{
	return GetConnectionTypeStr(type);
}

// サーバー情報の更新
bool SmRefreshServerInfo(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_SERVER_INFO t;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetServerInfo(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	// 製品名
	StrToUni(tmp, sizeof(tmp), t.ServerProductName);
	LvInsertAdd(b, ICO_VPNSERVER, NULL, 2, _UU("SM_INFO_PRODUCT_NAME"), tmp);

	// バージョン
	StrToUni(tmp, sizeof(tmp), t.ServerVersionString);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_INFO_VERSION"), tmp);

	// ビルド
	StrToUni(tmp, sizeof(tmp), t.ServerBuildInfoString);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_INFO_BUILD"), tmp);

	// ホスト名
	StrToUni(tmp, sizeof(tmp), t.ServerHostName);
	LvInsertAdd(b, ICO_TOWER, NULL, 2, _UU("SM_INFO_HOSTNAME"), tmp);

	// 種類
	LvInsertAdd(b, t.ServerType == SERVER_TYPE_STANDALONE ? ICO_SERVER_ONLINE : ICO_FARM, 0,
		2, _UU("SM_ST_SERVER_TYPE"),
		GetServerTypeStr(t.ServerType));

	// OS
	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsSystemName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_SYSTEM_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsProductName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_PRODUCT_NAME"), tmp);

	if (t.OsInfo.OsServicePack != 0)
	{
		UniFormat(tmp, sizeof(tmp), _UU("SM_OS_SP_TAG"), t.OsInfo.OsServicePack);
		LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_SERVICE_PACK"), tmp);
	}

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVendorName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_VENDER_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVersion);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_VERSION"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_KERNEL_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelVersion);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_KERNEL_VERSION"), tmp);

	SmAddServerCaps(b, p->CapsList);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcServerInfo(&t);

	return true;
}

// サーバーの Caps を画面に表示する
void SmAddServerCaps(LVB *b, CAPSLIST *t)
{
	UINT i;
	// 引数チェック
	if (b == NULL || t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);
		wchar_t title[MAX_SIZE];
		char name[256];

		Format(name, sizeof(name), "CT_%s", c->Name);

		UniStrCpy(title, sizeof(title), _UU(name));

		if (UniIsEmptyStr(title))
		{
			UniFormat(title, sizeof(title), L"%S", (StrLen(c->Name) >= 2) ? c->Name + 2 : c->Name);
		}

		if (StartWith(c->Name, "b_"))
		{
			bool icon_pass = c->Value == 0 ? false : true;
			if (StrCmpi(c->Name, "b_must_install_pcap") == 0)
			{
				// WinPcap の項目のみ反転する
				icon_pass = !icon_pass;
			}
			LvInsertAdd(b, icon_pass == false ? ICO_DISCARD : ICO_PASS,
				NULL, 2, title, c->Value == 0 ? _UU("CAPS_NO") : _UU("CAPS_YES"));
		}
		else
		{
			wchar_t str[64];
			UniToStru(str, c->Value);
			LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, title, str);
		}
	}
}

// サーバー状態の更新
bool SmRefreshServerStatus(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_SERVER_STATUS t;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetServerStatus(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	// サーバーの種類
	LvInsertAdd(b, t.ServerType == SERVER_TYPE_STANDALONE ? ICO_SERVER_ONLINE : ICO_FARM, 0,
		2, _UU("SM_ST_SERVER_TYPE"),
		GetServerTypeStr(t.ServerType));

	// TCP コネクション数
	UniToStru(tmp, t.NumTcpConnections);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_ST_NUM_TCP"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// ローカル TCP コネクション数
		UniToStru(tmp, t.NumTcpConnectionsLocal);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_ST_NUM_TCP_LOCAL"), tmp);

		// リモート TCP コネクション数
		UniToStru(tmp, t.NumTcpConnectionsRemote);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_ST_NUM_TCP_REMOTE"), tmp);
	}

	// 仮想 HUB 数
	UniToStru(tmp, t.NumHubTotal);
	LvInsertAdd(b, ICO_HUB, NULL, 2, _UU("SM_ST_NUM_HUB_TOTAL"), tmp);

	if (t.ServerType != SERVER_TYPE_STANDALONE)
	{
		// スタティック HUB 数
		UniToStru(tmp, t.NumHubStatic);
		LvInsertAdd(b, ICO_HUB, NULL, 2, _UU("SM_ST_NUM_HUB_STATIC"), tmp);

		// ダイナミック HUB 数
		UniToStru(tmp, t.NumHubDynamic);
		LvInsertAdd(b, ICO_HUB, NULL, 2, _UU("SM_ST_NUM_HUB_DYNAMIC"), tmp);
	}

	// セッション数
	UniToStru(tmp, t.NumSessionsTotal);
	LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_ST_NUM_SESSION_TOTAL"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// ローカルセッション数
		UniToStru(tmp, t.NumSessionsLocal);
		LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_ST_NUM_SESSION_LOCAL"), tmp);

		// ローカルセッション数
		UniToStru(tmp, t.NumSessionsRemote);
		LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_ST_NUM_SESSION_REMOTE"), tmp);
	}

	// MAC テーブル数
	UniToStru(tmp, t.NumMacTables);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_ST_NUM_MAC_TABLE"), tmp);

	// IP テーブル数
	UniToStru(tmp, t.NumIpTables);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_ST_NUM_IP_TABLE"), tmp);

	// ユーザー数
	UniToStru(tmp, t.NumUsers);
	LvInsertAdd(b, ICO_USER, NULL, 2, _UU("SM_ST_NUM_USERS"), tmp);

	// グループ数
	UniToStru(tmp, t.NumGroups);
	LvInsertAdd(b, ICO_GROUP, NULL, 2, _UU("SM_ST_NUM_GROUPS"), tmp);

	// 割り当て済みライセンス数
	UniToStru(tmp, t.AssignedClientLicenses);
	LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_CLIENT_LICENSE"), tmp);
	UniToStru(tmp, t.AssignedBridgeLicenses);
	LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_BRIDGE_LICENSE"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UniToStru(tmp, t.AssignedClientLicensesTotal);
		LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_CLIENT_LICENSE_EX"), tmp);
		UniToStru(tmp, t.AssignedBridgeLicensesTotal);
		LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_BRIDGE_LICENSE_EX"), tmp);
	}

	// トラフィック
	SmInsertTrafficInfo(b, &t.Traffic);

	// サーバー起動時刻
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartTime), NULL);
	LvInsertAdd(b, ICO_NULL, NULL, 2, _UU("SM_ST_START_TIME"), tmp);

	// 現在時刻
	GetDateTimeStrMilli64(str, sizeof(str), SystemToLocal64(t.CurrentTime));
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, ICO_NULL, NULL, 2, _UU("SM_ST_CURRENT_TIME"), tmp);

	// Tick 値
	UniFormat(tmp, sizeof(tmp), L"%I64u", t.CurrentTick);
	LvInsertAdd(b, ICO_NULL, NULL, 2, _UU("SM_ST_CURRENT_TICK"), tmp);

	// メモリ情報
	if (t.MemInfo.TotalMemory != 0)
	{
		char vv[128];

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_TOTAL_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_USED_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreeMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_FREE_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_TOTAL_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_USED_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreePhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_FREE_PHYS"), tmp);
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	return true;
}

// 初期化
void SmSaveKeyPairDlgInit(HWND hWnd, SM_SAVE_KEY_PAIR *s)
{
	UINT current;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	current = MsRegReadInt(REG_CURRENT_USER, SM_REG_KEY, "SavePkcs12");

	if (current == 1)
	{
		Check(hWnd, R_PKCS12, true);
	}
	else if (current == 2)
	{
		Check(hWnd, R_SECURE, true);
	}
	else
	{
		Check(hWnd, R_X509_AND_KEY, true);
	}

	SmSaveKeyPairDlgUpdate(hWnd, s);
}

// 更新
void SmSaveKeyPairDlgUpdate(HWND hWnd, SM_SAVE_KEY_PAIR *s)
{
	SECURE_DEVICE *dev;
	bool ok = true;
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	dev = GetSecureDevice(SmGetCurrentSecureIdFromReg());
	if (dev == NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), _UU("SEC_CURRENT_NO_DEVICE"));
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("SEC_CURRENT_DEVICE"), dev->DeviceName);
	}

	SetText(hWnd, S_INFO, tmp);

	if (IsChecked(hWnd, R_USE_PASS))
	{
		char *s1, *s2;
		s1 = GetTextA(hWnd, E_PASS1);
		s2 = GetTextA(hWnd, E_PASS2);
		if (StrCmp(s1, s2) != 0)
		{
			ok = false;
		}
		Free(s1);
		Free(s2);
	}

	if (IsChecked(hWnd, R_SECURE))
	{
		if (dev == NULL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, B_SELECT, IsChecked(hWnd, R_SECURE));
	SetEnable(hWnd, B_SECURE_MANAGER, IsChecked(hWnd, R_SECURE));
	SetEnable(hWnd, S_INFO, IsChecked(hWnd, R_SECURE));

	SetEnable(hWnd, E_PASS1, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, E_PASS2, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS1, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS2, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, R_USE_PASS, (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS3, (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS4, (IsChecked(hWnd, R_SECURE) == false));

	SetEnable(hWnd, IDOK, ok);
}

// OK ボタン
void SmSaveKeyPairDlgOnOk(HWND hWnd, SM_SAVE_KEY_PAIR *s)
{
	UINT pkcs12;
	char pass[MAX_SIZE];
	char *password;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	pkcs12 = 0;

	if (IsChecked(hWnd, R_PKCS12))
	{
		pkcs12 = 1;
	}
	else if (IsChecked(hWnd, R_SECURE))
	{
		pkcs12 = 2;
	}
	MsRegWriteInt(REG_CURRENT_USER, SM_REG_KEY, "SavePkcs12", pkcs12);

	if (pkcs12 != 2)
	{
		GetTxtA(hWnd, E_PASS1, pass, sizeof(pass));

		if (StrLen(pass) != 0)
		{
			password = pass;
		}
		else
		{
			password = NULL;
		}

		if (pkcs12 == false)
		{
			// X509 と KEY に書き込む
			wchar_t *x509_name, *key_name;
			x509_name = SaveDlg(hWnd, _UU("DLG_CERT_FILES"), _UU("DLG_SAVE_CERT"), NULL, L".cer");
			if (x509_name == NULL)
			{
				// キャンセル
				return;
			}
			else
			{
				wchar_t default_key_name[MAX_SIZE];
				UniReplaceStrEx(default_key_name, sizeof(default_key_name), x509_name,
					L".cer", L"", false);
				UniReplaceStrEx(default_key_name, sizeof(default_key_name), default_key_name,
								L".crt", L"", false);
				UniStrCat(default_key_name, sizeof(default_key_name), L".key");
				key_name = SaveDlg(hWnd, _UU("DLG_KEY_FILTER"), _UU("DLG_SAVE_KEY"),
					default_key_name, L".key");
				if (key_name == NULL)
				{
					// キャンセル
					Free(x509_name);
					return;
				}
				else
				{
					bool ok = true;
					char filename1[MAX_SIZE];
					char filename2[MAX_SIZE];

					UniToStr(filename1, sizeof(filename1), x509_name);
					UniToStr(filename2, sizeof(filename2), key_name);

					// 証明書の保存
					if (XToFile(s->Cert, filename1, true) == false)
					{
						MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_CERT_SAVE_ERROR"));
						ok = false;
					}
					else
					{
						if (KToFile(s->Key, filename2, true, password) == false)
						{
							MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_KEY_SAVE_ERROR"));
							ok = false;
						}
					}

					if (ok)
					{
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("DLG_KEY_PAIR_SAVE_OK"));
						EndDialog(hWnd, true);
					}

					Free(key_name);
				}
				Free(x509_name);
			}
		}
		else
		{
			// PKCS#12 に書き込む
			wchar_t *name = SaveDlg(hWnd, _UU("DLG_PKCS12_FILTER"), _UU("DLG_SAVE_P12"), NULL, L".p12");
			if (name == NULL)
			{
				// キャンセル
				return;
			}
			else
			{
				P12 *p12;
				char filename[MAX_SIZE];
				UniToStr(filename, sizeof(filename), name);

				// PKCS#12 に変換
				p12 = NewP12(s->Cert, s->Key, pass);
				if (p12 == NULL)
				{
					// 失敗
					MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_KEY_PAIR_SAVE_OK"));
				}
				else
				{
					// 保存
					if (P12ToFile(p12, filename) == false)
					{
						// 失敗
						MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_KEY_PAIR_SAVE_OK"));
					}
					else
					{
						// 成功
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("DLG_KEY_PAIR_SAVE_OK"));
						EndDialog(hWnd, true);
					}
					FreeP12(p12);
				}

				Free(name);
			}
		}
	}
	else
	{
		char default_name[MAX_SIZE];
		char *object_name;
		bool ok = false;
		X *x;
		K *k;
		WINUI_SECURE_BATCH batch[] =
		{
			{WINUI_SECURE_WRITE_CERT, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL},
			{WINUI_SECURE_WRITE_KEY, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL},
		};

		x = s->Cert;
		k = s->Key;

		// デフォルトの名前を生成する
		GetPrintNameFromXA(default_name, sizeof(default_name), x);
		ConvertSafeFileName(default_name, sizeof(default_name), default_name);

		object_name = StringDlgA(hWnd, _UU("SEC_OBJECT_NAME_TITLE"),
			_UU("SEC_OBJECT_NAME_INFO"), default_name, ICO_CERT, false, false);

		if (object_name != NULL)
		{
			// 書き込みと列挙
			batch[0].InputX = x;
			batch[0].Name = object_name;
			batch[1].InputK = k;
			batch[1].Name = object_name;

			if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), SmGetCurrentSecureIdFromReg(), 0) == false)
			{
				// 失敗
			}
			else
			{
				ok = true;
			}

			Free(object_name);
		}

		if (ok)
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SEC_NEW_CERT_IMPORT_OK"));

			EndDialog(hWnd, true);
		}
	}
}

// 証明書と秘密鍵の保存ダイアログ
UINT SmSaveKeyPairDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SAVE_KEY_PAIR *s = (SM_SAVE_KEY_PAIR *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmSaveKeyPairDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PASS1:
		case E_PASS2:
		case R_USE_PASS:
		case R_SECURE:
		case R_X509_AND_KEY:
		case R_PKCS12:
			SmSaveKeyPairDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmSaveKeyPairDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case R_USE_PASS:
			if (IsChecked(hWnd, R_USE_PASS))
			{
				FocusEx(hWnd, E_PASS1);
			}
			break;

		case B_SELECT:
			SmSelectSecureId(hWnd);
			SmSaveKeyPairDlgUpdate(hWnd, s);
			break;

		case B_SECURE_MANAGER:
			CmSecureManagerEx(hWnd, SmGetCurrentSecureId(hWnd), true);
			SmSaveKeyPairDlgUpdate(hWnd, s);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 証明書と秘密鍵を保存する
bool SmSaveKeyPairDlg(HWND hWnd, X *x, K *k)
{
	SM_SAVE_KEY_PAIR s;
	// 引数チェック
	if (hWnd == NULL || x == NULL || k == NULL)
	{
		return false;
	}

	Zero(&s, sizeof(s));
	s.Cert = x;
	s.Key = k;

	return Dialog(hWnd,	D_SM_SAVE_KEY_PAIR, SmSaveKeyPairDlgProc, &s);
}

// SSL 関係ダイアログで OK がクリックされた
void SmSslDlgOnOk(HWND hWnd, SM_SSL *s)
{
	char *name;
	RPC_KEEP t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->p->ServerAdminMode == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	name = GetTextA(hWnd, C_CIPHER);
	if (name == NULL)
	{
		return;
	}
	else
	{
		RPC_STR t;
		Zero(&t, sizeof(t));
		t.String = name;

		// 暗号化アルゴリズムの設定
		if (CALL(hWnd, ScSetServerCipher(s->p->Rpc, &t)) == false)
		{
			Focus(hWnd, C_CIPHER);
			return;
		}
		FreeRpcStr(&t);
	}

	if (s->SetCertAndKey)
	{
		// 証明書のセット
		RPC_KEY_PAIR t;
		Zero(&t, sizeof(t));

		t.Cert = CloneX(s->Cert);
		t.Key = CloneK(s->Key);

		if (CALL(hWnd, ScSetServerCert(s->p->Rpc, &t)) == false)
		{
			return;
		}
		FreeRpcKeyPair(&t);

		MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_CERT_SET_MSG"));
	}

	Zero(&t, sizeof(t));
	t.UseKeepConnect = IsChecked(hWnd, R_USE_KEEP_CONNECT);
	GetTxtA(hWnd, E_HOSTNAME, t.KeepConnectHost, sizeof(t.KeepConnectHost));
	t.KeepConnectPort = GetInt(hWnd, E_PORT);
	t.KeepConnectInterval = GetInt(hWnd, E_INTERVAL);
	t.KeepConnectProtocol = IsChecked(hWnd, R_UDP) ? 1 : 0;

	CALL(hWnd, ScSetKeep(s->p->Rpc, &t));

	if (GetCapsBool(s->p->CapsList, "b_support_syslog"))
	{
		if (s->p->ServerAdminMode)
		{
			SYSLOG_SETTING set;

			Zero(&set, sizeof(set));
			GetTxtA(hWnd, E_SYSLOG_HOSTNAME, set.Hostname, sizeof(set.Hostname));
			set.Port = GetInt(hWnd, E_SYSLOG_PORT);
			set.SaveType = CbGetSelect(hWnd, C_SYSLOG);

			if (CALL(hWnd, ScSetSysLog(s->p->Rpc, &set)) == false)
			{
				return;
			}
		}
	}

	EndDialog(hWnd, true);
}

// SSL 関係ダイアログ初期化
void SmSslDlgInit(HWND hWnd, SM_SSL *s)
{
	UINT i;
	TOKEN_LIST *cipher_list;
	RPC_KEEP t;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	// 暗号化アルゴリズム一覧を設定する
	cipher_list = GetCipherList();
	CbSetHeight(hWnd, C_CIPHER, 18);
	for (i = 0;i < cipher_list->NumTokens;i++)
	{
		wchar_t tmp[MAX_SIZE];
		char *name = cipher_list->Token[i];
		StrToUni(tmp, sizeof(tmp), name);
		CbAddStr(hWnd, C_CIPHER, tmp, 0);
	}

	if (s->p != NULL)
	{
		// サーバーから暗号化アルゴリズム名を取得する
		RPC_STR t;
		Zero(&t, sizeof(t));
		if (CALL(hWnd, ScGetServerCipher(s->p->Rpc, &t)))
		{
			wchar_t tmp[MAX_SIZE];
			StrToUni(tmp, sizeof(tmp), t.String);
			SetText(hWnd, C_CIPHER, tmp);
			FreeRpcStr(&t);
		}
		else
		{
			EndDialog(hWnd, 0);
			return;
		}
	}

	if (s->p != NULL)
	{
		wchar_t tmp[MAX_SIZE];
		// サーバーから SSL 証明書と秘密鍵を取得する
		RPC_KEY_PAIR t;
		s->SetCertAndKey = false;
		Zero(&t, sizeof(t));
		if (CALL(hWnd, ScGetServerCert(s->p->Rpc, &t)))
		{
			// 証明書と鍵のコピー
			s->Cert = CloneX(t.Cert);
			s->Key = CloneK(t.Key);
			FreeRpcKeyPair(&t);
		}
		else
		{
			EndDialog(hWnd, 0);
			return;
		}

		// 証明書情報の表示
		SmGetCertInfoStr(tmp, sizeof(tmp), s->Cert);
		SetText(hWnd, S_CERT_INFO, tmp);
	}

	// パスワード変更
	SetEnable(hWnd, B_PASSWORD, s->p->ServerAdminMode);

	// ボタンの有効化 / 無効化
	SetEnable(hWnd, B_IMPORT, s->p->ServerAdminMode);
	SetEnable(hWnd, B_EXPORT, s->p->ServerAdminMode);
	SetEnable(hWnd, R_USE_KEEP_CONNECT, s->p->ServerAdminMode);

	if (s->p->ServerAdminMode == false)
	{
		Disable(hWnd, C_CIPHER);
	}

	if (CALL(hWnd, ScGetKeep(s->p->Rpc, &t)))
	{
		Check(hWnd, R_USE_KEEP_CONNECT, t.UseKeepConnect);
		SetTextA(hWnd, E_HOSTNAME, t.KeepConnectHost);
		SetIntEx(hWnd, E_PORT, t.KeepConnectPort);
		SetInt(hWnd, E_INTERVAL, t.KeepConnectInterval);
		Check(hWnd, R_TCP, t.KeepConnectProtocol == 0);
		Check(hWnd, R_UDP, t.KeepConnectProtocol != 0);
	}

	CbSetHeight(hWnd, C_SYSLOG, 18);
	CbReset(hWnd, C_SYSLOG);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_0"), SYSLOG_NONE);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_1"), SYSLOG_SERVER_LOG);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_2"), SYSLOG_SERVER_AND_HUB_SECURITY_LOG);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_3"), SYSLOG_SERVER_AND_HUB_ALL_LOG);

	if (GetCapsBool(s->p->CapsList, "b_support_syslog"))
	{
		SYSLOG_SETTING set;

		SetEnable(hWnd, C_SYSLOG, s->p->ServerAdminMode);
		SetEnable(hWnd, E_SYSLOG_HOSTNAME, s->p->ServerAdminMode);
		SetEnable(hWnd, E_SYSLOG_PORT, s->p->ServerAdminMode);
		SetEnable(hWnd, S_01, s->p->ServerAdminMode);
		SetEnable(hWnd, S_02, s->p->ServerAdminMode);

		Zero(&set, sizeof(set));

		if (CALL(hWnd, ScGetSysLog(s->p->Rpc, &set)))
		{
			SetTextA(hWnd, E_SYSLOG_HOSTNAME, set.Hostname);
			SetInt(hWnd, E_SYSLOG_PORT, set.Port == 0 ? SYSLOG_PORT : set.Port);
			CbSelect(hWnd, C_SYSLOG, set.SaveType);
		}
	}
	else
	{
		Disable(hWnd, C_SYSLOG);
		Disable(hWnd, E_SYSLOG_HOSTNAME);
		Disable(hWnd, E_SYSLOG_PORT);
		Disable(hWnd, S_01);
		Disable(hWnd, S_02);
	}

	SmSslDlgUpdate(hWnd, s);
}

// SSL 関係ダイアログコントロール更新
void SmSslDlgUpdate(HWND hWnd, SM_SSL *s)
{
	bool ok = true;
	bool b;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, R_USE_KEEP_CONNECT))
	{
		UINT i;
		b = true;
		if (IsEmpty(hWnd, E_HOSTNAME))
		{
			ok = false;
		}
		i = GetInt(hWnd, E_PORT);
		if (i == 0 || i >= 65536)
		{
			ok = false;
		}
		i = GetInt(hWnd, E_INTERVAL);
		if (i < 5 || i > 600)
		{
			ok = false;
		}
	}
	else
	{
		b = false;
	}

	if (IsEnable(hWnd, C_SYSLOG))
	{
		UINT i = CbGetSelect(hWnd, C_SYSLOG);

		SetEnable(hWnd, E_SYSLOG_HOSTNAME, i != SYSLOG_NONE);
		SetEnable(hWnd, E_SYSLOG_PORT, i != SYSLOG_NONE);
		SetEnable(hWnd, S_01, i != SYSLOG_NONE);
		SetEnable(hWnd, S_02, i != SYSLOG_NONE);
	}

	SetEnable(hWnd, S_HOSTNAME, b);
	SetEnable(hWnd, E_HOSTNAME, b);
	SetEnable(hWnd, S_PORT, b);
	SetEnable(hWnd, E_PORT, b);
	SetEnable(hWnd, S_INTERVAL, b);
	SetEnable(hWnd, E_INTERVAL, b);
	SetEnable(hWnd, S_INTERVAL2, b);
	SetEnable(hWnd, S_PROTOCOL, b);
	SetEnable(hWnd, R_TCP, b);
	SetEnable(hWnd, R_UDP, b);
	SetEnable(hWnd, S_INFO, b);

	SetEnable(hWnd, IDOK, ok);
}

// 証明書情報文字列の取得
void SmGetCertInfoStr(wchar_t *str, UINT size, X *x)
{
	wchar_t subject[MAX_SIZE];
	wchar_t issuer[MAX_SIZE];
	wchar_t date[MAX_SIZE];
	// 引数チェック
	if (x == NULL || str == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	GetPrintNameFromName(subject, sizeof(subject), x->subject_name);
	GetPrintNameFromName(issuer, sizeof(issuer), x->issuer_name);
	GetDateStrEx64(date, sizeof(date), x->notAfter, NULL);

	UniFormat(str, size, _UU("CM_CERT_INFO"), subject, issuer, date);
}

// SSL 関係ダイアログプロシージャ
UINT SmSslDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SSL *s = (SM_SSL *)param;
	X *x;
	K *k;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SmSslDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_USE_KEEP_CONNECT:
		case E_HOSTNAME:
		case E_PORT:
		case E_INTERVAL:
		case R_TCP:
		case R_UDP:
		case C_SYSLOG:
		case E_SYSLOG_HOSTNAME:
		case E_SYSLOG_PORT:
			SmSslDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// OK ボタン
			SmSslDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;

		case B_IMPORT:
			// インポート
			if (CmLoadXAndK(hWnd, &x, &k))
			{
				wchar_t tmp[MAX_SIZE];
				FreeX(s->Cert);
				FreeK(s->Key);
				s->Cert = x;
				s->Key = k;
				s->SetCertAndKey = true;
				// 証明書情報の表示
				SmGetCertInfoStr(tmp, sizeof(tmp), s->Cert);
				SetText(hWnd, S_CERT_INFO, tmp);
			}
			break;

		case B_EXPORT:
			// エクスポート
			SmSaveKeyPairDlg(hWnd, s->Cert, s->Key);
			break;

		case B_VIEW:
			// 証明書の表示
			CertDlg(hWnd, s->Cert, NULL, true);
			break;

		case B_PASSWORD:
			// パスワード変更
			Dialog(hWnd, D_SM_CHANGE_PASSWORD, SmChangeServerPasswordDlg, s->p);
			break;

		case R_USE_KEEP_CONNECT:
			if (IsChecked(hWnd, R_USE_KEEP_CONNECT))
			{
				FocusEx(hWnd, E_HOSTNAME);
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// SSL 関係ダイアログの表示
void SmSslDlg(HWND hWnd, SM_SERVER *p)
{
	SM_SSL s;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&s, sizeof(s));
	s.p = p;

	Dialog(hWnd, D_SM_SSL, SmSslDlgProc, &s);

	// クリーンアップ
	FreeX(s.Cert);
	FreeK(s.Key);
}

// リスナー作成ダイアログプロシージャ
UINT SmCreateListenerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT port;
	RPC_LISTENER t;
	SM_SERVER *p = (SM_SERVER *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		Focus(hWnd, E_PORT);
		Disable(hWnd, IDOK);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PORT:
			port = GetInt(hWnd, E_PORT);
			if (port == 0 || port >= 65536)
			{
				Disable(hWnd, IDOK);
			}
			else
			{
				Enable(hWnd, IDOK);
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			port = GetInt(hWnd, E_PORT);
			Zero(&t, sizeof(t));
			t.Enable = true;
			t.Port = port;
			if (CALL(hWnd, ScCreateListener(p->Rpc, &t)))
			{
				EndDialog(hWnd, true);
			}
			break;
		case IDCANCEL:
			Close(hWnd);
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// リスナー作成ダイアログ
bool SmCreateListenerDlg(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_SM_CREATE_LISTENER, SmCreateListenerDlgProc, p);
}

// HUB 編集 OK ボタン
void SmEditHubOnOk(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_CREATE_HUB t;
	char pass1[MAX_SIZE];
	char pass2[MAX_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (s->EditMode)
	{
		StrCpy(hubname, sizeof(hubname), s->HubName);
		StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	}
	else
	{
		GetTxtA(hWnd, E_HUBNAME, t.HubName, sizeof(t.HubName));
		StrCpy(hubname, sizeof(hubname), t.HubName);
	}

	GetTxtA(hWnd, E_PASSWORD1, pass1, sizeof(pass1));
	GetTxtA(hWnd, E_PASSWORD2, pass2, sizeof(pass2));

	if (s->EditMode == false || StrCmp(pass1, HIDDEN_PASSWORD) != 0)
	{
		Hash(t.HashedPassword, pass1, StrLen(pass1), true);
		HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass1);
	}

	if (IsChecked(hWnd, R_LIMIT_MAX_SESSION))
	{
		t.HubOption.MaxSession = GetInt(hWnd, E_MAX_SESSION);
	}

	t.Online = IsChecked(hWnd, R_ONLINE);

	if (s->p->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		t.HubType = HUB_TYPE_FARM_STATIC;
		if (IsChecked(hWnd, R_DYNAMIC))
		{
			t.HubType = HUB_TYPE_FARM_DYNAMIC;
		}
	}

	t.HubOption.NoEnum = IsChecked(hWnd, R_NO_ENUM);

	if (s->EditMode == false)
	{
		if (CALL(hWnd, ScCreateHub(s->p->Rpc, &t)))
		{
			MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_EDIT_HUB_CREATER"), hubname);
			EndDialog(hWnd, true);
		}
	}
	else
	{
		if (CALL(hWnd, ScSetHub(s->p->Rpc, &t)))
		{
			EndDialog(hWnd, true);
		}
	}
}

// HUB 編集更新
void SmEditHubUpdate(HWND hWnd, SM_EDIT_HUB *s)
{
	bool ok = true;
	char *s1, *s2;
	char hubname[MAX_HUBNAME_LEN + 1];
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	s1 = GetTextA(hWnd, E_PASSWORD1);
	s2 = GetTextA(hWnd, E_PASSWORD2);
	if (StrCmp(s1, s2) != 0)
	{
		ok = false;
	}
	Free(s1);
	Free(s2);

	GetTxtA(hWnd, E_HUBNAME, hubname, sizeof(hubname));
	Trim(hubname);
	if (StrLen(hubname) == 0 ||
		IsSafeStr(hubname) == false)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_LIMIT_MAX_SESSION))
	{
		Enable(hWnd, E_MAX_SESSION);
		Enable(hWnd, S_MAX_SESSION_1);
		Enable(hWnd, S_MAX_SESSION_2);
		if (GetInt(hWnd, E_MAX_SESSION) == 0)
		{
			ok = false;
		}
	}
	else
	{
		Disable(hWnd, E_MAX_SESSION);
		Disable(hWnd, S_MAX_SESSION_1);
		Disable(hWnd, S_MAX_SESSION_2);
	}

	SetEnable(hWnd, IDOK, ok);
}

// HUB 編集初期化
void SmEditHubInit(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_CREATE_HUB t;
	bool b = false;
	bool support_extoption = false;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_HUB);

	Zero(&t, sizeof(t));

	if (s->EditMode == false)
	{
		// 新規作成
		SetText(hWnd, 0, _UU("CM_EDIT_HUB_1"));
		FocusEx(hWnd, E_HUBNAME);

		if (s->p->ServerType == SERVER_TYPE_STANDALONE)
		{
			// スタンドアロン モード
			Disable(hWnd, R_STATIC);
			Disable(hWnd, R_DYNAMIC);
			SetText(hWnd, S_FARM_INFO, _UU("CM_EDIT_HUB_STANDALONE"));
		}
		else
		{
			Check(hWnd, R_STATIC, true);
		}

		Check(hWnd, R_ONLINE, true);

		Hide(hWnd, B_ACL);
		Hide(hWnd, S_ACL);
		Hide(hWnd, S_ACL_2);
		Hide(hWnd, S_ACL_3);
		Hide(hWnd, S_MSG_1);
		Hide(hWnd, S_MSG_4);
		Hide(hWnd, S_MSG_2);
		Hide(hWnd, B_MSG);
	}
	else
	{
		// 編集
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("CM_EDIT_HUB_2"), s->HubName);
		SetText(hWnd, 0, tmp);
		SetTextA(hWnd, E_HUBNAME, s->HubName);
		Disable(hWnd, E_HUBNAME);

		if (s->p->ServerType == SERVER_TYPE_STANDALONE)
		{
			// スタンドアロン モード
			Disable(hWnd, R_STATIC);
			Disable(hWnd, R_DYNAMIC);
			SetText(hWnd, S_FARM_INFO, _UU("CM_EDIT_HUB_STANDALONE"));
		}

		if (s->p->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			// コントローラ
			if (GetCapsBool(s->p->CapsList, "b_cluster_hub_type_fixed"))
			{
				Disable(hWnd, R_STATIC);
				Disable(hWnd, R_DYNAMIC);
				SetText(hWnd, S_FARM_INFO, _UU("CM_EDIT_HUB_TYPE_FIXED"));
			}
		}

		// HUB 情報の取得
		StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
		if (CALL(hWnd, ScGetHub(s->p->Rpc, &t)) == false)
		{
			EndDialog(hWnd, false);
			return;
		}

		SetTextA(hWnd, E_PASSWORD1, HIDDEN_PASSWORD);
		SetTextA(hWnd, E_PASSWORD2, HIDDEN_PASSWORD);

		if (t.HubOption.MaxSession == 0)
		{
			Check(hWnd, R_LIMIT_MAX_SESSION, false);
		}
		else
		{
			Check(hWnd, R_LIMIT_MAX_SESSION, true);
		}

		Check(hWnd, R_NO_ENUM, t.HubOption.NoEnum);

		SetIntEx(hWnd, E_MAX_SESSION, t.HubOption.MaxSession);

		Check(hWnd, R_ONLINE, t.Online);
		Check(hWnd, R_OFFLINE, t.Online ? false : true);

		Check(hWnd, R_STATIC, t.HubType == HUB_TYPE_FARM_STATIC);
		Check(hWnd, R_DYNAMIC, t.HubType == HUB_TYPE_FARM_DYNAMIC);

		SetShow(hWnd, B_ACL, GetCapsBool(s->p->CapsList, "b_support_ac"));
		SetShow(hWnd, S_ACL, GetCapsBool(s->p->CapsList, "b_support_ac"));
		SetShow(hWnd, S_ACL_2, GetCapsBool(s->p->CapsList, "b_support_ac"));
		SetShow(hWnd, S_ACL_3, GetCapsBool(s->p->CapsList, "b_support_ac"));

		SetShow(hWnd, S_MSG_1, GetCapsBool(s->p->CapsList, "b_support_msg"));
		SetShow(hWnd, S_MSG_4, GetCapsBool(s->p->CapsList, "b_support_msg"));
		SetShow(hWnd, S_MSG_2, GetCapsBool(s->p->CapsList, "b_support_msg"));
		SetShow(hWnd, B_MSG, GetCapsBool(s->p->CapsList, "b_support_msg"));
	}

	// 拡張オプション
	if (s->EditMode)
	{
		support_extoption = GetCapsBool(s->p->CapsList, "b_support_hub_ext_options");
	}

	SetEnable(hWnd, S_STATIC, support_extoption);
	SetEnable(hWnd, B_EXTOPTION, support_extoption);

	SetEnable(hWnd, R_NO_ENUM, GetCapsBool(s->p->CapsList, "b_support_hide_hub"));

	SmEditHubUpdate(hWnd, s);

	if (s->EditMode)
	{
		Focus(hWnd, IDOK);
	}

	if (s->EditMode)
	{
		if (GetCapsBool(s->p->CapsList, "b_support_hub_admin_option"))
		{
			b = true;
		}
	}

	SetShow(hWnd, S_AO_1, b);
	SetShow(hWnd, S_AO_2, b);
	SetShow(hWnd, S_AO_3, b);
	SetShow(hWnd, B_ADMINOPTION, b);
}

// HUB 編集プロシージャ
UINT SmEditHubProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_HUB *s = (SM_EDIT_HUB *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEditHubInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PASSWORD1:
		case E_PASSWORD2:
		case E_HUBNAME:
		case R_LIMIT_MAX_SESSION:
		case E_MAX_SESSION:
			SmEditHubUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmEditHubOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_LIMIT_MAX_SESSION:
			if (IsChecked(hWnd, R_LIMIT_MAX_SESSION))
			{
				FocusEx(hWnd, E_MAX_SESSION);
			}
			break;

		case B_ADMINOPTION:
			SmHubAdminOption(hWnd, s);
			break;

		case B_EXTOPTION:
			SmHubExtOption(hWnd, s);
			break;

		case B_ACL:
			SmHubAc(hWnd, s);
			break;

		case B_MSG:
			SmHubMsg(hWnd, s);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// HUB 編集ダイアログ
bool SmEditHubDlg(HWND hWnd, SM_SERVER *p, char *hubname)
{
	SM_EDIT_HUB s;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&s, sizeof(s));
	s.p = p;
	s.EditMode = true;
	StrCpy(s.HubName, sizeof(s.HubName), hubname);

	if (p->Bridge == false)
	{
		return Dialog(hWnd, D_SM_EDIT_HUB, SmEditHubProc, &s);
	}
	else
	{
		SmHubExtOption(hWnd, &s);
		return false;
	}
}

// HUB 作成ダイアログ
bool SmCreateHubDlg(HWND hWnd, SM_SERVER *p)
{
	SM_EDIT_HUB s;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&s, sizeof(s));
	s.p = p;
	s.EditMode = false;

	return Dialog(hWnd, D_SM_EDIT_HUB, SmEditHubProc, &s);
}

// 仮想 HUB 状態の表示
bool SmRefreshHubStatus(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_HUB_STATUS t;
	// 引数チェック
	if (hWnd == NULL || p == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(RPC_HUB_STATUS));
	StrCpy(t.HubName, sizeof(t.HubName), (char *)param);
	if (CALL(hWnd, ScGetHubStatus(p->Rpc, &t)))
	{
		wchar_t *s;
		wchar_t tmp[MAX_SIZE];
		LVB *b = LvInsertStart();

		// HUB 名
		s = CopyStrToUni((char *)param);
		LvInsertAdd(b, ICO_HUB, 0, 2, _UU("SM_HUB_STATUS_HUBNAME"), s);
		Free(s);

		// オンライン
		LvInsertAdd(b, t.Online ? ICO_PROTOCOL : ICO_PROTOCOL_X, 0, 2, _UU("SM_HUB_STATUS_ONLINE"),
			t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		// HUB の種類
		LvInsertAdd(b, t.HubType == HUB_TYPE_STANDALONE ? ICO_TOWER : ICO_FARM, 0, 2, _UU("SM_HUB_TYPE"),
			GetHubTypeStr(t.HubType));

		if (t.HubType == HUB_TYPE_STANDALONE)
		{
			// SecureNAT の有効/無効
			LvInsertAdd(b, ICO_ROUTER, NULL, 2, _UU("SM_HUB_SECURE_NAT"),
				t.SecureNATEnabled ? _UU("SM_HUB_SECURE_NAT_YES") : _UU("SM_HUB_SECURE_NAT_NO"));
		}

		// その他の値
		UniToStru(tmp, t.NumSessions);
		LvInsertAdd(b, ICO_PROTOCOL, 0, 2, _UU("SM_HUB_NUM_SESSIONS"), tmp);
		if (t.NumSessionsClient != 0 || t.NumSessionsBridge != 0)
		{
			UniToStru(tmp, t.NumSessionsClient);
			LvInsertAdd(b, ICO_PROTOCOL, 0, 2, _UU("SM_HUB_NUM_SESSIONS_CLIENT"), tmp);
			UniToStru(tmp, t.NumSessionsBridge);
			LvInsertAdd(b, ICO_PROTOCOL, 0, 2, _UU("SM_HUB_NUM_SESSIONS_BRIDGE"), tmp);
		}

		UniToStru(tmp, t.NumAccessLists);
		LvInsertAdd(b, ICO_DISCARD, 0, 2, _UU("SM_HUB_NUM_ACCESSES"), tmp);

		if (p->ServerType != SERVER_TYPE_FARM_MEMBER)
		{
			UniToStru(tmp, t.NumUsers);
			LvInsertAdd(b, ICO_USER, 0, 2, _UU("SM_HUB_NUM_USERS"), tmp);
			UniToStru(tmp, t.NumGroups);
			LvInsertAdd(b, ICO_GROUP, 0, 2, _UU("SM_HUB_NUM_GROUPS"), tmp);
		}

		UniToStru(tmp, t.NumMacTables);
		LvInsertAdd(b, ICO_MACHINE, 0, 2, _UU("SM_HUB_NUM_MAC_TABLES"), tmp);
		UniToStru(tmp, t.NumIpTables);
		LvInsertAdd(b, ICO_MACHINE, 0, 2, _UU("SM_HUB_NUM_IP_TABLES"), tmp);

		// 利用状況
		UniToStru(tmp, t.NumLogin);
		LvInsertAdd(b, ICO_KEY, NULL, 2, _UU("SM_HUB_NUM_LOGIN"), tmp);

		if (t.LastLoginTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastLoginTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		LvInsertAdd(b, ICO_DATETIME, NULL, 2, _UU("SM_HUB_LAST_LOGIN_TIME"), tmp);

		if (t.LastCommTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastCommTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		LvInsertAdd(b, ICO_DATETIME, NULL, 2, _UU("SM_HUB_LAST_COMM_TIME"), tmp);

		if (t.CreatedTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		LvInsertAdd(b, ICO_DATETIME, NULL, 2, _UU("SM_HUB_CREATED_TIME"), tmp);

		// トラフィック情報
		SmInsertTrafficInfo(b, &t.Traffic);

		LvInsertEnd(b, hWnd, L_STATUS);
	}
	else
	{
		return false;
	}

	return true;
}

// トラフィック情報を LVB に追加
void SmInsertTrafficInfo(LVB *b, TRAFFIC *t)
{
	wchar_t tmp[MAX_SIZE];
	char vv[128];
	// 引数チェック
	if (b == NULL || t == NULL)
	{
		return;
	}

	// 送信情報
	ToStr3(vv, sizeof(vv), t->Send.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_BCAST_SIZE"), tmp);

	// 受信情報
	ToStr3(vv, sizeof(vv), t->Recv.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_BCAST_SIZE"), tmp);
}

// ステータス表示ダイアログプロシージャ
UINT SmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_STATUS *s = (SM_STATUS *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		LvInitEx(hWnd, L_STATUS, s->NoImage);
		LvSetStyle(hWnd, L_STATUS, LVS_EX_GRIDLINES);
		SetIcon(hWnd, 0, s->Icon);
		SetIcon(hWnd, S_ICON, s->Icon);
		SetText(hWnd, 0, s->Caption);
		SetText(hWnd, S_TITLE, s->Caption);
		DlgFont(hWnd, S_TITLE, 15, true);
		if (s->InitProc != NULL)
		{
			s->InitProc(hWnd, s->p, s->Param);
		}
		else
		{
			// カラム初期化
			LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 0);
			LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 0);
		}
		if (s->RefreshProc(hWnd, s->p, s->Param) == false)
		{
			Close(hWnd);
		}
		LvAutoSize(hWnd, L_STATUS);
		Focus(hWnd, L_STATUS);

		if (s->show_refresh_button == false)
		{
			Hide(hWnd, IDOK);
		}

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// 更新
			if (s->RefreshProc(hWnd, s->p, s->Param) == false)
			{
				Close(hWnd);
			}
			LvAutoSize(hWnd, L_STATUS);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_STATUS);

	return 0;
}

// ステータス表示ダイアログ
void SmStatusDlg(HWND hWnd, SM_SERVER *p, void *param, bool no_image, bool show_refresh_button, wchar_t *caption, UINT icon,
				 SM_STATUS_INIT_PROC *init, SM_STATUS_REFRESH_PROC *refresh)
{
	SM_STATUS s;
	// 引数チェック
	if (hWnd == NULL || p == NULL || refresh == NULL)
	{
		return;
	}

	if (icon == 0)
	{
		icon = ICO_INFORMATION;
	}
	if (caption == NULL)
	{
		caption = _UU("SM_INFORMATION");
	}

	Zero(&s, sizeof(s));
	s.show_refresh_button = show_refresh_button;
	s.p = p;
	s.NoImage = no_image;
	s.Param = param;
	s.Icon = icon;
	s.Caption = caption;
	s.InitProc = init;
	s.RefreshProc = refresh;

	Dialog(hWnd, D_SM_STATUS, SmStatusDlgProc, &s);
}

// サーバー管理ダイアログ更新
void SmServerDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	bool hub_selected = false;
	bool hub_selected_online = false;
	bool hub_selected_offline = false;
	bool hub_have_admin_right = false;
	bool listener_selected = false;
	bool listener_selected_enabled = false;
	bool listener_selected_disabled = false;
	bool two_or_more_listener = false;
	bool bridge;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	bridge = GetCapsBool(p->CapsList, "b_bridge");

	hub_selected = LvIsSelected(hWnd, L_HUB);

	if (hub_selected)
	{
		if (p->ServerAdminMode)
		{
			hub_have_admin_right = true;
		}
		i = LvGetSelected(hWnd, L_HUB);
		if (i != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_HUB, i, 1);
			if (p->ServerAdminMode == false)
			{
				char *hubname = LvGetStrA(hWnd, L_HUB, i, 0);
				if (hubname != NULL)
				{
					if (StrCmpi(hubname, p->HubName) == 0)
					{
						hub_have_admin_right = true;
					}
					Free(hubname);
				}
			}
			hub_selected_online = (UniStrCmpi(s, _UU("SM_HUB_ONLINE")) == 0);
			hub_selected_offline = hub_selected_online ? false : true;
			Free(s);
		}
	}

	listener_selected = LvIsSelected(hWnd, L_LISTENER);
	if (listener_selected)
	{
		wchar_t *s = LvGetSelectedStr(hWnd, L_LISTENER, 1);
		if (UniStrCmpi(s, _UU("CM_LISTENER_OFFLINE")) == 0)
		{
			listener_selected_disabled = true;
		}
		else
		{
			listener_selected_enabled = true;
		}
		Free(s);
	}

	if (LvNum(hWnd, L_LISTENER) >= 2)
	{
		two_or_more_listener = true;
	}

	SetEnable(hWnd, IDOK, bridge || (hub_selected && hub_have_admin_right));
	SetEnable(hWnd, B_ONLINE, bridge == false && hub_selected_offline && hub_have_admin_right && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_OFFLINE, bridge == false && hub_selected_online && hub_have_admin_right && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_HUB_STATUS, hub_selected && hub_have_admin_right);
	SetEnable(hWnd, B_DELETE, bridge == false && hub_selected && p->ServerAdminMode && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_EDIT, hub_selected && hub_have_admin_right && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_CREATE, bridge == false && p->ServerAdminMode && p->ServerType != SERVER_TYPE_FARM_MEMBER);

	SetEnable(hWnd, B_CREATE_LISTENER, p->ServerAdminMode);
	SetEnable(hWnd, B_DELETE_LISTENER, p->ServerAdminMode && listener_selected && two_or_more_listener);
	SetEnable(hWnd, B_START, p->ServerAdminMode && listener_selected_disabled);
	SetEnable(hWnd, B_STOP, p->ServerAdminMode && listener_selected_enabled);
	SetEnable(hWnd, B_FARM, GetCapsBool(p->CapsList, "b_support_cluster") && p->ServerAdminMode);
	SetEnable(hWnd, B_FARM_STATUS, GetCapsBool(p->CapsList, "b_support_cluster") && p->ServerType != SERVER_TYPE_STANDALONE);
}

// サーバー管理ダイアログ初期化
void SmServerDlgInit(HWND hWnd, SM_SERVER *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// カラム初期化
	LvInit(hWnd, L_HUB);
	LvSetStyle(hWnd, L_HUB, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_HUB, 0, _UU("SM_HUB_COLUMN_1"), 150);
	LvInsertColumn(hWnd, L_HUB, 1, _UU("SM_HUB_COLUMN_2"), 80);
	LvInsertColumn(hWnd, L_HUB, 2, _UU("SM_HUB_COLUMN_3"), 80);
	LvInsertColumn(hWnd, L_HUB, 3, _UU("SM_HUB_COLUMN_4"), 80);
	LvInsertColumn(hWnd, L_HUB, 4, _UU("SM_HUB_COLUMN_5"), 80);
	LvInsertColumn(hWnd, L_HUB, 5, _UU("SM_HUB_COLUMN_6"), 80);
	LvInsertColumn(hWnd, L_HUB, 6, _UU("SM_HUB_COLUMN_7"), 80);
	LvInsertColumn(hWnd, L_HUB, 7, _UU("SM_HUB_COLUMN_8"), 80);
	LvInsertColumn(hWnd, L_HUB, 8, _UU("SM_HUB_COLUMN_9"), 80);
	LvInsertColumn(hWnd, L_HUB, 9, _UU("SM_HUB_COLUMN_10"), 120);
	LvInsertColumn(hWnd, L_HUB, 10, _UU("SM_HUB_COLUMN_11"), 120);

	LvInit(hWnd, L_LISTENER);
	LvSetStyle(hWnd, L_LISTENER, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_LISTENER, 0, _UU("CM_LISTENER_COLUMN_1"), 90);
	LvInsertColumn(hWnd, L_LISTENER, 1, _UU("CM_LISTENER_COLUMN_2"), 80);

	SmServerDlgRefresh(hWnd, p);

	if (p->ServerAdminMode == false)
	{
		// 仮想 HUB 管理モードの場合は唯一の HUB を選択する
		wchar_t *s = CopyStrToUni(p->HubName);
		LvSelect(hWnd, L_HUB, LvSearchStr(hWnd, L_HUB, 0, s));
		Free(s);
	}
	else
	{
		// サーバー全体の管理モードの場合
		UINT num_hubs = LvNum(hWnd, L_HUB);

		if (num_hubs == 1)
		{
			// 仮想 HUB が 1 個の場合は必ずその仮想 HUB を選択する
			LvSelect(hWnd, L_HUB, 0);
		}
		else
		{
			// 仮想 HUB が複数個ある場合は前回最後に選択した仮想 HUB を選択する
			char tmp[MAX_SIZE];
			char *hubname;

			Format(tmp, sizeof(tmp), "%s:%u:%s", p->CurrentSetting->ClientOption.Hostname,
				p->CurrentSetting->ClientOption.Port,
				p->CurrentSetting->ServerAdminMode ? "" : p->CurrentSetting->HubName);

			hubname = MsRegReadStr(REG_CURRENT_USER, SM_LASTHUB_REG_KEY, tmp);

			if (IsEmptyStr(hubname) == false)
			{
				LvSelect(hWnd, L_HUB, LvSearchStrA(hWnd, L_HUB, 0, hubname));
			}

			Free(hubname);
		}
	}

	Focus(hWnd, L_HUB);

	SmServerDlgUpdate(hWnd, p);

	if (GetCapsBool(p->CapsList, "b_bridge"))
	{
		Disable(hWnd, L_HUB);
	}

	// ローカルブリッジボタン等はサーバーの Admin の場合に有効にする
	SetEnable(hWnd, B_BRIDGE, GetCapsBool(p->CapsList, "b_local_bridge") && p->ServerAdminMode);
	SetEnable(hWnd, B_CONNECTION, p->ServerAdminMode);

	// Config R/W ボタン
	SetEnable(hWnd, B_CONFIG, GetCapsBool(p->CapsList, "b_support_config_rw") && p->ServerAdminMode);

	// レイヤ 3 ボタン
	SetEnable(hWnd, B_L3, GetCapsBool(p->CapsList, "b_support_layer3") && p->ServerAdminMode);

	// ライセンスボタン
	SetShow(hWnd, B_LICENSE, GetCapsBool(p->CapsList, "b_support_license") && p->ServerAdminMode);
	SetShow(hWnd, S_LICENSE, GetCapsBool(p->CapsList, "b_support_license") && p->ServerAdminMode);
	SetShow(hWnd, S_BETA, GetCapsBool(p->CapsList, "b_beta_version") && (IsShow(hWnd, B_LICENSE) == false));

	DlgFont(hWnd, S_BETA, 12, false);
}

// サーバー管理ダイアログ更新
void SmServerDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	RPC_ENUM_HUB t;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// 仮想 HUB リスト更新
	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumHub(p->Rpc, &t)))
	{
		LVB *b = LvInsertStart();
		for (i = 0;i < t.NumHub;i++)
		{
			RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
			wchar_t name[MAX_HUBNAME_LEN + 1];
			wchar_t s1[64], s2[64], s3[64], s4[64], s5[64];
			wchar_t s6[64], s7[128], s8[128];
			UniToStru(s1, e->NumUsers);
			UniToStru(s2, e->NumGroups);
			UniToStru(s3, e->NumSessions);
			UniToStru(s4, e->NumMacTables);
			UniToStru(s5, e->NumIpTables);

			UniToStru(s6, e->NumLogin);

			if (e->LastLoginTime != 0)
			{
				GetDateTimeStr64Uni(s7, sizeof(s7), SystemToLocal64(e->LastLoginTime));
			}
			else
			{
				UniStrCpy(s7, sizeof(s7), _UU("COMMON_UNKNOWN"));
			}

			if (e->LastCommTime != 0)
			{
				GetDateTimeStr64Uni(s8, sizeof(s8), SystemToLocal64(e->LastCommTime));
			}
			else
			{
				UniStrCpy(s8, sizeof(s8), _UU("COMMON_UNKNOWN"));
			}

			StrToUni(name, sizeof(name), e->HubName);

			LvInsertAdd(b,
				e->Online ? ICO_HUB : ICO_HUB_OFFLINE,
				NULL,
				11,
				name,
				e->Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"),
				GetHubTypeStr(e->HubType),
				s1, s2, s3, s4, s5, s6, s7, s8);
		}
		LvInsertEnd(b, hWnd, L_HUB);
		FreeRpcEnumHub(&t);
	}

	// リスナーリスト更新
	if (p != NULL)
	{
		RPC_LISTENER_LIST t;
		Zero(&t, sizeof(RPC_LISTENER_LIST));
		if (CALL(hWnd, ScEnumListener(p->Rpc, &t)))
		{
			LVB *b = LvInsertStart();
			for (i = 0;i < t.NumPort;i++)
			{
				wchar_t tmp[MAX_SIZE];
				wchar_t *status;
				UINT icon;
				UniFormat(tmp, sizeof(tmp), _UU("CM_LISTENER_TCP_PORT"), t.Ports[i]);

				status = _UU("CM_LISTENER_ONLINE");
				icon = ICO_PROTOCOL;
				if (t.Errors[i])
				{
					status = _UU("CM_LISTENER_ERROR");
					icon = ICO_PROTOCOL_X;
				}
				else if (t.Enables[i] == false)
				{
					status = _UU("CM_LISTENER_OFFLINE");
					icon = ICO_PROTOCOL_OFFLINE;
				}

				LvInsertAdd(b, icon, (void *)t.Ports[i], 2, tmp, status);
			}
			LvInsertEnd(b, hWnd, L_LISTENER);
			FreeRpcListenerList(&t);
		}
	}

	SmServerDlgUpdate(hWnd, p);
}

// サーバー管理ダイアログプロシージャ
UINT SmServerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	wchar_t *s;
	wchar_t tmp[MAX_SIZE];
	NMHDR *n;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, 0, p->Title);

		if (p->Bridge == false)
		{
			FormatText(hWnd, S_TITLE, p->ServerName);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("SM_SERVER_BRIDGE_TITLE"), p->ServerName);
			SetText(hWnd, S_TITLE, tmp);

			SetText(hWnd, S_VHUB_BRIDGE, _UU("SM_S_VHUB_BRIDGE"));
		}

		DlgFont(hWnd, S_TITLE, 16, 1);

		SetIcon(hWnd, 0, p->Bridge == false ? ICO_VPNSERVER : ICO_BRIDGE);

		SmServerDlgInit(hWnd, p);

		SetTimer(hWnd, 1, 50, NULL);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// 管理
			if (IsEnable(hWnd, IDOK))
			{
				if (p->Bridge == false)
				{
					s = LvGetSelectedStr(hWnd, L_HUB, 0);
				}
				else
				{
					s = CopyUniStr(L"BRIDGE");
				}
				if (s != NULL)
				{
					char hubname[MAX_HUBNAME_LEN + 1];
					SM_HUB hub;
					Zero(&hub, sizeof(hub));
					UniToStr(hubname, sizeof(hubname), s);
					hub.p = p;
					hub.Rpc = p->Rpc;
					hub.HubName = hubname;
					SmHubDlg(hWnd, &hub);
					//SmServerDlgRefresh(hWnd, p);
					Free(s);
				}
			}
			break;

		case B_ONLINE:
			// オンラインにする
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				RPC_SET_HUB_ONLINE t;
				Zero(&t, sizeof(t));
				UniToStr(t.HubName, sizeof(t.HubName), s);
				t.Online = true;
				if (CALL(hWnd, ScSetHubOnline(p->Rpc, &t)))
				{
					SmServerDlgRefresh(hWnd, p);
				}
				Free(s);
			}
			break;

		case B_OFFLINE:
			// オフラインにする
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				RPC_SET_HUB_ONLINE t;
				Zero(&t, sizeof(t));
				// 確認メッセージ
				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
					_UU("CM_OFFLINE_MSG"), s) == IDYES)
				{
					UniToStr(t.HubName, sizeof(t.HubName), s);
					t.Online = false;
					if (CALL(hWnd, ScSetHubOnline(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
					}
				}
				Free(s);
			}
			break;

		case B_HUB_STATUS:
			// HUB の状態
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				wchar_t tmp[MAX_SIZE];
				char *hubname = CopyUniToStr(s);
				UniFormat(tmp, sizeof(tmp), _UU("SM_HUB_STATUS_CAPTION"), s);
				SmStatusDlg(hWnd, p, hubname, false, true, tmp, ICO_HUB,
					NULL, SmRefreshHubStatus);
				Free(hubname);
				Free(s);
			}
			break;

		case B_CREATE:
			// HUB の作成
			if (SmCreateHubDlg(hWnd, p))
			{
				SmServerDlgRefresh(hWnd, p);
			}
			break;

		case B_EDIT:
			// HUB の編集
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				char *name = CopyUniToStr(s);
				if (SmEditHubDlg(hWnd, p, name))
				{
					SmServerDlgRefresh(hWnd, p);
				}
				Free(name);
				Free(s);
			}
			break;

		case B_DELETE:
			// HUB の削除
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				char *name = CopyUniToStr(s);
				RPC_DELETE_HUB t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), name);
				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_HUB_MSG"), name) == IDYES)
				{
					if (CALL(hWnd, ScDeleteHub(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
						MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_HUB_DELETED_MSG"), name);
					}
				}
				Free(name);
				Free(s);
			}
			break;

		case B_CREATE_LISTENER:
			// リスナー作成
			if (SmCreateListenerDlg(hWnd, p))
			{
				SmServerDlgRefresh(hWnd, p);
			}
			break;

		case B_DELETE_LISTENER:
			// リスナー削除
			i = LvGetSelected(hWnd, L_LISTENER);
			if (i != INFINITE)
			{
				UINT port = (UINT)LvGetParam(hWnd, L_LISTENER, i);
				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_LISTENER_MSG"), port) == IDYES)
				{
					RPC_LISTENER t;
					Zero(&t, sizeof(t));
					t.Enable = false;
					t.Port = port;

					if (CALL(hWnd, ScDeleteListener(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
					}
				}
			}
			break;

		case B_START:
			// 開始
			i = LvGetSelected(hWnd, L_LISTENER);
			if (i != INFINITE)
			{
				UINT port = (UINT)LvGetParam(hWnd, L_LISTENER, i);
				RPC_LISTENER t;
				Zero(&t, sizeof(t));
				t.Enable = true;
				t.Port = port;

				if (CALL(hWnd, ScEnableListener(p->Rpc, &t)))
				{
					SmServerDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_STOP:
			// 停止
			i = LvGetSelected(hWnd, L_LISTENER);
			if (i != INFINITE)
			{
				UINT port = (UINT)LvGetParam(hWnd, L_LISTENER, i);
				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_STOP_LISTENER_MSG"), port) == IDYES)
				{
					RPC_LISTENER t;
					Zero(&t, sizeof(t));
					t.Enable = false;
					t.Port = port;

					if (CALL(hWnd, ScEnableListener(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
					}
				}
			}
			break;

		case B_SSL:
			// SSL 関係
			SmSslDlg(hWnd, p);
			break;

		case B_STATUS:
			// サーバー状態
			SmStatusDlg(hWnd, p, p, false, true, _UU("SM_SERVER_STATUS"), ICO_VPNSERVER,
				NULL, SmRefreshServerStatus);
			break;

		case B_INFO:
			// サーバー情報
			SmStatusDlg(hWnd, p, p, false, false, _UU("SM_INFO_TITLE"), ICO_VPNSERVER,
				NULL, SmRefreshServerInfo);
			break;

		case B_BRIDGE:
			// ローカルブリッジ設定
			SmBridgeDlg(hWnd, p);
			SmServerDlgRefresh(hWnd, p);
			break;

		case B_FARM:
			// サーバーファーム
			if (SmFarmDlg(hWnd, p))
			{
				// サーバー ファーム構成が変更された場合はダイアログを閉じる
				Close(hWnd);
			}
			break;

		case B_FARM_STATUS:
			// サーバー ファーム 状態
			if (p->ServerType == SERVER_TYPE_FARM_CONTROLLER)
			{
				Dialog(hWnd, D_SM_FARM_MEMBER, SmFarmMemberDlgProc, p);
			}
			else if (p->ServerType == SERVER_TYPE_FARM_MEMBER)
			{
				SmStatusDlg(hWnd, p, NULL, false, true, _UU("SM_FC_STATUS_CAPTION"),
					ICO_FARM, NULL, SmRefreshFarmConnectionInfo);
			}
			break;

		case B_CONNECTION:
			// TCP コネクション一覧
			SmConnectionDlg(hWnd, p);
			break;

		case B_REFRESH:
			// 最新の状態に更新
			SmServerDlgRefresh(hWnd, p);
			break;

		case B_CONFIG:
			// config 編集
			SmConfig(hWnd, p);
			break;

		case B_L3:
			// L3 スイッチ
			SmL3(hWnd, p);
			break;

		case B_LICENSE:
			// ライセンスの追加と削除
			SmLicense(hWnd, p);
			SmServerDlgUpdate(hWnd, p);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		{
			// 最後に選択されていた HUB を保存する
			char *hubname = NULL;
			char tmp[MAX_SIZE];


			Format(tmp, sizeof(tmp), "%s:%u:%s", p->CurrentSetting->ClientOption.Hostname,
				p->CurrentSetting->ClientOption.Port,
				p->CurrentSetting->ServerAdminMode ? "" : p->CurrentSetting->HubName);

			if (LvIsSingleSelected(hWnd, L_HUB))
			{
				hubname = LvGetSelectedStrA(hWnd, L_HUB, 0);
			}

			if (IsEmptyStr(hubname) == false)
			{
				MsRegWriteStr(REG_CURRENT_USER, SM_LASTHUB_REG_KEY, tmp, hubname);
			}
			else
			{
				MsRegDeleteValue(REG_CURRENT_USER, SM_LASTHUB_REG_KEY, tmp);
			}

			Free(hubname);

			EndDialog(hWnd, false);
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_HUB:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmServerDlgUpdate(hWnd, p);
				break;
			}
			break;
		case L_LISTENER:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmServerDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			if (p->EmptyPassword && p->ServerAdminMode)
			{
				// パスワードが空の場合は変更を推奨する
				if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_PASSWORD_MSG")) == IDYES)
				{
					Dialog(hWnd, D_SM_CHANGE_PASSWORD, SmChangeServerPasswordDlg, p);
				}
			}

			if (p->ServerAdminMode)
			{
				// ライセンスキーが登録されていない場合は登録を促す
				RPC_LICENSE_STATUS t;

				Zero(&t, sizeof(t));
				if (p->Bridge == false && GetCapsBool(p->CapsList, "b_support_license"))
				{
					if (ScGetLicenseStatus(p->Rpc, &t) == ERR_NO_ERROR)
					{
						if (t.EditionId == LICENSE_EDITION_VPN3_NO_LICENSE || (t.NeedSubscription && t.SubscriptionExpires == 0))
						{
							// 有効なライセンスキーが 1 つも登録されていない

							if (MsgBox(hWnd, MB_YESNO | MB_ICONINFORMATION,
								_UU("SM_SETUP_NO_LICENSE_KEY")) == IDYES)
							{
								SmLicense(hWnd, p);
							}
						}
					}
				}
			}

			SetTimer(hWnd, 2, 150, NULL);
			break;

		case 2:
			// セットアップ
			KillTimer(hWnd, 2);

			if (SmSetupIsNew(p))
			{
				if (SmSetup(hWnd, p))
				{
					SmServerDlgRefresh(hWnd, p);
				}
			}

			SetTimer(hWnd, 3, 150, NULL);
			break;

		case 3:
			// 管理者向けメッセージ
			KillTimer(hWnd, 3);

			if (UniIsEmptyStr(p->AdminMsg) == false)
			{
				wchar_t tmp[MAX_SIZE];

				UniFormat(tmp, sizeof(tmp), _UU("SM_SERVER_ADMIN_MSG"), p->ServerName);
				OnceMsg(hWnd, tmp, p->AdminMsg, true, ICO_VPNSERVER);
			}
			break;
		}
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_HUB);

	return 0;
}

// 接続
void SmConnect(HWND hWnd, SETTING *s)
{
	bool ok;
	RPC *rpc;
	char *pass;
	bool empty_password = false;
	bool first_bad_password = false;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// コントロールの無効化
	Disable(hWnd, L_SETTING);
	Disable(hWnd, B_NEW_SETTING);
	Disable(hWnd, B_EDIT_SETTING);
	Disable(hWnd, B_DELETE);
	Disable(hWnd, IDOK);
	Disable(hWnd, B_ABOUT);
	Disable(hWnd, IDCANCEL);
	Disable(hWnd, B_SECURE_MANAGER);
	Disable(hWnd, B_SELECT_SECURE);

	ok = true;

	if (IsZero(s->HashedPassword, SHA1_SIZE))
	{
		// パスワード入力画面
ENTER_PASSWORD:
		pass = SmPassword(hWnd, s->ClientOption.Hostname);
		if (pass != NULL)
		{
			Hash(s->HashedPassword, pass, StrLen(pass), true);
			Free(pass);
			ok = true;
		}
		else
		{
			ok = false;
		}
	}

	if (ok)
	{
		UINT err = ERR_INTERNAL_ERROR;
		// 接続
		rpc = AdminConnectEx2(sm->Cedar, &s->ClientOption, s->ServerAdminMode ? "" : s->HubName, s->HashedPassword, &err, NULL,
			hWnd);
		if (rpc == NULL)
		{
			// エラー発生
			if (err != ERR_ACCESS_DENIED || first_bad_password)
			{
				MsgBox(hWnd, MB_ICONSTOP, _E(err));
			}
			if (err == ERR_ACCESS_DENIED)
			{
				// パスワード間違い
				first_bad_password = true;
				goto ENTER_PASSWORD;
			}
			else
			{
				// その他のエラー
			}
		}
		else
		{
			UCHAR test[SHA1_SIZE];
			SM_SERVER p;
			RPC_SERVER_STATUS status;
			RPC_SERVER_INFO info;
			SETTING *setting;
			RPC_MSG msg;

			Hash(test, "", 0, true);

			if (Cmp(test, s->HashedPassword, SHA1_SIZE) == 0)
			{
				empty_password = true;
			}

			if (sm->TempSetting == NULL)
			{
				setting = SmGetSetting(s->Title);
				if (setting != NULL)
				{
					if (IsZero(setting->HashedPassword, SHA1_SIZE) == false)
					{
						Copy(setting->HashedPassword, s->HashedPassword, SHA1_SIZE);
						SmWriteSettingList();
					}
				}
			}

			rpc->ServerAdminMode = s->ServerAdminMode;
			if (s->ServerAdminMode == false)
			{
				StrCpy(rpc->HubName, sizeof(rpc->HubName), s->HubName);
			}

			Zero(&p, sizeof(p));
			p.CurrentSetting = s;
			p.Rpc = rpc;
			p.EmptyPassword = empty_password;
			p.ServerAdminMode = rpc->ServerAdminMode;
			StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption.Hostname);
			if (p.ServerAdminMode == false)
			{
				StrCpy(p.HubName, sizeof(p.HubName), rpc->HubName);
			}
			UniStrCpy(p.Title, sizeof(p.Title), s->Title);

			// サーバーの種類の取得
			Zero(&status, sizeof(status));
			ScGetServerStatus(rpc, &status);

			p.ServerType = status.ServerType;

			Zero(&info, sizeof(info));
			ScGetServerInfo(rpc, &info);

			Copy(&p.ServerInfo, &info, sizeof(RPC_SERVER_INFO));
			Copy(&p.ServerStatus, &status, sizeof(RPC_SERVER_STATUS));

			// Admin Msg の取得
			Zero(&msg, sizeof(msg));
			if (ScGetAdminMsg(rpc, &msg) == ERR_NO_ERROR)
			{
				p.AdminMsg = UniCopyStr(msg.Msg);
				FreeRpcMsg(&msg);
			}

			// Caps の取得
			p.CapsList = ScGetCapsEx(p.Rpc);

			p.Bridge = GetCapsBool(p.CapsList, "b_bridge");

			if (GetCapsBool(p.CapsList, "b_support_policy_ver_3"))
			{
				p.PolicyVer = 3;
			}
			else
			{
				p.PolicyVer = 2;
			}

			// サーバー管理画面
			Dialog(hWnd, D_SM_SERVER, SmServerDlgProc, &p);

			// 切断
			AdminDisconnect(rpc);

			// Caps の解放
			FreeCapsList(p.CapsList);

			Free(p.AdminMsg);
			p.AdminMsg = NULL;

			FreeRpcServerInfo(&info);
		}
	}

	// コントロールの有効化
	Enable(hWnd, L_SETTING);
	Enable(hWnd, B_NEW_SETTING);
	Enable(hWnd, B_EDIT_SETTING);
	Enable(hWnd, B_DELETE);
	Enable(hWnd, IDOK);
	Enable(hWnd, B_ABOUT);
	Enable(hWnd, IDCANCEL);
	Enable(hWnd, B_SECURE_MANAGER);
	Enable(hWnd, B_SELECT_SECURE);
}

// パスワード入力ダイアログ
char *SmPassword(HWND hWnd, char *server_name)
{
	char *ret;
	UI_PASSWORD_DLG p;
	// 引数チェック
	if (server_name == NULL)
	{
		return NULL;
	}

	Zero(&p, sizeof(p));
	p.AdminMode = true;
	StrCpy(p.ServerName, sizeof(p.ServerName), server_name);

	if (PasswordDlg(hWnd, &p) == false)
	{
		return NULL;
	}

	ret = CopyStr(p.Password);

	return ret;
}

// 設定の編集ダイアログ初期化
void SmEditSettingDlgInit(HWND hWnd, SM_EDIT_SETTING *p)
{
	SETTING *s;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	p->Inited = false;

	s = p->Setting;

	// タイトル
	if (p->EditMode == false)
	{
		SetText(hWnd, 0, _UU("SM_EDIT_CAPTION_1"));
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_CAPTION_2"), s->Title);
		SetText(hWnd, 0, tmp);
	}

	// 接続設定名
	SetText(hWnd, E_ACCOUNT_NAME, s->Title);

	// ホスト名
	SetTextA(hWnd, E_HOSTNAME, s->ClientOption.Hostname);

	// ポート番号
	CbSetHeight(hWnd, C_PORT, 18);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_4"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_1"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_2"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_3"), 0);
	SetIntEx(hWnd, C_PORT, s->ClientOption.Port);

	// プロキシ設定
	Check(hWnd, R_DIRECT_TCP, s->ClientOption.ProxyType == PROXY_DIRECT);
	Check(hWnd, R_HTTPS, s->ClientOption.ProxyType == PROXY_HTTP);
	Check(hWnd, R_SOCKS, s->ClientOption.ProxyType == PROXY_SOCKS);

	// 管理モード設定
	Check(hWnd, R_SERVER_ADMIN, s->ServerAdminMode);
	Check(hWnd, R_HUB_ADMIN, s->ServerAdminMode == false ? true : false);
	CbSetHeight(hWnd, C_HUBNAME, 18);
	SetTextA(hWnd, C_HUBNAME, s->HubName);

	// パスワード
	if (IsZero(s->HashedPassword, SHA1_SIZE))
	{
		Check(hWnd, R_NO_SAVE, true);
	}
	else
	{
		UCHAR test[SHA1_SIZE];

		Hash(test, "", 0, true);
		if (Cmp(test, s->HashedPassword, SHA1_SIZE) != 0)
		{
			SetTextA(hWnd, E_PASSWORD, HIDDEN_PASSWORD);
		}
	}

	if (p->EditMode == false)
	{
		FocusEx(hWnd, E_ACCOUNT_NAME);
	}
	else
	{
		FocusEx(hWnd, E_HOSTNAME);
	}

	p->Inited = true;

	// 仮想 HUB の列挙を開始
	CmEnumHubStart(hWnd, &s->ClientOption);

	SmEditSettingDlgUpdate(hWnd, p);
}

// 設定の編集ダイアログ更新
void SmEditSettingDlgUpdate(HWND hWnd, SM_EDIT_SETTING *p)
{
	bool ok = true;
	UINT delete_hub_list = 0;
	SETTING *s;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL || p->Inited == false)
	{
		return;
	}

	s = p->Setting;

	GetTxt(hWnd, E_ACCOUNT_NAME, s->Title, sizeof(s->Title));
	UniTrim(s->Title);

	if (UniStrLen(s->Title) == 0)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_LOCALHOST))
	{
		SetTextA(hWnd, E_HOSTNAME, "localhost");
		Disable(hWnd, E_HOSTNAME);
	}
	else
	{
		Enable(hWnd, E_HOSTNAME);
	}

	GetTxtA(hWnd, E_HOSTNAME, tmp, sizeof(tmp));
	Trim(tmp);

	if (StrCmpi(tmp, s->ClientOption.Hostname) != 0)
	{
		delete_hub_list++;
	}

	StrCpy(s->ClientOption.Hostname, sizeof(s->ClientOption.Hostname), tmp);

	if (StrLen(s->ClientOption.Hostname) == 0)
	{
		ok = false;
	}

	s->ClientOption.Port = GetInt(hWnd, C_PORT);
	if (s->ClientOption.Port == 0)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_DIRECT_TCP))
	{
		s->ClientOption.ProxyType = PROXY_DIRECT;
	}
	else if (IsChecked(hWnd, R_HTTPS))
	{
		s->ClientOption.ProxyType = PROXY_HTTP;
	}
	else
	{
		s->ClientOption.ProxyType = PROXY_SOCKS;
	}

	SetEnable(hWnd, B_PROXY_CONFIG, s->ClientOption.ProxyType != PROXY_DIRECT);

	if (s->ClientOption.ProxyType != PROXY_DIRECT)
	{
		if (StrLen(s->ClientOption.ProxyName) == 0)
		{
			ok = false;
		}
		if (s->ClientOption.ProxyPort == 0)
		{
			ok = false;
		}
	}

	s->ServerAdminMode = IsChecked(hWnd, R_SERVER_ADMIN);

	SetEnable(hWnd, C_HUBNAME, s->ServerAdminMode == false ? true : false);
	SetEnable(hWnd, S_HUBNAME, s->ServerAdminMode == false ? true : false);

	GetTxtA(hWnd, C_HUBNAME, s->HubName, sizeof(s->HubName));
	Trim(s->HubName);
	if (StrLen(s->HubName) == 0)
	{
		if (s->ServerAdminMode == false)
		{
			ok = false;
		}
	}

	if (IsChecked(hWnd, R_NO_SAVE))
	{
		Zero(s->HashedPassword, SHA1_SIZE);
		SetTextA(hWnd, E_PASSWORD, "");
		Disable(hWnd, E_PASSWORD);
		Disable(hWnd, S_PASSWORD);
	}
	else
	{
		char tmp[MAX_PASSWORD_LEN + 1];
		Enable(hWnd, E_PASSWORD);
		Enable(hWnd, S_PASSWORD);
		GetTxtA(hWnd, E_PASSWORD, tmp, sizeof(tmp));
		if (StrCmp(tmp, HIDDEN_PASSWORD) != 0)
		{
			Hash(s->HashedPassword, tmp, StrLen(tmp), true);
		}
	}

	if (delete_hub_list)
	{
		CbReset(hWnd, C_HUBNAME);
	}

	SetEnable(hWnd, IDOK, ok);
}

// 設定の編集ダイアログ OK ボタン
void SmEditSettingDlgOnOk(HWND hWnd, SM_EDIT_SETTING *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (p->EditMode == false)
	{
		// 新規登録
		SETTING *s = ZeroMalloc(sizeof(SETTING));
		Copy(s, p->Setting, sizeof(SETTING));
		if (SmAddSetting(s) == false)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_SETTING_EXISTS"), s->Title);
			Free(s);
			FocusEx(hWnd, E_ACCOUNT_NAME);
			return;
		}
		EndDialog(hWnd, true);
	}
	else
	{
		// 更新登録
		SETTING *t = SmGetSetting(p->Setting->Title);
		if (t != NULL && t != p->OldSetting)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_SETTING_EXISTS"), p->Setting->Title);
			FocusEx(hWnd, E_ACCOUNT_NAME);
			return;
		}

		Copy(p->OldSetting, p->Setting, sizeof(SETTING));
		Sort(sm->SettingList);
		SmWriteSettingList();

		EndDialog(hWnd, true);
	}
}

// 設定の追加 / 編集ダイアログ
UINT SmEditSettingDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_SETTING *p = (SM_EDIT_SETTING *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEditSettingDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_LOCALHOST:
		case E_ACCOUNT_NAME:
		case E_HOSTNAME:
		case C_PORT:
		case R_DIRECT_TCP:
		case R_HTTPS:
		case R_SOCKS:
		case R_SERVER_ADMIN:
		case R_HUB_ADMIN:
		case C_HUBNAME:
		case E_PASSWORD:
		case R_NO_SAVE:
			SmEditSettingDlgUpdate(hWnd, p);
			break;
		}

		if (LOWORD(wParam) == R_LOCALHOST)
		{
			FocusEx(hWnd, E_HOSTNAME);
		}

		switch (LOWORD(wParam))
		{
		case E_HOSTNAME:
			if (HIWORD(wParam) == EN_KILLFOCUS)
			{
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;
		case C_PORT:
			if (HIWORD(wParam) == CBN_KILLFOCUS)
			{
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;
		case R_DIRECT_TCP:
		case R_HTTPS:
		case R_SOCKS:
			if (HIWORD(wParam) == BN_CLICKED)
			{
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmEditSettingDlgOnOk(hWnd, p);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_PROXY_CONFIG:
			// プロキシ設定
			if (CmProxyDlg(hWnd, &p->Setting->ClientOption))
			{
				UINT n = GetInt(hWnd, C_PORT);
				if (p->Setting->ClientOption.ProxyType == PROXY_HTTP &&
					n != 443)
				{
					// HTTP プロキシ経由の設定になっていて接続先が 443 番ポート
					// 以外のポートである場合は警告を表示する
					if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("CM_HTTP_PROXY_WARNING"), n) == IDYES)
					{
						// ポート番号を 443 に変更する
						SetText(hWnd, C_PORT, _UU("CM_PORT_2"));
					}
				}
				SmEditSettingDlgUpdate(hWnd, p);
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;

		case R_NO_SAVE:
			if (IsChecked(hWnd, R_NO_SAVE) == false)
			{
				FocusEx(hWnd, E_PASSWORD);
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 設定の追加ダイアログを表示
bool SmAddSettingDlg(HWND hWnd, wchar_t *new_name, UINT new_name_size)
{
	SM_EDIT_SETTING p;
	SETTING s;
	UINT i;
	bool ret;
	// 引数チェック
	if (hWnd == NULL || new_name == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	Zero(&s, sizeof(s));

	s.ClientOption.Port = 443;

	p.EditMode = false;
	p.Setting = &s;

	for (i = 1;;i++)
	{
		wchar_t tmp[MAX_SIZE];
		if (i == 1)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_NEW_ACCOUNT_NAME_1"));
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_NEW_ACCOUNT_NAME_2"), i);
		}

		if (SmGetSetting(tmp) == NULL)
		{
			UniStrCpy(s.Title, sizeof(s.Title), tmp);
			Hash(s.HashedPassword, "", 0, true);
			s.ServerAdminMode = true;
			break;
		}
	}

	ret = Dialog(hWnd, D_SM_EDIT_SETTING, SmEditSettingDlgProc, &p);

	if (ret)
	{
		UniStrCpy(new_name, new_name_size, s.Title);
	}

	return ret;
}

// 設定の編集ダイアログを表示
bool SmEditSettingDlg(HWND hWnd)
{
	SM_EDIT_SETTING p;
	SETTING s, *setting;
	UINT i;
	wchar_t *name;
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	i = LvGetSelected(hWnd, L_SETTING);
	if (i == INFINITE)
	{
		return false;
	}

	name = LvGetStr(hWnd, L_SETTING, i, 0);

	setting = SmGetSetting(name);
	if (setting == NULL)
	{
		Free(name);
		return false;
	}

	Free(name);

	Copy(&s, setting, sizeof(SETTING));

	Zero(&p, sizeof(p));

	p.EditMode = true;
	p.OldSetting = setting;
	p.Setting = &s;

	return Dialog(hWnd, D_SM_EDIT_SETTING, SmEditSettingDlgProc, &p);
}

// 設定の更新
bool SmCheckNewName(SETTING *s, wchar_t *new_title)
{
	UINT i;
	// 引数チェック
	if (new_title == NULL)
	{
		return false;
	}
	if (s != NULL)
	{
		if (IsInList(sm->SettingList, s) == false)
		{
			return false;
		}
	}

	// 他に同一の名前が無いかどうかチェック
	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		SETTING *t = LIST_DATA(sm->SettingList, i);

		if (s != t)
		{
			if (UniStrCmpi(t->Title, new_title) == 0)
			{
				return false;
			}
		}
	}

	return true;
}

// 設定の削除
void SmDeleteSetting(wchar_t *title)
{
	SETTING *s;
	// 引数チェック
	if (title == NULL)
	{
		return;
	}

	s = SmGetSetting(title);
	if (s == NULL)
	{
		return;
	}

	Delete(sm->SettingList, s);
	Free(s);
	Sort(sm->SettingList);

	SmWriteSettingList();
}

// 設定の追加
bool SmAddSetting(SETTING *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	if (SmGetSetting(s->Title) != NULL)
	{
		return false;
	}

	Insert(sm->SettingList, s);

	SmWriteSettingList();

	return true;
}

// 設定の取得
SETTING *SmGetSetting(wchar_t *title)
{
	SETTING s;
	// 引数チェック
	if (title == NULL)
	{
		return NULL;
	}

	Zero(&s, sizeof(SETTING));
	UniStrCpy(s.Title, sizeof(s.Title), title);

	return (SETTING *)Search(sm->SettingList, &s);
}

// 接続設定の比較
int SmCompareSetting(void *p1, void *p2)
{
	SETTING *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(SETTING **)p1;
	s2 = *(SETTING **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	return UniStrCmpi(s1->Title, s2->Title);
}

// 設定リストの初期化
void SmInitSettingList()
{
	sm->SettingList = NewList(SmCompareSetting);

	SmLoadSettingList();

	SmInitDefaultSettingList();
}

// 設定リストの解放
void SmFreeSettingList()
{
	UINT i;

	// 書き込み
	SmWriteSettingList();

	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		SETTING *s = LIST_DATA(sm->SettingList, i);
		Free(s);
	}
	ReleaseList(sm->SettingList);

	sm->SettingList = NULL;
}

// 設定リストの書き込み
void SmWriteSettingList()
{
	TOKEN_LIST *t;
	UINT i;

	t = MsRegEnumValue(REG_CURRENT_USER, SM_SETTING_REG_KEY);
	if (t != NULL)
	{
		// 既存のすべての値を削除する
		for (i = 0;i < t->NumTokens;i++)
		{
			char *name = t->Token[i];
			MsRegDeleteValue(REG_CURRENT_USER, SM_SETTING_REG_KEY, name);
		}

		FreeToken(t);
	}

	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		char name[MAX_SIZE];
		SETTING *s = LIST_DATA(sm->SettingList, i);

		// 書き込む
		Format(name, sizeof(name), "Setting%u", i + 1);
		MsRegWriteBin(REG_CURRENT_USER, SM_SETTING_REG_KEY, name, s, sizeof(SETTING));
	}
}

// 接続リストの読み込み
void SmLoadSettingList()
{
	TOKEN_LIST *t;
	UINT i;
	char *key_name = SM_SETTING_REG_KEY;

	t = MsRegEnumValue(REG_CURRENT_USER, key_name);
	if (t == NULL)
	{
		key_name = SM_SETTING_REG_KEY_OLD;
		t = MsRegEnumValue(REG_CURRENT_USER, key_name);
		if (t == NULL)
		{
			return;
		}
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		BUF *b = MsRegReadBin(REG_CURRENT_USER, key_name, name);
		if (b != NULL)
		{
			if (b->Size == sizeof(SETTING))
			{
				SETTING *s = ZeroMalloc(sizeof(SETTING));
				Copy(s, b->Buf, sizeof(SETTING));

				Add(sm->SettingList, s);
			}
			FreeBuf(b);
		}
	}

	FreeToken(t);

	Sort(sm->SettingList);
}

// デフォルトの設定リストの初期化
void SmInitDefaultSettingList()
{
	if (LIST_NUM(sm->SettingList) == 0)
	{
		bool b = false;
		LIST *pl = MsGetProcessList();

		if (pl != NULL)
		{
			UINT i;
			for (i = 0;i < LIST_NUM(pl);i++)
			{
				MS_PROCESS *p = LIST_DATA(pl, i);

				if (InStr(p->ExeFilename, "utvpnserver.exe") || InStr(p->ExeFilename, "utvpnserver_x64.exe") ||
					InStr(p->ExeFilename, "utvpnserver_ia64.exe") ||
					InStr(p->ExeFilename, "utvpnbridge.exe") || InStr(p->ExeFilename, "utvpnbridge_x64.exe") ||
					InStr(p->ExeFilename, "utvpnbridge_ia64.exe"))
				{
					b = true;
				}
			}
		}

		MsFreeProcessList(pl);

		if (b == false)
		{
			if (MsIsServiceRunning(_SS("SVC_UTVPNSERVER_NAME")))
			{
				b = true;
			}
		}

		if (b)
		{
			SETTING *s = ZeroMalloc(sizeof(SETTING));

			UniStrCpy(s->Title, sizeof(s->Title), _UU("SM_LOCALHOST"));
			s->ServerAdminMode = true;
			Hash(s->HashedPassword, "", 0, true);
			UniStrCpy(s->ClientOption.AccountName, sizeof(s->ClientOption.AccountName), s->Title);
			StrCpy(s->ClientOption.Hostname, sizeof(s->ClientOption.Hostname), "localhost");
			s->ClientOption.Port = 5555;

			Add(sm->SettingList, s);
		}
	}
}

// メインダイアログ初期化
void SmMainDlgInit(HWND hWnd)
{
	wchar_t *last_select;
	UINT i = INFINITE;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_VPNSERVER);

	LvInit(hWnd, L_SETTING);
	LvSetStyle(hWnd, L_SETTING, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_SETTING, 0, _UU("SM_MAIN_COLUMN_1"), 146);
	LvInsertColumn(hWnd, L_SETTING, 1, _UU("SM_MAIN_COLUMN_2"), 130);
	LvInsertColumn(hWnd, L_SETTING, 2, _UU("SM_MAIN_COLUMN_3"), 130);

	SmRefreshSetting(hWnd);

	last_select = MsRegReadStrW(REG_CURRENT_USER, SM_REG_KEY, "Last Select");
	if (UniIsEmptyStr(last_select) == false)
	{
		i = LvSearchStr(hWnd, L_SETTING, 0, last_select);
	}
	Free(last_select);

	if (i == INFINITE)
	{
		LvSelect(hWnd, L_SETTING, 0);
	}
	else
	{
		LvSelect(hWnd, L_SETTING, i);
	}

	Focus(hWnd, L_SETTING);

	SmMainDlgUpdate(hWnd);
}

// 設定一覧の更新
void SmRefreshSetting(HWND hWnd)
{
	SmRefreshSettingEx(hWnd, NULL);
}
void SmRefreshSettingEx(HWND hWnd, wchar_t *select_name)
{
	LVB *b;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		SETTING *s = LIST_DATA(sm->SettingList, i);

		if (s->ServerAdminMode)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_MODE_SERVER"));
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("SM_MODE_HUB"), s->HubName);
		}

		StrToUni(tmp2, sizeof(tmp2), s->ClientOption.Hostname);

		LvInsertAdd(b,
			(s->ServerAdminMode ? ICO_SERVER_ONLINE : ICO_HUB),
			NULL,
			3,
			s->Title,
			tmp2,
			tmp);
	}

	LvInsertEnd(b, hWnd, L_SETTING);

	if (UniIsEmptyStr(select_name) == false)
	{
		LvSelect(hWnd, L_SETTING, LvSearchStr(hWnd, L_SETTING, 0, select_name));
	}
}

// メインダイアログ更新
void SmMainDlgUpdate(HWND hWnd)
{
	bool ok = true;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_SETTING) == false)
	{
		ok = false;
	}
	if (LvIsMultiMasked(hWnd, L_SETTING))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, B_EDIT_SETTING, ok);
	SetEnable(hWnd, B_DELETE, ok);
}

// メインウインドウプロシージャ
UINT SmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	NMLVDISPINFOW *info;
	NMLVKEYDOWN *key;
	wchar_t *tmp;
	UINT i;
	wchar_t new_name[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		ShowSplashEx(hWnd, "UT-VPN Server", 1300, SM_SPLASH_BORDER_COLOR);
		SmMainDlgInit(hWnd);
		SetTimer(hWnd, 4, 100, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 4:
			KillTimer(hWnd, 4);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// 接続
			i = LvGetSelected(hWnd, L_SETTING);
			if (i != INFINITE)
			{
				tmp = LvGetStr(hWnd, L_SETTING, i, 0);
				if (tmp != NULL)
				{
					SETTING *setting = SmGetSetting(tmp);
					if (setting != NULL)
					{
						SETTING s;

						// レジストリに最後の選択として記録
						MsRegWriteStrW(REG_CURRENT_USER, SM_REG_KEY, "Last Select", tmp);

						// 設定コピー
						Copy(&s, setting, sizeof(SETTING));
						SmConnect(hWnd, &s);
					}
					Free(tmp);
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_NEW_SETTING:
			// 追加
			if (SmAddSettingDlg(hWnd, new_name, sizeof(new_name)))
			{
				SmRefreshSettingEx(hWnd, new_name);
			}
			break;

		case B_EDIT_SETTING:
			// 編集
			if (SmEditSettingDlg(hWnd))
			{
				SmWriteSettingList();
				SmRefreshSetting(hWnd);
			}

			break;

		case B_DELETE:
			// 削除
			i = LvGetSelected(hWnd, L_SETTING);
			if (i != INFINITE)
			{
				tmp = LvGetStr(hWnd, L_SETTING, i, 0);
				if (tmp != NULL)
				{
					if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
						_UU("SM_SETTING_DELETE_MSG"), tmp) == IDYES)
					{
						SmDeleteSetting(tmp);
						SmWriteSettingList();
						SmRefreshSetting(hWnd);
					}
					Free(tmp);
				}
			}
			break;

		case B_ABOUT:
			// バージョン情報
			ShowSplashEx(hWnd, "UT-VPN Server", 0, SM_SPLASH_BORDER_COLOR);
			break;

		case B_SECURE_MANAGER:
			// スマートカードマネージャ
			SmSecureManager(hWnd);
			break;

		case B_SELECT_SECURE:
			// スマートカード選択
			SmSelectSecureId(hWnd);
			break;
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_SETTING:
			switch (n->code)
			{
			case NM_DBLCLK:
				Command(hWnd, IDOK);
				break;

			case LVN_KEYDOWN:
				key = (NMLVKEYDOWN *)n;
				if (key != NULL)
				{
					UINT code = key->wVKey;
					switch (code)
					{
					case VK_F2:
						if (LvIsSelected(hWnd, L_SETTING))
						{
							LvRename(hWnd, L_SETTING, LvGetSelected(hWnd, L_SETTING));
						}
						break;

					case VK_DELETE:
						Command(hWnd, B_DELETE);
						break;

					case VK_RETURN:
						Command(hWnd, IDOK);
						break;
					}
				}
				break;

			case LVN_ENDLABELEDITW:
				// 名前の変更
				info = (NMLVDISPINFOW *)n;
				if (info->item.pszText != NULL)
				{
					wchar_t *new_name = info->item.pszText;
					wchar_t *old_name = LvGetStr(hWnd, L_SETTING, info->item.iItem, 0);

					if (old_name != NULL)
					{
						if (UniStrCmp(new_name, old_name) != 0 && UniStrLen(new_name) != 0)
						{
							// 名前変更の実行
							SETTING *s = SmGetSetting(old_name);
							if (s != NULL)
							{
								if (SmGetSetting(new_name) != NULL)
								{
									MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_SETTING_EXISTS"),
										new_name);
								}
								else
								{
									UniStrCpy(s->Title, sizeof(s->Title), new_name);
									Sort(sm->SettingList);
									SmWriteSettingList();
									LvSetItem(hWnd, L_SETTING, info->item.iItem, 0, new_name);
								}
							}
						}

						Free(old_name);
					}
				}
				break;

			case LVN_ITEMCHANGED:
				SmMainDlgUpdate(hWnd);
				break;
			}
			break;
		}
		break;
	}

	LvSortHander(hWnd, msg, wParam, lParam, L_SETTING);

	return 0;
}

// メインウインドウ
void SmMainDlg()
{
	Dialog(NULL, D_SM_MAIN, SmMainDlgProc, NULL);
}

// Server Manager メイン処理
void MainSM()
{
	if (sm->TempSetting == NULL)
	{
		// メインウインドウを開く
		SmMainDlg();
	}
	else
	{
		SmConnect(sm->hParentWnd, sm->TempSetting);
	}
}

// 初期化
void InitSM()
{
	if (sm != NULL)
	{
		// すでに初期化されている
		return;
	}

	sm = ZeroMalloc(sizeof(SM));

	InitWinUi(_UU("SM_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	sm->Cedar = NewCedar(NULL, NULL);

	SmInitSettingList();

	InitCM();

	// コマンドラインを解釈する
	SmParseCommandLine();
}

// コマンドラインを解釈する
void SmParseCommandLine()
{
	LIST *o;
	CONSOLE *c = NewLocalConsole(NULL, NULL);
	wchar_t *cmdline;
	PARAM args[] =
	{
		{"[vpnserver]", NULL, NULL, NULL, NULL,},
		{"HUB", NULL, NULL, NULL, NULL,},
		{"PASSWORD", NULL, NULL, NULL, NULL,},
		{"TITLE", NULL, NULL, NULL, NULL,},
		{"HWND", NULL, NULL, NULL, NULL,},
	};
	if (c == NULL)
	{
		return;
	}
	
	cmdline = GetCommandLineUniStr();

	if (UniIsEmptyStr(cmdline) == false)
	{
		o = ParseCommandList(c, "vpnsmgr", cmdline, args, sizeof(args) / sizeof(args[0]));
		if (o != NULL)
		{
			char *host;
			UINT port;

			if (ParseHostPort(GetParamStr(o, "[vpnserver]"), &host, &port, 443))
			{
				char *hub = GetParamStr(o, "HUB");
				char *password = GetParamStr(o, "PASSWORD");
				char *title = GetParamStr(o, "TITLE");
				char *hwndstr = GetParamStr(o, "HWND");

				if (hub == NULL || StrCmpi(hub, "\"") == 0)
				{
					hub = CopyStr("");
				}
				if (password == NULL)
				{
					password = CopyStr("");
				}
				if (title == NULL)
				{
					title = CopyStr(host);
				}

				if (IsEmptyStr(host) == false)
				{
					SETTING *s = ZeroMalloc(sizeof(SETTING));
					BUF *b;
					CLIENT_OPTION *o;

					StrToUni(s->Title, sizeof(s->Title), title);

					if (IsEmptyStr(hub))
					{
						s->ServerAdminMode = true;
					}
					else
					{
						s->ServerAdminMode = false;
						StrCpy(s->HubName, sizeof(s->HubName), hub);
					}

					b = StrToBin(password);
					if (b == NULL || b->Size != SHA1_SIZE)
					{
						Hash(s->HashedPassword, password, StrLen(password), true);
					}
					else
					{
						Copy(s->HashedPassword, b->Buf, SHA1_SIZE);
					}
					FreeBuf(b);

					o = &s->ClientOption;

					UniStrCpy(o->AccountName, sizeof(o->AccountName), s->Title);
					StrCpy(o->Hostname, sizeof(o->Hostname), host);
					o->Port = port;
					o->ProxyType = PROXY_DIRECT;
					StrCpy(o->DeviceName, sizeof(o->DeviceName), "DUMMY");

					sm->TempSetting = s;

					if (IsEmptyStr(hwndstr) == false)
					{
						sm->hParentWnd = (HWND)ToInt64(hwndstr);
					}
				}

				Free(hwndstr);
				Free(title);
				Free(hub);
				Free(password);
				Free(host);
			}
		}
	}

	Free(cmdline);

	c->Free(c);
}

// 解放
void FreeSM()
{
	if (sm == NULL)
	{
		// 初期化されていない
		return;
	}

	FreeCM();

	SmFreeSettingList();

	ReleaseCedar(sm->Cedar);

	FreeWinUi();

	if (sm->TempSetting != NULL)
	{
		Free(sm->TempSetting);
	}

	Free(sm);
	sm = NULL;
}

// Server Manager の実行
void SMExec()
{
	InitSM();
	MainSM();
	FreeSM();
}

#endif	// WIN32


