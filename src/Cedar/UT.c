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

// UT.c
// Win32 用 SoftEther Network Utility

#ifdef	WIN32

#define	UT_C

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
#include "../PenCore/resource.h"

static char *selected_adapter = NULL;

// Q. 「スピードメーター」という関数名になっているがこれはどういう意味か? 警察のオービスなのか?
// A. もともとこのネットワーク情報表示ユーティリティは、通信速度を測定するために開発
//    されたのである。しかし、その後「TrafficServer」、「TrafficClient」機能が別途
//    開発されたため、速度測定機能はこのユーティリティからは削除された。
//    関数名はその時代の名残である。

// ステータスの更新
void UtSpeedMeterDlgRefreshStatus(HWND hWnd)
{
	char *title;
	MS_ADAPTER *a;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	title = selected_adapter;

	a = MsGetAdapter(title);
	if (a == NULL)
	{
		LbReset(hWnd, L_STATUS);
		Disable(hWnd, L_STATUS);
	}
	else
	{
		LVB *b;
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		char str[MAX_SIZE];
		b = LvInsertStart();

		StrToUni(tmp, sizeof(tmp), a->Title);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_TITLE"), tmp);

		StrToUni(tmp, sizeof(tmp), a->Guid);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_GUID"), tmp);

		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_TYPE"), MsGetAdapterTypeStr(a->Type));

		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_STATUS"), MsGetAdapterStatusStr(a->Status));

		UniToStr3(tmp, sizeof(tmp), a->Mtu);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_MTU"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->Speed);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SPEED"), tmp);

		Zero(str, sizeof(str));
		BinToStrEx2(str, sizeof(str), a->Address, a->AddressSize, '-');
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_ADDRESS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->RecvBytes);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_RECV_BYTES"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->RecvPacketsBroadcast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_RECV_BCASTS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->RecvPacketsUnicast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_RECV_UNICASTS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->SendBytes);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SEND_BYTES"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->SendPacketsBroadcast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SEND_BCASTS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->SendPacketsUnicast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SEND_UNICASTS"), tmp);

		for (i = 0;i < a->NumIpAddress;i++)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("UT_SM_ST_IP"), i + 1);
			IPToUniStr(tmp, sizeof(tmp), &a->IpAddresses[i]);
			LvInsertAdd(b, 0, NULL, 2, tmp2, tmp);

			UniFormat(tmp2, sizeof(tmp2), _UU("UT_SM_ST_SUBNET"), i + 1);
			IPToUniStr(tmp, sizeof(tmp), &a->SubnetMasks[i]);
			LvInsertAdd(b, 0, NULL, 2, tmp2, tmp);
		}

		for (i = 0;i < a->NumGateway;i++)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("UT_SM_ST_GATEWAY"), i + 1);
			IPToUniStr(tmp, sizeof(tmp), &a->Gateways[i]);
			LvInsertAdd(b, 0, NULL, 2, tmp2, tmp);
		}

		if (a->UseDhcp)
		{
			IPToUniStr(tmp, sizeof(tmp), &a->DhcpServer);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_DHCP"), tmp);

			GetDateTimeStrEx64(tmp, sizeof(tmp), a->DhcpLeaseStart, NULL);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_DHCP_1"), tmp);

			GetDateTimeStrEx64(tmp, sizeof(tmp), a->DhcpLeaseExpires, NULL);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_DHCP_2"), tmp);
		}

		if (a->UseWins)
		{
			IPToUniStr(tmp, sizeof(tmp), &a->PrimaryWinsServer);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_WINS_1"), tmp);

			IPToUniStr(tmp, sizeof(tmp), &a->SecondaryWinsServer);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_WINS_2"), tmp);
		}

		LvInsertEnd(b, hWnd, L_STATUS);
		Enable(hWnd, L_STATUS);

		MsFreeAdapter(a);
	}

}

// アダプタリストの更新
void UtSpeedMeterDlgRefreshList(HWND hWnd)
{
	wchar_t *old;
	MS_ADAPTER_LIST *o;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	// 現在の選択を取得
	old = GetText(hWnd, E_LIST);
	if (old != NULL)
	{
		if (UniStrLen(old) == 0)
		{
			Free(old);
			old = NULL;
		}
	}

	o = MsCreateAdapterList();
	CbReset(hWnd, E_LIST);
	CbSetHeight(hWnd, E_LIST, 18);

	for (i = 0;i < o->Num;i++)
	{
		wchar_t tmp[MAX_SIZE];
		MS_ADAPTER *a = o->Adapters[i];

		if (a->Info)
		{
			StrToUni(tmp, sizeof(tmp), a->Title);
			CbAddStr(hWnd, E_LIST, tmp, 0);
		}
	}


	// 前回の選択を再選択
	if (old != NULL)
	{
		CbSelectIndex(hWnd, E_LIST, CbFindStr(hWnd, E_LIST, old));
		Free(old);
	}

	MsFreeAdapterList(o);
}

// スピードメーターダイアログコントロール更新
void UtSpeedMeterDlgUpdate(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}
}

// スピードメーターダイアログ初期化
void UtSpeedMeterDlgInit(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	LvInitEx(hWnd, L_STATUS, true);
	LvInsertColumn(hWnd, L_STATUS, 0, _UU("UT_SM_COLUMN_1"), 150);
	LvInsertColumn(hWnd, L_STATUS, 1, _UU("UT_SM_COLUMN_2"), 290);

	UtSpeedMeterDlgRefreshList(hWnd);
	selected_adapter = GetTextA(hWnd, E_LIST);
	UtSpeedMeterDlgRefreshStatus(hWnd);
	UtSpeedMeterDlgUpdate(hWnd);
}

// スピードメーターダイアログ
UINT UtSpeedMeterDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_NIC_ONLINE);
		UtSpeedMeterDlgInit(hWnd);
		SetTimer(hWnd, 1, SPEED_METER_REFRESH_INTERVAL, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			UtSpeedMeterDlgRefreshStatus(hWnd);
			UtSpeedMeterDlgUpdate(hWnd);
			SetTimer(hWnd, 1, SPEED_METER_REFRESH_INTERVAL, NULL);
			break;
		}
		break;

	case WM_COMMAND:
		if (HIWORD(wParam) == CBN_SELCHANGE) {
			Free(selected_adapter);
			selected_adapter = GetTextA(hWnd, E_LIST);
			UtSpeedMeterDlgUpdate(hWnd);
		} else {
			switch (wParam)
			{
			case B_REFRESH:
				UtSpeedMeterDlgRefreshList(hWnd);
				Free(selected_adapter);
				selected_adapter = GetTextA(hWnd, E_LIST);
				UtSpeedMeterDlgUpdate(hWnd);
				break;

			case IDCANCEL:
				Close(hWnd);
				break;
			}
		}
		break;

	case WM_CLOSE:
		Free(selected_adapter);
		selected_adapter = NULL;
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// スピードメーター
void UtSpeedMeter()
{
	UtSpeedMeterEx(NULL);
}
void UtSpeedMeterEx(void *hWnd)
{
	Dialog((HWND)hWnd, D_SPEEDMETER, UtSpeedMeterDlgProc, NULL);
}

#endif // WIN32

