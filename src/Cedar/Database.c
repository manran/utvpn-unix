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

// Database.c
// ライセンスデータベース

// 注意: このコードは製品版 PacketiX VPN と互換性を保つために存在しており、
//       UT-VPN ではほとんど必要がないプログラムが含まれている。

#include "CedarPch.h"

// ライセンス状態文字列の取得
wchar_t *LiGetLicenseStatusStr(UINT i)
{
	wchar_t *ret = _UU("LICENSE_STATUS_OTHERERROR");

	switch (i)
	{
	case LICENSE_STATUS_OK:
		ret = _UU("LICENSE_STATUS_OK");
		break;

	case LICENSE_STATUS_EXPIRED:
		ret = _UU("LICENSE_STATUS_EXPIRED");
		break;

	case LICENSE_STATUS_ID_DIFF:
		ret = _UU("LICENSE_STATUS_ID_DIFF");
		break;

	case LICENSE_STATUS_DUP:
		ret = _UU("LICENSE_STATUS_DUP");
		break;

	case LICENSE_STATUS_INSUFFICIENT:
		ret = _UU("LICENSE_STATUS_INSUFFICIENT");
		break;

	case LICENSE_STATUS_COMPETITION:
		ret = _UU("LICENSE_STATUS_COMPETITION");
		break;

	case LICENSE_STATUS_NONSENSE:
		ret = _UU("LICENSE_STATUS_NONSENSE");
		break;

	case LICENSE_STATUS_CPU:
		ret = _UU("LICENSE_STATUS_CPU");
		break;
	}

	return ret;
}

// 現在のライセンスのステータスを解析して保存する
void LiParseCurrentLicenseStatus(LICENSE_SYSTEM *s, LICENSE_STATUS *status)
{
	// 引数チェック
	if (s == NULL)
	{
		if (status != NULL)
		{
			Zero(status, sizeof(LICENSE_STATUS));
		}
		return;
	}

	if (true)
	{
		LICENSE_STATUS *st = ZeroMalloc(sizeof(LICENSE_STATUS));

		st->MaxHubs = MAX_HUBS;

		if (Is64())
		{
			st->MaxHubs = MAX_HUBS_FOR_64BIT;
		}

		st->MaxSessions = SERVER_MAX_SESSIONS;

		if (Is64())
		{
			st->MaxSessions = SERVER_MAX_SESSIONS_FOR_64BIT;
		}

		// エディション名
		StrCpy(st->EditionStr, sizeof(st->EditionStr),
			"SoftEther UT-VPN Server (GPL)");
		st->Edition = LICENSE_EDITION_UTVPN_GPL;

		st->AllowAcceptFromClient = true;
		st->NeedSubscription = false;
		st->NumUserLicense = INFINITE;
		st->NumBridgeLicense = INFINITE;
		st->NumClientLicense = INFINITE;
		st->AllowEnterpriseFunction = true;
		st->CarrierEdition = false;
		st->Expires = 0;
		st->IsSubscriptionExpired = false;
		st->SystemId = 0;

		if (status != NULL)
		{
			Copy(status, st, sizeof(LICENSE_STATUS));
		}

		Copy(s->Status, st, sizeof(LICENSE_STATUS));

		Free(st);
	}
	UnlockList(s->LicenseList);
}

// ライセンスシステムの解放
void LiFreeLicenseSystem(LICENSE_SYSTEM *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	ReleaseList(s->LicenseList);

	if (s->Status != NULL)
	{
		Free(s->Status);
	}

	Free(s);
}

// ライセンスシステムをデバッグモードで作成
LICENSE_SYSTEM *LiNewLicenseSystem()
{
	LICENSE_SYSTEM *s;

	s = ZeroMalloc(sizeof(LICENSE_SYSTEM));

	s->Status = ZeroMalloc(sizeof(LICENSE_STATUS));

	return s;
}
