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

// Client.c
// クライアントマネージャ

#include "CedarPch.h"

static CLIENT *client = NULL;
static LISTENER *cn_listener = NULL;
static LOCK *cn_listener_lock = NULL;
static UINT64 cn_next_allow = 0;

#ifdef	OS_WIN32

#endif	// OS_WIN32

// 注意: VPN Client サービスを実装するこのソースコードの一部には、
// リエントラント (Reentrant: 再入可能) でないコードが含まれている。
// もともと VPN Client のサービスと GUI (クライアント接続マネージャ) は一体
// のものとして開発され、途中で分離された。その際に本来であれば TLS 等を用いて
// スレッドセーフにしなければならない部分が、もとのままになってしまっている。
// したがって、ごくまれに、GUI (クライアント接続マネージャ) や utvpncmd が
// 複数個、1 個の VPN Client サービスに対して接続して、ほぼ同時に何らかの
// 内部状態を変化させる処理を行ったとき、戻り値に不整合が生じる場合がある。

// RPC_CLIENT_ENUM_ACCOUNT_ITEM を最終接続日時で逆ソート
int CiCompareClientAccountEnumItemByLastConnectDateTime(void *p1, void *p2)
{
	RPC_CLIENT_ENUM_ACCOUNT_ITEM *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(RPC_CLIENT_ENUM_ACCOUNT_ITEM **)p1;
	a2 = *(RPC_CLIENT_ENUM_ACCOUNT_ITEM **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	if (a1->LastConnectDateTime > a2->LastConnectDateTime)
	{
		return -1;
	}
	else if (a1->LastConnectDateTime < a2->LastConnectDateTime)
	{
		return 1;
	}

	return 0;
}

// マシンが変更されていた場合はすべての仮想 LAN カードの MAC アドレスを乱数に設定する
// このあたりは急いで実装したのでコードがあまり美しくない。
// Q. なぜこのような処理が必要なのか?
// A. Windows をインストールし、次に VPN Client をインストールして仮想 LAN カード
//    を作成した状態を初期状態として HDD イメージをクローンし社内の複数の PC に
//    インストールするような企業が存在する。
//    そのような企業においてクローン後も仮想 LAN カードの MAC アドレスがすべて同一
//    であれば障害の理由になる可能性があるためである。
void CiChangeAllVLanMacAddressIfMachineChanged(CLIENT *c)
{
	UCHAR current_hash[SHA1_SIZE];
	UCHAR current_hash_old[SHA1_SIZE];
	UCHAR saved_hash[SHA1_SIZE];
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

#ifdef OS_WIN32
	if (MsIsAdmin() == false)
	{
		return;
	}
#endif

	// このあたりは急いで実装したのでコードがあまり美しくない。
	CiGetCurrentMachineHash(current_hash);
	CiGetCurrentMachineHashOld(current_hash_old);

	if (CiReadLastMachineHash(saved_hash) == false)
	{
		CiWriteLastMachineHash(current_hash);
		return;
	}

	if (Cmp(saved_hash, current_hash_old, SHA1_SIZE) == 0)
	{
		CiWriteLastMachineHash(current_hash);
		return;
	}

	if (Cmp(saved_hash, current_hash, SHA1_SIZE) == 0)
	{
		return;
	}

	if (CiWriteLastMachineHash(current_hash) == false)
	{
		return;
	}

	CiChangeAllVLanMacAddress(c);
}

// 現在のマシンハッシュを取得する (古い方式)
// このあたりは急いで実装したのでコードがあまり美しくない。
void CiGetCurrentMachineHashOld(void *data)
{
	char name[MAX_PATH];
	char *product_id = NULL;
	// 引数チェック
	if (data == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	// プロダクト ID
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}

	StrCpy(name, sizeof(name), product_id);

	Free(product_id);

#else	// OS_WIN32
	GetMachineName(name, sizeof(name));
#endif	// OS_WIN32

	Trim(name);
	StrUpper(name);

	Hash(data, name, StrLen(name), true);
}

// 現在のマシンハッシュを取得する
void CiGetCurrentMachineHash(void *data)
{
	char name[MAX_PATH];
	char *product_id = NULL;
	// 引数チェック
	if (data == NULL)
	{
		return;
	}

	GetMachineName(name, sizeof(name));

	Trim(name);
	StrUpper(name);

	Hash(data, name, StrLen(name), true);
}

// マシンハッシュを書き込む
bool CiWriteLastMachineHash(void *data)
{
	// 引数チェック
	if (data == NULL)
	{
		return false;
	}

#ifdef OS_WIN32
	if (MsRegWriteBinEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "LastMachineHash_UTVPNClient", data, SHA1_SIZE, true) == false)
	{
		return false;
	}

	return true;
#else	// OS_WIN32
	return false;
#endif	// OS_WIN32
}

// 前回のマシンハッシュを取得する
bool CiReadLastMachineHash(void *data)
{
	BUF *b = NULL;
	// 引数チェック
	if (data == NULL)
	{
		return false;
	}

#ifdef OS_WIN32
	b = MsRegReadBinEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "LastMachineHash_UTVPNClient", true);
	if (b == NULL)
	{
		return false;
	}
	if (b->Size == SHA1_SIZE)
	{
		Copy(data, b->Buf, b->Size);
		FreeBuf(b);

		return true;
	}

	FreeBuf(b);
	return false;
#else	// OS_WIN32
	return false;
#endif	// OS_WIN32
}

// すべての仮想 LAN カードの MAC アドレスを乱数に設定する
void CiChangeAllVLanMacAddress(CLIENT *c)
{
	RPC_CLIENT_ENUM_VLAN t;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CtEnumVLan(c, &t))
	{
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_CLIENT_ENUM_VLAN_ITEM *e = t.Items[i];
			UCHAR mac[6];

			if (StrToMac(mac, e->MacAddress) && mac[1] == 0xAC)
			{
				char *name = e->DeviceName;
				RPC_CLIENT_SET_VLAN s;
				UCHAR mac[6];

				GenMacAddress(mac);

				Zero(&s, sizeof(s));
				StrCpy(s.DeviceName, sizeof(s.DeviceName), name);

				MacToStr(s.MacAddress, sizeof(s.MacAddress), mac);

				CtSetVLan(c, &s);
			}
		}

		CiFreeClientEnumVLan(&t);
	}
}

// 通知サービスの準備が完了するまで待機する
void CnWaitForCnServiceReady()
{
	UINT64 start_time = Tick64();

	while ((start_time + (UINT64)CLIENT_WAIT_CN_READY_TIMEOUT) >= Tick64())
	{
		if (CnIsCnServiceReady())
		{
			break;
		}

		SleepThread(100);
	}
}

// 通知サービスの準備が完了しているかどうかチェックする
// このあたりは急いで実装したのでコードがあまり美しくない。
bool CnIsCnServiceReady()
{
	SOCK *s;
	// 通知サービスの起動を確認する
	if (CnCheckAlreadyExists(false) == false)
	{
		// 起動していない
		return false;
	}

	// TCP ポートへの接続を試行する
	s = ConnectEx("localhost", CLIENT_NOTIFY_PORT, 500);
	if (s == NULL)
	{
		// TCP ポートを開いていない
		return false;
	}

	Disconnect(s);
	ReleaseSock(s);

	// 起動していた
	return true;
}

// すでに通知サービスが動作しているかどうかチェックする
bool CnCheckAlreadyExists(bool lock)
{
	bool ret = false;

#ifdef	OS_WIN32
	ret = Win32CnCheckAlreadyExists(lock);
#endif

	return ret;
}

typedef struct CNC_STATUS_PRINTER_WINDOW_PARAM
{
	THREAD *Thread;
	SESSION *Session;
	SOCK *Sock;
} CNC_STATUS_PRINTER_WINDOW_PARAM;

typedef struct CNC_CONNECT_ERROR_DLG_THREAD_PARAM
{
	SESSION *Session;
	SOCK *Sock;
	bool HaltThread;
	EVENT *Event;
} CNC_CONNECT_ERROR_DLG_THREAD_PARAM;


// Win32 における utvpnclient.exe のファイル名を取得する
char *CiGetVpnClientExeFileName()
{
	if (Is64() == false)
	{
		return CLIENT_WIN32_EXE_FILENAME;
	}
	else
	{
		if (IsX64())
		{
			return CLIENT_WIN32_EXE_FILENAME_X64;
		}
		else
		{
			return CLIENT_WIN32_EXE_FILENAME_IA64;
		}
	}
}

// 証明書チェックダイアログクライアント強制停止用スレッド
void CncCheckCertHaltThread(THREAD *thread, void *param)
{
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp = (CNC_CONNECT_ERROR_DLG_THREAD_PARAM *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		if (dp->Session->Halt || dp->HaltThread)
		{
			break;
		}

		Wait(dp->Event, 100);
	}

	Disconnect(dp->Sock);
}

// 証明書チェックダイアログの表示
void CncCheckCert(SESSION *session, UI_CHECKCERT *dlg)
{
	SOCK *s;
	PACK *p;
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp;
	THREAD *t;
	// 引数チェック
	if (dlg == NULL || session == NULL)
	{
		return;
	}

	s = CncConnect();
	if (s == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "function", "check_cert");
	PackAddUniStr(p, "AccountName", dlg->AccountName);
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddX(p, "x", dlg->x);
	PackAddX(p, "parent_x", dlg->parent_x);
	PackAddX(p, "old_x", dlg->old_x);
	PackAddBool(p, "DiffWarning", dlg->DiffWarning);
	PackAddBool(p, "Ok", dlg->Ok);
	PackAddBool(p, "SaveServerCert", dlg->SaveServerCert);

	SendPack(s, p);
	FreePack(p);

	dp = ZeroMalloc(sizeof(CNC_CONNECT_ERROR_DLG_THREAD_PARAM));
	dp->Sock = s;
	dp->Event = NewEvent();
	dp->Session = session;

	t = NewThread(CncCheckCertHaltThread, dp);

	p = RecvPack(s);
	if (p != NULL)
	{
		dlg->Ok = PackGetBool(p, "Ok");
		dlg->DiffWarning = PackGetBool(p, "DiffWarning");
		dlg->SaveServerCert = PackGetBool(p, "SaveServerCert");

		FreePack(p);
	}

	dp->HaltThread = true;
	Set(dp->Event);

	WaitThread(t, INFINITE);

	ReleaseEvent(dp->Event);
	Free(dp);
	ReleaseThread(t);

	Disconnect(s);
	ReleaseSock(s);
}

// スマートカード署名ダイアログ
bool CncSecureSignDlg(SECURE_SIGN *sign)
{
	SOCK *s;
	PACK *p;
	bool ret = false;
	// 引数チェック
	if (sign == NULL)
	{
		return false;
	}

	s = CncConnect();
	if (s == NULL)
	{
		return false;
	}

	p = NewPack();
	PackAddStr(p, "function", "secure_sign");
	OutRpcSecureSign(p, sign);

	SendPack(s, p);
	FreePack(p);

	p = RecvPack(s);
	if (p != NULL)
	{
		ret = PackGetBool(p, "ret");

		if (ret)
		{
			FreeRpcSecureSign(sign);

			Zero(sign, sizeof(SECURE_SIGN));
			InRpcSecureSign(sign, p);
		}

		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// NIC 情報ダイアログの表示
SOCK *CncNicInfo(UI_NICINFO *info)
{
	SOCK *s;
	PACK *p;
	bool ret = false;
	// 引数チェック
	if (info == NULL)
	{
		return NULL;
	}

	s = CncConnectEx(200);
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "function", "nicinfo");
	PackAddStr(p, "NicName", info->NicName);
	PackAddUniStr(p, "AccountName", info->AccountName);

	SendPack(s, p);
	FreePack(p);

	return s;
}

// NIC 情報ダイアログを閉じる
void CncNicInfoFree(SOCK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Disconnect(s);
	ReleaseSock(s);
}

// メッセージダイアログの表示
SOCK *CncMsgDlg(UI_MSG_DLG *dlg)
{
	SOCK *s;
	PACK *p;
	bool ret = false;
	char *utf;
	// 引数チェック
	if (dlg == NULL)
	{
		return NULL;
	}

	s = CncConnectEx(200);
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "function", "msg_dialog");
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddStr(p, "HubName", dlg->HubName);
	utf = CopyUniToUtf(dlg->Msg);
	PackAddData(p, "Msg", utf, StrLen(utf));
	Free(utf);

	SendPack(s, p);
	FreePack(p);

	return s;
}

// メッセージダイアログを閉じる
void CndMsgDlgFree(SOCK *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Disconnect(s);
	ReleaseSock(s);
}

// パスワード入力ダイアログクライアント強制停止用スレッド
void CncPasswordDlgHaltThread(THREAD *thread, void *param)
{
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp = (CNC_CONNECT_ERROR_DLG_THREAD_PARAM *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		if (dp->Session->Halt || dp->HaltThread)
		{
			break;
		}

		Wait(dp->Event, 100);
	}

	Disconnect(dp->Sock);
}

// パスワード入力ダイアログの表示
bool CncPasswordDlg(SESSION *session, UI_PASSWORD_DLG *dlg)
{
	SOCK *s;
	PACK *p;
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp;
	THREAD *t;
	bool ret = false;
	// 引数チェック
	if (dlg == NULL || session == NULL)
	{
		return false;
	}

	s = CncConnect();
	if (s == NULL)
	{
		Wait(session->HaltEvent, session->RetryInterval);
		return true;
	}

	p = NewPack();
	PackAddStr(p, "function", "password_dialog");
	PackAddInt(p, "Type", dlg->Type);
	PackAddStr(p, "Username", dlg->Username);
	PackAddStr(p, "Password", dlg->Password);
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddInt(p, "RetryIntervalSec", dlg->RetryIntervalSec);
	PackAddBool(p, "ProxyServer", dlg->ProxyServer);
	PackAddBool(p, "AdminMode", dlg->AdminMode);
	PackAddBool(p, "ShowNoSavePassword", dlg->ShowNoSavePassword);
	PackAddBool(p, "NoSavePassword", dlg->NoSavePassword);

	SendPack(s, p);
	FreePack(p);

	dp = ZeroMalloc(sizeof(CNC_CONNECT_ERROR_DLG_THREAD_PARAM));
	dp->Session = session;
	dp->Sock = s;
	dp->Event = NewEvent();

	t = NewThread(CncConnectErrorDlgHaltThread, dp);

	p = RecvPack(s);
	if (p != NULL)
	{
		ret = PackGetBool(p, "ok");
		dlg->NoSavePassword = PackGetBool(p, "NoSavePassword");
		dlg->ProxyServer = PackGetBool(p, "ProxyServer");
		dlg->Type = PackGetInt(p, "Type");
		PackGetStr(p, "Username", dlg->Username, sizeof(dlg->Username));
		PackGetStr(p, "Password", dlg->Password, sizeof(dlg->Password));

		FreePack(p);
	}

	dp->HaltThread = true;
	Set(dp->Event);

	WaitThread(t, INFINITE);

	ReleaseEvent(dp->Event);
	Free(dp);
	ReleaseThread(t);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// 接続エラーダイアログクライアント強制停止用スレッド
void CncConnectErrorDlgHaltThread(THREAD *thread, void *param)
{
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp = (CNC_CONNECT_ERROR_DLG_THREAD_PARAM *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		if (dp->Session->Halt || dp->HaltThread)
		{
			break;
		}

		Wait(dp->Event, 100);
	}

	Disconnect(dp->Sock);
}

// 接続エラーダイアログの表示
bool CncConnectErrorDlg(SESSION *session, UI_CONNECTERROR_DLG *dlg)
{
	SOCK *s;
	PACK *p;
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp;
	THREAD *t;
	bool ret = false;
	// 引数チェック
	if (dlg == NULL || session == NULL)
	{
		return false;
	}

	s = CncConnect();
	if (s == NULL)
	{
		Wait(session->HaltEvent, session->RetryInterval);
		return true;
	}

	p = NewPack();
	PackAddStr(p, "function", "connecterror_dialog");
	PackAddUniStr(p, "AccountName", dlg->AccountName);
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddInt(p, "Err", dlg->Err);
	PackAddInt(p, "CurrentRetryCount", dlg->CurrentRetryCount);
	PackAddInt(p, "RetryLimit", dlg->RetryLimit);
	PackAddInt(p, "RetryIntervalSec", dlg->RetryIntervalSec);
	PackAddBool(p, "HideWindow", dlg->HideWindow);

	SendPack(s, p);
	FreePack(p);

	dp = ZeroMalloc(sizeof(CNC_CONNECT_ERROR_DLG_THREAD_PARAM));
	dp->Session = session;
	dp->Sock = s;
	dp->Event = NewEvent();

	t = NewThread(CncConnectErrorDlgHaltThread, dp);

	p = RecvPack(s);
	if (p != NULL)
	{
		ret = PackGetBool(p, "ok");
		dlg->HideWindow = PackGetBool(p, "HideWindow");

		FreePack(p);
	}

	dp->HaltThread = true;
	Set(dp->Event);

	WaitThread(t, INFINITE);

	ReleaseEvent(dp->Event);
	Free(dp);
	ReleaseThread(t);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// ステータス表示器クライアント用スレッド
void CncStatusPrinterWindowThreadProc(THREAD *thread, void *param)
{
	CNC_STATUS_PRINTER_WINDOW_PARAM *pp;
	SOCK *sock;
	PACK *p;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	pp = (CNC_STATUS_PRINTER_WINDOW_PARAM *)param;
	sock = pp->Sock;
	pp->Thread = thread;
	AddRef(pp->Thread->ref);

	NoticeThreadInit(thread);

	p = RecvPack(sock);
	if (p != NULL)
	{
		// セッションを停止する
		StopSessionEx(pp->Session, true);

		FreePack(p);
	}
}

// ステータス表示器クライアントの作成
SOCK *CncStatusPrinterWindowStart(SESSION *s)
{
	SOCK *sock;
	PACK *p;
	THREAD *t;
	CNC_STATUS_PRINTER_WINDOW_PARAM *param;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	sock = CncConnect();

	if (sock == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "function", "status_printer");
	PackAddUniStr(p, "account_name", s->Account->ClientOption->AccountName);

	if (SendPack(sock, p) == false)
	{
		FreePack(p);
		ReleaseSock(sock);

		return NULL;
	}

	FreePack(p);

	param = ZeroMalloc(sizeof(CNC_STATUS_PRINTER_WINDOW_PARAM));
	param->Sock = sock;
	param->Session = s;

	sock->Param = param;

	t = NewThread(CncStatusPrinterWindowThreadProc, param);
	WaitThreadInit(t);

	ReleaseThread(t);

	return sock;
}

// ステータス表示器に対して文字列を送信
void CncStatusPrinterWindowPrint(SOCK *s, wchar_t *str)
{
	CNC_STATUS_PRINTER_WINDOW_PARAM *param;
	PACK *p;
	// 引数チェック
	if (s == NULL || str == NULL)
	{
		return;
	}

	param = (CNC_STATUS_PRINTER_WINDOW_PARAM *)s->Param;

	p = NewPack();
	PackAddUniStr(p, "string", str);
	SendPack(s, p);
	FreePack(p);
}

// ステータス表示器クライアントの停止
void CncStatusPrinterWindowStop(SOCK *s)
{
	CNC_STATUS_PRINTER_WINDOW_PARAM *param;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	param = (CNC_STATUS_PRINTER_WINDOW_PARAM *)s->Param;

	// クライアントソケット切断
	Disconnect(s);

	// スレッド終了
	WaitThread(param->Thread, INFINITE);
	ReleaseThread(param->Thread);

	Free(param);
	ReleaseSock(s);
}

// Windows Vista 用のドライバインストーラの起動
bool CncExecDriverInstaller(char *arg)
{
	SOCK *s = CncConnect();
	PACK *p;
	bool ret;
	if (s == NULL)
	{
		return false;
	}

	p = NewPack();
	PackAddStr(p, "function", "exec_driver_installer");
	PackAddStr(p, "arg", arg);

	SendPack(s, p);
	FreePack(p);

	p = RecvPack(s);
	if (p == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
		return false;
	}

	ret = PackGetBool(p, "ret");

	FreePack(p);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// 現在動作しているクライアント通知サービスにソケットを解放させる
void CncReleaseSocket()
{
	SOCK *s = CncConnect();
	PACK *p;
	if (s == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "function", "release_socket");

#ifdef OS_WIN32
	PackAddInt(p, "pid", MsGetProcessId());
#endif	// OS_WIN32

	SendPack(s, p);
	FreePack(p);

	Disconnect(s);
	ReleaseSock(s);
}

// クライアント通知サービスのセッション ID の取得
UINT CncGetSessionId()
{
	SOCK *s = CncConnect();
	PACK *p;
	UINT ret;
	if (s == NULL)
	{
		return INFINITE;
	}

	p = NewPack();
	PackAddStr(p, "function", "get_session_id");

	SendPack(s, p);
	FreePack(p);

	p = RecvPack(s);
	if (p == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
		return INFINITE;
	}

	ret = PackGetInt(p, "session_id");

	FreePack(p);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// クライアント通知サービスのプロセスの終了
void CncExit()
{
	SOCK *s = CncConnectEx(256);
	PACK *p;
	if (s != NULL)
	{
		p = NewPack();
		PackAddStr(p, "function", "exit");

		SendPack(s, p);

		FreePack(p);

		FreePack(RecvPack(s));

		Disconnect(s);
		ReleaseSock(s);
	}

#ifdef	OS_WIN32
	MsKillOtherInstanceEx("utvpnclient");
#endif	// OS_WIN32
}

// クライアント通知サービスへの接続
SOCK *CncConnect()
{
	return CncConnectEx(0);
}
SOCK *CncConnectEx(UINT timeout)
{
	SOCK *s = ConnectEx("localhost", CLIENT_NOTIFY_PORT, timeout);

	return s;
}

#ifdef	OS_WIN32

// 証明書チェックダイアログ用スレッド
void Win32CnCheckCertThreadProc(THREAD *thread, void *param)
{
	UI_CHECKCERT *dlg;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	dlg = (UI_CHECKCERT *)param;

	CheckCertDlg(dlg);
	{
		PACK *p = NewPack();

		PackAddBool(p, "Ok", dlg->Ok);
		PackAddBool(p, "SaveServerCert", dlg->SaveServerCert);

		SendPack(dlg->Sock, p);
		FreePack(p);

		FreePack(RecvPack(dlg->Sock));
	}

	Disconnect(dlg->Sock);
}

// 証明書チェックダイアログ
void Win32CnCheckCert(SOCK *s, PACK *p)
{
	UI_CHECKCERT dlg;
	THREAD *t;
	Zero(&dlg, sizeof(dlg));
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetUniStr(p, "AccountName", dlg.AccountName, sizeof(dlg.AccountName));
	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	dlg.x = PackGetX(p, "x");
	dlg.parent_x = PackGetX(p, "parent_x");
	dlg.old_x = PackGetX(p, "old_x");
	dlg.DiffWarning = PackGetBool(p, "DiffWarning");
	dlg.Ok = PackGetBool(p, "Ok");
	dlg.SaveServerCert = PackGetBool(p, "SaveServerCert");
	dlg.Sock = s;

	t = NewThread(Win32CnCheckCertThreadProc, &dlg);

	FreePack(RecvPack(s));

	dlg.Halt = true;

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	FreeX(dlg.parent_x);
	FreeX(dlg.old_x);
	FreeX(dlg.x);
}

// メッセージ表示ダイアログスレッドプロシージャ
void Win32CnMsgDlgThreadProc(THREAD *thread, void *param)
{
	UI_MSG_DLG *dlg = (UI_MSG_DLG *)param;
	wchar_t tmp[MAX_SIZE];
	char url[MAX_SIZE];
	// 引数チェック
	if (thread == NULL || dlg == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CM_MSG_TITLE"),
		dlg->ServerName, dlg->HubName);

	if (IsURLMsg(dlg->Msg, url, sizeof(url)) == false)
	{
		OnceMsgEx(NULL, tmp, dlg->Msg, true, 167, &dlg->Halt);
	}
	else
	{
		if (MsExecute(url, NULL) == false)
		{
			OnceMsgEx(NULL, tmp, dlg->Msg, true, 167, &dlg->Halt);
		}
	}

	Disconnect(dlg->Sock);
}

// NIC 情報ダイアログスレッドプロシージャ
void Win32CnNicInfoThreadProc(THREAD *thread, void *param)
{
	UI_NICINFO *info = (UI_NICINFO *)param;
	// 引数チェック
	if (thread == NULL || info == NULL)
	{
		return;
	}

	if (MsIsNt())
	{
		// Windows 9x 系ではダイアログを表示しない
		NicInfo(info);
	}

	Disconnect(info->Sock);
}

// NIC 情報ダイアログ
void Win32CnNicInfo(SOCK *s, PACK *p)
{
	UI_NICINFO info;
	THREAD *t;
	Zero(&info, sizeof(info));
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "NicName", info.NicName, sizeof(info.NicName));
	PackGetUniStr(p, "AccountName", info.AccountName, sizeof(info.AccountName));

	info.Sock = s;

	t = NewThread(Win32CnNicInfoThreadProc, &info);

	FreePack(RecvPack(s));

	info.Halt = true;

	WaitThread(t, INFINITE);
	ReleaseThread(t);
}

// メッセージ表示ダイアログ
void Win32CnMsgDlg(SOCK *s, PACK *p)
{
	UI_MSG_DLG dlg;
	THREAD *t;
	UINT utf_size;
	char *utf;
	wchar_t *msg;
	Zero(&dlg, sizeof(dlg));
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	PackGetStr(p, "HubName", dlg.HubName, sizeof(dlg.HubName));

	utf_size = PackGetDataSize(p, "Msg");
	utf = ZeroMalloc(utf_size + 8);

	PackGetData(p, "Msg", utf);

	msg = CopyUtfToUni(utf);
	Free(utf);

	dlg.Sock = s;
	dlg.Msg = msg;

	t = NewThread(Win32CnMsgDlgThreadProc, &dlg);

	FreePack(RecvPack(s));

	dlg.Halt = true;

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	Free(msg);
}

// パスワード入力ダイアログ用スレッド
void Win32CnPasswordDlgThreadProc(THREAD *thread, void *param)
{
	UI_PASSWORD_DLG *dlg;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	dlg = (UI_PASSWORD_DLG *)param;

	if (PasswordDlg(NULL, dlg))
	{
		PACK *p = NewPack();

		PackAddBool(p, "ok", true);
		PackAddStr(p, "Username", dlg->Username);
		PackAddStr(p, "Password", dlg->Password);
		PackAddInt(p, "Type", dlg->Type);
		PackAddBool(p, "ProxyServer", dlg->ProxyServer);
		PackAddBool(p, "NoSavePassword", dlg->NoSavePassword);

		SendPack(dlg->Sock, p);
		FreePack(p);

		FreePack(RecvPack(dlg->Sock));
	}

	Disconnect(dlg->Sock);
}

// パスワード入力ダイアログ
void Win32CnPasswordDlg(SOCK *s, PACK *p)
{
	UI_PASSWORD_DLG dlg;
	THREAD *t = NULL;
	Zero(&dlg, sizeof(dlg));
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	dlg.Type = PackGetInt(p, "Type");
	PackGetStr(p, "Username", dlg.Username, sizeof(dlg.Username));
	PackGetStr(p, "Password", dlg.Password, sizeof(dlg.Password));
	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	dlg.RetryIntervalSec = PackGetInt(p, "RetryIntervalSec");
	dlg.ProxyServer = PackGetBool(p, "ProxyServer");
	dlg.AdminMode = PackGetBool(p, "AdminMode");
	dlg.ShowNoSavePassword = PackGetBool(p, "ShowNoSavePassword");
	dlg.NoSavePassword = PackGetBool(p, "NoSavePassword");
	dlg.CancelEvent = NewEvent();
	dlg.Sock = s;

	t = NewThread(Win32CnPasswordDlgThreadProc, &dlg);

	FreePack(RecvPack(s));

	Set(dlg.CancelEvent);

	WaitThread(t, INFINITE);
	ReleaseEvent(dlg.CancelEvent);
	ReleaseThread(t);
}

// 接続エラーダイアログ用スレッド
void Win32CnConnectErrorDlgThreadProc(THREAD *thread, void *param)
{
	UI_CONNECTERROR_DLG *dlg;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	dlg = (UI_CONNECTERROR_DLG *)param;

	if (ConnectErrorDlg(dlg))
	{
		PACK *p = NewPack();

		PackAddBool(p, "ok", true);
		PackAddBool(p, "HideWindow", dlg->HideWindow);

		SendPack(dlg->Sock, p);
		FreePack(p);

		FreePack(RecvPack(dlg->Sock));
	}

	Disconnect(dlg->Sock);
}

// 接続エラーダイアログ (Win32)
void Win32CnConnectErrorDlg(SOCK *s, PACK *p)
{
	UI_CONNECTERROR_DLG dlg;
	THREAD *t;
	Zero(&dlg, sizeof(dlg));
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetUniStr(p, "AccountName", dlg.AccountName, sizeof(dlg.AccountName));
	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	dlg.Err = PackGetInt(p, "Err");
	dlg.CurrentRetryCount = PackGetInt(p, "CurrentRetryCount");
	dlg.RetryLimit = PackGetInt(p, "RetryLimit");
	dlg.RetryIntervalSec = PackGetInt(p, "RetryIntervalSec");
	dlg.HideWindow = PackGetBool(p, "HideWindow");
	dlg.CancelEvent = NewEvent();
	dlg.Sock = s;

	t = NewThread(Win32CnConnectErrorDlgThreadProc, &dlg);

	FreePack(RecvPack(s));

	Set(dlg.CancelEvent);

	WaitThread(t, INFINITE);
	ReleaseEvent(dlg.CancelEvent);
	ReleaseThread(t);
}

// ステータス表示器 (Win32)
void Win32CnStatusPrinter(SOCK *s, PACK *p)
{
	STATUS_WINDOW *w;
	wchar_t account_name[MAX_ACCOUNT_NAME_LEN + 1];
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetUniStr(p, "account_name", account_name, sizeof(account_name));

	w = StatusPrinterWindowStart(s, account_name);

	while (true)
	{
		PACK *p = RecvPack(s);

		if (p == NULL)
		{
			// 切断されたのでダイアログを終了する
			break;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			// 文字列を書き換える
			PackGetUniStr(p, "string", tmp, sizeof(tmp));

			StatusPrinterWindowPrint(w, tmp);

			FreePack(p);
		}
	}

	StatusPrinterWindowStop(w);
}

// ドライバインストーラの起動 (Windows Vista 用)
void Win32CnExecDriverInstaller(SOCK *s, PACK *p)
{
	char arg[MAX_SIZE];
	bool ret;
	void *helper = NULL;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "arg", arg, sizeof(arg)) == false)
	{
		return;
	}

	if (MsIsVista())
	{
		helper = CmStartUacHelper();
	}

	ret = MsExecDriverInstaller(arg);

	CmStopUacHelper(helper);

	p = NewPack();
	PackAddBool(p, "ret", ret);
	SendPack(s, p);

	FreePack(p);
}

#endif	// OS_WIN32

// ドライバインストーラの起動
void CnExecDriverInstaller(SOCK *s, PACK *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnExecDriverInstaller(s, p);
#endif	// OS_WIN32
}

// 証明書確認ダイアログ
void CnCheckCert(SOCK *s, PACK *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnCheckCert(s, p);
#endif	// OS_WIN32
}

// NIC 情報ダイアログ
void CnNicInfo(SOCK *s, PACK *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnNicInfo(s, p);
#endif	// OS_WIN32
}

// メッセージ表示ダイアログ
void CnMsgDlg(SOCK *s, PACK *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnMsgDlg(s, p);
#endif	// OS_WIN32
}

// パスワード入力ダイアログ
void CnPasswordDlg(SOCK *s, PACK *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnPasswordDlg(s, p);
#endif	// OS_WIN32
}

// 接続エラーダイアログ
void CnConnectErrorDlg(SOCK *s, PACK *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnConnectErrorDlg(s, p);
#endif	// OS_WIN32
}

// ステータス表示器
void CnStatusPrinter(SOCK *s, PACK *p)
{
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnStatusPrinter(s, p);
#endif	// OS_WIN32
}

// クライアント通知サービスリスナースレッド
// このあたりは急いで実装したのでコードがあまり美しくない。
void CnListenerProc(THREAD *thread, void *param)
{
	TCP_ACCEPTED_PARAM *data = (TCP_ACCEPTED_PARAM *)param;
	SOCK *s;
	PACK *p;
	// 引数チェック
	if (data == NULL || thread == NULL)
	{
		return;
	}

	s = data->s;
	AddRef(s->ref);
	NoticeThreadInit(thread);

	if (s->LocalIP.addr[0] == 127)
	{
		p = RecvPack(s);

		if (p != NULL)
		{
			char function[MAX_SIZE];

			if (PackGetStr(p, "function", function, sizeof(function)))
			{
				if (StrCmpi(function, "status_printer") == 0)
				{
					CnStatusPrinter(s, p);
				}
				else if (StrCmpi(function, "connecterror_dialog") == 0)
				{
					CnConnectErrorDlg(s, p);
				}
				else if (StrCmpi(function, "msg_dialog") == 0)
				{
					CnMsgDlg(s, p);
				}
				else if (StrCmpi(function, "nicinfo") == 0)
				{
					CnNicInfo(s, p);
				}
				else if (StrCmpi(function, "password_dialog") == 0)
				{
					CnPasswordDlg(s, p);
				}
				else if (StrCmpi(function, "secure_sign") == 0)
				{
					CnSecureSign(s, p);
				}
				else if (StrCmpi(function, "check_cert") == 0)
				{
					CnCheckCert(s, p);
				}
				else if (StrCmpi(function, "exit") == 0)
				{
#ifdef	OS_WIN32
					MsTerminateProcess();
#else	// OS_WIN32
					_exit(0);
#endif	// OS_WIN32
				}
				else if (StrCmpi(function, "get_session_id") == 0)
				{
					PACK *p = NewPack();
#ifdef	OS_WIN32
					PackAddInt(p, "session_id", MsGetCurrentTerminalSessionId());
#endif	// OS_WIN32
					SendPack(s, p);
					FreePack(p);
				}
				else if (StrCmpi(function, "exec_driver_installer") == 0)
				{
					CnExecDriverInstaller(s, p);
				}
				else if (StrCmpi(function, "release_socket") == 0)
				{
					// リスナーを停止する
					CnReleaseSocket(s, p);
				}
			}

			FreePack(p);
		}
	}

	Disconnect(s);
	ReleaseSock(s);
}

// Secure Sign を行う
void CnSecureSign(SOCK *s, PACK *p)
{
	SECURE_SIGN sign;
	bool ret = false;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	Zero(&sign, sizeof(sign));
	InRpcSecureSign(&sign, p);

#ifdef	OS_WIN32
	// Win32: ダイアログを表示
	ret = Win32CiSecureSign(&sign);
#else	// OS_WIN32
	// UNIX: 未実装
	ret = false;
#endif	// OS_WIN32

	p = NewPack();

	OutRpcSecureSign(p, &sign);
	FreeRpcSecureSign(&sign);

	PackAddBool(p, "ret", ret);

	SendPack(s, p);
	FreePack(p);
}

// リスナーを停止する
void CnReleaseSocket(SOCK *s, PACK *p)
{
	UINT pid = 0;
	UINT current_pid = 0;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	pid = PackGetInt(p, "pid");

#ifdef	OS_WIN32
	current_pid = MsGetProcessId();
#endif	// OS_WIN32

	if (current_pid == pid)
	{
		return;
	}

	Lock(cn_listener_lock);
	{
		if (cn_listener != NULL)
		{
			if (cn_listener->Halt == false)
			{
				StopListener(cn_listener);

				cn_next_allow = Tick64() + (6 * 1000);
			}
		}
	}
	Unlock(cn_listener_lock);
}

// クライアント通知サービスの開始
void CnStart()
{
	CEDAR *cedar;
	LISTENER *o;
	UINT last_cursor_hash = 0;
	bool last_session_active = false;

	cn_next_allow = 0;
	cn_listener_lock = NewLock();

#ifdef	OS_WIN32
	MsSetShutdownParameters(0xff, 0x00000001);
	InitWinUi(_UU("CN_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));
#endif	// OS_WIN32

	cedar = NewCedar(NULL, NULL);

	if (CnCheckAlreadyExists(true))
	{
		// すでに起動している
		ReleaseCedar(cedar);
#ifdef	OS_WIN32
		FreeWinUi();
#endif	// OS_WIN32
		return;
	}

#ifdef	OS_WIN32
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY,
		"NotifyServerProcessId", MsGetProcessId());
#endif	// OS_WIN32

BEGIN_LISTENER:
	Lock(cn_listener_lock);
	cn_listener = o = NewListenerEx(cedar, LISTENER_TCP, CLIENT_NOTIFY_PORT, CnListenerProc, NULL);
	Unlock(cn_listener_lock);

	while (true)
	{
		UINT current_cursor_hash = 0;
		bool cursor_changed = false;

#ifdef	OS_WIN32
		// 現在のカーソル位置を取得
		current_cursor_hash = MsGetCursorPosHash();
#endif	// OS_WIN32

		if (last_cursor_hash != current_cursor_hash)
		{
			// カーソル位置をチェック
			cursor_changed = true;
			last_cursor_hash = current_cursor_hash;
		}

		Lock(cn_listener_lock);

		// リスナーが開始した後一定間隔で状態をチェックする
		if (cn_listener->Status == LISTENER_STATUS_TRYING || cn_listener->Halt)
		{
			bool session_active = false;
#ifdef	OS_WIN32
			session_active = MsIsCurrentTerminalSessionActive();
			if (cursor_changed)
			{
				// カーソル位置が変化してもターミナルセッションがアクティブでない
				// 場合は変化していないものと見なす
				if (session_active == false)
				{
					cursor_changed = false;
				}
			}
			if (last_session_active != session_active)
			{
				// カーソルが変化していなくてもターミナルセッション
				// 前回と比較してアクティブになった場合はカーソルが変化した
				// ものとみなす
				last_session_active = session_active;

				if (session_active)
				{
					cursor_changed = true;
				}
			}
#endif	// OS_WIN32

			// ポートが開けない場合
			if (cn_next_allow <= Tick64())
			{
				if (cursor_changed || cn_listener->Halt)
				{
					if (cursor_changed)
					{
						// マウスカーソルが移動しているので自分がポートを開く権利を持っている
						// と判断できる。
						// そこで、他のプロセスが持っているポートを強制的に奪う。
						CncReleaseSocket();
					}

					if (cn_listener->Halt)
					{
						ReleaseListener(cn_listener);
						cn_listener = NULL;

						Unlock(cn_listener_lock);
						goto BEGIN_LISTENER;
					}
				}
			}
		}

		Unlock(cn_listener_lock);

		SleepThread(1000);
	}
}

// バッファからアカウント情報を読み込む
RPC_CLIENT_CREATE_ACCOUNT *CiCfgToAccount(BUF *b)
{
	RPC_CLIENT_CREATE_ACCOUNT *t;
	FOLDER *f;
	ACCOUNT *a;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	f = CfgBufTextToFolder(b);
	if (f == NULL)
	{
		return NULL;
	}

	a = CiLoadClientAccount(f);

	CfgDeleteFolder(f);

	if (a == NULL)
	{
		return NULL;
	}

	DeleteLock(a->lock);

	t = ZeroMalloc(sizeof(RPC_CLIENT_CREATE_ACCOUNT));
	t->ClientOption = a->ClientOption;
	t->ClientAuth = a->ClientAuth;
	t->StartupAccount = a->StartupAccount;
	t->CheckServerCert = a->CheckServerCert;
	t->ServerCert = a->ServerCert;
	Free(a);

	return t;
}

// アカウント情報をバッファに書き出す
BUF *CiAccountToCfg(RPC_CLIENT_CREATE_ACCOUNT *t)
{
	BUF *b;
	FOLDER *root;
	ACCOUNT a;
	// 引数チェック
	if (t == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);
	Zero(&a, sizeof(a));
	a.ClientOption = t->ClientOption;
	a.ClientAuth = t->ClientAuth;
	a.CheckServerCert = t->CheckServerCert;
	a.ServerCert = t->ServerCert;
	a.StartupAccount = t->StartupAccount;

	CiWriteAccountData(root, &a);

	b = CfgFolderToBufEx(root, true, true);
	CfgDeleteFolder(root);

	return b;
}

// RPC ディスパッチルーチン
PACK *CiRpcDispatch(RPC *rpc, char *name, PACK *p)
{
	CLIENT *c = rpc->Param;
	PACK *ret;
	// 引数チェック
	if (rpc == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}

	ret = NewPack();

	if (StrCmpi(name, "GetClientVersion") == 0)
	{
		RPC_CLIENT_VERSION a;
		if (CtGetClientVersion(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientVersion(ret, &a);
		}
	}
	else if (StrCmpi(name, "GetCmSetting") == 0)
	{
		CM_SETTING a;
		if (CtGetCmSetting(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcCmSetting(ret, &a);
		}
	}
	else if (StrCmpi(name, "SetCmSetting") == 0)
	{
		CM_SETTING a;
		Zero(&a, sizeof(a));
		InRpcCmSetting(&a, p);
		if (CtSetCmSetting(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetPassword") == 0)
	{
		RPC_CLIENT_PASSWORD a;
		InRpcClientPassword(&a, p);
		if (CtSetPassword(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetPasswordSetting") == 0)
	{
		RPC_CLIENT_PASSWORD_SETTING a;
		if (CtGetPasswordSetting(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientPasswordSetting(ret, &a);
		}
	}
	else if (StrCmpi(name, "EnumCa") == 0)
	{
		RPC_CLIENT_ENUM_CA a;
		if (CtEnumCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumCa(ret, &a);
			CiFreeClientEnumCa(&a);
		}
	}
	else if (StrCmpi(name, "AddCa") == 0)
	{
		RPC_CERT a;
		InRpcCert(&a, p);
		if (CtAddCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		FreeX(a.x);
	}
	else if (StrCmpi(name, "DeleteCa") == 0)
	{
		RPC_CLIENT_DELETE_CA a;
		InRpcClientDeleteCa(&a, p);
		if (CtDeleteCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetCa") == 0)
	{
		RPC_GET_CA a;
		InRpcGetCa(&a, p);
		if (CtGetCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcGetCa(ret, &a);
		}
		CiFreeGetCa(&a);
	}
	else if (StrCmpi(name, "EnumSecure") == 0)
	{
		RPC_CLIENT_ENUM_SECURE a;
		if (CtEnumSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumSecure(ret, &a);
			CiFreeClientEnumSecure(&a);
		}
	}
	else if (StrCmpi(name, "UseSecure") == 0)
	{
		RPC_USE_SECURE a;
		InRpcUseSecure(&a, p);
		if (CtUseSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetUseSecure") == 0)
	{
		RPC_USE_SECURE a;
		Zero(&a, sizeof(a));
		if (CtGetUseSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcUseSecure(ret, &a);
		}
	}
	else if (StrCmpi(name, "EnumObjectInSecure") == 0)
	{
		RPC_ENUM_OBJECT_IN_SECURE a;
		if (CtEnumObjectInSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcEnumObjectInSecure(ret, &a);
			CiFreeEnumObjectInSecure(&a);
		}
	}
	else if (StrCmpi(name, "CreateVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtCreateVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "UpgradeVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtUpgradeVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetVLan") == 0)
	{
		RPC_CLIENT_GET_VLAN a;
		InRpcClientGetVLan(&a, p);
		if (CtGetVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientGetVLan(ret, &a);
		}
	}
	else if (StrCmpi(name, "SetVLan") == 0)
	{
		RPC_CLIENT_SET_VLAN a;
		InRpcClientSetVLan(&a, p);
		if (CtSetVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "EnumVLan") == 0)
	{
		RPC_CLIENT_ENUM_VLAN a;
		if (CtEnumVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumVLan(ret, &a);
			CiFreeClientEnumVLan(&a);
		}
	}
	else if (StrCmpi(name, "DeleteVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtDeleteVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "EnableVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtEnableVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "DisableVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtDisableVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "CreateAccount") == 0)
	{
		RPC_CLIENT_CREATE_ACCOUNT a;
		InRpcClientCreateAccount(&a, p);
		if (CtCreateAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		CiFreeClientCreateAccount(&a);
	}
	else if (StrCmpi(name, "EnumAccount") == 0)
	{
		RPC_CLIENT_ENUM_ACCOUNT a;
		if (CtEnumAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumAccount(ret, &a);
			CiFreeClientEnumAccount(&a);
		}
	}
	else if (StrCmpi(name, "DeleteAccount") == 0)
	{
		RPC_CLIENT_DELETE_ACCOUNT a;
		InRpcClientDeleteAccount(&a, p);
		if (CtDeleteAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetStartupAccount") == 0)
	{
		RPC_CLIENT_DELETE_ACCOUNT a;
		InRpcClientDeleteAccount(&a, p);
		if (CtSetStartupAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "RemoveStartupAccount") == 0)
	{
		RPC_CLIENT_DELETE_ACCOUNT a;
		InRpcClientDeleteAccount(&a, p);
		if (CtRemoveStartupAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetIssuer") == 0)
	{
		RPC_GET_ISSUER a;
		InRpcGetIssuer(&a, p);
		if (CtGetIssuer(c, &a))
		{
			OutRpcGetIssuer(ret, &a);
		}
		else
		{
			RpcError(ret, c->Err);
		}
		CiFreeGetIssuer(&a);
	}
	else if (StrCmpi(name, "SetAccount") == 0)
	{
		RPC_CLIENT_CREATE_ACCOUNT a;
		InRpcClientCreateAccount(&a, p);
		if (CtSetAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		CiFreeClientCreateAccount(&a);
	}
	else if (StrCmpi(name, "GetAccount") == 0)
	{
		RPC_CLIENT_GET_ACCOUNT a;
		InRpcClientGetAccount(&a, p);
		if (CtGetAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientGetAccount(ret, &a);
		}
		CiFreeClientGetAccount(&a);
	}
	else if (StrCmpi(name, "RenameAccount") == 0)
	{
		RPC_RENAME_ACCOUNT a;
		InRpcRenameAccount(&a, p);
		if (CtRenameAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetClientConfig") == 0)
	{
		CLIENT_CONFIG a;
		InRpcClientConfig(&a, p);
		if (CtSetClientConfig(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetClientConfig") == 0)
	{
		CLIENT_CONFIG a;
		if (CtGetClientConfig(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientConfig(ret, &a);
		}
	}
	else if (StrCmpi(name, "Connect") == 0)
	{
		RPC_CLIENT_CONNECT a;
		InRpcClientConnect(&a, p);
		if (CtConnect(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "Disconnect") == 0)
	{
		RPC_CLIENT_CONNECT a;
		InRpcClientConnect(&a, p);
		if (CtDisconnect(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetAccountStatus") == 0)
	{
		RPC_CLIENT_GET_CONNECTION_STATUS a;
		InRpcClientGetConnectionStatus(&a, p);
		if (CtGetAccountStatus(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientGetConnectionStatus(ret, &a);
		}
		CiFreeClientGetConnectionStatus(&a);
	}
	else
	{
		FreePack(ret);
		ret = NULL;
	}

	return ret;
}

// CM_SETTING の設定
UINT CcSetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a)
{
	PACK *ret, *p;
	UINT err;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCmSetting(p, a);

	ret = RpcCall(r->Rpc, "SetCmSetting", p);

	if (RpcIsOk(ret))
	{
		FreePack(ret);
		return 0;
	}
	else
	{
		err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// CM_SETTING の取得
UINT CcGetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a)
{
	PACK *ret;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetCmSetting", NULL);

	if (RpcIsOk(ret))
	{
		InRpcCmSetting(a, ret);
		FreePack(ret);
		return 0;
	}
	else
	{
		UINT err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// クライアントバージョンの取得
UINT CcGetClientVersion(REMOTE_CLIENT *r, RPC_CLIENT_VERSION *a)
{
	PACK *ret;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetClientVersion", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientVersion(a, ret);
		FreePack(ret);
		return 0;
	}
	else
	{
		UINT err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// パスワードの設定
UINT CcSetPassword(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD *pass)
{
	PACK *ret, *p;
	// 引数チェック
	if (r == NULL || pass == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();

	OutRpcClientPassword(p, pass);

	ret = RpcCall(r->Rpc, "SetPassword", p);

	if (RpcIsOk(ret))
	{
		FreePack(ret);
		return 0;
	}
	else
	{
		UINT err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// パスワード設定の取得
UINT CcGetPasswordSetting(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD_SETTING *a)
{
	PACK *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetPasswordSetting", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientPasswordSetting(a, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);
	return err;
}

// CA の列挙
UINT CcEnumCa(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_CA *e)
{
	PACK *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumCa", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientEnumCa(e, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// CA の追加
UINT CcAddCa(REMOTE_CLIENT *r, RPC_CERT *cert)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || cert == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCert(p, cert);

	ret = RpcCall(r->Rpc, "AddCa", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// CA の削除
UINT CcDeleteCa(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_CA *c)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteCa(p, c);

	ret = RpcCall(r->Rpc, "DeleteCa", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// 署名者の取得
UINT CcGetIssuer(REMOTE_CLIENT *r, RPC_GET_ISSUER *a)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcGetIssuer(p, a);

	ret = RpcCall(r->Rpc, "GetIssuer", p);

	if (RpcIsOk(ret))
	{
		if (a->x != NULL)
		{
			FreeX(a->x);
			a->x = NULL;
		}
		InRpcGetIssuer(a, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// CA の取得
UINT CcGetCa(REMOTE_CLIENT *r, RPC_GET_CA *get)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || get == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcGetCa(p, get);

	ret = RpcCall(r->Rpc, "GetCa", p);

	if (RpcIsOk(ret))
	{
		InRpcGetCa(get, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// セキュアデバイスの列挙
UINT CcEnumSecure(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_SECURE *e)
{
	PACK *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumSecure", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientEnumSecure(e, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// 使用しているセキュアデバイスの取得
UINT CcGetUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || sec == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();

	ret = RpcCall(r->Rpc, "GetUseSecure", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}
	else
	{
		InRpcUseSecure(sec, ret);
	}

	FreePack(ret);

	return err;
}

// セキュアデバイスの使用
UINT CcUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || sec == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcUseSecure(p, sec);

	ret = RpcCall(r->Rpc, "UseSecure", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// セキュアデバイス内のオブジェクトの列挙
UINT CcEnumObjectInSecure(REMOTE_CLIENT *r, RPC_ENUM_OBJECT_IN_SECURE *e)
{
	PACK *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumObjectInSecure", NULL);

	if (RpcIsOk(ret))
	{
		InRpcEnumObjectInSecure(e, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN の作成
UINT CcCreateVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create)
{
	PACK *ret, *p;
	UINT err = 0;
	char *s = NULL;
	// 引数チェック
	if (r == NULL || create == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, create);

#ifdef	OS_WIN32
	s = MsNoWarningSoundInit();
#endif	// OS_WIN32

	ret = RpcCall(r->Rpc, "CreateVLan", p);

#ifdef	OS_WIN32
	MsNoWarningSoundFree(s);
#endif	// OS_WIN32

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN のアップグレード
UINT CcUpgradeVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create)
{
	PACK *ret, *p;
	UINT err = 0;
	char *s = NULL;
	// 引数チェック
	if (r == NULL || create == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, create);

#ifdef	OS_WIN32
	s = MsNoWarningSoundInit();
#endif	// OS_WIN32

	ret = RpcCall(r->Rpc, "UpgradeVLan", p);

#ifdef	OS_WIN32
	MsNoWarningSoundFree(s);
#endif	// OS_WIN32


	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN の取得
UINT CcGetVLan(REMOTE_CLIENT *r, RPC_CLIENT_GET_VLAN *get)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || get == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientGetVLan(p, get);

	ret = RpcCall(r->Rpc, "GetVLan", p);

	if (RpcIsOk(ret))
	{
		InRpcClientGetVLan(get, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN の設定
UINT CcSetVLan(REMOTE_CLIENT *r, RPC_CLIENT_SET_VLAN *set)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || set == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientSetVLan(p, set);

	ret = RpcCall(r->Rpc, "SetVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN の列挙
UINT CcEnumVLan(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_VLAN *e)
{
	PACK *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumVLan", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientEnumVLan(e, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN の削除
UINT CcDeleteVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *d)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || d == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, d);

	ret = RpcCall(r->Rpc, "DeleteVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN の有効化
UINT CcEnableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || vlan == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, vlan);

	ret = RpcCall(r->Rpc, "EnableVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN の無効化
UINT CcDisableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || vlan == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, vlan);

	ret = RpcCall(r->Rpc, "DisableVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// アカウントの作成
UINT CcCreateAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientCreateAccount(p, a);

	ret = RpcCall(r->Rpc, "CreateAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// アカウントの列挙
UINT CcEnumAccount(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_ACCOUNT *e)
{
	PACK *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumAccount", NULL);

	if (RpcIsOk(ret))
	{
		UINT i;
		InRpcClientEnumAccount(e, ret);

		for (i = 0;i < e->NumItem;i++)
		{
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *t = e->Items[i];

			if (IsEmptyStr(t->HubName) && t->Port == 0)
			{
				UINT err2;
				RPC_CLIENT_GET_ACCOUNT a;

				// 古いバージョンの VPN Client では列挙時に HUB 名とポート番号
				// を取得できないので、別途取得する。
				Zero(&a, sizeof(a));
				UniStrCpy(a.AccountName, sizeof(a.AccountName), t->AccountName);
				err2 = CcGetAccount(r, &a);
				if (err2 == ERR_NO_ERROR)
				{
					StrCpy(t->HubName, sizeof(t->HubName), a.ClientOption->HubName);
					t->Port = a.ClientOption->Port;

					CiFreeClientGetAccount(&a);
				}
			}
		}
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// スタートアップを解除する
UINT CcRemoveStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteAccount(p, a);

	ret = RpcCall(r->Rpc, "RemoveStartupAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// スタートアップにする
UINT CcSetStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteAccount(p, a);

	ret = RpcCall(r->Rpc, "SetStartupAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// アカウントの削除
UINT CcDeleteAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteAccount(p, a);

	ret = RpcCall(r->Rpc, "DeleteAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// アカウントの設定
UINT CcSetAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientCreateAccount(p, a);

	ret = RpcCall(r->Rpc, "SetAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// アカウントの取得
UINT CcGetAccount(REMOTE_CLIENT *r, RPC_CLIENT_GET_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientGetAccount(p, a);

	ret = RpcCall(r->Rpc, "GetAccount", p);

	if (RpcIsOk(ret))
	{
		InRpcClientGetAccount(a, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// アカウント名の変更
UINT CcRenameAccount(REMOTE_CLIENT *r, RPC_RENAME_ACCOUNT *rename)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || rename == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcRenameAccount(p, rename);

	ret = RpcCall(r->Rpc, "RenameAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// クライアント設定の設定
UINT CcSetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o)
{
	PACK *p, *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || o == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientConfig(p, o);

	ret = RpcCall(r->Rpc, "SetClientConfig", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// クライアント設定の取得
UINT CcGetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o)
{
	PACK *ret;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || o == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetClientConfig", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientConfig(o, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// サービスをフォアグラウンドプロセスに設定する
void CcSetServiceToForegroundProcess(REMOTE_CLIENT *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return;
	}
	// 廃止
/*
	if (r->Rpc != NULL && r->Rpc->Sock != NULL && r->Rpc->Sock->RemoteIP.addr[0] == 127)
	{
		if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) &&
			GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			// Windows 2000 以降でのみこの操作は行う
			RPC_CLIENT_VERSION v;
			Zero(&v, sizeof(v));

			if (r->ClientBuildInt == 0)
			{
				CcGetClientVersion(r, &v);
				r->ClientBuildInt = v.ClientBuildInt;
				r->ProcessId = v.ProcessId;
			}
			if (r->ProcessId != 0 && r->ClientBuildInt <= 5080)
			{
#ifdef	OS_WIN32
				// サービスプロセスをフォアグラウンドウインドウに設定する
				AllowFGWindow(v.ProcessId);
#endif	// OS_WIN32
			}
		}
	}*/
}

// 接続
UINT CcConnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || connect == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	CcSetServiceToForegroundProcess(r);

	p = NewPack();
	OutRpcClientConnect(p, connect);

	ret = RpcCall(r->Rpc, "Connect", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// 切断
UINT CcDisconnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || connect == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	CcSetServiceToForegroundProcess(r);

	p = NewPack();
	OutRpcClientConnect(p, connect);

	ret = RpcCall(r->Rpc, "Disconnect", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// アカウント状況の取得
UINT CcGetAccountStatus(REMOTE_CLIENT *r, RPC_CLIENT_GET_CONNECTION_STATUS *st)
{
	PACK *ret, *p;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || st == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientGetConnectionStatus(p, st);

	ret = RpcCall(r->Rpc, "GetAccountStatus", p);

	if (RpcIsOk(ret))
	{
		InRpcClientGetConnectionStatus(st, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}


// クライアントサービスが接続マネージャに対して通知を送信する
void CiNotify(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// すべての通知イベントを起動する
	LockList(c->NotifyCancelList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->NotifyCancelList);i++)
		{
			CANCEL *cancel = LIST_DATA(c->NotifyCancelList, i);
			Cancel(cancel);
		}
	}
	UnlockList(c->NotifyCancelList);
}

// RPC_CLIENT_ENUM_ACCOUNT の解放
void CiFreeClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *a)
{
	UINT i;
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	for (i = 0;i < a->NumItem;i++)
	{
		RPC_CLIENT_ENUM_ACCOUNT_ITEM *e = a->Items[i];
		Free(e);
	}
	Free(a->Items);
}


// 一定時間ごとに設定ファイルを保存するスレッド
void CiSaverThread(THREAD *t, void *param)
{
	CLIENT *c = (CLIENT *)param;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	NoticeThreadInit(t);

	// 一定時間待つ
	while (c->Halt == false)
	{
		Wait(c->SaverHalter, CLIENT_SAVER_INTERVAL);

		// 保存
		CiSaveConfigurationFile(c);
	}
}

// 設定データ自動保存の初期化
void CiInitSaver(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->SaverHalter = NewEvent();

	c->SaverThread = NewThread(CiSaverThread, c);
	WaitThreadInit(c->SaverThread);
}

// 設定データ自動保存の解放
void CiFreeSaver(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->Halt = true;
	Set(c->SaverHalter);
	WaitThread(c->SaverThread, INFINITE);
	ReleaseThread(c->SaverThread);

	ReleaseEvent(c->SaverHalter);
}

// CM_SETTING
void InRpcCmSetting(CM_SETTING *c, PACK *p)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CM_SETTING));
	c->EasyMode = PackGetBool(p, "EasyMode");
	c->LockMode = PackGetBool(p, "LockMode");
	PackGetData2(p, "HashedPassword", c->HashedPassword, sizeof(c->HashedPassword));
}
void OutRpcCmSetting(PACK *p, CM_SETTING *c)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "EasyMode", c->EasyMode);
	PackAddBool(p, "LockMode", c->LockMode);
	PackAddData(p, "HashedPassword", c->HashedPassword, sizeof(c->HashedPassword));
}

// CLIENT_CONFIG
void InRpcClientConfig(CLIENT_CONFIG *c, PACK *p)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CLIENT_CONFIG));
	c->UseKeepConnect = PackGetInt(p, "UseKeepConnect") == 0 ? false : true;
	c->KeepConnectPort = PackGetInt(p, "KeepConnectPort");
	c->KeepConnectProtocol = PackGetInt(p, "KeepConnectProtocol");
	c->KeepConnectInterval = PackGetInt(p, "KeepConnectInterval");
	c->AllowRemoteConfig = PackGetInt(p, "AllowRemoteConfig") == 0 ? false : true;
	PackGetStr(p, "KeepConnectHost", c->KeepConnectHost, sizeof(c->KeepConnectHost));
}
void OutRpcClientConfig(PACK *p, CLIENT_CONFIG *c)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "UseKeepConnect", c->UseKeepConnect);
	PackAddInt(p, "KeepConnectPort", c->KeepConnectPort);
	PackAddInt(p, "KeepConnectProtocol", c->KeepConnectProtocol);
	PackAddInt(p, "KeepConnectInterval", c->KeepConnectInterval);
	PackAddInt(p, "AllowRemoteConfig", c->AllowRemoteConfig);
	PackAddStr(p, "KeepConnectHost", c->KeepConnectHost);
}

// RPC_CLIENT_VERSION
void InRpcClientVersion(RPC_CLIENT_VERSION *ver, PACK *p)
{
	// 引数チェック
	if (ver == NULL || p == NULL)
	{
		return;
	}

	Zero(ver, sizeof(RPC_CLIENT_VERSION));
	PackGetStr(p, "ClientProductName", ver->ClientProductName, sizeof(ver->ClientProductName));
	PackGetStr(p, "ClientVersionString", ver->ClientVersionString, sizeof(ver->ClientVersionString));
	PackGetStr(p, "ClientBuildInfoString", ver->ClientBuildInfoString, sizeof(ver->ClientBuildInfoString));
	ver->ClientVerInt = PackGetInt(p, "ClientVerInt");
	ver->ClientBuildInt = PackGetInt(p, "ClientBuildInt");
	ver->ProcessId = PackGetInt(p, "ProcessId");
	ver->OsType = PackGetInt(p, "OsType");
}
void OutRpcClientVersion(PACK *p, RPC_CLIENT_VERSION *ver)
{
	// 引数チェック
	if (ver == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ClientProductName", ver->ClientProductName);
	PackAddStr(p, "ClientVersionString", ver->ClientVersionString);
	PackAddStr(p, "ClientBuildInfoString", ver->ClientBuildInfoString);
	PackAddInt(p, "ClientVerInt", ver->ClientVerInt);
	PackAddInt(p, "ClientBuildInt", ver->ClientBuildInt);
	PackAddInt(p, "ProcessId", ver->ProcessId);
	PackAddInt(p, "OsType", ver->OsType);
}

// RPC_CLIENT_PASSWORD
void InRpcClientPassword(RPC_CLIENT_PASSWORD *pw, PACK *p)
{
	// 引数チェック
	if (pw == NULL || p == NULL)
	{
		return;
	}

	Zero(pw, sizeof(RPC_CLIENT_PASSWORD));
	PackGetStr(p, "Password", pw->Password, sizeof(pw->Password));
	pw->PasswordRemoteOnly = PackGetInt(p, "PasswordRemoteOnly");
}
void OutRpcClientPassword(PACK *p, RPC_CLIENT_PASSWORD *pw)
{
	// 引数チェック
	if (pw == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Password", pw->Password);
	PackAddInt(p, "PasswordRemoteOnly", pw->PasswordRemoteOnly);
}

// RPC_CLIENT_PASSWORD_SETTING
void InRpcClientPasswordSetting(RPC_CLIENT_PASSWORD_SETTING *a, PACK *p)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_CLIENT_PASSWORD_SETTING));

	a->IsPasswordPresented = PackGetInt(p, "IsPasswordPresented") == 0 ? false : true;
	a->PasswordRemoteOnly = PackGetInt(p, "PasswordRemoteOnly") == 0 ? false : true;
}
void OutRpcClientPasswordSetting(PACK *p, RPC_CLIENT_PASSWORD_SETTING *a)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "IsPasswordPresented", a->IsPasswordPresented);
	PackAddInt(p, "PasswordRemoteOnly", a->PasswordRemoteOnly);
}

// RPC_CLIENT_ENUM_CA
void InRpcClientEnumCa(RPC_CLIENT_ENUM_CA *e, PACK *p)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_CA));
	e->NumItem = PackGetNum(p, "NumItem");

	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM *) * e->NumItem);
	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_CA_ITEM *item = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM));
		e->Items[i] = item;

		item->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "SubjectName", item->SubjectName, sizeof(item->SubjectName), i);
		PackGetUniStrEx(p, "IssuerName", item->IssuerName, sizeof(item->IssuerName), i);
		item->Expires = PackGetInt64Ex(p, "Expires", i);
	}
}
void OutRpcClientEnumCa(PACK *p, RPC_CLIENT_ENUM_CA *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_CA_ITEM *item = e->Items[i];
		PackAddIntEx(p, "Key", item->Key, i, e->NumItem);
		PackAddUniStrEx(p, "SubjectName", item->SubjectName, i, e->NumItem);
		PackAddUniStrEx(p, "IssuerName", item->IssuerName, i, e->NumItem);
		PackAddInt64Ex(p, "Expires", item->Expires, i, e->NumItem);
	}
}

// RPC_GET_ISSUER
void InRpcGetIssuer(RPC_GET_ISSUER *c, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_GET_ISSUER));
	b = PackGetBuf(p, "x");
	if (b != NULL)
	{
		if (c->x != NULL)
		{
			FreeX(c->x);
		}
		c->x = BufToX(b, false);
		FreeBuf(b);
	}

	b = PackGetBuf(p, "issuer_x");
	if (b != NULL)
	{
		c->issuer_x = BufToX(b, false);
		FreeBuf(b);
	}
}
void OutRpcGetIssuer(PACK *p, RPC_GET_ISSUER *c)
{
	BUF *b;
	// 引数チェック
	if (p == NULL || c == NULL)
	{
		return;
	}

	if (c->x != NULL)
	{
		b = XToBuf(c->x, false);

		PackAddBuf(p, "x", b);
		FreeBuf(b);
	}

	if (c->issuer_x != NULL)
	{
		b = XToBuf(c->issuer_x, false);

		PackAddBuf(p, "issuer_x", b);
		FreeBuf(b);
	}
}

// TRAFFIC_EX
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(TRAFFIC));
	t->Recv.BroadcastBytes = PackGetInt64Ex(p, "Ex.Recv.BroadcastBytes", i);
	t->Recv.BroadcastCount = PackGetInt64Ex(p, "Ex.Recv.BroadcastCount", i);
	t->Recv.UnicastBytes = PackGetInt64Ex(p, "Ex.Recv.UnicastBytes", i);
	t->Recv.UnicastCount = PackGetInt64Ex(p, "Ex.Recv.UnicastCount", i);
	t->Send.BroadcastBytes = PackGetInt64Ex(p, "Ex.Send.BroadcastBytes", i);
	t->Send.BroadcastCount = PackGetInt64Ex(p, "Ex.Send.BroadcastCount", i);
	t->Send.UnicastBytes = PackGetInt64Ex(p, "Ex.Send.UnicastBytes", i);
	t->Send.UnicastCount = PackGetInt64Ex(p, "Ex.Send.UnicastCount", i);
}
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt64Ex(p, "Ex.Recv.BroadcastBytes", t->Recv.BroadcastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Recv.BroadcastCount", t->Recv.BroadcastCount, i, num);
	PackAddInt64Ex(p, "Ex.Recv.UnicastBytes", t->Recv.UnicastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Recv.UnicastCount", t->Recv.UnicastCount, i, num);
	PackAddInt64Ex(p, "Ex.Send.BroadcastBytes", t->Send.BroadcastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Send.BroadcastCount", t->Send.BroadcastCount, i, num);
	PackAddInt64Ex(p, "Ex.Send.UnicastBytes", t->Send.UnicastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Send.UnicastCount", t->Send.UnicastCount, i, num);
}

// TRAFFIC
void InRpcTraffic(TRAFFIC *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(TRAFFIC));
	t->Recv.BroadcastBytes = PackGetInt64(p, "Recv.BroadcastBytes");
	t->Recv.BroadcastCount = PackGetInt64(p, "Recv.BroadcastCount");
	t->Recv.UnicastBytes = PackGetInt64(p, "Recv.UnicastBytes");
	t->Recv.UnicastCount = PackGetInt64(p, "Recv.UnicastCount");
	t->Send.BroadcastBytes = PackGetInt64(p, "Send.BroadcastBytes");
	t->Send.BroadcastCount = PackGetInt64(p, "Send.BroadcastCount");
	t->Send.UnicastBytes = PackGetInt64(p, "Send.UnicastBytes");
	t->Send.UnicastCount = PackGetInt64(p, "Send.UnicastCount");
}
void OutRpcTraffic(PACK *p, TRAFFIC *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt64(p, "Recv.BroadcastBytes", t->Recv.BroadcastBytes);
	PackAddInt64(p, "Recv.BroadcastCount", t->Recv.BroadcastCount);
	PackAddInt64(p, "Recv.UnicastBytes", t->Recv.UnicastBytes);
	PackAddInt64(p, "Recv.UnicastCount", t->Recv.UnicastCount);
	PackAddInt64(p, "Send.BroadcastBytes", t->Send.BroadcastBytes);
	PackAddInt64(p, "Send.BroadcastCount", t->Send.BroadcastCount);
	PackAddInt64(p, "Send.UnicastBytes", t->Send.UnicastBytes);
	PackAddInt64(p, "Send.UnicastCount", t->Send.UnicastCount);
}

// RPC_CERT
void InRpcCert(RPC_CERT *c, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CERT));
	b = PackGetBuf(p, "x");
	if (b == NULL)
	{
		return;
	}

	c->x = BufToX(b, false);
	FreeBuf(b);
}
void OutRpcCert(PACK *p, RPC_CERT *c)
{
	BUF *b;
	// 引数チェック
	if (p == NULL || c == NULL)
	{
		return;
	}

	if (c->x != NULL)
	{
		b = XToBuf(c->x, false);

		PackAddBuf(p, "x", b);

		FreeBuf(b);
	}
}

// RPC_CLIENT_DELETE_CA
void InRpcClientDeleteCa(RPC_CLIENT_DELETE_CA *c, PACK *p)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_DELETE_CA));
	c->Key = PackGetInt(p, "Key");
}
void OutRpcClientDeleteCa(PACK *p, RPC_CLIENT_DELETE_CA *c)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Key", c->Key);
}

// RPC_GET_CA
void InRpcGetCa(RPC_GET_CA *c, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_GET_CA));

	c->Key = PackGetInt(p, "Key");

	b = PackGetBuf(p, "x");
	if (b != NULL)
	{
		c->x = BufToX(b, false);

		FreeBuf(b);
	}
}
void OutRpcGetCa(PACK *p, RPC_GET_CA *c)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Key", c->Key);

	if (c->x != NULL)
	{
		BUF *b = XToBuf(c->x, false);

		PackAddBuf(p, "x", b);

		FreeBuf(b);
	}
}

// RPC_CLIENT_ENUM_SECURE
void InRpcClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e, PACK *p)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_SECURE));

	e->NumItem = PackGetNum(p, "NumItem");
	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM *) * e->NumItem);
	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_SECURE_ITEM *item = e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM));

		item->DeviceId = PackGetIntEx(p, "DeviceId", i);
		item->Type = PackGetIntEx(p, "Type", i);
		PackGetStrEx(p, "DeviceName", item->DeviceName, sizeof(item->DeviceName), i);
		PackGetStrEx(p, "Manufacturer", item->Manufacturer, sizeof(item->Manufacturer), i);
	}
}
void OutRpcClientEnumSecure(PACK *p, RPC_CLIENT_ENUM_SECURE *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_SECURE_ITEM *item = e->Items[i];

		PackAddIntEx(p, "DeviceId", item->DeviceId, i, e->NumItem);
		PackAddIntEx(p, "Type", item->Type, i, e->NumItem);
		PackAddStrEx(p, "DeviceName", item->DeviceName, i, e->NumItem);
		PackAddStrEx(p, "Manufacturer", item->Manufacturer, i, e->NumItem);
	}
}

// RPC_USE_SECURE
void InRpcUseSecure(RPC_USE_SECURE *u, PACK *p)
{
	// 引数チェック
	if (u == NULL || p == NULL)
	{
		return;
	}

	Zero(u, sizeof(RPC_USE_SECURE));
	u->DeviceId = PackGetInt(p, "DeviceId");
}
void OutRpcUseSecure(PACK *p, RPC_USE_SECURE *u)
{
	// 引数チェック
	if (u == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "DeviceId", u->DeviceId);
}

// RPC_ENUM_OBJECT_IN_SECURE の解放
void CiFreeEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *a)
{
	UINT i;
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	for (i = 0;i < a->NumItem;i++)
	{
		Free(a->ItemName[i]);
	}
	Free(a->ItemName);
	Free(a->ItemType);
}

// RPC_ENUM_OBJECT_IN_SECURE
void InRpcEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *e, PACK *p)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	Zero(e, sizeof(RPC_ENUM_OBJECT_IN_SECURE));

	e->NumItem = PackGetNum(p, "NumItem");
	e->hWnd = PackGetInt(p, "hWnd");
	e->ItemName = ZeroMalloc(sizeof(char *) * e->NumItem);
	e->ItemType = ZeroMalloc(sizeof(bool) * e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		char name[MAX_SIZE];

		Zero(name, sizeof(name));
		PackGetStrEx(p, "ItemName", name, sizeof(name), i);
		e->ItemName[i] = CopyStr(name);

		e->ItemType[i] = PackGetIntEx(p, "ItemType", i) ? true : false;
	}
}
void OutRpcEnumObjectInSecure(PACK *p, RPC_ENUM_OBJECT_IN_SECURE *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);
	PackAddInt(p, "hWnd", e->hWnd);

	for (i = 0;i < e->NumItem;i++)
	{
		PackAddStrEx(p, "ItemName", e->ItemName[i], i, e->NumItem);
		PackAddIntEx(p, "ItemType", e->ItemType[i], i, e->NumItem);
	}
}

// RPC_CLIENT_CREATE_VLAN
void InRpcCreateVLan(RPC_CLIENT_CREATE_VLAN *v, PACK *p)
{
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_CREATE_VLAN));
	PackGetStr(p, "DeviceName", v->DeviceName, sizeof(v->DeviceName));
}
void OutRpcCreateVLan(PACK *p, RPC_CLIENT_CREATE_VLAN *v)
{
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", v->DeviceName);
}

// RPC_CLIENT_GET_VLAN
void InRpcClientGetVLan(RPC_CLIENT_GET_VLAN *v, PACK *p)
{
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_GET_VLAN));
	PackGetStr(p, "DeviceName", v->DeviceName, sizeof(v->DeviceName));
	v->Enabled = PackGetInt(p, "Enabled") ? true : false;
	PackGetStr(p, "MacAddress", v->MacAddress, sizeof(v->MacAddress));
	PackGetStr(p, "Version", v->Version, sizeof(v->Version));
	PackGetStr(p, "FileName", v->FileName, sizeof(v->FileName));
	PackGetStr(p, "Guid", v->Guid, sizeof(v->Guid));
}
void OutRpcClientGetVLan(PACK *p, RPC_CLIENT_GET_VLAN *v)
{
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", v->DeviceName);
	PackAddInt(p, "Enabled", v->Enabled);
	PackAddStr(p, "MacAddress", v->MacAddress);
	PackAddStr(p, "Version", v->Version);
	PackAddStr(p, "FileName", v->FileName);
	PackAddStr(p, "Guid", v->Guid);
}

// RPC_CLIENT_SET_VLAN
void InRpcClientSetVLan(RPC_CLIENT_SET_VLAN *v, PACK *p)
{
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_SET_VLAN));
	PackGetStr(p, "DeviceName", v->DeviceName, sizeof(v->DeviceName));
	PackGetStr(p, "MacAddress", v->MacAddress, sizeof(v->MacAddress));
}
void OutRpcClientSetVLan(PACK *p, RPC_CLIENT_SET_VLAN *v)
{
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", v->DeviceName);
	PackAddStr(p, "MacAddress", v->MacAddress);
}

// RPC_CLIENT_ENUM_VLAN
void InRpcClientEnumVLan(RPC_CLIENT_ENUM_VLAN *v, PACK *p)
{
	UINT i;
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_ENUM_VLAN));
	v->NumItem = PackGetNum(p, "NumItem");
	v->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM *) * v->NumItem);

	for (i = 0;i < v->NumItem;i++)
	{
		RPC_CLIENT_ENUM_VLAN_ITEM *item = v->Items[i] =
			ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM));

		PackGetStrEx(p, "DeviceName", item->DeviceName, sizeof(item->DeviceName), i);
		item->Enabled = PackGetIntEx(p, "Enabled", i) ? true : false;
		PackGetStrEx(p, "MacAddress", item->MacAddress, sizeof(item->MacAddress), i);
		PackGetStrEx(p, "Version", item->Version, sizeof(item->Version), i);
	}
}
void OutRpcClientEnumVLan(PACK *p, RPC_CLIENT_ENUM_VLAN *v)
{
	UINT i;
	// 引数チェック
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", v->NumItem);

	for (i = 0;i < v->NumItem;i++)
	{
		RPC_CLIENT_ENUM_VLAN_ITEM *item = v->Items[i];

		PackAddStrEx(p, "DeviceName", item->DeviceName, i, v->NumItem);
		PackAddIntEx(p, "Enabled", item->Enabled, i, v->NumItem);
		PackAddStrEx(p, "MacAddress", item->MacAddress, i, v->NumItem);
		PackAddStrEx(p, "Version", item->Version, i, v->NumItem);
	}
}

// CLIENT_OPTION
void InRpcClientOption(CLIENT_OPTION *c, PACK *p)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CLIENT_OPTION));

	PackGetUniStr(p, "AccountName", c->AccountName, sizeof(c->AccountName));
	PackGetStr(p, "Hostname", c->Hostname, sizeof(c->Hostname));
	c->Port = PackGetInt(p, "Port");
	c->PortUDP = PackGetInt(p, "PortUDP");
	c->ProxyType = PackGetInt(p, "ProxyType");
	c->ProxyPort = PackGetInt(p, "ProxyPort");
	c->NumRetry = PackGetInt(p, "NumRetry");
	c->RetryInterval = PackGetInt(p, "RetryInterval");
	c->MaxConnection = PackGetInt(p, "MaxConnection");
	c->AdditionalConnectionInterval = PackGetInt(p, "AdditionalConnectionInterval");
	c->ConnectionDisconnectSpan = PackGetInt(p, "ConnectionDisconnectSpan");
	c->HideStatusWindow = PackGetBool(p, "HideStatusWindow");
	c->HideNicInfoWindow = PackGetBool(p, "HideNicInfoWindow");
	c->DisableQoS = PackGetBool(p, "DisableQoS");
	PackGetStr(p, "ProxyName", c->ProxyName, sizeof(c->ProxyName));
	PackGetStr(p, "ProxyUsername", c->ProxyUsername, sizeof(c->ProxyUsername));
	PackGetStr(p, "ProxyPassword", c->ProxyPassword, sizeof(c->ProxyPassword));
	PackGetStr(p, "HubName", c->HubName, sizeof(c->HubName));
	PackGetStr(p, "DeviceName", c->DeviceName, sizeof(c->DeviceName));
	c->UseEncrypt = PackGetInt(p, "UseEncrypt") ? true : false;
	c->UseCompress = PackGetInt(p, "UseCompress") ? true : false;
	c->HalfConnection = PackGetInt(p, "HalfConnection") ? true : false;
	c->NoRoutingTracking = PackGetInt(p, "NoRoutingTracking") ? true : false;
	c->RequireMonitorMode = PackGetBool(p, "RequireMonitorMode");
	c->RequireBridgeRoutingMode = PackGetBool(p, "RequireBridgeRoutingMode");
	c->FromAdminPack = PackGetBool(p, "FromAdminPack");
	c->NoTls1 = PackGetBool(p, "NoTls1");
}
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);
	PackAddStr(p, "Hostname", c->Hostname);
	PackAddStr(p, "ProxyName", c->ProxyName);
	PackAddStr(p, "ProxyUsername", c->ProxyUsername);
	PackAddStr(p, "ProxyPassword", c->ProxyPassword);
	PackAddStr(p, "HubName", c->HubName);
	PackAddStr(p, "DeviceName", c->DeviceName);
	PackAddInt(p, "Port", c->Port);
	PackAddInt(p, "PortUDP", c->PortUDP);
	PackAddInt(p, "ProxyType", c->ProxyType);
	PackAddInt(p, "ProxyPort", c->ProxyPort);
	PackAddInt(p, "NumRetry", c->NumRetry);
	PackAddInt(p, "RetryInterval", c->RetryInterval);
	PackAddInt(p, "MaxConnection", c->MaxConnection);
	PackAddInt(p, "UseEncrypt", c->UseEncrypt);
	PackAddInt(p, "UseCompress", c->UseCompress);
	PackAddInt(p, "HalfConnection", c->HalfConnection);
	PackAddInt(p, "NoRoutingTracking", c->NoRoutingTracking);
	PackAddInt(p, "AdditionalConnectionInterval", c->AdditionalConnectionInterval);
	PackAddInt(p, "ConnectionDisconnectSpan", c->ConnectionDisconnectSpan);
	PackAddBool(p, "HideStatusWindow", c->HideStatusWindow);
	PackAddBool(p, "HideNicInfoWindow", c->HideNicInfoWindow);
	PackAddBool(p, "RequireMonitorMode", c->RequireMonitorMode);
	PackAddBool(p, "RequireBridgeRoutingMode", c->RequireBridgeRoutingMode);
	PackAddBool(p, "DisableQoS", c->DisableQoS);
	PackAddBool(p, "FromAdminPack", c->FromAdminPack);
	PackAddBool(p, "NoTls1", c->NoTls1);
}

// CLIENT_AUTH
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CLIENT_AUTH));
	c->AuthType = PackGetInt(p, "AuthType");
	PackGetStr(p, "Username", c->Username, sizeof(c->Username));

	switch (c->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		if (PackGetDataSize(p, "HashedPassword") == SHA1_SIZE)
		{
			PackGetData(p, "HashedPassword", c->HashedPassword);
		}
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackGetStr(p, "PlainPassword", c->PlainPassword, sizeof(c->PlainPassword));
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = PackGetBuf(p, "ClientX");
		if (b != NULL)
		{
			c->ClientX = BufToX(b, false);
			FreeBuf(b);
		}
		b = PackGetBuf(p, "ClientK");
		if (b != NULL)
		{
			c->ClientK = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_SECURE:
		PackGetStr(p, "SecurePublicCertName", c->SecurePublicCertName, sizeof(c->SecurePublicCertName));
		PackGetStr(p, "SecurePrivateKeyName", c->SecurePrivateKeyName, sizeof(c->SecurePrivateKeyName));
		break;
	}
}
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "AuthType", c->AuthType);
	PackAddStr(p, "Username", c->Username);

	switch (c->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedPassword", c->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackAddStr(p, "PlainPassword", c->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = XToBuf(c->ClientX, false);
		if (b != NULL)
		{
			PackAddBuf(p, "ClientX", b);
			FreeBuf(b);
		}
		b = KToBuf(c->ClientK, false, NULL);
		if (b != NULL)
		{
			PackAddBuf(p, "ClientK", b);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_SECURE:
		PackAddStr(p, "SecurePublicCertName", c->SecurePublicCertName);
		PackAddStr(p, "SecurePrivateKeyName", c->SecurePrivateKeyName);
		break;
	}
}

// RPC_CLIENT_CREATE_ACCOUNT
void InRpcClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *c, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_CREATE_ACCOUNT));
	c->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	c->ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));

	InRpcClientOption(c->ClientOption, p);
	InRpcClientAuth(c->ClientAuth, p);

	c->StartupAccount = PackGetInt(p, "StartupAccount") ? true : false;
	c->CheckServerCert = PackGetInt(p, "CheckServerCert") ? true : false;
	b = PackGetBuf(p, "ServerCert");
	if (b != NULL)
	{
		c->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}
	PackGetData2(p, "ShortcutKey", c->ShortcutKey, sizeof(c->ShortcutKey));
}
void OutRpcClientCreateAccount(PACK *p, RPC_CLIENT_CREATE_ACCOUNT *c)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	OutRpcClientOption(p, c->ClientOption);
	OutRpcClientAuth(p, c->ClientAuth);

	PackAddInt(p, "StartupAccount", c->StartupAccount);
	PackAddInt(p, "CheckServerCert", c->CheckServerCert);
	if (c->ServerCert != NULL)
	{
		b = XToBuf(c->ServerCert, false);
		if (b != NULL)
		{
			PackAddBuf(p, "ServerCert", b);
			FreeBuf(b);
		}
	}
	PackAddData(p, "ShortcutKey", c->ShortcutKey, sizeof(c->ShortcutKey));
}

// RPC_CLIENT_ENUM_ACCOUNT
void InRpcClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *e, PACK *p)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_ACCOUNT));

	e->NumItem = PackGetNum(p, "NumItem");
	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM *) * e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = e->Items[i] =
			ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM));

		PackGetUniStrEx(p, "AccountName", item->AccountName, sizeof(item->AccountName), i);
		PackGetStrEx(p, "UserName", item->UserName, sizeof(item->UserName), i);
		PackGetStrEx(p, "ServerName", item->ServerName, sizeof(item->ServerName), i);
		PackGetStrEx(p, "ProxyName", item->ProxyName, sizeof(item->ProxyName), i);
		PackGetStrEx(p, "DeviceName", item->DeviceName, sizeof(item->DeviceName), i);
		item->ProxyType = PackGetIntEx(p, "ProxyType", i);
		item->Active = PackGetIntEx(p, "Active", i) ? true : false;
		item->StartupAccount = PackGetIntEx(p, "StartupAccount", i) ? true : false;
		item->Connected = PackGetBoolEx(p, "Connected", i);
		item->Port = PackGetIntEx(p, "Port", i);
		PackGetStrEx(p, "HubName", item->HubName, sizeof(item->HubName), i);
		item->CreateDateTime = PackGetInt64Ex(p, "CreateDateTime", i);
		item->UpdateDateTime = PackGetInt64Ex(p, "UpdateDateTime", i);
		item->LastConnectDateTime = PackGetInt64Ex(p, "LastConnectDateTime", i);
	}
}
void OutRpcClientEnumAccount(PACK *p, RPC_CLIENT_ENUM_ACCOUNT *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = e->Items[i];

		PackAddUniStrEx(p, "AccountName", item->AccountName, i, e->NumItem);
		PackAddStrEx(p, "UserName", item->UserName, i, e->NumItem);
		PackAddStrEx(p, "ServerName", item->ServerName, i, e->NumItem);
		PackAddStrEx(p, "ProxyName", item->ProxyName, i, e->NumItem);
		PackAddStrEx(p, "DeviceName", item->DeviceName, i, e->NumItem);
		PackAddIntEx(p, "ProxyType", item->ProxyType, i, e->NumItem);
		PackAddIntEx(p, "Active", item->Active, i, e->NumItem);
		PackAddIntEx(p, "StartupAccount", item->StartupAccount, i, e->NumItem);
		PackAddBoolEx(p, "Connected", item->Connected, i, e->NumItem);
		PackAddIntEx(p, "Port", item->Port, i, e->NumItem);
		PackAddStrEx(p, "HubName", item->HubName, i, e->NumItem);
		PackAddInt64Ex(p, "CreateDateTime", item->CreateDateTime, i, e->NumItem);
		PackAddInt64Ex(p, "UpdateDateTime", item->UpdateDateTime, i, e->NumItem);
		PackAddInt64Ex(p, "LastConnectDateTime", item->LastConnectDateTime, i, e->NumItem);
	}
}

// RPC_CLIENT_DELETE_ACCOUNT
void InRpcClientDeleteAccount(RPC_CLIENT_DELETE_ACCOUNT *a, PACK *p)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_CLIENT_DELETE_ACCOUNT));
	PackGetUniStr(p, "AccountName", a->AccountName, sizeof(a->AccountName));
}
void OutRpcClientDeleteAccount(PACK *p, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", a->AccountName);
}

// RPC_RENAME_ACCOUNT
void InRpcRenameAccount(RPC_RENAME_ACCOUNT *a, PACK *p)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_RENAME_ACCOUNT));

	PackGetUniStr(p, "OldName", a->OldName, sizeof(a->OldName));
	PackGetUniStr(p, "NewName", a->NewName, sizeof(a->NewName));
}
void OutRpcRenameAccount(PACK *p, RPC_RENAME_ACCOUNT *a)
{
	// 引数チェック
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "OldName", a->OldName);
	PackAddUniStr(p, "NewName", a->NewName);
}

// RPC_CLIENT_GET_ACCOUNT
void InRpcClientGetAccount(RPC_CLIENT_GET_ACCOUNT *c, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_GET_ACCOUNT));

	c->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	c->ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));

	PackGetUniStr(p, "AccountName", c->AccountName, sizeof(c->AccountName));
	c->StartupAccount = PackGetInt(p, "StartupAccount") ? true : false;
	c->CheckServerCert = PackGetInt(p, "CheckServerCert") ? true : false;
	b = PackGetBuf(p, "ServerCert");
	if (b != NULL)
	{
		c->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}

	InRpcClientOption(c->ClientOption, p);
	InRpcClientAuth(c->ClientAuth, p);

	c->CreateDateTime = PackGetInt64(p, "CreateDateTime");
	c->UpdateDateTime = PackGetInt64(p, "UpdateDateTime");
	c->LastConnectDateTime = PackGetInt64(p, "LastConnectDateTime");

	PackGetData2(p, "ShortcutKey", c->ShortcutKey, SHA1_SIZE);
}
void OutRpcClientGetAccount(PACK *p, RPC_CLIENT_GET_ACCOUNT *c)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);
	PackAddInt(p, "StartupAccount", c->StartupAccount);
	PackAddInt(p, "CheckServerCert", c->CheckServerCert);

	if (c->ServerCert != NULL)
	{
		b = XToBuf(c->ServerCert, false);
		if (b != NULL)
		{
			PackAddBuf(p, "ServerCert", b);
			FreeBuf(b);
		}
	}

	OutRpcClientOption(p, c->ClientOption);
	OutRpcClientAuth(p, c->ClientAuth);

	PackAddData(p, "ShortcutKey", c->ShortcutKey, SHA1_SIZE);

	PackAddInt64(p, "CreateDateTime", c->CreateDateTime);
	PackAddInt64(p, "UpdateDateTime", c->UpdateDateTime);
	PackAddInt64(p, "LastConnectDateTime", c->LastConnectDateTime);
}

// RPC_CLIENT_CONNECT
void InRpcClientConnect(RPC_CLIENT_CONNECT *c, PACK *p)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_CONNECT));

	PackGetUniStr(p, "AccountName", c->AccountName, sizeof(c->AccountName));
}
void OutRpcClientConnect(PACK *p, RPC_CLIENT_CONNECT *c)
{
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);
}

// POLICY
void InRpcPolicy(POLICY *o, PACK *p)
{
	POLICY *pol;
	// 引数チェック
	if (o == NULL || p == NULL)
	{
		return;
	}

	pol = PackGetPolicy(p);
	Copy(o, pol, sizeof(POLICY));
	Free(pol);
}
void OutRpcPolicy(PACK *p, POLICY *o)
{
	// 引数チェック
	if (o == NULL || p == NULL)
	{
		return;
	}

	PackAddPolicy(p, o);
}

// RPC_CLIENT_GET_CONNECTION_STATUS
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p)
{
	BUF *b;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	Zero(s, sizeof(RPC_CLIENT_GET_CONNECTION_STATUS));

	PackGetUniStr(p, "AccountName", s->AccountName, sizeof(s->AccountName));

	PackGetStr(p, "ServerName", s->ServerName, sizeof(s->ServerName));
	PackGetStr(p, "ServerProductName", s->ServerProductName, sizeof(s->ServerProductName));
	PackGetStr(p, "CipherName", s->CipherName, sizeof(s->CipherName));
	PackGetStr(p, "SessionName", s->SessionName, sizeof(s->SessionName));
	PackGetStr(p, "ConnectionName", s->ConnectionName, sizeof(s->ConnectionName));

	if (PackGetDataSize(p, "SessionKey") == SHA1_SIZE)
	{
		PackGetData(p, "SessionKey", s->SessionKey);
	}

	s->SessionStatus = PackGetInt(p, "SessionStatus");
	s->ServerPort = PackGetInt(p, "ServerPort");
	s->ServerProductVer = PackGetInt(p, "ServerProductVer");
	s->ServerProductBuild = PackGetInt(p, "ServerProductBuild");
	s->NumConnectionsEatablished = PackGetInt(p, "NumConnectionsEatablished");
	s->MaxTcpConnections = PackGetInt(p, "MaxTcpConnections");
	s->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	s->NumTcpConnectionsUpload = PackGetInt(p, "NumTcpConnectionsUpload");
	s->NumTcpConnectionsDownload = PackGetInt(p, "NumTcpConnectionsDownload");

	s->StartTime = PackGetInt64(p, "StartTime");
	s->FirstConnectionEstablisiedTime = PackGetInt64(p, "FirstConnectionEstablisiedTime");
	s->CurrentConnectionEstablishTime = PackGetInt64(p, "CurrentConnectionEstablishTime");
	s->TotalSendSize = PackGetInt64(p, "TotalSendSize");
	s->TotalRecvSize = PackGetInt64(p, "TotalRecvSize");
	s->TotalSendSizeReal = PackGetInt64(p, "TotalSendSizeReal");
	s->TotalRecvSizeReal = PackGetInt64(p, "TotalRecvSizeReal");

	s->Active = PackGetInt(p, "Active") ? true : false;
	s->Connected = PackGetInt(p, "Connected") ? true : false;
	s->HalfConnection = PackGetInt(p, "HalfConnection") ? true : false;
	s->QoS = PackGetInt(p, "QoS") ? true : false;
	s->UseEncrypt = PackGetInt(p, "UseEncrypt") ? true : false;
	s->UseCompress = PackGetInt(p, "UseCompress") ? true : false;

	s->IsBridgeMode = PackGetBool(p, "IsBridgeMode");
	s->IsMonitorMode = PackGetBool(p, "IsMonitorMode");

	s->VLanId = PackGetInt(p, "VLanId");

	b = PackGetBuf(p, "ServerX");
	if (b != NULL)
	{
		s->ServerX = BufToX(b, false);
		FreeBuf(b);
	}

	b = PackGetBuf(p, "ClientX");
	if (b != NULL)
	{
		s->ClientX = BufToX(b, false);
		FreeBuf(b);
	}

	InRpcPolicy(&s->Policy, p);

	InRpcTraffic(&s->Traffic, p);
}
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c)
{
	BUF *b;
	// 引数チェック
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);

	PackAddStr(p, "ServerName", c->ServerName);
	PackAddStr(p, "ServerProductName", c->ServerProductName);
	PackAddStr(p, "CipherName", c->CipherName);
	PackAddStr(p, "SessionName", c->SessionName);
	PackAddStr(p, "ConnectionName", c->ConnectionName);

	PackAddData(p, "SessionKey", c->SessionKey, SHA1_SIZE);

	PackAddInt(p, "Active", c->Active);
	PackAddInt(p, "Connected", c->Connected);
	PackAddInt(p, "SessionStatus", c->SessionStatus);
	PackAddInt(p, "ServerPort", c->ServerPort);
	PackAddInt(p, "ServerProductVer", c->ServerProductVer);
	PackAddInt(p, "ServerProductBuild", c->ServerProductBuild);
	PackAddInt(p, "NumConnectionsEatablished", c->NumConnectionsEatablished);
	PackAddInt(p, "HalfConnection", c->HalfConnection);
	PackAddInt(p, "QoS", c->QoS);
	PackAddInt(p, "MaxTcpConnections", c->MaxTcpConnections);
	PackAddInt(p, "NumTcpConnections", c->NumTcpConnections);
	PackAddInt(p, "NumTcpConnectionsUpload", c->NumTcpConnectionsUpload);
	PackAddInt(p, "NumTcpConnectionsDownload", c->NumTcpConnectionsDownload);
	PackAddInt(p, "UseEncrypt", c->UseEncrypt);
	PackAddInt(p, "UseCompress", c->UseCompress);

	PackAddBool(p, "IsBridgeMode", c->IsBridgeMode);
	PackAddBool(p, "IsMonitorMode", c->IsMonitorMode);

	PackAddInt64(p, "StartTime", c->StartTime);
	PackAddInt64(p, "FirstConnectionEstablisiedTime", c->FirstConnectionEstablisiedTime);
	PackAddInt64(p, "CurrentConnectionEstablishTime", c->CurrentConnectionEstablishTime);
	PackAddInt64(p, "TotalSendSize", c->TotalSendSize);
	PackAddInt64(p, "TotalRecvSize", c->TotalRecvSize);
	PackAddInt64(p, "TotalSendSizeReal", c->TotalSendSizeReal);
	PackAddInt64(p, "TotalRecvSizeReal", c->TotalRecvSizeReal);

	PackAddInt(p, "VLanId", c->VLanId);

	OutRpcPolicy(p, &c->Policy);

	OutRpcTraffic(p, &c->Traffic);

	if (c->ServerX != NULL)
	{
		b = XToBuf(c->ServerX, false);
		PackAddBuf(p, "ServerX", b);
		FreeBuf(b);
	}

	if (c->ClientX != NULL)
	{
		b = XToBuf(c->ClientX, false);
		PackAddBuf(p, "ClientX", b);
		FreeBuf(b);
	}
}

void InRpcClientNotify(RPC_CLIENT_NOTIFY *n, PACK *p)
{
	// 引数チェック
	if (n == NULL || p == NULL)
	{
		return;
	}

	Zero(n, sizeof(RPC_CLIENT_NOTIFY));

	n->NotifyCode = PackGetInt(p, "NotifyCode");
}
void OutRpcClientNotify(PACK *p, RPC_CLIENT_NOTIFY *n)
{
	// 引数チェック
	if (n == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NotifyCode", n->NotifyCode);
}

// 通知メイン
void CiNotifyMain(CLIENT *c, SOCK *s)
{
	CANCEL *cancel;
	// 引数チェック
	if (c == NULL || s == NULL)
	{
		return;
	}

	// キャンセルを登録
	cancel = NewCancel();
	LockList(c->NotifyCancelList);
	{
		Add(c->NotifyCancelList, cancel);
	}
	UnlockList(c->NotifyCancelList);

	// 待機
	while (true)
	{
		char ch = '@';
		SOCKSET set;
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, INFINITE, cancel, NULL);

		if (c->Halt)
		{
			// 強制終了
			break;
		}

		// 1 バイト送信
		if (Send(s, &ch, 1, false) == 0)
		{
			// 切断された
			break;
		}
	}

	// 切断
	Disconnect(s);

	// キャンセルを登録解除
	LockList(c->NotifyCancelList);
	{
		Delete(c->NotifyCancelList, cancel);
	}
	UnlockList(c->NotifyCancelList);

	ReleaseCancel(cancel);
}

// RPC 受付コード
void CiRpcAccepted(CLIENT *c, SOCK *s)
{
	UCHAR hashed_password[SHA1_SIZE];
	UINT rpc_mode;
	UINT retcode;
	RPC *rpc;
	// 引数チェック
	if (c == NULL || s == NULL)
	{
		return;
	}

	// RPC モード受信
	if (RecvAll(s, &rpc_mode, sizeof(UINT), false) == false)
	{
		return;
	}

	rpc_mode = Endian32(rpc_mode);

	if (rpc_mode == CLIENT_RPC_MODE_NOTIFY)
	{
		// 通知モード
		CiNotifyMain(c, s);
		return;
	}
	else if (rpc_mode == CLIENT_RPC_MODE_SHORTCUT || rpc_mode == CLIENT_RPC_MODE_SHORTCUT_DISCONNECT)
	{
		// ショートカットキー受信
		UCHAR key[SHA1_SIZE];
		UINT err = ERR_NO_ERROR;
		if (RecvAll(s, key, SHA1_SIZE, false))
		{
			UINT i;
			wchar_t title[MAX_ACCOUNT_NAME_LEN + 1];
			bool ok = false;
			// 指定された接続設定に接続する
			LockList(c->AccountList);
			{
				for (i = 0;i < LIST_NUM(c->AccountList);i++)
				{
					ACCOUNT *a = LIST_DATA(c->AccountList, i);
					Lock(a->lock);
					{
						if (Cmp(a->ShortcutKey, key, SHA1_SIZE) == 0)
						{
							ok = true;
							UniStrCpy(title, sizeof(title), a->ClientOption->AccountName);
						}
					}
					Unlock(a->lock);
				}
			}
			UnlockList(c->AccountList);

			if (ok == false)
			{
				err = ERR_ACCOUNT_NOT_FOUND;
			}
			else
			{
				RPC_CLIENT_CONNECT t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), title);

				if (rpc_mode == CLIENT_RPC_MODE_SHORTCUT)
				{
					// 接続
					if (CtConnect(c, &t))
					{
						err = ERR_NO_ERROR;
					}
					else
					{
						err = c->Err;
					}
				}
				else
				{
					// 接続
					if (CtDisconnect(c, &t))
					{
						err = ERR_NO_ERROR;
					}
					else
					{
						err = c->Err;
					}
				}
			}

			err = Endian32(err);
			SendAll(s, &err, sizeof(UINT), false);
			RecvAll(s, &err, sizeof(UINT), false);
		}
		return;
	}

	// パスワード受信
	if (RecvAll(s, hashed_password, SHA1_SIZE, false) == false)
	{
		return;
	}

	retcode = 0;

	// パスワード比較
	if (Cmp(hashed_password, c->EncryptedPassword, SHA1_SIZE) != 0)
	{
		retcode = 1;
	}

	if (c->PasswordRemoteOnly && s->RemoteIP.addr[0] == 127)
	{
		// リモートのみパスワードを要求するモードで、ローカルから接続された場合は
		// パスワードを常に正しいと見なす
		retcode = 0;
	}

	Lock(c->lock);
	{
		if (c->Config.AllowRemoteConfig == false)
		{
			// リモート管理が禁止されている場合は
			// このコネクションが外部からのものであるかどうか識別する
			if (s->RemoteIP.addr[0] != 127)
			{
				retcode = 2;
			}
		}
	}
	Unlock(c->lock);

	retcode = Endian32(retcode);
	// エラーコード送信
	if (SendAll(s, &retcode, sizeof(UINT), false) == false)
	{
		return;
	}



	if (retcode != 0)
	{
		// エラーによる切断
		return;
	}

	// RPC サーバー作成
	rpc = StartRpcServer(s, CiRpcDispatch, c);

	// RPC サーバー動作
	RpcServer(rpc);

	// RPC サーバーの解放
	EndRpc(rpc);
}

// RPC 受付スレッド
void CiRpcAcceptThread(THREAD *thread, void *param)
{
	CLIENT_RPC_CONNECTION *conn;
	CLIENT *c;
	SOCK *s;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	conn = (CLIENT_RPC_CONNECTION *)param;
	s = conn->Sock;
	c = conn->Client;
	AddRef(s->ref);

	// RPC コネクションリストに追加
	LockList(c->RpcConnectionList);
	{
		Add(c->RpcConnectionList, conn);
	}
	UnlockList(c->RpcConnectionList);

	NoticeThreadInit(thread);

	// メイン処理
	CiRpcAccepted(c, s);

	// コネクションリストから解放
	LockList(c->RpcConnectionList);
	{
		Delete(c->RpcConnectionList, conn);
	}
	UnlockList(c->RpcConnectionList);

	ReleaseSock(conn->Sock);
	ReleaseThread(conn->Thread);
	Free(conn);

	Disconnect(s);
	ReleaseSock(s);
}

// RPC サーバースレッド
void CiRpcServerThread(THREAD *thread, void *param)
{
	CLIENT *c;
	SOCK *listener;
	UINT i;
	LIST *thread_list;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	c = (CLIENT *)param;

	// RPC コネクションリスト
	c->RpcConnectionList = NewList(NULL);

	// ポートを開く
	listener = NULL;
	for (i = CLIENT_CONFIG_PORT;i < (CLIENT_CONFIG_PORT + 5);i++)
	{
		listener = Listen(i);
		if (listener != NULL)
		{
			break;
		}
	}

	if (listener == NULL)
	{
		// エラー
		Alert("SoftEther UT-VPN Client RPC Port Open Failed.", CEDAR_CLIENT_STR);
		return;
	}

	c->RpcListener = listener;
	AddRef(listener->ref);

	NoticeThreadInit(thread);

	while (true)
	{
		// クライアント接続を待機
		CLIENT_RPC_CONNECTION *conn;
		SOCK *s = Accept(listener);
		if (s == NULL)
		{
			// 停止
			break;
		}

		// クライアント処理用スレッドを作成する
		conn = ZeroMalloc(sizeof(CLIENT_RPC_CONNECTION));
		conn->Client = c;
		conn->Sock = s;
		AddRef(s->ref);

		conn->Thread = NewThread(CiRpcAcceptThread, (void *)conn);
		WaitThreadInit(conn->Thread);

		ReleaseSock(s);
	}

	// リスナーを解放
	ReleaseSock(listener);

	thread_list = NewListFast(NULL);

	// すべての通知イベントを起動する
	LockList(c->NotifyCancelList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->NotifyCancelList);i++)
		{
			CANCEL *cancel = LIST_DATA(c->NotifyCancelList, i);
			Cancel(cancel);
		}
	}
	UnlockList(c->NotifyCancelList);

	// まだ接続しているすべてのコネクションを切断する
	LockList(c->RpcConnectionList);
	{
		for (i = 0;i < LIST_NUM(c->RpcConnectionList);i++)
		{
			CLIENT_RPC_CONNECTION *cc = LIST_DATA(c->RpcConnectionList, i);
			AddRef(cc->Thread->ref);
			Add(thread_list, cc->Thread);
			Disconnect(cc->Sock);
		}
	}
	UnlockList(c->RpcConnectionList);

	for (i = 0;i < LIST_NUM(thread_list);i++)
	{
		THREAD *t = LIST_DATA(thread_list, i);
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	ReleaseList(c->RpcConnectionList);
	ReleaseList(thread_list);
}

// Keep を開始
void CiInitKeep(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->Keep = StartKeep();

	// 設定の適用
	if (c->Config.UseKeepConnect)
	{
		KEEP *k = c->Keep;
		Lock(k->lock);
		{
			StrCpy(k->ServerName, sizeof(k->ServerName), c->Config.KeepConnectHost);
			k->ServerPort = c->Config.KeepConnectPort;
			k->Interval = c->Config.KeepConnectInterval * 1000;
			k->UdpMode = (c->Config.KeepConnectProtocol == CONNECTION_UDP) ? true : false;
			k->Enable = true;
		}
		Unlock(k->lock);
	}
}

// Keep を停止
void CiFreeKeep(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	StopKeep(c->Keep);
	c->Keep = NULL;
}

// RPC を開始
void CiStartRpcServer(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->RpcThread = NewThread(CiRpcServerThread, (void *)c);
	WaitThreadInit(c->RpcThread);
}

// RPC を終了
void CiStopRpcServer(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	Disconnect(c->RpcListener);
	ReleaseSock(c->RpcListener);

	WaitThread(c->RpcThread, INFINITE);
	ReleaseThread(c->RpcThread);
}

// 次の通知を待機する
bool CcWaitNotify(NOTIFY_CLIENT *n)
{
	UCHAR c;
	// 引数チェック
	if (n == NULL)
	{
		return false;
	}

	// 1 文字受信する
	if (RecvAll(n->Sock, &c, 1, false) == false)
	{
		// 切断された
		return false;
	}

	return true;
}

// 通知クライアントとして接続する
NOTIFY_CLIENT *CcConnectNotify(REMOTE_CLIENT *rc)
{
	NOTIFY_CLIENT *n;
	SOCK *s;
	char tmp[MAX_SIZE];
	bool rpc_mode = false;
	UINT port;
	// 引数チェック
	if (rc == NULL || rc->Rpc == NULL || rc->Rpc->Sock == NULL)
	{
		return NULL;
	}

	// 接続
	IPToStr(tmp, sizeof(tmp), &rc->Rpc->Sock->RemoteIP);
	port = rc->Rpc->Sock->RemotePort;

	s = Connect(tmp, port);
	if (s == NULL)
	{
		return NULL;
	}

	rpc_mode = Endian32(rpc_mode);
	if (SendAll(s, &rpc_mode, sizeof(rpc_mode), false) == false)
	{
		ReleaseSock(s);
		return NULL;
	}

	n = ZeroMalloc(sizeof(NOTIFY_CLIENT));
	n->Sock = s;

	return n;
}

// 通知クライアントを停止する
void CcStopNotify(NOTIFY_CLIENT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	Disconnect(n->Sock);
}

// 通知クライアントを削除する
void CcDisconnectNotify(NOTIFY_CLIENT *n)
{
	// 引数チェック
	if (n == NULL)
	{
		return;
	}

	// 切断
	Disconnect(n->Sock);
	ReleaseSock(n->Sock);

	// メモリ解放
	Free(n);
}

// リモート接続を切断する
void CcDisconnectRpc(REMOTE_CLIENT *rc)
{
	// 引数チェック
	if (rc == NULL)
	{
		return;
	}

	RpcFree(rc->Rpc);
	Free(rc);
}

// クライアントに接続しショートカット接続設定を起動する
UINT CcShortcut(UCHAR *key)
{
	UINT ret;
	// 引数チェック
	if (key == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CcConnectRpcEx("localhost", NULL, NULL, NULL, key, &ret, false, 0);

	return ret;
}

// 接続中のショートカット接続を切断する
UINT CcShortcutDisconnect(UCHAR *key)
{
	UINT ret;
	// 引数チェック
	if (key == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CcConnectRpcEx("localhost", NULL, NULL, NULL, key, &ret, true, 0);

	return ret;
}

// クライアントにリモート接続する
REMOTE_CLIENT *CcConnectRpc(char *server_name, char *password, bool *bad_pass, bool *no_remote, UINT wait_retry)
{
	return CcConnectRpcEx(server_name, password, bad_pass, no_remote, NULL, NULL, false, wait_retry);
}
REMOTE_CLIENT *CcConnectRpcEx(char *server_name, char *password, bool *bad_pass, bool *no_remote, UCHAR *key, UINT *key_error_code, bool shortcut_disconnect, UINT wait_retry)
{
	SOCK *s;
	UINT i;
	UINT retcode;
	UINT rpc_mode = CLIENT_RPC_MODE_MANAGEMENT;
	RPC *rpc;
	REMOTE_CLIENT *ret;
	UCHAR hash_password[SHA1_SIZE];
	UINT port_start;
	UINT64 try_started = 0;
	bool ok;
	// 引数チェック
	if (server_name == NULL)
	{
		return NULL;
	}
	if (password == NULL)
	{
		password = "";
	}

	if (key_error_code != NULL)
	{
		*key_error_code = ERR_NO_ERROR;
	}

	if (bad_pass != NULL)
	{
		*bad_pass = false;
	}

	if (no_remote != NULL)
	{
		*no_remote = false;
	}

	port_start = CLIENT_CONFIG_PORT - 1;

RETRY:
	port_start++;

	if (port_start >= (CLIENT_CONFIG_PORT + 5))
	{
		return NULL;
	}

	ok = false;

	while (true)
	{
		for (i = port_start;i < (CLIENT_CONFIG_PORT + 5);i++)
		{
			if (CheckTCPPort(server_name, i))
			{
				ok = true;
				break;
			}
		}

		if (ok)
		{
			break;
		}

		if (wait_retry == 0)
		{
			break;
		}

		if (try_started == 0)
		{
			try_started = Tick64();
		}

		if ((try_started + (UINT64)wait_retry) <= Tick64())
		{
			break;
		}
	}

	if (ok == false)
	{
		if (key_error_code)
		{
			*key_error_code = ERR_CONNECT_FAILED;
		}
		return NULL;
	}

	port_start = i;

	s = Connect(server_name, i);
	if (s == NULL)
	{
		if (key_error_code)
		{
			*key_error_code = ERR_CONNECT_FAILED;
		}
		goto RETRY;
	}

	Hash(hash_password, password, StrLen(password), true);

	if (key != NULL)
	{
		if (shortcut_disconnect == false)
		{
			rpc_mode = CLIENT_RPC_MODE_SHORTCUT;
		}
		else
		{
			rpc_mode = CLIENT_RPC_MODE_SHORTCUT_DISCONNECT;
		}
	}

	rpc_mode = Endian32(rpc_mode);
	SendAdd(s, &rpc_mode, sizeof(UINT));

	if (key != NULL)
	{
		SendAdd(s, key, SHA1_SIZE);
	}
	else
	{
		SendAdd(s, hash_password, SHA1_SIZE);
	}

	if (SendNow(s, false) == false)
	{
		ReleaseSock(s);
		goto RETRY;
	}

	if (RecvAll(s, &retcode, sizeof(UINT), false) == false)
	{
		ReleaseSock(s);
		goto RETRY;
	}

	retcode = Endian32(retcode);

	if (retcode >= 1024)
	{
		goto RETRY;
	}

	if (key != NULL)
	{
		if (key_error_code)
		{
			*key_error_code = retcode;
		}
		SendAll(s, &retcode, sizeof(UINT), false);
		ReleaseSock(s);
		return NULL;
	}

	switch (retcode)
	{
	case 1:
		if (bad_pass != NULL)
		{
			*bad_pass = true;
		}
		break;
	case 2:
		if (no_remote != NULL)
		{
			*no_remote = true;
		}
		break;
	}

	if (retcode != 0)
	{
		ReleaseSock(s);
		return NULL;
	}

	rpc = StartRpcClient(s, NULL);

	ReleaseSock(s);

	ret = ZeroMalloc(sizeof(REMOTE_CLIENT));
	ret->Rpc = rpc;
	rpc->Param = ret;

	if (ret != NULL)
	{
		RPC_CLIENT_VERSION t;
		Zero(&t, sizeof(t));
		CcGetClientVersion(ret, &t);
		ret->OsType = t.OsType;
		ret->Unix = OS_IS_UNIX(ret->OsType);
		ret->Win9x = OS_IS_WINDOWS_9X(ret->OsType);
	}

	return ret;
}

// セッションから RPC_CLIENT_GET_CONNECTION_STATUS を取得
void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s)
{
	// 引数チェック
	if (st == NULL || s == NULL)
	{
		return;
	}

	Lock(s->lock);
	{
		// 動作フラグ
		st->Active = true;

		// セッションステータス
		st->SessionStatus = s->ClientStatus;

		// アカウント名
		UniStrCpy(st->AccountName, sizeof(st->AccountName), s->ClientOption->AccountName);

		if (s->ClientStatus == CLIENT_STATUS_ESTABLISHED && s->Connection != NULL)
		{
			Lock(s->Connection->lock);
			{
				// 接続済みフラグ
				st->Connected = true;
				// 製品名
				StrCpy(st->ServerProductName, sizeof(st->ServerProductName), s->Connection->ServerStr);
				// バージョン
				st->ServerProductVer = s->Connection->ServerVer;
				// ビルド番号
				st->ServerProductBuild = s->Connection->ServerBuild;
				// サーバー証明書
				st->ServerX = CloneX(s->Connection->ServerX);
				// クライアント証明書
				st->ClientX = CloneX(s->Connection->ClientX);
				// このコネクションの接続完了時刻
				st->CurrentConnectionEstablishTime = TickToTime(s->CurrentConnectionEstablishTime);
				// 最大の TCP コネクション数
				st->MaxTcpConnections = s->MaxConnection;
				// ハーフコネクション
				st->HalfConnection = s->HalfConnection;
				// VLAN
				st->VLanId = s->VLanId;
				// VoIP / QoS
				st->QoS = s->QoS;
				if (s->Connection->Protocol == CONNECTION_TCP)
				{
					UINT i;
					// 現在の TCP コネクション数
					LockList(s->Connection->Tcp->TcpSockList);
					{
						st->NumTcpConnections = LIST_NUM(s->Connection->Tcp->TcpSockList);
						if (st->HalfConnection)
						{
							for (i = 0;i < st->NumTcpConnections;i++)
							{
								TCPSOCK *ts = LIST_DATA(s->Connection->Tcp->TcpSockList, i);
								if (ts->Direction & TCP_SERVER_TO_CLIENT)
								{
									st->NumTcpConnectionsDownload++;
								}
								else
								{
									st->NumTcpConnectionsUpload++;
								}
							}
						}
					}
					UnlockList(s->Connection->Tcp->TcpSockList);
				}
				// 暗号化の使用
				st->UseEncrypt = s->UseEncrypt;
				if (st->UseEncrypt)
				{
					StrCpy(st->CipherName, sizeof(st->CipherName), s->Connection->CipherName);
				}
				// 圧縮の使用
				st->UseCompress = s->UseCompress;
				// セッションキー
				Copy(st->SessionKey, s->SessionKey, SHA1_SIZE);
				// ポリシー
				Copy(&st->Policy, s->Policy, sizeof(POLICY));
				// データサイズ
				if (s->ServerMode == false)
				{
					st->TotalSendSize = s->TotalSendSize;
					st->TotalRecvSize = s->TotalRecvSize;
					st->TotalRecvSizeReal = s->TotalRecvSizeReal;
					st->TotalSendSizeReal = s->TotalSendSizeReal;
				}
				else
				{
					st->TotalSendSize = s->TotalRecvSize;
					st->TotalRecvSize = s->TotalSendSize;
					st->TotalRecvSizeReal = s->TotalSendSizeReal;
					st->TotalSendSizeReal = s->TotalRecvSizeReal;
				}
				// セッション名
				StrCpy(st->SessionName, sizeof(st->SessionName), s->Name);
				// コネクション名
				StrCpy(st->ConnectionName, sizeof(st->ConnectionName), s->Connection->Name);
				// サーバー名
				StrCpy(st->ServerName, sizeof(st->ServerName), s->Connection->ServerName);
				// ポート番号
				st->ServerPort = s->Connection->ServerPort;
				// トラフィックデータ
				Lock(s->TrafficLock);
				{
					Copy(&st->Traffic, s->Traffic, sizeof(TRAFFIC));
				}
				Unlock(s->TrafficLock);

				st->IsBridgeMode = s->IsBridgeMode;
				st->IsMonitorMode = s->IsMonitorMode;
			}
			Unlock(s->Connection->lock);
		}
		// 接続開始時刻
		st->StartTime = TickToTime(s->CreatedTime);
		// 最初のコネクションの接続完了時刻
		st->FirstConnectionEstablisiedTime = TickToTime(s->FirstConnectionEstablisiedTime);
		// これまでに確立したコネクション数
		st->NumConnectionsEatablished = s->NumConnectionsEatablished;
	}
	Unlock(s->lock);
}

// 接続ステータスの取得
bool CtGetAccountStatus(CLIENT *c, RPC_CLIENT_GET_CONNECTION_STATUS *st)
{
	// 引数チェック
	if (c == NULL || st == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;

		// アカウントを検索
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), st->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			Zero(st, sizeof(RPC_CLIENT_GET_CONNECTION_STATUS));
			if (r->ClientSession != NULL)
			{
				SESSION *s = r->ClientSession;
				CiGetSessionStatus(st, s);
			}
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	return true;
}

// 接続ステータスの解放
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st)
{
	// 引数チェック
	if (st == NULL)
	{
		return;
	}

	if (st->ServerX != NULL)
	{
		FreeX(st->ServerX);
	}

	if (st->ClientX != NULL)
	{
		FreeX(st->ClientX);
	}
}

// サーバー証明書の確認プロシージャ
bool CiCheckCertProc(SESSION *s, CONNECTION *c, X *server_x, bool *expired)
{
#ifdef	OS_WIN32
	ACCOUNT *a;
	X *old_x = NULL;
	UI_CHECKCERT dlg;
	// 引数チェック
	if (s == NULL || c == NULL || server_x == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	Zero(&dlg, sizeof(dlg));

	a = s->Account;
	if (a == NULL)
	{
		return false;
	}

	Lock(a->lock);
	{
		if (a->CheckServerCert == false)
		{
			// サーバー証明書を検証しない
			Unlock(a->lock);
			return true;
		}

		if (a->ServerCert != NULL)
		{
			old_x = CloneX(a->ServerCert);
		}
	}
	Unlock(a->lock);

	if (CheckXDateNow(server_x) == false)
	{
		// 有効期限が切れている
		if (old_x != NULL)
		{
			FreeX(old_x);
		}

		if (expired != NULL)
		{
			*expired = true;
		}

		return false;
	}

	if (old_x != NULL)
	{
		if (CompareX(old_x, server_x))
		{
			// すでに登録されている証明書と完全一致した
			if (old_x != NULL)
			{
				FreeX(old_x);
			}
			return true;
		}
		else
		{
			dlg.DiffWarning = true;
		}
	}

	// この証明書は信頼できないのでダイアログボックスを出して確認する
	UniStrCpy(dlg.AccountName, sizeof(dlg.AccountName), a->ClientOption->AccountName);
	StrCpy(dlg.ServerName, sizeof(dlg.ServerName), a->ClientOption->Hostname);
	dlg.x = server_x;
	dlg.old_x = old_x;
	
	dlg.Session = s;
	AddRef(s->ref);

	CncCheckCert(s, &dlg);

	ReleaseSession(s);

	if (old_x != NULL)
	{
		FreeX(old_x);
	}

	if (dlg.Ok && dlg.SaveServerCert)
	{
		// このサーバー証明書を保存し次回から信頼する
		Lock(a->lock);
		{
			if (a->ServerCert != NULL)
			{
				FreeX(a->ServerCert);
			}

			a->ServerCert = CloneX(server_x);
		}
		Unlock(a->lock);
		CiSaveConfigurationFile(s->Cedar->Client);
	}

	return dlg.Ok;
#else	// OS_WIN32
	ACCOUNT *a;
	X *old_x = NULL;
	// 引数チェック
	if (s == NULL || c == NULL || server_x == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	a = s->Account;
	if (a == NULL)
	{
		return false;
	}

	Lock(a->lock);
	{
		if (a->CheckServerCert == false)
		{
			// サーバー証明書を検証しない
			Unlock(a->lock);
			return true;
		}

		if (a->ServerCert != NULL)
		{
			old_x = CloneX(a->ServerCert);
		}
	}
	Unlock(a->lock);

	if (CheckXDateNow(server_x) == false)
	{
		// 有効期限が切れている
		if (old_x != NULL)
		{
			FreeX(old_x);
		}

		if (expired != NULL)
		{
			*expired = true;
		}

		return false;
	}

	if (old_x != NULL)
	{
		if (CompareX(old_x, server_x))
		{
			// すでに登録されている証明書と完全一致した
			if (old_x != NULL)
			{
				FreeX(old_x);
			}
			return true;
		}
		else
		{
			// 不一致
			if (old_x != NULL)
			{
				FreeX(old_x);
			}
			return false;
		}
	}

	if (old_x != NULL)
	{
		FreeX(old_x);
	}

	return false;
#endif	// OS_WIN32
}

// セキュアデバイスを使用した署名プロシージャ
bool CiSecureSignProc(SESSION *s, CONNECTION *c, SECURE_SIGN *sign)
{
	// Win32 の場合は UI を使用することができる
	return CncSecureSignDlg(sign);
}

#ifdef	OS_WIN32
// 署名プロシージャ (Win32 用)
bool Win32CiSecureSign(SECURE_SIGN *sign)
{
	bool ret = false;
	BUF *random;
	// 引数チェック
	if (sign == NULL)
	{
		return false;
	}

	random = NewBuf();
	WriteBuf(random, sign->Random, SHA1_SIZE);

	// バッチ処理
	{
		WINUI_SECURE_BATCH batch[] =
		{
			{WINUI_SECURE_READ_CERT, sign->SecurePublicCertName, true, NULL, NULL, NULL, NULL, NULL, NULL},
			{WINUI_SECURE_SIGN_WITH_KEY, sign->SecurePrivateKeyName, true, random, NULL, NULL, NULL, NULL, NULL}
		};

		if (SecureDeviceWindow(NULL, batch, sizeof(batch) / sizeof(batch[0]),
			sign->UseSecureDeviceId, sign->BitmapId) == false)
		{
			// 失敗
			if (batch[0].OutputX != 0)
			{
				FreeX(batch[0].OutputX);
			}
			ret = false;
		}
		else
		{
			// 成功
			ret = true;
			sign->ClientCert = batch[0].OutputX;
			Copy(sign->Signature, batch[1].OutputSign, 128);
		}
	}

	FreeBuf(random);

	return ret;
}
#endif	// OS_WIN32

// 切断
bool CtDisconnect(CLIENT *c, RPC_CLIENT_CONNECT *connect)
{
	bool ret = false;
	ACCOUNT t, *r;
	SESSION *s = NULL;
	// 引数チェック
	if (c == NULL || connect == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{

		// アカウントを検索
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), connect->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			if (r->ClientSession == NULL)
			{
				// 接続していない
				CiSetError(c, ERR_ACCOUNT_INACTIVE);
			}
			else
			{
				s = r->ClientSession;
				AddRef(s->ref);
				// 切断完了
				r->ClientSession = NULL;
				ret = true;
			}
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	if (s != NULL)
	{
		// 接続を切断 (切断完了まで待機)
		CLog(c, "LC_DISCONNECT", connect->AccountName);
		StopSession(s);
		ReleaseSession(s);
	}

	if (ret != false)
	{
		CiNotify(c);
	}

	return ret;
}

// 接続
bool CtConnect(CLIENT *c, RPC_CLIENT_CONNECT *connect)
{
	bool ret = false;
	RPC_CLIENT_ENUM_VLAN t;
	// 引数チェック
	if (c == NULL || connect == NULL)
	{
		return false;
	}

	Lock(c->lockForConnect);
	{
		Zero(&t, sizeof(t));
		if (CtEnumVLan(c, &t))
		{
			if (t.NumItem == 0)
			{
				// システムに仮想 LAN カードが 1 枚も無い
				if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) || OS_IS_UNIX(GetOsInfo()->OsType))
				{
					// Windows NT 系または Linux 系の場合のみ、自動的に "VPN" という名前の
					// 新しい仮想 LAN カードを作成する
					RPC_CLIENT_CREATE_VLAN t;

					Zero(&t, sizeof(t));
					StrCpy(t.DeviceName, sizeof(t.DeviceName), "VPN");
					CtCreateVLan(c,  &t);
				}
			}

			CiFreeClientEnumVLan(&t);
		}
	}
	Unlock(c->lockForConnect);

	CiNormalizeAccountVLan(c);

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		bool unix_disabled = false;

		// アカウントを検索
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), connect->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

#ifndef	OS_WIN32
		// 仮想 LAN カードを検索する
		LockList(c->UnixVLanList);
		{
			UNIX_VLAN *v, t;

			Zero(&t, sizeof(t));
			StrCpy(t.Name, sizeof(t.Name), r->ClientOption->DeviceName);

			v = Search(c->UnixVLanList, &t);
			if (v == NULL)
			{
				UnlockList(c->UnixVLanList);
				CiSetError(c, ERR_OBJECT_NOT_FOUND);
				return false;
			}

			unix_disabled = v->Enabled ? false : true;
		}
		UnlockList(c->UnixVLanList);
#endif	// OS_WIN32

		Lock(r->lock);
		{
			bool already_used = false;
			UINT i;

			if (r->ClientSession != NULL)
			{
				// すでに接続中
				CiSetError(c, ERR_ACCOUNT_ACTIVE);
			}
			else if (r->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE &&
				client->UseSecureDeviceId == 0)
			{
				// セキュアデバイスが指定されていない
				CiSetError(c, ERR_NO_SECURE_DEVICE_SPECIFIED);
			}
#ifdef	OS_WIN32
			else if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, r->ClientOption->DeviceName) == false)
			{
				// 仮想 LAN カードが見つからない
				CiSetError(c, ERR_VLAN_FOR_ACCOUNT_NOT_FOUND);
				CiNotify(c);
			}
			else if (MsIsVLanEnabled(r->ClientOption->DeviceName) == false)
			{
				// 仮想 LAN カードは無効化されている
				CiSetError(c, ERR_VLAN_FOR_ACCOUNT_DISABLED);
				CiNotify(c);
			}
#else	// OS_WIN32
			else if (unix_disabled)
			{
				// 仮想 LAN カードは無効化されている
				CiSetError(c, ERR_VLAN_FOR_ACCOUNT_DISABLED);
				CiNotify(c);
			}
#endif	// OS_WIN32
			else
			{
				// 仮想 LAN カードがすでに別のアカウントで使用されているかどうか調べる
				for (i = 0;i < LIST_NUM(c->AccountList);i++)
				{
					ACCOUNT *a = LIST_DATA(c->AccountList, i);
					if (a != r)
					{
						if (StrCmpi(a->ClientOption->DeviceName,
							r->ClientOption->DeviceName) == 0)
						{
							if (a->ClientSession != NULL)
							{
								already_used = true;
								break;
							}
						}
					}
				}

				if (already_used)
				{
					CiSetError(c, ERR_VLAN_FOR_ACCOUNT_USED);
				}
				else
				{
					// 接続を開始
					PACKET_ADAPTER *pa = VLanGetPacketAdapter();

					if (r->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE)
					{
						// セキュアデバイス認証のためのプロシージャを登録する
						r->ClientAuth->SecureSignProc = CiSecureSignProc;
					}
					else
					{
						r->ClientAuth->SecureSignProc = NULL;
					}

					if (r->CheckServerCert)
					{
						// サーバー証明書確認のためのプロシージャを登録する
						r->ClientAuth->CheckCertProc = CiCheckCertProc;
					}
					else
					{
						r->ClientAuth->CheckCertProc = NULL;
					}

					r->StatusPrinter = CiClientStatusPrinter;
					r->LastConnectDateTime = SystemTime64();

					CLog(c, "LC_CONNECT", connect->AccountName);

					r->ClientSession = NewClientSessionEx(c->Cedar, r->ClientOption, r->ClientAuth, pa, r);
					Notify(r->ClientSession, CLIENT_NOTIFY_ACCOUNT_CHANGED);

					ret = true;
				}
			}
		}
		Unlock(r->lock);

	}
	UnlockList(c->AccountList);

	CiSaveConfigurationFile(c);

	return ret;
}

// アカウント情報の取得
bool CtGetAccount(CLIENT *c, RPC_CLIENT_GET_ACCOUNT *a)
{
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;

		// アカウントを検索
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// クライアントオプションをコピー
			if (a->ClientOption != NULL)
			{
				Free(a->ClientOption);
			}
			a->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(a->ClientOption, r->ClientOption, sizeof(CLIENT_OPTION));

			// 認証データをコピー
			if (a->ClientAuth != NULL)
			{
				CiFreeClientAuth(a->ClientAuth);
			}
			a->ClientAuth = CopyClientAuth(r->ClientAuth);

			a->StartupAccount = r->StartupAccount;

			a->CheckServerCert = r->CheckServerCert;
			a->ServerCert = NULL;
			if (r->ServerCert != NULL)
			{
				a->ServerCert = CloneX(r->ServerCert);
			}

			// ショートカットキー
			Copy(a->ShortcutKey, r->ShortcutKey, SHA1_SIZE);

			a->CreateDateTime = r->CreateDateTime;
			a->LastConnectDateTime = r->LastConnectDateTime;
			a->UpdateDateTime = r->UpdateDateTime;
		}
		Unlock(r->lock);

	}
	UnlockList(c->AccountList);

	return true;
}

// アカウント名の変更
bool CtRenameAccount(CLIENT *c, RPC_RENAME_ACCOUNT *rename)
{
	bool ret;
	// 引数チェック
	if (c == NULL || rename == NULL)
	{
		return false;
	}

	ret = false;

	if (UniStrCmp(rename->NewName, rename->OldName) == 0)
	{
		// 名前が変更されていない
		return true;
	}

	LockList(c->AccountList);
	{
		ACCOUNT t, *r, *r2;

		if (UniStrLen(rename->NewName) == 0)
		{
			// 名前が不正
			CiSetError(c, ERR_INVALID_VALUE);
			UnlockList(c->AccountList);
			return false;
		}

		// 古いアカウント名を検索
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), rename->OldName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		// 新しいアカウント名を検索
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), rename->NewName);

		r2 = Search(c->AccountList, &t);
		if (r2 != NULL)
		{
			// 指定した名前のアカウントはすでに存在する
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_ALREADY_EXISTS);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// アカウントの動作状態チェック
			if (r->ClientSession != NULL)
			{
				// アカウントは動作中
				Unlock(r->lock);
				UnlockList(c->AccountList);
				CiSetError(c, ERR_ACCOUNT_ACTIVE);

				return false;
			}

			// アカウント名を更新
			UniStrCpy(r->ClientOption->AccountName, sizeof(r->ClientOption->AccountName),
				rename->NewName);

			CLog(c, "LC_RENAME_ACCOUNT", rename->OldName, rename->NewName);

			ret = true;
		}
		Unlock(r->lock);

		Sort(c->AccountList);

	}
	UnlockList(c->AccountList);

	CiSaveConfigurationFile(c);

	CiNotify(c);

	return ret;
}

// クライアント設定の設定
bool CtSetClientConfig(CLIENT *c, CLIENT_CONFIG *o)
{
	KEEP *k;
	// 引数チェック
	if (c == NULL || o == NULL)
	{
		return false;
	}

	if (o->UseKeepConnect)
	{
		if (IsEmptyStr(o->KeepConnectHost) ||
			o->KeepConnectPort == 0 ||
			o->KeepConnectPort >= 65536)
		{
			CiSetError(c, ERR_INVALID_PARAMETER);
			return false;
		}
	}

	Lock(c->lock);
	{
		Copy(&c->Config, o, sizeof(CLIENT_CONFIG));
	}
	Unlock(c->lock);

	// 設定の保存
	CiSaveConfigurationFile(c);

	// Keep Connect の適用
	k = c->Keep;
	Lock(k->lock);
	{
		if (o->UseKeepConnect)
		{
			StrCpy(k->ServerName, sizeof(k->ServerName), c->Config.KeepConnectHost);
			k->ServerPort = c->Config.KeepConnectPort;
			k->Interval = c->Config.KeepConnectInterval * 1000;
			k->UdpMode = (c->Config.KeepConnectProtocol == CONNECTION_UDP) ? true : false;
			k->Enable = true;
		}
		else
		{
			k->Enable = false;
		}
	}
	Unlock(k->lock);

	return true;
}

// ククライアント設定の取得
bool CtGetClientConfig(CLIENT *c, CLIENT_CONFIG *o)
{
	// 引数チェック
	if (c == NULL || o == NULL)
	{
		return false;
	}

	Lock(c->lock);
	{
		Copy(o, &c->Config, sizeof(CLIENT_CONFIG));
	}
	Unlock(c->lock);

	return true;
}

// アカウントのスタートアップ属性を解除する
bool CtRemoveStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	bool ret;
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	ret = false;

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		// アカウントの検索

		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// スタートアップアカウントを解除する
			ret = true;
			r->StartupAccount = false;
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	if (ret)
	{
		CiSaveConfigurationFile(c);
		CiNotify(c);
	}

	return ret;
}

// アカウントをスタートアップアカウントにする
bool CtSetStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	bool ret;
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	ret = false;

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		// アカウントの検索

		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// スタートアップアカウントにする
			ret = true;
			r->StartupAccount = true;
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	if (ret)
	{
		CiSaveConfigurationFile(c);
		CiNotify(c);
	}

	return ret;
}

// アカウントの削除
bool CtDeleteAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	bool ret;
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	ret = false;

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		// アカウントの検索

		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// 指定したアカウントは見つからない
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// アカウントの動作状態チェック
			if (r->ClientSession != NULL)
			{
				// アカウントは動作中
				Unlock(r->lock);
				UnlockList(c->AccountList);
				CiSetError(c, ERR_ACCOUNT_ACTIVE);

				return false;
			}

			// このアカウントをリストから削除する
			Delete(c->AccountList, r);
		}
		Unlock(r->lock);

		// このアカウントのメモリを解放する
		CiFreeAccount(r);

		CLog(c, "LC_DELETE_ACCOUNT", a->AccountName);
		ret = true;

	}
	UnlockList(c->AccountList);

	if (ret)
	{
		CiSaveConfigurationFile(c);
		CiNotify(c);
	}

	return ret;
}

// アカウントの列挙
bool CtEnumAccount(CLIENT *c, RPC_CLIENT_ENUM_ACCOUNT *e)
{
	// 引数チェック
	if (c == NULL || e == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{
		UINT i;
		// アカウント件数
		e->NumItem = LIST_NUM(c->AccountList);
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM));
			e->Items[i] = item;

			// アカウント名
			UniStrCpy(item->AccountName, sizeof(item->AccountName), a->ClientOption->AccountName);

			// ユーザー名
			StrCpy(item->UserName, sizeof(item->UserName), a->ClientAuth->Username);

			// サーバー名
			StrCpy(item->ServerName, sizeof(item->ServerName), a->ClientOption->Hostname);

			// プロキシ種類
			item->ProxyType = a->ClientOption->ProxyType;

			// デバイス名
			StrCpy(item->DeviceName, sizeof(item->DeviceName), a->ClientOption->DeviceName);

			// プロキシ情報
			if (item->ProxyType != PROXY_DIRECT)
			{
				StrCpy(item->ProxyName, sizeof(item->ProxyName), a->ClientOption->ProxyName);
			}

			// スタートアップ
			item->StartupAccount = a->StartupAccount;

			// 動作フラグ
			item->Active = (a->ClientSession == NULL ? false : true);

			// 接続フラグ
			item->Connected = (item->Active == false) ? false : a->ClientSession->ConnectSucceed;

			// ポート番号
			item->Port = a->ClientOption->Port;

			// 仮想 HUB 名
			StrCpy(item->HubName, sizeof(item->HubName), a->ClientOption->HubName);

			item->CreateDateTime = a->CreateDateTime;
			item->LastConnectDateTime = a->LastConnectDateTime;
			item->UpdateDateTime = a->UpdateDateTime;
		}
	}
	UnlockList(c->AccountList);

	return true;
}

// アカウントの設定
bool CtSetAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a)
{
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	// 既存のアカウントが存在するかどうかチェック
	LockList(c->AccountList);
	{
		ACCOUNT t, *ret;
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
			a->ClientOption->AccountName);

		ret = Search(c->AccountList, &t);
		if (ret == NULL)
		{
			// 存在しない
			UnlockList(c->AccountList);
			Free(t.ClientOption);

			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);

			return false;
		}
		Free(t.ClientOption);

		if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (a->ClientAuth->ClientX == NULL ||
				a->ClientAuth->ClientX->is_compatible_bit == false ||
				a->ClientAuth->ClientK == NULL)
			{
				// クライアント証明書が不正
				UnlockList(c->AccountList);
				CiSetError(c, ERR_NOT_RSA_1024);
				return false;
			}
		}

		if (a->ServerCert != NULL && a->ServerCert->is_compatible_bit == false)
		{
			// サーバー証明書が不正
			UnlockList(c->AccountList);
			CiSetError(c, ERR_NOT_RSA_1024);
			return false;
		}

		Lock(ret->lock);
		{

#if	0
			// 現在のバージョンではアカウント動作中でも設定の書き換えは行われる
			// (ただし次回接続時まで設定は適用されない)
			if (ret->ClientSession != NULL)
			{
				// アカウントが動作中である
				Unlock(ret->lock);
				UnlockList(c->AccountList);

				CiSetError(c, ERR_ACCOUNT_ACTIVE);

				return false;
			}
#endif

			// クライアント認証データの削除
			CiFreeClientAuth(ret->ClientAuth);

			// クライアント認証データのコピー
			ret->ClientAuth = CopyClientAuth(a->ClientAuth);

			// クライアントオプションの削除
			Free(ret->ClientOption);

			// クライアントオプションのコピー
			ret->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(ret->ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));

			ret->StartupAccount = a->StartupAccount;

			ret->CheckServerCert = a->CheckServerCert;

			if (a->ServerCert != NULL)
			{
				if (ret->ServerCert != NULL)
				{
					FreeX(ret->ServerCert);
				}
				ret->ServerCert = CloneX(a->ServerCert);
			}
			else
			{
				if (ret->ServerCert != NULL)
				{
					FreeX(ret->ServerCert);
				}
				ret->ServerCert = false;
			}

			ret->UpdateDateTime = SystemTime64();
		}
		Unlock(ret->lock);
	}
	UnlockList(c->AccountList);

	CiSaveConfigurationFile(c);

	CiNotify(c);

	return true;
}

// アカウントの作成
bool CtCreateAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a)
{
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	// 既存のアカウントが存在するかどうかチェック
	LockList(c->AccountList);
	{
		ACCOUNT t, *ret, *new_account;
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
			a->ClientOption->AccountName);

		ret = Search(c->AccountList, &t);
		if (ret != NULL)
		{
			// すでに存在する
			UnlockList(c->AccountList);
			Free(t.ClientOption);

			CiSetError(c, ERR_ACCOUNT_ALREADY_EXISTS);

			return false;
		}

		Free(t.ClientOption);

		if (UniStrLen(a->ClientOption->AccountName) == 0)
		{
			// 名前が不正
			UnlockList(c->AccountList);
			CiSetError(c, ERR_INVALID_VALUE);
			return false;
		}

		if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (a->ClientAuth->ClientX == NULL ||
				a->ClientAuth->ClientX->is_compatible_bit == false ||
				a->ClientAuth->ClientK == NULL)
			{
				// クライアント証明書が不正
				UnlockList(c->AccountList);
				CiSetError(c, ERR_NOT_RSA_1024);
				return false;
			}
		}

		if (a->ServerCert != NULL && a->ServerCert->is_compatible_bit == false)
		{
			// サーバー証明書が不正
			UnlockList(c->AccountList);
			CiSetError(c, ERR_NOT_RSA_1024);
			return false;
		}

		// 新しいアカウントを追加する
		new_account = ZeroMalloc(sizeof(ACCOUNT));
		new_account->lock = NewLock();

		// クライアント認証データのコピー
		new_account->ClientAuth = CopyClientAuth(a->ClientAuth);

		// クライアントオプションのコピー
		new_account->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(new_account->ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));

		new_account->StartupAccount = a->StartupAccount;

		new_account->CheckServerCert = a->CheckServerCert;
		if (a->ServerCert != NULL)
		{
			new_account->ServerCert = CloneX(a->ServerCert);
		}

		// ショートカットキー
		if (IsZero(a->ShortcutKey, SHA1_SIZE))
		{
			Rand(new_account->ShortcutKey, SHA1_SIZE);
		}
		else
		{
			Copy(new_account->ShortcutKey, a->ShortcutKey, SHA1_SIZE);
		}

		new_account->CreateDateTime = new_account->UpdateDateTime = SystemTime64();

		// リストに挿入する
		Insert(c->AccountList, new_account);

		CLog(c, "LC_NEW_ACCOUNT", a->ClientOption->AccountName);
	}
	UnlockList(c->AccountList);

	CiNormalizeAccountVLan(c);

	CiSaveConfigurationFile(c);

	CiNotify(c);

	return true;
}

// アカウント取得構造体の解放
void CiFreeClientGetAccount(RPC_CLIENT_GET_ACCOUNT *a)
{
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	// アカウント情報の解放
	if (a->ServerCert != NULL)
	{
		FreeX(a->ServerCert);
	}
	CiFreeClientAuth(a->ClientAuth);
	Free(a->ClientOption);
}

// アカウント作成構造体の解放
void CiFreeClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *a)
{
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	// アカウント情報の解放
	if (a->ServerCert != NULL)
	{
		FreeX(a->ServerCert);
	}
	CiFreeClientAuth(a->ClientAuth);
	Free(a->ClientOption);
}

// 仮想 LAN カードの停止
bool CtDisableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan)
{
	UINT i;
	bool used;
	// 引数チェック
	if (c == NULL || vlan == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// MacOS X では仮想 LAN カードは増減できない
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// 指定した名前の仮想 LAN カードが 1 つ以上のアカウントによって使用されていない
	// かどうか確認する
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, vlan->DeviceName) == 0)
			{
				Lock(a->lock);
				{
					if (a->ClientSession != NULL)
					{
						used = true;
					}
				}
				Unlock(a->lock);
			}
		}
	}
	UnlockList(c->AccountList);

	// 仮想 LAN カードを検索する
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN *v, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), vlan->DeviceName);

		v = Search(c->UnixVLanList, &t);
		if (v == NULL)
		{
			UnlockList(c->UnixVLanList);
			CiSetError(c, ERR_OBJECT_NOT_FOUND);
			return false;
		}

		// 停止する
		v->Enabled = false;
	}
	UnlockList(c->UnixVLanList);

	CiSaveConfigurationFile(c);
	CiNotify(c);

	return true;

#else	// OS_WIN32

	// 指定した名前の仮想 LAN カードが 1 つ以上のアカウントによって使用されていない
	// かどうか確認する
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, vlan->DeviceName) == 0)
			{
				Lock(a->lock);
				{
					if (a->ClientSession != NULL)
					{
						used = true;
					}
				}
				Unlock(a->lock);
			}
		}
	}
	UnlockList(c->AccountList);

#if	0
	if (used)
	{
		// 使用中
		CiSetError(c, ERR_VLAN_IS_USED);
		return false;
	}
#endif


	// 仮想 LAN カードが存在しているかチェック
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, vlan->DeviceName) == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		CiNotify(c);
		return false;
	}


	if (MsIs64BitWindows() && Is32() && MsIsAdmin())
	{
		// Windows は 64 bit だがこのコードは 32 bit であるので
		// driver_installer を起動して処理を実行する
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "disablevlan %s", vlan->DeviceName);

		if (MsExecDriverInstaller(tmp) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}
	else
	{
		// 仮想 LAN カードを停止
		if (MsDisableVLan(vlan->DeviceName) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}

	CiNotify(c);

	return true;

#endif	// OS_WIN32

}

// 仮想 LAN カードの開始
bool CtEnableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan)
{
	// 引数チェック
	if (c == NULL || vlan == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// MacOS X では仮想 LAN カードは増減できない
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// 仮想 LAN カードを検索する
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN *v, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), vlan->DeviceName);

		v = Search(c->UnixVLanList, &t);
		if (v == NULL)
		{
			UnlockList(c->UnixVLanList);
			CiSetError(c, ERR_OBJECT_NOT_FOUND);
			return false;
		}

		// 有効にする
		v->Enabled = true;
	}
	UnlockList(c->UnixVLanList);

	CiSaveConfigurationFile(c);
	CiNotify(c);

	return true;

#else	// OS_WIN32

	// 仮想 LAN カードが存在しているかチェック
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, vlan->DeviceName) == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		CiNotify(c);
		return false;
	}

	if (MsIs64BitWindows() && Is32() && MsIsAdmin())
	{
		// Windows は 64 bit だがこのコードは 32 bit であるので
		// driver_installer を起動して処理を実行する
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "enablevlan %s", vlan->DeviceName);

		if (MsExecDriverInstaller(tmp) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}
	else
	{
		// 仮想 LAN カードを開始
		if (MsEnableVLan(vlan->DeviceName) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}

	CiNotify(c);

	return true;

#endif	// OS_WIN32

}

// 仮想 LAN カードの削除
bool CtDeleteVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *d)
{
	UINT i;
	bool used;
	// 引数チェック
	if (c == NULL || d == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// MacOS X では仮想 LAN カードは増減できない
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// 指定した名前の仮想 LAN カードが 1 つ以上のアカウントによって使用されていない
	// かどうか確認する
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, d->DeviceName) == 0)
			{
				used = true;
			}
		}
	}
	UnlockList(c->AccountList);

#if	0
	if (used)
	{
		// 使用中
		CiSetError(c, ERR_VLAN_IS_USED);
		return false;
	}
#endif

	// 仮想 LAN カードを検索する
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN *v, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), d->DeviceName);

		v = Search(c->UnixVLanList, &t);
		if (v == NULL)
		{
			UnlockList(c->UnixVLanList);
			CiSetError(c, ERR_OBJECT_NOT_FOUND);
			return false;
		}

		// 削除する
		if (Delete(c->UnixVLanList, v))
		{
			Free(v);
		}

		CLog(c, "LC_DELETE_VLAN", d->DeviceName);

		UnixVLanDelete(d->DeviceName);
	}
	UnlockList(c->UnixVLanList);

	CiNormalizeAccountVLan(c);

	CiSaveConfigurationFile(c);
	CiNotify(c);

	return true;

#else	// OS_WIN32

	if (MsIsNt() == false)
	{
		// Win9x では使用できない
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// 仮想 LAN カードが存在しているかチェック
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, d->DeviceName) == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}

	// 指定した名前の仮想 LAN カードが 1 つ以上のアカウントによって使用されていない
	// かどうか確認する
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, d->DeviceName) == 0)
			{
				used = true;
			}
		}
	}
	UnlockList(c->AccountList);

#if	0
	if (used)
	{
		// 使用中
		CiSetError(c, ERR_VLAN_IS_USED);
		return false;
	}
#endif

	if (MsIs64BitWindows() && Is32() && MsIsAdmin())
	{
		// Windows は 64 bit だがこのコードは 32 bit であるので
		// driver_installer を起動して処理を実行する
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "uninstvlan %s", d->DeviceName);

		if (MsExecDriverInstaller(tmp) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			return false;
		}
	}
	else
	{
		// 仮想 LAN カードを直接削除
		if (MsUninstallVLan(d->DeviceName) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}

	CLog(c, "LC_DELETE_VLAN", d->DeviceName);

	CiNormalizeAccountVLan(c);

	CiNotify(c);

	return true;

#endif	// OS_WIN32

}

// 最初の VLAN の名前を取得
char *CiGetFirstVLan(CLIENT *c)
{
	char *ret = NULL;
	RPC_CLIENT_ENUM_VLAN t;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	if (CtEnumVLan(c, &t) == false)
	{
		return NULL;
	}

	if (t.NumItem >= 1)
	{
		UINT i;
		char *tmp = t.Items[0]->DeviceName;

		for (i = 0;i < t.NumItem;i++)
		{
			if (t.Items[i]->Enabled)
			{
				tmp = t.Items[i]->DeviceName;
			}
		}

		ret = CopyStr(tmp);
	}

	CiFreeClientEnumVLan(&t);

	return ret;
}

// 仮想 LAN カードの列挙
bool CtEnumVLan(CLIENT *c, RPC_CLIENT_ENUM_VLAN *e)
{
	UINT i;
	TOKEN_LIST *t;
	// 引数チェック
	if (c == NULL || e == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	LockList(c->UnixVLanList);
	{
		e->NumItem = LIST_NUM(c->UnixVLanList);
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			RPC_CLIENT_ENUM_VLAN_ITEM *item;
			UNIX_VLAN *v;

			v = LIST_DATA(c->UnixVLanList, i);
			e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM));
			item = e->Items[i];

			item->Enabled = v->Enabled;
			BinToStr(item->MacAddress, sizeof(item->MacAddress), v->MacAddress, 6);
			StrCpy(item->DeviceName, sizeof(item->DeviceName), v->Name);
			StrCpy(item->Version, sizeof(item->Version), c->Cedar->VerString);
		}
	}
	UnlockList(c->UnixVLanList);

	return true;

#else	// OS_WIN32

	// 列挙
	t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, "---dummy-string-ut--");
	if (t == NULL)
	{
		// 列挙失敗
		e->NumItem = 0;
		e->Items = ZeroMalloc(0);
	}
	else
	{
		// 列挙成功
		e->NumItem = t->NumTokens;
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			char *tmp;
			RPC_CLIENT_ENUM_VLAN_ITEM *item;
			e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM));
			item = e->Items[i];

			StrCpy(item->DeviceName, sizeof(item->DeviceName), t->Token[i]);
			item->Enabled = MsIsVLanEnabled(item->DeviceName);

			tmp = MsGetMacAddress(VLAN_ADAPTER_NAME_TAG, item->DeviceName);

			StrCpy(item->MacAddress, sizeof(item->MacAddress), tmp);
			Free(tmp);

			tmp = MsGetDriverVersion(VLAN_ADAPTER_NAME_TAG, item->DeviceName);

			StrCpy(item->Version, sizeof(item->Version), tmp);
			Free(tmp);
		}

		FreeToken(t);
	}

	return true;

#endif	// OS_WIN32
}

// 仮想 LAN カード列挙体の解放
void CiFreeClientEnumVLan(RPC_CLIENT_ENUM_VLAN *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->NumItem;i++)
	{
		Free(e->Items[i]);
	}
	Free(e->Items);
}

// 仮想 LAN カードに関する情報の設定
bool CtSetVLan(CLIENT *c, RPC_CLIENT_SET_VLAN *set)
{
	// 引数チェック
	if (c == NULL || set == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	LockList(c->UnixVLanList);
	{
		UNIX_VLAN t, *r;
		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), set->DeviceName);

		r = Search(c->UnixVLanList, &t);
		if (r == NULL)
		{
			// 存在しない
			CiSetError(c, ERR_VLAN_ALREADY_EXISTS);
			UnlockList(c->UnixVLanList);
			return false;
		}

		StrToMac(r->MacAddress, set->MacAddress);
	}
	UnlockList(c->UnixVLanList);

	CiSaveConfigurationFile(c);
	CiNotify(c);

	return true;

#else	// OS_WIN32

	// 指定された名前の仮想 LAN カードが存在するかチェック
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, set->DeviceName) == false)
	{
		// 存在していない
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}

	// MAC アドレスの設定
	MsSetMacAddress(VLAN_ADAPTER_NAME_TAG, set->DeviceName, set->MacAddress);

	CiNotify(c);

	return true;

#endif	// OS_WIN32
}

// 仮想 LAN カードに関する情報の取得
bool CtGetVLan(CLIENT *c, RPC_CLIENT_GET_VLAN *get)
{
	char *tmp;
	// 引数チェック
	if (c == NULL || get == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	// サポートされていない
	CiSetError(c, ERR_NOT_SUPPORTED);
	return false;

#else	// OS_WIN32

	// 指定された名前の仮想 LAN カードが存在するかチェック
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, get->DeviceName) == false)
	{
		// 存在していない
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}

	// 動作状況
	get->Enabled = MsIsVLanEnabled(get->DeviceName);

	// MAC アドレス
	tmp = MsGetMacAddress(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	StrCpy(get->MacAddress, sizeof(get->MacAddress), tmp);
	Free(tmp);

	// バージョン
	tmp = MsGetDriverVersion(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	StrCpy(get->Version, sizeof(get->Version), tmp);
	Free(tmp);

	// ファイル名
	tmp = MsGetDriverFileName(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	StrCpy(get->FileName, sizeof(get->FileName), tmp);
	Free(tmp);

	// GUID
	tmp = MsGetNetworkAdapterGuid(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	StrCpy(get->Guid, sizeof(get->Guid), tmp);
	Free(tmp);

	return true;

#endif	// OS_WIN32
}

// 仮想 LAN カードのアップグレード
bool CtUpgradeVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create)
{
#ifdef	OS_WIN32
	KAKUSHI *k = NULL;
#endif	// OS_WIN32

	// 引数チェック
	if (c == NULL || create == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	// 常に成功
	return true;

#else	// OS_WIN32

	if (MsIsNt() == false)
	{
		// Win9x では不可
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// 指定された名前の LAN カードがすでに存在していないかどうかチェックする
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, create->DeviceName) == false)
	{
		// 存在していない
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		CiNotify(c);
		return false;
	}

	if (MsIsVista() == false)
	{
		k = InitKakushi();	
	}


	if (MsIsVista() == false)
	{
		// インストールを行う (Windows Vista 以外)
		if (MsUpgradeVLan(VLAN_ADAPTER_NAME_TAG,
			VLAN_CONNECTION_NAME,
			create->DeviceName) == false)
		{
			// インストール失敗
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}
	else
	{
		// インストールを行う (Windows Vista)
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "upgradevlan %s", create->DeviceName);

		if (CncExecDriverInstaller(tmp) == false)
		{
			// インストール失敗
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}

	FreeKakushi(k);

	CLog(c, "LC_UPDATE_VLAN", create->DeviceName);

	CiNotify(c);

	return true;

#endif	// OS_WIN32
}

// 仮想 LAN カードの作成
bool CtCreateVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create)
{
	TOKEN_LIST *t;
	UINT max_len;

#ifdef	OS_WIN32
	KAKUSHI *k = NULL;
#endif	// OS_WIN32

	// 引数チェック
	if (c == NULL || create == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	// Win32 以外
	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// MacOS X では仮想 LAN カードは増減できない
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// 指定された名前が有効かどうかチェックする
	if (IsSafeStr(create->DeviceName) == false)
	{
		// 名前が不正
		CiSetError(c, ERR_VLAN_INVALID_NAME);
		return false;
	}

	// 指定した名前の LAN カードがすでに存在していないかどうかチェックする
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN t, *r;
		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), create->DeviceName);

		r = Search(c->UnixVLanList, &t);
		if (r != NULL)
		{
			// すでに存在している
			CiSetError(c, ERR_VLAN_ALREADY_EXISTS);
			UnlockList(c->UnixVLanList);
			return false;
		}

		// 登録する
		r = ZeroMalloc(sizeof(UNIX_VLAN));
		r->Enabled = true;
		GenMacAddress(r->MacAddress);
		StrCpy(r->Name, sizeof(r->Name), create->DeviceName);

		// tap 作成
		if (UnixVLanCreate(r->Name, r->MacAddress) == false)
		{
			// 失敗
			Free(r);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			UnlockList(c->UnixVLanList);
			return false;
		}

		CLog(c, "LC_CREATE_VLAN", create->DeviceName);

		Add(c->UnixVLanList, r);
	}
	UnlockList(c->UnixVLanList);

	CiNormalizeAccountVLan(c);

	CiNotify(c);
	CiSaveConfigurationFile(c);

	return true;

#else	// OS_WIN32

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		// Win9x では LAN カードは 1 個しか作成できない
		TOKEN_LIST *t;

		t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, "---dummy-string-ut--");
		if (t != NULL)
		{
			if (t->NumTokens >= 1)
			{
				FreeToken(t);
				CiSetError(c, ERR_NOT_SUPPORTED);
				return false;
			}
			FreeToken(t);
		}
	}

	// 指定された名前が有効かどうかチェックする
	if (IsSafeStr(create->DeviceName) == false)
	{
		// 名前が不正
		CiSetError(c, ERR_VLAN_INVALID_NAME);
		return false;
	}

	max_len = MsIsNt() ? MAX_DEVICE_NAME_LEN : MAX_DEVICE_NAME_LEN_9X;
	if (StrLen(create->DeviceName) > max_len)
	{
		// 名前が長すぎる
		CiSetError(c, ERR_VLAN_INVALID_NAME);
		return false;
	}

	// 指定された名前の LAN カードがすでに存在していないかどうかチェックする
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, create->DeviceName))
	{
		// すでに存在している
		CiSetError(c, ERR_VLAN_ALREADY_EXISTS);
		return false;
	}

	if (MsIsNt())
	{
		if (MsIsVista() == false)
		{
			k = InitKakushi();
		}
	}

	if (MsIsVista() == false)
	{
		// インストールを行う (Windows Vista 以外)
		if (MsInstallVLan(VLAN_ADAPTER_NAME_TAG, VLAN_CONNECTION_NAME, create->DeviceName) == false)
		{
			// インストール失敗
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}
	else
	{
		// インストールを行う (Windows Vista)
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "instvlan %s", create->DeviceName);

		if (CncExecDriverInstaller(tmp) == false)
		{
			// インストール失敗
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			return false;
		}
	}

	FreeKakushi(k);

	t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, "---dummy-string-ut--");
	if (t->NumTokens == 1)
	{
		UINT i;
		// インストールを行った結果、仮想 LAN カードが 1 つになった場合は
		// 既存のすべてのアカウントの仮想 LAN カードをこの仮想 LAN カードにセットする
		LockList(c->AccountList);
		{
			for (i = 0;i < LIST_NUM(c->AccountList);i++)
			{
				ACCOUNT *a = LIST_DATA(c->AccountList, i);
				Lock(a->lock);
				{
					if (a->ClientOption != NULL)
					{
						StrCpy(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName), create->DeviceName);
					}
				}
				Unlock(a->lock);
			}
		}
		UnlockList(c->AccountList);
	}
	FreeToken(t);

	CLog(c, "LC_CREATE_VLAN", create->DeviceName);

	CiNormalizeAccountVLan(c);

	CiNotify(c);

	CiSaveConfigurationFile(c);

	if (MsIsNt() == false)
	{
		if (GetOsInfo()->OsType == OSTYPE_WINDOWS_ME)
		{
			// Windows Me の場合は警告表示
			MsgBox(NULL, 0x00000040L, _UU("CM_9X_VLAN_ME_MESSAGE"));
		}

		ReleaseThread(NewThread(Win9xRebootThread, NULL));
	}

	return true;

#endif	// OS_WIN32
}

// セキュアデバイス内のオブジェクト列挙
bool CtEnumObjectInSecure(CLIENT *c, RPC_ENUM_OBJECT_IN_SECURE *e)
{
	UINT i;
	// 引数チェック
	if (c == NULL || e == NULL)
	{
		return false;
	}

	e->NumItem = 5;
	e->ItemName = ZeroMalloc(sizeof(char *) * e->NumItem);
	e->ItemType = ZeroMalloc(sizeof(bool) * e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		char tmp[MAX_SIZE];
		Format(tmp, sizeof(tmp), "Test Object %u", i);
		e->ItemName[i] = CopyStr(tmp);
		e->ItemType[i] = (i % 2 == 0) ? false : true;
	}

	return true;
}

// 使用するセキュアデバイスの取得
bool CtGetUseSecure(CLIENT *c, RPC_USE_SECURE *sec)
{
	// 引数チェック
	if (c == NULL || sec == NULL)
	{
		return false;
	}

	sec->DeviceId = c->UseSecureDeviceId;

	return true;
}

// 使用するセキュアデバイスの指定
bool CtUseSecure(CLIENT *c, RPC_USE_SECURE *sec)
{
	// 引数チェック
	if (c == NULL || sec == NULL)
	{
		return false;
	}

// クライアントマネージャに指定されたデバイスが存在するかどうかチェックしない
/*	if (CheckSecureDeviceId(sec->DeviceId))
	{
		c->UseSecureDeviceId = sec->DeviceId;
	}
	else
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}
*/
	c->UseSecureDeviceId = sec->DeviceId;

	CiSaveConfigurationFile(c);

	return true;
}

// セキュアデバイスの列挙
bool CtEnumSecure(CLIENT *c, RPC_CLIENT_ENUM_SECURE *e)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (c == NULL || e == NULL)
	{
		return false;
	}

	o = GetSecureDeviceList();

	e->NumItem = LIST_NUM(o);
	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM *) * e->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		RPC_CLIENT_ENUM_SECURE_ITEM *item = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM));
		SECURE_DEVICE *s = LIST_DATA(o, i);

		item->DeviceId = s->Id;
		StrCpy(item->DeviceName, sizeof(item->DeviceName), s->DeviceName);
		StrCpy(item->Manufacturer, sizeof(item->Manufacturer), s->Manufacturer);
		item->Type = s->Type;

		e->Items[i] = item;
	}

	return true;
}

// セキュアデバイス列挙体の解放
void CiFreeClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->NumItem;i++)
	{
		Free(e->Items[i]);
	}
	Free(e->Items);
}

// RPC_GET_ISSUER の解放
void CiFreeGetIssuer(RPC_GET_ISSUER *a)
{
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	if (a->issuer_x != NULL)
	{
		FreeX(a->issuer_x);
	}
	if (a->x != NULL)
	{
		FreeX(a->x);
	}
}

// 署名者の取得
bool CtGetIssuer(CLIENT *c, RPC_GET_ISSUER *a)
{
	X *x;
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	x = FindCaSignedX(c->Cedar->CaList, a->x);
	if (x == NULL)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);;
		return false;
	}
	else
	{
		a->issuer_x = x;
		if (a->x != NULL)
		{
			FreeX(a->x);
			a->x = NULL;
		}
		return true;
	}
}

// CA 証明書の取得
bool CtGetCa(CLIENT *c, RPC_GET_CA *get)
{
	bool ret = true;
	X *cert = NULL;
	// 引数チェック
	if (c == NULL || get == NULL)
	{
		return false;
	}

	LockList(c->Cedar->CaList);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(c->Cedar->CaList);i++)
		{
			X *x = LIST_DATA(c->Cedar->CaList, i);

			if (POINTER_TO_KEY(x) == get->Key)
			{
				cert = CloneX(x);
				break;
			}
		}
	}
	UnlockList(c->Cedar->CaList);

	if (cert == NULL)
	{
		// 証明書は存在しない
		ret = false;
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
	}
	else
	{
		ret = true;
		get->x = cert;
	}

	return ret;
}

// CA 証明書の削除
bool CtDeleteCa(CLIENT *c, RPC_CLIENT_DELETE_CA *p)
{
	bool ret;
	// 引数チェック
	if (c == NULL || p == NULL)
	{
		return false;
	}

	ret = DeleteCa(c->Cedar, p->Key);

	if (ret == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
	}

	CiSaveConfigurationFile(c);

	return ret;
}

// CA 証明書の追加
bool CtAddCa(CLIENT *c, RPC_CERT *cert)
{
	// 引数チェック
	if (c == NULL || cert == NULL)
	{
		return false;
	}

	if (cert->x->is_compatible_bit == false)
	{
		CiSetError(c, ERR_NOT_RSA_1024);
		return false;
	}

	AddCa(c->Cedar, cert->x);

	CiSaveConfigurationFile(c);

	return true;
}

// 信頼する CA の列挙
bool CtEnumCa(CLIENT *c, RPC_CLIENT_ENUM_CA *e)
{
	// 引数チェック
	if (c == NULL || e == NULL)
	{
		return false;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_CA));

	LockList(c->Cedar->CaList);
	{
		UINT i;
		e->NumItem = LIST_NUM(c->Cedar->CaList);
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			X *x = LIST_DATA(c->Cedar->CaList, i);
			e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM));
			GetAllNameFromNameEx(e->Items[i]->SubjectName, sizeof(e->Items[i]->SubjectName), x->subject_name);
			GetAllNameFromNameEx(e->Items[i]->IssuerName, sizeof(e->Items[i]->IssuerName), x->issuer_name);
			e->Items[i]->Expires = x->notAfter;
			e->Items[i]->Key = POINTER_TO_KEY(x);
		}
	}
	UnlockList(c->Cedar->CaList);

	return true;
}

// CA 列挙体を解放する
void CiFreeClientEnumCa(RPC_CLIENT_ENUM_CA *e)
{
	UINT i;
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_CA_ITEM *ca = e->Items[i];
		Free(ca);
	}
	Free(e->Items);
}

// パスワードの設定の取得
bool CtGetPasswordSetting(CLIENT *c, RPC_CLIENT_PASSWORD_SETTING *a)
{
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (c == NULL || a == NULL)
	{
		return false;
	}

	Hash(hash, "", 0, true);
	if (Cmp(hash, c->EncryptedPassword, SHA1_SIZE) == 0)
	{
		a->IsPasswordPresented = false;
	}
	else
	{
		a->IsPasswordPresented = true;
	}

	a->PasswordRemoteOnly = c->PasswordRemoteOnly;

	return true;
}

// パスワードの設定
bool CtSetPassword(CLIENT *c, RPC_CLIENT_PASSWORD *pass)
{
	char *str;
	if (c == NULL)
	{
		return false;
	}
	if (pass->Password == NULL)
	{
		str = "";
	}
	else
	{
		str = pass->Password;
	}

	if (StrCmp(str, "********") != 0)
	{
		// パスワードのハッシュ
		Hash(c->EncryptedPassword, str, StrLen(str), true);
	}

	c->PasswordRemoteOnly = pass->PasswordRemoteOnly;

	CLog(c, "LC_SET_PASSWORD");

	CiSaveConfigurationFile(c);

	return true;
}

// クライアントエラーコードの設定
void CiSetError(CLIENT *c, UINT err)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->Err = err;
}

// UNIX 仮想 LAN カード比較関数
int CiCompareUnixVLan(void *p1, void *p2)
{
	UNIX_VLAN *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(UNIX_VLAN **)p1;
	v2 = *(UNIX_VLAN **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->Name, v2->Name);
}

// 不正な VLAN 名が指定されているアカウントの設定を修正する
void CiNormalizeAccountVLan(CLIENT *c)
{
	bool b = false;
	char *name;
	UINT i;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	name = CiGetFirstVLan(c);

	if (name != NULL)
	{
		LockList(c->AccountList);
		{
			for (i = 0;i < LIST_NUM(c->AccountList);i++)
			{
				ACCOUNT *a = LIST_DATA(c->AccountList, i);

				Lock(a->lock);
				{
					if (a->ClientOption != NULL)
					{
						if (CiIsVLan(c, a->ClientOption->DeviceName) == false)
						{
							StrCpy(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName),
								name);
							b = true;
						}
					}
				}
				Unlock(a->lock);
			}
		}
		UnlockList(c->AccountList);

		Free(name);
	}

	if (b)
	{
		CiNotify(c);
		CiSaveConfigurationFile(c);
	}
}

// 指定した名前の仮想 LAN カードが存在しているかどうか調べる
bool CiIsVLan(CLIENT *c, char *name)
{
	// 引数チェック
	if (c == NULL || name == NULL)
	{
		return false;
	}

#ifdef	OS_WIN32
	{
		TOKEN_LIST *t;
		UINT i;

		t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, "---dummy-string-ut--");
		if (t == NULL)
		{
			return false;
		}

		for (i = 0;i < t->NumTokens;i++)
		{
			if (StrCmpi(t->Token[i], name) == 0)
			{
				FreeToken(t);
				return true;
			}
		}

		FreeToken(t);

		return false;
	}
#else	// OS_WIN32
	{
		UNIX_VLAN *v;
		UINT i;
		bool ret = false;

		LockList(c->UnixVLanList);
		{
			for (i = 0;i < LIST_NUM(c->UnixVLanList);i++)
			{
				v = (UNIX_VLAN *)LIST_DATA(c->UnixVLanList, i);
				if (StrCmpi(v->Name, name) == 0)
				{
					ret = true;
				}
			}
		}
		UnlockList(c->UnixVLanList);

		return ret;
	}
#endif	// OS_WIN32
}

// すべての接続アカウントにおいて、存在しない仮想 LAN カードが指定されている場合で
// 現在の仮想 LAN カードが 1 枚だけの場合は、その仮想 LAN カードに指定しなおす
void CiSetVLanToDefault(CLIENT *c)
{
	char device_name[MAX_SIZE];
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	{
		TOKEN_LIST *t;

		t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, "---dummy-string-ut--");
		if (t == NULL)
		{
			return;
		}
		if (t->NumTokens != 1)
		{
			FreeToken(t);
			return;
		}
		StrCpy(device_name, sizeof(device_name), t->Token[0]);
		FreeToken(t);
	}
#else	// OS_WIN32
	{
		UINT i;
		UNIX_VLAN *v;

		LockList(c->UnixVLanList);

		if (LIST_NUM(c->UnixVLanList) != 1)
		{
			UnlockList(c->UnixVLanList);
			return;
		}
		v = LIST_DATA(c->UnixVLanList, 0);
		StrCpy(device_name, sizeof(device_name), v->Name);

		UnlockList(c->UnixVLanList);
	}
#endif	// OS_WIN32

	{
		UINT i;
		LockList(c->AccountList);
		{
			for (i = 0;i < LIST_NUM(c->AccountList);i++)
			{
				ACCOUNT *a = LIST_DATA(c->AccountList, i);

				Lock(a->lock);
				{
					if (CiIsVLan(c, a->ClientOption->DeviceName) == false)
					{
						StrCpy(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName),
							device_name);
					}
				}
				Unlock(a->lock);
			}
		}
		UnlockList(c->AccountList);
	}
}

// 設定の初期化
void CiInitConfiguration(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

#ifdef	OS_UNIX
	// VLAN 初期化
	UnixVLanInit();
#endif	 // OS_UNIX

	// アカウントリスト
	c->AccountList = NewList(CiCompareAccount);

	// Unix 版 VLAN リスト
	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		c->UnixVLanList = NewList(CiCompareUnixVLan);
	}

	// 設定ファイルの読み込み
	CLog(c, "LC_LOAD_CONFIG_1");
	if (CiLoadConfigurationFile(c) == false)
	{
		CLog(c, "LC_LOAD_CONFIG_3");
		// 設定ファイルが存在しないので初期設定を行う
		// パスワードを空にする
		Hash(c->EncryptedPassword, "", 0, true);
		// クライアント設定を初期化
		if (OS_IS_WINDOWS(GetOsInfo()->OsType))
		{
			// Windows の場合はリモートを禁止
			c->Config.AllowRemoteConfig = false;
		}
		else
		{
			// UNIX の場合もリモートを禁止
			c->Config.AllowRemoteConfig = false;
		}
		StrCpy(c->Config.KeepConnectHost, sizeof(c->Config.KeepConnectHost), CLIENT_DEFAULT_KEEPALIVE_HOST);
		c->Config.KeepConnectPort = CLIENT_DEFAULT_KEEPALIVE_PORT;
		c->Config.KeepConnectProtocol = CONNECTION_UDP;
		c->Config.KeepConnectInterval = CLIENT_DEFAULT_KEEPALIVE_INTERVAL;
		c->Config.UseKeepConnect = false;	// Client ではデフォルトでは接続維持機能を使用しない
		// 自動ファイル削除器
		c->Eraser = NewEraser(c->Logger, 0);
	}
	else
	{
		CLog(c, "LC_LOAD_CONFIG_2");
	}

	// 仮想 LAN カードの適切な設定
	CiSetVLanToDefault(c);
}

// 設定の解放
void CiFreeConfiguration(CLIENT *c)
{
	UINT i;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// 設定ファイルへ書き込み
	CiSaveConfigurationFile(c);

	// 設定ファイル解放
	FreeCfgRw(c->CfgRw);

	// アカウントリストの解放
	for (i = 0;i < LIST_NUM(c->AccountList);i++)
	{
		ACCOUNT *a = LIST_DATA(c->AccountList, i);

		CiFreeAccount(a);
	}
	ReleaseList(c->AccountList);

	if (c->UnixVLanList != NULL)
	{
		// UNIX 版 VLAN リストの解放
		for (i = 0;i < LIST_NUM(c->UnixVLanList);i++)
		{
			UNIX_VLAN *v = LIST_DATA(c->UnixVLanList, i);
			Free(v);
		}
		ReleaseList(c->UnixVLanList);
	}
	c->UnixVLanList = NULL;

#ifdef	OS_UNIX
	// VLAN 解放
	UnixVLanFree();
#endif	// OS_UNIX
}

// 証明書取得データの解放
void CiFreeGetCa(RPC_GET_CA *a)
{
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	FreeX(a->x);
}

// クライアント認証データの解放
void CiFreeClientAuth(CLIENT_AUTH *auth)
{
	// 引数チェック
	if (auth == NULL)
	{
		return;
	}

	if (auth->ClientX != NULL)
	{
		FreeX(auth->ClientX);
	}
	if (auth->ClientK != NULL)
	{
		FreeK(auth->ClientK);
	}

	Free(auth);
}

// アカウントの解放
void CiFreeAccount(ACCOUNT *a)
{
	// 引数チェック
	if (a == NULL)
	{
		return;
	}

	// ロック解放
	DeleteLock(a->lock);

	// クライアントオプションの解放
	Free(a->ClientOption);

	// クライアント認証データの解放
	CiFreeClientAuth(a->ClientAuth);

	if (a->ServerCert != NULL)
	{
		FreeX(a->ServerCert);
	}

	Free(a);
}

// アカウントのソート
int CiCompareAccount(void *p1, void *p2)
{
	ACCOUNT *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ACCOUNT **)p1;
	a2 = *(ACCOUNT **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	return UniStrCmpi(a1->ClientOption->AccountName, a2->ClientOption->AccountName);
}

// クライアントコンフィグレーションの読み込み
void CiLoadClientConfig(CLIENT_CONFIG *c, FOLDER *f)
{
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	c->UseKeepConnect = CfgGetBool(f, "UseKeepConnect");
	CfgGetStr(f, "KeepConnectHost", c->KeepConnectHost, sizeof(c->KeepConnectHost));
	c->KeepConnectPort = CfgGetInt(f, "KeepConnectPort");
	c->KeepConnectProtocol = CfgGetInt(f, "KeepConnectProtocol");
	c->AllowRemoteConfig = CfgGetBool(f, "AllowRemoteConfig");
	c->KeepConnectInterval = MAKESURE(CfgGetInt(f, "KeepConnectInterval"), KEEP_INTERVAL_MIN, KEEP_INTERVAL_MAX);
}

// クライアント認証データの読み込み
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f)
{
	CLIENT_AUTH *a;
	char *s;
	BUF *b;
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(CLIENT_AUTH));

	a->AuthType = CfgGetInt(f, "AuthType");
	CfgGetStr(f, "Username", a->Username, sizeof(a->Username));

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		CfgGetByte(f, "HashedPassword", a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		b = CfgGetBuf(f, "EncryptedPassword");
		if (b != NULL)
		{
			s = DecryptPassword(b);
			StrCpy(a->PlainPassword, sizeof(a->PlainPassword), s);
			Free(s);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = CfgGetBuf(f, "ClientCert");
		if (b != NULL)
		{
			a->ClientX = BufToX(b, false);
		}
		FreeBuf(b);
		b = CfgGetBuf(f, "ClientKey");
		if (b != NULL)
		{
			a->ClientK = BufToK(b, true, false, NULL);
		}
		FreeBuf(b);
		break;

	case CLIENT_AUTHTYPE_SECURE:
		CfgGetStr(f, "SecurePublicCertName", a->SecurePublicCertName, sizeof(a->SecurePublicCertName));
		CfgGetStr(f, "SecurePrivateKeyName", a->SecurePrivateKeyName, sizeof(a->SecurePrivateKeyName));
		break;
	}

	return a;
}

// クライアントオプションの読み込み
CLIENT_OPTION *CiLoadClientOption(FOLDER *f)
{
	CLIENT_OPTION *o;
	char *s;
	BUF *b;
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(CLIENT_OPTION));

	CfgGetUniStr(f, "AccountName", o->AccountName, sizeof(o->AccountName));
	CfgGetStr(f, "Hostname", o->Hostname, sizeof(o->Hostname));
	o->Port = CfgGetInt(f, "Port");
	o->PortUDP = CfgGetInt(f, "PortUDP");
	o->ProxyType = CfgGetInt(f, "ProxyType");
	CfgGetStr(f, "ProxyName", o->ProxyName, sizeof(o->ProxyName));
	o->ProxyPort = CfgGetInt(f, "ProxyPort");
	CfgGetStr(f, "ProxyUsername", o->ProxyUsername, sizeof(o->ProxyUsername));
	b = CfgGetBuf(f, "ProxyPassword");
	s = DecryptPassword(b);
	StrCpy(o->ProxyPassword, sizeof(o->ProxyPassword), s);
	Free(s);
	FreeBuf(b);
	o->NumRetry = CfgGetInt(f, "NumRetry");
	o->RetryInterval = CfgGetInt(f, "RetryInterval");
	CfgGetStr(f, "HubName", o->HubName, sizeof(o->HubName));
	o->MaxConnection = CfgGetInt(f, "MaxConnection");
	o->UseEncrypt = CfgGetBool(f, "UseEncrypt");
	o->UseCompress = CfgGetBool(f, "UseCompress");
	o->HalfConnection = CfgGetBool(f, "HalfConnection");
	o->NoRoutingTracking = CfgGetBool(f, "NoRoutingTracking");
	CfgGetStr(f, "DeviceName", o->DeviceName, sizeof(o->DeviceName));
	o->AdditionalConnectionInterval = CfgGetInt(f, "AdditionalConnectionInterval");
	o->HideStatusWindow = CfgGetBool(f, "HideStatusWindow");
	o->HideNicInfoWindow = CfgGetBool(f, "HideNicInfoWindow");
	o->ConnectionDisconnectSpan = CfgGetInt(f, "ConnectionDisconnectSpan");
	o->RequireMonitorMode = CfgGetBool(f, "RequireMonitorMode");
	o->RequireBridgeRoutingMode = CfgGetBool(f, "RequireBridgeRoutingMode");
	o->DisableQoS = CfgGetBool(f, "DisableQoS");
	o->FromAdminPack = CfgGetBool(f, "FromAdminPack");
	o->NoTls1 = CfgGetBool(f, "NoTls1");

	return o;
}

// アカウントデータの読み込み
ACCOUNT *CiLoadClientAccount(FOLDER *f)
{
	ACCOUNT *a;
	FOLDER *client_option_folder, *client_auth_folder;
	BUF *b;
	char tmp[64];
	// 引数チェック
	if (f == NULL)
	{
		return NULL;
	}

	client_option_folder = CfgGetFolder(f, "ClientOption");

	if (client_option_folder != NULL)
	{
		// すでに登録されているアカウント名と一致するかどうか比較する
	}

	client_auth_folder = CfgGetFolder(f, "ClientAuth");

	if (client_option_folder == NULL || client_auth_folder == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(ACCOUNT));
	a->lock = NewLock();

	a->ClientOption = CiLoadClientOption(client_option_folder);
	a->ClientAuth = CiLoadClientAuth(client_auth_folder);

	a->StartupAccount = CfgGetBool(f, "StartupAccount");
	a->CheckServerCert = CfgGetBool(f, "CheckServerCert");
	a->CreateDateTime = CfgGetInt64(f, "CreateDateTime");
	a->UpdateDateTime = CfgGetInt64(f, "UpdateDateTime");
	a->LastConnectDateTime = CfgGetInt64(f, "LastConnectDateTime");

	b = CfgGetBuf(f, "ServerCert");
	if (b != NULL)
	{
		a->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}

	if (CfgGetStr(f, "ShortcutKey", tmp, sizeof(tmp)))
	{
		BUF *b = StrToBin(tmp);
		if (b->Size == SHA1_SIZE)
		{
			Copy(a->ShortcutKey, b->Buf, SHA1_SIZE);
		}
		FreeBuf(b);
	}

	if (IsZero(a->ShortcutKey, SHA1_SIZE))
	{
		Rand(a->ShortcutKey, SHA1_SIZE);
	}

	return a;
}

// アカウントデータベースの読み込み
void CiLoadAccountDatabase(CLIENT *c, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = CfgGetFolder(f, t->Token[i]);

		if (ff != NULL)
		{
			ACCOUNT *a = CiLoadClientAccount(ff);
			if (a != NULL)
			{
				Add(c->AccountList, a);
			}
		}
	}

	Sort(c->AccountList);

	FreeToken(t);
}

// ルート CA 証明書を読み込む
void CiLoadCACert(CLIENT *c, FOLDER *f)
{
	BUF *b;
	X *x;
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	b = CfgGetBuf(f, "X509");
	if (b == NULL)
	{
		return;
	}

	x = BufToX(b, false);

	AddCa(c->Cedar, x);

	FreeX(x);

	FreeBuf(b);
}

// ルート CA リストを読み込む
void CiLoadCAList(CLIENT *c, FOLDER *f)
{
	CEDAR *cedar;
	TOKEN_LIST *t;
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	cedar = c->Cedar;

	LockList(cedar->CaList);
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			FOLDER *folder = CfgGetFolder(f, t->Token[i]);
			CiLoadCACert(c, folder);
		}
	}
	UnlockList(cedar->CaList);

	FreeToken(t);
}

// VLAN を読み込む
void CiLoadVLan(CLIENT *c, FOLDER *f)
{
	char tmp[MAX_SIZE];
	UCHAR addr[6];
	BUF *b;
	UNIX_VLAN *v;
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	if (CfgGetStr(f, "MacAddress", tmp, sizeof(tmp)) == false)
	{
		return;
	}

	b = StrToBin(tmp);
	if (b == NULL)
	{
		return;
	}

	if (b->Size != 6)
	{
		FreeBuf(b);
		return;
	}

	Copy(addr, b->Buf, 6);

	FreeBuf(b);

	if (IsZero(addr, 6))
	{
		return;
	}

	v = ZeroMalloc(sizeof(UNIX_VLAN));
	Copy(v->MacAddress, addr, 6);
	StrCpy(v->Name, sizeof(v->Name), f->Name);
	v->Enabled = CfgGetBool(f, "Enabled");

	Add(c->UnixVLanList, v);

#ifdef	OS_UNIX
	UnixVLanCreate(v->Name, v->MacAddress);
#endif	// OS_UNIX
}

// VLAN リストを読み込む
void CiLoadVLanList(CLIENT *c, FOLDER *f)
{
	TOKEN_LIST *t;
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	LockList(c->UnixVLanList);
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			FOLDER *folder = CfgGetFolder(f, t->Token[i]);
			CiLoadVLan(c, folder);
		}
	}
	UnlockList(c->UnixVLanList);

	FreeToken(t);
}

// 設定ファイルから設定の読み込み
bool CiReadSettingFromCfg(CLIENT *c, FOLDER *root)
{
	FOLDER *config;
	FOLDER *cert;
	FOLDER *db;
	FOLDER *vlan;
	FOLDER *cmsetting;
	char user_agent[MAX_SIZE];
	// 引数チェック
	if (c == NULL || root == NULL)
	{
		return false;
	}

	// Config と AccountDatabase の両方が無い場合は設定を初期化する
	config = CfgGetFolder(root, "Config");
	if (config == NULL)
	{
		return false;
	}

	db = CfgGetFolder(root, "AccountDatabase");
	if (db == NULL)
	{
		return false;
	}

	cmsetting = CfgGetFolder(root, "ClientManagerSetting");

	CiLoadClientConfig(&c->Config, config);

	// 自動ファイル削除器
	c->Eraser = NewEraser(c->Logger, CfgGetInt64(config, "AutoDeleteCheckDiskFreeSpaceMin"));

	if (OS_IS_UNIX(GetOsInfo()->OsType) && GetOsInfo()->OsType != OSTYPE_MACOS_X)
	{
		// Unix 版仮想 LAN カード一覧の読み込み (MacOS の場合はしない)
		vlan = CfgGetFolder(root, "UnixVLan");
		if (vlan != NULL)
		{
			CiLoadVLanList(c, vlan);
		}
	}

	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
#ifdef	OS_UNIX
		UNIX_VLAN *uv;

		// MacOS X の場合は Tap を作成する
		if (UnixVLanCreate(CLIENT_MACOS_TAP_NAME, NULL) == false)
		{
			// 失敗 (強制終了)
			CLog(c, "LC_TAP_NOT_FOUND");
			Alert("tun/tap driver not found.", NULL);
			exit(0);
		}

		uv = ZeroMalloc(sizeof(UNIX_VLAN));
		uv->Enabled = true;
		StrCpy(uv->Name, sizeof(uv->Name), CLIENT_MACOS_TAP_NAME);
		Add(c->UnixVLanList, uv);
#endif	// OS_UNIX
	}

	CiLoadAccountDatabase(c, db);

	if (CfgGetByte(root, "EncryptedPassword", c->EncryptedPassword, SHA1_SIZE) == false)
	{
		Hash(c->EncryptedPassword, "", 0, true);
	}

	c->PasswordRemoteOnly = CfgGetBool(root, "PasswordRemoteOnly");
	c->UseSecureDeviceId = CfgGetInt(root, "UseSecureDeviceId");

	if (CfgGetStr(root, "UserAgent", user_agent, sizeof(user_agent)))
	{
		if (IsEmptyStr(user_agent) == false)
		{
			Free(c->Cedar->HttpUserAgent);
			c->Cedar->HttpUserAgent = CopyStr(user_agent);
		}
	}

	cert = CfgGetFolder(root, "RootCA");
	if (cert != NULL)
	{
		CiLoadCAList(c, cert);
	}

	c->DontSavePassword = CfgGetBool(root, "DontSavePassword");

	if (cmsetting != NULL)
	{
		UINT ostype = GetOsInfo()->OsType;
		// CM_SETTING
		CM_SETTING *s = c->CmSetting;

		if (OS_IS_UNIX(ostype) || OS_IS_WINDOWS_NT(ostype))
		{
			s->EasyMode = CfgGetBool(cmsetting, "EasyMode");
		}

		s->LockMode = CfgGetBool(cmsetting, "LockMode");
		CfgGetByte(cmsetting, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));
	}

	return true;
}

// 設定ファイルの読み込み
bool CiLoadConfigurationFile(CLIENT *c)
{
	bool ret;
	FOLDER *root;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	// 設定ファイルの読み込み
	c->CfgRw = NewCfgRw(&root, CLIENT_CONFIG_FILE_NAME);

	if (root == NULL)
	{
		return false;
	}

	ret = CiReadSettingFromCfg(c, root);

	CfgDeleteFolder(root);

	return ret;
}

// CLIENT_CONFIG を書き込む
void CiWriteClientConfig(FOLDER *cc, CLIENT_CONFIG *config)
{
	// 引数チェック
	if (cc == NULL || config == NULL)
	{
		return;
	}

	CfgAddBool(cc, "UseKeepConnect", config->UseKeepConnect);
	CfgAddStr(cc, "KeepConnectHost", config->KeepConnectHost);
	CfgAddInt(cc, "KeepConnectPort", config->KeepConnectPort);
	CfgAddInt(cc, "KeepConnectProtocol", config->KeepConnectProtocol);
	CfgAddBool(cc, "AllowRemoteConfig", config->AllowRemoteConfig);
	CfgAddInt(cc, "KeepConnectInterval", config->KeepConnectInterval);
}

// クライアント認証データを書き込む
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a)
{
	BUF *b;
	// 引数チェック
	if (f == NULL || a == NULL)
	{
		return;
	}

	CfgAddInt(f, "AuthType", a->AuthType);
	CfgAddStr(f, "Username", a->Username);

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		CfgAddByte(f, "HashedPassword", a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		b = EncryptPassword(a->PlainPassword);
		CfgAddByte(f, "EncryptedPassword", b->Buf, b->Size);
		FreeBuf(b);
		break;

	case CLIENT_AUTHTYPE_CERT:
		if (a->ClientK != NULL && a->ClientX != NULL)
		{
			b = XToBuf(a->ClientX, false);
			CfgAddByte(f, "ClientCert", b->Buf, b->Size);
			FreeBuf(b);

			b = KToBuf(a->ClientK, false, NULL);
			CfgAddByte(f, "ClientKey", b->Buf, b->Size);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_SECURE:
		CfgAddStr(f, "SecurePublicCertName", a->SecurePublicCertName);
		CfgAddStr(f, "SecurePrivateKeyName", a->SecurePrivateKeyName);
		break;
	}
}

// クライアントオプションを書き込む
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o)
{
	BUF *b;
	// 引数チェック
	if (f == NULL || o == NULL)
	{
		return;
	}

	CfgAddUniStr(f, "AccountName", o->AccountName);
	CfgAddStr(f, "Hostname", o->Hostname);
	CfgAddInt(f, "Port", o->Port);
	CfgAddInt(f, "PortUDP", o->PortUDP);
	CfgAddInt(f, "ProxyType", o->ProxyType);
	CfgAddStr(f, "ProxyName", o->ProxyName);
	CfgAddInt(f, "ProxyPort", o->ProxyPort);
	CfgAddStr(f, "ProxyUsername", o->ProxyUsername);
	b = EncryptPassword(o->ProxyPassword);
	CfgAddByte(f, "ProxyPassword", b->Buf, b->Size);
	FreeBuf(b);
	CfgAddInt(f, "NumRetry", o->NumRetry);
	CfgAddInt(f, "RetryInterval", o->RetryInterval);
	CfgAddStr(f, "HubName", o->HubName);
	CfgAddInt(f, "MaxConnection", o->MaxConnection);
	CfgAddBool(f, "UseEncrypt", o->UseEncrypt);
	CfgAddBool(f, "UseCompress", o->UseCompress);
	CfgAddBool(f, "HalfConnection", o->HalfConnection);
	CfgAddBool(f, "NoRoutingTracking", o->NoRoutingTracking);
	CfgAddStr(f, "DeviceName", o->DeviceName);
	CfgAddInt(f, "AdditionalConnectionInterval", o->AdditionalConnectionInterval);
	CfgAddBool(f, "HideStatusWindow", o->HideStatusWindow);
	CfgAddBool(f, "HideNicInfoWindow", o->HideNicInfoWindow);
	CfgAddInt(f, "ConnectionDisconnectSpan", o->ConnectionDisconnectSpan);
	CfgAddBool(f, "RequireMonitorMode", o->RequireMonitorMode);
	CfgAddBool(f, "RequireBridgeRoutingMode", o->RequireBridgeRoutingMode);
	CfgAddBool(f, "DisableQoS", o->DisableQoS);
	CfgAddBool(f, "NoTls1", o->NoTls1);

	if (o->FromAdminPack)
	{
		CfgAddBool(f, "FromAdminPack", o->FromAdminPack);
	}
}

// パスワードの解読
char *DecryptPassword(BUF *b)
{
	char *str;
	char *key = "EncryptPassword";
	CRYPT *c;
	// 引数チェック
	if (b == NULL)
	{
		return CopyStr("");
	}

	str = ZeroMalloc(b->Size + 1);
	c = NewCrypt(key, sizeof(key));
	Encrypt(c, str, b->Buf, b->Size);
	FreeCrypt(c);

	str[b->Size] = 0;

	return str;
}

// パスワードの暗号化
BUF *EncryptPassword(char *password)
{
	UCHAR *tmp;
	UINT size;
	char *key = "EncryptPassword";
	CRYPT *c;
	BUF *b;
	// 引数チェック
	if (password == NULL)
	{
		password = "";
	}

	size = StrLen(password) + 1;
	tmp = ZeroMalloc(size);

	c = NewCrypt(key, sizeof(key));
	Encrypt(c, tmp, password, size - 1);
	FreeCrypt(c);

	b = NewBuf();
	WriteBuf(b, tmp, size - 1);
	SeekBuf(b, 0, 0);
	Free(tmp);

	return b;
}

// アカウントデータを書き込む
void CiWriteAccountData(FOLDER *f, ACCOUNT *a)
{
	// 引数チェック
	if (f == NULL || a == NULL)
	{
		return;
	}

	// クライアントオプション
	CiWriteClientOption(CfgCreateFolder(f, "ClientOption"), a->ClientOption);

	// クライアント認証データ
	CiWriteClientAuth(CfgCreateFolder(f, "ClientAuth"), a->ClientAuth);

	// スタートアップアカウント
	CfgAddBool(f, "StartupAccount", a->StartupAccount);

	// サーバー証明書チェックフラグ
	CfgAddBool(f, "CheckServerCert", a->CheckServerCert);

	// 日時
	CfgAddInt64(f, "CreateDateTime", a->CreateDateTime);
	CfgAddInt64(f, "UpdateDateTime", a->UpdateDateTime);
	CfgAddInt64(f, "LastConnectDateTime", a->LastConnectDateTime);

	// サーバー証明書本体
	if (a->ServerCert != NULL)
	{
		BUF *b = XToBuf(a->ServerCert, false);
		if (b != NULL)
		{
			CfgAddBuf(f, "ServerCert", b);
			FreeBuf(b);
		}
	}

	// ショートカットキー
	if (IsZero(a->ShortcutKey, SHA1_SIZE) == false)
	{
		char tmp[64];
		BinToStr(tmp, sizeof(tmp), a->ShortcutKey, SHA1_SIZE);
		CfgAddStr(f, "ShortcutKey", tmp);
	}
}

// アカウントデータベースを書き込む
void CiWriteAccountDatabase(CLIENT *c, FOLDER *f)
{
	char name[MAX_SIZE];
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	LockList(c->AccountList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			Format(name, sizeof(name), "Account%u", i);
			Lock(a->lock);
			{
				CiWriteAccountData(CfgCreateFolder(f, name), a);
			}
			Unlock(a->lock);
		}
	}
	UnlockList(c->AccountList);
}

// CA 証明書を書き込む
void CiWriteCACert(CLIENT *c, FOLDER *f, X *x)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || f == NULL || x == NULL)
	{
		return;
	}

	b = XToBuf(x, false);
	CfgAddBuf(f, "X509", b);
	FreeBuf(b);
}

// VLAN を書き込む
void CiWriteVLan(CLIENT *c, FOLDER *f, UNIX_VLAN *v)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (c == NULL || f == NULL || v == NULL)
	{
		return;
	}

	MacToStr(tmp, sizeof(tmp), v->MacAddress);
	CfgAddStr(f, "MacAddress", tmp);
	CfgAddBool(f, "Enabled", v->Enabled);
}

// VLAN リストを書き込む
void CiWriteVLanList(CLIENT *c, FOLDER *f)
{
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	LockList(c->UnixVLanList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->UnixVLanList);i++)
		{
			UNIX_VLAN *v = LIST_DATA(c->UnixVLanList, i);
			CiWriteVLan(c, CfgCreateFolder(f, v->Name), v);
		}
	}
	UnlockList(c->UnixVLanList);
}

// CA リストを書き込む
void CiWriteCAList(CLIENT *c, FOLDER *f)
{
	CEDAR *cedar;
	// 引数チェック
	if (c == NULL || f == NULL)
	{
		return;
	}

	cedar = c->Cedar;

	LockList(cedar->CaList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(cedar->CaList);i++)
		{
			char tmp[MAX_SIZE];
			X *x = LIST_DATA(cedar->CaList, i);
			Format(tmp, sizeof(tmp), "Certificate%u", i);
			CiWriteCACert(c, CfgCreateFolder(f, tmp), x);
		}
	}
	UnlockList(cedar->CaList);
}

// 現在の設定を ROOT に書き込む
void CiWriteSettingToCfg(CLIENT *c, FOLDER *root)
{
	FOLDER *cc;
	FOLDER *account_database;
	FOLDER *ca;
	FOLDER *vlan;
	FOLDER *cmsetting;
	// 引数チェック
	if (c == NULL || root == NULL)
	{
		return;
	}

	cmsetting = CfgCreateFolder(root, "ClientManagerSetting");

	// CLIENT_CONFIG
	cc = CfgCreateFolder(root, "Config");
	CiWriteClientConfig(cc, &c->Config);

	// 自動ファイル削除器
	CfgAddInt64(cc, "AutoDeleteCheckDiskFreeSpaceMin", c->Eraser->MinFreeSpace);

	// Account Database
	account_database = CfgCreateFolder(root, "AccountDatabase");
	CiWriteAccountDatabase(c, account_database);

	// CA
	ca = CfgCreateFolder(root, "RootCA");
	CiWriteCAList(c, ca);

	// VLAN
	if (OS_IS_UNIX(GetOsInfo()->OsType) && GetOsInfo()->OsType != OSTYPE_MACOS_X)
	{
		vlan = CfgCreateFolder(root, "UnixVLan");
		CiWriteVLanList(c, vlan);
	}

	// Password
	CfgAddByte(root, "EncryptedPassword", c->EncryptedPassword, SHA1_SIZE);
	CfgAddBool(root, "PasswordRemoteOnly", c->PasswordRemoteOnly);

	// UseSecureDeviceId
	CfgAddInt(root, "UseSecureDeviceId", c->UseSecureDeviceId);

	// DontSavePassword
	CfgAddBool(root, "DontSavePassword", c->DontSavePassword);

	// UserAgent
	if (c->Cedar != NULL)
	{
		CfgAddStr(root, "UserAgent", c->Cedar->HttpUserAgent);
	}

	if (cmsetting != NULL)
	{
		CM_SETTING *s = c->CmSetting;

		CfgAddBool(cmsetting, "EasyMode", s->EasyMode);
		CfgAddBool(cmsetting, "LockMode", s->LockMode);

		if (IsZero(s->HashedPassword, sizeof(s->HashedPassword)) == false)
		{
			CfgAddByte(cmsetting, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));
		}
	}
}

// 設定ファイルへ書き込み
void CiSaveConfigurationFile(CLIENT *c)
{
	FOLDER *root;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}
	
	// 設定ファイルを保存しない
	if(c->NoSaveConfig)
	{
		return;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);
	CiWriteSettingToCfg(c, root);

	SaveCfgRw(c->CfgRw, root);

	CfgDeleteFolder(root);
}

// CM_SETTING の設定
bool CtSetCmSetting(CLIENT *c, CM_SETTING *s)
{
	// 引数チェック
	if (c == NULL || s == NULL)
	{
		return false;
	}

	Copy(c->CmSetting, s, sizeof(CM_SETTING));

	CiSaveConfigurationFile(c);

	return true;
}

// CM_SETTING の取得
bool CtGetCmSetting(CLIENT *c, CM_SETTING *s)
{
	// 引数チェック
	if (c == NULL || s == NULL)
	{
		return false;
	}

	Copy(s, c->CmSetting, sizeof(CM_SETTING));
	
	return true;
}

// クライアントバージョンの取得
bool CtGetClientVersion(CLIENT *c, RPC_CLIENT_VERSION *ver)
{
	// 引数チェック
	if (ver == NULL)
	{
		return false;
	}

	Zero(ver, sizeof(RPC_CLIENT_VERSION));
	StrCpy(ver->ClientProductName, sizeof(ver->ClientProductName), CEDAR_CLIENT_STR);
	StrCpy(ver->ClientVersionString, sizeof(ver->ClientVersionString), c->Cedar->VerString);
	StrCpy(ver->ClientBuildInfoString, sizeof(ver->ClientBuildInfoString), c->Cedar->BuildInfo);
	ver->ClientVerInt = c->Cedar->Version;
	ver->ClientBuildInt = c->Cedar->Build;

#ifdef	OS_WIN32
	ver->ProcessId = MsGetProcessId();
#endif	// OS_WIN32

	ver->OsType = GetOsInfo()->OsType;

	return true;
}

// クライアントオブジェクトの作成
CLIENT *CiNewClient()
{
	CLIENT *c = ZeroMalloc(sizeof(CLIENT));

//	StartCedarLog();

	c->CmSetting = ZeroMalloc(sizeof(CM_SETTING));

	c->SockList = NewSockList();

	c->lock = NewLock();
	c->lockForConnect = NewLock();
	c->ref = NewRef();

	c->Cedar = NewCedar(NULL, NULL);

	c->Cedar->Client = c;

	c->NotifyCancelList = NewList(NULL);

	Hash(c->EncryptedPassword, "", 0, true);

	// ログ設定
	if(c->NoSaveLog == false)
	{
		MakeDir(CLIENT_LOG_DIR_NAME);
		c->Logger = NewLog(CLIENT_LOG_DIR_NAME, CLIENT_LOG_PREFIX, LOG_SWITCH_DAY);
	}

	CLog(c, "L_LINE");
	CLog(c, "LC_START_2", CEDAR_CLIENT_STR, c->Cedar->VerString);
	CLog(c, "LC_START_3", c->Cedar->BuildInfo);
	CLog(c, "LC_START_1");

#ifdef	OS_WIN32
	{
		// Win32 UI の初期化
		wchar_t tmp[MAX_SIZE];
		StrToUni(tmp, sizeof(tmp), CEDAR_CLIENT_STR);

		InitWinUi(tmp, _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));
	}
#endif	// OS_WIN32

	// 設定の初期化
	CiInitConfiguration(c);

	// 優先順位を上げる
	OSSetHighPriority();

#ifdef	OS_WIN32
	// Win9x の場合、すべての仮想 LAN カードの DHCP アドレスを解放する
	if (MsIsNt() == false)
	{
		Win32ReleaseAllDhcp9x(true);
	}
#endif	// OS_WIN32

	CiChangeAllVLanMacAddressIfMachineChanged(c);

	return c;
}

// クライアントのクリーンアップ
void CiCleanupClient(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// 設定の解放
	CiFreeConfiguration(c);

#ifdef	OS_WIN32
	// Win32 UI の解放
	FreeWinUi();
#endif	// OS_WIN32

	CLog(c, "LC_END");
	CLog(c, "L_LINE");
	FreeEraser(c->Eraser);
	FreeLog(c->Logger);
	c->Logger = NULL;

	ReleaseCedar(c->Cedar);

	DeleteLock(c->lockForConnect);
	DeleteLock(c->lock);

	ReleaseList(c->NotifyCancelList);

	FreeSockList(c->SockList);

	Free(c->CmSetting);

	Free(c);

#ifdef	OS_WIN32
	// Win9x の場合、すべての仮想 LAN カードの DHCP アドレスを解放する
	if (MsIsNt() == false)
	{
		Win32ReleaseAllDhcp9x(true);
	}
#endif	// OS_WIN32

	StopCedarLog();
}

// クライアントの解放
void CtReleaseClient(CLIENT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CiCleanupClient(c);
	}
}

// クライアントプログラムの動作開始
void CtStartClient()
{
	UINT i;
	LIST *o;
	if (client != NULL)
	{
		// すでに動作している
		return;
	}

	// OS チェック
	CiCheckOs();

#ifdef	OS_WIN32
	RegistWindowsFirewallAll();
#endif

	// クライアントの作成
	client = CiNewClient();

	// Keep を開始
	CiInitKeep(client);

	// RPC サーバーを開始
	CiStartRpcServer(client);

	// 設定データ自動保存を開始
	CiInitSaver(client);

	// スタートアップ接続を開始する
	o = NewListFast(NULL);
	LockList(client->AccountList);
	{
		for (i = 0;i < LIST_NUM(client->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(client->AccountList, i);
			Lock(a->lock);
			{
				if (a->StartupAccount)
				{
					Add(o, CopyUniStr(a->ClientOption->AccountName));
				}
			}
			Unlock(a->lock);
		}
	}
	UnlockList(client->AccountList);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		RPC_CLIENT_CONNECT c;
		Zero(&c, sizeof(c));
		UniStrCpy(c.AccountName, sizeof(c.AccountName), s);
		CtConnect(client, &c);
		Free(s);
	}
	ReleaseList(o);
}

// クライアントプログラムの動作終了
void CtStopClient()
{
	UINT i, num;
	ACCOUNT **account_list;
	if (client == NULL)
	{
		// まだ動作していない
		return;
	}

	// 停止フラグ
	client->Halt = true;

	// RPC をすべて切断
	CiStopRpcServer(client);

	// クライアント通知サービスを終了
	CncExit();

	// Keep を終了
	CiFreeKeep(client);

	// 接続中のアカウントをすべて切断
	LockList(client->AccountList);
	{
		num = LIST_NUM(client->AccountList);
		account_list = ToArray(client->AccountList);
	}
	UnlockList(client->AccountList);

	for (i = 0;i < num;i++)
	{
		ACCOUNT *a = account_list[i];
		SESSION *s = NULL;

		Lock(a->lock);
		{
			if (a->ClientSession != NULL)
			{
				s = a->ClientSession;
				AddRef(s->ref);
			}
		}
		Unlock(a->lock);

		if (s != NULL)
		{
			StopSession(s);
			ReleaseSession(s);
			Lock(a->lock);
			{
				if (a->ClientSession != NULL)
				{
					ReleaseSession(a->ClientSession);
					a->ClientSession = NULL;
				}
			}
			Unlock(a->lock);
		}
	}

	Free(account_list);

	// 設定データ自動保存を停止
	CiFreeSaver(client);

	// クライアントの解放
	CtReleaseClient(client);
	client = NULL;
}

// OS チェック
void CiCheckOs()
{
	// OS の種類の取得
	OS_INFO *info = GetOsInfo();

	if (OS_IS_WINDOWS(info->OsType))
	{
		bool ok = IS_CLIENT_SUPPORTED_OS(info->OsType);

		if (ok == false)
		{
			Alert(
				"SoftEther UT-VPN Client doesn't support this Windows Operating System.\n"
				"SoftEther UT-VPN Client requires Windows 98 SE, Windows Me, Windows 2000, Windows XP, Windows Server 2003 or Greater.\n\n"
				"Please contact your system administrator.", "SoftEther UT-VPN Client");
			exit(0);
		}
	}
}

// クライアントオブジェクトの取得
CLIENT *CtGetClient()
{
	if (client == NULL)
	{
		return NULL;
	}

	AddRef(client->ref);

	return client;
}

// クライアントステータス表示器
void CiClientStatusPrinter(SESSION *s, wchar_t *status)
{
#ifdef	OS_WIN32
	ACCOUNT *a;
	// 引数チェック
	if (s == NULL || status == NULL)
	{
		return;
	}

	a = s->Account;
	if (a == NULL)
	{
		return;
	}

	if (UniStrCmpi(status, L"init") == 0)
	{
		if (a->StatusWindow == NULL && s->Win32HideConnectWindow == false)
		{
			a->StatusWindow = CncStatusPrinterWindowStart(s);
		}
	}
	else if (UniStrCmpi(status, L"free") == 0)
	{
		if (a->StatusWindow != NULL)
		{
			CncStatusPrinterWindowStop(a->StatusWindow);
			a->StatusWindow = NULL;
		}
	}
	else
	{
		if (a->StatusWindow != NULL)
		{
			CncStatusPrinterWindowPrint(a->StatusWindow, status);
		}
	}
#else	// OS_WIN32
	UniPrint(L"Status: %s\n", status);
#endif	// OS_WIN32
}


