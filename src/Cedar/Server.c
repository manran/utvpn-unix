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

// Server.c
// サーバーマネージャ

#include "CedarPch.h"

static SERVER *server = NULL;
static LOCK *server_lock = NULL;
char *SERVER_CONFIG_FILE_NAME = "@vpn_server.config";
char *BRIDGE_CONFIG_FILE_NAME = "@vpn_bridge.config";

static bool server_reset_setting = false;

// VPN Server に登録されているユーザーオブジェクト数が多すぎるかどうか取得
bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore)
{
	LICENSE_STATUS st;
	UINT num;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	num = SiGetServerNumUserObjects(s);

	Zero(&st, sizeof(st));

	LiParseCurrentLicenseStatus(s->LicenseSystem, &st);

	if (st.NumUserLicense == INFINITE)
	{
		return false;
	}

	if (oneMore)
	{
		st.NumUserLicense++;
	}

	if (st.NumUserLicense <= num)
	{
		return true;
	}

	return false;
}

// VPN Server に登録されているユーザーオブジェクト数を取得
UINT SiGetServerNumUserObjects(SERVER *s)
{
	CEDAR *c;
	UINT ret = 0;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	c = s->Cedar;

	LockList(c->HubList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);

			if (h->HubDb != NULL)
			{
				ret += LIST_NUM(h->HubDb->UserList);
			}
		}
	}
	UnlockList(c->HubList);

	return ret;
}


typedef struct SI_DEBUG_PROC_LIST
{
	UINT Id;
	char *Description;
	char *Args;
	SI_DEBUG_PROC *Proc;
} SI_DEBUG_PROC_LIST;

// デバッグ機能
UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str)
{
	SI_DEBUG_PROC_LIST proc_list[] =
	{
		{1, "Hello World", "<test string>", SiDebugProcHelloWorld},
		{2, "Terminate process now", "", SiDebugProcExit},
		{3, "Write memory dumpfile", "", SiDebugProcDump},
		{4, "Restore process priority", "", SiDebugProcRestorePriority},
		{5, "Set the process priority high", "", SiDebugProcSetHighPriority},
		{6, "Get the .exe filename of the process", "", SiDebugProcGetExeFileName},
		{7, "Crash the process", "", SiDebugProcCrash},
	};
	UINT num_proc_list = sizeof(proc_list) / sizeof(proc_list[0]);
	UINT j;
	UINT ret_value = ERR_NO_ERROR;
	// 引数チェック
	if (s == NULL || ret == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (i == 0)
	{
		char tmp[MAX_SIZE];
		Zero(ret, sizeof(RPC_TEST));

		StrCat(ret->StrValue, sizeof(ret->StrValue),
			"\n--- Debug Functions List --\n");

		for (j = 0;j < num_proc_list;j++)
		{
			SI_DEBUG_PROC_LIST *p = &proc_list[j];

			if (IsEmptyStr(p->Args) == false)
			{
				Format(tmp, sizeof(tmp),
					" %u: %s - Usage: %u /ARGS:\"%s\"\n",
					p->Id, p->Description, p->Id, p->Args);
			}
			else
			{
				Format(tmp, sizeof(tmp),
					" %u: %s - Usage: %u\n",
					p->Id, p->Description, p->Id);
			}

			StrCat(ret->StrValue, sizeof(ret->StrValue), tmp);
		}
	}
	else
	{
		ret_value = ERR_NOT_SUPPORTED;

		for (j = 0;j < num_proc_list;j++)
		{
			SI_DEBUG_PROC_LIST *p = &proc_list[j];

			if (p->Id == i)
			{
				ret_value = p->Proc(s, str, ret->StrValue, sizeof(ret->StrValue));

				if (ret_value == ERR_NO_ERROR && IsEmptyStr(ret->StrValue))
				{
					StrCpy(ret->StrValue, sizeof(ret->StrValue), "Ok.");
				}
				break;
			}
		}
	}

	return ret_value;
}
UINT SiDebugProcHelloWorld(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// 引数チェック
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Format(ret_str, ret_str_size, "Hello World %s\n", in_str);

	return ERR_NO_ERROR;
}
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// 引数チェック
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	_exit(1);

	return ERR_NO_ERROR;
}
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// 引数チェック
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

#ifdef	OS_WIN32
	MsWriteMinidump(NULL, NULL);
#else	// OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif	// OS_WIN32

	return ERR_NO_ERROR;
}
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// 引数チェック
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSRestorePriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// 引数チェック
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSSetHighPriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// 引数チェック
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	GetExeName(ret_str, ret_str_size);

	return ERR_NO_ERROR;
}
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// 引数チェック
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CrashNow();

	return ERR_NO_ERROR;
}

// デバッグログの書き込み
void SiDebugLog(SERVER *s, char *msg)
{
	// 引数チェック
	if (s == NULL || msg == NULL)
	{
		return;
	}

	if (s->DebugLog != NULL)
	{
		WriteTinyLog(s->DebugLog, msg);
	}
}

// デッドロック検査メイン
void SiCheckDeadLockMain(SERVER *s, UINT timeout)
{
	CEDAR *cedar;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Debug("SiCheckDeadLockMain Start.\n");

	cedar = s->Cedar;

	if (s->ServerListenerList != NULL)
	{
		CheckDeadLock(s->ServerListenerList->lock, timeout, "s->ServerListenerList->lock");
	}

	CheckDeadLock(s->lock, timeout, "s->lock");

	if (s->FarmMemberList != NULL)
	{
		CheckDeadLock(s->FarmMemberList->lock, timeout, "s->FarmMemberList->lock");
	}

	if (s->HubCreateHistoryList != NULL)
	{
		CheckDeadLock(s->HubCreateHistoryList->lock, timeout, "s->HubCreateHistoryList->lock");
	}

	CheckDeadLock(s->CapsCacheLock, timeout, "s->CapsCacheLock");

	CheckDeadLock(s->TasksFromFarmControllerLock, timeout, "s->TasksFromFarmControllerLock");

	if (cedar != NULL)
	{
		if (cedar->HubList != NULL)
		{
			CheckDeadLock(cedar->HubList->lock, timeout, "cedar->HubList->lock");
		}

		if (cedar->ListenerList != NULL)
		{
			UINT i;
			LIST *o = NewListFast(NULL);

			CheckDeadLock(cedar->ListenerList->lock, timeout, "cedar->ListenerList->lock");

			LockList(cedar->ListenerList);
			{
				for (i = 0;i < LIST_NUM(cedar->ListenerList);i++)
				{
					LISTENER *r = LIST_DATA(cedar->ListenerList, i);

					AddRef(r->ref);

					Add(o, r);
				}
			}
			UnlockList(cedar->ListenerList);

			for (i = 0;i < LIST_NUM(o);i++)
			{
				LISTENER *r = LIST_DATA(o, i);

				ReleaseListener(r);
			}

			ReleaseList(o);
		}

		if (cedar->ConnectionList != NULL)
		{
			CheckDeadLock(cedar->ConnectionList->lock, timeout, "cedar->ConnectionList->lock");
		}

		if (cedar->CaList != NULL)
		{
			CheckDeadLock(cedar->CaList->lock, timeout, "cedar->CaList->lock");
		}

		if (cedar->TrafficLock != NULL)
		{
			CheckDeadLock(cedar->TrafficLock, timeout, "cedar->TrafficLock");
		}

		if (cedar->TrafficDiffList != NULL)
		{
			CheckDeadLock(cedar->TrafficDiffList->lock, timeout, "cedar->TrafficDiffList->lock");
		}

		if (cedar->LocalBridgeList != NULL)
		{
			CheckDeadLock(cedar->LocalBridgeList->lock, timeout, "cedar->LocalBridgeList->lock");
		}

		if (cedar->L3SwList != NULL)
		{
			CheckDeadLock(cedar->L3SwList->lock, timeout, "cedar->L3SwList->lock");
		}
	}

	Debug("SiCheckDeadLockMain Finish.\n");
}

// デッドロックチェックスレッド
void SiDeadLockCheckThread(THREAD *t, void *param)
{
	SERVER *s = (SERVER *)param;
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	while (true)
	{
		Wait(s->DeadLockWaitEvent, SERVER_DEADLOCK_CHECK_SPAN);

		if (s->HaltDeadLockThread)
		{
			break;
		}

		SiCheckDeadLockMain(s, SERVER_DEADLOCK_CHECK_TIMEOUT);
	}
}

// デッドロックチェックの初期化
void SiInitDeadLockCheck(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}
	if (s->DisableDeadLockCheck)
	{
		return;
	}

	s->HaltDeadLockThread = false;
	s->DeadLockWaitEvent = NewEvent();
	s->DeadLockCheckThread = NewThread(SiDeadLockCheckThread, s);
}

// デッドロックチェックの解放
void SiFreeDeadLockCheck(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (s->DeadLockCheckThread == NULL)
	{
		return;
	}

	s->HaltDeadLockThread = true;
	Set(s->DeadLockWaitEvent);

	WaitThread(s->DeadLockCheckThread, INFINITE);

	ReleaseThread(s->DeadLockCheckThread);
	s->DeadLockCheckThread = NULL;

	ReleaseEvent(s->DeadLockWaitEvent);
	s->DeadLockWaitEvent = NULL;

	s->HaltDeadLockThread = false;
}

// 指定した仮想 HUB が作成履歴に登録されているかどうか調べる
bool SiIsHubRegistedOnCreateHistory(SERVER *s, char *name)
{
	UINT i;
	bool ret = false;
	// 引数チェック
	if (s == NULL || name == NULL)
	{
		return false;
	}

	SiDeleteOldHubCreateHistory(s);

	LockList(s->HubCreateHistoryList);
	{
		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if (StrCmpi(h->HubName, name) == 0)
			{
				ret = true;
				break;
			}
		}
	}
	UnlockList(s->HubCreateHistoryList);

	return ret;
}

// 仮想 HUB 作成履歴の削除
void SiDelHubCreateHistory(SERVER *s, char *name)
{
	UINT i;
	// 引数チェック
	if (s == NULL || name == NULL)
	{
		return;
	}

	LockList(s->HubCreateHistoryList);
	{
		SERVER_HUB_CREATE_HISTORY *hh = NULL;
		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if (StrCmpi(h->HubName, name) == 0)
			{
				Delete(s->HubCreateHistoryList, h);
				Free(h);
				break;
			}
		}
	}
	UnlockList(s->HubCreateHistoryList);

	SiDeleteOldHubCreateHistory(s);
}

// 仮想 HUB 作成履歴への登録
void SiAddHubCreateHistory(SERVER *s, char *name)
{
	UINT i;
	// 引数チェック
	if (s == NULL || name == NULL)
	{
		return;
	}

	LockList(s->HubCreateHistoryList);
	{
		SERVER_HUB_CREATE_HISTORY *hh = NULL;
		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if (StrCmpi(h->HubName, name) == 0)
			{
				hh = h;
				break;
			}
		}

		if (hh == NULL)
		{
			hh = ZeroMalloc(sizeof(SERVER_HUB_CREATE_HISTORY));
			StrCpy(hh->HubName, sizeof(hh->HubName), name);

			Add(s->HubCreateHistoryList, hh);
		}

		hh->CreatedTime = Tick64();
	}
	UnlockList(s->HubCreateHistoryList);

	SiDeleteOldHubCreateHistory(s);
}

// 古くなった仮想 HUB 作成履歴の削除
void SiDeleteOldHubCreateHistory(SERVER *s)
{
	UINT i;
	LIST *o;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	LockList(s->HubCreateHistoryList);
	{
		o = NewListFast(NULL);

		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if ((h->CreatedTime + ((UINT64)TICKET_EXPIRES)) <= Tick64())
			{
				// 有効期限切れ
				Add(o, h);
			}
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(o, i);

			Delete(s->HubCreateHistoryList, h);

			Free(h);
		}

		ReleaseList(o);
	}
	UnlockList(s->HubCreateHistoryList);
}

// 仮想 HUB 作成履歴の初期化
void SiInitHubCreateHistory(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	s->HubCreateHistoryList = NewList(NULL);
}

// 仮想 HUB 作成履歴の解放
void SiFreeHubCreateHistory(SERVER *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
	{
		SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

		Free(h);
	}

	ReleaseList(s->HubCreateHistoryList);

	s->HubCreateHistoryList = NULL;
}

// Admin Pack のインストーラ作成キットで作成した VPN Client が
// 接続可能なサーバーかどうか判別
bool IsAdminPackSupportedServerProduct(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return true;
	}

	return true;

#if	0
	// SoftEther UT-VPN ではこの制限はなくなった
	if (SearchStrEx(name, "home", 0, false) != INFINITE)
	{
		return false;
	}

	if (SearchStrEx(name, "soho", 0, false) != INFINITE)
	{
		return false;
	}

	if (SearchStrEx(name, "small business", 0, false) != INFINITE)
	{
		return false;
	}

	if (SearchStrEx(name, "standard", 0, false) != INFINITE)
	{
		return false;
	}

	return true;
#endif
}


// Server スナップショットの初期化
void InitServerSnapshot(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (s->Cedar->Bridge)
	{
		return;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return;
	}

	s->SnapshotLogger = NewLog(CE_SNAPSHOT_DIR_NAME, CE_SNAPSHOT_PREFIX, LOG_SWITCH_MONTH);
	s->LastSnapshotTime = SystemTime64();
	s->HaltSnapshot = false;
	s->SnapshotHaltEvent = NewEvent();
	s->SnapshotThread = NewThread(ServerSnapshotThread, s);
	s->SnapshotInited = true;
}

// Server スナップショットの解放
void FreeServerSnapshot(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}
	if (s->SnapshotInited == false)
	{
		return;
	}

	s->HaltSnapshot = true;
	Set(s->SnapshotHaltEvent);

	WaitThread(s->SnapshotThread, INFINITE);
	ReleaseThread(s->SnapshotThread);

	FreeLog(s->SnapshotLogger);
	ReleaseEvent(s->SnapshotHaltEvent);
}

// スナップショットをバッファに書き出す
BUF *ServerSnapshotToBuf(SERVER_SNAPSHOT *t)
{
	BUF *b = NewBuf();
	char tmp[MAX_SIZE * 3];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	UCHAR hash2[SHA1_SIZE];
	UINT i;
	// 引数チェック
	if (t == NULL)
	{
		return NULL;
	}

	WriteBufLine(b, "------------------------------------------------------");
	WriteBufLine(b, "[RECORD_INFO]");

	GetDateTimeStr64(tmp2, sizeof(tmp2), SystemToLocal64(t->DateTime));
	Format(tmp, sizeof(tmp), "DATETIME: %s", tmp2);
	WriteBufLine(b, tmp);

	IPToStr(tmp2, sizeof(tmp2), &t->ServerIp);
	Format(tmp, sizeof(tmp), "SERVER_IP: %s", tmp2);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "SERVER_HOSTNAME: %s", t->ServerHostname);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "SERVER_PRODUCT: %s", t->ServerProduct);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "SERVER_VERSION: %s", t->ServerVersion);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "SERVER_BUILD: %s", t->ServerBuild);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "SERVER_OS: %s", t->ServerOs);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "SERVER_LICENSE_ID: %I64u", t->ServerLicenseId);
	WriteBufLine(b, tmp);

	if (t->ServerLicenseExpires != 0)
	{
		GetDateTimeStr64(tmp2, sizeof(tmp2), SystemToLocal64(t->ServerLicenseExpires));
	}
	else
	{
		StrCpy(tmp2, sizeof(tmp2), "None");
	}
	Format(tmp, sizeof(tmp), "SERVER_LICENSE_EXPIRES: %s", tmp2);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "SERVER_TYPE: %u", t->ServerType);
	WriteBufLine(b, tmp);

	GetDateTimeStr64(tmp2, sizeof(tmp), SystemToLocal64(t->ServerStartupDatetime));
	Format(tmp, sizeof(tmp), "SERVER_STARTUP_DATETIME: %s", tmp2);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "NUMBER_OF_CLUSTER_NODES: %u", t->NumClusterNodes);
	WriteBufLine(b, tmp);

	Format(tmp, sizeof(tmp), "NUMBER_OF_HUBS: %u", LIST_NUM(t->HubList));
	WriteBufLine(b, tmp);

	for (i = 0;i < LIST_NUM(t->HubList);i++)
	{
		HUB_SNAPSHOT *h = LIST_DATA(t->HubList, i);
		Format(tmp, sizeof(tmp), "[HUB%u]", i);
		WriteBufLine(b, tmp);

		Format(tmp, sizeof(tmp), "HUB_NAME: %s", h->HubName);
		WriteBufLine(b, tmp);

		Format(tmp, sizeof(tmp), "HUB_STATUS: %s",
			h->HubStatus ? "Online" : "Offline");
		WriteBufLine(b, tmp);

		Format(tmp, sizeof(tmp), "HUB_MAX_SESSIONS_CLIENT: %u",
			h->HubMaxSessionsClient);
		WriteBufLine(b, tmp);

		Format(tmp, sizeof(tmp), "HUB_MAX_SESSIONS_BRIDGE: %u",
			h->HubMaxSessionsBridge);
		WriteBufLine(b, tmp);
	}

	// ハッシュ計算
	HashSha1(hash, b->Buf, b->Size);
	HashSha1(hash2, hash, sizeof(hash));

	WriteBufLine(b, "[DIGITAL_SIGNATURE]");
	BinToStr(tmp2, sizeof(tmp2), hash2, sizeof(hash2));
	Format(tmp, sizeof(tmp), "SIGNATURE: %s", tmp2);
	WriteBufLine(b, tmp);

	SeekBuf(b, 0, 0);

	return b;
}

// スナップショットのログを書き込む
void WriteServerSnapshotLog(SERVER *s, SERVER_SNAPSHOT *t)
{
	BUF *b;
	LOG *g;
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	b = ServerSnapshotToBuf(t);
	if (b == NULL)
	{
		return;
	}

	g = s->SnapshotLogger;

	WriteMultiLineLog(g, b);

	FreeBuf(b);
}

// Server スナップショットスレッド
void ServerSnapshotThread(THREAD *t, void *param)
{
	SERVER *s;
	UINT64 last_check_license = 0;
	LICENSE_STATUS license;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (SERVER *)param;

	Zero(&license, sizeof(license));

	while (true)
	{
		UINT64 now;
		if (s->HaltSnapshot)
		{
			break;
		}

		if (last_check_license == 0 || (last_check_license + (UINT64)(CE_SNAPSHOT_POLLING_INTERVAL_LICENSE)) <= Tick64())
		{
			last_check_license = Tick64();

			LiParseCurrentLicenseStatus(s->LicenseSystem, &license);
		}

		if (license.CarrierEdition)
		{
			now = SystemTime64();

			if ((s->LastSnapshotTime / CE_SNAPSHOT_INTERVAL) !=
				(now / CE_SNAPSHOT_INTERVAL))
			{
				SERVER_SNAPSHOT t;
				if (MakeServerSnapshot(s, 0, &t))
				{
					s->LastSnapshotTime = now;
					WriteServerSnapshotLog(s, &t);

					FreeSnapshot(&t);
				}
			}
		}

		Wait(s->SnapshotHaltEvent, CE_SNAPSHOT_POLLING_INTERVAL);
	}
}

// Server のスナップショットの保存
bool MakeServerSnapshot(SERVER *s, UINT64 now, SERVER_SNAPSHOT *t)
{
	LICENSE_STATUS license;
	OS_INFO *os = GetOsInfo();
	CEDAR *cedar;
	HUB **hubs;
	UINT i, num_hubs;
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return false;
	}
	if (now == 0)
	{
		now = SystemTime64();
	}

	cedar = s->Cedar;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return false;
	}

	Zero(&license, sizeof(license));
	LiParseCurrentLicenseStatus(s->LicenseSystem, &license);

	if (license.CarrierEdition == false)
	{
		return false;
	}

	now = (now / CE_SNAPSHOT_INTERVAL) * CE_SNAPSHOT_INTERVAL;

	t->DateTime = now;
	GetMachineIp(&t->ServerIp);
	GetMachineName(t->ServerHostname, sizeof(t->ServerHostname));
	StrCpy(t->ServerProduct, sizeof(t->ServerProduct), license.EditionStr);
	t->ServerLicenseId = license.SystemId;
	t->ServerLicenseExpires = license.Expires;
	t->ServerType = s->ServerType;
	if (t->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		LockList(s->FarmMemberList);
		{
			t->NumClusterNodes = LIST_NUM(s->FarmMemberList);
		}
		UnlockList(s->FarmMemberList);
	}

	StrCpy(t->ServerVersion, sizeof(t->ServerVersion), s->Cedar->VerString);
	StrCpy(t->ServerBuild, sizeof(t->ServerBuild), s->Cedar->BuildInfo);
	Format(t->ServerOs, sizeof(t->ServerOs),
		"%s %s %s",
		os->OsVendorName, os->OsProductName, os->OsVersion);

	t->ServerStartupDatetime = s->StartTime;

	LockList(cedar->HubList);
	{
		num_hubs = LIST_NUM(cedar->HubList);
		hubs = ZeroMalloc(sizeof(HUB *) * num_hubs);

		for (i = 0;i < num_hubs;i++)
		{
			HUB *h = LIST_DATA(cedar->HubList, i);
			hubs[i] = h;

			AddRef(h->ref);
		}
	}
	UnlockList(cedar->HubList);

	t->HubList = NewListFast(NULL);

	for (i = 0;i < num_hubs;i++)
	{
		HUB *h = hubs[i];
		UINT client, bridge;
		HUB_SNAPSHOT *sn;

		client = GetHubAdminOption(h, "max_sessions_client");
		bridge = GetHubAdminOption(h, "max_sessions_bridge");

		sn = ZeroMalloc(sizeof(HUB_SNAPSHOT));
		sn->HubMaxSessionsClient = client;
		sn->HubMaxSessionsBridge = bridge;
		StrCpy(sn->HubName, sizeof(sn->HubName), h->Name);
		sn->HubStatus = h->Offline ? false : true;

		Insert(t->HubList, sn);

		ReleaseHub(h);
	}

	Free(hubs);

	return true;
}

// スナップショットの解放
void FreeSnapshot(SERVER_SNAPSHOT *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->HubList);i++)
	{
		HUB_SNAPSHOT *h = LIST_DATA(t->HubList, i);

		Free(h);
	}

	ReleaseList(t->HubList);

	Zero(t, sizeof(SERVER_SNAPSHOT));
}

// サーバーの現在のライセンスステータスを取得する
void SiGetServerLicenseStatus(SERVER *s, LICENSE_STATUS *st)
{
	// 引数チェック
	if (s == NULL || st == NULL)
	{
		return;
	}

	if (s->LicenseSystem == NULL || s->LicenseSystem->Status == NULL)
	{
		Zero(st, sizeof(LICENSE_STATUS));
		return;
	}

	Copy(st, s->LicenseSystem->Status, sizeof(LICENSE_STATUS));
}

// サーバー製品名を取得する
void GetServerProductName(SERVER *s, char *name, UINT size)
{
	char *cpu;
	// 引数チェック
	if (s == NULL || name == NULL)
	{
		return;
	}

	GetServerProductNameInternal(s, name, size);

#ifdef	CPU_64
	cpu = " (64 bit)";
#else	// CPU_64
	cpu = " (32 bit)";
#endif	// CPU_64

	StrCat(name, size, cpu);
}
void GetServerProductNameInternal(SERVER *s, char *name, UINT size)
{
	// 引数チェック
	if (s == NULL || name == NULL)
	{
		return;
	}

#ifdef	BETA_NUMBER
	if (s->Cedar->Bridge)
	{
		StrCpy(name, size, CEDAR_BRIDGE_STR);
	}
	else
	{
		StrCpy(name, size, CEDAR_BETA_SERVER);
	}
	return;
#else	// BETA_NUMBER
	if (s->Cedar->Bridge)
	{
		StrCpy(name, size, CEDAR_BRIDGE_STR);
	}
	else
	{
		LICENSE_STATUS st;

		LiParseCurrentLicenseStatus(s->LicenseSystem, &st);

		StrCpy(name, size, st.EditionStr);
	}
#endif	// BETA_NUMBER
}

// ログファイル列挙を結合する
void AdjoinEnumLogFile(LIST *o, LIST *src)
{
	UINT i;
	// 引数チェック
	if (o == NULL || src == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(src);i++)
	{
		LOG_FILE *f = LIST_DATA(src, i);

		Insert(o, Clone(f, sizeof(LOG_FILE)));
	}
}

// 指定した名前のログファイルが列挙リストに入っているかどうか確認する
bool CheckLogFileNameFromEnumList(LIST *o, char *name, char *server_name)
{
	LOG_FILE t;
	// 引数チェック
	if (o == NULL || name == NULL || server_name == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Path, sizeof(t.Path), name);
	StrCpy(t.ServerName, sizeof(t.ServerName), server_name);

	if (Search(o, &t) == NULL)
	{
		return false;
	}

	return true;
}

// ログファイル列挙を解放する
void FreeEnumLogFile(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);

		Free(f);
	}

	ReleaseList(o);
}

// 仮想 HUB に関連するログファイルを列挙する (サーバー管理者の場合はすべて列挙する)
LIST *EnumLogFile(char *hubname)
{
	char exe_dir[MAX_PATH];
	char tmp[MAX_PATH];
	LIST *o = NewListFast(CmpLogFile);
	DIRLIST *dir;

	if (StrLen(hubname) == 0)
	{
		hubname = NULL;
	}

	GetExeDir(exe_dir, sizeof(exe_dir));

	// server_log の下を列挙する
	if (hubname == NULL)
	{
		EnumLogFileDir(o, "server_log");
	}

	// packet_log の下を列挙する
	Format(tmp, sizeof(tmp), "%s/packet_log", exe_dir);
	dir = EnumDir(tmp);
	if (dir != NULL)
	{
		UINT i;
		for (i = 0;i < dir->NumFiles;i++)
		{
			DIRENT *e = dir->File[i];

			if (e->Folder)
			{
				char dir_name[MAX_PATH];

				if (hubname == NULL || StrCmpi(hubname, e->FileName) == 0)
				{
					Format(dir_name, sizeof(dir_name), "packet_log/%s", e->FileName);
					EnumLogFileDir(o, dir_name);
				}
			}
		}

		FreeDir(dir);
	}

	// security_log の下を列挙する
	Format(tmp, sizeof(tmp), "%s/security_log", exe_dir);
	dir = EnumDir(tmp);
	if (dir != NULL)
	{
		UINT i;
		for (i = 0;i < dir->NumFiles;i++)
		{
			DIRENT *e = dir->File[i];

			if (e->Folder)
			{
				char dir_name[MAX_PATH];

				if (hubname == NULL || StrCmpi(hubname, e->FileName) == 0)
				{
					Format(dir_name, sizeof(dir_name), "security_log/%s", e->FileName);
					EnumLogFileDir(o, dir_name);
				}
			}
		}

		FreeDir(dir);
	}

	return o;
}

// 指定した名前のディレクトリのログファイルを列挙する
void EnumLogFileDir(LIST *o, char *dirname)
{
	UINT i;
	char exe_dir[MAX_PATH];
	char dir_full_path[MAX_PATH];
	DIRLIST *dir;
	// 引数チェック
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(dir_full_path, sizeof(dir_full_path), "%s/%s", exe_dir, dirname);

	dir = EnumDir(dir_full_path);
	if (dir == NULL)
	{
		return;
	}

	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];

		if (e->Folder == false && e->FileSize > 0)
		{
			char full_path[MAX_PATH];
			char file_path[MAX_PATH];

			Format(file_path, sizeof(file_path), "%s/%s", dirname, e->FileName);
			Format(full_path, sizeof(full_path), "%s/%s", exe_dir, file_path);

			if (EndWith(file_path, ".log"))
			{
				LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

				StrCpy(f->Path, sizeof(f->Path), file_path);
				f->FileSize = (UINT)(MIN(e->FileSize, 0xffffffffUL));
				f->UpdatedTime = e->UpdateDate;

				GetMachineName(f->ServerName, sizeof(f->ServerName));

				Insert(o, f);
			}
		}
	}

	FreeDir(dir);
}

// ログファイルリストエントリ比較
int CmpLogFile(void *p1, void *p2)
{
	LOG_FILE *f1, *f2;
	UINT i;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(LOG_FILE **)p1;
	f2 = *(LOG_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}

	i = StrCmpi(f1->Path, f2->Path);
	if (i != 0)
	{
		return i;
	}

	return StrCmpi(f1->ServerName, f2->ServerName);
}

// サーバーの Caps を取得する
UINT GetServerCapsInt(SERVER *s, char *name)
{
	CAPSLIST t;
	UINT ret;
	// 引数チェック
	if (s == NULL || name == NULL)
	{
		return 0;
	}

	Zero(&t, sizeof(t));
	GetServerCaps(s, &t);

	ret = GetCapsInt(&t, name);

	return ret;
}
bool GetServerCapsBool(SERVER *s, char *name)
{
	return (GetServerCapsInt(s, name) == 0) ? false : true;
}

// サーバーの Caps キャッシュの初期化
void InitServerCapsCache(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	s->CapsCacheLock = NewLock();
	s->CapsListCache = NULL;
}

// サーバーの Caps キャッシュの解放
void FreeServerCapsCache(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (s->CapsListCache != NULL)
	{
		FreeCapsList(s->CapsListCache);
		s->CapsListCache = NULL;
	}
	DeleteLock(s->CapsCacheLock);
}

// サーバーの Caps キャッシュの廃棄
void DestroyServerCapsCache(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{
		if (s->CapsListCache != NULL)
		{
			FreeCapsList(s->CapsListCache);
			s->CapsListCache = NULL;
		}
	}
	Unlock(s->CapsCacheLock);
}

// このサーバーの Caps リストを取得する
void GetServerCaps(SERVER *s, CAPSLIST *t)
{
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{
		if (s->CapsListCache == NULL)
		{
			s->CapsListCache = ZeroMalloc(sizeof(CAPSLIST));
			GetServerCapsMain(s, s->CapsListCache);
		}

		Copy(t, s->CapsListCache, sizeof(s->CapsListCache));
	}
	Unlock(s->CapsCacheLock);
}

// サーバーの Caps 取得メイン
void GetServerCapsMain(SERVER *s, CAPSLIST *t)
{
	// 引数チェック
	if (s == NULL || t == NULL)
	{
		return;
	}

	// 初期化
	InitCapsList(t);

	// 最大 Ethernet パケットサイズ
	AddCapsInt(t, "i_max_packet_size", MAX_PACKET_SIZE);

	if (s->Cedar->Bridge == false)
	{
		LICENSE_STATUS st;
		UINT max_sessions, max_clients, max_bridges, max_user_creations;

		LiParseCurrentLicenseStatus(s->LicenseSystem, &st);

		max_clients = st.NumClientLicense;
		max_bridges = st.NumBridgeLicense;
		max_sessions = st.MaxSessions;
		max_user_creations = st.NumUserLicense;

		// 最大仮想 HUB 数
		AddCapsInt(t, "i_max_hubs", st.MaxHubs);

		// 最大同時接続セッション数
		AddCapsInt(t, "i_max_sessions", max_sessions);

		// 最大作成可能ユーザー数
		AddCapsInt(t, "i_max_user_creation", max_user_creations);

		// 最大クライアント数
		AddCapsInt(t, "i_max_clients", max_clients);

		// 最大ブリッジ数
		AddCapsInt(t, "i_max_bridges", max_bridges);

		if (s->ServerType != SERVER_TYPE_FARM_MEMBER)
		{
			// 登録可能な最大ユーザー数 / 仮想 HUB
			AddCapsInt(t, "i_max_users_per_hub", MAX_USERS);

			// 登録可能な最大グループ数 / 仮想 HUB
			AddCapsInt(t, "i_max_groups_per_hub", MAX_GROUPS);

			// 登録可能な最大アクセスリスト数 / 仮想 HUB
			AddCapsInt(t, "i_max_access_lists", MAX_ACCESSLISTS);
		}
		else
		{
			// 登録可能な最大ユーザー数 / 仮想 HUB
			AddCapsInt(t, "i_max_users_per_hub", 0);

			// 登録可能な最大グループ数 / 仮想 HUB
			AddCapsInt(t, "i_max_groups_per_hub", 0);

			// 登録可能な最大アクセスリスト数 / 仮想 HUB
			AddCapsInt(t, "i_max_access_lists", 0);
		}

		// 多重ログインに関するポリシー
		AddCapsBool(t, "b_support_limit_multilogin", true);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);
	}
	else
	{
		// 最大仮想 HUB 数
		AddCapsInt(t, "i_max_hubs", 0);

		// 最大同時接続セッション数
		AddCapsInt(t, "i_max_sessions", 0);

		// 最大クライアント数
		AddCapsInt(t, "i_max_clients", 0);

		// 最大ブリッジ数
		AddCapsInt(t, "i_max_bridges", 0);

		// 登録可能な最大ユーザー数 / 仮想 HUB
		AddCapsInt(t, "i_max_users_per_hub", 0);

		// 登録可能な最大グループ数 / 仮想 HUB
		AddCapsInt(t, "i_max_groups_per_hub", 0);

		// 登録可能な最大アクセスリスト数 / 仮想 HUB
		AddCapsInt(t, "i_max_access_lists", 0);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);

		// syslog
		AddCapsBool(t, "b_support_syslog", true);
	}

	// syslog は使用不可
	AddCapsBool(t, "b_support_syslog", false);

	// クラスタ内仮想 HUB の種類の変更が禁止されている
	AddCapsBool(t, "b_cluster_hub_type_fixed", true);

	// MAC アドレステーブル最大サイズ / 仮想 HUB
	AddCapsInt(t, "i_max_mac_tables", MAX_MAC_TABLES);

	// IP アドレステーブル最大サイズ / 仮想 HUB
	AddCapsInt(t, "i_max_ip_tables", MAX_IP_TABLES);

	// SecureNAT 機能が使用できる
	AddCapsBool(t, "b_support_securenat", true);

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		AddCapsBool(t, "b_virtual_nat_disabled", true);
	}

	// NAT テーブル最大サイズ / 仮想 HUB
	AddCapsInt(t, "i_max_secnat_tables", NAT_MAX_SESSIONS);

	// カスケード接続
	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		AddCapsBool(t, "b_support_cascade", true);
	}
	else
	{
		AddCapsBool(t, "b_support_cascade", false);
	}

	if (s->Cedar->Bridge)
	{
		// ブリッジ モード
		AddCapsBool(t, "b_bridge", true);
	}
	else if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		// スタンドアロン モード
		AddCapsBool(t, "b_standalone", true);
	}
	else if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// クラスタ コントローラ モード
		AddCapsBool(t, "b_cluster_controller", true);
	}
	else
	{
		// クラスタ メンバ モード
		AddCapsBool(t, "b_cluster_member", true);
	}

	// 仮想 HUB の設定変更が可能である
	AddCapsBool(t, "b_support_config_hub", s->ServerType != SERVER_TYPE_FARM_MEMBER &&
		s->Cedar->Bridge == false);

	// VPN クライアントが接続可能である
	AddCapsBool(t, "b_vpn_client_connect", s->Cedar->Bridge == false ? true : false);

	// 外部認証サーバーは使用不可
	AddCapsBool(t, "b_support_radius", false);

	// ローカル ブリッジ機能が使用できる
	AddCapsBool(t, "b_local_bridge", IsBridgeSupported());

	if (OS_IS_WINDOWS(GetOsInfo()->OsType))
	{
		// パケットキャプチャドライバが未インストール
		AddCapsBool(t, "b_must_install_pcap", IsEthSupported() == false ? true : false);
	}
	else
	{
		// Linux 版ではドライバはインストール済みとする
		AddCapsBool(t, "b_must_install_pcap", false);
	}

	if (IsBridgeSupported())
	{
		// tun/tap が使用可能 (Linux のみ)
		AddCapsBool(t, "b_tap_supported", GetOsInfo()->OsType == OSTYPE_LINUX ? true : false);
	}

	// カスケード接続
	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		AddCapsBool(t, "b_support_cascade", true);
	}
	else
	{
		AddCapsBool(t, "b_support_cascade", false);
	}

	// カスケード接続時のサーバー認証が使用できる
	AddCapsBool(t, "b_support_cascade_cert", true);

	// ログファイル設定の変更ができる
	AddCapsBool(t, "b_support_config_log", s->ServerType != SERVER_TYPE_FARM_MEMBER);

	// ログファイルの自動削除が使用可能である
	AddCapsBool(t, "b_support_autodelete", true);

	// config 操作が使用可能である
	AddCapsBool(t, "b_support_config_rw", true);

	// 仮想 HUB ごとの属性が設定可能である
	AddCapsBool(t, "b_support_hub_admin_option", true);

	// カスケード接続でクライアント証明書が設定可能である
	AddCapsBool(t, "b_support_cascade_client_cert", true);

	// 仮想 HUB を隠すことができる
	AddCapsBool(t, "b_support_hide_hub", true);

	// 統合管理
	AddCapsBool(t, "b_support_cluster_admin", true);

	if (s->Cedar->Bridge == false)
	{
		LICENSE_STATUS status;
		// 仮想レイヤ 3 スイッチ機能が使える
		AddCapsBool(t, "b_support_layer3", true);

		AddCapsInt(t, "i_max_l3_sw", MAX_NUM_L3_SWITCH);
		AddCapsInt(t, "i_max_l3_if", MAX_NUM_L3_IF);
		AddCapsInt(t, "i_max_l3_table", MAX_NUM_L3_TABLE);

		LiParseCurrentLicenseStatus(s->LicenseSystem, &status);

		if (status.AllowEnterpriseFunction || s->ServerType != SERVER_TYPE_STANDALONE)
		{
			// クラスタの一部として動作できる
			AddCapsBool(t, "b_support_cluster", true);
		}
		else
		{
			// クラスタとして動作できない
			AddCapsBool(t, "b_support_cluster", false);
		}
	}
	else
	{
		AddCapsBool(t, "b_support_layer3", false);

		AddCapsInt(t, "i_max_l3_sw", 0);
		AddCapsInt(t, "i_max_l3_if", 0);
		AddCapsInt(t, "i_max_l3_table", 0);

		AddCapsBool(t, "b_support_cluster", false);
	}

	if (s->ServerType != SERVER_TYPE_FARM_MEMBER && s->Cedar->Bridge == false)
	{
		// CRL をサポート
		AddCapsBool(t, "b_support_crl", true);
	}

	// AC は非サポート
	AddCapsBool(t, "b_support_ac", false);

	// ログ ファイルのダウンロードをサポート
	AddCapsBool(t, "b_support_read_log", true);

	// カスケード接続の名前の変更が可能である
	AddCapsBool(t, "b_support_rename_cascade", true);

	// ライセンス管理は不可能
	AddCapsBool(t, "b_support_license", false);

	if (s->Cedar->Beta)
	{
		// ベータ版
		AddCapsBool(t, "b_beta_version", true);
	}

	// ローカルブリッジにネットワーク接続の名前表示をサポート
#ifdef	OS_WIN32
	if (IsBridgeSupported() && IsNt() && GetOsInfo()->OsType >= OSTYPE_WINDOWS_2000_PROFESSIONAL)
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}
#else	// OS_WIN32
	if (IsBridgeSupported() && EthIsInterfaceDescriptionSupportedUnix())
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}
#endif	// OS_WIN32

	// MAC アドレスフィルタリングをサポート
	AddCapsBool(t, "b_support_check_mac", true);

	// TCP コネクションの状態チェックをサポート
	AddCapsBool(t, "b_support_check_tcp_state", true);

	// Radius 認証は使用不可
	AddCapsBool(t, "b_support_radius_retry_interval_and_several_servers", false);

	// MAC アドレステーブルでタグ付き VLAN の ID を管理できる
	AddCapsBool(t, "b_support_vlan", true);

	// 仮想 HUB 拡張オプションをサポート
	if ((s->Cedar->Bridge == false) &&
		(s->ServerType == SERVER_TYPE_STANDALONE || s->ServerType == SERVER_TYPE_FARM_CONTROLLER))
	{
		AddCapsBool(t, "b_support_hub_ext_options", true);
	}
	else
	{
		AddCapsBool(t, "b_support_hub_ext_options", false);
	}

	// セキュリティポリシー バージョン 3.0 をサポート
	AddCapsBool(t, "b_support_policy_ver_3", true);

	// IPv6 アクセスリストをサポート
	AddCapsBool(t, "b_support_ipv6_acl", true);

	// アクセスリストで遅延・ジッタ・パケットロスの設定をサポート
	AddCapsBool(t, "b_support_ex_acl", true);

	// アクセスリストでグループ名による指定をサポート
	AddCapsBool(t, "b_support_acl_group", true);

	// IPv6 接続元 IP 制限リストをサポート
	AddCapsBool(t, "b_support_ipv6_ac", true);

	// タグ付き VLAN パケット透過設定ツールをサポート
	AddCapsBool(t, "b_support_eth_vlan", (OS_IS_WINDOWS_NT(GetOsType()) && GET_KETA(GetOsType(), 100) >= 2));

	// 仮想 HUB への VPN 接続時のメッセージ表示機能をサポート
	AddCapsBool(t, "b_support_msg", true);

	// VPN3
	AddCapsBool(t, "b_vpn3", true);

	// オープンソース版
	AddCapsBool(t, "b_gpl", true);
}

// SYSLOG_SETTING
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(SYSLOG_SETTING));
	t->SaveType = PackGetInt(p, "SaveType");
	t->Port = PackGetInt(p, "Port");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
}
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "SaveType", t->SaveType);
	PackAddInt(p, "Port", t->Port);
	PackAddStr(p, "Hostname", t->Hostname);
}

// CAPSLIST
void InitCapsList(CAPSLIST *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(NULL);
}
void InRpcCapsList(CAPSLIST *t, PACK *p)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(CompareCaps);

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		if (StartWith(e->name, "caps_") && e->type == VALUE_INT && e->num_value == 1)
		{
			CAPS *c = NewCaps(e->name + 5, e->values[0]->IntValue);
			Insert(t->CapsList, c);
		}
	}
}
void OutRpcCapsList(PACK *p, CAPSLIST *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		char tmp[MAX_SIZE];
		CAPS *c = LIST_DATA(t->CapsList, i);

		Format(tmp, sizeof(tmp), "caps_%s", c->Name);
		PackAddInt(p, tmp, c->Value);
	}
}
void FreeRpcCapsList(CAPSLIST *t)
{
	UINT i;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(t->CapsList);
}

// Caps リストに bool 型を追加
void AddCapsBool(CAPSLIST *caps, char *name, bool b)
{
	CAPS *c;
	// 引数チェック
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, b == false ? 0 : 1);
	AddCaps(caps, c);
}

// Caps リストに int 型を追加
void AddCapsInt(CAPSLIST *caps, char *name, UINT i)
{
	CAPS *c;
	// 引数チェック
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, i);
	AddCaps(caps, c);
}

// Caps リストから int 型を取得
UINT GetCapsInt(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// 引数チェック
	if (caps == NULL || name == NULL)
	{
		return 0;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return 0;
	}

	return c->Value;
}

// Caps リストから bool 型を取得
bool GetCapsBool(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// 引数チェック
	if (caps == NULL || name == NULL)
	{
		return false;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return false;
	}

	return c->Value == 0 ? false : true;
}

// Caps リストの解放
void FreeCapsList(CAPSLIST *caps)
{
	UINT i;
	// 引数チェック
	if (caps == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(caps->CapsList);
	Free(caps);
}

// Caps の取得
CAPS *GetCaps(CAPSLIST *caps, char *name)
{
	UINT i;
	// 引数チェック
	if (caps == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		if (StrCmpi(c->Name, name) == 0)
		{
			return c;
		}
	}

	return NULL;
}

// Caps の追加
void AddCaps(CAPSLIST *caps, CAPS *c)
{
	// 引数チェック
	if (caps == NULL || c == NULL)
	{
		return;
	}

	Insert(caps->CapsList, c);
}

// Caps の比較
int CompareCaps(void *p1, void *p2)
{
	CAPS *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CAPS **)p1;
	c2 = *(CAPS **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

// Caps リストの作成
CAPSLIST *NewCapsList()
{
	CAPSLIST *caps = ZeroMalloc(sizeof(CAPSLIST));

	caps->CapsList = NewListFast(CompareCaps);

	return caps;
}

// Caps の解放
void FreeCaps(CAPS *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	Free(c->Name);
	Free(c);
}

// Caps の作成
CAPS *NewCaps(char *name, UINT value)
{
	CAPS *c;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CAPS));
	c->Name = CopyStr(name);
	c->Value = value;

	return c;
}

// 現在の接続数と重みから得点を計算する
UINT SiCalcPoint(SERVER *s, UINT num, UINT weight)
{
	UINT server_max_sessions = SERVER_MAX_SESSIONS;
	if (s == NULL)
	{
		return 0;
	}
	if (weight == 0)
	{
		weight = 100;
	}

	server_max_sessions = GetServerCapsInt(s, "i_max_sessions");

	return (UINT)(((double)server_max_sessions -
		MIN((double)num * 100.0 / (double)weight, (double)server_max_sessions))
		* (double)FARM_BASE_POINT / (double)server_max_sessions);
}

// サーバー得点の取得
UINT SiGetPoint(SERVER *s)
{
	UINT num_session;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	num_session = Count(s->Cedar->CurrentSessions);

	return SiCalcPoint(s, num_session, s->Weight);
}

// デフォルトの証明書を生成する
void SiGenerateDefualtCert(X **server_x, K **server_k)
{
	X *x;
	K *private_key, *public_key;
	NAME *name;
	char tmp[MAX_SIZE];
	wchar_t cn[MAX_SIZE];
	// 引数チェック
	if (server_x == NULL || server_k == NULL)
	{
		return;
	}

	// 鍵ペアの作成
	RsaGen(&private_key, &public_key, 1024);

	// ホスト名の取得
	StrCpy(tmp, sizeof(tmp), "server.softether.vpn");
	GetMachineName(tmp, sizeof(tmp));

	StrToUni(cn, sizeof(cn), tmp);
	name = NewName(cn, L"Default Random Certification", L"VPN Server",
		L"JP", NULL, NULL);
	x = NewRootX(public_key, private_key, name, MAX(GetDaysUntil2038(), SERVER_DEFAULT_CERT_DAYS), NULL);

	*server_x = x;
	*server_k = private_key;

	FreeName(name);

	FreeK(public_key);
}

// サーバー証明書をデフォルトにする
void SiInitDefaultServerCert(SERVER *s)
{
	X *x = NULL;
	K *k = NULL;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// サーバー証明書と秘密鍵を生成する
	SiGenerateDefualtCert(&x, &k);

	// 設定する
	SetCedarCert(s->Cedar, x, k);

	FreeX(x);
	FreeK(k);
}

// 暗号化アルゴリズム名をデフォルトにする
void SiInitCipherName(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	SetCedarCipherList(s->Cedar, SERVER_DEFAULT_CIPHER_NAME);
}

// リスナーリストを初期化する
void SiInitListenerList(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		// デフォルト ポートとして 443, 992, 5555 の 3 つのポートを登録する
		SiAddListener(s, 443, true);
		SiAddListener(s, 992, true);
		SiAddListener(s, 5555, true);
	}
	SiUnlockListenerList(s);
}

// リスナーを削除する
bool SiDeleteListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// 引数チェック
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	// まだ動作中であれば停止する
	SiDisableListener(s, port);

	if (e->Listener != NULL)
	{
		ReleaseListener(e->Listener);
	}

	Delete(s->ServerListenerList, e);
	Free(e);

	return true;
}

// SERVER_LISTENER を比較する
int CompareServerListener(void *p1, void *p2)
{
	SERVER_LISTENER *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(SERVER_LISTENER **)p1;
	s2 = *(SERVER_LISTENER **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1->Port > s2->Port)
	{
		return 1;
	}
	else if (s1->Port < s2->Port)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// リスナーを停止する
bool SiDisableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// 引数チェック
	if (s == NULL || port == 0)
	{
		return false;
	}

	// リスナーを取得する
	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled == false || e->Listener == NULL)
	{
		// 停止中である
		return true;
	}

	// リスナーを停止する
	StopListener(e->Listener);

	// リスナーを解放する
	ReleaseListener(e->Listener);
	e->Listener = NULL;

	e->Enabled = false;

	return true;
}

// リスナーを開始する
bool SiEnableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// 引数チェック
	if (s == NULL || port == 0)
	{
		return false;
	}

	// リスナーを取得する
	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled)
	{
		// すでに開始されている
		return true;
	}

	// リスナーを作成する
	e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
	if (e->Listener == NULL)
	{
		// 失敗
		return false;
	}

	e->Enabled = true;

	return true;
}

// リスナーを取得する
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port)
{
	UINT i;
	// 引数チェック
	if (s == NULL || port == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			return e;
		}
	}

	return NULL;
}

// リスナーを追加する
bool SiAddListener(SERVER *s, UINT port, bool enabled)
{
	SERVER_LISTENER *e;
	UINT i;
	// 引数チェック
	if (s == NULL || port == 0)
	{
		return false;
	}

	// 既存のリスナーが存在していないかどうかチェックする
	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			// すでに存在する
			return false;
		}
	}

	// 新しいリスナーを初期化して登録する
	e = ZeroMalloc(sizeof(SERVER_LISTENER));
	e->Enabled = enabled;
	e->Port = port;

	if (e->Enabled)
	{
		// リスナーを作成する
		e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
	}

	Insert(s->ServerListenerList, e);

	return true;
}

// リスナーリストをロックする
void SiLockListenerList(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
}

// リスナーリストのロックを解除する
void SiUnlockListenerList(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	UnlockList(s->ServerListenerList);
}

// Bridge の初期化
void SiInitBridge(SERVER *s)
{
	HUB *h;
	HUB_OPTION o;
	HUB_LOG g;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));
	o.MaxSession = 0;

	h = NewHub(s->Cedar, SERVER_DEFAULT_BRIDGE_NAME, &o);
	AddHub(s->Cedar, h);

	h->Offline = true;
	SetHubOnline(h);

	// ログ設定
	SiSetDefaultLogSetting(&g);
	SetHubLogSetting(h, &g);

	ReleaseHub(h);
}

// デフォルトの仮想 HUB を作成する
void SiInitDefaultHubList(SERVER *s)
{
	HUB *h;
	HUB_OPTION o;
	HUB_LOG g;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));
	o.MaxSession = 0;
	o.VlanTypeId = MAC_PROTO_TAGVLAN;
	o.NoIPv6DefaultRouterInRAWhenIPv6 = true;
	o.ManageOnlyPrivateIP = true;
	o.ManageOnlyLocalUnicastIPv6 = true;
	o.NoMacAddressLog = true;

	h = NewHub(s->Cedar, s->Cedar->Bridge == false ? SERVER_DEFAULT_HUB_NAME : SERVER_DEFAULT_BRIDGE_NAME, &o);
	h->CreatedTime = SystemTime64();
	AddHub(s->Cedar, h);

	if (s->Cedar->Bridge)
	{
		// パスワードを乱数にする
		Rand(h->HashedPassword, sizeof(h->HashedPassword));
		Rand(h->SecurePassword, sizeof(h->SecurePassword));
	}

	h->Offline = true;
	SetHubOnline(h);

	// ログ設定
	SiSetDefaultLogSetting(&g);
	SetHubLogSetting(h, &g);

	{
		UINT i;
		for (i = 0;i < 0;i++)
		{
			char tmp[MAX_SIZE];
			USER *u;
			sprintf(tmp, "user%u", i);
			AcLock(h);
			u = NewUser(tmp, L"test", L"", AUTHTYPE_ANONYMOUS, NULL);
			AcAddUser(h, u);
			ReleaseUser(u);
			AcUnlock(h);
		}
	}

	ReleaseHub(h);
}

// ログ設定をデフォルトにする
void SiSetDefaultLogSetting(HUB_LOG *g)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = true;
	g->SecurityLogSwitchType = LOG_SWITCH_DAY;
	g->SavePacketLog = false;
	g->PacketLogSwitchType = LOG_SWITCH_DAY;
	g->PacketLogConfig[PACKET_LOG_TCP_CONN] =
		g->PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
}

// テスト
void SiTest(SERVER *s)
{
#if	0
	USER *u;
	USERGROUP *g;
	HUB *h;
	LINK *k;
	CLIENT_OPTION o;
	CLIENT_AUTH a;
	ACCESS *ac;
	X *x;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	h = GetHub(s->Cedar, SERVER_DEFAULT_HUB_NAME);
	if (h == NULL)
	{
		return;
	}

	// ユーザーを作成する
	g = NewGroup("test_group", L"テスト グループ", L"テストです。");
	AcAddGroup(h, g);

	u = NewUser("test", L"テスト", L"はむです", AUTHTYPE_ANONYMOUS, NULL);
	AcAddUser(h, u);
	JoinUserToGroup(u, g);
	ReleaseUser(u);

	u = NewUser("anonymous", L"匿名ユーザー", L"ソフトイーサ株式会社", AUTHTYPE_ANONYMOUS, NULL);
	AcAddUser(h, u);
	JoinUserToGroup(u, g);
	ReleaseUser(u);

	u = NewUser("password", L"パスワードユーザー", L"ソフトイーサ株式会社", AUTHTYPE_PASSWORD, NewPasswordAuthData("password", "microsoft"));
	AcAddUser(h, u);
	ReleaseUser(u);

	x = FileToX("mayaqua.cer");
	u = NewUser("usercert", L"ユーザー証明書テストユーザー", L"ソフトイーサ株式会社", AUTHTYPE_USERCERT, NewUserCertAuthData(x));
	AcAddUser(h, u);
	ReleaseUser(u);
	FreeX(x);

	u = NewUser("rootcert", L"ルート証明書テストユーザー", L"ソフトイーサ株式会社", AUTHTYPE_ROOTCERT, NewRootCertAuthData(NULL, NULL));
	AcAddUser(h, u);
	ReleaseUser(u);

	u = NewUser("*", L"*", L"すべて", AUTHTYPE_RADIUS, NewRadiusAuthData(L""));
	AcAddUser(h, u);
	ReleaseUser(u);

	ReleaseGroup(g);

	// Radius サーバーを設定する
	SetRadiusServer(h, "dc.sec.softether.co.jp", RADIUS_DEFAULT_PORT, "microsoft");

	// HUB 間リンクを作成する
	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"テスト リンク");
	o.MaxConnection = 8;
	o.NumRetry = INFINITE;
	o.UseEncrypt = true;
	StrCpy(o.HubName, sizeof(o.HubName), "TEST_HUB");
	o.Port = 443;
	StrCpy(o.Hostname, sizeof(o.Hostname), "ts.softether.co.jp");

	Zero(&a, sizeof(a));
	a.AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
	StrCpy(a.Username, sizeof(a.Username), "anonymous_test");

	k = NewLink(s->Cedar, h, &o, &a, GetDefaultPolicy());
	StartLink(k);

	ReleaseLink(k);

	// 証明書を追加する
	x = FileToX("root.cer");
	AddRootCert(h, x);
	FreeX(x);

	// アクセスリストを追加する
	ac = ZeroMalloc(sizeof(ACCESS));
	ac->Id = 1;
	UniStrCpy(ac->Note, sizeof(ac->Note), L"アクセスリストのテスト");
	ac->Active = true;
	ac->Priority = 3;
	ac->Discard = true;
	ac->SrcIpAddress = 0x12345678;
	ac->SrcSubnetMask = 0xffffffff;
	ac->DestIpAddress = 0x36547894;
	ac->DestSubnetMask = 0xffffffff;
	ac->Protocol = IP_PROTO_TCP;
	StrCpy(ac->SrcUsername, 0, "yagi");
	StrCpy(ac->DestUsername, 0, "neko");
	AddAccessList(h, ac);
	Free(ac);

	ReleaseHub(h);
#endif
}

// 初期コンフィグレーションを設定する
void SiLoadInitialConfiguration(SERVER *s)
{
	RPC_KEEP k;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// 自動保存間隔関係
	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;

	s->Weight = FARM_DEFAULT_WEIGHT;

	// KEEP 関係
	Zero(&k, sizeof(k));
	k.UseKeepConnect = true;
	k.KeepConnectPort = 80;
	StrCpy(k.KeepConnectHost, sizeof(k.KeepConnectHost), CLIENT_DEFAULT_KEEPALIVE_HOST);
	k.KeepConnectInterval = KEEP_INTERVAL_DEFAULT * 1000;
	k.KeepConnectProtocol = CONNECTION_UDP;

	Lock(s->Keep->lock);
	{
		KEEP *keep = s->Keep;
		keep->Enable = k.UseKeepConnect;
		keep->Server = true;
		StrCpy(keep->ServerName, sizeof(keep->ServerName), k.KeepConnectHost);
		keep->ServerPort = k.KeepConnectPort;
		keep->UdpMode = k.KeepConnectProtocol;
		keep->Interval = k.KeepConnectInterval;
	}
	Unlock(s->Keep->lock);

	// パスワードを初期化する
	Hash(s->HashedPassword, "", 0, true);

	// 暗号化アルゴリズム名をデフォルトにする
	SiInitCipherName(s);

	// サーバー証明書をデフォルトにする
	SiInitDefaultServerCert(s);

	// リスナーリストをデフォルト設定する
	SiInitListenerList(s);

	// デフォルト HUB の作成
	SiInitDefaultHubList(s);

	s->Eraser = NewEraser(s->Logger, 0);
}

// コンフィグレーションファイルを読み込む (メイン)
bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root)
{
	// 引数チェック
	if (s == NULL || root == NULL)
	{
		return false;
	}

	return SiLoadConfigurationCfg(s, root);
}

// コンフィグレーションファイルを読み込む
bool SiLoadConfigurationFile(SERVER *s)
{
	// 引数チェック
	bool ret = false;
	FOLDER *root;
	if (s == NULL)
	{
		return false;
	}

	s->CfgRw = NewCfgRw(&root,
		s->Cedar->Bridge == false ? SERVER_CONFIG_FILE_NAME : BRIDGE_CONFIG_FILE_NAME);

	if (server_reset_setting)
	{
		CfgDeleteFolder(root);
		root = NULL;
		server_reset_setting = false;
	}

	if (root == NULL)
	{
		return false;
	}

	ret = SiLoadConfigurationFileMain(s, root);

	CfgDeleteFolder(root);

	return ret;
}

// コンフィグレーション初期化
void SiInitConfiguration(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// Ethernet 初期化
	InitEth();

	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;

	SLog(s->Cedar, "LS_LOAD_CONFIG_1");
	if (SiLoadConfigurationFile(s) == false)
	{
		SLog(s->Cedar, "LS_LOAD_CONFIG_3");
		SiLoadInitialConfiguration(s);

		server_reset_setting = false;
	}
	else
	{
		SLog(s->Cedar, "LS_LOAD_CONFIG_2");
	}

	// Linux における arp_filter
	if (GetOsInfo()->OsType == OSTYPE_LINUX)
	{
		if (s->NoLinuxArpFilter == false)
		{
			SetLinuxArpFilter();
		}
	}

	// 保存スレッド作成
	SLog(s->Cedar, "LS_INIT_SAVE_THREAD", s->AutoSaveConfigSpan / 1000);
	s->SaveHaltEvent = NewEvent();
	s->SaveThread = NewThread(SiSaverThread, s);
}

// サーバー設定を CFG から読み込む
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root)
{
	FOLDER *f1, *f2, *f3, *f4, *f5, *f6;
	// 引数チェック
	if (s == NULL || root == NULL)
	{
		return false;
	}

	f1 = CfgGetFolder(root, "ServerConfiguration");
	f2 = CfgGetFolder(root, "VirtualHUB");
	f3 = CfgGetFolder(root, "ListenerList");
	f4 = CfgGetFolder(root, "LocalBridgeList");
	f5 = CfgGetFolder(root, "VirtualLayer3SwitchList");
	f6 = CfgGetFolder(root, "LicenseManager");

	if (f1 == NULL)
	{
		SLog(s->Cedar, "LS_BAD_CONFIG");
		return false;
	}

	s->ConfigRevision = CfgGetInt(root, "ConfigRevision");

	if (s->Cedar->Bridge == false && f6 != NULL)
	{
		if (GetServerCapsBool(s, "b_support_license"))
		{
			SiLoadLicenseManager(s, f6);
		}
	}

	DestroyServerCapsCache(s);

	SiLoadServerCfg(s, f1);

	if (s->ServerType != SERVER_TYPE_FARM_MEMBER)
	{
		SiLoadHubs(s, f2);
	}

	SiLoadListeners(s, f3);

	if (f4 != NULL)
	{
		SiLoadLocalBridges(s, f4);
	}

	if (s->Cedar->Bridge == false && f5 != NULL)
	{
		SiLoadL3Switchs(s, f5);
	}

	return true;
}

// リスナー設定を書き出す
void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r)
{
	// 引数チェック
	if (f == NULL || r == NULL)
	{
		return;
	}

	CfgAddBool(f, "Enabled", r->Enabled);
	CfgAddInt(f, "Port", r->Port);
}

// リスナー設定を読み込む
void SiLoadListenerCfg(SERVER *s, FOLDER *f)
{
	bool enable;
	UINT port;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	enable = CfgGetBool(f, "Enabled");
	port = CfgGetInt(f, "Port");

	if (port == 0)
	{
		return;
	}

	SiAddListener(s, port, enable);
}

// リスナー一覧を読み込む
void SiLoadListeners(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = CfgGetFolder(f, t->Token[i]);
		if (ff != NULL)
		{
			SiLoadListenerCfg(s, ff);
		}
	}
	FreeToken(t);
}

// リスナー一覧を書き出す
void SiWriteListeners(FOLDER *f, SERVER *s)
{
	// 引数チェック
	if (f == NULL || s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
		{
			SERVER_LISTENER *r = LIST_DATA(s->ServerListenerList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Listener%u", i);
			SiWriteListenerCfg(CfgCreateFolder(f, name), r);
		}
	}
	UnlockList(s->ServerListenerList);
}

// ブリッジを書き出す
void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br)
{
	// 引数チェック
	if (f == NULL || br == NULL)
	{
		return;
	}

	CfgAddStr(f, "DeviceName", br->DeviceName);
	CfgAddStr(f, "HubName", br->HubName);
	CfgAddBool(f, "NoPromiscuousMode", br->Local);
	CfgAddBool(f, "MonitorMode", br->Monitor);
	CfgAddBool(f, "FullBroadcastMode", br->FullBroadcast);

	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		CfgAddBool(f, "TapMode", br->TapMode);

		if (br->TapMode)
		{
			char tmp[MAX_SIZE];
			MacToStr(tmp, sizeof(tmp), br->TapMacAddress);
			CfgAddStr(f, "TapMacAddress", tmp);
		}
	}
}

// ブリッジ一覧を書き出す
void SiWriteLocalBridges(FOLDER *f, SERVER *s)
{
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	LockList(s->Cedar->LocalBridgeList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->Cedar->LocalBridgeList);i++)
		{
			LOCALBRIDGE *br = LIST_DATA(s->Cedar->LocalBridgeList, i);
			char name[MAX_SIZE];

			Format(name, sizeof(name), "LocalBridge%u", i);
			SiWriteLocalBridgeCfg(CfgCreateFolder(f, name), br);
		}
	}
	UnlockList(s->Cedar->LocalBridgeList);
}

// ブリッジを読み込む
void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f)
{
	char hub[MAX_SIZE];
	char nic[MAX_SIZE];
	bool tapmode = false;
	UCHAR tapaddr[6];
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	Zero(hub, sizeof(hub));
	Zero(nic, sizeof(nic));

	CfgGetStr(f, "HubName", hub, sizeof(hub));
	CfgGetStr(f, "DeviceName", nic, sizeof(nic));

	if (IsEmptyStr(hub) || IsEmptyStr(nic))
	{
		return;
	}

	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		if (CfgGetBool(f, "TapMode"))
		{
			char tmp[MAX_SIZE];
			tapmode = true;
			Zero(tapaddr, sizeof(tapaddr));
			if (CfgGetStr(f, "TapMacAddress", tmp, sizeof(tmp)))
			{
				BUF *b;
				b = StrToBin(tmp);
				if (b != NULL && b->Size == 6)
				{
					Copy(tapaddr, b->Buf, sizeof(tapaddr));
				}
				FreeBuf(b);
			}
		}
	}

	AddLocalBridge(s->Cedar, hub, nic, CfgGetBool(f, "NoPromiscuousMode"), CfgGetBool(f, "MonitorMode"),
		tapmode, tapaddr, CfgGetBool(f, "FullBroadcastMode"));
}

// ブリッジ一覧を読み込む
void SiLoadLocalBridges(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];

		SiLoadLocalBridgeCfg(s, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// サーバーの設定リビジョンをインクリメントする
void IncrementServerConfigRevision(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	s->ConfigRevision++;
}

// サーバー設定を CFG に書き出す
FOLDER *SiWriteConfigurationToCfg(SERVER *s)
{
	FOLDER *root;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	CfgAddInt(root, "ConfigRevision", s->ConfigRevision);

	SiWriteListeners(CfgCreateFolder(root, "ListenerList"), s);

	SiWriteLocalBridges(CfgCreateFolder(root, "LocalBridgeList"), s);

	SiWriteServerCfg(CfgCreateFolder(root, "ServerConfiguration"), s);

	if (s->UpdatedServerType != SERVER_TYPE_FARM_MEMBER)
	{
		SiWriteHubs(CfgCreateFolder(root, "VirtualHUB"), s);
	}

	if (s->Cedar->Bridge == false)
	{
		SiWriteL3Switchs(CfgCreateFolder(root, "VirtualLayer3SwitchList"), s);

		if (GetServerCapsBool(s, "b_support_license"))
		{
			SiWriteLicenseManager(CfgCreateFolder(root, "LicenseManager"), s);
		}
	}

	return root;
}

// ポリシーの読み込み
void SiLoadPolicyCfg(POLICY *p, FOLDER *f)
{
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	Zero(p, sizeof(POLICY));

	// Ver 2
	p->Access = CfgGetBool(f, "Access");
	p->DHCPFilter = CfgGetBool(f, "DHCPFilter");
	p->DHCPNoServer = CfgGetBool(f, "DHCPNoServer");
	p->DHCPForce = CfgGetBool(f, "DHCPForce");
	p->NoBridge = CfgGetBool(f, "NoBridge");
	p->NoRouting = CfgGetBool(f, "NoRouting");
	p->CheckMac = CfgGetBool(f, "CheckMac");
	p->CheckIP = CfgGetBool(f, "CheckIP");
	p->ArpDhcpOnly = CfgGetBool(f, "ArpDhcpOnly");
	p->PrivacyFilter = CfgGetBool(f, "PrivacyFilter");
	p->NoServer = CfgGetBool(f, "NoServer");
	p->NoBroadcastLimiter = CfgGetBool(f, "NoBroadcastLimiter");
	p->MonitorPort = CfgGetBool(f, "MonitorPort");
	p->MaxConnection = CfgGetInt(f, "MaxConnection");
	p->TimeOut = CfgGetInt(f, "TimeOut");
	p->MaxMac = CfgGetInt(f, "MaxMac");
	p->MaxIP = CfgGetInt(f, "MaxIP");
	p->MaxUpload = CfgGetInt(f, "MaxUpload");
	p->MaxDownload = CfgGetInt(f, "MaxDownload");
	p->FixPassword = CfgGetBool(f, "FixPassword");
	p->MultiLogins = CfgGetInt(f, "MultiLogins");
	p->NoQoS = CfgGetBool(f, "NoQoS");

	// Ver 3
	p->RSandRAFilter = CfgGetBool(f, "RSandRAFilter");
	p->RAFilter = CfgGetBool(f, "RAFilter");
	p->DHCPv6Filter = CfgGetBool(f, "DHCPv6Filter");
	p->DHCPv6NoServer = CfgGetBool(f, "DHCPv6NoServer");
	p->NoRoutingV6 = CfgGetBool(f, "NoRoutingV6");
	p->CheckIPv6 = CfgGetBool(f, "CheckIPv6");
	p->NoServerV6 = CfgGetBool(f, "NoServerV6");
	p->MaxIPv6 = CfgGetInt(f, "MaxIPv6");
	p->NoSavePassword = CfgGetBool(f, "NoSavePassword");
	p->AutoDisconnect = CfgGetInt(f, "AutoDisconnect");
	p->FilterIPv4 = CfgGetBool(f, "FilterIPv4");
	p->FilterIPv6 = CfgGetBool(f, "FilterIPv6");
	p->FilterNonIP = CfgGetBool(f, "FilterNonIP");
	p->NoIPv6DefaultRouterInRA = CfgGetBool(f, "NoIPv6DefaultRouterInRA");
	p->NoIPv6DefaultRouterInRAWhenIPv6 = CfgGetBool(f, "NoIPv6DefaultRouterInRAWhenIPv6");
	p->VLanId = CfgGetInt(f, "VLanId");
}

// ポリシーの書き込み
void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode)
{
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return;
	}

	// Ver 2.0
	if (cascade_mode == false)
	{
		CfgAddBool(f, "Access", p->Access);
	}

	CfgAddBool(f, "DHCPFilter", p->DHCPFilter);
	CfgAddBool(f, "DHCPNoServer", p->DHCPNoServer);
	CfgAddBool(f, "DHCPForce", p->DHCPForce);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoBridge", p->NoBridge);
		CfgAddBool(f, "NoRouting", p->NoRouting);
	}

	CfgAddBool(f, "CheckMac", p->CheckMac);
	CfgAddBool(f, "CheckIP", p->CheckIP);
	CfgAddBool(f, "ArpDhcpOnly", p->ArpDhcpOnly);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "PrivacyFilter", p->PrivacyFilter);
	}

	CfgAddBool(f, "NoServer", p->NoServer);
	CfgAddBool(f, "NoBroadcastLimiter", p->NoBroadcastLimiter);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "MonitorPort", p->MonitorPort);
		CfgAddInt(f, "MaxConnection", p->MaxConnection);
		CfgAddInt(f, "TimeOut", p->TimeOut);
	}

	CfgAddInt(f, "MaxMac", p->MaxMac);
	CfgAddInt(f, "MaxIP", p->MaxIP);
	CfgAddInt(f, "MaxUpload", p->MaxUpload);
	CfgAddInt(f, "MaxDownload", p->MaxDownload);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "FixPassword", p->FixPassword);
		CfgAddInt(f, "MultiLogins", p->MultiLogins);
		CfgAddBool(f, "NoQoS", p->NoQoS);
	}

	// Ver 3.0
	CfgAddBool(f, "RSandRAFilter", p->RSandRAFilter);
	CfgAddBool(f, "RAFilter", p->RAFilter);
	CfgAddBool(f, "DHCPv6Filter", p->DHCPv6Filter);
	CfgAddBool(f, "DHCPv6NoServer", p->DHCPv6NoServer);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoRoutingV6", p->NoRoutingV6);
	}

	CfgAddBool(f, "CheckIPv6", p->CheckIPv6);
	CfgAddBool(f, "NoServerV6", p->NoServerV6);
	CfgAddInt(f, "MaxIPv6", p->MaxIPv6);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoSavePassword", p->NoSavePassword);
		CfgAddInt(f, "AutoDisconnect", p->AutoDisconnect);
	}

	CfgAddBool(f, "FilterIPv4", p->FilterIPv4);
	CfgAddBool(f, "FilterIPv6", p->FilterIPv6);
	CfgAddBool(f, "FilterNonIP", p->FilterNonIP);
	CfgAddBool(f, "NoIPv6DefaultRouterInRA", p->NoIPv6DefaultRouterInRA);
	CfgAddBool(f, "NoIPv6DefaultRouterInRAWhenIPv6", p->NoIPv6DefaultRouterInRAWhenIPv6);
	CfgAddInt(f, "VLanId", p->VLanId);
}

// 仮想 HUB のリンク情報の書き込み
void SiWriteHubLinkCfg(FOLDER *f, LINK *k)
{
	// 引数チェック
	if (f == NULL || k == NULL)
	{
		return;
	}

	Lock(k->lock);
	{
		// オンライン
		CfgAddBool(f, "Online", k->Offline ? false : true);

		// クライアントオプション
		CiWriteClientOption(CfgCreateFolder(f, "ClientOption"), k->Option);

		// クライアント認証データ
		CiWriteClientAuth(CfgCreateFolder(f, "ClientAuth"), k->Auth);

		// ポリシー
		if (k->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), k->Policy, true);
		}

		CfgAddBool(f, "CheckServerCert", k->CheckServerCert);

		if (k->ServerCert != NULL)
		{
			BUF *b = XToBuf(k->ServerCert, false);
			CfgAddBuf(f, "ServerCert", b);
			FreeBuf(b);
		}
	}
	Unlock(k->lock);
}

// リンク情報の読み込み
void SiLoadHubLinkCfg(FOLDER *f, HUB *h)
{
	bool online;
	CLIENT_OPTION *o;
	CLIENT_AUTH *a;
	FOLDER *pf;
	POLICY p;
	LINK *k;
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	pf = CfgGetFolder(f, "Policy");
	if (pf == NULL)
	{
		return;
	}

	SiLoadPolicyCfg(&p, pf);

	online = CfgGetBool(f, "Online");

	o = CiLoadClientOption(CfgGetFolder(f, "ClientOption"));
	a = CiLoadClientAuth(CfgGetFolder(f, "ClientAuth"));
	if (o == NULL || a == NULL)
	{
		Free(o);
		CiFreeClientAuth(a);
		return;
	}

	k = NewLink(h->Cedar, h, o, a, &p);
	if (k != NULL)
	{
		BUF *b;
		k->CheckServerCert = CfgGetBool(f, "CheckServerCert");
		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL)
		{
			k->ServerCert = BufToX(b, false);
			FreeBuf(b);
		}

		if (online)
		{
			k->Offline = true;
			SetLinkOnline(k);
		}
		else
		{
			k->Offline = false;
			SetLinkOffline(k);
		}
		ReleaseLink(k);
	}

	Free(o);
	CiFreeClientAuth(a);
}

// 仮想 HUB の SecureNAT の書き込み
void SiWriteSecureNAT(HUB *h, FOLDER *f)
{
	// 引数チェック
	if (h == NULL || f == NULL)
	{
		return;
	}

	CfgAddBool(f, "Disabled", h->EnableSecureNAT ? false : true);

	NiWriteVhOptionEx(h->SecureNATOption, f);
}

// 仮想 HUB の管理オプションの読み込み
void SiLoadHubAdminOptions(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	// 引数チェック
	if (h == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumItemToTokenList(f);
	if (t != NULL)
	{
		UINT i;

		LockList(h->AdminOptionList);
		{
			DeleteAllHubAdminOption(h, false);

			for (i = 0;i < t->NumTokens;i++)
			{
				char *name = t->Token[i];
				ADMIN_OPTION *a;
				UINT value = CfgGetInt(f, name);;

				Trim(name);

				a = ZeroMalloc(sizeof(ADMIN_OPTION));
				StrCpy(a->Name, sizeof(a->Name), name);
				a->Value = value;

				Insert(h->AdminOptionList, a);
			}

			AddHubAdminOptionsDefaults(h, false);
		}
		UnlockList(h->AdminOptionList);

		FreeToken(t);
	}
}

// 仮想 HUB の管理オプションの書き込み
void SiWriteHubAdminOptions(FOLDER *f, HUB *h)
{
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->AdminOptionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
		{
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);

			CfgAddInt(f, a->Name, a->Value);
		}
	}
	UnlockList(h->AdminOptionList);
}

// 仮想 HUB のリンクリストの書き込み
void SiWriteHubLinks(FOLDER *f, HUB *h)
{
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = LIST_DATA(h->LinkList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Cascade%u", i);
			SiWriteHubLinkCfg(CfgCreateFolder(f, name), k);
		}
	}
	UnlockList(h->LinkList);
}

// リンクリストの読み込み
void SiLoadHubLinks(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// 引数チェック
	if (h == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		SiLoadHubLinkCfg(CfgGetFolder(f, name), h);
	}

	FreeToken(t);
}

// アクセスリスト項目の書き込み
void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a)
{
	// 引数チェック
	if (f == NULL || a == NULL)
	{
		return;
	}

	CfgAddUniStr(f, "Note", a->Note);
	CfgAddBool(f, "Active", a->Active);
	CfgAddInt(f, "Priority", a->Priority);
	CfgAddBool(f, "Discard", a->Discard);
	CfgAddBool(f, "IsIPv6", a->IsIPv6);

	if (a->IsIPv6 == false)
	{
		CfgAddIp32(f, "SrcIpAddress", a->SrcIpAddress);
		CfgAddIp32(f, "SrcSubnetMask", a->SrcSubnetMask);
		CfgAddIp32(f, "DestIpAddress", a->DestIpAddress);
		CfgAddIp32(f, "DestSubnetMask", a->DestSubnetMask);
	}
	else
	{
		CfgAddIp6Addr(f, "SrcIpAddress6", &a->SrcIpAddress6);
		CfgAddIp6Addr(f, "SrcSubnetMask6", &a->SrcSubnetMask6);
		CfgAddIp6Addr(f, "DestIpAddress6", &a->DestIpAddress6);
		CfgAddIp6Addr(f, "DestSubnetMask6", &a->DestSubnetMask6);
	}

	CfgAddInt(f, "Protocol", a->Protocol);
	CfgAddInt(f, "SrcPortStart", a->SrcPortStart);
	CfgAddInt(f, "SrcPortEnd", a->SrcPortEnd);
	CfgAddInt(f, "DestPortStart", a->DestPortStart);
	CfgAddInt(f, "DestPortEnd", a->DestPortEnd);
	CfgAddStr(f, "SrcUsername", a->SrcUsername);
	CfgAddStr(f, "DestUsername", a->DestUsername);
	CfgAddBool(f, "CheckSrcMac", a->CheckSrcMac);

	if (a->CheckSrcMac)
	{
		char tmp[MAX_PATH];

		MacToStr(tmp, sizeof(tmp), a->SrcMacAddress);
		CfgAddStr(f, "SrcMacAddress", tmp);

		MacToStr(tmp, sizeof(tmp), a->SrcMacMask);
		CfgAddStr(f, "SrcMacMask", tmp);
	}

	CfgAddBool(f, "CheckDstMac", a->CheckDstMac);

	if (a->CheckDstMac)
	{
		char tmp[MAX_PATH];

		MacToStr(tmp, sizeof(tmp), a->DstMacAddress);
		CfgAddStr(f, "DstMacAddress", tmp);

		MacToStr(tmp, sizeof(tmp), a->DstMacMask);
		CfgAddStr(f, "DstMacMask", tmp);
	}

	CfgAddBool(f, "CheckTcpState", a->CheckTcpState);
	CfgAddBool(f, "Established", a->Established);

	CfgAddInt(f, "Delay", a->Delay);
	CfgAddInt(f, "Jitter", a->Jitter);
	CfgAddInt(f, "Loss", a->Loss);
}

// アクセスリスト項目の読み込み
void SiLoadHubAccessCfg(HUB *h, FOLDER *f)
{
	ACCESS a;
	char tmp[MAX_PATH];
	// 引数チェック
	if (h == NULL || f == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));

	CfgGetUniStr(f, "Note", a.Note, sizeof(a.Note));
	a.Active = CfgGetBool(f, "Active");
	a.Priority = CfgGetInt(f, "Priority");
	a.Discard = CfgGetBool(f, "Discard");
	a.IsIPv6 = CfgGetBool(f, "IsIPv6");

	if (a.IsIPv6 == false)
	{
		a.SrcIpAddress = CfgGetIp32(f, "SrcIpAddress");
		a.SrcSubnetMask = CfgGetIp32(f, "SrcSubnetMask");
		a.DestIpAddress = CfgGetIp32(f, "DestIpAddress");
		a.DestSubnetMask = CfgGetIp32(f, "DestSubnetMask");
	}
	else
	{
		CfgGetIp6Addr(f, "SrcIpAddress6", &a.SrcIpAddress6);
		CfgGetIp6Addr(f, "SrcSubnetMask6", &a.SrcSubnetMask6);
		CfgGetIp6Addr(f, "DestIpAddress6", &a.DestIpAddress6);
		CfgGetIp6Addr(f, "DestSubnetMask6", &a.DestSubnetMask6);
	}

	a.Protocol = CfgGetInt(f, "Protocol");
	a.SrcPortStart = CfgGetInt(f, "SrcPortStart");
	a.SrcPortEnd = CfgGetInt(f, "SrcPortEnd");
	a.DestPortStart = CfgGetInt(f, "DestPortStart");
	a.DestPortEnd = CfgGetInt(f, "DestPortEnd");
	CfgGetStr(f, "SrcUsername", a.SrcUsername, sizeof(a.SrcUsername));
	CfgGetStr(f, "DestUsername", a.DestUsername, sizeof(a.DestUsername));
	a.CheckSrcMac = CfgGetBool(f, "CheckSrcMac");

	if (CfgGetByte(f, "SrcMacAddress", a.SrcMacAddress, sizeof(a.SrcMacAddress)) == 0)
	{
		CfgGetStr(f, "SrcMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacAddress, tmp) == false)
		{
			a.CheckSrcMac = false;
		}
	}

	if (CfgGetByte(f, "SrcMacMask", a.SrcMacMask, sizeof(a.SrcMacMask)) == 0)
	{
		CfgGetStr(f, "SrcMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacMask, tmp) == false)
		{
			a.CheckSrcMac = false;
		}
	}

	a.CheckDstMac = CfgGetBool(f, "CheckDstMac");

	if (CfgGetByte(f, "DstMacAddress", a.DstMacAddress, sizeof(a.DstMacAddress)) == 0)
	{
		CfgGetStr(f, "DstMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacAddress, tmp) == false)
		{
			a.CheckDstMac = false;
		}
	}

	if (CfgGetByte(f, "DstMacMask", a.DstMacMask, sizeof(a.DstMacMask)) == 0)
	{
		CfgGetStr(f, "DstMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacMask, tmp) == false)
		{
			a.CheckDstMac = false;
		}
	}

	a.CheckTcpState = CfgGetBool(f, "CheckTcpState");
	a.Established = CfgGetBool(f, "Established");
	a.Delay = MAKESURE(CfgGetInt(f, "Delay"), 0, HUB_ACCESSLIST_DELAY_MAX);
	a.Jitter = MAKESURE(CfgGetInt(f, "Jitter"), 0, HUB_ACCESSLIST_JITTER_MAX);
	a.Loss = MAKESURE(CfgGetInt(f, "Loss"), 0, HUB_ACCESSLIST_LOSS_MAX);

	AddAccessList(h, &a);
}

// アクセスリストの書き込み
void SiWriteHubAccessLists(FOLDER *f, HUB *h)
{
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->AccessList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(h->AccessList, i);
			char name[MAX_SIZE];
			ToStr(name, a->Id);
			SiWriteHubAccessCfg(CfgCreateFolder(f, name), a);
		}
	}
	UnlockList(h->AccessList);
}

// アクセスリストの読み込み
void SiLoadHubAccessLists(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		UINT id = ToInt(name);
		SiLoadHubAccessCfg(h, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// HUB_OPTION の読み込み
void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (f == NULL || o == NULL)
	{
		return;
	}

	o->MaxSession = CfgGetInt(f, "MaxSession");
	o->NoArpPolling = CfgGetBool(f, "NoArpPolling");
	o->NoIPv6AddrPolling = CfgGetBool(f, "NoIPv6AddrPolling");
	o->NoIpTable = CfgGetBool(f, "NoIpTable");
	o->NoEnum = CfgGetBool(f, "NoEnum");
	o->FilterPPPoE = CfgGetBool(f, "FilterPPPoE");
	o->FilterOSPF = CfgGetBool(f, "FilterOSPF");
	o->FilterIPv4 = CfgGetBool(f, "FilterIPv4");
	o->FilterIPv6 = CfgGetBool(f, "FilterIPv6");
	o->FilterNonIP = CfgGetBool(f, "FilterNonIP");
	o->FilterBPDU = CfgGetBool(f, "FilterBPDU");
	o->NoIPv4PacketLog = CfgGetBool(f, "NoIPv4PacketLog");
	o->NoIPv6PacketLog = CfgGetBool(f, "NoIPv6PacketLog");
	o->NoIPv6DefaultRouterInRAWhenIPv6 = CfgGetBool(f, "NoIPv6DefaultRouterInRAWhenIPv6");
	o->DisableIPParsing = CfgGetBool(f, "DisableIPParsing");
	o->YieldAfterStorePacket = CfgGetBool(f, "YieldAfterStorePacket");
	o->NoSpinLockForPacketDelay = CfgGetBool(f, "NoSpinLockForPacketDelay");
	o->BroadcastStormDetectionThreshold = CfgGetInt(f, "BroadcastStormDetectionThreshold");
	o->ClientMinimumRequiredBuild = CfgGetInt(f, "ClientMinimumRequiredBuild");
	o->RequiredClientId = CfgGetInt(f, "RequiredClientId");
	o->NoManageVlanId = CfgGetBool(f, "NoManageVlanId");
	o->VlanTypeId = 0;
	if (CfgGetStr(f, "VlanTypeId", tmp, sizeof(tmp)))
	{
		o->VlanTypeId = HexToInt(tmp);
	}
	if (o->VlanTypeId == 0)
	{
		o->VlanTypeId = MAC_PROTO_TAGVLAN;
	}
	o->FixForDLinkBPDU = CfgGetBool(f, "FixForDLinkBPDU");
	o->NoLookBPDUBridgeId = CfgGetBool(f, "NoLookBPDUBridgeId");

	// デフォルトで有効
	if (CfgIsItem(f, "ManageOnlyPrivateIP"))
	{
		o->ManageOnlyPrivateIP = CfgGetBool(f, "ManageOnlyPrivateIP");
	}
	else
	{
		o->ManageOnlyPrivateIP = true;
	}
	if (CfgIsItem(f, "ManageOnlyLocalUnicastIPv6"))
	{
		o->ManageOnlyLocalUnicastIPv6 = CfgGetBool(f, "ManageOnlyLocalUnicastIPv6");
	}
	else
	{
		o->ManageOnlyLocalUnicastIPv6 = true;
	}
	if (CfgIsItem(f, "NoMacAddressLog"))
	{
		o->NoMacAddressLog = CfgGetBool(f, "NoMacAddressLog");
	}
	else
	{
		o->NoMacAddressLog = true;
	}
}

// HUB_OPTION の書き込み
void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (f == NULL || o == NULL)
	{
		return;
	}

	CfgAddInt(f, "MaxSession", o->MaxSession);
	CfgAddBool(f, "NoArpPolling", o->NoArpPolling);
	CfgAddBool(f, "NoIPv6AddrPolling", o->NoIPv6AddrPolling);
	CfgAddBool(f, "NoIpTable", o->NoIpTable);
	CfgAddBool(f, "NoEnum", o->NoEnum);
	CfgAddBool(f, "FilterPPPoE", o->FilterPPPoE);
	CfgAddBool(f, "FilterOSPF", o->FilterOSPF);
	CfgAddBool(f, "FilterIPv4", o->FilterIPv4);
	CfgAddBool(f, "FilterIPv6", o->FilterIPv6);
	CfgAddBool(f, "FilterNonIP", o->FilterNonIP);
	CfgAddBool(f, "NoIPv4PacketLog", o->NoIPv4PacketLog);
	CfgAddBool(f, "NoIPv6PacketLog", o->NoIPv6PacketLog);
	CfgAddBool(f, "FilterBPDU", o->FilterBPDU);
	CfgAddBool(f, "NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6);
	CfgAddBool(f, "NoMacAddressLog", o->NoMacAddressLog);
	CfgAddBool(f, "ManageOnlyPrivateIP", o->ManageOnlyPrivateIP);
	CfgAddBool(f, "ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6);
	CfgAddBool(f, "DisableIPParsing", o->DisableIPParsing);
	CfgAddBool(f, "YieldAfterStorePacket", o->YieldAfterStorePacket);
	CfgAddBool(f, "NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay);
	CfgAddInt(f, "BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold);
	CfgAddInt(f, "ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild);
	CfgAddInt(f, "RequiredClientId", o->RequiredClientId);
	CfgAddBool(f, "NoManageVlanId", o->NoManageVlanId);
	Format(tmp, sizeof(tmp), "0x%x", o->VlanTypeId);
	CfgAddStr(f, "VlanTypeId", tmp);
	if (o->FixForDLinkBPDU)
	{
		CfgAddBool(f, "FixForDLinkBPDU", o->FixForDLinkBPDU);
	}
	CfgAddBool(f, "NoLookBPDUBridgeId", o->NoLookBPDUBridgeId);
}

// ユーザーの書き込み
void SiWriteUserCfg(FOLDER *f, USER *u)
{
	AUTHPASSWORD *password;
	// 引数チェック
	if (f == NULL || u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		CfgAddUniStr(f, "RealName", u->RealName);
		CfgAddUniStr(f, "Note", u->Note);
		if (u->Group != NULL)
		{
			CfgAddStr(f, "GroupName", u->GroupName);
		}
		CfgAddInt64(f, "CreatedTime", u->CreatedTime);
		CfgAddInt64(f, "UpdatedTime", u->UpdatedTime);
		CfgAddInt64(f, "ExpireTime", u->ExpireTime);
		CfgAddInt64(f, "LastLoginTime", u->LastLoginTime);
		CfgAddInt(f, "NumLogin", u->NumLogin);
		if (u->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), u->Policy, false);
		}
		SiWriteTraffic(f, "Traffic", u->Traffic);

		CfgAddInt(f, "AuthType", u->AuthType);
		if (u->AuthData != NULL)
		{
			switch (u->AuthType)
			{
			case AUTHTYPE_ANONYMOUS:
				break;

			case AUTHTYPE_PASSWORD:
				password = (AUTHPASSWORD *)u->AuthData;
				CfgAddByte(f, "AuthPassword", password->HashedKey, sizeof(password->HashedKey));
				break;
			}
		}
	}
	Unlock(u->lock);
}

// ユーザーの読み込み
void SiLoadUserCfg(HUB *h, FOLDER *f)
{
	char *username;
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char groupname[MAX_SIZE];
	FOLDER *pf;
	UINT64 created_time;
	UINT64 updated_time;
	UINT64 expire_time;
	UINT64 last_login_time;
	UINT num_login;
	POLICY p;
	TRAFFIC t;
	UINT authtype;
	void *authdata;
	X_SERIAL *serial = NULL;
	UCHAR hashed_password[SHA1_SIZE];
	USER *u;
	USERGROUP *g;
	// 引数チェック
	if (h == NULL || f == NULL)
	{
		return;
	}

	username = f->Name;
	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));
	CfgGetStr(f, "GroupName", groupname, sizeof(groupname));

	created_time = CfgGetInt64(f, "CreatedTime");
	updated_time = CfgGetInt64(f, "UpdatedTime");
	expire_time = CfgGetInt64(f, "ExpireTime");
	last_login_time = CfgGetInt64(f, "LastLoginTime");
	num_login = CfgGetInt(f, "NumLogin");
	pf = CfgGetFolder(f, "Policy");
	if (pf != NULL)
	{
		SiLoadPolicyCfg(&p, pf);
	}
	SiLoadTraffic(f, "Traffic", &t);

	authtype = CfgGetInt(f, "AuthType");
	authdata = NULL;

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		// 通常のパスワード認証
		CfgGetByte(f, "AuthPassword", hashed_password, sizeof(hashed_password));
		authdata = NewPasswordAuthDataRaw(hashed_password);
		break;

	default:
		// それ以外の認証方法が指定された
		authtype = AUTHTYPE_ANONYMOUS;
		authdata = NULL;
		break;
	}

	// ユーザーの追加
	AcLock(h);
	{
		if (StrLen(groupname) > 0)
		{
			g = AcGetGroup(h, groupname);
		}
		else
		{
			g = NULL;
		}

		u = NewUser(username, realname, note, authtype, authdata);
		if (u != NULL)
		{
			if (g != NULL)
			{
				JoinUserToGroup(u, g);
			}

			SetUserTraffic(u, &t);

			if (pf != NULL)
			{
				SetUserPolicy(u, &p);
			}

			Lock(u->lock);
			{
				u->CreatedTime = created_time;
				u->UpdatedTime = updated_time;
				u->ExpireTime = expire_time;
				u->LastLoginTime = last_login_time;
				u->NumLogin = num_login;
			}
			Unlock(u->lock);

			AcAddUser(h, u);

			ReleaseUser(u);
		}

		if (g != NULL)
		{
			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	if (serial != NULL)
	{
		FreeXSerial(serial);
	}
}

// ユーザーリストの書き込み
void SiWriteUserList(FOLDER *f, LIST *o)
{
	// 引数チェック
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USER *u = LIST_DATA(o, i);
			SiWriteUserCfg(CfgCreateFolder(f, u->Name), u);
		}
	}
	UnlockList(o);
}

// ユーザーリストの読み込み
void SiLoadUserList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff;
		name = t->Token[i];
		ff = CfgGetFolder(f, name);
		SiLoadUserCfg(h, ff);
	}

	FreeToken(t);
}

// グループ情報の書き込み
void SiWriteGroupCfg(FOLDER *f, USERGROUP *g)
{
	// 引数チェック
	if (f == NULL || g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		CfgAddUniStr(f, "RealName", g->RealName);
		CfgAddUniStr(f, "Note", g->Note);
		if (g->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), g->Policy, false);
		}
		SiWriteTraffic(f, "Traffic", g->Traffic);
	}
	Unlock(g->lock);
}

// グループ情報の読み込み
void SiLoadGroupCfg(HUB *h, FOLDER *f)
{
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char *name;
	FOLDER *pf;
	POLICY p;
	TRAFFIC t;
	USERGROUP *g;
	// 引数チェック
	if (h == NULL || f == NULL)
	{
		return;
	}

	name = f->Name;

	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));

	pf = CfgGetFolder(f, "Policy");
	if (pf != NULL)
	{
		SiLoadPolicyCfg(&p, pf);
	}

	SiLoadTraffic(f, "Traffic", &t);

	g = NewGroup(name, realname, note);
	if (g == NULL)
	{
		return;
	}

	if (pf != NULL)
	{
		SetGroupPolicy(g, &p);
	}

	SetGroupTraffic(g, &t);

	AcLock(h);
	{
		AcAddGroup(h, g);
	}
	AcUnlock(h);

	ReleaseGroup(g);
}

// グループリストの書き込み
void SiWriteGroupList(FOLDER *f, LIST *o)
{
	// 引数チェック
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USERGROUP *g = LIST_DATA(o, i);
			SiWriteGroupCfg(CfgCreateFolder(f, g->Name), g);
		}
	}
	UnlockList(o);
}

// グループリストの読み込み
void SiLoadGroupList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		name = t->Token[i];
		SiLoadGroupCfg(h, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// 無効な証明書リストの書き込み
void SiWriteCrlList(FOLDER *f, LIST *o)
{
	// 引数チェック
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			CRL *crl = LIST_DATA(o, i);
			FOLDER *ff;
			NAME *n;

			Format(name, sizeof(name), "Crl%u", i);

			ff = CfgCreateFolder(f, name);
			n = crl->Name;

			if (UniIsEmptyStr(n->CommonName) == false)
			{
				CfgAddUniStr(ff, "CommonName", n->CommonName);
			}

			if (UniIsEmptyStr(n->Organization) == false)
			{
				CfgAddUniStr(ff, "Organization", n->Organization);
			}

			if (UniIsEmptyStr(n->Unit) == false)
			{
				CfgAddUniStr(ff, "Unit", n->Unit);
			}

			if (UniIsEmptyStr(n->Country) == false)
			{
				CfgAddUniStr(ff, "Country", n->Country);
			}

			if (UniIsEmptyStr(n->State) == false)
			{
				CfgAddUniStr(ff, "State", n->State);
			}

			if (UniIsEmptyStr(n->Local) == false)
			{
				CfgAddUniStr(ff, "Local", n->Local);
			}

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestMD5, MD5_SIZE);
				CfgAddStr(ff, "DigestMD5", tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestSHA1, SHA1_SIZE);
				CfgAddStr(ff, "DigestSHA1", tmp);
			}

			if (crl->Serial != NULL)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->Serial->data, crl->Serial->size);
				CfgAddStr(ff, "Serial", tmp);
			}
		}
	}
	UnlockList(o);
}

// 無効な証明書リストの読み込み
void SiLoadCrlList(LIST *o, FOLDER *f)
{
	// 引数チェック
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		TOKEN_LIST *t;

		t = CfgEnumFolderToTokenList(f);

		for (i = 0;i < t->NumTokens;i++)
		{
			CRL *crl;
			FOLDER *ff = CfgGetFolder(f, t->Token[i]);
			wchar_t cn[MAX_SIZE], org[MAX_SIZE], u[MAX_SIZE], c[MAX_SIZE],
				st[MAX_SIZE], l[MAX_SIZE];
			char tmp[MAX_SIZE];

			if (ff != NULL)
			{
				BUF *b;

				crl = ZeroMalloc(sizeof(CRL));

				CfgGetUniStr(ff, "CommonName", cn, sizeof(cn));
				CfgGetUniStr(ff, "Organization", org, sizeof(org));
				CfgGetUniStr(ff, "Unit", u, sizeof(u));
				CfgGetUniStr(ff, "Country", c, sizeof(c));
				CfgGetUniStr(ff, "State", st, sizeof(st));
				CfgGetUniStr(ff, "Local", l, sizeof(l));

				crl->Name = NewName(cn, org, u, c, st, l);

				if (CfgGetStr(ff, "Serial", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size >= 1)
						{
							crl->Serial = NewXSerial(b->Buf, b->Size);
						}

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestMD5", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size == MD5_SIZE)
						{
							Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
						}

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestSHA1", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size == SHA1_SIZE)
						{
							Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
						}

						FreeBuf(b);
					}
				}

				Insert(o, crl);
			}
		}

		FreeToken(t);
	}
	UnlockList(o);
}

// 証明書リストの書き込み
void SiWriteCertList(FOLDER *f, LIST *o)
{
	// 引数チェック
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		X *x;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			BUF *b;
			x = LIST_DATA(o, i);
			Format(name, sizeof(name), "Cert%u", i);
			b = XToBuf(x, false);
			if (b != NULL)
			{
				CfgAddBuf(CfgCreateFolder(f, name), "X509", b);
				FreeBuf(b);
			}
		}
	}
	UnlockList(o);
}

// 証明書リストの読み込み
void SiLoadCertList(LIST *o, FOLDER *f)
{
	// 引数チェック
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		TOKEN_LIST *t;

		t = CfgEnumFolderToTokenList(f);

		for (i = 0;i < t->NumTokens;i++)
		{
			FOLDER *ff = CfgGetFolder(f, t->Token[i]);
			BUF *b;

			b = CfgGetBuf(ff, "X509");
			if (b != NULL)
			{
				X *x = BufToX(b, false);
				if (x != NULL)
				{
					Insert(o, x);
				}
				FreeBuf(b);
			}
		}

		FreeToken(t);
	}
	UnlockList(o);
}

// データベースの書き込み
void SiWriteHubDb(FOLDER *f, HUBDB *db)
{
	// 引数チェック
	if (f == NULL || db == NULL)
	{
		return;
	}

	SiWriteUserList(CfgCreateFolder(f, "UserList"), db->UserList);
	SiWriteGroupList(CfgCreateFolder(f, "GroupList"), db->GroupList);
	SiWriteCertList(CfgCreateFolder(f, "CertList"), db->RootCertList);
	SiWriteCrlList(CfgCreateFolder(f, "CrlList"), db->CrlList);
}

// データベースの読み込み
void SiLoadHubDb(HUB *h, FOLDER *f)
{
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	SiLoadGroupList(h, CfgGetFolder(f, "GroupList"));
	SiLoadUserList(h, CfgGetFolder(f, "UserList"));

	if (h->HubDb != NULL)
	{
		SiLoadCertList(h->HubDb->RootCertList, CfgGetFolder(f, "CertList"));
		SiLoadCrlList(h->HubDb->CrlList, CfgGetFolder(f, "CrlList"));
	}
}

// 仮想 HUB 設定の書き込み
void SiWriteHubCfg(FOLDER *f, HUB *h)
{
	// 引数チェック
	if (f == NULL || h == NULL)
	{
		return;
	}

	// パスワード
	CfgAddByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword));
	CfgAddByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword));

	// Online / Offline フラグ
	if (h->Cedar->Bridge == false)
	{
		CfgAddBool(f, "Online", (h->Offline && (h->HubIsOnlineButHalting == false)) ? false : true);
	}

	// トラフィック情報
	SiWriteTraffic(f, "Traffic", h->Traffic);

	// HUB オプション
	SiWriteHubOptionCfg(CfgCreateFolder(f, "Option"), h->Option);

	// メッセージ
	{
		FOLDER *folder = CfgCreateFolder(f, "Message");

		if (IsEmptyUniStr(h->Msg) == false)
		{
			CfgAddUniStr(folder, "MessageText", h->Msg);
		}
	}

	// HUB_LOG
	SiWriteHubLogCfg(CfgCreateFolder(f, "LogSetting"), &h->LogSetting);

	if (h->Type == HUB_TYPE_STANDALONE)
	{
		// リンクリスト
		SiWriteHubLinks(CfgCreateFolder(f, "CascadeList"), h);
	}

	if (h->Type != HUB_TYPE_FARM_STATIC)
	{
		if (GetServerCapsBool(h->Cedar->Server, "b_support_securenat"))
		{
			// SecureNAT
			SiWriteSecureNAT(h, CfgCreateFolder(f, "SecureNAT"));
		}
	}

	// アクセスリスト
	SiWriteHubAccessLists(CfgCreateFolder(f, "AccessList"), h);

	// 管理オプション
	SiWriteHubAdminOptions(CfgCreateFolder(f, "AdminOption"), h);

	// HUB の種類
	CfgAddInt(f, "Type", h->Type);

	// データベース
	if (h->Cedar->Bridge == false)
	{
		SiWriteHubDb(CfgCreateFolder(f, "SecurityAccountDatabase"), h->HubDb);
	}

	// 利用状況
	CfgAddInt64(f, "LastCommTime", h->LastCommTime);
	CfgAddInt64(f, "LastLoginTime", h->LastLoginTime);
	CfgAddInt64(f, "CreatedTime", h->CreatedTime);
	CfgAddInt(f, "NumLogin", h->NumLogin);
}

// ログオプションの読み込み
void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f)
{
	// 引数チェック
	if (f == NULL || g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = CfgGetBool(f, "SaveSecurityLog");
	g->SecurityLogSwitchType = CfgGetInt(f, "SecurityLogSwitchType");
	g->SavePacketLog = CfgGetBool(f, "SavePacketLog");
	g->PacketLogSwitchType = CfgGetInt(f, "PacketLogSwitchType");

	g->PacketLogConfig[PACKET_LOG_TCP_CONN] = CfgGetInt(f, "PACKET_LOG_TCP_CONN");
	g->PacketLogConfig[PACKET_LOG_TCP] = CfgGetInt(f, "PACKET_LOG_TCP");
	g->PacketLogConfig[PACKET_LOG_DHCP] = CfgGetInt(f, "PACKET_LOG_DHCP");
	g->PacketLogConfig[PACKET_LOG_UDP] = CfgGetInt(f, "PACKET_LOG_UDP");
	g->PacketLogConfig[PACKET_LOG_ICMP] = CfgGetInt(f, "PACKET_LOG_ICMP");
	g->PacketLogConfig[PACKET_LOG_IP] = CfgGetInt(f, "PACKET_LOG_IP");
	g->PacketLogConfig[PACKET_LOG_ARP] = CfgGetInt(f, "PACKET_LOG_ARP");
	g->PacketLogConfig[PACKET_LOG_ETHERNET] = CfgGetInt(f, "PACKET_LOG_ETHERNET");
}

// ログオプションの書き込み
void SiWriteHubLogCfg(FOLDER *f, HUB_LOG *g)
{
	SiWriteHubLogCfgEx(f, g, false);
}
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode)
{
	// 引数チェック
	if (f == NULL || g == NULL)
	{
		return;
	}

	if (el_mode == false)
	{
		CfgAddBool(f, "SaveSecurityLog", g->SaveSecurityLog);
		CfgAddInt(f, "SecurityLogSwitchType", g->SecurityLogSwitchType);
		CfgAddBool(f, "SavePacketLog", g->SavePacketLog);
	}

	CfgAddInt(f, "PacketLogSwitchType", g->PacketLogSwitchType);

	CfgAddInt(f, "PACKET_LOG_TCP_CONN", g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
	CfgAddInt(f, "PACKET_LOG_TCP", g->PacketLogConfig[PACKET_LOG_TCP]);
	CfgAddInt(f, "PACKET_LOG_DHCP", g->PacketLogConfig[PACKET_LOG_DHCP]);
	CfgAddInt(f, "PACKET_LOG_UDP", g->PacketLogConfig[PACKET_LOG_UDP]);
	CfgAddInt(f, "PACKET_LOG_ICMP", g->PacketLogConfig[PACKET_LOG_ICMP]);
	CfgAddInt(f, "PACKET_LOG_IP", g->PacketLogConfig[PACKET_LOG_IP]);
	CfgAddInt(f, "PACKET_LOG_ARP", g->PacketLogConfig[PACKET_LOG_ARP]);
	CfgAddInt(f, "PACKET_LOG_ETHERNET", g->PacketLogConfig[PACKET_LOG_ETHERNET]);
}

// 仮想 HUB 設定の読み込み
void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name)
{
	HUB *h;
	CEDAR *c;
	HUB_OPTION o;
	bool online;
	UINT hub_old_type = 0;
	// 引数チェック
	if (s == NULL || f == NULL || name == NULL)
	{
		return;
	}

	c = s->Cedar;

	// オプションの取得
	Zero(&o, sizeof(o));
	SiLoadHubOptionCfg(CfgGetFolder(f, "Option"), &o);

	// HUB の作成
	h = NewHub(c, name, &o);
	if (h != NULL)
	{
		HUB_LOG g;

		// パスワード
		if (CfgGetByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword)) != sizeof(h->HashedPassword))
		{
			Hash(h->HashedPassword, "", 0, true);
		}
		if (CfgGetByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword)) != sizeof(h->SecurePassword))
		{
			HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
		}

		// ログ設定
		Zero(&g, sizeof(g));
		SiLoadHubLogCfg(&g, CfgGetFolder(f, "LogSetting"));
		SetHubLogSetting(h, &g);

		// Online / Offline フラグ
		if (h->Cedar->Bridge == false)
		{
			online = CfgGetBool(f, "Online");
		}
		else
		{
			online = true;
		}

		// トラフィック情報
		SiLoadTraffic(f, "Traffic", h->Traffic);

		// アクセスリスト
		SiLoadHubAccessLists(h, CfgGetFolder(f, "AccessList"));

		// HUB の種類
		hub_old_type = h->Type = CfgGetInt(f, "Type");
		if (s->ServerType == SERVER_TYPE_STANDALONE)
		{
			if (h->Type != HUB_TYPE_STANDALONE)
			{
				// サーバーがスタンドアロンの場合は HUB の種類をスタンドアロンに変換する
				h->Type = HUB_TYPE_STANDALONE;
			}
		}
		else
		{
			if (h->Type == HUB_TYPE_STANDALONE)
			{
				// サーバーがファームコントローラの場合は HUB の種類をファーム対応にする
				h->Type = HUB_TYPE_FARM_DYNAMIC;
			}
		}

		// メッセージ
		{
			FOLDER *folder = CfgGetFolder(f, "Message");
			if (folder != NULL)
			{
				wchar_t *tmp = Malloc(sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1));
				if (CfgGetUniStr(folder, "MessageText", tmp, sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1)))
				{
					SetHubMsg(h, tmp);
				}
				Free(tmp);
			}
		}

		// リンクリスト
		if (h->Type == HUB_TYPE_STANDALONE)
		{
			// リンクリストはスタンドアロン HUB の場合しか使用しない
			SiLoadHubLinks(h, CfgGetFolder(f, "CascadeList"));
		}

		// SecureNAT
		if (GetServerCapsBool(h->Cedar->Server, "b_support_securenat"))
		{
			if (h->Type == HUB_TYPE_STANDALONE || h->Type == HUB_TYPE_FARM_DYNAMIC)
			{
				// SecureNAT はスタンドアロン HUB かダイナミック HUB の場合しか使用しない
				SiLoadSecureNAT(h, CfgGetFolder(f, "SecureNAT"));

				if (h->Type != HUB_TYPE_STANDALONE && h->Cedar != NULL && h->Cedar->Server != NULL &&
					h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
				{
					NiClearUnsupportedVhOptionForDynamicHub(h->SecureNATOption,
						hub_old_type == HUB_TYPE_STANDALONE);
				}

			}
		}

		// 管理オプション
		SiLoadHubAdminOptions(h, CfgGetFolder(f, "AdminOption"));

		// データベース
		if (h->Cedar->Bridge == false)
		{
			SiLoadHubDb(h, CfgGetFolder(f, "SecurityAccountDatabase"));
		}

		// 利用状況
		h->LastCommTime = CfgGetInt64(f, "LastCommTime");
		if (h->LastCommTime == 0)
		{
			h->LastCommTime = SystemTime64();
		}
		h->LastLoginTime = CfgGetInt64(f, "LastLoginTime");
		if (h->LastLoginTime == 0)
		{
			h->LastLoginTime = SystemTime64();
		}
		h->CreatedTime = CfgGetInt64(f, "CreatedTime");
		h->NumLogin = CfgGetInt(f, "NumLogin");

		// HUB の動作開始
		AddHub(c, h);

		if (online)
		{
			h->Offline = true;
			SetHubOnline(h);
		}
		else
		{
			h->Offline = false;
			SetHubOffline(h);
		}

		WaitLogFlush(h->SecurityLogger);
		WaitLogFlush(h->PacketLogger);

		ReleaseHub(h);
	}
}

// SecureNAT 設定の読み込み
void SiLoadSecureNAT(HUB *h, FOLDER *f)
{
	VH_OPTION o;
	// 引数チェック
	if (h == NULL || f == NULL)
	{
		return;
	}

	// VH_OPTION を読み込む
	NiLoadVhOptionEx(&o, f);

	// VH_OPTION をセット
	Copy(h->SecureNATOption, &o, sizeof(VH_OPTION));

	EnableSecureNAT(h, CfgGetBool(f, "Disabled") ? false : true);
}

// 仮想レイヤ 3 スイッチ設定の読み込み
void SiLoadL3SwitchCfg(L3SW *sw, FOLDER *f)
{
	UINT i;
	FOLDER *if_folder, *table_folder;
	TOKEN_LIST *t;
	bool active = false;
	// 引数チェック
	if (sw == NULL || f == NULL)
	{
		return;
	}

	active = CfgGetBool(f, "Active");

	// インターフェイスリスト
	if_folder = CfgGetFolder(f, "InterfaceList");
	if (if_folder != NULL)
	{
		t = CfgEnumFolderToTokenList(if_folder);
		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				FOLDER *ff = CfgGetFolder(if_folder, t->Token[i]);
				char name[MAX_HUBNAME_LEN + 1];
				UINT ip, subnet;

				CfgGetStr(ff, "HubName", name, sizeof(name));
				ip = CfgGetIp32(ff, "IpAddress");
				subnet = CfgGetIp32(ff, "SubnetMask");

				L3AddIf(sw, name, ip, subnet);
			}
			FreeToken(t);
		}
	}

	// ルーティングテーブル
	table_folder = CfgGetFolder(f, "RoutingTable");
	if (table_folder != NULL)
	{
		t = CfgEnumFolderToTokenList(table_folder);
		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				FOLDER *ff = CfgGetFolder(table_folder, t->Token[i]);
				L3TABLE tbl;

				Zero(&tbl, sizeof(tbl));
				tbl.NetworkAddress = CfgGetIp32(ff, "NetworkAddress");
				tbl.SubnetMask = CfgGetIp32(ff, "SubnetMask");
				tbl.GatewayAddress = CfgGetIp32(ff, "GatewayAddress");
				tbl.Metric = CfgGetInt(ff, "Metric");

				L3AddTable(sw, &tbl);
			}
			FreeToken(t);
		}
	}

	if (active)
	{
		L3SwStart(sw);
	}
}

// 仮想レイヤ 3 スイッチ設定の書き込み
void SiWriteL3SwitchCfg(FOLDER *f, L3SW *sw)
{
	UINT i;
	FOLDER *if_folder, *table_folder;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (f == NULL || sw == NULL)
	{
		return;
	}

	// 動作フラグ
	CfgAddBool(f, "Active", sw->Active);

	// インターフェイスリスト
	if_folder = CfgCreateFolder(f, "InterfaceList");
	for (i = 0;i < LIST_NUM(sw->IfList);i++)
	{
		L3IF *e = LIST_DATA(sw->IfList, i);
		FOLDER *ff;

		Format(tmp, sizeof(tmp), "Interface%u", i);
		ff = CfgCreateFolder(if_folder, tmp);

		CfgAddStr(ff, "HubName", e->HubName);
		CfgAddIp32(ff, "IpAddress", e->IpAddress);
		CfgAddIp32(ff, "SubnetMask", e->SubnetMask);
	}

	// ルーティングテーブル
	table_folder = CfgCreateFolder(f, "RoutingTable");
	for (i = 0;i < LIST_NUM(sw->TableList);i++)
	{
		L3TABLE *e = LIST_DATA(sw->TableList, i);
		FOLDER *ff;

		Format(tmp, sizeof(tmp), "Entry%u", i);
		ff = CfgCreateFolder(table_folder, tmp);

		CfgAddIp32(ff, "NetworkAddress", e->NetworkAddress);
		CfgAddIp32(ff, "SubnetMask", e->SubnetMask);
		CfgAddIp32(ff, "GatewayAddress", e->GatewayAddress);
		CfgAddInt(ff, "Metric", e->Metric);
	}
}

// 仮想レイヤ 3 スイッチ一覧の読み込み
void SiLoadL3Switchs(SERVER *s, FOLDER *f)
{
	UINT i;
	TOKEN_LIST *t;
	CEDAR *c;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}
	c = s->Cedar;

	t = CfgEnumFolderToTokenList(f);
	if (t != NULL)
	{
		for (i = 0;i < t->NumTokens;i++)
		{
			char *name = t->Token[i];
			L3SW *sw = L3AddSw(c, name);

			SiLoadL3SwitchCfg(sw, CfgGetFolder(f, name));

			ReleaseL3Sw(sw);
		}
	}
	FreeToken(t);
}

// 仮想レイヤ 3 スイッチ一覧の書き込み
void SiWriteL3Switchs(FOLDER *f, SERVER *s)
{
	UINT i;
	FOLDER *folder;
	CEDAR *c;
	// 引数チェック
	if (f == NULL || s == NULL)
	{
		return;
	}
	c = s->Cedar;

	LockList(c->L3SwList);
	{
		for (i = 0;i < LIST_NUM(c->L3SwList);i++)
		{
			L3SW *sw = LIST_DATA(c->L3SwList, i);

			Lock(sw->lock);
			{
				folder = CfgCreateFolder(f, sw->Name);

				SiWriteL3SwitchCfg(folder, sw);
			}
			Unlock(sw->lock);
		}
	}
	UnlockList(c->L3SwList);
}

// ライセンス一覧の書き込み
void SiWriteLicenseManager(FOLDER *f, SERVER *s)
{
	LICENSE_SYSTEM *ss;
	// 引数チェック
	if (f == NULL || s == NULL)
	{
		return;
	}

	ss = s->LicenseSystem;
	if (s == NULL)
	{
		return;
	}

	LockList(ss->LicenseList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(ss->LicenseList);i++)
		{
			LICENSE *e = LIST_DATA(ss->LicenseList, i);
			char name[MAX_SIZE];
			FOLDER *ff;

			Format(name, sizeof(name), "License%u", i);
			ff = CfgCreateFolder(f, name);
			CfgAddStr(ff, "LicenseKey", e->LicenseKeyStr);
			CfgAddInt(ff, "LicenseType", e->ProductId);
		}
	}
	UnlockList(ss->LicenseList);
}

// ライセンス一覧の読み込み
void SiLoadLicenseManager(SERVER *s, FOLDER *f)
{
	UINT i;
	TOKEN_LIST *t;
	CEDAR *c;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}
	c = s->Cedar;

	t = CfgEnumFolderToTokenList(f);
	if (t != NULL)
	{
		for (i = 0;i < t->NumTokens;i++)
		{
			char *str = t->Token[i];
			FOLDER *ff = CfgGetFolder(f, str);

			if (ff != NULL)
			{
				UINT product_id = CfgGetInt(ff, "LicenseType");
				char key[MAX_SIZE];

				if (CfgGetStr(ff, "LicenseKey", key, sizeof(key)))
				{
					// ライセンス登録
					//LiInputLicenseKeyEx(c, s->LicenseSystem, key, product_id, NULL);
				}
			}
		}
	}
	FreeToken(t);

	DestroyServerCapsCache(s);
}

// 仮想 HUB 一覧の書き込み
void SiWriteHubs(FOLDER *f, SERVER *s)
{
	UINT i;
	FOLDER *hub_folder;
	CEDAR *c;
	UINT num;
	HUB **hubs;
	// 引数チェック
	if (f == NULL || s == NULL)
	{
		return;
	}
	c = s->Cedar;

	LockList(c->HubList);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);

		for (i = 0;i < num;i++)
		{
			AddRef(hubs[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num;i++)
	{
		HUB *h = hubs[i];

		Lock(h->lock);
		{
			hub_folder = CfgCreateFolder(f, h->Name);
			SiWriteHubCfg(hub_folder, h);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if ((i % 30) == 1)
		{
			YieldCpu();
		}
	}

	Free(hubs);
}

// 仮想 HUB 一覧の読み込み
void SiLoadHubs(SERVER *s, FOLDER *f)
{
	UINT i;
	FOLDER *hub_folder;
	CEDAR *c;
	TOKEN_LIST *t;
	bool b = false;
	// 引数チェック
	if (f == NULL || s == NULL)
	{
		return;
	}
	c = s->Cedar;

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		if (s->Cedar->Bridge)
		{
			if (StrCmpi(name, SERVER_DEFAULT_BRIDGE_NAME) == 0)
			{
				// Bridge の場合は "BRIDGE" という名前の仮想 HUB の設定
				// しか読み込まない
				b = true;
			}
			else
			{
				continue;
			}
		}
		hub_folder = CfgGetFolder(f, name);
		if (hub_folder != NULL)
		{
			SiLoadHubCfg(s, hub_folder, name);
		}
	}
	FreeToken(t);

	if (s->Cedar->Bridge && b == false)
	{
		// "BRIDGE" という名前の仮想 HUB の設定が存在しない場合は新たに作成する
		SiInitDefaultHubList(s);
	}
}

// サーバー固有の設定の読み込み
void SiLoadServerCfg(SERVER *s, FOLDER *f)
{
	BUF *b;
	CEDAR *c;
	char tmp[MAX_SIZE];
	X *x = NULL;
	K *k = NULL;
	bool cluster_allowed = false;
	UINT num_connections_per_ip = 0;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	// 保存間隔関係
	s->AutoSaveConfigSpan = CfgGetInt(f, "AutoSaveConfigSpan") * 1000;
	if (s->AutoSaveConfigSpan == 0)
	{
		s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	}
	else
	{
		s->AutoSaveConfigSpan = MAKESURE(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_MIN, SERVER_FILE_SAVE_INTERVAL_MAX);
	}

	c = s->Cedar;
	Lock(c->lock);
	{
		{
			RPC_KEEP k;

			// キープアライブ関係
			Zero(&k, sizeof(k));
			k.UseKeepConnect = CfgGetBool(f, "UseKeepConnect");
			CfgGetStr(f, "KeepConnectHost", k.KeepConnectHost, sizeof(k.KeepConnectHost));
			k.KeepConnectPort = CfgGetInt(f, "KeepConnectPort");
			k.KeepConnectProtocol = CfgGetInt(f, "KeepConnectProtocol");
			k.KeepConnectInterval = CfgGetInt(f, "KeepConnectInterval") * 1000;
			if (k.KeepConnectPort == 0)
			{
				k.KeepConnectPort = 80;
			}
			if (StrLen(k.KeepConnectHost) == 0)
			{
				StrCpy(k.KeepConnectHost, sizeof(k.KeepConnectHost), CLIENT_DEFAULT_KEEPALIVE_HOST);
			}
			if (k.KeepConnectInterval == 0)
			{
				k.KeepConnectInterval = KEEP_INTERVAL_DEFAULT * 1000;
			}
			if (k.KeepConnectInterval < 5000)
			{
				k.KeepConnectInterval = 5000;
			}
			if (k.KeepConnectInterval > 600000)
			{
				k.KeepConnectInterval = 600000;
			}

			Lock(s->Keep->lock);
			{
				KEEP *keep = s->Keep;
				keep->Enable = k.UseKeepConnect;
				keep->Server = true;
				StrCpy(keep->ServerName, sizeof(keep->ServerName), k.KeepConnectHost);
				keep->ServerPort = k.KeepConnectPort;
				keep->UdpMode = k.KeepConnectProtocol;
				keep->Interval = k.KeepConnectInterval;
			}
			Unlock(s->Keep->lock);
		}

		// IPv6 リスナーを無効にするかどうか
		s->Cedar->DisableIPv6Listener = CfgGetBool(f, "DisableIPv6Listener");

		// DeadLock
		s->DisableDeadLockCheck = CfgGetBool(f, "DisableDeadLockCheck");

		// 自動ファイル削除器
		s->Eraser = NewEraser(s->Logger, CfgGetInt64(f, "AutoDeleteCheckDiskFreeSpaceMin"));

		// NoLinuxArpFilter
		s->NoLinuxArpFilter = CfgGetBool(f, "NoLinuxArpFilter");

		// NoHighPriorityProcess
		s->NoHighPriorityProcess = CfgGetBool(f, "NoHighPriorityProcess");

		// NoDebugDump
		s->NoDebugDump = CfgGetBool(f, "NoDebugDump");
		if (s->NoDebugDump)
		{
#ifdef	OS_WIN32
			MsSetEnableMinidump(false);
#endif	// OS_WIN32
		}

		// クライアントにシグネチャを送信させない
		s->NoSendSignature = CfgGetBool(f, "NoSendSignature");

		// デバッグログ
		s->SaveDebugLog = CfgGetBool(f, "SaveDebugLog");
		if (s->SaveDebugLog)
		{
			s->DebugLog = NewTinyLog();
		}

		// サーバー証明書
		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL)
		{
			x = BufToX(b, false);
			FreeBuf(b);
		}

		// サーバー秘密鍵
		b = CfgGetBuf(f, "ServerKey");
		if (b != NULL)
		{
			k = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}

		if (x == NULL || k == NULL || CheckXandK(x, k) == false)
		{
			FreeX(x);
			FreeK(k);
			SiGenerateDefualtCert(&x, &k);

			SetCedarCert(c, x, k);

			FreeX(x);
			FreeK(k);
		}
		else
		{
			SetCedarCert(c, x, k);

			FreeX(x);
			FreeK(k);
		}

		// 暗号化名
		if (CfgGetStr(f, "CipherName", tmp, sizeof(tmp)))
		{
			StrUpper(tmp);
			if (CheckCipherListName(tmp))
			{
				SetCedarCipherList(c, tmp);
			}
		}

		// トラフィック情報
		Lock(c->TrafficLock);
		{
			SiLoadTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		// 現在のライセンスでクラスタモードが許可されているかどうかを取得する
		cluster_allowed = false;
		if (s->Cedar->Bridge == false)
		{
			LICENSE_STATUS status;

			LiParseCurrentLicenseStatus(s->LicenseSystem, &status);

			if (status.AllowEnterpriseFunction)
			{
				cluster_allowed = true;
			}
		}

		// サーバーの種類
		s->UpdatedServerType = s->ServerType = 
			cluster_allowed ? CfgGetInt(f, "ServerType") : SERVER_TYPE_STANDALONE;

		// パスワード
		if (CfgGetByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword)) != sizeof(s->HashedPassword))
		{
			Hash(s->HashedPassword, "", 0, true);
		}

		if (s->ServerType != SERVER_TYPE_STANDALONE)
		{
			// サーバーの性能基準比
			s->Weight = CfgGetInt(f, "ClusterMemberWeight");
			if (s->Weight == 0)
			{
				s->Weight = FARM_DEFAULT_WEIGHT;
			}
		}
		else
		{
			s->Weight = FARM_DEFAULT_WEIGHT;
		}

		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			s->ControllerOnly = CfgGetBool(f, "ControllerOnly");
		}

		if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			char tmp[6 * MAX_PUBLIC_PORT_NUM + 1];
			// ファームメンバの場合の設定項目の読み込み
			CfgGetStr(f, "ControllerName", s->ControllerName, sizeof(s->ControllerName));
			s->ControllerPort = CfgGetInt(f, "ControllerPort");
			CfgGetByte(f, "MemberPassword", s->MemberPassword, SHA1_SIZE);
			s->PublicIp = CfgGetIp32(f, "PublicIp");
			if (CfgGetStr(f, "PublicPorts", tmp, sizeof(tmp)))
			{
				TOKEN_LIST *t = ParseToken(tmp, ", ");
				UINT i;
				s->NumPublicPort = t->NumTokens;
				s->PublicPorts = ZeroMalloc(s->NumPublicPort * sizeof(UINT));
				for (i = 0;i < s->NumPublicPort;i++)
				{
					s->PublicPorts[i] = ToInt(t->Token[i]);
				}
				FreeToken(t);
			}
		}
	}
	Unlock(c->lock);
}

// サーバー固有の設定の書き込み
void SiWriteServerCfg(FOLDER *f, SERVER *s)
{
	BUF *b;
	CEDAR *c;
	// 引数チェック
	if (f == NULL || s == NULL)
	{
		return;
	}

	CfgAddInt(f, "AutoSaveConfigSpan", s->AutoSaveConfigSpan / 1000);

	c = s->Cedar;

	Lock(c->lock);
	{
		Lock(s->Keep->lock);
		{
			KEEP *k = s->Keep;
			CfgAddBool(f, "UseKeepConnect", k->Enable);
			CfgAddStr(f, "KeepConnectHost", k->ServerName);
			CfgAddInt(f, "KeepConnectPort", k->ServerPort);
			CfgAddInt(f, "KeepConnectProtocol", k->UdpMode);
			CfgAddInt(f, "KeepConnectInterval", k->Interval / 1000);
		}
		Unlock(s->Keep->lock);

		// IPv6 リスナー無効化設定
		CfgAddBool(f, "DisableIPv6Listener", s->Cedar->DisableIPv6Listener);

		// DeadLock
		CfgAddBool(f, "DisableDeadLockCheck", s->DisableDeadLockCheck);

		// 自動ファイル削除器関係
		CfgAddInt64(f, "AutoDeleteCheckDiskFreeSpaceMin", s->Eraser->MinFreeSpace);

		// NoLinuxArpFilter
		if (GetOsInfo()->OsType == OSTYPE_LINUX)
		{
			CfgAddBool(f, "NoLinuxArpFilter", s->NoLinuxArpFilter);
		}

		// NoHighPriorityProcess
		CfgAddBool(f, "NoHighPriorityProcess", s->NoHighPriorityProcess);

#ifdef	OS_WIN32
		CfgAddBool(f, "NoDebugDump", s->NoDebugDump);
#endif	// OS_WIN32

		// デバッグログ
		CfgAddBool(f, "SaveDebugLog", s->SaveDebugLog);

		// クライアントにシグネチャを送信させない
		CfgAddBool(f, "NoSendSignature", s->NoSendSignature);

		// サーバー証明書
		b = XToBuf(c->ServerX, false);
		CfgAddBuf(f, "ServerCert", b);
		FreeBuf(b);

		// サーバー秘密鍵
		b = KToBuf(c->ServerK, false, NULL);
		CfgAddBuf(f, "ServerKey", b);
		FreeBuf(b);

		// トラフィック情報
		Lock(c->TrafficLock);
		{
			SiWriteTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		// サーバーの種類
		if (s->Cedar->Bridge == false)
		{
			CfgAddInt(f, "ServerType", s->UpdatedServerType);
		}

		// 暗号化
		CfgAddStr(f, "CipherName", s->Cedar->CipherList);

		// パスワード
		CfgAddByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));

		if (s->UpdatedServerType == SERVER_TYPE_FARM_MEMBER)
		{
			char tmp[6 * MAX_PUBLIC_PORT_NUM + 1];
			UINT i;
			// ファームメンバの場合の設定項目
			CfgAddStr(f, "ControllerName", s->ControllerName);
			CfgAddInt(f, "ControllerPort", s->ControllerPort);
			CfgAddByte(f, "MemberPassword", s->MemberPassword, SHA1_SIZE);
			CfgAddIp32(f, "PublicIp", s->PublicIp);
			tmp[0] = 0;
			for (i = 0;i < s->NumPublicPort;i++)
			{
				char tmp2[MAX_SIZE];
				ToStr(tmp2, s->PublicPorts[i]);
				StrCat(tmp, sizeof(tmp), tmp2);
				StrCat(tmp, sizeof(tmp), ",");
			}
			if (StrLen(tmp) >= 1)
			{
				if (tmp[StrLen(tmp) - 1] == ',')
				{
					tmp[StrLen(tmp) - 1] = 0;
				}
			}
			CfgAddStr(f, "PublicPorts", tmp);
		}

		if (s->UpdatedServerType != SERVER_TYPE_STANDALONE)
		{
			CfgAddInt(f, "ClusterMemberWeight", s->Weight);
		}

		if (s->UpdatedServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			CfgAddBool(f, "ControllerOnly", s->ControllerOnly);
		}
	}
	Unlock(c->lock);
}

// トラフィック情報の読み込み
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	// 引数チェック
	if (t != NULL)
	{
		Zero(t, sizeof(TRAFFIC));
	}
	if (parent == NULL || name == NULL || t == NULL)
	{
		return;
	}

	f = CfgGetFolder(parent, name);

	if (f == NULL)
	{
		return;
	}

	SiLoadTrafficInner(f, "SendTraffic", &t->Send);
	SiLoadTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e)
{
	FOLDER *f;
	// 引数チェック
	if (e != NULL)
	{
		Zero(e, sizeof(TRAFFIC_ENTRY));
	}
	if (parent == NULL || name == NULL || e == NULL)
	{
		return;
	}

	f = CfgGetFolder(parent, name);
	if (f == NULL)
	{
		return;
	}

	e->BroadcastCount = CfgGetInt64(f, "BroadcastCount");
	e->BroadcastBytes = CfgGetInt64(f, "BroadcastBytes");
	e->UnicastCount = CfgGetInt64(f, "UnicastCount");
	e->UnicastBytes = CfgGetInt64(f, "UnicastBytes");
}

// トラフィック情報の書き込み
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	// 引数チェック
	if (parent == NULL || name == NULL || t == NULL)
	{
		return;
	}

	f = CfgCreateFolder(parent, name);

	SiWriteTrafficInner(f, "SendTraffic", &t->Send);
	SiWriteTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e)
{
	FOLDER *f;
	// 引数チェック
	if (parent == NULL || name == NULL || e == NULL)
	{
		return;
	}

	f = CfgCreateFolder(parent, name);
	CfgAddInt64(f, "BroadcastCount", e->BroadcastCount);
	CfgAddInt64(f, "BroadcastBytes", e->BroadcastBytes);
	CfgAddInt64(f, "UnicastCount", e->UnicastCount);
	CfgAddInt64(f, "UnicastBytes", e->UnicastBytes);
}

// 設定ファイル書き込み用スレッド
void SiSaverThread(THREAD *thread, void *param)
{
	SERVER *s = (SERVER *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (s->Halt == false)
	{
		// 設定ファイル保存
		SiWriteConfigurationFile(s);

		Wait(s->SaveHaltEvent, s->AutoSaveConfigSpan);
	}
}

// 設定ファイルに書き込む
UINT SiWriteConfigurationFile(SERVER *s)
{
	UINT ret;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	if (s->CfgRw == NULL)
	{
		return 0;
	}

	Lock(s->SaveCfgLock);
	{
		FOLDER *f;

		Debug("save: SiWriteConfigurationToCfg() start.\n");
		f = SiWriteConfigurationToCfg(s);
		Debug("save: SiWriteConfigurationToCfg() finished.\n");

		Debug("save: SaveCfgRw() start.\n");
		ret = SaveCfgRw(s->CfgRw, f);
		Debug("save: SaveCfgRw() finished.\n");

		Debug("save: CfgDeleteFolder() start.\n");
		CfgDeleteFolder(f);
		Debug("save: CfgDeleteFolder() finished.\n");
	}
	Unlock(s->SaveCfgLock);

	return ret;
}

// コンフィグレーション解放
void SiFreeConfiguration(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// 設定ファイルに書き込む
	SiWriteConfigurationFile(s);

	// 設定ファイル保存スレッドの終了
	s->Halt = true;
	Set(s->SaveHaltEvent);
	WaitThread(s->SaveThread, INFINITE);

	ReleaseEvent(s->SaveHaltEvent);
	ReleaseThread(s->SaveThread);

	FreeCfgRw(s->CfgRw);
	s->CfgRw = NULL;

	// Ethernet 解放
	FreeEth();
}

// StXxx 関係関数の初期化
void StInit()
{
	if (server_lock != NULL)
	{
		return;
	}

	server_lock = NewLock();
}

// StXxx 関係関数の解放
void StFree()
{
	DeleteLock(server_lock);
	server_lock = NULL;
}

// サーバーの開始
void StStartServer(bool bridge)
{
	Lock(server_lock);
	{
		if (server != NULL)
		{
			// すでに開始されている
			Unlock(server_lock);
			return;
		}

		// サーバーの作成
		server = SiNewServer(bridge);
	}
	Unlock(server_lock);

//	StartCedarLog();
}

// サーバーの取得
SERVER *StGetServer()
{
	if (server == NULL)
	{
		return NULL;
	}
	return server;
}

// サーバーの停止
void StStopServer()
{
	Lock(server_lock);
	{
		if (server == NULL)
		{
			// 開始されていない
			Unlock(server_lock);
			return;
		}

		// サーバーの解放
		SiReleaseServer(server);
		server = NULL;
	}
	Unlock(server_lock);

	StopCedarLog();
}

// サーバーの種類の設定
void SiSetServerType(SERVER *s, UINT type,
					 UINT ip, UINT num_port, UINT *ports,
					 char *controller_name, UINT controller_port, UCHAR *password, UINT weight, bool controller_only)
{
	bool bridge;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}
	if (type == SERVER_TYPE_FARM_MEMBER &&
		(num_port == 0 || ports == NULL || controller_name == NULL ||
		controller_port == 0 || password == NULL || num_port > MAX_PUBLIC_PORT_NUM))
	{
		return;
	}
	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	bridge = s->Cedar->Bridge;

	Lock(s->lock);
	{
		// 種類の更新
		s->UpdatedServerType = type;

		s->Weight = weight;

		// 値の設定
		if (type == SERVER_TYPE_FARM_MEMBER)
		{
			StrCpy(s->ControllerName, sizeof(s->ControllerName), controller_name);
			s->ControllerPort = controller_port;
			if (IsZero(password, SHA1_SIZE) == false)
			{
				Copy(s->MemberPassword, password, SHA1_SIZE);
			}
			s->PublicIp = ip;
			s->NumPublicPort = num_port;
			if (s->PublicPorts != NULL)
			{
				Free(s->PublicPorts);
			}
			s->PublicPorts = ZeroMalloc(num_port * sizeof(UINT));
			Copy(s->PublicPorts, ports, num_port * sizeof(UINT));
		}

		if (type == SERVER_TYPE_FARM_CONTROLLER)
		{
			s->ControllerOnly = controller_only;
		}
	}
	Unlock(s->lock);

	// サーバーの再起動
	SiRebootServer(bridge);
}

// サーバーの再起動スレッド
void SiRebootServerThread(THREAD *thread, void *param)
{
	// 引数チェック
	if (thread == NULL)
	{
		return;
	}

	if (server == NULL)
	{
		return;
	}

	// サーバーの停止
	StStopServer();

	// サーバーの開始
	StStartServer((bool)param);
}

// サーバーの再起動
void SiRebootServer(bool bridge)
{
	SiRebootServerEx(bridge, false);
}
void SiRebootServerEx(bool bridge, bool reset_setting)
{
	THREAD *t;

	server_reset_setting = reset_setting;

	t = NewThread(SiRebootServerThread, (void *)bridge);
	ReleaseThread(t);
}

// すべてのリスナーの停止
void SiStopAllListener(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		UINT i;
		LIST *o = NewListFast(NULL);
		for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
			Add(o, e);
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(o, i);
			SiDeleteListener(s, e->Port);
		}

		ReleaseList(o);
	}
	SiUnlockListenerList(s);

	ReleaseList(s->ServerListenerList);
}

// サーバーのクリーンアップ
void SiCleanupServer(SERVER *s)
{
	UINT i;
	CEDAR *c;
	LISTENER **listener_list;
	UINT num_listener;
	HUB **hub_list;
	UINT num_hub;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	SiFreeDeadLockCheck(s);

	FreeServerSnapshot(s);

	c = s->Cedar;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		// ファームメンバの場合、ファームコントローラへの接続を停止
		SLog(c, "LS_STOP_FARM_MEMBER");
		SiStopConnectToController(s->FarmController);
		s->FarmController = NULL;
		SLog(c, "LS_STOP_FARM_MEMBER_2");
	}

	IncrementServerConfigRevision(s);

	SLog(c, "LS_END_2");

	SLog(c, "LS_STOP_ALL_LISTENER");
	// すべてのリスナーを停止
	LockList(c->ListenerList);
	{
		listener_list = ToArray(c->ListenerList);
		num_listener = LIST_NUM(c->ListenerList);
		for (i = 0;i < num_listener;i++)
		{
			AddRef(listener_list[i]->ref);
		}
	}
	UnlockList(c->ListenerList);

	for (i = 0;i < num_listener;i++)
	{
		StopListener(listener_list[i]);
		ReleaseListener(listener_list[i]);
	}
	Free(listener_list);
	SLog(c, "LS_STOP_ALL_LISTENER_2");

	SLog(c, "LS_STOP_ALL_HUB");
	// すべての HUB を停止
	LockList(c->HubList);
	{
		hub_list = ToArray(c->HubList);
		num_hub = LIST_NUM(c->HubList);
		for (i = 0;i < num_hub;i++)
		{
			AddRef(hub_list[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num_hub;i++)
	{
		StopHub(hub_list[i]);
		ReleaseHub(hub_list[i]);
	}
	Free(hub_list);
	SLog(c, "LS_STOP_ALL_HUB_2");

	// コンフィグレーション解放
	SiFreeConfiguration(s);

	// Cedar の停止
	SLog(c, "LS_STOP_CEDAR");
	StopCedar(s->Cedar);
	SLog(c, "LS_STOP_CEDAR_2");

	// すべてのリスナーの停止
	SiStopAllListener(s);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// ファームコントローラの場合
		UINT i;

		SLog(c, "LS_STOP_FARM_CONTROL");

		// ファームコントロールを停止
		SiStopFarmControl(s);

		// ファームメンバ情報を解放
		ReleaseList(s->FarmMemberList);
		s->FarmMemberList = NULL;

		for (i = 0;i < LIST_NUM(s->Me->HubList);i++)
		{
			Free(LIST_DATA(s->Me->HubList, i));
		}
		ReleaseList(s->Me->HubList);

		Free(s->Me);

		SLog(c, "LS_STOP_FARM_CONTROL_2");
	}

	if (s->PublicPorts != NULL)
	{
		Free(s->PublicPorts);
	}

	SLog(s->Cedar, "LS_END_1");
	SLog(s->Cedar, "L_LINE");

	ReleaseCedar(s->Cedar);
	DeleteLock(s->lock);
	DeleteLock(s->SaveCfgLock);

	StopKeep(s->Keep);

	FreeEraser(s->Eraser);

	// ライセンスシステム解放
	if (s->LicenseSystem != NULL)
	{
		LiFreeLicenseSystem(s->LicenseSystem);
	}

	FreeLog(s->Logger);

	FreeServerCapsCache(s);

	SiFreeHubCreateHistory(s);

	// デバッグログの停止
	FreeTinyLog(s->DebugLog);

	DeleteLock(s->TasksFromFarmControllerLock);

	Free(s);
}

// サーバーの解放
void SiReleaseServer(SERVER *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		SiCleanupServer(s);
	}
}

// 次に処理をさせるファームメンバーを指定する
FARM_MEMBER *SiGetNextFarmMember(SERVER *s)
{
	UINT i, num;
	UINT min_point = 0;
	FARM_MEMBER *ret = NULL;
	// 引数チェック
	if (s == NULL || s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return NULL;
	}

	num = LIST_NUM(s->FarmMemberList);
	if (num == 0)
	{
		return NULL;
	}

	for (i = 0;i < num;i++)
	{
		UINT num_sessions;
		UINT max_sessions;
		FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
		if (s->ControllerOnly)
		{
			if (f->Me)
			{
				// ControllerOnly のとき自分自身は選定しない
				continue;
			}
		}

		if (f->Me == false)
		{
			num_sessions = f->NumSessions;
			max_sessions = f->MaxSessions;
		}
		else
		{
			num_sessions = Count(s->Cedar->CurrentSessions);
			max_sessions = GetServerCapsInt(s, "i_max_sessions");
		}

		if (max_sessions == 0)
		{
			max_sessions = GetServerCapsInt(s, "i_max_sessions");
		}

		if (num_sessions < max_sessions)
		{
			if (f->Point >= min_point)
			{
				min_point = f->Point;
				ret = f;
			}
		}
	}

	return ret;
}

// HUB 列挙指令受信
void SiCalledEnumHub(SERVER *s, PACK *p, PACK *req)
{
	UINT i;
	CEDAR *c;
	LICENSE_STATUS st;
	UINT num = 0;
	// 引数チェック
	if (s == NULL || p == NULL || req == NULL)
	{
		return;
	}

	LiParseCurrentLicenseStatus(s->LicenseSystem, &st);

	c = s->Cedar;

	LockList(c->HubList);
	{
		UINT num = LIST_NUM(c->HubList);
		for (i = 0;i < num;i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			Lock(h->lock);
			{
				PackAddStrEx(p, "HubName", h->Name, i, num);
				PackAddIntEx(p, "HubType", h->Type, i, num);
				PackAddIntEx(p, "NumSession", Count(h->NumSessions), i, num);

				PackAddIntEx(p, "NumSessions", LIST_NUM(h->SessionList), i, num);
				PackAddIntEx(p, "NumSessionsClient", Count(h->NumSessionsClient), i, num);
				PackAddIntEx(p, "NumSessionsBridge", Count(h->NumSessionsBridge), i, num);

				PackAddIntEx(p, "NumMacTables", LIST_NUM(h->MacTable), i, num);

				PackAddIntEx(p, "NumIpTables", LIST_NUM(h->IpTable), i, num);

				PackAddInt64Ex(p, "LastCommTime", h->LastCommTime, i, num);
				PackAddInt64Ex(p, "CreatedTime", h->CreatedTime, i, num);
			}
			Unlock(h->lock);
		}
	}
	UnlockList(c->HubList);

	PackAddInt(p, "Point", SiGetPoint(s));
	PackAddInt(p, "NumTcpConnections", Count(s->Cedar->CurrentTcpConnections));
	PackAddInt(p, "NumTotalSessions", Count(s->Cedar->CurrentSessions));
	PackAddInt(p, "MaxSessions", GetServerCapsInt(s, "i_max_sessions"));

	PackAddInt(p, "AssignedClientLicense", Count(s->Cedar->AssignedClientLicense));
	PackAddInt(p, "AssignedBridgeLicense", Count(s->Cedar->AssignedBridgeLicense));

	PackAddData(p, "RandomKey", s->MyRandomKey, SHA1_SIZE);
	PackAddInt64(p, "SystemId", st.SystemId);

	Lock(c->TrafficLock);
	{
		OutRpcTraffic(p, c->Traffic);
	}
	Unlock(c->TrafficLock);

	LockList(c->TrafficDiffList);
	{
		UINT num = LIST_NUM(c->TrafficDiffList);
		UINT i;

		for (i = 0;i < num;i++)
		{
			TRAFFIC_DIFF *d = LIST_DATA(c->TrafficDiffList, i);

			PackAddIntEx(p, "TdType", d->Type, i, num);
			PackAddStrEx(p, "TdHubName", d->HubName, i, num);
			PackAddStrEx(p, "TdName", d->Name, i, num);

			OutRpcTrafficEx(&d->Traffic, p, i, num);

			Free(d->HubName);
			Free(d->Name);
			Free(d);
		}

		DeleteAll(c->TrafficDiffList);
	}
	UnlockList(c->TrafficDiffList);
}

// HUB 削除指令受信
void SiCalledDeleteHub(SERVER *s, PACK *p)
{
	char name[MAX_SIZE];
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", name, sizeof(name)) == false)
	{
		return;
	}

	LockHubList(s->Cedar);

	h = GetHub(s->Cedar, name);
	if (h == NULL)
	{
		UnlockHubList(s->Cedar);
		return;
	}
	UnlockHubList(s->Cedar);

	SetHubOffline(h);

	LockHubList(s->Cedar);

	DelHubEx(s->Cedar, h, true);

	UnlockHubList(s->Cedar);

	ReleaseHub(h);
}

// HUB 更新指令受信
void SiCalledUpdateHub(SERVER *s, PACK *p)
{
	char name[MAX_SIZE];
	UINT type;
	HUB_OPTION o;
	HUB_LOG log;
	bool save_packet_log;
	UINT packet_log_switch_type;
	UINT packet_log_config[NUM_PACKET_LOG];
	bool save_security_log;
	bool type_changed = false;
	UINT security_log_switch_type;
	UINT i;
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "HubName", name, sizeof(name));
	type = PackGetInt(p, "HubType");
	Zero(&o, sizeof(o));
	o.MaxSession = PackGetInt(p, "MaxSession");
	o.NoArpPolling = PackGetBool(p, "NoArpPolling");
	o.NoIPv6AddrPolling = PackGetBool(p, "NoIPv6AddrPolling");
	o.FilterPPPoE = PackGetBool(p, "FilterPPPoE");
	o.YieldAfterStorePacket = PackGetBool(p, "YieldAfterStorePacket");
	o.NoSpinLockForPacketDelay = PackGetBool(p, "NoSpinLockForPacketDelay");
	o.BroadcastStormDetectionThreshold = PackGetInt(p, "BroadcastStormDetectionThreshold");
	o.ClientMinimumRequiredBuild = PackGetInt(p, "ClientMinimumRequiredBuild");
	o.FixForDLinkBPDU = PackGetBool(p, "FixForDLinkBPDU");
	o.NoLookBPDUBridgeId = PackGetBool(p, "NoLookBPDUBridgeId");
	o.NoManageVlanId = PackGetBool(p, "NoManageVlanId");
	o.VlanTypeId = PackGetInt(p, "VlanTypeId");
	if (o.VlanTypeId == 0)
	{
		o.VlanTypeId = MAC_PROTO_TAGVLAN;
	}
	o.FilterOSPF = PackGetBool(p, "FilterOSPF");
	o.FilterIPv4 = PackGetBool(p, "FilterIPv4");
	o.FilterIPv6 = PackGetBool(p, "FilterIPv6");
	o.FilterNonIP = PackGetBool(p, "FilterNonIP");
	o.NoIPv4PacketLog = PackGetBool(p, "NoIPv4PacketLog");
	o.NoIPv6PacketLog = PackGetBool(p, "NoIPv6PacketLog");
	o.FilterBPDU = PackGetBool(p, "FilterBPDU");
	o.NoIPv6DefaultRouterInRAWhenIPv6 = PackGetBool(p, "NoIPv6DefaultRouterInRAWhenIPv6");
	o.NoMacAddressLog = PackGetBool(p, "NoMacAddressLog");
	o.ManageOnlyPrivateIP = PackGetBool(p, "ManageOnlyPrivateIP");
	o.ManageOnlyLocalUnicastIPv6 = PackGetBool(p, "ManageOnlyLocalUnicastIPv6");
	o.DisableIPParsing = PackGetBool(p, "DisableIPParsing");
	o.NoIpTable = PackGetBool(p, "NoIpTable");
	o.NoEnum = PackGetBool(p, "NoEnum");
	save_packet_log = PackGetInt(p, "SavePacketLog");
	packet_log_switch_type = PackGetInt(p, "PacketLogSwitchType");
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		packet_log_config[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
	save_security_log = PackGetInt(p, "SaveSecurityLog");
	security_log_switch_type = PackGetInt(p, "SecurityLogSwitchType");

	Zero(&log, sizeof(log));
	log.SavePacketLog = save_packet_log;
	log.PacketLogSwitchType = packet_log_switch_type;
	Copy(log.PacketLogConfig, packet_log_config, sizeof(log.PacketLogConfig));
	log.SaveSecurityLog = save_security_log;
	log.SecurityLogSwitchType = security_log_switch_type;

	h = GetHub(s->Cedar, name);
	if (h == NULL)
	{
		return;
	}

	h->FarmMember_MaxSessionClient = PackGetInt(p, "MaxSessionClient");
	h->FarmMember_MaxSessionBridge = PackGetInt(p, "MaxSessionBridge");
	h->FarmMember_MaxSessionClientBridgeApply = PackGetBool(p, "MaxSessionClientBridgeApply");

	if (h->FarmMember_MaxSessionClientBridgeApply == false)
	{
		h->FarmMember_MaxSessionClient = INFINITE;
		h->FarmMember_MaxSessionBridge = INFINITE;
	}

	Lock(h->lock);
	{
		Copy(h->Option, &o, sizeof(HUB_OPTION));
		PackGetData2(p, "SecurePassword", h->SecurePassword, SHA1_SIZE);
		PackGetData2(p, "HashedPassword", h->HashedPassword, SHA1_SIZE);
	}
	Unlock(h->lock);

	SetHubLogSetting(h, &log);

	if (h->Type != type)
	{
		h->Type = type;
		type_changed = true;
	}

	LockList(h->AccessList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(h->AccessList, i);
			Free(a);
		}
		DeleteAll(h->AccessList);
	}
	UnlockList(h->AccessList);

	for (i = 0;i < SiNumAccessFromPack(p);i++)
	{
		ACCESS *a = SiPackToAccess(p, i);
		AddAccessList(h, a);
		Free(a);
	}

	if (PackGetBool(p, "EnableSecureNAT"))
	{
		VH_OPTION t;
		bool changed;

		InVhOption(&t, p);

		changed = Cmp(h->SecureNATOption, &t, sizeof(VH_OPTION)) == 0 ? false : true;
		Copy(h->SecureNATOption, &t, sizeof(VH_OPTION));

		EnableSecureNAT(h, true);

		if (changed)
		{
			Lock(h->lock_online);
			{
				if (h->SecureNAT != NULL)
				{
					SetVirtualHostOption(h->SecureNAT->Nat->Virtual, &t);
					Debug("SiCalledUpdateHub: SecureNAT Updated.\n");
				}
			}
			Unlock(h->lock_online);
		}
	}
	else
	{
		EnableSecureNAT(h, false);
		Debug("SiCalledUpdateHub: SecureNAT Disabled.\n");
	}

	if (type_changed)
	{
		// HUB の種類が変更されたのですべてのセッションを削除する
		if (h->Offline == false)
		{
			SetHubOffline(h);
			SetHubOnline(h);
		}
	}

	ReleaseHub(h);
}

// チケットの検査
bool SiCheckTicket(HUB *h, UCHAR *ticket, char *username, UINT username_size, char *usernamereal, UINT usernamereal_size, POLICY *policy, char *sessionname, UINT sessionname_size, char *groupname, UINT groupname_size)
{
	bool ret = false;
	// 引数チェック
	if (h == NULL || ticket == NULL || username == NULL || usernamereal == NULL || policy == NULL || sessionname == NULL)
	{
		return false;
	}

	LockList(h->TicketList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->TicketList);i++)
		{
			TICKET *t = LIST_DATA(h->TicketList, i);
			if (Cmp(t->Ticket, ticket, SHA1_SIZE) == 0)
			{
				ret = true;
				StrCpy(username, username_size, t->Username);
				StrCpy(usernamereal, usernamereal_size, t->UsernameReal);
				StrCpy(sessionname, sessionname_size, t->SessionName);
				StrCpy(groupname, groupname_size, t->GroupName);
				Copy(policy, &t->Policy, sizeof(POLICY));
				Delete(h->TicketList, t);
				Free(t);
				break;
			}
		}
	}
	UnlockList(h->TicketList);

	return ret;
}

// MAC アドレス削除指令受信
void SiCalledDeleteMacTable(SERVER *s, PACK *p)
{
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return;
	}
	key = PackGetInt(p, "Key");

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		return;
	}

	LockList(h->MacTable);
	{
		if (IsInList(h->MacTable, (void *)key))
		{
			MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)key;
			Delete(h->MacTable, e);
			Free(e);
		}
	}
	UnlockList(h->MacTable);

	ReleaseHub(h);
}

// IP アドレス削除指令受信
void SiCalledDeleteIpTable(SERVER *s, PACK *p)
{
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return;
	}
	key = PackGetInt(p, "Key");

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		return;
	}

	LockList(h->IpTable);
	{
		if (IsInList(h->IpTable, (void *)key))
		{
			IP_TABLE_ENTRY *e = (IP_TABLE_ENTRY *)key;
			Delete(h->IpTable, e);
			Free(e);
		}
	}
	UnlockList(h->IpTable);

	ReleaseHub(h);
}

// セッション削除指令受信
void SiCalledDeleteSession(SERVER *s, PACK *p)
{
	char name[MAX_SESSION_NAME_LEN + 1];
	char hubname[MAX_HUBNAME_LEN + 1];
	HUB *h;
	SESSION *sess;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return;
	}
	if (PackGetStr(p, "SessionName", name, sizeof(name)) == false)
	{
		return;
	}

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		return;
	}

	sess = GetSessionByName(h, name);

	if (sess != NULL)
	{
		if (sess->BridgeMode == false && sess->LinkModeServer == false && sess->SecureNATMode == false)
		{
			StopSession(sess);
		}
		ReleaseSession(sess);
	}

	ReleaseHub(h);
}

// ログファイル読み込み指令受信
PACK *SiCalledReadLogFile(SERVER *s, PACK *p)
{
	RPC_READ_LOG_FILE t;
	PACK *ret;
	char filepath[MAX_PATH];
	UINT offset;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NULL;
	}

	PackGetStr(p, "FilePath", filepath, sizeof(filepath));
	offset = PackGetInt(p, "Offset");

	Zero(&t, sizeof(t));

	SiReadLocalLogFile(s, filepath, offset, &t);

	ret = NewPack();

	OutRpcReadLogFile(ret, &t);
	FreeRpcReadLogFile(&t);

	return ret;
}

// ログファイル列挙指令受信
PACK *SiCalledEnumLogFileList(SERVER *s, PACK *p)
{
	RPC_ENUM_LOG_FILE t;
	PACK *ret;
	char hubname[MAX_HUBNAME_LEN + 1];
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NULL;
	}

	PackGetStr(p, "HubName", hubname, sizeof(hubname));

	Zero(&t, sizeof(t));

	SiEnumLocalLogFileList(s, hubname, &t);

	ret = NewPack();

	OutRpcEnumLogFile(ret, &t);
	FreeRpcEnumLogFile(&t);

	return ret;
}

// セッション情報指令受信
PACK *SiCalledGetSessionStatus(SERVER *s, PACK *p)
{
	RPC_SESSION_STATUS t;
	ADMIN a;
	PACK *ret;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	InRpcSessionStatus(&t, p);

	Zero(&a, sizeof(a));
	a.Server = s;
	a.ServerAdmin = true;

	if (StGetSessionStatus(&a, &t) != ERR_NO_ERROR)
	{
		FreeRpcSessionStatus(&t);
		return NULL;
	}

	ret = NewPack();

	OutRpcSessionStatus(ret, &t);

	FreeRpcSessionStatus(&t);

	return ret;
}

// IP テーブル列挙指令
PACK *SiCalledEnumIpTable(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_IP_TABLE t;
	PACK *ret;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	SiEnumIpTable(s, hubname, &t);

	ret = NewPack();
	OutRpcEnumIpTable(ret, &t);
	FreeRpcEnumIpTable(&t);

	return ret;
}

// MAC テーブル列挙指令
PACK *SiCalledEnumMacTable(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_MAC_TABLE t;
	PACK *ret;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	SiEnumMacTable(s, hubname, &t);

	ret = NewPack();
	OutRpcEnumMacTable(ret, &t);
	FreeRpcEnumMacTable(&t);

	return ret;
}

// NAT の状況取得指令
PACK *SiCalledGetNatStatus(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_NAT_STATUS t;
	PACK *ret;
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h != NULL)
	{
		Lock(h->lock_online);
		{
			if (h->SecureNAT != NULL)
			{
				NtGetStatus(h->SecureNAT->Nat, &t);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);

	ret = NewPack();
	OutRpcNatStatus(ret, &t);
	FreeRpcNatStatus(&t);

	return ret;
}

// DHCP テーブル列挙指令
PACK *SiCalledEnumDhcp(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_DHCP t;
	PACK *ret;
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h != NULL)
	{
		Lock(h->lock_online);
		{
			if (h->SecureNAT != NULL)
			{
				NtEnumDhcpList(h->SecureNAT->Nat, &t);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);

	ret = NewPack();
	OutRpcEnumDhcp(ret, &t);
	FreeRpcEnumDhcp(&t);

	return ret;
}

// NAT テーブル列挙指令
PACK *SiCalledEnumNat(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_NAT t;
	PACK *ret;
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h != NULL)
	{
		Lock(h->lock_online);
		{
			if (h->SecureNAT != NULL)
			{
				NtEnumNatList(h->SecureNAT->Nat, &t);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);

	ret = NewPack();
	OutRpcEnumNat(ret, &t);
	FreeRpcEnumNat(&t);

	return ret;
}

// セッション列挙指令受信
PACK *SiCalledEnumSession(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_SESSION t;
	PACK *ret;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	SiEnumLocalSession(s, hubname, &t);

	ret = NewPack();
	OutRpcEnumSession(ret, &t);
	FreeRpcEnumSession(&t);

	return ret;
}

// チケット作成指令受信
PACK *SiCalledCreateTicket(SERVER *s, PACK *p)
{
	char username[MAX_SIZE];
	char hubname[MAX_SIZE];
	char groupname[MAX_SIZE];
	char realusername[MAX_SIZE];
	char sessionname[MAX_SESSION_NAME_LEN + 1];
	POLICY policy;
	UCHAR ticket[SHA1_SIZE];
	char ticket_str[MAX_SIZE];
	HUB *h;
	UINT i;
	PACK *ret;
	TICKET *t;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}

	PackGetStr(p, "UserName", username, sizeof(username));
	PackGetStr(p, "GroupName", groupname, sizeof(groupname));
	PackGetStr(p, "HubName", hubname, sizeof(hubname));
	PackGetStr(p, "RealUserName", realusername, sizeof(realusername));
	PackGetStr(p, "SessionName", sessionname, sizeof(sessionname));

	InRpcPolicy(&policy, p);
	if (PackGetDataSize(p, "Ticket") == SHA1_SIZE)
	{
		PackGetData(p, "Ticket", ticket);
	}

	BinToStr(ticket_str, sizeof(ticket_str), ticket, SHA1_SIZE);

	SLog(s->Cedar, "LS_TICKET_2", hubname, username, realusername, sessionname,
		ticket_str, TICKET_EXPIRES / 1000);

	// HUB を取得
	h = GetHub(s->Cedar, hubname);
	if (h == NULL)
	{
		return NewPack();
	}

	LockList(h->TicketList);
	{
		LIST *o = NewListFast(NULL);
		// 古いチケットを破棄
		for (i = 0;i < LIST_NUM(h->TicketList);i++)
		{
			TICKET *t = LIST_DATA(h->TicketList, i);
			if ((t->CreatedTick + TICKET_EXPIRES) < Tick64())
			{
				Add(o, t);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			TICKET *t = LIST_DATA(o, i);
			Delete(h->TicketList, t);
			Free(t);
		}
		ReleaseList(o);

		// チケットを作成
		t = ZeroMalloc(sizeof(TICKET));
		t->CreatedTick = Tick64();
		Copy(&t->Policy, &policy, sizeof(POLICY));
		Copy(t->Ticket, ticket, SHA1_SIZE);
		StrCpy(t->Username, sizeof(t->Username), username);
		StrCpy(t->UsernameReal, sizeof(t->UsernameReal), realusername);
		StrCpy(t->GroupName, sizeof(t->GroupName), groupname);
		StrCpy(t->SessionName, sizeof(t->SessionName), sessionname);

		Add(h->TicketList, t);
	}
	UnlockList(h->TicketList);

	ReleaseHub(h);

	ret = NewPack();

	PackAddInt(ret, "Point", SiGetPoint(s));

	return ret;
}

// HUB 作成指令受信
void SiCalledCreateHub(SERVER *s, PACK *p)
{
	char name[MAX_SIZE];
	UINT type;
	HUB_OPTION o;
	HUB_LOG log;
	bool save_packet_log;
	UINT packet_log_switch_type;
	UINT packet_log_config[NUM_PACKET_LOG];
	bool save_security_log;
	UINT security_log_switch_type;
	UINT i;
	HUB *h;
	// 引数チェック
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "HubName", name, sizeof(name));
	type = PackGetInt(p, "HubType");
	Zero(&o, sizeof(o));
	o.MaxSession = PackGetInt(p, "MaxSession");
	save_packet_log = PackGetInt(p, "SavePacketLog");
	packet_log_switch_type = PackGetInt(p, "PacketLogSwitchType");
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		packet_log_config[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
	save_security_log = PackGetInt(p, "SaveSecurityLog");
	security_log_switch_type = PackGetInt(p, "SecurityLogSwitchType");

	Zero(&log, sizeof(log));
	log.SavePacketLog = save_packet_log;
	log.PacketLogSwitchType = packet_log_switch_type;
	Copy(log.PacketLogConfig, packet_log_config, sizeof(log.PacketLogConfig));
	log.SaveSecurityLog = save_security_log;
	log.SecurityLogSwitchType = security_log_switch_type;

	h = NewHub(s->Cedar, name, &o);
	h->LastCommTime = h->LastLoginTime = h->CreatedTime = 0;
	SetHubLogSetting(h, &log);
	h->Type = type;
	h->FarmMember_MaxSessionClient = PackGetInt(p, "MaxSessionClient");
	h->FarmMember_MaxSessionBridge = PackGetInt(p, "MaxSessionBridge");
	h->FarmMember_MaxSessionClientBridgeApply = PackGetBool(p, "MaxSessionClientBridgeApply");

	if (h->FarmMember_MaxSessionClientBridgeApply == false)
	{
		h->FarmMember_MaxSessionClient = INFINITE;
		h->FarmMember_MaxSessionBridge = INFINITE;
	}

	PackGetData2(p, "SecurePassword", h->SecurePassword, SHA1_SIZE);
	PackGetData2(p, "HashedPassword", h->HashedPassword, SHA1_SIZE);

	for (i = 0;i < SiNumAccessFromPack(p);i++)
	{
		ACCESS *a = SiPackToAccess(p, i);
		AddAccessList(h, a);
		Free(a);
	}

	if (PackGetBool(p, "EnableSecureNAT"))
	{
		VH_OPTION t;

		InVhOption(&t, p);

		Copy(h->SecureNATOption, &t, sizeof(VH_OPTION));
		EnableSecureNAT(h, true);

		Debug("SiCalledCreateHub: SecureNAT Created.\n");
	}

	AddHub(s->Cedar, h);
	h->Offline = true;
	SetHubOnline(h);

	ReleaseHub(h);
}

// ファームコントロールスレッド
void SiFarmControlThread(THREAD *thread, void *param)
{
	SERVER *s;
	CEDAR *c;
	EVENT *e;
	LIST *o;
	UINT i;
	char tmp[MAX_PATH];
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	s = (SERVER *)param;
	c = s->Cedar;
	e = s->FarmControlThreadHaltEvent;

	while (true)
	{
		Lock(c->CedarSuperLock);

		// 各ファームメンバーがホストしている HUB 一覧を列挙する
		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		LockList(s->FarmMemberList);
		{
			UINT i;
			UINT num;
			UINT assigned_client_license = 0;
			UINT assigned_bridge_license = 0;

			Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
			SiDebugLog(s, tmp);

			num = 0;

			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				SiCallEnumHub(s, f);
				// サーバーファーム全体での合計セッション数を取得する
				num += f->NumSessions;

				assigned_client_license += f->AssignedClientLicense;
				assigned_bridge_license += f->AssignedBridgeLicense;
			}

			s->CurrentTotalNumSessionsOnFarm = num;

			// 割り当て済みライセンス数を更新する
			s->CurrentAssignedBridgeLicense = assigned_bridge_license;
			s->CurrentAssignedClientLicense = assigned_client_license;

			Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
			SiDebugLog(s, tmp);
		}
		UnlockList(s->FarmMemberList);

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		o = NewListFast(NULL);

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		// 各 HUB に対して更新通知を発する
		LockList(c->HubList);
		{
			UINT i;
			for (i = 0;i < LIST_NUM(c->HubList);i++)
			{
				HUB *h = LIST_DATA(c->HubList, i);
				AddRef(h->ref);
				Add(o, h);
			}
		}
		UnlockList(c->HubList);

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			HUB *h = LIST_DATA(o, i);
			SiHubUpdateProc(h);
			ReleaseHub(h);
		}

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		ReleaseList(o);

		Unlock(c->CedarSuperLock);

		Wait(e, SERVER_FARM_CONTROL_INTERVAL);
		if (s->Halt)
		{
			break;
		}
	}
}

// ファームコントロールの開始
void SiStartFarmControl(SERVER *s)
{
	// 引数チェック
	if (s == NULL || s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return;
	}

	s->FarmControlThreadHaltEvent = NewEvent();
	s->FarmControlThread = NewThread(SiFarmControlThread, s);
}

// ファームコントロールの終了
void SiStopFarmControl(SERVER *s)
{
	// 引数チェック
	if (s == NULL || s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return;
	}

	Set(s->FarmControlThreadHaltEvent);
	WaitThread(s->FarmControlThread, INFINITE);
	ReleaseEvent(s->FarmControlThreadHaltEvent);
	ReleaseThread(s->FarmControlThread);
}

// HUB 列挙指令
void SiCallEnumHub(SERVER *s, FARM_MEMBER *f)
{
	CEDAR *c;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	c = s->Cedar;

	if (f->Me)
	{
		LICENSE_STATUS st;

		LiParseCurrentLicenseStatus(s->LicenseSystem, &st);

		// ローカルの HUB を列挙する
		LockList(f->HubList);
		{
			// ローカル HUB の場合、まず STATIC HUB リストを一旦
			// すべて消去して再列挙を行うようにする
			UINT i;
			LIST *o = NewListFast(NULL);
			for (i = 0;i < LIST_NUM(f->HubList);i++)
			{
				HUB_LIST *h = LIST_DATA(f->HubList, i);
				if (h->DynamicHub == false)
				{
					Add(o, h);
				}
			}

			// STATIC HUB をすべて消去
			for (i = 0;i < LIST_NUM(o);i++)
			{
				HUB_LIST *h = LIST_DATA(o, i);
				Free(h);
				Delete(f->HubList, h);
			}
			ReleaseList(o);

			// 次に DYNAMIC HUB でユーザーが 1 人もいないものを停止する
			o = NewListFast(NULL);
			for (i = 0;i < LIST_NUM(f->HubList);i++)
			{
				HUB_LIST *h = LIST_DATA(f->HubList, i);
				if (h->DynamicHub == true)
				{
					LockList(c->HubList);
					{
						HUB *hub = GetHub(s->Cedar, h->Name);
						if (hub != NULL)
						{
							if (Count(hub->NumSessions) == 0 || hub->Type != HUB_TYPE_FARM_DYNAMIC)
							{
								Add(o, h);
							}
							ReleaseHub(hub);
						}
					}
					UnlockList(c->HubList);
				}
			}

			for (i = 0;i < LIST_NUM(o);i++)
			{
				HUB_LIST *h = LIST_DATA(o, i);
				Debug("Delete HUB: %s\n", h->Name);
				Free(h);
				Delete(f->HubList, h);
			}

			ReleaseList(o);

			// 列挙結果を設定
			LockList(c->HubList);
			{
				for (i = 0;i < LIST_NUM(c->HubList);i++)
				{
					HUB *h = LIST_DATA(c->HubList, i);
					if (h->Offline == false)
					{
						if (h->Type == HUB_TYPE_FARM_STATIC)
						{
							HUB_LIST *hh = ZeroMalloc(sizeof(HUB_LIST));
							hh->FarmMember = f;
							hh->DynamicHub = false;
							StrCpy(hh->Name, sizeof(hh->Name), h->Name);
							Add(f->HubList, hh);

							LockList(h->SessionList);
							{
								hh->NumSessions = LIST_NUM(h->SessionList);
								hh->NumSessionsBridge = Count(h->NumSessionsBridge);
								hh->NumSessionsClient = Count(h->NumSessionsClient);
							}
							UnlockList(h->SessionList);

							LockList(h->MacTable);
							{
								hh->NumMacTables = LIST_NUM(h->MacTable);
							}
							UnlockList(h->MacTable);

							LockList(h->IpTable);
							{
								hh->NumIpTables = LIST_NUM(h->IpTable);
							}
							UnlockList(h->IpTable);
						}
					}
				}
			}
			UnlockList(c->HubList);
		}
		UnlockList(f->HubList);

		// ポイント
		f->Point = SiGetPoint(s);
		f->NumSessions = Count(s->Cedar->CurrentSessions);
		f->MaxSessions = GetServerCapsInt(s, "i_max_sessions");
		f->NumTcpConnections = Count(s->Cedar->CurrentTcpConnections);

		Lock(s->Cedar->TrafficLock);
		{
			Copy(&f->Traffic, s->Cedar->Traffic, sizeof(TRAFFIC));
		}
		Unlock(s->Cedar->TrafficLock);

		f->AssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
		f->AssignedClientLicense = Count(s->Cedar->AssignedClientLicense);

		Copy(f->RandomKey, s->MyRandomKey, SHA1_SIZE);
		f->SystemId = st.SystemId;

		Debug("Server %s: Point %u\n", f->hostname, f->Point);
	}
	else
	{
		// リモートのメンバの HUB を列挙する
		PACK *p = NewPack();
		UINT i, num, j;
		LIST *o = NewListFast(NULL);

		num = 0;

		for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

			if (IsZero(f->RandomKey, SHA1_SIZE) == false && f->SystemId != 0)
			{
				num++;
			}
		}

		j = 0;

		for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

			if (IsZero(f->RandomKey, SHA1_SIZE) == false && f->SystemId != 0)
			{
				PackAddDataEx(p, "MemberRandomKey", f->RandomKey, SHA1_SIZE, j, num);
				PackAddInt64Ex(p, "MemberSystemId", f->SystemId, j, num);
				j++;
			}
		}
		PackAddInt(p, "MemberSystemIdNum", num);

		p = SiCallTask(f, p, "enumhub");
		if (p != NULL)
		{
			LockList(f->HubList);
			{
				UINT i;
				// リスト消去
				for (i = 0;i < LIST_NUM(f->HubList);i++)
				{
					HUB_LIST *hh = LIST_DATA(f->HubList, i);
					Free(hh);
				}
				DeleteAll(f->HubList);

				for (i = 0;i < PackGetIndexCount(p, "HubName");i++)
				{
					HUB_LIST *hh = ZeroMalloc(sizeof(HUB_LIST));
					UINT num;
					UINT64 LastCommTime;

					PackGetStrEx(p, "HubName", hh->Name, sizeof(hh->Name), i);
					num = PackGetIntEx(p, "NumSession", i);
					hh->DynamicHub = ((PackGetIntEx(p, "HubType", i) == HUB_TYPE_FARM_DYNAMIC) ? true : false);
					hh->FarmMember = f;
					hh->NumSessions = PackGetIntEx(p, "NumSessions", i);
					hh->NumSessionsClient = PackGetIntEx(p, "NumSessionsClient", i);
					hh->NumSessionsBridge = PackGetIntEx(p, "NumSessionsBridge", i);
					hh->NumIpTables = PackGetIntEx(p, "NumIpTables", i);
					hh->NumMacTables = PackGetIntEx(p, "NumMacTables", i);
					LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
					Add(f->HubList, hh);
					Debug("%s\n", hh->Name);

					LockList(c->HubList);
					{
						HUB *h = GetHub(c, hh->Name);

						if (h != NULL)
						{
							// 仮想 HUB の LastCommTime を更新する
							Lock(h->lock);
							{
								if (h->LastCommTime < LastCommTime)
								{
									h->LastCommTime = LastCommTime;
								}
							}
							Unlock(h->lock);

							ReleaseHub(h);
						}
					}
					UnlockList(c->HubList);

					if (hh->DynamicHub && num >= 1)
					{
						// すでにユーザーセッションが 1 以上接続されているので
						// 仮想 HUB 作成履歴リストに登録しておく必要はない
						// 仮想 HUB 作成履歴リストから削除する
						SiDelHubCreateHistory(s, hh->Name);
					}

					if (hh->DynamicHub && num == 0)
					{
						// 仮想 HUB 作成履歴リストを確認する
						// 直近 60 秒以内に作成され、まだ 1 人目のユーザーが接続
						// していない仮想 HUB の場合は、ユーザーが 1 人もいないという
						// 理由で削除しない
						if (SiIsHubRegistedOnCreateHistory(s, hh->Name) == false)
						{
							// ダイナミック HUB でユーザーが 1 人もいないので停止する
							HUB *h;
							LockList(c->HubList);
							{
								h = GetHub(c, hh->Name);
							}
							UnlockList(c->HubList);

							if (h != NULL)
							{
								Add(o, h);
							}
						}
					}
				}
			}
			UnlockList(f->HubList);
			f->Point = PackGetInt(p, "Point");
			Debug("Server %s: Point %u\n", f->hostname, f->Point);
			f->NumSessions = PackGetInt(p, "NumTotalSessions");
			if (f->NumSessions == 0)
			{
				f->NumSessions = PackGetInt(p, "NumSessions");
			}
			f->MaxSessions = PackGetInt(p, "MaxSessions");
			f->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
			InRpcTraffic(&f->Traffic, p);

			f->AssignedBridgeLicense = PackGetInt(p, "AssignedBridgeLicense");
			f->AssignedClientLicense = PackGetInt(p, "AssignedClientLicense");

			if (PackGetDataSize(p, "RandomKey") == SHA1_SIZE)
			{
				PackGetData(p, "RandomKey", f->RandomKey);
			}

			f->SystemId = PackGetInt64(p, "SystemId");

			// トラフィック差分情報を適用する
			num = PackGetIndexCount(p, "TdType");
			for (i = 0;i < num;i++)
			{
				TRAFFIC traffic;
				UINT type;
				HUB *h;
				char name[MAX_SIZE];
				char hubname[MAX_SIZE];

				type = PackGetIntEx(p, "TdType", i);
				PackGetStrEx(p, "TdName", name, sizeof(name), i);
				PackGetStrEx(p, "TdHubName", hubname, sizeof(hubname), i);
				InRpcTrafficEx(&traffic, p, i);

				LockList(c->HubList);
				{
					h = GetHub(c, hubname);
					if (h != NULL)
					{
						if (type == TRAFFIC_DIFF_HUB)
						{
							Lock(h->TrafficLock);
							{
								AddTraffic(h->Traffic, &traffic);
							}
							Unlock(h->TrafficLock);
						}
						else
						{
							AcLock(h);
							{
								USER *u = AcGetUser(h, name);
								if (u != NULL)
								{
									Lock(u->lock);
									{
										AddTraffic(u->Traffic, &traffic);
									}
									Unlock(u->lock);
									if (u->Group != NULL)
									{
										Lock(u->Group->lock);
										{
											AddTraffic(u->Group->Traffic, &traffic);
										}
										Unlock(u->Group->lock);
									}
									ReleaseUser(u);
								}
							}
							AcUnlock(h);
						}
						ReleaseHub(h);
					}
					UnlockList(c->HubList);
				}
			}

			FreePack(p);
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			HUB *h = LIST_DATA(o, i);
			SiCallDeleteHub(s, f, h);
			Debug("Delete HUB: %s\n", h->Name);
			ReleaseHub(h);
		}

		ReleaseList(o);
	}
}

// セッション情報取得指令
bool SiCallGetSessionStatus(SERVER *s, FARM_MEMBER *f, RPC_SESSION_STATUS *t)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return false;
	}

	p = NewPack();
	OutRpcSessionStatus(p, t);
	FreeRpcSessionStatus(t);
	Zero(t, sizeof(RPC_SESSION_STATUS));

	p = SiCallTask(f, p, "getsessionstatus");

	if (p == NULL)
	{
		return false;
	}

	InRpcSessionStatus(t, p);
	FreePack(p);

	return true;
}

// ログファイル読み込み指令
bool SiCallReadLogFile(SERVER *s, FARM_MEMBER *f, RPC_READ_LOG_FILE *t)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return false;
	}

	p = NewPack();
	OutRpcReadLogFile(p, t);
	FreeRpcReadLogFile(t);
	Zero(t, sizeof(RPC_READ_LOG_FILE));

	p = SiCallTask(f, p, "readlogfile");

	if (p == NULL)
	{
		return false;
	}

	InRpcReadLogFile(t, p);
	FreePack(p);

	return true;
}

// ログファイルリスト列挙指令
bool SiCallEnumLogFileList(SERVER *s, FARM_MEMBER *f, RPC_ENUM_LOG_FILE *t, char *hubname)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return false;
	}

	p = NewPack();
	OutRpcEnumLogFile(p, t);
	FreeRpcEnumLogFile(t);
	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumlogfilelist");

	if (p == NULL)
	{
		return false;
	}

	InRpcEnumLogFile(t, p);
	FreePack(p);

	return true;
}

// HUB 削除指令
void SiCallDeleteHub(SERVER *s, FARM_MEMBER *f, HUB *h)
{
	PACK *p;
	UINT i;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	if (f->Me == false)
	{
		p = NewPack();

		PackAddStr(p, "HubName", h->Name);

		p = SiCallTask(f, p, "deletehub");
		FreePack(p);
	}

	LockList(f->HubList);
	{
		for (i = 0;i < LIST_NUM(f->HubList);i++)
		{
			HUB_LIST *hh = LIST_DATA(f->HubList, i);
			if (StrCmpi(hh->Name, h->Name) == 0)
			{
				Free(hh);
				Delete(f->HubList, hh);
			}
		}
	}
	UnlockList(f->HubList);
}

// HUB 更新指令送信
void SiCallUpdateHub(SERVER *s, FARM_MEMBER *f, HUB *h)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	if (f->Me == false)
	{
		p = NewPack();

		SiPackAddCreateHub(p, h);

		p = SiCallTask(f, p, "updatehub");
		FreePack(p);
	}
}

// チケット作成指令送信
void SiCallCreateTicket(SERVER *s, FARM_MEMBER *f, char *hubname, char *username, char *realusername, POLICY *policy, UCHAR *ticket, UINT counter, char *groupname)
{
	PACK *p;
	char name[MAX_SESSION_NAME_LEN + 1];
	char hub_name_upper[MAX_SIZE];
	char user_name_upper[MAX_USERNAME_LEN + 1];
	char ticket_str[MAX_SIZE];
	UINT point;
	// 引数チェック
	if (s == NULL || f == NULL || realusername == NULL || hubname == NULL || username == NULL || policy == NULL || ticket == NULL)
	{
		return;
	}
	if (groupname == NULL)
	{
		groupname = "";
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddStr(p, "UserName", username);
	PackAddStr(p, "groupname", groupname);
	PackAddStr(p, "RealUserName", realusername);
	OutRpcPolicy(p, policy);
	PackAddData(p, "Ticket", ticket, SHA1_SIZE);

	BinToStr(ticket_str, sizeof(ticket_str), ticket, SHA1_SIZE);

	StrCpy(hub_name_upper, sizeof(hub_name_upper), hubname);
	StrUpper(hub_name_upper);
	StrCpy(user_name_upper, sizeof(user_name_upper), username);
	StrUpper(user_name_upper);
	Format(name, sizeof(name), "SID-%s-%u", user_name_upper,
		counter);
	PackAddStr(p, "SessionName", name);

	p = SiCallTask(f, p, "createticket");

	SLog(s->Cedar, "LS_TICKET_1", f->hostname, hubname, username, realusername, name, ticket_str);

	point = PackGetInt(p, "Point");
	if (point != 0)
	{
		f->Point = point;
		f->NumSessions++;
	}

	FreePack(p);
}

// MAC アドレス削除指令送信
void SiCallDeleteMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddInt(p, "Key", key);

	p = SiCallTask(f, p, "deletemactable");

	FreePack(p);
}

// IP アドレス削除指令送信
void SiCallDeleteIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddInt(p, "Key", key);

	p = SiCallTask(f, p, "deleteiptable");

	FreePack(p);
}

// セッション削除指令送信
void SiCallDeleteSession(SERVER *s, FARM_MEMBER *f, char *hubname, char *session_name)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL || session_name == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddStr(p, "SessionName", session_name);

	p = SiCallTask(f, p, "deletesession");

	FreePack(p);
}

// IP テーブル列挙指令送信
void SiCallEnumIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_IP_TABLE *t)
{
	PACK *p;
	UINT i;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumiptable");

	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	InRpcEnumIpTable(t, p);

	for (i = 0;i < t->NumIpTable;i++)
	{
		t->IpTables[i].RemoteItem = true;
		StrCpy(t->IpTables[i].RemoteHostname, sizeof(t->IpTables[i].RemoteHostname),
			f->hostname);
	}

	FreePack(p);
}

// MAC テーブル列挙指令送信
void SiCallEnumMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_MAC_TABLE *t)
{
	PACK *p;
	UINT i;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enummactable");

	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));
	InRpcEnumMacTable(t, p);

	for (i = 0;i < t->NumMacTable;i++)
	{
		t->MacTables[i].RemoteItem = true;
		StrCpy(t->MacTables[i].RemoteHostname, sizeof(t->MacTables[i].RemoteHostname),
			f->hostname);
	}

	FreePack(p);
}

// SecureNAT 状況の取得指令送信
void SiCallGetNatStatus(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_NAT_STATUS *t)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "getnatstatus");

	Zero(t, sizeof(RPC_NAT_STATUS));
	InRpcNatStatus(t, p);

	FreePack(p);
}

// DHCP エントリ列挙指令送信
void SiCallEnumDhcp(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_DHCP *t)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumdhcp");

	Zero(t, sizeof(RPC_ENUM_DHCP));
	InRpcEnumDhcp(t, p);

	FreePack(p);
}

// NAT エントリ列挙指令送信
void SiCallEnumNat(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_NAT *t)
{
	PACK *p;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumnat");

	Zero(t, sizeof(RPC_ENUM_NAT));
	InRpcEnumNat(t, p);

	FreePack(p);
}

// セッション列挙指令送信
void SiCallEnumSession(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_SESSION *t)
{
	PACK *p;
	UINT i;
	// 引数チェック
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumsession");

	Zero(t, sizeof(RPC_ENUM_SESSION));
	InRpcEnumSession(t, p);

	for (i = 0;i < t->NumSession;i++)
	{
		t->Sessions[i].RemoteSession = true;
		StrCpy(t->Sessions[i].RemoteHostname, sizeof(t->Sessions[i].RemoteHostname),
			f->hostname);
	}

	FreePack(p);
}

// HUB 作成指令送信
void SiCallCreateHub(SERVER *s, FARM_MEMBER *f, HUB *h)
{
	PACK *p;
	HUB_LIST *hh;
	// 引数チェック
	if (s == NULL || f == NULL)
	{
		return;
	}

	if (f->Me == false)
	{
		p = NewPack();

		SiPackAddCreateHub(p, h);

		p = SiCallTask(f, p, "createhub");
		FreePack(p);
	}

	hh = ZeroMalloc(sizeof(HUB_LIST));
	hh->DynamicHub = (h->Type == HUB_TYPE_FARM_DYNAMIC ? true : false);
	StrCpy(hh->Name, sizeof(hh->Name), h->Name);
	hh->FarmMember = f;

	LockList(f->HubList);
	{
		bool exists = false;
		UINT i;
		for (i = 0;i < LIST_NUM(f->HubList);i++)
		{
			HUB_LIST *t = LIST_DATA(f->HubList, i);
			if (StrCmpi(t->Name, hh->Name) == 0)
			{
				exists = true;
			}
		}
		if (exists == false)
		{
			Add(f->HubList, hh);
		}
		else
		{
			Free(hh);
		}
	}
	UnlockList(f->HubList);
}

// HUB 作成用 PACK の書き込み
void SiPackAddCreateHub(PACK *p, HUB *h)
{
	UINT i;
	UINT max_session;
	SERVER *s;
	LICENSE_STATUS license;
	// 引数チェック
	if (p == NULL || h == NULL)
	{
		return;
	}

	Zero(&license, sizeof(license));
	s = h->Cedar->Server;
	if (s != NULL)
	{
		LiParseCurrentLicenseStatus(s->LicenseSystem, &license);
	}

	PackAddStr(p, "HubName", h->Name);
	PackAddInt(p, "HubType", h->Type);

	max_session = h->Option->MaxSession;

	if (GetHubAdminOption(h, "max_sessions") != 0)
	{
		if (max_session == 0)
		{
			max_session = GetHubAdminOption(h, "max_sessions");
		}
		else
		{
			max_session = MIN(max_session, GetHubAdminOption(h, "max_sessions"));
		}
	}

	PackAddInt(p, "MaxSession", max_session);

	if (GetHubAdminOption(h, "max_sessions_client_bridge_apply") != 0 || license.CarrierEdition)
	{
		PackAddInt(p, "MaxSessionClient", GetHubAdminOption(h, "max_sessions_client"));
		PackAddInt(p, "MaxSessionBridge", GetHubAdminOption(h, "max_sessions_bridge"));
		PackAddBool(p, "MaxSessionClientBridgeApply", true);
	}
	else
	{
		PackAddInt(p, "MaxSessionClient", INFINITE);
		PackAddInt(p, "MaxSessionBridge", INFINITE);
	}

	PackAddBool(p, "NoArpPolling", h->Option->NoArpPolling);
	PackAddBool(p, "NoIPv6AddrPolling", h->Option->NoIPv6AddrPolling);
	PackAddBool(p, "NoIpTable", h->Option->NoIpTable);
	PackAddBool(p, "NoEnum", h->Option->NoEnum);
	PackAddBool(p, "FilterPPPoE", h->Option->FilterPPPoE);
	PackAddBool(p, "YieldAfterStorePacket", h->Option->YieldAfterStorePacket);
	PackAddBool(p, "NoSpinLockForPacketDelay", h->Option->NoSpinLockForPacketDelay);
	PackAddInt(p, "BroadcastStormDetectionThreshold", h->Option->BroadcastStormDetectionThreshold);
	PackAddInt(p, "ClientMinimumRequiredBuild", h->Option->ClientMinimumRequiredBuild);
	PackAddBool(p, "FixForDLinkBPDU", h->Option->FixForDLinkBPDU);
	PackAddBool(p, "NoLookBPDUBridgeId", h->Option->NoLookBPDUBridgeId);
	PackAddBool(p, "NoManageVlanId", h->Option->NoManageVlanId);
	PackAddInt(p, "VlanTypeId", h->Option->VlanTypeId);
	PackAddBool(p, "FilterOSPF", h->Option->FilterOSPF);
	PackAddBool(p, "FilterIPv4", h->Option->FilterIPv4);
	PackAddBool(p, "FilterIPv6", h->Option->FilterIPv6);
	PackAddBool(p, "FilterNonIP", h->Option->FilterNonIP);
	PackAddBool(p, "NoIPv4PacketLog", h->Option->NoIPv4PacketLog);
	PackAddBool(p, "NoIPv6PacketLog", h->Option->NoIPv6PacketLog);
	PackAddBool(p, "FilterBPDU", h->Option->FilterBPDU);
	PackAddBool(p, "NoIPv6DefaultRouterInRAWhenIPv6", h->Option->NoIPv6DefaultRouterInRAWhenIPv6);
	PackAddBool(p, "NoMacAddressLog", h->Option->NoMacAddressLog);
	PackAddBool(p, "ManageOnlyPrivateIP", h->Option->ManageOnlyPrivateIP);
	PackAddBool(p, "ManageOnlyLocalUnicastIPv6", h->Option->ManageOnlyLocalUnicastIPv6);
	PackAddBool(p, "DisableIPParsing", h->Option->DisableIPParsing);

	PackAddInt(p, "SavePacketLog", h->LogSetting.SavePacketLog);
	PackAddInt(p, "PacketLogSwitchType", h->LogSetting.PacketLogSwitchType);
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		PackAddIntEx(p, "PacketLogConfig", h->LogSetting.PacketLogConfig[i], i, NUM_PACKET_LOG);
	}
	PackAddInt(p, "SaveSecurityLog", h->LogSetting.SaveSecurityLog);
	PackAddInt(p, "SecurityLogSwitchType", h->LogSetting.SecurityLogSwitchType);
	PackAddData(p, "HashedPassword", h->HashedPassword, SHA1_SIZE);
	PackAddData(p, "SecurePassword", h->SecurePassword, SHA1_SIZE);

	SiAccessListToPack(p, h->AccessList);

	if (h->EnableSecureNAT)
	{
		PackAddBool(p, "EnableSecureNAT", h->EnableSecureNAT);
		OutVhOption(p, h->SecureNATOption);
	}
}

// HUB の設定が更新された
void SiHubUpdateProc(HUB *h)
{
	SERVER *s;
	UINT i;
	// 引数チェック
	if (h == NULL || h->Cedar->Server == NULL || h->Cedar->Server->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return;
	}

	s = h->Cedar->Server;

	if (s->FarmMemberList == NULL)
	{
		return;
	}

	if (h->LastVersion != h->CurrentVersion || h->CurrentVersion == 0)
	{
		if (h->CurrentVersion == 0)
		{
			h->CurrentVersion = 1;
		}
		h->LastVersion = h->CurrentVersion;

		LockList(s->FarmMemberList);
		{
			// すべてのメンバで HUB を更新する
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me == false)
				{
					SiCallUpdateHub(s, f, h);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	if (h->Offline == false)
	{
		SiHubOnlineProc(h);
	}
}

// HUB がオンラインになった
void SiHubOnlineProc(HUB *h)
{
	SERVER *s;
	UINT i;
	// 引数チェック
	if (h == NULL || h->Cedar->Server == NULL || h->Cedar->Server->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		// ファームコントローラ以外では処理しない
		return;
	}

	s = h->Cedar->Server;

	if (s->FarmMemberList == NULL)
	{
		return;
	}

	LockList(s->FarmMemberList);
	{
		if (h->Type == HUB_TYPE_FARM_STATIC)
		{
			// スタティック HUB
			// すべてのメンバで HUB を作成する
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				UINT j;
				bool exists = false;
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				LockList(f->HubList);
				{
					for (j = 0;j < LIST_NUM(f->HubList);j++)
					{
						HUB_LIST *hh = LIST_DATA(f->HubList, j);
						if (StrCmpi(hh->Name, h->Name) == 0)
						{
							exists = true;
						}
					}
				}
				UnlockList(f->HubList);

				if (exists == false)
				{
					SiCallCreateHub(s, f, h);
				}
			}
		}
	}
	UnlockList(s->FarmMemberList);
}

// HUB がオフラインになった
void SiHubOfflineProc(HUB *h)
{
	SERVER *s;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;
	// 引数チェック
	if (h == NULL || h->Cedar->Server == NULL || h->Cedar->Server->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		// ファームコントローラ以外では処理しない
		return;
	}

	s = h->Cedar->Server;

	if (s->FarmMemberList == NULL)
	{
		return;
	}

	StrCpy(hubname, sizeof(hubname), h->Name);

	LockList(s->FarmMemberList);
	{
		// すべてのメンバで HUB を停止する
		for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
			SiCallDeleteHub(s, f, h);
		}
	}
	UnlockList(s->FarmMemberList);
}

// アクセスを PACK に変換する
void SiAccessToPack(PACK *p, ACCESS *a, UINT i, UINT total)
{
	// 引数チェック
	if (p == NULL || a == NULL)
	{
		return;
	}

	PackAddUniStrEx(p, "Note", a->Note, i, total);
	PackAddIntEx(p, "Active", a->Active, i, total);
	PackAddIntEx(p, "Priority", a->Priority, i, total);
	PackAddIntEx(p, "Discard", a->Discard, i, total);
	if (a->IsIPv6)
	{
		PackAddIp32Ex(p, "SrcIpAddress", 0xFDFFFFDF, i, total);
		PackAddIp32Ex(p, "SrcSubnetMask", 0xFFFFFFFF, i, total);
		PackAddIp32Ex(p, "DestIpAddress", 0xFDFFFFDF, i, total);
		PackAddIp32Ex(p, "DestSubnetMask", 0xFFFFFFFF, i, total);
	}
	else
	{
		PackAddIp32Ex(p, "SrcIpAddress", a->SrcIpAddress, i, total);
		PackAddIp32Ex(p, "SrcSubnetMask", a->SrcSubnetMask, i, total);
		PackAddIp32Ex(p, "DestIpAddress", a->DestIpAddress, i, total);
		PackAddIp32Ex(p, "DestSubnetMask", a->DestSubnetMask, i, total);
	}
	PackAddIntEx(p, "Protocol", a->Protocol, i, total);
	PackAddIntEx(p, "SrcPortStart", a->SrcPortStart, i, total);
	PackAddIntEx(p, "SrcPortEnd", a->SrcPortEnd, i, total);
	PackAddIntEx(p, "DestPortStart", a->DestPortStart, i, total);
	PackAddIntEx(p, "DestPortEnd", a->DestPortEnd, i, total);
	PackAddStrEx(p, "SrcUsername", a->SrcUsername, i, total);
	PackAddStrEx(p, "DestUsername", a->DestUsername, i, total);
	PackAddBoolEx(p, "CheckSrcMac", a->CheckSrcMac, i, total);
	PackAddDataEx(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), i, total);
	PackAddDataEx(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), i, total);
	PackAddBoolEx(p, "CheckDstMac", a->CheckDstMac, i, total);
	PackAddDataEx(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), i, total);
	PackAddDataEx(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), i, total);
	PackAddBoolEx(p, "CheckTcpState", a->CheckTcpState, i, total);
	PackAddBoolEx(p, "Established", a->Established, i, total);
	PackAddIntEx(p, "Delay", a->Delay, i, total);
	PackAddIntEx(p, "Jitter", a->Jitter, i, total);
	PackAddIntEx(p, "Loss", a->Loss, i, total);
	PackAddBoolEx(p, "IsIPv6", a->IsIPv6, i, total);
	if (a->IsIPv6)
	{
		PackAddIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, i, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, i, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, i, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, i, total);
	}
	else
	{
		IPV6_ADDR zero;

		Zero(&zero, sizeof(zero));

		PackAddIp6AddrEx(p, "SrcIpAddress6", &zero, i, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &zero, i, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &zero, i, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &zero, i, total);
	}
}

// PACK に入っているアクセス個数を取得
UINT SiNumAccessFromPack(PACK *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return 0;
	}

	return PackGetIndexCount(p, "Active");
}

// PACK をアクセスに変換する
ACCESS *SiPackToAccess(PACK *p, UINT i)
{
	ACCESS *a;
	// 引数チェック
	if (p == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(ACCESS));

	PackGetUniStrEx(p, "Note", a->Note, sizeof(a->Note), i);
	a->Active = PackGetIntEx(p, "Active", i);
	a->Priority = PackGetIntEx(p, "Priority", i);
	a->Discard = PackGetIntEx(p, "Discard", i);
	a->SrcIpAddress = PackGetIp32Ex(p, "SrcIpAddress", i);
	a->SrcSubnetMask = PackGetIp32Ex(p, "SrcSubnetMask", i);
	a->DestIpAddress = PackGetIp32Ex(p, "DestIpAddress", i);
	a->DestSubnetMask = PackGetIp32Ex(p, "DestSubnetMask", i);
	a->Protocol = PackGetIntEx(p, "Protocol", i);
	a->SrcPortStart = PackGetIntEx(p, "SrcPortStart", i);
	a->SrcPortEnd = PackGetIntEx(p, "SrcPortEnd", i);
	a->DestPortStart = PackGetIntEx(p, "DestPortStart", i);
	a->DestPortEnd = PackGetIntEx(p, "DestPortEnd", i);
	PackGetStrEx(p, "SrcUsername", a->SrcUsername, sizeof(a->SrcUsername), i);
	PackGetStrEx(p, "DestUsername", a->DestUsername, sizeof(a->DestUsername), i);
	a->CheckSrcMac = PackGetBoolEx(p, "CheckSrcMac", i);
	PackGetDataEx2(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), i);
	PackGetDataEx2(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), i);
	a->CheckDstMac = PackGetBoolEx(p, "CheckDstMac", i);
	PackGetDataEx2(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), i);
	PackGetDataEx2(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), i);
	a->CheckTcpState = PackGetBoolEx(p, "CheckTcpState", i);
	a->Established = PackGetBoolEx(p, "Established", i);
	a->Delay = PackGetIntEx(p, "Delay", i);
	a->Jitter = PackGetIntEx(p, "Jitter", i);
	a->Loss = PackGetIntEx(p, "Loss", i);
	a->IsIPv6 = PackGetBoolEx(p, "IsIPv6", i);
	if (a->IsIPv6)
	{
		PackGetIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, i);
		PackGetIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, i);
		PackGetIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, i);
		PackGetIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, i);
	}

	return a;
}

// アクセスリストを PACK に変換する
void SiAccessListToPack(PACK *p, LIST *o)
{
	// 引数チェック
	if (p == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			ACCESS *a = LIST_DATA(o, i);
			SiAccessToPack(p, a, i, LIST_NUM(o));
		}
	}
	UnlockList(o);
}

// 指定した HUB をホストしているメンバを取得する
FARM_MEMBER *SiGetHubHostingMember(SERVER *s, HUB *h, bool admin_mode)
{
	FARM_MEMBER *ret = NULL;
	char name[MAX_SIZE];
	// 引数チェック
	if (s == NULL || h == NULL)
	{
		return NULL;
	}

	StrCpy(name, sizeof(name), h->Name);

	if (h->Type == HUB_TYPE_FARM_STATIC)
	{
		// スタティック HUB の場合 任意のメンバを選択すれば良い
		if (admin_mode == false)
		{
			ret = SiGetNextFarmMember(s);
		}
		else
		{
			UINT i;
			ret = NULL;

			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me)
				{
					ret = f;
					break;
				}
			}
		}
	}
	else
	{
		// ダイナミック HUB の場合
		// すでに HUB をホストしているメンバがあるかどうか調べる
		UINT i;

		for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
			HUB_LIST *hh, t;
			StrCpy(t.Name, sizeof(t.Name), name);
			LockList(f->HubList);
			{
				hh = Search(f->HubList, &t);
				if (hh != NULL)
				{
					// 発見した
					ret = f;
				}
			}
			UnlockList(f->HubList);
		}

		if (ret == NULL)
		{
			// 新しく HUB をホストさせる
			FARM_MEMBER *f;

			// ホストさせるメンバの選択
			ret = SiGetNextFarmMember(s);

			f = ret;
			if (f != NULL)
			{
				// HUB 作成指令
				SiAddHubCreateHistory(s, name);
				SiCallCreateHub(s, f, h);
				SiCallUpdateHub(s, f, h);
			}
		}
	}

	return ret;
}

// タスクが呼び出された
PACK *SiCalledTask(FARM_CONTROLLER *f, PACK *p, char *taskname)
{
	PACK *ret;
	SERVER *s;
	// 引数チェック
	if (f == NULL || p == NULL || taskname == NULL)
	{
		return NULL;
	}

	ret = NULL;
	s = f->Server;

	if (StrCmpi(taskname, "noop") == 0)
	{
		// NO OPERATION
		ret = NewPack();
	}
	else
	{
		Debug("Task Called: [%s].\n", taskname);
		if (StrCmpi(taskname, "createhub") == 0)
		{
			SiCalledCreateHub(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "deletehub") == 0)
		{
			SiCalledDeleteHub(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "enumhub") == 0)
		{
			ret = NewPack();
			SiCalledEnumHub(s, ret, p);
		}
		else if (StrCmpi(taskname, "updatehub") == 0)
		{
			SiCalledUpdateHub(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "createticket") == 0)
		{
			ret = SiCalledCreateTicket(s, p);
		}
		else if (StrCmpi(taskname, "enumnat") == 0)
		{
			ret = SiCalledEnumNat(s, p);
		}
		else if (StrCmpi(taskname, "enumdhcp") == 0)
		{
			ret = SiCalledEnumDhcp(s, p);
		}
		else if (StrCmpi(taskname, "getnatstatus") == 0)
		{
			ret = SiCalledGetNatStatus(s, p);
		}
		else if (StrCmpi(taskname, "enumsession") == 0)
		{
			ret = SiCalledEnumSession(s, p);
		}
		else if (StrCmpi(taskname, "deletesession") == 0)
		{
			SiCalledDeleteSession(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "deletemactable") == 0)
		{
			SiCalledDeleteMacTable(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "deleteiptable") == 0)
		{
			SiCalledDeleteIpTable(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "enummactable") == 0)
		{
			ret = SiCalledEnumMacTable(s, p);
		}
		else if (StrCmpi(taskname, "enumiptable") == 0)
		{
			ret = SiCalledEnumIpTable(s, p);
		}
		else if (StrCmpi(taskname, "getsessionstatus") == 0)
		{
			ret = SiCalledGetSessionStatus(s, p);
		}
		else if (StrCmpi(taskname, "enumlogfilelist") == 0)
		{
			ret = SiCalledEnumLogFileList(s, p);
		}
		else if (StrCmpi(taskname, "readlogfile") == 0)
		{
			ret = SiCalledReadLogFile(s, p);
		}
	}

	return ret;
}

// タスクを呼び出す
PACK *SiCallTask(FARM_MEMBER *f, PACK *p, char *taskname)
{
	PACK *ret;
	char tmp[MAX_PATH];
	// 引数チェック
	if (f == NULL || p == NULL || taskname == NULL)
	{
		return NULL;
	}

	PackAddStr(p, "taskname", taskname);

	Debug("Call Task [%s] (%s)\n", taskname, f->hostname);

	Format(tmp, sizeof(tmp), "CLUSTER_CALL: Entering Call [%s] to %s", taskname, f->hostname);
	SiDebugLog(f->Cedar->Server, tmp);

	ret = SiExecTask(f, p);

	Format(tmp, sizeof(tmp), "CLUSTER_CALL: Leaving Call [%s] to %s", taskname, f->hostname);
	SiDebugLog(f->Cedar->Server, tmp);

	return ret;
}

// タスク待ちうけプロシージャ (メイン処理)
void SiAcceptTasksFromControllerMain(FARM_CONTROLLER *f, SOCK *sock)
{
	PACK *request;
	PACK *response;
	char taskname[MAX_SIZE];
	// 引数チェック
	if (f == NULL || sock == NULL)
	{
		return;
	}

	while (true)
	{
		bool ret;
		// PACK を受信する
		request = HttpClientRecv(sock);
		if (request == NULL)
		{
			// 切断
			return;
		}

		response = NULL;

		// 名前の取得
		if (PackGetStr(request, "taskname", taskname, sizeof(taskname)))
		{
			Lock(f->Server->TasksFromFarmControllerLock);
			{
				response = SiCalledTask(f, request, taskname);
			}
			Unlock(f->Server->TasksFromFarmControllerLock);
		}

		FreePack(request);

		// 応答を返す
		if (response == NULL)
		{
			response = NewPack();
		}
		else
		{
			PackAddInt(response, "succeed", 1);
		}

		ret = HttpClientSend(sock, response);
		FreePack(response);

		if (ret == false)
		{
			// 切断
			return;
		}
	}
}

// タスク待ちうけプロシージャ
void SiAcceptTasksFromController(FARM_CONTROLLER *f, SOCK *sock)
{
	UINT i;
	HUB **hubs;
	UINT num_hubs;
	CEDAR *c;
	SERVER *s;
	// 引数チェック
	if (f == NULL || sock == NULL)
	{
		return;
	}

	s = f->Server;
	c = s->Cedar;

	// メイン処理
	SiAcceptTasksFromControllerMain(f, sock);

	// コントローラとの接続が切断されたためすべての仮想 HUB を停止する
	LockList(c->HubList);
	{
		hubs = ToArray(c->HubList);
		num_hubs = LIST_NUM(c->HubList);
		for (i = 0;i < num_hubs;i++)
		{
			AddRef(hubs[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num_hubs;i++)
	{
		SetHubOffline(hubs[i]);
		DelHub(c, hubs[i]);
		ReleaseHub(hubs[i]);
	}

	Free(hubs);
}

// タスクを実行する
PACK *SiExecTask(FARM_MEMBER *f, PACK *p)
{
	FARM_TASK *t;
	// 引数チェック
	if (f == NULL || p == NULL)
	{
		return NULL;
	}

	t = SiFarmServPostTask(f, p);
	if (t == NULL)
	{
		return NULL;
	}

	return SiFarmServWaitTask(t);
}

// タスク投入
FARM_TASK *SiFarmServPostTask(FARM_MEMBER *f, PACK *request)
{
	FARM_TASK *t;
	// 引数チェック
	if (f == NULL || request == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(FARM_TASK));
	t->CompleteEvent = NewEvent();
	t->Request = request;

	LockQueue(f->TaskQueue);
	{
		if (f->Halting)
		{
			// 停止中 (失敗)
			UnlockQueue(f->TaskQueue);
			ReleaseEvent(t->CompleteEvent);
			Free(t);
			return NULL;
		}

		InsertQueue(f->TaskQueue, t);
	}
	UnlockQueue(f->TaskQueue);

	Set(f->TaskPostEvent);

	return t;
}

// タスク結果待ち
PACK *SiFarmServWaitTask(FARM_TASK *t)
{
	PACK *response;
	// 引数チェック
	if (t == NULL)
	{
		return NULL;
	}

	Wait(t->CompleteEvent, INFINITE);
	ReleaseEvent(t->CompleteEvent);
	FreePack(t->Request);

	response = t->Response;
	Free(t);

	if (PackGetInt(response, "succeed") == 0)
	{
		// 何らかの原因でタスク呼び出しが失敗した
		FreePack(response);
		return NULL;
	}

	return response;
}

// ファームサーバー処理メイン
void SiFarmServMain(SERVER *server, SOCK *sock, FARM_MEMBER *f)
{
	UINT wait_time = SERVER_CONTROL_TCP_TIMEOUT / 2;
	bool send_noop = false;
	UINT i;
	CEDAR *c;
	// 引数チェック
	if (server == NULL || sock == NULL || f == NULL)
	{
		Debug("SiFarmServMain Failed.\n");
		return;
	}

	Debug("SiFarmServMain Started.\n");

	c = server->Cedar;

	// メンバがコントローラに接続してきた段階で
	// すべてのスタティック HUB の作成指令を送信する
	LockList(c->HubList);
	{
		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			if (h->Offline == false)
			{
				if (h->Type == HUB_TYPE_FARM_STATIC)
				{
					PACK *p;
					HUB_LIST *hh;
					p = NewPack();
					SiPackAddCreateHub(p, h);
					PackAddStr(p, "taskname", "createhub");
					HttpServerSend(sock, p);
					FreePack(p);
					p = HttpServerRecv(sock);
					FreePack(p);

					p = NewPack();
					SiPackAddCreateHub(p, h);
					PackAddStr(p, "taskname", "updatehub");
					HttpServerSend(sock, p);
					FreePack(p);
					p = HttpServerRecv(sock);
					FreePack(p);

					hh = ZeroMalloc(sizeof(HUB_LIST));
					hh->DynamicHub = false;
					hh->FarmMember = f;
					StrCpy(hh->Name, sizeof(hh->Name), h->Name);
					LockList(f->HubList);
					{
						Add(f->HubList, hh);
					}
					UnlockList(f->HubList);
				}
			}
		}
	}
	UnlockList(c->HubList);

	Debug("SiFarmServMain: while (true)\n");

	while (true)
	{
		FARM_TASK *t;
		UINT64 tick;

		do
		{
			// 新しいタスクが到着していないかどうか調べる
			LockQueue(f->TaskQueue);
			{
				t = GetNext(f->TaskQueue);
			}
			UnlockQueue(f->TaskQueue);

			if (t != NULL)
			{
				// このタスクを処理する
				PACK *p = t->Request;
				bool ret;

				// 送信
				ret = HttpServerSend(sock, p);
				send_noop = false;

				if (ret == false)
				{
					// 接続が切れた
					// このタスクをキャンセルする
					Set(t->CompleteEvent);
					goto DISCONNECTED;
				}

				// 受信
				p = HttpServerRecv(sock);

				t->Response = p;
				Set(t->CompleteEvent);

				send_noop = false;
			}
		}
		while (t != NULL);

		if (send_noop)
		{
			// NOOP を送信する
			PACK *p;
			bool ret;
			p = NewPack();
			PackAddStr(p, "taskname", "noop");

			ret = HttpServerSend(sock, p);
			FreePack(p);

			if (ret == false)
			{
				goto DISCONNECTED;
			}

			p = HttpServerRecv(sock);
			if (p == NULL)
			{
				goto DISCONNECTED;
			}

			FreePack(p);
		}

		tick = Tick64();

		while (true)
		{
			bool break_flag;
			if ((tick + wait_time) <= Tick64())
			{
				break;
			}

			Wait(f->TaskPostEvent, 250);

			break_flag = false;
			LockQueue(f->TaskQueue);
			{
				if (f->TaskQueue->num_item != 0)
				{
					break_flag = true;
				}
			}
			UnlockQueue(f->TaskQueue);

			if (break_flag || f->Halting || server->Halt)
			{
				break;
			}
		}
		send_noop = true;
	}

DISCONNECTED:

	Debug("SiFarmServMain: DISCONNECTED\n");

	f->Halting = true;
	// すべての未処理のタスクをキャンセルする
	LockQueue(f->TaskQueue);
	{
		FARM_TASK *t;

		while (t = GetNext(f->TaskQueue))
		{
			Set(t->CompleteEvent);
		}
	}
	UnlockQueue(f->TaskQueue);
}

// ファームメンバからの接続を処理するファームサーバー関数
void SiFarmServ(SERVER *server, SOCK *sock, X *cert, UINT ip, UINT num_port, UINT *ports, char *hostname, UINT point, UINT weight, UINT max_sessions)
{
	PACK *p;
	FARM_MEMBER *f;
	UINT i;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (server == NULL || sock == NULL || cert == NULL || num_port == 0 || ports == NULL || hostname == NULL)
	{
		return;
	}

	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	if (max_sessions == 0)
	{
		max_sessions = SERVER_MAX_SESSIONS;
	}

	if (ip == 0)
	{
		// 公開 IP アドレスが指定されていない場合はこのファームメンバサーバーの
		// 接続元 IP アドレスを指定する
		ip = IPToUINT(&sock->RemoteIP);
	}

	IPToStr32(tmp, sizeof(tmp), ip);
	SLog(server->Cedar, "LS_FARM_SERV_START", tmp, hostname);

	// 成功を知らせる
	p = NewPack();
	HttpServerSend(sock, p);
	FreePack(p);

	IPToStr32(tmp, sizeof(tmp), ip);
	Debug("Farm Member %s Connected. IP: %s\n", hostname, tmp);

	SetTimeout(sock, SERVER_CONTROL_TCP_TIMEOUT);

	f = ZeroMalloc(sizeof(FARM_MEMBER));
	f->Cedar = server->Cedar;
	f->Ip = ip;
	f->NumPort = num_port;
	f->Ports = ports;
	StrCpy(f->hostname, sizeof(f->hostname), hostname);
	f->ServerCert = cert;
	f->ConnectedTime = SystemTime64();
	f->Weight = weight;
	f->MaxSessions = max_sessions;

	f->HubList = NewList(CompareHubList);
	f->Point = point;

	f->TaskQueue = NewQueue();
	f->TaskPostEvent = NewEvent();

	// リストに追加する
	LockList(server->FarmMemberList);
	{
		Add(server->FarmMemberList, f);
	}
	UnlockList(server->FarmMemberList);

	// メイン処理
	SiFarmServMain(server, sock, f);

	// リストから削除する
	LockList(server->FarmMemberList);
	{
		Delete(server->FarmMemberList, f);
	}
	UnlockList(server->FarmMemberList);

	ReleaseQueue(f->TaskQueue);
	ReleaseEvent(f->TaskPostEvent);

	for (i = 0;i < LIST_NUM(f->HubList);i++)
	{
		HUB_LIST *hh = LIST_DATA(f->HubList, i);
		Free(hh);
	}

	ReleaseList(f->HubList);

	Free(f);

	SLog(server->Cedar, "LS_FARM_SERV_END", hostname);
}

// HUB リストの検索
int CompareHubList(void *p1, void *p2)
{
	HUB_LIST *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HUB_LIST **)p1;
	h2 = *(HUB_LIST **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}
	return StrCmpi(h1->Name, h2->Name);
}

// コントローラへの接続スレッド
void SiConnectToControllerThread(THREAD *thread, void *param)
{
	FARM_CONTROLLER *f;
	SESSION *s;
	CONNECTION *c;
	SERVER *server;
	bool first_failed;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	MsSetThreadPriorityRealtime();
#endif	// OS_WIN32

	f = (FARM_CONTROLLER *)param;
	f->Thread = thread;
	AddRef(f->Thread->ref);
	NoticeThreadInit(thread);

	f->StartedTime = SystemTime64();

	server = f->Server;

	f->StartedTime = SystemTime64();

	SLog(server->Cedar, "LS_FARM_CONNECT_1", server->ControllerName);

	first_failed = true;

	while (true)
	{
		// 接続を試行
		CLIENT_OPTION o;

		f->LastError = ERR_TRYING_TO_CONNECT;

		Zero(&o, sizeof(CLIENT_OPTION));
		StrCpy(o.Hostname, sizeof(o.Hostname), server->ControllerName);
		o.Port = server->ControllerPort;
		f->NumTry++;

		Debug("Try to Connect %s (Controller).\n", server->ControllerName);

		s = NewRpcSessionEx(server->Cedar, &o, NULL, CEDAR_SERVER_FARM_STR);

		if (s != NULL)
		{
			// 接続成功: 認証データを送信
			PACK *p = NewPack();
			UCHAR secure_password[SHA1_SIZE];
			BUF *b;

			c = s->Connection;

			Lock(f->lock);
			{
				f->Sock = c->FirstSock;
				AddRef(f->Sock->ref);
				SetTimeout(f->Sock, SERVER_CONTROL_TCP_TIMEOUT);
			}
			Unlock(f->lock);

			// メソッド
			PackAddStr(p, "method", "farm_connect");
			PackAddClientVersion(p, s->Connection);

			// パスワード
			SecurePassword(secure_password, server->MemberPassword, s->Connection->Random);
			PackAddData(p, "SecurePassword", secure_password, sizeof(secure_password));

			Lock(server->Cedar->lock);
			{
				b = XToBuf(server->Cedar->ServerX, false);
			}
			Unlock(server->Cedar->lock);

			if (b != NULL)
			{
				char tmp[MAX_SIZE];
				bool ret;
				UINT i;
				// サーバー証明書
				PackAddBuf(p, "ServerCert", b);
				FreeBuf(b);

				// 最大セッション数
				PackAddInt(p, "MaxSessions", GetServerCapsInt(server, "i_max_sessions"));

				// ポイント
				PackAddInt(p, "Point", SiGetPoint(server));
				PackAddInt(p, "Weight", server->Weight);

				// ホスト名
				GetMachineName(tmp, sizeof(tmp));
				PackAddStr(p, "HostName", tmp);

				// 公開 IP
				PackAddIp32(p, "PublicIp", server->PublicIp);

				// 公開ポート
				for (i = 0;i < server->NumPublicPort;i++)
				{
					PackAddIntEx(p, "PublicPort", server->PublicPorts[i], i, server->NumPublicPort);
				}

				ret = HttpClientSend(c->FirstSock, p);

				if (ret)
				{
					PACK *p;
					UINT err = ERR_PROTOCOL_ERROR;

					first_failed = true;
					p = HttpClientRecv(c->FirstSock);
					if (p != NULL && (err = GetErrorFromPack(p)) == 0)
					{
						// 接続成功
						SLog(server->Cedar, "LS_FARM_START");
						f->CurrentConnectedTime = SystemTime64();
						if (f->FirstConnectedTime == 0)
						{
							f->FirstConnectedTime = SystemTime64();
						}
						f->NumConnected++;
						Debug("Connect Succeed.\n");
						f->Online = true;

						// メイン処理
						SiAcceptTasksFromController(f, c->FirstSock);

						f->Online = false;
					}
					else
					{
						// エラー
						f->LastError = err;
						SLog(server->Cedar, "LS_FARM_CONNECT_2", server->ControllerName,
							GetUniErrorStr(err), err);
					}
					FreePack(p);
				}
				else
				{
					f->LastError = ERR_DISCONNECTED;

					if (first_failed)
					{
						SLog(server->Cedar, "LS_FARM_CONNECT_3", server->ControllerName, RETRY_CONNECT_TO_CONTROLLER_INTERVAL / 1000);
						first_failed = false;
					}
				}
			}

			FreePack(p);

			// 接続切断
			Lock(f->lock);
			{
				if (f->Sock != NULL)
				{
					ReleaseSock(f->Sock);
					f->Sock = NULL;
				}
			}
			Unlock(f->lock);

			ReleaseSession(s);
			s = NULL;

			if (f->LastError == ERR_TRYING_TO_CONNECT)
			{
				f->LastError = ERR_DISCONNECTED;
			}
		}
		else
		{
			// 接続失敗
			f->LastError = ERR_CONNECT_TO_FARM_CONTROLLER;

			if (first_failed)
			{
				SLog(server->Cedar, "LS_FARM_CONNECT_3", server->ControllerName, RETRY_CONNECT_TO_CONTROLLER_INTERVAL / 1000);
				first_failed = false;
			}
		}

		Debug("Controller Disconnected. ERROR = %S\n", _E(f->LastError));

		f->NumFailed = f->NumTry - f->NumConnected;

		// イベント待機
		Wait(f->HaltEvent, RETRY_CONNECT_TO_CONTROLLER_INTERVAL);

		if (f->Halt)
		{
			// 停止フラグ
			break;
		}
	}

	SLog(server->Cedar, "LS_FARM_DISCONNECT");
}

// コントローラへの接続を切断
void SiStopConnectToController(FARM_CONTROLLER *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	f->Halt = true;

	// 接続を停止
	Lock(f->lock);
	{
		Disconnect(f->Sock);
	}
	Unlock(f->lock);

	Set(f->HaltEvent);

	// スレッド停止を待機
	WaitThread(f->Thread, INFINITE);
	ReleaseThread(f->Thread);

	DeleteLock(f->lock);
	ReleaseEvent(f->HaltEvent);

	Free(f);
}

// コントローラへの接続の開始
FARM_CONTROLLER *SiStartConnectToController(SERVER *s)
{
	FARM_CONTROLLER *f;
	THREAD *t;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	f = ZeroMalloc(sizeof(FARM_CONTROLLER));
	f->Server = s;
	f->LastError = ERR_TRYING_TO_CONNECT;
	f->HaltEvent = NewEvent();
	f->lock = NewLock();

	t = NewThread(SiConnectToControllerThread, f);
	WaitThreadInit(t);
	ReleaseThread(t);

	return f;
}

// サーバーの作成
SERVER *SiNewServer(bool bridge)
{
	SERVER *s;

	s = ZeroMalloc(sizeof(SERVER));

	SiInitHubCreateHistory(s);

	InitServerCapsCache(s);

	Rand(s->MyRandomKey, sizeof(s->MyRandomKey));

	s->lock = NewLock();
	s->SaveCfgLock = NewLock();
	s->ref = NewRef();
	s->Cedar = NewCedar(NULL, NULL);
	s->Cedar->Server = s;
	s->Cedar->CheckExpires = true;
	s->ServerListenerList = NewList(CompareServerListener);
	s->StartTime = SystemTime64();
	s->TasksFromFarmControllerLock = NewLock();

	if (bridge)
	{
		SetCedarVpnBridge(s->Cedar);
	}

#ifdef OS_WIN32
	if (IsHamMode() == false)
	{
		RegistWindowsFirewallAll();
	}
#endif

	s->Keep = StartKeep();

	// ログ関係
	MakeDir(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME);
	s->Logger = NewLog(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME, SERVER_LOG_PERFIX, LOG_SWITCH_DAY);

	SLog(s->Cedar, "L_LINE");
	SLog(s->Cedar, "LS_START_2", s->Cedar->ServerStr, s->Cedar->VerString);
	SLog(s->Cedar, "LS_START_3", s->Cedar->BuildInfo);
	SLog(s->Cedar, "LS_START_UTF8");
	SLog(s->Cedar, "LS_START_1");

	if (s->Cedar->Bridge == false)
	{
		s->LicenseSystem = LiNewLicenseSystem();
	}

	// コンフィグレーション初期化
	SiInitConfiguration(s);

	// 優先順位を上げる
	if (s->NoHighPriorityProcess == false)
	{
		OSSetHighPriority();
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		// コントローラへの接続を開始する
		s->FarmController = SiStartConnectToController(s);
	}
	else if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		FARM_MEMBER *f;
		// コントローラとしての動作を開始する
		s->FarmMemberList = NewList(NULL);

		f = ZeroMalloc(sizeof(FARM_MEMBER));
		f->Cedar = s->Cedar;
		GetMachineName(f->hostname, sizeof(f->hostname));
		f->Me = true;
		f->HubList = NewList(CompareHubList);
		f->Weight = s->Weight;

		s->Me = f;

		Add(s->FarmMemberList, f);

		SiStartFarmControl(s);

		s->FarmControllerInited = true;
	}

	InitServerSnapshot(s);

	SiInitDeadLockCheck(s);

	return s;
}

