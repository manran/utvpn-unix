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

// Cedar.c
// Cedar 通信モジュールプログラムコード

// Build 7101


#include "CedarPch.h"

static UINT init_cedar_counter = 0;
static REF *cedar_log_ref = NULL;
static LOG *cedar_log;

// 現在サポートされている Windows のバージョンかどうか取得する
// (以前、XP までしか想定していないコードを Vista (Longhorn) で動作させたときに
//  OS ごと大変おかしくなってしまったことがあるので、バージョンチェックは
//  必ず行うようにした。ただし、警告メッセージを画面に表示するだけであり、
//  動作は一応できるようにしている。)
bool IsSupportedWinVer(RPC_WINVER *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return false;
	}

	if (v->IsWindows == false)
	{
		return true;
	}

	if (v->IsNT == false)
	{
		return true;
	}

	if (v->IsBeta)
	{
		return true;
	}

	if (v->VerMajor <= 4)
	{
		// Windows NT
		return true;
	}

	if (v->VerMajor == 5 && v->VerMinor == 0)
	{
		// Windows 2000
		if (v->ServicePack <= 4)
		{
			// SP4 までサポート
			return true;
		}
	}

	if (v->VerMajor == 5 && v->VerMinor == 1)
	{
		// Windows XP x86
		if (v->ServicePack <= 3)
		{
			// SP3 までサポート
			return true;
		}
	}

	if (v->VerMajor == 5 && v->VerMinor == 2)
	{
		// Windows XP x64, Windows Server 2003
		if (v->ServicePack <= 2)
		{
			// SP2 までサポート
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 0)
	{
		// Windows Vista, Server 2008
		if (v->ServicePack <= 2)
		{
			// SP2 までサポート
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 1)
	{
		// Windows 7, Server 2008 R2
		if (v->ServicePack <= 0)
		{
			// SP0 までサポート
			return true;
		}
	}

	return false;
}

// Windows のバージョンを取得する
void GetWinVer(RPC_WINVER *v)
{
	// 引数チェック
	if (v == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32GetWinVer(v);
#else	// OS_WIN32
	Zero(v, sizeof(RPC_WINVER));
	StrCpy(v->Title, sizeof(v->Title), GetOsInfo()->OsProductName);
#endif	// OS_WIN32
}

// 簡易ログを閉じる
void FreeTinyLog(TINY_LOG *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	FileClose(t->io);
	DeleteLock(t->Lock);
	Free(t);
}

// 簡易ログの書き込み
void WriteTinyLog(TINY_LOG *t, char *str)
{
	BUF *b;
	char dt[MAX_PATH];
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	GetDateTimeStrMilli64(dt, sizeof(dt), LocalTime64());
	StrCat(dt, sizeof(dt), ": ");

	b = NewBuf();

	WriteBuf(b, dt, StrLen(dt));
	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, "\r\n", 2);

	Lock(t->Lock);
	{
		FileWrite(t->io, b->Buf, b->Size);
		FileFlush(t->io);
	}
	Unlock(t->Lock);

	FreeBuf(b);
}

// 簡易ログの初期化
TINY_LOG *NewTinyLog()
{
	char name[MAX_PATH];
	SYSTEMTIME st;
	TINY_LOG *t;

	LocalTime(&st);

	MakeDir(TINY_LOG_DIRNAME);

	Format(name, sizeof(name), TINY_LOG_FILENAME,
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	t = ZeroMalloc(sizeof(TINY_LOG));

	StrCpy(t->FileName, sizeof(t->FileName), name);
	t->io = FileCreate(name);
	t->Lock = NewLock();

	return t;
}

// 非 SSL リストのエントリの比較
int CompareNoSslList(void *p1, void *p2)
{
	NON_SSL *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NON_SSL **)p1;
	n2 = *(NON_SSL **)p2;
	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}
	return CmpIpAddr(&n1->IpAddress, &n2->IpAddress);
}

// 指定された IP アドレスが非 SSL リストに存在するかどうかチェック
bool IsInNoSsl(CEDAR *c, IP *ip)
{
	bool ret = false;
	// 引数チェック
	if (c == NULL || ip == NULL)
	{
		return false;
	}

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL)
		{
			if (n->EntryExpires > Tick64() && n->Count > NON_SSL_MIN_COUNT)
			{
				n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;
				ret = true;
			}
		}
	}
	UnlockList(c->NonSslList);

	return ret;
}

// 非 SSL リストのエントリをデクリメント
void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec)
{
	// 引数チェック
	if (c == NULL || ip == NULL)
	{
		return;
	}

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL)
		{
			if (n->Count >= num_dec)
			{
				n->Count -= num_dec;
			}
		}
	}
	UnlockList(c->NonSslList);
}

// 非 SSL リストにエントリを追加
bool AddNoSsl(CEDAR *c, IP *ip)
{
	NON_SSL *n;
	bool ret = true;
	// 引数チェック
	if (c == NULL || ip == NULL)
	{
		return true;
	}

	LockList(c->NonSslList);
	{
		DeleteOldNoSsl(c);

		n = SearchNoSslList(c, ip);

		if (n == NULL)
		{
			n = ZeroMalloc(sizeof(NON_SSL));
			Copy(&n->IpAddress, ip, sizeof(IP));
			n->Count = 0;

			Add(c->NonSslList, n);
		}

		n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;

		n->Count++;

		if (n->Count > NON_SSL_MIN_COUNT)
		{
			ret = false;
		}
	}
	UnlockList(c->NonSslList);

	return ret;
}

// 古い非 SSL リストの削除
void DeleteOldNoSsl(CEDAR *c)
{
	UINT i;
	LIST *o;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(c->NonSslList);i++)
	{
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		if (n->EntryExpires <= Tick64())
		{
			Add(o, n);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		NON_SSL *n = LIST_DATA(o, i);

		Delete(c->NonSslList, n);
		Free(n);
	}

	ReleaseList(o);
}

// 非 SSL リストの検索
NON_SSL *SearchNoSslList(CEDAR *c, IP *ip)
{
	NON_SSL *n, t;
	// 引数チェック
	if (c == NULL || ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.IpAddress, ip, sizeof(IP));

	n = Search(c->NonSslList, &t);

	if (n == NULL)
	{
		return NULL;
	}

	return n;
}

// 非 SSL リストの初期化
void InitNoSslList(CEDAR *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->NonSslList = NewList(CompareNoSslList);
}

// 非 SSL リストの解放
void FreeNoSslList(CEDAR *c)
{
	UINT i;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(c->NonSslList);i++)
	{
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		Free(n);
	}

	ReleaseList(c->NonSslList);
	c->NonSslList = NULL;
}

// Cedar ログをとる
void CedarLog(char *str)
{
	char *tmp;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}
	if (cedar_log_ref == NULL)
	{
		return;
	}

	tmp = CopyStr(str);

	// このあたりは急いで実装したのでコードがあまり美しくない。
	if (StrLen(tmp) > 1)
	{
		if (tmp[StrLen(tmp) - 1] == '\n')
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
		if (StrLen(tmp) > 1)
		{
			if (tmp[StrLen(tmp) - 1] == '\r')
			{
				tmp[StrLen(tmp) - 1] = 0;
			}
		}
	}

	InsertStringRecord(cedar_log, tmp);

	Free(tmp);
}

// ログを開始する
void StartCedarLog()
{
	if (cedar_log_ref == NULL)
	{
		cedar_log_ref = NewRef();
	}
	else
	{
		AddRef(cedar_log_ref);
	}

	cedar_log = NewLog("debug_log", "debug", LOG_SWITCH_DAY);
}

// ログを停止する
void StopCedarLog()
{
	if (cedar_log_ref == NULL)
	{
		return;
	}

	if (Release(cedar_log_ref) == 0)
	{
		FreeLog(cedar_log);
		cedar_log = NULL;
		cedar_log_ref = NULL;
	}
}

// トラフィックのパケットサイズを取得する
UINT64 GetTrafficPacketSize(TRAFFIC *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return 0;
	}

	return t->Recv.BroadcastBytes + t->Recv.UnicastBytes +
		t->Send.BroadcastBytes + t->Send.UnicastBytes;
}

// トラフィックのパケット数を取得する
UINT64 GetTrafficPacketNum(TRAFFIC *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return 0;
	}

	return t->Recv.BroadcastCount + t->Recv.UnicastCount +
		t->Send.BroadcastCount + t->Send.UnicastCount;
}

// 非表示パスワードの内容が変更されたかどうかチェックする
bool IsHiddenPasswordChanged(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return true;
	}

	if (StrCmpi(str, HIDDEN_PASSWORD) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// 非表示パスワードを初期化する
void InitHiddenPassword(char *str, UINT size)
{
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	StrCpy(str, size, HIDDEN_PASSWORD);
}

// 証明書が仮想 HUB に登録されている CA によって署名されているかどうか確認する
bool CheckSignatureByCaLinkMode(SESSION *s, X *x)
{
	LINK *k;
	HUB *h;
	bool ret = false;
	// 引数チェック
	if (s == NULL || x == NULL)
	{
		return false;
	}

	if (s->LinkModeClient == false || (k = s->Link) == NULL)
	{
		return false;
	}

	h = k->Hub;

	if (h->HubDb != NULL)
	{
		LockList(h->HubDb->RootCertList);
		{
			X *root_cert;
			root_cert = GetIssuerFromList(h->HubDb->RootCertList, x);
			if (root_cert != NULL)
			{
				ret = true;
			}
		}
		UnlockList(h->HubDb->RootCertList);
	}

	return ret;
}

// 証明書が Cedar に登録されている CA によって署名されているかどうか確認する
bool CheckSignatureByCa(CEDAR *cedar, X *x)
{
	X *ca;
	// 引数チェック
	if (cedar == NULL || x == NULL)
	{
		return false;
	}

	// 指定された証明書を署名した CA を取得
	ca = FindCaSignedX(cedar->CaList, x);
	if (ca == NULL)
	{
		// 発見できなかった
		return false;
	}

	// 発見した
	FreeX(ca);
	return true;
}

// 指定された証明書を署名した CA を取得
X *FindCaSignedX(LIST *o, X *x)
{
	X *ret;
	// 引数チェック
	if (o == NULL || x == NULL)
	{
		return NULL;
	}

	ret = NULL;

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			X *ca = LIST_DATA(o, i);
			if (CheckXDateNow(ca))
			{
				if (CompareName(ca->subject_name, x->issuer_name))
				{
					K *k = GetKFromX(ca);
					if (k != NULL)
					{
						if (CheckSignature(x, k))
						{
							ret = CloneX(ca);
						}
						FreeK(k);
					}
				}
				else if (CompareX(ca, x))
				{
					ret = CloneX(ca);
				}
			}

			if (ret != NULL)
			{
				break;
			}
		}
	}
	UnlockList(o);

	return ret;
}

// Cedar から CA を削除する
bool DeleteCa(CEDAR *cedar, UINT ptr)
{
	bool b = false;
	// 引数チェック
	if (cedar == NULL || ptr == 0)
	{
		return false;
	}

	LockList(cedar->CaList);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(cedar->CaList);i++)
		{
			X *x = LIST_DATA(cedar->CaList, i);

			if (POINTER_TO_KEY(x) == ptr)
			{
				Delete(cedar->CaList, x);
				FreeX(x);

				b = true;

				break;
			}
		}
	}
	UnlockList(cedar->CaList);

	return b;
}

// Cedar に CA を追加する
void AddCa(CEDAR *cedar, X *x)
{
	// 引数チェック
	if (cedar == NULL || x == NULL)
	{
		return;
	}

	LockList(cedar->CaList);
	{
		UINT i;
		bool ok = true;

		for (i = 0;i < LIST_NUM(cedar->CaList);i++)
		{
			X *exist_x = LIST_DATA(cedar->CaList, i);
			if (CompareX(exist_x, x))
			{
				ok = false;
				break;
			}
		}

		if (ok)
		{
			Insert(cedar->CaList, CloneX(x));
		}
	}
	UnlockList(cedar->CaList);
}

// Cedar からコネクションを削除する
void DelConnection(CEDAR *cedar, CONNECTION *c)
{
	// 引数チェック
	if (cedar == NULL || c == NULL)
	{
		return;
	}

	LockList(cedar->ConnectionList);
	{
		Debug("Connection %s Deleted from Cedar.\n", c->Name);
		if (Delete(cedar->ConnectionList, c))
		{
			ReleaseConnection(c);
		}
	}
	UnlockList(cedar->ConnectionList);
}

// 現在の未確立コネクション数を取得する
UINT GetUnestablishedConnections(CEDAR *cedar)
{
	UINT i, ret;
	// 引数チェック
	if (cedar == NULL)
	{
		return 0;
	}

	ret = 0;

	LockList(cedar->ConnectionList);
	{
		for (i = 0;i < LIST_NUM(cedar->ConnectionList);i++)
		{
			CONNECTION *c = LIST_DATA(cedar->ConnectionList, i);

			switch (c->Type)
			{
			case CONNECTION_TYPE_CLIENT:
			case CONNECTION_TYPE_INIT:
			case CONNECTION_TYPE_LOGIN:
			case CONNECTION_TYPE_ADDITIONAL:
				switch (c->Status)
				{
				case CONNECTION_STATUS_ACCEPTED:
				case CONNECTION_STATUS_NEGOTIATION:
				case CONNECTION_STATUS_USERAUTH:
					ret++;
					break;
				}
				break;
			}
		}
	}
	UnlockList(cedar->ConnectionList);

	return ret + Count(cedar->AcceptingSockets);
}

// Cedar にコネクションを追加する
void AddConnection(CEDAR *cedar, CONNECTION *c)
{
	char tmp[MAX_SIZE];
	UINT i;
	// 引数チェック
	if (cedar == NULL || c == NULL)
	{
		return;
	}

	//新しいコネクションの名前を決定する
	i = Inc(cedar->ConnectionIncrement);
	Format(tmp, sizeof(tmp), "CID-%u", i);
	Lock(c->lock);
	{
		Free(c->Name);
		c->Name = CopyStr(tmp);
	}
	Unlock(c->lock);

	LockList(cedar->ConnectionList);
	{
		Add(cedar->ConnectionList, c);
		AddRef(c->ref);
		Debug("Connection %s Inserted to Cedar.\n", c->Name);
	}
	UnlockList(cedar->ConnectionList);
}

// すべてのコネクションを停止
void StopAllConnection(CEDAR *c)
{
	UINT num;
	UINT i;
	CONNECTION **connections;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	LockList(c->ConnectionList);
	{
		connections = ToArray(c->ConnectionList);
		num = LIST_NUM(c->ConnectionList);
		DeleteAll(c->ConnectionList);
	}
	UnlockList(c->ConnectionList);

	for (i = 0;i < num;i++)
	{
		StopConnection(connections[i], false);
		ReleaseConnection(connections[i]);
	}
	Free(connections);
}

// CEDAR から HUB を削除
void DelHub(CEDAR *c, HUB *h)
{
	DelHubEx(c, h, false);
}
void DelHubEx(CEDAR *c, HUB *h, bool no_lock)
{
	// 引数チェック
	if (c == NULL || h == NULL)
	{
		return;
	}

	if (no_lock == false)
	{
		LockHubList(c);
	}

	if (Delete(c->HubList, h))
	{
		ReleaseHub(h);
	}

	if (no_lock == false)
	{
		UnlockHubList(c);
	}
}

// CEDAR に HUB を追加
void AddHub(CEDAR *c, HUB *h)
{
	// 引数チェック
	if (c == NULL || h == NULL)
	{
		return;
	}

	LockHubList(c);
	{
#if	0
		// HUB 数はここではチェックしないことにする
		if (LIST_NUM(c->HubList) >= MAX_HUBS)
		{
			// 上限数超過
			UnlockHubList(c);
			return;
		}
#endif

		// 同一名の HUB が存在しないかどうかチェック
		if (IsHub(c, h->Name))
		{
			// 存在する
			UnlockHubList(c);
			return;
		}

		// HUB を登録する
		Insert(c->HubList, h);
		AddRef(h->ref);
	}
	UnlockHubList(c);
}

// CEDAR のすべての HUB を停止
void StopAllHub(CEDAR *c)
{
	HUB **hubs;
	UINT i, num;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	LockHubList(c);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);
		DeleteAll(c->HubList);
	}
	UnlockHubList(c);

	for (i = 0;i < num;i++)
	{
		StopHub(hubs[i]);
		ReleaseHub(hubs[i]);
	}

	Free(hubs);
}

// CEDAR にリスナーを追加
void AddListener(CEDAR *c, LISTENER *r)
{
	// 引数チェック
	if (c == NULL || r == NULL)
	{
		return;
	}

	LockList(c->ListenerList);
	{
		Add(c->ListenerList, r);
		AddRef(r->ref);
	}
	UnlockList(c->ListenerList);
}

// CEDAR のすべてのリスナーを停止
void StopAllListener(CEDAR *c)
{
	LISTENER **array;
	UINT i, num;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	LockList(c->ListenerList);
	{
		array = ToArray(c->ListenerList);
		num = LIST_NUM(c->ListenerList);
		DeleteAll(c->ListenerList);
	}
	UnlockList(c->ListenerList);

	for (i = 0;i < num;i++)
	{
		StopListener(array[i]);
		ReleaseListener(array[i]);
	}
	Free(array);
}

// CEDAR の停止
void StopCedar(CEDAR *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	// 停止フラグ
	c->Halt = true;

	// すべてのリスナーを停止
	StopAllListener(c);
	// すべてのコネクションを停止
	StopAllConnection(c);
	// すべての HUB を停止
	StopAllHub(c);
	// すべての L3 スイッチを解放
	L3FreeAllSw(c);
}

// CEDAR のクリーンアップ
void CleanupCedar(CEDAR *c)
{
	UINT i;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	FreeCedarLayer3(c);

/*
	for (i = 0;i < LIST_NUM(c->HubList);i++)
	{
		HUB *h = LIST_DATA(c->HubList, i);
	}
*/
	for (i = 0;i < LIST_NUM(c->CaList);i++)
	{
		X *x = LIST_DATA(c->CaList, i);
		FreeX(x);
	}
	ReleaseList(c->CaList);

	ReleaseList(c->ListenerList);
	ReleaseList(c->HubList);
	ReleaseList(c->ConnectionList);
	//CleanupUDPEntry(c);
	ReleaseList(c->UDPEntryList);
	DeleteLock(c->lock);
	DeleteCounter(c->ConnectionIncrement);
	DeleteCounter(c->CurrentSessions);

	if (c->DebugLog != NULL)
	{
		FreeLog(c->DebugLog);
	}

	if (c->ServerX)
	{
		FreeX(c->ServerX);
	}
	if (c->ServerK)
	{
		FreeK(c->ServerK);
	}

	if (c->CipherList)
	{
		Free(c->CipherList);
	}

	for (i = 0;i < LIST_NUM(c->TrafficDiffList);i++)
	{
		TRAFFIC_DIFF *d = LIST_DATA(c->TrafficDiffList, i);
		Free(d->Name);
		Free(d->HubName);
		Free(d);
	}

	ReleaseList(c->TrafficDiffList);

	Free(c->ServerStr);
	Free(c->MachineName);

	Free(c->HttpUserAgent);
	Free(c->HttpAccept);
	Free(c->HttpAcceptLanguage);
	Free(c->HttpAcceptEncoding);

	FreeTraffic(c->Traffic);

	DeleteLock(c->TrafficLock);

	FreeNetSvcList(c);

	Free(c->VerString);
	Free(c->BuildInfo);

	FreeLocalBridgeList(c);

	DeleteCounter(c->AssignedBridgeLicense);
	DeleteCounter(c->AssignedClientLicense);

	FreeNoSslList(c);

	DeleteLock(c->CedarSuperLock);

	DeleteCounter(c->AcceptingSockets);

	Free(c);
}

// CEDAR の解放
void ReleaseCedar(CEDAR *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupCedar(c);
	}
}

// CipherList のセット
void SetCedarCipherList(CEDAR *cedar, char *name)
{
	// 引数チェック
	if (cedar == NULL)
	{
		return;
	}

	if (cedar->CipherList != NULL)
	{
		Free(cedar->CipherList);
	}
	if (name != NULL)
	{
		cedar->CipherList = CopyStr(name);
	}
	else
	{
		cedar->CipherList = NULL;
	}
}

// ネットサービスリストのソート
int CompareNetSvc(void *p1, void *p2)
{
	NETSVC *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NETSVC **)p1;
	n2 = *(NETSVC **)p2;
	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}
	if (n1->Port > n2->Port)
	{
		return 1;
	}
	else if (n1->Port < n2->Port)
	{
		return -1;
	}
	else if (n1->Udp > n2->Udp)
	{
		return 1;
	}
	else if (n1->Udp < n2->Udp)
	{
		return -1;
	}
	return 0;
}

// ネットサービスリストの初期化
void InitNetSvcList(CEDAR *cedar)
{
	char filename[MAX_PATH] = "/etc/services";
	BUF *b;
	// 引数チェック
	if (cedar == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	// 自力でがんばって読む
	Format(filename, sizeof(filename), "%s\\drivers\\etc\\services", MsGetSystem32Dir());
#endif

	cedar->NetSvcList = NewList(CompareNetSvc);

	b = ReadDump(filename);
	if (b == NULL)
	{
		return;
	}

	while (true)
	{
		char *s = CfgReadNextLine(b);
		if (s == NULL)
		{
			break;
		}

		Trim(s);
		if (s[0] != '#')
		{
			TOKEN_LIST *t = ParseToken(s, " \t/");
			if (t->NumTokens >= 3)
			{
				NETSVC *n = ZeroMalloc(sizeof(NETSVC));
				n->Name = CopyStr(t->Token[0]);
				n->Udp = (StrCmpi(t->Token[2], "udp") == 0 ? true : false);
				n->Port = ToInt(t->Token[1]);
				Add(cedar->NetSvcList, n);
			}
			FreeToken(t);
		}
		Free(s);
	}

	FreeBuf(b);
}

// ネットサービス名の取得
char *GetSvcName(CEDAR *cedar, bool udp, UINT port)
{
	char *ret = NULL;
	NETSVC t;
	// 引数チェック
	if (cedar == NULL)
	{
		return NULL;
	}

	t.Udp = (udp == 0 ? false : true);
	t.Port = port;

	LockList(cedar->NetSvcList);
	{
		NETSVC *n = Search(cedar->NetSvcList, &t);
		if (n != NULL)
		{
			ret = n->Name;
		}
	}
	UnlockList(cedar->NetSvcList);

	return ret;
}

// ネットサービスリストの解放
void FreeNetSvcList(CEDAR *cedar)
{
	UINT i;
	// 引数チェック
	if (cedar == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(cedar->NetSvcList);i++)
	{
		NETSVC *n = LIST_DATA(cedar->NetSvcList, i);
		Free(n->Name);
		Free(n);
	}
	ReleaseList(cedar->NetSvcList);
}

// CEDAR の証明書の変更
void SetCedarCert(CEDAR *c, X *server_x, K *server_k)
{
	// 引数チェック
	if (server_x == NULL || server_k == NULL)
	{
		return;
	}

	Lock(c->lock);
	{
		if (c->ServerX != NULL)
		{
			FreeX(c->ServerX);
		}

		if (c->ServerK != NULL)
		{
			FreeK(c->ServerK);
		}

		c->ServerX = CloneX(server_x);
		c->ServerK = CloneK(server_k);
	}
	Unlock(c->lock);
}

// デバッグログを有効にする
void EnableDebugLog(CEDAR *c)
{
	// 引数チェック
	if (c == NULL || c->DebugLog != NULL)
	{
		return;
	}

	c->DebugLog = NewLog("cedar_debug_log", "cedar", LOG_SWITCH_NO);
}

// CEDAR を VPN Bridge にする
void SetCedarVpnBridge(CEDAR *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	c->Bridge = true;

	Free(c->ServerStr);
	c->ServerStr = CopyStr(CEDAR_BRIDGE_STR);
}

// CEDAR の作成
CEDAR *NewCedar(X *server_x, K *server_k)
{
	CEDAR *c;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	char *beta_str;

	c = ZeroMalloc(sizeof(CEDAR));

	c->AcceptingSockets = NewCounter();

	c->CedarSuperLock = NewLock();

#ifdef	BETA_NUMBER
	c->Beta = BETA_NUMBER;
#endif	// BETA_NUMBER

	InitNoSslList(c);

	c->AssignedBridgeLicense = NewCounter();
	c->AssignedClientLicense = NewCounter();

	Rand(c->UniqueId, sizeof(c->UniqueId));

	c->CreatedTick = Tick64();

	c->lock = NewLock();
	c->ref = NewRef();

	c->CurrentTcpConnections = GetNumTcpConnectionsCounter();

	c->ListenerList = NewList(CompareListener);
	c->UDPEntryList = NewList(CompareUDPEntry);
	c->HubList = NewList(CompareHub);
	c->ConnectionList = NewList(CompareConnection);

	c->ConnectionIncrement = NewCounter();
	c->CurrentSessions = NewCounter();

	if (server_k && server_x)
	{
		c->ServerK = CloneK(server_k);
		c->ServerX = CloneX(server_x);
	}

	c->Version = CEDAR_VER;
	c->Build = CEDAR_BUILD;
	c->ServerStr = CopyStr(CEDAR_SERVER_STR);

	GetMachineName(tmp, sizeof(tmp));
	c->MachineName = CopyStr(tmp);

	c->HttpUserAgent = CopyStr(DEFAULT_USER_AGENT);
	c->HttpAccept = CopyStr(DEFAULT_ACCEPT);
	c->HttpAcceptLanguage = CopyStr("ja");
	c->HttpAcceptEncoding = CopyStr(DEFAULT_ENCODING);

	c->Traffic = NewTraffic();
	c->TrafficLock = NewLock();
	c->CaList = NewList(CompareCert);

	c->TrafficDiffList = NewList(NULL);

	SetCedarCipherList(c, "RC4-MD5");

	c->ClientId = _II("CLIENT_ID");

	InitNetSvcList(c);

	InitLocalBridgeList(c);

	InitCedarLayer3(c);

#ifdef	ALPHA_VERSION
	beta_str = "Alpha";
#else	// ALPHA_VERSION
	beta_str = "Release Candidate";
#endif	// ALPHA_VERSION

	ToStr(tmp2, c->Beta);

	Format(tmp, sizeof(tmp), "Version %u.%02u Build %u %s %s (%s)",
		CEDAR_VER / 100, CEDAR_VER - (CEDAR_VER / 100) * 100,
		CEDAR_BUILD,
		c->Beta == 0 ? "" : beta_str,
		c->Beta == 0 ? "" : tmp2,
		_SS("LANGSTR"));
	Trim(tmp);

	if (true)
	{
		SYSTEMTIME st;
		Zero(&st, sizeof(st));

		st.wYear = BUILD_DATE_Y;
		st.wMonth = BUILD_DATE_M;
		st.wDay = BUILD_DATE_D;

		c->BuiltDate = SystemToUINT64(&st);
	}

	c->VerString = CopyStr(tmp);

	Format(tmp, sizeof(tmp), "Compiled %04u/%02u/%02u %02u:%02u:%02u by %s at %s",
		BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D, BUILD_DATE_HO, BUILD_DATE_MI, BUILD_DATE_SE, BUILDER_NAME, BUILD_PLACE);

	c->BuildInfo = CopyStr(tmp);

	return c;
}

// 指定した日付よりも遅い日付にビルドされたものであるかどうか取得
bool IsLaterBuild(CEDAR *c, UINT64 t)
{
	SYSTEMTIME sb, st;
	UINT64 b;
	// 引数チェック
	if (c == NULL)
	{
		return false;
	}

	Zero(&sb, sizeof(sb));
	Zero(&st, sizeof(st));

	UINT64ToSystem(&sb, c->BuiltDate);
	UINT64ToSystem(&st, t);

	// 時刻データを無視
	sb.wHour = sb.wMinute = sb.wSecond = sb.wMilliseconds = 0;
	st.wHour = st.wMinute = st.wSecond = st.wMilliseconds = 0;

	b = SystemToUINT64(&sb);
	t = SystemToUINT64(&st);

	if (b > t)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// トラフィック情報の加算
void AddTraffic(TRAFFIC *dst, TRAFFIC *diff)
{
	// 引数チェック
	if (dst == NULL || diff == NULL)
	{
		return;
	}

	dst->Recv.BroadcastBytes += diff->Recv.BroadcastBytes;
	dst->Recv.BroadcastCount += diff->Recv.BroadcastCount;
	dst->Recv.UnicastBytes += diff->Recv.UnicastBytes;
	dst->Recv.UnicastCount += diff->Recv.UnicastCount;

	dst->Send.BroadcastBytes += diff->Send.BroadcastBytes;
	dst->Send.BroadcastCount += diff->Send.BroadcastCount;
	dst->Send.UnicastBytes += diff->Send.UnicastBytes;
	dst->Send.UnicastCount += diff->Send.UnicastCount;
}

// トラフィック情報の作成
TRAFFIC *NewTraffic()
{
	TRAFFIC *t;

	// メモリ確保
	t = ZeroMalloc(sizeof(TRAFFIC));
	return t;
}

// トラフィック情報の解放
void FreeTraffic(TRAFFIC *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// メモリ解放
	Free(t);
}

// Cedar 通信モジュールの初期化
void InitCedar()
{
	if ((init_cedar_counter++) > 0)
	{
		return;
	}

	// プロトコル初期化
	InitProtocol();
}

// Cedar 通信モジュールの解放
void FreeCedar()
{
	if ((--init_cedar_counter) > 0)
	{
		return;
	}

	// プロトコル解放
	FreeProtocol();
}

