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

// Command.c
// vpncmd コマンドライン管理ユーティリティ

#include "CedarPch.h"

// システムチェッカ定義
typedef bool (CHECKER_PROC_DEF)();
typedef struct CHECKER_PROC
{
	char *Title;
	CHECKER_PROC_DEF *Proc;
} CHECKER_PROC;

static CHECKER_PROC checker_procs[] =
{
	{"CHECK_PROC_KERNEL", CheckKernel},
	{"CHECK_PROC_MEMORY", CheckMemory},
	{"CHECK_PROC_STRINGS", CheckStrings},
	{"CHECK_PROC_FILESYSTEM", CheckFileSystem},
	{"CHECK_PROC_THREAD", CheckThread},
	{"CHECK_PROC_NETWORK", CheckNetwork},
};

typedef struct CHECK_NETWORK_1
{
	SOCK *ListenSocket;
} CHECK_NETWORK_1;

typedef struct CHECK_NETWORK_2
{
	SOCK *s;
	X *x;
	K *k;
} CHECK_NETWORK_2;


// TT_RESULT を RPC に変換
void OutRpcTtResult(PACK *p, TT_RESULT *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddBool(p, "Raw", t->Raw);
	PackAddBool(p, "Double", t->Double);
	PackAddInt64(p, "NumBytesUpload", t->NumBytesUpload);
	PackAddInt64(p, "NumBytesDownload", t->NumBytesDownload);
	PackAddInt64(p, "NumBytesTotal", t->NumBytesTotal);
	PackAddInt64(p, "Span", t->Span);
	PackAddInt64(p, "BpsUpload", t->BpsUpload);
	PackAddInt64(p, "BpsDownload", t->BpsDownload);
	PackAddInt64(p, "BpsTotal", t->BpsTotal);
}

// RPC を TT_RESULT に変換
void InRpcTtResult(PACK *p, TT_RESULT *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(TT_RESULT));

	t->Raw = PackGetBool(p, "Raw");
	t->Double = PackGetBool(p, "Double");
	t->NumBytesUpload = PackGetInt64(p, "NumBytesUpload");
	t->NumBytesDownload = PackGetInt64(p, "NumBytesDownload");
	t->NumBytesTotal = PackGetInt64(p, "NumBytesTotal");
	t->Span = PackGetInt64(p, "Span");
	t->BpsUpload = PackGetInt64(p, "BpsUpload");
	t->BpsDownload = PackGetInt64(p, "BpsDownload");
	t->BpsTotal = PackGetInt64(p, "BpsTotal");
}

// Accept スレッド
void CheckNetworkAcceptThread(THREAD *thread, void *param)
{
	CHECK_NETWORK_2 *c = (CHECK_NETWORK_2 *)param;
	SOCK *s = c->s;
	UINT i = 0;

	if (StartSSL(s, c->x, c->k))
	{
		while (true)
		{
			i++;
			if (Send(s, &i, sizeof(UINT), true) == 0)
			{
				break;
			}
		}
	}

	Disconnect(s);
	ReleaseSock(s);
}


// Listen スレッド
void CheckNetworkListenThread(THREAD *thread, void *param)
{
	CHECK_NETWORK_1 *c = (CHECK_NETWORK_1 *)param;
	SOCK *s;
	UINT i;
	K *pub, *pri;
	X *x;
	LIST *o = NewList(NULL);
	NAME *name = NewName(L"Test", L"Test", L"Test", L"JP", L"Ibaraki", L"Tsukuba");

	RsaGen(&pri, &pub, 1024);
	x = NewRootX(pub, pri, name, 1000, NULL);

	FreeName(name);

	for (i = 1025;;i++)
	{
		s = Listen(i);
		if (s != NULL)
		{
			break;
		}
	}

	c->ListenSocket = s;
	AddRef(s->ref);

	NoticeThreadInit(thread);

	while (true)
	{
		SOCK *new_sock = Accept(s);

		if (new_sock == NULL)
		{
			break;
		}
		else
		{
			CHECK_NETWORK_2 c;
			THREAD *t;

			Zero(&c, sizeof(c));
			c.s = new_sock;
			c.k = pri;
			c.x = x;

			t = NewThread(CheckNetworkAcceptThread, &c);
			Insert(o, t);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		THREAD *t = LIST_DATA(o, i);
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	FreeK(pri);
	FreeK(pub);

	FreeX(x);

	ReleaseSock(s);
	ReleaseList(o);
}

// ネットワーク機能チェック
bool CheckNetwork()
{
	CHECK_NETWORK_1 c;
	THREAD *t;
	SOCK *listen_socket;
	UINT port;
	UINT i, num;
	bool ok = true;
	SOCK **socks;
	SOCK_EVENT *se = NewSockEvent();

	Zero(&c, sizeof(c));
	t = NewThread(CheckNetworkListenThread, &c);
	WaitThreadInit(t);

	listen_socket = c.ListenSocket;

	port = listen_socket->LocalPort;

	num = 8;
	socks = ZeroMalloc(sizeof(SOCK *) * num);
	for (i = 0;i < num;i++)
	{
		socks[i] = Connect("localhost", port);
		if (socks[i] == NULL)
		{
			Print("Connect Failed. (%u)\n", i);
			ok = false;
			num = i;
			break;
		}
		if (StartSSL(socks[i], NULL, NULL) == false)
		{
			ReleaseSock(socks[i]);
			Print("Connect Failed. (%u)\n", i);
			ok = false;
			num = i;
			break;
		}

		JoinSockToSockEvent(socks[i], se);
	}

	if (ok)
	{
		while (true)
		{
			UINT i;
			bool end = false;
			bool all_blocked = true;

			for (i = 0;i < num;i++)
			{
				UINT n;
				UINT ret;

				n = 0;
				ret = Recv(socks[i], &n, sizeof(UINT), true);
				if (ret == 0)
				{
					Print("Recv Failed (Disconnected).\n", ret);
					end = true;
					ok = false;
				}
				if (ret != SOCK_LATER)
				{
					all_blocked = false;
				}

				if (n >= 128)
				{
					end = true;
				}
			}

			if (end)
			{
				break;
			}

			if (all_blocked)
			{
				WaitSockEvent(se, INFINITE);
			}
		}
	}

	for (i = 0;i < num;i++)
	{
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}
	Free(socks);

	Disconnect(listen_socket);

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	ReleaseSock(listen_socket);

	ReleaseSockEvent(se);

	return ok;
}

typedef struct CHECK_THREAD_1
{
	UINT num;
	LOCK *lock;
	THREAD *wait_thread;
} CHECK_THREAD_1;

static UINT check_thread_global_1 = 0;

#define	CHECK_THREAD_INCREMENT_COUNT		32

// テストスレッド 1
void CheckThread1(THREAD *thread, void *param)
{
	CHECK_THREAD_1 *ct1 = (CHECK_THREAD_1 *)param;
	UINT i;
	UINT num = CHECK_THREAD_INCREMENT_COUNT;

	WaitThread(ct1->wait_thread, INFINITE);

	for (i = 0;i < num;i++)
	{
		Lock(ct1->lock);
		check_thread_global_1 = ct1->num;
		InputToNull((void *)check_thread_global_1);
		check_thread_global_1 = check_thread_global_1 + 1 + RetZero();
		ct1->num = check_thread_global_1;
		Unlock(ct1->lock);
	}
}

// テストスレッド 2
void CheckThread2(THREAD *thread, void *param)
{
	EVENT *e = (EVENT *)param;
	Wait(e, INFINITE);
}

typedef struct CHECK_THREAD_3
{
	UINT num, a;
} CHECK_THREAD_3;

// テストスレッド 3
void CheckThread3(THREAD *thread, void *param)
{
	CHECK_THREAD_3 *c = (CHECK_THREAD_3 *)param;
	THREAD *t;

	if (c->num == 0)
	{
		return;
	}
	c->num--;
	c->a++;

	t = NewThread(CheckThread3, c);
	WaitThread(t, INFINITE);
	ReleaseThread(t);
}

// スレッドチェック
bool CheckThread()
{
	bool ok = true;
	CHECK_THREAD_1 ct1;
	UINT num = 32;
	UINT i;
	THREAD **threads;
	EVENT *e;
	THREAD *t2;
	THREAD *t;
	CHECK_THREAD_3 c;

	e = NewEvent();

	Zero(&ct1, sizeof(ct1));
	ct1.lock = NewLock();

	t2 = NewThread(CheckThread2, e);
	ct1.wait_thread = t2;

	threads = ZeroMalloc(sizeof(THREAD *) * num);
	for (i = 0;i < num;i++)
	{
		threads[i] = NewThread(CheckThread1, &ct1);
		if (threads[i] == NULL)
		{
			Print("Thread %u Create Failed.\n", i);
			ok = false;
		}
	}

	Set(e);

	for (i = 0;i < num;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}

	Free(threads);

	if (ct1.num != (num * CHECK_THREAD_INCREMENT_COUNT))
	{
		Print("Threading: %u != %u\n", ct1.num, num * CHECK_THREAD_INCREMENT_COUNT);
		ok = false;
	}

	DeleteLock(ct1.lock);

	WaitThread(t2, INFINITE);
	ReleaseThread(t2);

	ReleaseEvent(e);

	num = 32;

	Zero(&c, sizeof(c));
	c.num = num;
	t = NewThread(CheckThread3, &c);
	WaitThread(t, INFINITE);
	ReleaseThread(t);

	if (c.a != num)
	{
		Print("Threading: %u != %u\n", c.a, num);
		ok = false;
	}

	return ok;
}

// ファイルシステムチェック
bool CheckFileSystem()
{
	bool ok = true;
	char exe[MAX_PATH];
	char exe_dir[MAX_PATH];
	DIRLIST *dirs;
	UINT i;

	GetExeName(exe, sizeof(exe));
	GetExeDir(exe_dir, sizeof(exe_dir));

	ok = false;
	dirs = EnumDir(exe_dir);
	for (i = 0;i < dirs->NumFiles;i++)
	{
		if (EndWith(exe, dirs->File[i]->FileName))
		{
			ok = true;
			break;
		}
	}
	FreeDir(dirs);

	if (ok == false)
	{
		Print("EnumDir Failed.\n");
		return false;
	}
	else
	{
		UINT size = 1234567;
		UCHAR *buf;
		IO *io;
#ifndef	OS_WIN32
		wchar_t *filename = L"/tmp/vpn_checker_tmp";
#else	// OS_WIN32
		wchar_t filename[MAX_PATH];
		CombinePathW(filename, sizeof(filename), MsGetMyTempDirW(), L"vpn_checker_tmp");
#endif	// OS_WIN32

		buf = Malloc(size);
		for (i = 0;i < size;i++)
		{
			buf[i] = i % 256;
		}

		io = FileCreateW(filename);
		if (io == NULL)
		{
			Print("FileCreate Failed.\n");
			Free(buf);
			return false;
		}
		else
		{
			FileWrite(io, buf, size);
			Free(buf);
			FileClose(io);

			io = FileOpenW(filename, false);
			if (FileSize(io) != 1234567)
			{
				Print("FileSize Failed.\n");
				FileClose(io);
				return false;
			}
			else
			{
				BUF *b;

				FileClose(io);
				b = ReadDumpW(filename);

				for (i = 0;i < b->Size;i++)
				{
					UCHAR c = ((UCHAR *)b->Buf)[i];

					if (c != (i % 256))
					{
						Print("FileToBuf Failed.\n");
						FreeBuf(b);
						return false;
					}
				}

				FreeBuf(b);
			}
		}

		FileDeleteW(filename);
	}

	return ok;
}

// 文字列チェック
bool CheckStrings()
{
	wchar_t *numstr = _UU("CHECK_TEST_123456789");
	char tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	UINT i;
	UINT sum, sum2;
	UNI_TOKEN_LIST *t;

	UniStrCpy(tmp2, sizeof(tmp2), L"");

	sum2 = 0;
	for (i = 0;i < 64;i++)
	{
		sum2 += i;
		UniFormat(tmp2, sizeof(tmp2), L"%s,%u", tmp2, i);
	}

	t = UniParseToken(tmp2, L",");

	sum = 0;

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *s = t->Token[i];
		UINT n = UniToInt(s);

		sum += n;
	}

	UniFreeToken(t);

	if (sum != sum2)
	{
		Print("UniParseToken Failed.\n");
		return false;
	}

	if (UniToInt(numstr) != 123456789)
	{
		Print("UniToInt Failed.\n");
		return false;
	}

	UniToStr(tmp, sizeof(tmp), numstr);
	if (ToInt(tmp) != 123456789)
	{
		Print("UniToStr Failed.\n");
		return false;
	}

	StrToUni(tmp2, sizeof(tmp2), _SS("CHECK_TEST_TESTSTR"));
	if (UniStrCmp(_UU("CHECK_TEST_TESTSTR"), tmp2) != 0)
	{
		Print("StrToUni Failed.\n");
		printf("[%S] [%S]\n", tmp2, _UU("CHECK_TEST_TESTSTR"));
		return false;
	}

	ReplaceStrEx(tmp, sizeof(tmp), _SS("CHECK_TEST_REPLACE1"), _SS("CHECK_TEST_REPLACE3"),
		_SS("CHECK_TEST_REPLACE4"), false);

	if (StrCmp(tmp, _SS("CHECK_TEST_REPLACE2")) != 0)
	{
		Print("ReplaceStrEx Failed.\n");
		return false;
	}

	UniReplaceStrEx(tmp2, sizeof(tmp2), _UU("CHECK_TEST_REPLACE1"), _UU("CHECK_TEST_REPLACE3"),
		_UU("CHECK_TEST_REPLACE4"), false);

	if (UniStrCmp(tmp2, _UU("CHECK_TEST_REPLACE2")) != 0)
	{
		Print("UniReplaceStrEx Failed.\n");
		return false;
	}

	return true;
}

// メモリチェック
bool CheckMemory()
{
	UINT i, num, size, j;
	void **pp;
	bool ok = true;
	UINT old_size;

	num = 2000;
	size = 1000;
	pp = ZeroMalloc(sizeof(void *) * num);
	for (i = 0;i < num;i++)
	{
		pp[i] = ZeroMalloc(size);
		InputToNull(pp[i]);
		for (j = 0;j < size;j++)
		{
			((UCHAR *)pp[i])[j] = j % 256;
		}
	}
	old_size = size;
	size = size * 3;
	for (i = 0;i < num;i++)
	{
		pp[i] = ReAlloc(pp[i], size);
		for (j = old_size;j < size;j++)
		{
			InputToNull((void *)(UINT)(((UCHAR *)pp[i])[j] = j % 256));
		}
	}
	for (i = 0;i < num;i++)
	{
		for (j = 0;j < size;j++)
		{
			if (((UCHAR *)pp[i])[j] != (j % 256))
			{
				ok = false;
			}
		}
		Free(pp[i]);
	}
	Free(pp);

	return ok;
}

// 何もしない関数
void InputToNull(void *p)
{
	// 意味不明！
	if (RetZero() == 1)
	{
		UCHAR *c = (UCHAR *)p;
		c[0] = 0x32;
	}
}

// 0 を返す関数
UINT RetZero()
{
	// 意味不明！
	if (g_debug == 0x123455)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


// カーネルチェック
bool CheckKernel()
{
	UINT num = 10, i;
	UINT64 s = Tick64();
	UINT64 t = Tick64();

	for (i = 0;i < num;i++)
	{
		UINT64 q = Tick64();
		if (t > q)
		{
			Print("Tick64 #1 Failed.\n");
			return false;
		}

		t = q;

		SleepThread(100);
	}

	t = (Tick64() - s);
	if (t <= 500 || t >= 2000)
	{
		Print("Tick64 #2 Failed.\n");
		return false;
	}
	else if (false)
	{
		UINT64 tick1 = Tick64();
		UINT64 time1;
		UINT64 tick2, time2;

		SleepThread(1000);

		tick2 = Tick64();
		time2 = LocalTime64();
		time1 = SystemToLocal64(TickToTime(tick1));

		if (time2 > time1)
		{
			s = time2 - time1;
		}
		else
		{
			s = time1 - time2;
		}

		if (s <= 500 || s >= 2000)
		{
			Print("TickToTime Failed.\n");
			return false;
		}
	}

#ifdef	OS_UNIX
	{
		// 子プロセスのテスト
		UINT pid;
		char exe[MAX_SIZE];

		GetExeName(exe, sizeof(exe));

		pid = fork();

		if (pid == -1)
		{
			Print("fork Failed.\n");
			return false;
		}

		if (pid == 0)
		{
			char *param = UNIX_ARG_EXIT;
			char **args;

			args = ZeroMalloc(sizeof(char *) * 3);
			args[0] = exe;
			args[1] = param;
			args[2] = NULL;

			setsid();

			// 標準入出力をクローズする
			UnixCloseIO();

			// 不要なシグナルを停止する
			signal(SIGHUP, SIG_IGN);

			execvp(exe, args);
			AbortExit();
		}
		else
		{
			int status = 0, ret;

			// 子プロセスの終了を待機する
			ret = waitpid(pid, &status, 0);

			if (WIFEXITED(status) == 0)
			{
				// 異常終了した
				Print("waitpid Failed: 0x%x\n", ret);
				return false;
			}
		}
	}
#endif	// OS_UNIX

	return true;
}

// システムチェッカ
bool SystemCheck()
{
	UINT i;
	bool ng = false;

	UniPrint(_UU("CHECK_TITLE"));
	UniPrint(_UU("CHECK_NOTE"));
	for (i = 0;i < sizeof(checker_procs) / sizeof(checker_procs[0]);i++)
	{
		wchar_t *title;
		bool ret = false;
		CHECKER_PROC *p = &checker_procs[i];

		title = _UU(p->Title);

		UniPrint(_UU("CHECK_EXEC_TAG"), title);

		ret = p->Proc();

		if (ret == false)
		{
			ng = true;
		}

		UniPrint(L"              %s\n", ret ? _UU("CHECK_PASS") : _UU("CHECK_FAIL"));
	}

	UniPrint(L"\n");
	if (ng == false)
	{
		UniPrint(L"%s\n\n", _UU("CHECK_RESULT_1"));
	}
	else
	{
		UniPrint(L"%s\n\n", _UU("CHECK_RESULT_2"));
	}

	return true;
}


// 動作チェッカ
UINT PtCheck(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (SystemCheck() == false)
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

// VPN Tools メイン関数
void PtMain(PT *pt)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (pt == NULL)
	{
		return;
	}

	// 起動が完了したメッセージを表示する
	UniFormat(tmp, sizeof(tmp), _UU("CMD_UTVPNCMD_TOOLS_CONNECTED"));
	pt->Console->Write(pt->Console, tmp);
	pt->Console->Write(pt->Console, L"");

	while (true)
	{
		// コマンドの定義
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"MakeCert", PtMakeCert},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"Check", PtCheck},
		};

		// プロンプトの生成
		StrCpy(prompt, sizeof(prompt), "VPN Tools>");

		if (DispatchNextCmdEx(pt->Console, pt->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), pt) == false)
		{
			break;
		}
		pt->LastError = pt->Console->RetCode;

		if (pt->LastError == ERR_NO_ERROR && pt->Console->ConsoleType != CONSOLE_CSV)
		{
			pt->Console->Write(pt->Console, _UU("CMD_MSG_OK"));
			pt->Console->Write(pt->Console, L"");
		}

		if (pt->CmdLine != NULL)
		{
			break;
		}
	}
}

// VPN Tools コンテキストの作成
PT *NewPt(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	pt = ZeroMalloc(sizeof(PT));
	pt->Console = c;
	pt->CmdLine = CopyUniStr(cmdline);

	return pt;
}

// VPN Tools コンテキストの解放
void FreePt(PT *pt)
{
	// 引数チェック
	if (pt == NULL)
	{
		return;
	}

	Free(pt->CmdLine);
	Free(pt);
}

// VPN Tools 開始
UINT PtConnect(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	UINT ret = 0;
	// 引数チェック
	if (c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	pt = NewPt(c, cmdline);

	PtMain(pt);

	ret = pt->LastError;

	FreePt(pt);

	return ret;
}

// vpncmd コマンドの起動パス情報の初期化
void VpnCmdInitBootPath()
{
#ifdef	OS_WIN32
	char exe_path[MAX_PATH];
	char tmp[MAX_PATH];
	GetExeName(exe_path, sizeof(exe_path));

	if (SearchStrEx(exe_path, "ham.exe", 0, false) != INFINITE || SearchStrEx(exe_path, "ham_x64.exe", 0, false) != INFINITE || SearchStrEx(exe_path, "ham_ia64.exe", 0, false) != INFINITE)
	{
		return;
	}

	if (MsIsAdmin())
	{
		UINT current_ver;

		// 現在インストールされている vpncmd のバージョンの取得
		current_ver = MsRegReadInt(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER);

		if ((CEDAR_BUILD >= current_ver) ||
			MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
		{
			char *src_filename;
			bool b = false;
			// vpncmdsys.exe を system32 にコピーする
			if (MsIsNt())
			{
				Format(tmp, sizeof(tmp), "%s\\utvpncmd.exe", MsGetSystem32Dir());
			}
			else
			{
				Format(tmp, sizeof(tmp), "%s\\utvpncmd.exe", MsGetWindowsDir());
			}

			src_filename = VPNCMD_BOOTSTRAP_FILENAME;

			if (IsX64())
			{
				src_filename = VPNCMD_BOOTSTRAP_FILENAME_X64;
			}

			if (IsIA64())
			{
				src_filename = VPNCMD_BOOTSTRAP_FILENAME_IA64;
			}

			b = true;

			if (MsIs64BitWindows() == false || Is64())
			{
				if (IsFile(tmp) == false || (CEDAR_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
				{
					b = FileCopy(src_filename, tmp);
				}
			}
			else
			{
				void *wow;

				wow = MsDisableWow64FileSystemRedirection();

				if (true)
				{
					if (IsFile(tmp) == false || (CEDAR_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
					{
						b = FileCopy(src_filename, tmp);
					}
				}

				MsRestoreWow64FileSystemRedirection(wow);

				if (true)
				{
					if (IsFile(tmp) == false || (CEDAR_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
					{
						b = FileCopy(src_filename, tmp);
					}
				}
			}

			// 現在実行しているプロンプトのほうがバージョンが新しいのでレジストリを上書きする
			if (MsIs64BitWindows() == false)
			{
				MsRegWriteStr(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path);
				MsRegWriteInt(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_BUILD);
			}
			else
			{
				MsRegWriteStrEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path, true, false);
				MsRegWriteIntEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_BUILD, true, false);

				MsRegWriteStrEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path, false, true);
				MsRegWriteIntEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_BUILD, false, true);
			}
		}
	}
#endif	// OS_WIN32
}

// 文字列の表示
void TtPrint(void *param, TT_PRINT_PROC *print_proc, wchar_t *str)
{
	// 引数チェック
	if (print_proc == NULL || str == NULL)
	{
		return;
	}

	print_proc(param, str);
}

// 新しいランダムデータの生成
void TtGenerateRandomData(UCHAR **buf, UINT *size)
{
	UCHAR *tmp;
	UINT sz;
	UINT i;
	// 引数チェック
	if (buf == NULL || size == NULL)
	{
		return;
	}

	sz = TRAFFIC_BUF_SIZE;
	tmp = Malloc(sz);
	for (i = 0;i < sz;i++)
	{
		tmp[i] = rand() % 256;

		if (tmp[i] == '!')
		{
			tmp[i] = '_';
		}
	}

	*buf = tmp;
	*size = sz;
}

// 通信スループット測定サーバーワーカースレッド
void TtsWorkerThread(THREAD *thread, void *param)
{
	TTS *tts;
	UINT buf_size;
	UCHAR *send_buf_data, *recv_buf_data;
	bool all_sockets_blocked = false;
	UINT64 tmp64;
	LIST *o;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool dont_block_next_time = false;
	char *ver_str = TRAFFIC_VER_STR;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// データ領域の確保
	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	tts = (TTS *)param;

	// ソケットイベントの準備
	tts->SockEvent = NewSockEvent();
	AddRef(tts->SockEvent->ref);

	// サーバーソケットリストの準備
	tts->TtsSockList = NewList(NULL);

	// 親スレッドに準備完了を伝える
	NoticeThreadInit(thread);

	o = NewList(NULL);

	while (tts->Halt == false)
	{
		// すべてのソケットを待機する
		if (dont_block_next_time == false)
		{
			WaitSockEvent(tts->SockEvent, 50);
		}
		dont_block_next_time = false;

		// 現在登録されているソケットについて処理する
		LockList(tts->TtsSockList);
		{
			UINT i;

			all_sockets_blocked = false;

			// すべてのソケットがブロック状態にならない限り
			// データの送受信を続ける
			while (all_sockets_blocked == false)
			{
				all_sockets_blocked = true;

				for (i = 0;i < LIST_NUM(tts->TtsSockList);i++)
				{
					UINT ret = SOCK_LATER;
					UCHAR *send_data = NULL, *recv_data = NULL;
					UINT send_size = 0, recv_size = 0;
					TTS_SOCK *ts = LIST_DATA(tts->TtsSockList, i);
					bool blocked_for_this_socket = false;

					if (ts->SockJoined == false)
					{
						JoinSockToSockEvent(ts->Sock, tts->SockEvent);
						ts->SockJoined = true;
					}

					switch (ts->State)
					{
					case 0:
						// バージョン文字列を返す
						ret = Send(ts->Sock, ver_str, TRAFFIC_VER_STR_SIZE, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							ts->State = 5;
						}
						break;

					case 5:
						// クライアントから方向を受信する
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							UCHAR c;

							// 受信した 1 バイト目にデータの方向が入っている
							c = recv_buf_data[0];

							if (c == 0)
							{
								// 0 の場合はクライアント -> サーバー
								ts->State = 1;
							}
							else
							{
								// それ以外の場合はサーバー -> クライアント
								ts->State = 2;
							}
						}
						break;

					case 1:
						// クライアント -> サーバー
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ret != 0 && ret != SOCK_LATER)
						{
							// 受信した 1 バイト目を検査する
							UCHAR c = recv_buf_data[0];

							if (c == '!')
							{
								// サーバーからクライアントにサイズ情報を通知
								ts->State = 3;
								Debug("!");
							}
						}
						break;

					case 2:
						// サーバー -> クライアント
						ret = Send(ts->Sock, send_buf_data, buf_size, false);
						break;

					case 3:
						// サーバー -> クライアントにサイズ情報を通知する
						tmp64 = Endian64(ts->NumBytes);

						Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ts->LastWaitTick == 0 || ts->LastWaitTick <= Tick64())
						{
							ret = Send(ts->Sock, &tmp64, sizeof(tmp64), false);

							if (ret != SOCK_LATER)
							{
								ts->LastWaitTick = Tick64() + 100;
							}
						}
						break;
					}

					if (ret == 0)
					{
						// 切断されたのでこのソケットを削除としてマークする
						Insert(o, ts);
					}
					else if (ret == SOCK_LATER)
					{
						// 遅延が発生した
						blocked_for_this_socket = true;
						dont_block_next_time = false;
					}
					else
					{
						if (ts->State == 1)
						{
							ts->NumBytes += (UINT64)ret;
						}
					}

					if (blocked_for_this_socket == false)
					{
						all_sockets_blocked = false;
					}
				}

				if (LIST_NUM(o) != 0)
				{
					UINT i;
					// 1 つ以上のソケットが切断された
					for (i = 0;i < LIST_NUM(o);i++)
					{
						TTS_SOCK *ts = LIST_DATA(o, i);

						UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECTED"), ts->Id, ts->Sock->RemoteHostname);
						TtPrint(tts->Param, tts->Print, tmp);

						Disconnect(ts->Sock);
						ReleaseSock(ts->Sock);

						Delete(tts->TtsSockList, ts);

						Free(ts);
					}

					DeleteAll(o);
				}

				if (tts->NewSocketArrived || tts->Halt)
				{
					tts->NewSocketArrived = false;
					all_sockets_blocked = true;
					dont_block_next_time = true;
				}
			}
		}
		UnlockList(tts->TtsSockList);
	}

	LockList(tts->TtsSockList);
	{
		// 残留しているすべてのソケットを解放する
		for (i = 0;i < LIST_NUM(tts->TtsSockList);i++)
		{
			TTS_SOCK *ts = LIST_DATA(tts->TtsSockList, i);

			UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECT"), ts->Id, ts->Sock->RemoteHostname);
			TtPrint(tts->Param, tts->Print, tmp);

			Disconnect(ts->Sock);
			ReleaseSock(ts->Sock);

			Free(ts);
		}
	}
	UnlockList(tts->TtsSockList);

	// クリーンアップ
	ReleaseList(o);
	ReleaseList(tts->TtsSockList);
	ReleaseSockEvent(tts->SockEvent);
	Free(send_buf_data);
	Free(recv_buf_data);
}

// IPv6 用 Accept スレッド
void TtsIPv6AcceptThread(THREAD *thread, void *param)
{
	TTS *tts = (TTS *)param;
	// 引数チェック
	if (tts == NULL || param == NULL)
	{
		return;
	}

	TtsAcceptProc(tts, tts->ListenSocketV6);
}

// Accept プロシージャ
void TtsAcceptProc(TTS *tts, SOCK *listen_socket)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (tts == NULL || listen_socket == NULL)
	{
		return;
	}

	while (tts->Halt == false)
	{
		SOCK *s;
		// Accept する
		s = Accept(listen_socket);

		if (s == NULL)
		{
			if (tts->Halt == false)
			{
				SleepThread(10);
			}
			continue;
		}
		else
		{
			// クライアントから接続された
			AcceptInit(s);
			tts->NewSocketArrived = true;
			LockList(tts->TtsSockList);
			{
				TTS_SOCK *ts = ZeroMalloc(sizeof(TTS_SOCK));

				ts->Id = (++tts->IdSeed);
				ts->Sock = s;

				UniFormat(tmp, sizeof(tmp), _UU("TTS_ACCEPTED"), ts->Id,
					s->RemoteHostname, s->RemotePort);
				TtPrint(tts->Param, tts->Print, tmp);

				Insert(tts->TtsSockList, ts);
				tts->NewSocketArrived = true;
			}
			UnlockList(tts->TtsSockList);
		}
	}
}

// 通信スループット測定サーバー待機スレッド
void TtsListenThread(THREAD *thread, void *param)
{
	TTS *tts;
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	tts = (TTS *)param;

	tts->ListenSocket = NULL;
	tts->ListenSocket = Listen(tts->Port);
	tts->ListenSocketV6 = Listen6(tts->Port);

	if (tts->ListenSocket == NULL && tts->ListenSocketV6 == NULL)
	{
		// Listen に失敗した
		UniFormat(tmp, sizeof(tmp), _UU("TT_LISTEN_FAILED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		// 親スレッドに準備完了を伝える
		NoticeThreadInit(thread);

		tts->ErrorCode = ERR_INTERNAL_ERROR;
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_STARTED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		if (tts->ListenSocketV6 != NULL)
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_STARTED_V6"), tts->Port);
			TtPrint(tts->Param, tts->Print, tmp);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_FAILED_V6"), tts->Port);
			TtPrint(tts->Param, tts->Print, tmp);
		}

		if (tts->ListenSocket != NULL)
		{
			AddRef(tts->ListenSocket->ref);
		}
		if (tts->ListenSocketV6 != NULL)
		{
			AddRef(tts->ListenSocketV6->ref);
		}

		// ワーカースレッドを開始する
		tts->WorkThread = NewThread(TtsWorkerThread, tts);
		WaitThreadInit(tts->WorkThread);

		// 親スレッドに準備完了を伝える
		NoticeThreadInit(thread);

		// IPv6 用 Accept スレッドを準備
		tts->IPv6AcceptThread = NULL;
		if (tts->ListenSocketV6 != NULL)
		{
			tts->IPv6AcceptThread = NewThread(TtsIPv6AcceptThread, tts);
		}

		TtsAcceptProc(tts, tts->ListenSocket);

		if (tts->IPv6AcceptThread != NULL)
		{
			WaitThread(tts->IPv6AcceptThread, INFINITE);
			ReleaseThread(tts->IPv6AcceptThread);
		}

		TtPrint(tts->Param, tts->Print, _UU("TTS_LISTEN_STOP"));

		ReleaseSock(tts->ListenSocket);
		ReleaseSock(tts->ListenSocketV6);
		SetSockEvent(tts->SockEvent);

		// ワーカースレッドの停止を待機する
		WaitThread(tts->WorkThread, INFINITE);
		ReleaseThread(tts->WorkThread);
		ReleaseSockEvent(tts->SockEvent);
	}
}

// データが流れる方向の文字列
wchar_t *GetTtcTypeStr(UINT type)
{
	switch (type)
	{
	case TRAFFIC_TYPE_DOWNLOAD:
		return _UU("TTC_TYPE_DOWNLOAD");

	case TRAFFIC_TYPE_UPLOAD:
		return _UU("TTC_TYPE_UPLOAD");

	default:
		return _UU("TTC_TYPE_FULL");
	}
}

// サマリーの表示
void TtcPrintSummary(TTC *ttc)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t *tag = L"%-35s %s";
	// 引数チェック
	if (ttc == NULL)
	{
		return;
	}

	TtPrint(ttc->Param, ttc->Print, L"");
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_TITLE"));
	TtPrint(ttc->Param, ttc->Print, L"");

	// 接続先のホスト名
	StrToUni(tmp2, sizeof(tmp2), ttc->Host);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_HOST"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// 接続先の TCP ポート番号
	UniToStru(tmp2, ttc->Port);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_PORT"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// 確立する TCP コネクション数
	UniToStru(tmp2, ttc->NumTcp);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_NUMTCP"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// データ伝送方向
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_TYPE"), GetTtcTypeStr(ttc->Type));
	TtPrint(ttc->Param, ttc->Print, tmp);

	// データ伝送時間
	UniFormat(tmp2, sizeof(tmp2), _UU("TTC_SPAN_STR"), (double)(ttc->Span) / 1000.0);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_SPAN"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Ethernet フレーム用にデータ補正
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_ETHER"), ttc->Raw ? _UU("SEC_NO") : _UU("SEC_YES"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	// 中継機器の入出力合計スループット計測
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_DOUBLE"), ttc->Double ? _UU("SEC_YES") : _UU("SEC_NO"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, L"");
}

// 通信スループット測定クライアントの停止
void StopTtc(TTC *ttc)
{
	// 引数チェック
	if (ttc == NULL)
	{
		return;
	}

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_STOPPING"));

	ttc->Halt = true;
	SetSockEvent(ttc->SockEvent);
}

// 結果を生成
void TtcGenerateResult(TTC *ttc)
{
	TT_RESULT *res;
	UINT i;
	// 引数チェック
	if (ttc == NULL)
	{
		return;
	}

	res = &ttc->Result;

	Zero(res, sizeof(TT_RESULT));

	res->Raw = ttc->Raw;
	res->Double = ttc->Double;
	res->Span = ttc->RealSpan;

	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		if (ts->Download == false)
		{
			// アップロード
			res->NumBytesUpload += ts->NumBytes;
		}
		else
		{
			// ダウンロード
			res->NumBytesDownload += ts->NumBytes;
		}
	}

	if (res->Raw == false)
	{
		// Ethernet に合わせて補正する
		// (1 個の Ethernet フレーム中の最大の TCP ペイロードサイズは 1460 である。)
		res->NumBytesDownload = (UINT64)((double)res->NumBytesDownload * 1514.0 / 1460.0);
		res->NumBytesUpload = (UINT64)((double)res->NumBytesUpload * 1514.0 / 1460.0);
	}

	res->NumBytesTotal = res->NumBytesDownload + res->NumBytesUpload;

	// スループットを計測する
	if (res->Span != 0)
	{
		res->BpsUpload = (UINT64)((double)res->NumBytesUpload * 8.0 / ((double)res->Span / 1000.0));
		res->BpsDownload = (UINT64)((double)res->NumBytesDownload * 8.0 / ((double)res->Span / 1000.0));
	}

	if (res->Double)
	{
		res->BpsUpload *= 2ULL;
		res->BpsDownload *= 2ULL;
	}

	res->BpsTotal = res->BpsUpload + res->BpsDownload;
}

// クライアントスレッド
void TtcThread(THREAD *thread, void *param)
{
	TTC *ttc;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool ok = false;
	UINT buf_size;
	UCHAR *send_buf_data, *recv_buf_data;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// データ領域の確保
	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	ttc = (TTC *)param;

	ttc->SockEvent = NewSockEvent();
	AddRef(ttc->SockEvent->ref);

	// 準備完了
	NoticeThreadInit(thread);

	TtcPrintSummary(ttc);

	UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_START"),
		ttc->Host, ttc->Port, ttc->NumTcp);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// クライアントへのすべてのコネクションを確立する
	ttc->ItcSockList = NewList(NULL);

	ok = true;

	for (i = 0;i < ttc->NumTcp;i++)
	{
		SOCK *s;
		TTC_SOCK *ts = ZeroMalloc(sizeof(TTC_SOCK));

		ts->Id = i + 1;

		if (ttc->Type == TRAFFIC_TYPE_DOWNLOAD)
		{
			ts->Download = true;
		}
		else if (ttc->Type == TRAFFIC_TYPE_UPLOAD)
		{
			ts->Download = false;
		}
		else
		{
			ts->Download = ((i % 2) == 0) ? true : false;
		}

		s = Connect(ttc->Host, ttc->Port);

		if (s == NULL)
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_FAILED"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);
			ok = false;
			Free(ts);
			break;
		}
		else
		{
			char buffer[TRAFFIC_VER_STR_SIZE];

			SetTimeout(s, 5000);

			Zero(buffer, sizeof(buffer));
			if (Recv(s, buffer, sizeof(buffer), false) != sizeof(buffer) || Cmp(buffer, TRAFFIC_VER_STR, TRAFFIC_VER_STR_SIZE) != 0)
			{
				TtPrint(ttc->Param, ttc->Print, _UU("TTC_CONNECT_NOT_SERVER"));
				ok = false;
				ReleaseSock(s);
				Free(ts);
				break;
			}

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK_2"), GetTtcTypeStr(ts->Download ? TRAFFIC_TYPE_DOWNLOAD : TRAFFIC_TYPE_UPLOAD));
			TtPrint(ttc->Param, ttc->Print, tmp);

			ts->Sock = s;

			SetTimeout(s, TIMEOUT_INFINITE);

			JoinSockToSockEvent(s, ttc->SockEvent);
		}

		Insert(ttc->ItcSockList, ts);
	}

	Set(ttc->InitedEvent);

	if (ttc->StartEvent != NULL)
	{
		Wait(ttc->StartEvent, INFINITE);
		SleepThread(500);
	}

	if (ok)
	{
		bool all_sockets_blocked;
		bool dont_block_next_time = false;
		bool halt_flag = false;
		UINT64 start_tick, end_tick;
		UINT64 halt_timeout = 0;
		wchar_t tmp1[MAX_SIZE], tmp2[MAX_SIZE];
		UINT check_clock_seed = 0;
		bool halting = false;
		UINT64 tmp64;

		// 現在時刻を記録
		start_tick = Tick64();
		end_tick = start_tick + ttc->Span;

		// 開始メッセージを表示
		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(TickToTime(start_tick)), NULL);
		GetDateTimeStrEx64(tmp2, sizeof(tmp2), SystemToLocal64(TickToTime(end_tick)), NULL);
		UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_START"), tmp1, tmp2);
		TtPrint(ttc->Param, ttc->Print, tmp);

		// メインループ
		while (true)
		{
			UINT i;

			if (dont_block_next_time == false)
			{
				WaitSockEvent(ttc->SockEvent, 50);
			}

			dont_block_next_time = false;

			if (ttc->AbnormalTerminated)
			{
				// 異常終了が発生した
				break;
			}

			if (ttc->Halt || end_tick <= Tick64())
			{
				// 計測終了
				if (halting == false)
				{
					if (ttc->Halt)
					{
						// ユーザーキャンセル
						TtPrint(ttc->Param, ttc->Print, _UU("TTC_COMM_USER_CANCEL"));
					}
					else
					{
						// 時間経過
						UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_END"),
							(double)ttc->Span / 1000.0);
						TtPrint(ttc->Param, ttc->Print, tmp);
					}

					ttc->RealSpan = Tick64() - start_tick;

					halting = true;

					// サーバーからの報告データを待つ
					halt_timeout = Tick64() + 60000ULL;
				}
			}

			if (halt_timeout != 0)
			{
				bool ok = true;

				// すべての TCP コネクションが処理を完了するまで待機する
				for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
				{
					TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

					if (ts->Download == false)
					{
						if (ts->ServerUploadReportReceived == false)
						{
							ok = false;
						}
					}
				}

				if (ok)
				{
					// 測定完了
					// 結果を表示する
					TtcGenerateResult(ttc);
					break;
				}
				else
				{
					if (halt_timeout <= Tick64())
					{
						// 異常発生
						ttc->AbnormalTerminated = true;
						ttc->ErrorCode = ERR_PROTOCOL_ERROR;
						break;
					}
				}
			}

			all_sockets_blocked = false;

			// すべてのソケットがブロック状態にならない限り
			// データの送受信を続ける
			while (all_sockets_blocked == false)
			{
				all_sockets_blocked = true;

				for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
				{
					UINT ret = SOCK_LATER;
					TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);
					bool blocked_for_this_socket = false;
					UCHAR c = 0;

					if (halt_timeout != 0)
					{
						if (ts->State != 3 && ts->State != 4)
						{
							if (ts->Download == false)
							{
								if (ts->State != 0)
								{
									ts->State = 3;
								}
								else
								{
									ts->ServerUploadReportReceived = true;
									ts->State = 4;
								}
							}
							else
							{
								ts->State = 4;
							}
						}
					}

					switch (ts->State)
					{
					case 0:
						// 初期状態: クライアント／サーバー間のデータの流れの
						// 方向を指定する
						if (ts->Download)
						{
							c = 1;
						}
						else
						{
							c = 0;
						}

						ret = Send(ts->Sock, &c, 1, false);

						if (ret != 0 && ret != SOCK_LATER)
						{
							if (ts->Download)
							{
								ts->State = 1;
							}
							else
							{
								ts->State = 2;
							}
						}
						break;

					case 1:
						// サーバー -> クライアント (ダウンロード)
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
						break;

					case 2:
						// クライアント -> サーバー (アップロード)
						ret = Send(ts->Sock, send_buf_data, buf_size, false);
						break;

					case 3:
						// クライアント -> サーバー (アップロード) の送信完了
						// データサイズの要求処理
						if (ts->NextSendRequestReportTick == 0 ||
							(Tick64() >= ts->NextSendRequestReportTick))
						{
							UCHAR suprise[MAX_SIZE];
							UINT i;

							ts->NextSendRequestReportTick = Tick64() + 200ULL;

							for (i = 0;i < sizeof(suprise);i++)
							{
								suprise[i] = '!';
							}

							ret = Send(ts->Sock, suprise, sizeof(suprise), false);
						}

						ret = Recv(ts->Sock, &tmp64, sizeof(tmp64), false);
						if (ret != 0 && ret != SOCK_LATER && ret == sizeof(tmp64))
						{
							ts->NumBytes = Endian64(tmp64);

							ts->ServerUploadReportReceived = true;

							ts->State = 4;
						}
						break;

					case 4:
						// 何もしない
						if (Recv(ts->Sock, recv_buf_data, buf_size, false) == SOCK_LATER)
						{
							ret = SOCK_LATER;
						}
						break;
					}

					if (ret == 0)
					{
						// ソケットが切断された
						ttc->AbnormalTerminated = true;
						ttc->ErrorCode = ERR_PROTOCOL_ERROR;
						blocked_for_this_socket = true;
						dont_block_next_time = false;

						UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_DISCONNECTED"), ts->Id);
						TtPrint(ttc->Param, ttc->Print, tmp);
					}
					else if (ret == SOCK_LATER)
					{
						// 遅延が発生した
						blocked_for_this_socket = true;
						dont_block_next_time = false;
					}
					else
					{
						if (ts->Download)
						{
							ts->NumBytes += (UINT64)ret;
						}
					}

					if (blocked_for_this_socket == false)
					{
						all_sockets_blocked = false;
					}
				}

				if (ttc->Halt)
				{
					all_sockets_blocked = true;
					dont_block_next_time = true;
				}

				if (end_tick <= Tick64())
				{
					all_sockets_blocked = true;
					dont_block_next_time = true;
				}
			}
		}
	}
	else
	{
		// 中止
		TtPrint(ttc->Param, ttc->Print, _UU("TTC_ERROR_ABORTED"));
		ttc->ErrorCode = ERR_CONNECT_FAILED;
	}

	// クリーンアップ
	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		Disconnect(ts->Sock);
		ReleaseSock(ts->Sock);
		Free(ts);
	}

	ReleaseSockEvent(ttc->SockEvent);
	ReleaseList(ttc->ItcSockList);
	Free(send_buf_data);
	Free(recv_buf_data);
}

// 通信スループット測定クライアントの開始
TTC *NewTtc(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param)
{
	return NewTtcEx(host, port, numtcp, type, span, dbl, raw, print_proc, param, NULL);
}
TTC *NewTtcEx(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param, EVENT *start_event)
{
	TTC *ttc;

	ttc = ZeroMalloc(sizeof(TTC));
	ttc->InitedEvent = NewEvent();
	ttc->Port = port;
	StrCpy(ttc->Host, sizeof(ttc->Host), host);
	ttc->NumTcp = numtcp;
	ttc->Type = type;
	ttc->Span = span;
	ttc->Double = dbl;
	ttc->Raw = raw;
	ttc->StartEvent = start_event;

	if (ttc->Type == TRAFFIC_TYPE_FULL && ttc->NumTcp < 2)
	{
		ttc->NumTcp = 2;
	}

	ttc->Print = print_proc;
	ttc->Param = param;
	ttc->ErrorCode = ERR_NO_ERROR;

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_INIT"));

	ttc->Thread = NewThread(TtcThread, ttc);
	WaitThreadInit(ttc->Thread);

	return ttc;
}

// 通信スループット測定クライアントの終了を待機
UINT FreeTtc(TTC *ttc, TT_RESULT *result)
{
	UINT ret;
	// 引数チェック
	if (ttc == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	WaitThread(ttc->Thread, INFINITE);
	ReleaseThread(ttc->Thread);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_FREE"));

	ret = ttc->ErrorCode;

	if (ret == ERR_NO_ERROR)
	{
		if (result != NULL)
		{
			Copy(result, &ttc->Result, sizeof(TT_RESULT));
		}
	}

	ReleaseSockEvent(ttc->SockEvent);
	ReleaseEvent(ttc->InitedEvent);

	Free(ttc);

	return ret;
}

// 通信スループット測定サーバーの開始
TTS *NewTts(UINT port, void *param, TT_PRINT_PROC *print_proc)
{
	TTS *tts;
	THREAD *t;

	tts = ZeroMalloc(sizeof(TTS));
	tts->Port = port;
	tts->Param = param;
	tts->Print = print_proc;

	TtPrint(param, print_proc, _UU("TTS_INIT"));

	// スレッドの作成
	t = NewThread(TtsListenThread, tts);
	WaitThreadInit(t);

	tts->Thread = t;

	return tts;
}

// 通信スループット測定サーバーの終了を待機
UINT FreeTts(TTS *tts)
{
	UINT ret;
	// 引数チェック
	if (tts == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_INIT"));

	tts->Halt = true;
	Disconnect(tts->ListenSocket);
	ReleaseSock(tts->ListenSocket);
	Disconnect(tts->ListenSocketV6);
	ReleaseSock(tts->ListenSocketV6);

	// スレッドの終了を待機
	WaitThread(tts->Thread, INFINITE);

	ReleaseThread(tts->Thread);

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_FINISHED"));

	ret = tts->ErrorCode;

	Free(tts);

	return ret;
}

// 測定ツールプロンプトの表示
void PtTrafficPrintProc(void *param, wchar_t *str)
{
	CONSOLE *c;
	// 引数チェック
	if (param == NULL || str == NULL)
	{
		return;
	}

	c = (CONSOLE *)param;

	if (c->ConsoleType == CONSOLE_LOCAL)
	{
		wchar_t tmp[MAX_SIZE];

		// ローカルコンソールの場合のみ表示する (それ以外の場合はマルチスレッドの同期
		//  がとれないので表示できない？)
		UniStrCpy(tmp, sizeof(tmp), str);
		if (UniEndWith(str, L"\n") == false)
		{
			UniStrCat(tmp, sizeof(tmp), L"\n");
		}
		UniPrint(L"%s", tmp);
	}
}

// 通信スループット結果の表示
void TtcPrintResult(CONSOLE *c, TT_RESULT *res)
{
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char str[MAX_SIZE];
	// 引数チェック
	if (c == NULL || res == NULL)
	{
		return;
	}

	c->Write(c, _UU("TTC_RES_TITLE"));

	ct = CtNew();
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_2"), true);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_3"), true);

	// 測定に使用した時間
	GetSpanStrMilli(str, sizeof(str), res->Span);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("TTC_RES_SPAN"), tmp, L"");

	// Ethernet フレーム用にデータ補正
	CtInsert(ct, _UU("TTC_RES_ETHER"), res->Raw ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// ダウンロード方向の通信データ量
	ToStr3(str, sizeof(str), res->NumBytesDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesDownload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_DOWNLOAD"), tmp1, tmp2);

	// アップロード方向の通信データ量
	ToStr3(str, sizeof(str), res->NumBytesUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesUpload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_UPLOAD"), tmp1, tmp2);

	// 合計通信データ量
	ToStr3(str, sizeof(str), res->NumBytesTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesTotal);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_TOTAL"), tmp1, tmp2);

	// 中継機器入出力合計スループット算出
	CtInsert(ct, _UU("TTC_RES_DOUBLE"), (res->Double == false) ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// ダウンロード方向の平均スループット
	ToStr3(str, sizeof(str), res->BpsDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsDownload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_DOWNLOAD"), tmp1, tmp2);

	// アップロード方向の平均スループット
	ToStr3(str, sizeof(str), res->BpsUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsUpload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_UPLOAD"), tmp1, tmp2);

	// 合計平均スループット
	ToStr3(str, sizeof(str), res->BpsTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsTotal);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_TOTAL"), tmp1, tmp2);

	CtFree(ct, c);
}

// 通信スループット測定ツールサーバーの実行
UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	UINT port;
	TTS *tts;
	PARAM args[] =
	{
		{"[port]", NULL, NULL, NULL, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	port = GetParamInt(o, "[port]");
	if (port == 0)
	{
		port = TRAFFIC_DEFAULT_PORT;
	}

	tts = NewTts(port, c, PtTrafficPrintProc);

	c->Write(c, _UU("TTS_ENTER_TO_EXIT"));

	Free(c->ReadLine(c, L"", true));

	ret = tts->ErrorCode;

	FreeTts(tts);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 通信スループット測定ツールクライアントの実行
UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	TTC *ttc;
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	char *host = NULL;
	UINT port;
	UINT num, type;
	bool dbl = false, raw = false;
	UINT64 span;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_TrafficClient_EVAL_NUMTCP",
		0, TRAFFIC_NUMTCP_MAX,
	};
	PARAM args[] =
	{
		{"[host:port]", CmdPrompt, _UU("CMD_TrafficClient_PROMPT_HOST"), CmdEvalNotEmpty, NULL},
		{"NUMTCP", NULL, NULL, CmdEvalMinMax, &minmax},
		{"TYPE", NULL, NULL, NULL, NULL},
		{"SPAN", NULL, NULL, NULL, NULL},
		{"DOUBLE", NULL, NULL, NULL, NULL},
		{"RAW", NULL, NULL, NULL, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (ParseHostPort(GetParamStr(o, "[host:port]"), &host, &port, TRAFFIC_DEFAULT_PORT) == false)
	{
		c->Write(c, _UU("CMD_TrafficClient_ERROR_HOSTPORT"));
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		char *s;
		UINT i;

		Trim(host);

		num = GetParamInt(o, "NUMTCP");
		if (num == 0)
		{
			num = TRAFFIC_NUMTCP_DEFAULT;
		}
		s = GetParamStr(o, "TYPE");

		if (StartWith("download", s))
		{
			type = TRAFFIC_TYPE_DOWNLOAD;
		}
		else if (StartWith("upload", s))
		{
			type = TRAFFIC_TYPE_UPLOAD;
		}
		else
		{
			type = TRAFFIC_TYPE_FULL;
		}

		i = GetParamInt(o, "SPAN");

		if (i == 0)
		{
			i = TRAFFIC_SPAN_DEFAULT;
		}

		span = (UINT64)i * 1000ULL;

		dbl = GetParamYes(o, "DOUBLE");
		raw = GetParamYes(o, "RAW");

		if (type == TRAFFIC_TYPE_FULL)
		{
			if ((num % 2) != 0)
			{
				ret = ERR_INVALID_PARAMETER;
				c->Write(c, _UU("CMD_TrafficClient_ERROR_NUMTCP"));
			}
		}

		if (ret == ERR_NO_ERROR)
		{
			TT_RESULT result;
			ttc = NewTtc(host, port, num, type, span, dbl, raw, PtTrafficPrintProc, c);

			if (c->ConsoleType == CONSOLE_LOCAL)
			{
				if (c->Param != NULL && (((LOCAL_CONSOLE_PARAM *)c->Param)->InBuf == NULL))
				{
//					c->Write(c, _UU("TTC_ENTER_TO_EXIT"));
//					GetLine(NULL, 0);
//					StopTtc(ttc);
				}
			}


			Zero(&result, sizeof(result));
			ret = FreeTtc(ttc, &result);

			if (ret == ERR_NO_ERROR)
			{
				TtcPrintResult(c, &result);
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	Free(host);

	return ret;
}

// 証明書簡易作成ツール
UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	X *x = NULL;
	K *pub = NULL;
	K *pri = NULL;
	NAME *n;
	X_SERIAL *x_serial = NULL;
	BUF *buf;
	UINT days;
	X *root_x = NULL;
	K *root_k = NULL;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_MakeCert_EVAL_EXPIRES",
		0,
		10950,
	};
	PARAM args[] =
	{
		{"CN", CmdPrompt, _UU("CMD_MakeCert_PROMPT_CN"), NULL, NULL},
		{"O", CmdPrompt, _UU("CMD_MakeCert_PROMPT_O"), NULL, NULL},
		{"OU", CmdPrompt, _UU("CMD_MakeCert_PROMPT_OU"), NULL, NULL},
		{"C", CmdPrompt, _UU("CMD_MakeCert_PROMPT_C"), NULL, NULL},
		{"ST", CmdPrompt, _UU("CMD_MakeCert_PROMPT_ST"), NULL, NULL},
		{"L", CmdPrompt, _UU("CMD_MakeCert_PROMPT_L"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SERIAL"), NULL, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_MakeCert_PROMPT_EXPIRES"), CmdEvalMinMax, &minmax},
		{"SIGNCERT", NULL, NULL, CmdEvalIsFile, NULL},
		{"SIGNKEY", NULL, NULL, CmdEvalIsFile, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
		{"SAVEKEY", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVEKEY"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "SIGNCERT")) == false && IsEmptyStr(GetParamStr(o, "SIGNKEY")) == false)
	{
		root_x = FileToX(GetParamStr(o, "SIGNCERT"));
		root_k = FileToK(GetParamStr(o, "SIGNKEY"), true, NULL);

		if (root_x == NULL || root_k == NULL || CheckXandK(root_x, root_k) == false)
		{
			ret = ERR_INTERNAL_ERROR;

			c->Write(c, _UU("CMD_MakeCert_ERROR_SIGNKEY"));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		buf = StrToBin(GetParamStr(o, "SERIAL"));
		if (buf != NULL && buf->Size >= 1)
		{
			x_serial = NewXSerial(buf->Buf, buf->Size);
		}
		FreeBuf(buf);

		n = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"), 
			GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		days = GetParamInt(o, "EXPIRES");
		if (days == 0)
		{
			days = 3650;
		}

		RsaGen(&pri, &pub, 1024);

		if (root_x == NULL)
		{
			x = NewRootX(pub, pri, n, days, x_serial);
		}
		else
		{
			x = NewX(pub, root_k, root_x, n, days, x_serial);
		}

		FreeXSerial(x_serial);
		FreeName(n);

		if (x == NULL)
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MakeCert_ERROR_GEN_FAILED"));
		}
		else
		{
			if (XToFile(x, GetParamStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
			}
			else if (KToFile(pri, GetParamStr(o, "SAVEKEY"), true, NULL) == false)
			{
				c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	FreeX(root_x);
	FreeK(root_k);

	FreeX(x);
	FreeK(pri);
	FreeK(pub);

	return ret;
}


// クライアント管理ツールメイン
void PcMain(PC *pc)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (pc == NULL)
	{
		return;
	}

	// 接続が完了したメッセージを表示する
	UniFormat(tmp, sizeof(tmp), _UU("CMD_UTVPNCMD_CLIENT_CONNECTED"),
		pc->ServerName);
	pc->Console->Write(pc->Console, tmp);
	pc->Console->Write(pc->Console, L"");

	while (true)
	{
		// コマンドの定義
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"Check", PtCheck},
			{"VersionGet", PcVersionGet},
			{"PasswordSet", PcPasswordSet},
			{"PasswordGet", PcPasswordGet},
			{"CertList", PcCertList},
			{"CertAdd", PcCertAdd},
			{"CertDelete", PcCertDelete},
			{"CertGet", PcCertGet},
			{"SecureList", PcSecureList},
			{"SecureSelect", PcSecureSelect},
			{"SecureGet", PcSecureGet},
			{"NicCreate", PcNicCreate},
			{"NicDelete", PcNicDelete},
			{"NicUpgrade", PcNicUpgrade},
			{"NicGetSetting", PcNicGetSetting},
			{"NicSetSetting", PcNicSetSetting},
			{"NicEnable", PcNicEnable},
			{"NicDisable", PcNicDisable},
			{"NicList", PcNicList},
			{"AccountList", PcAccountList},
			{"AccountCreate", PcAccountCreate},
			{"AccountSet", PcAccountSet},
			{"AccountGet", PcAccountGet},
			{"AccountDelete", PcAccountDelete},
			{"AccountUsernameSet", PcAccountUsernameSet},
			{"AccountAnonymousSet", PcAccountAnonymousSet},
			{"AccountPasswordSet", PcAccountPasswordSet},
			{"AccountCertSet", PcAccountCertSet},
			{"AccountCertGet", PcAccountCertGet},
			{"AccountEncryptDisable", PcAccountEncryptDisable},
			{"AccountEncryptEnable", PcAccountEncryptEnable},
			{"AccountCompressEnable", PcAccountCompressEnable},
			{"AccountCompressDisable", PcAccountCompressDisable},
			{"AccountProxyNone", PcAccountProxyNone},
			{"AccountProxyHttp", PcAccountProxyHttp},
			{"AccountProxySocks", PcAccountProxySocks},
			{"AccountServerCertEnable", PcAccountServerCertEnable},
			{"AccountServerCertDisable", PcAccountServerCertDisable},
			{"AccountServerCertSet", PcAccountServerCertSet},
			{"AccountServerCertDelete", PcAccountServerCertDelete},
			{"AccountServerCertGet", PcAccountServerCertGet},
			{"AccountDetailSet", PcAccountDetailSet},
			{"AccountRename", PcAccountRename},
			{"AccountConnect", PcAccountConnect},
			{"AccountDisconnect", PcAccountDisconnect},
			{"AccountStatusGet", PcAccountStatusGet},
			{"AccountNicSet", PcAccountNicSet},
			{"AccountStatusShow", PcAccountStatusShow},
			{"AccountStatusHide", PcAccountStatusHide},
			{"AccountSecureCertSet", PcAccountSecureCertSet},
			{"AccountRetrySet", PcAccountRetrySet},
			{"AccountStartupSet", PcAccountStartupSet},
			{"AccountStartupRemove", PcAccountStartupRemove},
			{"AccountExport", PcAccountExport},
			{"AccountImport", PcAccountImport},
			{"RemoteEnable", PcRemoteEnable},
			{"RemoteDisable", PcRemoteDisable},
			{"KeepEnable", PcKeepEnable},
			{"KeepDisable", PcKeepDisable},
			{"KeepSet", PcKeepSet},
			{"KeepGet", PcKeepGet},
			{"MakeCert", PtMakeCert},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
		};

		// プロンプトの生成
		StrCpy(prompt, sizeof(prompt), "VPN Client>");

		if (DispatchNextCmdEx(pc->Console, pc->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), pc) == false)
		{
			break;
		}
		pc->LastError = pc->Console->RetCode;

		if (pc->LastError == ERR_NO_ERROR && pc->Console->ConsoleType != CONSOLE_CSV)
		{
			pc->Console->Write(pc->Console, _UU("CMD_MSG_OK"));
			pc->Console->Write(pc->Console, L"");
		}

		if (pc->CmdLine != NULL)
		{
			break;
		}
	}
}

// VPN Client サービスのバージョン情報の取得
UINT PcVersionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_VERSION t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetClientVersion(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		// 成功
		ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.ClientProductName);
		CtInsert(ct, _UU("CMD_VersionGet_1"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ClientVersionString);
		CtInsert(ct, _UU("CMD_VersionGet_2"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ClientBuildInfoString);
		CtInsert(ct, _UU("CMD_VersionGet_3"), tmp);

		UniToStru(tmp, t.ProcessId);
		CtInsert(ct, _UU("CMD_VersionGet_4"), tmp);

		StrToUni(tmp, sizeof(tmp), OsTypeToStr(t.OsType));
		CtInsert(ct, _UU("CMD_VersionGet_5"), tmp);

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// VPN Client サービスに接続するためのパスワードの設定
UINT PcPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_PASSWORD t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"REMOTEONLY", NULL, NULL, NULL, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.Password, sizeof(t.Password), GetParamStr(o, "[password]"));
	t.PasswordRemoteOnly = GetParamYes(o, "REMOTEONLY");

	ret = CcSetPassword(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// VPN Client サービスに接続するためのパスワードの設定の取得
UINT PcPasswordGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_PASSWORD_SETTING t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetPasswordSetting(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_PasswordGet_1"),
			t.IsPasswordPresented ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_PasswordGet_2"),
			t.PasswordRemoteOnly ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 信頼する証明機関の証明書一覧の取得
UINT PcCertList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_CA t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcEnumCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
		UINT i;
		CT *ct = CtNewStandard();

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[64];
			RPC_CLIENT_ENUM_CA_ITEM *e = t.Items[i];

			GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

			UniToStru(tmp2, e->Key);

			CtInsert(ct, _UU("CMD_CAList_COLUMN_ID"), tmp2);
			CtInsert(ct, _UU("CM_CERT_COLUMN_1"), e->SubjectName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_2"), e->IssuerName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_3"), tmp);

			if (i != (t.NumItem - 1))
			{
				CtInsert(ct, L"---", L"---");
			}
		}

		CtFree(ct, c);

		CiFreeClientEnumCa(&t);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}


	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 信頼する証明機関の証明書の追加
UINT PcCertAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CERT t;
	X *x;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[path]", CmdPrompt, _UU("CMD_CAAdd_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}


	x = FileToX(GetParamStr(o, "[path]"));

	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_MSG_LOAD_CERT_FAILED"));
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	t.x = x;

	ret = CcAddCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	FreeX(x);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 信頼する証明機関の証明書の削除
UINT PcCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_DELETE_CA t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CADelete_PROMPT_ID"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	t.Key = GetParamInt(o, "[id]");

	ret = CcDeleteCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 信頼する証明機関の証明書の取得
UINT PcCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_GET_CA t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CAGet_PROMPT_ID"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_CAGet_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	t.Key = GetParamInt(o, "[id]");

	ret = CcGetCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
		if (XToFile(t.x, GetParamStr(o, "SAVECERT"), true))
		{
			// 成功
		}
		else
		{
			// 失敗
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MSG_SAVE_CERT_FAILED"));
		}

		CiFreeGetCa(&t);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 使用できるスマートカードの種類の一覧の取得
UINT PcSecureList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_SECURE t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcEnumSecure(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		CT *ct;
		UINT i;
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t *tmp3;

		// 成功
		ct = CtNew();
		CtInsertColumn(ct, _UU("SEC_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SEC_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SEC_COLUMN3"), false);
		CtInsertColumn(ct, _UU("SEC_COLUMN4"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_CLIENT_ENUM_SECURE_ITEM *e = t.Items[i];

			// ID
			UniToStru(tmp1, e->DeviceId);

			// デバイス名
			StrToUni(tmp2, sizeof(tmp2), e->DeviceName);

			// 種類
			tmp3 = (e->Type == SECURE_IC_CARD) ? _UU("SEC_SMART_CARD") : _UU("SEC_USB_TOKEN");

			// 製造元
			StrToUni(tmp4, sizeof(tmp4), e->Manufacturer);

			CtInsert(ct, tmp1, tmp2, tmp3, tmp4);
		}

		CtFreeEx(ct, c, true);

		CiFreeClientEnumSecure(&t);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 使用するスマートカードの種類の選択
UINT PcSecureSelect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_USE_SECURE t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_SecureSelect_PROMPT_ID"), NULL, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	t.DeviceId = GetParamInt(o, "[id]");

	ret = CcUseSecure(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 使用するスマートカードの種類の ID の取得
UINT PcSecureGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_USE_SECURE t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetUseSecure(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
		wchar_t tmp[MAX_SIZE];

		if (t.DeviceId != 0)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CMD_SecureGet_Print"), t.DeviceId);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_SecureGet_NoPrint"));
		}
		c->Write(c, tmp);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 新規仮想 LAN カードの作成
UINT PcNicCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcCreateVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 仮想 LAN カードの削除
UINT PcNicDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcDeleteVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 仮想 LAN カードのデバイスドライバのアップグレード
UINT PcNicUpgrade(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcUpgradeVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 仮想 LAN カードの設定の取得
UINT PcNicGetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_VLAN t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcGetVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
		CT *ct = CtNewStandard();
		wchar_t tmp[MAX_SIZE];

		StrToUni(tmp, sizeof(tmp), t.DeviceName);
		CtInsert(ct, _UU("CMD_NicGetSetting_1"), tmp);

		CtInsert(ct, _UU("CMD_NicGetSetting_2"), t.Enabled ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		StrToUni(tmp, sizeof(tmp), t.MacAddress);
		CtInsert(ct, _UU("CMD_NicGetSetting_3"), tmp);

		StrToUni(tmp, sizeof(tmp), t.Version);
		CtInsert(ct, _UU("CMD_NicGetSetting_4"), tmp);

		StrToUni(tmp, sizeof(tmp), t.FileName);
		CtInsert(ct, _UU("CMD_NicGetSetting_5"), tmp);

		StrToUni(tmp, sizeof(tmp), t.Guid);
		CtInsert(ct, _UU("CMD_NicGetSetting_6"), tmp);

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 仮想 LAN カードの設定の変更
UINT PcNicSetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_SET_VLAN t;
	UCHAR mac_address[6];
	BUF *b;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"MAC", CmdPrompt, _UU("CMD_NicSetSetting_PROMPT_MAC"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// MAC アドレスの検査
	Zero(mac_address, sizeof(mac_address));
	b = StrToBin(GetParamStr(o, "MAC"));
	if (b != NULL && b->Size == 6)
	{
		Copy(mac_address, b->Buf, 6);
	}
	FreeBuf(b);

	if (IsZero(mac_address, 6))
	{
		// MAC アドレスが不正
		FreeParamValueList(o);

		CmdPrintError(c, ERR_INVALID_PARAMETER);
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));
	NormalizeMacAddress(t.MacAddress, sizeof(t.MacAddress), GetParamStr(o, "MAC"));

	ret = CcSetVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 仮想 LAN カードの有効化
UINT PcNicEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcEnableVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 仮想 LAN カードの無効化
UINT PcNicDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcDisableVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 仮想 LAN カード一覧の取得
UINT PcNicList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_VLAN t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcEnumVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		CT *ct;
		UINT i;

		// 成功
		ct = CtNew();
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_4"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t name[MAX_SIZE];
			wchar_t mac[MAX_SIZE];
			wchar_t ver[MAX_SIZE];
			wchar_t *status;
			RPC_CLIENT_ENUM_VLAN_ITEM *v = t.Items[i];

			// デバイス名
			StrToUni(name, sizeof(name), v->DeviceName);

			// 状態
			status = v->Enabled ? _UU("CM_VLAN_ENABLED") : _UU("CM_VLAN_DISABLED");

			// MAC アドレス
			StrToUni(mac, sizeof(mac), v->MacAddress);

			// バージョン
			StrToUni(ver, sizeof(ver), v->Version);

			CtInsert(ct,
				name, status, mac, ver);
		}

		CtFreeEx(ct, c, true);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientEnumVLan(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// プロトコル名文字列を取得
wchar_t *GetProtocolName(UINT n)
{
	switch (n)
	{
	case PROXY_DIRECT:
		return _UU("PROTO_DIRECT_TCP");
	case PROXY_HTTP:
		return _UU("PROTO_HTTP_PROXY");
	case PROXY_SOCKS:
		return _UU("PROTO_SOCKS_PROXY");
	}

	return _UU("PROTO_UNKNOWN");
}

// 接続設定一覧の取得
UINT PcAccountList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_ACCOUNT t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcEnumAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i;
		CT *ct;

		// 成功
		ct = CtNew();
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_3_2"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_4"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *e = t.Items[i];
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			IP ip;
			char ip_str[MAX_SIZE];

			// IPv6 アドレスの場合の特別処理
			if (StrToIP6(&ip, e->ServerName) && StartWith(e->ServerName, "[") == false)
			{
				Format(ip_str, sizeof(ip_str),
					"[%s]", e->ServerName);
			}
			else
			{
				StrCpy(ip_str, sizeof(ip_str), e->ServerName);
			}

			if (e->Port == 0)
			{
				// ポート番号不明
				UniFormat(tmp2, sizeof(tmp2), L"%S (%s)", ip_str, GetProtocolName(e->ProxyType));
			}
			else
			{
				// ポート番号併記
				UniFormat(tmp2, sizeof(tmp2), L"%S:%u (%s)", ip_str, e->Port, GetProtocolName(e->ProxyType));
			}

			// 仮想 HUB 名
			StrToUni(tmp4, sizeof(tmp4), e->HubName);

			// 追加
			StrToUni(tmp, sizeof(tmp), e->DeviceName);

			CtInsert(ct,
				e->AccountName,
				e->Active == false ? _UU("CM_ACCOUNT_OFFLINE") :
				(e->Connected ? _UU("CM_ACCOUNT_ONLINE") : _UU("CM_ACCOUNT_CONNECTING")),
				tmp2, tmp4,
				tmp);
		}

		CtFreeEx(ct, c, true);
	}

	CiFreeClientEnumAccount(&t);

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 新しい接続設定の作成
UINT PcAccountCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_ACCOUNT t;
	UINT port = 443;
	char *host = NULL;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Hub"), CmdEvalSafe, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
		{"NICNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Nicname"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));
	t.ClientOption->NumRetry = INFINITE;
	t.ClientOption->RetryInterval = 15;
	t.ClientOption->MaxConnection = 1;
	t.ClientOption->UseEncrypt = true;
	t.ClientOption->AdditionalConnectionInterval = 1;
	StrCpy(t.ClientOption->DeviceName, sizeof(t.ClientOption->DeviceName), GetParamStr(o, "NICNAME"));

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

	Free(host);

	ret = CcCreateAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	CiFreeClientCreateAccount(&t);

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の接続先の設定
UINT PcAccountSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	char *host = NULL;
	UINT port = 443;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Hub"), CmdEvalSafe, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT c;
		// 成功
		t.ClientOption->Port = port;
		StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
		StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));

		Zero(&c, sizeof(c));

		c.ClientAuth = t.ClientAuth;
		c.ClientOption = t.ClientOption;
		c.CheckServerCert = t.CheckServerCert;
		c.ServerCert = t.ServerCert;
		c.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	Free(host);

	return ret;
}

// 接続設定の設定の取得
UINT PcAccountGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 接続設定の内容を表示
		wchar_t tmp[MAX_SIZE];

		CT *ct = CtNewStandard();

		// 接続設定名
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NAME"), t.ClientOption->AccountName);

		// 接続先 VPN Server のホスト名
		StrToUni(tmp, sizeof(tmp), t.ClientOption->Hostname);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HOSTNAME"), tmp);

		// 接続先 VPN Server のポート番号
		UniToStru(tmp, t.ClientOption->Port);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PORT"), tmp);

		// 接続先 VPN Server の仮想 HUB 名
		StrToUni(tmp, sizeof(tmp), t.ClientOption->HubName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HUBNAME"), tmp);

		// 経由するプロキシ サーバーの種類
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_TYPE"), GetProxyTypeStr(t.ClientOption->ProxyType));

		if (t.ClientOption->ProxyType != PROXY_DIRECT)
		{
			// プロキシ サーバーのホスト名
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyName);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_HOSTNAME"), tmp);

			// プロキシ サーバーのポート番号
			UniToStru(tmp, t.ClientOption->ProxyPort);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_PORT"), tmp);

			// プロキシ サーバーのユーザー名
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyUsername);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_USERNAME"), tmp);
		}

		// サーバー証明書の検証
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_USE"),
			t.CheckServerCert ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// 登録されている固有証明書
		if (t.ServerCert != NULL)
		{
			GetAllNameFromX(tmp, sizeof(tmp), t.ServerCert);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_NAME"), tmp);
		}

		// 接続に使用するデバイス名
		StrToUni(tmp, sizeof(tmp), t.ClientOption->DeviceName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_DEVICE_NAME"), tmp);

		// 認証の種類
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_TYPE"), GetClientAuthTypeStr(t.ClientAuth->AuthType));

		// ユーザー名
		StrToUni(tmp, sizeof(tmp), t.ClientAuth->Username);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_USERNAME"), tmp);

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (t.ClientAuth->ClientX != NULL)
			{
				// クライアント証明書名
				GetAllNameFromX(tmp, sizeof(tmp), t.ClientAuth->ClientX);
				CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_CERT_NAME"), tmp);
			}
		}

		// VPN 通信に使用する TCP コネクション数
		UniToStru(tmp, t.ClientOption->MaxConnection);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NUMTCP"), tmp);

		// 各 TCP コネクションの確立間隔
		UniToStru(tmp, t.ClientOption->AdditionalConnectionInterval);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_INTERVAL"), tmp);

		// 各 TCP コネクションの寿命
		if (t.ClientOption->ConnectionDisconnectSpan != 0)
		{
			UniToStru(tmp, t.ClientOption->ConnectionDisconnectSpan);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_TTL"), tmp);

		// 半二重モードの使用
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_HALF"),
			t.ClientOption->HalfConnection ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// SSL による暗号化
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ENCRYPT"),
			t.ClientOption->UseEncrypt ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// データ圧縮
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_COMPRESS"),
			t.ClientOption->UseCompress ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// ブリッジ / ルータモードで接続
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_BRIDGE_ROUTER"),
			t.ClientOption->RequireBridgeRoutingMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// モニタリングモードで接続
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_MONITOR"),
			t.ClientOption->RequireMonitorMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// ルーティング テーブルを書き換えない
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NO_TRACKING"),
			t.ClientOption->NoRoutingTracking ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// QoS制御を無効化する
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_QOS_DISABLE"),
			t.ClientOption->DisableQoS ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の削除
UINT PcAccountDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_DELETE_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcDeleteAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の接続に使用するユーザー名の設定
UINT PcAccountUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
		{
			c->Write(c, _UU("CMD_AccountUsername_Notice"));
		}

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のユーザー認証の種類を匿名認証に設定
UINT PcAccountAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のユーザー認証の種類をパスワード認証に設定
UINT PcAccountPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"TYPE", CmdPrompt, _UU("CMD_CascadePasswordSet_Prompt_Type"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		char *typestr = GetParamStr(o, "TYPE");
		RPC_CLIENT_CREATE_ACCOUNT z;

		// 設定変更
		if (StartWith("standard", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
			HashPassword(t.ClientAuth->HashedPassword, t.ClientAuth->Username,
				GetParamStr(o, "PASSWORD"));
		}
		else if (StartWith("radius", typestr) || StartWith("ntdomain", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;

			StrCpy(t.ClientAuth->PlainPassword, sizeof(t.ClientAuth->PlainPassword),
				GetParamStr(o, "PASSWORD"));
		}
		else
		{
			// エラー発生
			c->Write(c, _UU("CMD_CascadePasswordSet_Type_Invalid"));
			ret = ERR_INVALID_PARAMETER;
		}

		if (ret == ERR_NO_ERROR)
		{
			Zero(&z, sizeof(z));
			z.CheckServerCert = t.CheckServerCert;
			z.ClientAuth = t.ClientAuth;
			z.ClientOption = t.ClientOption;
			z.ServerCert = t.ServerCert;
			z.StartupAccount = t.StartupAccount;

			ret = CcSetAccount(pc->RemoteClient, &z);
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のユーザー認証の種類をクライアント証明書認証に設定
UINT PcAccountCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	X *x;
	K *k;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (CmdLoadCertAndKey(c, &x, &k, GetParamStr(o, "LOADCERT"), GetParamStr(o, "LOADKEY")) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;

		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_CERT;
		if (t.ClientAuth->ClientX != NULL)
		{
			FreeX(t.ClientAuth->ClientX);
		}
		if (t.ClientAuth->ClientK != NULL)
		{
			FreeK(t.ClientAuth->ClientK);
		}

		t.ClientAuth->ClientX = CloneX(x);
		t.ClientAuth->ClientK = CloneK(k);

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	FreeX(x);
	FreeK(k);

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定に用いるクライアント証明書の取得
UINT PcAccountCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		if (t.ClientAuth->AuthType != CLIENT_AUTHTYPE_CERT)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Not_Auth_Cert"));
			ret = ERR_INTERNAL_ERROR;
		}
		else if (t.ClientAuth->ClientX == NULL)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Cert_Not_Exists"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			XToFile(t.ClientAuth->ClientX, GetParamStr(o, "SAVECERT"), true);
		}
	}

	CiFreeClientGetAccount(&t);

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の通信時の暗号化の無効化
UINT PcAccountEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientOption->UseEncrypt = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の通信時の暗号化の有効化
UINT PcAccountEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientOption->UseEncrypt = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の通信時のデータ圧縮の有効化
UINT PcAccountCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientOption->UseCompress = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の通信時のデータ圧縮の無効化
UINT PcAccountCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientOption->UseCompress = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の接続方法を直接 TCP/IP 接続に設定
UINT PcAccountProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientOption->ProxyType = PROXY_DIRECT;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の接続方法を HTTP プロキシサーバー経由接続に設定
UINT PcAccountProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		char *host;
		UINT port;

		// データ変更
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 8080))
		{
			t.ClientOption->ProxyType = PROXY_HTTP;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の接続方法を SOCKS プロキシサーバー経由接続に設定
UINT PcAccountProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		char *host;
		UINT port;

		// データ変更
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 8080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のサーバー証明書の検証オプションの有効化
UINT PcAccountServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.CheckServerCert = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のサーバー証明書の検証オプションの無効化
UINT PcAccountServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.CheckServerCert = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のサーバー固有証明書の設定
UINT PcAccountServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	X *x;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToX(GetParamStr(o, "LOADCERT"));
	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return ERR_INTERNAL_ERROR;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = CloneX(x);

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	FreeX(x);

	return ret;
}

// 接続設定のサーバー固有証明書の削除
UINT PcAccountServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のサーバー固有証明書の取得
UINT PcAccountServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の高度な通信設定の設定
UINT PcAccountDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	CMD_EVAL_MIN_MAX mm_maxtcp =
	{
		"CMD_CascadeDetailSet_Eval_MaxTcp", 1, 32
	};
	CMD_EVAL_MIN_MAX mm_interval =
	{
		"CMD_CascadeDetailSet_Eval_Interval", 1, 4294967295UL
	};
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"MAXTCP", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_MaxTcp"), CmdEvalMinMax, &mm_maxtcp},
		{"INTERVAL", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_Interval"), CmdEvalMinMax, &mm_interval},
		{"TTL", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_TTL"), NULL, NULL},
		{"HALF", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_HALF"), NULL, NULL},
		{"BRIDGE", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_BRIDGE"), NULL, NULL},
		{"MONITOR", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_MONITOR"), NULL, NULL},
		{"NOTRACK", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOTRACK"), NULL, NULL},
		{"NOQOS", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOQOS"), NULL, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// データ変更
		t.ClientOption->MaxConnection = GetParamInt(o, "MAXTCP");
		t.ClientOption->AdditionalConnectionInterval = GetParamInt(o, "INTERVAL");
		t.ClientOption->ConnectionDisconnectSpan = GetParamInt(o, "TTL");
		t.ClientOption->HalfConnection = GetParamYes(o, "HALF");
		t.ClientOption->RequireBridgeRoutingMode = GetParamYes(o, "BRIDGE");
		t.ClientOption->RequireMonitorMode = GetParamYes(o, "MONITOR");
		t.ClientOption->NoRoutingTracking = GetParamYes(o, "NOTRACK");
		t.ClientOption->DisableQoS = GetParamYes(o, "NOQOS");

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の名前の変更
UINT PcAccountRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_RENAME_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountRename_PROMPT_OLD"), CmdEvalNotEmpty, NULL},
		{"NEW", CmdPrompt, _UU("CMD_AccountRename_PROMPT_NEW"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	UniStrCpy(t.NewName, sizeof(t.NewName), GetParamUniStr(o, "NEW"));
	UniStrCpy(t.OldName, sizeof(t.OldName), GetParamUniStr(o, "[name]"));

	ret = CcRenameAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定を使用して VPN Server へ接続を開始
UINT PcAccountConnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CONNECT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcConnect(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続中の接続設定の切断
UINT PcAccountDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CONNECT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcDisconnect(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の現在の状態の取得
UINT PcAccountStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_CONNECTION_STATUS t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccountStatus(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		if (t.Active == false)
		{
			// 切断されている
			ret = ERR_ACCOUNT_INACTIVE;
		}
		else
		{
			CT *ct = CtNewStandard();

			CmdPrintStatusToListView(ct, &t);

			CtFree(ct, c);
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetConnectionStatus(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定で使用する仮想 LAN カードの設定
UINT PcAccountNicSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NICNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Nicname"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT c;
		// 成功
		StrCpy(t.ClientOption->DeviceName, sizeof(t.ClientOption->DeviceName),
			GetParamStr(o, "NICNAME"));

		Zero(&c, sizeof(c));

		c.ClientAuth = t.ClientAuth;
		c.ClientOption = t.ClientOption;
		c.CheckServerCert = t.CheckServerCert;
		c.ServerCert = t.ServerCert;
		c.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// VPN Server への接続中に接続状況やエラー画面を表示するように設定
UINT PcAccountStatusShow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientOption->HideStatusWindow = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// VPN Server への接続中に接続状況やエラー画面を表示しないように設定
UINT PcAccountStatusHide(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientOption->HideStatusWindow = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のユーザー認証の種類をスマートカード認証に設定
UINT PcAccountSecureCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"CERTNAME", CmdPrompt, _UU("CMD_AccountSecureCertSet_PROMPT_CERTNAME"), CmdEvalNotEmpty, NULL},
		{"KEYNAME", CmdPrompt, _UU("CMD_AccountSecureCertSet_PROMPT_KEYNAME"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_SECURE;
		StrCpy(t.ClientAuth->SecurePublicCertName, sizeof(t.ClientAuth->SecurePublicCertName),
			GetParamStr(o, "CERTNAME"));
		StrCpy(t.ClientAuth->SecurePrivateKeyName, sizeof(t.ClientAuth->SecurePrivateKeyName),
			GetParamStr(o, "KEYNAME"));

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定の接続失敗または切断時の再試行回数と間隔の設定
UINT PcAccountRetrySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccountRetrySet_EVAL_INTERVAL",
		5,
		4294967295UL,
	};
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NUM", CmdPrompt, _UU("CMD_AccountRetrySet_PROMPT_NUM"), CmdEvalNotEmpty, NULL},
		{"INTERVAL", CmdPrompt, _UU("CMD_AccountRetrySet_PROMPY_INTERVAL"), CmdEvalMinMax, &minmax},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		UINT num = GetParamInt(o, "NUM");
		UINT interval = GetParamInt(o, "INTERVAL");

		t.ClientOption->NumRetry = (num == 999) ? INFINITE : num;
		t.ClientOption->RetryInterval = interval;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}


// 接続設定をスタートアップ接続に設定
UINT PcAccountStartupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.StartupAccount = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のスタートアップ接続を解除
UINT PcAccountStartupRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// 設定変更
		t.StartupAccount = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 接続設定のエクスポート
UINT PcAccountExport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVEPATH", CmdPrompt, _UU("CMD_AccountExport_PROMPT_SAVEPATH"), CmdEvalNotEmpty, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		BUF *b;
		BUF *b2;
		char tmp[MAX_SIZE];
		UCHAR *buf;
		UINT buf_size;
		UCHAR bom[] = {0xef, 0xbb, 0xbf, };

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		b = CiAccountToCfg(&z);

		StrCpy(tmp, sizeof(tmp), GetParamStr(o, "SAVEPATH"));
		b2 = NewBuf();

		WriteBuf(b2, bom, sizeof(bom));

		// ヘッダ部分を付加する
		buf_size = CalcUniToUtf8(_UU("CM_ACCOUNT_FILE_BANNER"));
		buf = ZeroMalloc(buf_size + 32);
		UniToUtf8(buf, buf_size, _UU("CM_ACCOUNT_FILE_BANNER"));

		WriteBuf(b2, buf, StrLen((char *)buf));
		WriteBuf(b2, b->Buf, b->Size);
		SeekBuf(b2, 0, 0);

		FreeBuf(b);

		if (DumpBuf(b2, tmp) == false)
		{
			c->Write(c, _UU("CMD_SAVEFILE_FAILED"));
			ret = ERR_INTERNAL_ERROR;
		}

		FreeBuf(b2);
		Free(buf);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// 指定されたアカウント名が存在するかチェックする
bool CmdIsAccountName(REMOTE_CLIENT *r, wchar_t *name)
{
	UINT i;
	RPC_CLIENT_ENUM_ACCOUNT t;
	wchar_t tmp[MAX_SIZE];
	bool b = false;
	// 引数チェック
	if (r == NULL || name == NULL)
	{
		return false;
	}

	if (CcEnumAccount(r, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	UniStrCpy(tmp, sizeof(tmp), name);
	UniTrim(tmp);

	for (i = 0;i < t.NumItem;i++)
	{
		if (UniStrCmpi(t.Items[i]->AccountName, tmp) == 0)
		{
			b = true;
			break;
		}
	}

	CiFreeClientEnumAccount(&t);

	return b;
}

// インポート名の生成
void CmdGenerateImportName(REMOTE_CLIENT *r, wchar_t *name, UINT size, wchar_t *old_name)
{
	UINT i;
	// 引数チェック
	if (r == NULL || name == NULL || old_name == NULL)
	{
		return;
	}

	for (i = 1;;i++)
	{
		wchar_t tmp[MAX_SIZE];
		if (i == 1)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_IMPORT_NAME_1"), old_name);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_IMPORT_NAME_2"), old_name, i);
		}

		if (CmdIsAccountName(r, tmp) == false)
		{
			UniStrCpy(name, size, tmp);
			return;
		}
	}
}

// 接続設定のインポート
UINT PcAccountImport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	BUF *b;
	wchar_t name[MAX_SIZE];
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[path]", CmdPrompt, _UU("CMD_AccountImport_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// ファイルを読み込む
	b = ReadDump(GetParamStr(o, "[path]"));

	if (b == NULL)
	{
		// 読み込み失敗
		c->Write(c, _UU("CMD_LOADFILE_FAILED"));
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		RPC_CLIENT_CREATE_ACCOUNT *t;

		t = CiCfgToAccount(b);

		if (t == NULL)
		{
			// パースに失敗
			c->Write(c, _UU("CMD_AccountImport_FAILED_PARSE"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			CmdGenerateImportName(pc->RemoteClient, name, sizeof(name), t->ClientOption->AccountName);
			UniStrCpy(t->ClientOption->AccountName, sizeof(t->ClientOption->AccountName), name);

			ret = CcCreateAccount(pc->RemoteClient, t);

			if (ret == ERR_NO_ERROR)
			{
				wchar_t tmp[MAX_SIZE];

				UniFormat(tmp, sizeof(tmp), _UU("CMD_AccountImport_OK"), name);
				c->Write(c, tmp);
			}

			CiFreeClientCreateAccount(t);
			Free(t);
		}

		FreeBuf(b);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// VPN Client サービスのリモート管理の許可
UINT PcRemoteEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		t.AllowRemoteConfig = true;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// VPN Client サービスのリモート管理の禁止
UINT PcRemoteDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		t.AllowRemoteConfig = false;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// インターネット接続の維持機能の有効化
UINT PcKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 設定変更
		t.UseKeepConnect = true;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// インターネット接続の維持機能の無効化
UINT PcKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// パラメータリストの取得
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// 設定変更
		t.UseKeepConnect = false;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// 成功
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// インターネット接続の維持機能の設定
UINT PcKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;
	char *host;
	UINT port;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"HOST", CmdPrompt, _UU("CMD_KeepSet_PROMPT_HOST"), CmdEvalHostAndPort, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_PROTOCOL"), CmdEvalTcpOrUdp, NULL},
		{"INTERVAL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_INTERVAL"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, 0))
		{
			StrCpy(t.KeepConnectHost, sizeof(t.KeepConnectHost), host);
			t.KeepConnectPort = port;
			t.KeepConnectInterval = GetParamInt(o, "INTERVAL");
			t.KeepConnectProtocol = (StrCmpi(GetParamStr(o, "PROTOCOL"), "tcp") == 0) ? 0 : 1;
			Free(host);

			ret = CcSetClientConfig(pc->RemoteClient, &t);
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}

// インターネット接続の維持機能の取得
UINT PcKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.KeepConnectHost);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_1"), tmp);

		UniToStru(tmp, t.KeepConnectPort);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_2"), tmp);

		UniToStru(tmp, t.KeepConnectInterval);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_3"), tmp);

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_4"),
			t.KeepConnectProtocol == 0 ? L"TCP/IP" : L"UDP/IP");

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_5"),
			t.UseKeepConnect ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"));

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// エラーが発生した
		CmdPrintError(c, ret);
	}

	// パラメータリストの解放
	FreeParamValueList(o);

	return ret;
}


// 新しいクライアント管理ツールコンテキストの作成
PC *NewPc(CONSOLE *c, REMOTE_CLIENT *remote_client, char *servername, wchar_t *cmdline)
{
	PC *pc;
	// 引数チェック
	if (c == NULL || remote_client == NULL || servername == NULL)
	{
		return NULL;
	}
	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	pc = ZeroMalloc(sizeof(PC));
	pc->ConsoleForServer = false;
	pc->ServerName = CopyStr(servername);
	pc->Console = c;
	pc->LastError = 0;
	pc->RemoteClient = remote_client;
	pc->CmdLine = CopyUniStr(cmdline);

	return pc;
}

// クライアント管理ツールコンテキストの解放
void FreePc(PC *pc)
{
	// 引数チェック
	if (pc == NULL)
	{
		return;
	}

	Free(pc->ServerName);
	Free(pc->CmdLine);
	Free(pc);
}

// クライアント管理ツール
UINT PcConnect(CONSOLE *c, char *target, wchar_t *cmdline, char *password)
{
	CEDAR *cedar;
	REMOTE_CLIENT *client;
	bool bad_pass;
	bool no_remote;
	char pass[MAX_SIZE];
	UINT ret = 0;
	// 引数チェック
	if (c == NULL || target == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	StrCpy(pass, sizeof(pass), password);

	cedar = NewCedar(NULL, NULL);

RETRY:
	client = CcConnectRpc(target, pass, &bad_pass, &no_remote, 0);

	if (client == NULL)
	{
		if (no_remote)
		{
			// リモート接続拒否
			c->Write(c, _UU("CMD_UTVPNCMD_CLIENT_NO_REMODE"));
			ReleaseCedar(cedar);
			return ERR_INTERNAL_ERROR;
		}
		else if (bad_pass)
		{
			char *tmp;
			// パスワード違い
			c->Write(c, _UU("CMD_UTVPNCMD_PASSWORD_1"));
			tmp = c->ReadPassword(c, _UU("CMD_UTVPNCMD_PASSWORD_2"));
			c->Write(c, L"");

			if (tmp == NULL)
			{
				// キャンセル
				ReleaseCedar(cedar);
				return ERR_ACCESS_DENIED;
			}
			else
			{
				StrCpy(pass, sizeof(pass), tmp);
				Free(tmp);
			}

			goto RETRY;
		}
		else
		{
			// 接続失敗
			CmdPrintError(c, ERR_CONNECT_FAILED);
			ReleaseCedar(cedar);
			return ERR_CONNECT_FAILED;
		}
	}
	else
	{
		// 接続完了
		PC *pc = NewPc(c, client, target, cmdline);
		PcMain(pc);
		ret = pc->LastError;
		FreePc(pc);
	}

	CcDisconnectRpc(client);

	ReleaseCedar(cedar);

	return ret;
}


// サーバー管理ツールプロセッサメイン
void PsMain(PS *ps)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (ps == NULL)
	{
		return;
	}

	// CSV モードでなければ、接続が完了したメッセージを表示する
	if(ps->Console->ConsoleType != CONSOLE_CSV)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_UTVPNCMD_SERVER_CONNECTED"),
			ps->ServerName, ps->ServerPort);
		ps->Console->Write(ps->Console, tmp);
		ps->Console->Write(ps->Console, L"");

		if (ps->HubName == NULL)
		{
			// サーバー管理モード
			ps->Console->Write(ps->Console, _UU("CMD_UTVPNCMD_SERVER_CONNECTED_1"));
		}
		else
		{
			// 仮想 HUB 管理モード
			UniFormat(tmp, sizeof(tmp), _UU("CMD_UTVPNCMD_SERVER_CONNECTED_2"),
				ps->HubName);
			ps->Console->Write(ps->Console, tmp);
		}
		ps->Console->Write(ps->Console, L"");
	}

	// Caps を取得
	ps->CapsList = ScGetCapsEx(ps->Rpc);

	if (ps->AdminHub != NULL)
	{
		RPC_HUB_STATUS t;
		UINT ret;
		wchar_t tmp[MAX_SIZE];

		// ADMINHUB で指定された仮想 HUB を選択する
		Zero(&t, sizeof(t));

		StrCpy(t.HubName, sizeof(t.HubName), ps->AdminHub);

		ret = ScGetHubStatus(ps->Rpc, &t);
		if (ret == ERR_NO_ERROR)
		{
			// 成功
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);

			if (ps->HubName != NULL)
			{
				Free(ps->HubName);
			}
			ps->HubName = CopyStr(t.HubName);

			if( ps->Console->ConsoleType != CONSOLE_CSV)
			{
				ps->Console->Write(ps->Console, tmp);
			}
		}
		else
		{
			// 失敗
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Select_Failed"), ps->AdminHub);

			ps->Console->Write(ps->Console, tmp);
			CmdPrintError(ps->Console, ret);
		}
	}

	while (true)
	{
		// コマンドの定義
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"Check", PtCheck},
			{"Crash", PsCrash},
			{"Flush", PsFlush},
			{"Debug", PsDebug},
			{"ServerInfoGet", PsServerInfoGet},
			{"ServerStatusGet", PsServerStatusGet},
			{"ListenerCreate", PsListenerCreate},
			{"ListenerDelete", PsListenerDelete},
			{"ListenerList", PsListenerList},
			{"ListenerEnable", PsListenerEnable},
			{"ListenerDisable", PsListenerDisable},
			{"ServerPasswordSet", PsServerPasswordSet},
			{"ClusterSettingGet", PsClusterSettingGet},
			{"ClusterSettingStandalone", PsClusterSettingStandalone},
			{"ClusterSettingController", PsClusterSettingController},
			{"ClusterSettingMember", PsClusterSettingMember},
			{"ClusterMemberList", PsClusterMemberList},
			{"ClusterMemberInfoGet", PsClusterMemberInfoGet},
			{"ClusterMemberCertGet", PsClusterMemberCertGet},
			{"ClusterConnectionStatusGet", PsClusterConnectionStatusGet},
			{"ServerCertGet", PsServerCertGet},
			{"ServerKeyGet", PsServerKeyGet},
			{"ServerCertSet", PsServerCertSet},
			{"ServerCipherGet", PsServerCipherGet},
			{"ServerCipherSet", PsServerCipherSet},
			{"KeepEnable", PsKeepEnable},
			{"KeepDisable", PsKeepDisable},
			{"KeepSet", PsKeepSet},
			{"KeepGet", PsKeepGet},
			{"SyslogGet", PsSyslogGet},
			{"SyslogDisable", PsSyslogDisable},
			{"SyslogEnable", PsSyslogEnable},
			{"ConnectionList", PsConnectionList},
			{"ConnectionGet", PsConnectionGet},
			{"ConnectionDisconnect", PsConnectionDisconnect},
			{"BridgeDeviceList", PsBridgeDeviceList},
			{"BridgeList", PsBridgeList},
			{"BridgeCreate", PsBridgeCreate},
			{"BridgeDelete", PsBridgeDelete},
			{"Caps", PsCaps},
			{"Reboot", PsReboot},
			{"ConfigGet", PsConfigGet},
			{"ConfigSet", PsConfigSet},
			{"RouterList", PsRouterList},
			{"RouterAdd", PsRouterAdd},
			{"RouterDelete", PsRouterDelete},
			{"RouterStart", PsRouterStart},
			{"RouterStop", PsRouterStop},
			{"RouterIfList", PsRouterIfList},
			{"RouterIfAdd", PsRouterIfAdd},
			{"RouterIfDel", PsRouterIfDel},
			{"RouterTableList", PsRouterTableList},
			{"RouterTableAdd", PsRouterTableAdd},
			{"RouterTableDel", PsRouterTableDel},
			{"LogFileList", PsLogFileList},
			{"LogFileGet", PsLogFileGet},
			{"HubCreate", PsHubCreate},
			{"HubCreateDynamic", PsHubCreateDynamic},
			{"HubCreateStatic", PsHubCreateStatic},
			{"HubDelete", PsHubDelete},
			{"HubSetStatic", PsHubSetStatic},
			{"HubSetDynamic", PsHubSetDynamic},
			{"HubList", PsHubList},
			{"Hub", PsHub},
			{"Online", PsOnline},
			{"Offline", PsOffline},
			{"SetMaxSession", PsSetMaxSession},
			{"SetHubPassword", PsSetHubPassword},
			{"SetEnumAllow", PsSetEnumAllow},
			{"SetEnumDeny", PsSetEnumDeny},
			{"OptionsGet", PsOptionsGet},
			{"RadiusServerSet", PsRadiusServerSet},
			{"RadiusServerDelete", PsRadiusServerDelete},
			{"RadiusServerGet", PsRadiusServerGet},
			{"StatusGet", PsStatusGet},
			{"LogGet", PsLogGet},
			{"LogEnable", PsLogEnable},
			{"LogDisable", PsLogDisable},
			{"LogSwitchSet", PsLogSwitchSet},
			{"LogPacketSaveType", PsLogPacketSaveType},
			{"CAList", PsCAList},
			{"CAAdd", PsCAAdd},
			{"CADelete", PsCADelete},
			{"CAGet", PsCAGet},
			{"CascadeList", PsCascadeList},
			{"CascadeCreate", PsCascadeCreate},
			{"CascadeSet", PsCascadeSet},
			{"CascadeGet", PsCascadeGet},
			{"CascadeDelete", PsCascadeDelete},
			{"CascadeUsernameSet", PsCascadeUsernameSet},
			{"CascadeAnonymousSet", PsCascadeAnonymousSet},
			{"CascadePasswordSet", PsCascadePasswordSet},
			{"CascadeCertSet", PsCascadeCertSet},
			{"CascadeCertGet", PsCascadeCertGet},
			{"CascadeEncryptEnable", PsCascadeEncryptEnable},
			{"CascadeEncryptDisable", PsCascadeEncryptDisable},
			{"CascadeCompressEnable", PsCascadeCompressEnable},
			{"CascadeCompressDisable", PsCascadeCompressDisable},
			{"CascadeProxyNone", PsCascadeProxyNone},
			{"CascadeProxyHttp", PsCascadeProxyHttp},
			{"CascadeProxySocks", PsCascadeProxySocks},
			{"CascadeServerCertEnable", PsCascadeServerCertEnable},
			{"CascadeServerCertDisable", PsCascadeServerCertDisable},
			{"CascadeServerCertSet", PsCascadeServerCertSet},
			{"CascadeServerCertDelete", PsCascadeServerCertDelete},
			{"CascadeServerCertGet", PsCascadeServerCertGet},
			{"CascadeDetailSet", PsCascadeDetailSet},
			{"CascadePolicySet", PsCascadePolicySet},
			{"PolicyList", PsPolicyList},
			{"CascadeStatusGet", PsCascadeStatusGet},
			{"CascadeRename", PsCascadeRename},
			{"CascadeOnline", PsCascadeOnline},
			{"CascadeOffline", PsCascadeOffline},
			{"AccessAdd", PsAccessAdd},
			{"AccessAddEx", PsAccessAddEx},
			{"AccessAdd6", PsAccessAdd6},
			{"AccessAddEx6", PsAccessAddEx6},
			{"AccessList", PsAccessList},
			{"AccessDelete", PsAccessDelete},
			{"AccessEnable", PsAccessEnable},
			{"AccessDisable", PsAccessDisable},
			{"UserList", PsUserList},
			{"UserCreate", PsUserCreate},
			{"UserSet", PsUserSet},
			{"UserDelete", PsUserDelete},
			{"UserGet", PsUserGet},
			{"UserAnonymousSet", PsUserAnonymousSet},
			{"UserPasswordSet", PsUserPasswordSet},
			{"UserCertSet", PsUserCertSet},
			{"UserCertGet", PsUserCertGet},
			{"UserSignedSet", PsUserSignedSet},
			{"UserRadiusSet", PsUserRadiusSet},
			{"UserNTLMSet", PsUserNTLMSet},
			{"UserPolicyRemove", PsUserPolicyRemove},
			{"UserPolicySet", PsUserPolicySet},
			{"UserExpiresSet", PsUserExpiresSet},
			{"GroupList", PsGroupList},
			{"GroupCreate", PsGroupCreate},
			{"GroupSet", PsGroupSet},
			{"GroupDelete", PsGroupDelete},
			{"GroupGet", PsGroupGet},
			{"GroupJoin", PsGroupJoin},
			{"GroupUnjoin", PsGroupUnjoin},
			{"GroupPolicyRemove", PsGroupPolicyRemove},
			{"GroupPolicySet", PsGroupPolicySet},
			{"SessionList", PsSessionList},
			{"SessionGet", PsSessionGet},
			{"SessionDisconnect", PsSessionDisconnect},
			{"MacTable", PsMacTable},
			{"MacDelete", PsMacDelete},
			{"IpTable", PsIpTable},
			{"IpDelete", PsIpDelete},
			{"SecureNatEnable", PsSecureNatEnable},
			{"SecureNatDisable", PsSecureNatDisable},
			{"SecureNatStatusGet", PsSecureNatStatusGet},
			{"SecureNatHostGet", PsSecureNatHostGet},
			{"SecureNatHostSet", PsSecureNatHostSet},
			{"NatGet", PsNatGet},
			{"NatEnable", PsNatEnable},
			{"NatDisable", PsNatDisable},
			{"NatSet", PsNatSet},
			{"NatTable", PsNatTable},
			{"DhcpGet", PsDhcpGet},
			{"DhcpEnable", PsDhcpEnable},
			{"DhcpDisable", PsDhcpDisable},
			{"DhcpSet", PsDhcpSet},
			{"DhcpTable", PsDhcpTable},
			{"AdminOptionList", PsAdminOptionList},
			{"AdminOptionSet", PsAdminOptionSet},
			{"ExtOptionList", PsExtOptionList},
			{"ExtOptionSet", PsExtOptionSet},
			{"CrlList", PsCrlList},
			{"CrlAdd", PsCrlAdd},
			{"CrlDel", PsCrlDel},
			{"CrlGet", PsCrlGet},
			{"AcList", PsAcList},
			{"AcAdd", PsAcAdd},
			{"AcAdd6", PsAcAdd6},
			{"AcDel", PsAcDel},
			{"MakeCert", PtMakeCert},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"LicenseAdd", PsLicenseAdd},
			{"LicenseDel", PsLicenseDel},
			{"LicenseList", PsLicenseList},
			{"LicenseStatus", PsLicenseStatus},
		};

		// プロンプトの生成
		if (ps->HubName == NULL)
		{
			Format(prompt, sizeof(prompt), "VPN Server>");
		}
		else
		{
			Format(prompt, sizeof(prompt), "VPN Server/%s>", ps->HubName);
		}

		if (DispatchNextCmdEx(ps->Console, ps->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), ps) == false)
		{
			break;
		}
		ps->LastError = ps->Console->RetCode;

		if (ps->LastError == ERR_NO_ERROR && ps->Console->ConsoleType != CONSOLE_CSV)
		{
			ps->Console->Write(ps->Console, _UU("CMD_MSG_OK"));
			ps->Console->Write(ps->Console, L"");
		}

		if (ps->CmdLine != NULL)
		{
			break;
		}
	}

	// Caps を解放
	FreeCapsList(ps->CapsList);
	ps->CapsList = NULL;
}

// 新しいコマンド関数のテンプレート
UINT PsXxx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerCreate_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScCreateListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// スタンドアロンモードに設定
UINT PsClusterSettingStandalone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.ServerType = SERVER_TYPE_STANDALONE;

	// RPC 呼び出し
	ret = ScSetFarmSetting(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// クラスタコントローラモードに設定
UINT PsClusterSettingController(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM t;
	UINT weight;
	PARAM args[] =
	{
		{"WEIGHT", NULL, NULL, NULL, NULL},
		{"ONLY", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	weight = GetParamInt(o, "WEIGHT");
	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	Zero(&t, sizeof(t));
	t.ServerType = SERVER_TYPE_FARM_CONTROLLER;
	t.Weight = weight;
	t.ControllerOnly = GetParamYes(o, "ONLY");

	// RPC 呼び出し
	ret = ScSetFarmSetting(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// IP アドレスの評価
bool CmdEvalIp(CONSOLE *c, wchar_t *str, void *param)
{
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	if (UniIsEmptyStr(str))
	{
		return true;
	}

	if (UniStrToIP32(str) == 0 && UniStrCmpi(str, L"0.0.0.0") != 0)
	{
		wchar_t *msg = (param == NULL) ? _UU("CMD_IP_EVAL_FAILED") : (wchar_t *)param;
		c->Write(c, msg);
		return false;
	}

	return true;
}

// 文字列をポートリストに変換
LIST *StrToPortList(char *str)
{
	LIST *o;
	TOKEN_LIST *t;
	UINT i;
	if (str == NULL)
	{
		return NULL;
	}

	// トークンに変換
	t = ParseToken(str, ", ");
	if (t == NULL)
	{
		return NULL;
	}
	if (t->NumTokens == 0)
	{
		FreeToken(t);
		return NULL;
	}

	o = NewListFast(NULL);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *s = t->Token[i];
		UINT n;
		if (IsNum(s) == false)
		{
			ReleaseList(o);
			FreeToken(t);
			return NULL;
		}
		n = ToInt(s);
		if (n == 0 || n >= 65536)
		{
			ReleaseList(o);
			FreeToken(t);
			return NULL;
		}
		if (IsInList(o, (void *)n))
		{
			ReleaseList(o);
			FreeToken(t);
			return NULL;
		}
		Add(o, (void *)n);
	}

	FreeToken(t);

	if (LIST_NUM(o) > MAX_PUBLIC_PORT_NUM)
	{
		ReleaseList(o);
		return NULL;
	}

	return o;
}

// クラスタメンバモードに設定
UINT PsClusterSettingMember(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM t;
	char *host_and_port;
	char *host;
	UINT port;
	UINT weight;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[server:port]", CmdPrompt, _UU("CMD_ClusterSettingMember_Prompt_HOST_1"), CmdEvalHostAndPort, NULL},
		{"IP", PsClusterSettingMemberPromptIp, NULL, CmdEvalIp, NULL},
		{"PORTS", PsClusterSettingMemberPromptPorts, NULL, CmdEvalPortList, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"WEIGHT", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	weight = GetParamInt(o, "WEIGHT");

	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	Zero(&t, sizeof(t));
	host_and_port = GetParamStr(o, "[server:port]");
	if (ParseHostPort(host_and_port, &host, &port, 0))
	{
		char *pw;
		char *ports_str;
		LIST *ports;
		UINT i;

		StrCpy(t.ControllerName, sizeof(t.ControllerName), host);
		t.ControllerPort = port;
		Free(host);

		pw = GetParamStr(o, "PASSWORD");

		Hash(t.MemberPassword, pw, StrLen(pw), true);
		t.PublicIp = StrToIP32(GetParamStr(o, "IP"));
		t.ServerType = SERVER_TYPE_FARM_MEMBER;

		ports_str = GetParamStr(o, "PORTS");

		ports = StrToPortList(ports_str);

		t.NumPort = LIST_NUM(ports);
		t.Ports = ZeroMalloc(sizeof(UINT) * t.NumPort);

		for (i = 0;i < t.NumPort;i++)
		{
			t.Ports[i] = (UINT)LIST_DATA(ports, i);
		}

		t.Weight = weight;

		ReleaseList(ports);

		// RPC 呼び出し
		ret = ScSetFarmSetting(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcFarm(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// ポート一覧の評価
bool CmdEvalPortList(CONSOLE *c, wchar_t *str, void *param)
{
	char *s;
	bool ret = false;
	LIST *o;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	s = CopyUniToStr(str);

	o = StrToPortList(s);

	if (o != NULL)
	{
		ret = true;
	}

	ReleaseList(o);

	Free(s);

	if (ret == false)
	{
		c->Write(c, _UU("CMD_PORTLIST_EVAL_FAILED"));
	}

	return ret;
}

// ホスト名とポート番号の形式の文字列のチェック
bool CmdEvalHostAndPort(CONSOLE *c, wchar_t *str, void *param)
{
	char *tmp;
	bool ret = false;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	tmp = CopyUniToStr(str);

	ret = ParseHostPort(tmp, NULL, NULL, (UINT)param);

	if (ret == false)
	{
		c->Write(c, param == NULL ? _UU("CMD_HOSTPORT_EVAL_FAILED") : (wchar_t *)param);
	}

	Free(tmp);

	return ret;
}

// 公開 ポート番号の入力
wchar_t *PsClusterSettingMemberPromptPorts(CONSOLE *c, void *param)
{
	wchar_t *ret;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	c->Write(c, _UU("CMD_ClusterSettingMember_Prompt_PORT_1"));
	c->Write(c, L"");

	ret = c->ReadLine(c, _UU("CMD_ClusterSettingMember_Prompt_PORT_2"), true);

	return ret;
}

// 公開 IP アドレスの入力
wchar_t *PsClusterSettingMemberPromptIp(CONSOLE *c, void *param)
{
	wchar_t *ret;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	c->Write(c, _UU("CMD_ClusterSettingMember_Prompt_IP_1"));
	c->Write(c, L"");

	ret = c->ReadLine(c, _UU("CMD_ClusterSettingMember_Prompt_IP_2"), true);

	return ret;
}

// クラスタメンバリストの表示
UINT PsClusterMemberList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_FARM t;
	CT *ct;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScEnumFarmMember(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_ID"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_4"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_5"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_6"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_7"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_8"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_9"), true);

	for (i = 0;i < t.NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t.Farms[i];
		wchar_t tmp0[64];
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

		UniToStru(tmp0, e->Id);

		CtInsert(ct, tmp0,
			e->Controller ? _UU("SM_FM_CONTROLLER") : _UU("SM_FM_MEMBER"),
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8);
	}

	CtFree(ct, c);

	FreeRpcEnumFarm(&t);

	FreeParamValueList(o);

	return 0;
}

// クラスタ メンバの情報の取得
UINT PsClusterMemberInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM_INFO t;
	CT *ct;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_ClusterMemberInfoGet_PROMPT_ID"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Id = UniToInt(GetParamUniStr(o, "[id]"));

	// RPC 呼び出し
	ret = ScGetFarmInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNewStandard();

	{
		wchar_t tmp[MAX_SIZE];
		char str[MAX_SIZE];
		UINT i;

		CtInsert(ct, _UU("SM_FMINFO_TYPE"),
			t.Controller ? _UU("SM_FARM_CONTROLLER") : _UU("SM_FARM_MEMBER"));

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
		CtInsert(ct, _UU("SM_FMINFO_CONNECT_TIME"), tmp);

		IPToStr32(str, sizeof(str), t.Ip);
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("SM_FMINFO_IP"), tmp);

		StrToUni(tmp, sizeof(tmp), t.Hostname);
		CtInsert(ct, _UU("SM_FMINFO_HOSTNAME"), tmp);

		UniToStru(tmp, t.Point);
		CtInsert(ct, _UU("SM_FMINFO_POINT"), tmp);

		UniToStru(tmp, t.Weight);
		CtInsert(ct, _UU("SM_FMINFO_WEIGHT"), tmp);

		UniToStru(tmp, t.NumPort);
		CtInsert(ct, _UU("SM_FMINFO_NUM_PORT"), tmp);

		for (i = 0;i < t.NumPort;i++)
		{
			wchar_t tmp2[MAX_SIZE];
			UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_PORT"), i + 1);
			UniToStru(tmp2, t.Ports[i]);
			CtInsert(ct, tmp, tmp2);
		}

		UniToStru(tmp, t.NumFarmHub);
		CtInsert(ct, _UU("SM_FMINFO_NUM_HUB"), tmp);

		for (i = 0;i < t.NumFarmHub;i++)
		{
			wchar_t tmp2[MAX_SIZE];
			UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_HUB"), i + 1);
			UniFormat(tmp2, sizeof(tmp2),
				t.FarmHubs[i].DynamicHub ? _UU("SM_FMINFO_HUB_TAG_2") : _UU("SM_FMINFO_HUB_TAG_1"),
				t.FarmHubs[i].HubName);
			CtInsert(ct, tmp, tmp2);
		}

		UniToStru(tmp, t.NumSessions);
		CtInsert(ct, _UU("SM_FMINFO_NUM_SESSION"), tmp);

		UniToStru(tmp, t.NumTcpConnections);
		CtInsert(ct, _UU("SM_FMINFO_NUN_CONNECTION"), tmp);
	}

	CtFree(ct, c);

	FreeRpcFarmInfo(&t);

	FreeParamValueList(o);

	return 0;
}

// クラスタ メンバの証明書の取得
UINT PsClusterMemberCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM_INFO t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_ClusterMemberCertGet_PROMPT_ID"), NULL, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.Id = UniToInt(GetParamUniStr(o, "[id]"));

	// RPC 呼び出し
	ret = ScGetFarmInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		X *x = t.ServerCert;
		char *filename = GetParamStr(o, "SAVECERT");

		if (XToFile(x, filename, true) == false)
		{
			c->Write(c, _UU("CMD_SAVECERT_FAILED"));

			ret = ERR_INTERNAL_ERROR;
		}
	}

	FreeRpcFarmInfo(&t);

	FreeParamValueList(o);

	return ret;
}

// クラスタ コントローラへの接続状態の取得
UINT PsClusterConnectionStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM_CONNECTION_STATUS t;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetFarmConnectionStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		char str[MAX_SIZE];

		if (t.Online == false)
		{
			CtInsert(ct, _UU("SM_FC_IP"), _UU("SM_FC_NOT_CONNECTED"));

			CtInsert(ct, _UU("SM_FC_PORT"), _UU("SM_FC_NOT_CONNECTED"));
		}
		else
		{
			IPToStr32(str, sizeof(str), t.Ip);
			StrToUni(tmp, sizeof(tmp), str);
			CtInsert(ct, _UU("SM_FC_IP"), tmp);

			UniToStru(tmp, t.Port);
			CtInsert(ct, _UU("SM_FC_PORT"), tmp);
		}

		CtInsert(ct,
			_UU("SM_FC_STATUS"),
			t.Online ? _UU("SM_FC_ONLINE") : _UU("SM_FC_OFFLINE"));

		if (t.Online == false)
		{
			UniFormat(tmp, sizeof(tmp), _UU("SM_FC_ERROR_TAG"), _E(t.LastError), t.LastError);
			CtInsert(ct,
				_UU("SM_FC_LAST_ERROR"), tmp);
		}

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartedTime), NULL);
		CtInsert(ct, _UU("SM_FC_START_TIME"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.FirstConnectedTime), NULL);
		CtInsert(ct, _UU("SM_FC_FIRST_TIME"), tmp);

		//if (t.Online == false)
		{
			GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CurrentConnectedTime), NULL);
			CtInsert(ct, _UU("SM_FC_CURRENT_TIME"), tmp);
		}

		UniToStru(tmp, t.NumTry);
		CtInsert(ct, _UU("SM_FC_NUM_TRY"), tmp);

		UniToStru(tmp, t.NumConnected);
		CtInsert(ct, _UU("SM_FC_NUM_CONNECTED"), tmp);

		UniToStru(tmp, t.NumFailed);
		CtInsert(ct, _UU("SM_FC_NUM_FAILED"), tmp);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// VPN Server の SSL 証明書の取得
UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[cert]", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (XToFile(t.Cert, GetParamStr(o, "[cert]"), true) == false)
	{
		c->Write(c, _UU("CMD_SAVECERT_FAILED"));
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return 0;
}

// VPN Server の SSL 証明書の秘密鍵の取得
UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[key]", CmdPrompt, _UU("CMD_SAVEKEYPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Key != NULL)
	{
		if (KToFile(t.Key, GetParamStr(o, "[key]"), true, NULL) == false)
		{
			c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
		}
	}
	else
	{
		ret = ERR_NOT_ENOUGH_RIGHT;
		CmdPrintError(c, ret);
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return ret;
}

// 証明書と秘密鍵の読み込み
bool CmdLoadCertAndKey(CONSOLE *c, X **xx, K **kk, char *cert_filename, char *key_filename)
{
	X *x;
	K *k;
	// 引数チェック
	if (c == NULL || cert_filename == NULL || key_filename == NULL || xx == NULL || kk == NULL)
	{
		return false;
	}

	x = FileToX(cert_filename);
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return false;
	}

	k = CmdLoadKey(c, key_filename);
	if (k == NULL)
	{
		c->Write(c, _UU("CMD_LOADKEY_FAILED"));
		FreeX(x);
		return false;
	}

	if (CheckXandK(x, k) == false)
	{
		c->Write(c, _UU("CMD_KEYPAIR_FAILED"));
		FreeX(x);
		FreeK(k);

		return false;
	}

	*xx = x;
	*kk = k;

	return true;
}

// 秘密鍵の読み込み
K *CmdLoadKey(CONSOLE *c, char *filename)
{
	BUF *b;
	// 引数チェック
	if (c == NULL || filename == NULL)
	{
		return NULL;
	}

	b = ReadDump(filename);
	if (b == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return NULL;
	}
	else
	{
		K *key;
		if (IsEncryptedK(b, true) == false)
		{
			key = BufToK(b, true, IsBase64(b), NULL);
		}
		else
		{
			c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_1"));

			while (true)
			{
				char *pass = c->ReadPassword(c, _UU("CMD_LOADKEY_ENCRYPTED_2"));

				if (pass == NULL)
				{
					FreeBuf(b);
					return NULL;
				}

				key = BufToK(b, true, IsBase64(b), pass);
				Free(pass);

				if (key != NULL)
				{
					break;
				}

				c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_3"));
			}
		}

		FreeBuf(b);

		return key;
	}
}

// VPN Server の SSL 証明書と秘密鍵の設定
UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (CmdLoadCertAndKey(c, &t.Cert, &t.Key,
		GetParamStr(o, "LOADCERT"),
		GetParamStr(o, "LOADKEY")))
	{
		// RPC 呼び出し
		ret = ScSetServerCert(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcKeyPair(&t);
	}
	else
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

// VPN 通信で使用される暗号化アルゴリズムの取得
UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	TOKEN_LIST *ciphers;
	UINT i;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ciphers = GetCipherList();

	c->Write(c, _UU("CMD_ServerCipherGet_SERVER"));

	UniFormat(tmp, sizeof(tmp), L" %S", t.String);
	c->Write(c, tmp);

	c->Write(c, L"");
	c->Write(c, _UU("CMD_ServerCipherGet_CIPHERS"));

	for (i = 0;i < ciphers->NumTokens;i++)
	{
		UniFormat(tmp, sizeof(tmp), L" %S", ciphers->Token[i]);
		c->Write(c, tmp);
	}

	FreeRpcStr(&t);

	FreeParamValueList(o);

	return 0;
}

// VPN 通信で使用される暗号化アルゴリズムの設定
UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ServerCipherSet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.String = CopyStr(GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScSetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcStr(&t);

	FreeParamValueList(o);

	return 0;
}

// インターネット接続の維持機能の有効化
UINT PsKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.UseKeepConnect = true;

	ret = ScSetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// インターネット接続の維持機能の無効化
UINT PsKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.UseKeepConnect = false;

	ret = ScSetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// tcp または udp の評価
bool CmdEvalTcpOrUdp(CONSOLE *c, wchar_t *str, void *param)
{
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	if (UniStrCmpi(str, L"tcp") == 0 || UniStrCmpi(str, L"udp") == 0)
	{
		return true;
	}

	c->Write(c, _UU("CMD_KeepSet_EVAL_TCP_UDP"));

	return false;
}

// syslog 設定の有効化
UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;
	CMD_EVAL_MIN_MAX minmax = {"CMD_SyslogEnable_MINMAX", 1, 3};
	char *host;
	UINT port;

	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[1|2|3]", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_123"), CmdEvalMinMax, &minmax},
		{"HOST", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_HOST"), CmdEvalHostAndPort, (void *)SYSLOG_PORT},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, SYSLOG_PORT))
	{
		StrCpy(t.Hostname, sizeof(t.Hostname), host);
		t.Port = port;
		t.SaveType = GetParamInt(o, "[1|2|3]");

		Free(host);

		// RPC 呼び出し
		ret = ScSetSysLog(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// syslog 設定の無効化
UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.SaveType = SYSLOG_NONE;

	// RPC 呼び出し
	ret = ScSetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// syslog 設定の取得
UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_1"), GetSyslogSettingName(t.SaveType));

		if (t.SaveType != SYSLOG_NONE)
		{
			StrToUni(tmp, sizeof(tmp), t.Hostname);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_2"), tmp);

			UniToStru(tmp, t.Port);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_3"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// syslog 設定名を取得
wchar_t *GetSyslogSettingName(UINT n)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), "SM_SYSLOG_%u", n);

	return _UU(tmp);
}

// インターネット接続の維持機能の設定
UINT PsKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;
	char *host;
	UINT port;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"HOST", CmdPrompt, _UU("CMD_KeepSet_PROMPT_HOST"), CmdEvalHostAndPort, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_PROTOCOL"), CmdEvalTcpOrUdp, NULL},
		{"INTERVAL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_INTERVAL"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, 0))
	{
		StrCpy(t.KeepConnectHost, sizeof(t.KeepConnectHost), host);
		t.KeepConnectPort = port;
		t.KeepConnectInterval = GetParamInt(o, "INTERVAL");
		t.KeepConnectProtocol = (StrCmpi(GetParamStr(o, "PROTOCOL"), "tcp") == 0) ? 0 : 1;
		Free(host);

		// RPC 呼び出し
		ret = ScSetKeep(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// インターネット接続の維持機能の取得
UINT PsKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.KeepConnectHost);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_1"), tmp);

		UniToStru(tmp, t.KeepConnectPort);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_2"), tmp);

		UniToStru(tmp, t.KeepConnectInterval);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_3"), tmp);

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_4"),
			t.KeepConnectProtocol == 0 ? L"TCP/IP" : L"UDP/IP");

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_5"),
			t.UseKeepConnect ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// コネクション種類文字列の取得
wchar_t *GetConnectionTypeStr(UINT type)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_CONNECTION_TYPE_%u", type);

	return _UU(tmp);
}

// VPN Server に接続中の TCP コネクション一覧の取得
UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CONNECTION t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScEnumConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_4"), false);

	for (i = 0;i < t.NumConnection;i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t name[MAX_SIZE];
		wchar_t datetime[MAX_SIZE];
		RPC_ENUM_CONNECTION_ITEM *e = &t.Connections[i];

		StrToUni(name, sizeof(name), e->Name);
		UniFormat(tmp, sizeof(tmp), _UU("SM_HOSTNAME_AND_PORT"), e->Hostname, e->Port);
		GetDateTimeStrEx64(datetime, sizeof(datetime), SystemToLocal64(e->ConnectedTime), NULL);

		CtInsert(ct, name, tmp, datetime,
			GetConnectionTypeStr(e->Type));
	}

	CtFree(ct, c);

	FreeRpcEnumConnetion(&t);

	FreeParamValueList(o);

	return 0;
}

// VPN Server に接続中の TCP コネクションの情報の取得
UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONNECTION_INFO t;
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetConnectionInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("SM_CONNINFO_NAME"), tmp);

		CtInsert(ct, _UU("SM_CONNINFO_TYPE"), GetConnectionTypeStr(t.Type));

		StrToUni(tmp, sizeof(tmp), t.Hostname);
		CtInsert(ct, _UU("SM_CONNINFO_HOSTNAME"), tmp);

		UniToStru(tmp, t.Port);
		CtInsert(ct, _UU("SM_CONNINFO_PORT"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
		CtInsert(ct, _UU("SM_CONNINFO_TIME"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ServerStr);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_STR"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ServerVer / 100, t.ServerVer % 100);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_VER"), tmp);

		UniToStru(tmp, t.ServerBuild);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_BUILD"), tmp);

		if (StrLen(t.ClientStr) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientStr);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_STR"), tmp);

			UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ClientVer / 100, t.ClientVer % 100);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_VER"), tmp);

			UniToStru(tmp, t.ClientBuild);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_BUILD"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// VPN Server に接続中の TCP コネクションの切断
UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DISCONNECT_CONNECTION t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionDisconnect_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScDisconnectConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// ローカル ブリッジに使用できる LAN カード一覧の取得
UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ETH t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScEnumEthernet(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *item = &t.Items[i];
		wchar_t tmp[MAX_SIZE * 2];

		if(UniIsEmptyStr(item->NetworkConnectionName) == false)
		{
			UniFormat(tmp, sizeof(tmp), BRIDGE_NETWORK_CONNECTION_STR, item->NetworkConnectionName, item->DeviceName);
		}
		else
		{
			StrToUni(tmp, sizeof(tmp), item->DeviceName);
		}
		c->Write(c, tmp);
	}

	FreeRpcEnumEth(&t);

	FreeParamValueList(o);

	return 0;
}

// ローカル ブリッジ接続の一覧の取得
UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScEnumLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_4"), false);

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

		CtInsert(ct, name, hub, nic, status);
	}

	CtFree(ct, c);

	FreeRpcEnumLocalBridge(&t);

	FreeParamValueList(o);

	return 0;
}

// ローカル ブリッジ接続の作成
UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
		{"TAP", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.Active = true;
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));
	t.Online = true;
	t.TapMode = GetParamYes(o, "TAP");

	// RPC 呼び出し
	ret = ScAddLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		c->Write(c, _UU("SM_BRIDGE_INTEL"));
		c->Write(c, L"");
	}

	FreeParamValueList(o);

	return 0;
}

// ローカル ブリッジ接続の削除
UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));

	// RPC 呼び出し
	ret = ScDeleteLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// サーバーの機能・能力一覧の取得
UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	CAPSLIST *t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC 呼び出し
	t = ScGetCapsEx(ps->Rpc);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct;

		ct = CtNewStandard();

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
				CtInsert(ct, title, c->Value == 0 ? _UU("CAPS_NO") : _UU("CAPS_YES"));
			}
			else
			{
				wchar_t str[64];
				UniToStru(str, c->Value);
				CtInsert(ct, title, str);
			}
		}

		CtFree(ct, c);
	}

	FreeCapsList(t);

	FreeParamValueList(o);

	return 0;
}

// VPN Server サービスの再起動
UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"RESETCONFIG", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.IntValue = GetParamYes(o, "RESETCONFIG") ? 1 : 0;

	// RPC 呼び出し
	ret = ScRebootServer(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcTest(&t);

	FreeParamValueList(o);

	return 0;
}

// VPN Server の現在のコンフィグレーションの取得
UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScGetConfig(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *filename = GetParamStr(o, "[path]");

		if (IsEmptyStr(filename))
		{
			// 画面に表示
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *buf;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_ConfigGet_FILENAME"), t.FileName,
				StrLen(t.FileData));
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)t.FileData, StrLen(t.FileData));
			buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(buf, buf_size, (BYTE *)t.FileData, StrLen(t.FileData));

			c->Write(c, buf);
			c->Write(c, L"");

			Free(buf);
		}
		else
		{
			// ファイルに保存
			IO *io = FileCreate(filename);

			if (io == NULL)
			{
				c->Write(c, _UU("CMD_ConfigGet_FILE_SAVE_FAILED"));

				ret = ERR_INTERNAL_ERROR;
			}
			else
			{
				FileWrite(io, t.FileData, StrLen(t.FileData));
				FileClose(io);
			}
		}
	}

	FreeRpcConfig(&t);

	FreeParamValueList(o);

	return ret;
}

// VPN Server へのコンフィグレーションの書き込み
UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	char *filename;
	BUF *buf;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", CmdPrompt, _UU("CMD_ConfigSet_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamStr(o, "[path]");

	buf = ReadDump(filename);
	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_ConfigSet_FILE_LOAD_FAILED"));
	}
	else
	{
		Zero(&t, sizeof(t));

		t.FileData = ZeroMalloc(buf->Size + 1);
		Copy(t.FileData, buf->Buf, buf->Size);
		FreeBuf(buf);

		// RPC 呼び出し
		ret = ScSetConfig(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcConfig(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチ一覧の取得
UINT PsRouterList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_L3SW t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScEnumL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN3"), true);
		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN4"), true);

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

			CtInsert(ct,
				tmp1, tmp2, tmp3, tmp4);
		}

		CtFree(ct, c);
	}

	FreeRpcEnumL3Sw(&t);

	FreeParamValueList(o);

	return 0;
}

// 新しい仮想レイヤ 3 スイッチの定義
UINT PsRouterAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScAddL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチの削除
UINT PsRouterDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterDelete_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScDelL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチの動作の開始
UINT PsRouterStart(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterStart_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScStartL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチの動作の停止
UINT PsRouterStop(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterStop_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScStopL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチに登録されているインターフェイス一覧の取得
UINT PsRouterIfList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_L3IF t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterIfList_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScEnumL3If(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_L3_SW_IF_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_IF_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_IF_COLUMN3"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3IF *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->IpAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			StrToUni(tmp3, sizeof(tmp3), e->HubName);

			CtInsert(ct, tmp1, tmp2, tmp3);
		}


		CtFree(ct, c);
	}

	FreeRpcEnumL3If(&t);

	FreeParamValueList(o);

	return 0;
}

// IP アドレスとマスクの評価
bool CmdEvalIpAndMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	UINT ip, mask;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask4(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1"));
		return false;
	}

	return true;
}
bool CmdEvalIpAndMask6(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	IP ip, mask;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask6(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1_6"));
		return false;
	}

	return true;
}
bool CmdEvalIpAndMask46(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	bool ret = false;

	Zero(tmp, sizeof(tmp));
	UniToStr(tmp, sizeof(tmp), str);

	t = ParseToken(tmp, "/");
	if (t == NULL)
	{
		return false;
	}

	if (t->NumTokens >= 1)
	{
		Trim(t->Token[0]);

		if (IsIpStr4(t->Token[0]))
		{
			ret = CmdEvalIpAndMask4(c, str, param);
		}
		else
		{
			ret = CmdEvalIpAndMask6(c, str, param);
		}
	}

	FreeToken(t);

	return ret;
}

// ネットワークアドレスとサブネットマスクの評価
bool CmdEvalNetworkAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	UINT ip, mask;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndSubnetMask4(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_1"));
		return false;
	}

	if (IsNetworkAddress32(ip, mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_2"));
		return false;
	}

	return true;
}
bool CmdEvalNetworkAndSubnetMask6(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	IP ip, mask;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndSubnetMask6(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_1_6"));
		return false;
	}

	if (IsNetworkPrefixAddress6(&ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_3"));
		return false;
	}

	return true;
}
bool CmdEvalNetworkAndSubnetMask46(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	bool ret = false;

	Zero(tmp, sizeof(tmp));
	UniToStr(tmp, sizeof(tmp), str);

	t = ParseToken(tmp, "/");
	if (t == NULL)
	{
		return false;
	}

	if (t->NumTokens >= 1)
	{
		Trim(t->Token[0]);

		if (IsIpStr4(t->Token[0]))
		{
			ret = CmdEvalNetworkAndSubnetMask4(c, str, param);
		}
		else
		{
			ret = CmdEvalNetworkAndSubnetMask6(c, str, param);
		}
	}

	FreeToken(t);

	return ret;
}

// IP アドレスとサブネットマスクの評価
bool CmdEvalHostAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndSubnetMask4(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_1"));
		return false;
	}

	return true;
}

// 仮想レイヤ 3 スイッチへの仮想インターフェイスの追加
UINT PsRouterIfAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3IF t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"HUB", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_HUB"), CmdEvalNotEmpty, NULL},
		{"IP", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_IP"), CmdEvalHostAndSubnetMask4, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	ParseIpAndSubnetMask4(GetParamStr(o, "IP"), &t.IpAddress, &t.SubnetMask);
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "HUB"));

	// RPC 呼び出し
	ret = ScAddL3If(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチの仮想インターフェイスの削除
UINT PsRouterIfDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3IF t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"HUB", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_HUB"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "HUB"));

	// RPC 呼び出し
	ret = ScDelL3If(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチのルーティング テーブル一覧の取得
UINT PsRouterTableList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_L3TABLE t;
	CT *ct;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t tmp3[MAX_SIZE];
	wchar_t tmp4[MAX_SIZE];
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_RouterTableList_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScEnumL3Table(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;

		ct = CtNew();

		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN3"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN4"), true);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3TABLE *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->NetworkAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			IPToUniStr32(tmp3, sizeof(tmp3), e->GatewayAddress);
			UniToStru(tmp4, e->Metric);

			CtInsert(ct, tmp1, tmp2, tmp3, tmp4);
		}

		CtFree(ct, c);
	}

	FreeRpcEnumL3Table(&t);

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチへのルーティング テーブル エントリの追加
UINT PsRouterTableAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3TABLE t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"NETWORK", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NETWORK"), CmdEvalNetworkAndSubnetMask4, NULL},
		{"GATEWAY", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_GATEWAY"), CmdEvalIp, NULL},
		{"METRIC", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_METRIC"), CmdEvalInt1, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	ParseIpAndSubnetMask4(GetParamStr(o, "NETWORK"), &t.NetworkAddress, &t.SubnetMask);
	t.Metric = GetParamInt(o, "METRIC");
	t.GatewayAddress = StrToIP32(GetParamStr(o, "GATEWAY"));

	// RPC 呼び出し
	ret = ScAddL3Table(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想レイヤ 3 スイッチのルーティング テーブル エントリの削除
UINT PsRouterTableDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3TABLE t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"NETWORK", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NETWORK"), CmdEvalNetworkAndSubnetMask4, NULL},
		{"GATEWAY", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_GATEWAY"), CmdEvalIp, NULL},
		{"METRIC", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_METRIC"), CmdEvalInt1, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	ParseIpAndSubnetMask4(GetParamStr(o, "NETWORK"), &t.NetworkAddress, &t.SubnetMask);
	t.Metric = GetParamInt(o, "METRIC");
	t.GatewayAddress = StrToIP32(GetParamStr(o, "GATEWAY"));

	// RPC 呼び出し
	ret = ScDelL3Table(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// ログ ファイル一覧の取得
UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOG_FILE t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	c->Write(c, _UU("CMD_LogFileList_START"));
	c->Write(c, L"");

	// RPC 呼び出し
	ret = ScEnumLogFile(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileList_NUM_LOGS"), t.NumItem);
		c->Write(c, tmp);

		ct = CtNew();

		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_4"), false);

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

			CtInsert(ct, tmp1, tmp2, tmp3, tmp4);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLogFile(&t);

	FreeParamValueList(o);

	return 0;
}

// ログ ファイルのダウンロード
UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	BUF *buf;
	char *filename = NULL;
	char *server_name;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_LogFileGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"SERVER", NULL, NULL, NULL, NULL},
		{"SAVEPATH", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamStr(o, "SAVE");

	c->Write(c, _UU("CMD_LogFileGet_START"));

	server_name = GetParamStr(o, "SERVER");

	buf = DownloadFileFromServer(ps->Rpc, server_name,
		GetParamStr(o, "[name]"), 0, NULL, NULL);

	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_LogFileGet_FAILED"));

		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		if (IsEmptyStr(filename) == false)
		{
			// ファイルに保存
			if (DumpBuf(buf, filename) == false)
			{
				ret = ERR_INTERNAL_ERROR;
				c->Write(c, _UU("CMD_LogFileGet_SAVE_FAILED"));
			}
		}
		else
		{
			// 画面に表示
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *uni_buf;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileGet_FILESIZE"),
				buf->Size);
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)buf->Buf, buf->Size);
			uni_buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(uni_buf, buf_size, (BYTE *)buf->Buf, buf->Size);

			c->Write(c, uni_buf);
			c->Write(c, L"");

			Free(uni_buf);
		}

		FreeBuf(buf);
	}

	FreeParamValueList(o);

	return ret;
}

// 新しい仮想 HUB の作成
UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	UINT hub_type = HUB_TYPE_STANDALONE;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	else
	{
		RPC_SERVER_INFO t;
		Zero(&t, sizeof(t));
		if (ScGetServerInfo(ps->Rpc, &t) == ERR_NO_ERROR)
		{
			if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
			{
				hub_type = HUB_TYPE_FARM_DYNAMIC;
			}
			FreeRpcServerInfo(&t);
		}
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = hub_type;

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Hash(t.HashedPassword, pass, StrLen(pass), true);
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	// RPC 呼び出し
	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 新しい仮想 HUB の作成 (ダイナミックモード)
UINT PsHubCreateDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	UINT hub_type = HUB_TYPE_FARM_DYNAMIC;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = hub_type;

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Hash(t.HashedPassword, pass, StrLen(pass), true);
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	// RPC 呼び出し
	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 新しい仮想 HUB の作成 (スタティックモード)
UINT PsHubCreateStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	UINT hub_type = HUB_TYPE_FARM_STATIC;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = hub_type;

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Hash(t.HashedPassword, pass, StrLen(pass), true);
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	// RPC 呼び出し
	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の削除
UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_HUB t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_HubDelete_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScDeleteHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB をスタティックにする
UINT PsHubSetStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_HubChange_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	// まず現在の設定を取得する
	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 設定を変更する
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = HUB_TYPE_FARM_STATIC;

	// 書き込む
	ret = ScSetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の種類をダイナミック仮想 HUB に変更
UINT PsHubSetDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_HubChange_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	// まず現在の設定を取得する
	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 設定を変更する
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = HUB_TYPE_FARM_DYNAMIC;

	// 書き込む
	ret = ScSetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の一覧の取得
UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_HUB t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScEnumHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_7"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_8"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_9"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_10"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_11"), false);

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

			CtInsert(ct,
				name,
				e->Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"),
				GetHubTypeStr(e->HubType),
				s1, s2, s3, s4, s5, s6, s7, s8);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumHub(&t);

	FreeParamValueList(o);

	return 0;
}

// 管理する仮想 HUB の選択
UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "[name]")) == false)
	{
		wchar_t tmp[MAX_SIZE];
		Zero(&t, sizeof(t));

		// 指定した仮想 HUB にアクセスできるかどうか調べる
		StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

		// RPC 呼び出し
		ret = ScGetHubStatus(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		// 選択を変更する
		if (ps->HubName != NULL)
		{
			Free(ps->HubName);
		}
		ps->HubName = CopyStr(t.HubName);

		UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);
		c->Write(c, tmp);
	}
	else
	{
		// 選択を解除する
		if (ps->HubName != NULL)
		{
			c->Write(c, _UU("CMD_Hub_Unselected"));
			Free(ps->HubName);
		}
		ps->HubName = NULL;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB をオンラインにする
UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Online = true;

	// RPC 呼び出し
	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB をオフラインにする
UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Online = false;

	// RPC 呼び出し
	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の最大同時接続セッション数を設定する
UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[max_session]", CmdPrompt, _UU("CMD_SetMaxSession_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 現在の仮想 HUB の設定を取得
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.MaxSession = GetParamInt(o, "[max_session]");

	// 仮想 HUB の設定を書き込み
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の管理パスワードを設定する
UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pw;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 現在の仮想 HUB の設定を取得
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 設定の変更
	pw = GetParamStr(o, "[password]");
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pw);
	Hash(t.HashedPassword, pw, StrLen(pw), true);

	// 仮想 HUB の設定を書き込み
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の匿名ユーザーへの列挙の許可設定
UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 現在の仮想 HUB の設定を取得
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = false;

	// 仮想 HUB の設定を書き込み
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の匿名ユーザーへの列挙の禁止設定
UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 現在の仮想 HUB の設定を取得
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = true;

	// 仮想 HUB の設定を書き込み
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB のオプション設定の取得
UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct;
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), _UU("CMD_OptionsGet_TITLE"), ps->HubName);
		c->Write(c, tmp);

		// 設定の表示
		ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_OptionsGet_ENUM"),
			t.HubOption.NoEnum ? _UU("CMD_MSG_DENY") : _UU("CMD_MSG_ALLOW"));

		if (t.HubOption.MaxSession == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		else
		{
			UniToStru(tmp, t.HubOption.MaxSession);
		}
		CtInsert(ct, _UU("CMD_OptionsGet_MAXSESSIONS"), tmp);

		CtInsert(ct, _UU("CMD_OptionsGet_STATUS"), t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		CtInsert(ct, _UU("CMD_OptionsGet_TYPE"), GetHubTypeStr(t.HubType));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// ユーザー認証に使用する Radius サーバーの設定
UINT PsRadiusServerSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RADIUS t;
	char *host;
	UINT port;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_RadiusServerSet_EVAL_NUMINTERVAL", RADIUS_RETRY_INTERVAL, RADIUS_RETRY_TIMEOUT,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[server_name:port]", CmdPrompt, _UU("CMD_RadiusServerSet_Prompt_Host"), CmdEvalNotEmpty, NULL},
		{"SECRET", CmdPromptChoosePassword, _UU("CMD_RadiusServerSet_Prompt_Secret"), NULL, NULL},
		{"RETRY_INTERVAL", CmdPrompt, _UU("CMD_RadiusServerSet_Prompt_RetryInterval"), CmdEvalMinMax, &minmax},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (ParseHostPort(GetParamStr(o, "[server_name:port]"), &host, &port, 1812))
	{
		Zero(&t, sizeof(t));

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
		t.RadiusPort = port;
		StrCpy(t.RadiusServerName, sizeof(t.RadiusServerName), host);
		StrCpy(t.RadiusSecret, sizeof(t.RadiusSecret), GetParamStr(o, "SECRET"));
		t.RadiusRetryInterval = GetParamInt(o, "RETRY_INTERVAL");

		Free(host);

		// RPC 呼び出し
		ret = ScSetHubRadius(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// ユーザー認証に使用する Radius サーバー設定の削除
UINT PsRadiusServerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RADIUS t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.RadiusPort = 1812;

	// RPC 呼び出し
	ret = ScSetHubRadius(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// ユーザー認証に使用する Radius サーバー設定の取得
UINT PsRadiusServerGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RADIUS t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubRadius(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct;
		wchar_t tmp[MAX_SIZE];

		ct = CtNewStandard();

		if (IsEmptyStr(t.RadiusServerName))
		{
			CtInsert(ct, _UU("CMD_RadiusServerGet_STATUS"), _UU("CMD_MSG_DISABLE"));
		}
		else
		{
			CtInsert(ct, _UU("CMD_RadiusServerGet_STATUS"), _UU("CMD_MSG_ENABLE"));

			StrToUni(tmp, sizeof(tmp), t.RadiusServerName);
			CtInsert(ct, _UU("CMD_RadiusServerGet_HOST"), tmp);

			UniToStri(tmp, t.RadiusPort);
			CtInsert(ct, _UU("CMD_RadiusServerGet_PORT"), tmp);

			StrToUni(tmp, sizeof(tmp), t.RadiusSecret);
			CtInsert(ct, _UU("CMD_RadiusServerGet_SECRET"), tmp);

			UniToStri(tmp, t.RadiusRetryInterval);
			CtInsert(ct, _UU("CMD_RadiusServerGet_RetryInterval"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB の現在の状況の取得
UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		wchar_t *s;
		wchar_t tmp[MAX_SIZE];

		// HUB 名
		s = CopyStrToUni(t.HubName);
		CtInsert(ct, _UU("SM_HUB_STATUS_HUBNAME"), s);
		Free(s);

		// オンライン
		CtInsert(ct, _UU("SM_HUB_STATUS_ONLINE"),
			t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		// HUB の種類
		CtInsert(ct, _UU("SM_HUB_TYPE"),
			GetHubTypeStr(t.HubType));

		if (t.HubType == HUB_TYPE_STANDALONE)
		{
			// SecureNAT の有効/無効
			CtInsert(ct, _UU("SM_HUB_SECURE_NAT"),
				t.SecureNATEnabled ? _UU("SM_HUB_SECURE_NAT_YES") : _UU("SM_HUB_SECURE_NAT_NO"));
		}

		// その他の値
		UniToStru(tmp, t.NumSessions);
		CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS"), tmp);

		if (t.NumSessionsClient != 0 || t.NumSessionsBridge != 0)
		{
			UniToStru(tmp, t.NumSessionsClient);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_CLIENT"), tmp);
			UniToStru(tmp, t.NumSessionsBridge);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_BRIDGE"), tmp);
		}

		UniToStru(tmp, t.NumAccessLists);
		CtInsert(ct, _UU("SM_HUB_NUM_ACCESSES"), tmp);

		UniToStru(tmp, t.NumUsers);
		CtInsert(ct, _UU("SM_HUB_NUM_USERS"), tmp);
		UniToStru(tmp, t.NumGroups);
		CtInsert(ct, _UU("SM_HUB_NUM_GROUPS"), tmp);

		UniToStru(tmp, t.NumMacTables);
		CtInsert(ct, _UU("SM_HUB_NUM_MAC_TABLES"), tmp);
		UniToStru(tmp, t.NumIpTables);
		CtInsert(ct, _UU("SM_HUB_NUM_IP_TABLES"), tmp);

		// 利用状況
		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_HUB_NUM_LOGIN"), tmp);

		if (t.LastLoginTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastLoginTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_LOGIN_TIME"), tmp);

		if (t.LastCommTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastCommTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_COMM_TIME"), tmp);

		if (t.CreatedTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_CREATED_TIME"), tmp);

		// トラフィック情報
		CmdInsertTrafficInfo(ct, &t.Traffic);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// ログ切り替え文字列の取得
wchar_t *GetLogSwitchStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "SM_LOG_SWITCH_%u", i);

	return _UU(tmp);
}

// パケットログ名文字列の取得
wchar_t *GetPacketLogNameStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "CMD_Log_%u", i);

	return _UU(tmp);
}

// 仮想 HUB のログ保存設定の取得
UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_Log_SecurityLog"),
			t.LogSetting.SaveSecurityLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SaveSecurityLog)
		{
			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.SecurityLogSwitchType));
		}

		CtInsert(ct, L"", L"");

		CtInsert(ct, _UU("CMD_Log_PacketLog"),
			t.LogSetting.SavePacketLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SavePacketLog)
		{
			UINT i;

			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.PacketLogSwitchType));

			for (i = 0;i <= 7;i++)
			{
				wchar_t *tmp = NULL;

				switch (t.LogSetting.PacketLogConfig[i])
				{
				case PACKET_LOG_NONE:
					tmp = _UU("D_SM_LOG@B_PACKET_0_0");
					break;

				case PACKET_LOG_HEADER:
					tmp = _UU("D_SM_LOG@B_PACKET_0_1");
					break;

				case PACKET_LOG_ALL:
					tmp = _UU("D_SM_LOG@B_PACKET_0_2");
					break;
				}

				CtInsert(ct, GetPacketLogNameStr(i),
					tmp);
			}
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// LogEnable コマンド
UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ret;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = true;
	}
	else
	{
		t.LogSetting.SavePacketLog = true;
	}

	// RPC 呼び出し
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// セキュリティ ログまたはパケット ログの無効化
UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = false;
	}
	else
	{
		t.LogSetting.SavePacketLog = false;
	}

	// RPC 呼び出し
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 文字列をログ切り替え種類に変換
UINT StrToLogSwitchType(char *str)
{
	UINT ret = INFINITE;
	// 引数チェック
	if (str == NULL)
	{
		return INFINITE;
	}

	if (IsEmptyStr(str) || StartWith("none", str))
	{
		ret = LOG_SWITCH_NO;
	}
	else if (StartWith("second", str))
	{
		ret = LOG_SWITCH_SECOND;
	}
	else if (StartWith("minute", str))
	{
		ret = LOG_SWITCH_MINUTE;
	}
	else if (StartWith("hour", str))
	{
		ret = LOG_SWITCH_HOUR;
	}
	else if (StartWith("day", str))
	{
		ret = LOG_SWITCH_DAY;
	}
	else if (StartWith("month", str))
	{
		ret = LOG_SWITCH_MONTH;
	}

	return ret;
}

// ログ ファイルの切り替え周期の設定
UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	UINT new_switch_type = 0;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
		{"SWITCH", CmdPrompt, _UU("CMD_LogSwitchSet_Prompt"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}
	
	new_switch_type = StrToLogSwitchType(GetParamStr(o, "SWITCH"));

	if (new_switch_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SecurityLogSwitchType = new_switch_type;
	}
	else
	{
		t.LogSetting.PacketLogSwitchType = new_switch_type;
	}

	// RPC 呼び出し
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// パケットログのパケットの保存内容の文字列を整数に変換
UINT StrToPacketLogSaveInfoType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL)
	{
		return INFINITE;
	}

	if (StartWith("none", str) || IsEmptyStr(str))
	{
		ret = PACKET_LOG_NONE;
	}
	else if (StartWith("header", str))
	{
		ret = PACKET_LOG_HEADER;
	}
	else if (StartWith("full", str) || StartWith("all", str))
	{
		ret = PACKET_LOG_ALL;
	}

	return ret;
}

// パケットログのパケットの種類の文字列を整数に変換
UINT StrToPacketLogType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL || IsEmptyStr(str))
	{
		return INFINITE;
	}

	if (StartWith("tcpconn", str))
	{
		ret = PACKET_LOG_TCP_CONN;
	}
	else if (StartWith("tcpdata", str))
	{
		ret = PACKET_LOG_TCP;
	}
	else if (StartWith("dhcp", str))
	{
		ret = PACKET_LOG_DHCP;
	}
	else if (StartWith("udp", str))
	{
		ret = PACKET_LOG_UDP;
	}
	else if (StartWith("icmp", str))
	{
		ret = PACKET_LOG_ICMP;
	}
	else if (StartWith("ip", str))
	{
		ret = PACKET_LOG_IP;
	}
	else if (StartWith("arp", str))
	{
		ret = PACKET_LOG_ARP;
	}
	else if (StartWith("ethernet", str))
	{
		ret = PACKET_LOG_ETHERNET;
	}

	return ret;
}

// パケット ログに保存するパケットの種類と保存内容の設定
UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	UINT packet_type = INFINITE;
	UINT packet_save_info_type = INFINITE;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"TYPE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_TYPE"), NULL, NULL},
		{"SAVE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_SAVE"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	
	packet_type = StrToPacketLogType(GetParamStr(o, "TYPE"));
	packet_save_info_type = StrToPacketLogSaveInfoType(GetParamStr(o, "SAVE"));

	if (packet_type == INFINITE || packet_save_info_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.LogSetting.PacketLogConfig[packet_type] = packet_save_info_type;

	// RPC 呼び出し
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 信頼する証明機関の証明書一覧の取得
UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ENUM_CA t;
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNewStandard();

		for (i = 0;i < t.NumCa;i++)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[64];
			RPC_HUB_ENUM_CA_ITEM *e = &t.Ca[i];

			GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

			UniToStru(tmp2, e->Key);

			CtInsert(ct, _UU("CMD_CAList_COLUMN_ID"), tmp2);
			CtInsert(ct, _UU("CM_CERT_COLUMN_1"), e->SubjectName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_2"), e->IssuerName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_3"), tmp);

			if (i != (t.NumCa - 1))
			{
				CtInsert(ct, L"---", L"---");
			}
		}

		CtFree(ct, c);
	}

	FreeRpcHubEnumCa(&t);

	FreeParamValueList(o);

	return 0;
}

// 信頼する証明機関の証明書の追加
UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ADD_CA t;
	X *x;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", CmdPrompt, _UU("CMD_CAAdd_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToX(GetParamStr(o, "[path]"));

	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_MSG_LOAD_CERT_FAILED"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Cert = x;

	// RPC 呼び出し
	ret = ScAddCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcHubAddCa(&t);

	FreeParamValueList(o);

	return 0;
}

// 信頼する証明機関の証明書の削除
UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_DELETE_CA t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CADelete_PROMPT_ID"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScDeleteCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 信頼する証明機関の証明書の取得
UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_GET_CA t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CAGet_PROMPT_ID"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_CAGet_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScGetCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (XToFile(t.Cert, GetParamStr(o, "SAVECERT"), true))
		{
			// 成功
		}
		else
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MSG_SAVE_CERT_FAILED"));
		}
	}

	FreeRpcHubGetCa(&t);

	FreeParamValueList(o);

	return ret;
}

// カスケード接続一覧の取得
UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LINK t;
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_5"), false);

		for (i = 0;i < t.NumLink;i++)
		{
			RPC_ENUM_LINK_ITEM *e = &t.Links[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];

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

			CtInsert(ct, e->AccountName, tmp4, tmp1, tmp2, tmp3);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLink(&t);

	FreeParamValueList(o);

	return 0;
}

// 新しいカスケード接続の作成
UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	t.Online = false;

	Copy(&t.Policy, GetDefaultPolicy(), sizeof(POLICY));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));
	t.ClientOption->NumRetry = INFINITE;
	t.ClientOption->RetryInterval = 15;
	t.ClientOption->MaxConnection = 8;
	t.ClientOption->UseEncrypt = true;
	t.ClientOption->AdditionalConnectionInterval = 1;
	t.ClientOption->RequireBridgeRoutingMode = true;

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

	Free(host);

	// RPC 呼び出し
	ret = ScCreateLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の接続先とユーザー名の設定
UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		Free(host);
		return ret;
	}

	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));

	Free(host);

	// RPC 呼び出し
	ret = ScSetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// プロキシの種類文字列の取得
wchar_t *GetProxyTypeStr(UINT i)
{
	switch (i)
	{
	case PROXY_DIRECT:

		return _UU("PROTO_DIRECT_TCP");

	case PROXY_HTTP:
		return _UU("PROTO_HTTP_PROXY");

	case PROXY_SOCKS:
		return _UU("PROTO_SOCKS_PROXY");

	default:
		return _UU("PROTO_UNKNOWN");
	}
}

// クライアントのユーザー認証の種類文字列の取得
wchar_t *GetClientAuthTypeStr(UINT i)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "PW_TYPE_%u", i);

	return _UU(tmp);
}

// カスケード接続の設定の取得
UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
		GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// 接続設定の内容を表示
		wchar_t tmp[MAX_SIZE];

		CT *ct = CtNewStandard();

		// 接続設定名
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NAME"), t.ClientOption->AccountName);

		// 接続先 VPN Server のホスト名
		StrToUni(tmp, sizeof(tmp), t.ClientOption->Hostname);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HOSTNAME"), tmp);

		// 接続先 VPN Server のポート番号
		UniToStru(tmp, t.ClientOption->Port);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PORT"), tmp);

		// 接続先 VPN Server の仮想 HUB 名
		StrToUni(tmp, sizeof(tmp), t.ClientOption->HubName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HUBNAME"), tmp);

		// 経由するプロキシ サーバーの種類
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_TYPE"), GetProxyTypeStr(t.ClientOption->ProxyType));

		if (t.ClientOption->ProxyType != PROXY_DIRECT)
		{
			// プロキシ サーバーのホスト名
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyName);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_HOSTNAME"), tmp);

			// プロキシ サーバーのポート番号
			UniToStru(tmp, t.ClientOption->ProxyPort);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_PORT"), tmp);

			// プロキシ サーバーのユーザー名
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyUsername);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_USERNAME"), tmp);
		}

		// サーバー証明書の検証
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_USE"),
			t.CheckServerCert ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// 登録されている固有証明書
		if (t.ServerCert != NULL)
		{
			GetAllNameFromX(tmp, sizeof(tmp), t.ServerCert);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_NAME"), tmp);
		}

		// 接続に使用するデバイス名
		StrToUni(tmp, sizeof(tmp), t.ClientOption->DeviceName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_DEVICE_NAME"), tmp);

		// 認証の種類
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_TYPE"), GetClientAuthTypeStr(t.ClientAuth->AuthType));

		// ユーザー名
		StrToUni(tmp, sizeof(tmp), t.ClientAuth->Username);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_USERNAME"), tmp);

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (t.ClientAuth->ClientX != NULL)
			{
				// クライアント証明書名
				GetAllNameFromX(tmp, sizeof(tmp), t.ClientAuth->ClientX);
				CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_CERT_NAME"), tmp);
			}
		}

		// VPN 通信に使用する TCP コネクション数
		UniToStru(tmp, t.ClientOption->MaxConnection);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NUMTCP"), tmp);

		// 各 TCP コネクションの確立間隔
		UniToStru(tmp, t.ClientOption->AdditionalConnectionInterval);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_INTERVAL"), tmp);

		// 各 TCP コネクションの寿命
		if (t.ClientOption->ConnectionDisconnectSpan != 0)
		{
			UniToStru(tmp, t.ClientOption->ConnectionDisconnectSpan);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_TTL"), tmp);

		// 半二重モードの使用
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_HALF"),
			t.ClientOption->HalfConnection ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// SSL による暗号化
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ENCRYPT"),
			t.ClientOption->UseEncrypt ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// データ圧縮
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_COMPRESS"),
			t.ClientOption->UseCompress ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// ブリッジ / ルータモードで接続
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_BRIDGE_ROUTER"),
			t.ClientOption->RequireBridgeRoutingMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// モニタリングモードで接続
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_MONITOR"),
			t.ClientOption->RequireMonitorMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// ルーティング テーブルを書き換えない
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NO_TRACKING"),
			t.ClientOption->NoRoutingTracking ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// QoS制御を無効化する
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_QOS_DISABLE"),
			t.ClientOption->DisableQoS ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtFree(ct, c);

		// セキュリティ ポリシー
		c->Write(c, L"");
		c->Write(c, _UU("CMD_CascadeGet_Policy"));
		PrintPolicy(c, &t.Policy, true);
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の削除
UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScDeleteLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の接続に使用するユーザー名の設定
UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// カスケード接続の設定の変更
		StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username),
			GetParamStr(o, "USERNAME"));

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
		{
			c->Write(c, _UU("CMD_CascadeUsername_Notice"));
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

//カスケード接続のユーザー認証の種類を匿名認証に設定
UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// カスケード接続の設定の変更
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のユーザー認証の種類をパスワード認証に設定
UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"TYPE", CmdPrompt, _UU("CMD_CascadePasswordSet_Prompt_Type"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// カスケード接続の設定の変更
		char *typestr = GetParamStr(o, "TYPE");

		if (StartWith("standard", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
			HashPassword(t.ClientAuth->HashedPassword, t.ClientAuth->Username,
				GetParamStr(o, "PASSWORD"));
		}
		else if (StartWith("radius", typestr) || StartWith("ntdomain", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;

			StrCpy(t.ClientAuth->PlainPassword, sizeof(t.ClientAuth->PlainPassword),
				GetParamStr(o, "PASSWORD"));
		}
		else
		{
			// エラー発生
			c->Write(c, _UU("CMD_CascadePasswordSet_Type_Invalid"));
			FreeRpcCreateLink(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のユーザー認証の種類をクライアント証明書認証に設定
UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	K *k;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (CmdLoadCertAndKey(c, &x, &k, GetParamStr(o, "LOADCERT"), GetParamStr(o, "LOADKEY")) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		FreeX(x);
		FreeK(k);
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// 認証データ変更
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_CERT;
		if (t.ClientAuth->ClientX != NULL)
		{
			FreeX(t.ClientAuth->ClientX);
		}
		if (t.ClientAuth->ClientK != NULL)
		{
			FreeK(t.ClientAuth->ClientK);
		}

		t.ClientAuth->ClientX = x;
		t.ClientAuth->ClientK = k;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続に用いるクライアント証明書の取得
UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.ClientAuth->AuthType != CLIENT_AUTHTYPE_CERT)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Not_Auth_Cert"));
			ret = ERR_INTERNAL_ERROR;
		}
		else if (t.ClientAuth->ClientX == NULL)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Cert_Not_Exists"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			XToFile(t.ClientAuth->ClientX, GetParamStr(o, "SAVECERT"), true);
		}
		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// カスケード接続の通信時の暗号化の有効化
UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.ClientOption->UseEncrypt = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の通信時の暗号化の無効化
UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.ClientOption->UseEncrypt = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の通信時のデータ圧縮の有効化
UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.ClientOption->UseCompress = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の通信時のデータ圧縮の無効化
UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.ClientOption->UseCompress = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の接続方法を直接 TCP/IP 接続に設定
UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.ClientOption->ProxyType = PROXY_DIRECT;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の接続方法を HTTP プロキシサーバー経由接続に設定
UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// データ変更
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 8080))
		{
			t.ClientOption->ProxyType = PROXY_HTTP;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の接続方法を SOCKS プロキシサーバー経由接続に設定
UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// データ変更
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 8080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のサーバー証明書の検証オプションの有効化
UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.CheckServerCert = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のサーバー証明書の検証オプションの無効化
UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.CheckServerCert = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のサーバー固有証明書の設定
UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToX(GetParamStr(o, "LOADCERT"));
	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}
	else
	{
		// データ変更
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = x;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のサーバー固有証明書の削除
UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のサーバー固有証明書の取得
UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// 証明書保存
		if (t.ServerCert == NULL)
		{
			c->Write(c, _UU("CMD_CERT_NOT_EXISTS"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			if (XToFile(t.ServerCert, GetParamStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
				ret = ERR_INTERNAL_ERROR;
			}
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// カスケード接続の高度な通信設定の設定
UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	CMD_EVAL_MIN_MAX mm_maxtcp =
	{
		"CMD_CascadeDetailSet_Eval_MaxTcp", 1, 32
	};
	CMD_EVAL_MIN_MAX mm_interval =
	{
		"CMD_CascadeDetailSet_Eval_Interval", 1, 4294967295UL
	};
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"MAXTCP", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_MaxTcp"), CmdEvalMinMax, &mm_maxtcp},
		{"INTERVAL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_Interval"), CmdEvalMinMax, &mm_interval},
		{"TTL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_TTL"), NULL, NULL},
		{"HALF", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_HALF"), NULL, NULL},
		{"NOQOS", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOQOS"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// データ変更
		t.ClientOption->MaxConnection = GetParamInt(o, "MAXTCP");
		t.ClientOption->AdditionalConnectionInterval = GetParamInt(o, "INTERVAL");
		t.ClientOption->ConnectionDisconnectSpan = GetParamInt(o, "TTL");
		t.ClientOption->HalfConnection = GetParamYes(o, "HALF");
		t.ClientOption->DisableQoS = GetParamYes(o, "NOQOS");

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// セキュリティ ポリシーを表示
void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode)
{
	UINT i;
	CT *ct;
	PACK *p;
	// 引数チェック
	if (c == NULL || pol == NULL)
	{
		return;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_3"), false);

	p = NewPack();
	OutRpcPolicy(p, pol);

	// すべてのポリシー一覧を表示する
	for (i = 0; i < PolicyNum();i++)
	{
		char name[64];
		wchar_t *tmp;

		if (cascade_mode == false || PolicyIsSupportedForCascade(i))
		{
			wchar_t value_str[256];
			UINT value;
			char tmp2[256];

			Format(tmp2, sizeof(tmp2), "policy:%s", PolicyIdToStr(i));
			value = PackGetInt(p, tmp2);

			tmp = CopyStrToUni(PolicyIdToStr(i));

			FormatPolicyValue(value_str, sizeof(value_str),
				i, value);

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name), value_str);

			Free(tmp);
		}
	}

	FreePack(p);

	CtFree(ct, c);
}

// セキュリティ ポリシー リストを表示
void PrintPolicyList(CONSOLE *c, char *name)
{
	UINT id;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}
	if (IsEmptyStr(name))
	{
		name = NULL;
	}

	if (name != NULL)
	{
		id = PolicyStrToId(name);
		if (id == INFINITE)
		{
			// 不正な ID
			c->Write(c, _UU("CMD_PolicyList_Invalid_Name"));
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			char name1[64], name2[64];
			wchar_t *title, *descript;
			wchar_t policy_name[MAX_SIZE];

			Format(name1, sizeof(name1), "POL_%u", id);
			Format(name2, sizeof(name2), "POL_EX_%u", id);

			title = _UU(name1);
			descript = _UU(name2);

			StrToUni(policy_name, sizeof(policy_name), PolicyIdToStr(id));

			// ポリシー名
			c->Write(c, _UU("CMD_PolicyList_Help_1"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", policy_name);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// ポリシーの簡易説明
			c->Write(c, _UU("CMD_PolicyList_Help_2"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", title);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// 設定できる値の範囲
			GetPolicyValueRangeStr(tmp, sizeof(tmp), id);
			c->Write(c, _UU("CMD_PolicyList_Help_3"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// デフォルト値
			FormatPolicyValue(tmp, sizeof(tmp), id, GetPolicyItem(id)->DefaultValue);
			c->Write(c, _UU("CMD_PolicyList_Help_4"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// ポリシーの詳細説明
			c->Write(c, _UU("CMD_PolicyList_Help_5"));
			c->Write(c, descript);
			c->Write(c, L"");
		}
	}
	else
	{
		UINT i;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);

		// すべてのポリシー一覧を表示する
		for (i = 0; i < PolicyNum();i++)
		{
			char name[64];
			wchar_t *tmp;

			tmp = CopyStrToUni(PolicyIdToStr(i));

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name));

			Free(tmp);
		}

		CtFree(ct, c);
	}
}

// ポリシーの内容の編集
bool EditPolicy(CONSOLE *c, POLICY *pol, char *name, char *value, bool cascade_mode)
{
	PACK *p;
	ELEMENT *e;
	POLICY_ITEM *item;
	UINT id;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char pack_name[128];
	// 引数チェック
	if (c == NULL || pol == NULL || name == NULL || value == NULL)
	{
		return false;
	}

	p = NewPack();

	OutRpcPolicy(p, pol);

	Format(pack_name, sizeof(pack_name), "policy:%s", PolicyIdToStr(PolicyStrToId(name)));

	if ((e = GetElement(p, pack_name, VALUE_INT)) == NULL || (id = PolicyStrToId(name)) == INFINITE)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	if (cascade_mode && (PolicyIsSupportedForCascade(id) == false))
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name_For_Cadcade"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	item = GetPolicyItem(id);

	if (item->TypeInt == false)
	{
		// bool 型
		e->values[0]->IntValue = (
			StartWith(value, "y") || StartWith(value, "t") ||
			ToInt(value) != 0) ? 1 : 0;
	}
	else
	{
		UINT n = ToInt(value);
		bool b = true;

		// int 型
		GetPolicyValueRangeStr(tmp, sizeof(tmp), id);

		if (item->AllowZero == false)
		{
			if (n == 0)
			{
				b = false;
			}
		}

		if (n != 0 && (n < item->MinValue || n > item->MaxValue))
		{
			b = false;
		}

		if (b == false)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("CMD_CascadePolicySet_Invalid_Range"), PolicyIdToStr(id), tmp);
			c->Write(c, tmp2);
			FreePack(p);
			return false;
		}

		e->values[0]->IntValue = n;
	}

	Zero(pol, sizeof(POLICY));

	InRpcPolicy(pol, p);

	FreePack(p);

	return true;
}

// セキュリティ ポリシーの種類と設定可能値の一覧を表示
UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", NULL, NULL, NULL, NULL}
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	PrintPolicyList(c, GetParamStr(o, "[name]"));

	FreeParamValueList(o);

	return ERR_NO_ERROR;
}

// カスケード接続セッションのセキュリティ ポリシーの設定
UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (EditPolicy(c, &t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), true) == false)
		{
			// エラー発生
			FreeRpcCreateLink(&t);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// セッションのステータス情報の表示
void CmdPrintStatusToListView(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s)
{
	CmdPrintStatusToListViewEx(ct, s, false);
}
void CmdPrintStatusToListViewEx(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	char vv[128];
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (server_mode == false)
	{
		CtInsert(ct, _UU("CM_ST_ACCOUNT_NAME"), s->AccountName);

		if (s->Connected == false)
		{
			wchar_t *st = _UU("CM_ST_CONNECTED_FALSE");
			switch (s->SessionStatus)
			{
			case CLIENT_STATUS_CONNECTING:
				st = _UU("CM_ST_CONNECTING");
				break;
			case CLIENT_STATUS_NEGOTIATION:
				st = _UU("CM_ST_NEGOTIATION");
				break;
			case CLIENT_STATUS_AUTH:
				st = _UU("CM_ST_AUTH");
				break;
			case CLIENT_STATUS_ESTABLISHED:
				st = _UU("CM_ST_ESTABLISHED");
				break;
			case CLIENT_STATUS_RETRY:
				st = _UU("CM_ST_RETRY");
				break;
			case CLIENT_STATUS_IDLE:
				st = _UU("CM_ST_IDLE");
				break;
			}
			CtInsert(ct, _UU("CM_ST_CONNECTED"), st);
		}
		else
		{
			CtInsert(ct, _UU("CM_ST_CONNECTED"), _UU("CM_ST_CONNECTED_TRUE"));
		}
	}

	if (s->Connected)
	{
		if (s->VLanId == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_NO_VLAN"));
		}
		else
		{
			UniToStru(tmp, s->VLanId);
		}

		CtInsert(ct, _UU("CM_ST_VLAN_ID"), tmp);

		if (server_mode == false)
		{
			StrToUni(tmp, sizeof(tmp), s->ServerName);
			CtInsert(ct, _UU("CM_ST_SERVER_NAME"), tmp);

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_PORT_TCP"), s->ServerPort);
			CtInsert(ct, _UU("CM_ST_SERVER_PORT"), tmp);
		}

		StrToUni(tmp, sizeof(tmp), s->ServerProductName);
		CtInsert(ct, _UU("CM_ST_SERVER_P_NAME"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", s->ServerProductVer / 100, s->ServerProductVer % 100);
		CtInsert(ct, _UU("CM_ST_SERVER_P_VER"), tmp);
		UniFormat(tmp, sizeof(tmp), L"Build %u", s->ServerProductBuild);
		CtInsert(ct, _UU("CM_ST_SERVER_P_BUILD"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->StartTime), NULL);
	CtInsert(ct, _UU("CM_ST_START_TIME"), tmp);
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->FirstConnectionEstablisiedTime), NULL);
	CtInsert(ct, _UU("CM_ST_FIRST_ESTAB_TIME"), s->FirstConnectionEstablisiedTime == 0 ? _UU("CM_ST_NONE") : tmp);

	if (s->Connected)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->CurrentConnectionEstablishTime), NULL);
		CtInsert(ct, _UU("CM_ST_CURR_ESTAB_TIME"), tmp);
	}

	if (server_mode == false)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_STR"), s->NumConnectionsEatablished);
		CtInsert(ct, _UU("CM_ST_NUM_ESTABLISHED"), tmp);
	}

	if (s->Connected)
	{
		CtInsert(ct, _UU("CM_ST_HALF_CONNECTION"), s->HalfConnection ? _UU("CM_ST_HALF_TRUE") : _UU("CM_ST_HALF_FALSE"));

		CtInsert(ct, _UU("CM_ST_QOS"), s->QoS ? _UU("CM_ST_QOS_TRUE") : _UU("CM_ST_QOS_FALSE"));

		UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnections);
		CtInsert(ct, _UU("CM_ST_NUM_TCP"), tmp);

		if (s->HalfConnection)
		{
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsUpload);
			CtInsert(ct, _UU("CM_ST_NUM_TCP_UPLOAD"), tmp);
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsDownload);
			CtInsert(ct, _UU("CM_ST_NUM_TCP_DOWNLOAD"), tmp);
		}

		UniFormat(tmp, sizeof(tmp), L"%u", s->MaxTcpConnections);
		CtInsert(ct, _UU("CM_ST_MAX_TCP"), tmp);

		if (s->UseEncrypt == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_FALSE"));
		}
		else
		{
			if (StrLen(s->CipherName) != 0)
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE"), s->CipherName);
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE2"));
			}
		}
		CtInsert(ct, _UU("CM_ST_USE_ENCRYPT"), tmp);

		if (s->UseCompress)
		{
			UINT percent = 0;
			if ((s->TotalRecvSize + s->TotalSendSize) > 0)
			{
				percent = (UINT)((UINT64)100 - (UINT64)(s->TotalRecvSizeReal + s->TotalSendSizeReal) * (UINT64)100 /
					(s->TotalRecvSize + s->TotalSendSize));
				percent = MAKESURE(percent, 0, 100);
			}

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_TRUE"), percent);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_FALSE"));
		}
		CtInsert(ct, _UU("CM_ST_USE_COMPRESS"), tmp);

		StrToUni(tmp, sizeof(tmp), s->SessionName);
		CtInsert(ct, _UU("CM_ST_SESSION_NAME"), tmp);

		StrToUni(tmp, sizeof(tmp), s->ConnectionName);
		if (UniStrCmpi(tmp, L"INITING") != 0)
		{
			CtInsert(ct, _UU("CM_ST_CONNECTION_NAME"), tmp);
		}

		BinToStr(str, sizeof(str), s->SessionKey, sizeof(s->SessionKey));
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("CM_ST_SESSION_KEY"), tmp);

		CtInsert(ct, _UU("CM_ST_BRIDGE_MODE"), s->IsBridgeMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		CtInsert(ct, _UU("CM_ST_MONITOR_MODE"), s->IsMonitorMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		ToStr3(vv, sizeof(vv), s->TotalSendSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->TotalRecvSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_BCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_BCAST_SIZE"), tmp);
	}
}

// カスケード接続の現在の状態の取得
UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK_STATUS t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetLinkStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// カスケード接続状態の取得
		CT *ct = CtNewStandard();

		CmdPrintStatusToListView(ct, &t.Status);

		CtFree(ct, c);

		FreeRpcLinkStatus(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続の名前の変更
UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RENAME_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_OLD"), CmdEvalNotEmpty, NULL},
		{"NEW", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_NEW"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	UniStrCpy(t.NewAccountName, sizeof(t.NewAccountName), GetParamUniStr(o, "NEW"));
	UniStrCpy(t.OldAccountName, sizeof(t.OldAccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScRenameLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のオンライン状態への設定
UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScSetLinkOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// カスケード接続のオフライン状態への設定
UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScSetLinkOffline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 文字列を pass/discard に変換
bool StrToPassOrDiscard(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	if (ToInt(str) != 0)
	{
		return true;
	}

	if (StartWith(str, "p") || StartWith(str, "y") || StartWith(str, "t"))
	{
		return true;
	}

	return false;
}

// 文字列をプロトコルに変換
UINT StrToProtocol(char *str)
{
	if (IsEmptyStr(str))
	{
		return 0;
	}

	if (StartWith("ip", str))
	{
		return 0;
	}
	else if (StartWith("tcp", str))
	{
		return IP_PROTO_TCP;
	}
	else if (StartWith("udp", str))
	{
		return IP_PROTO_UDP;
	}
	else if (StartWith("icmpv4", str))
	{
		return IP_PROTO_ICMPV4;
	}
	else if (StartWith("icmpv6", str))
	{
		return IP_PROTO_ICMPV6;
	}

	if (ToInt(str) == 0)
	{
		if (StrCmpi(str, "0") == 0)
		{
			return 0;
		}
		else
		{
			return INFINITE;
		}
	}

	if (ToInt(str) >= 256)
	{
		return INFINITE;
	}

	return ToInt(str);
}

// プロトコル名のチェック
bool CmdEvalProtocol(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (StrToProtocol(tmp) == INFINITE)
	{
		c->Write(c, _UU("CMD_PROTOCOL_EVAL_FAILED"));
		return false;
	}

	return true;
}

// ポート範囲のパース
bool ParsePortRange(char *str, UINT *start, UINT *end)
{
	UINT a = 0, b = 0;
	TOKEN_LIST *t;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	if (IsEmptyStr(str) == false)
	{

		t = ParseToken(str, "\t -");

		if (t->NumTokens == 1)
		{
			a = b = ToInt(t->Token[0]);
		}
		else if (t->NumTokens == 2)
		{
			a = ToInt(t->Token[0]);
			b = ToInt(t->Token[1]);
		}

		FreeToken(t);

		if (a > b)
		{
			return false;
		}

		if (a >= 65536 || b >= 65536)
		{
			return false;
		}

		if (a == 0 && b != 0)
		{
			return false;
		}
	}

	if (start != NULL)
	{
		*start = a;
	}
	if (end != NULL)
	{
		*end = b;
	}

	return true;
}

// ポート範囲のチェック
bool CmdEvalPortRange(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParsePortRange(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_PORT_RANGE_EVAL_FAILED"));
		return false;
	}

	return true;
}

// MAC アドレスとマスクのパース
bool ParseMacAddressAndMask(char *src, bool *check_mac, UCHAR *mac_bin, UCHAR *mask_bin)
{
	TOKEN_LIST *t;
	char *macstr, *maskstr;
	UCHAR mac[6], mask[6];
	bool ok = false;

	// 引数チェック
	if (src == NULL)
	{
		return false;
	}

	//Zero(mac, sizeof(mac));
	//Zero(mask, sizeof(mask));

	if(check_mac != NULL && mac_bin != NULL && mask_bin != NULL)
	{
		ok = true;
	}
	if(IsEmptyStr(src) != false)
	{
		if(ok != false)
		{
			*check_mac = false;
			Zero(mac_bin, 6);
			Zero(mask_bin, 6);
		}
		return true;
	}

	t = ParseToken(src, "/");
	if(t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	macstr = t->Token[0];
	maskstr = t->Token[1];

	Trim(macstr);
	Trim(maskstr);

	if(StrToMac(mac, macstr) == false || StrToMac(mask, maskstr) == false)
	{
		FreeToken(t);
		return false;
	}
	else
	{
		if(ok != false)
		{
			Copy(mac_bin, mac, 6);
			Copy(mask_bin, mask, 6);
			*check_mac = true;
		}
	}
	FreeToken(t);

	return true;
}

// MAC アドレスとマスクのチェック
bool CmdEvalMacAddressAndMask(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// 引数チェック
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);


	if(ParseMacAddressAndMask(tmp, NULL, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_MAC_ADDRESS_AND_MASK_EVAL_FAILED"));
		return false;
	}

	return true;
}
// TCP コネクションの状態パース
bool ParseTcpState(char *src, bool *check_tcp_state, bool *established)
{
	bool ok = false;
	// 引数チェック
	if(src == NULL)
	{
		return false;
	}

	if(check_tcp_state != NULL && established != NULL)
	{
		ok = true;
	}

	if (IsEmptyStr(src) == false)
	{
		if (StartWith("Established", src) == 0)
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = true;
			}
		}
		else if (StartWith("Unestablished", src) == 0)
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = false;
			}
		}
		else
		{
			// 不正な文字列
			return false;
		}
	}
	else
	{
		if(ok != false)
		{
			*check_tcp_state = false;
			*established = false;
		}
	}

	return true;
}
// TCP コネクションの状態チェック
bool CmdEvalTcpState(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// 引数チェック
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if(ParseTcpState(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_TCP_CONNECTION_STATE_EVAL_FAILED"));
		return false;
	}

	return true;
}

// アクセス リストへのルールの追加 (標準、IPv4)
UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	// RPC 呼び出し
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// アクセス リストへのルールの追加 (拡張、IPv4)
UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// サポートしているかどうかチェック
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");

	// RPC 呼び出し
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// アクセス リストへのルールの追加 (標準、IPv6)
UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// サポートしているかどうかチェック
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	// RPC 呼び出し
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// アクセス リストへのルールの追加 (拡張、IPv6)
UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx6_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx6_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx6_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// サポートしているかどうかチェック
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");

	// RPC 呼び出し
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}


// アクセス リストのルール一覧の取得
UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	CT *ct;
	UINT i;
	
	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_0"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_1"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_2"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_3"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_5"), false);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_4"), false);

	for (i = 0;i < t.NumAccess;i++)
	{
		ACCESS *a = &t.Accesses[i];
		char tmp[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];

		GetAccessListStr(tmp, sizeof(tmp), a);
		UniToStru(tmp1, a->Priority);
		StrToUni(tmp2, sizeof(tmp2), tmp);

		UniToStru(tmp3, a->Id);

		CtInsert(ct,
			tmp3,
			a->Discard ? _UU("SM_ACCESS_DISCARD") : _UU("SM_ACCESS_PASS"),
			a->Active ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"),
			tmp1,
			tmp2,
			a->Note);
	}

	CtFreeEx(ct, c, true);

	FreeRpcEnumAccessList(&t);

	FreeParamValueList(o);

	return 0;
}

// アクセス リストからルールを削除
UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_ACCESS t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Id = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScDeleteAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// アクセス リストのルールの有効化
UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;
		for (i = 0;i < t.NumAccess;i++)
		{
			ACCESS *a = &t.Accesses[i];

			if (a->Id == GetParamInt(o, "[id]"))
			{
				b = true;

				a->Active = true;
			}
		}

		if (b == false)
		{
			// 指定した ID が見つからない
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// アクセス リストのルールの無効化
UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;
		for (i = 0;i < t.NumAccess;i++)
		{
			ACCESS *a = &t.Accesses[i];

			if (a->Id == GetParamInt(o, "[id]"))
			{
				b = true;

				a->Active = false;
			}
		}

		if (b == false)
		{
			// 指定した ID が見つからない
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// ユーザー一覧の取得
UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_USER t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_USER_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_7"), false);

		for (i = 0;i < t.NumUser;i++)
		{
			RPC_ENUM_USER_ITEM *e = &t.Users[i];
			wchar_t name[MAX_SIZE];
			wchar_t group[MAX_SIZE];
			wchar_t num[MAX_SIZE];
			wchar_t time[MAX_SIZE];

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

			CtInsert(ct,
				name, e->Realname, group, e->Note, GetAuthTypeStr(e->AuthType),
				num, time);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザー認証方法の文字列の取得
wchar_t *GetAuthTypeStr(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_AUTHTYPE_%u", id);

	return _UU(tmp);
}

// ユーザーの作成
UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	Trim(t.Name);
	if (StrCmpi(t.Name, "*") == 0)
	{
		t.AuthType = AUTHTYPE_RADIUS;
		t.AuthData = NewRadiusAuthData(NULL);
	}
	else
	{
		UCHAR random_pass[SHA1_SIZE];

		Rand(random_pass, sizeof(random_pass));
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = NewPasswordAuthDataRaw(random_pass);
	}

	// RPC 呼び出し
	ret = ScCreateUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザー情報の変更
UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報を更新する
	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーの削除
UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScDeleteUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// ユーザー情報の取得
UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		// ユーザーデータを表示
		ct = CtNewStandard();

		// ユーザー名
		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_UserGet_Column_Name"), tmp);

		// 本名
		CtInsert(ct, _UU("CMD_UserGet_Column_RealName"), t.Realname);

		// 説明
		CtInsert(ct, _UU("CMD_UserGet_Column_Note"), t.Note);

		// グループ名
		if (IsEmptyStr(t.GroupName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.GroupName);
			CtInsert(ct, _UU("CMD_UserGet_Column_Group"), tmp);
		}

		// 有効期限
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ExpireTime), NULL);
		CtInsert(ct, _UU("CMD_UserGet_Column_Expires"), tmp);

		// 認証方法
		CtInsert(ct, _UU("CMD_UserGet_Column_AuthType"), GetAuthTypeStr(t.AuthType));

		switch (t.AuthType)
		{
		case AUTHTYPE_USERCERT:
			if (t.AuthData != NULL)
			{
				AUTHUSERCERT *auc = (AUTHUSERCERT *)t.AuthData;

				if (auc != NULL && auc->UserX != NULL)
				{
					// 登録済みユーザー固有証明書
					GetAllNameFromX(tmp, sizeof(tmp), auc->UserX);
					CtInsert(ct, _UU("CMD_UserGet_Column_UserCert"), tmp);
				}
			}
			break;

		case AUTHTYPE_ROOTCERT:
			if (t.AuthData != NULL)
			{
				AUTHROOTCERT *arc = (AUTHROOTCERT *)t.AuthData;

				if (IsEmptyUniStr(arc->CommonName) == false)
				{
					// 証明書の CN の値の限定
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_CN"), arc->CommonName);
				}

				if (arc->Serial != NULL && arc->Serial->size >= 1)
				{
					char tmp2[MAX_SIZE];

					// 証明書のシリアル番号の限定
					BinToStrEx(tmp2, sizeof(tmp2), arc->Serial->data, arc->Serial->size);
					StrToUni(tmp, sizeof(tmp), tmp2);
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_SERIAL"), tmp);
				}
			}
			break;

		case AUTHTYPE_RADIUS:
		case AUTHTYPE_NT:
			if (t.AuthData != NULL)
			{
				AUTHRADIUS *ar = (AUTHRADIUS *)t.AuthData;

				// 外部認証サーバーの認証ユーザー名
				if (IsEmptyUniStr(ar->RadiusUsername) == false)
				{
					CtInsert(ct, _UU("CMD_UserGet_Column_RadiusAlias"), ar->RadiusUsername);
				}
			}
			break;
		}

		CtInsert(ct, L"---", L"---");

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_CREATE"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.UpdatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_UPDATE"), tmp);

		CmdInsertTrafficInfo(ct, &t.Traffic);

		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_USERINFO_NUMLOGIN"), tmp);


		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_UserGet_Policy"));
			PrintPolicy(c, t.Policy, false);
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーの認証方法を匿名認証に設定
UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報を更新する
	FreeAuthData(t.AuthType, t.AuthData);

	// 匿名認証に設定する
	t.AuthType = AUTHTYPE_ANONYMOUS;
	t.AuthData = NULL;

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーの認証方法をパスワード認証に設定しパスワードを設定
UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報を更新する
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHPASSWORD *pw;

		pw = NewPasswordAuthData(t.Name, GetParamStr(o, "PASSWORD"));

		// パスワード認証に設定する
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = pw;
	}

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーの認証方法を固有証明書認証に設定し証明書を設定
UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	X *x;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 証明書を読み込む
	x = FileToX(GetParamStr(o, "LOADCERT"));
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));

		FreeParamValueList(o);

		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}

	// 情報を更新する
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHUSERCERT *c;

		c = NewUserCertAuthData(x);

		FreeX(x);

		// パスワード認証に設定する
		t.AuthType = AUTHTYPE_USERCERT;
		t.AuthData = c;
	}

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// 固有証明書認証のユーザーの登録されている証明書の取得
UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	AUTHUSERCERT *a;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	a = (AUTHUSERCERT *)t.AuthData;

	if (t.AuthType != AUTHTYPE_USERCERT || a == NULL || a->UserX == NULL)
	{
		// ユーザーは固有証明書認証ではない
		ret = ERR_INVALID_PARAMETER;

		c->Write(c, _UU("CMD_UserCertGet_Not_Cert"));
	}
	else
	{
		if (XToFile(a->UserX, GetParamStr(o, "SAVECERT"), true) == false)
		{
			c->Write(c, _UU("CMD_SAVECERT_FAILED"));
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

// ユーザーの認証方法を署名済み証明書認証に設定
UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"CN", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_CN"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_SERIAL"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報を更新する
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHROOTCERT *c;
		BUF *b;
		X_SERIAL *serial = NULL;

		b = StrToBin(GetParamStr(o, "SERIAL"));

		if (b != NULL && b->Size >= 1)
		{
			serial = NewXSerial(b->Buf, b->Size);
		}

		FreeBuf(b);

		c = NewRootCertAuthData(serial, GetParamUniStr(o, "CN"));

		FreeXSerial(serial);

		// パスワード認証に設定する
		t.AuthType = AUTHTYPE_ROOTCERT;
		t.AuthData = c;
	}

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーの認証方法を Radius 認証に設定
UINT PsUserRadiusSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"ALIAS", CmdPrompt, _UU("CMD_UserRadiusSet_Prompt_ALIAS"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報を更新する
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHRADIUS *a;

		a = NewRadiusAuthData(GetParamUniStr(o, "ALIAS"));

		// Radius 認証に設定する
		t.AuthType = AUTHTYPE_RADIUS;
		t.AuthData = a;
	}

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーの認証方法を NT ドメイン認証に設定
UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"ALIAS", CmdPrompt, _UU("CMD_UserRadiusSet_Prompt_ALIAS"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報を更新する
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHRADIUS *a;

		a = NewRadiusAuthData(GetParamUniStr(o, "ALIAS"));

		// NT ドメイン認証に設定する
		t.AuthType = AUTHTYPE_NT;
		t.AuthData = a;
	}

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーのセキュリティ ポリシーの削除
UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 更新
	if (t.Policy != NULL)
	{
		Free(t.Policy);
		t.Policy = NULL;
	}

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// ユーザーのセキュリティ ポリシーの設定
UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 更新
	if (t.Policy == NULL)
	{
		t.Policy = ClonePolicy(GetDefaultPolicy());
	}

	// 編集
	if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
	{
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		// ユーザーオブジェクトを書き込み
		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

// 文字列を日時に変換
UINT64 StrToDateTime64(char *str)
{
	UINT64 ret = 0;
	TOKEN_LIST *t;
	UINT a, b, c, d, e, f;
	// 引数チェック
	if (str == NULL)
	{
		return INFINITE;
	}

	if (IsEmptyStr(str) || StrCmpi(str, "none") == 0)
	{
		return 0;
	}

	t = ParseToken(str, ":/,. \"");
	if (t->NumTokens != 6)
	{
		FreeToken(t);
		return INFINITE;
	}

	a = ToInt(t->Token[0]);
	b = ToInt(t->Token[1]);
	c = ToInt(t->Token[2]);
	d = ToInt(t->Token[3]);
	e = ToInt(t->Token[4]);
	f = ToInt(t->Token[5]);

	ret = INFINITE;

	if (a >= 1000 && a <= 9999 && b >= 1 && b <= 12 && c >= 1 && c <= 31 &&
		d >= 0 && d <= 23 && e >= 0 && e <= 59 && f >= 0 && f <= 59)
	{
		SYSTEMTIME t;

		Zero(&t, sizeof(t));
		t.wYear = a;
		t.wMonth = b;
		t.wDay = c;
		t.wHour = d;
		t.wMinute = e;
		t.wSecond = f;

		ret = SystemToUINT64(&t);
	}

	FreeToken(t);

	return ret;
}

// 日時文字列の評価
bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param)
{
	UINT64 ret;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	ret = StrToDateTime64(tmp);

	if (ret == INFINITE)
	{
		c->Write(c, _UU("CMD_EVAL_DATE_TIME_FAILED"));
		return false;
	}

	return true;
}

// ユーザーの有効期限の設定
UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	UINT64 expires;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_UserExpiresSet_Prompt_EXPIRES"), CmdEvalDateTime, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// ユーザーオブジェクトを取得
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報を更新する
	expires = StrToDateTime64(GetParamStr(o, "EXPIRES"));

	if (expires != 0)
	{
		expires = LocalToSystem64(expires);
	}

	t.ExpireTime = expires;

	// ユーザーオブジェクトを書き込み
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// グループ一覧の取得
UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_GROUP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_GROUPLIST_NAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_REALNAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NOTE"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NUMUSERS"), false);

		for (i = 0;i < t.NumGroup;i++)
		{
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			RPC_ENUM_GROUP_ITEM *e = &t.Groups[i];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->NumUsers);

			CtInsert(ct, tmp1, e->Realname, e->Note, tmp2);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// グループの作成
UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// RPC 呼び出し
	ret = ScCreateGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// グループ情報の設定
UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// 情報更新
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// RPC 呼び出し
	ret = ScSetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// グループの削除
UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScDeleteGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// グループ情報と所属しているユーザー一覧の取得
UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char groupname[MAX_USERNAME_LEN + 1];
		CT *ct = CtNewStandard();

		StrCpy(groupname, sizeof(groupname), t.Name);

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NAME"), tmp);
		CtInsert(ct, _UU("CMD_GroupGet_Column_REALNAME"), t.Realname);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NOTE"), t.Note);

		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_GroupGet_Column_POLICY"));

			PrintPolicy(c, t.Policy, false);
		}

		{
			RPC_ENUM_USER t;
			bool b = false;

			Zero(&t, sizeof(t));

			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

			if (ScEnumUser(ps->Rpc, &t) == ERR_NO_ERROR)
			{
				UINT i;

				for (i = 0;i < t.NumUser;i++)
				{
					RPC_ENUM_USER_ITEM *u = &t.Users[i];

					if (StrCmpi(u->GroupName, groupname) == 0)
					{
						if (b == false)
						{
							b = true;
							c->Write(c, L"");
							c->Write(c, _UU("CMD_GroupGet_Column_MEMBERS"));
						}

						UniFormat(tmp, sizeof(tmp), L" %S", u->Name);
						c->Write(c, tmp);
					}
				}
				FreeRpcEnumUser(&t);

				if (b)
				{
					c->Write(c, L"");
				}
			}
		}

	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// グループにユーザーを追加
UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_GroupJoin_Prompt_USERNAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "USERNAME"));

	// RPC 呼び出し
	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// グループの更新
		StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "[name]"));

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// グループからユーザーを削除
UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupUnjoin_Prompt_name"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// グループの更新
		StrCpy(t.GroupName, sizeof(t.GroupName), "");

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// グループのセキュリティ ポリシーの削除
UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// 更新
		if (t.Policy != NULL)
		{
			Free(t.Policy);
			t.Policy = NULL;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// グループのセキュリティ ポリシーの設定
UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// 更新
		if (t.Policy == NULL)
		{
			t.Policy = ClonePolicy(GetDefaultPolicy());
		}

		if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
		{
			// エラー発生
			FreeRpcSetGroup(&t);
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// 接続中のセッション一覧の取得
UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_SESSION t;
	UINT server_type = 0;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	{
		// サーバー種類の取得
		RPC_SERVER_INFO t;

		Zero(&t, sizeof(t));

		if (ScGetServerInfo(ps->Rpc, &t) == ERR_NO_ERROR)
		{
			server_type = t.ServerType;

			FreeRpcServerInfo(&t);
		}
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_8"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_5"), true);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), true);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), true);

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

			StrToUni(tmp1, sizeof(tmp1), e->Name);

			tmp2 = _UU("SM_SESS_NORMAL");
			if (server_type != SERVER_TYPE_STANDALONE)
			{
				if (e->RemoteSession)
				{
					tmp2 = ZeroMalloc(MAX_SIZE);
					UniFormat(tmp2, MAX_SIZE, _UU("SM_SESS_REMOTE"), e->RemoteHostname);
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
			}
			else if (e->SecureNATMode)
			{
				/*if (free_tmp2)
				{
					Free(tmp2);
					free_tmp2 = false;
				}*/
				tmp2 = _UU("SM_SESS_SNAT");
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

			UniToStr3(tmp6, sizeof(tmp6), e->PacketSize);
			UniToStr3(tmp7, sizeof(tmp7), e->PacketNum);

			if (e->VLanId == 0)
			{
				UniStrCpy(tmp8, sizeof(tmp8), _UU("CM_ST_NO_VLAN"));
			}
			else
			{
				UniToStru(tmp8, e->VLanId);
			}

			CtInsert(ct, tmp1, tmp8, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7);

			if (free_tmp2)
			{
				Free(tmp2);
			}
		}


		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumSession(&t);

	FreeParamValueList(o);

	return 0;
}

// NODE_INFO の表示
void CmdPrintNodeInfo(CT *ct, NODE_INFO *info)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// 引数チェック
	if (ct == NULL || info == NULL)
	{
		return;
	}

	StrToUni(tmp, sizeof(tmp), info->ClientProductName);
	CtInsert(ct, _UU("SM_NODE_CLIENT_NAME"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%u.%02u", Endian32(info->ClientProductVer) / 100, Endian32(info->ClientProductVer) % 100);
	CtInsert(ct, _UU("SM_NODE_CLIENT_VER"), tmp);

	UniFormat(tmp, sizeof(tmp), L"Build %u", Endian32(info->ClientProductBuild));
	CtInsert(ct, _UU("SM_NODE_CLIENT_BUILD"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsName);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsVer);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_VER"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsProductId);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_PID"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientHostname);
	CtInsert(ct, _UU("SM_NODE_CLIENT_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ClientIpAddress, info->ClientIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("SM_NODE_CLIENT_IP"), tmp);

	UniToStru(tmp, Endian32(info->ClientPort));
	CtInsert(ct, _UU("SM_NODE_CLIENT_PORT"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ServerHostname);
	CtInsert(ct, _UU("SM_NODE_SERVER_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ServerIpAddress, info->ServerIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("SM_NODE_SERVER_IP"), tmp);

	UniToStru(tmp, Endian32(info->ServerPort));
	CtInsert(ct, _UU("SM_NODE_SERVER_PORT"), tmp);

	if (StrLen(info->ProxyHostname) != 0)
	{
		StrToUni(tmp, sizeof(tmp), info->ProxyHostname);
		CtInsert(ct, _UU("SM_NODE_PROXY_HOSTNAME"), tmp);

		IPToStr4or6(str, sizeof(str), info->ProxyIpAddress, info->ProxyIpAddress6);
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("SM_NODE_PROXY_IP"), tmp);

		UniToStru(tmp, Endian32(info->ProxyPort));
		CtInsert(ct, _UU("SM_NODE_PROXY_PORT"), tmp);
	}
}

// セッション情報の取得
UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SESSION_STATUS t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScGetSessionStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char str[MAX_SIZE];
		CT *ct = CtNewStandard();

		if (t.ClientIp != 0)
		{
			IPToStr4or6(str, sizeof(str), t.ClientIp, t.ClientIp6);
			StrToUni(tmp, sizeof(tmp), str);
			CtInsert(ct, _UU("SM_CLIENT_IP"), tmp);
		}

		if (StrLen(t.ClientHostName) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientHostName);
			CtInsert(ct, _UU("SM_CLIENT_HOSTNAME"), tmp);
		}

		StrToUni(tmp, sizeof(tmp), t.Username);
		CtInsert(ct, _UU("SM_SESS_STATUS_USERNAME"), tmp);

		if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.RealUsername);
			CtInsert(ct, _UU("SM_SESS_STATUS_REALUSER"), tmp);
		}

		if (IsEmptyStr(t.GroupName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.GroupName);
			CtInsert(ct, _UU("SM_SESS_STATUS_GROUPNAME"), tmp);
		}


		CmdPrintStatusToListViewEx(ct, &t.Status, true);

		if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0 &&
			StartWith(t.Username, L3_USERNAME) == false)
		{
			CmdPrintNodeInfo(ct, &t.NodeInfo);
		}

		CtFree(ct, c);
	}

	FreeRpcSessionStatus(&t);

	FreeParamValueList(o);

	return 0;
}

// セッションの切断
UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_SESSION t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC 呼び出し
	ret = ScDeleteSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// MAC アドレス テーブル データベースの取得
UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_MAC_TABLE t;
	UINT i;

	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_1A"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_5"), false);

		for (i = 0;i < t.NumMacTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			wchar_t tmp6[MAX_SIZE];

			RPC_ENUM_MAC_TABLE_ITEM *e = &t.MacTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

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

				CtInsert(ct,
					tmp0, tmp1, tmp6, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumMacTable(&t);

	FreeParamValueList(o);

	return 0;
}

// MAC アドレス テーブル エントリの削除
UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScDeleteMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// IP アドレス テーブル データベースの取得
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_5"), false);

		for (i = 0;i < t.NumIpTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

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

				CtInsert(ct,
					tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumIpTable(&t);

	FreeParamValueList(o);

	return 0;
}

// IP アドレス テーブル エントリの削除
UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScDeleteIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 NAT および DHCP サーバー機能 (SecureNAT 機能) の有効化
UINT PsSecureNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnableSecureNAT(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 NAT および DHCP サーバー機能 (SecureNAT 機能) の無効化
UINT PsSecureNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScDisableSecureNAT(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 仮想 NAT および DHCP サーバー機能 (SecureNAT 機能) の動作状況の取得
UINT PsSecureNatStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_NAT_STATUS t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), ps->HubName);
		CtInsert(ct, _UU("SM_HUB_COLUMN_1"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumTcpSessions);
		CtInsert(ct, _UU("NM_STATUS_TCP"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumUdpSessions);
		CtInsert(ct, _UU("NM_STATUS_UDP"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_CLIENT"), t.NumDhcpClients);
		CtInsert(ct, _UU("NM_STATUS_DHCP"), tmp);

		CtFree(ct, c);
	}

	FreeRpcNatStatus(&t);

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想ホストのネットワーク インターフェイス設定の取得
UINT PsSecureNatHostGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char str[MAX_SIZE];
		CT *ct = CtNewStandard();

		// 使用フラグ
		// MAC アドレス
		MacToStr(str, sizeof(str), t.MacAddress);
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_MAC"), tmp);

		// IP アドレス
		IPToUniStr(tmp, sizeof(tmp), &t.Ip);
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_IP"), tmp);

		// サブネット マスク
		IPToUniStr(tmp, sizeof(tmp), &t.Mask);
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_MASK"), tmp);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想ホストのネットワーク インターフェイス設定の変更
UINT PsSecureNatHostSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"MAC", CmdPrompt, _UU("CMD_SecureNatHostSet_Prompt_MAC"), NULL, NULL},
		{"IP", CmdPrompt, _UU("CMD_SecureNatHostSet_Prompt_IP"), CmdEvalIp, NULL},
		{"MASK", CmdPrompt, _UU("CMD_SecureNatHostSet_Prompt_MASK"), CmdEvalIp, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *mac, *ip, *mask;
		bool ok = true;

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

		mac = GetParamStr(o, "MAC");
		ip = GetParamStr(o, "IP");
		mask = GetParamStr(o, "MASK");

		if (IsEmptyStr(mac) == false)
		{
			BUF *b = StrToBin(mac);

			if (b == NULL || b->Size != 6)
			{
				ok = false;
			}
			else
			{
				Copy(t.MacAddress, b->Buf, 6);
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(ip) == false)
		{
			if (IsIpStr4(ip) == false)
			{
				ok = false;
			}
			else
			{
				UINT u = StrToIP32(ip);

				if (u == 0 || u == 0xffffffff)
				{
					ok = false;
				}
				else
				{
					UINTToIP(&t.Ip, u);
				}
			}
		}

		if (IsEmptyStr(mask) == false)
		{
			if (IsIpStr4(mask) == false)
			{
				ok = false;
			}
			else
			{
				StrToIP(&t.Mask, mask);
			}
		}

		if (ok == false)
		{
			// パラメータが不正
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 NAT 機能の設定の取得
UINT PsNatGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		// 仮想 NAT 機能を使用する
		CtInsert(ct, _UU("CMD_NatGet_Column_USE"), t.UseNat ? _UU("SEC_YES") : _UU("SEC_NO"));

		// MTU 値
		UniToStru(tmp, t.Mtu);
		CtInsert(ct, _UU("CMD_NetGet_Column_MTU"), tmp);

		// TCP セッションのタイムアウト (秒)
		UniToStru(tmp, t.NatTcpTimeout);
		CtInsert(ct, _UU("CMD_NatGet_Column_TCP"), tmp);

		// UDP セッションのタイムアウト (秒)
		UniToStru(tmp, t.NatUdpTimeout);
		CtInsert(ct, _UU("CMD_NatGet_Column_UDP"), tmp);

		// ログ保存
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_LOG"), t.SaveLog ? _UU("SEC_YES") : _UU("SEC_NO"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 NAT 機能の有効化
UINT PsNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		bool ok = true;

		t.UseNat = true;

		if (ok == false)
		{
			// パラメータが不正
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 NAT 機能の無効化
UINT PsNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		bool ok = true;

		t.UseNat = false;

		if (ok == false)
		{
			// パラメータが不正
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 NAT 機能の設定の変更
UINT PsNatSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX mtu_mm =
	{
		"CMD_NatSet_Eval_MTU", TCP_HEADER_SIZE + IP_HEADER_SIZE + MAC_HEADER_SIZE + 8, MAX_L3_DATA_SIZE,
	};
	CMD_EVAL_MIN_MAX tcp_mm =
	{
		"CMD_NatSet_Eval_TCP", NAT_TCP_MIN_TIMEOUT / 1000, NAT_TCP_MAX_TIMEOUT / 1000,
	};
	CMD_EVAL_MIN_MAX udp_mm =
	{
		"CMD_NatSet_Eval_UDP", NAT_UDP_MIN_TIMEOUT / 1000, NAT_UDP_MAX_TIMEOUT / 1000,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"MTU", CmdPrompt, _UU("CMD_NatSet_Prompt_MTU"), CmdEvalMinMax, &mtu_mm},
		{"TCPTIMEOUT", CmdPrompt, _UU("CMD_NatSet_Prompt_TCPTIMEOUT"), CmdEvalMinMax, &tcp_mm},
		{"UDPTIMEOUT", CmdPrompt, _UU("CMD_NatSet_Prompt_UDPTIMEOUT"), CmdEvalMinMax, &udp_mm},
		{"LOG", CmdPrompt, _UU("CMD_NatSet_Prompt_LOG"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		bool ok = true;

		t.Mtu = GetParamInt(o, "MTU");
		t.NatTcpTimeout = GetParamInt(o, "TCPTIMEOUT");
		t.NatUdpTimeout = GetParamInt(o, "UDPTIMEOUT");
		t.SaveLog = GetParamYes(o, "LOG");

		if (ok == false)
		{
			// パラメータが不正
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 NAT 機能のセッション テーブルの取得
UINT PsNatTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_NAT t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumNAT(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("NM_NAT_ID"), false);
		CtInsertColumn(ct, _UU("NM_NAT_PROTOCOL"), false);
		CtInsertColumn(ct, _UU("NM_NAT_SRC_HOST"), false);
		CtInsertColumn(ct, _UU("NM_NAT_SRC_PORT"), false);
		CtInsertColumn(ct, _UU("NM_NAT_DST_HOST"), false);
		CtInsertColumn(ct, _UU("NM_NAT_DST_PORT"), false);
		CtInsertColumn(ct, _UU("NM_NAT_CREATED"), false);
		CtInsertColumn(ct, _UU("NM_NAT_LAST_COMM"), false);
		CtInsertColumn(ct, _UU("NM_NAT_SIZE"), false);
		CtInsertColumn(ct, _UU("NM_NAT_TCP_STATUS"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_NAT_ITEM *e = &t.Items[i];
			wchar_t tmp0[MAX_SIZE];
			wchar_t *tmp1 = L"";
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			wchar_t tmp6[MAX_SIZE];
			wchar_t tmp7[MAX_SIZE];
			wchar_t tmp8[MAX_SIZE];
			wchar_t *tmp9 = L"";
			char v1[128], v2[128];

			// ID
			UniToStru(tmp0, e->Id);

			// プロトコル
			switch (e->Protocol)
			{
			case NAT_TCP:
				tmp1 = _UU("NM_NAT_PROTO_TCP");
				break;
			case NAT_UDP:
				tmp1 = _UU("NM_NAT_PROTO_UDP");
				break;
			case NAT_DNS:
				tmp1 = _UU("NM_NAT_PROTO_DNS");
				break;
			}

			// 接続元ホスト
			StrToUni(tmp2, sizeof(tmp2), e->SrcHost);

			// 接続元ポート
			UniToStru(tmp3, e->SrcPort);

			// 接続先ホスト
			StrToUni(tmp4, sizeof(tmp4), e->DestHost);

			// 接続先ポート
			UniToStru(tmp5, e->DestPort);

			// セッション作成日時
			GetDateTimeStrEx64(tmp6, sizeof(tmp6), SystemToLocal64(e->CreatedTime), NULL);

			// 最終通信日時
			GetDateTimeStrEx64(tmp7, sizeof(tmp7), SystemToLocal64(e->LastCommTime), NULL);

			// 通信量
			ToStr3(v1, sizeof(v1), e->RecvSize);
			ToStr3(v2, sizeof(v2), e->SendSize);
			UniFormat(tmp8, sizeof(tmp8), L"%S / %S", v1, v2);

			// TCP 状態
			if (e->Protocol == NAT_TCP)
			{
				switch (e->TcpStatus)
				{
				case NAT_TCP_CONNECTING:
					tmp9 = _UU("NAT_TCP_CONNECTING");
					break;
				case NAT_TCP_SEND_RESET:
					tmp9 = _UU("NAT_TCP_SEND_RESET");
					break;
				case NAT_TCP_CONNECTED:
					tmp9 = _UU("NAT_TCP_CONNECTED");
					break;
				case NAT_TCP_ESTABLISHED:
					tmp9 = _UU("NAT_TCP_ESTABLISHED");
					break;
				case NAT_TCP_WAIT_DISCONNECT:
					tmp9 = _UU("NAT_TCP_WAIT_DISCONNECT");
					break;
				}
			}

			CtInsert(ct,
				tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumNat(&t);

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 DHCP サーバー機能の設定の取得
UINT PsDhcpGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		// 仮想 DHCP 機能を使用する
		CtInsert(ct, _UU("CMD_DhcpGet_Column_USE"), t.UseDhcp ? _UU("SEC_YES") : _UU("SEC_NO"));

		// 配布アドレス帯の開始
		IPToUniStr(tmp, sizeof(tmp), &t.DhcpLeaseIPStart);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_IP1"), tmp);

		// 配布アドレス帯の終了
		IPToUniStr(tmp, sizeof(tmp), &t.DhcpLeaseIPEnd);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_IP2"), tmp);

		// サブネット マスク
		IPToUniStr(tmp, sizeof(tmp), &t.DhcpSubnetMask);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_MASK"), tmp);

		// リース期限 (秒)
		UniToStru(tmp, t.DhcpExpireTimeSpan);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_LEASE"), tmp);

		// デフォルトゲートウェイアドレス
		UniStrCpy(tmp, sizeof(tmp), _UU("SEC_NONE"));
		if (IPToUINT(&t.DhcpGatewayAddress) != 0)
		{
			IPToUniStr(tmp, sizeof(tmp), &t.DhcpGatewayAddress);
		}
		CtInsert(ct, _UU("CMD_DhcpGet_Column_GW"), tmp);

		// DNS サーバー アドレス
		UniStrCpy(tmp, sizeof(tmp), _UU("SEC_NONE"));
		if (IPToUINT(&t.DhcpDnsServerAddress) != 0)
		{
			IPToUniStr(tmp, sizeof(tmp), &t.DhcpDnsServerAddress);
		}
		CtInsert(ct, _UU("CMD_DhcpGet_Column_DNS"), tmp);

		// ドメイン名
		StrToUni(tmp, sizeof(tmp), t.DhcpDomainName);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_DOMAIN"), tmp);

		// ログ保存
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_LOG"), t.SaveLog ? _UU("SEC_YES") : _UU("SEC_NO"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 DHCP サーバー機能の有効化
UINT PsDhcpEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		bool ok = true;

		t.UseDhcp = true;

		if (ok == false)
		{
			// パラメータが不正
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 DHCP サーバー機能の無効化
UINT PsDhcpDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		bool ok = true;

		t.UseDhcp = false;

		if (ok == false)
		{
			// パラメータが不正
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 DHCP サーバー機能の設定の変更
UINT PsDhcpSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_NatSet_Eval_UDP", NAT_UDP_MIN_TIMEOUT / 1000, NAT_UDP_MAX_TIMEOUT / 1000,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"START", CmdPrompt, _UU("CMD_DhcpSet_Prompt_START"), CmdEvalIp, NULL},
		{"END", CmdPrompt, _UU("CMD_DhcpSet_Prompt_END"), CmdEvalIp, NULL},
		{"MASK", CmdPrompt, _UU("CMD_DhcpSet_Prompt_MASK"), CmdEvalIp, NULL},
		{"EXPIRE", CmdPrompt, _UU("CMD_DhcpSet_Prompt_EXPIRE"), CmdEvalMinMax, &mm},
		{"GW", CmdPrompt, _UU("CMD_DhcpSet_Prompt_GW"), CmdEvalIp, NULL},
		{"DNS", CmdPrompt, _UU("CMD_DhcpSet_Prompt_DNS"), CmdEvalIp, NULL},
		{"DOMAIN", CmdPrompt, _UU("CMD_DhcpSet_Prompt_DOMAIN"), NULL, NULL},
		{"LOG", CmdPrompt, _UU("CMD_NatSet_Prompt_LOG"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		bool ok = true;

		StrToIP(&t.DhcpLeaseIPStart, GetParamStr(o, "START"));
		StrToIP(&t.DhcpLeaseIPEnd, GetParamStr(o, "END"));
		StrToIP(&t.DhcpSubnetMask, GetParamStr(o, "MASK"));
		t.DhcpExpireTimeSpan = GetParamInt(o, "EXPIRE");
		StrToIP(&t.DhcpGatewayAddress, GetParamStr(o, "GW"));
		StrToIP(&t.DhcpDnsServerAddress, GetParamStr(o, "DNS"));
		StrCpy(t.DhcpDomainName, sizeof(t.DhcpDomainName), GetParamStr(o, "DOMAIN"));
		t.SaveLog = GetParamYes(o, "LOG");

		if (ok == false)
		{
			// パラメータが不正
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// SecureNAT 機能の仮想 DHCP サーバー機能のリース テーブルの取得
UINT PsDhcpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_DHCP t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumDHCP(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("DHCP_DHCP_ID"), false);
		CtInsertColumn(ct, _UU("DHCP_LEASED_TIME"), false);
		CtInsertColumn(ct, _UU("DHCP_EXPIRE_TIME"), false);
		CtInsertColumn(ct, _UU("DHCP_MAC_ADDRESS"), false);
		CtInsertColumn(ct, _UU("DHCP_IP_ADDRESS"), false);
		CtInsertColumn(ct, _UU("DHCP_HOSTNAME"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_DHCP_ITEM *e = &t.Items[i];
			wchar_t tmp0[MAX_SIZE];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			char str[MAX_SIZE];

			// ID
			UniToStru(tmp0, e->Id);

			// 時刻
			GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->LeasedTime), NULL);
			GetDateTimeStrEx64(tmp2, sizeof(tmp2), SystemToLocal64(e->ExpireTime), NULL);

			MacToStr(str, sizeof(str), e->MacAddress);
			StrToUni(tmp3, sizeof(tmp3), str);

			IPToStr32(str, sizeof(str), e->IpAddress);
			StrToUni(tmp4, sizeof(tmp4), str);

			StrToUni(tmp5, sizeof(tmp5), e->Hostname);

			CtInsert(ct,
				tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumDhcp(&t);

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB 管理オプションの一覧の取得
UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandardEx();
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			ADMIN_OPTION *e = &t.Items[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->Value);

			CtInsert(ct, tmp1, tmp2, GetHubAdminOptionHelpString(e->Name));
				
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB 管理オプションの値の設定
UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;

		for (i = 0;i < t.NumItem;i++)
		{
			if (StrCmpi(t.Items[i].Name, GetParamStr(o, "[name]")) == 0)
			{
				t.Items[i].Value = GetParamInt(o, "VALUE");
				b = true;
			}
		}

		if (b == false)
		{
			// エラー発生
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcAdminOption(&t);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetHubAdminOptions(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB 拡張オプションの一覧の取得
UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandardEx();
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			ADMIN_OPTION *e = &t.Items[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->Value);

			CtInsert(ct, tmp1, tmp2, GetHubAdminOptionHelpString(e->Name));

		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// 仮想 HUB 拡張オプションの値の設定
UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;

		for (i = 0;i < t.NumItem;i++)
		{
			if (StrCmpi(t.Items[i].Name, GetParamStr(o, "[name]")) == 0)
			{
				t.Items[i].Value = GetParamInt(o, "VALUE");
				b = true;
			}
		}

		if (b == false)
		{
			// エラー発生
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcAdminOption(&t);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetHubExtOptions(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// エラー発生
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// 無効な証明書リストの一覧の取得
UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CRL t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScEnumCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_CRL_COLUMN_1"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t tmp[64];
			RPC_ENUM_CRL_ITEM *e = &t.Items[i];

			UniToStru(tmp, e->Key);
			CtInsert(ct, tmp, e->CrlInfo);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// 無効な証明書の追加
UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		{"SERIAL", NULL, NULL, NULL, NULL},
		{"MD5", NULL, NULL, NULL, NULL},
		{"SHA1", NULL, NULL, NULL, NULL},
		{"CN", NULL, NULL, NULL, NULL},
		{"O", NULL, NULL, NULL, NULL},
		{"OU", NULL, NULL, NULL, NULL},
		{"C", NULL, NULL, NULL, NULL},
		{"ST", NULL, NULL, NULL, NULL},
		{"L", NULL, NULL, NULL, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	{
		bool param_exists = false;
		CRL *crl = ZeroMalloc(sizeof(CRL));
		NAME *n;
		n = crl->Name = ZeroMalloc(sizeof(NAME));

		if (IsEmptyStr(GetParamStr(o, "CN")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "CN"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "O")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "O"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "OU")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "OU"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "C")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "C"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "ST")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "ST"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "L")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "L"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "SERIAL")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "SERIAL"));

			if (b != NULL && b->Size >= 1)
			{
				crl->Serial = NewXSerial(b->Buf, b->Size);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "MD5")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "MD5"));

			if (b != NULL && b->Size == MD5_SIZE)
			{
				Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "SHA1")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "SHA1"));

			if (b != NULL && b->Size == SHA1_SIZE)
			{
				Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		t.Crl = crl;

		if (param_exists == false)
		{
			FreeRpcCrl(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	// RPC 呼び出し
	ret = ScAddCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// 無効な証明書の削除
UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CrlDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScDelCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// 無効な証明書の取得
UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CrlGet_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScGetCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// 内容の表示
		CT *ct = CtNewStandard();
		CRL *crl = t.Crl;
		NAME *n;

		if (crl != NULL)
		{
			n = crl->Name;

			if (n != NULL)
			{
				if (UniIsEmptyStr(n->CommonName) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_CN"), n->CommonName);
				}
				if (UniIsEmptyStr(n->Organization) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_O"), n->Organization);
				}
				if (UniIsEmptyStr(n->Unit) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_OU"), n->Unit);
				}
				if (UniIsEmptyStr(n->Country) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_C"), n->Country);
				}
				if (UniIsEmptyStr(n->State) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_ST"), n->State);
				}
				if (UniIsEmptyStr(n->Local) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_L"), n->Local);
				}
			}

			if (crl->Serial != NULL && crl->Serial->size >= 1)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SERI"), tmp);
			}

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_MD5_HASH"), tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SHA1_HASH"), tmp);
			}
		}
		CtFree(ct, c);
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// IP アクセス制御リストのルール一覧の取得
UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct;

		ct = CtNew();
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_1"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_4"), false);

		for (i = 0;i < LIST_NUM(t.o);i++)
		{
			wchar_t tmp1[32], *tmp2, tmp3[MAX_SIZE], tmp4[32];
			char *tmp_str;
			AC *ac = LIST_DATA(t.o, i);

			UniToStru(tmp1, ac->Id);
			tmp2 = ac->Deny ? _UU("SM_AC_DENY") : _UU("SM_AC_PASS");
			tmp_str = GenerateAcStr(ac);
			StrToUni(tmp3, sizeof(tmp3), tmp_str);

			Free(tmp_str);

			UniToStru(tmp4, ac->Priority);

			CtInsert(ct, tmp1, tmp4, tmp2, tmp3);
		}

		CtFree(ct, c);
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// IP アクセス制御リストにルールを追加 (IPv4)
UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd_Prompt_IP"), CmdEvalIpAndMask4, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// リストに新しい項目を追加する
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		UINT u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask4(GetParamStr(o, "IP"), &u_ip, &u_mask);
		UINTToIP(&ac->IpAddress, u_ip);

		if (u_mask == 0xffffffff)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			UINTToIP(&ac->SubnetMask, u_mask);
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// IP アクセス制御リストにルールを追加 (IPv6)
UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// 指定できるパラメータ リスト
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd6_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd6_Prompt_IP"), CmdEvalIpAndMask6, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// リストに新しい項目を追加する
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		IP u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask6(GetParamStr(o, "IP"), &u_ip, &u_mask);
		Copy(&ac->IpAddress, &u_ip, sizeof(IP));

		if (SubnetMaskToInt6(&u_mask) == 128)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			Copy(&ac->SubnetMask, &u_mask, sizeof(IP));
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// デバッグコマンドを実行する
UINT PsDebug(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	UINT id;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", NULL, NULL, NULL, NULL},
		{"ARG", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	id = GetParamInt(o, "[id]");

	if (true)
	{
		RPC_TEST t;
		UINT ret;

		c->Write(c, _UU("CMD_Debug_Msg1"));

		Zero(&t, sizeof(t));

		t.IntValue = id;
		StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "ARG"));

		ret = ScDebug(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			wchar_t tmp[sizeof(t.StrValue)];

			UniFormat(tmp, sizeof(tmp), _UU("CMD_Debug_Msg2"), t.StrValue);
			c->Write(c, tmp);
		}
	}

	FreeParamValueList(o);

	return 0;
}

// サーバーの設定ファイルをフラッシュする
UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (true)
	{
		RPC_TEST t;
		UINT ret;
		wchar_t tmp[MAX_SIZE];
		char sizestr[MAX_SIZE];

		c->Write(c, _UU("CMD_Flush_Msg1"));

		Zero(&t, sizeof(t));

		ret = ScFlush(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		ToStr3(sizestr, sizeof(sizestr), (UINT64)t.IntValue);
		UniFormat(tmp, sizeof(tmp), _UU("CMD_Flush_Msg2"), sizestr);
		c->Write(c, tmp);
	}

	FreeParamValueList(o);

	return 0;
}

// クラッシュさせる
UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	char *yes;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[yes]", CmdPrompt, _UU("CMD_Crash_Confirm"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	yes = GetParamStr(o, "[yes]");

	if (StrCmpi(yes, "yes") != 0)
	{
		c->Write(c, _UU("CMD_Crash_Aborted"));
	}
	else
	{
		RPC_TEST t;
		UINT ret;

		c->Write(c, _UU("CMD_Crash_Msg"));

		Zero(&t, sizeof(t));

		ret = ScCrash(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// IP アクセス制御リスト内のルールの削除
UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_AcDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// 仮想 HUB が選択されていない場合はエラー
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC 呼び出し
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// ID 一致を削除
		UINT i;
		bool b = false;

		for (i = 0;i < LIST_NUM(t.o);i++)
		{
			AC *ac = LIST_DATA(t.o, i);

			if (ac->Id == GetParamInt(o, "[id]"))
			{
				Delete(t.o, ac);
				Free(ac);
				b = true;
				break;
			}
		}

		if (b == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
			FreeRpcAcList(&t);
		}
		else
		{
			ret = ScSetAcList(ps->Rpc, &t);
		}
		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);
	FreeParamValueList(o);

	return 0;
}

// 新しいライセンスキーの登録
UINT PsLicenseAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[key]", CmdPrompt, _UU("CMD_LicenseAdd_Prompt_Key"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[key]"));

	// RPC 呼び出し
	ret = ScAddLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 登録されているライセンスの削除
UINT PsLicenseDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// 指定できるパラメータ リスト
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_LicenseDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.IntValue = GetParamInt(o, "[id]");

	// RPC 呼び出し
	ret = ScDelLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 登録されているライセンス一覧の取得
UINT PsLicenseList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LICENSE_KEY t;
	CT *ct;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC 呼び出し
	ret = ScEnumLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_4"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_5"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_6"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_7"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_8"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_9"), false);

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

		CtInsert(ct,
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
	}

	CtFreeEx(ct, c, true);

	FreeRpcEnumLicenseKey(&t);

	FreeParamValueList(o);

	return 0;
}

// 現在の VPN Server のライセンス状態の取得
UINT PsLicenseStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LICENSE_STATUS st;
	CT *ct;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&st, sizeof(st));

	// RPC 呼び出し
	ret = ScGetLicenseStatus(ps->Rpc, &st);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNewStandard();

	if (st.EditionId == LICENSE_EDITION_VPN3_NO_LICENSE)
	{
		CtInsert(ct, _UU("SM_NO_LICENSE_COLUMN"), _UU("SM_NO_LICENSE"));
	}
	else
	{
		// 製品エディション名
		StrToUni(tmp, sizeof(tmp), st.EditionStr);
		CtInsert(ct, _UU("SM_LICENSE_STATUS_EDITION"), tmp);

		// リリース日付
		if (st.ReleaseDate != 0)
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.ReleaseDate, NULL);
			CtInsert(ct, _UU("SM_LICENSE_STATUS_RELEASE"), tmp);
		}

		// 現在のシステム ID
		UniFormat(tmp, sizeof(tmp), L"%I64u", st.SystemId);
		CtInsert(ct, _UU("SM_LICENSE_STATUS_SYSTEM_ID"), tmp);

		// 現在の製品ライセンスの有効期限
		if (st.SystemExpires == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.SystemExpires, NULL);
		}
		CtInsert(ct,  _UU("SM_LICENSE_STATUS_EXPIRES"), tmp);

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
		CtInsert(ct, _UU("SM_LICENSE_STATUS_SUBSCRIPTION"), tmp);

		if (st.NeedSubscription == false && st.SubscriptionExpires != 0)
		{
			wchar_t dtstr[MAX_PATH];

			GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

			CtInsert(ct, _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD_STR"), tmp);
		}

		if (GetCapsBool(ps->CapsList, "b_vpn3"))
		{
			// ユーザー作成可能数
			if (st.NumClientConnectLicense == INFINITE)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
			}
			else
			{
				UniToStru(tmp, st.NumClientConnectLicense);
			}
			CtInsert(ct, _UU("SM_LICENSE_NUM_CLIENT"), tmp);
		}

		// クライアント同時接続可能数
		if (st.NumBridgeConnectLicense == INFINITE)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
		}
		else
		{
			UniToStru(tmp, st.NumBridgeConnectLicense);
		}
		CtInsert(ct, _UU("SM_LICENSE_NUM_BRIDGE"), tmp);

		// エンタープライズ機能の利用可否
		CtInsert(ct, _UU("SM_LICENSE_STATUS_ENTERPRISE"),
			st.AllowEnterpriseFunction ? _UU("SM_LICENSE_STATUS_ENTERPRISE_YES") : _UU("SM_LICENSE_STATUS_ENTERPRISE_NO"));
	}

	CtFreeEx(ct, c, false);

	FreeParamValueList(o);

	return 0;
}


// クラスタ設定の取得
UINT PsClusterSettingGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_FARM t;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetFarmSetting(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Weight == 0)
	{
		t.Weight = FARM_DEFAULT_WEIGHT;
	}

	// クラスタ設定の表示
	ct = CtNewStandard();

	CtInsert(ct, _UU("CMD_ClusterSettingGet_Current"),
		GetServerTypeStr(t.ServerType));

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		CtInsert(ct, _UU("CMD_ClusterSettingGet_ControllerOnly"), t.ControllerOnly ? _UU("SEC_YES") : _UU("SEC_NO"));
	}

	if (t.ServerType != SERVER_TYPE_STANDALONE)
	{
		wchar_t tmp[MAX_SIZE];

		UniToStru(tmp, t.Weight);

		CtInsert(ct, _UU("CMD_ClusterSettingGet_Weight"), tmp);
	}

	if (t.ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		wchar_t tmp[MAX_SIZE];
		UINT i;

		// 公開 IP アドレス
		if (t.PublicIp != 0)
		{
			IPToUniStr32(tmp, sizeof(tmp), t.PublicIp);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_ClusterSettingGet_None"));
		}

		CtInsert(ct, _UU("CMD_ClusterSettingGet_PublicIp"), tmp);

		// 公開ポート一覧
		tmp[0] = 0;
		for (i = 0;i < t.NumPort;i++)
		{
			wchar_t tmp2[64];

			UniFormat(tmp2, sizeof(tmp2), L"%u, ", t.Ports[i]);

			UniStrCat(tmp, sizeof(tmp), tmp2);
		}

		if (UniEndWith(tmp, L", "))
		{
			tmp[UniStrLen(tmp) - 2] = 0;
		}

		CtInsert(ct, _UU("CMD_ClusterSettingGet_PublicPorts"), tmp);

		// 接続先コントローラ
		UniFormat(tmp, sizeof(tmp), L"%S:%u", t.ControllerName, t.ControllerPort);
		CtInsert(ct, _UU("CMD_ClusterSettingGet_Controller"), tmp);
	}

	CtFree(ct, c);

	FreeRpcFarm(&t);
	FreeParamValueList(o);

	return 0;
}

// サーバーパスワードの設定
UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SET_PASSWORD t;
	char *pw;
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	pw = GetParamStr(o, "[password]");

	Zero(&t, sizeof(t));
	Hash(t.HashedPassword, pw, StrLen(pw), true);

	ret = ScSetServerPassword(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// パスワード決定プロンプト (プロンプト関数用)
wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param)
{
	char *s;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	s = CmdPasswordPrompt(c);

	if (s == NULL)
	{
		return NULL;
	}
	else
	{
		wchar_t *ret = CopyStrToUni(s);

		Free(s);

		return ret;
	}
}

// パスワード入力用プロンプト (汎用)
char *CmdPasswordPrompt(CONSOLE *c)
{
	char *pw1, *pw2;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	c->Write(c, _UU("CMD_UTVPNCMD_PWPROMPT_0"));

RETRY:
	c->Write(c, L"");


	pw1 = c->ReadPassword(c, _UU("CMD_UTVPNCMD_PWPROMPT_1"));
	if (pw1 == NULL)
	{
		return NULL;
	}

	pw2 = c->ReadPassword(c, _UU("CMD_UTVPNCMD_PWPROMPT_2"));
	if (pw2 == NULL)
	{
		Free(pw1);
		return NULL;
	}

	c->Write(c, L"");

	if (StrCmp(pw1, pw2) != 0)
	{
		Free(pw1);
		Free(pw2);
		c->Write(c, _UU("CMD_UTVPNCMD_PWPROMPT_3"));
		goto RETRY;
	}

	Free(pw1);

	return pw2;
}

// リスナー無効化
UINT PsListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDisable_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = false;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScEnableListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// リスナー有効化
UINT PsListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerEnable_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScEnableListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// コンソールテーブルの 1 行を描画
void CtPrintRow(CONSOLE *c, UINT num, UINT *widths, wchar_t **strings, bool *rights, char separate_char)
{
	UINT i;
	wchar_t *buf;
	UINT buf_size;
	bool is_sep_line = true;
	// 引数チェック
	if (c == NULL || num == 0 || widths == NULL || strings == NULL || rights == NULL)
	{
		return;
	}

	buf_size = 32;
	for (i = 0;i < num;i++)
	{
		buf_size += sizeof(wchar_t) * widths[i] + 6;
	}

	buf = ZeroMalloc(buf_size);

	for (i = 0;i < num;i++)
	{
		char *tmp;
		wchar_t *space_string;
		UINT w;
		UINT space = 0;
		wchar_t *string = strings[i];
		wchar_t *tmp_line = NULL;

		if (UniStrCmpi(string, L"---") == 0)
		{
			char *s = MakeCharArray('-', widths[i]);
			tmp_line = string = CopyStrToUni(s);

			Free(s);
		}
		else
		{
			is_sep_line = false;
		}

		w = UniStrWidth(string);

		if (widths[i] >= w)
		{
			space = widths[i] - w;
		}

		tmp = MakeCharArray(' ', space);
		space_string = CopyStrToUni(tmp);

		if (rights[i] != false)
		{
			UniStrCat(buf, buf_size, space_string);
		}

		UniStrCat(buf, buf_size, string);

		if (rights[i] == false)
		{
			UniStrCat(buf, buf_size, space_string);
		}

		Free(space_string);
		Free(tmp);

		if (i < (num - 1))
		{
			wchar_t tmp[4];
			char str[2];

			if (UniStrCmpi(strings[i], L"---") == 0)
			{
				str[0] = '+';
			}
			else
			{
				str[0] = separate_char;
			}
			str[1] = 0;

			StrToUni(tmp, sizeof(tmp), str);

			UniStrCat(buf, buf_size, tmp);
		}

		if (tmp_line != NULL)
		{
			Free(tmp_line);
		}
	}

	UniTrimRight(buf);

	if (is_sep_line)
	{
		if (UniStrLen(buf) > (c->GetWidth(c) - 1))
		{
			buf[c->GetWidth(c) - 1] = 0;
		}
	}

	c->Write(c, buf);

	Free(buf);
}

// コンソール テーブルを標準形式で描画
void CtPrintStandard(CT *ct, CONSOLE *c)
{
	CT *t;
	UINT i, j;
	// 引数チェック
	if (ct == NULL || c == NULL)
	{
		return;
	}

	t = CtNewStandard();
	for (i = 0;i < LIST_NUM(ct->Rows);i++)
	{
		CTR *row = LIST_DATA(ct->Rows, i);

		for (j = 0;j < LIST_NUM(ct->Columns);j++)
		{
			CTC *column = LIST_DATA(ct->Columns, j);

			CtInsert(t, column->String, row->Strings[j]);
		}

		if (i != (LIST_NUM(ct->Rows) - 1))
		{
			CtInsert(t, L"---", L"---");
		}
	}

	CtFree(t, c);
}

// コンソールテーブルの描画
void CtPrint(CT *ct, CONSOLE *c)
{
	UINT *widths;
	UINT num;
	UINT i, j;
	wchar_t **header_strings;
	bool *rights;
	// 引数チェック
	if (ct == NULL || c == NULL)
	{
		return;
	}

	num = LIST_NUM(ct->Columns);
	widths = ZeroMalloc(sizeof(UINT) * num);

	// 各列の最大文字幅を計算する
	for (i = 0;i < num;i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);
		UINT w;

		w = UniStrWidth(ctc->String);
		widths[i] = MAX(widths[i], w);
	}
	for (j = 0;j < LIST_NUM(ct->Rows);j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);

		for (i = 0;i < num;i++)
		{
			UINT w;

			w = UniStrWidth(ctr->Strings[i]);
			widths[i] = MAX(widths[i], w);
		}
	}

	// ヘッダ部分を表示する
	header_strings = ZeroMalloc(sizeof(wchar_t *) * num);
	rights = ZeroMalloc(sizeof(bool) * num);

	for (i = 0;i < num;i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);

		header_strings[i] = ctc->String;
		rights[i] = ctc->Right;
	}

	CtPrintRow(c, num, widths, header_strings, rights, '|');

	for (i = 0;i < num;i++)
	{
		char *s;

		s = MakeCharArray('-', widths[i]);
		header_strings[i] = CopyStrToUni(s);
		Free(s);
	}

	CtPrintRow(c, num, widths, header_strings, rights, '+');

	for (i = 0;i < num;i++)
	{
		Free(header_strings[i]);
	}

	// データ部を表示する
	for (j = 0;j < LIST_NUM(ct->Rows);j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);

		CtPrintRow(c, num, widths, ctr->Strings, rights, '|');
	}

	Free(rights);
	Free(header_strings);
	Free(widths);
}

// CSV でのメタ文字をエスケープする
void CtEscapeCsv(wchar_t *dst, UINT size, wchar_t *src){
	UINT i;
	UINT len = UniStrLen(src);
	UINT idx;
	BOOL need_to_escape = false;
	wchar_t tmp[2]=L"*";

	// 入力値のチェック
	if (src==NULL || dst==NULL)
	{
		return;
	}

	// 入力文字中にエスケープする必要のある文字が無ければそのまま出力にコピー
	len = UniStrLen(src);
	for (i=0; i<len; i++)
	{
		tmp[0] = src[i];
		if (tmp[0] == L","[0] || tmp[0] == L"\n"[0] || tmp[0] == L"\""[0])
		{
			need_to_escape = true;
		}
	}
	if (need_to_escape == false)
	{
		UniStrCpy(dst,size,src);
		return;
	}

	// メタ文字（改行、コンマ、ダブルクオート）を含んでいる場合は”で囲む
	UniStrCpy(dst, size, L"\"");
	idx = UniStrLen(dst);
	if(idx<size-1)
	{
		for (i=0; i<len; i++)
		{
			tmp[0] = src[i];
			// ”は””に変換する（MS-Excel方式）
			if (tmp[0] == L"\""[0])
			{
				UniStrCat(dst, size, tmp);
			}
			UniStrCat(dst, size, tmp);
		}
	}
	UniStrCat(dst, size, L"\"");
	return;
}

// コンソールテーブルの CSV 形式の表示
void CtPrintCsv(CT *ct, CONSOLE *c)
{
	UINT i, j;
	UINT num_columns = LIST_NUM(ct->Columns);
	wchar_t buf[MAX_SIZE];
	wchar_t fmtbuf[MAX_SIZE];

	// 見出しの行を表示
	buf[0] = 0;
	for(i=0; i<num_columns; i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);
		CtEscapeCsv(fmtbuf, MAX_SIZE, ctc->String);
		UniStrCat(buf, MAX_SIZE, fmtbuf);
		if(i != num_columns-1)
			UniStrCat(buf, MAX_SIZE, L",");
	}
	c->Write(c, buf);

	// 表の本体を表示
	for(j=0; j<LIST_NUM(ct->Rows); j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);
		buf[0] = 0;
		for(i=0; i<num_columns; i++)
		{
			CtEscapeCsv(fmtbuf, MAX_SIZE, ctr->Strings[i]);
			UniStrCat(buf, MAX_SIZE, fmtbuf);
			if(i != num_columns-1)
				UniStrCat(buf, MAX_SIZE, L",");
		}
		c->Write(c, buf);
	}
}

// コンソールテーブルの削除
void CtFreeEx(CT *ct, CONSOLE *c, bool standard_view)
{
	UINT i, num;
	// 引数チェック
	if (ct == NULL)
	{
		return;
	}

	if (c != NULL)
	{
		if (c->ConsoleType == CONSOLE_CSV)
		{
			CtPrintCsv(ct, c);
		}
		else
		{
			if (standard_view == false)
			{
				CtPrint(ct, c);
			}
			else
			{
				CtPrintStandard(ct, c);
			}
		}
	}

	num = LIST_NUM(ct->Columns);

	for (i = 0;i < LIST_NUM(ct->Rows);i++)
	{
		UINT j;
		CTR *ctr = LIST_DATA(ct->Rows, i);

		for (j = 0;j < num;j++)
		{
			Free(ctr->Strings[j]);
		}

		Free(ctr->Strings);
		Free(ctr);
	}

	for (i = 0;i < LIST_NUM(ct->Columns);i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);

		Free(ctc->String);
		Free(ctc);
	}

	ReleaseList(ct->Columns);
	ReleaseList(ct->Rows);

	Free(ct);
}
void CtFree(CT *ct, CONSOLE *c)
{
	CtFreeEx(ct, c, false);
}

// テーブルに行を追加
void CtInsert(CT *ct, ...)
{
	CTR *ctr;
	UINT num, i;
	va_list va;
	// 引数チェック
	if (ct == NULL)
	{
		return;
	}

	num = LIST_NUM(ct->Columns);

	va_start(va, ct);

	ctr = ZeroMalloc(sizeof(CTR));
	ctr->Strings = ZeroMalloc(sizeof(wchar_t *) * num);

	for (i = 0;i < num;i++)
	{
		wchar_t *s = va_arg(va, wchar_t *);

		ctr->Strings[i] = CopyUniStr(s);
	}

	va_end(va);

	Insert(ct->Rows, ctr);
}

// テーブルにカラムを追加
void CtInsertColumn(CT *ct, wchar_t *str, bool right)
{
	CTC *ctc;
	// 引数チェック
	if (ct == NULL)
	{
		return;
	}
	if (str == NULL)
	{
		str = L"";
	}

	ctc = ZeroMalloc(sizeof(CTC));
	ctc->String = CopyUniStr(str);
	ctc->Right = right;

	Insert(ct->Columns, ctc);
}

// 新規コンソールテーブルの作成
CT *CtNew()
{
	CT *ct;

	ct = ZeroMalloc(sizeof(CT));
	ct->Columns = NewList(NULL);
	ct->Rows = NewList(NULL);

	return ct;
}

// テーブルのカラムに標準的なカラムを追加する
CT *CtNewStandard()
{
	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_2"), false);

	return ct;
}
CT *CtNewStandardEx()
{
	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_3"), false);

	return ct;
}

// TCP リスナー一覧の取得
UINT PsListenerList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER_LIST t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScEnumListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_2"), false);

	for (i = 0;i < t.NumPort;i++)
	{
		wchar_t *status = _UU("CM_LISTENER_OFFLINE");
		wchar_t tmp[128];

		if (t.Errors[i])
		{
			status = _UU("CM_LISTENER_ERROR");
		}
		else if (t.Enables[i])
		{
			status = _UU("CM_LISTENER_ONLINE");
		}

		UniFormat(tmp, sizeof(tmp), _UU("CM_LISTENER_TCP_PORT"), t.Ports[i]);

		CtInsert(ct, tmp, status);
	}

	CtFree(ct, c);

	FreeRpcListenerList(&t);

	FreeParamValueList(o);

	return 0;
}

// TCP リスナーの削除
UINT PsListenerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDelete_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScDeleteListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// 行を描画
void CmdPrintRow(CONSOLE *c, wchar_t *title, wchar_t *tag, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	wchar_t buf2[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (title == NULL || c == NULL || tag == NULL)
	{
		return;
	}

	va_start(args, tag);
	UniFormatArgs(buf, sizeof(buf), tag, args);

	UniFormat(buf2, sizeof(buf2), L"[%s] %s", title, buf);

	va_end(args);

	c->Write(c, buf2);
}

// ServerInfoGet コマンド
UINT PsServerInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SERVER_INFO t;
	CT *ct;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	ret = ScGetServerInfo(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_2"), false);

	// 製品名
	StrToUni(tmp, sizeof(tmp), t.ServerProductName);
	CtInsert(ct, _UU("SM_INFO_PRODUCT_NAME"), tmp);

	// バージョン
	StrToUni(tmp, sizeof(tmp), t.ServerVersionString);
	CtInsert(ct, _UU("SM_INFO_VERSION"), tmp);

	// ビルド
	StrToUni(tmp, sizeof(tmp), t.ServerBuildInfoString);
	CtInsert(ct, _UU("SM_INFO_BUILD"), tmp);

	// ホスト名
	StrToUni(tmp, sizeof(tmp), t.ServerHostName);
	CtInsert(ct, _UU("SM_INFO_HOSTNAME"), tmp);

	// 種類
	CtInsert(ct, _UU("SM_ST_SERVER_TYPE"), GetServerTypeStr(t.ServerType));

	// OS
	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsSystemName);
	CtInsert(ct, _UU("SM_OS_SYSTEM_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsProductName);
	CtInsert(ct, _UU("SM_OS_PRODUCT_NAME"), tmp);

	if (t.OsInfo.OsServicePack != 0)
	{
		UniFormat(tmp, sizeof(tmp), _UU("SM_OS_SP_TAG"), t.OsInfo.OsServicePack);
		CtInsert(ct, _UU("SM_OS_SERVICE_PACK"), tmp);
	}

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVendorName);
	CtInsert(ct, _UU("SM_OS_VENDER_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVersion);
	CtInsert(ct, _UU("SM_OS_VERSION"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelName);
	CtInsert(ct, _UU("SM_OS_KERNEL_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelVersion);
	CtInsert(ct, _UU("SM_OS_KERNEL_VERSION"), tmp);

	CtFree(ct, c);

	FreeRpcServerInfo(&t);

	FreeParamValueList(o);

	return 0;
}

// HUB の種類の文字列を取得
wchar_t *GetHubTypeStr(UINT type)
{
	if (type == HUB_TYPE_FARM_STATIC)
	{
		return _UU("SM_HUB_STATIC");
	}
	else if (type == HUB_TYPE_FARM_DYNAMIC)
	{
		return _UU("SM_HUB_DYNAMIC");
	}
	return _UU("SM_HUB_STANDALONE");
}

// サーバーの種類の文字列を取得
wchar_t *GetServerTypeStr(UINT type)
{
	if (type == SERVER_TYPE_FARM_CONTROLLER)
	{
		return _UU("SM_FARM_CONTROLLER");
	}
	else if (type == SERVER_TYPE_FARM_MEMBER)
	{
		return _UU("SM_FARM_MEMBER");
	}
	return _UU("SM_SERVER_STANDALONE");
}

// ServerStatusGet コマンド
UINT PsServerStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SERVER_STATUS t;
	wchar_t tmp[MAX_PATH];
	char tmp2[MAX_PATH];
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	ret = ScGetServerStatus(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_2"), false);

	// サーバーの種類
	CtInsert(ct, _UU("SM_ST_SERVER_TYPE"),
		t.ServerType == SERVER_TYPE_STANDALONE ? _UU("SM_SERVER_STANDALONE") :
		t.ServerType == SERVER_TYPE_FARM_MEMBER ? _UU("SM_FARM_MEMBER") : _UU("SM_FARM_CONTROLLER"));

	// TCP コネクション数
	UniToStru(tmp, t.NumTcpConnections);
	CtInsert(ct, _UU("SM_ST_NUM_TCP"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// ローカル TCP コネクション数
		UniToStru(tmp, t.NumTcpConnectionsLocal);
		CtInsert(ct, _UU("SM_ST_NUM_TCP_LOCAL"), tmp);

		// リモート TCP コネクション数
		UniToStru(tmp, t.NumTcpConnectionsRemote);
		CtInsert(ct, _UU("SM_ST_NUM_TCP_REMOTE"), tmp);
	}

	// 仮想 HUB 数
	UniToStru(tmp, t.NumHubTotal);
	CtInsert(ct, _UU("SM_ST_NUM_HUB_TOTAL"), tmp);

	if (t.ServerType != SERVER_TYPE_STANDALONE)
	{
		// スタティック HUB 数
		UniToStru(tmp, t.NumHubStatic);
		CtInsert(ct, _UU("SM_ST_NUM_HUB_STATIC"), tmp);

		// ダイナミック HUB 数
		UniToStru(tmp, t.NumHubDynamic);
		CtInsert(ct, _UU("SM_ST_NUM_HUB_DYNAMIC"), tmp);
	}

	// セッション数
	UniToStru(tmp, t.NumSessionsTotal);
	CtInsert(ct, _UU("SM_ST_NUM_SESSION_TOTAL"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// ローカルセッション数
		UniToStru(tmp, t.NumSessionsLocal);
		CtInsert(ct, _UU("SM_ST_NUM_SESSION_LOCAL"), tmp);

		// ローカルセッション数
		UniToStru(tmp, t.NumSessionsRemote);
		CtInsert(ct, _UU("SM_ST_NUM_SESSION_REMOTE"), tmp);
	}

	// MAC テーブル数
	UniToStru(tmp, t.NumMacTables);
	CtInsert(ct, _UU("SM_ST_NUM_MAC_TABLE"), tmp);

	// IP テーブル数
	UniToStru(tmp, t.NumIpTables);
	CtInsert(ct, _UU("SM_ST_NUM_IP_TABLE"), tmp);

	// ユーザー数
	UniToStru(tmp, t.NumUsers);
	CtInsert(ct, _UU("SM_ST_NUM_USERS"), tmp);

	// グループ数
	UniToStru(tmp, t.NumGroups);
	CtInsert(ct, _UU("SM_ST_NUM_GROUPS"), tmp);

	// 割り当て済みライセンス数
	UniToStru(tmp, t.AssignedClientLicenses);
	CtInsert(ct, _UU("SM_ST_CLIENT_LICENSE"), tmp);

	UniToStru(tmp, t.AssignedBridgeLicenses);
	CtInsert(ct, _UU("SM_ST_BRIDGE_LICENSE"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UniToStru(tmp, t.AssignedClientLicensesTotal);
		CtInsert(ct, _UU("SM_ST_CLIENT_LICENSE_EX"), tmp);

		UniToStru(tmp, t.AssignedBridgeLicensesTotal);
		CtInsert(ct, _UU("SM_ST_BRIDGE_LICENSE_EX"), tmp);
	}

	// トラフィック
	CmdInsertTrafficInfo(ct, &t.Traffic);

	// サーバー起動時刻
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartTime), NULL);
	CtInsert(ct, _UU("SM_ST_START_TIME"), tmp);

	// 現在時刻
	GetDateTimeStrMilli64(tmp2, sizeof(tmp2), SystemToLocal64(t.CurrentTime));
	StrToUni(tmp, sizeof(tmp), tmp2);
	CtInsert(ct, _UU("SM_ST_CURRENT_TIME"), tmp);

	// Tick 値
	UniFormat(tmp, sizeof(tmp), L"%I64u", t.CurrentTick);
	CtInsert(ct, _UU("SM_ST_CURRENT_TICK"), tmp);

	// メモリ情報
	if (t.MemInfo.TotalMemory != 0)
	{
		char vv[128];

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_TOTAL_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_USED_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreeMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_FREE_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_TOTAL_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_USED_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreePhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_FREE_PHYS"), tmp);
	}

	CtFree(ct, c);

	FreeParamValueList(o);

	return 0;
}

// トラフィック情報を LVB に追加
void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t)
{
	wchar_t tmp[MAX_SIZE];
	char vv[128];
	// 引数チェック
	if (ct == NULL || t == NULL)
	{
		return;
	}

	// 送信情報
	ToStr3(vv, sizeof(vv), t->Send.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_BCAST_SIZE"), tmp);

	// 受信情報
	ToStr3(vv, sizeof(vv), t->Recv.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_BCAST_SIZE"), tmp);
}

// ポート番号の入力
wchar_t *CmdPromptPort(CONSOLE *c, void *param)
{
	wchar_t *prompt_str;

	if (param != NULL)
	{
		prompt_str = (wchar_t *)param;
	}
	else
	{
		prompt_str = _UU("CMD_PROPMT_PORT");
	}

	return c->ReadLine(c, prompt_str, true);
}

// ポート番号の検証
bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param)
{
	UINT i;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	i = UniToInt(str);

	if (i >= 1 && i <= 65535)
	{
		return true;
	}

	c->Write(c, _UU("CMD_EVAL_PORT"));

	return false;
}

// ListenerCreate コマンド
UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerCreate_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScCreateListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// About コマンド
UINT PsAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// バージョン情報を表示する
	CmdPrintAbout(c);

	FreeParamValueList(o);

	return 0;
}

// 新しいサーバー管理コンテキストの作成
PS *NewPs(CONSOLE *c, RPC *rpc, char *servername, UINT serverport, char *hubname, char *adminhub, wchar_t *cmdline)
{
	PS *ps;
	// 引数チェック
	if (c == NULL || rpc == NULL || servername == NULL)
	{
		return NULL;
	}

	if (IsEmptyStr(hubname))
	{
		hubname = NULL;
	}
	if (IsEmptyStr(adminhub))
	{
		adminhub = NULL;
	}
	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	ps = ZeroMalloc(sizeof(PS));
	ps->ConsoleForServer = true;
	ps->ServerPort = serverport;
	ps->ServerName = CopyStr(servername);
	ps->Console = c;
	ps->Rpc = rpc;
	ps->HubName = CopyStr(hubname);
	ps->LastError = 0;
	ps->AdminHub = CopyStr(adminhub);
	ps->CmdLine = CopyUniStr(cmdline);

	return ps;
}

// サーバー管理コンテキストの解放
void FreePs(PS *ps)
{
	// 引数チェック
	if (ps == NULL)
	{
		return;
	}

	Free(ps->HubName);
	Free(ps->AdminHub);
	Free(ps->CmdLine);
	Free(ps->ServerName);

	Free(ps);
}

// サーバー管理ツール
UINT PsConnect(CONSOLE *c, char *host, UINT port, char *hub, char *adminhub, wchar_t *cmdline, char *password)
{
	UINT retcode = 0;
	RPC *rpc = NULL;
	CEDAR *cedar;
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];
	bool b = false;
	// 引数チェック
	if (c == NULL || host == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (port == 0)
	{
		port = 443;
	}
	if (hub != NULL)
	{
		adminhub = NULL;
	}

	cedar = NewCedar(NULL, NULL);

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"VPNCMD");
	StrCpy(o.Hostname, sizeof(o.Hostname), host);
	o.Port = port;
	o.ProxyType = PROXY_DIRECT;

	Hash(hashed_password, password, StrLen(password), true);

	if (IsEmptyStr(password) == false)
	{
		b = true;
	}

	// 接続
	while (true)
	{
		UINT err;

		rpc = AdminConnectEx(cedar, &o, hub, hashed_password, &err, CEDAR_CUI_STR);
		if (rpc == NULL)
		{
			// 失敗
			retcode = err;

			if (err == ERR_ACCESS_DENIED)
			{
				char *pass;
				// パスワード違い
				if (b)
				{
					// パスワードを入力させる
					c->Write(c, _UU("CMD_UTVPNCMD_PASSWORD_1"));
				}

				b = true;

				pass = c->ReadPassword(c, _UU("CMD_UTVPNCMD_PASSWORD_2"));
				c->Write(c, L"");

				if (pass != NULL)
				{
					Hash(hashed_password, pass, StrLen(pass), true);
					Free(pass);
				}
				else
				{
					break;
				}
			}
			else
			{
				// その他のエラー
				CmdPrintError(c, err);
				break;
			}
		}
		else
		{
			PS *ps;

			// 成功
			ps = NewPs(c, rpc, host, port, hub, adminhub, cmdline);
			PsMain(ps);
			retcode = ps->LastError;
			FreePs(ps);
			AdminDisconnect(rpc);
			break;
		}
	}

	ReleaseCedar(cedar);

	return retcode;
}

// エラーを表示する
void CmdPrintError(CONSOLE *c, UINT err)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CMD_UTVPNCMD_ERROR"),
		err, GetUniErrorStr(err));
	c->Write(c, tmp);

	if (err == ERR_DISCONNECTED)
	{
		c->Write(c, _UU("CMD_DISCONNECTED_MSG"));
	}
}

// バージョン情報を表示する
void CmdPrintAbout(CONSOLE *c)
{
	CEDAR *cedar;
	wchar_t tmp[MAX_SIZE];
	char exe[MAX_PATH];
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	cedar = NewCedar(NULL, NULL);

	GetExeName(exe, sizeof(exe));

	UniFormat(tmp, sizeof(tmp), _UU("CMD_UTVPNCMD_ABOUT"),
		cedar->VerString, cedar->BuildInfo);

	c->Write(c, tmp);

	ReleaseCedar(cedar);
}

// ホスト名とポート番号をパースする (@ で区切る)
bool ParseHostPortAtmark(char *src, char **host, UINT *port, UINT default_port)
{
	TOKEN_LIST *t;
	bool ret = false;
	// 引数チェック
	if (src == NULL)
	{
		return false;
	}

	t = ParseToken(src, "@");
	if (t == NULL)
	{
		return false;
	}

	if (port != NULL)
	{
		*port = 0;
	}

	if (default_port == 0)
	{
		if (t->NumTokens < 2)
		{
			FreeToken(t);
			return false;
		}

		if (ToInt(t->Token[1]) == 0)
		{
			FreeToken(t);
			return false;
		}
	}

	if (t->NumTokens >= 2 && ToInt(t->Token[1]) == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens >= 1 && IsEmptyStr(t->Token[0]) == false)
	{
		ret = true;

		if (host != NULL)
		{
			*host = CopyStr(t->Token[0]);
			Trim(*host);
		}

		if (t->NumTokens >= 2)
		{
			if (port != NULL)
			{
				*port = ToInt(t->Token[1]);
			}
		}
	}

	if (port != NULL)
	{
		if (*port == 0)
		{
			*port = default_port;
		}
	}

	FreeToken(t);

	return ret;
}

// ホスト名とポート番号をパースする
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port)
{
	TOKEN_LIST *t;
	bool ret = false;
	// 引数チェック
	if (src == NULL)
	{
		return false;
	}

	if (StartWith(src, "["))
	{
		if (InStr(src, "]"))
		{
			// [target]:port の形式
			UINT i, n;
			char tmp[MAX_SIZE];

			StrCpy(tmp, sizeof(tmp), src);

			n = SearchStrEx(tmp, "]", 0, false);
			if (n != INFINITE)
			{
				UINT len = StrLen(tmp);

				for (i = n;i < len;i++)
				{
					if (tmp[i] == ':')
					{
						tmp[i] = '@';
					}
				}
			}

			return ParseHostPortAtmark(tmp, host, port, default_port);
		}
	}

	if (InStr(src, "@"))
	{
		// @ で区切られている
		return ParseHostPortAtmark(src, host, port, default_port);
	}

	t = ParseToken(src, ":");
	if (t == NULL)
	{
		return false;
	}

	if (port != NULL)
	{
		*port = 0;
	}

	if (default_port == 0)
	{
		if (t->NumTokens < 2)
		{
			FreeToken(t);
			return false;
		}

		if (ToInt(t->Token[1]) == 0)
		{
			FreeToken(t);
			return false;
		}
	}

	if (t->NumTokens >= 2 && ToInt(t->Token[1]) == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens >= 1 && IsEmptyStr(t->Token[0]) == false)
	{
		ret = true;

		if (host != NULL)
		{
			*host = CopyStr(t->Token[0]);
			Trim(*host);
		}

		if (t->NumTokens >= 2)
		{
			if (port != NULL)
			{
				*port = ToInt(t->Token[1]);
			}
		}
	}

	if (port != NULL)
	{
		if (*port == 0)
		{
			*port = default_port;
		}
	}

	FreeToken(t);

	return ret;
}

// vpncmd コマンドプロシージャ
UINT VpnCmdProc(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	char *target;
	bool server = false;
	bool client = false;
	bool tools = false;
	char *hostname = NULL;
	char *password;
	wchar_t *cmdline;
	bool host_inputted = false;
	UINT port = 0;
	UINT retcode = 0;
	PARAM args[] =
	{
		{"[host:port]", NULL, NULL, NULL, NULL},
		{"CLIENT", NULL, NULL, NULL, NULL},
		{"SERVER", NULL, NULL, NULL, NULL},
		{"TOOLS", NULL, NULL, NULL, NULL},
		{"HUB", NULL, NULL, NULL, NULL},
		{"ADMINHUB", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
		{"IN", NULL, NULL, NULL, NULL},
		{"OUT", NULL, NULL, NULL, NULL},
		{"CMD", NULL, NULL, NULL, NULL},
		{"CSV", NULL, NULL, NULL, NULL},
	};

	if (c->ConsoleType == CONSOLE_LOCAL)
	{
		// 起動パス情報の初期化
		VpnCmdInitBootPath();
	}

	if(c->ConsoleType != CONSOLE_CSV)
	{
		CmdPrintAbout(c);
		c->Write(c, L"");
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));

	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Client か Server か Tools かの指定
	if ((GetParamStr(o, "CLIENT") == NULL && GetParamStr(o, "SERVER") == NULL && GetParamStr(o, "TOOLS") == NULL) ||
		(GetParamStr(o, "CLIENT") != NULL && GetParamStr(o, "SERVER") != NULL && GetParamStr(o, "TOOLS") != NULL))
	{
		wchar_t *ret;
		UINT code;
		// Client か Server か Tools かが指定されていない
		c->Write(c, _UU("CMD_UTVPNCMD_CS_1"));

		ret = c->ReadLine(c, _UU("CMD_UTVPNCMD_CS_2"), true);

		code = UniToInt(ret);
		Free(ret);

		switch (code)
		{
		case 1:
			// Server
			server = true;
			break;

		case 2:
			// Client
			client = true;
			break;

		case 3:
			// Tools
			tools = true;
			break;

		default:
			// 指定無し
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		c->Write(c, L"");
	}
	else
	{
		if (GetParamStr(o, "SERVER") != NULL)
		{
			server = true;
		}
		else if (GetParamStr(o, "CLIENT") != NULL)
		{
			client = true;
		}
		else
		{
			tools = true;
		}
	}

	// 接続先ホスト名
	target = CopyStr(GetParamStr(o, "[host:port]"));

	if (target == NULL && tools == false)
	{
		wchar_t *str;
		// ホスト名を入力させる
		if (server)
		{
			c->Write(c, _UU("CMD_UTVPNCMD_HOST_1"));
		}
		else if (client)
		{
			c->Write(c, _UU("CMD_UTVPNCMD_HOST_2"));
		}

		str = c->ReadLine(c, _UU("CMD_UTVPNCMD_HOST_3"), true);
		c->Write(c, L"");
		target = CopyUniToStr(str);
		Free(str);

		if (target == NULL)
		{
			// キャンセル
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		if (IsEmptyStr(target))
		{
			Free(target);
			target = CopyStr("localhost");
		}
	}
	else
	{
		// ユーザーがホスト名を指定した
		host_inputted = true;
	}

	if (tools == false)
	{
		if (ParseHostPort(target, &hostname, &port, 443) == false)
		{
			c->Write(c, _UU("CMD_MSG_INVALID_HOSTNAME"));
			Free(target);
			FreeParamValueList(o);
			return ERR_INVALID_PARAMETER;
		}
	}

	// パスワード
	password = GetParamStr(o, "PASSWORD");
	if (password == NULL)
	{
		password = "";
	}

	// コマンドライン
	cmdline = GetParamUniStr(o, "CMD");

	if (server)
	{
		// サーバーとしての処理
		char *hub;
		char *adminhub = NULL;

		hub = CopyStr(GetParamStr(o, "HUB"));
		adminhub = GetParamStr(o, "ADMINHUB");

		// 仮想 HUB 管理モードで指定する仮想 HUB を決定する
		if (hub == NULL)
		{
			if (host_inputted == false)
			{
				wchar_t *s;
				// ユーザーがホスト名をコマンドラインで指定していない場合は
				// プロンプトを表示して仮想 HUB 名も取得する
				c->Write(c, _UU("CMD_UTVPNCMD_HUB_1"));

				s = c->ReadLine(c, _UU("CMD_UTVPNCMD_HUB_2"), true);

				hub = CopyUniToStr(s);
				Free(s);
			}
		}

		if (IsEmptyStr(hub))
		{
			Free(hub);
			hub = NULL;
		}
		if (IsEmptyStr(adminhub))
		{
			adminhub = NULL;
		}

		retcode = PsConnect(c, hostname, port, hub, adminhub, cmdline, password);

		Free(hub);
	}
	else if (client)
	{
		// クライアントとしての処理
		Trim(target);

		retcode = PcConnect(c, target, cmdline, password);
	}
	else if (tools)
	{
		// VPN Tools として処理
		retcode = PtConnect(c, cmdline);
	}

	Free(hostname);
	Free(target);
	FreeParamValueList(o);

	return retcode;
}

// vpncmd のエントリポイント
UINT CommandMain(wchar_t *command_line)
{
	UINT ret = 0;
	wchar_t *infile, *outfile;
	char *a_infile, *a_outfile;
	wchar_t *csvmode;
	CONSOLE *c;

	// 引数チェック
	if (command_line == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// /in と /out の項目だけ先読みする
	infile = ParseCommand(command_line, L"in");
	outfile = ParseCommand(command_line, L"out");
	if (UniIsEmptyStr(infile))
	{
		Free(infile);
		infile = NULL;
	}
	if (UniIsEmptyStr(outfile))
	{
		Free(outfile);
		outfile = NULL;
	}

	a_infile = CopyUniToStr(infile);
	a_outfile = CopyUniToStr(outfile);

	// ローカルコンソールの確保
	c = NewLocalConsole(infile, outfile);
	if (c != NULL)
	{
		// vpncmd コマンドの定義
		CMD cmd[] =
		{
			{"utvpncmd", VpnCmdProc},
		};

		// CSV モードを先読みしてチェック
		csvmode = ParseCommand(command_line, L"csv");
		if(csvmode != NULL)
		{
			Free(csvmode);
			c->ConsoleType = CONSOLE_CSV;
		}

		if (DispatchNextCmdEx(c, command_line, ">", cmd, sizeof(cmd) / sizeof(cmd[0]), NULL) == false)
		{
			ret = ERR_INVALID_PARAMETER;
		}
		else
		{
			ret = c->RetCode;
		}

		// ローカルコンソールの解放
		c->Free(c);
	}
	else
	{
		Print("Error: Couldn't open local console.\n");
	}

	Free(a_infile);
	Free(a_outfile);
	Free(infile);
	Free(outfile);

	return ret;
}

