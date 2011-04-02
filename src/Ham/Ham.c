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

// Ham.c
// Hamster テストプログラム
// (UT-VPN の動作テストを行うための CUI プログラム。)



#define	HAM_C

#ifdef	WIN32
#define	HAM_WIN32
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <DbgHelp.h>
#include <Iphlpapi.h>
#include <wtsapi32.h>
#include "../pencore/resource.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "Ham.h"

// テスト関数一覧定義
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
} TEST_LIST;

typedef struct TESTST
{
	USHORT a:4, b:4;
} TESTST;

void test(UINT num, char **arg)
{
}

// デバッグ
void debug(UINT num, char **arg)
{
	// カーネル状態の表示
	if (g_debug)
	{
		PrintKernelStatus();
	}

	// デバッグ情報の表示
	if (g_memcheck)
	{
		PrintDebugInformation();
	}
}

void client_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	MsWriteCallingServiceManagerProcessId("utvpnclient", MsGetCurrentProcessId());
#endif	// OS_WIN32

	Print("Client Test.\n");
	CtStartClient();
	GetLine(NULL, 0);
	CtStopClient();

#ifdef	OS_WIN32
	MsWriteCallingServiceManagerProcessId("utvpnclient", 0);
#endif	// OS_WIN32
}

void server_test(UINT num, char **arg)
{
	UINT p[] = {52, 80, 8080, 3128};
	Print("Server Test.\n");

	if (num != 0)
	{
		SERVER_CONFIG_FILE_NAME = "@vpn_member_server.config";
	}

	StInit();

	StStartServer(false);

	GetLine(NULL, 0);

	if (0 && num != 0)
	{
		UINT ports[] = {443, 992};
		UCHAR password[SHA1_SIZE];
		Hash(password, "", 0, true);
		SiSetServerType(StGetServer(), SERVER_TYPE_FARM_MEMBER, 0x0100007f,
			sizeof(ports) / sizeof(ports[0]), ports, "pc1.sec.softether.co.jp", 5555, password, 0, false);
		GetLine(NULL, 0);
	}

	if (0 && num == 0)
	{
		HUB *h = GetHub(StGetServer()->Cedar, "DEFAULT");
		SetHubOffline(h);
		GetLine(NULL, 0);
		SetHubOnline(h);
		GetLine(NULL, 0);
		ReleaseHub(h);
	}

	StStopServer();

	StFree();
}

void disablevlan(UINT num, char **arg)
{
#ifdef	OS_WIN32
	bool ok;
	if (num < 1)
	{
		Print("NO NAME.\n");
		return;
	}

	ok = MsDisableVLan(arg[0]);

#ifdef	VISTA_HAM
	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
#endif
#endif	// OS_WIN32
}

void enablevlan(UINT num, char **arg)
{
#ifdef	OS_WIN32
	bool ok;
	if (num < 1)
	{
		Print("NO NAME.\n");
		return;
	}

	ok = MsEnableVLan(arg[0]);

#ifdef	VISTA_HAM
	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
#endif
#endif	// OS_WIN32
}

void instvlan(UINT num, char **arg)
{
#ifdef	OS_WIN32
	KAKUSHI *k = NULL;
	bool ok;
	if (num < 1)
	{
		Print("NO NAME.\n");
		return;
	}

	InitWinUi(L"VPN", _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	if (MsIsNt())
	{
		k = InitKakushi();
	}

	ok = MsInstallVLan(VLAN_ADAPTER_NAME_TAG, VLAN_CONNECTION_NAME, arg[0]);

	FreeKakushi(k);

	FreeWinUi();

#ifdef	VISTA_HAM
	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
#endif
#endif
}

void upgradevlan(UINT num, char **arg)
{
#ifdef	OS_WIN32
	bool ok;
	KAKUSHI *k = NULL;
	if (num < 1)
	{
		Print("NO NAME.\n");
		return;
	}

	InitWinUi(L"VPN", _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	if (MsIsNt())
	{
		k = InitKakushi();
	}

	ok = MsUpgradeVLan(VLAN_ADAPTER_NAME_TAG, VLAN_CONNECTION_NAME, arg[0]);

	FreeKakushi(k);

	FreeWinUi();

#ifdef	VISTA_HAM
	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
#endif
#endif
}

void uninstvlan(UINT num, char **arg)
{
#ifdef	OS_WIN32
	bool ok;
	if (num < 1)
	{
		Print("NO NAME.\n");
		return;
	}

	ok = MsUninstallVLan(arg[0]);

#ifdef	VISTA_HAM
	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
#endif
#endif
}

void sm_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	SMExec();
#endif
}

void cm_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	CMExec();
#endif
}

TEST_LIST test_list[] =
{
	{"cc", client_test},
	{"ss", server_test},
	{"instvlan", instvlan},
	{"uninstvlan", uninstvlan},
	{"upgradevlan", upgradevlan},
	{"enablevlan", enablevlan},
	{"disablevlan", disablevlan},
	{"cm", cm_test},
	{"sm", sm_test},
	{"test", test},
};

// テスト関数
void TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;

	Print("SoftEther UT-VPN Hamster Tester\n\n"
		"Copyright (C) 2004-2010 SoftEther Corporation.\nCopyright (C) 2004-2010 University of Tsukuba, Japan.\n"
		"Copyright (C) 2003-2010 Daiyuu Nobori.\nAll Rights Reserved.\n\n");

#ifdef	OS_WIN32
	MsSetEnableMinidump(false);
#endif	// OS_WIN32

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
			GetLine(tmp, sizeof(tmp));
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			if (StartWith(tmp, "utvpncmd"))
			{
				wchar_t *s = CopyStrToUni(tmp);
				CommandMain(s);
				Free(s);
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
}

#ifdef	WIN32
// winmain 関数
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	main(0, NULL);
}
#endif

// main 関数
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;

	printf("Starting Test Program...\n");

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	InitMayaqua(memchk, true, argc, argv);
	EnableProbe(true);
	InitCedar();
	SetHamMode();
	TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return 0;
}

