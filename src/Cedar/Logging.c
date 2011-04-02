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

// Logging.c
// ログ保存モジュール

#include "CedarPch.h"

static char *delete_targets[] =
{
	"backup.vpn_bridge.config",
	"backup.vpn_client.config",
	"backup.vpn_server.config",
	"backup.etherlogger.config",
	"packet_log",
	"etherlogger_log",
	"secure_nat_log",
	"security_log",
	"server_log",
	"bridge_log",
};

// syslog の送信
void SendSysLog(SLOG *g, wchar_t *str)
{
	UCHAR *buf;
	UINT buf_size;
	// 引数チェック
	if (g == NULL || str == NULL)
	{
		return;
	}

	buf_size = CalcUniToUtf8(str);
	buf = ZeroMalloc(buf_size);
	UniToUtf8(buf, buf_size, str);

	if (buf_size >= 1024)
	{
		buf_size = 1023;
	}

	Lock(g->lock);
	{
		if (Tick64() >= g->NextPollIp)
		{
			IP ip;

			if (GetIP(&ip, g->HostName))
			{
				g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL;
				Copy(&g->DestIp, &ip, sizeof(IP));
			}
			else
			{
				g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL_NG;
			}
		}

		if (g->DestPort != 0 && IsZeroIp(&g->DestIp) == false)
		{
			SendTo(g->Udp, &g->DestIp, g->DestPort, buf, buf_size);
		}
	}
	Unlock(g->lock);

	Free(buf);
}

// syslog クライアントの解放
void FreeSysLog(SLOG *g)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	DeleteLock(g->lock);
	ReleaseSock(g->Udp);
	Free(g);
}

// syslog クライアントの設定
void SetSysLog(SLOG *g, char *hostname, UINT port)
{
	IP ip;
	// 引数チェック
	if (g == NULL)
	{
		return;
	}
	if (port == 0)
	{
		port = SYSLOG_PORT;
	}

	if (hostname == NULL)
	{
		hostname = "";
	}

	Zero(&ip, sizeof(IP));
	GetIP(&ip, hostname);

	Lock(g->lock);
	{
		Copy(&g->DestIp, &ip, sizeof(IP));
		g->DestPort = port;
		StrCpy(g->HostName, sizeof(g->HostName), hostname);
		g->NextPollIp = Tick64() + IsZeroIp(&ip) ? SYSLOG_POLL_IP_INTERVAL_NG : SYSLOG_POLL_IP_INTERVAL;
	}
	Unlock(g->lock);
}

// syslog クライアントの作成
SLOG *NewSysLog(char *hostname, UINT port)
{
	// 引数チェック
	SLOG *g = ZeroMalloc(sizeof(SLOG));

	g->lock = NewLock();
	g->Udp = NewUDP(0);

	SetSysLog(g, hostname, port);

	return g;
}

// ディスクに十分な空き容量があるかチェックする
bool CheckEraserDiskFreeSpace(ERASER *e)
{
	UINT64 s;
	// 引数チェック
	if (e == NULL)
	{
		return true;
	}

	// ディスクの空き容量を取得する
	if (GetDiskFree(e->DirName, &s, NULL, NULL) == false)
	{
		// 取得失敗
		return true;
	}

	if (e->MinFreeSpace > s)
	{
		// 空き容量が指定されたバイト数未満である
		return false;
	}

	// 十分空いている
	return true;
}

// 削除対象ファイルリストを解放する
void FreeEraseFileList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);
		Free(f->FullPath);
		Free(f);
	}

	ReleaseList(o);
}

// 削除対象ファイルリストを表示する
void PrintEraseFileList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);
		Print("%I64u - %s\n", f->UpdateTime, f->FullPath);
	}
}

// 指定されたディレクトリの削除対象ファイルリストを生成する
void EnumEraseFile(LIST *o, char *dirname)
{
	DIRLIST *dir;
	UINT i;
	char tmp[MAX_PATH];
	// 引数チェック
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	// 列挙
	dir = EnumDir(dirname);

	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];
		Format(tmp, sizeof(tmp), "%s/%s", dirname, e->FileName);
		NormalizePath(tmp, sizeof(tmp), tmp);

		if (e->Folder == false)
		{
			// ファイル
			ERASE_FILE *f;

			if (EndWith(tmp, ".log") || EndWith(tmp, ".config"))
			{
				// ログファイルと .config ファイルのみを対象とする
				f = ZeroMalloc(sizeof(ERASE_FILE));
				f->FullPath = CopyStr(tmp);
				f->UpdateTime = e->UpdateDate;

				Add(o, f);
			}
		}
		else
		{
			// フォルダ
			EnumEraseFile(o, tmp);
		}
	}

	FreeDir(dir);
}

// 削除対象ファイルリストを生成する
LIST *GenerateEraseFileList(ERASER *e)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (e == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareEraseFile);

	// 各ディレクトリを走査する
	for (i = 0;i < sizeof(delete_targets) / sizeof(delete_targets[0]);i++)
	{
		char dirname[MAX_PATH];
		Format(dirname, sizeof(dirname), "%s/%s", e->DirName, delete_targets[i]);

		EnumEraseFile(o, dirname);
	}

	// ソートする
	Sort(o);

	return o;
}

// 不要ファイルの消去処理
void EraserMain(ERASER *e)
{
	LIST *o;
	UINT i;
	bool ok = false;
	char bs[64];
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	// まず空き容量をチェック
	if (CheckEraserDiskFreeSpace(e))
	{
		// 十分空いている
		return;
	}

	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);

	// ファイル一覧の生成
	o = GenerateEraseFileList(e);

	// ファイルを古い順に 1 つずつ削除してみる
	for (i = 0;i < LIST_NUM(o);i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);

		// ファイルを削除する
		if (FileDelete(f->FullPath))
		{
			ELog(e, "LE_DELETE", bs, f->FullPath);
		}

		// 削除したあと空き容量を確認してみる
		if (CheckEraserDiskFreeSpace(e))
		{
			// 空き容量が回復した
			ok = true;
			break;
		}
	}

	// ファイル一覧の解放
	FreeEraseFileList(o);

	if (e->LastFailed == false && ok == false)
	{
		// 空き容量が足りないがこれ以上ファイルを削除できない状態になってしまった
		ELog(e, "LE_NOT_ENOUGH_FREE", bs);
	}

	e->LastFailed = ok ? false : true;
}

// 削除するファイル項目の比較
int CompareEraseFile(void *p1, void *p2)
{
	ERASE_FILE *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(ERASE_FILE **)p1;
	f2 = *(ERASE_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	if (f1->UpdateTime > f2->UpdateTime)
	{
		return 1;
	}
	else if (f1->UpdateTime == f2->UpdateTime)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

// 自動ファイル削除器スレッド
void EraserThread(THREAD *t, void *p)
{
	ERASER *e = (ERASER *)p;
	char bs[64];
	// 引数チェック
	if (t == NULL || e == NULL)
	{
		return;
	}

	// 監視を開始
	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);
	ELog(e, "LE_START", e->DirName, bs);

	while (e->Halt == false)
	{
		// 一定間隔ごとにディスクの空き容量をチェックする
		EraserMain(e);

		Wait(e->HaltEvent, DISK_FREE_CHECK_INTERVAL);
	}
}

// 新しい自動ファイル削除器の作成
ERASER *NewEraser(LOG *log, UINT64 min_size)
{
	ERASER *e;
	char dir[MAX_PATH];

	if (min_size == 0)
	{
		min_size = DISK_FREE_SPACE_DEFAULT;
	}

	if (min_size < DISK_FREE_SPACE_MIN)
	{
		min_size = DISK_FREE_SPACE_MIN;
	}

	e = ZeroMalloc(sizeof(ERASER));

	GetExeDir(dir, sizeof(dir));

	e->Log = log;
	e->MinFreeSpace = min_size;
	e->DirName = CopyStr(dir);
	e->HaltEvent = NewEvent();

	e->Thread = NewThread(EraserThread, e);

	return e;
}

// 自動ファイル削除器の解放
void FreeEraser(ERASER *e)
{
	// 引数チェック
	if (e == NULL)
	{
		return;
	}

	e->Halt = true;
	Set(e->HaltEvent);
	WaitThread(e->Thread, INFINITE);
	ReleaseThread(e->Thread);
	ReleaseEvent(e->HaltEvent);

	Free(e->DirName);
	Free(e);
}

// デバッグログをとる (可変長引数)
void DebugLog(CEDAR *c, char *fmt, ...)
{
	char buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}
	if (c->DebugLog == NULL)
	{
		return;
	}

	va_start(args, fmt);
	FormatArgs(buf, sizeof(buf), fmt, args);

	InsertStringRecord(c->DebugLog, buf);
	va_end(args);
}

// 自動ファイル削除器のログをとる
void ELog(ERASER *e, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	InsertUnicodeRecord(e->Log, buf);

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", buf);
	}
	va_end(args);
}

// サーバーのログをとる
void ServerLog(CEDAR *c, wchar_t *fmt, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniFormatArgs(buf, sizeof(buf), fmt, args);

	WriteServerLog(c, buf);
	va_end(args);
}
void SLog(CEDAR *c, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	WriteServerLog(c, buf);
	va_end(args);
}

// クライアントログ
void CLog(CLIENT *c, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	if (c == NULL || c->NoSaveLog)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	WriteClientLog(c, buf);
	va_end(args);
}

// HUB のセキュリティログをとる
void HubLog(HUB *h, wchar_t *fmt, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniFormatArgs(buf, sizeof(buf), fmt, args);

	WriteHubLog(h, buf);
	va_end(args);
}
void ALog(ADMIN *a, HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	wchar_t tmp[MAX_SIZE * 2];
	va_list args;
	RPC *r;
	// 引数チェック
	if (a == NULL || name == NULL)
	{
		return;
	}

	r = a->Rpc;

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	if (h == NULL)
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_1"), r->Name);
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_2"), r->Name, h->Name);
	}

	UniStrCat(tmp, sizeof(tmp), buf);

	if (h == NULL)
	{
		WriteServerLog(((ADMIN *)r->Param)->Server->Cedar, tmp);
	}
	else
	{
		WriteHubLog(h, tmp);
	}
	va_end(args);
}
void HLog(HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	WriteHubLog(h, buf);
	va_end(args);
}
void NLog(VH *v, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	static wchar_t snat_prefix[] = L"SecureNAT: ";
	va_list args;
	// 引数チェック
	if (name == NULL || v == NULL || v->nat == NULL || v->nat->SecureNAT == NULL)
	{
		return;
	}

	va_start(args, name);
	Copy(buf, snat_prefix, sizeof(snat_prefix));
	UniFormatArgs(&buf[11], sizeof(buf) - 12 * sizeof(wchar_t), _UU(name), args);

	WriteHubLog(v->nat->SecureNAT->Hub, buf);
	va_end(args);
}

// HUB のセキュリティログを保存する
void WriteHubLog(HUB *h, wchar_t *str)
{
	wchar_t buf[MAX_SIZE * 2];
	SERVER *s;
	// 引数チェック
	if (h == NULL || str == NULL)
	{
		return;
	}

	s = h->Cedar->Server;

	UniFormat(buf, sizeof(buf), L"[HUB \"%S\"] %s", h->Name, str);

	WriteServerLog(h->Cedar, buf);

	if (h->LogSetting.SaveSecurityLog == false)
	{
		return;
	}

	InsertUnicodeRecord(h->SecurityLogger, str);
}

// クライアントログを保存する
void WriteClientLog(CLIENT *c, wchar_t *str)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	InsertUnicodeRecord(c->Logger, str);
}

// サーバーのセキュリティログを保存する
void WriteServerLog(CEDAR *c, wchar_t *str)
{
	SERVER *s;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return;
	}

	s = c->Server;
	if (s == NULL)
	{
		return;
	}

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", str);
	}

	InsertUnicodeRecord(s->Logger, str);
}

// 複数行にわたるログを書き出す
void WriteMultiLineLog(LOG *g, BUF *b)
{
	// 引数チェック
	if (g == NULL || b == NULL)
	{
		return;
	}

	SeekBuf(b, 0, 0);

	while (true)
	{
		char *s = CfgReadNextLine(b);
		if (s == NULL)
		{
			break;
		}

		if (IsEmptyStr(s) == false)
		{
			InsertStringRecord(g, s);
		}

		Free(s);
	}
}

// セキュリティログをとる (可変長引数) ※ 廃止
void SecLog(HUB *h, char *fmt, ...)
{
	char buf[MAX_SIZE * 2];
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	if (h->LogSetting.SaveSecurityLog == false)
	{
		return;
	}

	va_start(args, fmt);
	FormatArgs(buf, sizeof(buf), fmt, args);

	WriteSecurityLog(h, buf);
	va_end(args);
}

// セキュリティログをとる
void WriteSecurityLog(HUB *h, char *str)
{
	// 引数チェック
	if (h == NULL || str == NULL)
	{
		return;
	}

	InsertStringRecord(h->SecurityLogger, str);
}

// パケットログをとる
void PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet)
{
	UINT level;
	PKT *p;
	PACKET_LOG *pl;
	SERVER *s;
	bool no_log = false;
	// 引数チェック
	if (hub == NULL || src_session == NULL || packet == NULL)
	{
		return;
	}

	s = hub->Cedar->Server;

	if (hub->LogSetting.SavePacketLog == false)
	{
		// パケットログをとらない
		return;
	}

	if (Cmp(hub->HubMacAddr, packet->MacAddressSrc, 6) == 0 ||
		Cmp(hub->HubMacAddr, packet->MacAddressDest, 6) == 0)
	{
		return;
	}

	// ロギングレベルの決定
	level = CalcPacketLoggingLevel(hub, packet);
	if (level == PACKET_LOG_NONE)
	{
		// 保存しない
		return;
	}

	if (hub->Option != NULL)
	{
		if (hub->Option->NoIPv4PacketLog && (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4))
		{
			// IPv4 パケットログを一切保存しない
			return;
		}

		if (hub->Option->NoIPv6PacketLog && packet->TypeL3 == L3_IPV6)
		{
			// IPv6 パケットログを一切保存しない
			return;
		}
	}

	if (s->Cedar->Bridge == false)
	{
		if (s->LicenseSystem != NULL && s->LicenseSystem->Status != NULL)
		{
			if (s->LicenseSystem->Status->AllowEnterpriseFunction == false &&
				s->LicenseSystem->Status->Edition != 0)
			{
				// VPN Server の製品エディションが低い場合はパケットログのうち一部
				// を保存しない
				no_log = true;
			}
		}
	}

	// パケットのクローン
	p = ClonePacket(packet, level == PACKET_LOG_ALL ? true : false);

	// 情報の取得
	pl = ZeroMalloc(sizeof(PACKET_LOG));
	pl->Cedar = hub->Cedar;
	pl->Packet = p;
	pl->NoLog = no_log;
	if (src_session != NULL)
	{
		pl->SrcSessionName = CopyStr(src_session->Name);
	}
	else
	{
		pl->SrcSessionName = CopyStr("");
	}
	if (dest_session != NULL)
	{
		pl->DestSessionName = CopyStr(dest_session->Name);
	}
	else
	{
		pl->DestSessionName = CopyStr("");
	}

	if (src_session->LoggingRecordCount != NULL)
	{
		UINT n = 0;
		while (src_session->LoggingRecordCount->c >= 30000)
		{
			SleepThread(50);
			n++;
			if (n >= 5)
			{
				break;
			}
		}
	}

	pl->SrcSession = src_session;
	AddRef(src_session->ref);

	Inc(src_session->LoggingRecordCount);

	// パケットログの挿入
	InsertRecord(hub->PacketLogger, pl, PacketLogParseProc);
}

// 指定されたパケットのロギングレベルを計算する
UINT CalcPacketLoggingLevelEx(HUB_LOG *g, PKT *packet)
{
	UINT ret = 0;
	// 引数チェック
	if (g == NULL || packet == NULL)
	{
		return PACKET_LOG_NONE;
	}

	// Ethernet ログ
	ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ETHERNET]);

	switch (packet->TypeL3)
	{
	case L3_ARPV4:
		// ARP
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ARP]);
		break;

	case L3_IPV4:
		// IPv4
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_IP]);

		switch (packet->TypeL4)
		{
		case L4_ICMPV4:
			// ICMPv4
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ICMP]);
			break;

		case L4_TCP:
			// TCPv4
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP]);

			if (packet->L4.TCPHeader->Flag & TCP_SYN ||
				packet->L4.TCPHeader->Flag & TCP_RST ||
				packet->L4.TCPHeader->Flag & TCP_FIN)
			{
				// TCP SYN LOG
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
			}

			break;

		case L4_UDP:
			// UDPv4
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_UDP]);

			switch (packet->TypeL7)
			{
			case L7_DHCPV4:
				// DHCPv4
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_DHCP]);
				break;
			}

			break;
		}

		break;

	case L3_IPV6:
		// IPv6
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_IP]);

		switch (packet->TypeL4)
		{
		case L4_ICMPV6:
			// ICMPv6
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ICMP]);
			break;

		case L4_TCP:
			// TCPv6
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP]);

			if (packet->L4.TCPHeader->Flag & TCP_SYN ||
				packet->L4.TCPHeader->Flag & TCP_RST ||
				packet->L4.TCPHeader->Flag & TCP_FIN)
			{
				// TCP SYN LOG
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
			}

			break;

		case L4_UDP:
			// UDPv6
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_UDP]);

			break;
		}

		break;
	}

	return ret;
}
UINT CalcPacketLoggingLevel(HUB *hub, PKT *packet)
{
	// 引数チェック
	if (hub == NULL || packet == NULL)
	{
		return PACKET_LOG_NONE;
	}

	return CalcPacketLoggingLevelEx(&hub->LogSetting, packet);
}

// パケットログエントリを文字列に変換するプロシージャ
char *PacketLogParseProc(RECORD *rec)
{
	PACKET_LOG *pl;
	PKT *p;
	char *s;
	TOKEN_LIST *t;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (rec == NULL)
	{
		return NULL;
	}

	pl = (PACKET_LOG *)rec->Data;
	p = pl->Packet;

	// 各部を生成する
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = 16;
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	// 送信元セッション
	t->Token[0] = pl->SrcSessionName;

	// 宛先セッション
	t->Token[1] = pl->DestSessionName;

	// 送信元 MAC アドレス
	BinToStr(tmp, sizeof(tmp), p->MacAddressSrc, 6);

	t->Token[2] = CopyStr(tmp);
	// 宛先 MAC アドレス
	BinToStr(tmp, sizeof(tmp), p->MacAddressDest, 6);

	t->Token[3] = CopyStr(tmp);

	// MAC プロトコル
	snprintf(tmp, sizeof(tmp), "0x%04X", Endian16(p->MacHeader->Protocol));
	t->Token[4] = CopyStr(tmp);

	// パケットサイズ
	ToStr(tmp, p->PacketSize);
	t->Token[5] = CopyStr(tmp);

	// パケットログ本体は実装されていない
	t->Token[6] = CopyUniToUtf(_UU("LH_PACKET_LOG_NO_LOG"));

	s = GenCsvLine(t);
	FreeToken(t);

	// パケットデータを破棄する
	if (pl->PurePacket == false)
	{
		FreeClonePacket(p);
	}
	else
	{
		Free(p->PacketData);
		FreePacket(p);
	}

	// セッションを解放する
	if (pl->SrcSession != NULL)
	{
		Dec(pl->SrcSession->LoggingRecordCount);
		ReleaseSession(pl->SrcSession);
	}

	// PACKET_LOG を破棄する
	Free(pl);

	return s;
}

// TCP フラグを文字列に変換
char *TcpFlagStr(UCHAR flag)
{
	char tmp[MAX_SIZE];
	StrCpy(tmp, sizeof(tmp), "");

	if (flag & TCP_FIN)
	{
		StrCat(tmp, sizeof(tmp), "FIN+");
	}

	if (flag & TCP_SYN)
	{
		StrCat(tmp, sizeof(tmp), "SYN+");
	}

	if (flag & TCP_RST)
	{
		StrCat(tmp, sizeof(tmp), "RST+");
	}

	if (flag & TCP_PSH)
	{
		StrCat(tmp, sizeof(tmp), "PSH+");
	}

	if (flag & TCP_ACK)
	{
		StrCat(tmp, sizeof(tmp), "ACK+");
	}

	if (flag & TCP_URG)
	{
		StrCat(tmp, sizeof(tmp), "URG+");
	}

	if (StrLen(tmp) >= 1)
	{
		if (tmp[StrLen(tmp) - 1] == '+')
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	return CopyStr(tmp);
}

// ポート文字列の生成
char *PortStr(CEDAR *cedar, UINT port, bool udp)
{
	char tmp[MAX_SIZE];
	char *name;
	// 引数チェック
	if (cedar == NULL)
	{
		return NULL;
	}

	name = GetSvcName(cedar, udp, port);

	if (name == NULL)
	{
		snprintf(tmp, sizeof(tmp), "%u", port);
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "%s(%u)", name, port);
	}

	return CopyStr(tmp);
}

// カンマで区切られた文字列を生成する
char *GenCsvLine(TOKEN_LIST *t)
{
	UINT i;
	BUF *b;
	char *ret;
	// 引数チェック
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	for (i = 0;i < t->NumTokens;i++)
	{
		if (t->Token[i] != NULL)
		{
			ReplaceForCsv(t->Token[i]);
			if (StrLen(t->Token[i]) == 0)
			{
				WriteBuf(b, "-", 1);
			}
			else
			{
				WriteBuf(b, t->Token[i], StrLen(t->Token[i]));
			}
		}
		else
		{
			WriteBuf(b, "-", 1);
		}
		if (i != (t->NumTokens - 1))
		{
			WriteBuf(b, ",", 1);
		}
	}
	WriteBuf(b, "\0", 1);

	ret = (char *)b->Buf;

	Free(b);

	return ret;
}

// CSV の中に入る文字列を正しく置換する
void ReplaceForCsv(char *str)
{
	UINT i, len;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	// 空白があればトリミングする
	Trim(str);
	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		// カンマをアンダーバーに変換する
		if (str[i] == ',')
		{
			str[i] = '_';
		}
	}
}

// ログのディレクトリ名を設定
void SetLogDirName(LOG *g, char *dir)
{
	// 引数チェック
	if (g == NULL || dir == NULL)
	{
		return;
	}

	LockLog(g);
	{
		if (g->DirName != NULL)
		{
			Free(g->DirName);
		}
		g->DirName = CopyStr(dir);
	}
	UnlockLog(g);
}

// ログの名前を設定
void SetLogPrefix(LOG *g, char *prefix)
{
	// 引数チェック
	if (g == NULL || prefix == NULL)
	{
		return;
	}

	LockLog(g);
	{
		if (g->DirName != NULL)
		{
			Free(g->Prefix);
		}
		g->DirName = CopyStr(prefix);
	}
	UnlockLog(g);
}

// ログのスイッチ種類を設定
void SetLogSwitchType(LOG *g, UINT switch_type)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	LockLog(g);
	{
		g->SwitchType = switch_type;
	}
	UnlockLog(g);
}

// 文字列レコードの解析
char *StringRecordParseProc(RECORD *rec)
{
	// 引数チェック
	if (rec == NULL)
	{
		return NULL;
	}

	return (char *)rec->Data;
}

// ログに Unicode 文字列レコードを追加
void InsertUnicodeRecord(LOG *g, wchar_t *unistr)
{
	char *str;
	UINT size;
	// 引数チェック
	if (g == NULL || unistr == NULL)
	{
		return;
	}

	size = CalcUniToUtf8(unistr) + 32;
	str = ZeroMalloc(size);

	UniToUtf8((BYTE *)str, size, unistr);
	InsertStringRecord(g, str);
	Free(str);
}

// ログに文字列レコードを追加
void InsertStringRecord(LOG *g, char *str)
{
	char *str_copy;
	// 引数チェック
	if (g == NULL || str == NULL)
	{
		return;
	}

	str_copy = CopyStr(str);

	InsertRecord(g, str_copy, StringRecordParseProc);
}

// ログにレコードを追加
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc)
{
	RECORD *rec;
	// 引数チェック
	if (g == NULL || data == NULL || proc == NULL)
	{
		return;
	}

	rec = ZeroMalloc(sizeof(RECORD));
	rec->Tick = Tick64();
	rec->ParseProc = proc;
	rec->Data = data;

	LockQueue(g->RecordQueue);
	{
		InsertQueue(g->RecordQueue, rec);
	}
	UnlockQueue(g->RecordQueue);

	Set(g->Event);
}

// ログのロック
void LockLog(LOG *g)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
}

// ログのロック解除
void UnlockLog(LOG *g)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	Unlock(g->lock);
}

// ログファイル名の文字列部分を時刻とスイッチ規則から生成する
void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type)
{
	UINT64 time;
	SYSTEMTIME st;

	// 引数チェック
	if (str == NULL || g == NULL)
	{
		return;
	}

	if (g->CacheFlag)
	{
		if (g->LastTick == tick &&
			g->LastSwitchType == switch_type)
		{
			StrCpy(str, size, g->LastStr);
			return;
		}
	}

	time = TickToTime(tick);
	UINT64ToSystem(&st, SystemToLocal64(time));

	switch (switch_type)
	{
	case LOG_SWITCH_SECOND:	// 1 秒単位
		snprintf(str, size, "_%04u%02u%02u_%02u%02u%02u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		break;

	case LOG_SWITCH_MINUTE:	// 1 分単位
		snprintf(str, size, "_%04u%02u%02u_%02u%02u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
		break;

	case LOG_SWITCH_HOUR:	// 1 時間単位
		snprintf(str, size, "_%04u%02u%02u_%02u", st.wYear, st.wMonth, st.wDay, st.wHour);
		break;

	case LOG_SWITCH_DAY:	// 1 日単位
		snprintf(str, size, "_%04u%02u%02u", st.wYear, st.wMonth, st.wDay);
		break;

	case LOG_SWITCH_MONTH:	// 1 ヶ月単位
		snprintf(str, size, "_%04u%02u", st.wYear, st.wMonth);
		break;

	default:				// 切り替え無し
		snprintf(str, size, "");
		break;
	}

	g->CacheFlag = true;
	g->LastTick = tick;
	g->LastSwitchType = switch_type;
	StrCpy(g->LastStr, sizeof(g->LastStr), str);
}

// ログファイル名を作成する
bool MakeLogFileName(LOG *g, char *name, UINT size, char *dir, char *prefix, UINT64 tick, UINT switch_type, UINT num, char *old_datestr)
{
	char tmp[MAX_SIZE];
	char tmp2[64];
	bool ret = false;
	// 引数チェック
	if (g == NULL || name == NULL || prefix == NULL || old_datestr == NULL)
	{
		return false;
	}

	MakeLogFileNameStringFromTick(g, tmp, sizeof(tmp), tick, switch_type);

	if (num == 0)
	{
		tmp2[0] = 0;
	}
	else
	{
		snprintf(tmp2, sizeof(tmp2), "~%02u", num);
	}

	if (strcmp(old_datestr, tmp) != 0)
	{
		ret = true;
		strcpy(old_datestr, tmp);
	}

	snprintf(name, size, "%s%s%s%s%s.log", dir,
		StrLen(dir) == 0 ? "" : "/",
		prefix, tmp, tmp2
		);

	return ret;
}

// ログがフラッシュされるまで待機
void WaitLogFlush(LOG *g)
{
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	while (true)
	{
		UINT num;
		LockQueue(g->RecordQueue);
		{
			num = g->RecordQueue->num_item;
		}
		UnlockQueue(g->RecordQueue);

		if (num == 0)
		{
			break;
		}

		Wait(g->FlushEvent, 100);
	}
}

// ログ記録用スレッド
void LogThread(THREAD *thread, void *param)
{
	LOG *g;
	IO *io;
	BUF *b;
	bool flag = false;
	char current_file_name[MAX_SIZE];
	char current_logfile_datename[MAX_SIZE];
	bool last_priority_flag = false;
	bool log_date_changed = false;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	Zero(current_file_name, sizeof(current_file_name));
	Zero(current_logfile_datename, sizeof(current_logfile_datename));

	g = (LOG *)param;

	io = NULL;
	b = NewBuf();

#ifdef	OS_WIN32

	// 優先順位を最低にする
	MsSetThreadPriorityIdle();

#endif	// OS_WIN32

	NoticeThreadInit(thread);

	while (true)
	{
		RECORD *rec;
		UINT64 s = Tick64();

		while (true)
		{
			char file_name[MAX_SIZE];
			UINT num;

			// キューの先頭からレコードを取得する
			LockQueue(g->RecordQueue);
			{
				rec = GetNext(g->RecordQueue);
				num = g->RecordQueue->num_item;
			}
			UnlockQueue(g->RecordQueue);

#ifdef	OS_WIN32
			if (num >= LOG_ENGINE_SAVE_START_CACHE_COUNT)
			{
				// 優先順位を上げる
				if (last_priority_flag == false)
				{
					Debug("LOG_THREAD: MsSetThreadPriorityRealtime\n");
					MsSetThreadPriorityRealtime();
					last_priority_flag = true;
				}
			}

			if (num < (LOG_ENGINE_SAVE_START_CACHE_COUNT / 2))
			{
				// 優先順位を戻す
				if (last_priority_flag)
				{
					Debug("LOG_THREAD: MsSetThreadPriorityIdle\n");
					MsSetThreadPriorityIdle();
					last_priority_flag = false;
				}
			}
#endif	// OS_WIN32

			if (b->Size > g->MaxLogFileSize)
			{
				// バッファのサイズが最大ログファイルサイズを超える場合は消去する
				ClearBuf(b);
			}

			if (b->Size >= LOG_ENGINE_BUFFER_CACHE_SIZE_MAX)
			{
				// バッファの中身をファイルに書き出す
				if (io != NULL)
				{
					if ((g->CurrentFilePointer + (UINT64)b->Size) > g->MaxLogFileSize)
					{
						if (g->log_number_incremented == false)
						{
							g->CurrentLogNumber++;
							g->log_number_incremented = true;
						}
					}
					else
					{
						if (FileWrite(io, b->Buf, b->Size) == false)
						{
							FileCloseEx(io, true);
							// ファイルへの書き込みに失敗した場合は仕方が無い
							// のでバッファを消して諦める
							ClearBuf(b);
							io = NULL;
						}
						else
						{
							g->CurrentFilePointer += (UINT64)b->Size;
							ClearBuf(b);
						}
					}
				}
			}

			if (rec == NULL)
			{
				if (b->Size != 0)
				{
					// バッファの中身をファイルに書き出す
					if (io != NULL)
					{
						if ((g->CurrentFilePointer + (UINT64)b->Size) > g->MaxLogFileSize)
						{
							if (g->log_number_incremented == false)
							{
								g->CurrentLogNumber++;
								g->log_number_incremented = true;
							}
						}
						else
						{
							if (FileWrite(io, b->Buf, b->Size) == false)
							{
								FileCloseEx(io, true);
								// ファイルへの書き込みに失敗した場合は仕方が無い
								// のでバッファを消して諦める
								ClearBuf(b);
								io = NULL;
							}
							else
							{
								g->CurrentFilePointer += (UINT64)b->Size;
								ClearBuf(b);
							}
						}
					}
				}

				Set(g->FlushEvent);
				break;
			}

			// ログファイル名を生成する
			LockLog(g);
			{
				log_date_changed = MakeLogFileName(g, file_name, sizeof(file_name),
					g->DirName, g->Prefix, rec->Tick, g->SwitchType, g->CurrentLogNumber, current_logfile_datename);

				if (log_date_changed)
				{
					UINT i;

					g->CurrentLogNumber = 0;
					MakeLogFileName(g, file_name, sizeof(file_name),
						g->DirName, g->Prefix, rec->Tick, g->SwitchType, 0, current_logfile_datename);
					for (i = 0;;i++)
					{
						char tmp[MAX_SIZE];
						MakeLogFileName(g, tmp, sizeof(tmp),
							g->DirName, g->Prefix, rec->Tick, g->SwitchType, i, current_logfile_datename);

						if (IsFileExists(tmp) == false)
						{
							break;
						}
						StrCpy(file_name, sizeof(file_name), tmp);
						g->CurrentLogNumber = i;
					}
				}
			}
			UnlockLog(g);

			if (io != NULL)
			{
				if (StrCmp(current_file_name, file_name) != 0)
				{
					// 現在ログファイルを開いていて今回別のログファイルへの書き込みが必要になった
					// 場合はログファイルにバッファの内容を書き込んでからログファイルを閉じる
					// バッファの中身をファイルに書き出す
					if (io != NULL)
					{
						if (log_date_changed)
						{
							if ((g->CurrentFilePointer + (UINT64)b->Size) <= g->MaxLogFileSize)
							{
								if (FileWrite(io, b->Buf, b->Size) == false)
								{
									FileCloseEx(io, true);
									ClearBuf(b);
									io = NULL;
								}
								else
								{
									g->CurrentFilePointer += (UINT64)b->Size;
									ClearBuf(b);
								}
							}
						}
						// ファイルを閉じる
						FileCloseEx(io, true);
					}

					g->log_number_incremented = false;

					// 新しいログファイルを開くか作成する
					StrCpy(current_file_name, sizeof(current_file_name), file_name);
					io = FileOpen(file_name, true);
					if (io == NULL)
					{
						// ログファイルを作成する
						LockLog(g);
						{
							MakeDir(g->DirName);

#ifdef	OS_WIN32
							Win32SetFolderCompress(g->DirName, true);
#endif	// OS_WIN32
						}
						UnlockLog(g);
						io = FileCreate(file_name);
						g->CurrentFilePointer = 0;
					}
					else
					{
						// ログファイルの末尾に移動する
						g->CurrentFilePointer = FileSize64(io);
						FileSeek(io, SEEK_END, 0);
					}
				}
			}
			else
			{
				// 新しいログファイルを開くか作成する
				StrCpy(current_file_name, sizeof(current_file_name), file_name);
				io = FileOpen(file_name, true);
				if (io == NULL)
				{
					// ログファイルを作成する
					LockLog(g);
					{
						MakeDir(g->DirName);
#ifdef	OS_WIN32
						Win32SetFolderCompress(g->DirName, true);
#endif	// OS_WIN32
					}
					UnlockLog(g);
					io = FileCreate(file_name);
					g->CurrentFilePointer = 0;
					if (io == NULL)
					{
						Debug("Logging.c: SleepThread(30);\n");
						SleepThread(30);
					}
				}
				else
				{
					// ログファイルの末尾に移動する
					g->CurrentFilePointer = FileSize64(io);
					FileSeek(io, SEEK_END, 0);
				}

				g->log_number_incremented = false;
			}

			// ログの内容をバッファに書き出す
			WriteRecordToBuffer(b, rec);

			// レコードのメモリを解放
			Free(rec);

			if (io == NULL)
			{
				break;
			}
		}

		if (g->Halt)
		{
			// 停止フラグが立った場合
			// すべてのレコードを保存し終えるとブレイクする
			UINT num;

			if (flag == false)
			{
#ifdef	OS_WIN32
				MsSetThreadPriorityRealtime();
#endif	// OS_WIN32
				flag = true;
			}

			LockQueue(g->RecordQueue);
			{
				num = g->RecordQueue->num_item;
			}
			UnlockQueue(g->RecordQueue);

			if (num == 0 || io == NULL)
			{
				break;
			}
		}
		else
		{
			Wait(g->Event, 9821);
		}
	}

	if (io != NULL)
	{
		FileCloseEx(io, true);
	}

	FreeBuf(b);
}

// ログの内容をバッファに書き出す
void WriteRecordToBuffer(BUF *b, RECORD *r)
{
	UINT64 time;
	char time_str[MAX_SIZE];
	char date_str[MAX_SIZE];
	char *s;
	// 引数チェック
	if (b == NULL || r == NULL)
	{
		return;
	}

	// 時刻の取得
	time = SystemToLocal64(TickToTime(r->Tick));

	// 時刻を文字列に変換
	GetDateStr64(date_str, sizeof(date_str), time);
	GetTimeStrMilli64(time_str, sizeof(time_str), time);

	if (r->ParseProc != PacketLogParseProc)
	{
		// パケットログ以外
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, " ", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, " ", 1);
	}
	else
	{
		// パケットログ
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, ",", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, ",", 1);
	}

	// 本文を出力
	s = r->ParseProc(r);
	WriteBuf(b, s, StrLen(s));
	Free(s);

	WriteBuf(b, "\r\n", 2);
}

// ログ記録の終了
void FreeLog(LOG *g)
{
	RECORD *rec;
	// 引数チェック
	if (g == NULL)
	{
		return;
	}

	// 停止フラグ
	g->Halt = true;
	Set(g->Event);

	WaitThread(g->Thread, INFINITE);
	ReleaseThread(g->Thread);

	DeleteLock(g->lock);
	Free(g->DirName);
	Free(g->Prefix);

	// 未処理のレコードが残っている場合は解放する
	// (本来はここでは残っていないはず)
	while (rec = GetNext(g->RecordQueue))
	{
		char *s = rec->ParseProc(rec);
		Free(s);
		Free(rec);
	}
	ReleaseQueue(g->RecordQueue);

	ReleaseEvent(g->Event);
	ReleaseEvent(g->FlushEvent);

	Free(g);
}

// 新しいログ記録の開始
LOG *NewLog(char *dir, char *prefix, UINT switch_type)
{
	LOG *g;

	g = ZeroMalloc(sizeof(LOG));
	g->lock = NewLock();
	g->DirName = CopyStr(dir == NULL ? "" : dir);
	g->Prefix = CopyStr(prefix == NULL ? "log" : prefix);
	g->SwitchType = switch_type;
	g->RecordQueue = NewQueue();
	g->Event = NewEvent();
	g->MaxLogFileSize = MAX_LOG_SIZE;
	g->FlushEvent = NewEvent();

	g->Thread = NewThread(LogThread, g);

	WaitThreadInit(g->Thread);

	return g;
}


