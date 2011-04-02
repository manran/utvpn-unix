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

// Command.h
// Command.c のヘッダ

#ifndef	COMMAND_H
#define	COMMAND_H

// 定数
#define	TRAFFIC_DEFAULT_PORT		9821
#define	TRAFFIC_NUMTCP_MAX			32
#define	TRAFFIC_NUMTCP_DEFAULT		32
#define	TRAFFIC_SPAN_DEFAULT		15
#define	TRAFFIC_TYPE_DOWNLOAD		1
#define	TRAFFIC_TYPE_UPLOAD			2
#define	TRAFFIC_TYPE_FULL			0
#define	TRAFFIC_BUF_SIZE			65535
#define	TRAFFIC_VER_STR_SIZE		16
#define	TRAFFIC_VER_STR				"TrafficServer\r\n"

// Win32 用定数
#define	VPNCMD_BOOTSTRAP_REG_KEYNAME	"Software\\SoftEther Corporation\\UT-VPN Command Line Utility"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_VER	"InstalledVersion"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH	"InstalledPath"
#define	VPNCMD_BOOTSTRAP_FILENAME		"|utvpncmdsys.exe"
#define	VPNCMD_BOOTSTRAP_FILENAME_X64	"|utvpncmdsys_x64.exe"
#define	VPNCMD_BOOTSTRAP_FILENAME_IA64	"|utvpncmdsys_ia64.exe"


// トラフィックテスト結果
struct TT_RESULT
{
	bool Raw;					// 生データかどうか
	bool Double;				// 2 倍にしているかどうか
	UINT64 NumBytesUpload;		// アップロードしたサイズ
	UINT64 NumBytesDownload;	// ダウンロードしたサイズ
	UINT64 NumBytesTotal;		// 合計サイズ
	UINT64 Span;				// 期間 (ミリ秒)
	UINT64 BpsUpload;			// アップロードスループット
	UINT64 BpsDownload;			// ダウンロードスループット
	UINT64 BpsTotal;			// 合計スループット
};

// 文字表示関数
typedef void (TT_PRINT_PROC)(void *param, wchar_t *str);

// クライアント側ソケット
struct TTC_SOCK
{
	SOCK *Sock;				// ソケット
	UINT State;				// ステート
	UINT64 NumBytes;		// 伝送したバイト数
	bool Download;			// ダウンロードソケット
	bool ServerUploadReportReceived;	// サーバーからのアップロード量レポートの受信完了
	UINT64 NextSendRequestReportTick;	// 次にレポートをリクエストする時刻
	UINT Id;
};

// トラフィックテストクライアント
struct TTC
{
	TT_PRINT_PROC *Print;	// 文字表示関数
	void *Param;			// 任意のパラメータ
	bool Double;			// 2 倍モード
	bool Raw;				// 生データモード
	UINT Port;				// ポート番号
	char Host[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT NumTcp;			// TCP コネクション数
	UINT Type;				// 種類
	UINT64 Span;			// 期間
	UINT64 RealSpan;		// 実際の期間
	THREAD *Thread;			// スレッド
	volatile bool Halt;		// 停止フラグ
	SOCK_EVENT *SockEvent;	// ソケットイベント
	LIST *ItcSockList;		// クライアントソケットリスト
	TT_RESULT Result;		// 結果
	UINT ErrorCode;			// エラーコード
	bool AbnormalTerminated;	// 異常終了
	EVENT *StartEvent;		// 開始イベント
	EVENT *InitedEvent;		// 初期化完了通知イベント
};

// サーバー側ソケット
struct TTS_SOCK
{
	SOCK *Sock;				// ソケット
	UINT State;				// ステート
	UINT64 NumBytes;		// 伝送したバイト数
	bool SockJoined;		// イベントに追加されたかどうか
	UINT Id;				// ID
	UINT64 LastWaitTick;	// クライアントにサイズ情報を通知するための再試行待機時間
};

// トラフィックテストサーバー
struct TTS
{
	TT_PRINT_PROC *Print;	// 文字表示関数
	void *Param;			// 任意のパラメータ
	volatile bool Halt;		// 停止フラグ
	UINT Port;				// ポート番号
	THREAD *Thread;			// スレッド
	THREAD *WorkThread;		// ワーカースレッド
	THREAD *IPv6AcceptThread;	// IPv6 Accept スレッド
	SOCK *ListenSocket;		// 待機するソケット
	SOCK *ListenSocketV6;	// 待機するソケット (IPv6)
	UINT ErrorCode;			// エラーコード
	SOCK_EVENT *SockEvent;	// ソケットイベント
	LIST *TtsSockList;		// サーバーソケットリスト
	bool NewSocketArrived;	// 新しいソケットが到着している
	UINT IdSeed;			// ID 値
};

// VPN Tools コンテキスト
struct PT
{
	CONSOLE *Console;	// コンソール
	UINT LastError;		// 最後のエラー
	wchar_t *CmdLine;	// 実行するコマンドライン
};

// サーバー管理コンテキスト
struct PS
{
	bool ConsoleForServer;	// サーバーのためのコンソール (常に true)
	CONSOLE *Console;	// コンソール
	RPC *Rpc;			// RPC
	char *ServerName;	// サーバー名
	UINT ServerPort;	// ポート番号
	char *HubName;		// 現在管理対象にある仮想 HUB 名
	UINT LastError;		// 最後のエラー
	char *AdminHub;		// デフォルトで管理する仮想 HUB
	wchar_t *CmdLine;	// 実行するコマンドライン
	CAPSLIST *CapsList;	// Caps リスト
};

// クライアント管理コンテキスト
struct PC
{
	bool ConsoleForServer;	// サーバーのためのコンソール (常に false)
	CONSOLE *Console;	// コンソール
	REMOTE_CLIENT *RemoteClient;	// リモートクライアント
	char *ServerName;	// サーバー名
	UINT LastError;		// 最後のエラー
	wchar_t *CmdLine;	// コマンドライン
};

// テーブルのカラム
struct CTC
{
	wchar_t *String;	// 文字列
	bool Right;			// 右寄せ
};

// テーブルの行
struct CTR
{
	wchar_t **Strings;	// 文字列リスト
};

// コンソール用テーブル
struct CT
{
	LIST *Columns;		// カラム一覧
	LIST *Rows;			// 行一覧
};

UINT CommandMain(wchar_t *command_line);
UINT VpnCmdProc(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port);
bool ParseHostPortAtmark(char *src, char **host, UINT *port, UINT default_port);
CT *CtNew();
void CtFree(CT *ct, CONSOLE *c);
void CtFreeEx(CT *ct, CONSOLE *c, bool standard_view);
void CtInsertColumn(CT *ct, wchar_t *str, bool right);
CT *CtNewStandard();
CT *CtNewStandardEx();
void CtInsert(CT *ct, ...);
void CtPrint(CT *ct, CONSOLE *c);
void CtPrintStandard(CT *ct, CONSOLE *c);
void CtPrintRow(CONSOLE *c, UINT num, UINT *widths, wchar_t **strings, bool *rights, char separate_char);
void VpnCmdInitBootPath();
void OutRpcTtResult(PACK *p, TT_RESULT *t);
void InRpcTtResult(PACK *p, TT_RESULT *t);

void CmdPrintError(CONSOLE *c, UINT err);
void CmdPrintAbout(CONSOLE *c);
void CmdPrintRow(CONSOLE *c, wchar_t *title, wchar_t *tag, ...);
wchar_t *CmdPromptPort(CONSOLE *c, void *param);
wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param);
bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param);
void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t);
wchar_t *GetHubTypeStr(UINT type);
wchar_t *GetServerTypeStr(UINT type);
char *CmdPasswordPrompt(CONSOLE *c);
bool CmdEvalIp(CONSOLE *c, wchar_t *str, void *param);
wchar_t *PsClusterSettingMemberPromptIp(CONSOLE *c, void *param);
bool CmdEvalHostAndPort(CONSOLE *c, wchar_t *str, void *param);
LIST *StrToPortList(char *str);
bool CmdEvalPortList(CONSOLE *c, wchar_t *str, void *param);
wchar_t *PsClusterSettingMemberPromptPorts(CONSOLE *c, void *param);
K *CmdLoadKey(CONSOLE *c, char *filename);
bool CmdLoadCertAndKey(CONSOLE *c, X **xx, K **kk, char *cert_filename, char *key_filename);
bool CmdEvalTcpOrUdp(CONSOLE *c, wchar_t *str, void *param);
wchar_t *GetConnectionTypeStr(UINT type);
bool CmdEvalHostAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalNetworkAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalNetworkAndSubnetMask6(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalNetworkAndSubnetMask46(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask6(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask46(CONSOLE *c, wchar_t *str, void *param);
wchar_t *GetLogSwitchStr(UINT i);
wchar_t *GetPacketLogNameStr(UINT i);
UINT StrToLogSwitchType(char *str);
UINT StrToPacketLogType(char *str);
UINT StrToPacketLogSaveInfoType(char *str);
wchar_t *GetProxyTypeStr(UINT i);
wchar_t *GetClientAuthTypeStr(UINT i);
void PrintPolicyList(CONSOLE *c, char *name);
void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode);
bool EditPolicy(CONSOLE *c, POLICY *pol, char *name, char *value, bool cascade_mode);
void CmdPrintStatusToListView(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s);
void CmdPrintStatusToListViewEx(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode);
bool CmdEvalPassOrDiscard(CONSOLE *c, wchar_t *str, void *param);
bool StrToPassOrDiscard(char *str);
bool CmdEvalProtocol(CONSOLE *c, wchar_t *str, void *param);
UINT StrToProtocol(char *str);
bool CmdEvalPortRange(CONSOLE *c, wchar_t *str, void *param);
bool ParsePortRange(char *str, UINT *start, UINT *end);
wchar_t *GetAuthTypeStr(UINT id);
UINT64 StrToDateTime64(char *str);
bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param);
void CmdPrintNodeInfo(CT *ct, NODE_INFO *info);
wchar_t *GetProtocolName(UINT n);
void CmdGenerateImportName(REMOTE_CLIENT *r, wchar_t *name, UINT size, wchar_t *old_name);
bool CmdIsAccountName(REMOTE_CLIENT *r, wchar_t *name);
wchar_t *GetSyslogSettingName(UINT n);


void TtPrint(void *param, TT_PRINT_PROC *print_proc, wchar_t *str);
void TtGenerateRandomData(UCHAR **buf, UINT *size);
void TtsWorkerThread(THREAD *thread, void *param);
void TtsListenThread(THREAD *thread, void *param);
void TtsAcceptProc(TTS *tts, SOCK *listen_socket);
void TtsIPv6AcceptThread(THREAD *thread, void *param);
wchar_t *GetTtcTypeStr(UINT type);
void TtcPrintSummary(TTC *ttc);
void StopTtc(TTC *ttc);
void TtcGenerateResult(TTC *ttc);
void TtcThread(THREAD *thread, void *param);
TTC *NewTtcEx(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param, EVENT *start_event);
TTC *NewTtc(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param);
UINT FreeTtc(TTC *ttc, TT_RESULT *result);
TTS *NewTts(UINT port, void *param, TT_PRINT_PROC *print_proc);
UINT FreeTts(TTS *tts);
void PtTrafficPrintProc(void *param, wchar_t *str);
void TtcPrintResult(CONSOLE *c, TT_RESULT *res);


bool SystemCheck();
bool CheckKernel();
bool CheckMemory();
bool CheckStrings();
bool CheckFileSystem();
bool CheckThread();
bool CheckNetwork();
void InputToNull(void *p);
UINT RetZero();



UINT PtConnect(CONSOLE *c, wchar_t *cmdline);
PT *NewPt(CONSOLE *c, wchar_t *cmdline);
void FreePt(PT *pt);
void PtMain(PT *pt);
UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtCheck(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


UINT PcConnect(CONSOLE *c, char *target, wchar_t *cmdline, char *password);
PC *NewPc(CONSOLE *c, REMOTE_CLIENT *remote_client, char *servername, wchar_t *cmdline);
void FreePc(PC *pc);
void PcMain(PC *pc);
UINT PcAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcVersionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcPasswordGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureSelect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicUpgrade(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicGetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicSetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountConnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountNicSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusShow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusHide(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountSecureCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRetrySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStartupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStartupRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountExport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountImport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcRemoteEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcRemoteDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


PS *NewPs(CONSOLE *c, RPC *rpc, char *servername, UINT serverport, char *hubname, char *adminhub, wchar_t *cmdline);
void FreePs(PS *ps);
UINT PsConnect(CONSOLE *c, char *host, UINT port, char *hub, char *adminhub, wchar_t *cmdline, char *password);
void PsMain(PS *ps);
UINT PsAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingStandalone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingController(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingMember(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterConnectionStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDebug(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterStart(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterStop(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreateDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreateStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubSetStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubSetDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserRadiusSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatHostGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatHostSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


#endif	// COMMAND_H


