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

// Logging.h
// Logging.c のヘッダ

#ifndef	LOGGING_H
#define	LOGGING_H


#define	MAX_LOG_SIZE						1073741823ULL

typedef char *(RECORD_PARSE_PROC)(RECORD *rec);

// パケットログ構造体
struct PACKET_LOG
{
	CEDAR *Cedar;
	struct PKT *Packet;
	char *SrcSessionName;
	char *DestSessionName;
	bool PurePacket;						// クローンしていないパケット
	bool PurePacketNoPayload;				// クローンしていないパケット (ペイロード無し)
	SESSION *SrcSession;
	bool NoLog;								// ログを書かない
};

// HUB のログ保存オプション
struct HUB_LOG
{
	bool SaveSecurityLog;					// セキュリティログの保存
	UINT SecurityLogSwitchType;				// セキュリティログの切り替え種類
	bool SavePacketLog;						// パケットログの保存
	UINT PacketLogSwitchType;				// パケットログの切り替え種類
	UINT PacketLogConfig[NUM_PACKET_LOG];	// パケットログ設定
};

// レコード
struct RECORD
{
	UINT64 Tick;							// 時刻
	RECORD_PARSE_PROC *ParseProc;			// パース用プロシージャ
	void *Data;								// データ
};

// LOG オブジェクト
struct LOG
{
	LOCK *lock;								// ロック
	THREAD *Thread;							// スレッド
	char *DirName;							// 保存先ディレクトリ名
	char *Prefix;							// ファイル名
	UINT SwitchType;						// ログファイルの切り替え種類
	QUEUE *RecordQueue;						// レコードキュー
	volatile bool Halt;						// 停止フラグ
	EVENT *Event;							// ログ用イベント
	EVENT *FlushEvent;						// フラッシュ完了イベント
	bool CacheFlag;
	UINT64 LastTick;
	UINT LastSwitchType;
	char LastStr[MAX_SIZE];
	UINT64 CurrentFilePointer;				// 現在のファイルポインタ
	UINT64 MaxLogFileSize;					// 最大ログファイルサイズ
	UINT CurrentLogNumber;					// 現在のログファイル番号
	bool log_number_incremented;
};

// ERASER オブジェクト
struct ERASER
{
	LOG *Log;								// ロガー
	UINT64 MinFreeSpace;					// ファイルの削除を開始するディスク空き容量
	char *DirName;							// ディレクトリ名
	volatile bool Halt;						// 停止フラグ
	THREAD *Thread;							// スレッド
	bool LastFailed;						// 最後にファイル削除に失敗したかどうか
	EVENT *HaltEvent;						// 停止イベント
};

// 削除できるファイルの一覧
typedef struct ERASE_FILE
{
	char *FullPath;							// フルパス
	UINT64 UpdateTime;						// 更新日時
} ERASE_FILE;

// SYSLOG オブジェクト
struct SLOG
{
	LOCK *lock;								// ロック
	SOCK *Udp;								// UDP ソケット
	IP DestIp;								// 宛先 IP アドレス
	UINT DestPort;							// 宛先ポート番号
	char HostName[MAX_HOST_NAME_LEN + 1];	// ホスト名
	UINT64 NextPollIp;						// 最後に IP アドレスを調べた日時
};

// 関数プロトタイプ
LOG *NewLog(char *dir, char *prefix, UINT switch_type);
void FreeLog(LOG *g);
void LogThread(THREAD *thread, void *param);
void WaitLogFlush(LOG *g);
void LockLog(LOG *g);
void UnlockLog(LOG *g);
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc);
void InsertStringRecord(LOG *g, char *str);
void InsertUnicodeRecord(LOG *g, wchar_t *unistr);
char *StringRecordParseProc(RECORD *rec);
bool MakeLogFileName(LOG *g, char *name, UINT size, char *dir, char *prefix, UINT64 tick, UINT switch_type, UINT num, char *old_datestr);
void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type);
void WriteRecordToBuffer(BUF *b, RECORD *r);
void SetLogDirName(LOG *g, char *dir);
void SetLogPrefix(LOG *g, char *prefix);
void SetLogSwitchType(LOG *g, UINT switch_type);
void PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet);
char *PacketLogParseProc(RECORD *rec);
UINT CalcPacketLoggingLevel(HUB *hub, PKT *packet);
UINT CalcPacketLoggingLevelEx(HUB_LOG *g, PKT *packet);
char *GenCsvLine(TOKEN_LIST *t);
void ReplaceForCsv(char *str);
char *PortStr(CEDAR *cedar, UINT port, bool udp);
char *TcpFlagStr(UCHAR flag);
void WriteSecurityLog(HUB *h, char *str);
void SecLog(HUB *h, char *fmt, ...);
void SiSetDefaultLogSetting(HUB_LOG *g);
void DebugLog(CEDAR *c, char *fmt, ...);
void HubLog(HUB *h, wchar_t *fmt, ...);
void ServerLog(CEDAR *c, wchar_t *fmt, ...);
void SLog(CEDAR *c, char *name, ...);
void WriteHubLog(HUB *h, wchar_t *str);
void HLog(HUB *h, char *name, ...);
void NLog(VH *v, char *name, ...);
void WriteServerLog(CEDAR *c, wchar_t *str);
void ALog(ADMIN *a, HUB *h, char *name, ...);
void CLog(CLIENT *c, char *name, ...);
void WriteClientLog(CLIENT *c, wchar_t *str);
ERASER *NewEraser(LOG *log, UINT64 min_size);
void FreeEraser(ERASER *e);
void ELog(ERASER *e, char *name, ...);
void EraserThread(THREAD *t, void *p);
void EraserMain(ERASER *e);
bool CheckEraserDiskFreeSpace(ERASER *e);
int CompareEraseFile(void *p1, void *p2);
LIST *GenerateEraseFileList(ERASER *e);
void FreeEraseFileList(LIST *o);
void PrintEraseFileList(LIST *o);
void EnumEraseFile(LIST *o, char *dirname);
SLOG *NewSysLog(char *hostname, UINT port);
void SetSysLog(SLOG *g, char *hostname, UINT port);
void FreeSysLog(SLOG *g);
void SendSysLog(SLOG *g, wchar_t *str);
void WriteMultiLineLog(LOG *g, BUF *b);

#endif	// LOGGING_G

