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

// Console.h
// Console.c のヘッダ

#ifndef	CONSOLE_H
#define	CONSOLE_H

// 定数
#define	MAX_PROMPT_STRSIZE			65536
#define	WIN32_DEFAULT_CONSOLE_WIDTH	100

// コンソールの種類
#define	CONSOLE_LOCAL				0	// ローカルコンソール
#define	CONSOLE_CSV					1	// CSV 出力モード

// パラメータ補完プロンプト関数
typedef wchar_t *(PROMPT_PROC)(CONSOLE *c, void *param);

// パラメータ検証プロンプト関数
typedef bool (EVAL_PROC)(CONSOLE *c, wchar_t *str, void *param);

// パラメータ項目の定義
struct PARAM
{
	char *Name;					// パラメータ名
	PROMPT_PROC *PromptProc;	// パラメータが指定されていない場合に自動的に呼び出す
								// プロンプト関数 (NULL の場合は呼ばない)
	void *PromptProcParam;		// プロンプト関数に渡す任意のポインタ
	EVAL_PROC *EvalProc;		// パラメータ文字列検証関数
	void *EvalProcParam;		// 検証関数に渡す任意のポインタ
	char *Tmp;					// 一時変数
};

// パラメータ値内部データ
struct PARAM_VALUE
{
	char *Name;					// 名前
	char *StrValue;				// 文字列値
	wchar_t *UniStrValue;		// Unicode 文字列値
	UINT IntValue;				// 整数値
};

// コンソールサービス構造体
struct CONSOLE
{
	UINT ConsoleType;										// コンソールの種類
	UINT RetCode;											// 最後の終了コード
	void *Param;											// 任意のデータ
	void (*Free)(CONSOLE *c);								// 解放関数
	wchar_t *(*ReadLine)(CONSOLE *c, wchar_t *prompt, bool nofile);		// 1 行読み込む関数
	char *(*ReadPassword)(CONSOLE *c, wchar_t *prompt);		// パスワードを読み込む関数
	bool (*Write)(CONSOLE *c, wchar_t *str);				// 文字列を書き出す関数
	UINT (*GetWidth)(CONSOLE *c);							// 画面の横幅の取得
};

// ローカルコンソールパラメータ
struct LOCAL_CONSOLE_PARAM
{
	IO *InFile;		// 入力ファイル
	BUF *InBuf;		// 入力バッファ
	IO *OutFile;	// 出力ファイル
	UINT Win32_OldConsoleWidth;	// 以前のコンソールサイズ
};

// コマンドプロシージャ
typedef UINT (COMMAND_PROC)(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);

// コマンドの定義
struct CMD
{
	char *Name;				// コマンド名
	COMMAND_PROC *Proc;		// プロシージャ関数
};

// パラメータの最小 / 最大値評価
struct CMD_EVAL_MIN_MAX
{
	char *StrName;
	UINT MinValue, MaxValue;
};


// 関数プロトタイプ
wchar_t *Prompt(wchar_t *prompt_str);
char *PromptA(wchar_t *prompt_str);
bool PasswordPrompt(char *password, UINT size);
void *SetConsoleRaw();
void RestoreConsole(void *p);
wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list);
wchar_t *ParseCommand(wchar_t *str, wchar_t *name);
TOKEN_LIST *GetCommandNameList(wchar_t *str);
char *ParseCommandA(wchar_t *str, char *name);
LIST *NewParamValueList();
int CmpParamValue(void *p1, void *p2);
void FreeParamValueList(LIST *o);
PARAM_VALUE *FindParamValue(LIST *o, char *name);
char *GetParamStr(LIST *o, char *name);
wchar_t *GetParamUniStr(LIST *o, char *name);
UINT GetParamInt(LIST *o, char *name);
bool GetParamYes(LIST *o, char *name);
LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param);
bool IsNameInRealName(char *input_name, char *real_name);
void GetOmissionName(char *dst, UINT size, char *src);
bool IsOmissionName(char *input_name, char *real_name);
TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list);
bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param);
UINT GetConsoleWidth(CONSOLE *c);
bool DispatchNextCmd(CONSOLE *c, char *prompt, CMD cmd[], UINT num_cmd, void *param);
bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param);
void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space);
UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width);
void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help);
void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description);
bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param);
wchar_t *CmdPrompt(CONSOLE *c, void *param);
bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalInt1(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param);
void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list);
int CompareCandidateStr(void *p1, void *p2);
bool IsHelpStr(char *str);

CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile);
void ConsoleLocalFree(CONSOLE *c);
wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile);
char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt);
bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str);
void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf);
wchar_t *ConsoleReadNextFromInFile(CONSOLE *c);
UINT ConsoleLocalGetWidth(CONSOLE *c);


#endif	// CONSOLE_H



