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

// Console.c
// コンソール サービス

#include "CedarPch.h"


// コマンドのヘルプを表示する
void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t *buf;
	UINT buf_size;
	wchar_t *description, *args, *help;
	UNI_TOKEN_LIST *t;
	UINT width;
	UINT i;
	char *space;
	// 引数チェック
	if (c == NULL || cmd_name == NULL || param_list == NULL)
	{
		return;
	}

	width = GetConsoleWidth(c) - 2;

	buf_size = sizeof(wchar_t) * (width + 32);
	buf = Malloc(buf_size);

	GetCommandHelpStr(cmd_name, &description, &args, &help);

	space = MakeCharArray(' ', 2);

	// タイトル
	UniFormat(tmp, sizeof(tmp), _UU("CMD_HELP_TITLE"), cmd_name);
	c->Write(c, tmp);
	c->Write(c, L"");

	// 目的
	c->Write(c, _UU("CMD_HELP_DESCRIPTION"));
	t = SeparateStringByWidth(description, width - 2);
	for (i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);
	c->Write(c, L"");

	// 説明
	c->Write(c, _UU("CMD_HELP_HELP"));
	t = SeparateStringByWidth(help, width - 2);
	for (i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);
	c->Write(c, L"");

	// 使用方法
	c->Write(c, _UU("CMD_HELP_USAGE"));
	t = SeparateStringByWidth(args, width - 2);
	for (i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);

	// 引数
	if (param_list->NumTokens >= 1)
	{
		c->Write(c, L"");
		c->Write(c, _UU("CMD_HELP_ARGS"));
		PrintCandidateHelp(c, cmd_name, param_list, 2);
	}

	Free(space);

	Free(buf);
}

// SafeStr であるかどうかの評価
bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_SAFE") : (wchar_t *)param;

	if (IsSafeUniStr(str))
	{
		return true;
	}

	c->Write(c, p);

	return false;
}

// 文字列入力プロンプト
wchar_t *CmdPrompt(CONSOLE *c, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_PROMPT") : (wchar_t *)param;

	return c->ReadLine(c, p, true);
}

// 指定されたファイルが存在するかどうか評価
bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_PATH];
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (IsEmptyStr(tmp))
	{
		c->Write(c, _UU("CMD_FILE_NAME_EMPTY"));
		return false;
	}

	if (IsFileExists(tmp) == false)
	{
		wchar_t tmp2[MAX_SIZE];

		UniFormat(tmp2, sizeof(tmp2), _UU("CMD_FILE_NOT_FOUND"), tmp);
		c->Write(c, tmp2);

		return false;
	}

	return true;
}

// 整数の評価
bool CmdEvalInt1(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_INT") : (wchar_t *)param;

	if (UniToInt(str) == 0)
	{
		c->Write(c, p);

		return false;
	}

	return true;
}

// 空白を指定できないパラメータの評価
bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_NOT_EMPTY") : (wchar_t *)param;

	if (UniIsEmptyStr(str) == false)
	{
		return true;
	}

	c->Write(c, p);

	return false;
}

// パラメータの最小 / 最大値評価関数
bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param)
{
	CMD_EVAL_MIN_MAX *e;
	wchar_t *tag;
	UINT v;
	// 引数チェック
	if (param == NULL)
	{
		return false;
	}

	e = (CMD_EVAL_MIN_MAX *)param;

	if (e->StrName == NULL)
	{
		tag = _UU("CMD_EVAL_MIN_MAX");
	}
	else
	{
		tag = _UU(e->StrName);
	}

	v = UniToInt(str);

	if (v >= e->MinValue && v <= e->MaxValue)
	{
		return true;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), tag, e->MinValue, e->MaxValue);
		c->Write(c, tmp);

		return false;
	}
}

// コマンドのヘルプ文字列を取得する
void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help)
{
	char tmp1[128], tmp2[128], tmp3[128];

	Format(tmp1, sizeof(tmp1), "CMD_%s", command_name);
	Format(tmp2, sizeof(tmp2), "CMD_%s_ARGS", command_name);
	Format(tmp3, sizeof(tmp3), "CMD_%s_HELP", command_name);

	if (description != NULL)
	{
		*description = _UU(tmp1);
		if (UniIsEmptyStr(*description))
		{
			*description = _UU("CMD_UNKNOWM");
		}
	}

	if (args != NULL)
	{
		*args = _UU(tmp2);
		if (UniIsEmptyStr(*args))
		{
			*args = _UU("CMD_UNKNOWN_ARGS");
		}
	}

	if (help != NULL)
	{
		*help = _UU(tmp3);
		if (UniIsEmptyStr(*help))
		{
			*help = _UU("CMD_UNKNOWN_HELP");
		}
	}
}

// パラメータのヘルプ文字列を取得する
void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description)
{
	char tmp[160];
	if (description == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "CMD_%s_%s", command_name, param_name);

	*description = _UU(tmp);

	if (UniIsEmptyStr(*description))
	{
		*description = _UU("CMD_UNKNOWN_PARAM");
	}
}

// 文字列比較関数
int CompareCandidateStr(void *p1, void *p2)
{
	char *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(char **)p1;
	s2 = *(char **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1[0] == '[' && s2[0] != '[')
	{
		return -1;
	}
	else if (s2[0] == '[' && s1[0] != '[')
	{
		return 1;
	}

	return StrCmp(s1, s2);
}

// 候補一覧のヘルプを表示する
void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space)
{
	UINT console_width;
	UINT max_keyword_width;
	LIST *o;
	UINT i;
	wchar_t *tmpbuf;
	UINT tmpbuf_size;
	char *left_space_array;
	char *max_space_array;
	// 引数チェック
	if (c == NULL || candidate_list == NULL)
	{
		return;
	}

	// 画面の横幅の取得
	console_width = GetConsoleWidth(c) - 1;

	tmpbuf_size = sizeof(wchar_t) * (console_width + 32);
	tmpbuf = Malloc(tmpbuf_size);

	left_space_array = MakeCharArray(' ', left_space);

	// コマンド名はソートしてリスト化する
	// パラメータ名はソートしない
	o = NewListFast(cmd_name == NULL ? CompareCandidateStr : NULL);

	max_keyword_width = 0;

	for (i = 0;i < candidate_list->NumTokens;i++)
	{
		UINT keyword_width;

		// 各キーワードの横幅を取得する
		Insert(o, candidate_list->Token[i]);

		keyword_width = StrWidth(candidate_list->Token[i]);
		if (cmd_name != NULL)
		{
			if (candidate_list->Token[i][0] != '[')
			{
				keyword_width += 1;
			}
			else
			{
				keyword_width -= 2;
			}
		}

		max_keyword_width = MAX(max_keyword_width, keyword_width);
	}

	max_space_array = MakeCharArray(' ', max_keyword_width);

	// 候補を表示する
	for (i = 0;i < LIST_NUM(o);i++)
	{
		char tmp[128];
		char *name = LIST_DATA(o, i);
		UNI_TOKEN_LIST *t;
		wchar_t *help;
		UINT j;
		UINT keyword_start_width = left_space;
		UINT descript_start_width = left_space + max_keyword_width + 1;
		UINT descript_width;
		char *space;

		if (console_width >= (descript_start_width + 5))
		{
			descript_width = console_width - descript_start_width - 3;
		}
		else
		{
			descript_width = 2;
		}

		// 名前を生成する
		if (cmd_name != NULL && name[0] != '[')
		{
			// パラメータの場合は先頭に "/" を付ける
			Format(tmp, sizeof(tmp), "/%s", name);
		}
		else
		{
			// コマンド名の場合はそのままの文字を使用する
			if (cmd_name == NULL)
			{
				StrCpy(tmp, sizeof(tmp), name);
			}
			else
			{
				StrCpy(tmp, sizeof(tmp), name + 1);
				if (StrLen(tmp) >= 1)
				{
					tmp[StrLen(tmp) - 1] = 0;
				}
			}
		}

		// ヘルプ文字を取得する
		if (cmd_name == NULL)
		{
			GetCommandHelpStr(name, &help, NULL, NULL);
		}
		else
		{
			GetCommandParamHelpStr(cmd_name, name, &help);
		}

		space = MakeCharArray(' ', max_keyword_width - StrWidth(name) - (cmd_name == NULL ? 0 : (name[0] != '[' ? 1 : -2)));

		t = SeparateStringByWidth(help, descript_width);

		for (j = 0;j < t->NumTokens;j++)
		{
			if (j == 0)
			{
				UniFormat(tmpbuf, tmpbuf_size, L"%S%S%S - %s",
					left_space_array, tmp, space, t->Token[j]);
			}
			else
			{
				UniFormat(tmpbuf, tmpbuf_size, L"%S%S   %s",
					left_space_array, max_space_array, t->Token[j]);
			}

			c->Write(c, tmpbuf);
		}

		Free(space);

		UniFreeToken(t);
	}

	ReleaseList(o);

	Free(max_space_array);
	Free(tmpbuf);
	Free(left_space_array);
}

// 文字列を指定された横幅で分割する
UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width)
{
	UINT wp;
	wchar_t *tmp;
	UINT len, i;
	LIST *o;
	UNI_TOKEN_LIST *ret;
	// 引数チェック
	if (str == NULL)
	{
		return UniNullToken();
	}
	if (width == 0)
	{
		width = 1;
	}

	o = NewListFast(NULL);

	len = UniStrLen(str);
	tmp = ZeroMalloc(sizeof(wchar_t) * (len + 32));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = str[i];

		switch (c)
		{
		case 0:
		case L'\r':
		case L'\n':
			if (c == L'\r')
			{
				if (str[i + 1] == L'\n')
				{
					i++;
				}
			}

			tmp[wp++] = 0;
			wp = 0;

			Insert(o, UniCopyStr(tmp));
			break;

		default:
			tmp[wp++] = c;
			tmp[wp] = 0;
			if (UniStrWidth(tmp) >= width)
			{
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, UniCopyStr(tmp));
			}
			break;
		}
	}

	if (LIST_NUM(o) == 0)
	{
		Insert(o, CopyUniStr(L""));
	}

	ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->NumTokens = LIST_NUM(o);
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);

		ret->Token[i] = s;
	}

	ReleaseList(o);
	Free(tmp);

	return ret;
}

// 指定した文字列が help を示すかどうかをチェック
bool IsHelpStr(char *str)
{
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}

	if (StrCmpi(str, "help") == 0 || StrCmpi(str, "?") == 0 ||
		StrCmpi(str, "man") == 0 || StrCmpi(str, "/man") == 0 ||
		StrCmpi(str, "-man") == 0 || StrCmpi(str, "--man") == 0 ||
		StrCmpi(str, "/help") == 0 || StrCmpi(str, "/?") == 0 ||
		StrCmpi(str, "-help") == 0 || StrCmpi(str, "-?") == 0 ||
		StrCmpi(str, "/h") == 0 || StrCmpi(str, "--help") == 0 ||
		StrCmpi(str, "--?") == 0)
	{
		return true;
	}

	return false;
}

// コマンドの実行
bool DispatchNextCmd(CONSOLE *c, char *prompt, CMD cmd[], UINT num_cmd, void *param)
{
	return DispatchNextCmdEx(c, NULL, prompt, cmd, num_cmd, param);
}
bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param)
{
	wchar_t *str;
	wchar_t *tmp;
	char *cmd_name;
	bool b_exit = false;
	wchar_t *cmd_param;
	UINT ret = ERR_NO_ERROR;
	TOKEN_LIST *t;
	TOKEN_LIST *candidate;
	bool no_end_crlf = false;
	UINT i;
	// 引数チェック
	if (c == NULL || (num_cmd >= 1 && cmd == NULL))
	{
		return false;
	}

	if (exec_command == NULL)
	{
		// プロンプトを表示
RETRY:
		tmp = CopyStrToUni(prompt);
		str = c->ReadLine(c, tmp, false);
		Free(tmp);

		if (str != NULL && IsEmptyUniStr(str))
		{
			Free(str);
			goto RETRY;
		}
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		// exec_command を使用
		if (UniStartWith(exec_command, L"utvpncmd") == false)
		{
			if (prompt != NULL)
			{
				if (c->ConsoleType != CONSOLE_CSV)
				{
					UniFormat(tmp, sizeof(tmp), L"%S%s", prompt, exec_command);
					c->Write(c, tmp);
				}
			}
		}
		str = CopyUniStr(exec_command);
	}

	if (str == NULL)
	{
		// ユーザーキャンセル
		return false;
	}

	UniTrimCrlf(str);
	UniTrim(str);

	if (UniIsEmptyStr(str))
	{
		// 何もしない
		Free(str);
		return true;
	}

	// コマンド名とパラメータに分ける
	if (SeparateCommandAndParam(str, &cmd_name, &cmd_param) == false)
	{
		// 何もしない
		Free(str);
		return true;
	}

	if (StrLen(cmd_name) >= 2 && cmd_name[0] == '?' && cmd_name[1] != '?')
	{
		char tmp[MAX_SIZE];
		wchar_t *s;

		StrCpy(tmp, sizeof(tmp), cmd_name + 1);
		StrCpy(cmd_name, 0, tmp);

		s = UniCopyStr(L"/?");
		Free(cmd_param);

		cmd_param = s;
	}

	if (StrLen(cmd_name) >= 2 && EndWith(cmd_name, "?") && cmd_name[StrLen(cmd_name) - 2] != '?')
	{
		wchar_t *s;

		cmd_name[StrLen(cmd_name) - 1] = 0;

		s = UniCopyStr(L"/?");
		Free(cmd_param);

		cmd_param = s;
	}

	// コマンドの候補を取得する
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = num_cmd;
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = CopyStr(cmd[i].Name);
	}

	if (IsHelpStr(cmd_name))
	{
		if (UniIsEmptyStr(cmd_param))
		{
			wchar_t tmp[MAX_SIZE];

			// 使用できるコマンド一覧を表示する
			UniFormat(tmp, sizeof(tmp), _UU("CMD_HELP_1"), t->NumTokens);
			c->Write(c, tmp);

			PrintCandidateHelp(c, NULL, t, 1);

			c->Write(c, L"");
			c->Write(c, _UU("CMD_HELP_2"));
		}
		else
		{
			char *cmd_name;

			// 指定したコマンドのヘルプを表示する
			if (SeparateCommandAndParam(cmd_param, &cmd_name, NULL))
			{
				bool b = true;

				if (IsHelpStr(cmd_name))
				{
					b = false;
				}

				if (b)
				{
					wchar_t str[MAX_SIZE];

					UniFormat(str, sizeof(str), L"%S /help", cmd_name);
					DispatchNextCmdEx(c, str, NULL, cmd, num_cmd, param);
					no_end_crlf = true;
				}

				Free(cmd_name);
			}
		}
	}
	else if (StrCmpi(cmd_name, "exit") == 0 || StrCmpi(cmd_name, "quit") == 0)
	{
		// 終了
		b_exit = true;
	}
	else
	{
		candidate = GetRealnameCandidate(cmd_name, t);

		if (candidate == NULL || candidate->NumTokens == 0)
		{
			wchar_t tmp[MAX_SIZE];

			// 候補無し
			UniFormat(tmp, sizeof(tmp), _UU("CON_UNKNOWN_CMD"), cmd_name);
			c->Write(c, tmp);

			c->RetCode = ERR_BAD_COMMAND_OR_PARAM;
		}
		else if (candidate->NumTokens >= 2)
		{
			wchar_t tmp[MAX_SIZE];

			// 候補が複数ある
			UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGIOUS_CMD"), cmd_name);
			c->Write(c, tmp);
			c->Write(c, _UU("CON_AMBIGIOUS_CMD_1"));
			PrintCandidateHelp(c, NULL, candidate, 1);
			c->Write(c, _UU("CON_AMBIGIOUS_CMD_2"));

			c->RetCode = ERR_BAD_COMMAND_OR_PARAM;
		}
		else
		{
			char *real_cmd_name;
			UINT i;

			// 1 つに定まった
			real_cmd_name = candidate->Token[0];

			for (i = 0;i < num_cmd;i++)
			{
				if (StrCmpi(cmd[i].Name, real_cmd_name) == 0)
				{
					if (cmd[i].Proc != NULL)
					{
						// CSV モードでなければコマンドの説明を表示する
						if(c->ConsoleType != CONSOLE_CSV)
						{
							wchar_t tmp[256];
							wchar_t *note;

							GetCommandHelpStr(cmd[i].Name, &note, NULL, NULL);
							UniFormat(tmp, sizeof(tmp), _UU("CMD_EXEC_MSG_NAME"), cmd[i].Name, note);
							c->Write(c, tmp);
						}

						// コマンドのプロシージャを呼び出す
						ret = cmd[i].Proc(c, cmd[i].Name, cmd_param, param);

						if (ret == INFINITE)
						{
							// 終了コマンド
							b_exit = true;
						}
						else
						{
							c->RetCode = ret;
						}
					}
				}
			}
		}

		FreeToken(candidate);
	}

	FreeToken(t);
	Free(str);
	Free(cmd_name);
	Free(cmd_param);

	if (no_end_crlf == false)
	{
		//c->Write(c, L"");
	}

	if (b_exit)
	{
		return false;
	}

	return true;
}

// 現在のコンソールの横幅を取得する
UINT GetConsoleWidth(CONSOLE *c)
{
	UINT size;

	size = c->GetWidth(c);

	if (size == 0)
	{
		size = 80;
	}

	if (size < 32)
	{
		size = 32;
	}

	if (size > 65536)
	{
		size = 65535;
	}

	return size;
}

// コマンドラインをコマンドとパラメータの 2 つに分離する
bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param)
{
	UINT i, len, wp;
	wchar_t *tmp;
	wchar_t *src_tmp;
	// 引数チェック
	if (src == NULL)
	{
		return false;
	}
	if (cmd != NULL)
	{
		*cmd = NULL;
	}
	if (param != NULL)
	{
		*param = NULL;
	}

	src_tmp = UniCopyStr(src);
	UniTrimCrlf(src_tmp);
	UniTrim(src_tmp);

	len = UniStrLen(src_tmp);
	tmp = Malloc(sizeof(wchar_t) * (len + 32));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = src_tmp[i];

		switch (c)
		{
		case 0:
		case L' ':
		case L'\t':
			tmp[wp] = 0;
			if (UniIsEmptyStr(tmp))
			{
				Free(tmp);
				Free(src_tmp);
				return false;
			}
			if (cmd != NULL)
			{
				*cmd = CopyUniToStr(tmp);
				Trim(*cmd);
			}
			goto ESCAPE;

		default:
			tmp[wp++] = c;
			break;
		}
	}

ESCAPE:
	if (param != NULL)
	{
		*param = CopyUniStr(&src_tmp[wp]);
		UniTrim(*param);
	}

	Free(tmp);
	Free(src_tmp);

	return true;
}

// ユーザーが指定したコマンド名の省略形に一致する実在するコマンドの一覧の候補を取得する
TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list)
{
	TOKEN_LIST *ret;
	LIST *o;
	UINT i;
	bool ok = false;
	// 引数チェック
	if (input_name == NULL || real_name_list == NULL)
	{
		return NullToken();
	}

	o = NewListFast(NULL);

	for (i = 0;i < real_name_list->NumTokens;i++)
	{
		char *name = real_name_list->Token[i];

		// まず最優先で完全一致するものを検索する
		if (StrCmpi(name, input_name) == 0)
		{
			Insert(o, name);
			ok = true;
			break;
		}
	}

	if (ok == false)
	{
		// 完全一致するコマンドが無い場合、省略形コマンドとして一致するかどうかチェックする
		for (i = 0;i < real_name_list->NumTokens;i++)
		{
			char *name = real_name_list->Token[i];

			if (IsOmissionName(input_name, name) || IsNameInRealName(input_name, name))
			{
				// 省略形を発見した
				Insert(o, name);
				ok = true;
			}
		}
	}

	if (ok)
	{
		// 1 つ以上の候補が見つかった
		ret = ListToTokenList(o);
	}
	else
	{
		ret = NullToken();
	}

	ReleaseList(o);

	return ret;
}

// ユーザーが指定したコマンドが既存のコマンドの省略形かどうかチェックする
bool IsOmissionName(char *input_name, char *real_name)
{
	char oname[128];
	// 引数チェック
	if (input_name == NULL || real_name == NULL)
	{
		return false;
	}

	if (IsAllUpperStr(real_name))
	{
		// すべて大文字のコマンドは省略形をとらない
		return false;
	}

	GetOmissionName(oname, sizeof(oname), real_name);

	if (IsEmptyStr(oname))
	{
		return false;
	}

	if (StartWith(oname, input_name))
	{
		// 例: AccountSecureCertSet の oname は ascs だが
		//     ユーザーが asc と入力した場合は true を返す
		return true;
	}

	if (StartWith(input_name, oname))
	{
		// 例: AccountConnect と
		//     AccountCreate の 2 つのコマンドが実在する際、
		//     ユーザーが "aconnect" と入力すると、
		//     AccountConnect のみ true になるようにする

		if (EndWith(real_name, &input_name[StrLen(oname)]))
		{
			return true;
		}
	}

	return false;
}

// 指定したコマンド名の省略名を取得する
void GetOmissionName(char *dst, UINT size, char *src)
{
	UINT i, len;
	// 引数チェック
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(dst, size, "");
	len = StrLen(src);

	for (i = 0;i < len;i++)
	{
		char c = src[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z'))
		{
			char tmp[2];
			tmp[0] = c;
			tmp[1] = 0;

			StrCat(dst, size, tmp);
		}
	}
}

// ユーザーが指定したコマンドが既存のコマンドに一致するかどうかチェックする
bool IsNameInRealName(char *input_name, char *real_name)
{
	// 引数チェック
	if (input_name == NULL || real_name == NULL)
	{
		return false;
	}

	if (StartWith(real_name, input_name))
	{
		return true;
	}

	return false;
}

// コマンドリストをパースする
LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param)
{
	UINT i;
	LIST *o;
	bool ok = true;
	TOKEN_LIST *param_list;
	TOKEN_LIST *real_name_list;
	bool help_mode = false;
	wchar_t *tmp;
	// 引数チェック
	if (c == NULL || command == NULL || (num_param >= 1 && param == NULL) || cmd_name == NULL)
	{
		return NULL;
	}

	// 初期化
	for (i = 0;i < num_param;i++)
	{
		if (IsEmptyStr(param[i].Name) == false)
		{
			if (param[i].Name[0] == '[')
			{
				param[i].Tmp = "";
			}
			else
			{
				param[i].Tmp = NULL;
			}
		}
		else
		{
			param[i].Tmp = "";
		}
	}

	real_name_list = ZeroMalloc(sizeof(TOKEN_LIST));
	real_name_list->NumTokens = num_param;
	real_name_list->Token = ZeroMalloc(sizeof(char *) * real_name_list->NumTokens);

	for (i = 0;i < real_name_list->NumTokens;i++)
	{
		real_name_list->Token[i] = CopyStr(param[i].Name);
	}

	// ユーザーが指定したパラメータ名のリストを生成する
	param_list = GetCommandNameList(command);

	for (i = 0;i < param_list->NumTokens;i++)
	{
		char *s = param_list->Token[i];

		if (StrCmpi(s, "help") == 0 || StrCmpi(s, "?") == 0)
		{
			help_mode = true;
			break;
		}
	}

	tmp = ParseCommand(command, L"");
	if (tmp != NULL)
	{
		if (UniStrCmpi(tmp, L"?") == 0)
		{
			help_mode = true;
		}
		Free(tmp);
	}

	if (help_mode)
	{
		// ヘルプを表示
		PrintCmdHelp(c, cmd_name, real_name_list);
		FreeToken(param_list);
		FreeToken(real_name_list);
		return NULL;
	}

	for (i = 0;i < param_list->NumTokens;i++)
	{
		// ユーザーが指定したすべてのパラメータ名について対応するコマンドを取得する
		TOKEN_LIST *candidate = GetRealnameCandidate(param_list->Token[i], real_name_list);

		if (candidate != NULL && candidate->NumTokens >= 1)
		{
			if (candidate->NumTokens >= 2)
			{
				wchar_t tmp[MAX_SIZE];

				// 2 つ以上の候補がある
				UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGIOUS_PARAM"), param_list->Token[i]);
				c->Write(c, tmp);
				UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGIOUS_PARAM_1"), cmd_name);
				c->Write(c, tmp);

				PrintCandidateHelp(c, cmd_name, candidate, 1);

				c->Write(c, _UU("CON_AMBIGIOUS_PARAM_2"));

				ok = false;
			}
			else
			{
				UINT j;
				char *real_name = candidate->Token[0];

				// 候補が 1 つだけしか無い
				for (j = 0;j < num_param;j++)
				{
					if (StrCmpi(param[j].Name, real_name) == 0)
					{
						param[j].Tmp = param_list->Token[i];
					}
				}
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			// 候補無し
			UniFormat(tmp, sizeof(tmp), _UU("CON_INVALID_PARAM"), param_list->Token[i], cmd_name, cmd_name);
			c->Write(c, tmp);

			ok = false;
		}

		FreeToken(candidate);
	}

	if (ok == false)
	{
		FreeToken(param_list);
		FreeToken(real_name_list);

		return NULL;
	}

	// リストの作成
	o = NewParamValueList();

	// パラメータ一覧に指定された名前のすべてのパラメータを読み込む
	for (i = 0;i < num_param;i++)
	{
		bool prompt_input_value = false;
		PARAM *p = &param[i];

		if (p->Tmp != NULL || p->PromptProc != NULL)
		{
			wchar_t *name = CopyStrToUni(p->Name);
			wchar_t *tmp;
			wchar_t *str;

			if (p->Tmp != NULL)
			{
				tmp = CopyStrToUni(p->Tmp);
			}
			else
			{
				tmp = CopyStrToUni(p->Name);
			}

			str = ParseCommand(command, tmp);
			Free(tmp);
			if (str != NULL)
			{
				wchar_t *unistr;
				bool ret;
EVAL_VALUE:
				// 読み込みに成功した
				unistr = str;

				if (p->EvalProc != NULL)
				{
					// EvalProc が指定されている場合は値を評価する
					ret = p->EvalProc(c, unistr, p->EvalProcParam);
				}
				else
				{
					// EvalProc が指定されていない場合はどのような値でも受け付ける
					ret = true;
				}

				if (ret == false)
				{
					// 指定した値は不正である
					if (p->PromptProc == NULL)
					{
						// キャンセル
						ok = false;
						Free(name);
						Free(str);
						break;
					}
					else
					{
						// もう一度入力させる
						Free(str);
						str = NULL;
						goto SHOW_PROMPT;
					}
				}
				else
				{
					PARAM_VALUE *v;
					// 読み込み完了したのでリストに追加する
					v = ZeroMalloc(sizeof(PARAM_VALUE));
					v->Name = CopyStr(p->Name);
					v->StrValue = CopyUniToStr(str);
					v->UniStrValue = CopyUniStr(str);
					v->IntValue = ToInt(v->StrValue);
					Insert(o, v);
				}
			}
			else
			{
				// 読み込みに失敗した。指定されたパラメータが指定されていない
				if (p->PromptProc != NULL)
				{
					wchar_t *tmp;
SHOW_PROMPT:
					// 必須パラメータであるのでプロンプトを表示する
					tmp = p->PromptProc(c, p->PromptProcParam);
					if (tmp == NULL)
					{
						// ユーザーがキャンセルした
						ok = false;
						Free(str);
						Free(name);
						break;
					}
					else
					{
						// ユーザーが入力した
						c->Write(c, L"");
						str = tmp;
						prompt_input_value = true;
						goto EVAL_VALUE;
					}
				}
			}

			Free(str);
			Free(name);
		}
	}

	FreeToken(param_list);
	FreeToken(real_name_list);

	if (ok)
	{
		return o;
	}
	else
	{
		FreeParamValueList(o);
		return NULL;
	}
}

// [はい] か [いいえ] の取得
bool GetParamYes(LIST *o, char *name)
{
	char *s;
	char tmp[64];
	// 引数チェック
	if (o == NULL)
	{
		return false;
	}

	s = GetParamStr(o, name);
	if (s == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), s);
	Trim(tmp);

	if (StartWith(tmp, "y"))
	{
		return true;
	}

	if (StartWith(tmp, "t"))
	{
		return true;
	}

	if (ToInt(tmp) != 0)
	{
		return true;
	}

	return false;
}

// パラメータ値 Int の取得
UINT GetParamInt(LIST *o, char *name)
{
	PARAM_VALUE *v;
	// 引数チェック
	if (o == NULL)
	{
		return 0;
	}

	v = FindParamValue(o, name);
	if (v == NULL)
	{
		return 0;
	}
	else
	{
		return v->IntValue;
	}
}

// パラメータ値 Unicode 文字列の取得
wchar_t *GetParamUniStr(LIST *o, char *name)
{
	PARAM_VALUE *v;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	v = FindParamValue(o, name);
	if (v == NULL)
	{
		return NULL;
	}
	else
	{
		return v->UniStrValue;
	}
}

// パラメータ値文字列の所得
char *GetParamStr(LIST *o, char *name)
{
	PARAM_VALUE *v;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}

	v = FindParamValue(o, name);
	if (v == NULL)
	{
		return NULL;
	}
	else
	{
		return v->StrValue;
	}
}

// パラメータ値の取得
PARAM_VALUE *FindParamValue(LIST *o, char *name)
{
	PARAM_VALUE t, *ret;
	// 引数チェック
	if (o == NULL)
	{
		return NULL;
	}
	if (name == NULL)
	{
		name = "";
	}

	Zero(&t, sizeof(t));
	t.Name = name;

	ret = Search(o, &t);

	return ret;
}

// パラメータ値リストの解放
void FreeParamValueList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		PARAM_VALUE *v = LIST_DATA(o, i);

		Free(v->StrValue);
		Free(v->UniStrValue);
		Free(v->Name);
		Free(v);
	}

	ReleaseList(o);
}

// パラメータ値リストソート関数
int CmpParamValue(void *p1, void *p2)
{
	PARAM_VALUE *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(PARAM_VALUE **)p1;
	v2 = *(PARAM_VALUE **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	if (IsEmptyStr(v1->Name) && IsEmptyStr(v2->Name))
	{
		return 0;
	}
	return StrCmpi(v1->Name, v2->Name);
}

// パラメータ値リストの生成
LIST *NewParamValueList()
{
	return NewListFast(CmpParamValue);
}

// 入力されたコマンドに含まれていたパラメータ名のリストを取得する
TOKEN_LIST *GetCommandNameList(wchar_t *str)
{
	TOKEN_LIST *t;
	// 引数チェック
	if (str == NULL)
	{
		return NullToken();
	}

	Free(ParseCommandEx(str, L"dummy_str", &t));

	return t;
}

// 指定した名前で始まるコマンドを取得する
wchar_t *ParseCommand(wchar_t *str, wchar_t *name)
{
	return ParseCommandEx(str, name, NULL);
}
wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list)
{
	UNI_TOKEN_LIST *t;
	UINT i;
	wchar_t *tmp;
	wchar_t *ret = NULL;
	LIST *o;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}
	if (name != NULL && UniIsEmptyStr(name))
	{
		name = NULL;
	}

	o = NULL;
	if (param_list != NULL)
	{
		o = NewListFast(CompareStr);
	}

	tmp = CopyUniStr(str);
	UniTrim(tmp);

	i = UniSearchStrEx(tmp, L"/CMD ", 0, false);

	// このあたりは急いで実装したのでコードがあまり美しくない。
	if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
	{
		i = INFINITE;
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"/CMD\t", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"/CMD:", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"/CMD=", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'/')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD ", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD\t", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD:", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}
	if (i == INFINITE)
	{
		i = UniSearchStrEx(tmp, L"-CMD=", 0, false);
		if (i != INFINITE && i >= 1 && tmp[i - 1] == L'-')
		{
			i = INFINITE;
		}
	}

	if (i != INFINITE)
	{
		char *s = CopyStr("CMD");
		if (InsertStr(o, s) == false)
		{
			Free(s);
		}
		if (UniStrCmpi(name, L"CMD") == 0)
		{
			ret = CopyUniStr(&str[i + 5]);
			UniTrim(ret);
		}
		else
		{
			tmp[i] = 0;
		}
	}

	if (ret == NULL)
	{
		t = UniParseCmdLine(tmp);

		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				wchar_t *token = t->Token[i];

				if ((token[0] == L'-' && token[1] != L'-') ||
					(UniStrCmpi(token, L"--help") == 0) ||
					(token[0] == L'/' && token[1] != L'/'))
				{
					UINT i;

					// 名前付き引数
					// コロン文字があるかどうか調べる

					if (UniStrCmpi(token, L"--help") == 0)
					{
						token++;
					}

					i = UniSearchStrEx(token, L":", 0, false);
					if (i == INFINITE)
					{
						i = UniSearchStrEx(token, L"=", 0, false);
					}
					if (i != INFINITE)
					{
						wchar_t *tmp;
						char *a;

						// コロン文字がある
						tmp = CopyUniStr(token);
						tmp[i] = 0;

						a = CopyUniToStr(&tmp[1]);
						if (InsertStr(o, a) == false)
						{
							Free(a);
						}

						if (UniStrCmpi(name, &tmp[1]) == 0)
						{
							if (ret == NULL)
							{
								// 内容
								ret = UniCopyStr(&token[i + 1]);
							}
						}

						Free(tmp);
					}
					else
					{
						// コロン文字が無い
						char *a;

						a = CopyUniToStr(&token[1]);
						if (InsertStr(o, a) == false)
						{
							Free(a);
						}

						if (UniStrCmpi(name, &token[1]) == 0)
						{
							if (ret == NULL)
							{
								// 空文字
								ret = UniCopyStr(L"");
							}
						}
					}
				}
				else
				{
					// 名前無し引数
					if (name == NULL)
					{
						if (ret == NULL)
						{
							if (token[0] == L'-' && token[1] == L'-')
							{
								ret = UniCopyStr(&token[1]);
							}
							else if (token[0] == L'/' && token[1] == L'/')
							{
								ret = UniCopyStr(&token[1]);
							}
							else
							{
								ret = UniCopyStr(token);
							}
						}
					}
				}
			}

			UniFreeToken(t);
		}
	}

	Free(tmp);

	if (o != NULL)
	{
		TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
		UINT i;

		t->NumTokens = LIST_NUM(o);
		t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

		for (i = 0;i < t->NumTokens;i++)
		{
			t->Token[i] = LIST_DATA(o, i);
		}

		ReleaseList(o);

		*param_list = t;
	}

	if (UniStrCmpi(ret, L"none") == 0 || UniStrCmpi(ret, L"null") == 0)
	{
		// none と null は予約語である
		ret[0] = 0;
	}

	return ret;
}
char *ParseCommandA(wchar_t *str, char *name)
{
	wchar_t *tmp1, *tmp2;
	char *ret;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	if (name != NULL)
	{
		tmp1 = CopyStrToUni(name);
	}
	else
	{
		tmp1 = NULL;
	}

	tmp2 = ParseCommand(str, tmp1);

	if (tmp2 == NULL)
	{
		ret = NULL;
	}
	else
	{
		ret = CopyUniToStr(tmp2);
		Free(tmp2);
	}

	Free(tmp1);

	return ret;
}

// パスワードプロンプト
bool PasswordPrompt(char *password, UINT size)
{
	UINT wp;
	bool escape = false;
	void *console;
	// 引数チェック
	if (password == NULL || size <= 1)
	{
		if (size >= 1)
		{
			password[0] = 0;
		}
		return false;
	}

	wp = 0;

	Zero(password, size);

	console = SetConsoleRaw();

	while (true)
	{
		int c;

#ifdef	OS_WIN32
		c = getch();
#else	// OS_WIN32
		c = getc(stdin);
#endif	// OS_WIN32

		if (c >= 0x20 && c <= 0x7E)
		{
			// 文字
			if ((wp + 1) < size)
			{
				password[wp++] = (char)c;
				putc('*', stdout);
			}
		}
		else if (c == 0x03)
		{
			// 強制終了
			exit(0);
		}
		else if (c == 0x04 || c == 0x1a || c == 0x0D || c==0x0A)
		{
			// 終了
			if (c == 0x04 || c == 0x1a)
			{
				escape = true;
			}
			break;
		}
		else if (c == 0xE0)
		{
			// もう 1 文字読む
			c = getch();
			if (c == 0x4B || c == 0x53)
			{
				// バックスペース
				goto BACKSPACE;
			}
		}
		else if (c == 0x08)
		{
BACKSPACE:
			// バックスペース
			if (wp >= 1)
			{
				password[--wp] = 0;
				putc(0x08, stdout);
				putc(' ', stdout);
				putc(0x08, stdout);
			}
		}
	}
	Print("\n");

	RestoreConsole(console);

	return (escape ? false : true);
}

// プロンプトを表示
wchar_t *Prompt(wchar_t *prompt_str)
{
	wchar_t *ret = NULL;
	wchar_t *tmp = NULL;
	// 引数チェック
	if (prompt_str == NULL)
	{
		prompt_str = L"";
	}

#ifdef	OS_WIN32
	UniPrint(L"%s", prompt_str);
	tmp = Malloc(MAX_PROMPT_STRSIZE);
	if (fgetws(tmp, MAX_PROMPT_STRSIZE - 1, stdin) != NULL)
	{
		bool escape = false;
		UINT i, len;

		len = UniStrLen(tmp);
		for (i = 0;i < len;i++)
		{
			if (tmp[i] == 0x04 || tmp[i] == 0x1A)
			{
				escape = true;
				break;
			}
		}

		if (escape == false)
		{
			UniTrimCrlf(tmp);

			ret = UniCopyStr(tmp);
		}
	}
	Free(tmp);
#else	// OS_WIN32
	{
		char *prompt = CopyUniToStr(prompt_str);
		char *s = readline(prompt);
		Free(prompt);

		if (s != NULL)
		{
			TrimCrlf(s);
			Trim(s);

			if (IsEmptyStr(s) == false)
			{
				add_history(s);
			}

			ret = CopyStrToUni(s);

			free(s);
		}
	}
#endif	// OS_WIN32

	if (ret == NULL)
	{
		Print("\n");
	}

	return ret;
}
char *PromptA(wchar_t *prompt_str)
{
	wchar_t *str = Prompt(prompt_str);

	if (str == NULL)
	{
		return NULL;
	}
	else
	{
		char *ret = CopyUniToStr(str);

		Free(str);
		return ret;
	}
}

// コンソールを Raw モードにする
void *SetConsoleRaw()
{
#ifdef	OS_UNIX
	struct termios t, *ret;

	Zero(&t, sizeof(t));
	if (tcgetattr(0, &t) != 0)
	{
		// 失敗
		return NULL;
	}

	// 現在の設定をコピー
	ret = Clone(&t, sizeof(t));

	// 設定を変更
	t.c_lflag &= (~ICANON);
	t.c_lflag &= (~ECHO);
	t.c_cc[VTIME] = 0;
	t.c_cc[VMIN] = 1;
	tcsetattr(0, TCSANOW, &t);

	return ret;
#else	// OS_UNIX
	return Malloc(0);
#endif	// OS_UNIX
}

// コンソールのモードを復帰する
void RestoreConsole(void *p)
{
#ifdef	OS_UNIX
	struct termios *t;
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	t = (struct termios *)p;

	// 設定を復帰する
	tcsetattr(0, TCSANOW, t);

	Free(t);
#else	// OS_UNIX
	if (p != NULL)
	{
		Free(p);
	}
#endif	// OS_UNIX
}

////////////////////////////
// ローカルコンソール関数

// 新しいローカルコンソールの作成
CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile)
{
	IO *in_io = NULL, *out_io = NULL;
	CONSOLE *c = ZeroMalloc(sizeof(CONSOLE));
	LOCAL_CONSOLE_PARAM *p;
	UINT old_size = 0;

#ifdef	OS_WIN32
	if (MsGetConsoleWidth() == 80)
	{
		//old_size = MsSetConsoleWidth(WIN32_DEFAULT_CONSOLE_WIDTH);
	}
#endif	// OS_WIN32

	c->ConsoleType = CONSOLE_LOCAL;
	c->Free = ConsoleLocalFree;
	c->ReadLine = ConsoleLocalReadLine;
	c->ReadPassword = ConsoleLocalReadPassword;
	c->Write = ConsoleLocalWrite;
	c->GetWidth = ConsoleLocalGetWidth;

	if (UniIsEmptyStr(infile) == false)
	{
		// 入力ファイルが指定されている
		in_io = FileOpenW(infile, false);
		if (in_io == NULL)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_INFILE_ERROR"), infile);
			c->Write(c, tmp);
			Free(c);
			return NULL;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_INFILE_START"), infile);
			c->Write(c, tmp);
		}
	}

	if (UniIsEmptyStr(outfile) == false)
	{
		// 出力ファイルが指定されている
		out_io = FileCreateW(outfile);
		if (out_io == NULL)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_OUTFILE_ERROR"), outfile);
			c->Write(c, tmp);
			Free(c);

			if (in_io != NULL)
			{
				FileClose(in_io);
			}
			return NULL;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_OUTFILE_START"), outfile);
			c->Write(c, tmp);
		}
	}

	p = ZeroMalloc(sizeof(LOCAL_CONSOLE_PARAM));
	c->Param = p;

	p->InFile = in_io;
	p->OutFile = out_io;
	p->Win32_OldConsoleWidth = old_size;

	if (in_io != NULL)
	{
		UINT size;
		void *buf;

		size = FileSize(in_io);
		buf = ZeroMalloc(size + 1);
		FileRead(in_io, buf, size);

		p->InBuf = NewBuf();
		WriteBuf(p->InBuf, buf, size);
		Free(buf);

		p->InBuf->Current = 0;
	}

	return c;
}

// コンソール解放
void ConsoleLocalFree(CONSOLE *c)
{
	LOCAL_CONSOLE_PARAM *p;
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	p = (LOCAL_CONSOLE_PARAM *)c->Param;

#ifdef	OS_WIN32
	if (p->Win32_OldConsoleWidth != 0)
	{
		MsSetConsoleWidth(p->Win32_OldConsoleWidth);
	}
#endif	// OS_WIN32

	if (p != NULL)
	{
		if (p->InFile != NULL)
		{
			FileClose(p->InFile);
			FreeBuf(p->InBuf);
		}

		if (p->OutFile != NULL)
		{
			FileClose(p->OutFile);
		}

		Free(p);
	}

	// メモリ解放
	Free(c);
}

// 画面の横幅を取得
UINT ConsoleLocalGetWidth(CONSOLE *c)
{
	UINT ret = 0;
	// 引数チェック
	if (c == NULL)
	{
		return 0;
	}

#ifdef	OS_WIN32
	ret = MsGetConsoleWidth();
#else	// OS_WIN32
	{
		struct winsize t;

		Zero(&t, sizeof(t));

		if (ioctl(1, TIOCGWINSZ, &t) == 0)
		{
			ret = t.ws_col;
		}
	}
#endif	// OS_WIN32

	return ret;
}

// コンソールから 1 行読み込む
wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile)
{
	wchar_t *ret;
	LOCAL_CONSOLE_PARAM *p;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}
	p = (LOCAL_CONSOLE_PARAM *)c->Param;
	if (prompt == NULL)
	{
		prompt = L">";
	}

	ConsoleWriteOutFile(c, prompt, false);

	if (nofile == false && p->InBuf != NULL)
	{
		// ファイルから次の行を読み込む
		ret = ConsoleReadNextFromInFile(c);

		if (ret != NULL)
		{
			// 擬似プロンプトを表示する
			UniPrint(L"%s", prompt);

			// 画面に描画する
			UniPrint(L"%s\n", ret);
		}
	}
	else
	{
		// 画面から次の行を読み込む
		ret = Prompt(prompt);
	}

	if (ret != NULL)
	{
		ConsoleWriteOutFile(c, ret, true);
	}
	else
	{
		ConsoleWriteOutFile(c, _UU("CON_USER_CANCEL"), true);
	}

	return ret;
}

// コンソールからパスワードを読み込む
char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt)
{
	char tmp[64];
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}
	if (prompt == NULL)
	{
		prompt = L"Password>";
	}

	UniPrint(L"%s", prompt);
	ConsoleWriteOutFile(c, prompt, false);

	if (PasswordPrompt(tmp, sizeof(tmp)))
	{
		ConsoleWriteOutFile(c, L"********", true);
		return CopyStr(tmp);
	}
	else
	{
		ConsoleWriteOutFile(c, _UU("CON_USER_CANCEL"), true);
		return NULL;
	}
}

// コンソールに文字列を表示する
bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str)
{
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniPrint(L"%s%s", str, (UniEndWith(str, L"\n") ? L"" : L"\n"));

	ConsoleWriteOutFile(c, str, true);

	return true;
}

// 入力ファイルから次の 1 行を読み込む
wchar_t *ConsoleReadNextFromInFile(CONSOLE *c)
{
	LOCAL_CONSOLE_PARAM *p;
	char *str;
	// 引数チェック
	if (c == NULL)
	{
		return NULL;
	}

	p = (LOCAL_CONSOLE_PARAM *)c->Param;

	if (p->InBuf == NULL)
	{
		return NULL;
	}

	while (true)
	{
		str = CfgReadNextLine(p->InBuf);

		if (str == NULL)
		{
			return NULL;
		}

		Trim(str);

		if (IsEmptyStr(str) == false)
		{
			UINT size;
			wchar_t *ret;

			size = CalcUtf8ToUni((BYTE *)str, StrLen(str));
			ret = ZeroMalloc(size + 32);
			Utf8ToUni(ret, size, (BYTE *)str, StrLen(str));

			Free(str);

			return ret;
		}

		Free(str);
	}
}

// 出力ファイルが指定されている場合は書き出す
void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf)
{
	LOCAL_CONSOLE_PARAM *p;
	// 引数チェック
	if (c == NULL || str == NULL)
	{
		return;
	}

	p = (LOCAL_CONSOLE_PARAM *)c->Param;

	if (p != NULL && p->OutFile != NULL)
	{
		wchar_t *tmp = UniNormalizeCrlf(str);
		UINT utf8_size;
		UCHAR *utf8;

		utf8_size = CalcUniToUtf8(tmp);
		utf8 = ZeroMalloc(utf8_size + 1);
		UniToUtf8(utf8, utf8_size + 1, tmp);

		FileWrite(p->OutFile, utf8, utf8_size);

		if (UniEndWith(str, L"\n") == false && add_last_crlf)
		{
			char *crlf = "\r\n";
			FileWrite(p->OutFile, "\r\n", StrLen(crlf));
		}

		Free(utf8);
		Free(tmp);
	}

}

