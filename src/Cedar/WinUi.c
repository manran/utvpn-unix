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

// WinUi.c
// Win32 用ユーザーインターフェースコード

#ifdef	WIN32

#define	WINUI_C

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <Iphlpapi.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "../PenCore/resource.h"

char cached_pin_code[MAX_SIZE] = {0};
UINT64 cached_pin_code_expires = 0;

static HINSTANCE hDll = NULL;
static wchar_t *title_bar = NULL;
static char *font_name = NULL;
static UINT font_size = 9;
static HIMAGELIST large_image_list = NULL, small_image_list = NULL;
static LIST *icon_list = NULL;
static HINSTANCE hMsHtml = NULL;
static UINT init_winui_counter = 0;
static bool new_style_mode = false;

bool UseAlpha = false;
UINT AlphaValue = 100;

static THREAD *led_thread = NULL;
static bool thread_stop = false;
static bool g_led_special = false;
static bool g_tcpip_topmost = false;

typedef struct GDI_CACHE
{
	bool IsInited;
	COLORREF BackgroundColor;
	COLORREF ForegroundColor;
	COLORREF TextBoxBackgroundColor;
	HBRUSH BlackBrush;
	HBRUSH WhiteBrush;
	HBRUSH BackgroundColorBrush;
	HBRUSH ForegroundColorBrush;
	HBRUSH TextBoxBackgroundColorBrush;
} GDI_CACHE;

static GDI_CACHE gdi_cache = { false, };

// スプラッシュウインドウデータ
typedef struct SPLASH
{
	HWND hWnd;
	HWND hWndParent;
	WINBMP *Bmp;
	void *Param;
	UINT64 Ticks;
	UINT64 StartTick;
	char *Title;
	wchar_t *Caption;
	HPEN LinePen;
	WINMEMDC *BackDC;
} SPLASH;

// 画面がフルカラーモードかどうか取得
bool IsFullColor()
{
	bool ret = false;
	HDC hDC = CreateCompatibleDC(0);

	if (GetDeviceCaps(hDC, BITSPIXEL) >= 16)
	{
		ret = true;
	}

	DeleteDC(hDC);

	return ret;
}

// リストビューの背景に画像を表示する
void LvSetBkImage(HWND hWnd, UINT id, char *bmp_file_name)
{
	LVBKIMAGE t;
	char *tmp;
	// 引数チェック
	if (hWnd == NULL || bmp_file_name == NULL)
	{
		return;
	}
	if (IsFullColor() == false)
	{
		// 256 色モードの場合は表示しない
		return;
	}

	Zero(&t, sizeof(t));

	tmp = MsCreateTempFileNameByExt(".bmp");

	FileCopy(bmp_file_name, tmp);

	t.ulFlags = LVBKIF_SOURCE_URL | LVBKIF_STYLE_NORMAL;
	t.pszImage = tmp;
	t.xOffsetPercent = 100;
	t.yOffsetPercent = 100;

	ListView_SetBkImage(DlgItem(hWnd, id), &t);

	Free(tmp);
}

// メモリ DC を解放する
void FreeMemDC(WINMEMDC *m)
{
	// 引数チェック
	if (m == NULL)
	{
		return;
	}

	DeleteDC(m->hDC);
	DeleteObject(m->hBitmap);

	Free(m);
}

// メモリ DC を作成する
WINMEMDC *NewMemDC(UINT width, UINT height)
{
	WINMEMDC *m = ZeroMalloc(sizeof(WINMEMDC));
	BITMAPINFOHEADER h;
	BITMAPINFO bi;

	m->Width = width;
	m->Height = height;

	m->hDC = CreateCompatibleDC(0);

	Zero(&h, sizeof(h));
	h.biSize = sizeof(h);
	h.biWidth = width;
	h.biHeight = height;
	h.biPlanes = 1;
	h.biBitCount = 24;
	h.biXPelsPerMeter = 2834;
	h.biYPelsPerMeter = 2834;

	Zero(&bi, sizeof(bi));
	Copy(&bi.bmiHeader, &h, sizeof(BITMAPINFOHEADER));

	m->hBitmap = CreateDIBSection(m->hDC, &bi, DIB_RGB_COLORS,
		&m->Data, NULL, 0);

	SelectObject(m->hDC, m->hBitmap);

	return m;
}

// スプラッシュ画面を表示する (毎回絵が変わる)
void ShowSplashEx(HWND hWndParent, char *software_name, UINT ticks, UINT line_color)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t caption[MAX_SIZE];
	UINT id = MsRegReadInt(REG_CURRENT_USER, SPLASH_BMP_REGKEY, SPLASH_BMP_REGVALUE);
	id++;
	if (id > 20)
	{
		id = 1;
	}
	MsRegWriteInt(REG_CURRENT_USER, SPLASH_BMP_REGKEY, SPLASH_BMP_REGVALUE, id);

	UniFormat(tmp, sizeof(tmp), L"|Splash%02u.bmp", id);

	StrToUni(caption, sizeof(caption), software_name);

	ShowSplash(hWndParent, tmp, software_name, caption, ticks, line_color, NULL);
}

// フォント描画
void DrawFont(HDC hDC, wchar_t *text, UINT x, UINT y, HFONT font, UINT fore_color,
			  UINT back_color, UINT back_width)
{
	int i, j;

	SelectObject(hDC, font);
	SetBkMode(hDC, TRANSPARENT);

	// 背景の描画
	SetTextColor(hDC, back_color);
	for (i = -((int)back_width);i <= (int)back_width;i++)
	{
		for (j = -((int)back_width); j <= (int)back_width;j++)
		{
			if (i != 0 || j != 0)
			{
				TextOutW(hDC, (int)x + i, (int)y + j, text, UniStrLen(text));
			}
		}
	}

	// 文字の描画
	SetTextColor(hDC, fore_color);
	TextOutW(hDC, x, y, text, UniStrLen(text));
}

// スプラッシュウインドウを開く
LRESULT CALLBACK SplashProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	SPLASH *splash;
	CREATESTRUCT *cs = (CREATESTRUCT *)lParam;
	UINT64 now = Tick64();
	UINT64 current_span = 0;
	UINT a;
	UINT fade = 8;

	if (msg == WM_CREATE)
	{
		splash = (SPLASH *)cs->lpCreateParams;
		current_span = 0;
	}
	else
	{
		splash = (SPLASH *)GetWindowLongPtrA(hWnd, GWLP_USERDATA);
		if (splash != NULL)
		{
			current_span = now - splash->StartTick;
		}
	}

	switch (msg)
	{
	case WM_CREATE:
		SetWindowLongPtrA(hWnd, GWLP_USERDATA, (LONG_PTR)splash);

		CenterParent(hWnd);

		if (splash->Ticks != 0)
		{
			SetTimer(hWnd, 1, 1, NULL);

			splash->StartTick = now;

			SetAplha(hWnd, 0);

			Top(hWnd);
		}

		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			a = 0;

			if (current_span < (splash->Ticks / fade))
			{
				// フェードイン
				a = (UINT)((double)current_span * 255.0 / (double)(splash->Ticks / fade));
			}
			else if (current_span < (splash->Ticks * (fade - 1) / fade))
			{
				// 通常表示
				a = 255;
			}
			else if (current_span < splash->Ticks)
			{
				// フェードアウト
				a = 255 - (UINT)(((double)(current_span - (splash->Ticks * (fade - 1) / fade))) * 255.0 / (double)(splash->Ticks / fade));
			}
			else
			{
				// 閉じる
				goto LABEL_CLOSE;
			}

			SetAplha(hWnd, a);

			SetTimer(hWnd, 1, 1, NULL);
			break;
		}
		break;

	case WM_PAINT:
		if (true)
		{
			PAINTSTRUCT ps;
			HDC hDC, hWndDC;

			Zero(&ps, sizeof(ps));
			hWndDC = BeginPaint(hWnd, &ps);
			if (hWndDC != NULL)
			{
				POINT points[5];
				wchar_t tmp[MAX_SIZE];

				hDC = splash->BackDC->hDC;

				// ビットマップ画像
				BitBlt(hDC, 0, 0, splash->Bmp->Width, splash->Bmp->Height,
					splash->Bmp->hDC, 0, 0, SRCCOPY);

				// 線
				Zero(points, sizeof(points));
				points[0].x = 0; points[0].y = 0;
				points[1].x = splash->Bmp->Width - 1; points[1].y = 0;
				points[2].x = splash->Bmp->Width - 1; points[2].y = splash->Bmp->Height - 1;
				points[3].x = 0; points[3].y = splash->Bmp->Height - 1;
				points[4].x = 0; points[4].y = 0;

				SelectObject(hDC, splash->LinePen);
				Polyline(hDC, points, 5);

				// ソフトウェアのタイトルの描画
				DrawFont(hDC, splash->Caption, 114, 136,
					GetFont("Arial", 36, true, false, false, false),
					RGB(0, 0, 0),
					RGB(255, 255, 255),
					3);

				// ソフトウェアのバージョン情報の描画
				UniFormat(tmp, sizeof(tmp),
					L"Version %u.%02u Build %u, Compiled in %04u/%02u/%02u.",
					CEDAR_VER / 100, CEDAR_VER - (CEDAR_VER / 100) * 100,
					CEDAR_BUILD, BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D);
				DrawFont(hDC, tmp, 200, 202,
					GetFont("Arial", 8, true, false, false, false),
					RGB(0, 0, 0),
					RGB(255, 255, 255),
					1);

				// 画面に描画
				BitBlt(hWndDC, 0, 0, splash->Bmp->Width, splash->Bmp->Height,
					hDC, 0, 0, SRCCOPY);

				EndPaint(hWnd, &ps);
			}
		}
		break;

	case WM_CLOSE:
		if (splash->Ticks != 0)
		{
			return 0;
		}
LABEL_CLOSE:
		if (splash->hWndParent != NULL)
		{
			Enable(splash->hWndParent, 0);
		}
		DestroyWindow(hWnd);
		return 0;

	case WM_KEYDOWN:
		switch (wParam)
		{
		case VK_ESCAPE:
		case VK_RETURN:
		case VK_SPACE:
			Close(hWnd);
			break;
		}
		break;

	case WM_LBUTTONUP:
	case WM_RBUTTONUP:
	case WM_MBUTTONUP:
		Close(hWnd);
		break;

	case WM_DESTROY:
		if (splash->hWndParent != NULL)
		{
			Enable(splash->hWndParent, 0);
		}
		PostQuitMessage(0);
		return 0;
	}

	return DefWindowProc(hWnd, msg, wParam, lParam);
}

// スプラッシュウインドウ
void ShowSplash(HWND hWndParent, wchar_t *bmp_file_name, char *title, wchar_t *caption, UINT ticks, UINT line_color, void *param)
{
	SPLASH *p;
	WNDCLASSA wc;
	char wndclass_name[MAX_SIZE];
	// 引数チェック
	if (bmp_file_name == NULL)
	{
		return;
	}
	if (IsEmptyStr(title))
	{
		title = "Splash Window";
	}

	p = ZeroMalloc(sizeof(SPLASH));

	p->Bmp = LoadBmpFromFileW(bmp_file_name);
	if (p->Bmp == NULL)
	{
		Free(p);
		return;
	}

	p->BackDC = NewMemDC(p->Bmp->Width, p->Bmp->Height);

	p->LinePen = CreatePen(PS_SOLID, 1, line_color);

	p->hWndParent = hWndParent;

	p->Title = title;
	p->Caption = caption;
	p->Ticks = ticks;

	p->Param = param;

	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL, ticks == 0 ? IDC_ARROW : IDC_APPSTARTING);
	wc.hInstance = GetModuleHandleA(NULL);
	wc.lpfnWndProc = SplashProc;

	Format(wndclass_name, sizeof(wndclass_name), "WINUI_SPLASH_CLASS_%I64u", Rand64());
	wc.lpszClassName = wndclass_name;

	RegisterClassA(&wc);

	p->hWnd = CreateWindowA(wndclass_name, title,
		WS_POPUP, 0, 0,
		p->Bmp->Width, p->Bmp->Height,
		hWndParent, NULL, GetModuleHandleA(NULL), p);
	if (p->hWnd == NULL)
	{
		Debug("CreateWindowA Error: %u\n", GetLastError());
	}

	if (hWndParent != NULL)
	{
		Disable(hWndParent, 0);
	}

	ShowWindow(p->hWnd, SW_SHOW);

	if (p->hWnd != NULL)
	{
		MSG msg;

		while (true)
		{
			Zero(&msg, sizeof(msg));

			if (GetMessageA(&msg, NULL, 0, 0) == 0)
			{
				break;
			}

			TranslateMessage(&msg);
			DispatchMessageA(&msg);
		}
	}

	if (hWndParent != NULL)
	{
		Enable(hWndParent, 0);
		SetActiveWindow(hWndParent);
		BringWindowToTop(hWndParent);
	}

	UnregisterClassA(wndclass_name, GetModuleHandleA(NULL));

	FreeMemDC(p->BackDC);

	FreeBmp(p->Bmp);

	DeleteObject(p->LinePen);

	Free(p);
}

// GDI オブジェクトのキャッシュがまだ作成されていない場合は作成する
void InitGdiCache()
{
	if (gdi_cache.IsInited)
	{
		return;
	}

	gdi_cache.BlackBrush = GetStockObject(BLACK_BRUSH);
	gdi_cache.WhiteBrush = GetStockObject(WHITE_BRUSH);

	gdi_cache.BackgroundColor = RGB(247, 238, 255);
	gdi_cache.BackgroundColorBrush = CreateSolidBrush(gdi_cache.BackgroundColor);

	gdi_cache.ForegroundColor = RGB(0, 0, 0);
	gdi_cache.ForegroundColorBrush = CreateSolidBrush(gdi_cache.ForegroundColor);

	gdi_cache.TextBoxBackgroundColor = RGB(255, 255, 255);
	gdi_cache.TextBoxBackgroundColorBrush = CreateSolidBrush(gdi_cache.TextBoxBackgroundColor);

	gdi_cache.IsInited = true;
}

// ビットマップをリソースから読む
WINBMP *LoadBmpFromResource(UINT id)
{
	HANDLE h;
	// 引数チェック
	if (id == 0)
	{
		return NULL;
	}

	h = LoadImageA(hDll, MAKEINTRESOURCEA(id), IMAGE_BITMAP, 0, 0,
		LR_CREATEDIBSECTION | LR_VGACOLOR);

	if (h == NULL)
	{
		return NULL;
	}

	return LoadBmpMain(h);
}

// ビットマップをファイルから読む
WINBMP *LoadBmpFromFileW(wchar_t *filename)
{
	wchar_t tmp[MAX_SIZE];
	char *tmpa;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	// 一時ファイルにコピー
	tmpa = MsCreateTempFileNameByExt("bmp");

	StrToUni(tmp, sizeof(tmp), tmpa);

	Free(tmpa);

	if (FileCopyW(filename, tmp) == false)
	{
		return NULL;
	}

	return LoadBmpFromFileInnerW(tmp);
}
WINBMP *LoadBmpFromFileInnerW(wchar_t *filename)
{
	HANDLE h;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	if (MsIsNt())
	{
		h = LoadImageW(NULL, filename, IMAGE_BITMAP, 0, 0,
			LR_CREATEDIBSECTION | LR_LOADFROMFILE | LR_VGACOLOR);
	}
	else
	{
		char tmp[MAX_SIZE];

		UniToStr(tmp, sizeof(tmp), filename);

		h = LoadImageA(NULL, tmp, IMAGE_BITMAP, 0, 0,
			LR_CREATEDIBSECTION | LR_LOADFROMFILE | LR_VGACOLOR);
	}

	if (h == NULL)
	{
		return NULL;
	}

	return LoadBmpMain(h);
}
WINBMP *LoadBmpFromFileA(char *filename)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	StrToUni(tmp, sizeof(tmp), filename);

	return LoadBmpFromFileW(tmp);
}

// ビットマップ読み込みメイン
WINBMP *LoadBmpMain(void *hBitmap)
{
	WINBMP *b;
	BITMAP d;
	HDC hDC;
	// 引数チェック
	if (hBitmap == NULL)
	{
		return NULL;
	}

	Zero(&d, sizeof(d));

	if (GetObject((HANDLE)hBitmap, sizeof(d), &d) == 0)
	{
		DeleteObject((HANDLE)hBitmap);
		return NULL;
	}

	b = ZeroMalloc(sizeof(WINBMP));
	b->Bits = d.bmBitsPixel;
	b->hBitmap = hBitmap;
	b->Height = d.bmHeight;
	b->Width = d.bmWidth;

	hDC = CreateCompatibleDC(0);

	SelectObject(hDC, hBitmap);

	b->hDC = hDC;

	return b;
}

// ビットマップを解放する
void FreeBmp(WINBMP *b)
{
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	DeleteDC(b->hDC);
	DeleteObject(b->hBitmap);

	Free(b);
}

// 新しいスタイルを開始
void EnableNewStyleMode()
{
	InitGdiCache();

	new_style_mode = true;
}

// 新しいスタイルを終了
void DisableNewStyleMode()
{
	new_style_mode = false;
}

// 新しいスタイルが有効になっているかどうかチェック
bool IsNewStyleModeEnabled()
{
	return new_style_mode;
}

// NIC 情報ダイアログプロシージャ
UINT NicInfoProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_NICINFO *info = (UI_NICINFO *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		NicInfoInit(hWnd, info);

		SetTimer(hWnd, 1, 50, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			NicInfoOnTimer(hWnd, info);

			SetTimer(hWnd, 1, 50, NULL);
			break;

		case 2:
			KillTimer(hWnd, 2);
			Close(hWnd);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		KillTimer(hWnd, 1);
		KillTimer(hWnd, 2);
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}
void NicInfoCloseAfterTime(HWND hWnd, UI_NICINFO *info, UINT tick)
{
	UINT64 now;
	UINT64 closetime;
	// 引数チェック
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	now = Tick64();
	closetime = now + (UINT64)tick;

	if (info->CloseAfterTime == 0 || info->CloseAfterTime >= closetime)
	{
		info->CloseAfterTime = closetime;
		KillTimer(hWnd, 2);
		SetTimer(hWnd, 2, tick, NULL);
	}
}
void NicInfoShowStatus(HWND hWnd, UI_NICINFO *info, wchar_t *msg1, wchar_t *msg2, UINT icon, bool animate)
{
	// 引数チェック
	if (hWnd == NULL || info == NULL)
	{
		return;
	}
	if (icon == 0)
	{
		icon = ICO_TEST;
	}
	if (msg1 == NULL)
	{
		msg1 = L"";
	}
	if (msg2 == NULL)
	{
		msg2 = L"";
	}

	if (info->CurrentIcon != icon)
	{
		SetIcon(hWnd, S_ICON, icon);
		info->CurrentIcon = icon;
	}

	SetText(hWnd, S_STATUS1, msg1);
	SetText(hWnd, S_STATUS2, msg2);

	SetShow(hWnd, P_BAR, animate && MsIsWinXPOrWinVista());
}
void NicInfoRefresh(HWND hWnd, UI_NICINFO *info)
{
	MS_ADAPTER *a;
	IP ip;
	char ip_str[MAX_SIZE];
	char title[MAX_SIZE];
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool has_ip = false;
	// 引数チェック
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	Format(title, sizeof(title), VLAN_ADAPTER_NAME_TAG, info->NicName);

	a = MsGetAdapter(title);
	if (a == NULL)
	{
		Close(hWnd);
		return;
	}

	// IP アドレスが割り当てら割れているかどうかチェック
	Zero(&ip, sizeof(ip));
	for (i = 0;i < MAX_MS_ADAPTER_IP_ADDRESS;i++)
	{
		if (IsZeroIP(&a->IpAddresses[i]) == false)
		{
			Copy(&ip, &a->IpAddresses[i], sizeof(IP));

			if (!(ip.addr[0] == 169 && ip.addr[1] == 254))
			{
				has_ip = true;
			}
		}
	}
	IPToStr(ip_str, sizeof(ip_str), &ip);

	if (has_ip == false)
	{
		if (a->UseDhcp)
		{
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_1"), _UU("NICINFO_1_1"), ICO_NIC_OFFLINE, true);
		}
		else
		{
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_1"), _UU("NICINFO_1_2"), ICO_NIC_OFFLINE, true);
		}
	}
	else
	{
		if (a->UseDhcp)
		{
			UniFormat(tmp, sizeof(tmp), _UU("NICINFO_2_1"), ip_str);
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_2"), tmp, ICO_NIC_ONLINE, false);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("NICINFO_3_1"), ip_str);
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_3"), tmp, ICO_NIC_ONLINE, false);
		}

		NicInfoCloseAfterTime(hWnd, info, NICINFO_AUTOCLOSE_TIME_2);
	}

	MsFreeAdapter(a);
}
void NicInfoInit(HWND hWnd, UI_NICINFO *info)
{
	// 引数チェック
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	if (MsIsWinXPOrWinVista())
	{
		// Windows XP 以降の場合はプログレスバーを表示する
		SendMsg(hWnd, P_BAR, PBM_SETMARQUEE, TRUE, 150);
		SetStyle(hWnd, P_BAR, PBS_MARQUEE);
	}

	DlgFont(hWnd, S_STATUS1, 9, false);
	DlgFont(hWnd, S_STATUS2, 11, false);

	SetIcon(hWnd, 0, ICO_NIC_ONLINE);

	FormatText(hWnd, 0, info->NicName);

	NicInfoRefresh(hWnd, info);

	NicInfoCloseAfterTime(hWnd, info, NICINFO_AUTOCLOSE_TIME_1);
}
void NicInfoOnTimer(HWND hWnd, UI_NICINFO *info)
{
	// 引数チェック
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	if (info->Halt)
	{
		Close(hWnd);
		return;
	}

	if (info->RouteChange != NULL &&
		IsRouteChanged(info->RouteChange) == false)
	{
		return;
	}

	NicInfoRefresh(hWnd, info);
}

// NIC 情報ダイアログの表示
void NicInfo(UI_NICINFO *info)
{
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	info->RouteChange = NewRouteChange();

	DialogEx2(NULL, D_NICINFO, NicInfoProc, info, true, true);

	FreeRouteChange(info->RouteChange);
	info->RouteChange = NULL;
}

// TCP 接続スレッド
void WinConnectDlgThread(THREAD *thread, void *param)
{
	SOCK *s;
	WINCONNECT_DLG_DATA *d = (WINCONNECT_DLG_DATA *)param;
	// 引数チェック
	if (d == NULL || thread == NULL)
	{
		return;
	}

	// ソケット接続
	s = ConnectEx2(d->hostname, d->port, d->timeout, &d->cancel);

	d->ret_sock = s;

	PostMessageA(d->hWnd, WM_APP + 68, 0, 0);
}

// TCP 接続ダイアログプロシージャ
UINT WinConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINCONNECT_DLG_DATA *d = (WINCONNECT_DLG_DATA *)param;
	// 引数チェック
	if (hWnd == NULL || d == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// UI 設定
		CenterParent(hWnd);
		SetText(hWnd, 0, d->caption);
		SetText(hWnd, S_INFO, d->info);
		SetIcon(hWnd, S_ICON, d->icon_id);
		d->hWnd = hWnd;

		if (MsIsWinXPOrWinVista())
		{
			// Windows XP 以降の場合はプログレスバーを表示する
			SendMsg(hWnd, IDC_PROGRESS1, PBM_SETMARQUEE, TRUE, 100);
			SetStyle(hWnd, IDC_PROGRESS1, PBS_MARQUEE);
		}
		else
		{
			// Windows 2000 以前の場合はプログレスバーを非表示にする
			Hide(hWnd, IDC_PROGRESS1);
		}

		// スレッドの作成
		d->thread = NewThread(WinConnectDlgThread, d);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_APP + 68:
	case WM_CLOSE:
		if (d->cancel == false)
		{
			d->cancel = true;
			Disable(hWnd, IDCANCEL);
			if (d->ret_sock == NULL)
			{
				SetText(hWnd, S_INFO, _UU("CONNECTDLG_CANCELING"));
			}
			DoEvents(hWnd);
			Refresh(hWnd);
			WaitThread(d->thread, INFINITE);
			ReleaseThread(d->thread);
			EndDialog(hWnd, 0);
		}
		break;
	}

	return 0;
}

// TCP 接続を UI を表示しながら実施
SOCK *WinConnectEx2(HWND hWnd, char *server, UINT port, UINT timeout, UINT icon_id, wchar_t *caption, wchar_t *info)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	WINCONNECT_DLG_DATA d;
	// 引数チェック
	if (server == NULL || port == 0)
	{
		return NULL;
	}
	if (icon_id == 0)
	{
		icon_id = ICO_USER_ADMIN;
	}
	if (caption == NULL)
	{
		if (hWnd == NULL)
		{
			caption = _UU("CONNECTDLG_CAPTION");
		}
		else
		{
			GetTxt(hWnd, 0, tmp2, sizeof(tmp2));
			caption = tmp2;
		}
	}
	if (info == NULL)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CONNECTDLG_MESSAGE"), server, port);

		info = tmp;
	}

	Zero(&d, sizeof(d));

	d.cancel = false;
	d.caption = caption;
	d.icon_id = icon_id;
	d.info = info;
	d.timeout = timeout;
	d.hostname = server;
	d.port = port;

	Dialog(hWnd, D_CONNECT, WinConnectDlgProc, &d);

	return d.ret_sock;
}

// Windows ネットワーク設定画面の表示
bool ShowWindowsNetworkConnectionDialog()
{
	wchar_t exe_name[MAX_SIZE];
	void *proc;

	CombinePathW(exe_name, sizeof(exe_name), MsGetSystem32DirW(), L"control.exe");

	proc = Win32RunEx2W(exe_name, L"netconnections", false, NULL);

	if (proc == NULL)
	{
		return false;
	}

	Win32CloseProcess(proc);

	return true;
}

// メイリオフォントの取得
HFONT GetMeiryoFont()
{
	return GetMeiryoFontEx(0);
}
HFONT GetMeiryoFontEx(UINT font_size)
{
	// 少し適当な処理。日本語版では Meiryo, 中文版では Microsoft YaHei を使用する。
	if (_GETLANG() == 0)
	{
		return GetFont("Meiryo", font_size, false, false, false, false);
	}
	else if (_GETLANG() == 2)
	{
		return GetFont("Microsoft YaHei", font_size, false, false, false, false);
	}
	else
	{
		return GetFont(NULL, font_size, false, false, false, false);
	}
}

// メイリオフォントに設定
void SetFontMeiryo(HWND hWnd, UINT id)
{
	SetFont(hWnd, id, GetMeiryoFont());
}

// デフォルトフォントに設定
void SetFontDefault(HWND hWnd, UINT id)
{
	SetFont(hWnd, id, GetDialogDefaultFont());
}

// 悪いプロセスに関する警告メッセージの表示
void ShowBadProcessWarning(HWND hWnd, BAD_PROCESS *bad)
{
	wchar_t title[MAX_SIZE];
	wchar_t message[8192];
	// 引数チェック
	if (bad == NULL)
	{
		return;
	}

	UniFormat(title, sizeof(title), _UU("BAD_PROCESS_TITLE"), bad->Title);
	UniFormat(message, sizeof(message), _UU("BAD_PROCESS_MESSAGE"),
		bad->Title, bad->Title, bad->Title, bad->Title);

	OnceMsg(hWnd, title, message, true, ICO_WARNING);
}

// 競合するアンチウイルスソフトの一覧を検索し、該当するものがあれば表示する
bool CheckBadProcesses(HWND hWnd)
{
	bool ret = true;
	UINT i;
	LIST *o;

	o = MsGetProcessList();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		char exe[MAX_PATH];
		BAD_PROCESS *bad;

		GetFileNameFromFilePath(exe, sizeof(exe), p->ExeFilename);

		bad = IsBadProcess(exe);

		if (bad != NULL)
		{
			// 悪いプロセスを発見したのでメッセージを表示する
			ret = false;

			ShowBadProcessWarning(hWnd, bad);
		}
	}

	MsFreeProcessList(o);

	return ret;
}

// 指定したプロセス名が悪いプロセスに該当するかどうか検索する
BAD_PROCESS *IsBadProcess(char *exe)
{
	UINT i;
	// 引数チェック
	if (exe == NULL)
	{
		return NULL;
	}

	for (i = 0;i < num_bad_processes;i++)
	{
		BAD_PROCESS *bad = &bad_processes[i];

		if (StrCmpi(bad->ExeName, exe) == 0)
		{
			return bad;
		}
	}

	return NULL;
}

// メッセージ表示プロシージャ
UINT OnceMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	ONCEMSG_DLG *d = (ONCEMSG_DLG *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetText(hWnd, 0, d->Title);
		SetText(hWnd, E_TEXT, d->Message);
		SetShow(hWnd, C_DONTSHOWAGAIN, d->ShowCheckbox);
		//DisableClose(hWnd);
		Focus(hWnd, IDCANCEL);
		if (d->Icon != 0)
		{
			SetIcon(hWnd, 0, d->Icon);
		}

		if (MsIsVista())
		{
			SetFont(hWnd, E_TEXT, GetMeiryoFont());
		}
		else
		{
			DlgFont(hWnd, E_TEXT, 11, false);
		}

		SetTimer(hWnd, 1, 50, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (*d->halt)
			{
				Close(hWnd);
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		KillTimer(hWnd, 1);
		d->Checked = IsChecked(hWnd, C_DONTSHOWAGAIN);
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// メッセージを表示する
void OnceMsg(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon)
{
	OnceMsgEx(hWnd, title, message, show_checkbox, icon, NULL);
}
void OnceMsgEx(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon, bool *halt)
{
	ONCEMSG_DLG d;
	UINT hash;
	char valuename[MAX_PATH];
	bool b_dummy = false;
	// 引数チェック
	if (title == NULL)
	{
		title = title_bar;
	}
	if (message == NULL)
	{
		message = L"message";
	}
	if (halt == NULL)
	{
		halt = &b_dummy;
	}

	Zero(&d, sizeof(d));
	d.Message = message;
	d.Title = title;
	d.ShowCheckbox = show_checkbox;
	d.Icon = icon;
	d.halt = halt;

	hash = GetOnceMsgHash(title, message);
	Format(valuename, sizeof(valuename), ONCE_MSG_REGVALUE, hash);

	if (MsRegReadInt(REG_CURRENT_USER, ONCE_MSG_REGKEY, valuename) == 0)
	{
		switch (icon)
		{
		case ICO_WARNING:
			MessageBeep(MB_ICONEXCLAMATION);
			break;

		case ICO_INFORMATION:
			MessageBeep(MB_ICONASTERISK);
			break;
		}

		Dialog(hWnd, D_ONCEMSG, OnceMsgProc, &d);

		if (show_checkbox)
		{
			if (d.Checked)
			{
				MsRegWriteInt(REG_CURRENT_USER, ONCE_MSG_REGKEY, valuename, 1);
			}
		}
	}
}

// メッセージハッシュの取得
UINT GetOnceMsgHash(wchar_t *title, wchar_t *message)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	UINT ret;
	// 引数チェック
	if (title == NULL)
	{
		title = title_bar;
	}
	if (message == NULL)
	{
		message = L"message";
	}

	b = NewBuf();
	WriteBuf(b, title, UniStrSize(title));
	WriteBuf(b, message, UniStrSize(message));
	HashSha1(hash, b->Buf, b->Size);
	FreeBuf(b);

	Copy(&ret, hash, sizeof(UINT));

	return ret;
}

// Windows Vista のテーマを設定する
void InitVistaWindowTheme(HWND hWnd)
{
	static HINSTANCE hInstDll = NULL;
	HRESULT (WINAPI *_SetWindowTheme)(HWND, LPCWSTR, LPCWSTR) = NULL;

	if (MsIsVista() == false)
	{
		return;
	}

	if (hInstDll == NULL)
	{
		hInstDll = LoadLibraryA("uxtheme.dll");
	}

	if (hInstDll == NULL)
	{
		return;
	}

	if (_SetWindowTheme == NULL)
	{
		_SetWindowTheme = (HRESULT (WINAPI *)(HWND,LPCWSTR,LPCWSTR))GetProcAddress(hInstDll, "SetWindowTheme");
	}

	if (_SetWindowTheme == NULL)
	{
		return;
	}

	_SetWindowTheme(hWnd, L"explorer", NULL);
}

// 現在のディレクトリに存在する可能性のある Windows ファイアウォールに登録すべき
// すべてのアプリケーションを登録する
// Q. 行儀が悪いのではないか?
// A. 確かに行儀が悪いが、Windows Firewall でブロックされていることが原因で
//    VPN ソフトウェアが使用できないという苦情メールがよく来ていたので
//    やむを得ずこのように行うことにした。
//    なお、Microsoft 純正のサーバーソフトや他社のサーバーソフト等もこのように
//    して対応しているようであるから、良いのではないか。
void RegistWindowsFirewallAll()
{
	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_STR, "utvpnclient.exe");
	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_STR, "utvpnclient_x64.exe");
	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_STR, "utvpnclient_ia64.exe");

	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_MANAGER_STR, "utvpncmgr.exe");
	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_MANAGER_STR, "utvpncmgr_x64.exe");
	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_MANAGER_STR, "utvpncmgr_ia64.exe");

	MsRegistWindowsFirewallEx2(CEDAR_SERVER_STR, "utvpnserver.exe");
	MsRegistWindowsFirewallEx2(CEDAR_SERVER_STR, "utvpnserver_x64.exe");
	MsRegistWindowsFirewallEx2(CEDAR_SERVER_STR, "utvpnserver_ia64.exe");

	MsRegistWindowsFirewallEx2(CEDAR_CUI_STR, "utvpncmd.exe");
	MsRegistWindowsFirewallEx2(CEDAR_CUI_STR, "utvpncmd_x64.exe");
	MsRegistWindowsFirewallEx2(CEDAR_CUI_STR, "utvpncmd_ia64.exe");

	MsRegistWindowsFirewallEx2(CEDAR_PRODUCT_STR, "ham.exe");
	MsRegistWindowsFirewallEx2(CEDAR_PRODUCT_STR, "ham_x64.exe");
	MsRegistWindowsFirewallEx2(CEDAR_PRODUCT_STR, "ham_ia64.exe");
}

// すでに通知サービスが動作しているかどうかチェックする
bool Win32CnCheckAlreadyExists(bool lock)
{
	char tmp[MAX_SIZE];
	HANDLE hMutex;

	HashInstanceNameLocal(tmp, sizeof(tmp), CLIENT_NOTIFY_SERVICE_INSTANCENAME);

	hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, tmp);
	if (hMutex != NULL)
	{
		CloseHandle(hMutex);
		return true;
	}

	if (lock == false)
	{
		return false;
	}

	hMutex = CreateMutex(NULL, FALSE, tmp);
	if (hMutex == NULL)
	{
		CloseHandle(hMutex);
		return true;
	}

	return false;
}

// hamcore 内の EXE の実行
bool ExecuteHamcoreExe(char *name)
{
	BUF *b;
	wchar_t tmp[MAX_PATH];
	char tmp2[MAX_PATH];
	UCHAR hash[MD5_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	b = ReadDump(name);
	if (b == NULL)
	{
		return false;
	}

	Hash(hash, name, StrLen(name), false);
	BinToStr(tmp2, sizeof(tmp2), hash, sizeof(hash));
	UniFormat(tmp, sizeof(tmp), L"%s\\tmp_%S.exe", MsGetMyTempDirW(), tmp2);
	SeekBuf(b, 0, 0);
	DumpBufW(b, tmp);

	FreeBuf(b);

	return RunW(tmp, NULL, false, false);
}

// イースターエッグの表示
void ShowEasterEgg(HWND hWnd)
{
}

void KakushiThread(THREAD *thread, void *param)
{
	KAKUSHI *k;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	k = (KAKUSHI *)param;

	k->Thread = thread;
	AddRef(k->Thread->ref);
	NoticeThreadInit(thread);

	Dialog(NULL, D_CM_KAKUSHI, KakushiDlgProc, k);
	k->hWnd = NULL;
}

KAKUSHI *InitKakushi()
{
	THREAD *t;
	KAKUSHI *k = ZeroMalloc(sizeof(KAKUSHI));

	t = NewThread(KakushiThread, k);

	WaitThreadInit(t);
	ReleaseThread(t);

	return k;
}

UINT KakushiDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	KAKUSHI *k = (KAKUSHI *)param;
	UINT64 now;
	bool b;
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetText(hWnd, S_INFO, _UU("CM_VLAN_CREATING"));

		b = false;

		if (MsIsVista())
		{
			if (_GETLANG() == 0)
			{
				SetFont(hWnd, S_INFO, GetFont("Meiryo", 11, false, false, false, false));
				b = true;
			}
			else if (_GETLANG() == 2)
			{
				SetFont(hWnd, S_INFO, GetFont("Microsoft YaHei", 11, false, false, false, false));
				b = true;
			}
		}

		if (b == false)
		{
			DlgFont(hWnd, S_INFO, 11, false);
		}

		SetTimer(hWnd, 1, 50, NULL);
		k->hWnd = hWnd;

		k->Span = 20 * 1000;
		k->StartTick = Tick64();

		SetRange(hWnd, P_PROGRESS, 0, (UINT)k->Span);

	case WM_APP + 9821:
		now = Tick64();

		if (((k->StartTick + k->Span) <= now) || k->Halt)
		{
			EndDialog(hWnd, 0);
			break;
		}

		SetPos(hWnd, P_PROGRESS, (UINT)(now - k->StartTick));
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			AllowSetForegroundWindow(ASFW_ANY);
			SetForegroundWindow(hWnd);
			SetActiveWindow(hWnd);

			now = Tick64();

			if (((k->StartTick + k->Span) <= now) || k->Halt)
			{
				EndDialog(hWnd, 0);
				break;
			}

			SetPos(hWnd, P_PROGRESS, (UINT)(now - k->StartTick));
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// 隠し画面解放
void FreeKakushi(KAKUSHI *k)
{
	// 引数チェック
	if (k == NULL)
	{
		return;
	}

	k->Halt = true;

	if (k->hWnd != NULL)
	{
		PostMessage(k->hWnd, WM_APP + 9821, 0, 0);
	}

	WaitThread(k->Thread, INFINITE);
	ReleaseThread(k->Thread);

	Free(k);
}

// TCP/IP 最適化選択ダイアログプロシージャ
UINT TcpMsgDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SETUP);
		//DlgFont(hWnd, R_OPTIMIZE, 0, true);

		Check(hWnd, R_NO, true);

		if (g_tcpip_topmost)
		{
			Top(hWnd);
		}

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			ret = 1;
			if (IsChecked(hWnd, R_MANUAL))
			{
				ret = 2;
			}
			else if (IsChecked(hWnd, R_NO))
			{
				ret = 0;
			}

			EndDialog(hWnd, ret);
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// ダイアログ初期化
void TcpIpDlgInit(HWND hWnd)
{
	MS_TCP tcp;

	SetIcon(hWnd, 0, ICO_SETUP);

	MsGetTcpConfig(&tcp);

	Check(hWnd, R_RECV_DISABLE, tcp.RecvWindowSize == 0);
	Check(hWnd, R_RECV_ENABLE, tcp.RecvWindowSize != 0);
	SetInt(hWnd, E_RECV, tcp.RecvWindowSize != 0 ? tcp.RecvWindowSize : DEFAULT_TCP_MAX_WINDOW_SIZE_RECV);

	Check(hWnd, R_SEND_DISABLE, tcp.SendWindowSize == 0);
	Check(hWnd, R_SEND_ENABLE, tcp.SendWindowSize != 0);
	SetInt(hWnd, E_SEND, tcp.SendWindowSize != 0 ? tcp.SendWindowSize : DEFAULT_TCP_MAX_WINDOW_SIZE_SEND);

	TcpIpDlgUpdate(hWnd);
}

// ダイアログ更新
void TcpIpDlgUpdate(HWND hWnd)
{
	bool ok = true;

	SetEnable(hWnd, E_RECV, IsChecked(hWnd, R_RECV_ENABLE));
	SetEnable(hWnd, S_RECV, IsChecked(hWnd, R_RECV_ENABLE));
	SetEnable(hWnd, E_SEND, IsChecked(hWnd, R_SEND_ENABLE));
	SetEnable(hWnd, S_SEND, IsChecked(hWnd, R_SEND_ENABLE));

	if (IsChecked(hWnd, R_RECV_ENABLE) && GetInt(hWnd, E_RECV) < 1454)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_SEND_ENABLE) && GetInt(hWnd, E_SEND) < 1454)
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// TCP/IP ダイアログプロシージャ
UINT TcpIpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	MS_TCP tcp, old;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		TcpIpDlgInit(hWnd);

		if (g_tcpip_topmost)
		{
			Top(hWnd);
		}

		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_RECV_DISABLE:
		case R_RECV_ENABLE:
		case R_SEND_DISABLE:
		case R_SEND_ENABLE:
		case E_RECV:
		case E_SEND:
			TcpIpDlgUpdate(hWnd);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			Zero(&tcp, sizeof(tcp));

			if (IsChecked(hWnd, R_RECV_ENABLE))
			{
				tcp.RecvWindowSize = GetInt(hWnd, E_RECV);
			}

			if (IsChecked(hWnd, R_SEND_ENABLE))
			{
				tcp.SendWindowSize = GetInt(hWnd, E_SEND);
			}

			MsGetTcpConfig(&old);

			MsSetTcpConfig(&tcp);
			MsSaveTcpConfigReg(&tcp);

			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_RECV_ENABLE:
			FocusEx(hWnd, E_RECV);
			break;

		case R_SEND_ENABLE:
			FocusEx(hWnd, E_SEND);
			break;

		case B_RECV:
			SetInt(hWnd, E_RECV, DEFAULT_TCP_MAX_WINDOW_SIZE_RECV);
			Check(hWnd, R_RECV_DISABLE, false);
			Check(hWnd, R_RECV_ENABLE, true);
			TcpIpDlgUpdate(hWnd);
			FocusEx(hWnd, E_RECV);
			break;

		case B_SEND:
			SetInt(hWnd, E_SEND, DEFAULT_TCP_MAX_WINDOW_SIZE_SEND);
			Check(hWnd, R_SEND_DISABLE, false);
			Check(hWnd, R_SEND_ENABLE, true);
			TcpIpDlgUpdate(hWnd);
			FocusEx(hWnd, E_SEND);
			break;

		case B_DELETE:
			Zero(&tcp, sizeof(tcp));
			MsSetTcpConfig(&tcp);
			MsDeleteTcpConfigReg();
			EndDialog(hWnd, 0);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 64 bit に関する警告ダイアログ
UINT Cpu64DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_WARNING);
		DlgFont(hWnd, S_BOLD, 9, true);
		SetTimer(hWnd, 1, 30 * 1000, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			Command(hWnd, IDOK);
			break;
		}

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// 64 bit に関する警告ダイアログの表示
void ShowCpu64Warning()
{
	Dialog(NULL, D_CPU64_WARNING, Cpu64DlgProc, NULL);
}

// TCP/IP 設定ユーティリティの表示
void ShowTcpIpConfigUtil(HWND hWnd, bool util_mode)
{
	if (MsIsTcpConfigSupported() == false)
	{
		if (util_mode)
		{
			// 現在の OS ではサポートされていない旨のメッセージを表示
			if (MsIsAdmin() == false)
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("TCPOPT_NOT_ADMIN"));
			}
			else
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("TCPOPT_NOT_SUPPORTED"));
			}
		}
		return;
	}

	if (util_mode == false)
	{
		// utvpncmd を起動してすぐに終了する
		wchar_t tmp[MAX_PATH];
		wchar_t exedir[MAX_PATH];
		HANDLE h;

		GetExeDirW(exedir, sizeof(exedir));

		if (IsX64())
		{
			UniFormat(tmp, sizeof(tmp), L"%s\\utvpncmd_x64.exe", exedir);
		}
		else if (IsIA64())
		{
			UniFormat(tmp, sizeof(tmp), L"%s\\utvpncmd_ia64.exe", exedir);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), L"%s\\utvpncmd.exe", exedir);
		}

		if (IsFileW(tmp))
		{
			RunW(tmp, L"/tool /cmd:exit", true, false);
		}

		// netsh によるタスクオフローディングの無効化
		if (MsIsVista())
		{
			char netsh_exe[MAX_SIZE];
			DIRLIST *dl;
			UINT i;
			bool b = false;

			dl = EnumDirW(exedir);

			for (i = 0;i < dl->NumFiles;i++)
			{
				if (UniInStr(dl->File[i]->FileNameW, L"utvpnbridge") || 
					UniInStr(dl->File[i]->FileNameW, L"utvpnserver"))
				{
					b = true;
				}
			}

			FreeDir(dl);

			if (b)
			{
				CombinePath(netsh_exe, sizeof(netsh_exe), MsGetSystem32Dir(), "netsh.exe");

				Run(netsh_exe, "netsh int ipv6 set global taskoffload=disabled", true, false);
				Run(netsh_exe, "netsh int ipv4 set global taskoffload=disabled", true, false);
			}
		}

		// Windows Firewall 登録
		RegistWindowsFirewallAll();

		SleepThread(1000);

		// utvpnclient.exe /uihelp の起動
		h = CmExecUiHelperMain();
		if (h != NULL)
		{
			CloseHandle(h);
		}

		if (Is64() == false)
		{
			if (MsIs64BitWindows())
			{
				// 32 bit 版を 64 bit Windows 上で使用している場合は
				// 警告メッセージを表示する
				ShowCpu64Warning();
			}
		}

		if (MsIsAdmin())
		{
			if (MsIsVista())
			{
				// Windows Vista でインストールする場合は
				// MMCSS のネットワーク制限を解除する
				if (MsIsMMCSSNetworkThrottlingEnabled())
				{
					MsSetMMCSSNetworkThrottlingEnable(false);
				}
			}
		}
	}

	if (util_mode == false && MsIsShouldShowTcpConfigApp() == false)
	{
		return;
	}

	if (util_mode == false)
	{
		// 2006.07.04 nobori
		// インストーラ上では TCP/IP 最適化ユーティリティは表示しないことにした
		return;
	}

	g_tcpip_topmost = util_mode ? false : true;

	if (util_mode == false)
	{
		UINT ret = Dialog(hWnd, D_TCP_MSG, TcpMsgDlgProc, NULL);

		if (ret == 0)
		{
			MS_TCP tcp;

			Zero(&tcp, sizeof(tcp));
			MsGetTcpConfig(&tcp);
			MsSaveTcpConfigReg(&tcp);
			return;
		}
		else if (ret == 1)
		{
			MS_TCP tcp;

			Zero(&tcp, sizeof(tcp));

			tcp.RecvWindowSize = DEFAULT_TCP_MAX_WINDOW_SIZE_RECV;
			tcp.SendWindowSize = DEFAULT_TCP_MAX_WINDOW_SIZE_SEND;
			MsSetTcpConfig(&tcp);
			MsSaveTcpConfigReg(&tcp);

			return;
		}
	}

	Dialog(hWnd, D_TCP, TcpIpDlgProc, NULL);
}

// メニューの国際化対応処理を行う (Unicode)
void InitMenuInternationalUni(HMENU hMenu, char *prefix)
{
	UINT i, num;
	// 引数チェック
	if (hMenu == NULL || prefix == NULL)
	{
		return;
	}

	// メニューの項目数を取得する
	num = GetMenuItemCount(hMenu);

	// メニューを列挙する
	for (i = 0;i < num;i++)
	{
		HMENU hSubMenu = GetSubMenu(hMenu, i);
		MENUITEMINFOW info;
		wchar_t tmp[MAX_SIZE];

		if (hSubMenu != NULL)
		{
			// サブメニューがある場合再帰呼び出しする
			InitMenuInternational(hSubMenu, prefix);
		}

		// メニュー項目を取得する
		Zero(&info, sizeof(info));
		info.cbSize = sizeof(info);
		info.cch = sizeof(tmp);
		info.dwTypeData = tmp;
		info.fMask = MIIM_STRING;
		Zero(tmp, sizeof(tmp));

		if (GetMenuItemInfoW(hMenu, i, true, &info))
		{
			if (tmp[0] == L'@')
			{
				char name[256];
				wchar_t *ret;

				Format(name, sizeof(name), "%s@%S", prefix, &tmp[1]);

				ret = _UU(name);
				if (UniIsEmptyStr(ret) == false)
				{
					UniStrCpy(tmp, sizeof(tmp), ret);
					info.cch = UniStrLen(tmp);

					SetMenuItemInfoW(hMenu, i, true, &info);
				}
			}
		}
	}
}

// メニューの国際化対応処理を行う
void InitMenuInternational(HMENU hMenu, char *prefix)
{
	UINT i, num;
	// 引数チェック
	if (hMenu == NULL || prefix == NULL)
	{
		return;
	}

	if (MsIsNt())
	{
		InitMenuInternationalUni(hMenu, prefix);
		return;
	}

	// メニューの項目数を取得する
	num = GetMenuItemCount(hMenu);

	// メニューを列挙する
	for (i = 0;i < num;i++)
	{
		HMENU hSubMenu = GetSubMenu(hMenu, i);
		MENUITEMINFO info;
		char tmp[MAX_SIZE];

		if (hSubMenu != NULL)
		{
			// サブメニューがある場合再帰呼び出しする
			InitMenuInternational(hSubMenu, prefix);
		}

		// メニュー項目を取得する
		Zero(&info, sizeof(info));
		info.cbSize = sizeof(info);
		info.cch = sizeof(tmp);
		info.dwTypeData = tmp;
		info.fMask = MIIM_STRING;
		Zero(tmp, sizeof(tmp));

		if (GetMenuItemInfo(hMenu, i, true, &info))
		{
			if (tmp[0] == '@')
			{
				char name[256];
				char *ret;

				Format(name, sizeof(name), "%s@%s", prefix, &tmp[1]);

				ret = _SS(name);
				if (IsEmptyStr(ret) == false)
				{
					StrCpy(tmp, sizeof(tmp), ret);
					info.cch = StrLen(tmp);

					SetMenuItemInfo(hMenu, i, true, &info);
				}
			}
		}
	}
}

// ダイアログボックス用のデフォルトのフォントを取得する
HFONT GetDialogDefaultFont()
{
	return GetDialogDefaultFontEx(false);
}
HFONT GetDialogDefaultFontEx(bool meiryo)
{
	char *default_font_name = _SS("DEFAULT_FONT");
	UINT default_font_size = _II("DEFAULT_FONT_SIZE");

	if (meiryo)
	{
		if (_GETLANG() == 2)
		{
			default_font_name = "Microsoft YaHei";
		}
		else
		{
			default_font_name = "Meiryo";
		}
	}

	if (IsEmptyStr(default_font_name))
	{
		default_font_name = font_name;
	}

	if (default_font_size == 0)
	{
		default_font_size = 9;
	}

	return GetFont(default_font_name, default_font_size, false, false, false, false);
}

// ウインドウサイズとコントロールサイズを調整する
void AdjustWindowAndControlSize(HWND hWnd)
{
	HFONT hDlgFont;
	UINT dlgfont_x, dlgfont_y;
	RECT rect, rect2;
	LIST *o;
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	// 現在のウインドウのフォントを取得する
	hDlgFont = (HFONT)SendMsg(hWnd, 0, WM_GETFONT, 0, 0);

	// 現在のウインドウのフォントの幅と高さを取得する
	CalcFontSize(hDlgFont, &dlgfont_x, &dlgfont_y);

	if ((dlgfont_x == WINUI_DEFAULT_DIALOG_UNIT_X) &&
		(dlgfont_y == WINUI_DEFAULT_DIALOG_UNIT_Y))
	{
		// 調整する必要が無い
		return;
	}

	// ウインドウのサイズを調整する
	if (GetWindowRect(hWnd, &rect))
	{
		if (GetClientRect(hWnd, &rect2))
		{
			UINT width = rect2.right - rect2.left;
			UINT height = rect2.bottom - rect2.top;

			AdjustDialogXY(&width, &height, dlgfont_x, dlgfont_y);

			width += (rect.right - rect.left) - (rect2.right - rect2.left);
			height += (rect.bottom - rect.top) - (rect2.bottom - rect2.top);

			if (true)
			{
				HWND hParent = GetParent(hWnd);

				if (hParent != NULL)
				{
					RECT r;

					Zero(&r, sizeof(r));

					if (GetWindowRect(hParent, &r))
					{
						RECT r2;

						rect.top = r.top + GetSystemMetrics(SM_CYCAPTION);

						Zero(&r2, sizeof(r2));
						if (SystemParametersInfo(SPI_GETWORKAREA, 0, &r2, 0))
						{
							if (r2.bottom < (rect.top + (int)height))
							{
								rect.top -= (rect.top + (int)height) - r2.bottom;

								if (rect.top < 0)
								{
									rect.top = 0;
								}
							}
						}
					}
				}
			}

			MoveWindow(hWnd, rect.left, rect.top, width, height, false);
		}
	}

	// 子ウインドウを列挙する
	o = EnumAllChildWindowEx(hWnd, false, true, true);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		// 子ウインドウのサイズを調整する
		HWND h = *((HWND *)LIST_DATA(o, i));
		HWND hWndParent = GetParent(h);
		RECT current_rect;
		char class_name[MAX_PATH];
		bool is_image = false;

		// クラス名を取得
		Zero(class_name, sizeof(class_name));
		GetClassNameA(h, class_name, sizeof(class_name));

		if (StrCmpi(class_name, "static") == 0)
		{
			if (SendMsg(h, 0, STM_GETIMAGE, IMAGE_BITMAP, 0) != 0 ||
				SendMsg(h, 0, STM_GETIMAGE, IMAGE_ICON, 0) != 0 ||
				SendMsg(h, 0, STM_GETICON, 0, 0) != 0)
			{
				is_image = true;
			}
		}

		// 位置を取得
		if (GetWindowRect(h, &current_rect))
		{
			// クライアント座標に変換
			POINT p1, p2;

			p1.x = current_rect.left;
			p1.y = current_rect.top;

			p2.x = current_rect.right;
			p2.y = current_rect.bottom;

			ScreenToClient(hWndParent, &p1);
			ScreenToClient(hWndParent, &p2);

			// 位置を調整
			AdjustDialogXY(&p1.x, &p1.y, dlgfont_x, dlgfont_y);
			AdjustDialogXY(&p2.x, &p2.y, dlgfont_x, dlgfont_y);

			if (is_image)
			{
				p2.x = p1.x + (current_rect.right - current_rect.left);
				p2.y = p1.y + (current_rect.bottom - current_rect.top);
			}

			// 移動
			MoveWindow(h, p1.x, p1.y, p2.x - p1.x, p2.y - p1.y, false);
		}
	}

	FreeWindowList(o);
}

// x と y の値をフォントに応じて調整する
void AdjustDialogXY(UINT *x, UINT *y, UINT dlgfont_x, UINT dlgfont_y)
{
	if (x != NULL)
	{
		*x = (UINT)(((double)*x) * (double)WINUI_DEFAULT_DIALOG_UNIT_X / (double)dlgfont_x);
	}

	if (y != NULL)
	{
		*y = (UINT)(((double)*y) * (double)WINUI_DEFAULT_DIALOG_UNIT_Y / (double)dlgfont_y);
	}
}

// ダイアログボックスの国際化対応処理を行う
void InitDialogInternational(HWND hWnd, void *param)
{
	LIST *o;
	UINT i;
	bool is_managed_dialog = false;
	char caption[MAX_PATH];
	char *dialog_name;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	AdjustWindowAndControlSize(hWnd);

	GetTxtA(hWnd, 0, caption, sizeof(caption));
	if (caption[0] == '@')
	{
		dialog_name = &caption[1];

		is_managed_dialog = true;
	}

	// すべてのウインドウハンドルを列挙する
	o = EnumAllChildWindow(hWnd);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND hControl = *((HWND *)LIST_DATA(o, i));

		if (hControl != NULL)
		{
			HFONT hFont = GetDialogDefaultFontEx(param && ((DIALOG_PARAM *)param)->meiryo);

			SetFont(hControl, 0, hFont);

			if (MsIsVista())
			{
				char classname[MAX_PATH];
				GetClassNameA(hControl, classname, sizeof(classname));

				if (StrCmpi(classname, "syslistview32") == 0)
				{
					InitVistaWindowTheme(hControl);
				}
			}

			if (is_managed_dialog)
			{
				char str[MAX_PATH];

				GetTxtA(hControl, 0, str, sizeof(str));
				if (str[0] == '@')
				{
					char *control_name = &str[1];
					char tmp[MAX_PATH];
					wchar_t *ret;

					StrCpy(tmp, sizeof(tmp), dialog_name);
					StrCat(tmp, sizeof(tmp), "@");

					if (hWnd == hControl)
					{
						StrCat(tmp, sizeof(tmp), "CAPTION");
					}
					else
					{
						StrCat(tmp, sizeof(tmp), control_name);
					}

					ret = _UU(tmp);

					if (ret != NULL && UniIsEmptyStr(ret) == false)
					{
						SetText(hControl, 0, ret);
					}
				}
			}
		}
	}

	FreeWindowList(o);
}

// 子ウインドウ列挙プロシージャ
// ダイアログ初期化
void StringDlgInit(HWND hWnd, STRING_DLG *s)
{
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetText(hWnd, E_STRING, s->String);

	SetIcon(hWnd, S_ICON, s->Icon);
	SetText(hWnd, S_INFO, s->Info);
	SetText(hWnd, 0, s->Title);

	FocusEx(hWnd, E_STRING);

	StringDlgUpdate(hWnd, s);
}

// ダイアログコントロール更新
void StringDlgUpdate(HWND hWnd, STRING_DLG *s)
{
	wchar_t *tmp;
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	tmp = GetText(hWnd, E_STRING);

	if (tmp != NULL)
	{
		if (s->AllowEmpty == false)
		{
			if (UniIsEmptyStr(tmp))
			{
				b = false;
			}
		}

		if (s->AllowUnsafe == false)
		{
			if (IsSafeUniStr(tmp) == false)
			{
				b = false;
			}
		}

		Free(tmp);
	}

	SetEnable(hWnd, IDOK, b);
}

// 文字列ダイアログプロシージャ
UINT StringDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	STRING_DLG *s = (STRING_DLG *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		StringDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_STRING:
			StringDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			GetTxt(hWnd, E_STRING, s->String, sizeof(s->String));
			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 文字列ダイアログを表示する
wchar_t *StringDlg(HWND hWnd, wchar_t *title, wchar_t *info, wchar_t *def, UINT icon, bool allow_empty, bool allow_unsafe)
{
	STRING_DLG s;
	// 引数チェック
	if (title == NULL)
	{
		title = _UU("DLG_STRING_DEFTITLE");
	}
	if (info == NULL)
	{
		info = _UU("DLG_STRING_DEFINFO");
	}
	if (def == NULL)
	{
		def = L"";
	}
	if (icon == 0)
	{
		icon = ICO_NULL;
	}

	Zero(&s, sizeof(s));
	s.Icon = icon;
	s.Info = info;
	s.Title = title;
	s.Icon = icon;
	UniStrCpy(s.String, sizeof(s.String), def);
	s.AllowEmpty = allow_empty;
	s.AllowUnsafe = allow_unsafe;

	if (Dialog(hWnd, D_STRING, StringDlgProc, &s) == false)
	{
		return NULL;
	}
	else
	{
		return CopyUniStr(s.String);
	}
}
char *StringDlgA(HWND hWnd, wchar_t *title, wchar_t *info, char *def, UINT icon, bool allow_empty, bool allow_unsafe)
{
	wchar_t unidef[MAX_SIZE];
	wchar_t *tmp;
	char *ret;
	if (def == NULL)
	{
		def = "";
	}

	StrToUni(unidef, sizeof(unidef), def);

	tmp = StringDlg(hWnd, title, info, unidef, icon, allow_empty, allow_unsafe);
	if (tmp == NULL)
	{
		return NULL;
	}

	ret = CopyUniToStr(tmp);
	Free(tmp);

	return ret;
}

// 再起動ダイアログ
UINT Win9xRebootDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WIN9X_REBOOT_DLG *d = (WIN9X_REBOOT_DLG *)param;
	UINT64 now;
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		d->StartTime = Tick64();
		SetRange(hWnd, P_PROGRESS, 0, d->TotalTime);
		SetTimer(hWnd, 1, 100, NULL);
		goto UPDATE;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
UPDATE:
			now = Tick64();
			if ((d->StartTime + (UINT64)d->TotalTime) <= now)
			{
				KillTimer(hWnd, 1);
				UniStrCpy(tmp, sizeof(tmp), _UU("DLG_REBOOT_INFO_2"));
				SetText(hWnd, S_INFO, tmp);
				if (MsShutdown(true, false) == false)
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_REBOOT_ERROR"));
				}
				EndDialog(hWnd, 0);
			}
			else
			{
				SetPos(hWnd, P_PROGRESS, (UINT)(now - d->StartTime));
				UniFormat(tmp, sizeof(tmp), _UU("DLG_REBOOT_INFO"),
					(UINT)((UINT64)d->TotalTime - (now - d->StartTime)) / 1000 + 1);
				SetText(hWnd, S_INFO, tmp);
			}

			break;
		}
		break;
	}
	return 0;
}

// 再起動用スレッド
void Win9xRebootThread(THREAD *t, void *p)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Win9xReboot(NULL);
}

// 自動的に再起動する
void Win9xReboot(HWND hWnd)
{
	WIN9X_REBOOT_DLG d;

	Zero(&d, sizeof(d));
	d.TotalTime = 10 * 1000;

	Dialog(hWnd, D_WIN9X_REBOOT, Win9xRebootDlgProc, &d);
}

// バージョン情報の初期化
void AboutDlgInit(HWND hWnd, WINUI_ABOUT *a)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("ABOUT_CAPTION"), a->ProductName);
	SetText(hWnd, 0, tmp);

	SetFont(hWnd, S_VERSION, GetFont(NULL, 15, true, false, false, false));

	SetTextA(hWnd, S_VERSION, a->ProductName);

	SetFont(hWnd, S_VERSION2, GetFont("Verdana", 13, false, false, false, false));
	UniFormat(tmp, sizeof(tmp),
		L"Version %u.%02u Build %u ",
		a->Cedar->Version / 100, a->Cedar->Version % 100,
		a->Cedar->Build);
	SetText(hWnd, S_VERSION2, tmp);

	SetFont(hWnd, S_BUILD, GetFont("Verdana", 11, false, false, true, false));
	SetTextA(hWnd, S_BUILD, a->Cedar->BuildInfo);

	SendMsg(hWnd, S_LOGO, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)LoadBitmap(hDll, MAKEINTRESOURCE(a->Bitmap)));
}

// バージョン情報プロシージャ
UINT AboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINUI_ABOUT *a = (WINUI_ABOUT *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		AboutDlgInit(hWnd, a);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			if ((GetKeyState(VK_SHIFT) & 0x8000) &&
				(GetKeyState(VK_CONTROL) & 0x8000) &&
				(GetKeyState(VK_MENU) & 0x8000))
			{
				ShowEasterEgg(hWnd);
			}
			EndDialog(hWnd, true);
			break;
		case B_WEB:
			ShellExecute(hWnd, "open", _SS("SE_COMPANY_URL"), NULL, NULL, SW_SHOW);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// バージョン情報 (古い形式)
void About(HWND hWnd, CEDAR *cedar, char *product_name, UINT bitmap)
{
	WINUI_ABOUT a;
	// 引数チェック
	if (cedar == NULL || product_name == NULL || bitmap == 0)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.Bitmap = bitmap;
	a.Cedar = cedar;
	a.ProductName = product_name;

	Dialog(hWnd, D_ABOUT, AboutDlgProc, &a);
}

// テスト
void UiTest()
{
}

// IP アドレスが入力されているフィルード数を調べる
UINT IpGetFilledNum(HWND hWnd, UINT id)
{
	UINT ret;
	DWORD value;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	ret = SendMsg(hWnd, id, IPM_GETADDRESS, 0, (LPARAM)&value);

	return ret;
}

// IP アドレスが入力されているかどうか調べる
bool IpIsFilled(HWND hWnd, UINT id)
{
	UINT ret;
	DWORD value;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	ret = SendMsg(hWnd, id, IPM_GETADDRESS, 0, (LPARAM)&value);

	if (ret != 4)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// IP アドレスのクリア
void IpClear(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, IPM_CLEARADDRESS, 0, 0);
}

// IP アドレスの取得
UINT IpGet(HWND hWnd, UINT id)
{
	UINT ret;
	DWORD value;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	ret = SendMsg(hWnd, id, IPM_GETADDRESS, 0, (LPARAM)&value);

	if (ret != 4)
	{
		return 0;
	}
	else
	{
		return Endian32((UINT)value);
	}
}

// IP アドレスのセット
void IpSet(HWND hWnd, UINT id, UINT ip)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, IPM_SETADDRESS, 0, Endian32(ip));
}

// レジストリに候補を書き込む
void WriteCandidateToReg(UINT root, char *key, LIST *o, char *name)
{
	BUF *b;
	// 引数チェック
	if (key == NULL || o == NULL || name == NULL)
	{
		return;
	}

	b = CandidateToBuf(o);
	if (b == NULL)
	{
		return;
	}

	MsRegWriteBin(root, key, name, b->Buf, b->Size);

	FreeBuf(b);
}

// レジストリから候補を読み込む
LIST *ReadCandidateFromReg(UINT root, char *key, char *name)
{
	BUF *b;
	// 引数チェック
	if (key == NULL || name == NULL)
	{
		return NULL;
	}

	b = MsRegReadBin(root, key, name);
	if (b == NULL)
	{
		return NewCandidateList();
	}
	else
	{
		LIST *o = BufToCandidate(b);
		FreeBuf(b);

		return o;
	}
}

// リモート接続ダイアログ初期化
void RemoteDlgInit(HWND hWnd, WINUI_REMOTE *r)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, r->Icon);

	SetText(hWnd, 0, r->Caption);
	SetText(hWnd, S_TITLE, r->Title);
	SetIcon(hWnd, S_ICON, r->Icon);

	// 候補を読み込む
	o = ReadCandidateFromReg(REG_CURRENT_USER, r->RegKeyName, "RemoteHostCandidate");
	r->CandidateList = o;

	// 候補を表示する
	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		CbAddStr(hWnd, C_HOSTNAME, c->Str, 0);
	}

	if (r->DefaultHostname != NULL)
	{
		SetTextA(hWnd, C_HOSTNAME, r->DefaultHostname);
	}

	FocusEx(hWnd, C_HOSTNAME);

	RemoteDlgRefresh(hWnd, r);
}

// リモート接続ダイアログ更新
void RemoteDlgRefresh(HWND hWnd, WINUI_REMOTE *r)
{
	char *s;
	bool ok = true;
	bool localhost_mode = false;
	// 引数チェック
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	s = GetTextA(hWnd, C_HOSTNAME);
	if (s != NULL)
	{
		Trim(s);
		if (StrCmpi(s, "localhost") == 0 || StartWith(s, "127."))
		{
			localhost_mode = true;
		}
		Free(s);
	}

	if (localhost_mode == false)
	{
		Enable(hWnd, C_HOSTNAME);
		Enable(hWnd, S_HOSTNAME);
		Check(hWnd, R_LOCAL, false);
	}
	else
	{
		if (r->Title != _UU("NM_CONNECT_TITLE"))
		{
			Disable(hWnd, C_HOSTNAME);
			Disable(hWnd, S_HOSTNAME);
		}
		Check(hWnd, R_LOCAL, true);
		SetTextA(hWnd, C_HOSTNAME, "localhost");

		if (r->flag1 == false)
		{
			Focus(hWnd, IDOK);
		}
	}

	if (IsEmpty(hWnd, C_HOSTNAME))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);

	r->flag1 = true;
}

// リモート接続ダイアログ OK ボタン
void RemoteDlgOnOk(HWND hWnd, WINUI_REMOTE *r)
{
	char *hostname;
	wchar_t *s;
	LIST *o;
	// 引数チェック
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	// 入力されているホスト名を取得
	hostname = GetTextA(hWnd, C_HOSTNAME);
	if (hostname == NULL)
	{
		return;
	}
	Trim(hostname);

	// 候補を追加
	o = r->CandidateList;
	s = CopyStrToUni(hostname);
	AddCandidate(o, s, 64);
	Free(s);

	// 候補を書き込む
	WriteCandidateToReg(REG_CURRENT_USER, r->RegKeyName, o, "RemoteHostCandidate");
	FreeCandidateList(o);

	r->Hostname = hostname;

	EndDialog(hWnd, true);
}

// リモート接続ダイアログプロシージャ
UINT RemoteDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINUI_REMOTE *r = (WINUI_REMOTE *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		RemoteDlgInit(hWnd, r);
		SetTimer(hWnd, 1, 100, NULL);
		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			RemoteDlgRefresh(hWnd, r);
			SetTimer(hWnd, 1, 100, NULL);
			break;
		}
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case R_LOCAL:
			if (IsChecked(hWnd, R_LOCAL) == false)
			{
				SetTextA(hWnd, C_HOSTNAME, "");
				RemoteDlgRefresh(hWnd, r);
				FocusEx(hWnd, C_HOSTNAME);
			}
			else
			{
				SetTextA(hWnd, C_HOSTNAME, "localhost");
				RemoteDlgRefresh(hWnd, r);
				Focus(hWnd, IDOK);
			}
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		case IDOK:
			RemoteDlgOnOk(hWnd, r);
			break;
		}
		switch (LOWORD(wParam))
		{
		case R_LOCAL:
		case C_HOSTNAME:
			RemoteDlgRefresh(hWnd, r);
			break;
		}
		break;
	case WM_CLOSE:
		FreeCandidateList(r->CandidateList);
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// リモート接続ダイアログ
char *RemoteDlg(HWND hWnd, char *regkey, UINT icon, wchar_t *caption, wchar_t *title, char *default_host)
{
	WINUI_REMOTE r;
	// 引数チェック
	if (regkey == NULL)
	{
		regkey = "Software\\SoftEther Corporation\\SoftEther UT-VPN\\WinUI Common Module";
	}
	if (caption == NULL)
	{
		caption = _UU("REMOTE_DEF_CAPTION");
	}
	if (title == NULL)
	{
		title = _UU("REMOTE_DEF_TITLE");
	}
	if (icon == 0)
	{
		icon = ICO_INTERNET;
	}

	Zero(&r, sizeof(r));
	r.RegKeyName = regkey;
	r.Caption = caption;
	r.Title = title;
	r.Icon = icon;
	r.DefaultHostname = default_host;

	if (Dialog(hWnd, D_REMOTE, RemoteDlgProc, &r) == false)
	{
		return NULL;
	}

	return r.Hostname;
}

// ウインドウの検索プロシージャ
bool CALLBACK SearchWindowEnumProc(HWND hWnd, LPARAM lParam)
{
	if (hWnd != NULL && lParam != 0)
	{
		wchar_t *s = GetText(hWnd, 0);
		SEARCH_WINDOW_PARAM *p = (SEARCH_WINDOW_PARAM *)lParam;
		if (s != NULL)
		{
			if (UniStrCmpi(p->caption, s) == 0)
			{
				p->hWndFound = hWnd;
			}
			Free(s);
		}
	}
	return true;
}

// ウインドウの検索
HWND SearchWindow(wchar_t *caption)
{
	SEARCH_WINDOW_PARAM p;
	// 引数チェック
	if (caption == NULL)
	{
		return NULL;
	}

	Zero(&p, sizeof(p));
	p.caption = caption;
	p.hWndFound = NULL;

	EnumWindows(SearchWindowEnumProc, (LPARAM)&p);

	return p.hWndFound;
}

// 指定したプロセスにフォアグラウンドウインドウになることを許可
void AllowFGWindow(UINT process_id)
{
	if (process_id == 0)
	{
		return;
	}

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) &&
		GET_KETA(GetOsInfo()->OsType, 100) >= 2)
	{
		AllowSetForegroundWindow(process_id);
	}
}

// アイテムのリネーム
void LvRename(HWND hWnd, UINT id, UINT pos)
{
	// 引数チェック
	if (hWnd == NULL || pos == INFINITE)
	{
		return;
	}

	ListView_EditLabel(DlgItem(hWnd, id), pos);
}

// メニューを表示する
void PrintMenu(HWND hWnd, HMENU hMenu)
{
	POINT p;
	// 引数チェック
	if (hMenu == NULL || hWnd == NULL)
	{
		return;
	}

	GetCursorPos(&p);

	TrackPopupMenu(hMenu, TPM_LEFTALIGN, p.x, p.y, 0, hWnd, NULL);
}

// メニューからショートカット文字列を削除する
void RemoveShortcutKeyStrFromMenu(HMENU hMenu)
{
	UINT i, num;
	// 引数チェック
	if (hMenu == NULL)
	{
		return;
	}

	num = GetMenuNum(hMenu);
	for (i = 0;i < num;i++)
	{
		wchar_t *str = GetMenuStr(hMenu, i);
		if (str != NULL)
		{
			UINT j, len;
			len = UniStrLen(str);
			for (j = 0;j < len;j++)
			{
				if (str[j] == L'\t')
				{
					str[j] = 0;
				}
			}
			SetMenuStr(hMenu, i, str);
			Free(str);
		}
	}
}

// メニュー内の項目数を取得する
UINT GetMenuNum(HMENU hMenu)
{
	UINT ret;
	// 引数チェック
	if (hMenu == NULL)
	{
		return 0;
	}

	ret = GetMenuItemCount(hMenu);
	if (ret == INFINITE)
	{
		return 0;
	}
	else
	{
		return ret;
	}
}

// メニュー内の文字列を設定する
void SetMenuStr(HMENU hMenu, UINT pos, wchar_t *str)
{
	MENUITEMINFOW info;
	// 引数チェック
	if (hMenu == NULL || pos == INFINITE || str == NULL)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		SetMenuStrA(hMenu, pos, s);
		Free(s);
		return;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = MIIM_STRING;
	info.dwTypeData = str;
	SetMenuItemInfoW(hMenu, pos, true, &info);
}
void SetMenuStrA(HMENU hMenu, UINT pos, char *str)
{
	MENUITEMINFOA info;
	// 引数チェック
	if (hMenu == NULL || pos == INFINITE || str == NULL)
	{
		return;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = MIIM_STRING;
	info.dwTypeData = str;
	SetMenuItemInfoA(hMenu, pos, true, &info);
}

// メニュー内の文字列を取得する
wchar_t *GetMenuStr(HMENU hMenu, UINT pos)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hMenu == NULL || pos == INFINITE)
	{
		return NULL;
	}
	if (MsIsNt() == false)
	{
		char *s = GetMenuStrA(hMenu, pos);
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

	if (GetMenuStringW(hMenu, pos, tmp, sizeof(tmp), MF_BYPOSITION) == 0)
	{
		return NULL;
	}

	return UniCopyStr(tmp);
}
char *GetMenuStrA(HMENU hMenu, UINT pos)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hMenu == NULL || pos == INFINITE)
	{
		return NULL;
	}

	if (GetMenuString(hMenu, pos, tmp, sizeof(tmp), MF_BYPOSITION) == 0)
	{
		return NULL;
	}

	return CopyStr(tmp);
}

// メニュー項目を太字にする
void SetMenuItemBold(HMENU hMenu, UINT pos, bool bold)
{
	MENUITEMINFO info;
	// 引数チェック
	if (hMenu == NULL || pos == INFINITE)
	{
		return;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = MIIM_STATE;

	if (GetMenuItemInfo(hMenu, pos, true, &info) == false)
	{
		return;
	}

	if (bold)
	{
		info.fState |= MFS_DEFAULT;
	}
	else
	{
		info.fState = info.fState & ~MFS_DEFAULT;
	}

	SetMenuItemInfo(hMenu, pos, true, &info);
}

// メニュー項目を有効 / 無効にする
void SetMenuItemEnable(HMENU hMenu, UINT pos, bool enable)
{
	MENUITEMINFO info;
	// 引数チェック
	if (hMenu == NULL || pos == INFINITE)
	{
		return;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = MIIM_STATE;

	if (GetMenuItemInfo(hMenu, pos, true, &info) == false)
	{
		return;
	}

	if (enable)
	{
		info.fState |= MFS_ENABLED;
		info.fState = info.fState & ~MFS_DISABLED;
	}
	else
	{
		info.fState |= MFS_DISABLED;
		info.fState = info.fState & ~MFS_ENABLED;
	}

	SetMenuItemInfo(hMenu, pos, true, &info);
}

// メニュー項目を削除する
void DeleteMenuItem(HMENU hMenu, UINT pos)
{
	// 引数チェック
	if (hMenu == NULL || pos == INFINITE)
	{
		return;
	}

	DeleteMenu(hMenu, pos, MF_BYPOSITION);
}

// メニュー内の ID から位置を取得する
UINT GetMenuItemPos(HMENU hMenu, UINT id)
{
	UINT num, i;
	// 引数チェック
	if (hMenu == NULL)
	{
		return INFINITE;
	}

	num = GetMenuItemCount(hMenu);
	if (num == INFINITE)
	{
		return INFINITE;
	}

	for (i = 0;i < num;i++)
	{
		if (GetMenuItemID(hMenu, i) == id)
		{
			return i;
		}
	}

	return INFINITE;
}

// サブメニューを取得
HMENU LoadSubMenu(UINT menu_id, UINT pos, HMENU *parent_menu)
{
	HMENU h = LoadMenu(hDll, MAKEINTRESOURCE(menu_id));
	HMENU ret;
	if (h == NULL)
	{
		return NULL;
	}

	ret = GetSubMenu(h, pos);

	if (parent_menu != NULL)
	{
		*parent_menu = h;
	}

	return ret;
}

// ユーザーインターフェイスの DLL を取得
HINSTANCE GetUiDll()
{
	return hDll;
}

// 接続エラーダイアログプロシージャ
UINT ConnectErrorDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_CONNECTERROR_DLG *p = (UI_CONNECTERROR_DLG *)param;
	wchar_t tmp[1024];
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		if (p->Err == ERR_DISCONNECTED || p->Err == ERR_SESSION_TIMEOUT)
		{
			// 接続が切断された旨のメッセージ
			SetText(hWnd, S_TITLE, _UU("ERRDLG_DISCONNECTED_MSG"));
		}
		if (p->HideWindow)
		{
			Hide(hWnd, R_HIDE);
		}
		FormatText(hWnd, 0, p->AccountName);
		FormatText(hWnd, S_TITLE, p->ServerName);
		UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_ERRMSG"), p->Err, _E(p->Err));
		SetText(hWnd, E_ERROR, tmp);

		SetIcon(hWnd, 0, ICO_SERVER_OFFLINE);

		if (p->RetryIntervalSec == 0)
		{
			SetText(hWnd, S_COUNTDOWN, _UU("ERRDLG_INFORMATION"));
			Hide(hWnd, P_PROGRESS);
			Hide(hWnd, S_RETRYINFO);
		}
		else
		{
			if (p->RetryLimit != INFINITE)
			{
				UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_RETRY_INFO_1"), p->CurrentRetryCount, p->RetryLimit);
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_RETRY_INFO_2"), p->CurrentRetryCount);
			}
			SetText(hWnd, S_RETRYINFO, tmp);
			SetRange(hWnd, P_PROGRESS, 0, p->RetryIntervalSec);
			SetPos(hWnd, P_PROGRESS, 0);
			SetTimer(hWnd, 1, 10, NULL);
			p->StartTick = Tick64();
		}
		SetTimer(hWnd, 2, 10, NULL);
		Focus(hWnd, IDOK);
		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (p->RetryIntervalSec != 0)
			{
				UINT64 start, end, now;
				now = Tick64();
				start = p->StartTick;
				end = start + (UINT64)p->RetryIntervalSec;

				if (end > now)
				{
					SetPos(hWnd, P_PROGRESS, (UINT)(now - start));
					UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_RETRYCOUNT"), ((UINT)(end - now)) / 1000);
					SetText(hWnd, S_COUNTDOWN, tmp);
				}
				else
				{
					Command(hWnd, IDOK);
				}
			}
			break;
		case 2:
			if (p->CancelEvent != NULL)
			{
				if (WaitForSingleObject((HANDLE)p->CancelEvent->pData, 0) != WAIT_TIMEOUT)
				{
					// 強制キャンセル
					Close(hWnd);
				}
			}
			break;
		}
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_HIDE:
			p->HideWindow = IsChecked(hWnd, R_HIDE);
			break;
		}
		switch (wParam)
		{
		case IDOK:
			EndDialog(hWnd, true);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 接続エラーダイアログを表示
bool ConnectErrorDlg(UI_CONNECTERROR_DLG *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return false;
	}

	return DialogEx2(NULL, D_CONNECTERROR, ConnectErrorDlgProc, p, true, true);
}

// 証明書の内容を表示する
void PrintCheckCertInfo(HWND hWnd, UI_CHECKCERT *p)
{
	wchar_t tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR md5[MD5_SIZE];
	UCHAR sha1[SHA1_SIZE];
	X *x;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	x = p->x;

	GetAllNameFromNameEx(tmp, sizeof(tmp), x->subject_name);
	SetText(hWnd, E_SUBJECT, tmp);

	GetAllNameFromNameEx(tmp, sizeof(tmp), x->issuer_name);
	SetText(hWnd, E_ISSUER, tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notAfter), NULL);
	SetText(hWnd, E_EXPIRES, tmp);

	GetXDigest(x, md5, false);
	BinToStr(tmp2, sizeof(tmp2), md5, sizeof(md5));
	SetTextA(hWnd, E_MD5, tmp2);

	GetXDigest(x, sha1, true);
	BinToStr(tmp2, sizeof(tmp2), sha1, sizeof(sha1));
	SetTextA(hWnd, E_SHA1, tmp2);

	SetFont(hWnd, E_MD5, GetFont("Arial", 8, false, false, false, false));
	SetFont(hWnd, E_SHA1, GetFont("Arial", 8, false, false, false, false));
}

// 証明書が相違する旨を警告する
void ShowDlgDiffWarning(HWND hWnd, UI_CHECKCERT *p)
{
	UCHAR sha1_new[SHA1_SIZE], sha1_old[SHA1_SIZE];
	UCHAR md5_new[MD5_SIZE], md5_old[MD5_SIZE];
	char sha1_new_str[MAX_SIZE], sha1_old_str[MAX_SIZE];
	char md5_new_str[MAX_SIZE], md5_old_str[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL || p == NULL || p->x == NULL || p->old_x == NULL)
	{
		return;
	}

	GetXDigest(p->x, sha1_new, true);
	GetXDigest(p->x, md5_new, false);

	GetXDigest(p->old_x, sha1_old, true);
	GetXDigest(p->old_x, md5_old, false);

	BinToStrEx(sha1_new_str, sizeof(sha1_new_str), sha1_new, sizeof(sha1_new));
	BinToStrEx(md5_new_str, sizeof(md5_new_str), md5_new, sizeof(md5_new));
	BinToStrEx(sha1_old_str, sizeof(sha1_old_str), sha1_old, sizeof(sha1_old));
	BinToStrEx(md5_old_str, sizeof(md5_old_str), md5_old, sizeof(md5_old));

	MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("CC_DANGEROUS_MSG"),
		p->ServerName, md5_old_str, sha1_old_str, md5_new_str, sha1_new_str);
}

// [OK] ボタンが押された
void CheckCertDialogOnOk(HWND hWnd, UI_CHECKCERT *p)
{
	UCHAR sha1_new[SHA1_SIZE];
	UCHAR md5_new[MD5_SIZE];
	char sha1_new_str[MAX_SIZE];
	char md5_new_str[MAX_SIZE];
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	GetXDigest(p->x, sha1_new, true);
	GetXDigest(p->x, md5_new, false);
	BinToStrEx(sha1_new_str, sizeof(sha1_new_str), sha1_new, sizeof(sha1_new));
	BinToStrEx(md5_new_str, sizeof(md5_new_str), md5_new, sizeof(md5_new));

	ret = MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNOCANCEL | MB_DEFBUTTON2,
		_UU("CC_WARNING_MSG"),
		p->AccountName, sha1_new_str, md5_new_str);

	if (ret == IDYES)
	{
		p->SaveServerCert = true;
	}

	if (ret == IDCANCEL)
	{
		return;
	}

	p->Ok = true;
	EndDialog(hWnd, true);
}

// 証明書ダイアログプロシージャ
UINT CheckCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_CHECKCERT *p = (UI_CHECKCERT *)param;
	// 引数チェック
	if (hWnd == NULL || param == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, 0, p->AccountName);
		FormatText(hWnd, S_TITLE, p->ServerName);
		FormatText(hWnd, S_MSG1, p->ServerName);

		PrintCheckCertInfo(hWnd, p);

		Focus(hWnd, IDCANCEL);

		SetIcon(hWnd, 0, ICO_WARNING);

		if (p->DiffWarning)
		{
			SetTimer(hWnd, 1, 1, NULL);
		}

		SetTimer(hWnd, 2, 100, NULL);

		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			ShowDlgDiffWarning(hWnd, p);
			break;
		case 2:
			if ((p->Session != NULL && p->Session->Halt) ||
				(p->Halt))
			{
				p->Ok = false;
				EndDialog(hWnd, false);
			}
			break;
		}
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case B_SHOW:
			CertDlg(hWnd, p->x, p->parent_x, false);
			break;
		case IDOK:
			CheckCertDialogOnOk(hWnd, p);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;
	case WM_CLOSE:
		p->Ok = false;
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// 証明書のチェックダイアログ
void CheckCertDlg(UI_CHECKCERT *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	Dialog(NULL, D_CHECKCERT, CheckCertDlgProc, p);
}

// アイコン ID からイメージリスト ID を取得する
UINT GetIcon(UINT icon_id)
{
	IMAGELIST_ICON *c, t;
	t.id = icon_id;

	c = Search(icon_list, &t);
	if (c == NULL)
	{
		if (icon_id != ICO_NULL)
		{
			return GetIcon(ICO_NULL);
		}
		else
		{
			return INFINITE;
		}
	}
	else
	{
		return c->Index;
	}
}

// イメージリスト用にアイコンをロードする
IMAGELIST_ICON *LoadIconForImageList(UINT id)
{
	IMAGELIST_ICON *ret = ZeroMalloc(sizeof(IMAGELIST_ICON));
	HICON small_icon, large_icon;

	ret->id = id;

	large_icon = LoadLargeIcon(id);
	if (large_icon == NULL)
	{
		large_icon = LoadSmallIcon(id);
	}

	small_icon = LoadSmallIcon(id);
	if (small_icon == NULL)
	{
		small_icon = LoadLargeIcon(id);
	}

	ret->hSmallImage = small_icon;
	ret->hLargeImage = large_icon;
	ret->Index = ImageList_AddIcon(large_image_list, large_icon);
	ImageList_AddIcon(small_image_list, small_icon);

	return ret;
}

// イメージリストアイコンの比較
int CompareImageListIcon(void *p1, void *p2)
{
	IMAGELIST_ICON *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IMAGELIST_ICON **)p1;
	c2 = *(IMAGELIST_ICON **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	if (c1->id > c2->id)
	{
		return 1;
	}
	else if (c1->id < c2->id)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// イメージリストの初期化
void InitImageList()
{
	large_image_list = ImageList_Create(32, 32, ILC_COLOR32 | ILC_MASK, 1, 0);
	ImageList_SetBkColor(large_image_list, RGB(255, 255, 255));
	small_image_list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 0);
	ImageList_SetBkColor(small_image_list, RGB(255, 255, 255));
	icon_list = NewList(CompareImageListIcon);

	// 列挙
	EnumResourceNames(hDll, RT_GROUP_ICON, EnumResNameProc, 0);
}

// アイコンリソース列挙プロシージャ
BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam)
{
	if (IS_INTRESOURCE(lpszName))
	{
		UINT icon_id = (UINT)lpszName;
		IMAGELIST_ICON *img = LoadIconForImageList(icon_id);

		Add(icon_list, img);
	}

	return TRUE;
}

// イメージリストの解放
void FreeImageList()
{
	UINT i;
	ImageList_Destroy(large_image_list);
	ImageList_Destroy(small_image_list);
	large_image_list = small_image_list = NULL;

	for (i = 0;i < LIST_NUM(icon_list);i++)
	{
		IMAGELIST_ICON *c = LIST_DATA(icon_list, i);
		Free(c);
	}

	ReleaseList(icon_list);
	icon_list = NULL;
}

// カラムの横幅の取得
UINT LvGetColumnWidth(HWND hWnd, UINT id, UINT index)
{
	return ListView_GetColumnWidth(DlgItem(hWnd, id), index);
}

// カラムの挿入
void LvInsertColumn(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT width)
{
	LVCOLUMNW c;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));
	c.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;

	c.pszText = str;
	c.iSubItem = index;
	c.cx = width;

	SendMsg(hWnd, id, LVM_INSERTCOLUMNW, index, (LPARAM)&c);
}

// すべてのアイテムを削除
void LvReset(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	ListView_DeleteAllItems(DlgItem(hWnd, id));
}

// リストビューを初期化
void LvInitEx(HWND hWnd, UINT id, bool no_image)
{
	LvInitEx2(hWnd, id, no_image, false);
}
void LvInitEx2(HWND hWnd, UINT id, bool no_image, bool large_icon)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	ListView_SetUnicodeFormat(DlgItem(hWnd, id), true);

	if (no_image == false)
	{
		ListView_SetImageList(DlgItem(hWnd, id), large_image_list, LVSIL_NORMAL);
		ListView_SetImageList(DlgItem(hWnd, id), large_icon ? large_image_list : small_image_list, LVSIL_SMALL);
	}

	ListView_SetExtendedListViewStyle(DlgItem(hWnd, id), LVS_EX_FULLROWSELECT);

	if (MsIsVista())
	{
		LvSetStyle(hWnd, id, LVS_EX_DOUBLEBUFFER);
	}
}
void LvInit(HWND hWnd, UINT id)
{
	LvInitEx(hWnd, id, false);
}

// バッチ追加処理完了 (高速)
void LvInsertEnd(LVB *b, HWND hWnd, UINT id)
{
	LvInsertEndEx(b, hWnd, id, false);
}
void LvInsertEndEx(LVB *b, HWND hWnd, UINT id, bool force_reset)
{
	UINT i, num;
	LIST *new_list, *exist_list;
	wchar_t *last_selected = NULL;
	// 引数チェック
	if (b == NULL || hWnd == NULL)
	{
		return;
	}

	new_list = NewListFast(CompareUniStr);

	for (i = 0;i < LIST_NUM(b->ItemList);i++)
	{
		LVB_ITEM *t = LIST_DATA(b->ItemList, i);
		Add(new_list, t->Strings[0]);
	}

	Sort(new_list);

	if ((LIST_NUM(b->ItemList) >= LV_INSERT_RESET_ALL_ITEM_MIN) || force_reset)
	{
		last_selected = LvGetFocusedStr(hWnd, id, 0);
		LvReset(hWnd, id);
	}

	exist_list = NewListFast(CompareUniStr);

	num = LvNum(hWnd, id);

	// 既存項目のうちバッチリスト内に存在していない項目を削除する
	for (i = 0;i < num;i++)
	{
		bool exists = false;
		wchar_t *s = LvGetStr(hWnd, id, i, 0);
		if (Search(new_list, s) != NULL)
		{
			exists = true;
		}
		if (exists == false)
		{
			// 追加予定バッチリスト内に存在しない項目はリストビューから削除する
			LvDeleteItem(hWnd, id, i);
			num = LvNum(hWnd, id);
			i--;
			Free(s);
		}
		else
		{
			Add(exist_list, s);
		}
	}

	Sort(exist_list);

	// バッチ内の項目を 1 つずつ追加していく
	for (i = 0;i < LIST_NUM(b->ItemList);i++)
	{
		LVB_ITEM *t = LIST_DATA(b->ItemList, i);
		UINT index;
		UINT j;
		bool exists = false;

		if (Search(exist_list, t->Strings[0]) != NULL)
		{
			index = LvSearchStr(hWnd, id, 0, t->Strings[0]);
		}
		else
		{
			index = INFINITE;
		}

		if (index != INFINITE)
		{
			UINT j;
			// 追加しようとする項目と同じ文字列の項目がすでに存在する場合は
			// 追加ではなく更新を行う
			for (j = 0;j < t->NumStrings;j++)
			{
				LvSetItem(hWnd, id, index, j, t->Strings[j]);
			}
			LvSetItemImageByImageListId(hWnd, id, index, t->Image);
			LvSetItemParam(hWnd, id, index, t->Param);
		}
		else
		{
			// 新しく追加を行う
			UINT index = INFINITE;
			UINT j;
			for (j = 0;j < t->NumStrings;j++)
			{
				if (j == 0)
				{
					index = LvInsertItemByImageListId(hWnd, id, t->Image, t->Param, t->Strings[j]);
				}
				else
				{
					LvSetItem(hWnd, id, index, j, t->Strings[j]);
				}
			}
		}

		// メモリを解放する
		for (j = 0;j < t->NumStrings;j++)
		{
			Free(t->Strings[j]);
		}
		Free(t->Strings);
		Free(t);
	}

	// リストを解放する
	ReleaseList(b->ItemList);

	// メモリを解放する
	Free(b);

	ReleaseList(new_list);

	for (i = 0;i < LIST_NUM(exist_list);i++)
	{
		Free(LIST_DATA(exist_list, i));
	}
	ReleaseList(exist_list);

	if (last_selected != NULL)
	{
		UINT pos = LvSearchStr(hWnd, id, 0, last_selected);

		if (pos != INFINITE)
		{
			LvSelect(hWnd, id, pos);
		}

		Free(last_selected);
	}
}

// カラム数の取得
UINT LvGetColumnNum(HWND hWnd, UINT id)
{
	UINT i;
	LVCOLUMN c;
	if (hWnd == NULL)
	{
		return 0;
	}

	for (i = 0;;i++)
	{
		Zero(&c, sizeof(c));
		c.mask = LVCF_SUBITEM;
		if (ListView_GetColumn(DlgItem(hWnd, id), i, &c) == false)
		{
			break;
		}
	}

	return i;
}

// ソート関数
int CALLBACK LvSortProc(LPARAM param1, LPARAM param2, LPARAM sort_param)
{
	WINUI_LV_SORT *sort = (WINUI_LV_SORT *)sort_param;
	HWND hWnd;
	UINT id;
	UINT i1, i2;
	int ret = 0;
	wchar_t *s1, *s2;
	if (sort == NULL)
	{
		return 0;
	}

	hWnd = sort->hWnd;
	id = sort->id;

	if (hWnd == NULL)
	{
		return 0;
	}

	i1 = (UINT)param1;
	i2 = (UINT)param2;

	s1 = LvGetStr(hWnd, id, i1, sort->subitem);
	if (s1 == NULL)
	{
		return 0;
	}

	s2 = LvGetStr(hWnd, id, i2, sort->subitem);
	if (s2 == NULL)
	{
		Free(s1);
		return 0;
	}

	if (sort->numeric == false)
	{
		if (UniStrCmpi(s1, _UU("CM_NEW_ICON")) == 0)
		{
			ret = -1;
		}
		else if (UniStrCmpi(s1, _UU("CM_ASP")) == 0)
		{
			ret = -1;
		}
		else if (UniStrCmpi(s2, _UU("CM_NEW_ICON")) == 0)
		{
			ret = 1;
		}
		else if (UniStrCmpi(s2, _UU("CM_ASP")) == 0)
		{
			return 1;
		}
		else
		{
			ret = UniStrCmpi(s1, s2);
		}
	}
	else
	{
		UINT64 v1, v2;
		v1 = UniToInt64(s1);
		v2 = UniToInt64(s2);
		if (v1 > v2)
		{
			ret = 1;
		}
		else if (v1 < v2)
		{
			ret = -1;
		}
		else
		{
			ret = 0;
		}
	}

	Free(s1);
	Free(s2);

	if (sort->desc)
	{
		ret = -ret;
	}

	return ret;
}

// 標準的なハンドラ
void LvStandardHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id)
{
	NMHDR *n;
	NMLVKEYDOWN *key;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	LvSortHander(hWnd, msg, wParam, lParam, id);

	switch (msg)
	{
	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		if (n->idFrom == id)
		{
			switch (n->code)
			{
			case NM_DBLCLK:
				Command(hWnd, IDOK);
				break;
			case LVN_KEYDOWN:
				key = (NMLVKEYDOWN *)n;
				if (key != NULL)
				{
					UINT code = key->wVKey;
					switch (code)
					{
					case VK_DELETE:
						Command(hWnd, B_DELETE);
						break;

					case VK_RETURN:
						Command(hWnd, IDOK);
						break;

					case VK_F5:
						Command(hWnd, B_REFRESH);
						break;
					}
				}
				break;
			}
		}
		break;
	}
}

// ソートヘッダハンドラ
void LvSortHander(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id)
{
	NMHDR *nmhdr;
	UINT subitem;
	bool desc;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	switch (msg)
	{
	case WM_NOTIFY:
		nmhdr = (NMHDR *)lParam;

		if (nmhdr != NULL)
		{
			if (nmhdr->idFrom == id)
			{
				NMLISTVIEW *v;
				switch (nmhdr->code)
				{
				case LVN_COLUMNCLICK:
					desc = false;
					v = (NMLISTVIEW *)lParam;
					subitem = v->iSubItem;

					if ((GetStyle(hWnd, id) & LVS_SORTDESCENDING) == 0)
					{
						desc = true;
						SetStyle(hWnd, id, LVS_SORTDESCENDING);
						RemoveStyle(hWnd, id, LVS_SORTASCENDING);
					}
					else
					{
						SetStyle(hWnd, id, LVS_SORTASCENDING);
						RemoveStyle(hWnd, id, LVS_SORTDESCENDING);
					}

					LvSort(hWnd, id, subitem, desc);
					break;
				}
			}
		}
		break;
	}
}

// ソートを行う
void LvSort(HWND hWnd, UINT id, UINT subitem, bool desc)
{
	UINT i, num;
	bool numeric = true;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	num = LvNum(hWnd, id);
	for (i = 0;i < num;i++)
	{
		wchar_t *s = LvGetStr(hWnd, id, i, subitem);
		if (s != NULL)
		{
			if (UniIsNum(s) == false)
			{
				numeric = false;
				Free(s);
				break;
			}
			Free(s);
		}
		else
		{
			numeric = false;
			break;
		}
	}

	LvSortEx(hWnd, id, subitem, desc, numeric);
}

void LvSortEx(HWND hWnd, UINT id, UINT subitem, bool desc, bool numeric)
{
	WINUI_LV_SORT s;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}
	if (subitem >= LvGetColumnNum(hWnd, id))
	{
		return;
	}

	Zero(&s, sizeof(s));
	s.desc = desc;
	s.numeric = numeric;
	s.id = id;
	s.hWnd = hWnd;
	s.subitem = subitem;

	ListView_SortItemsEx(DlgItem(hWnd, id), LvSortProc, (LPARAM)&s);
}

// 項目追加バッチへの追加
void LvInsertAdd(LVB *b, UINT icon, void *param, UINT num_str, ...)
{
	UINT i;
	va_list va;
	UINT index = 0;
	LVB_ITEM *t;
	// 引数チェック
	if (b == NULL || num_str == 0)
	{
		return;
	}

	t = ZeroMalloc(sizeof(LVB_ITEM));

	va_start(va, num_str);

	t->Strings = (wchar_t **)ZeroMalloc(sizeof(wchar_t *) * num_str);
	t->NumStrings = num_str;

	for (i = 0;i < num_str;i++)
	{
		wchar_t *s = va_arg(va, wchar_t *);

		t->Strings[i] = UniCopyStr(s);
	}

	t->Param = param;
	t->Image = GetIcon(icon);

	Add(b->ItemList, t);

	va_end(va);
}

// 項目追加バッチの開始
LVB *LvInsertStart()
{
	LVB *b = ZeroMalloc(sizeof(LVB));
	b->ItemList = NewListFast(NULL);

	return b;
}

// リストビューに項目を追加する
void LvInsert(HWND hWnd, UINT id, UINT icon, void *param, UINT num_str, ...)
{
	UINT i;
	va_list va;
	UINT index = 0;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	va_start(va, num_str);

	for (i = 0;i < num_str;i++)
	{
		wchar_t *s = va_arg(va, wchar_t *);
		if (i == 0)
		{
			index = LvInsertItem(hWnd, id, icon, param, s);
		}
		else
		{
			LvSetItem(hWnd, id, index, i, s);
		}
	}

	va_end(va);
}

// アイテムのサイズを自動調整する
void LvAutoSize(HWND hWnd, UINT id)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	i = 0;
	while (true)
	{
		if (ListView_SetColumnWidth(DlgItem(hWnd, id), i, LVSCW_AUTOSIZE) == false)
		{
			break;
		}
		i++;
	}
}

// アイテムを追加する
UINT LvInsertItem(HWND hWnd, UINT id, UINT icon, void *param, wchar_t *str)
{
	return LvInsertItemByImageListId(hWnd, id, GetIcon(icon), param, str);
}
UINT LvInsertItemByImageListId(HWND hWnd, UINT id, UINT image, void *param, wchar_t *str)
{
	LVITEMW t;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}
	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		UINT ret;
		ret = LvInsertItemByImageListIdA(hWnd, id, image, param, s);
		Free(s);
		return ret;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_IMAGE | LVIF_PARAM | LVIF_TEXT;
	t.pszText = str;
	t.iImage = image;
	t.lParam = (LPARAM)param;
	t.iItem = LvNum(hWnd, id);

	return SendMsg(hWnd, id, LVM_INSERTITEMW, 0, (LPARAM)&t);
}
UINT LvInsertItemByImageListIdA(HWND hWnd, UINT id, UINT image, void *param, char *str)
{
	LVITEM t;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_IMAGE | LVIF_PARAM | LVIF_TEXT;
	t.pszText = str;
	t.iImage = image;
	t.lParam = (LPARAM)param;
	t.iItem = LvNum(hWnd, id);

	return SendMsg(hWnd, id, LVM_INSERTITEM, 0, (LPARAM)&t);
}

// イメージを変更する
void LvSetItemImage(HWND hWnd, UINT id, UINT index, UINT icon)
{
	LvSetItemImageByImageListId(hWnd, id, index, GetIcon(icon));
}
void LvSetItemImageByImageListId(HWND hWnd, UINT id, UINT index, UINT image)
{
	LVITEM t;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_IMAGE;
	t.iImage = image;
	t.iItem = index;

	SendMsg(hWnd, id, LVM_SETITEM, 0, (LPARAM)&t);
}

// アイテムのパラメータを設定する
void LvSetItemParam(HWND hWnd, UINT id, UINT index, void *param)
{
	LvSetItemParamEx(hWnd, id, index, 0, param);
}
void LvSetItemParamEx(HWND hWnd, UINT id, UINT index, UINT subitem, void *param)
{
	LVITEM t;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_PARAM;
	t.iItem = index;
	t.iSubItem = subitem;
	t.lParam = (LPARAM)param;

	SendMsg(hWnd, id, LVM_SETITEM, 0, (LPARAM)&t);
}

// アイテムを設定する
void LvSetItem(HWND hWnd, UINT id, UINT index, UINT pos, wchar_t *str)
{
	LVITEMW t;
	wchar_t *old_str;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return;
	}
	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		LvSetItemA(hWnd, id, index, pos, s);
		Free(s);
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.pszText = str;
	t.iItem = index;
	t.iSubItem = pos;

	old_str = LvGetStr(hWnd, id, index, pos);

	if (UniStrCmp(old_str, str) != 0)
	{
		SendMsg(hWnd, id, LVM_SETITEMW, 0, (LPARAM)&t);
	}

	Free(old_str);
}
void LvSetItemA(HWND hWnd, UINT id, UINT index, UINT pos, char *str)
{
	LVITEM t;
	wchar_t *old_str;
	char *old_str_2;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.pszText = str;
	t.iItem = index;
	t.iSubItem = pos;

	old_str = LvGetStr(hWnd, id, index, pos);
	old_str_2 = CopyUniToStr(old_str);

	if (StrCmp(old_str_2, str) != 0)
	{
		SendMsg(hWnd, id, LVM_SETITEM, 0, (LPARAM)&t);
	}

	Free(old_str_2);
	Free(old_str);
}

// リストボックスのビューを設定
void LvSetView(HWND hWnd, UINT id, bool details)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (details)
	{
		RemoveStyle(hWnd, id, LVS_ICON);
		SetStyle(hWnd, id, LVS_REPORT);
	}
	else
	{
		RemoveStyle(hWnd, id, LVS_REPORT);
		SetStyle(hWnd, id, LVS_ICON);
	}
}

// 指定したアイテムが必ず表示されるようにする
void LvShow(HWND hWnd, UINT id, UINT index)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	ListView_EnsureVisible(DlgItem(hWnd, id), index, false);
}

// 現在選択されている項目が存在するかどうかを取得する
bool LvIsSelected(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	if (LvGetSelected(hWnd, id) == INFINITE)
	{
		return false;
	}

	return true;
}

// 現在選択されている項目を取得する
UINT LvGetFocused(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return ListView_GetNextItem(DlgItem(hWnd, id), -1, LVNI_FOCUSED);
}

// 現在選択されている文字列を取得する
wchar_t *LvGetFocusedStr(HWND hWnd, UINT id, UINT pos)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	i = LvGetFocused(hWnd, id);
	if (i == INFINITE)
	{
		return NULL;
	}

	return LvGetStr(hWnd, id, i, pos);
}

// 現在選択されている項目を取得する
UINT LvGetSelected(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return ListView_GetNextItem(DlgItem(hWnd, id), -1, LVNI_FOCUSED | LVNI_SELECTED);
}

// 現在選択されている文字列を取得する
wchar_t *LvGetSelectedStr(HWND hWnd, UINT id, UINT pos)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	i = LvGetSelected(hWnd, id);
	if (i == INFINITE)
	{
		return NULL;
	}

	return LvGetStr(hWnd, id, i, pos);
}
char *LvGetSelectedStrA(HWND hWnd, UINT id, UINT pos)
{
	char *ret;
	wchar_t *tmp = LvGetSelectedStr(hWnd, id, pos);
	if (tmp == NULL)
	{
		return NULL;
	}
	ret = CopyUniToStr(tmp);
	Free(tmp);
	return ret;
}

// 2 つ以上の項目がマスクされているかどうかを取得する
bool LvIsMultiMasked(HWND hWnd, UINT id)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	i = INFINITE;
	i = LvGetNextMasked(hWnd, id, i);
	if (i != INFINITE)
	{
		if (LvGetNextMasked(hWnd, id, i) != INFINITE)
		{
			return true;
		}
	}

	return false;
}

// ただ 1 つの項目だけが選択されているかどうか調べる
bool LvIsSingleSelected(HWND hWnd, UINT id)
{
	return LvIsSelected(hWnd, id) && (LvIsMultiMasked(hWnd, id) == false);
}

// 現在マスクされている項目が存在するかどうかを取得する
bool LvIsMasked(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	if (LvGetNextMasked(hWnd, id, INFINITE) == INFINITE)
	{
		return false;
	}

	return true;
}

// 現在マスクされている項目数を取得する
UINT LvGetMaskedNum(HWND hWnd, UINT id)
{
	UINT i = INFINITE;
	UINT num = 0;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	while (true)
	{
		i = LvGetNextMasked(hWnd, id, i);
		if (i == INFINITE)
		{
			break;
		}

		num++;
	}

	return num;
}

// 現在マスクされている項目を取得する
UINT LvGetNextMasked(HWND hWnd, UINT id, UINT start)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return ListView_GetNextItem(DlgItem(hWnd, id), start, LVNI_SELECTED);
}

// 指定した文字列を持つ項目を検索する
UINT LvSearchStr_(HWND hWnd, UINT id, UINT pos, wchar_t *str)
{
	UINT ret;
	LVFINDINFOW t;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	Zero(&t, sizeof(t));
	t.flags = LVFI_STRING;
	t.psz = str;
	t.vkDirection = VK_DOWN;

	ret = SendMsg(hWnd, id, LVM_FINDITEMW, -1, (LPARAM)&t);

	return ret;
}

// 指定した文字列を持つ項目を検索する
UINT LvSearchStr(HWND hWnd, UINT id, UINT pos, wchar_t *str)
{
	UINT i, num;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	num = LvNum(hWnd, id);

	for (i = 0;i < num;i++)
	{
		wchar_t *s = LvGetStr(hWnd, id, i, pos);
		if (s != NULL)
		{
			if (UniStrCmpi(s, str) == 0)
			{
				Free(s);
				return i;
			}
			else
			{
				Free(s);
			}
		}
	}

	return INFINITE;
}
UINT LvSearchStrA(HWND hWnd, UINT id, UINT pos, char *str)
{
	wchar_t *tmp = CopyStrToUni(str);
	UINT ret = LvSearchStr(hWnd, id, pos, tmp);
	Free(tmp);
	return ret;
}

// 指定した param を持つ項目を検索する
UINT LvSearchParam(HWND hWnd, UINT id, void *param)
{
	UINT i, num;
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	num = LvNum(hWnd, id);

	for (i = 0;i < num;i++)
	{
		if (LvGetParam(hWnd, id, i) == param)
		{
			return i;
		}
	}

	return INFINITE;
}

// 項目数を取得する
UINT LvNum(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	return ListView_GetItemCount(DlgItem(hWnd, id));
}

// 項目を削除する
void LvDeleteItem(HWND hWnd, UINT id, UINT index)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	ListView_DeleteItem(DlgItem(hWnd, id), index);

	i = LvGetSelected(hWnd, id);
	if (i != INFINITE)
	{
		LvSelect(hWnd, id, i);
	}
}

// 項目からデータを取得する
void *LvGetParam(HWND hWnd, UINT id, UINT index)
{
	return LvGetParamEx(hWnd, id, index, 0);
}
void *LvGetParamEx(HWND hWnd, UINT id, UINT index, UINT subitem)
{
	LVITEM t;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}
	if (index == INFINITE)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_PARAM;
	t.iItem = index;
	t.iSubItem = subitem;

	if (ListView_GetItem(DlgItem(hWnd, id), &t) == false)
	{
		return NULL;
	}

	return (void *)t.lParam;
}

// 項目の文字列を取得する
wchar_t *LvGetStr(HWND hWnd, UINT id, UINT index, UINT pos)
{
	wchar_t *tmp;
	UINT size;
	LVITEMW t;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}
	if (MsIsNt() == false)
	{
		char *s = LvGetStrA(hWnd, id, index, pos);
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

	size = 65536;
	tmp = Malloc(size);

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.iItem = index;
	t.iSubItem = pos;
	t.pszText = tmp;
	t.cchTextMax = size;

	if (SendMsg(hWnd, id, LVM_GETITEMTEXTW, index, (LPARAM)&t) <= 0)
	{
		Free(tmp);
		return UniCopyStr(L"");
	}
	else
	{
		wchar_t *ret = UniCopyStr(tmp);
		Free(tmp);
		return ret;
	}
}
char *LvGetStrA(HWND hWnd, UINT id, UINT index, UINT pos)
{
	char *tmp;
	UINT size;
	LVITEM t;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	size = 65536;
	tmp = Malloc(size);

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.iItem = index;
	t.iSubItem = pos;
	t.pszText = tmp;
	t.cchTextMax = size;

	if (SendMsg(hWnd, id, LVM_GETITEMTEXT, index, (LPARAM)&t) <= 0)
	{
		Free(tmp);
		return CopyStr("");
	}
	else
	{
		char *ret = CopyStr(tmp);
		Free(tmp);
		return ret;
	}
}

// スタイルを設定する
void LvSetStyle(HWND hWnd, UINT id, UINT style)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if ((ListView_GetExtendedListViewStyle(DlgItem(hWnd, id)) & style) == 0)
	{
		ListView_SetExtendedListViewStyleEx(DlgItem(hWnd, id), style, style);
	}
}

// スタイルを削除する
void LvRemoveStyle(HWND hWnd, UINT id, UINT style)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if ((ListView_GetExtendedListViewStyle(DlgItem(hWnd, id)) & style) != 0)
	{
		ListView_SetExtendedListViewStyleEx(DlgItem(hWnd, id), style, 0);
	}
}

// 項目の選択を反転する
void LvSwitchSelect(HWND hWnd, UINT id)
{
	UINT i, num;
	bool *states;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	num = LvNum(hWnd, id);
	states = ZeroMalloc(sizeof(bool) * num);

	i = INFINITE;
	while (true)
	{
		i = LvGetNextMasked(hWnd, id, i);
		if (i == INFINITE)
		{
			break;
		}

		states[i] = true;
	}

	for (i = 0;i < num;i++)
	{
		if (states[i] == false)
		{
			ListView_SetItemState(DlgItem(hWnd, id), i, LVIS_SELECTED, LVIS_SELECTED);
		}
		else
		{
			ListView_SetItemState(DlgItem(hWnd, id), i, 0, LVIS_SELECTED);
		}
	}

	Free(states);
}

// すべての項目を選択する
void LvSelectAll(HWND hWnd, UINT id)
{
	UINT i, num;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	num = LvNum(hWnd, id);
	for (i = 0;i < num;i++)
	{
		ListView_SetItemState(DlgItem(hWnd, id), i, LVIS_SELECTED, LVIS_SELECTED);
	}
}

// 項目を選択する
void LvSelect(HWND hWnd, UINT id, UINT index)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (index == INFINITE)
	{
		UINT i, num;
		// すべて選択解除する
		num = LvNum(hWnd, id);
		for (i = 0;i < num;i++)
		{
			ListView_SetItemState(DlgItem(hWnd, id), i, 0, LVIS_SELECTED);
		}
	}
	else
	{
		// 選択する
		ListView_SetItemState(DlgItem(hWnd, id), index, LVIS_FOCUSED | LVIS_SELECTED, LVIS_FOCUSED | LVIS_SELECTED);
		ListView_EnsureVisible(DlgItem(hWnd, id), index, true);
	}
}

// 証明書情報を表示する
void PrintCertInfo(HWND hWnd, CERT_DLG *p)
{
	X *x;
	char *serial_tmp;
	UINT serial_size;
	wchar_t *wchar_tmp;
	wchar_t tmp[1024 * 5];
	UCHAR md5[MD5_SIZE];
	UCHAR sha1[SHA1_SIZE];
	char *s_tmp;
	K *k;
	// 引数チェック
	if (p == NULL || hWnd == NULL)
	{
		return;
	}

	x = p->x;

	// シリアル番号
	if (x->serial != NULL)
	{
		serial_size = x->serial->size * 3 + 1;
		serial_tmp = ZeroMalloc(serial_size);
		BinToStrEx(serial_tmp, serial_size, x->serial->data, x->serial->size);
		wchar_tmp = CopyStrToUni(serial_tmp);
		Free(serial_tmp);
	}
	else
	{
		wchar_tmp = CopyUniStr(_UU("CERT_NO_SERIAL"));
	}
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_SERIAL"), wchar_tmp);

	// 発行者
	GetAllNameFromName(tmp, sizeof(tmp), x->issuer_name);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_ISSUER"), tmp);

	// サブジェクト
	GetAllNameFromName(tmp, sizeof(tmp), x->subject_name);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_SUBJECT"), tmp);

	// 有効期限の開始
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notBefore), NULL);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_NOT_BEFORE"), tmp);

	// 有効期限の終了
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notAfter), NULL);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_NOT_AFTER"), tmp);

	// ビット数
	if (x->is_compatible_bit)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CERT_BITS_FORMAT"), x->bits);
		LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_BITS"), tmp);
	}

	// 公開鍵
	k = GetKFromX(x);
	if (k != NULL)
	{
		BUF *b = KToBuf(k, false, NULL);
		s_tmp = CopyBinToStrEx(b->Buf, b->Size);
		StrToUni(tmp, sizeof(tmp), s_tmp);
		Free(s_tmp);
		LvInsert(hWnd, L_CERTINFO, ICO_KEY, NULL, 2, _UU("CERT_PUBLIC_KEY"), tmp);
		FreeBuf(b);
	}
	FreeK(k);

	GetXDigest(x, md5, false);
	GetXDigest(x, sha1, true);

	// ダイジェスト (MD5)
	s_tmp = CopyBinToStrEx(md5, sizeof(md5));
	StrToUni(tmp, sizeof(tmp), s_tmp);
	Free(s_tmp);
	LvInsert(hWnd, L_CERTINFO, ICO_KEY, NULL, 2, _UU("CERT_DIGEST_MD5"), tmp);

	// ダイジェスト (SHA-1)
	s_tmp = CopyBinToStrEx(sha1, sizeof(sha1));
	StrToUni(tmp, sizeof(tmp), s_tmp);
	Free(s_tmp);
	LvInsert(hWnd, L_CERTINFO, ICO_KEY, NULL, 2, _UU("CERT_DIGEST_SHA1"), tmp);

	Free(wchar_tmp);

	LvSelect(hWnd, L_CERTINFO, 0);
}

// 表示の更新
void CertDlgUpdate(HWND hWnd, CERT_DLG *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_CERTINFO) == false)
	{
		SetText(hWnd, E_DETAIL, L"");
	}
	else
	{
		UINT i = LvGetSelected(hWnd, L_CERTINFO);
		wchar_t *tmp = LvGetStr(hWnd, L_CERTINFO, i, 1);
		SetText(hWnd, E_DETAIL, tmp);
		Free(tmp);
	}
}

// 証明書の保存
void CertDlgSave(HWND hWnd, CERT_DLG *p)
{
	wchar_t *name;
	X *x;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// 保存
	name = SaveDlg(hWnd, _UU("DLG_CERT_FILES"), _UU("DLG_SAVE_CERT"), NULL, L".cer");
	x = p->x;
	if (name != NULL)
	{
		char str[MAX_SIZE];
		UniToStr(str, sizeof(str), name);
		if (XToFile(x, str, true))
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("DLG_CERT_SAVE_OK"));
		}
		else
		{
			MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_CERT_SAVE_ERROR"));
		}
		Free(name);
	}
}

// 証明書表示ダイアログプロシージャ
UINT CertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CERT_DLG *p = (CERT_DLG *)param;
	X *x;
	wchar_t tmp[MAX_SIZE];
	NMHDR *n;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_CERT);
		x = p->x;
		GetAllNameFromNameEx(tmp, sizeof(tmp), x->subject_name);
		SetText(hWnd, E_SUBJECT, tmp);
		GetAllNameFromNameEx(tmp, sizeof(tmp), x->issuer_name);
		SetText(hWnd, E_ISSUER, tmp);
		GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notAfter), NULL);
		SetText(hWnd, E_EXPIRES, tmp);
		SetFont(hWnd, E_SUBJECT, Font(0, 1));
		SetFont(hWnd, E_ISSUER, Font(0, 1));
		SetFont(hWnd, E_EXPIRES, Font(0, 1));
		SetIcon(hWnd, B_PARENT, ICO_CERT);
		if (x->root_cert)
		{
			// ルート証明書
			Hide(hWnd, S_WARNING_ICON);
			SetText(hWnd, S_PARENT, _UU("CERT_ROOT"));
			Hide(hWnd, B_PARENT);
			Hide(hWnd, S_PARENT_BUTTON_STR);
		}
		else if (p->issuer_x != NULL)
		{
			// 親証明書がある
			Hide(hWnd, S_WARNING_ICON);
		}
		else
		{
			// 親証明書が無い
			Hide(hWnd, S_CERT_ICON);
			Hide(hWnd, B_PARENT);
			Hide(hWnd, S_PARENT_BUTTON_STR);
			SetText(hWnd, S_PARENT, _UU("CERT_NOT_FOUND"));
			if (p->ManagerMode)
			{
				Hide(hWnd, IDC_STATIC1);
				Hide(hWnd, S_PARENT);
				Hide(hWnd, S_WARNING_ICON);
				Hide(hWnd, S_CERT_ICON);
				Hide(hWnd, B_PARENT);
				Hide(hWnd, S_PARENT_BUTTON_STR);
			}
		}


		LvInit(hWnd, L_CERTINFO);
		LvInsertColumn(hWnd, L_CERTINFO, 0, _UU("CERT_LV_C1"), 130);
		LvInsertColumn(hWnd, L_CERTINFO, 1, _UU("CERT_LV_C2"), 250);

		PrintCertInfo(hWnd, p);
		Focus(hWnd, L_CERTINFO);

		CertDlgUpdate(hWnd, p);

		if (p->ManagerMode)
		{
			Show(hWnd, B_SAVE);
		}
		else
		{
			// セキュリティのため非表示にする
			Hide(hWnd, B_SAVE);
		}

		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		case B_PARENT:
			CertDlg(hWnd, p->issuer_x, NULL, p->ManagerMode);
			break;
		case B_SAVE:
			// ファイルに保存
			CertDlgSave(hWnd, p);
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_CERTINFO:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				CertDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;
	}

	LvSortHander(hWnd, msg, wParam, lParam, L_CERTINFO);

	return 0;
}

// 証明書表示ダイアログ
void CertDlg(HWND hWnd, X *x, X *issuer_x, bool manager)
{
	CERT_DLG p;
	// 引数チェック
	if (x == NULL)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.x = x;
	if (CompareX(x, issuer_x) == false)
	{
		p.issuer_x = issuer_x;
	}
	p.ManagerMode = manager;
	Dialog(hWnd, D_CERT, CertDlgProc, &p);
}

// ステータスウインドウダイアログ
UINT StatusPrinterWindowDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	STATUS_WINDOW_PARAM *p = (STATUS_WINDOW_PARAM *)param;
	PACK *pack;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// 初期化
		SetIcon(hWnd, 0, ICO_SERVER_ONLINE);
		RemoveExStyle(hWnd, 0, WS_EX_APPWINDOW);
		p->hWnd = hWnd;
		NoticeThreadInit(p->Thread);
		FormatText(hWnd, 0, p->AccountName);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			// キャンセルボタン
			Close(hWnd);
			break;
		}

		break;

	case WM_APP + 1:
		// 文字列を設定
		SetText(hWnd, S_STATUS, (wchar_t *)lParam);
		break;

	case WM_APP + 2:
		// このウインドウを閉じる
		EndDialog(hWnd, false);
		break;

	case WM_CLOSE:
		// セッションを終了する
		pack = NewPack();
		SendPack(p->Sock, pack);
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// ステータスウインドウ制御用スレッド
void StatusPrinterWindowThread(THREAD *thread, void *param)
{
	STATUS_WINDOW_PARAM *p = (STATUS_WINDOW_PARAM *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	p->Thread = thread;
	DialogEx2(NULL, D_STATUS, StatusPrinterWindowDlg, p, true, true);

	Free(p);
}

// ステータスウインドウにメッセージを表示する
void StatusPrinterWindowPrint(STATUS_WINDOW *sw, wchar_t *str)
{
	// 引数チェック
	if (sw == NULL)
	{
		return;
	}

	SendMessage(sw->hWnd, WM_APP + 1, 0, (LPARAM)str);
}

// ステータスウインドウの終了と解放
void StatusPrinterWindowStop(STATUS_WINDOW *sw)
{
	// 引数チェック
	if (sw == NULL)
	{
		return;
	}

	// 停止メッセージを送信
	SendMessage(sw->hWnd, WM_APP + 2, 0, 0);

	// スレッド停止まで待機
	WaitThread(sw->Thread, INFINITE);

	// メモリ解放
	ReleaseThread(sw->Thread);
	Free(sw);
}

// ステータスウインドウの初期化
STATUS_WINDOW *StatusPrinterWindowStart(SOCK *s, wchar_t *account_name)
{
	STATUS_WINDOW_PARAM *p;
	STATUS_WINDOW *sw;
	THREAD *t;
	// 引数チェック
	if (s == NULL || account_name == NULL)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(STATUS_WINDOW_PARAM));
	p->Sock = s;
	UniStrCpy(p->AccountName, sizeof(p->AccountName), account_name);

	// スレッド作成
	t = NewThread(StatusPrinterWindowThread, p);
	WaitThreadInit(t);

	sw = ZeroMalloc(sizeof(STATUS_WINDOW));
	sw->hWnd = p->hWnd;
	sw->Thread = t;

	return sw;
}

// 文字列を取得
wchar_t *LbGetStr(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	return GetText(hWnd, id);
}

// 文字列検索
UINT LbFindStr(HWND hWnd, UINT id, wchar_t *str)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, LB_FINDSTRING, -1, (LPARAM)str);

	return ret;
}

// 項目数を取得
UINT LbNum(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, LB_GETCOUNT, 0, 0);
}

// 文字列追加
UINT LbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data)
{
	UINT ret;

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		ret = LbAddStrA(hWnd, id, s, data);
		Free(s);
		return ret;
	}

	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, LB_ADDSTRING, 0, (LPARAM)str);
	SendMsg(hWnd, id, LB_SETITEMDATA, ret, (LPARAM)data);

	if (LbNum(hWnd, id) == 1)
	{
		LbSelectIndex(hWnd, id, 0);
	}

	return ret;
}
UINT LbAddStrA(HWND hWnd, UINT id, char *str, UINT data)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, LB_ADDSTRING, 0, (LPARAM)str);
	SendMsg(hWnd, id, LB_SETITEMDATA, ret, (LPARAM)data);

	if (LbNum(hWnd, id) == 1)
	{
		LbSelectIndex(hWnd, id, 0);
	}

	return ret;
}

// 文字列挿入
UINT LbInsertStr(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT data)
{
	UINT ret;

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		ret = LbInsertStrA(hWnd, id, index, s, data);
		Free(s);
		return ret;
	}

	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, LB_INSERTSTRING, index, (LPARAM)str);
	SendMsg(hWnd, id, LB_SETITEMDATA, ret, (LPARAM)data);

	if (LbNum(hWnd, id) == 1)
	{
		LbSelect(hWnd, id, 0);
	}

	return ret;
}
UINT LbInsertStrA(HWND hWnd, UINT id, UINT index, char *str, UINT data)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, LB_INSERTSTRING, index, (LPARAM)str);
	SendMsg(hWnd, id, LB_SETITEMDATA, ret, (LPARAM)data);

	if (LbNum(hWnd, id) == 1)
	{
		LbSelect(hWnd, id, 0);
	}

	return ret;
}

// すべて削除
void LbReset(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, LB_RESETCONTENT, 0, 0);
}

// インデックスを指定して選択
void LbSelectIndex(HWND hWnd, UINT id, UINT index)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, LB_SETCURSEL, index, 0);
}

// データを取得
UINT LbGetData(HWND hWnd, UINT id, UINT index)
{
	// 引数チェック
	if (hWnd == NULL || index == INFINITE)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, LB_GETITEMDATA, index, 0);
}

// データを検索
UINT LbFindData(HWND hWnd, UINT id, UINT data)
{
	UINT i, num;
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	num = LbNum(hWnd, id);
	if (num == INFINITE)
	{
		return INFINITE;
	}

	for (i = 0;i < num;i++)
	{
		if (LbGetData(hWnd, id, i) == data)
		{
			return i;
		}
	}

	return INFINITE;
}

// アイテムの高さを設定
void LbSetHeight(HWND hWnd, UINT id, UINT value)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, LB_SETITEMHEIGHT, 0, value);
}

// データを指定して検索
void LbSelect(HWND hWnd, UINT id, int data)
{
	UINT index;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (data == INFINITE)
	{
		// 最初の項目を取得
		LbSelectIndex(hWnd, id, 0);
		return;
	}

	index = LbFindData(hWnd, id, data);
	if (index == INFINITE)
	{
		// 発見できなかった
		return;
	}

	// 選択する
	LbSelectIndex(hWnd, id, index);
}

// 現在選択されている項目を取得
UINT LbGetSelectIndex(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, LB_GETCURSEL, 0, 0);
}

// 現在選択されている値を取得
UINT LbGetSelect(HWND hWnd, UINT id)
{
	UINT index;
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	index = LbGetSelectIndex(hWnd, id);
	if (index == INFINITE)
	{
		return INFINITE;
	}

	return LbGetData(hWnd, id, index);
}

// パスワード入力ダイアログ状態変化
void PasswordDlgProcChange(HWND hWnd, UI_PASSWORD_DLG *p)
{
	bool b;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	b = true;
	if (IsEmpty(hWnd, E_USERNAME))
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);

	p->StartTick = Tick64();
	if (p->RetryIntervalSec)
	{
		KillTimer(hWnd, 1);
		Hide(hWnd, P_PROGRESS);
		Hide(hWnd, S_COUNTDOWN);
	}
}

// 文字列を取得
wchar_t *CbGetStr(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	return GetText(hWnd, id);
}

// 文字列検索
UINT CbFindStr(HWND hWnd, UINT id, wchar_t *str)
{
	UINT ret;
	if (MsIsNt() == false)
	{
		char *tmp = CopyUniToStr(str);
		ret = CbFindStr9xA(hWnd, id, tmp);
		Free(tmp);
		return ret;
	}
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_FINDSTRINGEXACT, -1, (LPARAM)str);

	return ret;
}
UINT CbFindStr9xA(HWND hWnd, UINT id, char *str)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_FINDSTRINGEXACT, -1, (LPARAM)str);

	return ret;
}

// 項目数を取得
UINT CbNum(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, CB_GETCOUNT, 0, 0);
}

// 文字列追加
UINT CbAddStrA(HWND hWnd, UINT id, char *str, UINT data)
{
	wchar_t *tmp;
	UINT ret;
	// 引く数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}
	tmp = CopyStrToUni(str);
	ret = CbAddStr(hWnd, id, tmp, data);
	Free(tmp);
	return ret;
}
UINT CbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data)
{
	UINT ret;
	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		ret = CbAddStr9xA(hWnd, id, s, data);
		Free(s);
		return ret;
	}
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_ADDSTRING, 0, (LPARAM)str);
	SendMsg(hWnd, id, CB_SETITEMDATA, ret, (LPARAM)data);

	if (CbNum(hWnd, id) == 1)
	{
		wchar_t tmp[MAX_SIZE];
		GetTxt(hWnd, id, tmp, sizeof(tmp));
		if (UniStrLen(tmp) == 0)
		{
			CbSelectIndex(hWnd, id, 0);
		}
	}

	return ret;
}
UINT CbAddStr9xA(HWND hWnd, UINT id, char *str, UINT data)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_ADDSTRING, 0, (LPARAM)str);
	SendMsg(hWnd, id, CB_SETITEMDATA, ret, (LPARAM)data);

	if (CbNum(hWnd, id) == 1)
	{
		wchar_t tmp[MAX_SIZE];
		GetTxt(hWnd, id, tmp, sizeof(tmp));
		if (UniStrLen(tmp) == 0)
		{
			CbSelectIndex(hWnd, id, 0);
		}
	}

	return ret;
}

// 文字列挿入
UINT CbInsertStrA(HWND hWnd, UINT id, UINT index, char *str, UINT data)
{
	wchar_t *tmp;
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}
	tmp = CopyStrToUni(str);
	ret = CbInsertStr(hWnd, id, index, tmp, data);
	Free(tmp);
	return ret;
}
UINT CbInsertStr(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT data)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		ret = CbInsertStr9xA(hWnd, id, index, s, data);
		Free(s);
		return ret;
	}

	ret = SendMsg(hWnd, id, CB_INSERTSTRING, index, (LPARAM)str);
	SendMsg(hWnd, id, CB_SETITEMDATA, ret, (LPARAM)data);

	if (CbNum(hWnd, id) == 1)
	{
		CbSelect(hWnd, id, 0);
	}

	return ret;
}
UINT CbInsertStr9xA(HWND hWnd, UINT id, UINT index, char *str, UINT data)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_INSERTSTRING, index, (LPARAM)str);
	SendMsg(hWnd, id, CB_SETITEMDATA, ret, (LPARAM)data);

	if (CbNum(hWnd, id) == 1)
	{
		CbSelect(hWnd, id, 0);
	}

	return ret;
}

// すべて削除
void CbReset(HWND hWnd, UINT id)
{
	wchar_t *s;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	s = GetText(hWnd, id);

	SendMsg(hWnd, id, CB_RESETCONTENT, 0, 0);

	if (s != NULL)
	{
		SetText(hWnd, id, s);
		Free(s);
	}
}

// インデックスを指定して選択
void CbSelectIndex(HWND hWnd, UINT id, UINT index)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, CB_SETCURSEL, index, 0);
}

// データを取得
UINT CbGetData(HWND hWnd, UINT id, UINT index)
{
	// 引数チェック
	if (hWnd == NULL || index == INFINITE)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, CB_GETITEMDATA, index, 0);
}

// データを検索
UINT CbFindData(HWND hWnd, UINT id, UINT data)
{
	UINT i, num;
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	num = CbNum(hWnd, id);
	if (num == INFINITE)
	{
		return INFINITE;
	}

	for (i = 0;i < num;i++)
	{
		if (CbGetData(hWnd, id, i) == data)
		{
			return i;
		}
	}

	return INFINITE;
}

// アイテムの高さを設定
void CbSetHeight(HWND hWnd, UINT id, UINT value)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, CB_SETITEMHEIGHT, 0, value);
}

// データを指定して検索
void CbSelect(HWND hWnd, UINT id, int data)
{
	UINT index;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (data == INFINITE)
	{
		// 最初の項目を取得
		CbSelectIndex(hWnd, id, 0);
		return;
	}

	index = CbFindData(hWnd, id, data);
	if (index == INFINITE)
	{
		// 発見できなかった
		return;
	}

	// 選択する
	CbSelectIndex(hWnd, id, index);
}

// 現在選択されている項目を取得
UINT CbGetSelectIndex(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, CB_GETCURSEL, 0, 0);
}

// 現在選択されている値を取得
UINT CbGetSelect(HWND hWnd, UINT id)
{
	UINT index;
	// 引数チェック
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	index = CbGetSelectIndex(hWnd, id);
	if (index == INFINITE)
	{
		return INFINITE;
	}

	return CbGetData(hWnd, id, index);
}

// OK ボタンが押された
void PasswordDlgOnOk(HWND hWnd, UI_PASSWORD_DLG *p)
{
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_USERNAME, p->Username, sizeof(p->Username));
	GetTxtA(hWnd, E_PASSWORD, p->Password, sizeof(p->Password));
	p->Type = CbGetSelect(hWnd, C_TYPE);

	if (p->ShowNoSavePassword)
	{
		p->NoSavePassword = IsChecked(hWnd, R_NO_SAVE_PASSWORD);
	}

	EndDialog(hWnd, true);
}

// パスワード入力ダイアログプロシージャ
UINT PasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_PASSWORD_DLG *p = (UI_PASSWORD_DLG *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_KEY);
		CbSetHeight(hWnd, C_TYPE, 18);
		if (p->ServerName != NULL)
		{
			FormatText(hWnd, 0, p->ServerName);
		}
		else
		{
			SetText(hWnd, 0, _UU("PW_LOGIN_DLG_TITLE"));
		}

		if (p->ProxyServer == false)
		{
			FormatText(hWnd, S_TITLE, p->ServerName == NULL ? "" : p->ServerName);
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			UniFormat(tmp, sizeof(tmp), _UU("PW_MSG_PROXY"), p->ServerName == NULL ? "" : p->ServerName);
			SetText(hWnd, S_TITLE, tmp);
		}

		// 接続方法の列挙
		SendMsg(hWnd, C_TYPE, CBEM_SETUNICODEFORMAT, true, 0);

		if (StrCmpi(p->Username, WINUI_PASSWORD_NULL_USERNAME) != 0)
		{
			SetTextA(hWnd, E_USERNAME, p->Username);
			SetTextA(hWnd, E_PASSWORD, p->Password);
		}
		else
		{
			p->RetryIntervalSec = 0;
			SetTextA(hWnd, E_USERNAME, "");
			SetTextA(hWnd, E_PASSWORD, "");
		}

		if (p->AdminMode == false)
		{
			if (p->ProxyServer == false)
			{
				CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_1"), CLIENT_AUTHTYPE_PASSWORD);
				CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_2"), CLIENT_AUTHTYPE_PLAIN_PASSWORD);
			}
			else
			{
				CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_PROXY"), 0);
				Disable(hWnd, C_TYPE);
			}

			CbSelect(hWnd, C_TYPE, p->Type);
		}
		else
		{
			CbAddStr(hWnd, C_TYPE, _UU("SM_PASSWORD_TYPE_STR"), 0);
			Disable(hWnd, C_TYPE);
			SetTextA(hWnd, E_USERNAME, "Administrator");
			Disable(hWnd, E_USERNAME);
		}

		if (IsEmpty(hWnd, E_USERNAME))
		{
			FocusEx(hWnd, E_USERNAME);
		}
		else
		{
			FocusEx(hWnd, E_PASSWORD);
		}
		LimitText(hWnd, E_USERNAME, MAX_USERNAME_LEN);
		LimitText(hWnd, E_PASSWORD, MAX_PASSWORD_LEN);

		PasswordDlgProcChange(hWnd, p);

		if (p->RetryIntervalSec != 0)
		{
			SetTimer(hWnd, 1, 50, NULL);
			FormatText(hWnd, S_COUNTDOWN, p->RetryIntervalSec);
			Show(hWnd, S_COUNTDOWN);
			Show(hWnd, P_PROGRESS);
			SetRange(hWnd, P_PROGRESS, 0, p->RetryIntervalSec * 1000);
		}
		else
		{
			Hide(hWnd, S_COUNTDOWN);
			Hide(hWnd, P_PROGRESS);
		}

		if (p->ShowNoSavePassword)
		{
			Show(hWnd, R_NO_SAVE_PASSWORD);
			Check(hWnd, R_NO_SAVE_PASSWORD, p->NoSavePassword);
		}
		else
		{
			Hide(hWnd, R_NO_SAVE_PASSWORD);
		}

		p->StartTick = Tick64();

		if (p->CancelEvent != NULL)
		{
			SetTimer(hWnd, 2, 50, NULL);
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (p->RetryIntervalSec != 0)
			{
				wchar_t tmp[MAX_SIZE];
				UINT64 end, now, start;
				start = p->StartTick;
				end = p->StartTick + (UINT64)(p->RetryIntervalSec * 1000);
				now = Tick64();

				if (now <= end)
				{
					UniFormat(tmp, sizeof(tmp), _UU("PW_RETRYCOUNT"), (UINT)((end - now) / 1000));
					SetText(hWnd, S_COUNTDOWN, tmp);
					SetPos(hWnd, P_PROGRESS, (UINT)(now - start));
				}
				else
				{
					EndDialog(hWnd, true);
				}
			}
			break;

		case 2:
			if (p->CancelEvent != NULL)
			{
				// 終了イベントを待機する
				HANDLE hEvent = (HANDLE)p->CancelEvent->pData;
				UINT ret = WaitForSingleObject(hEvent, 0);
				if (ret != WAIT_TIMEOUT)
				{
					// 強制終了イベントがセットされた
					Close(hWnd);
				}
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			PasswordDlgOnOk(hWnd, p);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		switch (HIWORD(wParam))
		{
		case EN_CHANGE:
			switch (LOWORD(wParam))
			{
			case E_USERNAME:
			case E_PASSWORD:
				PasswordDlgProcChange(hWnd, p);
				break;
			}
			break;
		case CBN_SELCHANGE:
			switch (LOWORD(wParam))
			{
			case C_TYPE:
				PasswordDlgProcChange(hWnd, p);
				if (IsEmpty(hWnd, E_USERNAME))
				{
					FocusEx(hWnd, E_USERNAME);
				}
				else
				{
					FocusEx(hWnd, E_PASSWORD);
				}
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// プログレスバーの位置を設定
void SetPos(HWND hWnd, UINT id, UINT pos)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, PBM_SETPOS, pos, 0);
}

// プログレスバーの範囲を設定
void SetRange(HWND hWnd, UINT id, UINT start, UINT end)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, PBM_SETRANGE32, start, end);
}

// パスワード入力ダイアログ
bool PasswordDlg(HWND hWnd, UI_PASSWORD_DLG *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return false;
	}

	p->StartTick = Tick64();

	return Dialog(hWnd, D_PASSWORD, PasswordDlgProc, p);
}

// パスフレーズ入力ダイアログ
bool PassphraseDlg(HWND hWnd, char *pass, UINT pass_size, BUF *buf, bool p12)
{
	PASSPHRASE_DLG p;
	// 引数チェック
	if (pass == NULL || buf == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(PASSPHRASE_DLG));

	p.buf = buf;
	p.p12 = p12;

	// まず暗号化されているかどうかを調べる
	if (p12 == false)
	{
		// 秘密鍵
		if (IsEncryptedK(buf, true) == false)
		{
			// 暗号化されていない
			StrCpy(pass, pass_size, "");
			return true;
		}
	}
	else
	{
		// PKCS#12
		P12 *p12 = BufToP12(buf);
		if (p12 == NULL)
		{
			// 不明な形式だが暗号化されていない
			StrCpy(pass, pass_size, "");
			return true;
		}

		if (IsEncryptedP12(p12) == false)
		{
			// 暗号化されていない
			StrCpy(pass, pass_size, "");
			FreeP12(p12);
			return true;
		}
		FreeP12(p12);
	}

	// ダイアログ表示
	if (Dialog(hWnd, D_PASSPHRASE, PassphraseDlgProc, &p) == false)
	{
		// キャンセル
		return false;
	}

	StrCpy(pass, pass_size, p.pass);

	return true;
}

// WM_COMMAND ハンドラ
void PassphraseDlgProcCommand(HWND hWnd, PASSPHRASE_DLG *p)
{
	char *pass;
	bool ok;
	// 引数チェック
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	pass = GetTextA(hWnd, E_PASSPHRASE);
	if (pass == NULL)
	{
		return;
	}

	ok = false;

	if (p->p12 == false)
	{
		K *k;
		k = BufToK(p->buf, true, true, pass);
		if (k != NULL)
		{
			ok = true;
			FreeK(k);
		}
	}
	else
	{
		X *x;
		K *k;
		P12 *p12;
		p12 = BufToP12(p->buf);
		if (p12 != NULL)
		{
			if (ParseP12(p12, &x, &k, pass))
			{
				FreeX(x);
				FreeK(k);
				ok = true;
			}
			FreeP12(p12);
		}
	}

	Free(pass);

	SetEnable(hWnd, IDOK, ok);
}

// パスフレーズ入力ダイアログプロシージャ
UINT PassphraseDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	PASSPHRASE_DLG *p = (PASSPHRASE_DLG *)param;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		PassphraseDlgProcCommand(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_PASSPHRASE, p->pass, sizeof(p->pass));
			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}

		switch (LOWORD(wParam))
		{
		case E_PASSPHRASE:
			PassphraseDlgProcCommand(hWnd, p);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// PKCS ユーティリティ
void PkcsUtil()
{
	InitWinUi(_UU("PKCS_UTIL_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));
	Dialog(NULL, D_PKCSUTIL, PkcsUtilProc, NULL);
	FreeWinUi();
}

// PKCS 書き込み
void PkcsUtilWrite(HWND hWnd)
{
	wchar_t *filename;
	BUF *in_buf;
	char filename_ansi[MAX_SIZE];
	char pass[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	filename = OpenDlg(hWnd, _UU("DLG_PKCS12_FILTER"), _UU("PKCS_UTIL_SAVEDLG_TITLE"));
	if (filename == NULL)
	{
		return;
	}

	UniToStr(filename_ansi, sizeof(filename_ansi), filename);

	in_buf = ReadDump(filename_ansi);

	if (in_buf == NULL)
	{
		MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("PKCS_UTIL_READ_ERROR"), filename);
	}
	else
	{
		if (PassphraseDlg(hWnd, pass, sizeof(pass), in_buf, true))
		{
			P12 *p12 = BufToP12(in_buf);
			if (p12 == NULL)
			{
				MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("PKCS_UTIL_BAD_FILE"));
			}
			else
			{
				X *x = NULL;
				K *k = NULL;
				BUF *b;
				ParseP12(p12, &x, &k, pass);
				FreeP12(p12);
				p12 = NewP12(x, k, NULL);
				FreeX(x);
				FreeK(k);
				b = P12ToBuf(p12);
				FreeP12(p12);
				if (b != NULL)
				{
					// バッチ処理
					WINUI_SECURE_BATCH batch[] =
					{
						{WINUI_SECURE_WRITE_DATA, _SS("PKCS_UTIL_SECA_FILENAME"), false,
							b, NULL, NULL, NULL, NULL, NULL},
					};

					if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), 2, 0))
					{
						MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("PKCS_UTIL_WRITE_OK_MSG"), filename);
					}
				}
				FreeBuf(b);
			}
		}

		FreeBuf(in_buf);
	}

	Free(filename);
}

// PKCS 消去
void PkcsUtilErase(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
		_UU("PKCS_MAKE_SURE")) == IDYES)
	{
		// バッチ処理
		WINUI_SECURE_BATCH batch[] =
		{
			{WINUI_SECURE_DELETE_OBJECT, _SS("PKCS_UTIL_SECA_FILENAME"), false,
				NULL, NULL, NULL, NULL, NULL, NULL},
		};

		if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), 2, 0))
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("PKCS_UTIL_DELETE_OK_MSG"));
		}
	}
}

// PKCS ユーティリティ ダイアログ
UINT PkcsUtilProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		DlgFont(hWnd, S_TITLE, 12, true);
		SetIcon(hWnd, 0, ICO_CERT);
		SetFont(hWnd, S_COPYRIGHT, GetFont("Arial", 8, false, false, false, false));
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_WRITE:
			PkcsUtilWrite(hWnd);
			break;

		case B_ERASE:
			PkcsUtilErase(hWnd);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// [ファイルを保存する] ダイアログ
wchar_t *SaveDlg(HWND hWnd, wchar_t *filter, wchar_t *title, wchar_t *default_name, wchar_t *default_ext)
{
	wchar_t *filter_str;
	wchar_t tmp[MAX_SIZE];
	OPENFILENAMEW o;

	if (MsIsNt() == false)
	{
		char *ret, *s1, *s2, *s3, *s4;
		wchar_t *wr;
		s1 = CopyUniToStr(filter);
		s2 = CopyUniToStr(title);
		s3 = CopyUniToStr(default_name);
		s4 = CopyUniToStr(default_ext);
		ret = SaveDlgA(hWnd, s1, s2, s3, s4);
		Free(s1);
		Free(s2);
		Free(s3);
		Free(s4);
		wr = CopyStrToUni(ret);
		Free(ret);
		return wr;
	}

	// 引数チェック
	if (filter == NULL)
	{
		filter = _UU("DLG_ALL_FILES");
	}

	filter_str = MakeFilter(filter);

	Zero(&o, sizeof(o));
	Zero(tmp, sizeof(tmp));

	if (default_name != NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), default_name);
	}

	o.lStructSize = sizeof(o);
	
	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400W;
	}

	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandleA(NULL);
	o.lpstrFile = tmp;
	o.lpstrTitle = title;
	o.lpstrFilter = filter_str;
	o.nMaxFile = sizeof(tmp);
	o.Flags = OFN_OVERWRITEPROMPT;
	o.lpstrDefExt = default_ext;

	if (GetSaveFileNameW(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return UniCopyStr(tmp);
}
char *SaveDlgA(HWND hWnd, char *filter, char *title, char *default_name, char *default_ext)
{
	char *filter_str;
	char tmp[MAX_SIZE];
	OPENFILENAME o;
	// 引数チェック
	if (filter == NULL)
	{
		filter = _SS("DLG_ALL_FILES");
	}

	filter_str = MakeFilterA(filter);

	Zero(&o, sizeof(o));
	Zero(tmp, sizeof(tmp));

	if (default_name != NULL)
	{
		StrCpy(tmp, sizeof(tmp), default_name);
	}

	o.lStructSize = sizeof(o);
	
	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400A;
	}

	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandleA(NULL);
	o.lpstrFile = tmp;
	o.lpstrTitle = title;
	o.lpstrFilter = filter_str;
	o.nMaxFile = sizeof(tmp);
	o.Flags = OFN_OVERWRITEPROMPT;
	o.lpstrDefExt = default_ext;

	if (GetSaveFileName(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return CopyStr(tmp);
}

// [ファイルを開く] ダイアログ
wchar_t *OpenDlg(HWND hWnd, wchar_t *filter, wchar_t *title)
{
	wchar_t *filter_str;
	wchar_t tmp[MAX_SIZE];
	OPENFILENAMEW o;

	if (MsIsNt() == false)
	{
		char *ret;
		char *filter_a;
		char *title_a;
		wchar_t *w;
		filter_a = CopyUniToStr(filter);
		title_a = CopyUniToStr(title);
		ret = OpenDlgA(hWnd, filter_a, title_a);
		Free(filter_a);
		Free(title_a);
		w = CopyStrToUni(ret);
		Free(ret);
		return w;
	}

	// 引数チェック
	if (filter == NULL)
	{
		filter = _UU("DLG_ALL_FILES");
	}

	filter_str = MakeFilter(filter);

	Zero(&o, sizeof(OPENFILENAMEW));
	Zero(tmp, sizeof(tmp));

	o.lStructSize = sizeof(o);


	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400W;
	}


	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandleA(NULL);
	o.lpstrFilter = filter_str;
	o.lpstrFile = tmp;
	o.nMaxFile = sizeof(tmp);
	o.lpstrTitle = title;
	o.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

	if (GetOpenFileNameW(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return UniCopyStr(tmp);
}
char *OpenDlgA(HWND hWnd, char *filter, char *title)
{
	char *filter_str;
	char tmp[MAX_SIZE];
	OPENFILENAME o;
	// 引数チェック
	if (filter == NULL)
	{
		filter = _SS("DLG_ALL_FILES");
	}

	filter_str = MakeFilterA(filter);

	Zero(&o, sizeof(OPENFILENAME));
	Zero(tmp, sizeof(tmp));

	o.lStructSize = sizeof(o);

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400A;
	}

	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandleA(NULL);
	o.lpstrFilter = filter_str;
	o.lpstrFile = tmp;
	o.nMaxFile = sizeof(tmp);
	o.lpstrTitle = title;
	o.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

	if (GetOpenFileName(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return CopyStr(tmp);
}

// フィルタ文字列の生成
wchar_t *MakeFilter(wchar_t *str)
{
	UINT i;
	wchar_t *ret;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(UniStrSize(str) + 32);

	for (i = 0;i < UniStrLen(str);i++)
	{
		if (str[i] == L'|')
		{
			ret[i] = L'\0';
		}
		else
		{
			ret[i] = str[i];
		}
	}

	return ret;
}
char *MakeFilterA(char *str)
{
	UINT i;
	char *ret;
	// 引数チェック
	if (str == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(StrSize(str) + 32);

	for (i = 0;i < StrLen(str);i++)
	{
		if (str[i] == '|')
		{
			ret[i] = '\0';
		}
		else
		{
			ret[i] = str[i];
		}
	}

	return ret;
}

// バッチの実行
bool ExecuteSecureDeviceBatch(HWND hWnd, SECURE *sec, SECURE_DEVICE_THREAD *p, SECURE_DEVICE *dev, WINUI_SECURE_BATCH *batch)
{
	LIST *o;
	void *buf;
	UINT size = 10 * 1024;		// データの最大サイズ
	UINT type = INFINITE;
	// 引数チェック
	if (hWnd == NULL || p == NULL || dev == NULL || batch == NULL || sec == NULL)
	{
		return false;
	}

	switch (batch->Type)
	{
	case WINUI_SECURE_DELETE_CERT:
		type = SEC_X;
		goto DELETE_OBJECT;

	case WINUI_SECURE_DELETE_KEY:
		type = SEC_K;
		goto DELETE_OBJECT;

	case WINUI_SECURE_DELETE_DATA:
		type = SEC_DATA;
		goto DELETE_OBJECT;

	case WINUI_SECURE_DELETE_OBJECT:
		// オブジェクトの削除
DELETE_OBJECT:
		SetText(hWnd, S_STATUS, _UU("SEC_DELETE"));
		if (DeleteSecObjectByName(sec, batch->Name, type) == false)
		{
			p->ErrorMessage = UniCopyStr(_UU("SEC_ERROR_DELETE"));
			return false;
		}
		break;

	case WINUI_SECURE_ENUM_OBJECTS:
		// オブジェクトの列挙
		SetText(hWnd, S_STATUS, _UU("SEC_ENUM"));
		o = EnumSecObject(sec);
		if (o == NULL)
		{
			p->ErrorMessage = UniCopyStr(_UU("SEC_ERROR_ENUM"));
			return false;
		}

		batch->EnumList = o;
		break;

	case WINUI_SECURE_WRITE_DATA:
		// データの書き込み
		SetText(hWnd, S_STATUS, _UU("SEC_WRITE_DATA"));
		if (WriteSecData(sec, batch->Private, batch->Name, batch->InputData->Buf, batch->InputData->Size) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_WRITE_1") : _UU("SEC_ERROR_WRITE_2"));
			return false;
		}
		break;

	case WINUI_SECURE_READ_DATA:
		// データの読み込み
		SetText(hWnd, S_STATUS, _UU("SEC_READ_DATA"));
		buf = MallocEx(size, true);
		size = ReadSecData(sec, batch->Name, buf, size);
		if (size == 0)
		{
			Free(buf);
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_NOT_FOUND_1") : _UU("SEC_ERROR_NOT_FOUND_2"));
			return false;
		}
		batch->OutputData = NewBuf();
		WriteBuf(batch->OutputData, buf, size);
		SeekBuf(batch->OutputData, 0, 0);
		Free(buf);
		break;

	case WINUI_SECURE_WRITE_CERT:
		// 証明書の書き込み
		SetText(hWnd, S_STATUS, _UU("SEC_WRITE_CERT"));
		if (WriteSecCert(sec, batch->Private, batch->Name, batch->InputX) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_WRITE_1") : _UU("SEC_ERROR_WRITE_2"));
			return false;
		}
		break;

	case WINUI_SECURE_READ_CERT:
		// 証明書の読み込み
		SetText(hWnd, S_STATUS, _UU("SEC_READ_CERT"));
		batch->OutputX = ReadSecCert(sec, batch->Name);
		if (batch->OutputX == NULL)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_NOT_FOUND_1") : _UU("SEC_ERROR_NOT_FOUND_2"));
			return false;
		}
		break;

	case WINUI_SECURE_WRITE_KEY:
		// 秘密鍵の書き込み
		SetText(hWnd, S_STATUS, _UU("SEC_WRITE_KEY"));
		if (WriteSecKey(sec, batch->Private, batch->Name, batch->InputK) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_WRITE_1") : _UU("SEC_ERROR_WRITE_2"));
			return false;
		}
		break;

	case WINUI_SECURE_SIGN_WITH_KEY:
		// 署名
		SetText(hWnd, S_STATUS, _UU("SEC_SIGN"));
		if (SignSec(sec, batch->Name, batch->OutputSign, batch->InputData->Buf, batch->InputData->Size) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_SIGN_1") : _UU("SEC_ERROR_SIGN_2"));
			return false;
		}
		break;
	}

	return true;
}

// セキュアデバイス操作をバッチ処理で実行する
void SecureDeviceBatch(HWND hWnd, SECURE *sec, SECURE_DEVICE_THREAD *p, SECURE_DEVICE *dev)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL || p == NULL || dev == NULL || sec == NULL)
	{
		return;
	}

	// 逐次処理を行う
	for (i = 0;i < p->w->num_batch;i++)
	{
		WINUI_SECURE_BATCH *batch = &p->w->batch[i];

		if (ExecuteSecureDeviceBatch(hWnd, sec, p, dev, batch) == false)
		{
			// 1 つでも失敗したら直ちに中断する
			return;
		}
	}

	// すべてのバッチ処理が成功した
	p->Succeed = true;
}

// セキュアデバイス操作を行うスレッド
void SecureDeviceThread(THREAD *t, void *param)
{
	SECURE *sec;
	SECURE_DEVICE_THREAD *p = (SECURE_DEVICE_THREAD *)param;
	SECURE_DEVICE *dev;
	HWND hWnd;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	p->Succeed = false;
	p->ErrorMessage = NULL;

	hWnd = p->hWnd;

	// デバイスを開く
	dev = GetSecureDevice(p->w->device_id);
	SetText(hWnd, S_STATUS, _UU("SEC_OPENING"));
	sec = OpenSec(p->w->device_id);
	if (sec == NULL)
	{
		// デバイスオープン失敗
		if (p->w->device_id != 9)
		{
			p->ErrorMessage = CopyUniFormat(_UU("SEC_ERROR_OPEN_DEVICE"), dev->DeviceName);
		}
		else
		{
			p->ErrorMessage = CopyUniFormat(_UU("SEC_ERROR_OPEN_DEVICEEX"), dev->DeviceName);
		}
	}
	else
	{
		// セッションを開く
		SetText(hWnd, S_STATUS, _UU("SEC_OPEN_SESSION"));
		if (OpenSecSession(sec, 0) == false)
		{
			// セッション初期化失敗
			p->ErrorMessage = CopyUniFormat(_UU("SEC_ERROR_OPEN_SESSION"), dev->DeviceName);
		}
		else
		{
			// ログイン
			SetText(hWnd, S_STATUS, _UU("SEC_LOGIN"));
			if (LoginSec(sec, p->pin) == false)
			{
				// ログイン失敗
				p->ErrorMessage =UniCopyStr(_UU("SEC_ERROR_LOGIN"));
			}
			else
			{
				// バッチ処理メイン
				SetText(hWnd, S_STATUS, _UU("SEC_INIT_BATCH"));
				SecureDeviceBatch(hWnd, sec, p, dev);

				// ログアウト
				SetText(hWnd, S_STATUS, _UU("SEC_LOGOUT"));
				LogoutSec(sec);
			}

			// セッションを閉じる
			SetText(hWnd, S_STATUS, _UU("SEC_CLOSE_SESSION"));
			CloseSecSession(sec);
		}

		// デバイスを閉じる
		SetText(hWnd, S_STATUS, _UU("SEC_CLOSING"));
		CloseSec(sec);
	}

	if (p->Succeed)
	{
		// 成功した場合は 150ms メッセージを表示する (サービス)
		SetText(hWnd, S_STATUS, _UU("SEC_FINISHED"));
		SleepThread(150);
	}

	SendMessage(p->hWnd, WM_APP + 1, 0, 0);
}

// セキュアデバイス操作を開始する
void StartSecureDevice(HWND hWnd, SECURE_DEVICE_WINDOW *w)
{
	SECURE_DEVICE_THREAD *p;
	// 引数チェック
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	// コントロールを無効にする
	EnableSecureDeviceWindowControls(hWnd, false);

	// スレッドを開始する
	p = ZeroMalloc(sizeof(SECURE_DEVICE_THREAD));
	p->w = w;
	p->hWnd = hWnd;
	w->p = p;
	p->pin = GetTextA(hWnd, E_PIN);
	ReleaseThread(NewThread(SecureDeviceThread, p));
}

// セキュアデバイス操作用ウインドウのコントロールを有効・無効化する
void EnableSecureDeviceWindowControls(HWND hWnd, bool enable)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (enable)
	{
		Show(hWnd, S_PIN_CODE);
		Show(hWnd, E_PIN);
		Show(hWnd, S_WARNING);
	}
	else
	{
		Hide(hWnd, S_PIN_CODE);
		Hide(hWnd, E_PIN);
		Hide(hWnd, S_WARNING);
	}

	SetEnable(hWnd, IDOK, enable);
	SetEnable(hWnd, IDCANCEL, enable);
	SetEnable(hWnd, S_TITLE, enable);
	SetEnable(hWnd, S_DEVICE_INFO, enable);
	SetEnable(hWnd, S_INSERT_SECURE, enable);

	if (enable == false)
	{
		DisableClose(hWnd);
		SetText(hWnd, S_STATUS, L"");
		Show(hWnd, S_STATUS);
		PlayAvi(hWnd, A_PROGRESS, true);
	}
	else
	{
		EnableClose(hWnd);
		SetText(hWnd, S_STATUS, L"");
		Hide(hWnd, S_STATUS);
		StopAvi(hWnd, A_PROGRESS);
	}
}

// セキュアデバイス操作用ウインドウプロシージャ
UINT SecureDeviceWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SECURE_DEVICE_WINDOW *w = (SECURE_DEVICE_WINDOW *)param;
	SECURE_DEVICE *dev = GetSecureDevice(w->device_id);

	switch (msg)
	{
	case WM_INITDIALOG:
		if (dev == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SEC_ERROR_INVALID_ID"), w->device_id);
			EndDialog(hWnd, 0);
			break;
		}

		if (IsJPKI(dev->Id))
		{
			// 住基カード
			Hide(hWnd, S_IMAGE);
			Show(hWnd, S_IMAGE2);
			Hide(hWnd, S_IMAGE_TSUKUBA);
		}
		else
		{
			// 普通のカード
			Hide(hWnd, S_IMAGE2);

			if (w->BitmapId != 0)
			{
				// 筑波大学用
				Hide(hWnd, S_IMAGE);
				Show(hWnd, S_IMAGE_TSUKUBA);
			}
			else
			{
				// 一般用
				Show(hWnd, S_IMAGE);
				Hide(hWnd, S_IMAGE_TSUKUBA);
			}
		}

		FormatText(hWnd, 0, dev->Type != SECURE_USB_TOKEN ? _UU("SEC_SMART_CARD") : _UU("SEC_USB_TOKEN"),
			dev->DeviceName);
		FormatText(hWnd, S_TITLE, dev->DeviceName);
		FormatText(hWnd, S_INSERT_SECURE,
			dev->Type != SECURE_USB_TOKEN ? _UU("SEC_INIT_MSG_1") : _UU("SEC_INIT_MSG_2"));
		FormatText(hWnd, S_DEVICE_INFO,
			dev->DeviceName, dev->Manufacturer, dev->ModuleName);

		DlgFont(hWnd, S_SOFTWARE_TITLE, 11, 0);
		SetText(hWnd, S_SOFTWARE_TITLE, title_bar);

		DlgFont(hWnd, S_TITLE, 14, true);
		DlgFont(hWnd, S_DEVICE_INFO, 11, false);
		DlgFont(hWnd, S_STATUS, 13, true);
		EnableSecureDeviceWindowControls(hWnd, true);
		OpenAvi(hWnd, A_PROGRESS, AVI_PROGRESS);

		SetIcon(hWnd, 0, ICO_KEY);

		// 初期 PIN
		if ((w->default_pin != NULL && StrLen(w->default_pin) != 0) || (cached_pin_code_expires >= Tick64()))
		{
			if (w->default_pin != NULL && StrLen(w->default_pin) != 0)
			{
				SetTextA(hWnd, E_PIN, w->default_pin);
			}
			else
			{
				SetTextA(hWnd, E_PIN, cached_pin_code);
			}
			SetTimer(hWnd, 1, 1, NULL);
		}

		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			Command(hWnd, IDOK);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			StartSecureDevice(hWnd, w);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		if (IsEnable(hWnd, IDCANCEL))
		{
			CloseAvi(hWnd, A_PROGRESS);
			EndDialog(hWnd, false);
		}
		break;

	case WM_APP + 1:
		// スレッドから応答があった
		if (w->p != NULL)
		{
			if (w->p->Succeed)
			{
				// 成功
				if (w->default_pin != NULL)
				{
					StrCpy(w->default_pin, 128, w->p->pin);
				}
				StrCpy(cached_pin_code, sizeof(cached_pin_code), w->p->pin);
				cached_pin_code_expires = Tick64() + (UINT64)WINUI_SECUREDEVICE_PIN_CACHE_TIME;
				Free(w->p->pin);
				Free(w->p);
				EndDialog(hWnd, true);
			}
			else
			{
				// 失敗
				cached_pin_code_expires = 0;
				EnableSecureDeviceWindowControls(hWnd, true);
				FocusEx(hWnd, E_PIN);
				MsgBox(hWnd, MB_ICONEXCLAMATION, w->p->ErrorMessage);
				Free(w->p->pin);
				Free(w->p->ErrorMessage);
				Free(w->p);
			}
		}
		break;
	}

	return 0;
}

// WM_COMMAND を送信する
void Command(HWND hWnd, UINT id)
{
	SendMessage(hWnd, WM_COMMAND, id, 0);
}

// セキュアデバイスウインドウを表示する
bool SecureDeviceWindow(HWND hWnd, WINUI_SECURE_BATCH *batch, UINT num_batch, UINT device_id, UINT bitmap_id)
{
	SECURE_DEVICE_WINDOW w;
	UINT i;
	// 引数チェック
	if (batch == NULL || num_batch == 0 || device_id == 0)
	{
		return false;
	}

	// 成功フラグを初期化
	for (i = 0;i < num_batch;i++)
	{
		batch[i].Succeed = false;
	}

	Zero(&w, sizeof(w));
	w.batch = batch;
	w.device_id = device_id;
	w.num_batch = num_batch;
	w.BitmapId = bitmap_id;

	// ダイアログを開く
	return (bool)Dialog(hWnd, D_SECURE, SecureDeviceWindowProc, &w);
}

// AVI を停止する
void StopAvi(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	Animate_Stop(DlgItem(hWnd, id));
	Hide(hWnd, id);
}

// AVI を再生する
void PlayAvi(HWND hWnd, UINT id, bool repeat)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	Show(hWnd, id);
	Animate_Play(DlgItem(hWnd, id), 0, -1, (repeat ? -1 : 0));
}

// AVI ファイルを閉じる
void CloseAvi(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	StopAvi(hWnd, id);
	Animate_Close(DlgItem(hWnd, id));
}

// AVI ファイルを開く
void OpenAvi(HWND hWnd, UINT id, UINT avi_id)
{
	// 引数チェック
	if (hWnd == NULL || avi_id == 0)
	{
		return;
	}

	Hide(hWnd, id);
	Animate_OpenEx(DlgItem(hWnd, id), hDll, MAKEINTRESOURCE(avi_id));
}

// フォントをコントロールに設定する
void DlgFont(HWND hWnd, UINT id, UINT size, UINT bold)
{
	DIALOG_PARAM *param = (DIALOG_PARAM *)GetParam(hWnd);

	if (param == NULL || param->meiryo == false)
	{
		SetFont(hWnd, id, Font(size, bold));
	}
	else
	{
		SetFont(hWnd, id, GetFont((_GETLANG() == 2 ? "Microsoft YaHei" : "Meiryo"), size, bold, false, false, false));
	}
}

// 標準的なフォントを生成する
HFONT Font(UINT size, UINT bold)
{
	return GetFont(NULL, size, bold, false, false, false);
}

// 内部管理用ダイアログプロシージャ
UINT CALLBACK InternalDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	DIALOG_PARAM *param = (DIALOG_PARAM *)GetParam(hWnd);
	void *app_param = NULL;
	bool white_flag = false;
	UINT ret;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	if (msg == WM_INITDIALOG)
	{
		DoEvents(hWnd);
	}

	if (param == NULL)
	{
		if (msg == WM_INITDIALOG)
		{
			param = (void *)lParam;
			InitDialogInternational(hWnd, param);
		}
	}
	if (param != NULL)
	{
		app_param = param->param;
		white_flag = param->white;
	}

	ret = DlgProc(hWnd, msg, wParam, lParam, white_flag);
	if (ret != 0)
	{
		return ret;
	}

	ret = 0;

	if (param != NULL)
	{
		if (param->proc != NULL)
		{
			ret = param->proc(hWnd, msg, wParam, lParam, app_param);
		}
		else
		{
			if (msg == WM_CLOSE)
			{
				EndDialog(hWnd, 0);
			}
			else if (msg == WM_COMMAND && (wParam == IDOK || wParam == IDCANCEL))
			{
				Close(hWnd);
			}
		}
	}

	if (msg == WM_INITDIALOG)
	{
		SetForegroundWindow(hWnd);
		SetActiveWindow(hWnd);
	}

	return ret;
}

// ダイアログ ボックスを表示する
UINT Dialog(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param)
{
	bool white = true;

	return DialogEx(hWnd, id, proc, param, white);
}
UINT DialogEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white)
{
	return DialogEx2(hWnd, id, proc, param, white, false);
}
UINT DialogEx2(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white, bool meiryo)
{
	UINT ret;
	DIALOG_PARAM p;
	// 引数チェック
	if (id == 0)
	{
		return 0;
	}

	Zero(&p, sizeof(p));
	p.param = param;
	p.white = white;
	p.proc = proc;

	if (MsIsVista())
	{
		p.meiryo = meiryo;
	}

	ret = DialogInternal(hWnd, id, InternalDialogProc, &p);

	return ret;
}

// モードレスダイアログを作成する
HWND DialogCreateEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white)
{
	HWND ret = NULL;
	DIALOG_PARAM p;
	// 引数チェック
	if (id == 0)
	{
		return 0;
	}

	Zero(&p, sizeof(p));
	p.param = param;
	p.white = white;
	p.proc = proc;

	if (MsIsNt() == false)
	{
		// Win9x
		ret = CreateDialogParamA(hDll, MAKEINTRESOURCEA(id), hWnd,
			(DLGPROC)proc, (LPARAM)param);
	}
	else
	{
		// WinNT
		ret = CreateDialogParamW(hDll, MAKEINTRESOURCEW(id), hWnd,
			(DLGPROC)proc, (LPARAM)param);
	}

	return ret;
}

// ビットマップをボタンに設定する
void SetBitmap(HWND hWnd, UINT id, UINT bmp_id)
{
	HBITMAP bmp;
	char *class_name;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	bmp = LoadImage(hDll, MAKEINTRESOURCE(bmp_id), IMAGE_BITMAP, 0, 0, (MsIsNt() ? LR_SHARED : 0) | LR_VGACOLOR);
	if (bmp == NULL)
	{
		return;
	}

	class_name = GetClassA(hWnd, id);

	if (StrCmpi(class_name, "Static") != 0)
	{
		SendMsg(hWnd, id, BM_SETIMAGE, IMAGE_BITMAP, (LPARAM)bmp);
	}
	else
	{
		SendMsg(hWnd, id, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)bmp);
	}

	Free(class_name);
}

// アイコンキャッシュの初期化
void InitIconCache()
{
	if (icon_cache_list != NULL)
	{
		return;
	}

	icon_cache_list = NewList(NULL);
}

// アイコンキャッシュの解放
void FreeIconCache()
{
	UINT i;
	if (icon_cache_list == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(icon_cache_list);i++)
	{
		ICON_CACHE *c = LIST_DATA(icon_cache_list, i);
		DestroyIcon(c->hIcon);
		Free(c);
	}

	ReleaseList(icon_cache_list);
	icon_cache_list = NULL;
}

// アイコン取得
HICON LoadIconEx(UINT id, bool small_icon)
{
	HICON h = NULL;
	UINT i;
	if (icon_cache_list == NULL)
	{
		return small_icon == false ? LoadLargeIconInner(id) : LoadSmallIconInner(id);
	}

	LockList(icon_cache_list);
	{
		for (i = 0;i < LIST_NUM(icon_cache_list);i++)
		{
			ICON_CACHE *c = LIST_DATA(icon_cache_list, i);
			if (c->id == id && c->small_icon == small_icon)
			{
				h = c->hIcon;
				break;
			}
		}

		if (h == NULL)
		{
			h = small_icon == false ? LoadLargeIconInner(id) : LoadSmallIconInner(id);
			if (h != NULL)
			{
				ICON_CACHE *c = ZeroMalloc(sizeof(ICON_CACHE));
				c->hIcon = h;
				c->id = id;
				c->small_icon = small_icon;
				Add(icon_cache_list, c);
			}
		}
	}
	UnlockList(icon_cache_list);

	return h;
}

// 大きいアイコン取得
HICON LoadLargeIcon(UINT id)
{
	return LoadIconEx(id, false);
}

// 小さいアイコン取得
HICON LoadSmallIcon(UINT id)
{
	return LoadIconEx(id, true);
}

// 大きいアイコンを取得する
HICON LoadLargeIconInner(UINT id)
{
	HICON ret;
	ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 32, 32, 0);
	if (ret == NULL)
	{
		ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 32, 32, LR_VGACOLOR);
		if (ret == NULL)
		{
			ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, 0);
			if (ret == NULL)
			{
				ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, LR_VGACOLOR);
				if (ret == NULL)
				{
					ret = LoadIcon(hDll, MAKEINTRESOURCE(id));
				}
			}
		}
	}
	return ret;
}

// 小さいアイコンを取得する
HICON LoadSmallIconInner(UINT id)
{
	HICON ret;
	ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 16, 16, 0);
	if (ret == NULL)
	{
		ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 16, 16, LR_VGACOLOR);
		if (ret == NULL)
		{
			ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, 0);
			if (ret == NULL)
			{
				ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, LR_VGACOLOR);
				if (ret == NULL)
				{
					ret = LoadLargeIconInner(id);
				}
			}
		}
	}
	return ret;
}

// アイコンをウインドウまたはボタンに設定する
void SetIcon(HWND hWnd, UINT id, UINT icon_id)
{
	HICON icon1, icon2;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	icon1 = LoadLargeIcon(icon_id);
	if (icon1 == NULL)
	{
		return;
	}

	if (id == 0)
	{
		SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)icon1);
		icon2 = LoadSmallIcon(icon_id);
		if (icon2 == NULL)
		{
			icon2 = icon1;
		}
		SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)icon2);
	}
	else
	{
		bool is_btn = true;
		wchar_t *s = GetClass(hWnd, id);
		if (s != NULL)
		{
			if (UniStrCmpi(s, L"Static") == 0)
			{
				is_btn = false;
			}
			Free(s);
		}

		if (is_btn)
		{
			SendMsg(hWnd, id, BM_SETIMAGE, IMAGE_ICON, (LPARAM)icon1);
		}
		else
		{
			SendMsg(hWnd, id, STM_SETICON, (WPARAM)icon1, 0);
		}
	}
}

// ラジオボタンがチェックされているか確認する
bool IsChecked(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	return IsDlgButtonChecked(hWnd, id) == BST_CHECKED ? true : false;
}

// ラジオボタンをチェック
void Check(HWND hWnd, UINT id, bool b)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if ((!(!IsChecked(hWnd, id))) != (!(!b)))
	{
		CheckDlgButton(hWnd, id, b ? BST_CHECKED : BST_UNCHECKED);
	}
}

// テキストボックスの文字サイズが指定されたサイズ以下であることを確認する
bool CheckTextSize(HWND hWnd, UINT id, UINT size, bool unicode)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	if (GetTextSize(hWnd, id, unicode) <= size)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// テキストボックスに入っている文字列数が指定された文字列数以下であることを確認する
bool CheckTextLen(HWND hWnd, UINT id, UINT len, bool unicode)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	if (GetTextLen(hWnd, id, unicode) <= len)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// テキストボックスに入力できる文字数を制限する
void LimitText(HWND hWnd, UINT id, UINT count)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, EM_LIMITTEXT, count, 0);
}

// フォントの設定
void SetFont(HWND hWnd, UINT id, HFONT hFont)
{
	// 引数チェック
	if (hWnd == NULL || hFont == NULL)
	{
		return;
	}

	SendMessage(DlgItem(hWnd, id), WM_SETFONT, (WPARAM)hFont, true);
}

// フォントサイズの取得
bool GetFontSize(HFONT hFont, UINT *x, UINT *y)
{
	bool ret = false;
	UINT xx = 0;
	UINT yy = 0;

	// フォントハンドルを検索
	LockList(font_list);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(font_list);i++)
		{
			FONT *f = LIST_DATA(font_list, i);

			if (f->hFont == hFont)
			{
				xx = f->x;
				yy = f->y;

				ret = true;
				break;
			}
		}
	}
	UnlockList(font_list);

	if (ret == false)
	{
		ret = CalcFontSize(hFont, &xx, &yy);
	}

	if (xx == 0 || yy == 0)
	{
		xx = 8;
		yy = 16;
	}

	if (x != NULL)
	{
		*x = xx;
	}

	if (y != NULL)
	{
		*y = yy;
	}

	return ret;
}

// フォントサイズの計算
bool CalcFontSize(HFONT hFont, UINT *x, UINT *y)
{
	UINT xx = 0, yy = 0;
	TEXTMETRIC tm;
	SIZE sz;
	bool ret = false;
	HDC hDC;

	hDC = CreateCompatibleDC(NULL);

	SelectObject(hDC, hFont);

	Zero(&tm, sizeof(tm));
	Zero(&sz, sizeof(sz));

	if (GetTextMetrics(hDC, &tm))
	{
		xx = tm.tmAveCharWidth;
		yy = tm.tmHeight;

		ret = true;

		if (GetTextExtentPoint32(hDC,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
			52, &sz))
		{
			xx = (sz.cx / 26 + 1) / 2;
		}
	}

	if (x != NULL)
	{
		*x = xx;
	}

	if (y != NULL)
	{
		*y = yy;
	}

	DeleteDC(hDC);

	return ret;
}

// フォントの取得
HFONT GetFont(char *name, UINT size, bool bold, bool italic, bool underline, bool strikeout)
{
	HFONT hFont;
	HDC hDC;
	// 引数チェック
	if (name == NULL)
	{
		name = font_name;
	}
	if (size == 0)
	{
		size = font_size;
		if (size == 0)
		{
			size = 9;
		}
	}

	// 既存のフォントを探す
	LockList(font_list);
	{
		FONT *f, t;
		DWORD font_quality = ANTIALIASED_QUALITY;
		OS_INFO *os = GetOsInfo();
		UINT x = 0;
		UINT y = 0;
		int rotate = 0;

		Zero(&t, sizeof(t));
		t.Bold = bold;
		t.Italic = italic;
		t.Size = size;
		t.StrikeOut = strikeout;
		t.UnderLine = underline;
		t.Name = CopyStr(name);
		f = Search(font_list, &t);
		Free(t.Name);

		if (f != NULL)
		{
			// フォントを発見した
			UnlockList(font_list);
			return f->hFont;
		}

		// 新しいフォントを作成する
		hDC = CreateCompatibleDC(NULL);

		// Windows XP 以降では ClearType を指定する
		if (OS_IS_WINDOWS_NT(os->OsType) && GET_KETA(os->OsType, 100) >= 3)
		{
			font_quality = CLEARTYPE_NATURAL_QUALITY;
			rotate = 3600;
		}

		// フォント作成
		hFont = CreateFontA(-MulDiv(size, GetDeviceCaps(hDC, LOGPIXELSY), 72),
			0, rotate, rotate, (bold == false ? 500 : FW_BOLD),
			italic, underline, strikeout, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
			CLIP_DEFAULT_PRECIS, font_quality, DEFAULT_PITCH, name);

		if (hFont == NULL)
		{
			// 失敗
			DeleteDC(hDC);
			UnlockList(font_list);

			return NULL;
		}

		CalcFontSize(hFont, &x, &y);

		// テーブルに追加
		f = ZeroMalloc(sizeof(FONT));
		f->Bold = bold;
		f->hFont = hFont;
		f->Italic = italic;
		f->Name = CopyStr(name);
		f->Size = size;
		f->StrikeOut = strikeout;
		f->UnderLine = underline;
		f->x = x;
		f->y = y;

		Insert(font_list, f);

		DeleteDC(hDC);
	}
	UnlockList(font_list);

	return hFont;
}

// フォントの比較
int CompareFont(void *p1, void *p2)
{
	FONT *f1, *f2;
	UINT r;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(FONT **)p1;
	f2 = *(FONT **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	r = StrCmpi(f1->Name, f2->Name);
	if (r != 0)
	{
		return r;
	}
	else
	{
		if (f1->Bold > f2->Bold)
		{
			return 1;
		}
		else if (f1->Bold < f2->Bold)
		{
			return -1;
		}
		else if (f1->Italic > f2->Italic)
		{
			return 1;
		}
		else if (f1->Italic < f2->Italic)
		{
			return -1;
		}
		else if (f1->Size > f2->Size)
		{
			return 1;
		}
		else if (f1->Size < f2->Size)
		{
			return -1;
		}
		else if (f1->StrikeOut > f2->StrikeOut)
		{
			return 1;
		}
		else if (f1->StrikeOut < f2->StrikeOut)
		{
			return -1;
		}
		else if (f1->UnderLine > f2->UnderLine)
		{
			return 1;
		}
		else if (f1->UnderLine < f2->UnderLine)
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}
}

// フォントの初期化
void InitFont()
{
	if (font_list != NULL)
	{
		return;
	}
	font_list = NewList(CompareFont);
}

// フォントの解放
void FreeFont()
{
	UINT i;
	if (font_list == NULL)
	{
		return;
	}
	for (i = 0;i < LIST_NUM(font_list);i++)
	{
		FONT *f = LIST_DATA(font_list, i);
		Free(f->Name);
		DeleteObject((HGDIOBJ)f->hFont);
		Free(f);
	}
	ReleaseList(font_list);
	font_list = NULL;
}

// ウインドウを閉じるボタンを出す
void EnableClose(HWND hWnd)
{
	HMENU h;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	h = GetSystemMenu(hWnd, false);
	EnableMenuItem(h, SC_CLOSE, MF_ENABLED);
	DrawMenuBar(hWnd);
}

// ウインドウを閉じるボタンを消す
void DisableClose(HWND hWnd)
{
	HMENU h;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	h = GetSystemMenu(hWnd, false);
	EnableMenuItem(h, SC_CLOSE, MF_GRAYED);
	DrawMenuBar(hWnd);
}

// 親ウインドウの中央に移動する
void CenterParent(HWND hWnd)
{
	RECT rp;
	RECT r;
	HWND hWndParent = GetParent(hWnd);
	int win_x, win_y;
	int x, y;

	if (hWndParent == NULL || IsHide(hWndParent, 0) || IsIconic(hWndParent))
	{
		Center(hWnd);
		return;
	}

	if (GetWindowRect(hWndParent, &rp) == false)
	{
		Center(hWnd);
		return;
	}

	GetWindowRect(hWnd, &r);

	win_x = r.right - r.left;
	win_y = r.bottom - r.top;

	x = (rp.right - rp.left - win_x) / 2 + rp.left;
	y = (rp.bottom - rp.top - win_y) / 2 + rp.top;

	x = MAX(x, 0);
	y = MAX(y, 0);

	SetWindowPos(hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
}

// ウインドウを中央に移動する
void Center(HWND hWnd)
{
	RECT screen;
	RECT win;
	UINT x, y;
	UINT win_x, win_y;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (SystemParametersInfo(SPI_GETWORKAREA, 0, &screen, 0) == false)
	{
		return;
	}

	GetWindowRect(hWnd, &win);
	win_x = win.right - win.left;
	win_y = win.bottom - win.top;

	if (win_x < (UINT)(screen.right - screen.left))
	{
		x = (screen.right - screen.left - win_x) / 2;
	}
	else
	{
		x = 0;
	}

	if (win_y < (UINT)(screen.bottom - screen.top))
	{
		y = (screen.bottom - screen.top - win_y) / 2;
	}
	else
	{
		y = 0;
	}

	SetWindowPos(hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
}

// ウインドウを中央に移動する 2
void Center2(HWND hWnd)
{
	RECT screen;
	RECT win;
	UINT x, y;
	UINT win_x, win_y;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (SystemParametersInfo(SPI_GETWORKAREA, 0, &screen, 0) == false)
	{
		return;
	}

	GetWindowRect(hWnd, &win);
	win_x = win.right - win.left;
	win_y = win.bottom - win.top;

	if (win_x < (UINT)(screen.right - screen.left))
	{
		x = (screen.right - screen.left - win_x) / 2;
	}
	else
	{
		x = 0;
	}

	if (win_y < (UINT)(screen.bottom - screen.top))
	{
		y = (screen.bottom - screen.top - win_y) / 4;
	}
	else
	{
		y = 0;
	}

	SetWindowPos(hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
}

// モニタのサイズを取得する
void GetMonitorSize(UINT *width, UINT *height)
{
	// 引数チェック
	if (width == NULL || height == NULL)
	{
		return;
	}

	*width = GetSystemMetrics(SM_CXSCREEN);
	*height = GetSystemMetrics(SM_CYSCREEN);
}

// ウインドウ内の文字列をフォーマットする
void FormatText(HWND hWnd, UINT id, ...)
{
	va_list args;
	wchar_t *buf;
	UINT size;
	wchar_t *str;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	str = GetText(hWnd, id);
	if (str == NULL)
	{
		return;
	}

	size = MAX(UniStrSize(str) * 10, MAX_SIZE * 10);
	buf = MallocEx(size, true);

	va_start(args, id);
	UniFormatArgs(buf, size, str, args);

	SetText(hWnd, id, buf);

	Free(buf);

	Free(str);
	va_end(args);
}
void FormatTextA(HWND hWnd, UINT id, ...)
{
	va_list args;
	char *buf;
	UINT size;
	char *str;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	str = GetTextA(hWnd, id);
	if (str == NULL)
	{
		return;
	}

	size = MAX(StrSize(str) * 10, MAX_SIZE * 10);
	buf = MallocEx(size, true);

	va_start(args, id);
	FormatArgs(buf, size, str, args);

	SetTextA(hWnd, id, buf);

	Free(buf);

	Free(str);
	va_end(args);
}

// 可変長引数の文字列をウインドウに設定
void SetTextEx(HWND hWnd, UINT id, wchar_t *str, ...)
{
	va_list args;
	wchar_t *buf;
	UINT size;
	// 引数チェック
	if (str == NULL || hWnd == NULL)
	{
		return;
	}

	size = MAX(UniStrSize(str) * 10, MAX_SIZE * 10);
	buf = MallocEx(size, true);

	va_start(args, str);
	UniFormatArgs(buf, size, str, args);

	SetText(hWnd, id, buf);

	Free(buf);
	va_end(args);
}
void SetTextExA(HWND hWnd, UINT id, char *str, ...)
{
	va_list args;
	char *buf;
	UINT size;
	// 引数チェック
	if (str == NULL || hWnd == NULL)
	{
		return;
	}

	size = MAX(StrSize(str) * 10, MAX_SIZE * 10);
	buf = MallocEx(size, true);

	va_start(args, str);
	FormatArgs(buf, size, str, args);

	SetTextA(hWnd, id, buf);

	Free(buf);
	va_end(args);
}

// 可変長メッセージボックスの表示
UINT MsgBoxEx(HWND hWnd, UINT flag, wchar_t *msg, ...)
{
	va_list args;
	wchar_t *buf;
	UINT size;
	UINT ret;
	// 引数チェック
	if (msg == NULL)
	{
		msg = L"MessageBox";
	}

	size = MAX(UniStrSize(msg) * 10, MAX_SIZE * 10);
	buf = MallocEx(size, true);

	va_start(args, msg);
	UniFormatArgs(buf, size, msg, args);

	ret = MsgBox(hWnd, flag, buf);
	Free(buf);
	va_end(args);

	return ret;
}

// メッセージボックスの表示
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg)
{
	UINT ret;
	wchar_t *title;
	// 引数チェック
	if (msg == NULL)
	{
		msg = L"MessageBox";
	}

	if (title_bar != NULL)
	{
		title = CopyUniStr(title_bar);
	}
	else
	{
		title = CopyStrToUni(CEDAR_PRODUCT_STR);
	}

	if (hWnd)
	{
		// 親ウインドウが最上位ウインドウの場合はメッセージボックスも最上位にする
		if (GetExStyle(hWnd, 0) & WS_EX_TOPMOST)
		{
			flag |= MB_SYSTEMMODAL;
		}
	}

	ret = MessageBoxW(hWnd, msg, title, flag);

	Free(title);

	return ret;
}

// ダイアログの作成 (内部)
UINT DialogInternal(HWND hWnd, UINT id, DIALOG_PROC *proc, void *param)
{
	// 引数チェック
	if (proc == NULL)
	{
		return 0;
	}

	if (MsIsNt() == false)
	{
		// Win9x
		return (UINT)DialogBoxParam(hDll, MAKEINTRESOURCE(id), hWnd, (DLGPROC)proc, (LPARAM)param);
	}
	else
	{
		// WinNT
		return (UINT)DialogBoxParamW(hDll, MAKEINTRESOURCEW(id), hWnd, (DLGPROC)proc, (LPARAM)param);
	}
}

// システム設定が更新されたことを通知する
void NoticeSettingChange()
{
	PostMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 0);
	DoEvents(NULL);
}

// ウインドウを半透明にする
void SetAplha(HWND hWnd, UINT value0_255)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	value0_255 = MAKESURE(value0_255, 0, 255);

	if (true)
	{
		UINT os_type = GetOsInfo()->OsType;
		if (OS_IS_WINDOWS_NT(os_type) && GET_KETA(os_type, 100) >= 2)
		{
			bool (WINAPI *_SetLayeredWindowAttributes)(HWND, COLORREF, BYTE, DWORD);
			HINSTANCE hInst;

			hInst = LoadLibrary("user32.dll");

			_SetLayeredWindowAttributes =
				(bool (__stdcall *)(HWND,COLORREF,BYTE,DWORD))
				GetProcAddress(hInst, "SetLayeredWindowAttributes");

			if (_SetLayeredWindowAttributes != NULL)
			{
				// Windows 2000 以降でのみ対応
				SetExStyle(hWnd, 0, WS_EX_LAYERED);
				_SetLayeredWindowAttributes(hWnd, 0, value0_255, LWA_ALPHA);
			}

			FreeLibrary(hInst);
		}
	}
}

// WinUi が管理するダイアログボックスプロシージャ
UINT DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, bool white_color)
{
	void *param;
	HWND hWndParent;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		param = (void *)lParam;
		SetParam(hWnd, param);

		// 親ウインドウが存在するかどうか調べる
		hWndParent = GetParent(hWnd);
		if (hWndParent == NULL || IsShow(hWndParent, 0) == false)
		{
			// 存在しない場合は中央に配置する
			Center(hWnd);
		}

		if (UseAlpha)
		{
			SetAplha(hWnd, AlphaValue * 255 / 100);
		}

		break;
	}

	if (white_color)
	{
		if (IsNewStyleModeEnabled() == false)
		{
			switch (msg)
			{
			case WM_CTLCOLORBTN:
			case WM_CTLCOLORDLG:
			case WM_CTLCOLOREDIT:
			case WM_CTLCOLORLISTBOX:
			case WM_CTLCOLORMSGBOX:
			case WM_CTLCOLORSCROLLBAR:
			case WM_CTLCOLORSTATIC:
				return (UINT)GetStockObject(WHITE_BRUSH);
			}
		}
		else
		{
			switch (msg)
			{
			case WM_CTLCOLORDLG:
				// ダイアログの背景色
				return (UINT)gdi_cache.BackgroundColorBrush;

			case WM_CTLCOLORBTN:
				// ボタンの背景色
				SetTextColor((HDC)wParam, gdi_cache.ForegroundColor);
				SetBkColor((HDC)wParam, gdi_cache.BackgroundColor);
				return (UINT)gdi_cache.BackgroundColorBrush;

			case WM_CTLCOLORSTATIC:
				// ラベルの色
				SetTextColor((HDC)wParam, gdi_cache.ForegroundColor);
				SetBkColor((HDC)wParam, gdi_cache.BackgroundColor);
				return (UINT)gdi_cache.BackgroundColorBrush;

			case WM_CTLCOLOREDIT:
				// エディットコントロールの色
				return (UINT)gdi_cache.TextBoxBackgroundColorBrush;
			}
		}
	}

	return 0;
}

// ダイアログボックスのパラメータの設定
void SetParam(HWND hWnd, void *param)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetWindowLongPtr(hWnd, DWLP_USER, (LONG_PTR)param);
}

// ダイアログボックスのパラメータの取得
void *GetParam(HWND hWnd)
{
	void *ret;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	ret = (void *)GetWindowLongPtr(hWnd, DWLP_USER);
	return ret;
}

// ウインドウを最前面でなくする
void NoTop(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// ウインドウを最前面に表示する
void Top(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// ウインドウを隠す
void Hide(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (IsShow(hWnd, id))
	{
		ShowWindow(DlgItem(hWnd, id), SW_HIDE);
	}
}

// ウインドウを表示する
void Show(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (IsHide(hWnd, id))
	{
		ShowWindow(DlgItem(hWnd, id), SW_SHOW);
	}
}

// 表示設定の変更
void SetShow(HWND hWnd, UINT id, bool b)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (b)
	{
		Show(hWnd, id);
	}
	else
	{
		Hide(hWnd, id);
	}
}

// ウインドウが表示されているかどうか取得する
bool IsShow(HWND hWnd, UINT id)
{
	return IsHide(hWnd, id) ? false : true;
}

// ウインドウが隠れているかどうか取得する
bool IsHide(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return true;
	}

	if (GetStyle(hWnd, id) & WS_VISIBLE)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// ウインドウスタイルを削除する
void RemoveExStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	old = GetExStyle(hWnd, id);
	if ((old & style) == 0)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE, old & ~style);
	Refresh(DlgItem(hWnd, id));
}

// ウインドウスタイルを設定する
void SetExStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	old = GetExStyle(hWnd, id);
	if (old & style)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE, old | style);
	Refresh(DlgItem(hWnd, id));
}

// ウインドウスタイルを取得する
UINT GetExStyle(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	return GetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE);
}

// ウインドウスタイルを削除する
void RemoveStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	old = GetStyle(hWnd, id);
	if ((old & style) == 0)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_STYLE, old & ~style);
	Refresh(DlgItem(hWnd, id));
}

// ウインドウスタイルを設定する
void SetStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	old = GetStyle(hWnd, id);
	if (old & style)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_STYLE, old | style);
	Refresh(DlgItem(hWnd, id));
}

// ウインドウスタイルを取得する
UINT GetStyle(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	return GetWindowLong(DlgItem(hWnd, id), GWL_STYLE);
}

// テキストのバイト数を取得する
UINT GetTextSize(HWND hWnd, UINT id, bool unicode)
{
	UINT len;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	len = GetTextLen(hWnd, id, unicode);

	return len + (unicode ? 2 : 1);
}

// テキストの文字数を取得する
UINT GetTextLen(HWND hWnd, UINT id, bool unicode)
{
	wchar_t *s;
	UINT ret;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	s = GetText(hWnd, id);
	if (s == NULL)
	{
		return 0;
	}

	if (unicode)
	{
		ret = UniStrLen(s);
	}
	else
	{
		char *tmp = CopyUniToStr(s);
		ret = StrLen(tmp);
		Free(tmp);
	}

	Free(s);

	return ret;
}

// テキストが空白かどうかチェックする
bool IsEmpty(HWND hWnd, UINT id)
{
	bool ret;
	wchar_t *s;
	// 引数チェック
	if (hWnd == NULL)
	{
		return true;
	}

	s = GetText(hWnd, id);

	UniTrim(s);
	if (UniStrLen(s) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(s);

	return ret;
}

// ウインドウクラスを取得する
wchar_t *GetClass(HWND hWnd, UINT id)
{
	wchar_t tmp[MAX_SIZE];

	if (MsIsNt() == false)
	{
		wchar_t *ret;
		char *s;
		s = GetClassA(hWnd, id);
		ret = CopyStrToUni(s);
		Free(s);
		return ret;
	}

	// 引数チェック
	if (hWnd == NULL)
	{
		return CopyUniStr(L"");
	}

	GetClassNameW(DlgItem(hWnd, id), tmp, sizeof(tmp));

	return UniCopyStr(tmp);
}
char *GetClassA(HWND hWnd, UINT id)
{
	char tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return CopyStr("");
	}

	GetClassName(DlgItem(hWnd, id), tmp, sizeof(tmp));

	return CopyStr(tmp);
}

// コントロールにメッセージを送信する
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	if (MsIsNt())
	{
		return (UINT)SendMessageW(DlgItem(hWnd, id), msg, wParam, lParam);
	}
	else
	{
		return (UINT)SendMessageA(DlgItem(hWnd, id), msg, wParam, lParam);
	}
}

// EDIT のテキストをすべて選択する
void SelectEdit(HWND hWnd, UINT id)
{
	wchar_t *class_name;

	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	class_name = GetClass(hWnd, id);

	if (class_name != NULL)
	{
		if (UniStrCmpi(class_name, L"edit") == 0)
		{
			SendMsg(hWnd, id, EM_SETSEL, 0, -1);
		}
		Free(class_name);
	}
}

// EDIT のテキストの選択を解除する
void UnselectEdit(HWND hWnd, UINT id)
{
	wchar_t *class_name;

	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	class_name = GetClass(hWnd, id);

	if (class_name != NULL)
	{
		if (UniStrCmpi(class_name, L"edit") == 0)
		{
			SendMsg(hWnd, id, EM_SETSEL, -1, 0);
		}
		Free(class_name);
	}
}

// EDIT にフォーカスを設定してすべて選択する
void FocusEx(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (IsEnable(hWnd, id) == false || IsShow(hWnd, id) == false)
	{
		return;
	}

	SelectEdit(hWnd, id);

	Focus(hWnd, id);
}

// 指定したウインドウがフォーカスを持っているかどうか取得する
bool IsFocus(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	if (GetFocus() == DlgItem(hWnd, id))
	{
		return true;
	}

	return false;
}

// フォーカスを設定する
void Focus(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (IsEnable(hWnd, id) == false || IsShow(hWnd, id) == false)
	{
		return;
	}

	SetFocus(DlgItem(hWnd, id));
}

// int 型の値を設定する
void SetInt(HWND hWnd, UINT id, UINT value)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	UniToStru(tmp, value);
	SetText(hWnd, id, tmp);
}
void SetIntEx(HWND hWnd, UINT id, UINT value)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (value == 0)
	{
		// 0 の場合は空欄にする
		SetText(hWnd, id, L"");
	}
	else
	{
		SetInt(hWnd, id, value);
	}
}

// int 型の値を取得する
UINT GetInt(HWND hWnd, UINT id)
{
	wchar_t *s;
	UINT ret;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	s = GetText(hWnd, id);
	if (s == NULL)
	{
		return 0;
	}

	ret = UniToInt(s);
	Free(s);

	return ret;
}

// ウインドウ表示を更新する
void Refresh(HWND hWnd)
{
	HWND parent;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	DoEvents(hWnd);
	UpdateWindow(hWnd);
	DoEvents(hWnd);

	parent = GetParent(hWnd);
	if (parent != NULL)
	{
		Refresh(parent);
	}
}

// イベントを処理する
void DoEvents(HWND hWnd)
{
	MSG msg;

	if (PeekMessage(&msg, hWnd, 0, 0, PM_REMOVE))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	UpdateWindow(hWnd);

	if (hWnd)
	{
		DoEvents(NULL);
	}
}

// ウインドウを閉じる
void Close(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SendMessage(hWnd, WM_CLOSE, 0, 0);
}

// ウインドウを無効にする
void Disable(HWND hWnd, UINT id)
{
	SetEnable(hWnd, id, false);
}

// ウインドウを有効にする
void Enable(HWND hWnd, UINT id)
{
	SetEnable(hWnd, id, true);
}

// ウインドウの有効状態を設定する
void SetEnable(HWND hWnd, UINT id, bool b)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (b == false)
	{
		if (IsEnable(hWnd, id))
		{
			if (id != 0 && IsFocus(hWnd, id))
			{
				Focus(hWnd, IDCANCEL);
				Focus(hWnd, IDOK);
			}
			EnableWindow(DlgItem(hWnd, id), false);
			Refresh(DlgItem(hWnd, id));
		}
	}
	else
	{
		if (IsDisable(hWnd, id))
		{
			EnableWindow(DlgItem(hWnd, id), true);
			Refresh(DlgItem(hWnd, id));
		}
	}
}

// ウインドウが無効かどうか調べる
bool IsDisable(HWND hWnd, UINT id)
{
	return IsEnable(hWnd, id) ? false : true;
}

// ウインドウが有効かどうか調べる
bool IsEnable(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return false;
	}

	return IsWindowEnabled(DlgItem(hWnd, id));
}

static LOCK *winui_debug_lock = NULL;

// デバッグの初期化
void WinUiDebugInit()
{
	winui_debug_lock = NewLock();
}

// デバッグの解放
void WinUiDebugFree()
{
	DeleteLock(winui_debug_lock);
}

// デバッグファイルに文字列を書き込む
void WinUiDebug(wchar_t *str)
{
	wchar_t tmp[1024];
	char dtstr[256];
	char *buf;
	wchar_t exename[MAX_PATH];
	UINT tid;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	tid = GetCurrentThreadId();

	GetExeNameW(exename, sizeof(exename));
	GetFileNameFromFilePathW(exename, sizeof(exename), exename);

	GetDateTimeStrMilli64(dtstr, sizeof(dtstr), LocalTime64());

	UniFormat(tmp, sizeof(tmp), L"[%S] (%s:%u) %s\r\n", dtstr, exename, tid, str);

	buf = CopyUniToUtf(tmp);

	Lock(winui_debug_lock);
	{
		IO *o = FileOpenEx(WINUI_DEBUG_TEXT, true, true);
		if (o == NULL)
		{
			o = FileCreate(WINUI_DEBUG_TEXT);
		}

		if (o != NULL)
		{
			UINT size = FileSize(o);

			FileSeek(o, FILE_BEGIN, size);

			FileWrite(o, buf, StrLen(buf));
			FileFlush(o);

			FileClose(o);
		}
	}
	Unlock(winui_debug_lock);

	Free(buf);
}


// テキスト文字列の設定
void SetText(HWND hWnd, UINT id, wchar_t *str)
{
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	SetTextInner(hWnd, id, str);
}
void SetTextInner(HWND hWnd, UINT id, wchar_t *str)
{
	wchar_t *old;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	// 古い文字列を取得
	old = GetText(hWnd, id);
	if (UniStrCmp(str, old) == 0)
	{
		// 同一
		Free(old);
		return;
	}

	Free(old);

	if (MsIsNt())
	{
		SetWindowTextW(DlgItem(hWnd, id), str);
	}
	else
	{
		char *tmp = CopyUniToStr(str);

		if (MsIsNt() == false && StrLen(tmp) >= 32000)
		{
			// 32k 以下にきりつめる
			tmp[32000] = 0;
		}

		SetWindowTextA(DlgItem(hWnd, id), tmp);
		Free(tmp);
	}

	if (id != 0)
	{
		Refresh(DlgItem(hWnd, id));
	}
}
void SetTextA(HWND hWnd, UINT id, char *str)
{
	wchar_t *s;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	s = CopyStrToUni(str);
	if (s == NULL)
	{
		return;
	}

	SetText(hWnd, id, s);

	Free(s);
}

// テキスト文字列をバッファへ取得
bool GetTxt(HWND hWnd, UINT id, wchar_t *str, UINT size)
{
	wchar_t *s;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return false;
	}

	s = GetText(hWnd, id);
	if (s == NULL)
	{
		UniStrCpy(str, size, L"");
		return false;
	}

	UniStrCpy(str, size, s);
	Free(s);

	return true;
}
bool GetTxtA(HWND hWnd, UINT id, char *str, UINT size)
{
	char *s;
	// 引数チェック
	if (hWnd == NULL || str == NULL)
	{
		return false;
	}

	s = GetTextA(hWnd, id);
	if (s == NULL)
	{
		StrCpy(str, size, "");
		return false;
	}

	StrCpy(str, size, s);
	Free(s);

	return true;
}

// テキスト文字列の取得
wchar_t *GetText(HWND hWnd, UINT id)
{
	wchar_t *ret;
	UINT size, len;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (MsIsNt() == false)
	{
		char *s = GetTextA(hWnd, id);
		ret = CopyStrToUni(s);
		Free(s);

		return ret;
	}

	len = GetWindowTextLengthW(DlgItem(hWnd, id));
	if (len == 0)
	{
		return CopyUniStr(L"");
	}

	size = (len + 1) * 2;
	ret = ZeroMallocEx(size, true);

	GetWindowTextW(DlgItem(hWnd, id), ret, size);

	return ret;
}
char *GetTextA(HWND hWnd, UINT id)
{
	char *ret;
	UINT size, len;
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	len = GetWindowTextLengthA(DlgItem(hWnd, id));
	if (len == 0)
	{
		return CopyStr("");
	}

	size = len + 1;
	ret = ZeroMallocEx(size, true);

	GetWindowTextA(DlgItem(hWnd, id), ret, size);

	return ret;
}

// ダイアログ内のアイテムの取得
HWND DlgItem(HWND hWnd, UINT id)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (id == 0)
	{
		return hWnd;
	}
	else
	{
		return GetDlgItem(hWnd, id);
	}
}

// タイトルの設定
void SetWinUiTitle(wchar_t *title)
{
	// 引数チェック
	if (title == NULL)
	{
		return;
	}

	Free(title_bar);
	title_bar = CopyUniStr(title);
}

// WinUi の初期化
void InitWinUi(wchar_t *software_name, char *font, UINT fontsize)
{
	if ((init_winui_counter++) != 0)
	{
		return;
	}

	if (hDll != NULL)
	{
		return;
	}

	WinUiDebugInit();

	if (MayaquaIsMinimalMode() == false)
	{
		if (Is64())
		{
			hDll = MsLoadLibraryAsDataFile(MsGetPenCoreDllFileName());
		}
		else
		{
			hDll = MsLoadLibrary(MsGetPenCoreDllFileName());
		}

		if (hDll == NULL)
		{
			Alert(PENCORE_DLL_NAME " not found. SoftEther UT-VPN couldn't start.\r\n\r\n"
				"Please reinstall all files with SoftEther UT-VPN Installer.",
				NULL);
			exit(0);
		}
	}
	else
	{
		hDll = LoadLibrary(MsGetExeFileName());

		if (hDll == NULL)
		{
			Alert("MsLoadLibrary() Error.",
				NULL);
			exit(0);
		}
	}

	if (software_name != NULL)
	{
		title_bar = CopyUniStr(software_name);
	}
	else
	{
		title_bar = CopyUniStr(L"SoftEther UT-VPN");
	}

	if (font != NULL)
	{
		font_name = CopyStr(font);
	}
	else
	{
		font_name = CopyStr(_SS("DEFAULT_FONT"));
	}

	if (fontsize != 0)
	{
		font_size = fontsize;
	}
	else
	{
		font_size = _II("DEFAULT_FONT_SIZE");
		if (font_size == 0)
		{
			font_size = 9;
		}
	}

	InitIconCache();

	InitFont();

	InitImageList();

	InitGdiCache();

	EnableNewStyleMode();
}

// WinUi の解放
void FreeWinUi()
{
	if ((--init_winui_counter) != 0)
	{
		return;
	}

	if (hDll == NULL)
	{
		return;
	}

	FreeImageList();

	FreeFont();

	FreeIconCache();

	FreeLibrary(hDll);
	hDll = NULL;

	Free(title_bar);
	title_bar = NULL;

	Free(font_name);
	font_name = NULL;

	WinUiDebugFree();
}

#endif	// WIN32
