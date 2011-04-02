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

// Win32Html.c
// Win32 用 HTML 表示モジュール

// Q. ソースコード名が「HTML」となっているが、どう見ても HTML に関係のない処理
//    が入っているように見える。
// A. はい。

#ifdef	WIN32

#define	WIN32HTML_CPP

//#define	_WIN32_WINNT		0x0502
//#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <comdef.h>
#include <Mshtmhst.h>
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
extern "C"
{
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
}
#include "../PenCore/resource.h"

typedef struct FOLDER_DLG_INNER_DATA
{
	wchar_t *default_dir;
} FOLDER_DLG_INNER_DATA;

int CALLBACK FolderDlgInnerCallbackA(HWND hWnd, UINT msg, LPARAM lParam, LPARAM lData)
{
	FOLDER_DLG_INNER_DATA *data = (FOLDER_DLG_INNER_DATA *)lData;
	LPITEMIDLIST pidl;

	switch (msg)
	{
	case BFFM_INITIALIZED:
		if (data->default_dir != NULL)
		{
			char *default_dir_a = CopyUniToStr(data->default_dir);

			SendMessage(hWnd, BFFM_SETSELECTIONA, true, (LPARAM)default_dir_a);

			Free(default_dir_a);
		}
		break;

	case BFFM_SELCHANGED:
		pidl = (LPITEMIDLIST)lParam;

		if (pidl)
		{
			char tmp[MAX_PATH];

			Zero(tmp, sizeof(tmp));
			if (SHGetPathFromIDListA(pidl, tmp))
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 1);
			}
			else
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 0);
			}
		}
		break;
	}

	return 0;
}

char *FolderDlgInnerA(HWND hWnd, wchar_t *title, char *default_dir)
{
	BROWSEINFOA info;
	char display_name[MAX_PATH];
	FOLDER_DLG_INNER_DATA data;
	LPMALLOC pMalloc;
	char *ret = NULL;
	char *title_a;
	if (UniIsEmptyStr(title))
	{
		title = NULL;
	}
	if (IsEmptyStr(default_dir))
	{
		default_dir = NULL;
	}

	Zero(&data, sizeof(data));
	data.default_dir = CopyStrToUni(default_dir);

	Zero(display_name, sizeof(display_name));
	Zero(&info, sizeof(info));
	info.hwndOwner = hWnd;
	info.pidlRoot = NULL;
	info.pszDisplayName = display_name;
	title_a = CopyUniToStr(title);
	info.lpszTitle = title_a;
	info.ulFlags = BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS | BIF_VALIDATE | BIF_SHAREABLE;
	info.lpfn = FolderDlgInnerCallbackA;
	info.lParam = (LPARAM)&data;

	if (SUCCEEDED(SHGetMalloc(&pMalloc)))
	{
		LPITEMIDLIST pidl;

		pidl = SHBrowseForFolderA(&info);

		if (pidl)
		{
			char tmp[MAX_PATH];

			if (SHGetPathFromIDListA(pidl, tmp))
			{
				ret = CopyStr(tmp);
			}

			pMalloc->Free(pidl);
		}

		pMalloc->Release();
	}

	Free(data.default_dir);
	Free(title_a);

	return ret;
}

int CALLBACK FolderDlgInnerCallbackW(HWND hWnd, UINT msg, LPARAM lParam, LPARAM lData)
{
	FOLDER_DLG_INNER_DATA *data = (FOLDER_DLG_INNER_DATA *)lData;
	LPITEMIDLIST pidl;

	switch (msg)
	{
	case BFFM_INITIALIZED:
		if (data->default_dir != NULL)
		{
			SendMessage(hWnd, BFFM_SETSELECTIONW, true, (LPARAM)data->default_dir);
		}
		break;

	case BFFM_SELCHANGED:
		pidl = (LPITEMIDLIST)lParam;

		if (pidl)
		{
			wchar_t tmp[MAX_PATH];

			Zero(tmp, sizeof(tmp));
			if (SHGetPathFromIDListW(pidl, tmp))
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 1);
			}
			else
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 0);
			}
		}
		break;
	}

	return 0;
}

wchar_t *FolderDlgInnerW(HWND hWnd, wchar_t *title, wchar_t *default_dir)
{
	BROWSEINFOW info;
	wchar_t display_name[MAX_PATH];
	FOLDER_DLG_INNER_DATA data;
	LPMALLOC pMalloc;
	wchar_t *ret = NULL;
	if (UniIsEmptyStr(title))
	{
		title = NULL;
	}
	if (UniIsEmptyStr(default_dir))
	{
		default_dir = NULL;
	}

	Zero(&data, sizeof(data));
	data.default_dir = default_dir;

	Zero(display_name, sizeof(display_name));
	Zero(&info, sizeof(info));
	info.hwndOwner = hWnd;
	info.pidlRoot = NULL;
	info.pszDisplayName = display_name;
	info.lpszTitle = title;
	info.ulFlags = BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS | BIF_VALIDATE | BIF_SHAREABLE;
	info.lpfn = FolderDlgInnerCallbackW;
	info.lParam = (LPARAM)&data;

	if (SUCCEEDED(SHGetMalloc(&pMalloc)))
	{
		LPITEMIDLIST pidl;

		pidl = SHBrowseForFolderW(&info);

		if (pidl)
		{
			wchar_t tmp[MAX_PATH];

			if (SHGetPathFromIDListW(pidl, tmp))
			{
				ret = CopyUniStr(tmp);
			}

			pMalloc->Free(pidl);
		}

		pMalloc->Release();
	}

	return ret;
}


class CModule
{
public:
    CModule()
    {
        m_hInstLib = NULL;
    }
    CModule( HINSTANCE hInstLib )
    {
        m_hInstLib = NULL;
        this->Attach( hInstLib );
    }
    CModule( LPCTSTR pszModuleName )
    {
        m_hInstLib = NULL;
        this->LoadLibrary( pszModuleName );
    }
    virtual ~CModule()
    {
        this->FreeLibrary();
    }

public:
    BOOL Attach( HINSTANCE hInstLib )
    {
        this->FreeLibrary();
        m_hInstLib = hInstLib;
       
        return TRUE;
    }
    BOOL Detach()
    {
        m_hInstLib = NULL;
       
        return TRUE;
    }

public:
    HMODULE GetHandle()
    {
        return m_hInstLib;
    }
    // ＤＬＬのロード
    HINSTANCE LoadLibrary( LPCTSTR pszModuleName )
    {
        this->FreeLibrary();
        m_hInstLib = ::LoadLibrary( pszModuleName );
       
        return m_hInstLib;
    }
    // ＤＬＬの開放
    BOOL FreeLibrary()
    {
        if (m_hInstLib == NULL)
        {
            return FALSE;
        }
       
        BOOL bResult = ::FreeLibrary( m_hInstLib );
        m_hInstLib = NULL;
       
        return bResult;
    }
    // 関数のアドレスの取得
    FARPROC GetProcAddress( LPCTSTR pszProcName )
    {
        if (m_hInstLib == NULL)
        {
            return NULL;
        }
       
        return ::GetProcAddress(m_hInstLib, pszProcName);
    }
    // 指定されたタイプおよび名前を持つリソースの情報ブロックのハンドルを取得
    HRSRC FindResource(LPCTSTR lpName, LPCTSTR lpType)
    {
        if (m_hInstLib == NULL)
        {
            return NULL;
        }
       
        return ::FindResource(m_hInstLib, lpName, lpType);
    }
    // 指定されたリソースのロード
    HGLOBAL LoadResource(HRSRC hResInfo)
    {
        if (m_hInstLib == NULL)
        {
            return NULL;
        }
       
        return ::LoadResource(m_hInstLib, hResInfo);
    }

protected:
    HINSTANCE m_hInstLib;
};



static HRESULT _ShowHTMLDialog(
    HWND hwndParent,
    IMoniker* pMk,
    VARIANT* pvarArgIn = NULL,
    WCHAR* pchOptions = NULL,
    VARIANT* pvarArgOut = NULL)
{
    HRESULT hr = S_OK;
   
    try
    {
        CModule Module("MSHTML.DLL");
        if (Module.GetHandle() == NULL)
        {
            return E_FAIL;
        }
       
        SHOWHTMLDIALOGFN* fnShowHTMLDialog =
            (SHOWHTMLDIALOGFN*)Module.GetProcAddress("ShowHTMLDialog");
        if (fnShowHTMLDialog == NULL)
        {
            return E_FAIL;
        }
       
        hr = (*fnShowHTMLDialog)(hwndParent, pMk, pvarArgIn, pchOptions, pvarArgOut);
        if (FAILED(hr))
        {
            return hr;
        }
    }
    catch (...)
    {
        return E_FAIL;
    }
   
    return hr;
}

HRESULT ShowHTMLDialogFromURL(HWND hwndParent,wchar_t *szURL,VARIANT* pvarArgIn,WCHAR* pchOptions,VARIANT* pvarArgOut)
{
    HRESULT hr = S_OK;
   
    try
    {
        IMonikerPtr spMoniker;
        hr = ::CreateURLMoniker(NULL, szURL, &spMoniker);
        if (FAILED(hr))
        {
            return hr;
        }
       
        hr = ::_ShowHTMLDialog(hwndParent, spMoniker, pvarArgIn, pchOptions, pvarArgOut);
        if (FAILED(hr))
        {
            return hr;
        }
    }
    catch (...)
    {
        return E_FAIL;
    }
   
    return hr;
}

// ショートカットの作成
bool CreateLinkInnerA(char *filename, char *target, char *workdir, char *args,
				     char *comment, char *icon, UINT icon_index)
{
	HRESULT r;
	wchar_t tmp[MAX_SIZE];
	IShellLinkA* pShellLink;
	IPersistFile* pPersistFile;

	r = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkA, (void **)&pShellLink);
	if (FAILED(r))
	{
		return false;
	}

	r = pShellLink->QueryInterface(IID_IPersistFile,(void **)&pPersistFile);
	if (FAILED(r))
	{
		pShellLink->Release();
		return false;
	}

	r = pShellLink->SetPath(target);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	if (workdir != NULL)
	{
		r = pShellLink->SetWorkingDirectory(workdir);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (args != NULL)
	{
		r = pShellLink->SetArguments(args);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (comment != NULL)
	{
		r = pShellLink->SetDescription(comment);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (icon != NULL)
	{
		r = pShellLink->SetIconLocation(icon, icon_index);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	StrToUni(tmp, sizeof(tmp), filename);
	r = pPersistFile->Save(tmp, true);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	pShellLink->Release();
	pPersistFile->Release();
	return true;
}
bool CreateLinkInner(wchar_t *filename, wchar_t *target, wchar_t *workdir, wchar_t *args,
				     wchar_t *comment, wchar_t *icon, UINT icon_index)
{
	HRESULT r;
	bool ret;
	IShellLinkW* pShellLink;
	IPersistFile* pPersistFile;

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		char *a1, *a2, *a3, *a4, *a5, *a6;
		a1 = CopyUniToStr(filename);
		a2 = CopyUniToStr(target);
		a3 = CopyUniToStr(workdir);
		a4 = CopyUniToStr(args);
		a5 = CopyUniToStr(icon);
		a6 = CopyUniToStr(comment);

		ret = CreateLinkInnerA(a1, a2, a3, a4, a6, a5, icon_index);

		Free(a1);
		Free(a2);
		Free(a3);
		Free(a4);
		Free(a5);
		Free(a6);

		return ret;
	}

	r = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void **)&pShellLink);
	if (FAILED(r))
	{
		return false;
	}

	r = pShellLink->QueryInterface(IID_IPersistFile,(void **)&pPersistFile);
	if (FAILED(r))
	{
		pShellLink->Release();
		return false;
	}

	r = pShellLink->SetPath(target);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	if (workdir != NULL)
	{
		r = pShellLink->SetWorkingDirectory(workdir);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (comment != NULL)
	{
		r = pShellLink->SetDescription(comment);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (args != NULL)
	{
		r = pShellLink->SetArguments(args);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (icon != NULL)
	{
		r = pShellLink->SetIconLocation(icon, icon_index);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	r = pPersistFile->Save(filename, true);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	pShellLink->Release();
	pPersistFile->Release();
	return true;
}

extern "C"
{

// フォルダ選択ダイアログの表示
wchar_t *FolderDlgW(HWND hWnd, wchar_t *title, wchar_t *default_dir)
{
	wchar_t *ret;

	if (MsIsNt() == false)
	{
		char *default_dir_a = CopyUniToStr(default_dir);
		char *ret_a = FolderDlgA(hWnd, title, default_dir_a);

		ret = CopyStrToUni(ret_a);
		Free(ret_a);
		Free(default_dir_a);

		return ret;
	}

	ret = FolderDlgInnerW(hWnd, title, default_dir);

	return ret;
}
char *FolderDlgA(HWND hWnd, wchar_t *title, char *default_dir)
{
	char *ret;

	ret = FolderDlgInnerA(hWnd, title, default_dir);

	return ret;
}

// ショートカットの作成
bool CreateLink(wchar_t *filename, wchar_t *target, wchar_t *workdir, wchar_t *args,
				wchar_t *comment, wchar_t *icon, UINT icon_index)
{
	if (filename == NULL || target == NULL)
	{
		return false;
	}

	return CreateLinkInner(filename, target, workdir, args, comment, icon, icon_index);
}

// HTML の表示
void ShowHtml(HWND hWnd, char *url, wchar_t *option)
{
	wchar_t tmp[MAX_SIZE];
	// 引数チェック
	if (url == NULL || option == NULL)
	{
		return;
	}

	StrToUni(tmp, sizeof(tmp), url);

	ShowHTMLDialogFromURL(hWnd, tmp, NULL, option, NULL);
}

}

#endif
