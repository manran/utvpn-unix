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

// WinJumpList.cpp
// Windows7用　ジャンプリスト ソースコード

// Q. このソースコードだけ他と違ってコメントが少ないように見える。
// A. はい。

#ifdef	WIN32

//#define NTDDI_WIN7                          0x06010000
//#define	_WIN32_WINNT	_WIN32_WINNT_VISTA
//#define NTDDI_VERSION NTDDI_VISTA  // Specifies that the minimum required platform is Windows 7.
#define WIN32_LEAN_AND_MEAN       // Exclude rarely-used stuff from Windows headers
#define STRICT_TYPED_ITEMIDS      // Utilize strictly typed IDLists

//#include <objectarray.h>
#include <shobjidl.h>
#include <propkey.h>
#include <propvarutil.h>
//#include <knownfolders.h>
//#include <shlobj.h>


#ifdef StrCpy
#undef StrCpy
#endif

#ifdef StrCat
#undef StrCat
#endif

#ifdef StrCmp
#undef StrCmp
#endif


#define	WIN32HTML_CPP

//#define	_WIN32_WINNT		0x0502
//#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <comdef.h>
#include <Mshtmhst.h>
//#include <shlobj.h>
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

extern "C"
{

	//////////////////////////////////////////////////////////////////////////
	//JumpList
	// 注意: このあたりのコードは Win32 ヘッダファイル等からコピーした部分がある。
	//       ただしコピーしたのは単純な部分のみであり、創造的かつ複雑な部分ではないので
	//       GPL のコードの一部としてペーストしてあっても問題にはならないものと解釈
	//       している。

	#define CREATE_PROPERTYKEY(l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) { { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }, pid }


	JL_HRESULT JL_CreateCustomDestinationList(JL_PCustomDestinationList* poc, wchar_t* appID)
	{
		ICustomDestinationList *pcdl;

		//CLSID_DestinationList = 6332DEBF-87B5-4670-90C0-5E57-B408-A49E

		GUID destList;

		destList.Data1 = 2012286192;
		destList.Data2 = 15797;
		destList.Data3 = 18790;

		destList.Data4[0] = 181;
		destList.Data4[1] = 32;
		destList.Data4[2] = 183;
		destList.Data4[3] = 197;
		destList.Data4[4] = 79;
		destList.Data4[5] = 211;
		destList.Data4[6] = 94;
		destList.Data4[7] = 214;

		HRESULT hr = CoCreateInstance(destList, 
			NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pcdl));

		if (SUCCEEDED(hr))
		{
			pcdl->SetAppID(appID);
			(*poc) = (void*)pcdl;
		}
		else
		{
			(*poc) = NULL;
		}

		return hr;
	}

	JL_HRESULT JL_ReleaseCustomDestinationList(JL_PCustomDestinationList poc)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList*)poc;
		if(pcdl != NULL)
		{
			pcdl->Release();
		}

		return 0;
	}

	JL_HRESULT JL_BeginList(JL_PCustomDestinationList poc, JL_PObjectArray* oaRemoved)
	{
		UINT cMinSlots;
		IObjectArray *poaRemoved;

		ICustomDestinationList *pcdl = (ICustomDestinationList*)poc;

		HRESULT hr = pcdl->BeginList(&cMinSlots, IID_PPV_ARGS(&poaRemoved));

		(*oaRemoved) = poaRemoved;

		return hr;
	}

	JL_HRESULT JL_CommitList(JL_PCustomDestinationList cdl)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList*)cdl;

		return pcdl->CommitList();
	}

	JL_HRESULT JL_CreateObjectCollection(JL_PObjectCollection* jpoc)
	{

		//CLSID_EnumerableObjectCollection = 2D3468C1-36A7-43B6-AC24-D3F0-2FD9-607A


		GUID enumObjCol;

		enumObjCol.Data1 = 758409409;
		enumObjCol.Data2 = 13991;
		enumObjCol.Data3 = 17334;

		enumObjCol.Data4[0] = 172;
		enumObjCol.Data4[1] = 36;
		enumObjCol.Data4[2] = 211;
		enumObjCol.Data4[3] = 240;
		enumObjCol.Data4[4] = 47;
		enumObjCol.Data4[5] = 217;
		enumObjCol.Data4[6] = 96;
		enumObjCol.Data4[7] = 122;

		IObjectCollection *poc;
		HRESULT hr = CoCreateInstance(enumObjCol,
			NULL, CLSCTX_INPROC, IID_PPV_ARGS(&poc));

		if (SUCCEEDED(hr))
		{
			(*jpoc) = poc;
		}
		else{
			(*jpoc) = NULL;
		}
		return hr;
	}

	JL_HRESULT JL_ReleaseObjectCollection(JL_PObjectCollection jpoc)
	{
		IObjectCollection *poc = (IObjectCollection *)jpoc;
		if(poc != NULL)
		{
			return poc->Release();
		}

		return 0;
	}

	JL_HRESULT JL_ObjectCollectionAddShellLink(JL_PObjectCollection jpoc, JL_PShellLink jpsl)
	{
		IObjectCollection *poc = (IObjectCollection *)jpoc;
		IShellLink *psl = (IShellLink *) jpsl;

		return poc->AddObject(psl);

	}


	JL_HRESULT JL_AddCategoryToList(JL_PCustomDestinationList jpcdl, 
		JL_PObjectCollection jpoc, 
		wchar_t* categoryName,
		JL_PObjectArray jpoaRemoved)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList*)jpcdl;
		IObjectCollection *poc = (IObjectCollection *)jpoc;
		 IObjectArray *poaRemoved = (IObjectArray*)jpoaRemoved;

		IObjectArray *poa;
		HRESULT hr = poc->QueryInterface(IID_PPV_ARGS(&poa));
		if (SUCCEEDED(hr))
		{
		
			hr = pcdl->AppendCategory(categoryName, poa);
			poa->Release();

			if (SUCCEEDED(hr))
			{
			}
			else
			{
				Print("Failed AppendCategory\n");
			}
		}
		else
		{
			Print("Failed QueryInterface\n");
		}
		

		return hr;
	}



	JL_HRESULT JL_CreateShellLink(
		wchar_t* pszPath, 
		wchar_t* pszArguments, 
		wchar_t* pszTitle, 
		wchar_t* iconLocation,
		int iconIndex, 
		wchar_t* description, JL_PShellLink *ppsl)
	{
		IShellLinkW *psl;
		HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&psl));
		if (SUCCEEDED(hr))
		{
			psl->SetPath(pszPath);
			psl->SetArguments(pszArguments);
			if(iconLocation != NULL)
			{
				psl->SetIconLocation(iconLocation,iconIndex);
			}

			if(description != NULL)
			{
				psl->SetDescription(description);
			}
				if (SUCCEEDED(hr))
				{
					IPropertyStore *pps;
					hr = psl->QueryInterface(IID_PPV_ARGS(&pps));
					if (SUCCEEDED(hr))
					{
						PROPVARIANT propvar;
						hr = InitPropVariantFromString(pszTitle, &propvar);
						if (SUCCEEDED(hr))
						{

							PROPERTYKEY pkey_title = 
								CREATE_PROPERTYKEY(0xF29F85E0, 0x4FF9, 0x1068, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9, 2);

							hr = pps->SetValue(pkey_title, propvar);


							if (SUCCEEDED(hr))
							{
								hr = pps->Commit();
								if (SUCCEEDED(hr))
								{
									IShellLink *tpsl;
									hr = psl->QueryInterface(IID_PPV_ARGS(&tpsl));
									(*ppsl) = tpsl;
								}
							}
							PropVariantClear(&propvar);
						}
						pps->Release();
					}
				}
			psl->Release();
		}
		return hr;
	}

	JL_HRESULT JL_ReleaseShellLink(JL_PShellLink jpsl)
	{
		IShellLink *psl = (IShellLink *) jpsl;

		if(psl != NULL)
		{
			return psl->Release();
		}

		return 0;
	}

	JL_HRESULT JL_DeleteJumpList(JL_PCustomDestinationList jpcdl,wchar_t* appID)
	{
		ICustomDestinationList *pcdl = (ICustomDestinationList *)jpcdl;

		HRESULT	hr = pcdl->DeleteList(appID);


		return hr;
	}



	//////////////////////////////////////////////////////////////////////////
	//SetApplicationID for Windows 7
	JL_HRESULT JL_SetCurrentProcessExplicitAppUserModelID(wchar_t* appID)
	{
#ifdef UNICODE
		HMODULE hModule = LoadLibraryW( L"shell32.dll");
#else
		HMODULE hModule = LoadLibraryA( "shell32.dll");
#endif
		HRESULT (__stdcall *SetAppID) (PCWSTR);

		if( hModule == NULL )
		{
			Print("Not Found shell32.dll");
		}
		else
		{
			SetAppID = (HRESULT (__stdcall *)(PCWSTR))
				GetProcAddress( hModule, "SetCurrentProcessExplicitAppUserModelID" );
			if( SetAppID != NULL )
			{
				FreeLibrary( hModule );
				return SetAppID(appID);
			}
			else
			{
				Print("Not Found SetCurrentProcessExplicitAppUserModelID");

			}

			FreeLibrary( hModule );
		}
		return 0;


	}



}

#endif
