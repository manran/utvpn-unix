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

// Unix.c
// UNIX 依存コード

#ifdef	UNIX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// MacOS X 用の struct statfs
#ifdef	UNIX_MACOS
typedef struct fsid { int32_t val[2]; } fsid_t;
struct statfs {
        short   f_otype;                /* TEMPORARY SHADOW COPY OF f_type */
        short   f_oflags;               /* TEMPORARY SHADOW COPY OF f_flags */
        long    f_bsize;                /* fundamental file system block size */
        long    f_iosize;               /* optimal transfer block size */
        long    f_blocks;               /* total data blocks in file system */
        long    f_bfree;                /* free blocks in fs */
        long    f_bavail;               /* free blocks avail to non-superuser */
        long    f_files;                /* total file nodes in file system */
        long    f_ffree;                /* free file nodes in fs */
        fsid_t  f_fsid;                 /* file system id */
        uid_t   f_owner;                /* user that mounted the filesystem */
        short   f_reserved1;    /* spare for later */
        short   f_type;                 /* type of filesystem */
    long        f_flags;                /* copy of mount exported flags */
        long    f_reserved2[2]; /* reserved for future use */
        char    f_fstypename[15]; /* fs type name */
        char    f_mntonname[90];  /* directory on which mounted */
        char    f_mntfromname[90];/* mounted filesystem */
};
#endif	// UNIX_MACOS

// Solaris 用の scandir() 関数
#ifdef	UNIX_SOLARIS
#define scandir local_scandir
#define	alphasort local_alphasort

/*******************************************
 * Copyright Free の互換ルーチン (local_scandir)
 * コピー元: http://www005.upp.so-net.ne.jp/yoga/compile.html
 *******************************************/

int local_scandir(const char *dir, struct dirent ***namelist,
            int (*select)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **))
{
  DIR *d;
  struct dirent *entry;
  register int i=0;
  size_t entrysize;

  if ((d=opendir(dir)) == NULL)
     return(-1);

  *namelist=NULL;
  while ((entry=readdir(d)) != NULL)
  {
    if (select == NULL || (select != NULL && (*select)(entry)))
    {
      *namelist=(struct dirent **)realloc((void *)(*namelist),
                 (size_t)((i+1)*sizeof(struct dirent *)));
	if (*namelist == NULL) return(-1);
	entrysize=sizeof(struct dirent)-sizeof(entry->d_name)+strlen(entry->d_name)+1;
	(*namelist)[i]=(struct dirent *)malloc(entrysize);
	if ((*namelist)[i] == NULL) return(-1);
	memcpy((*namelist)[i], entry, entrysize);
	i++;
    }
  }
  if (closedir(d)) return(-1);
  if (i == 0) return(-1);
  if (compar != NULL)
    qsort((void *)(*namelist), (size_t)i, sizeof(struct dirent *), compar);
    
  return(i);
}

int local_alphasort(const struct dirent **a, const struct dirent **b)
{
  return(strcmp((*a)->d_name, (*b)->d_name));
}


#endif	// UNIX_SOLARIS

// UNIX 用スレッドデータ
typedef struct UNIXTHREAD
{
	pthread_t thread;
	bool finished;
} UNIXTHREAD;

// UNIX 用スレッド起動情報
typedef struct UNIXTHREADSTARTUPINFO
{
	THREAD_PROC *thread_proc;
	void *param;
	THREAD *thread;
} UNIXTHREADSTARTUPINFO;

// UNIX 用スレッド関数プロトタイプ
void *UnixDefaultThreadProc(void *param);

// 現在のプロセス ID
static pid_t current_process_id = 0;

// UNIX 用ファイル I/O データ
typedef struct UNIXIO
{
	int fd;
	bool write_mode;
} UNIXIO;

// UNIX 用ロックファイルデータ
typedef struct UNIXLOCKFILE
{
	char FileName[MAX_SIZE];
	int fd;
} UNIXLOCKFILE;

// UNIX 用イベントデータ
typedef struct UNIXEVENT
{
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool signal;
} UNIXEVENT;

static pthread_mutex_t get_time_lock;
static pthread_mutex_t malloc_lock;
static bool high_process = false;

static bool unix_svc_terminate = false;
static int solaris_sleep_p1 = -1, solaris_sleep_p2 = -1;

// ディスパッチテーブルの作成
OS_DISPATCH_TABLE *UnixGetDispatchTable()
{
	static OS_DISPATCH_TABLE t =
	{
		UnixInit,
		UnixFree,
		UnixMemoryAlloc,
		UnixMemoryReAlloc,
		UnixMemoryFree,
		UnixGetTick,
		UnixGetSystemTime,
		UnixInc32,
		UnixDec32,
		UnixSleep,
		UnixNewLock,
		UnixLock,
		UnixUnlock,
		UnixDeleteLock,
		UnixInitEvent,
		UnixSetEvent,
		UnixResetEvent,
		UnixWaitEvent,
		UnixFreeEvent,
		UnixWaitThread,
		UnixFreeThread,
		UnixInitThread,
		UnixThreadId,
		UnixFileOpen,
		UnixFileOpenW,
		UnixFileCreate,
		UnixFileCreateW,
		UnixFileWrite,
		UnixFileRead,
		UnixFileClose,
		UnixFileFlush,
		UnixFileSize,
		UnixFileSeek,
		UnixFileDelete,
		UnixFileDeleteW,
		UnixMakeDir,
		UnixMakeDirW,
		UnixDeleteDir,
		UnixDeleteDirW,
		UnixGetCallStack,
		UnixGetCallStackSymbolInfo,
		UnixFileRename,
		UnixFileRenameW,
		UnixRun,
		UnixRunW,
		UnixIsSupportedOs,
		UnixGetOsInfo,
		UnixAlert,
		UnixAlertW,
		UnixGetProductId,
		UnixSetHighPriority,
		UnixRestorePriority,
		UnixNewSingleInstance,
		UnixFreeSingleInstance,
		UnixGetMemInfo,
		UnixYield,
	};

	return &t;
}

// Solaris 用 Sleep の初期化
void UnixInitSolarisSleep()
{
	char tmp[MAX_SIZE];

	UnixNewPipe(&solaris_sleep_p1, &solaris_sleep_p2);
	read(solaris_sleep_p1, tmp, sizeof(tmp));
}

// Solaris 用 Sleep の解放
void UnixFreeSolarisSleep()
{
	UnixDeletePipe(solaris_sleep_p1, solaris_sleep_p2);
	solaris_sleep_p1 = -1;
	solaris_sleep_p2 = -1;
}

// Solaris 用 Sleep
void UnixSolarisSleep(UINT msec)
{
	struct pollfd p;

	memset(&p, 0, sizeof(p));
	p.fd = solaris_sleep_p1;
	p.events = POLLIN;

	poll(&p, 1, msec == INFINITE ? -1 : (int)msec);
}

// ディスクの空き容量を取得する
bool UnixGetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	char *path_a = CopyUniToStr(path);
	bool ret;

	ret = UnixGetDiskFree(path_a, free_size, used_size, total_size);

	Free(path_a);

	return ret;
}
bool UnixGetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	char tmp[MAX_PATH];
	bool ret = false;
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	NormalizePath(tmp, sizeof(tmp), path);

	while ((ret = UnixGetDiskFreeMain(tmp, free_size, used_size, total_size)) == false)
	{
		if (StrCmpi(tmp, "/") == 0)
		{
			break;
		}

		GetDirNameFromFilePath(tmp, sizeof(tmp), tmp);
	}

	return ret;
}
bool UnixGetDiskFreeMain(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
#ifndef	USE_STATVFS
	struct statfs st;
	char tmp[MAX_PATH];
	UINT64 v1 = 0, v2 = 0;
	bool ret = false;
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	NormalizePath(tmp, sizeof(tmp), path);

	Zero(&st, sizeof(st));
	if (statfs(tmp, &st) == 0)
	{
		v1 = (UINT64)st.f_bsize * (UINT64)st.f_bavail;
		v2 = (UINT64)st.f_bsize * (UINT64)st.f_blocks;
		ret = true;
	}

	if (free_size != NULL)
	{
		*free_size = v1;
	}

	if (total_size != NULL)
	{
		*total_size = v2;
	}

	if (used_size != NULL)
	{
		*used_size = v2 - v1;
	}

	return ret;
#else	// USE_STATVFS
	struct statvfs st;
	char tmp[MAX_PATH];
	UINT64 v1 = 0, v2 = 0;
	bool ret = false;
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	NormalizePath(tmp, sizeof(tmp), path);

	Zero(&st, sizeof(st));

	if (statvfs(tmp, &st) == 0)
	{
		v1 = (UINT64)st.f_bsize * (UINT64)st.f_bavail;
		v2 = (UINT64)st.f_bsize * (UINT64)st.f_blocks;
		ret = true;
	}

	if (free_size != NULL)
	{
		*free_size = v1;
	}

	if (total_size != NULL)
	{
		*total_size = v2;
	}

	if (used_size != NULL)
	{
		*used_size = v2 - v1;
	}

	return ret;
#endif	// USE_STATVFS
}

// ディレクトリ列挙
DIRLIST *UnixEnumDirEx(char *dirname, COMPARE *compare)
{
	char tmp[MAX_PATH];
	DIRLIST *d;
	int n;
	struct dirent **e;
	LIST *o;
	// 引数チェック
	if (dirname == NULL)
	{
		return NULL;
	}

	o = NewListFast(compare);

	NormalizePath(tmp, sizeof(tmp), dirname);

	if (StrLen(tmp) >= 1 && tmp[StrLen(tmp) - 1] != '/')
	{
		StrCat(tmp, sizeof(tmp), "/");
	}

	e = NULL;
	n = scandir(tmp, &e, 0, alphasort);

	if (StrLen(tmp) >= 1 && tmp[StrLen(tmp) - 1] == '/')
	{
		tmp[StrLen(tmp) - 1] = 0;
	}

	if (n >= 0 && e != NULL)
	{
		UINT i;

		for (i = 0;i < (UINT)n;i++)
		{
			char *filename = e[i]->d_name;

			if (filename != NULL)
			{
				if (StrCmpi(filename, "..") != 0 && StrCmpi(filename, ".") != 0)
				{
					char fullpath[MAX_PATH];
					struct stat st;
					Format(fullpath, sizeof(fullpath), "%s/%s", tmp, filename);

					Zero(&st, sizeof(st));

					if (stat(fullpath, &st) == 0)
					{
						DIRENT *f = ZeroMalloc(sizeof(DIRENT));
						SYSTEMTIME t;

						f->Folder = S_ISDIR(st.st_mode) ? true : false;
						f->FileName = CopyStr(filename);
						f->FileNameW = CopyUtfToUni(f->FileName);

						Zero(&t, sizeof(t));
						TimeToSystem(&t, st.st_ctime);
						f->CreateDate = LocalToSystem64(SystemToUINT64(&t));

						Zero(&t, sizeof(t));
						TimeToSystem(&t, st.st_mtime);
						f->UpdateDate = LocalToSystem64(SystemToUINT64(&t));

						if (f->Folder == false)
						{
							f->FileSize = st.st_size;
						}

						Add(o, f);
					}
				}
			}

			free(e[i]);
		}

		free(e);
	}

	Sort(o);

	d = ZeroMalloc(sizeof(DIRLIST));
	d->NumFiles = LIST_NUM(o);
	d->File = ToArray(o);

	ReleaseList(o);

	return d;
}
DIRLIST *UnixEnumDirExW(wchar_t *dirname, COMPARE *compare)
{
	char *dirname_a = CopyUniToUtf(dirname);
	DIRLIST *ret;

	ret = UnixEnumDirEx(dirname_a, compare);

	Free(dirname_a);

	return ret;
}

// 指定したファイルの実行権限をチェックする
bool UnixCheckExecAccess(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (access(name, X_OK) == 0)
	{
		return true;
	}

	return false;
}
bool UnixCheckExecAccessW(wchar_t *name)
{
	char *name_a;
	bool ret;
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	name_a = CopyUniToUtf(name);

	ret = UnixCheckExecAccess(name_a);

	Free(name_a);

	return ret;
}

// スレッドの優先順位を最高にする
void UnixSetThreadPriorityRealtime()
{
	struct sched_param p;
	Zero(&p, sizeof(p));
	p.sched_priority = 255;
	pthread_setschedparam(pthread_self(), SCHED_RR, &p);
}

// スレッドの優先順位を低くする
void UnixSetThreadPriorityLow()
{
	struct sched_param p;
	Zero(&p, sizeof(p));
	p.sched_priority = 32;
	pthread_setschedparam(pthread_self(), SCHED_OTHER, &p);
}

// スレッドの優先順位を高くする
void UnixSetThreadPriorityHigh()
{
	struct sched_param p;
	Zero(&p, sizeof(p));
	p.sched_priority = 127;
	pthread_setschedparam(pthread_self(), SCHED_RR, &p);
}

// スレッドの優先順位をアイドルにする
void UnixSetThreadPriorityIdle()
{
	struct sched_param p;
	Zero(&p, sizeof(p));
	p.sched_priority = 1;
	pthread_setschedparam(pthread_self(), SCHED_OTHER, &p);
}

// スレッドの優先順位を標準に戻す
void UnixRestoreThreadPriority()
{
	struct sched_param p;
	Zero(&p, sizeof(p));
	p.sched_priority = 64;
	pthread_setschedparam(pthread_self(), SCHED_OTHER, &p);
}

// 現在のディレクトリの取得
void UnixGetCurrentDir(char *dir, UINT size)
{
	// 引数チェック
	if (dir == NULL)
	{
		return;
	}

	getcwd(dir, size);
}
void UnixGetCurrentDirW(wchar_t *dir, UINT size)
{
	char dir_a[MAX_PATH];

	UnixGetCurrentDir(dir_a, sizeof(dir_a));

	UtfToUni(dir, size, dir_a);
}

// イールド
void UnixYield()
{
#ifdef UNIX_SOLARIS
	UnixSolarisSleep(1);
#else
	sleep(1);
#endif
}

// メモリ情報の取得
void UnixGetMemInfo(MEMINFO *info)
{
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	// 知らん！！
	Zero(info, sizeof(MEMINFO));
}

// シングルインスタンスの解放
void UnixFreeSingleInstance(void *data)
{
	UNIXLOCKFILE *o;
	struct flock lock;
	// 引数チェック
	if (data == NULL)
	{
		return;
	}

	o = (UNIXLOCKFILE *)data;

	Zero(&lock, sizeof(lock));
	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;

	fcntl(o->fd, F_SETLK, &lock);
	close(o->fd);

	remove(o->FileName);

	Free(data);
}

// シングルインスタンスの作成
void *UnixNewSingleInstance(char *instance_name)
{
	UNIXLOCKFILE *ret;
	char tmp[MAX_SIZE];
	char name[MAX_SIZE];
	char dir[MAX_PATH];
	int fd;
	struct flock lock;
	// 引数チェック
	if (instance_name == NULL)
	{
		GetExeName(tmp, sizeof(tmp));
		HashInstanceName(tmp, sizeof(tmp), tmp);
	}
	else
	{
		StrCpy(tmp, sizeof(tmp), instance_name);
	}

	GetExeDir(dir, sizeof(dir));

	// ファイル名の生成
	Format(name, sizeof(name), "%s/.%s", dir, tmp);

	fd = open(name, O_WRONLY);
	if (fd == -1)
	{
		fd = creat(name, 0600);
	}
	if (fd == -1)
	{
		Format(tmp, sizeof(tmp), "Unable to create %s.", name);
		Alert(tmp, NULL);
		exit(0);
		return NULL;
	}

	Zero(&lock, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &lock) == -1)
	{
		return NULL;
	}
	else
	{
		ret = ZeroMalloc(sizeof(UNIXLOCKFILE));
		ret->fd = fd;
		StrCpy(ret->FileName, sizeof(ret->FileName), name);
		return (void *)ret;
	}
}

// プロセスの優先順位を上げる
void UnixSetHighPriority()
{
	if (high_process == false)
	{
		UINT pid = getpid();
		UINT pgid = getpgid(pid);

		high_process = true;
		nice(-20);

		setpriority(PRIO_PROCESS, pid, -20);
		setpriority(PRIO_PGRP, pgid, -20);
	}
}

// プロセスの優先順位を戻す
void UnixRestorePriority()
{
	if (high_process != false)
	{
		high_process = false;
		nice(20);
	}
}

// プロダクト ID を取得する
char *UnixGetProductId()
{
	return CopyStr("--");
}

// アラートを表示する
void UnixAlertW(wchar_t *msg, wchar_t *caption)
{
	char *msg8 = CopyUniToUtf(msg);
	char *caption8 = CopyUniToUtf(caption);

	UnixAlert(msg8, caption8);

	Free(msg8);
	Free(caption8);
}
void UnixAlert(char *msg, char *caption)
{
	char *tag =
		"-- Alert: %s --\n%s\n";
	// 引数チェック
	if (msg == NULL)
	{
		msg = "Alert";
	}
	if (caption == NULL)
	{
		caption = "SoftEther UT-VPN Kernel";
	}

	printf(tag, caption, msg);
}

// 現在の OS の情報を取得する
void UnixGetOsInfo(OS_INFO *info)
{
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	Zero(info, sizeof(OS_INFO));
	info->OsType = OSTYPE_UNIX_UNKNOWN;

#ifdef	UNIX_SOLARIS
	info->OsType = OSTYPE_SOLARIS;
#endif	// UNIX_SOLARIS

#ifdef	UNIX_CYGWIN
	info->OsType = OSTYPE_CYGWIN;
#endif	// UNIX_CYGWIN

#ifdef	UNIX_MACOS
	info->OsType = OSTYPE_MACOS_X;
#endif	// UNIX_MACOS

#ifdef	UNIX_BSD
	info->OsType = OSTYPE_BSD;
#endif	// UNIX_BSD

#ifdef	UNIX_LINUX
	info->OsType = OSTYPE_LINUX;
#endif	// UNIX_LINUX

	info->OsServicePack = 0;

	if (info->OsType != OSTYPE_LINUX)
	{
		info->OsSystemName = CopyStr("UNIX");
		info->OsProductName = CopyStr("UNIX");
	}
	else
	{
		info->OsSystemName = CopyStr("Linux");
		info->OsProductName = CopyStr("Linux");
	}

	if (info->OsType == OSTYPE_LINUX)
	{
		// Linux の場合 ディストリビューション名を取得する
		BUF *b;
		b = ReadDump("/etc/redhat-release");
		if (b != NULL)
		{
			info->OsVersion = CfgReadNextLine(b);
			info->OsVendorName = CopyStr("Red Hat, Inc.");
			FreeBuf(b);
		}
		else
		{
			b = ReadDump("/etc/turbolinux-release");
			if (b != NULL)
			{
				info->OsVersion = CfgReadNextLine(b);
				info->OsVendorName = CopyStr("Turbolinux, Inc.");
				FreeBuf(b);
			}
			else
			{
				info->OsVersion = CopyStr("Unknown Liunx Version");
				info->OsVendorName = CopyStr("Unknown Vendor");
			}
		}

		info->KernelName = CopyStr("Linux Kernel");

		b = ReadDump("/proc/sys/kernel/osrelease");
		if (b != NULL)
		{
			info->KernelVersion = CfgReadNextLine(b);
			FreeBuf(b);
		}
		else
		{
			info->KernelVersion = CopyStr("Unknown Version");
		}
	}
	else
	{
		// その他の場合
		info->OsProductName = CopyStr(OsTypeToStr(info->OsType));
		info->OsVersion = CopyStr("Unknown Version");
		info->KernelName = CopyStr(OsTypeToStr(info->OsType));
		info->KernelVersion = CopyStr("Unknown Version");
	}
}

// 現在の OS が SoftEther UT-VPN Kernel によってサポートされているかどうか調べる
bool UnixIsSupportedOs()
{
	// すべての起動可能な UNIX OS をサポートしている
	return true;
}

// 指定したコマンドを実行する
bool UnixRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	char *filename8 = CopyUniToUtf(filename);
	char *arg8 = CopyUniToUtf(arg);
	bool ret = UnixRun(filename8, arg8, hide, wait);

	Free(filename8);
	Free(arg8);

	return ret;
}
bool UnixRun(char *filename, char *arg, bool hide, bool wait)
{
	TOKEN_LIST *t;
	UINT ret;
	// 引数チェック
	if (filename == NULL)
	{
		return false;
	}
	if (arg == NULL)
	{
		arg = "";
	}

	// 子プロセス作成
	ret = fork();
	if (ret == -1)
	{
		// 子プロセス作成失敗
		return false;
	}

	if (ret == 0)
	{
		Print("", filename, arg);
		// 子プロセス
		if (hide)
		{
			// 標準入出力を閉じる
			UnixCloseIO();
		}

		t = ParseToken(arg, " ");
		if (t == NULL)
		{
			AbortExit();
		}
		else
		{
			char **args;
			UINT num_args;
			UINT i;
			num_args = t->NumTokens + 2;
			args = ZeroMalloc(sizeof(char *) * num_args);
			args[0] = filename;
			for (i = 1;i < num_args - 1;i++)
			{
				args[i] = t->Token[i - 1];
			}
			execvp(filename, args);
			AbortExit();
		}
	}
	else
	{
		// 親プロセス
		pid_t pid = (pid_t)ret;

		if (wait)
		{
			int status = 0;
			// 子プロセスの終了を待機する
			if (waitpid(pid, &status, 0) == -1)
			{
				return false;
			}

			if (WEXITSTATUS(status) == 0)
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		return true;
	}
}

// デーモンの初期化
void UnixDaemon(bool debug_mode)
{
	UINT ret;

	if (debug_mode)
	{
		// デバッグモード
		signal(SIGHUP, SIG_IGN);
		return;
	}

	ret = fork();

	if (ret == -1)
	{
		// エラー
		return;
	}
	else if (ret == 0)
	{
		// 子プロセス用に新しいセッションを作成する
		setsid();

		// 標準入出力をクローズする
		UnixCloseIO();

		// 不要なシグナルを停止する
		signal(SIGHUP, SIG_IGN);
	}
	else
	{
		// 親プロセスを終了する
		exit(0);
	}
}

// 標準入出力をクローズする
void UnixCloseIO()
{
	static bool close_io_first = false;

	// 1 回しか実行できない
	if (close_io_first)
	{
		return;
	}
	else
	{
		close(0);
		close(1);
		close(2);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		close_io_first = false;
	}
}

// ファイル名を変更する
bool UnixFileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	char *old_name8 = CopyUniToUtf(old_name);
	char *new_name8 = CopyUniToUtf(new_name);
	bool ret = UnixFileRename(old_name8, new_name8);

	Free(old_name8);
	Free(new_name8);

	return ret;
}
bool UnixFileRename(char *old_name, char *new_name)
{
	// 引数チェック
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	if (rename(old_name, new_name) != 0)
	{
		return false;
	}

	return true;
}

// コールスタックを取得する
CALLSTACK_DATA *UnixGetCallStack()
{
	// Win32 以外ではサポートされていない
	return NULL;
}

// コールスタックからシンボル情報を取得
bool UnixGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	// Win32 以外ではサポートされていない
	return false;
}

// ディレクトリを削除する
bool UnixDeleteDirW(wchar_t *name)
{
	char *name8 = CopyUniToUtf(name);
	bool ret = UnixDeleteDir(name8);

	Free(name8);

	return ret;
}
bool UnixDeleteDir(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (rmdir(name) != 0)
	{
		return false;
	}

	return true;
}

// ディレクトリを作成する
bool UnixMakeDirW(wchar_t *name)
{
	char *name8 = CopyUniToUtf(name);
	bool ret = UnixMakeDir(name8);

	Free(name8);

	return ret;
}
bool UnixMakeDir(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (mkdir(name, 0700) != 0)
	{
		return false;
	}

	return true;
}

// ファイルを削除する
bool UnixFileDeleteW(wchar_t *name)
{
	bool ret;
	char *name8 = CopyUniToUtf(name);

	ret = UnixFileDelete(name8);

	Free(name8);

	return ret;
}
bool UnixFileDelete(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (remove(name) != 0)
	{
		return false;
	}

	return true;
}

// ファイルをシークする
bool UnixFileSeek(void *pData, UINT mode, int offset)
{
	UNIXIO *p;
	UINT ret;
	// 引数チェック
	if (pData == NULL)
	{
		return 0;
	}
	if (mode != FILE_BEGIN && mode != FILE_END && mode != FILE_CURRENT)
	{
		return false;
	}

	p = (UNIXIO *)pData;

	ret = lseek(p->fd, offset, mode);

	if (ret == -1)
	{
		return false;
	}

	return true;
}

// ファイルサイズを取得する
UINT64 UnixFileSize(void *pData)
{
	struct stat st;
	UNIXIO *p;
	// 引数チェック
	if (pData == NULL)
	{
		return 0;
	}

	p = (UNIXIO *)pData;

	if (fstat(p->fd, &st) != 0)
	{
		return 0;
	}

	return (UINT64)st.st_size;
}

// ファイルに書き込む
bool UnixFileWrite(void *pData, void *buf, UINT size)
{
	UNIXIO *p;
	UINT ret;
	// 引数チェック
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (UNIXIO *)pData;

	ret = write(p->fd, buf, size);
	if (ret != size)
	{
		return false;
	}

	return true;
}

// ファイルから読み込む
bool UnixFileRead(void *pData, void *buf, UINT size)
{
	UNIXIO *p;
	UINT ret;
	// 引数チェック
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (UNIXIO *)pData;

	ret = read(p->fd, buf, size);
	if (ret != size)
	{
		return false;
	}

	return true;
}

// ファイルをフラッシュする
void UnixFileFlush(void *pData)
{
	UNIXIO *p;
	bool write_mode;
	// 引数チェック
	if (pData == NULL)
	{
		return;
	}

	p = (UNIXIO *)pData;

	write_mode = p->write_mode;

	if (write_mode)
	{
		fsync(p->fd);
	}
}

// ファイルを閉じる
void UnixFileClose(void *pData, bool no_flush)
{
	UNIXIO *p;
	bool write_mode;
	// 引数チェック
	if (pData == NULL)
	{
		return;
	}

	p = (UNIXIO *)pData;

	write_mode = p->write_mode;

	if (write_mode && no_flush == false)
	{
		fsync(p->fd);
	}

	close(p->fd);

	UnixMemoryFree(p);

	if (write_mode)
	{
		//sync();
	}
}

// ファイルを作成する
void *UnixFileCreateW(wchar_t *name)
{
	void *ret;
	char *name8 = CopyUniToUtf(name);

	ret = UnixFileCreate(name8);

	Free(name8);

	return ret;
}
void *UnixFileCreate(char *name)
{
	UNIXIO *p;
	int fd;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	fd = creat(name, 0600);
	if (fd == -1)
	{
		return NULL;
	}

	// メモリ確保
	p = UnixMemoryAlloc(sizeof(UNIXIO));
	p->fd = fd;
	p->write_mode = true;

	return (void *)p;
}

// ファイルを開く
void *UnixFileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	char *name8 = CopyUniToUtf(name);
	void *ret;

	ret = UnixFileOpen(name8, write_mode, read_lock);

	Free(name8);

	return ret;
}
void *UnixFileOpen(char *name, bool write_mode, bool read_lock)
{
	UNIXIO *p;
	int fd;
	int mode;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	if (write_mode == false)
	{
		mode = O_RDONLY;
	}
	else
	{
		mode = O_RDWR;
	}

	// ファイルを開く
	fd = open(name, mode);
	if (fd == -1)
	{
		return NULL;
	}

	// メモリ確保
	p = UnixMemoryAlloc(sizeof(UNIXIO));
	p->fd = fd;
	p->write_mode = write_mode;

	return (void *)p;
}

// 現在のスレッド ID を返す
UINT UnixThreadId()
{
	UINT ret;

	ret = (UINT)pthread_self();

	return ret;
}

// スレッド関数
void *UnixDefaultThreadProc(void *param)
{
	UNIXTHREAD *ut;
	UNIXTHREADSTARTUPINFO *info = (UNIXTHREADSTARTUPINFO *)param;
	if (info == NULL)
	{
		return 0;
	}

	ut = (UNIXTHREAD *)info->thread->pData;

	// スレッド関数の呼び出し
	info->thread_proc(info->thread, info->param);

	// 終了フラグを立てる
	ut->finished = true;

	// 参照の解放
	ReleaseThread(info->thread);

	UnixMemoryFree(info);

	FreeOpenSSLThreadState();

	return 0;
}

// スレッドの解放
void UnixFreeThread(THREAD *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	// メモリの解放
	UnixMemoryFree(t->pData);
}

// スレッドの終了を待機
bool UnixWaitThread(THREAD *t)
{
	UNIXTHREAD *ut;
	void *retcode = NULL;
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}
	ut = (UNIXTHREAD *)t->pData;
	if (ut == NULL)
	{
		return false;
	}

	pthread_join(ut->thread, &retcode);

	return true;
}

// スレッドの初期化
bool UnixInitThread(THREAD *t)
{
	UNIXTHREAD *ut;
	UNIXTHREADSTARTUPINFO *info;
	pthread_attr_t attr;
	// 引数チェック
	if (t == NULL || t->thread_proc == NULL)
	{
		return false;
	}

	// スレッドデータ作成
	ut = UnixMemoryAlloc(sizeof(UNIXTHREAD));
	Zero(ut, sizeof(UNIXTHREAD));

	// 起動情報作成
	info = UnixMemoryAlloc(sizeof(UNIXTHREADSTARTUPINFO));
	Zero(info, sizeof(UNIXTHREADSTARTUPINFO));
	info->param = t->param;
	info->thread_proc = t->thread_proc;
	info->thread = t;
	AddRef(t->ref);

	// スレッド作成
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, UNIX_THREAD_STACK_SIZE);

	t->pData = (void *)ut;

	if (pthread_create(&ut->thread, &attr, UnixDefaultThreadProc, info) != 0)
	{
		// エラー発生
		t->pData = NULL;
		Release(t->ref);
		UnixMemoryFree(ut);
		UnixMemoryFree(info);
		pthread_attr_destroy(&attr);
		return false;
	}

	pthread_attr_destroy(&attr);

	return true;
}

// イベントの解放
void UnixFreeEvent(EVENT *event)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	if (ue == NULL)
	{
		return;
	}

	pthread_cond_destroy(&ue->cond);
	pthread_mutex_destroy(&ue->mutex);

	UnixMemoryFree(ue);
}

// イベントの待機
bool UnixWaitEvent(EVENT *event, UINT timeout)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	struct timeval now;
	struct timespec to;
	bool ret;
	if (ue == NULL)
	{
		return false;
	}

	pthread_mutex_lock(&ue->mutex);
	gettimeofday(&now, NULL);
	to.tv_sec = now.tv_sec + timeout / 1000;
	to.tv_nsec = now.tv_usec * 1000 + (timeout % 1000) * 1000 * 1000;
	if ((to.tv_nsec / 1000000000) >= 1)
	{
		to.tv_sec += to.tv_nsec / 1000000000;
		to.tv_nsec = to.tv_nsec % 1000000000;
	}

	ret = true;

	while (ue->signal == false)
	{
		if (timeout != INFINITE)
		{
			if (pthread_cond_timedwait(&ue->cond, &ue->mutex, &to))
			{
				ret = false;
				break;
			}
		}
		else
		{
			pthread_cond_wait(&ue->cond, &ue->mutex);
		}
	}
	ue->signal = false;

	pthread_mutex_unlock(&ue->mutex);

	return ret;
}

// イベントのリセット
void UnixResetEvent(EVENT *event)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	if (ue == NULL)
	{
		return;
	}

	pthread_mutex_lock(&ue->mutex);
	ue->signal = false;
	pthread_cond_signal(&ue->cond);
	pthread_mutex_unlock(&ue->mutex);
}

// イベントのセット
void UnixSetEvent(EVENT *event)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	if (ue == NULL)
	{
		return;
	}

	pthread_mutex_lock(&ue->mutex);
	ue->signal = true;
	pthread_cond_signal(&ue->cond);
	pthread_mutex_unlock(&ue->mutex);
}

// イベントの初期化
void UnixInitEvent(EVENT *event)
{
	UNIXEVENT *ue = UnixMemoryAlloc(sizeof(UNIXEVENT));

	Zero(ue, sizeof(UNIXEVENT));

	pthread_cond_init(&ue->cond, NULL);
	pthread_mutex_init(&ue->mutex, NULL);
	ue->signal = false;

	event->pData = (void *)ue;
}

// ロックの削除
void UnixDeleteLock(LOCK *lock)
{
	pthread_mutex_t *mutex;
	// Ready フラグを安全に解除する
	UnixLock(lock);
	lock->Ready = false;
	UnixUnlockEx(lock, true);

	// mutex の削除
	mutex = (pthread_mutex_t *)lock->pData;
	pthread_mutex_destroy(mutex);

	// メモリ解放
	UnixMemoryFree(mutex);
	UnixMemoryFree(lock);
}

// ロック解除
void UnixUnlock(LOCK *lock)
{
	UnixUnlockEx(lock, false);
}
void UnixUnlockEx(LOCK *lock, bool inner)
{
	pthread_mutex_t *mutex;
	if (lock->Ready == false && inner == false)
	{
		// 状態が不正
		return;
	}
	mutex = (pthread_mutex_t *)lock->pData;

	if ((--lock->locked_count) > 0)
	{
		return;
	}

	lock->thread_id = INFINITE;

	pthread_mutex_unlock(mutex);

	return;
}

// ロック
bool UnixLock(LOCK *lock)
{
	pthread_mutex_t *mutex;
	UINT thread_id = UnixThreadId();
	if (lock->Ready == false)
	{
		// 状態が不正
		return false;
	}

	if (lock->thread_id == thread_id)
	{
		lock->locked_count++;
		return true;
	}

	mutex = (pthread_mutex_t *)lock->pData;

	pthread_mutex_lock(mutex);

	lock->thread_id = thread_id;
	lock->locked_count++;

	return true;
}

// 新しいロックの作成
LOCK *UnixNewLock()
{
	pthread_mutex_t *mutex;
	// メモリ確保
	LOCK *lock = UnixMemoryAlloc(sizeof(LOCK));

	// mutex 作成
	mutex = UnixMemoryAlloc(sizeof(pthread_mutex_t));

	// mutex 初期化
	pthread_mutex_init(mutex, NULL);

	lock->pData = (void *)mutex;
	lock->Ready = true;

	lock->thread_id = INFINITE;
	lock->locked_count = 0;

	return lock;
}

// スリープ
void UnixSleep(UINT time)
{
	UINT sec = 0, millisec = 0;
	// 引数チェック
	if (time == 0)
	{
		return;
	}

	if (time == INFINITE)
	{
		// 無限に待機する
		while (true)
		{
#ifdef UNIX_SOLARIS
			UnixSolarisSleep(time);
#else
			sleep(1000000);
#endif
		}
	}

#ifdef UNIX_SOLARIS
	UnixSolarisSleep(time);
#else

	// 桁あふれ防止
	sec = time / 1000;
	millisec = time % 1000;

	if (sec != 0)
	{
		sleep(sec);
	}
	if (millisec != 0)
	{
		usleep(millisec * 1000);
	}
#endif
}

// デクリメント
void UnixDec32(UINT *value)
{
	if (value != NULL)
	{
		(*value)--;
	}
}

// インクリメント
void UnixInc32(UINT *value)
{
	if (value != NULL)
	{
		(*value)++;
	}
}

// システム時刻の取得
void UnixGetSystemTime(SYSTEMTIME *system_time)
{
	time_t now = 0;
	struct tm tm;
	struct timeval tv;
	struct timezone tz;
	// 引数チェック
	if (system_time == NULL)
	{
		return;
	}

	pthread_mutex_lock(&get_time_lock);

	Zero(system_time, sizeof(SYSTEMTIME));
	Zero(&tv, sizeof(tv));
	Zero(&tz, sizeof(tz));

	time(&now);

	gmtime_r(&now, &tm);

	TmToSystem(system_time, &tm);

	gettimeofday(&tv, &tz);

	system_time->wMilliseconds = tv.tv_usec / 1000;

	pthread_mutex_unlock(&get_time_lock);
}

// システムタイマの取得 (64bit)
UINT64 UnixGetTick64()
{
#if	defined(OS_WIN32) || defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC) || defined(CLOCK_HIGHRES)

	struct timespec t;
	UINT64 ret;
	static bool akirame = false;

	if (akirame)
	{
		return TickRealtimeManual();
	}

	Zero(&t, sizeof(t));

	// システムの起動時刻を取得する関数
	// システムによって実装が異なるので注意
#ifdef	CLOCK_HIGHRES
	clock_gettime(CLOCK_HIGHRES, &t);
#else	// CLOCK_HIGHRES
#ifdef	CLOCK_MONOTONIC
	clock_gettime(CLOCK_MONOTONIC, &t);
#else	// CLOCK_MONOTONIC
	clock_gettime(CLOCK_REALTIME, &t);
#endif	// CLOCK_MONOTONIC
#endif	// CLOCK_HIGHRES

	ret = (UINT64)t.tv_sec * 1000LL + (UINT64)t.tv_nsec / 1000000LL;

	if (akirame == false && ret == 0)
	{
		ret = TickRealtimeManual();
		akirame = true;
	}

	return ret;

#else

	return TickRealtimeManual();

#endif
}

// システムタイマの取得
UINT UnixGetTick()
{
	return (UINT)UnixGetTick64();
}

// メモリの確保
void *UnixMemoryAlloc(UINT size)
{
	void *r;
	pthread_mutex_lock(&malloc_lock);
	r = malloc(size);
	pthread_mutex_unlock(&malloc_lock);
	return r;
}

// メモリの再確保
void *UnixMemoryReAlloc(void *addr, UINT size)
{
	void *r;
	pthread_mutex_lock(&malloc_lock);
	r = realloc(addr, size);
	pthread_mutex_unlock(&malloc_lock);
	return r;
}

// メモリの解放
void UnixMemoryFree(void *addr)
{
	pthread_mutex_lock(&malloc_lock);
	free(addr);
	pthread_mutex_unlock(&malloc_lock);
}

// SIGCHLD ハンドラ
void UnixSigChldHandler(int sig)
{
	// ゾンビプロセスの回収
	while (waitpid(-1, NULL, WNOHANG) > 0);
	signal(SIGCHLD, UnixSigChldHandler);
}

// UNIX 用ライブラリの初期化
void UnixInit()
{
	UNIXIO *o;

	UnixInitSolarisSleep();

	// グローバルロック
	pthread_mutex_init(&get_time_lock, NULL);
	pthread_mutex_init(&malloc_lock, NULL);

	// プロセス ID の取得
	current_process_id = getpid();

#ifdef	RLIMIT_CORE
	UnixSetResourceLimit(RLIMIT_CORE, UNIX_MAX_MEMORY);
#endif	// RLIMIT_CORE

#ifdef	RLIMIT_DATA
	UnixSetResourceLimit(RLIMIT_DATA, UNIX_MAX_MEMORY);
#endif	// RLIMIT_DATA

#ifdef	RLIMIT_NOFILE
	UnixSetResourceLimit(RLIMIT_NOFILE, UNIX_MAX_FD);
#endif	// RLIMIT_NOFILE

#ifdef	RLIMIT_STACK
//	UnixSetResourceLimit(RLIMIT_STACK, UNIX_MAX_MEMORY);
#endif	// RLIMIT_STACK

#ifdef	RLIMIT_RSS
	UnixSetResourceLimit(RLIMIT_RSS, UNIX_MAX_MEMORY);
#endif	// RLIMIT_RSS

#ifdef	RLIMIT_LOCKS
	UnixSetResourceLimit(RLIMIT_LOCKS, UNIX_MAX_LOCKS);
#endif	// RLIMIT_LOCKS

#ifdef	RLIMIT_MEMLOCK
	UnixSetResourceLimit(RLIMIT_MEMLOCK, UNIX_MAX_MEMORY);
#endif	// RLIMIT_MEMLOCK

#ifdef	RLIMIT_NPROC
	UnixSetResourceLimit(RLIMIT_NPROC, UNIX_MAX_CHILD_PROCESSES);
#endif	// RLIMIT_NPROC

	// proc ファイルシステムの threads-max に値を書き込む
	o = UnixFileCreate("/proc/sys/kernel/threads-max");
	if (o != NULL)
	{
		char tmp[128];
		sprintf(tmp, "%u\n", UNIX_LINUX_MAX_THREADS);
		UnixFileWrite(o, tmp, strlen(tmp));
		UnixFileClose(o, false);
	}

	// 無視するシグナルを設定
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, SIG_IGN);

#ifdef	UNIX_BSD
	signal(64, SIG_IGN);
#endif	// UNIX_BSD

#ifdef	SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif	// SIGXFSZ

	// 子プロセス回収用シグナルハンドラの設定
	signal(SIGCHLD, UnixSigChldHandler);
}

// UNIX 用ライブラリの解放
void UnixFree()
{
	UnixFreeSolarisSleep();

	current_process_id = 0;

	pthread_mutex_destroy(&get_time_lock);
}

// 占有することができる資源の上限値を調整
void UnixSetResourceLimit(UINT id, UINT value)
{
	struct rlimit t;
	UINT hard_limit;

	Zero(&t, sizeof(t));
	getrlimit(id, &t);

	hard_limit = t.rlim_max;

	Zero(&t, sizeof(t));
	t.rlim_cur = MIN(value, hard_limit);
	t.rlim_max = hard_limit;
	setrlimit(id, &t);

	Zero(&t, sizeof(t));
	t.rlim_cur = value;
	t.rlim_max = value;
	setrlimit(id, &t);
}

// PID ファイル名を生成する
void UnixGenPidFileName(char *name, UINT size)
{
	char exe_name[MAX_PATH];
	UCHAR hash[MD5_SIZE];
	char tmp1[64];
	char dir[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	GetExeDir(dir, sizeof(dir));

	GetExeName(exe_name, sizeof(exe_name));
	StrCat(exe_name, sizeof(exe_name), ":pid_hash");
	StrUpper(exe_name);

	Hash(hash, exe_name, StrLen(exe_name), false);
	BinToStr(tmp1, sizeof(tmp1), hash, sizeof(hash));

	Format(name, size, "%s/.pid_%s", dir, tmp1);
}

// PID ファイルを削除する
void UnixDeletePidFile()
{
	char tmp[MAX_PATH];

	UnixGenPidFileName(tmp, sizeof(tmp));

	UnixFileDelete(tmp);
}

// PID ファイルに書き込む
void UnixWritePidFile(UINT pid)
{
	char tmp[MAX_PATH];
	char tmp2[64];
	IO *o;

	UnixGenPidFileName(tmp, sizeof(tmp));
	Format(tmp2, sizeof(tmp2), "%u\n", pid);

	o = FileCreate(tmp);
	if (o != NULL)
	{
		FileWrite(o, tmp2, StrLen(tmp2));
		FileClose(o);
	}
}

// PID ファイルを読み込む
UINT UnixReadPidFile()
{
	char tmp[MAX_PATH];
	BUF *buf;

	UnixGenPidFileName(tmp, sizeof(tmp));

	buf = ReadDump(tmp);
	if (buf == NULL)
	{
		return 0;
	}

	Zero(tmp, sizeof(tmp));
	Copy(tmp, buf->Buf, MIN(buf->Size, sizeof(tmp)));
	FreeBuf(buf);

	return ToInt(tmp);
}

// サービスの開始
void UnixStartService(char *name)
{
	char *svc_name, *svc_title;
	char tmp[128];
	INSTANCE *inst;
	char exe[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	GetExeName(exe, sizeof(exe));

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	// すでにサービスが起動していないかどうか調べる
	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		// すでにサービスが起動している
		UniPrint(_UU("UNIX_SVC_ALREADY_START"), svc_title, svc_name);
	}
	else
	{
		int pid;
		// サービスの起動を開始する
		UniPrint(_UU("UNIX_SVC_STARTED"), svc_title);
		FreeSingleInstance(inst);

		// 子プロセスを作成する
		pid = fork();
		if (pid == -1)
		{
			UniPrint(_UU("UNIX_SVC_ERROR_FORK"), svc_title);
		}
		else
		{
			if (pid == 0)
			{
				// 子プロセス
				char *param = UNIX_SVC_ARG_EXEC_SVC;
				char **args;

				// デーモン化する
				setsid();
				UnixCloseIO();
				signal(SIGHUP, SIG_IGN);

				// 引数を準備
				args = ZeroMalloc(sizeof(char *) * 3);
				args[0] = exe;
				args[1] = param;
				args[2] = NULL;

				execvp(exe, args);
				AbortExit();
			}
			else
			{
				// 子プロセス番号をファイルに書き込まない
//				UnixWritePidFile(pid);
			}
		}
	}
}

// サービスの停止
void UnixStopService(char *name)
{
	char *svc_name, *svc_title;
	char tmp[128];
	INSTANCE *inst;
	char exe[MAX_PATH];
	UINT pid;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	GetExeName(exe, sizeof(exe));

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	inst = NewSingleInstance(NULL);
	pid = UnixReadPidFile();
	if (inst != NULL || pid == 0)
	{
		// まだサービスが起動していない
		UniPrint(_UU("UNIX_SVC_NOT_STARTED"), svc_title, svc_name);
	}
	else
	{
		int status;

		// サービスを停止する
		UniPrint(_UU("UNIX_SVC_STOPPING"), svc_title);

		// プロセスを終了する
		kill(pid, SIGTERM);
		if (UnixWaitProcessEx(pid, UNIX_SERVICE_STOP_TIMEOUT_2))
		{
			UniPrint(_UU("UNIX_SVC_STOPPED"), svc_title);
		}
		else
		{
			UniPrint(_UU("UNIX_SVC_STOP_FAILED"), svc_title);
		}
	}

	FreeSingleInstance(inst);
}

// プロセスへの停止シグナルのハンドラ
void UnixSigTermHandler(int signum)
{
	if (signum == SIGTERM)
	{
		unix_svc_terminate = true;
	}
}

// サービス停止用スレッド
void UnixStopThread(THREAD *t, void *param)
{
	SERVICE_FUNCTION *stop = (SERVICE_FUNCTION *)param;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	stop();
}

// サービスの内容の実行
void UnixExecService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	char *svc_name, *svc_title;
	char tmp[128];
	INSTANCE *inst;
	UINT yobi_size = 1024 * 128;
	void *yobi1, *yobi2;
	// 引数チェック
	if (start == NULL || stop == NULL || name == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	inst = NewSingleInstance(NULL);
	if (inst != NULL)
	{
		THREAD *t;

		yobi1 = ZeroMalloc(yobi_size);
		yobi2 = ZeroMalloc(yobi_size);

		// 起動
		UnixWritePidFile(getpid());

		start();

		// 起動完了 別のプロセスから SIGTERM が送られてくるのを待つ
		signal(SIGTERM, &UnixSigTermHandler);
		while (unix_svc_terminate == false)
		{
			pause();
		}

		// 停止
		Free(yobi1);
		t = NewThread(UnixStopThread, stop);
		if (t == NULL || (WaitThread(t, UNIX_SERVICE_STOP_TIMEOUT_1) == false))
		{
			// 停止用スレッドの作成に失敗したか、タイムアウトした場合は
			// 強制終了する
			Free(yobi2);
			FreeSingleInstance(inst);
			UnixDeletePidFile();
			_exit(0);
		}
		ReleaseThread(t);

		// PID ファイルを削除
		UnixDeletePidFile();

		FreeSingleInstance(inst);

		Free(yobi2);
	}
}

// 指定した pid のプロセスが存在するかどうか取得する
bool UnixIsProcess(UINT pid)
{
	if (getsid((pid_t)pid) == -1)
	{
		return false;
	}

	return true;
}

// 指定したプロセスの終了を待機する
bool UnixWaitProcessEx(UINT pid,  UINT timeout)
{
	UINT64 start_tick = Tick64();
	UINT64 end_tick = start_tick + (UINT64)timeout;
	if (timeout == INFINITE)
	{
		end_tick = 0;
	}
	while (UnixIsProcess(pid))
	{
		if (end_tick != 0)
		{
			if (end_tick < Tick64())
			{
				return false;
			}
		}
		SleepThread(100);
	}
	return true;
}
void UnixWaitProcess(UINT pid)
{
	UnixWaitProcessEx(pid, INFINITE);
}

// 起動方法の説明
void UnixUsage(char *name)
{
	char *svc_name, *svc_title;
	char tmp[128];
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	UniPrint(_UU("UNIX_SVC_HELP"), svc_title, svc_name, svc_name, svc_title, svc_name, svc_title);
}

// UNIX サービスのメイン関数
UINT UnixService(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	// 引数チェック
	if (name == NULL || start == NULL || stop == NULL)
	{
		return 0;
	}

	if (argc >= 2 && StrCmpi(argv[1], UNIX_SVC_ARG_EXEC_SVC) == 0)
	{
		UINT pid;
		// 子プロセスを生成して開始する
		// もし子プロセスが正しく終了しなかった場合は再起動する

RESTART_PROCESS:
		pid = fork();
		if ((int)pid != -1)
		{
			if (pid == 0)
			{
				// メイン処理の実行
				UnixServiceMain(argc, argv, name, start, stop);
			}
			else
			{
				int status = 0, ret;

				// 子プロセスの終了を待機する
				ret = waitpid(pid, &status, 0);

				if (WIFEXITED(status) == 0)
				{
					// 異常終了した
					UnixSleep(100);
					goto RESTART_PROCESS;
				}
			}
		}
	}
	else
	{
		// 通常に開始する
		UnixServiceMain(argc, argv, name, start, stop);
	}

	return 0;
}
void UnixServiceMain(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	UINT mode = 0;
	// Mayaqua の開始
	InitMayaqua(false, false, argc, argv);

	if (argc >= 2)
	{
		if (StrCmpi(argv[1], UNIX_SVC_ARG_START) == 0)
		{
			mode = UNIX_SVC_MODE_START;
		}
		if (StrCmpi(argv[1], UNIX_SVC_ARG_STOP) == 0)
		{
			mode = UNIX_SVC_MODE_STOP;
		}
		if (StrCmpi(argv[1], UNIX_SVC_ARG_EXEC_SVC) == 0)
		{
			mode = UNIX_SVC_MODE_EXEC_SVC;
		}
		if (StrCmpi(argv[1], UNIX_ARG_EXIT) == 0)
		{
			mode = UNIX_SVC_MODE_EXIT;
		}
	}

	switch (mode)
	{
	case UNIX_SVC_MODE_EXIT:
		break;

	case UNIX_SVC_MODE_START:
		UnixStartService(name);
		break;

	case UNIX_SVC_MODE_STOP:
		UnixStopService(name);
		break;

	case UNIX_SVC_MODE_EXEC_SVC:
		UnixExecService(name, start, stop);
		break;

	default:
		UnixUsage(name);
		break;
	}

	// Mayaquq の終了
	FreeMayaqua();

	return;
}

#endif	// UNIX
