#include "../third_party/doctest/doctest.h"

#include "LongPathSeams.h"

#include <tchar.h>
#include <windows.h>

namespace
{
	/**
	 * @brief Copies a deterministic fake Win32 volume root into the caller-provided buffer.
	 */
	BOOL CopyFakeVolumeRoot(LPTSTR pszVolumePathName, const DWORD cchBufferLength, LPCTSTR pszRoot)
	{
		return _tcscpy_s(pszVolumePathName, cchBufferLength, pszRoot) == 0 ? TRUE : FALSE;
	}
}

TEST_SUITE_BEGIN("startup_storage");

TEST_CASE("Startup storage classifier identifies mapped drive letters backed by network shares")
{
	const auto result = LongPathSeams::ClassifyStoragePlacement(
		_T("Z:\\profiles\\cl-emulebb-001\\config"),
		[](LPCTSTR, LPTSTR pszVolumePathName, DWORD cchBufferLength) -> BOOL {
			return CopyFakeVolumeRoot(pszVolumePathName, cchBufferLength, _T("Z:\\"));
		},
		[](LPCTSTR pszRootPathName) -> UINT {
			CHECK(LongPathSeams::PathString(pszRootPathName) == LongPathSeams::PathString(_T("Z:\\")));
			return DRIVE_REMOTE;
		});

	CHECK(result.bResolved);
	CHECK(result.eRisk == LongPathSeams::StoragePlacementRisk::NetworkShare);
	CHECK(result.dwDriveType == DRIVE_REMOTE);
	CHECK(result.strVolumeRoot == LongPathSeams::PathString(_T("Z:\\")));
}

TEST_CASE("Startup storage classifier falls back to direct UNC share roots")
{
	const auto result = LongPathSeams::ClassifyStoragePlacement(
		_T("\\\\?\\UNC\\fileserver\\emule\\profiles\\cl-emulebb-001"),
		[](LPCTSTR, LPTSTR, DWORD) -> BOOL {
			::SetLastError(ERROR_BAD_NETPATH);
			return FALSE;
		},
		[](LPCTSTR pszRootPathName) -> UINT {
			CHECK(LongPathSeams::PathString(pszRootPathName) == LongPathSeams::PathString(_T("\\\\fileserver\\emule\\")));
			return DRIVE_REMOTE;
		});

	CHECK(result.bResolved);
	CHECK(result.eRisk == LongPathSeams::StoragePlacementRisk::NetworkShare);
	CHECK(result.dwDriveType == DRIVE_REMOTE);
	CHECK(result.dwLastError == ERROR_BAD_NETPATH);
	CHECK(result.strVolumeRoot == LongPathSeams::PathString(_T("\\\\fileserver\\emule\\")));
}

TEST_CASE("Startup storage classifier identifies removable drive roots")
{
	const auto result = LongPathSeams::ClassifyStoragePlacement(
		_T("R:/emule/temp"),
		[](LPCTSTR, LPTSTR pszVolumePathName, DWORD cchBufferLength) -> BOOL {
			return CopyFakeVolumeRoot(pszVolumePathName, cchBufferLength, _T("R:\\"));
		},
		[](LPCTSTR pszRootPathName) -> UINT {
			CHECK(LongPathSeams::PathString(pszRootPathName) == LongPathSeams::PathString(_T("R:\\")));
			return DRIVE_REMOVABLE;
		});

	CHECK(result.bResolved);
	CHECK(result.eRisk == LongPathSeams::StoragePlacementRisk::RemovableDrive);
	CHECK(result.dwDriveType == DRIVE_REMOVABLE);
	CHECK(result.strInputPath == LongPathSeams::PathString(_T("R:\\emule\\temp")));
	CHECK(result.strVolumeRoot == LongPathSeams::PathString(_T("R:\\")));
}

TEST_CASE("Startup storage classifier preserves mounted-folder volume roots")
{
	const auto result = LongPathSeams::ClassifyStoragePlacement(
		_T("C:\\mounts\\usb\\eMule\\Incoming"),
		[](LPCTSTR, LPTSTR pszVolumePathName, DWORD cchBufferLength) -> BOOL {
			return CopyFakeVolumeRoot(pszVolumePathName, cchBufferLength, _T("C:\\mounts\\usb\\"));
		},
		[](LPCTSTR pszRootPathName) -> UINT {
			CHECK(LongPathSeams::PathString(pszRootPathName) == LongPathSeams::PathString(_T("C:\\mounts\\usb\\")));
			return DRIVE_REMOVABLE;
		});

	CHECK(result.bResolved);
	CHECK(result.eRisk == LongPathSeams::StoragePlacementRisk::RemovableDrive);
	CHECK(result.dwDriveType == DRIVE_REMOVABLE);
	CHECK(result.strVolumeRoot == LongPathSeams::PathString(_T("C:\\mounts\\usb\\")));
}

TEST_CASE("Startup storage classifier leaves fixed local volumes unrisky")
{
	const auto result = LongPathSeams::ClassifyStoragePlacement(
		_T("C:\\profiles\\cl-emulebb-001\\config"),
		[](LPCTSTR, LPTSTR pszVolumePathName, DWORD cchBufferLength) -> BOOL {
			return CopyFakeVolumeRoot(pszVolumePathName, cchBufferLength, _T("C:\\"));
		},
		[](LPCTSTR pszRootPathName) -> UINT {
			CHECK(LongPathSeams::PathString(pszRootPathName) == LongPathSeams::PathString(_T("C:\\")));
			return DRIVE_FIXED;
		});

	CHECK(result.bResolved);
	CHECK(result.eRisk == LongPathSeams::StoragePlacementRisk::None);
	CHECK(result.dwDriveType == DRIVE_FIXED);
	CHECK(result.strVolumeRoot == LongPathSeams::PathString(_T("C:\\")));
}
