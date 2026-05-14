#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "FileCompletionCommandSeams.h"
#include "PartFileCompletionSeams.h"

#include <vector>
#include <windows.h>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Part-file completion seam only warns about disabled long-path support for plausible move failures")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x434F4Du));

	const std::wstring stagedPartPath = fixture.MakeDirectoryChildPath(L"001 odd-[part].part");
	const std::wstring finishedPath = fixture.MakeDirectoryChildPath(L"finished odd-[leaf].bin");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(4099u, 0x50415254u);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(stagedPartPath, payload));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::MoveFileReplace(stagedPartPath, finishedPath));

	std::vector<BYTE> roundTrip;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(finishedPath, roundTrip));

	CString strLongPath(finishedPath.c_str());

	CHECK(strLongPath.GetLength() > MAX_PATH);
	CHECK(PartFileCompletionSeams::ShouldWarnAboutDisabledLongPathSupport(ERROR_FILENAME_EXCED_RANGE, strLongPath, false));
	CHECK(PartFileCompletionSeams::ShouldWarnAboutDisabledLongPathSupport(ERROR_PATH_NOT_FOUND, strLongPath, false));
	CHECK_FALSE(PartFileCompletionSeams::ShouldWarnAboutDisabledLongPathSupport(ERROR_ACCESS_DENIED, strLongPath, false));
	CHECK(roundTrip == payload);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(finishedPath));
}

TEST_CASE("Part-file completion seam skips disabled-long-path warnings for supported or short-path cases")
{
	LongPathTestSupport::ScopedLongPathFixture shortFixture;
	INFO(shortFixture.LastError());
	REQUIRE(shortFixture.Initialize(false, 0u, 0x53484F52u));
	const std::wstring shortFinishedPath = shortFixture.MakeDirectoryChildPath(L"finished.bin");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(shortFinishedPath, LongPathTestSupport::BuildDeterministicPayload(73u, 0x1111u)));
	const CString strShortPath(shortFinishedPath.c_str());

	LongPathTestSupport::ScopedLongPathFixture longFixture;
	INFO(longFixture.LastError());
	REQUIRE(longFixture.Initialize(true, 0u, 0x4C4F4E47u));
	const std::wstring longFinishedPath = longFixture.MakeDirectoryChildPath(L"finished odd-[enabled].bin");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(longFinishedPath, LongPathTestSupport::BuildDeterministicPayload(97u, 0x2222u)));
	const CString strLongPath(longFinishedPath.c_str());

	CHECK_FALSE(PartFileCompletionSeams::ShouldWarnAboutDisabledLongPathSupport(ERROR_FILENAME_EXCED_RANGE, strLongPath, true));
	CHECK_FALSE(PartFileCompletionSeams::ShouldWarnAboutDisabledLongPathSupport(ERROR_FILENAME_EXCED_RANGE, strShortPath, false));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(shortFinishedPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(longFinishedPath));
}

TEST_CASE("File completion command seam builds direct launch requests with supported tokens")
{
	FileCompletionCommandSeams::CompletionCommandContext context;
	context.enabled = true;
	context.completionSucceeded = true;
	context.knownFileAdded = true;
	context.programPath = _T("C:\\Tools\\complete.exe");
	context.argumentTemplate = _T("--input %F --dir %D --name %N --hash %H --size %S --cat %C");
	context.filePath = _T("C:\\Incoming\\linux iso.iso");
	context.directory = _T("C:\\Incoming\\");
	context.fileName = _T("linux iso.iso");
	context.fileHash = _T("abcdef0123456789abcdef0123456789");
	context.categoryName = _T("Linux");
	context.fileSize = 123456789u;

	FileCompletionCommandSeams::CompletionCommandLaunchRequest request;
	REQUIRE(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));

	CHECK(request.applicationName == CString(_T("C:\\Tools\\complete.exe")));
	CHECK(request.workingDirectory == CString(_T("C:\\Incoming\\")));
	CHECK(request.commandLine == CString(_T("\"C:\\Tools\\complete.exe\" --input \"C:\\Incoming\\linux iso.iso\" --dir \"C:\\Incoming\\\\\" --name linux iso.iso --hash abcdef0123456789abcdef0123456789 --size 123456789 --cat Linux")));
}

TEST_CASE("File completion command seam skips unsafe or non-retained completion states")
{
	FileCompletionCommandSeams::CompletionCommandContext context;
	context.enabled = true;
	context.completionSucceeded = true;
	context.knownFileAdded = true;
	context.programPath = _T("C:\\Tools\\complete.exe");
	context.filePath = _T("C:\\Incoming\\debian.iso");
	context.directory = _T("C:\\Incoming");
	context.fileName = _T("debian.iso");

	FileCompletionCommandSeams::CompletionCommandLaunchRequest request;
	CHECK(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));

	context.enabled = false;
	CHECK_FALSE(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));
	context.enabled = true;

	context.appClosing = true;
	CHECK_FALSE(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));
	context.appClosing = false;

	context.completionSucceeded = false;
	CHECK_FALSE(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));
	context.completionSucceeded = true;

	context.knownFileAdded = false;
	CHECK_FALSE(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));
	context.knownFileAdded = true;

	context.programPath = _T("C:\\Tools\\complete.bat");
	CHECK_FALSE(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));
}

TEST_CASE("File completion command seam accepts only executable program extensions")
{
	CHECK(FileCompletionCommandSeams::HasSupportedProgramExtension(CString(_T("C:\\Tools\\complete.exe"))));
	CHECK(FileCompletionCommandSeams::HasSupportedProgramExtension(CString(_T("C:\\Tools\\complete.COM"))));
	CHECK_FALSE(FileCompletionCommandSeams::HasSupportedProgramExtension(CString(_T("C:\\Tools\\complete.ps1"))));
	CHECK_FALSE(FileCompletionCommandSeams::HasSupportedProgramExtension(CString(_T("C:\\Tools\\complete.bat"))));
	CHECK_FALSE(FileCompletionCommandSeams::HasSupportedProgramExtension(CString(_T("C:\\Tools\\complete"))));
	CHECK(FileCompletionCommandSeams::QuoteCommandLineArgument(CString(_T("C:\\Incoming\\"))) == CString(_T("\"C:\\Incoming\\\\\"")));
}

TEST_CASE("File completion command seam preserves shell metacharacters as literal arguments")
{
	FileCompletionCommandSeams::CompletionCommandContext context;
	context.enabled = true;
	context.completionSucceeded = true;
	context.knownFileAdded = true;
	context.programPath = _T("C:\\Tools\\complete.exe");
	context.argumentTemplate = _T("--literal %TEMP% --pipe | --amp & --file %F");
	context.filePath = _T("C:\\Incoming\\literal test.bin");
	context.directory = _T("C:\\Incoming");

	FileCompletionCommandSeams::CompletionCommandLaunchRequest request;
	REQUIRE(FileCompletionCommandSeams::TryBuildLaunchRequest(context, request));

	CHECK(request.commandLine == CString(_T("\"C:\\Tools\\complete.exe\" --literal %TEMP% --pipe | --amp & --file \"C:\\Incoming\\literal test.bin\"")));
}

TEST_CASE("File completion command seam validates existing executable configuration")
{
	TCHAR systemDirectory[MAX_PATH] = {};
	REQUIRE(::GetSystemDirectory(systemDirectory, _countof(systemDirectory)) > 0);
	CString cmdPath(systemDirectory);
	cmdPath += _T("\\cmd.exe");
	CString missingExe(systemDirectory);
	missingExe += _T("\\missing-emule-completion-command.exe");
	CString scriptPath(systemDirectory);
	scriptPath += _T("\\WindowsPowerShell\\v1.0\\powershell.ps1");

	CHECK(FileCompletionCommandSeams::IsValidConfiguredProgramPath(cmdPath));
	CHECK_FALSE(FileCompletionCommandSeams::IsValidConfiguredProgramPath(missingExe));
	CHECK_FALSE(FileCompletionCommandSeams::IsValidConfiguredProgramPath(scriptPath));
	CHECK_FALSE(FileCompletionCommandSeams::IsValidConfiguredProgramPath(CString()));
}

TEST_CASE("File completion command seam validates long executable paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x434345u));

	const std::wstring executablePath = fixture.MakeDirectoryChildPath(L"complete.exe");
	const std::wstring missingPath = fixture.MakeDirectoryChildPath(L"missing.exe");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(513u, 0x434345u);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(executablePath, payload));

	CHECK(FileCompletionCommandSeams::IsValidConfiguredProgramPath(CString(executablePath.c_str())));
	CHECK_FALSE(FileCompletionCommandSeams::IsValidConfiguredProgramPath(CString(missingPath.c_str())));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(executablePath));
}

TEST_SUITE_END;
