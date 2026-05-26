#include "../third_party/doctest/doctest.h"

#include "RollingLogWindowSeams.h"

#include <deque>

namespace
{
RollingLogWindowSeams::SRollingLogEntry MakeEntry(LPCTSTR pszText)
{
	RollingLogWindowSeams::SRollingLogEntry entry;
	entry.strText = pszText;
	return entry;
}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Rolling log pane limits use bounded visible histories")
{
	CHECK(RollingLogWindowSeams::kNormalLogVisibleEntries == 2000u);
	CHECK(RollingLogWindowSeams::kVerboseLogVisibleEntries == 4000u);
	CHECK(RollingLogWindowSeams::kMaxVisibleLineChars == 1000);
	CHECK(RollingLogWindowSeams::BuildRichEditTextLimit(2000u, 1000) > 2000u * 1000u);
	CHECK(RollingLogWindowSeams::BuildRichEditTextLimit(4000u, 1000) > 4000u * 1000u);
}

TEST_CASE("Rolling log trim planning separates visible text from pending display entries")
{
	RollingLogWindowSeams::STrimPlan plan = RollingLogWindowSeams::BuildTrimPlan(5001u, 100u, 2000u);
	CHECK(plan.uVisibleEntriesToTrim == 3001u);
	CHECK(plan.uPendingEntriesToDrop == 0u);

	plan = RollingLogWindowSeams::BuildTrimPlan(5000u, 4000u, 2000u);
	CHECK(plan.uVisibleEntriesToTrim == 1000u);
	CHECK(plan.uPendingEntriesToDrop == 2000u);
}

TEST_CASE("Rolling log trim drops pending entries before display when a batch exceeds retention")
{
	std::deque<RollingLogWindowSeams::SRollingLogEntry> entries;
	std::deque<RollingLogWindowSeams::SRollingLogEntry> pending;
	entries.push_back(MakeEntry(_T("visible-0\r\n")));
	entries.push_back(MakeEntry(_T("visible-1\r\n")));
	for (int i = 0; i < 5; ++i) {
		CString text;
		text.Format(_T("pending-%d\r\n"), i);
		RollingLogWindowSeams::SRollingLogEntry entry = MakeEntry(text);
		entries.push_back(entry);
		pending.push_back(entry);
	}

	const int charsToRemove = RollingLogWindowSeams::ApplyTrimPlan(
		entries,
		pending,
		3u,
		[](const RollingLogWindowSeams::SRollingLogEntry &rEntry) { return rEntry.strText.GetLength(); });

	CHECK(charsToRemove == CString(_T("visible-0\r\nvisible-1\r\n")).GetLength());
	REQUIRE(entries.size() == 3u);
	REQUIRE(pending.size() == 3u);
	CHECK(entries.front().strText == CString(_T("pending-2\r\n")));
	CHECK(pending.front().strText == CString(_T("pending-2\r\n")));
}

TEST_CASE("Rolling log trim character arithmetic saturates instead of overflowing")
{
	CHECK(RollingLogWindowSeams::SaturatingAddChars(INT_MAX - 1, 10) == INT_MAX);
	CHECK(RollingLogWindowSeams::SaturatingAddChars(10, 20) == 30);
	CHECK(RollingLogWindowSeams::SaturatingAddChars(10, -1) == 10);
}

TEST_SUITE_END;
