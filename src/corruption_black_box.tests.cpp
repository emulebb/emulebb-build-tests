#include "../third_party/doctest/doctest.h"

#include "CorruptionBlackBoxSeams.h"

#include <vector>

namespace
{
	enum TestBBRStatus
	{
		TEST_BBR_NONE = 0,
		TEST_BBR_VERIFIED,
		TEST_BBR_CORRUPTED
	};

	struct TestCBBRecord
	{
		TestCBBRecord(uint64 nStartPos, uint64 nEndPos, uint32 dwIP, TestBBRStatus eStatus = TEST_BBR_NONE)
			: m_nStartPos(nStartPos)
			, m_nEndPos(nEndPos)
			, m_dwIP(dwIP)
			, m_BBRStatus(eStatus)
		{
		}

		uint64 m_nStartPos;
		uint64 m_nEndPos;
		uint32 m_dwIP;
		TestBBRStatus m_BBRStatus;
	};

	struct TestRecordArray
	{
		std::vector<TestCBBRecord> records;

		TestCBBRecord& operator[](INT_PTR nIndex)
		{
			return records[static_cast<size_t>(nIndex)];
		}

		void Add(const TestCBBRecord &record)
		{
			records.push_back(record);
		}
	};
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Corruption black box seam marks middle spans before appending split remainders")
{
	TestRecordArray records;
	records.records.reserve(1u);
	records.Add(TestCBBRecord(0u, 999u, 0x01020304u, TEST_BBR_NONE));

	const uint64 nMarkedBytes = CorruptionBlackBoxSeams::MarkRecordOverlapAndAppendRemainders<TestRecordArray, TestCBBRecord>(
		records, 0, 400u, 599u, TEST_BBR_VERIFIED);

	REQUIRE_EQ(records.records.size(), 3u);
	CHECK_EQ(nMarkedBytes, 200u);
	CHECK_EQ(records.records[0].m_nStartPos, 400u);
	CHECK_EQ(records.records[0].m_nEndPos, 599u);
	CHECK_EQ(records.records[0].m_BBRStatus, TEST_BBR_VERIFIED);
	CHECK_EQ(records.records[1].m_nStartPos, 600u);
	CHECK_EQ(records.records[1].m_nEndPos, 999u);
	CHECK_EQ(records.records[1].m_BBRStatus, TEST_BBR_NONE);
	CHECK_EQ(records.records[2].m_nStartPos, 0u);
	CHECK_EQ(records.records[2].m_nEndPos, 399u);
	CHECK_EQ(records.records[2].m_BBRStatus, TEST_BBR_NONE);
}

TEST_CASE("Corruption black box seam preserves existing status for untouched tails")
{
	TestRecordArray records;
	records.records.reserve(1u);
	records.Add(TestCBBRecord(100u, 300u, 0x05060708u, TEST_BBR_VERIFIED));

	const uint64 nMarkedBytes = CorruptionBlackBoxSeams::MarkRecordOverlapAndAppendRemainders<TestRecordArray, TestCBBRecord>(
		records, 0, 150u, 200u, TEST_BBR_CORRUPTED);

	REQUIRE_EQ(records.records.size(), 3u);
	CHECK_EQ(nMarkedBytes, 51u);
	CHECK_EQ(records.records[0].m_nStartPos, 150u);
	CHECK_EQ(records.records[0].m_nEndPos, 200u);
	CHECK_EQ(records.records[0].m_BBRStatus, TEST_BBR_CORRUPTED);
	CHECK_EQ(records.records[1].m_BBRStatus, TEST_BBR_VERIFIED);
	CHECK_EQ(records.records[2].m_BBRStatus, TEST_BBR_VERIFIED);
}

TEST_CASE("Corruption black box seam ignores non-overlapping records")
{
	TestRecordArray records;
	records.Add(TestCBBRecord(0u, 99u, 0x01010101u, TEST_BBR_NONE));

	const uint64 nMarkedBytes = CorruptionBlackBoxSeams::MarkRecordOverlapAndAppendRemainders<TestRecordArray, TestCBBRecord>(
		records, 0, 100u, 200u, TEST_BBR_VERIFIED);

	REQUIRE_EQ(records.records.size(), 1u);
	CHECK_EQ(nMarkedBytes, 0u);
	CHECK_EQ(records.records[0].m_nStartPos, 0u);
	CHECK_EQ(records.records[0].m_nEndPos, 99u);
	CHECK_EQ(records.records[0].m_BBRStatus, TEST_BBR_NONE);
}

TEST_SUITE_END;
