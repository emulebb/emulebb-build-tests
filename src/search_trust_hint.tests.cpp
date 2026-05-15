#include "../third_party/doctest/doctest.h"

#include "SearchTrustHintSeams.h"

TEST_SUITE_BEGIN("search_trust_hint");

TEST_CASE("Search trust hint maps fake severity into warning-only risk buckets")
{
	using FakeFileDetectorSeams::Severity;
	using SearchTrustHintSeams::DisplayKind;

	const SearchTrustHintSeams::TrustHint ok = SearchTrustHintSeams::BuildTrustHint(false, 0, Severity::None);
	CHECK(ok.displayKind == DisplayKind::Ok);
	CHECK(ok.riskBucket == 0);
	CHECK(ok.fakeScore == 0);

	const SearchTrustHintSeams::TrustHint caution = SearchTrustHintSeams::BuildTrustHint(false, 10, Severity::Low);
	CHECK(caution.displayKind == DisplayKind::Caution);
	CHECK(caution.riskBucket == 1);
	CHECK(caution.fakeScore == 10);

	const SearchTrustHintSeams::TrustHint warning = SearchTrustHintSeams::BuildTrustHint(false, 40, Severity::Medium);
	CHECK(warning.displayKind == DisplayKind::Warning);
	CHECK(warning.riskBucket == 2);
	CHECK(warning.fakeScore == 40);

	const SearchTrustHintSeams::TrustHint high = SearchTrustHintSeams::BuildTrustHint(false, 65, Severity::High);
	CHECK(high.displayKind == DisplayKind::HighRisk);
	CHECK(high.riskBucket == 3);

	const SearchTrustHintSeams::TrustHint critical = SearchTrustHintSeams::BuildTrustHint(false, 95, Severity::Critical);
	CHECK(critical.displayKind == DisplayKind::HighRisk);
	CHECK(critical.riskBucket == 3);
}

TEST_CASE("Search trust hint ranks spam above fake-file warnings")
{
	using FakeFileDetectorSeams::Severity;
	using SearchTrustHintSeams::DisplayKind;

	const SearchTrustHintSeams::TrustHint spam = SearchTrustHintSeams::BuildTrustHint(true, 0, Severity::None);
	CHECK(spam.displayKind == DisplayKind::Spam);
	CHECK(spam.riskBucket == 4);

	const SearchTrustHintSeams::TrustHint critical = SearchTrustHintSeams::BuildTrustHint(false, 95, Severity::Critical);
	CHECK(SearchTrustHintSeams::CompareTrustHints(critical, spam) < 0);
	CHECK(SearchTrustHintSeams::CompareTrustHints(spam, critical) > 0);
}

TEST_CASE("Search trust hint compares by bucket then score")
{
	using FakeFileDetectorSeams::Severity;

	const SearchTrustHintSeams::TrustHint lowScore = SearchTrustHintSeams::BuildTrustHint(false, 30, Severity::Medium);
	const SearchTrustHintSeams::TrustHint highScore = SearchTrustHintSeams::BuildTrustHint(false, 45, Severity::Medium);
	const SearchTrustHintSeams::TrustHint highRisk = SearchTrustHintSeams::BuildTrustHint(false, 60, Severity::High);

	CHECK(SearchTrustHintSeams::CompareTrustHints(lowScore, highScore) < 0);
	CHECK(SearchTrustHintSeams::CompareTrustHints(highScore, lowScore) > 0);
	CHECK(SearchTrustHintSeams::CompareTrustHints(highScore, highRisk) < 0);
	CHECK(SearchTrustHintSeams::CompareTrustHints(lowScore, lowScore) == 0);
}

TEST_SUITE_END();
