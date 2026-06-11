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

TEST_CASE("Kad trust hint uses simple publish trust buckets")
{
	using SearchTrustHintSeams::KadTrustKind;

	const SearchTrustHintSeams::KadTrustHint unknown = SearchTrustHintSeams::BuildKadTrustHint(0);
	CHECK(unknown.kind == KadTrustKind::Unknown);

	const SearchTrustHintSeams::KadTrustHint low = SearchTrustHintSeams::BuildKadTrustHint((2u << 24) | (4u << 16) | 99u);
	CHECK(low.kind == KadTrustKind::Low);
	CHECK(low.publishers == 4);
	CHECK(low.differentNames == 2);

	const SearchTrustHintSeams::KadTrustHint normal = SearchTrustHintSeams::BuildKadTrustHint((1u << 24) | (8u << 16) | 100u);
	CHECK(normal.kind == KadTrustKind::Normal);

	const SearchTrustHintSeams::KadTrustHint high = SearchTrustHintSeams::BuildKadTrustHint((1u << 24) | (8u << 16) | 300u);
	CHECK(high.kind == KadTrustKind::High);
	CHECK(SearchTrustHintSeams::CompareKadTrustHints(normal, high) < 0);
	CHECK(SearchTrustHintSeams::CompareKadTrustHints(high, low) > 0);
}

TEST_CASE("Search trust hint classifies fake-file reason codes")
{
	using SearchTrustHintSeams::ExplanationReason;

	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("multiple_names") == ExplanationReason::MultipleNames);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("name_media_tag_mismatch") == ExplanationReason::NameMediaTagMismatch);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("bad_signal_name") == ExplanationReason::BadSignalName);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("bad_signal_comment") == ExplanationReason::BadSignalComment);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("header_extension_mismatch") == ExplanationReason::HeaderExtensionMismatch);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("executable_masquerade") == ExplanationReason::ExecutableMasquerade);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("archive_masquerade") == ExplanationReason::ArchiveMasquerade);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("pending_header_check") == ExplanationReason::PendingHeaderCheck);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("claimed_type_mismatch") == ExplanationReason::ClaimedTypeMismatch);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("spam_score") == ExplanationReason::SpamScore);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("spam_status") == ExplanationReason::SpamStatus);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("bad_rating") == ExplanationReason::BadRating);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("fake_rating") == ExplanationReason::FakeRating);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("multiple_aich") == ExplanationReason::MultipleAich);
	CHECK(SearchTrustHintSeams::ClassifyExplanationReason("future_reason") == ExplanationReason::Unknown);
}

TEST_CASE("Confidence hint folds spam and fake severity into the negative bands")
{
	using FakeFileDetectorSeams::Severity;
	using SearchTrustHintSeams::ConfidenceLevel;
	const SearchTrustHintSeams::KadTrustHint noKad = SearchTrustHintSeams::BuildKadTrustHint(0);

	const auto spam = SearchTrustHintSeams::BuildConfidenceHint(true, Severity::None, 0, noKad, 0, false);
	CHECK(spam.level == ConfidenceLevel::Spam);
	CHECK(spam.rank == 0);
	CHECK(spam.score == 0);

	const auto likelyFake = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::High, 80, noKad, 0, false);
	CHECK(likelyFake.level == ConfidenceLevel::LikelyFake);
	CHECK(likelyFake.fakeScore == 80);

	const auto critical = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::Critical, 95, noKad, 0, false);
	CHECK(critical.level == ConfidenceLevel::LikelyFake);

	const auto suspect = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::Medium, 40, noKad, 0, false);
	CHECK(suspect.level == ConfidenceLevel::Suspect);

	const auto caution = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::Low, 15, noKad, 0, false);
	CHECK(caution.level == ConfidenceLevel::Caution);
}

TEST_CASE("Confidence hint surfaces the positive end from ratings and Kad publish trust")
{
	using FakeFileDetectorSeams::Severity;
	using SearchTrustHintSeams::ConfidenceLevel;
	const SearchTrustHintSeams::KadTrustHint noKad = SearchTrustHintSeams::BuildKadTrustHint(0);
	const SearchTrustHintSeams::KadTrustHint highKad = SearchTrustHintSeams::BuildKadTrustHint((1u << 24) | (8u << 16) | 300u);
	const SearchTrustHintSeams::KadTrustHint normalKad = SearchTrustHintSeams::BuildKadTrustHint((1u << 24) | (8u << 16) | 100u);

	const auto neutral = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::None, 0, noKad, 0, false);
	CHECK(neutral.level == ConfidenceLevel::LooksGood);
	CHECK(neutral.score == 70);

	const auto genuineByKad = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::None, 0, highKad, 0, false);
	CHECK(genuineByKad.level == ConfidenceLevel::Genuine);
	CHECK(genuineByKad.score >= 90);

	const auto genuineByRating = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::None, 0, noKad, 5, true);
	CHECK(genuineByRating.level == ConfidenceLevel::Genuine);

	const auto looksGoodByKad = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::None, 0, normalKad, 0, false);
	CHECK(looksGoodByKad.level == ConfidenceLevel::LooksGood);
	CHECK(looksGoodByKad.score == 78);
}

TEST_CASE("Confidence hint comparison and tokens follow the symmetric scale")
{
	using FakeFileDetectorSeams::Severity;
	using SearchTrustHintSeams::ConfidenceLevel;
	const SearchTrustHintSeams::KadTrustHint noKad = SearchTrustHintSeams::BuildKadTrustHint(0);
	const SearchTrustHintSeams::KadTrustHint highKad = SearchTrustHintSeams::BuildKadTrustHint((1u << 24) | (8u << 16) | 300u);

	const auto spam = SearchTrustHintSeams::BuildConfidenceHint(true, Severity::None, 0, noKad, 0, false);
	const auto genuine = SearchTrustHintSeams::BuildConfidenceHint(false, Severity::None, 0, highKad, 0, false);
	CHECK(SearchTrustHintSeams::CompareConfidenceHints(spam, genuine) < 0);
	CHECK(SearchTrustHintSeams::CompareConfidenceHints(genuine, spam) > 0);
	CHECK(SearchTrustHintSeams::CompareConfidenceHints(spam, spam) == 0);

	using namespace std::string_literals;
	CHECK(SearchTrustHintSeams::ConfidenceToken(ConfidenceLevel::Spam) == "spam"s);
	CHECK(SearchTrustHintSeams::ConfidenceToken(ConfidenceLevel::LikelyFake) == "likely_fake"s);
	CHECK(SearchTrustHintSeams::ConfidenceToken(ConfidenceLevel::Suspect) == "suspect"s);
	CHECK(SearchTrustHintSeams::ConfidenceToken(ConfidenceLevel::Caution) == "caution"s);
	CHECK(SearchTrustHintSeams::ConfidenceToken(ConfidenceLevel::LooksGood) == "looks_good"s);
	CHECK(SearchTrustHintSeams::ConfidenceToken(ConfidenceLevel::Genuine) == "genuine"s);
}

TEST_SUITE_END();
