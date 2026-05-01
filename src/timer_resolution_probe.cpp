#include "../include/TimerResolutionProbe.h"

#include <Windows.h>
#include <mmsystem.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
	constexpr std::size_t kTargetObservedChanges = 128u;
	constexpr std::uint64_t kMaxReads = 1000000000ull;
	constexpr double kMaxMeasurementMicroseconds = 5000000.0;
	constexpr std::uint64_t kYieldEveryReads = 65536ull;

	struct TimerSampleSummary
	{
		std::string Name;
		std::string Unit;
		double TheoreticalResolution = 0.0;
		std::uint64_t Reads = 0;
		std::uint64_t ZeroReads = 0;
		std::vector<double> Deltas;
	};

	struct ProbePhase
	{
		const char *pszName;
		bool bRequestOneMillisecondPeriod;
	};

	/**
	 * @brief Pairs a successful timeBeginPeriod call with timeEndPeriod on every exit path.
	 */
	class CScopedTimerPeriod
	{
	public:
		explicit CScopedTimerPeriod(const UINT uPeriod)
			: m_uPeriod(uPeriod)
			, m_bActive(::timeBeginPeriod(uPeriod) == TIMERR_NOERROR)
		{
		}

		~CScopedTimerPeriod()
		{
			if (m_bActive)
				::timeEndPeriod(m_uPeriod);
		}

		CScopedTimerPeriod(const CScopedTimerPeriod &) = delete;
		CScopedTimerPeriod &operator=(const CScopedTimerPeriod &) = delete;

		bool IsActive() const
		{
			return m_bActive;
		}

	private:
		UINT m_uPeriod;
		bool m_bActive;
	};

	/**
	 * @brief Returns whether the command line requested the timer-resolution probe.
	 */
	bool IsProbeRequested(const int argc, char **argv)
	{
		for (int i = 1; i < argc; ++i)
			if (std::string(argv[i]) == "--timer-resolution-probe")
				return true;
		return false;
	}

	/**
	 * @brief Converts a QPC delta to microseconds without losing sub-microsecond ticks.
	 */
	double QpcTicksToMicroseconds(const LONGLONG nTicks, const LONGLONG nFrequency)
	{
		if (nFrequency <= 0)
			return 0.0;
		return (static_cast<double>(nTicks) * 1000000.0) / static_cast<double>(nFrequency);
	}

	/**
	 * @brief Returns a QPC timestamp suitable for bounding probe runtime.
	 */
	LONGLONG ReadQpcTicks()
	{
		LARGE_INTEGER counter = {};
		return ::QueryPerformanceCounter(&counter) ? counter.QuadPart : 0;
	}

	/**
	 * @brief Reports whether a measurement loop should keep collecting samples.
	 */
	bool ShouldContinueMeasurement(const std::size_t nObservedChanges, const std::uint64_t nReads, const LONGLONG nStartTicks, const LONGLONG nFrequency)
	{
		if (nObservedChanges >= kTargetObservedChanges || nReads >= kMaxReads)
			return false;
		if ((nReads % kYieldEveryReads) != 0)
			return true;
		if (nFrequency <= 0 || nStartTicks <= 0)
			return true;
		const LONGLONG nElapsedTicks = ReadQpcTicks() - nStartTicks;
		return QpcTicksToMicroseconds(nElapsedTicks, nFrequency) < kMaxMeasurementMicroseconds;
	}

	/**
	 * @brief Samples one millisecond counter until enough visible changes have been observed.
	 */
	template <typename TCounter, typename TReadFn, typename TDeltaFn>
	TimerSampleSummary MeasureTickCounter(
		const std::string &strName,
		const double dTheoreticalResolution,
		TReadFn readCounter,
		TDeltaFn computeDelta)
	{
		TimerSampleSummary summary;
		summary.Name = strName;
		summary.Unit = "ms";
		summary.TheoreticalResolution = dTheoreticalResolution;
		summary.Deltas.reserve(kTargetObservedChanges);

		LARGE_INTEGER frequency = {};
		const LONGLONG nFrequency = ::QueryPerformanceFrequency(&frequency) ? frequency.QuadPart : 0;
		const LONGLONG nStartTicks = ReadQpcTicks();
		TCounter previous = readCounter();
		while (ShouldContinueMeasurement(summary.Deltas.size(), summary.Reads, nStartTicks, nFrequency)) {
			const TCounter current = readCounter();
			++summary.Reads;
			const double dDelta = computeDelta(previous, current);
			if (dDelta > 0.0) {
				summary.Deltas.push_back(dDelta);
				previous = current;
			} else {
				++summary.ZeroReads;
			}
			if ((summary.Reads % kYieldEveryReads) == 0)
				::Sleep(0);
		}
		return summary;
	}

	/**
	 * @brief Samples QueryPerformanceCounter until enough visible changes have been observed.
	 */
	TimerSampleSummary MeasureQpc()
	{
		TimerSampleSummary summary;
		summary.Name = "QueryPerformanceCounter";
		summary.Unit = "us";
		summary.Deltas.reserve(kTargetObservedChanges);

		LARGE_INTEGER frequency = {};
		if (!::QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
			return summary;
		summary.TheoreticalResolution = 1000000.0 / static_cast<double>(frequency.QuadPart);

		const LONGLONG nStartTicks = ReadQpcTicks();
		LARGE_INTEGER previous = {};
		::QueryPerformanceCounter(&previous);
		while (ShouldContinueMeasurement(summary.Deltas.size(), summary.Reads, nStartTicks, frequency.QuadPart)) {
			LARGE_INTEGER current = {};
			::QueryPerformanceCounter(&current);
			++summary.Reads;
			const LONGLONG nDeltaTicks = current.QuadPart - previous.QuadPart;
			if (nDeltaTicks > 0) {
				summary.Deltas.push_back(QpcTicksToMicroseconds(nDeltaTicks, frequency.QuadPart));
				previous = current;
			} else {
				++summary.ZeroReads;
			}
			if ((summary.Reads % kYieldEveryReads) == 0)
				::Sleep(0);
		}
		return summary;
	}

	/**
	 * @brief Returns one percentile from an already sorted sample vector.
	 */
	double GetPercentile(const std::vector<double> &samples, const double dPercentile)
	{
		if (samples.empty())
			return 0.0;
		const double dIndex = (static_cast<double>(samples.size() - 1u) * dPercentile) / 100.0;
		const std::size_t nIndex = static_cast<std::size_t>(dIndex + 0.5);
		return samples[std::min(nIndex, samples.size() - 1u)];
	}

	/**
	 * @brief Formats a floating-point measurement with stable precision for log output.
	 */
	std::string FormatDouble(const double dValue)
	{
		std::ostringstream out;
		out << std::fixed << std::setprecision(3) << dValue;
		return out.str();
	}

	/**
	 * @brief Emits a compact statistical summary for one timer API.
	 */
	void PrintSummary(const TimerSampleSummary &summary)
	{
		std::vector<double> sorted = summary.Deltas;
		std::sort(sorted.begin(), sorted.end());
		const double dZeroReadRatio = summary.Reads == 0
			? 0.0
			: (static_cast<double>(summary.ZeroReads) * 100.0) / static_cast<double>(summary.Reads);

		std::cout
			<< "api=" << summary.Name
			<< " unit=" << summary.Unit
			<< " theoreticalResolution=" << FormatDouble(summary.TheoreticalResolution)
			<< " reads=" << summary.Reads
			<< " zeroReadRatioPercent=" << FormatDouble(dZeroReadRatio)
			<< " observedChanges=" << sorted.size()
			<< " min=" << FormatDouble(sorted.empty() ? 0.0 : sorted.front())
			<< " median=" << FormatDouble(GetPercentile(sorted, 50.0))
			<< " p95=" << FormatDouble(GetPercentile(sorted, 95.0))
			<< " max=" << FormatDouble(sorted.empty() ? 0.0 : sorted.back())
			<< std::endl;
	}

	/**
	 * @brief Runs one complete measurement phase for all supported timer APIs.
	 */
	void RunPhase(const ProbePhase &phase)
	{
		std::cout << "phase=" << phase.pszName << std::endl;

		TIMECAPS timeCaps = {};
		const MMRESULT capsResult = ::timeGetDevCaps(&timeCaps, sizeof(timeCaps));
		if (capsResult == TIMERR_NOERROR) {
			std::cout
				<< "timeGetDevCaps minPeriodMs=" << timeCaps.wPeriodMin
				<< " maxPeriodMs=" << timeCaps.wPeriodMax
				<< std::endl;
		} else {
			std::cout << "timeGetDevCaps error=" << capsResult << std::endl;
		}

		if (phase.bRequestOneMillisecondPeriod) {
			CScopedTimerPeriod timerPeriod(1u);
			std::cout << "timeBeginPeriod1ms=" << (timerPeriod.IsActive() ? "active" : "failed") << std::endl;
			PrintSummary(MeasureTickCounter<DWORD>(
				"timeGetTime",
				1.0,
				[]() { return ::timeGetTime(); },
				[](const DWORD previous, const DWORD current) { return static_cast<double>(current - previous); }));
			PrintSummary(MeasureTickCounter<ULONGLONG>(
				"GetTickCount64",
				1.0,
				[]() { return ::GetTickCount64(); },
				[](const ULONGLONG previous, const ULONGLONG current) { return static_cast<double>(current - previous); }));
			PrintSummary(MeasureQpc());
			return;
		}

		PrintSummary(MeasureTickCounter<DWORD>(
			"timeGetTime",
			1.0,
			[]() { return ::timeGetTime(); },
			[](const DWORD previous, const DWORD current) { return static_cast<double>(current - previous); }));
		PrintSummary(MeasureTickCounter<ULONGLONG>(
			"GetTickCount64",
			1.0,
			[]() { return ::GetTickCount64(); },
			[](const ULONGLONG previous, const ULONGLONG current) { return static_cast<double>(current - previous); }));
		PrintSummary(MeasureQpc());
	}

	/**
	 * @brief Executes the full timer-resolution diagnostic.
	 */
	int RunProbe()
	{
		std::cout
			<< "timer-resolution-probe"
			<< " targetObservedChanges=" << kTargetObservedChanges
			<< " maxReads=" << kMaxReads
			<< " maxMeasurementMs=" << FormatDouble(kMaxMeasurementMicroseconds / 1000.0)
			<< std::endl;

		RunPhase({"default", false});
		RunPhase({"timeBeginPeriod(1)", true});
		return 0;
	}
}

int RunTimerResolutionProbeIfRequested(const int argc, char **argv)
{
	if (!IsProbeRequested(argc, argv))
		return -1;
	return RunProbe();
}
