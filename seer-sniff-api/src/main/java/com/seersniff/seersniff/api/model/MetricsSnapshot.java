package com.seersniff.seersniff.api.model;

import java.util.List;
import java.util.Map;

public record MetricsSnapshot(
        String sensorId,
        long ts,
        double packetsPerSec,
        double packetsPerSecAvg60,
        long alertsLast10m,
        String highestSeverityLast10m,
        String topSourceIpLast10m,
        Map<String, Integer> protocolCounts,
        Map<String, Integer> severityCounts,
        List<TalkerStat> topTalkers,
        List<RuleStat> recentRuleTriggers
) {}
