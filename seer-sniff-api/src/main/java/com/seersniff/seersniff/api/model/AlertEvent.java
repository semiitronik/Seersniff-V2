package com.seersniff.seersniff.api.model;

import java.util.List;
import java.util.Map;

public record AlertEvent(
        String sensorId,
        long ts,

        // optional packet meta (can be null for now)
        String srcIp,
        String dstIp,
        Integer srcPort,
        Integer dstPort,
        String protocol,

        int score,
        Double confidence,
        String severity,
        String summary,
        List<String> reasons,
        List<String> ruleIds,
        List<String> findings,
        Map<String, Object> evidence,
        Map<String, Integer> ruleScores
) {}
