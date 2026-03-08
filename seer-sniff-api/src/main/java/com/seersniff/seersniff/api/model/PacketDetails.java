package com.seersniff.seersniff.api.model;

import java.util.List;
import java.util.Map;

public record PacketDetails(
        String sensorId,
        long ts,
        long packetId,
        String srcIp,
        String dstIp,
        Integer srcPort,
        Integer dstPort,
        String protocol,
        Integer length,
        String info,
        int score,
        String severity,
        Double confidence,
        List<String> reasons,
        List<String> findings,
        List<String> evidence,
        Map<String,Integer> ruleScores,
        String rawText,
        String payloadHex
) {}
