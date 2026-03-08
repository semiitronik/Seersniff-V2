package com.seersniff.seersniff.api.model;

public record TalkerStat(
        String srcIp,
        String dstIp,
        int packets,
        int alerts
) {}
