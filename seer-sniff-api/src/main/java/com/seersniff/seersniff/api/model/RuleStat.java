package com.seersniff.seersniff.api.model;

public record RuleStat(
        String ruleId,
        int count,
        long lastSeen,
        double avgScore
) {}
