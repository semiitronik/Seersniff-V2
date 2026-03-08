package com.seersniff.sensor.analysis;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Fixed PacketAnalyzer: reuses a single AnalysisContext so window-based rules
 * (ICMP/TCP/UDP burst detectors) can accumulate events across packets.
 *
 * Also provides safer rule execution and correlation bonus logic.
 */
public class PacketAnalyzer {

    private final List<SuspicionRule> rules;
    private final AnalysisContext context;
    private final RulesConfig config;
    private final Map<String, Long> recentAlertsByKey = new LinkedHashMap<>();

    public PacketAnalyzer(List<SuspicionRule> rules) {
        this(rules, RulesConfig.load());
    }

    public PacketAnalyzer(List<SuspicionRule> rules, RulesConfig config) {
        this.rules = (rules == null) ? List.of() : List.copyOf(rules);
        this.config = (config == null) ? RulesConfig.defaults() : config;
        this.context = new AnalysisContext(this.config);
    }

    /**
     * Live/default analysis (uses wall-clock time).
     * Good for live capture.
     */
    public SuspicionResult analyze(Packet packet) {
        return analyze(packet, System.currentTimeMillis());
    }

    /**
     * Deterministic analysis using a caller-provided packet timestamp (ms).
     * Useful for testing / pcap replay.
     */
    public SuspicionResult analyze(Packet packet, long packetTimeMillis) {
        if (packet == null) return SuspicionResult.clean();

        // Set 'now' for burst/window rules
        context.setCurrentPacketTime(packetTimeMillis);

        int total = 0;
        List<String> reasons = new ArrayList<>();
        Map<String, Integer> contributions = new LinkedHashMap<>();

        for (SuspicionRule rule : rules) {
            int s = safeScore(rule, packet);
            if (s > 0) {
                total += s;
                contributions.merge(rule.getClass().getSimpleName(), s, Integer::sum);
                safeExplain(rule, packet, reasons);
            }
        }

        PacketMeta meta = PacketMeta.from(packet);
        String srcIp = meta.srcIp;

        total += applyCorrelationBonus(packetTimeMillis, srcIp, reasons, contributions);

        int finalScore = applyTrustedMultipliers(total, srcIp, meta.dstIp, reasons, contributions);
        finalScore = Math.min(finalScore, 100);

        Severity sev = mapSeverity(finalScore);

        if (finalScore > 0 && isInCooldown(packetTimeMillis, srcIp, meta.dstIp)) {
            return SuspicionResult.clean();
        }

        return new SuspicionResult(finalScore, sev, reasons, contributions);
    }

    public AnalysisContext getContext() {
        return context;
    }

    /** Exposes the active rules (useful for exports / experiment reports). */
    public List<SuspicionRule> getRules() {
        return rules;
    }

    private int applyCorrelationBonus(long now, String srcIp, List<String> reasons, Map<String, Integer> contributions) {
        if (srcIp == null) return 0;
        if (config.correlation.windowSeconds <= 0 || config.correlation.distinctRuleCount <= 0) return 0;
        if (contributions.isEmpty()) return 0;

        long windowMillis = config.correlation.windowSeconds * 1000L;
        var hits = context.correlationWindow(srcIp);

        for (String ruleName : contributions.keySet()) {
            hits.addLast(new AnalysisContext.RuleHit(ruleName, now));
        }

        while (!hits.isEmpty() && (now - hits.peekFirst().timestamp) > windowMillis) {
            hits.removeFirst();
        }

        Set<String> distinct = new LinkedHashSet<>();
        for (AnalysisContext.RuleHit hit : hits) {
            distinct.add(hit.ruleName);
        }

        if (distinct.size() < config.correlation.distinctRuleCount) return 0;

        int scoreBonus = config.correlation.scoreBonus;
        int confidenceScore = 0;
        if (config.correlation.confidenceBonus > 0) {
            confidenceScore = (int) Math.round(scoreBonus * config.correlation.confidenceBonus);
        }
        if (scoreBonus > 0) {
            contributions.put("CorrelationBonus", scoreBonus);
        }
        if (confidenceScore > 0) {
            contributions.put("CorrelationConfidenceBonus", confidenceScore);
        }

        if (scoreBonus > 0 || confidenceScore > 0) {
            reasons.add("Correlation: " + distinct.size() + " distinct rules in " + config.correlation.windowSeconds
                    + "s (+score " + scoreBonus + ", +confidence " + config.correlation.confidenceBonus + ").");
        }
        return scoreBonus + confidenceScore;
    }

    private int applyTrustedMultipliers(int total, String srcIp, String dstIp, List<String> reasons, Map<String, Integer> contributions) {
        boolean trusted = context.isTrusted(srcIp) || context.isTrusted(dstIp);
        if (!trusted) return total;

        double riskMultiplier = config.trusted.riskMultiplier;
        double confidenceMultiplier = config.trusted.confidenceMultiplier;
        if (riskMultiplier <= 0) riskMultiplier = 1.0;
        if (confidenceMultiplier <= 0) confidenceMultiplier = 1.0;

        double combined = riskMultiplier * confidenceMultiplier;
        int adjusted = (int) Math.round(total * combined);
        if (adjusted != total) {
            contributions.put("TrustedRiskMultiplier", adjusted - total);
            reasons.add("Trusted IP adjustment: score * " + combined + " (src=" + srcIp + ", dst=" + dstIp + ").");
        }
        return adjusted;
    }

    private boolean isInCooldown(long now, String srcIp, String dstIp) {
        int cooldownSeconds = config.global.cooldownSeconds;
        int expireSeconds = config.global.expireAlertsSeconds;
        if (cooldownSeconds <= 0) return false;

        long expireMillis = Math.max(1, expireSeconds) * 1000L;
        long cooldownMillis = cooldownSeconds * 1000L;

        recentAlertsByKey.entrySet().removeIf(e -> (now - e.getValue()) > expireMillis);

        String key = buildDedupKey(srcIp, dstIp);
        Long last = recentAlertsByKey.get(key);
        if (last != null && (now - last) < cooldownMillis) {
            return true;
        }

        recentAlertsByKey.put(key, now);
        return false;
    }

    private String buildDedupKey(String srcIp, String dstIp) {
        String src = (srcIp == null) ? "unknown-src" : srcIp;
        String dst = (dstIp == null) ? "unknown-dst" : dstIp;
        return src + "->" + dst;
    }

    private Severity mapSeverity(int score) {
        if (score <= config.severity.infoMax) return Severity.INFO;
        if (score <= config.severity.lowMax) return Severity.LOW;
        if (score <= config.severity.mediumMax) return Severity.MEDIUM;
        if (score <= config.severity.highMax) return Severity.HIGH;
        return Severity.CRITICAL;
    }

    private int safeScore(SuspicionRule rule, Packet packet) {
        try {
            return rule.score(packet, context);
        } catch (Exception e) {
            System.err.println("[PacketAnalyzer] rule.score() threw for " + rule.getClass().getSimpleName() + ": " + e.getMessage());
            return 0;
        }
    }

    private void safeExplain(SuspicionRule rule, Packet packet, List<String> reasons) {
        try {
            rule.explain(packet, context, reasons);
        } catch (Exception e) {
            System.err.println("[PacketAnalyzer] rule.explain() threw for " + rule.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
