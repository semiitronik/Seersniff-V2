package com.seersniff.sensor.analysis;

import java.util.*;

public class AnalysisContext {

    private final Set<String> trustedIps;

    // ---- time windows keyed by src IP ----
    private final Map<String, Deque<Long>> icmpEchoBySrc = new HashMap<>();

    // Port scan: src -> timestamps + dst ports seen recently
    private final Map<String, Deque<Long>> synTimesBySrc = new HashMap<>();
    private final Map<String, Map<Integer, Long>> synPortLastSeenBySrc = new HashMap<>();

    // RST burst: src -> RST timestamps
    private final Map<String, Deque<Long>> rstTimesBySrc = new HashMap<>();

    // UDP fanout: src -> UDP timestamps + dst ports recently
    private final Map<String, Deque<Long>> udpTimesBySrc = new HashMap<>();
    private final Map<String, Map<Integer, Long>> udpPortLastSeenBySrc = new HashMap<>();

    // High-risk port repeat detection: key -> timestamps
    private final Map<String, Deque<Long>> highRiskHitsByKey = new HashMap<>();

    // Correlation: src -> list of rule hits
    private final Map<String, Deque<RuleHit>> correlationHitsBySrc = new HashMap<>();

    // Used by rules so they all share a consistent "now"
    private long currentPacketTime = -1;

    public AnalysisContext(RulesConfig config) {
        Set<String> ips = (config == null || config.trusted == null || config.trusted.ips == null)
                ? Set.of()
                : config.trusted.ips;
        this.trustedIps = new HashSet<>(ips);
    }

    public AnalysisContext() {
        this(RulesConfig.defaults());
    }

    public void setCurrentPacketTime(long ts) {
        this.currentPacketTime = ts;
    }

    public long getCurrentPacketTime() {
        return (currentPacketTime > 0) ? currentPacketTime : System.currentTimeMillis();
    }

    public Deque<Long> icmpWindow(String srcIp) {
        return icmpEchoBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Deque<Long> synTimeWindow(String srcIp) {
        return synTimesBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Map<Integer, Long> synPortsWindow(String srcIp) {
        return synPortLastSeenBySrc.computeIfAbsent(srcIp, k -> new HashMap<>());
    }

    public Deque<Long> rstWindow(String srcIp) {
        return rstTimesBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Deque<Long> udpTimeWindow(String srcIp) {
        return udpTimesBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Map<Integer, Long> udpPortsWindow(String srcIp) {
        return udpPortLastSeenBySrc.computeIfAbsent(srcIp, k -> new HashMap<>());
    }

    public Deque<Long> highRiskWindow(String key) {
        return highRiskHitsByKey.computeIfAbsent(key, k -> new ArrayDeque<>());
    }

    public Deque<RuleHit> correlationWindow(String srcIp) {
        return correlationHitsBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public boolean isTrusted(String ip) {
        return ip != null && trustedIps.contains(ip);
    }

    public static class RuleHit {
        public final String ruleName;
        public final long timestamp;

        public RuleHit(String ruleName, long timestamp) {
            this.ruleName = ruleName;
            this.timestamp = timestamp;
        }
    }

    // Utility: evict old timestamps from a deque
    public static void evictOld(Deque<Long> q, long now, long windowMillis) {
        while (!q.isEmpty() && (now - q.peekFirst()) > windowMillis) q.removeFirst();
    }

    // Utility: evict old entries from (value = lastSeenMillis) maps
    public static void evictOld(Map<Integer, Long> lastSeen, long now, long windowMillis) {
        lastSeen.entrySet().removeIf(e -> (now - e.getValue()) > windowMillis);
    }
}
