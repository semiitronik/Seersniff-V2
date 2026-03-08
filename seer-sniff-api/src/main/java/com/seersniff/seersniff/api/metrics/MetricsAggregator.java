package com.seersniff.seersniff.api.metrics;

import com.seersniff.seersniff.api.model.AlertEvent;
import com.seersniff.seersniff.api.model.MetricsSnapshot;
import com.seersniff.seersniff.api.model.PacketSummary;
import com.seersniff.seersniff.api.model.RuleStat;
import com.seersniff.seersniff.api.model.TalkerStat;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class MetricsAggregator {

    private final Map<String, MetricsWindow> windows = new ConcurrentHashMap<>();

    public void recordPacket(PacketSummary summary) {
        if (summary == null) return;
        String sensorId = summary.sensorId() != null ? summary.sensorId() : "default";
        windows.computeIfAbsent(sensorId, MetricsWindow::new).recordPacket(summary);
    }

    public void recordAlert(AlertEvent alert) {
        if (alert == null) return;
        String sensorId = alert.sensorId() != null ? alert.sensorId() : "default";
        windows.computeIfAbsent(sensorId, MetricsWindow::new).recordAlert(alert);
    }

    public List<MetricsSnapshot> snapshots() {
        ArrayList<MetricsSnapshot> out = new ArrayList<>();
        for (MetricsWindow window : windows.values()) {
            out.add(window.snapshot());
        }
        return out;
    }

    private static final class MetricsWindow {
        private static final int WINDOW_SEC = 600;
        private static final int AVG_SEC = 60;

        private final String sensorId;
        private final Deque<PacketEntry> packets = new ArrayDeque<>();
        private final Deque<AlertEntry> alerts = new ArrayDeque<>();

        private final Map<String, Integer> protocolCounts = new HashMap<>();
        private final Map<String, Integer> severityCounts = new HashMap<>();
        private final Map<String, Integer> srcIpCounts = new HashMap<>();
        private final Map<String, Integer> talkerPacketCounts = new HashMap<>();
        private final Map<String, Integer> talkerAlertCounts = new HashMap<>();
        private final Map<String, Integer> ruleCounts = new HashMap<>();
        private final Map<String, Integer> ruleScoreSum = new HashMap<>();
        private final Map<String, Long> ruleLastSeen = new HashMap<>();

        private final long[] packetSecTs = new long[WINDOW_SEC];
        private final int[] packetSecCounts = new int[WINDOW_SEC];
        private final long[] alertSecTs = new long[WINDOW_SEC];
        private final int[] alertSecCounts = new int[WINDOW_SEC];

        private MetricsWindow(String sensorId) {
            this.sensorId = sensorId;
        }

        public synchronized void recordPacket(PacketSummary summary) {
            long tsSec = summary.ts() > 0 ? summary.ts() / 1000 : System.currentTimeMillis() / 1000;
            int idx = (int) Math.floorMod(tsSec, WINDOW_SEC);
            if (packetSecTs[idx] != tsSec) {
                packetSecTs[idx] = tsSec;
                packetSecCounts[idx] = 0;
            }
            packetSecCounts[idx] += 1;

            String protocol = normalize(summary.protocol(), "OTHER");
            String srcIp = summary.srcIp();
            String dstIp = summary.dstIp();
            String talkerKey = (srcIp != null && dstIp != null) ? srcIp + "->" + dstIp : null;

            packets.addLast(new PacketEntry(tsSec, protocol, srcIp, dstIp, talkerKey));
            increment(protocolCounts, protocol);
            if (srcIp != null) increment(srcIpCounts, srcIp);
            if (talkerKey != null) increment(talkerPacketCounts, talkerKey);

            purgeOld(tsSec);
        }

        public synchronized void recordAlert(AlertEvent alert) {
            long tsSec = alert.ts() > 0 ? alert.ts() / 1000 : System.currentTimeMillis() / 1000;
            int idx = (int) Math.floorMod(tsSec, WINDOW_SEC);
            if (alertSecTs[idx] != tsSec) {
                alertSecTs[idx] = tsSec;
                alertSecCounts[idx] = 0;
            }
            alertSecCounts[idx] += 1;

            String severity = normalize(alert.severity(), "INFO");
            String srcIp = alert.srcIp();
            String dstIp = alert.dstIp();
            String talkerKey = (srcIp != null && dstIp != null) ? srcIp + "->" + dstIp : null;

            List<String> ruleIds = new ArrayList<>();
            if (alert.ruleIds() != null) ruleIds.addAll(alert.ruleIds());
            if (ruleIds.isEmpty() && alert.ruleScores() != null) ruleIds.addAll(alert.ruleScores().keySet());

            alerts.addLast(new AlertEntry(tsSec, severity, srcIp, dstIp, talkerKey, ruleIds, alert.score()));
            increment(severityCounts, severity);
            if (talkerKey != null) increment(talkerAlertCounts, talkerKey);
            if (srcIp != null) increment(srcIpCounts, srcIp);
            for (String ruleId : ruleIds) {
                increment(ruleCounts, ruleId);
                ruleScoreSum.merge(ruleId, alert.score(), Integer::sum);
                ruleLastSeen.put(ruleId, alert.ts());
            }

            purgeOld(tsSec);
        }

        public synchronized MetricsSnapshot snapshot() {
            long nowSec = System.currentTimeMillis() / 1000;
            purgeOld(nowSec);

            int currentPps = bucketValue(packetSecTs, packetSecCounts, nowSec);
            int sum = 0;
            for (int i = 0; i < AVG_SEC; i++) {
                long ts = nowSec - i;
                sum += bucketValue(packetSecTs, packetSecCounts, ts);
            }
            double avg = sum / (double) AVG_SEC;

            long alertsLast10m = alerts.size();
            String highestSeverity = highestSeverity();
            String topSource = topSourceIp();

            List<TalkerStat> talkers = topTalkers();
            List<RuleStat> rules = topRules();

            return new MetricsSnapshot(
                    sensorId,
                    System.currentTimeMillis(),
                    currentPps,
                    avg,
                    alertsLast10m,
                    highestSeverity,
                    topSource,
                    new HashMap<>(protocolCounts),
                    new HashMap<>(severityCounts),
                    talkers,
                    rules
            );
        }

        private void purgeOld(long nowSec) {
            long cutoff = nowSec - (WINDOW_SEC - 1);
            while (!packets.isEmpty() && packets.peekFirst().tsSec < cutoff) {
                PacketEntry removed = packets.removeFirst();
                decrement(protocolCounts, removed.protocol);
                if (removed.srcIp != null) decrement(srcIpCounts, removed.srcIp);
                if (removed.talkerKey != null) decrement(talkerPacketCounts, removed.talkerKey);
            }
            while (!alerts.isEmpty() && alerts.peekFirst().tsSec < cutoff) {
                AlertEntry removed = alerts.removeFirst();
                decrement(severityCounts, removed.severity);
                if (removed.talkerKey != null) decrement(talkerAlertCounts, removed.talkerKey);
                if (removed.srcIp != null) decrement(srcIpCounts, removed.srcIp);
                for (String ruleId : removed.ruleIds) {
                    decrement(ruleCounts, ruleId);
                    ruleScoreSum.merge(ruleId, -removed.score, Integer::sum);
                    if (ruleScoreSum.getOrDefault(ruleId, 0) <= 0) ruleScoreSum.remove(ruleId);
                    if (ruleLastSeen.getOrDefault(ruleId, 0L) == removed.originalTs()) {
                        recomputeLastSeen(ruleId);
                    }
                }
            }
        }

        private void recomputeLastSeen(String ruleId) {
            long last = 0;
            for (AlertEntry entry : alerts) {
                if (entry.ruleIds.contains(ruleId)) {
                    long ts = entry.originalTs();
                    if (ts > last) last = ts;
                }
            }
            if (last == 0) ruleLastSeen.remove(ruleId);
            else ruleLastSeen.put(ruleId, last);
        }

        private static int bucketValue(long[] ts, int[] counts, long sec) {
            int idx = (int) Math.floorMod(sec, WINDOW_SEC);
            return ts[idx] == sec ? counts[idx] : 0;
        }

        private String highestSeverity() {
            String[] order = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};
            for (String sev : order) {
                if (severityCounts.getOrDefault(sev, 0) > 0) return sev;
            }
            return "INFO";
        }

        private String topSourceIp() {
            return srcIpCounts.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(null);
        }

        private List<TalkerStat> topTalkers() {
            ArrayList<TalkerStat> out = new ArrayList<>();
            talkerPacketCounts.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .limit(6)
                    .forEach(entry -> {
                        String[] parts = entry.getKey().split("->", 2);
                        String src = parts.length > 0 ? parts[0] : null;
                        String dst = parts.length > 1 ? parts[1] : null;
                        int alerts = talkerAlertCounts.getOrDefault(entry.getKey(), 0);
                        out.add(new TalkerStat(src, dst, entry.getValue(), alerts));
                    });
            return out;
        }

        private List<RuleStat> topRules() {
            return ruleCounts.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .limit(6)
                    .map(entry -> {
                        String ruleId = entry.getKey();
                        int count = entry.getValue();
                        int sum = ruleScoreSum.getOrDefault(ruleId, 0);
                        long lastSeen = ruleLastSeen.getOrDefault(ruleId, 0L);
                        double avg = count > 0 ? (sum / (double) count) : 0.0;
                        return new RuleStat(ruleId, count, lastSeen, avg);
                    })
                    .toList();
        }

        private static String normalize(String value, String fallback) {
            if (value == null || value.isBlank()) return fallback;
            return value.toUpperCase();
        }

        private static void increment(Map<String, Integer> map, String key) {
            map.merge(key, 1, Integer::sum);
        }

        private static void decrement(Map<String, Integer> map, String key) {
            Integer v = map.get(key);
            if (v == null) return;
            if (v <= 1) map.remove(key);
            else map.put(key, v - 1);
        }
    }

    private record PacketEntry(
            long tsSec,
            String protocol,
            String srcIp,
            String dstIp,
            String talkerKey
    ) {}

    private record AlertEntry(
            long tsSec,
            String severity,
            String srcIp,
            String dstIp,
            String talkerKey,
            List<String> ruleIds,
            int score
    ) {
        private long originalTs() {
            return tsSec * 1000;
        }
    }
}
