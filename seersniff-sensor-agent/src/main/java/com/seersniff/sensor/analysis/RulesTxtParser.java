package com.seersniff.sensor.analysis;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

public class RulesTxtParser {

    public static RulesConfig load() {
        RulesConfig config = RulesConfig.defaults();
        Path path = findRulesPath();
        if (path != null) {
            if (parsePath(path, config)) {
                return config;
            }
        }

        try (InputStream is = RulesTxtParser.class.getResourceAsStream("/rules.txt")) {
            if (is != null) {
                parseReader(new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8)), config, "classpath:/rules.txt");
                return config;
            }
        } catch (IOException e) {
            System.err.println("[RulesTxtParser] Error reading classpath rules.txt: " + e.getMessage());
        }

        System.err.println("[RulesTxtParser] No rules.txt found (checked -Dseersniff.rules, ./config/rules.txt, ./rules.txt, classpath). Using defaults.");
        return config;
    }

    public static RulesConfig load(Path path) {
        RulesConfig config = RulesConfig.defaults();
        if (path == null) {
            System.err.println("[RulesTxtParser] Null rules path provided. Using defaults.");
            return config;
        }
        parsePath(path, config);
        return config;
    }

    private static boolean parsePath(Path path, RulesConfig config) {
        if (path == null) return false;
        if (!Files.isRegularFile(path)) {
            System.err.println("[RulesTxtParser] rules.txt not found at " + path);
            return false;
        }
        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            parseReader(br, config, path.toString());
            return true;
        } catch (IOException e) {
            System.err.println("[RulesTxtParser] Error reading rules.txt at " + path + ": " + e.getMessage());
            return false;
        }
    }

    private static Path findRulesPath() {
        String prop = System.getProperty("seersniff.rules");
        if (prop != null && !prop.isBlank()) {
            Path p = Paths.get(prop.trim());
            if (!p.isAbsolute()) {
                p = Paths.get("").toAbsolutePath().resolve(p);
            }
            if (Files.isRegularFile(p)) {
                return p;
            }
            System.err.println("[RulesTxtParser] -Dseersniff.rules set but file not found: " + p);
        }

        Path configPath = Paths.get("config", "rules.txt");
        if (Files.isRegularFile(configPath)) {
            return configPath.toAbsolutePath();
        }

        Path localPath = Paths.get("rules.txt");
        if (Files.isRegularFile(localPath)) {
            return localPath.toAbsolutePath();
        }

        return null;
    }

    private static void parseReader(BufferedReader br, RulesConfig config, String sourceLabel) throws IOException {
        String section = "";
        int lineNum = 0;

        String line;
        while ((line = br.readLine()) != null) {
            lineNum++;
            String raw = line.trim();
            if (raw.isEmpty() || raw.startsWith("#")) continue;

            if (raw.startsWith("[") && raw.endsWith("]")) {
                section = raw.substring(1, raw.length() - 1).trim().toUpperCase(Locale.ROOT);
                continue;
            }

            String[] parts = raw.split("=", 2);
            if (parts.length != 2) {
                warn(sourceLabel, lineNum, "Invalid line (missing '='): " + raw);
                continue;
            }

            String key = parts[0].trim();
            String value = parts[1].trim();

            switch (section) {
                case "GLOBAL" -> applyGlobal(config, key, value, sourceLabel, lineNum);
                case "TRUSTED" -> applyTrusted(config, key, value, sourceLabel, lineNum);
                case "CORRELATION" -> applyCorrelation(config, key, value, sourceLabel, lineNum);
                case "SEVERITY_THRESHOLDS" -> applySeverity(config, key, value, sourceLabel, lineNum);
                case "HIGH_RISK_PORTS" -> applyHighRiskPorts(config, key, value, sourceLabel, lineNum);
                case "ICMP_BURST" -> applyIcmpBurst(config, key, value, sourceLabel, lineNum);
                case "TCP_SYN_SCAN" -> applyTcpSynScan(config, key, value, sourceLabel, lineNum);
                case "UDP_FANOUT" -> applyUdpFanout(config, key, value, sourceLabel, lineNum);
                case "TCP_RST_BURST" -> applyTcpRstBurst(config, key, value, sourceLabel, lineNum);
                case "TCP_PORTSCAN_BURST" -> applyTcpPortscanBurst(config, key, value, sourceLabel, lineNum);
                default -> warn(sourceLabel, lineNum, "Unknown section [" + section + "], ignoring key: " + key);
            }
        }
    }

    private static void applyGlobal(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "cooldownSeconds" -> config.global.cooldownSeconds = parseInt(value, config.global.cooldownSeconds, source, line, key);
            case "expireAlertsSeconds" -> config.global.expireAlertsSeconds = parseInt(value, config.global.expireAlertsSeconds, source, line, key);
            case "ringBufferSize" -> config.global.ringBufferSize = parseInt(value, config.global.ringBufferSize, source, line, key);
            case "uiFlushMillis" -> config.global.uiFlushMillis = parseInt(value, config.global.uiFlushMillis, source, line, key);
            default -> warn(source, line, "Unknown GLOBAL key: " + key);
        }
    }

    private static void applyTrusted(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "ips" -> config.trusted.ips = parseStringSet(value, config.trusted.ips, source, line, key);
            case "riskMultiplier" -> config.trusted.riskMultiplier = parseDouble(value, config.trusted.riskMultiplier, source, line, key);
            case "confidenceMultiplier" -> config.trusted.confidenceMultiplier = parseDouble(value, config.trusted.confidenceMultiplier, source, line, key);
            default -> warn(source, line, "Unknown TRUSTED key: " + key);
        }
    }

    private static void applyCorrelation(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "windowSeconds" -> config.correlation.windowSeconds = parseInt(value, config.correlation.windowSeconds, source, line, key);
            case "distinctRuleCount" -> config.correlation.distinctRuleCount = parseInt(value, config.correlation.distinctRuleCount, source, line, key);
            case "scoreBonus" -> config.correlation.scoreBonus = parseInt(value, config.correlation.scoreBonus, source, line, key);
            case "confidenceBonus" -> config.correlation.confidenceBonus = parseDouble(value, config.correlation.confidenceBonus, source, line, key);
            default -> warn(source, line, "Unknown CORRELATION key: " + key);
        }
    }

    private static void applySeverity(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "infoMax" -> config.severity.infoMax = parseInt(value, config.severity.infoMax, source, line, key);
            case "lowMax" -> config.severity.lowMax = parseInt(value, config.severity.lowMax, source, line, key);
            case "mediumMax" -> config.severity.mediumMax = parseInt(value, config.severity.mediumMax, source, line, key);
            case "highMax" -> config.severity.highMax = parseInt(value, config.severity.highMax, source, line, key);
            default -> warn(source, line, "Unknown SEVERITY_THRESHOLDS key: " + key);
        }
    }

    private static void applyHighRiskPorts(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "ports" -> config.highRiskPorts.ports = parseIntSet(value, config.highRiskPorts.ports, source, line, key);
            case "baseScore" -> config.highRiskPorts.baseScore = parseInt(value, config.highRiskPorts.baseScore, source, line, key);
            case "repeatWindowSeconds" -> config.highRiskPorts.repeatWindowSeconds = parseInt(value, config.highRiskPorts.repeatWindowSeconds, source, line, key);
            case "repeatScoreStep" -> config.highRiskPorts.repeatScoreStep = parseInt(value, config.highRiskPorts.repeatScoreStep, source, line, key);
            case "repeatEscalateAt" -> config.highRiskPorts.repeatEscalateAt = parseInt(value, config.highRiskPorts.repeatEscalateAt, source, line, key);
            case "maxBonusScore" -> config.highRiskPorts.maxBonusScore = parseInt(value, config.highRiskPorts.maxBonusScore, source, line, key);
            default -> warn(source, line, "Unknown HIGH_RISK_PORTS key: " + key);
        }
    }

    private static void applyIcmpBurst(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "windowSeconds" -> config.icmpBurst.windowSeconds = parseInt(value, config.icmpBurst.windowSeconds, source, line, key);
            case "lowAt" -> config.icmpBurst.lowAt = parseInt(value, config.icmpBurst.lowAt, source, line, key);
            case "mediumAt" -> config.icmpBurst.mediumAt = parseInt(value, config.icmpBurst.mediumAt, source, line, key);
            case "highAt" -> config.icmpBurst.highAt = parseInt(value, config.icmpBurst.highAt, source, line, key);
            case "lowScore" -> config.icmpBurst.lowScore = parseInt(value, config.icmpBurst.lowScore, source, line, key);
            case "mediumScore" -> config.icmpBurst.mediumScore = parseInt(value, config.icmpBurst.mediumScore, source, line, key);
            case "highScore" -> config.icmpBurst.highScore = parseInt(value, config.icmpBurst.highScore, source, line, key);
            case "confidenceLow" -> config.icmpBurst.confidenceLow = parseDouble(value, config.icmpBurst.confidenceLow, source, line, key);
            case "confidenceMedium" -> config.icmpBurst.confidenceMedium = parseDouble(value, config.icmpBurst.confidenceMedium, source, line, key);
            case "confidenceHigh" -> config.icmpBurst.confidenceHigh = parseDouble(value, config.icmpBurst.confidenceHigh, source, line, key);
            default -> warn(source, line, "Unknown ICMP_BURST key: " + key);
        }
    }

    private static void applyTcpSynScan(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "windowSeconds" -> config.tcpSynScan.windowSeconds = parseInt(value, config.tcpSynScan.windowSeconds, source, line, key);
            case "mediumAtUniquePorts" -> config.tcpSynScan.mediumAtUniquePorts = parseInt(value, config.tcpSynScan.mediumAtUniquePorts, source, line, key);
            case "highAtUniquePorts" -> config.tcpSynScan.highAtUniquePorts = parseInt(value, config.tcpSynScan.highAtUniquePorts, source, line, key);
            case "criticalAtUniquePorts" -> config.tcpSynScan.criticalAtUniquePorts = parseInt(value, config.tcpSynScan.criticalAtUniquePorts, source, line, key);
            case "mediumScore" -> config.tcpSynScan.mediumScore = parseInt(value, config.tcpSynScan.mediumScore, source, line, key);
            case "highScore" -> config.tcpSynScan.highScore = parseInt(value, config.tcpSynScan.highScore, source, line, key);
            case "criticalScore" -> config.tcpSynScan.criticalScore = parseInt(value, config.tcpSynScan.criticalScore, source, line, key);
            case "confidenceMedium" -> config.tcpSynScan.confidenceMedium = parseDouble(value, config.tcpSynScan.confidenceMedium, source, line, key);
            case "confidenceHigh" -> config.tcpSynScan.confidenceHigh = parseDouble(value, config.tcpSynScan.confidenceHigh, source, line, key);
            case "confidenceCritical" -> config.tcpSynScan.confidenceCritical = parseDouble(value, config.tcpSynScan.confidenceCritical, source, line, key);
            default -> warn(source, line, "Unknown TCP_SYN_SCAN key: " + key);
        }
    }

    private static void applyUdpFanout(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "windowSeconds" -> config.udpFanout.windowSeconds = parseInt(value, config.udpFanout.windowSeconds, source, line, key);
            case "mediumAtUniquePorts" -> config.udpFanout.mediumAtUniquePorts = parseInt(value, config.udpFanout.mediumAtUniquePorts, source, line, key);
            case "highAtUniquePorts" -> config.udpFanout.highAtUniquePorts = parseInt(value, config.udpFanout.highAtUniquePorts, source, line, key);
            case "mediumScore" -> config.udpFanout.mediumScore = parseInt(value, config.udpFanout.mediumScore, source, line, key);
            case "highScore" -> config.udpFanout.highScore = parseInt(value, config.udpFanout.highScore, source, line, key);
            case "confidenceMedium" -> config.udpFanout.confidenceMedium = parseDouble(value, config.udpFanout.confidenceMedium, source, line, key);
            case "confidenceHigh" -> config.udpFanout.confidenceHigh = parseDouble(value, config.udpFanout.confidenceHigh, source, line, key);
            default -> warn(source, line, "Unknown UDP_FANOUT key: " + key);
        }
    }

    private static void applyTcpRstBurst(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "windowSeconds" -> config.tcpRstBurst.windowSeconds = parseInt(value, config.tcpRstBurst.windowSeconds, source, line, key);
            case "mediumAt" -> config.tcpRstBurst.mediumAt = parseInt(value, config.tcpRstBurst.mediumAt, source, line, key);
            case "highAt" -> config.tcpRstBurst.highAt = parseInt(value, config.tcpRstBurst.highAt, source, line, key);
            case "mediumScore" -> config.tcpRstBurst.mediumScore = parseInt(value, config.tcpRstBurst.mediumScore, source, line, key);
            case "highScore" -> config.tcpRstBurst.highScore = parseInt(value, config.tcpRstBurst.highScore, source, line, key);
            case "confidenceMedium" -> config.tcpRstBurst.confidenceMedium = parseDouble(value, config.tcpRstBurst.confidenceMedium, source, line, key);
            case "confidenceHigh" -> config.tcpRstBurst.confidenceHigh = parseDouble(value, config.tcpRstBurst.confidenceHigh, source, line, key);
            default -> warn(source, line, "Unknown TCP_RST_BURST key: " + key);
        }
    }

    private static void applyTcpPortscanBurst(RulesConfig config, String key, String value, String source, int line) {
        switch (key) {
            case "windowSeconds" -> config.tcpPortscanBurst.windowSeconds = parseInt(value, config.tcpPortscanBurst.windowSeconds, source, line, key);
            case "mediumAtUniquePorts" -> config.tcpPortscanBurst.mediumAtUniquePorts = parseInt(value, config.tcpPortscanBurst.mediumAtUniquePorts, source, line, key);
            case "highAtUniquePorts" -> config.tcpPortscanBurst.highAtUniquePorts = parseInt(value, config.tcpPortscanBurst.highAtUniquePorts, source, line, key);
            case "criticalAtUniquePorts" -> config.tcpPortscanBurst.criticalAtUniquePorts = parseInt(value, config.tcpPortscanBurst.criticalAtUniquePorts, source, line, key);
            case "mediumScore" -> config.tcpPortscanBurst.mediumScore = parseInt(value, config.tcpPortscanBurst.mediumScore, source, line, key);
            case "highScore" -> config.tcpPortscanBurst.highScore = parseInt(value, config.tcpPortscanBurst.highScore, source, line, key);
            case "criticalScore" -> config.tcpPortscanBurst.criticalScore = parseInt(value, config.tcpPortscanBurst.criticalScore, source, line, key);
            case "confidenceMedium" -> config.tcpPortscanBurst.confidenceMedium = parseDouble(value, config.tcpPortscanBurst.confidenceMedium, source, line, key);
            case "confidenceHigh" -> config.tcpPortscanBurst.confidenceHigh = parseDouble(value, config.tcpPortscanBurst.confidenceHigh, source, line, key);
            case "confidenceCritical" -> config.tcpPortscanBurst.confidenceCritical = parseDouble(value, config.tcpPortscanBurst.confidenceCritical, source, line, key);
            default -> warn(source, line, "Unknown TCP_PORTSCAN_BURST key: " + key);
        }
    }

    private static int parseInt(String raw, int fallback, String source, int line, String key) {
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            warn(source, line, "Invalid int for " + key + ": " + raw + " (using " + fallback + ")");
            return fallback;
        }
    }

    private static double parseDouble(String raw, double fallback, String source, int line, String key) {
        try {
            return Double.parseDouble(raw.trim());
        } catch (NumberFormatException e) {
            warn(source, line, "Invalid double for " + key + ": " + raw + " (using " + fallback + ")");
            return fallback;
        }
    }

    private static Set<String> parseStringSet(String raw, Set<String> fallback, String source, int line, String key) {
        Set<String> out = new LinkedHashSet<>();
        for (String part : raw.split(",")) {
            String v = part.trim();
            if (!v.isEmpty()) out.add(v);
        }
        if (out.isEmpty()) {
            warn(source, line, "Invalid list for " + key + ": " + raw + " (using defaults)");
            return fallback;
        }
        return out;
    }

    private static Set<Integer> parseIntSet(String raw, Set<Integer> fallback, String source, int line, String key) {
        Set<Integer> out = new LinkedHashSet<>();
        for (String part : raw.split(",")) {
            String v = part.trim();
            if (v.isEmpty()) continue;
            try {
                out.add(Integer.parseInt(v));
            } catch (NumberFormatException e) {
                warn(source, line, "Invalid int in list for " + key + ": " + v);
            }
        }
        if (out.isEmpty()) {
            warn(source, line, "Invalid list for " + key + ": " + raw + " (using defaults)");
            return fallback;
        }
        return out;
    }

    private static void warn(String source, int line, String msg) {
        System.err.println("[RulesTxtParser] " + source + ":" + line + " - " + msg);
    }

    public static void main(String[] args) {
        RulesConfig config;
        if (args.length > 0) {
            config = RulesTxtParser.load(Paths.get(args[0]));
        } else {
            config = RulesTxtParser.load();
        }
        System.out.println(config);
    }
}
