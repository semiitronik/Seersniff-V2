package com.seersniff.sensor.analysis;

import java.util.LinkedHashSet;
import java.util.Set;

public class RulesConfig {

    public final Global global = new Global();
    public final Trusted trusted = new Trusted();
    public final Correlation correlation = new Correlation();
    public final SeverityThresholds severity = new SeverityThresholds();
    public final HighRiskPorts highRiskPorts = new HighRiskPorts();
    public final IcmpBurst icmpBurst = new IcmpBurst();
    public final TcpSynScan tcpSynScan = new TcpSynScan();
    public final UdpFanout udpFanout = new UdpFanout();
    public final TcpRstBurst tcpRstBurst = new TcpRstBurst();
    public final TcpPortscanBurst tcpPortscanBurst = new TcpPortscanBurst();

    public static RulesConfig defaults() {
        return new RulesConfig();
    }

    public static RulesConfig load() {
        return RulesTxtParser.load();
    }

    public static class Global {
        public int cooldownSeconds = 10;
        public int expireAlertsSeconds = 120;
        public int ringBufferSize = 5000;
        public int uiFlushMillis = 200;
    }

    public static class Trusted {
        public Set<String> ips = new LinkedHashSet<>(Set.of("127.0.0.1", "192.168.1.1", "8.8.8.8"));
        public double riskMultiplier = 0.5;
        public double confidenceMultiplier = 0.5;
    }

    public static class Correlation {
        public int windowSeconds = 30;
        public int distinctRuleCount = 2;
        public int scoreBonus = 10;
        public double confidenceBonus = 0.10;
    }

    public static class SeverityThresholds {
        public int infoMax = 19;
        public int lowMax = 39;
        public int mediumMax = 64;
        public int highMax = 84;
    }

    public static class HighRiskPorts {
        public Set<Integer> ports = new LinkedHashSet<>(Set.of(23, 2323, 445, 3389, 5900, 1433, 3306));
        public int baseScore = 12;
        public int repeatWindowSeconds = 60;
        public int repeatScoreStep = 3;
        public int repeatEscalateAt = 3;
        public int maxBonusScore = 20;
    }

    public static class IcmpBurst {
        public int windowSeconds = 10;
        public int lowAt = 8;
        public int mediumAt = 15;
        public int highAt = 30;
        public int lowScore = 10;
        public int mediumScore = 20;
        public int highScore = 35;
        public double confidenceLow = 0.10;
        public double confidenceMedium = 0.20;
        public double confidenceHigh = 0.35;
    }

    public static class TcpSynScan {
        public int windowSeconds = 30;
        public int mediumAtUniquePorts = 6;
        public int highAtUniquePorts = 10;
        public int criticalAtUniquePorts = 20;
        public int mediumScore = 20;
        public int highScore = 35;
        public int criticalScore = 55;
        public double confidenceMedium = 0.20;
        public double confidenceHigh = 0.35;
        public double confidenceCritical = 0.50;
    }

    public static class UdpFanout {
        public int windowSeconds = 30;
        public int mediumAtUniquePorts = 8;
        public int highAtUniquePorts = 15;
        public int mediumScore = 15;
        public int highScore = 30;
        public double confidenceMedium = 0.15;
        public double confidenceHigh = 0.30;
    }

    public static class TcpRstBurst {
        public int windowSeconds = 10;
        public int mediumAt = 10;
        public int highAt = 20;
        public int mediumScore = 18;
        public int highScore = 32;
        public double confidenceMedium = 0.18;
        public double confidenceHigh = 0.32;
    }

    public static class TcpPortscanBurst {
        public int windowSeconds = 30;
        public int mediumAtUniquePorts = 8;
        public int highAtUniquePorts = 15;
        public int criticalAtUniquePorts = 25;
        public int mediumScore = 18;
        public int highScore = 30;
        public int criticalScore = 50;
        public double confidenceMedium = 0.18;
        public double confidenceHigh = 0.30;
        public double confidenceCritical = 0.50;
    }

    @Override
    public String toString() {
        return "RulesConfig{" +
                "global={cooldownSeconds=" + global.cooldownSeconds +
                ", expireAlertsSeconds=" + global.expireAlertsSeconds +
                ", ringBufferSize=" + global.ringBufferSize +
                ", uiFlushMillis=" + global.uiFlushMillis +
                "}, trusted={ips=" + trusted.ips +
                ", riskMultiplier=" + trusted.riskMultiplier +
                ", confidenceMultiplier=" + trusted.confidenceMultiplier +
                "}, correlation={windowSeconds=" + correlation.windowSeconds +
                ", distinctRuleCount=" + correlation.distinctRuleCount +
                ", scoreBonus=" + correlation.scoreBonus +
                ", confidenceBonus=" + correlation.confidenceBonus +
                "}, severity={infoMax=" + severity.infoMax +
                ", lowMax=" + severity.lowMax +
                ", mediumMax=" + severity.mediumMax +
                ", highMax=" + severity.highMax +
                "}, highRiskPorts={ports=" + highRiskPorts.ports +
                ", baseScore=" + highRiskPorts.baseScore +
                ", repeatWindowSeconds=" + highRiskPorts.repeatWindowSeconds +
                ", repeatScoreStep=" + highRiskPorts.repeatScoreStep +
                ", repeatEscalateAt=" + highRiskPorts.repeatEscalateAt +
                ", maxBonusScore=" + highRiskPorts.maxBonusScore +
                "}, icmpBurst={windowSeconds=" + icmpBurst.windowSeconds +
                ", lowAt=" + icmpBurst.lowAt +
                ", mediumAt=" + icmpBurst.mediumAt +
                ", highAt=" + icmpBurst.highAt +
                ", lowScore=" + icmpBurst.lowScore +
                ", mediumScore=" + icmpBurst.mediumScore +
                ", highScore=" + icmpBurst.highScore +
                ", confidenceLow=" + icmpBurst.confidenceLow +
                ", confidenceMedium=" + icmpBurst.confidenceMedium +
                ", confidenceHigh=" + icmpBurst.confidenceHigh +
                "}, tcpSynScan={windowSeconds=" + tcpSynScan.windowSeconds +
                ", mediumAtUniquePorts=" + tcpSynScan.mediumAtUniquePorts +
                ", highAtUniquePorts=" + tcpSynScan.highAtUniquePorts +
                ", criticalAtUniquePorts=" + tcpSynScan.criticalAtUniquePorts +
                ", mediumScore=" + tcpSynScan.mediumScore +
                ", highScore=" + tcpSynScan.highScore +
                ", criticalScore=" + tcpSynScan.criticalScore +
                ", confidenceMedium=" + tcpSynScan.confidenceMedium +
                ", confidenceHigh=" + tcpSynScan.confidenceHigh +
                ", confidenceCritical=" + tcpSynScan.confidenceCritical +
                "}, udpFanout={windowSeconds=" + udpFanout.windowSeconds +
                ", mediumAtUniquePorts=" + udpFanout.mediumAtUniquePorts +
                ", highAtUniquePorts=" + udpFanout.highAtUniquePorts +
                ", mediumScore=" + udpFanout.mediumScore +
                ", highScore=" + udpFanout.highScore +
                ", confidenceMedium=" + udpFanout.confidenceMedium +
                ", confidenceHigh=" + udpFanout.confidenceHigh +
                "}, tcpRstBurst={windowSeconds=" + tcpRstBurst.windowSeconds +
                ", mediumAt=" + tcpRstBurst.mediumAt +
                ", highAt=" + tcpRstBurst.highAt +
                ", mediumScore=" + tcpRstBurst.mediumScore +
                ", highScore=" + tcpRstBurst.highScore +
                ", confidenceMedium=" + tcpRstBurst.confidenceMedium +
                ", confidenceHigh=" + tcpRstBurst.confidenceHigh +
                "}, tcpPortscanBurst={windowSeconds=" + tcpPortscanBurst.windowSeconds +
                ", mediumAtUniquePorts=" + tcpPortscanBurst.mediumAtUniquePorts +
                ", highAtUniquePorts=" + tcpPortscanBurst.highAtUniquePorts +
                ", criticalAtUniquePorts=" + tcpPortscanBurst.criticalAtUniquePorts +
                ", mediumScore=" + tcpPortscanBurst.mediumScore +
                ", highScore=" + tcpPortscanBurst.highScore +
                ", criticalScore=" + tcpPortscanBurst.criticalScore +
                ", confidenceMedium=" + tcpPortscanBurst.confidenceMedium +
                ", confidenceHigh=" + tcpPortscanBurst.confidenceHigh +
                ", confidenceCritical=" + tcpPortscanBurst.confidenceCritical +
                "}" +
                "}";
    }
}
