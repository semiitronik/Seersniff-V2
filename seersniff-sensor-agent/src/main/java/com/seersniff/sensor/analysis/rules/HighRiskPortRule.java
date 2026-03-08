package com.seersniff.sensor.analysis.rules;

import com.seersniff.sensor.analysis.AnalysisContext;
import com.seersniff.sensor.analysis.PacketMeta;
import com.seersniff.sensor.analysis.RulesConfig;
import com.seersniff.sensor.analysis.SuspicionRule;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.util.List;

public class HighRiskPortRule implements SuspicionRule {

    private final RulesConfig.HighRiskPorts cfg;

    public HighRiskPortRule() {
        this(RulesConfig.defaults());
    }

    public HighRiskPortRule(RulesConfig config) {
        this.cfg = (config == null) ? RulesConfig.defaults().highRiskPorts : config.highRiskPorts;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        Integer dst = getDstPort(packet);
        if (dst == null || !cfg.ports.contains(dst)) return 0;

        int score = cfg.baseScore;
        String srcIp = PacketMeta.from(packet).srcIp;
        if (srcIp != null && cfg.repeatWindowSeconds > 0) {
            long now = ctx.getCurrentPacketTime();
            String key = srcIp + ":" + dst;
            var q = ctx.highRiskWindow(key);
            q.addLast(now);
            AnalysisContext.evictOld(q, now, cfg.repeatWindowSeconds * 1000L);

            int count = q.size();
            if (count >= cfg.repeatEscalateAt) {
                int bonus = (count - cfg.repeatEscalateAt + 1) * cfg.repeatScoreStep;
                bonus = Math.min(cfg.maxBonusScore, Math.max(0, bonus));
                score += bonus;
            }
        }

        return score;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        Integer dst = getDstPort(packet);
        if (dst == null || !cfg.ports.contains(dst)) return;

        String srcIp = PacketMeta.from(packet).srcIp;
        int count = 1;
        if (srcIp != null && cfg.repeatWindowSeconds > 0) {
            String key = srcIp + ":" + dst;
            count = ctx.highRiskWindow(key).size();
        }

        outReasons.add("High-risk port " + dst + " targeted (hits=" + count + " in " + cfg.repeatWindowSeconds
                + "s, baseScore=" + cfg.baseScore + ", step=" + cfg.repeatScoreStep + ", escalateAt="
                + cfg.repeatEscalateAt + ").");
    }

    private Integer getDstPort(Packet packet) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) return tcp.getHeader().getDstPort().valueAsInt();

        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) return udp.getHeader().getDstPort().valueAsInt();

        return null;
    }
}
