package com.seersniff.sensor.analysis.rules;

import com.seersniff.sensor.analysis.AnalysisContext;
import com.seersniff.sensor.analysis.PacketMeta;
import com.seersniff.sensor.analysis.RulesConfig;
import com.seersniff.sensor.analysis.SuspicionRule;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.Map;

public class UdpPortFanoutRule implements SuspicionRule {

    private final RulesConfig.UdpFanout cfg;

    public UdpPortFanoutRule() {
        this(RulesConfig.defaults());
    }

    public UdpPortFanoutRule(RulesConfig config) {
        this.cfg = (config == null) ? RulesConfig.defaults().udpFanout : config.udpFanout;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        PacketMeta m = PacketMeta.from(packet);
        if (!m.isUdp || !m.isIpv4 || m.srcIp == null || m.dstPort == null) return 0;

        long now = ctx.getCurrentPacketTime();
        long windowMillis = cfg.windowSeconds * 1000L;
        ctx.udpTimeWindow(m.srcIp).addLast(now);
        AnalysisContext.evictOld(ctx.udpTimeWindow(m.srcIp), now, windowMillis);

        Map<Integer, Long> ports = ctx.udpPortsWindow(m.srcIp);
        ports.put(m.dstPort, now);
        AnalysisContext.evictOld(ports, now, windowMillis);

        int uniquePorts = ports.size();
        if (uniquePorts >= cfg.highAtUniquePorts) return cfg.highScore;
        if (uniquePorts >= cfg.mediumAtUniquePorts) return cfg.mediumScore;
        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        PacketMeta m = PacketMeta.from(packet);
        if (m.srcIp == null) return;
        int uniquePorts = ctx.udpPortsWindow(m.srcIp).size();
        outReasons.add("Possible UDP scan/fanout: " + uniquePorts + " unique destination ports targeted by " + m.srcIp
                + " in " + cfg.windowSeconds + "s (med/high=" + cfg.mediumAtUniquePorts + "/"
                + cfg.highAtUniquePorts + ").");
    }
}
