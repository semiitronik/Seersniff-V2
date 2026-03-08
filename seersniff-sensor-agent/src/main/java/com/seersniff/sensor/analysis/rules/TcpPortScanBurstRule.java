package com.seersniff.sensor.analysis.rules;

import com.seersniff.sensor.analysis.AnalysisContext;
import com.seersniff.sensor.analysis.PacketMeta;
import com.seersniff.sensor.analysis.RulesConfig;
import com.seersniff.sensor.analysis.SuspicionRule;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.Map;

public class TcpPortScanBurstRule implements SuspicionRule {

    private final RulesConfig.TcpPortscanBurst cfg;

    public TcpPortScanBurstRule() {
        this(RulesConfig.defaults());
    }

    public TcpPortScanBurstRule(RulesConfig config) {
        this.cfg = (config == null) ? RulesConfig.defaults().tcpPortscanBurst : config.tcpPortscanBurst;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        PacketMeta m = PacketMeta.from(packet);
        if (!m.isTcp || !m.isIpv4 || m.srcIp == null || m.dstPort == null) return 0;

        // Track SYN attempts (SYN without ACK is the typical scan probe)
        if (!(m.syn && !m.ack)) return 0;

        long now = ctx.getCurrentPacketTime();
        long windowMillis = cfg.windowSeconds * 1000L;

        // window maintenance
        ctx.synTimeWindow(m.srcIp).addLast(now);
        AnalysisContext.evictOld(ctx.synTimeWindow(m.srcIp), now, windowMillis);

        Map<Integer, Long> ports = ctx.synPortsWindow(m.srcIp);
        ports.put(m.dstPort, now);
        AnalysisContext.evictOld(ports, now, windowMillis);

        int uniquePorts = ports.size();
        if (uniquePorts >= cfg.criticalAtUniquePorts) return cfg.criticalScore;
        if (uniquePorts >= cfg.highAtUniquePorts) return cfg.highScore;
        if (uniquePorts >= cfg.mediumAtUniquePorts) return cfg.mediumScore;
        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        PacketMeta m = PacketMeta.from(packet);
        if (m.srcIp == null) return;
        int uniquePorts = ctx.synPortsWindow(m.srcIp).size();
        outReasons.add("Possible TCP port scan: " + uniquePorts + " unique destination ports probed by " + m.srcIp
                + " in " + cfg.windowSeconds + "s (med/high/crit=" + cfg.mediumAtUniquePorts + "/"
                + cfg.highAtUniquePorts + "/" + cfg.criticalAtUniquePorts + ").");
    }
}
