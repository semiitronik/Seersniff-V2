package com.seersniff.sensor.analysis.rules;

import com.seersniff.sensor.analysis.AnalysisContext;
import com.seersniff.sensor.analysis.PacketMeta;
import com.seersniff.sensor.analysis.RulesConfig;
import com.seersniff.sensor.analysis.SuspicionRule;
import org.pcap4j.packet.Packet;

import java.util.List;

public class TcpRstBurstRule implements SuspicionRule {

    private final RulesConfig.TcpRstBurst cfg;

    public TcpRstBurstRule() {
        this(RulesConfig.defaults());
    }

    public TcpRstBurstRule(RulesConfig config) {
        this.cfg = (config == null) ? RulesConfig.defaults().tcpRstBurst : config.tcpRstBurst;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        PacketMeta m = PacketMeta.from(packet);
        if (!m.isTcp || !m.isIpv4 || m.srcIp == null) return 0;

        if (!m.rst) return 0;

        long now = ctx.getCurrentPacketTime();
        long windowMillis = cfg.windowSeconds * 1000L;
        var q = ctx.rstWindow(m.srcIp);
        q.addLast(now);
        AnalysisContext.evictOld(q, now, windowMillis);

        int c = q.size();
        if (c >= cfg.highAt) return cfg.highScore;
        if (c >= cfg.mediumAt) return cfg.mediumScore;
        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        PacketMeta m = PacketMeta.from(packet);
        if (m.srcIp == null) return;
        int count = ctx.rstWindow(m.srcIp).size();
        outReasons.add("High TCP RST rate from " + m.srcIp + " (count=" + count + " in "
                + cfg.windowSeconds + "s, med/high=" + cfg.mediumAt + "/" + cfg.highAt + ").");
    }
}
