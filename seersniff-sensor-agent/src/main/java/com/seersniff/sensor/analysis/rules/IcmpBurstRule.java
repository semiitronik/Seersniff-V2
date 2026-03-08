package com.seersniff.sensor.analysis.rules;

import com.seersniff.sensor.analysis.AnalysisContext;
import com.seersniff.sensor.analysis.RulesConfig;
import com.seersniff.sensor.analysis.SuspicionRule;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;

import java.util.Deque;
import java.util.List;

public class IcmpBurstRule implements SuspicionRule {

    private final RulesConfig.IcmpBurst cfg;

    public IcmpBurstRule() {
        this(RulesConfig.defaults());
    }

    public IcmpBurstRule(RulesConfig config) {
        this.cfg = (config == null) ? RulesConfig.defaults().icmpBurst : config.icmpBurst;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        if (icmp == null || ip == null) return 0;

        // Only consider ICMP Echo requests (ping bursts)
        if (!IcmpV4Type.ECHO.equals(icmp.getHeader().getType())) return 0;

        String srcIp = ip.getHeader().getSrcAddr().getHostAddress();

        long now = ctx.getCurrentPacketTime();
        Deque<Long> q = ctx.icmpWindow(srcIp);
        q.addLast(now);

        long windowMillis = cfg.windowSeconds * 1000L;
        AnalysisContext.evictOld(q, now, windowMillis);

        int c = q.size();
        if (c >= cfg.highAt) return cfg.highScore;
        if (c >= cfg.mediumAt) return cfg.mediumScore;
        if (c >= cfg.lowAt) return cfg.lowScore;
        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        IpV4Packet ip = packet.get(IpV4Packet.class);
        String srcIp = (ip == null) ? "unknown" : ip.getHeader().getSrcAddr().getHostAddress();
        int count = ctx.icmpWindow(srcIp).size();
        outReasons.add("High ICMP Echo rate from " + srcIp + " (count=" + count + " in "
                + cfg.windowSeconds + "s, low/med/high=" + cfg.lowAt + "/" + cfg.mediumAt + "/" + cfg.highAt + ").");
    }
}
