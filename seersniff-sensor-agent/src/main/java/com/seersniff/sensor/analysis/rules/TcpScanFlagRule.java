package com.seersniff.sensor.analysis.rules;

import com.seersniff.sensor.analysis.AnalysisContext;
import com.seersniff.sensor.analysis.RulesConfig;
import com.seersniff.sensor.analysis.SuspicionRule;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.List;

public class TcpScanFlagRule implements SuspicionRule {

    private final RulesConfig.TcpSynScan cfg;

    public TcpScanFlagRule() {
        this(RulesConfig.defaults());
    }

    public TcpScanFlagRule(RulesConfig config) {
        this.cfg = (config == null) ? RulesConfig.defaults().tcpSynScan : config.tcpSynScan;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp == null) return 0;

        TcpPacket.TcpHeader h = tcp.getHeader();

        boolean syn = h.getSyn();
        boolean ack = h.getAck();
        boolean fin = h.getFin();
        boolean rst = h.getRst();
        boolean psh = h.getPsh();
        boolean urg = h.getUrg();

        // SYN without ACK can be normal; keep moderate weight
        if (syn && !ack && !fin && !rst) return cfg.mediumScore;

        // NULL scan: no flags set
        if (!syn && !ack && !fin && !rst && !psh && !urg) return cfg.highScore;

        // FIN-only scan
        if (fin && !syn && !ack && !rst && !psh && !urg) return cfg.highScore;

        // Xmas scan: FIN+PSH+URG
        if (fin && psh && urg) return cfg.criticalScore;

        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp == null) return;

        TcpPacket.TcpHeader h = tcp.getHeader();

        boolean syn = h.getSyn();
        boolean ack = h.getAck();
        boolean fin = h.getFin();
        boolean rst = h.getRst();
        boolean psh = h.getPsh();
        boolean urg = h.getUrg();

        if (syn && !ack && !fin && !rst) {
            outReasons.add("TCP SYN without ACK (score=" + cfg.mediumScore + ").");
        } else if (!syn && !ack && !fin && !rst && !psh && !urg) {
            outReasons.add("TCP NULL flags pattern (score=" + cfg.highScore + ").");
        } else if (fin && !syn && !ack && !rst && !psh && !urg) {
            outReasons.add("TCP FIN-only pattern (score=" + cfg.highScore + ").");
        } else if (fin && psh && urg) {
            outReasons.add("TCP Xmas flags pattern (score=" + cfg.criticalScore + ").");
        }
    }
}
