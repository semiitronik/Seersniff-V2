package com.seersniff.seersniff.api.metrics;

import com.seersniff.seersniff.api.model.MetricsSnapshot;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class MetricsPublisher {

    private final MetricsAggregator aggregator;
    private final SimpMessagingTemplate messaging;

    public MetricsPublisher(MetricsAggregator aggregator, SimpMessagingTemplate messaging) {
        this.aggregator = aggregator;
        this.messaging = messaging;
    }

    @Scheduled(fixedRate = 1000)
    public void publish() {
        for (MetricsSnapshot snapshot : aggregator.snapshots()) {
            messaging.convertAndSend("/topic/metrics", snapshot);
        }
    }
}
