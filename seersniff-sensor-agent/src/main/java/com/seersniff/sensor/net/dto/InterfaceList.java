package com.seersniff.sensor.net.dto;

import java.util.List;

public record InterfaceList(
        String sensorId,
        long ts,
        List<InterfaceInfo> interfaces
) {}