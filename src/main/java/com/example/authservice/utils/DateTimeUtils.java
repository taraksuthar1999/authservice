package com.example.authservice.utils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;

public class DateTimeUtils {
    public static ZonedDateTime getUTCDateTime(LocalDateTime localDateTime) {
        if(localDateTime == null) {
            throw new IllegalArgumentException("UTC DateTime cannot be null");
        }
        return localDateTime.atZone(ZoneId.systemDefault()).withZoneSameInstant(ZoneId.of("UTC"));
    }
}
