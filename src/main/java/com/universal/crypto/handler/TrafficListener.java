package com.universal.crypto.handler;

public interface TrafficListener {
    void onTraffic(String method, String url, String status, String ruleInfo, HttpContextBase original, HttpContextBase modified);
}
