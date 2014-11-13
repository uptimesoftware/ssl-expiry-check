package com.uptimesoftware.uptime.plugin;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import org.junit.Test;

import com.uptimesoftware.uptime.plugin.SSLCertificateExpiry.UptimeSSLCertificateExpiry;

public class SSLCertificateExpiryTest {

	// Input params from Up.time.
	private HashMap<String, Object> inputs = new HashMap<String, Object>();

	@Test
	public void sslCertificateExpiryTest() {
		inputs.put(UptimeSSLCertificateExpiry.HTTPS_URL, "https://google.com");
		UptimeSSLCertificateExpiry testInstance = new UptimeSSLCertificateExpiry();

		HttpsURLConnection conn = testInstance.createURLConnection(inputs);
		Map<TimeUnit, Long> map = null;

		try {
			assertEquals(200, conn.getResponseCode());

			map = testInstance.computeDiff(conn.getDate(), conn.getExpiration());

			assertNotNull(map);

		} catch (IOException e) {
			e.printStackTrace();
		}

		for (Entry<TimeUnit, Long> entry : map.entrySet()) {
			System.out.println(entry.getKey() + " : " + entry.getValue());
		}
	}
}
