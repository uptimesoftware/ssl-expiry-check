package com.uptimesoftware.uptime.plugin;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import org.junit.Test;

import com.uptimesoftware.uptime.plugin.SSLExpiryCheck.UptimeSSLExpiryCheck;

public class SSLExpiryCheckTest {

	// Input params from Up.time.
	private HashMap<String, Object> inputs = new HashMap<String, Object>();

	@Test
	public void sslCertificateExpiryTest() throws IOException, CertificateNotYetValidException,
			CertificateExpiredException {
		inputs.put(UptimeSSLExpiryCheck.HTTPS_URL, "https://www.youtube.com/watch?v=z5YWHDxyRL4");
		UptimeSSLExpiryCheck testInstance = new UptimeSSLExpiryCheck();

		HttpsURLConnection conn = testInstance.createURLConnection(inputs);

		assertEquals(200, conn.getResponseCode());

		Certificate[] certs = conn.getServerCertificates();
		Map<TimeUnit, Long> dateMap = null;
		for (Certificate cert : certs) {
			System.out
					.println(((X509Certificate) cert).getIssuerX500Principal().getName("RFC1779"));
			System.out.println(((X509Certificate) cert).getNotBefore());
			System.out.println(((X509Certificate) cert).getNotAfter());
			dateMap = testInstance.computeDiff(new Date(), ((X509Certificate) cert).getNotAfter());
			System.out.println(dateMap.get(TimeUnit.DAYS).toString());
		}
	}
}
