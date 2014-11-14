package com.uptimesoftware.uptime.plugin;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ro.fortsoft.pf4j.PluginWrapper;
import com.uptimesoftware.uptime.plugin.api.Extension;
import com.uptimesoftware.uptime.plugin.api.Plugin;
import com.uptimesoftware.uptime.plugin.api.PluginMonitor;
import com.uptimesoftware.uptime.plugin.monitor.MonitorState;
import com.uptimesoftware.uptime.plugin.monitor.Parameters;
import com.uptimesoftware.uptime.plugin.monitor.PluginMonitorVariable;

/**
 * SSLExpiryCheck
 * 
 * @author uptime software
 */
public class SSLExpiryCheck extends Plugin {

	/**
	 * Constructor - a plugin wrapper.
	 * 
	 * @param wrapper
	 */
	public SSLExpiryCheck(PluginWrapper wrapper) {
		super(wrapper);
	}

	/**
	 * A nested static class which has to extend PluginMonitor.
	 * 
	 * Functions that require implementation :
	 * 1) The monitor function will implement the main functionality and should set the monitor's
	 * state and result message prior to completion.
	 * 2) The setParameters function will accept a Parameters object containing the values filled
	 * into the monitor's configuration page in Up.time.
	 */
	@Extension
	public static class UptimeSSLExpiryCheck extends PluginMonitor {
		// Logger object.
		private static final Logger logger = LoggerFactory.getLogger(UptimeSSLExpiryCheck.class);

		// Monitor message.
		private String monitorMessage = "";

		// Input params from Up.time.
		private HashMap<String, Object> inputs = new HashMap<String, Object>();

		// Input constants
		static final String HOSTNAME = "hostname";
		static final String HTTPS_URL = "httpsURL";

		// Output constants
		static final String EXPIRY_DATE = "expiryDate";
		static final String EXPIRY_REMAINING_DAYS = "expiryRemainingDays";
		static final String HTTP_RESPONSE = "httpResponse";
		static final String ISSUER_NAME = "issuerName";

		/**
		 * The setParameters function will accept a Parameters object containing the values filled
		 * into the monitor's configuration page in Up.time.
		 * 
		 * @param params
		 *            Parameters object which contains inputs.
		 */
		@Override
		public void setParameters(Parameters params) {
			logger.debug("Step 1 : Get inputs from Up.time and store them in HashMap.");
			// See definition in .xml file for plugin. Each plugin has different number of
			// input/output parameters.
			inputs.put(HOSTNAME, params.getString(HOSTNAME));
			inputs.put(HTTPS_URL, params.getString(HTTPS_URL));
		}

		/**
		 * The monitor function will implement the main functionality and should set the monitor's
		 * state and result message prior to completion.
		 */
		@Override
		public void monitor() {
			logger.debug("Connect to the given https URL.");
			HttpsURLConnection conn = createURLConnection(inputs);

			logger.debug("Check if the HTTPS URL connection is null or not.");
			if (conn == null) {
				setStateAndMessage(MonitorState.UNKNOWN, monitorMessage);
				return;
			}

			logger.debug("Get server certificates with a given HttpsURLConnection.");
			Certificate[] certs = getServerCertificates(conn);

			logger.debug("Check if the certs array is empty or not.");
			if (certs == null || certs.length == 0) {
				setStateAndMessage(MonitorState.UNKNOWN, monitorMessage);
				return;
			}

			try {
				addVariable(HTTP_RESPONSE, conn.getResponseCode());
			} catch (IOException e) {
				logger.error("IO error occurred.", e);
				return;
			}

			logger.debug("Add ranged type variables.");
			addRangedVariables(certs);

			setStateAndMessage(MonitorState.OK, "Monitor ran successfully.");
		}

		/**
		 * Create Https URL connection instance.
		 * 
		 * @param inputs
		 *            Input parameters from Up.Time.
		 * @return HttpsURLConnection instance.
		 */
		HttpsURLConnection createURLConnection(HashMap<String, Object> inputs) {
			HttpsURLConnection conn = null;
			try {
				conn = (HttpsURLConnection) (new URL((String) inputs.get(HTTPS_URL)))
						.openConnection();
				conn.connect();
			} catch (MalformedURLException e) {
				monitorMessage = "Wrong URL format is used.";
				logger.error(monitorMessage, e);
				return conn;
			} catch (IOException e) {
				monitorMessage = "IO error occurred.";
				logger.error(monitorMessage, e);
				return conn;
			}
			return conn;
		}

		/**
		 * Get server certificates with a given HttpsURLConnection instance.
		 * 
		 * @param conn
		 *            HttpsURLConnection instance.
		 * @return An array of server certificates.
		 */
		Certificate[] getServerCertificates(HttpsURLConnection conn) {
			Certificate[] certs = null;
			try {
				certs = conn.getServerCertificates();
				conn.disconnect();
			} catch (SSLPeerUnverifiedException e) {
				monitorMessage = "Failed to retrieve Server Certificates";
				logger.error(monitorMessage, e);
				return certs;
			}
			return certs;
		}

		/**
		 * Add Ranged type variables to Up.Time.
		 * 
		 * @param certs
		 *            An array of certificates.
		 */
		void addRangedVariables(Certificate[] certs) {
			Map<TimeUnit, Long> dateMap = null;

			for (Certificate cert : certs) {
				addVariable(EXPIRY_DATE, ((X509Certificate) cert).getNotAfter().toString());

				PluginMonitorVariable pmv = new PluginMonitorVariable();
				pmv.setName(EXPIRY_REMAINING_DAYS);
				// Issuer_name.expiry_remaining_days
				pmv.setObjectName(((X509Certificate) cert).getIssuerX500Principal().getName() + "."
						+ EXPIRY_REMAINING_DAYS);

				dateMap = computeDiff(new Date(), ((X509Certificate) cert).getNotAfter());

				pmv.setValue(dateMap.get(TimeUnit.DAYS).toString());
			}
		}

		/**
		 * Calculate time difference.
		 * 
		 * @param dateOne
		 *            current date in long.
		 * @param dateTwo
		 *            expiry date in long.
		 * @return Time difference of two dates in Map with TimeUnit and its value.
		 */
		Map<TimeUnit, Long> computeDiff(Date dateOne, Date dateTwo) {
			long diffInMillies = dateTwo.getTime() - dateOne.getTime();
			List<TimeUnit> units = new ArrayList<TimeUnit>(EnumSet.allOf(TimeUnit.class));
			Collections.reverse(units);

			Map<TimeUnit, Long> result = new LinkedHashMap<TimeUnit, Long>();
			long milliesRest = diffInMillies;
			for (TimeUnit unit : units) {
				long diff = unit.convert(milliesRest, TimeUnit.MILLISECONDS);
				long diffInMilliesForUnit = unit.toMillis(diff);
				milliesRest = milliesRest - diffInMilliesForUnit;
				result.put(unit, diff);
			}
			return result;
		}
	}
}