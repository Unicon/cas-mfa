package com.duosecurity;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public final class DuoWeb {
	private static final String DUO_PREFIX = "TX";
	private static final String APP_PREFIX = "APP";
	private static final String AUTH_PREFIX = "AUTH";

	private static final int DUO_EXPIRE = 300;
	private static final int APP_EXPIRE = 3600;

	private static final int IKEY_LEN = 20;
	private static final int SKEY_LEN = 40;
	private static final int AKEY_LEN = 40;

	public static final String ERR_USER = "ERR|The username passed to sign_request() is invalid.";
	public static final String ERR_IKEY = "ERR|The Duo integration key passed to sign_request() is invalid.";
	public static final String ERR_SKEY = "ERR|The Duo secret key passed to sign_request() is invalid.";
	public static final String ERR_AKEY = "ERR|The application secret key passed to sign_request() must be at least " + AKEY_LEN + " characters.";
	public static final String ERR_UNKNOWN = "ERR|An unknown error has occurred.";

	public static String signRequest(final String ikey, final String skey, final String akey, final String username) {
		final String duoSig;
		final String appSig;

		if (username.equals("")) {
			return ERR_USER;
		}
		if (username.indexOf('|') != -1) {
			return ERR_USER;
		}
		if (ikey.equals("") || ikey.length() != IKEY_LEN) {
			return ERR_IKEY;
		}
		if (skey.equals("") || skey.length() != SKEY_LEN) {
			return ERR_SKEY;
		}
		if (akey.equals("") || akey.length() < AKEY_LEN) {
			return ERR_AKEY;
		}

		try {
			duoSig = signVals(skey, username, ikey, DUO_PREFIX, DUO_EXPIRE);
			appSig = signVals(akey, username, ikey, APP_PREFIX, APP_EXPIRE);
		} catch (final Exception e) {
			return ERR_UNKNOWN;
		}

		return duoSig + ":" + appSig;
	}

	public static String verifyResponse(final String ikey, final String skey, final String akey, final String sigResponse)
		throws DuoWebException, NoSuchAlgorithmException, InvalidKeyException, IOException {
		String authUser;
		String appUser;

		final String[] sigs = sigResponse.split(":");
		final String authSig = sigs[0];
		final String appSig = sigs[1];

		authUser = parseVals(skey, authSig, AUTH_PREFIX, ikey);
		appUser = parseVals(akey, appSig, APP_PREFIX, ikey);

		if (!authUser.equals(appUser)) {
			throw new DuoWebException("Authentication failed.");
		}

		return authUser;
	}

	private static String signVals(final String key, final String username, final String ikey, final String prefix, final int expire)
		throws InvalidKeyException, NoSuchAlgorithmException {
		final long ts = System.currentTimeMillis() / 1000;
		final long expireTs = ts + expire;
		final String exp = Long.toString(expireTs);

		final String val = username + "|" + ikey + "|" + exp;
		final String cookie = prefix + "|" + Base64.encodeBytes(val.getBytes());
		final String sig = Util.hmacSign(key, cookie);

		return cookie + "|" + sig;
	}

	private static String parseVals(final String key, final String val, final String prefix, final String ikey)
		throws InvalidKeyException, NoSuchAlgorithmException, IOException, DuoWebException {
		final long ts = System.currentTimeMillis() / 1000;

		final String[] parts = val.split("\\|");
		if (parts.length != 3) {
			throw new DuoWebException("Invalid response");
		}

		final String uPrefix = parts[0];
		final String uB64 = parts[1];
		final String uSig = parts[2];

		final String sig = Util.hmacSign(key, uPrefix + "|" + uB64);
		if (!Util.hmacSign(key, sig).equals(Util.hmacSign(key, uSig))) {
			throw new DuoWebException("Invalid response");
		}

		if (!uPrefix.equals(prefix)) {
			throw new DuoWebException("Invalid response");
		}

		final byte[] decoded = Base64.decode(uB64);
		final String cookie = new String(decoded);

		final String[] cookieParts = cookie.split("\\|");
		if (cookieParts.length != 3) {
			throw new DuoWebException("Invalid response");
		}
		final String username = cookieParts[0];
		final String uIkey = cookieParts[1];
		final String expire = cookieParts[2];

		if (!uIkey.equals(ikey)) {
			throw new DuoWebException("Invalid response");
		}

		final long expireTs = Long.parseLong(expire);
		if (ts >= expireTs) {
			throw new DuoWebException("Transaction has expired. Please check that the system time is correct.");
		}

		return username;
	}
}
