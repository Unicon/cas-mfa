package com.duosecurity;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Util {
	public static String hmacSign(final String skey, final String data)
			throws NoSuchAlgorithmException, InvalidKeyException {
		final SecretKeySpec key = new SecretKeySpec(skey.getBytes(), "HmacSHA1");
		final Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(key);
		final byte[] raw = mac.doFinal(data.getBytes());
		return bytesToHex(raw);
	}

	public static String bytesToHex(final byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}
}
