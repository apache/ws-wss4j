/*
 * Created on Sep 22, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.apache.ws.axis.security.trust.secconv.interop;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Rucith, Muthulee
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class InteropUtil {
	
	public static byte[] generateSymmetricFromEntropy(String requesterNonce, String responderNonce) throws Exception {
			return P_hash(requesterNonce.getBytes(),responderNonce.getBytes(),16);
		}
	
		/**
		 * Stolen from WSUsernameToken  :-)
		 *
		 * @param secret
		 * @param seed
		 * @param mac
		 * @param required
		 * @return
		 * @throws java.lang.Exception
		 */
		private static byte[] P_hash(byte[] secret, byte[] seed, int required) throws Exception {
    	
			Mac mac = Mac.getInstance("HmacSHA1");
			byte[] out = new byte[required];
			int offset = 0, tocpy;
			byte[] A, tmp;
			A = seed;
			while (required > 0) {
				SecretKeySpec key = new SecretKeySpec(secret, "HMACSHA1");
				mac.init(key);
				mac.update(A);
				A = mac.doFinal();
				mac.reset();
				mac.init(key);
				mac.update(A);
				mac.update(seed);
				tmp = mac.doFinal();
				tocpy = min(required, tmp.length);
				System.arraycopy(tmp, 0, out, offset, tocpy);
				offset += tocpy;
				required -= tocpy;
			}
			return out;
		}
		
	private static int min(int a, int b) {
			return (a > b) ? b : a;
		}

}
