package org.apache.ws.security.conversation.dkAlgo;

/**
 * <p>Title: </p>
 * <p>Description: </p>
 * <p>Copyright: Copyright (c) 2004</p>
 * <p>Company: </p>
 * @author not attributable
 * @version 1.0
 */
import org.apache.ws.security.conversation.ConversationException;

public interface DerivationAlgorithm {

  /**
   * This is the default key generation algotithm
   */
  public static final String P_SHA_1 = "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk/p_sha1";

  /**
   *
   * @param secret
   * @param labelAndSeed
   * @param length
   * @return
   */
  public byte[] createKey(byte[] secret, String labelAndNonce, int offset, long length)throws ConversationException;

}