package org.apache.ws.security.conversation.dkAlgo;

import org.apache.ws.security.conversation.ConversationException;
/**
 * @author Ruchith Fernando
 * @version 1.0
 */

public class AlgoFactory {

  /**
   * This gives a DerivationAlgorithm instance from the default set of algorithms provided
   * @param algorithm The algo identifier @see DeivationAlgorithm
   * @return A derivatio algorithm
   * @throws ConversationException If the specified algorithmis not available in
   * default implementations
   */
  public static DerivationAlgorithm getInstance(String algorithm) throws
      ConversationException {
    if(algorithm.equals(DerivationAlgorithm.P_SHA_1)) {
       return new P_SHA1();
    } else {
      throw new ConversationException("No such algorithm");
      }
  }

/** @todo instanciate an algo from a algo class externally specified  */
//  public static DerivationAlgorithm getInstance(String algoClass, Properties properties) {
//
//  }
}