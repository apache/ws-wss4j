/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.conversation;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;

/**
 * @author Ruchith
 * @version 1.0
 */

public class ConversationSession {

	private Log log = LogFactory.getLog(ConversationSession.class.getName());

  /**
   * The security context info of this session
   */
  private SecurityContextInfo contextInfo;

  /**
   * The set of derived keys used in the session
   * Here a Hashtable is used to list the derived keys by their id's
   * This will be useful when selecting the relevant derived key in the key derivator
   */
  private Hashtable derivedKeys;

  /**
   * In cases where fixed length derived keys are to be used this will be set
   * The value will be the number of bytes in the key
   */
  private long keyLength = -1;

  /**
   * This is the label used in key derivation
   * If the label element is missing in the DerivedKeyToken element then the value
   * of this element will be used in the derivation
   * This value will be set by the DerivedKeyCallbackHandler
   */
  private String label;

  /**
   * Last time the session was used/modified
   */
  private long lastTouched;

  /**
   * Creates a new conversation session for a gien security context
   * @param contextInfo The security context info
   */
  public ConversationSession(SecurityContextInfo contextInfo) {
  	log.debug("Conversation Session : created. Identifier :" + contextInfo.getIdentifier());
    this.contextInfo = contextInfo;
    this.derivedKeys = new Hashtable();
    touch();
  }

  /**
   * Returns the security context info of this session
   * @return the security context info of this session
   */
  public SecurityContextInfo getContextInfo() {
    return this.contextInfo;
  }

  /**
   * Returns the Hashtable of derived keys (<code>DerivedKeyInfo</code> obects) of
   * this session
   * @return A Hashtable of DerivedKeyInfo objects
   */
  public Hashtable getDerivedKeys() {
    return this.derivedKeys;
  }

  /**
   * This adds a derived key into the session
   * @param dkInfo The info object of the relevant derived key
   */
  public void addDerivedKey(DerivedKeyInfo dkInfo) {
    this.derivedKeys.put(dkInfo.getId(),dkInfo);
    touch();
  }

  /**
   * The label value to be used in the key derivation
   * @return
   */
  public String getLabel() {
    return this.label;
  }

  /**
   * Set the label value to be used in key derivation
   * @param label
   */
  public void setLabel(String label) {
    this.label = label;
    touch();
  }

  /**
   * Get the length of the derived keys to be generated when fixed length keys are generated
   * @return
   */
  public long getKeyLength() {
    return keyLength;
  }

  /**
   * Set the length of the derived key to be derived in this session
   * This is set in the case where fixed length keys are used
   * @param keyLength
   */
  public void setKeyLength(long keyLength) {
    this.keyLength = keyLength;
    touch();
  }

  /**
   * Touch the session
   */
  public void touch() {
    this.lastTouched = System.currentTimeMillis();
  }

  /**
   * Returns the last time the session was used/modified
   * @return Last touched time in milliseconds
   */
  public long getLastTouched() {
    return this.lastTouched;
  }

}