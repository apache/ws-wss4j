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

/**
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 */
public class ConvEngineResult {
    public static final int SECURITY_TOKEN_RESPONSE = 1;
    public static final int SIGN_DERIVED_KEY = 2;
    public static final int ENCRYPT_DERIVED_KEY = 3;
    public static final int TRUST_VERIFIED = 4;
    public static final int SCT = 5;

    private String uuid = null;
    byte[] keyAssociated = null;
    private int Action;

    public ConvEngineResult(int Act) {
        this.Action = Act;
    }

    /**
     * @return
     */
    public int getAction() {
        return Action;
    }

    /**
     * @return
     */
    public String getUuid() {
        return uuid;
    }

    /**
     * @param i
     */
    public void setAction(int i) {
        Action = i;
    }

    /**
     * @param string
     */
    public void setUuid(String string) {
        uuid = string;
    }

    /**
     * @return
     */
    public byte[] getKeyAssociated() {
        return keyAssociated;
    }

    /**
     * @param bs
     */
    public void setKeyAssociated(byte[] bs) {
        keyAssociated = bs;
    }

}
