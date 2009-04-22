/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security;

/**
 * WSDataRef stores information about decrypted/signed elements
 * 
 * When a processor decrypts/verifies an element it stores information 
 * about that element in a WSDataRef so this information can 
 * be used for validation 
 * 
 */
import javax.xml.namespace.QName;

public class WSDataRef {
    
    /**
     * wsu:Id of the protected element
     */
    private String wsuId;
    
    /**
     * QName of the protected element
     */
    private QName name;
    
    /**
     * @deprecated 
     * This method is left in the class for backwards compatibility.
     * It returns the wsu:Id of the protected element, and not the data reference.
     * This was never implemented properly in WSS4J code anyway 
     * @return the wsu:Id
     */
    public String getDataref() {
        return wsuId;
    }

    /**
     * @return Id of the protected element
     */
    public String getWsuId() {
        return wsuId;
    }

    /**
     * @param wsuId Id of the protected element
     */
    public void setWsuId(String wsuId) {
        this.wsuId = wsuId;
    }

    /**
     * @return QName of the protected element
     */
    public QName getName() {
        return name;
    }

    /**
     * @param name QName of the protected element
     */
    public void setName(QName name) {
        this.name = name;
    }

}
