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

package org.apache.ws.security;

/**
 * WSDataRef stores information about decrypted/signed elements
 * 
 * When a processor decrypts an elements it stores information 
 * about that element in a WSDataRef so these information can 
 * be used for validation stages 
 * 
 */

import javax.xml.namespace.QName;

public class WSDataRef {
    
    /**
     * reference by which the Encrypted Data was referred 
     */
    private String dataref;
    
    /**
     * wsu:Id of the decrypted element (if present)
     */
    private String wsuId;
    
    /**
     * QName of the decrypted element
     */
    private QName name;
    
    
    /**
     * @param dataref reference by which the Encrypted Data was referred 
     */
    public WSDataRef(String dataref) {
        this.dataref = dataref;
    }
    
    /**
     * @param dataref reference by which the Encrypted Data was referred 
     * @param wsuId Id of the decrypted element (if present)
     */
    public WSDataRef(String dataref, String wsuId) {
        this.dataref = dataref;
        this.wsuId = wsuId;
    }
    
    /**
     * @param dataref reference by which the Encrypted Data was referred 
     * @param wsuId Id of the decrypted element (if present)
     * @param name QName of the decrypted element
     */
    public WSDataRef(String dataref, String wsuId, QName name) {
        this.dataref = dataref;
        this.wsuId = wsuId;
        this.name = name;
    }

    /**
     * @return the data reference 
     */
    public String getDataref() {
        return dataref;
    }

    /**
     * @param dataref reference by which the Encrypted Data was referred 
     */
    public void setDataref(String dataref) {
        this.dataref = dataref;
    }

    /**
     * @return Id of the decrypted element (if present)
     */
    public String getWsuId() {
        return wsuId;
    }

    /**
     * @param wsuId Id of the decrypted element (if present)
     */
    public void setWsuId(String wsuId) {
        this.wsuId = wsuId;
    }

    /**
     * @return QName of the decrypted element
     */
    public QName getName() {
        return name;
    }

    /**
     * @param name QName of the decrypted element
     */
    public void setName(QName name) {
        this.name = name;
    }

}
