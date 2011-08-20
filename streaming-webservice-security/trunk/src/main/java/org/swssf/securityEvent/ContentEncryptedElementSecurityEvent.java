/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.securityEvent;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class ContentEncryptedElementSecurityEvent extends SecurityEvent {

    //todo xpath or something unique
    private QName element; //this contents parent element
    private boolean notEncrypted; //if true this element is not encrypted.

    public ContentEncryptedElementSecurityEvent(Event securityEventType, boolean notEncrypted) {
        super(securityEventType);
        this.notEncrypted = notEncrypted;
    }

    public QName getElement() {
        return element;
    }

    public void setElement(QName element) {
        this.element = element;
    }

    public boolean isNotEncrypted() {
        return notEncrypted;
    }

    public void setNotEncrypted(boolean notEncrypted) {
        this.notEncrypted = notEncrypted;
    }
}
