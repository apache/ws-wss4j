package ch.gigerstyle.xmlsec.securityEvent;

import javax.xml.namespace.QName;

/**
 * User: giger
 * Date: Sep 14, 2010
 * Time: 4:52:40 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SignedElementSecurityEvent extends SecurityEvent {

    //todo xpath or something unique
    //todo message signature or supporting sig
    private QName element;

    public SignedElementSecurityEvent(Event securityEventType) {
        super(securityEventType);
    }

    public QName getElement() {
        return element;
    }

    public void setElement(QName element) {
        this.element = element;
    }
}
