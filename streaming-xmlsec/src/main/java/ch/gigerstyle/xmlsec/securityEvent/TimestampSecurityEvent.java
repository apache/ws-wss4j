package ch.gigerstyle.xmlsec.securityEvent;

import java.util.Calendar;

/**
 * User: giger
 * Date: Sep 5, 2010
 * Time: 6:06:28 PM
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
public class TimestampSecurityEvent extends SecurityEvent {

    private Calendar created;
    private Calendar expires;

    public TimestampSecurityEvent(Event securityEventType) {
        super(securityEventType);
    }

    public Calendar getCreated() {
        return created;
    }

    public void setCreated(Calendar created) {
        this.created = created;
    }

    public Calendar getExpires() {
        return expires;
    }

    public void setExpires(Calendar expires) {
        this.expires = expires;
    }
}
