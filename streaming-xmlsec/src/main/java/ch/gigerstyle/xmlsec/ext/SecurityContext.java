package ch.gigerstyle.xmlsec.ext;

import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEventListener;

import java.util.List;

/**
 * User: giger
 * Date: May 15, 2010
 * Time: 11:54:26 AM
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
public interface SecurityContext {

    public <T> void put(String key, T value);

    public <T> T get(String key);

    public <T> void putAsList(Class key, T value);

    public <T> List<T> getAsList(Class key);

    public void registerSecurityTokenProvider(String id, SecurityTokenProvider securityTokenProvider);

    public SecurityTokenProvider getSecurityTokenProvider(String id);

    public void setSecurityEventListener(SecurityEventListener securityEventListener);

    public void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException;

    public void setIsInEncryptedContent();

    public void unsetIsInEncryptedContent();

    public boolean isInEncryptedContent();

    public void setIsInSignedContent();

    public void unsetIsInSignedContent();

    public boolean isInSignedContent();
}
