package ch.gigerstyle.xmlsec.policy;

/**
 * User: giger
 * Date: Sep 2, 2010
 * Time: 8:22:33 PM
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
public class PolicyViolationException extends Exception {
    public PolicyViolationException(String message) {
        super(message);
    }

    public PolicyViolationException(String message, Throwable cause) {
        super(message, cause);
    }

    public PolicyViolationException(Throwable cause) {
        super(cause);
    }
}
