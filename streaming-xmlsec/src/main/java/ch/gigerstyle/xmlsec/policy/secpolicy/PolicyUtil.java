package ch.gigerstyle.xmlsec.policy.secpolicy;

/**
 * User: giger
 * Date: Sep 5, 2010
 * Time: 9:45:37 PM
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
public class PolicyUtil {

    public static SPConstants getSPVersion(String namespace) {
        if (SP13Constants.SP_NS.equals(namespace)) {
            return SP13Constants.INSTANCE;
        } else if (SP12Constants.SP_NS.equals(namespace)) {
            return SP12Constants.INSTANCE;
        } else if (SP11Constants.SP_NS.equals(namespace)) {
            return SP11Constants.INSTANCE;
        }
        return null;
    }
}
