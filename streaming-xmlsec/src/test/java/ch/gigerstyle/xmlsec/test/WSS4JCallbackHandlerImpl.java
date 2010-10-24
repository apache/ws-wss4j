package ch.gigerstyle.xmlsec.test;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
* User: giger
* Date: Oct 22, 2010
* Time: 10:07:25 PM
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
public class WSS4JCallbackHandlerImpl implements CallbackHandler {
   public void handle(javax.security.auth.callback.Callback[] callbacks) throws IOException, UnsupportedCallbackException {
       org.apache.ws.security.WSPasswordCallback pc = (org.apache.ws.security.WSPasswordCallback) callbacks[0];

       if (pc.getUsage() == org.apache.ws.security.WSPasswordCallback.DECRYPT || pc.getUsage() == org.apache.ws.security.WSPasswordCallback.SIGNATURE) {
           pc.setPassword("refApp9876");
       } else {
           throw new UnsupportedCallbackException(pc, "Unrecognized CallbackHandlerImpl");
       }
   }
}
