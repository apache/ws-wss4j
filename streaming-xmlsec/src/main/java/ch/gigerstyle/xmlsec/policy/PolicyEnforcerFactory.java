package ch.gigerstyle.xmlsec.policy;

import ch.gigerstyle.xmlsec.policy.secpolicy.WSSPolicyException;

import javax.wsdl.Definition;
import javax.wsdl.WSDLException;
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLReader;
import java.net.URL;

/**
 * User: giger
 * Date: Sep 4, 2010
 * Time: 2:53:20 PM
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
public class PolicyEnforcerFactory {

    private Definition wsdlDefinition;

    private PolicyEnforcerFactory() {
    }

    public static PolicyEnforcerFactory newInstance(URL wsdlUrl) throws WSSPolicyException {
        PolicyEnforcerFactory policyEnforcerFactory = new PolicyEnforcerFactory();
        policyEnforcerFactory.parseWsdl(wsdlUrl);
        return policyEnforcerFactory;
    }

    private void parseWsdl(URL wsdlUrl) throws WSSPolicyException {
        try {
            WSDLFactory wsdlFactory = WSDLFactory.newInstance();
            WSDLReader reader = wsdlFactory.newWSDLReader();
            reader.setFeature("javax.wsdl.verbose", false);
            wsdlDefinition = reader.readWSDL(wsdlUrl.toString());
        } catch (WSDLException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        }
    }

    public PolicyEnforcer newPolicyEnforcer(String soapAction) throws WSSPolicyException {
        return new PolicyEnforcer(wsdlDefinition, soapAction);
    }
}
