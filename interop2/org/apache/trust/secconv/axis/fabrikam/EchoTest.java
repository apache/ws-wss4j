/*
 * Created on Oct 11, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.apache.trust.secconv.axis.fabrikam;

import javax.xml.rpc.holders.StringHolder;

import org.apache.axis.utils.Options;
import org.apache.trust.secconv.axis.fabrikam.examples.EchoPort;
import org.apache.trust.secconv.axis.fabrikam.examples.EchoServiceLocator;

/**
 * @author Dimuthu Leelarathne.
 *
 */
public class EchoTest {
	
	
	/** Field address */
	private static final java.lang.String address =
			"http://localhost:9080/axis/services/EchoInterop";

	/**
	 * Method main
	 * 
	 * @param args 
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {

		Options opts = new Options(args);
		opts.setDefaultURL(address);

		/*
		 *     Start to prepare service call. Once this is done, several
		 *     calls can be made on the port (see below)
		 *
		 *     Fist: get the service locator. This implements the functionality
		 *     to get a client stub (aka port).
		 */
		EchoServiceLocator service = new EchoServiceLocator();

		/*
		 *     this is a JAX-RPC compliant call. It uses a preconfigured
		 *     endpoint address (usually contained in the WSDL). Note the
		 *     cast.
		 *    
		 * SecPort port = (SwaPort)service.getPort(SwaPortType.class);
		 */

		/*
		 *     Here we use an Axis specific call that allows to override the
		 *     port address (service endpoint address) with an own URL. Comes
		 *     in handy for testing.
		 */
		java.net.URL endpoint;

		try {
			endpoint = new java.net.URL(opts.getURL());
		} catch (java.net.MalformedURLException e) {
			throw new javax.xml.rpc.ServiceException(e);
		}

		EchoPort port = (EchoPort) service.getEchoInterop(endpoint);

		/*
		 *     At this point all preparations are done. Using the port we can
		 *     now perform as many calls as necessary.
		 */

		// perform call
		
		String success = new String("Lanka Software Foundation");
		
		StringHolder hold = new StringHolder(success);
		
		for (int i = 0; i < 3; i++) {
			port.echoMyData(hold);		
				
		}

	}

}
