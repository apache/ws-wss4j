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
package org.apache.ws.security.trust;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Properties;
import java.util.Random;
import java.util.TimeZone;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.axis.message.MessageElement;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.trust.message.token.BaseToken;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;


/**
 * @author Malinda Kaushalye
 *
 * STSUtil is the place where all the utility functions are stored.
 * These utility functions are being used in various modules.
 * 
 */
public class STSUtil {

	

	
	/**
	   * Returns an array of Message Elements for given array of elements 
	   * 
	   * @param elem
	   * @return
	   */
	  public static MessageElement[] generateMessgaeElemArray(Element[] elem){
		MessageElement[] meArr=new MessageElement[elem.length];
		for (int i=0;i<elem.length;i++){
			meArr[i]=new MessageElement(elem[i]);
		}
		return meArr;
	  }
	 
	  /**
	   * Returns a MessageElement for a given Element
	   * 
	   * @param elem 
	   * @return
	   */
	  public static MessageElement generateMessgaeElement(Element elem){
		MessageElement me=new MessageElement(elem);	
		return me;
	  }

	

	  /**
	   * Currently  support only for direct references
	   * @param doc
	   * @return
	   */
	  public static BinarySecurity findBinarySecurityToken(Document doc){
		try {
			BinarySecurity binarySecurity;
			//first find base token
			Element elemBase=(Element)WSSecurityUtil.findElement(doc,BaseToken.TOKEN.getLocalPart(),BaseToken.TOKEN.getNamespaceURI());
			Element elemBaseChild=(Element)elemBase.getFirstChild();
			//If the first child is null then return
			if((elemBaseChild==null)){
				return null;
			}
			//If the first child is a binary token
					
			if((elemBaseChild.getLocalName().equals("BinarySecurityToken"))   ){
				binarySecurity=new BinarySecurity(WSSConfig.getDefaultWSConfig(),elemBaseChild);
				return binarySecurity;
			}else if((elemBaseChild.getLocalName().equals(SecurityTokenReference.SECURITY_TOKEN_REFERENCE) )  ){
				return null;
			}else{
			    return null;
			}
		} catch (WSSecurityException e) {			
			e.printStackTrace();
		}		
		return null;
	  }
	
	 /**
	 * Currently we do support only for direct references
	 * @param doc
	 * @return
	 */
	public static UsernameToken findUsernameToken(Document doc){
	  try {
		UsernameToken unt;
		  //first find base token
		  Element elemBase=(Element)WSSecurityUtil.findElement(doc,BaseToken.TOKEN.getLocalPart(),BaseToken.TOKEN.getNamespaceURI());
		  Element elemBaseChild=(Element)elemBase.getFirstChild();
		  //If the first child is null then return
		  if((elemBaseChild==null)){
			  return null;
		  }
		 //If the first child is a UNT
					
		  if((elemBaseChild.getLocalName().equals("UsernameToken"))   ){
			  unt=new UsernameToken(WSSConfig.getDefaultWSConfig(),elemBaseChild);
			  return unt;
		  }else{
			  return null;
		  }
	  } catch (WSSecurityException e) {
			
		  e.printStackTrace();
	  }		
	  return null;
	}

/**
 * Replaces the Security Token Reference element with its Referenced element
 * Reason : In the Trust Comminicator no header elements are visible
 * @param doc start element of the search (Usually the wst:Base element)
 * @throws WSSecurityException
 */
	  public static void replaceSecurityTokenReferences(Document doc)throws WSSecurityException{
		//WSSecurityUtil.findElement(doc,SecurityTokenReference.TOKEN.getLocalPart(),SecurityTokenReference.TOKEN.getNamespaceURI());
		NodeList nList=doc.getElementsByTagName(SecurityTokenReference.SECURITY_TOKEN_REFERENCE);
		for(int i=0; i<nList.getLength();i++){
			SecurityTokenReference secTokRef=(SecurityTokenReference)nList.item(i);//SecTokRef
			Reference ref=secTokRef.getReference();
			String uri=ref.getURI();		
			//System.out.println("uri"+uri);
			Element elemFound=WSSecurityUtil.getElementByWsuId(WSSConfig.getDefaultWSConfig(),doc,uri);
			doc.replaceChild(secTokRef.getElement(),elemFound);			
		}			
			  	
	  }
	/**
	 * Load properties 
	 * @param propFilename
	 * @return
	 */
	public  static Properties getProperties(String propFilename) {
		Properties properties = new Properties();
		try {
			URL url = Loader.getResource(propFilename);
			properties.load(url.openStream());
			
		} catch (Exception e) {
			
		}
		return properties;
	}

}
