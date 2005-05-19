/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.idp;

import javax.servlet.ServletContext;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Constructs a DOM tree for the IdP configuration XML file.
 * 
 * @author Walter Hoehn
 * @author Noah Levitt
 */
public class IdPConfigLoader {

	private static Logger log = Logger.getLogger(IdPConfigLoader.class);
	private static Document idpConfig = null;
	private static String idpConfigFile = null;

	/**
	 * Returnes the location of the configuration file.
	 * 
	 * @param context
	 *            the context of the IdP servlet
	 * @return the location of the configuration file
	 */
	private static String getIdPConfigFile(ServletContext context) {

		if (context.getInitParameter("IdPConfigFile") != null) {
			return context.getInitParameter("IdPConfigFile");
		} else {
			return "/conf/idp.xml";
		}
	}

	/**
	 * Loads the IdP Configuration file into a DOM tree.
	 * 
	 * @param configFileLocation
	 *            URL of the configuration file
	 * @return the DOM Document
	 * @throws ShibbolethConfigurationException
	 *             if there was an error loading the file
	 */
	public static synchronized Document getIdPConfig(String configFileLocation) throws ShibbolethConfigurationException {

		if (log.isDebugEnabled()) {
			log.debug("Getting IdP configuration file: " + configFileLocation);
		}

		if (configFileLocation.equals(idpConfigFile)) {
			return idpConfig;

		} else if (idpConfigFile == null) {
			idpConfigFile = configFileLocation;

		} else {
			log.error("Previously read IdP configuration from (" + idpConfigFile + "), re-reading from ("
					+ configFileLocation + "). This probably indicates a bug in shibboleth.");
			idpConfigFile = configFileLocation;
		}

		try {
			idpConfig = Parser.loadDom(configFileLocation, true);
			if (log.isDebugEnabled()) {
				log.debug("IdP configuration file " + configFileLocation + " successfully read and cached.");
			}
		} catch (Exception e) {
			log.error("Encountered an error while parsing Shibboleth Identity Provider configuration file: " + e);
			throw new ShibbolethConfigurationException("Unable to parse IdP configuration file.");
		}
		return idpConfig;
	}

	/**
	 * Loads the IdP Configuration file into a DOM tree.
	 * 
	 * @param context
	 *            {@link ServletContext}from which to figure out the location of IdP
	 * @return the DOM Document
	 * @throws ShibbolethConfigurationException
	 *             if there was an error loading the file
	 */
	public static Document getIdPConfig(ServletContext context) throws ShibbolethConfigurationException {

		return getIdPConfig(getIdPConfigFile(context));

	}
}