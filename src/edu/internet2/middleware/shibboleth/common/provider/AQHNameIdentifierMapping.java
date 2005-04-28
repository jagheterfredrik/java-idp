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

package edu.internet2.middleware.shibboleth.common.provider;

import java.io.Serializable;

import org.apache.log4j.Logger;
import javax.xml.namespace.QName;
import org.opensaml.SAMLException;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;

/**
 * Base class for {@link NameIdentifierMapping}implementations that support Shibboleth Attribute Query Handles.
 * 
 * @author Walter Hoehn
 */
public abstract class AQHNameIdentifierMapping extends BaseNameIdentifierMapping {

	private static Logger log = Logger.getLogger(AQHNameIdentifierMapping.class.getName());
	/** Time in seconds for which handles are valid */
	protected long handleTTL = 1800;
	protected static QName[] errorCodes = {SAMLException.REQUESTER,
			new QName(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS, "InvalidHandle")};

	public AQHNameIdentifierMapping(Element config) throws NameIdentifierMappingException {

		super(config);

		String rawTTL = ((Element) config).getAttribute("handleTTL");
		try {
			if (rawTTL != null && !rawTTL.equals("")) {
				handleTTL = Long.parseLong(rawTTL);
				if (handleTTL < 30) {
					log.warn("You have set the Attribute Query Handle \"Time To Live\' to a very low "
							+ "value.  It is recommended that you increase it.");
				}
			}
			log.debug("Attribute Query Handle TTL set to (" + handleTTL + ") seconds.");

		} catch (NumberFormatException nfe) {
			log.error("Value for attribute \"handleTTL\" mus be a long integer.");
			throw new NameIdentifierMappingException("Could not load Name Identifier Mapping with configured data.");
		}
	}

	protected HandleEntry createHandleEntry(AuthNPrincipal principal) {

		return new HandleEntry(principal, handleTTL);
	}
}

class HandleEntry implements Serializable {

	static final long serialVersionUID = 1L;
	protected AuthNPrincipal principal;
	protected long expirationTime;

	/**
	 * Creates a HandleEntry
	 * 
	 * @param principal
	 *            the principal represented by this entry.
	 * @param TTL
	 *            the time, in seconds, for which the handle should be valid.
	 */
	protected HandleEntry(AuthNPrincipal principal, long TTL) {

		this.principal = principal;
		expirationTime = System.currentTimeMillis() + (TTL * 1000);
	}

	protected boolean isExpired() {

		return (System.currentTimeMillis() >= expirationTime);
	}
}
