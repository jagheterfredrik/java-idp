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

package edu.internet2.middleware.shibboleth.common;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;

import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;

/**
 * @author Walter Hoehn
 */
public class Trust {

	private static Logger log = Logger.getLogger(Trust.class.getName());

	public boolean validate(RoleDescriptor descriptor, X509Certificate[] certificateChain, int keyUse) {

		if (descriptor == null || certificateChain == null || certificateChain.length < 1) {
			log.error("Appropriate data was not supplied for trust evaluation.");
			return false;
		}

		// Iterator through all the keys in the metadata
		Iterator keyDescriptors = descriptor.getKeyDescriptors();
		while (keyDescriptors.hasNext()) {
			// Look for a key descriptor with the right usage bits
			KeyDescriptor keyDescriptor = (KeyDescriptor) keyDescriptors.next();
			if (keyDescriptor.getUse() != KeyDescriptor.UNSPECIFIED && keyDescriptor.getUse() != keyUse) {
				log.debug("Role contains a key descriptor, but the usage specification is not valid for this action.");
				continue;
			}

			// We found one, attempt to do an exact match between the metadata certificate
			// and the supplied end-entity certificate
			KeyInfo keyInfo = keyDescriptor.getKeyInfo();
			if (keyInfo.containsX509Data()) {
				log.debug("Attempting to match X509 certificate.");
				try {
					X509Certificate metaCert = keyInfo.getX509Certificate();
					if (certificateChain != null && certificateChain.length > 0
							&& Arrays.equals(metaCert.getEncoded(), certificateChain[0].getEncoded())) {
						log.debug("Match successful.");
						return true;
					} else {
						log.debug("Certificate did not match.");
					}

				} catch (KeyResolverException e) {
					log.error("Error extracting X509 certificate from metadata.");
				} catch (CertificateEncodingException e) {
					log.error("Error while comparing X509 encoded data.");
				}
			}
		}
		return false;
	}
}
