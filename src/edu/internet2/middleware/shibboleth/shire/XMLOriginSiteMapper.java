/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.shire;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.common.OriginSiteMapper;
import edu.internet2.middleware.shibboleth.common.OriginSiteMapperException;
import edu.internet2.middleware.shibboleth.common.XML;

/**
 *  OriginSiteMapper implementation using an XML file to populate an in-memory
 *  database from an optionally-signed XML file
 *
 * @author     Scott Cantor
 * @created    June 8, 2002
 */
public class XMLOriginSiteMapper implements OriginSiteMapper {

	private HashMap originSites = null;
	private HashMap hsKeys = null;
	private KeyStore ks = null;
	private static Logger log = Logger.getLogger(XMLOriginSiteMapper.class.getName());

	/**
	 *  Constructor for the XMLOriginSiteMapper object
	 *
	 * @param  registryURI               Tells where to find/download origin
	 *      site registry file
	 * @param  verifyKey                 Optional key to verify signature with
	 * @param  ks                        Key store containing the trusted roots
	 *      to be used by SHIRE
	 * @exception  Exception             Raised if the registry file cannot be
	 *      parsed and loaded
	 */

	public XMLOriginSiteMapper(String registryURI, Key verifyKey, KeyStore ks)
		throws OriginSiteMapperException {
		this.ks = ks;
		originSites = new HashMap();
		hsKeys = new HashMap();

		try {
			Document doc=org.opensaml.XML.parserPool.parse(registryURI);
			log.info("Located site file (" +registryURI +").");
			Element e = doc.getDocumentElement();
			if (!XML.SHIB_NS.equals(e.getNamespaceURI()) || !"Sites".equals(e.getLocalName())) {
				log.error("Construction requires a valid site file: (shib:Sites as root element)");
				throw new OriginSiteMapperException("Construction requires a valid site file: (shib:Sites as root element)");
			}

			// Loop over the OriginSite elements.
			NodeList nlist = e.getElementsByTagNameNS(XML.SHIB_NS, "OriginSite");
			for (int i = 0; nlist != null && i < nlist.getLength(); i++) {
				String os_name = ((Element) nlist.item(i)).getAttributeNS(null, "Name").trim();
				if (os_name.length() == 0)
					continue;

				OriginSite os_obj = new OriginSite(os_name);
				originSites.put(os_name, os_obj);

				Node os_child = nlist.item(i).getFirstChild();
				while (os_child != null) {
					if (os_child.getNodeType() != Node.ELEMENT_NODE) {
						os_child = os_child.getNextSibling();
						continue;
					}

					// Process the various kinds of OriginSite children that we care about...
					if (XML.SHIB_NS.equals(os_child.getNamespaceURI())
						&& "HandleService".equals(os_child.getLocalName())) {
						String hs_name = ((Element) os_child).getAttributeNS(null, "Name").trim();
						if (hs_name.length() > 0) {
							os_obj.handleServices.add(hs_name);

							// Check for KeyInfo.
							Node ki = os_child.getFirstChild();
							while (ki != null && ki.getNodeType() != Node.ELEMENT_NODE)
								ki = ki.getNextSibling();
							if (ki != null
								&& org.opensaml.XML.XMLSIG_NS.equals(ki.getNamespaceURI())
								&& "KeyInfo".equals(ki.getLocalName())) {
								try {
									KeyInfo kinfo = new KeyInfo((Element) ki, null);
									PublicKey pubkey = kinfo.getPublicKey();
									if (pubkey != null)
										hsKeys.put(hs_name, pubkey);
								} catch (XMLSecurityException exc) {
								}
							}
						}
					} else if (
						XML.SHIB_NS.equals(os_child.getNamespaceURI())
							&& "Domain".equals(os_child.getLocalName())) {
						String dom = os_child.getFirstChild().getNodeValue().trim();
						if (dom.length() > 0)
							os_obj.domains.add(dom);
					}
					os_child = os_child.getNextSibling();
				}
			}

			if (verifyKey != null) {
				log.info("Initialized with a key: attempting to verify document signature.");
				validateSignature(verifyKey, e);
			} else {
				log.info("Initialized without key: skipping signature verification.");
			}

		} catch (SAXException e) {
			log.error("Problem parsing site configuration" + e);
			throw new OriginSiteMapperException("Problem parsing site configuration" + e);
		} catch (IOException e) {
			log.error("Problem accessing site configuration" + e);
			throw new OriginSiteMapperException("Problem accessing site configuration" + e);
		} catch (org.opensaml.SAMLException e) {
                        log.error("Problem configuring parser: " + e);
                        throw new OriginSiteMapperException("Problem configuring parser: " + e);
                }
	}

	private void validateSignature(Key verifyKey, Element e) throws OriginSiteMapperException {

		Node n = e.getLastChild();
		while (n != null && n.getNodeType() != Node.ELEMENT_NODE)
			n = n.getPreviousSibling();

		if (n != null
			&& org.opensaml.XML.XMLSIG_NS.equals(n.getNamespaceURI())
			&& "Signature".equals(n.getLocalName())) {
				log.info("Located signature in document... verifying.");
			try {
				XMLSignature sig = new XMLSignature((Element) n, null);
				if (sig.checkSignatureValue(verifyKey)) {
					// Now we verify that what is signed is what we expect.
					SignedInfo sinfo = sig.getSignedInfo();
					if (sinfo.getLength() == 1
						&& (sinfo
							.getCanonicalizationMethodURI()
							.equals(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS)
							|| sinfo.getCanonicalizationMethodURI().equals(
								Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS))) {
						Reference ref = sinfo.item(0);
						if (ref.getURI() == null || ref.getURI().equals("")) {
							Transforms trans = ref.getTransforms();
							if (trans.getLength() == 1
								&& trans.item(0).getURI().equals(Transforms.TRANSFORM_ENVELOPED_SIGNATURE))
								log.info("Signature verification successful.");
								return;
						}
						log.error(
							"Unable to verify signature on registry file: Unsupported dsig reference or transform data submitted with signature.");
						throw new OriginSiteMapperException("Unable to verify signature on registry file: Unsupported dsig reference or transform data submitted with signature.");
					} else {
						log.error(
							"Unable to verify signature on registry file: Unsupported canonicalization method.");
						throw new OriginSiteMapperException("Unable to verify signature on registry file: Unsupported canonicalization method.");
					}
				} else {
					log.error(
						"Unable to verify signature on registry file: signature cannot be verified with the specified key.");
					throw new OriginSiteMapperException("Unable to verify signature on registry file: signature cannot be verified with the specified key.");
				}
			} catch (Exception sigE) {
				log.error(
					"Unable to verify signature on registry file: An error occured while attempting to verify the signature:"
						+ sigE);
				throw new OriginSiteMapperException(
					"Unable to verify signature on registry file: An error occured while attempting to verify the signature:"
						+ sigE);
			}
		} else {
			log.error("Unable to verify signature on registry file: no signature found in document.");
			throw new OriginSiteMapperException("Unable to verify signature on registry file: no signature found in document.");
		}

	}

	/**
	 *  Provides an iterator over the trusted Handle Services for the specified
	 *  origin site
	 *
	 * @param  originSite  The DNS name of the origin site to query
	 * @return             An iterator over the Handle Service DNS names
	 */
	public Iterator getHandleServiceNames(String originSite) {
		OriginSite o = (OriginSite) originSites.get(originSite);
		if (o != null)
			return o.handleServices.iterator();
		return null;
	}

	/**
	 *  Returns a preconfigured key to use in verifying a signature created by
	 *  the specified HS<P>
	 *
	 *  Any key returned is implicitly trusted and a certificate signed by
	 *  another trusted entity is not sought or required
	 *
	 * @param  handleService  Description of Parameter
	 * @return                A trusted key (probably public but could be
	 *      secret) or null
	 */
	public Key getHandleServiceKey(String handleService) {
		return (Key) hsKeys.get(handleService);
	}

	/**
	 *  Provides an iterator over the security domain expressions for which the
	 *  specified origin site is considered to be authoritative
	 *
	 * @param  originSite  The DNS name of the origin site to query
	 * @return             An iterator over a set of regular expression strings
	 */
	public Iterator getSecurityDomains(String originSite) {
		OriginSite o = (OriginSite) originSites.get(originSite);
		if (o != null)
			return o.domains.iterator();
		return null;
	}

	/**
	 *  Gets a key store containing certificate entries that are trusted to sign
	 *  Handle Service certificates that are encountered during processing<P>
	 *
	 *
	 *
	 * @return    A key store containing trusted certificate issuers
	 */
	public KeyStore getTrustedRoots() {
		return ks;
	}

	private class OriginSite {

		private Vector domains = null;
		private Vector handleServices = null;

		private OriginSite(String name) {
			domains = new Vector();
			domains.add(name);
			handleServices = new Vector();
		}
	}
}
