/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution, if any, must include the
 * following acknowledgment: "This product includes software developed by the University Corporation for Advanced
 * Internet Development <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement may appear in the
 * software itself, if and wherever such third-party acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor the University Corporation for
 * Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote products derived from this software
 * without specific prior written permission. For written permission, please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the University Corporation
 * for Advanced Internet Development, nor may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author Walter Hoehn
 *  
 */
public class Credentials {

	public static final String credentialsNamespace = "urn:mace:shibboleth:credentials";

	private static Logger log = Logger.getLogger(Credentials.class.getName());
	private Hashtable data = new Hashtable();

	public Credentials(Element e) {

		//TODO talk to Scott about the possibility of changing "resolver" to "loader", to avoid confusion with the AR

		if (!e.getTagName().equals("Credentials")) {
			throw new IllegalArgumentException();
		}

		NodeList resolverNodes = e.getChildNodes();
		if (resolverNodes.getLength() <= 0) {
			log.error("Credentials configuration inclues no Credential Resolver definitions.");
			throw new IllegalArgumentException("Cannot load credentials.");
		}

		for (int i = 0; resolverNodes.getLength() > i; i++) {
			if (resolverNodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
				try {

					String credentialId = ((Element) resolverNodes.item(i)).getAttribute("id");
					if (credentialId == null || credentialId.equals("")) {
						log.error("Found credential that was not labeled with a unique \"id\" attribute. Skipping.");
					}

					if (data.containsKey(credentialId)) {
						log.error("Duplicate credential id (" + credentialId + ") found. Skipping");
					}

					log.info("Found credential (" + credentialId + "). Loading...");
					data.put(credentialId, CredentialFactory.loadCredential((Element) resolverNodes.item(i)));

				} catch (CredentialFactoryException cfe) {
					log.error("Could not load credential, skipping: " + cfe.getMessage());
				} catch (ClassCastException cce) {
					log.error("Problem realizing credential configuration" + cce.getMessage());
				}
			}
		}
	}

	public boolean containsCredential(String identifier) {
		return data.containsKey(identifier);
	}

	public Credential getCredential(String identifier) {
		return (Credential) data.get(identifier);
	}

	static class CredentialFactory {

		private static Logger log = Logger.getLogger(CredentialFactory.class.getName());

		public static Credential loadCredential(Element e) throws CredentialFactoryException {
			if (e.getTagName().equals("KeyInfo")) {
				return new KeyInfoCredentialResolver().loadCredential(e);
			}

			if (e.getTagName().equals("FileCredResolver")) {
				return new FileCredentialResolver().loadCredential(e);
			}

			if (e.getTagName().equals("KeyStoreResolver")) {
				return new KeystoreCredentialResolver().loadCredential(e);
			}

			if (e.getTagName().equals("CustomCredResolver")) {
				return new CustomCredentialResolver().loadCredential(e);
			}

			log.error("Unrecognized Credential Resolver type: " + e.getTagName());
			throw new CredentialFactoryException("Failed to load credential.");
		}

	}

}

class KeyInfoCredentialResolver implements CredentialResolver {
	private static Logger log = Logger.getLogger(KeyInfoCredentialResolver.class.getName());
	KeyInfoCredentialResolver() throws CredentialFactoryException {
		log.error("Credential Resolver (KeyInfoCredentialResolver) not implemented");
		throw new CredentialFactoryException("Failed to load credential.");
	}

	public Credential loadCredential(Element e) {
		return null;
	}
}

class FileCredentialResolver implements CredentialResolver {
	private static Logger log = Logger.getLogger(FileCredentialResolver.class.getName());

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getTagName().equals("FileCredResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <FileCredResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String id = e.getAttribute("id");
		if (id == null || id.equals("")) {
			log.error("Credential Resolvers require specification of the attribute \"id\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String certFormat = getCertFormat(e);
		String certPath = getCertPath(e);
		String keyFormat = "DER";
		String keyPath = "/conf/test.pemkey";
		log.debug("Certificate Format: (" + certFormat + ").");
		log.debug("Certificate Path: (" + certPath + ").");
		
		//TODO provider optional
		//TODO other kinds of certs?
		try {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		Collection chain = certFactory.generateCertificates(new ShibResource(certPath, this.getClass()).getInputStream());
		if (chain.isEmpty()) {
			log.error("File did not contain any valid certificates.");
			throw new CredentialFactoryException("File did not contain any valid certificates.");
		}
		Iterator iterator = chain.iterator();
		while (iterator.hasNext()) {
			System.err.println(((X509Certificate)iterator.next()).getSubjectDN());
		}
		//TODO remove this
		}catch (Exception p) {
			System.err.println(p);
			p.printStackTrace();
		}
		
		try {
			
			//TODO provider??
			//TODO other algorithms
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					InputStream keyStream = new ShibResource(certPath, this.getClass()).getInputStream();
					byte[] inputBuffer = new byte[8];
					int i;
					ByteContainer inputBytes = new ByteContainer(400);
					do {
						i = keyStream.read(inputBuffer);
						for (int j = 0; j < i; j++) {
							inputBytes.append(inputBuffer[j]);
						}
					} while (i > -1);

//TODO other encodings?
					PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(inputBytes.toByteArray());
					PrivateKey key = keyFactory.generatePrivate(keySpec);

				} catch (Exception p) {
					log.error("Problem reading private key: " + p.getMessage());
					//throw new ExtKeyToolException("Problem reading private key.  Keys should be DER encoded pkcs8 or DER encoded native format.");
				}
		

		return new Credential(null, null);
	}
	
	private String getCertFormat(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			log.error("Certificate not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate> specification.");
		}
		if (certificateElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}
		
		String format = ((Element)certificateElements.item(0)).getAttribute("id");
		if (format == null || format.equals("")) {
			log.debug("No format specified for certificate, using default (PEM) format.");
			format = "PEM";
		}
		
		if ((!format.equals("PEM")) && (!format.equals("DER"))) {
			log.error("File credential resolver only supports the (DER) and (PEM) formats.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}
		
		return format;
	}

	private String getCertPath(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			log.error("Certificate not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate> specification.");
		}
		if (certificateElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}
		
		NodeList pathElements = ((Element) certificateElements.item(0)).getElementsByTagNameNS(Credentials.credentialsNamespace, "Path");
		if (pathElements.getLength() < 1) {
			log.error("Certificate path not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate><Path/></Certificate> specification.");
		}
		if (pathElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("Certificate path not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate><Path/></Certificate> specification.");
		}
		return path;
	}
	
	
	
	/**
	 * Auto-enlarging container for bytes.
	 */

	// Sure makes you wish bytes were first class objects.

	private class ByteContainer {

		private byte[] buffer;
		private int cushion;
		private int currentSize = 0;

		private ByteContainer(int cushion) {
			buffer = new byte[cushion];
			this.cushion = cushion;
		}

		private void grow() {
			log.debug("Growing ByteContainer.");
			int newSize = currentSize + cushion;
			byte[] b = new byte[newSize];
			int toCopy = Math.min(currentSize, newSize);
			int i;
			for (i = 0; i < toCopy; i++) {
				b[i] = buffer[i];
			}
			buffer = b;
		}

		/** 
		 * Returns an array of the bytes in the container. <p>
		 */

		private byte[] toByteArray() {
			byte[] b = new byte[currentSize];
			for (int i = 0; i < currentSize; i++) {
				b[i] = buffer[i];
			}
			return b;
		}

		/** 
		 * Add one byte to the end of the container.
		 */

		private void append(byte b) {
			if (currentSize == buffer.length) {
				grow();
			}
			buffer[currentSize] = b;
			currentSize++;
		}

	}
	
	
	
}

class KeystoreCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(KeystoreCredentialResolver.class.getName());

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getTagName().equals("KeyStoreResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <KeyStoreResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String id = e.getAttribute("id");
		if (id == null || id.equals("")) {
			log.error("Credential Resolvers require specification of the attribute \"id\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String keyStoreType = e.getAttribute("keyStoreType");
		if (keyStoreType == null || keyStoreType.equals("")) {
			log.debug("Using default store type for credential.");
			keyStoreType = "JKS";
		}

		String path = loadPath(e);
		String alias = loadAlias(e);
		String keyPassword = loadKeyPassword(e);
		String keyStorePassword = loadKeyStorePassword(e);

		try {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);

			keyStore.load(new ShibResource(path, this.getClass()).getInputStream(), keyStorePassword.toCharArray());

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray());

			if (privateKey == null) {
				throw new CredentialFactoryException("No key entry was found with an alias of (" + alias + ").");
			}

			Certificate[] certificates = keyStore.getCertificateChain(alias);
			if (certificates == null) {
				throw new CredentialFactoryException(
					"An error occurred while reading the java keystore: No certificate found with the specified alias ("
						+ alias
						+ ").");
			}

			X509Certificate[] x509Certs = new X509Certificate[certificates.length];
			for (int i = 0; i < certificates.length; i++) {
				if (certificates[i] instanceof X509Certificate) {
					x509Certs[i] = (X509Certificate) certificates[i];
				} else {
					throw new CredentialFactoryException(
						"The KeyStore Credential Resolver can only load X509 certificates.  Found an unsupported certificate of type ("
							+ certificates[i]
							+ ").");
				}
			}

			return new Credential(x509Certs, privateKey);

		} catch (KeyStoreException kse) {
			throw new CredentialFactoryException("An error occurred while accessing the java keystore: " + kse);
		} catch (NoSuchAlgorithmException nsae) {
			throw new CredentialFactoryException("Appropriate JCE provider not found in the java environment: " + nsae);
		} catch (CertificateException ce) {
			throw new CredentialFactoryException(
				"The java keystore contained a certificate that could not be loaded: " + ce);
		} catch (IOException ioe) {
			throw new CredentialFactoryException("An error occurred while reading the java keystore: " + ioe);
		} catch (UnrecoverableKeyException uke) {
			throw new CredentialFactoryException(
				"An error occurred while attempting to load the key from the java keystore: " + uke);
		}

	}

	private String loadPath(Element e) throws CredentialFactoryException {

		NodeList pathElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Path");
		if (pathElements.getLength() < 1) {
			log.error("KeyStore path not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires a <Path> specification.");
		}
		if (pathElements.getLength() > 1) {
			log.error("Multiple KeyStore path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("KeyStore path not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires a <Path> specification.");
		}
		return path;
	}

	private String loadAlias(Element e) throws CredentialFactoryException {

		NodeList aliasElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Alias");
		if (aliasElements.getLength() < 1) {
			log.error("KeyStore key alias not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <Alias> specification.");
		}
		if (aliasElements.getLength() > 1) {
			log.error("Multiple KeyStore alias specifications, using first.");
		}
		Node tnode = aliasElements.item(0).getFirstChild();
		String alias = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			alias = tnode.getNodeValue();
		}
		if (alias == null || alias.equals("")) {
			log.error("KeyStore key alias not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <Alias> specification.");
		}
		return alias;
	}

	private String loadKeyStorePassword(Element e) throws CredentialFactoryException {

		NodeList passwordElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "KeyStorePassword");
		if (passwordElements.getLength() < 1) {
			log.error("KeyStore password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyStorePassword> specification.");
		}
		if (passwordElements.getLength() > 1) {
			log.error("Multiple KeyStore password specifications, using first.");
		}
		Node tnode = passwordElements.item(0).getFirstChild();
		String password = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			password = tnode.getNodeValue();
		}
		if (password == null || password.equals("")) {
			log.error("KeyStore password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyStorePassword> specification.");
		}
		return password;
	}

	private String loadKeyPassword(Element e) throws CredentialFactoryException {

		NodeList passwords = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "KeyPassword");
		if (passwords.getLength() < 1) {
			log.error("KeyStore key password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyPassword> specification.");
		}
		if (passwords.getLength() > 1) {
			log.error("Multiple KeyStore key password specifications, using first.");
		}
		Node tnode = passwords.item(0).getFirstChild();
		String password = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			password = tnode.getNodeValue();
		}
		if (password == null || password.equals("")) {
			log.error("KeyStore key password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyPassword> specification.");
		}
		return password;
	}
}

class CustomCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(CustomCredentialResolver.class.getName());
	private CredentialResolver resolver;

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getTagName().equals("CustomCredResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <CustomCredResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String id = e.getAttribute("id");
		if (id == null || id.equals("")) {
			log.error("Credential Resolvers require specification of the attribute \"id\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String className = e.getAttribute("Class");
		if (className == null || className.equals("")) {
			log.error("Custom Credential Resolver requires specification of the attribute \"Class\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		try {
			return ((CredentialResolver) Class.forName(className).newInstance()).loadCredential(e);

		} catch (Exception loaderException) {
			log.error(
				"Failed to load Custom Credential Resolver implementation class: " + loaderException.getMessage());
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

	}

}

class CredentialFactoryException extends Exception {

	CredentialFactoryException(String message) {
		super(message);
	}
}