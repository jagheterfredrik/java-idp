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

import java.net.URI;
import java.net.URL;

/**
 * Defines a relationship between service providers and an identity provider. In Shibboleth parlance, a relying party
 * represents a SP or group of SPs (perhaps a federation).
 * 
 * @author Walter Hoehn
 */
public interface RelyingParty extends ServiceProvider {

	/**
	 * Returns the name of the relying party. If the relying party is a Shibboleth SP (not a group), this function
	 * returns the same thing as {@link #getProviderId}.
	 * 
	 * @return name of the relying party
	 */
	public String getName();

	/**
	 * Returns the appropriate identity provider to create assertions for this relying party.
	 * 
	 * @return the identity provider
	 */
	public IdentityProvider getIdentityProvider();

	/**
	 * Returns the id of the name format that should be used in authentication assertions issued to this
	 * {@link RelyingParty}.
	 * 
	 * @return the id for the format
	 */
	public String getHSNameFormatId();

	/**
	 * Returns a boolean indication of whether this {@link RelyingParty}is running &lt;= Shibboleth v1.1. Used to
	 * ensure backward compatibility.
	 */
	public boolean isLegacyProvider();

	/**
	 * Returns the location of the Shibboleth Attribute Authority that should answer requests for this
	 * {@link RelyingParty}.
	 * 
	 * @return the URL
	 */
	public URL getAAUrl();

	/**
	 * The authentication method that should be included in assertions to the {@link RelyingParty}, if one is not found
	 * in HTTP request headers.
	 * 
	 * @return the identifier for the method
	 */
	public URI getDefaultAuthMethod();

	/**
	 * A boolean indication of whether internal errors should be transmitted to this {@link RelyingParty}
	 */
	public boolean passThruErrors();

	/**
	 * A boolean indication of whether attributes should be pushed without regard for the profile (POST vs. Artifact).
	 * This should be be mutually exclusive with forceAttributeNoPush().
	 */
	public boolean forceAttributePush();

	/**
	 * A boolean indication of whether attributes should be NOT pushed without regard for the profile (POST vs.
	 * Artifact).
	 */
	public boolean forceAttributeNoPush();

	/**
	 * A boolean indication of whether the default SSO browser profile should be POST or Artifact. "true" indicates POST
	 * and "false" indicates Artifact.
	 */
	public boolean defaultToPOSTProfile();

	/**
	 * A boolean indication of whether assertions issued to this Relying Party should be digitall signed (This is in
	 * addition to profile-specific signing).
	 */
	public boolean wantsAssertionsSigned();

	/**
	 * Returns the type of SAML Artifact that this appropriate for use with this Relying Party.
	 */
	public int getPreferredArtifactType();

	/**
	 * Returns thhe default "TARGET" attribute to be used with the artifact profile or null if none is specified.
	 */
	public String getDefaultTarget();
}
