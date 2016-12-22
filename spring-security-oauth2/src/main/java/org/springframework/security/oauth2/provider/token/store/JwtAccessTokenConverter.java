/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.springframework.security.oauth2.provider.token.store;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.security.KeyPair;
import java.util.Map;

/**
 * Helper that translates between JWT encoded token values and OAuth authentication
 * information (in both directions). Also acts as a {@link TokenEnhancer} when tokens are
 * granted.
 *
 * @see TokenEnhancer
 * @see AccessTokenConverter
 *
 * @author Dave Syer
 * @author Luke Taylor
 */
public abstract class JwtAccessTokenConverter<S, V> implements TokenEnhancer, AccessTokenConverter {

	/**
	 * Field name for token id.
	 */
	public static final String TOKEN_ID = AccessTokenConverter.JTI;

	/**
	 * Field name for access token id.
	 */
	public static final String ACCESS_TOKEN_ID = AccessTokenConverter.ATI;

    protected JsonParser objectMapper = JsonParserFactory.create();

	private AccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();


	/**
	 * @param tokenConverter the tokenConverter to set
	 */
	public void setAccessTokenConverter(AccessTokenConverter tokenConverter) {
		this.tokenConverter = tokenConverter;
	}


	/**
	 * @return the tokenConverter in use
	 */
	public AccessTokenConverter getAccessTokenConverter() {
		return tokenConverter;
	}

	@Override
	public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		return getAccessTokenConverter().convertAccessToken(token, authentication);
	}

	@Override
	public OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map) {
		return getAccessTokenConverter().extractAccessToken(value, map);
	}

	@Override
	public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
		return getAccessTokenConverter().extractAuthentication(map);
	}

	/**
	 * Unconditionally set the verifier (the verifer key is then ignored).
	 *
	 * @param verifier the value to use
	 */
	public abstract void setVerifier(V verifier);

	/**
	 * Unconditionally set the signer to use (if needed). The signer key is then ignored.
	 *
	 * @param signer the value to use
	 */
	public abstract void setSigner(S signer);

    public abstract void setKeyPair(KeyPair keyPair);

	/**
	 * Get the verification key for the token signatures.
	 *
	 * @return the key used to verify tokens
	 */
	public abstract Map<String, String> getKey();

	/**
	 * @return true if the key has a public verifier
	 */
	private boolean isPublic(String key) {
		return key.startsWith("-----BEGIN");
	}

	/**
	 * @return true if the signing key is a public key
	 */
	public abstract boolean isPublic();

	public boolean isRefreshToken(OAuth2AccessToken token) {
		return token.getAdditionalInformation().containsKey(ACCESS_TOKEN_ID);
	}

	public abstract String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication);

    public abstract Map<String, Object> decode(String token);


}
