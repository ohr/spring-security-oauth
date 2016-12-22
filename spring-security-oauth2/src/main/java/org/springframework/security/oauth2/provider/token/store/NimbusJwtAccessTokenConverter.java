package org.springframework.security.oauth2.provider.token.store;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 */
public class NimbusJwtAccessTokenConverter extends JwtAccessTokenConverter<JWSSigner, JWSVerifier> implements InitializingBean {

    static final String WELL_KNOWN_OPENID_CONFIGURATION = "/.well-known/openid-configuration";
    static final String JWKS_URI_ENTRY = "jwks_uri";

    private JWKSource keySource;
    private JWSAlgorithm jwsAlgorithm;
    private JWEAlgorithm jweAlgorithm;
    private EncryptionMethod jweEncryptionMethod;

    private ConfigurableJWTProcessor jwtProcessor;
    private RSAEncrypter rsaEncrypter;
    private RSADecrypter rsaDecrypter;
    private JWSSigner signer;
    private JWSVerifier verifier;

    private KeyPair keyPair;

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        return null;
    }

    @Override
    public void setVerifier(JWSVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public void setSigner(JWSSigner signer) {
        this.signer = signer;
    }

    public void setJWSAlgorithm(String algorithm) {
        this.jwsAlgorithm = JWSAlgorithm.parse(algorithm);
    }

    public void setKeySource(JWKSource keySource) {
        this.keySource = keySource;
    }

    public void setJWEAlgorithm(String algorithm) {
        this.jweAlgorithm = JWEAlgorithm.parse(algorithm);
    }

    public void setJWEEncryptionMethod(String encryptionMethod) {
        this.jweEncryptionMethod = EncryptionMethod.parse(encryptionMethod);
    }

    /**
     * Sets key pair in order to derive encryption/descryption as well as signing/verification
     * @param keyPair
     */
    @Override
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @Override
    public Map<String, String> getKey() {
        Map<String, String> result = new LinkedHashMap<String, String>();
        result.put("alg", jwsAlgorithm.getName());
        result.put("value", "verifierKey"); // encoded public key
        return result;
    }

    @Override
    public boolean isPublic() {
        return false;
    }

    @Override
    public String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        try {
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
            for (Map.Entry<String, ?> claims : getAccessTokenConverter().convertAccessToken(accessToken, authentication).entrySet()) {
                claimsSetBuilder.claim(claims.getKey(), claims.getValue());
            }
            JWTClaimsSet claimsSet = claimsSetBuilder.build();

            if (jwsAlgorithm != null) {
                SignedJWT signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), claimsSet);
                signedJWT.sign(signer);
                return (jweAlgorithm != null && jweEncryptionMethod != null) ?
                    encrypt(new Payload(signedJWT)).serialize() :
                    signedJWT.serialize();
            }
            return (jweAlgorithm != null && jweEncryptionMethod != null) ?
                encrypt(new Payload(claimsSet.toJSONObject())).serialize() :
                claimsSet.toString();
        } catch (Exception e){
            throw new InvalidTokenException("Cannot JSON to access token", e);
        }
    }

    private JWEObject encrypt(Payload payload) {
        try {
            JWEHeader.Builder builder = new JWEHeader.Builder(jweAlgorithm, jweEncryptionMethod);
            if (payload.getOrigin() == Payload.Origin.SIGNED_JWT) {
                builder.contentType("JWT"); // required to signal nested JWT
            }
            JWEObject jweObject = new JWEObject(builder.build(), payload);
            jweObject.encrypt(rsaEncrypter);
            return jweObject;
        } catch (Exception e) {
            throw new InvalidTokenException("Cannot encrypt token", e);
        }
    }

    @Override
    public Map<String, Object> decode(String token) {
        try {
            JWTClaimsSet claimsSet;
            if (verifier != null) {
                SignedJWT signedJWT = SignedJWT.parse(token);
                Assert.isTrue(signedJWT.verify(verifier));
                claimsSet = signedJWT.getJWTClaimsSet();
            } else if (jwtProcessor != null) {
                claimsSet = jwtProcessor.process(token, null);
                return claimsSet.getClaims();
            } else {
                throw new IllegalStateException("Neither verifier nor JWK set are populated");
            }
            return claimsSet.getClaims();
        } catch (Exception e) {
            throw new InvalidTokenException("Cannot convert access token to JSON", e);
        }
    }


    @Override
    public void afterPropertiesSet() throws Exception {

        if (keyPair != null) {
            PrivateKey privateKey = keyPair.getPrivate();
            signer = new RSASSASigner(privateKey);
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            verifier = new RSASSAVerifier(publicKey);
            rsaEncrypter = new RSAEncrypter(publicKey);
            rsaDecrypter = new RSADecrypter(privateKey);
        }

        // Prefer keySource being set
        if (keySource != null) {
            jwtProcessor = new DefaultJWTProcessor();
            if (jwsAlgorithm != null) {
                JWSKeySelector keySelector = new JWSVerificationKeySelector(jwsAlgorithm, keySource);
                jwtProcessor.setJWSKeySelector(keySelector);
            }
            if (jweAlgorithm != null && jweEncryptionMethod != null) {
                JWEKeySelector jweKeySelector = new JWEDecryptionKeySelector(jweAlgorithm, jweEncryptionMethod, keySource);
                jwtProcessor.setJWEKeySelector(jweKeySelector);
            }
        }

        if (signer != null) {
            Assert.isTrue(signer.supportedJWSAlgorithms().contains(jwsAlgorithm));
        }


    }
}
