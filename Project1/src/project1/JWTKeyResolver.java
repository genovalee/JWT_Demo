package project1;

import java.security.interfaces.RSAPublicKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;

import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;

import sun.misc.BASE64Encoder;

public class JWTKeyResolver {

    public static void main(String[] args) throws Exception {

        /***************************SENDER'S END ***********************************/

        JwtClaims claims = new JwtClaims();
        claims.setAudience("Admins");
        claims.setExpirationTimeMinutesInTheFuture(10); //10 minutes from now
        claims.setGeneratedJwtId();
        claims.setIssuer("CA");
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject("100bytesAdmin");
        claims.setClaim("email", "100bytesAdmin@100bytes.com");
        claims.setClaim("Country", "Antartica");
        List hobbies = Arrays.asList("Blogging", "Playing cards", "Games");
        claims.setStringListClaim("hobbies", hobbies);
        System.out.println(claims.toJson());

        //SIGNING
        RsaJsonWebKey jsonSignKey = RsaJwkGenerator.generateJwk(2048);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(jsonSignKey.getPrivateKey());
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String signedJwt = jws.getCompactSerialization();
        System.out.println("Signed ::" + signedJwt);
        BASE64Encoder b64 = new BASE64Encoder();
        RSAPublicKey rsaPub = (RSAPublicKey) jsonSignKey.getPublicKey();


        /***************************RECEIVER'S END ***********************************/

        RsaJsonWebKey sign_jwk = new RsaJsonWebKey(rsaPub);
        sign_jwk.setAlgorithm("RSA");
        sign_jwk.setUse("sig");
        sign_jwk.setKeyId("12345");
        List jwks_list = new ArrayList();
        jwks_list.add(sign_jwk);
        JwksVerificationKeyResolver jwks_resolver = new JwksVerificationKeyResolver(jwks_list);

        JwtConsumer consumer = new JwtConsumerBuilder().setExpectedAudience("Admins")
                                                       .setExpectedIssuer("CA")
                                                       .setVerificationKeyResolver(jwks_resolver)
                                                       .setRequireSubject()
                                                       .build();
        JwtClaims receivedClaims = consumer.processToClaims(signedJwt);
        System.out.println("SUCESS :: JWT Validation :: " + receivedClaims);
    }
}
