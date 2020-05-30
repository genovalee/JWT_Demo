package project1;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;

import sun.misc.BASE64Encoder;

public class JWTNested {

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
		
		//ENCRYPTING
		RsaJsonWebKey ceKey = RsaJwkGenerator.generateJwk(2048);
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey contentEncryptKey = keyGen.generateKey();
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setKey(ceKey.getPublicKey());
		jwe.setPayload(signedJwt);
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
		jwe.setContentEncryptionKey(contentEncryptKey.getEncoded());
		jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
		jwe.setHeader("cty", "jwt"); //NESTED JWT
		SecureRandom iv = SecureRandom.getInstance("SHA1PRNG");
		jwe.setIv(iv.generateSeed(32));
		String encryptedJwt = jwe.getCompactSerialization();
		System.out.println("Encrypted ::" + encryptedJwt);
		
		
		/***************************RECEIVER'S END ***********************************/ 
		
		JwtConsumer consumer = new JwtConsumerBuilder()
						        .setSkipAllValidators()
						        .setDisableRequireSignature()
						        .setSkipSignatureVerification()
								.setDecryptionKey(ceKey.getPrivateKey())
								.build();
		JwtClaims receivedClaims = consumer.processToClaims(encryptedJwt);
		System.out.println("SUCESS :: JWT Validation :: " + receivedClaims);

		JwtContext jwtCtxt = consumer.process(encryptedJwt);
		
		//Signature verification
		consumer = new JwtConsumerBuilder()
					.setExpectedAudience("Admins")
					.setExpectedIssuer("CA")
					.setVerificationKey(jsonSignKey.getPublicKey())
					.setRequireSubject()
					.build();
		consumer.processContext(jwtCtxt);
		System.out.println("JWT signature is valid");
	}
}