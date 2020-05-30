package project1;

import java.security.PublicKey;
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
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import sun.misc.BASE64Encoder;

public class JWTOnlyEncryption {

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
		System.out.println("Senders side :: " + claims.toJson());
		
		//ENCRYPTING
		
		//Assume this code is executed at receivers end and send
		//public to sender
		RsaJsonWebKey ceKey = RsaJwkGenerator.generateJwk(2048);
		PublicKey receipentPubKey = ceKey.getPublicKey();
		
		//Generation of content encryption key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey contentEncryptKey = keyGen.generateKey();
		
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setKey(receipentPubKey);
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
		jwe.setContentEncryptionKey(contentEncryptKey.getEncoded());
		jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
		SecureRandom iv = SecureRandom.getInstance("SHA1PRNG");
		jwe.setIv(iv.generateSeed(32));
		jwe.setPayload(claims.toJson());
		String encryptedJwt = jwe.getCompactSerialization();
		System.out.println("Encrypted ::" + encryptedJwt);
		
		BASE64Encoder b64 = new BASE64Encoder();
		System.out.println("Public Key :: " + b64.encode(ceKey.getPublicKey().getEncoded()));
		System.out.println("Private Key :: " + b64.encode(ceKey.getPrivateKey().getEncoded()));
		
		
		/***************************RECEIVER'S END ***********************************/ 
		
		JwtConsumer consumer = new JwtConsumerBuilder()
								.setExpectedAudience("Admins")
								.setExpectedIssuer("CA")
								.setRequireSubject()
								.setDecryptionKey(ceKey.getPrivateKey())
								.setDisableRequireSignature()
								.build();
		JwtClaims receivedClaims = consumer.processToClaims(encryptedJwt);
		System.out.println("SUCESS :: JWT Validation :: " + receivedClaims);
		
	}

}