package com.scb.api.oauth2.jwt;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;

public class JWTGenerator {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Validation valid = null;
		String signedJWT = "";
		
		try {
			if(args.length < 5) {
				System.out.println("Error: Invalid number of parameters!");
				printUsage();
			}else {
				
				valid = validateInputs(args);
				
				if (valid.status==false) {
					System.out.println(valid.msg);
					printUsage();
					System.exit(400);
				}
				
				String typ = args[0];
				File keyFile = new File(args[4]);
				String targetURL = args[1];
				String htm = args[2];
				String client_id = args[3];
				
				if(typ.equalsIgnoreCase("jwt")) {
					signedJWT = createJWT(client_id, targetURL, keyFile);
				}else if(typ.equalsIgnoreCase("dpop")) {
					signedJWT = createDPoP(client_id, htm, targetURL, keyFile);
				}
				
				System.out.println(signedJWT);
			}
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static Validation validateInputs(String args[]) {
		
		Validation input = new Validation();
		
		if(args[0].equalsIgnoreCase("jwt")||args[0].equalsIgnoreCase("dpop")) {
			input.status = true;
		}else {
			input.status = false;
			input.msg = "Error: Incorrect Type value!";
			return input;
		}
		
		if(args[1].startsWith("https://")) {
			input.status = true;
		}else {
			input.status = false;
			input.msg = "Error: TargetURL is missing!";
			return input;
		}
		
		if(args[2].equalsIgnoreCase("POST")||args[2].equalsIgnoreCase("GET")||args[2].equalsIgnoreCase("PUT")||args[2].equalsIgnoreCase("PATCH")||args[2].equalsIgnoreCase("DELETE")) {
			input.status = true;
		}else {
			input.status = false;
			input.msg = "Error: Incorrect http_method value!";
			return input;
		}
		
		if(args[3].matches("([^']{28})")) {
			input.status = true;
		}else {
			input.status = false;
			input.msg = "client_id is missing!";
			return input;
		}
		
		if(args[4].matches("^(.+)\\/([^\\/]+)$")) {
			input.status = true;
		}else {
			input.status = false;
			input.msg = "Error: Private Key file is missing!";
			return input;
		}
		
		
		return input;
	}
	
	public static void printUsage() {
		System.out.println("Usage: java JWTGenerator [type] targetURL [http_method] client_id private_key_file");
		System.out.println("   type:");
		System.out.println("      jwt    Generate private key jwt");
		System.out.println("      dpop   Generate dpop jwt");
		System.out.println("   http_method:");
		System.out.println("      POST   Use this for Token calls and other POST method API calls");
		System.out.println("      GET    GET method");
		System.out.println("      PUT    PUT method");
		System.out.println("      PATCH    PATCH method");
		System.out.println("      DELETE    DELETE method");
	}
	
	public static String createJWT(String client_id, String targetURL, File key) {
		String encodedJWT = "";
		
		try {
			
			long nowMilis = System.currentTimeMillis();
			Date now = new Date(nowMilis);
			
			BufferedReader br = new BufferedReader(new FileReader(key));
			Security.addProvider(new BouncyCastleProvider());
			PEMParser pp = new PEMParser(br);
			PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
			KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
			
			
			JWK jwk = new RSAKey.Builder((RSAPublicKey)kp.getPublic())
			          .keyUse(KeyUse.SIGNATURE)
			          .algorithm(new Algorithm("RS256"))
			          .keyID(UUID.randomUUID().toString())
			          .issueTime(new Date())
			          .build();
			
			encodedJWT = Jwts.builder()
					     .setHeaderParam("typ", "jwt")
						 .setIssuer(client_id)
						 .setSubject(client_id)
						 .setAudience(targetURL)
						 .setExpiration(getJWTExpiry())
						 .setNotBefore(getCurrentTime())
						 .setIssuedAt(getCurrentTime())
						 .setId(UUID.randomUUID().toString())
						 .signWith(SignatureAlgorithm.RS256, kp.getPrivate())
						 .compact();
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		return encodedJWT;
		
	}
	
	public static String createDPoP(String client_id, String htm, String targetURL, File key) {
		String encodedJWT = "";
		
		try {
			
			long nowMilis = System.currentTimeMillis();
			Date now = new Date(nowMilis);
			
			BufferedReader br = new BufferedReader(new FileReader(key));
			Security.addProvider(new BouncyCastleProvider());
			PEMParser pp = new PEMParser(br);
			PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
			KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
			
			
			JWK jwk = new RSAKey.Builder((RSAPublicKey)kp.getPublic())
			          .keyUse(KeyUse.SIGNATURE)
			          .algorithm(new Algorithm("RS256"))
			          .keyID(UUID.randomUUID().toString())
			          .issueTime(new Date())
			          .build();
			
			encodedJWT = Jwts.builder()
					     .setHeaderParam("typ", "dpop+jwt")
					     .setHeaderParam("jwk", jwk.toJSONObject())
						 .setIssuer(client_id)
						 .setSubject(client_id)
						 .setAudience(targetURL)
						 .claim("htm", htm)
						 .claim("htu", targetURL)
						 .setExpiration(getJWTExpiry())
						 .setNotBefore(getCurrentTime())
						 .setIssuedAt(getCurrentTime())
						 .setId(UUID.randomUUID().toString())
						 .signWith(SignatureAlgorithm.RS256, kp.getPrivate())
						 .compact();
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		return encodedJWT;
		
	}
	
	public static Date getJWTExpiry() {
		Calendar currentTimeNow = Calendar.getInstance();
		currentTimeNow.add(Calendar.MINUTE, 15);
		return currentTimeNow.getTime();
	}
	
	public static Date getCurrentTime() {
		Calendar currentTimeNow = Calendar.getInstance();
		return currentTimeNow.getTime();
	}
	
	public static PrivateKey readPrivateKey(File file) throws Exception {
	    KeyFactory factory = KeyFactory.getInstance("RSA");

	    try (FileReader keyReader = new FileReader(file);
	      PemReader pemReader = new PemReader(keyReader)) {

	        PemObject pemObject = pemReader.readPemObject();
	        byte[] content = pemObject.getContent();
	        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
	        return factory.generatePrivate(privKeySpec);
	    }
	}
	
	public static class Validation{
		private String msg;
		private boolean status;
		
		public String getMsg() {
			return msg;
		}
		public void setMsg(String msg) {
			this.msg = msg;
		}
		public boolean isStatus() {
			return status;
		}
		public void setStatus(boolean status) {
			this.status = status;
		}
	}
}
