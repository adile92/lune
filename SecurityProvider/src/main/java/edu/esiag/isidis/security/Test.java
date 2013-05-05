package edu.esiag.isidis.security;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import edu.esiag.isidis.security.provider.MyProvider;
import fr.cryptohash.Digest;

public class Test {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException {
		// TODO Auto-generated method stub
		
		MyProvider provider = new MyProvider();
		Security.addProvider(provider);


		Cipher cipher = provider.getCipher("AES");
		
		System.out.println("cipher algo : "+cipher.getAlgorithm());
		
		Key key = provider.getKeyGenerator("AES").generateKey();
		
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		byte[] datas = cipher.doFinal("toto".getBytes());
		
		System.out.println(new String(datas));
		
		
		 cipher.init(Cipher.DECRYPT_MODE, key);
		
		 byte[] result = cipher.doFinal(datas);
		 
		 System.out.println(new String(result));
		 
		 
		 Digest keccak = provider.getKeccak(224);
		 
		 System.out.println("keccak "+keccak.digest("toto ss".getBytes()));
		 System.out.println("keccak "+keccak.digest("toto ss1".getBytes()));
		 System.out.println("keccak "+keccak.digest("toto ss..".getBytes()));
		 
		 MessageDigest md = provider.getMessageDigest("SHA");
			
			System.out.println("MD "+Arrays.toString(md.digest("toto".getBytes())));
			System.out.println("MD "+Arrays.toString(md.digest("toto".getBytes())));
		 

	}

}
