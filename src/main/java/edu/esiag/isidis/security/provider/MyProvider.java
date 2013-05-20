package edu.esiag.isidis.security.provider;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

import fr.cryptohash.Digest;
import fr.cryptohash.Keccak224;
import fr.cryptohash.Keccak256;
import fr.cryptohash.Keccak384;
import fr.cryptohash.Keccak512;

public class MyProvider extends Provider {

	private static final long serialVersionUID = -3111988086662886441L;

	private Cipher cipher;
	private KeyGenerator keyGenerator;
	private KeyAgreement keyAgreement;
	private Mac mac;
	private SecretKeyFactory secretKeyFactory;
	private SecureRandom secureRandom;
	private KeyPairGenerator keyPairGenerator;
	private MessageDigest messageDigest;
	private CertificateFactory certificatFactory;
	private KeyStore keyStore;
	private Digest keccak;

	protected MyProvider(String name, double version, String info) {
		super(name, version, info);
	}

	public MyProvider() {
		this(
				"EsiagCSP",
				1.0,
				"This provider provides Signature,Cipher,Keygenertor features with AES,DES,RC2,RSA,DiffieHellman");

	}

	/**
	 * @return the cipher
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 */
	public Cipher getCipher(String algo) throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		return Cipher.getInstance(algo);
	}

	/**
	 * @return the keyGenerator
	 * @throws NoSuchAlgorithmException
	 */
	public KeyGenerator getKeyGenerator(String algo)
			throws NoSuchAlgorithmException {
		return KeyGenerator.getInstance(algo);
	}

	/**
	 * @return the keyAgreement
	 * @throws NoSuchAlgorithmException
	 */
	public KeyAgreement getKeyAgreement(String algo)
			throws NoSuchAlgorithmException {
		return KeyAgreement.getInstance(algo);
	}

	/**
	 * @return the mac
	 * @throws NoSuchAlgorithmException
	 */
	public Mac getMac(String algo) throws NoSuchAlgorithmException {
		return Mac.getInstance(algo);
	}

	/**
	 * @return the secretKeyFactory
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKeyFactory getSecretKeyFactory(String algo)
			throws NoSuchAlgorithmException {
		return SecretKeyFactory.getInstance(algo);
	}

	/**
	 * @return the secureRandom
	 * @throws NoSuchAlgorithmException
	 */
	public SecureRandom getSecureRandom(String algo)
			throws NoSuchAlgorithmException {
		return SecureRandom.getInstance(algo);
	}

	/**
	 * @return the keyPaiGenerator
	 * @throws NoSuchAlgorithmException
	 */
	public KeyPairGenerator getKeyPairGenerator(String algo)
			throws NoSuchAlgorithmException {
		return KeyPairGenerator.getInstance(algo);
	}

	/**
	 * @return the messageDigest
	 * @throws NoSuchAlgorithmException
	 */
	public MessageDigest getMessageDigest(String algo)
			throws NoSuchAlgorithmException {
		return MessageDigest.getInstance(algo);
	}

	/**
	 * @return the certificatFactory
	 * @throws CertificateException
	 */
	public CertificateFactory getCertificatFactory(String type)
			throws CertificateException {
		return CertificateFactory.getInstance(type);
	}

	/**
	 * @return the keyStore
	 * @throws KeyStoreException
	 */
	public KeyStore getKeyStore(String type) throws KeyStoreException {
		return KeyStore.getInstance(type);
	}

	/**
	 * @return the signature
	 * @throws NoSuchAlgorithmException 
	 */
	public Signature getSignature(String algo) throws NoSuchAlgorithmException {
		return Signature.getInstance(algo);
	}

	
	/**
	 * @return the keccak
	 */
	public Digest getKeccak(int version) {
		switch (version) {
		case 224:
			return new Keccak224();
		case 256:
			return new Keccak256();
		case 384:
			return new Keccak384();
		case 512:
			return new Keccak512();
		default:
			return new Keccak224();
		}
	}

}
