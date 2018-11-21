package crypt;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class TesteCrypt {

	public static void main(String[] args) throws Exception {
		File file=null;
		JFileChooser chooser = new JFileChooser();
		chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		int retorno = chooser.showSaveDialog(null);
		byte[] arquivoBinario = null;
		// se cancelou/fechou
		if (retorno == JFileChooser.APPROVE_OPTION) {
			file = chooser.getSelectedFile();
			int len = (int) file.length();
			arquivoBinario = new byte[len];
			FileInputStream inFile = null;
			try {
				inFile = new FileInputStream(file);
				inFile.read(arquivoBinario, 0, len);
			} catch (FileNotFoundException fnfex) {
			} catch (IOException ioex) {
			}
		}

		System.out.println("Digite 1 para criptografar ou 0 para descriptografar: ");

		Scanner scanner = new Scanner(System.in);
		int i = scanner.nextInt();


		byte[] encryptedKey;
		byte[] iv = new byte[16];
		byte[] plainContent = null;
		byte[] salt = {0,1,2,3,4,5,6,7,8,9};
		switch(i){
			case 1:
				Scanner scannerString = new Scanner(System.in);
				System.out.println("Digite a chave: ");
				String keyString = scannerString.nextLine();
				encryptedKey = getEncryptedPassword(keyString,  salt, 32);

				Security.addProvider(new BouncyCastleProvider());

				try{

					plainContent = encrypt_AES_CBC(arquivoBinario, encryptedKey, iv);


				}catch (Exception e){
					System.err.println(e);
					System.out.println("Erro ao criptografar o arquivo.");
				}

				try {


					FileOutputStream outFile = null;

					outFile = new FileOutputStream(file, false);
					outFile.write(plainContent);
					outFile.close();



				}catch (Exception e){

					System.out.println("Erro ao gravar o arquivo.");
					System.err.println("Problem writing to the file statsTest.txt");

				}

				break;
			case 0:
				System.out.println("Digite a chave: ");
				scannerString = new Scanner(System.in);
				keyString = scannerString.nextLine();
				encryptedKey = getEncryptedPassword(keyString,  salt, 32);

				Security.addProvider(new BouncyCastleProvider());

				try{

					plainContent = decrypt_AES_CBC(arquivoBinario, encryptedKey, iv);


				}catch (Exception e){
					System.err.println(e);
					System.out.println("Erro ao criptografar o arquivo.");
				}

				try {

					FileOutputStream outFile = null;
					outFile = new FileOutputStream(file, false);
					outFile.write(plainContent);
					outFile.close();


				}catch (Exception e){

					System.out.println("Erro ao gravar o arquivo.");
					System.err.println("Problem writing to the file statsTest.txt");

				}

				break;



		}





/*
		Security.addProvider(new BouncyCastleProvider());
		String message = "ola";
		byte[] plainTextBytes = message.getBytes("utf-8");
		byte[] keyBytes = new byte[24];
		byte[] cipherText = encrypt_3DES_CBC(plainTextBytes, keyBytes, iv);
		// byte[] cipherText = encrypt_3DES_ECB( plainTextBytes, keyBytes);

		System.out.println("Mensagem plain: " + message);
		System.out.println("Mensagem plain (HEX): "
				+ Hex.toHexString(plainTextBytes));
		System.out.println("Tamanho: " + plainTextBytes.length);
		System.out.println("Tamanho: " + cipherText.length);
		System.out.println("Mensagem cifrada:" + Hex.toHexString(cipherText));

		// byte[] text = decrypt_3DES_ECB( cipherText, keyBytes);
		// System.out.println("Mensagem decifrada:"+ Hex.toHexString(text));

		// testAES();
		System.out.println("----------------------");
		testPbkdf2();
		
*/

	}
	public static void testPbkdf2() throws Exception {
		byte[] salt = {0,1,2,3,4,5,6,7,8,9};
		long time;
		time = System.currentTimeMillis();
		
		byte[] pbkdf2 = getEncryptedPassword("teste",  salt, 1000000);
		time = System.currentTimeMillis() - time;
		System.out.println(" Tempo de processamento? " + time + " ms");
	}
	

	public static void testHash() throws Exception {
		String frase = "Quero gerar c�digos hash desta mensagem.";

		System.out.println(Hex.toHexString(gerarHash(frase, "MD2")));
		System.out.println(Hex.toHexString(gerarHash(frase, "MD5")));
		System.out.println(Hex.toHexString(gerarHash(frase, "SHA-1")));
		System.out.println(Hex.toHexString(gerarHash(frase, "SHA-256")));
		System.out.println(Hex.toHexString(gerarHash(frase, "SHA-384")));
		System.out.println(Hex.toHexString(gerarHash(frase, "SHA-512")));
	}

	public static void testAES() throws Exception {

		String message = "ola";
		byte[] plainTextBytes = message.getBytes("utf-8");
		byte[] keyBytes = new byte[16];
		byte[] iv = new byte[16];
		byte[] cipherText = encrypt_AES_CBC(plainTextBytes, keyBytes, iv);
		System.out.println("Mensagem cifrada:" + Hex.toHexString(cipherText));

		plainTextBytes = decrypt_AES_CBC(cipherText, keyBytes, iv);
		System.out.println("Mensagem cifrada:" + new String(plainTextBytes));

	}
	
	// -----------------------------------------------------
	// Infra
	// -----------------------------------------------------
	

	public static byte[] encrypt_3DES_CBC(byte[] plainTextBytes,
			byte[] keyBytes, byte[] ivBytes) throws Exception {
		final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		final IvParameterSpec iv = new IvParameterSpec(ivBytes);
		final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding",
				"BC");
		// final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding",
		// "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		final byte[] cipherText = cipher.doFinal(plainTextBytes);
		return cipherText;

	}

	public static byte[] decrypt_3DES_CBC(byte[] cryptTextBytes,
			byte[] keyBytes, byte[] ivBytes) throws Exception {
		final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		final IvParameterSpec iv = new IvParameterSpec(ivBytes);
		// final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding",
		// "BC");
		final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		final byte[] cipherText = cipher.doFinal(cryptTextBytes);
		return cipherText;

	}

	public static byte[] encrypt_3DES_ECB(byte[] plainTextBytes, byte[] keyBytes)
			throws Exception {
		final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		// final Cipher cipher = Cipher.getInstance("DESede/EBC/PKCS5Padding",
		// "BC");
		final Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		final byte[] cipherText = cipher.doFinal(plainTextBytes);
		return cipherText;

	}

	public static byte[] decrypt_3DES_ECB(byte[] cryptTextBytes, byte[] keyBytes)
			throws Exception {
		final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		// final Cipher cipher = Cipher.getInstance("DESede/EBC/PKCS5Padding",
		// "BC");
		final Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, key);
		final byte[] cipherText = cipher.doFinal(cryptTextBytes);
		return cipherText;

	}

	public static byte[] encrypt_AES_CBC(byte[] plainTextBytes,
			byte[] keyBytes, byte[] ivBytes) throws Exception {
		final SecretKey key = new SecretKeySpec(keyBytes, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		return cipher.doFinal(plainTextBytes);
	}

	public static byte[] decrypt_AES_CBC(byte[] cryptTextBytes,
			byte[] keyBytes, byte[] ivBytes) throws Exception {
		final SecretKey key = new SecretKeySpec(keyBytes, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		return cipher.doFinal(cryptTextBytes);
	}

	public static byte[] gerarHash(String frase, String algoritmo) {
		try {
			MessageDigest md = MessageDigest.getInstance(algoritmo);
			md.update(frase.getBytes());
			return md.digest();
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

	public static boolean authenticate(String password, byte[] encryptedPassword, byte[] salt) throws Exception {
		// Encrypt the clear-text password using the same salt that was used to
		// encrypt the original password
		byte[] encryptedAttemptedPassword = getEncryptedPassword(
				password, salt,0);

		// Authentication succeeds if encrypted password that the user entered
		// is equal to the stored hash
		return Arrays.equals(encryptedPassword, encryptedAttemptedPassword);
	}

	public static byte[] getEncryptedPassword(String password, byte[] salt, int iterations)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// PBKDF2 with SHA-1 as the hashing algorithm. Note that the NIST
		// specifically names SHA-1 as an acceptable hashing algorithm for
		// PBKDF2
		String algorithm = "PBKDF2WithHmacSHA256";
		// SHA-1 generates 160 bit hashes, so that's what makes sense here
		int derivedKeyLength = 16 * 8;
		// Pick an iteration count that works for you. The NIST recommends at
		// least 1,000 iterations:
		// http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
		// iOS 4.x reportedly uses 10,000:
		// http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/
		if (iterations <= 0) iterations = 20000;

		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations,
				derivedKeyLength);

		SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);
		return f.generateSecret(spec).getEncoded();
	}
	

}
