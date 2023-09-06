package tjrn.siex.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import sun.security.rsa.RSAPublicKeyImpl;

public class SiexCriptoUtils {

	private static final String ALGORITMO_RSA = "RSA";
	private static final String pathArquivoPublicKey = "<path-completo>.public.key";

	public static void main(String[] args) {
		try {
			System.out.println(SiexCriptoUtils.gerarCredencialCriptografada("login", "cns"));
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
	
	/**
	 * Gera credenciais com base no login e CNS da serventia
	 * @param login
	 * @param cns
	 * @return
	 * @throws Exception 
	 * @throws ConfigurationException
	 */
	private static String gerarCredencialCriptografada(String login, String cns) throws Exception {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
			final String data = sdf.format(Calendar.getInstance().getTime());
			final String credencialPlana = login + "|" + data + "|" + cns;
			final String credencialCriptografada = criptografar(credencialPlana, SiexCriptoUtils.readPublicKeyFromRSAPublicKeyFile(pathArquivoPublicKey));
			return credencialCriptografada;
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * Criptograva um texto utilizando a chave pública fornecida pelo SIEX
	 * @param texto
	 * @param publicKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static String criptografar(String texto, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String valorCriptografado = "";
		byte[] cipherText = null;
		final Cipher cipher = Cipher.getInstance(ALGORITMO_RSA);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		cipherText = cipher.doFinal(texto.getBytes());
		for(byte ct : cipherText) {
			valorCriptografado += ct + ",";
		}

		valorCriptografado = new String(Base64.encodeBase64(valorCriptografado.getBytes()));
		return valorCriptografado;
	}

	/**
	 * Load da chave pública em disco no formato RSAPublicKeyImpl
	 * @return
	 * @throws Exception
	 */
	public static PublicKey readPublicKeyFromRSAPublicKeyFile(String pathArquivoPublicKey) throws Exception {
		File file = new File(pathArquivoPublicKey);
		if(!file.exists()) {
			throw new Exception("Arquivo KEY de chave pública do SIEX não encontrado.");
		}
		FileInputStream fileIn = new FileInputStream(file);
		try (ObjectInputStream objectIn = new ObjectInputStream(fileIn)) {
			RSAPublicKeyImpl keyImpl = (RSAPublicKeyImpl) objectIn.readObject();
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(keyImpl.getModulus(), keyImpl.getPublicExponent());
			KeyFactory keyFactory = KeyFactory.getInstance(ALGORITMO_RSA);
			PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
			return publicKey;
		}
	}

	public static String publicKeyToPEM(PublicKey publicKey) throws Exception {
		byte[] publicKeyBytes = publicKey.getEncoded();
		String base64PublicKey = Base64.encodeBase64String(publicKeyBytes);
		PemObject pemObject = new PemObject("PUBLIC KEY", base64PublicKey.getBytes());
		StringWriter stringWriter = new StringWriter();
		PemWriter pemWriter = new PemWriter(stringWriter);
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		return stringWriter.toString();
	}
}
