package br.com.malikoski.poc_certificate_public_api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

@SpringBootApplication
public class PocCertificatePublicApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(PocCertificatePublicApiApplication.class, args);
	}

	@RestController
	@RequestMapping("/api/external")
	class BalanceController {

		@Value("${api.public.key}")
		private String publicKey;

		@GetMapping("/balance/{document}")
		public ResponseEntity<BalanceResponse> getBalance(@PathVariable("document") String document) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
			var r = new Random();
			var randomValue = 0 + (100000 - 1) * r. nextDouble();
			var bd = BigDecimal.valueOf(randomValue);
			bd = bd.setScale(2, RoundingMode.HALF_UP);

			return ResponseEntity.ok(new BalanceResponse(cryptData(document), bd.doubleValue()));
		}

		private byte[] cryptData(String document) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			var file = ResourceUtils.getFile(publicKey);
			String key = Files.readString(file.toPath(), Charset.defaultCharset());

			var publicKeyPEM = key
					.replace("-----BEGIN PUBLIC KEY-----", "")
					.replaceAll(System.lineSeparator(), "")
					.replace("-----END PUBLIC KEY-----", "");

			var encodedKey = Base64.getDecoder().decode(publicKeyPEM);

			var keyFactory = KeyFactory.getInstance("RSA");
			var keySpec = new X509EncodedKeySpec(encodedKey);
			var rsaPublicKey = keyFactory.generatePublic(keySpec);

			final Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

			return cipher.doFinal(document.getBytes());

		}

	}

	record BalanceResponse(byte[] document, double balance){}


}
