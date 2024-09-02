package br.com.malikoski.poc_certificate_private_api;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClient;
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
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@SpringBootApplication
@EnableFeignClients
public class PocCertificatePrivateApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(PocCertificatePrivateApiApplication.class, args);
	}

	@RestController
	@RequestMapping("/api/document")
	@RequiredArgsConstructor
	class DocumentController {

		@Value("${api.private.key}")
		private String privateKey;

		private final ExternalClient externalClient;

		@GetMapping("{document}")
		public ResponseEntity<DocumentResponse> getBalance(@PathVariable("document") String document) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
			var response = externalClient.getBalance(document);
			return ResponseEntity.ok(new DocumentResponse(decrypt(response.document()), response.balance()));
		}


		private String decrypt(byte[] document) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			var file = ResourceUtils.getFile(privateKey);
			var key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

			var privateKeyPEM = key
					.replace("-----BEGIN PRIVATE KEY-----", "")
					.replaceAll(System.lineSeparator(), "")
					.replace("-----END PRIVATE KEY-----", "");

			var encodedKey = Base64.getDecoder().decode(privateKeyPEM);

			var keyFactory = KeyFactory.getInstance("RSA");
			var keySpec = new PKCS8EncodedKeySpec(encodedKey);
			var rsaPrivateKey = keyFactory.generatePrivate(keySpec);

			final Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
			var decryptText = cipher.doFinal(document);

			return new String(decryptText);
		}
	}

	@FeignClient(name = "ExternalApiClient", url = "${external.api.url}")
	interface ExternalClient {

		@GetMapping("/balance/{document}")
		ExternalResponse getBalance(@PathVariable("document") String document);
	}


	record ExternalResponse(byte[] document, double balance){}
    record DocumentResponse(String document, double balance){}

}
