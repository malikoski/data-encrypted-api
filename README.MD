# Test data encrypted
 
## Create private certificate
  ```
  openssl genrsa > certificate-pem.pem
  ```

## Create public certificate
  ```
  openssl rsa -in certificate-api.pem -pubout -out certificate-public-api.pem
  ```

## Running

```
    Run PocCertificatePublicApiApplication class
    Run PocCertificatePrivateApiApplication class
    
    Consuming API example: http://localhost:8080/api/document/02440078964
```