import eu.europa.esig.dss.*;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.*;
import eu.europa.esig.dss.validation.reports.*;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;
import eu.europa.esig.dss.x509.RevocationToken;

import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class DSSManager {

    private void signPDF(String pdfPath, String outputPath, String certificatePath, String certificatePassword, String nameOnSignature, boolean visual) {
        KeyStore keyStore;

        try {
            keyStore = KeyStore.getInstance("PKCS12");

            // Loading the certificate
            try (FileInputStream stream = new FileInputStream(certificatePath)) {
                keyStore.load(stream, certificatePassword.toCharArray());
            }

            // Getting the alias
            ArrayList<String> aliases = new ArrayList<>();
            keyStore.aliases().asIterator().forEachRemaining(aliases::add);
            String singleAlias = aliases.get(0);

            // Getting the certificate
            Certificate certificate = keyStore.getCertificate(singleAlias);

            if (certificate instanceof X509Certificate) {

                // Finding the PDF document
                DSSDocument document = new FileDocument(new File(pdfPath));

                // Preparing parameters for the PAdES signature
                PAdESSignatureParameters parameters = new PAdESSignatureParameters();

                // We choose the level of the signature (-B, -T, -LT, -LTA).
                parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

                // We set the digest algorithm to use with the signature algorithm. You must use the
                // same parameter when you invoke the method sign on the token. The default value is
                // SHA256
                parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

                // We set the signing certificate
                X509Certificate x509Certificate = (X509Certificate) certificate;
                parameters.setSigningCertificate(new CertificateToken(x509Certificate));

                // We set the certificate chain
                Certificate[] certificateChain = keyStore.getCertificateChain(singleAlias);
                List<CertificateToken> certificateTokens = Arrays.stream(certificateChain)
                        .map(cert -> new CertificateToken((X509Certificate) cert))
                        .collect(Collectors.toList());
                parameters.setCertificateChain(certificateTokens);

                //-------------------VISUAL SIGNATURE
                if (visual) {
                    // Initialize visual signature
                    SignatureImageParameters imageParameters = new SignatureImageParameters();
                    // the origin is the left and top corner of the page
                    imageParameters.setxAxis(200);
                    imageParameters.setyAxis(500);

                    // Initialize text to generate for visual signature
                    SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
                    textParameters.setFont(new Font("serif", Font.PLAIN, 14));
                    textParameters.setTextColor(Color.BLUE);
                    textParameters.setText(nameOnSignature);
                    imageParameters.setTextParameters(textParameters);

                    parameters.setSignatureImageParameters(imageParameters);
                }
                //-------------------VISUAL SIGNATURE

                // Create common certificate verifier
                CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

                // Create PAdESService for signature
                PAdESService service = new PAdESService(commonCertificateVerifier);

                // Get the SignedInfo segment that need to be signed.
                ToBeSigned dataToSign = service.getDataToSign(document, parameters);

                // Getting the private key from the certificate with the password
                try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(certificatePath, new KeyStore.PasswordProtection(certificatePassword.toCharArray()))) {
                    List<DSSPrivateKeyEntry> keys = token.getKeys();
                    DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

                    // This function obtains the signature value for signed information using the
                    // private key and specified algorithm

                    DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
                    SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);

                    // We invoke the padesService to sign the document with the signature value obtained in
                    // the previous step.
                    DSSDocument signedDocument = service.signDocument(document, parameters, signatureValue);

                    // Saving the signed document
                    signedDocument.save(outputPath);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void signPDF(String pdfPath, String outputPath, String certificatePath, String certificatePassword, String nameOnSignature) {
        signPDF(pdfPath, outputPath, certificatePath, certificatePassword, nameOnSignature, true);
    }

    public void signPDF(String pdfPath, String outputPath, String certificatePath, String certificatePassword) {
        signPDF(pdfPath, outputPath, certificatePath, certificatePassword, "", false);
    }

    public void signAsic(String[] inputPath, String outputPath, String certificatePath, String certificatePassword) {
        List<DSSDocument> documentsToBeSigned = new ArrayList<>();
        for (String path : inputPath) {
            documentsToBeSigned.add(new FileDocument(path));
        }

        // Preparing parameters for the ASiC-E signature
        ASiCWithCAdESSignatureParameters parameters = new ASiCWithCAdESSignatureParameters();

        // We choose the level of the signature (-B, -T, -LT or -LTA).
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        // We choose the container type (ASiC-S pr ASiC-E)
        parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        // We set the digest algorithm to use with the signature algorithm. You must use the
        // same parameter when you invoke the method sign on the token. The default value is SHA256
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        // Getting the token
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(certificatePath, new KeyStore.PasswordProtection(certificatePassword.toCharArray()))) {
            // Getting the keys
            List<DSSPrivateKeyEntry> keys = token.getKeys();

            // We set the signing certificate
            parameters.setSigningCertificate(keys.get(0).getCertificate());

            // We set the certificate chain
            parameters.setCertificateChain(keys.get(0).getCertificateChain());

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            // Create ASiC service for signature
            ASiCWithCAdESService service = new ASiCWithCAdESService(commonCertificateVerifier);

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(documentsToBeSigned, parameters);

            // This function obtains the signature value for signed information using the private key and specified algorithm
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, keys.get(0));

            // We invoke the xadesService to sign the document with the signature value obtained in the previous step.
            DSSDocument signedDocument = service.signDocument(documentsToBeSigned, parameters, signatureValue);
            try {
                // Saving the signed ASiC container
                signedDocument.save(outputPath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*public boolean isRevoked(String documentPath) {
        CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();

        // Firstly, we load the certificate to be validated
        CertificateToken toValidate = getCertificateFromSignature(documentPath);
        CertificateToken toValidateToken = adjunctCertificateSource.addCertificate(toValidate);

        //Configure the certificate verifier using the trust store and the intermediate certificates
        //OnlineOCSPSource and OnlineCRLSource will invoke the OCSP service and CRL
        //distribution point extracting the URL  from the certificate
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setAdjunctCertSource(adjunctCertificateSource);
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        certificateVerifier.setOcspSource(new OnlineOCSPSource());

        //Perform validation
        CertificatePool validationPool = certificateVerifier.createValidationPool();
        SignatureValidationContext validationContext = new SignatureValidationContext(validationPool);
        validationContext.addCertificateTokenForVerification(toValidateToken);
        validationContext.validate();

        // Get revocation status

    }*/

    private AdvancedSignature getSignatureFromDocument(String path) {
        // We have our signed document, we want to retrieve the original/signed data
        DSSDocument signedDocument = new FileDocument(path);

        // We create an instance of DocumentValidator. DSS automatically selects the validator depending of the signature file
        SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

        // We set a certificate verifier. It handles the certificate pool, allows to check the certificate status,...
        documentValidator.setCertificateVerifier(new CommonCertificateVerifier());

        // We retrieve the found signatures
        List<AdvancedSignature> signatures = documentValidator.getSignatures();

        Reports reports = documentValidator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();

        List<String> signatureIdList = simpleReport.getSignatureIdList();

        signatureIdList.get(0);

        // We select the wanted signature (the first one in our current case)
        return signatures.get(0);
    }

    private CertificateToken getCertificateFromSignature(String path) {
        // Getting the signature data from the signed document
        AdvancedSignature signature = getSignatureFromDocument(path);

        // Returning the first certificate of the signature
        return signature.getCertificates().get(0);
    }

    public boolean isSameCertificate(String documentPath, String certificatePath) {
        // Getting the certificate from the signed document
        CertificateToken certificateFromSignature = getCertificateFromSignature(documentPath);

        // TODO: Input validation

        // Getting the other certificate to compare
        CertificateToken otherCertificate = DSSUtils.loadCertificate(new File(certificatePath));

        // Checking if the two are the same
        return certificateFromSignature.isEquivalent(otherCertificate);
    }

    public boolean isCertificateValidOn(String documentPath, Date date) {
        // Getting the certificate from the signed document
        CertificateToken certificate = getCertificateFromSignature(documentPath);

        // Return if it is valid on the date
        return certificate.isValidOn(date);
    }

    public boolean isDocumentIntact(String documentPath) {
        // Getting the certificate from the document
        CertificateToken certificate = getCertificateFromSignature(documentPath);

        // Returning true if the document has not been modified since the signature
        return certificate.isSignatureValid();
    }
}
