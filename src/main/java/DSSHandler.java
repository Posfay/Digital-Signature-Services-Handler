import eu.europa.esig.dss.*;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.SimpleCertificateReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.CertificateToken;

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

public class DSSHandler {

    public void signPDF(String pdfPath, String outputPath, String certificatePath, String certificatePassword) {
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
//                // Initialize visual signature
//                SignatureImageParameters imageParameters = new SignatureImageParameters();
//                // the origin is the left and top corner of the page
//                imageParameters.setxAxis(200);
//                imageParameters.setyAxis(500);
//
//                // Initialize text to generate for visual signature
//                SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
//                textParameters.setFont(new Font("serif", Font.PLAIN, 14));
//                textParameters.setTextColor(Color.BLUE);
//                textParameters.setText("Signed");
//                imageParameters.setTextParameters(textParameters);
//
//                parameters.setSignatureImageParameters(imageParameters);
//                //-------------------VISUAL SIGNATURE


//                // Getting the private key from the certificate with the password
//                PrivateKey privateKey = (PrivateKey) keyStore.getKey(singleAlias, certificatePassword.toCharArray());
//                KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, certificateChain);
//                KSPrivateKeyEntry ksPrivateKeyEntry = new KSPrivateKeyEntry(singleAlias, privateKeyEntry);

//                // Creating the signing token
//                Pkcs12SignatureToken pkcs12SignatureToken = new Pkcs12SignatureToken(certificatePath, new KeyStore.PasswordProtection(certificatePassword.toCharArray()));

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


    public void signAsic(String inputPath[], String outputPath, String certificatePath, String certificatePassword) {
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


    public boolean validateCertificate(String certPath) {
        // Firstly, we load the certificate to be validated
        CertificateToken token = DSSUtils.loadCertificate(new File(certPath));

        // We need a certificate verifier and configure it  (see specific chapter about the CertificateVerifier configuration)
        CertificateVerifier cv = new CommonCertificateVerifier();

        // We create an instance of the CertificateValidator with the certificate
        CertificateValidator validator = CertificateValidator.fromCertificate(token);
        validator.setCertificateVerifier(cv);

        // We execute the validation
        CertificateReports certificateReports = validator.validate();

        // We have 3 reports
        // The diagnostic data which contains all used and static data
        DiagnosticData diagnosticData = certificateReports.getDiagnosticData();

        // The detailed report which is the result of the process of the diagnostic data and the validation policy
        DetailedReport detailedReport = certificateReports.getDetailedReport();

        // The simple report is a summary of the detailed report or diagnostic data (more user-friendly)
        SimpleCertificateReport simpleReport = certificateReports.getSimpleReport();

        String firstCert = simpleReport.getCertificateIds().get(0);

        Date notAfter = simpleReport.getCertificateNotAfter(firstCert);
        Date notBefore = simpleReport.getCertificateNotBefore(firstCert);
        Date now = new Date();

        // Checking whether the certificate is valid
        boolean valid = false;
        if (notBefore.after(now) || notAfter.before(now)) {
            valid = true;
        }

        boolean isValid = token.isSignatureValid();

        // Returning the simple report
        return isValid;
    }

}
