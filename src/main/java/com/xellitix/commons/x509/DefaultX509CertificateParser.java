package com.xellitix.commons.x509;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.xellitix.commons.encoding.base64.Base64;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Default {@link X509CertificateParser} implementation.
 *
 * @author Grayson Kuhns
 */
@Singleton
public class DefaultX509CertificateParser implements X509CertificateParser {

  // Constants
  private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
  private static final String END_CERT = "-----END CERTIFICATE-----";

  // Dependencies
  private final CertificateFactory certificateFactory;
  private final Base64 base64;

  /**
   * Constructor.
   *
   * @param certificateFactoryProvider The {@link X509CertificateFactoryProvider}.
   * @param base64 The {@link Base64}.
   */
  @Inject
  DefaultX509CertificateParser(
      final X509CertificateFactoryProvider certificateFactoryProvider,
      final Base64 base64) {

    /*
    Note that we injected a provider, rather than a factory, to avoid binding a provider
    to the generic CertificateFactory type.
     */
    this.certificateFactory = certificateFactoryProvider.get();
    this.base64 = base64;
  }

  /**
   * Parses an {@link X509Certificate}.
   *
   * @param certificate The certificate data.
   * @return The {@link X509Certificate}.
   * @throws CertificateException If an error occurs while parsing the {@link X509Certificate}.
   */
  @Override
  public X509Certificate parse(String certificate) throws CertificateException {
    // Remove boundary markers and newlines
    certificate = certificate
        .replace(BEGIN_CERT, "")
        .replace(END_CERT, "")
        .replace("\n", "")
        .trim();

    // Decode the certificate data
    final byte[] certificateData = base64.decodeToBytes(certificate);

    // Create a stream of the input
    final InputStream certificateDataStream = new ByteArrayInputStream(certificateData);

    // Create the certificate
    final Certificate cert = certificateFactory.generateCertificate(certificateDataStream);

    // Validate that the certificate is an X509 certificate
    if (!X509Certificate.class.isInstance(cert)) {
      throw new IllegalStateException(String.format(
          "Expected parsed Certificate to be an instance of %s. It was an instance of %s",
          X509Certificate.class.getName(),
          cert.getClass().getName()));
    }

    return (X509Certificate) cert;
  }
}
