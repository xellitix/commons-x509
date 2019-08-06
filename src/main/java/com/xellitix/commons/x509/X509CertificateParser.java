package com.xellitix.commons.x509;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * {@link X509Certificate} parser.
 *
 * @author Grayson Kuhns
 */
public interface X509CertificateParser {

  /**
   * Parses an {@link X509Certificate}.
   *
   * @param certificate The certificate data.
   * @return The {@link X509Certificate}.
   * @throws CertificateException If an error occurs while parsing the {@link X509Certificate}.
   */
  X509Certificate parse(String certificate) throws CertificateException;
}
