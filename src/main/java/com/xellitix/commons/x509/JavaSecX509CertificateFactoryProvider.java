package com.xellitix.commons.x509;

import com.google.inject.ProvisionException;
import com.google.inject.Singleton;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * {@link X509CertificateFactoryProvider} implemented using Java Security libraries.
 *
 * @author Grayson Kuhns
 */
@Singleton
public class JavaSecX509CertificateFactoryProvider implements X509CertificateFactoryProvider {

  /**
   * Gets an X509 {@link CertificateFactory}.
   *
   * @return The {@link CertificateFactory}.
   */
  @Override
  public CertificateFactory get() {
    try {
      return CertificateFactory.getInstance("X509");
    } catch (CertificateException ex) {
      throw new ProvisionException("Failed to create X509 Certificate Factory", ex);
    }
  }
}
