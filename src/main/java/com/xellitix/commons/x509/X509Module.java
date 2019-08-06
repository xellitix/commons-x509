package com.xellitix.commons.x509;

import com.google.inject.AbstractModule;
import java.security.cert.X509Certificate;

/**
 * {@link X509Certificate} module.
 *
 * @author Grayson Kuhns
 */
public class X509Module extends AbstractModule {

  /**
   * Configures the module.
   */
  @Override
  public void configure() {
    bind(X509CertificateFactoryProvider.class).to(JavaSecX509CertificateFactoryProvider.class);
    bind(X509CertificateParser.class).to(DefaultX509CertificateParser.class);
  }
}
