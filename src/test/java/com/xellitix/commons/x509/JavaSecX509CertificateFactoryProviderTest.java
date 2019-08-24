package com.xellitix.commons.x509;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.cert.CertificateFactory;
import org.junit.Before;
import org.junit.Test;

/**
 * {@link JavaSecX509CertificateFactoryProvider} test case.
 *
 * @author Grayson Kuhns
 */
public class JavaSecX509CertificateFactoryProviderTest {

  // Fixtures
  private JavaSecX509CertificateFactoryProvider certificateFactoryProvider;

  @Test
  public void certificateFactory__IsProvided__Test() {
    assertThat(certificateFactoryProvider
        .get())
        .isNotNull()
        .isInstanceOf(CertificateFactory.class);
  }

  @Test
  public void certificateFactory__HandlesX509__Test() {
    assertThat(certificateFactoryProvider
        .get()
        .getType())
        .isNotNull()
        .isEqualTo("X509");
  }

  @Before
  public void setUp() {
    certificateFactoryProvider = new JavaSecX509CertificateFactoryProvider();
  }
}
