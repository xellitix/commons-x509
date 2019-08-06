package com.xellitix.commons.x509;

import com.google.inject.Provider;
import java.security.cert.CertificateFactory;

/**
 * X509 {@link CertificateFactory} {@link Provider}.
 *
 * @author Grayson Kuhns
 */
public interface X509CertificateFactoryProvider extends Provider<CertificateFactory> {
}
