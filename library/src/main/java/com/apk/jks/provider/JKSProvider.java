package com.apk.jks.provider;

import com.apk.jks.pkcs12.PKCS12KeyStore;
import com.apk.jks.provider.JavaKeyStore.JKS;
import com.apk.jks.provider.JavaKeyStore.CaseExactJKS;

import java.security.Provider;
import java.security.Security;

/*
 * Created by APK Explorer & Editor <apkeditor@protonmail.com> on October 19, 2021
 * Based on the original work of @MuntashirAkon for https://github.com/MuntashirAkon/sun-security-android
 * Ref: https://github.com/MuntashirAkon/sun-security-android/blob/master/src/main/java/android/sun/security/provider/JavaKeyStoreProvider.java
 */
public class JKSProvider extends Provider {

    public JKSProvider() {
        super("JKS", 1.0D, "Java KeyStore");
        this.put("KeyStore.JKS", JKS.class.getName());
        this.put("KeyStore.CaseExactJKS", CaseExactJKS.class.getName());
        this.put("KeyStore.PKCS12", PKCS12KeyStore.class.getName());
        Security.setProperty("keystore.type", "jks");
    }

}