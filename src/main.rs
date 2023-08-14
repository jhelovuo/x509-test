use std::fs::File;
use std::io::{Write, Read, Seek, SeekFrom};
use std::process::Command;

use x509_certificate::certificate::{CapturedX509Certificate};

fn main() {
    let document = r#"MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha-256"; boundary="----26B97E9080C33B5E9E82D8FDC0946E23"

This is an S/MIME signed message

------26B97E9080C33B5E9E82D8FDC0946E23
Content-Type: text/plain

<?xml version="1.0" encoding="utf-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-Security/20170801/omg_shared_ca_domain_governance.xsd">
  <domain_access_rules>
    <domain_rule>
      <domains>
        <id>0</id>
      </domains>

      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <rtps_protection_kind>SIGN</rtps_protection_kind>
      <discovery_protection_kind>SIGN</discovery_protection_kind>
      <liveliness_protection_kind>SIGN</liveliness_protection_kind>

      <topic_access_rules>
        <topic_rule>
          <topic_expression>Square*</topic_expression>
          <enable_discovery_protection>true
          </enable_discovery_protection>
          <enable_liveliness_protection>false</enable_liveliness_protection>
          <enable_read_access_control>true
          </enable_read_access_control>
          <enable_write_access_control>true
          </enable_write_access_control>
          <metadata_protection_kind>ENCRYPT
          </metadata_protection_kind>
          <data_protection_kind>ENCRYPT
          </data_protection_kind>
        </topic_rule>
      </topic_access_rules>
    </domain_rule>
  </domain_access_rules>
</dds>

------26B97E9080C33B5E9E82D8FDC0946E23
Content-Type: application/x-pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

MIIC+QYJKoZIhvcNAQcCoIIC6jCCAuYCAQExDzANBglghkgBZQMEAgEFADALBgkq
hkiG9w0BBwGgggE/MIIBOzCB4qADAgECAhR361786/qVPfJWWDw4Wg5cmJUwBTAK
BggqhkjOPQQDAjASMRAwDgYDVQQDDAdzcm9zMkNBMB4XDTIzMDcyMzA4MjgzNloX
DTMzMDcyMTA4MjgzNlowEjEQMA4GA1UEAwwHc3JvczJDQTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABMpvJQ/91ZqnmRRteTL2qaEFz2d7SGAQQk9PIhhZCV1tlLwY
f/hI4xWLJaEv8FxJTjxXRGJ1U+/IqqqIvJVpWaSjFjAUMBIGA1UdEwEB/wQIMAYB
Af8CAQEwCgYIKoZIzj0EAwIDSAAwRQIgEiyVGRc664+/TE/HImA4WNwsSi/alHqP
YB58BWINj34CIQDDiHhbVPRB9Uxts9CwglxYgZoUdGUAxreYIIaLO4yLqzGCAX4w
ggF6AgEBMCowEjEQMA4GA1UEAwwHc3JvczJDQQIUd+te/Ov6lT3yVlg8OFoOXJiV
MAUwDQYJYIZIAWUDBAIBBQCggeQwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
BgkqhkiG9w0BCQUxDxcNMjMwODE0MDc1NDQxWjAvBgkqhkiG9w0BCQQxIgQgvAEn
eveae5s8eNw0HdhAcxPkLpHI3cdiMLrX5U6hwNoweQYJKoZIhvcNAQkPMWwwajAL
BglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAKBggqhkiG9w0D
BzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZI
hvcNAwICASgwCgYIKoZIzj0EAwIERzBFAiAZQGxjfAoLlk99UWV5AYkHr1CGvOrn
X/iBDEnMibF4NAIhAPB45KRXnnC8QmjYByycsOo4uGDrrUZ4K+tWLBfOv8v9

------26B97E9080C33B5E9E82D8FDC0946E23--
"#;
    let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIIBOzCB4qADAgECAhR361786/qVPfJWWDw4Wg5cmJUwBTAKBggqhkjOPQQDAjAS
MRAwDgYDVQQDDAdzcm9zMkNBMB4XDTIzMDcyMzA4MjgzNloXDTMzMDcyMTA4Mjgz
NlowEjEQMA4GA1UEAwwHc3JvczJDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BMpvJQ/91ZqnmRRteTL2qaEFz2d7SGAQQk9PIhhZCV1tlLwYf/hI4xWLJaEv8FxJ
TjxXRGJ1U+/IqqqIvJVpWaSjFjAUMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYIKoZI
zj0EAwIDSAAwRQIgEiyVGRc664+/TE/HImA4WNwsSi/alHqPYB58BWINj34CIQDD
iHhbVPRB9Uxts9CwglxYgZoUdGUAxreYIIaLO4yLqw==
-----END CERTIFICATE-----
"#;

    // First, use OpenSSL to ensure input is sane.
    let mut doc_file = tempfile::NamedTempFile::new().unwrap();
    doc_file.write_all(document.as_bytes()).unwrap();
    

    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();

    let openssl_output = 
        Command::new("openssl")
            .args(["smime", "-verify", "-text",  "-in"])
            .arg(doc_file.path())
            .arg("-CAfile")
            .arg(cert_file.path())
            .output()
            .unwrap();

    println!("openssl: {}", 
        String::from_utf8_lossy(&openssl_output.stderr));


    // Now try decoding & verify in Rust
    let parsed_s_mime = mailparse::parse_mail(document.as_bytes())
        .unwrap();

    match parsed_s_mime.subparts.as_slice() {
      [doc_content, signature] => {
        let content = doc_content.get_body_raw().unwrap();
        let signature_der = signature.get_body_raw().unwrap();
        //let signature_pem = 
        //    pem::encode(&pem::Pem::new("CERTIFICATE", signature_der.clone()));
                

        let cert = CapturedX509Certificate::from_pem(cert_pem).unwrap();

        //println!("{signature_pem:?}");
        println!("{cert:?}");

        println!("Verifying in Rust");
        cert.verify_signed_data(content, signature_der).unwrap();
        println!("Verification ok");
      }
      _  => panic!("Expected two subparts"),
    }
}


