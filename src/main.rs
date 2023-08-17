use std::io::Write;
use std::process::Command;

use x509_certificate::certificate::{CapturedX509Certificate};
use cms::signed_data::{SignedData,EncapsulatedContentInfo,};
use cms::attr::MessageDigest;
use der::{Encode,Decode};

use ring::{signature, digest};

use similar::{TextDiff, ChangeTag};

fn main() {

    let document = r#"MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha-256"; boundary="----F829CEB469DB45AAA9B96DE7DBD3C46C"

This is an S/MIME signed message

------F829CEB469DB45AAA9B96DE7DBD3C46C
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

------F829CEB469DB45AAA9B96DE7DBD3C46C
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
BgkqhkiG9w0BCQUxDxcNMjMwODE1MTIyNDI5WjAvBgkqhkiG9w0BCQQxIgQgvAEn
eveae5s8eNw0HdhAcxPkLpHI3cdiMLrX5U6hwNoweQYJKoZIhvcNAQkPMWwwajAL
BglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAKBggqhkiG9w0D
BzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZI
hvcNAwICASgwCgYIKoZIzj0EAwIERzBFAiAPZrU1Lb9q0q3sJXhJXsgB2X126Ays
fR/9Ru33iDhguAIhAIfqXvklH3HzFYnnthdHdyccBfqx09IY0x0ZRPDetB03

------F829CEB469DB45AAA9B96DE7DBD3C46C--

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
            .args(["smime", "-verify", /*"-text",*/ "-in"])
            .arg(doc_file.path())
            .arg("-CAfile")
            .arg(cert_file.path())
            .output()
            .unwrap();

    println!("openssl: {}\n", 
        String::from_utf8_lossy(&openssl_output.stderr));


    // Now try decoding & verify in Rust
    let parsed_s_mime = mailparse::parse_mail(document.as_bytes())
        .unwrap();

    match parsed_s_mime.subparts.as_slice() {
      [doc_content, signature] => {

        let mut content = Vec::<u8>::from(doc_content.raw_bytes);

        // to remove extra newline at end. mailparse seems to add this.
        content.pop();

        // OpenSSL has converted to MS-DOS line endings when MIME encoding.
        let newline = regex::bytes::Regex::new("\n").unwrap();
        let content = newline.replace_all(&content, b"\r\n").into_owned();

        if content == openssl_output.stdout {
            println!("Contents match");
        } else {
            let c = String::from_utf8_lossy( &content );
            let o = String::from_utf8_lossy( &openssl_output.stdout);
            let diff = TextDiff::from_lines( &c, &o );
            println!("-- contents diff:");
            for c in diff.iter_all_changes() {
                if c.tag() != ChangeTag::Equal {
                    println!("{c:?}");
                }
            }
            println!("-- contents diff end");
        }
        let contents_digest = digest::digest(&digest::SHA256, &content);
        println!("computed contents digest: {:?}", contents_digest);

        let signature_der = signature.get_body_raw().unwrap();

        let signature_encap = 
            EncapsulatedContentInfo::from_der(&signature_der).unwrap();
        let signature_oid = const_oid::ObjectIdentifier::
            new_unwrap("1.2.840.113549.1.7.2"); 
            // The SignedData type is defined in RFC 5652 Section 5.1.
            // OpenSSL calls this "pkcs7-signedData (1.2.840.113549.1.7.2)"
        assert!(signature_encap.econtent_type == signature_oid);
        // it is a signature
        let signed_data = match signature_encap.econtent {
          None => panic!("Empty signature container??"),
          Some(sig) =>
            sig.decode_as::<SignedData>().unwrap()
        };

        let signer_info = signed_data.signer_infos.0.get(0).unwrap();
        //println!("Signer_Info: {:?}\n", signer_info);

        let (message_digest, bytes_to_digest) = 
            match &signer_info.signed_attrs {
                None => panic!("Signature has no signed_attrs"),
                Some(sas) => {
                    println!("signed_attrs bytes={:02x?}\ndebug=\n{:?}",sas.to_der(), sas );
                    match sas.iter().find(|attr| attr.oid == 
                      const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4")) {
                        None => panic!("No message digest in signature"),
                        Some(attr) => 
                            ( attr.values.get(0).unwrap().decode_as::<MessageDigest>().unwrap(),
                              sas.to_der().unwrap() ),
                    }
                }
            };
        println!("signature message_digest = {:02x?}",message_digest.as_bytes() );

        // check that the hash in signature matches value computed from content
        assert_eq!(message_digest.as_bytes(), contents_digest.as_ref());

        let sig_bytes = signer_info.signature.as_bytes();      
        println!("signature ASN.1 data: {sig_bytes:?}\n");


        let cert = CapturedX509Certificate::from_pem(cert_pem).unwrap();
        //println!("{cert:?}\n");

        println!("Verifying with x509-certificate");

        // Force using elliptic curve P256, because that is what OpenSSL claims the
        // certificate to use. 
        //      algorithm: id-ecPublicKey (1.2.840.10045.2.1)
        //      parameter: OBJECT:prime256v1 (1.2.840.10045.3.1.7)
        // It seems that x509-certificate auto-detection 
        // just defaults to P384.
        let verify_result =
         cert.verify_signed_data_with_algorithm(&bytes_to_digest, sig_bytes,
             &signature::ECDSA_P256_SHA256_ASN1);
        println!("verify_result = {verify_result:?}");
      }
      _  => panic!("Expected two subparts"),
    }
}


