module Onelogin
  module Saml
    module SecurityStrategies
      module XMLSec
        REQUIRED_GEM = 'xml_security'
        REQUIRED_VERSION = '0.0.3'
        DSIG = {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}

        def self.is?(sym)
          sym == :xmlsec
        end

        def self.extended(base)
          begin
            gem REQUIRED_GEM, REQUIRED_VERSION
            require REQUIRED_GEM
          rescue LoadError => e
            puts "In order to use the XMLSec strategy with ruby-saml, the xml_security gem must be installed"
            raise
          end
        end

        def validate(idp_cert_fingerprint, soft = true)
          @idp_cert_fingerprint = idp_cert_fingerprint
          validate_doc(nil, soft)
        end

        def validate_doc(base64_cert, soft = true)
          options = {}
          if @idp_cert_fingerprint
            options[:cert_fingerprint] = @idp_cert_fingerprint
          end

          fix_incorrect_hrefs
          massage_x509_certificate

          result = ::XMLSecurity.verify_signature(self.to_s, options)

          if result.success?
            true
          else
            soft ? false : _raise_for_result(result)
          end
        end

        def fix_incorrect_hrefs
          xpaths_to_check = [
            "//ds:SignatureMethod",
            "//ds:DigestMethod",
          ]
          fixable_hrefs = {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2001/04/xmlenc#sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
          }
          xpaths_to_check.each do |xpath|
            element = REXML::XPath.first(self, xpath, DSIG)
            if fixable_hrefs.keys.include? element.attributes["Algorithm"]
              element.add_attribute("Algorithm", fixable_hrefs[element.attributes["Algorithm"]])
            end
          end
        end

        def massage_x509_certificate
          cert_element = REXML::XPath.first(self, "//ds:X509Certificate", DSIG)
          base64_cert  = cert_element.text
          cert_text    = Base64.decode64(base64_cert)
          cert         = OpenSSL::X509::Certificate.new(cert_text)
          cert_element.text = Base64.strict_encode64(cert.to_der)
        end

        def _raise_for_result(result)
          if result.fingerprint_mismatch?
            raise Onelogin::Saml::ValidationError.new("Fingerprint mismatch")
          elsif result.digest_mismatch?
            raise Onelogin::Saml::ValidationError.new("Digest mismatch")
          elsif result.signature_mismatch?
            raise Onelogin::Saml::ValidationError.new("Key validation error")
          else
            raise Onelogin::Saml::ValidationError.new(result.message)
          end
        end
      end
    end
  end
end
