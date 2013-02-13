# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require 'nokogiri'
require "digest/sha1"
require "digest/sha2"
require "onelogin/ruby-saml/validation_error"
require "onelogin/ruby-saml/security_strategies/pure_ruby"
require "onelogin/ruby-saml/security_strategies/xml_sec"

module Onelogin
  module Saml
    module XMLSecurity
      STRATEGIES = [
        Onelogin::Saml::SecurityStrategies::PureRuby,
        Onelogin::Saml::SecurityStrategies::XMLSec
      ]
      C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"

      class SignedDocument < REXML::Document
        attr_accessor :signed_element_id

        def initialize(response, strategy=Onelogin::Saml::SecurityStrategies::PureRuby)
          super(response)
          self.extend(strategy)
          extract_signed_element_id
        end

        def extract_signed_element_id
          reference_element       = REXML::XPath.first(self, "//ds:Signature/ds:SignedInfo/ds:Reference", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})
          self.signed_element_id  = reference_element.attribute("URI").value[1..-1] unless reference_element.nil?
        end

        def extract_inclusive_namespaces
          if element = REXML::XPath.first(self, "//ec:InclusiveNamespaces", { "ec" => C14N })
            prefix_list = element.attributes.get_attribute("PrefixList").value
            prefix_list.split(" ")
          else
            []
          end
        end
      end
    end
  end
end
