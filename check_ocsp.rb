#!/usr/bin/env ruby
#
#  check_ocsp.rb
#
# == Synopsis
#   This program is able to connect to a site using
#   an x509 certificate issued by Let's Encrypt and
#   check the OCSP status of the certificate.
#   The uri to the ocsp responder is derived from the
#   certificate but verrides can be passed to look up
#   OCSP directly against an IP address:port. This
#   allows a check to bypass a caching ip address.
#   (useful to the internal Let's Encrypt team)
#
# == Examples
#   Lookup ocsp for foo.com.
#     check_ocsp.rb -n foo.com
#   Lookup ocsp for foo.com against 10.1.1.32:4744
#     check_ocsp.rb -n foo.com -o 10.1.1.32:4744
#   Working example:
#     check_ocsp.rb -n helloworld.letsencrypt.org
#
# == Usage
#   check_ocsp.rb [options]
#
# == Options
#   -h, --help          Displays help message
#   -n, --hostname      Hostname running certificate to check
#   -o, --ocsp_override Override with custom ocsp responder address
#   -c, --check         Check mode. Returns short string and exit status.
#                       Useful for sensu/nagios type alerting.
#
# == Author
#   Andrew Gabbitas (mailto:andygabby@gmail.com)
#
# == Copyright
#   Copyright (c) 2016 Andrew Gabbitas. Licensed under the MIT License:
#   https://opensource.org/licenses/mit-license.php

require 'socket'
require 'openssl'
require 'open-uri'
require 'uri'
require 'net/http'
require 'optparse'

options = {}
OptionParser.new do |opt|
  opt.separator ''
  opt.separator 'required arguments:'
  opt.on('-n', '--hostname HOSTNAME',
         'Do not include protocol.',
         'example: -n somesite.com') do |o|
    options[:cert_uri] = URI "https://#{o}/"
  end
  opt.separator 'optional arguments:'
  opt.on('-o OCSPHOST', '--ocsp-override OCSPHOST',
         'Do not include protcol.',
         'example: -o ocsp.someca.com') do |o|
    options[:ocsp] = URI "http://#{o}/"
  end
  opt.on('-c', '--check', 'Run in check mode.',
         'Useful for Sensu/Nagios alerting.',
         'Returns short array and appropriate exit status.') do
    options[:check] = true
  end
  opt.on('-h', '--help', 'Show this message and exit.') do
    puts opt
    exit 2
  end
  opt.parse!
  unless options[:cert_uri]
    puts opt
    exit 2
  end
end

# Retrieve certificate ca certificate and ocsp response
# from remote website running the certificate over https.
# and cooresponding ocsp services from issuing CA
class Certificate
  attr_accessor :ocsp_uri, :ca_issuer_uri
  attr_reader :cert, :cert_uri, :ocsp_response, :health_status,
              :detail
  def initialize(options)
    @cert_uri = options[:cert_uri]
    @cert = ret_host_cert
    @auth_info_access = parse_authority_info_access
    @ocsp_uri = @auth_info_access[:ocsp_uri]
    @ca_issuer_uri = @auth_info_access[:ca_issuer_uri]
    @ca_cert = ret_ca_cert
    @ocsp_uri = options[:ocsp] if options[:ocsp]
    @ocsp_response = ret_ocsp
    @health_status = ocsp_health_check
    @detail = ocsp_detail
  end

  def ret_host_cert
    # Get the cert we want to check
    tcp_client = TCPSocket.new(@cert_uri.hostname, @cert_uri.port)
    ssl_client = OpenSSL::SSL::SSLSocket.new(tcp_client)
    ssl_client.hostname = @cert_uri.hostname
    ssl_client.connect
    cert = OpenSSL::X509::Certificate.new(ssl_client.peer_cert)
    ssl_client.sysclose
    tcp_client.close
    cert
  end

  def parse_authority_info_access
    # Get ocsp uri and ca issuer uri from cert.
    authority_info_access =
      @cert.extensions.detect { |n| n.oid == 'authorityInfoAccess' }

    oid_data = authority_info_access.value.split "\n"
    ocsp = oid_data.detect { |n| n.start_with? 'OCSP' }
    ca_issuer = oid_data.detect { |n| n.start_with? 'CA Issuers' }

    auth_info_access = {}
    auth_info_access[:ocsp_uri] = URI ocsp[/URI:(.*)/, 1]
    auth_info_access[:ca_issuer_uri] = URI ca_issuer[/URI:(.*)/, 1]
    auth_info_access
  end

  # Retrieve ca cert from the 'CA Issuer - URI'
  # line found in the authorityInfoAccess extention of the
  # certificate, or be passed an override uri.
  def ret_ca_cert
    cert = Net::HTTP.get(@ca_issuer_uri)
    cert = OpenSSL::X509::Certificate.new(cert)
    cert
  end

  # Takes an ocsp_uri URI object, certificate
  # X509 object, and ca_cert X509 object. It then crafts
  # and sends the OCSP request to the OCSP responder.
  # GetOCSP.response can then access that response.
  def ret_ocsp
    # Build ocsp request
    digest = OpenSSL::Digest::SHA1.new
    certificate_id = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, digest)
    request = OpenSSL::OCSP::Request.new
    request.add_certid(certificate_id)
    # request ocsp from ocsp responder
    http_response =
      Net::HTTP.start @ocsp_uri.hostname, @ocsp_uri.port do |http|
        http.post @ocsp_uri.path, request.to_der,
                  'content-type' => 'application/ocsp-request'
      end
    response = OpenSSL::OCSP::Response.new(http_response.body)
    response
  end

  def ocsp_health_check
    # Exit 0 if up and 2 if critical with short status string
    data = { OK: false,
             subject: @cert.subject.to_s,
             ocsp_responder: @ocsp_uri.to_s,
             status_string: @ocsp_response.status_string
           }
    data[:OK] = true if @ocsp_response.status_string == 'successful'
    data
  end

  def ocsp_detail
    # Diplay readable details of ocsp response
    data = ["OCSP Response for: #{@cert.subject}",
            "OCSP Responder: #{@ocsp_uri}",
            "OCSP Request: #{@ocsp_response.status_string}"]
    if @ocsp_response.status_string == 'successful'
      _response_certificate_id, status, reason, revocation_time,
        this_update, next_update, extensions = @ocsp_response.basic.status[0]
      data.push("status: #{status}",
                "reason: #{reason}",
                "revocation_time: #{revocation_time}",
                "this_update: #{this_update}",
                "next_update: #{next_update}",
                "extensions: #{extensions}")
    end
    data
  end
end

def run(options)
  c = Certificate.new(options)
  if options[:check]
    puts c.health_status
  else
    puts c.ocsp_detail
  end

  if c.health_status[:OK]
    exit 0
  else
    exit 2
  end
end

begin
  run(options)
rescue
  puts errors
  exit 2
end
