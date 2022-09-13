# frozen_string_literal: true

require "openssl"
require "base64"
require "json"

require_relative "dev_sandbox_ruby/version"

module DevSandboxRuby
  class Error < StandardError; end

  def self.create_content_signature(timestamp, payload, partner_privkey_path)
    privkey = OpenSSL::PKey::RSA.new(File.read(partner_privkey_path))
    digest = OpenSSL::Digest::SHA256.new
    data = timestamp + JSON.parse(payload.read).to_json
    signature = privkey.sign(digest, data)
    content_signature = Base64.encode64(signature)
    return content_signature
  end

  def self.verify_content_signature(encode_signature, data, truemoney_pubkey_path)
    pubkey = OpenSSL::PKey::RSA.new(File.read(truemoney_pubkey_path))
    digest = OpenSSL::Digest::SHA256.new
    signature = Base64.decode64(encode_signature)
    result = pubkey.verify(digest, signature, data)
    return result
  end
end
