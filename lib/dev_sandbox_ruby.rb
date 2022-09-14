# frozen_string_literal: true

require_relative "dev_sandbox_ruby/version"

module DevSandboxRuby
  class Error < StandardError; end
  class InvalidRequestHeaderError < Error; end

  def self.create_content_signature(timestamp, payload, partner_privkey_path)
    privkey = OpenSSL::PKey::RSA.new(File.read(partner_privkey_path))
    digest = OpenSSL::Digest::SHA256.new
    data = timestamp + JSON.generate(payload)
    signature = privkey.sign(digest, data)
    content_signature = Base64.strict_encode64(signature)
    return "digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data=#{content_signature}"
  end

  def self.verify_content_signature(timestamp, content_signature, payload, truemoney_pubkey_path)
    pubkey = OpenSSL::PKey::RSA.new(File.read(truemoney_pubkey_path))
    digest = OpenSSL::Digest::SHA256.new
    unless content_signature.match(/digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data=(\S+)/)
      raise InvalidRequestHeaderError, "Invalid Content-Signature header"
    end
    encoded_signature = content_signature.match(/digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data=(\S+)/)[1]
    signature = Base64.decode64(encoded_signature)
    data = timestamp + JSON.generate(payload).to_json
    result = pubkey.verify(digest, signature, data)
    return result
  end
end
