# frozen_string_literal: true

require_relative 'test_helper'
require 'resolv'
require 'socket'

# Tests for the SSRF / cross-scheme-redirect remediation in
# `CssParser::Parser#read_remote_file` and `Parser#load_uri!`
# (GHSA-9pmc-p236-855h).
#
# Pre-fix behaviour:
#   - load_uri! and @import-following accept any host, including loopback,
#     RFC-1918, link-local, and cloud-metadata IPs.
#   - HTTP 3xx responses are followed without re-validating the Location
#     scheme, so a Location: file://... turns the SSRF into local file
#     disclosure.
#   - Schemes other than http/https/file are accepted by `read_remote_file`
#     and silently treated as plain HTTP via Net::HTTP.new.
#   - Host validation is by literal hostname, not by *resolved* IP — so
#     a DNS record pointing a public-looking name at 127.0.0.1 trivially
#     bypasses any naive blocklist.
#   - `file://` URIs passed to `load_uri!` execute `File.read` against
#     any path the Ruby process can open. Combined with the redirect
#     bug above this is local file disclosure; even on its own, any
#     caller that hands a user-supplied URI to `load_uri!` is exposed.
#
# Post-fix expectations:
#   1. Loopback / private addresses are refused by default.
#   2. `file://` URIs are refused by `load_uri!` by default. `load_file!`
#      (the explicit local-file API taking a path, not a URI) is
#      unaffected.
#   3. Two independent opt-in flags restore each behaviour:
#        - `allow_local_network: true`  — re-enables HTTP to private IPs.
#        - `allow_file_uris:     true`  — re-enables `file://` via load_uri!.
#      Neither flag grants the other: setting `allow_local_network: true`
#      does NOT permit `file://`, and vice versa. The two threats
#      (CWE-918 SSRF vs CWE-73 local file disclosure) have independent
#      controls so callers can express exactly the threat-surface they
#      need open.
#   4. A 3xx response whose Location is a non-http(s) scheme is rejected
#      *before* the recursive fetch; in particular `file://` redirects
#      never reach `File.read`, even on the `allow_local_network: true`
#      code path.
#   5. Direct schemes other than http/https/file (e.g. `gopher://`,
#      `dict://`) are refused by `read_remote_file`.
#   6. Host validation runs on the resolved IP, so a CNAME / A record
#      pointing a public-looking hostname at a private address is also
#      rejected.
#
# Assertion strategy:
#   These tests assert at the *socket layer* rather than mocking
#   `Net::HTTP.new`. Mocking the HTTP client is fragile — a future
#   maintainer could swap libraries and the test would pass vacuously
#   while leaving the SSRF intact. Every Ruby HTTP client (Net::HTTP,
#   faraday, httparty, excon, ssrf_filter, raw sockets) ultimately
#   goes through one of `TCPSocket.new`, `TCPSocket.open`, or
#   `Socket.tcp`. We `expects(...).never` against all three for any
#   destination that the fix should refuse to reach.
#
#   We use `.expects(...).never` rather than `.stubs(...).raises(...)`
#   because the pre-fix code path includes a bare `rescue` that would
#   convert a stub-raised StandardError into a `RemoteFileError`,
#   falsely satisfying `assert_raises`. `.expects(...).never` instead
#   fails at teardown if the call was actually made, which is the
#   signal we want.
class CssParserSsrfTests < Minitest::Test
  include CssParser
  include WEBrick

  PORT = 12_010

  def setup
    @cp = Parser.new

    @uri_base = "http://127.0.0.1:#{PORT}"
    @loopback_base = "http://localhost:#{PORT}"

    @www_root = File.expand_path('fixtures', __dir__)
    @fixture_file = File.expand_path('fixtures/simple.css', __dir__)

    @server_thread = Thread.new do
      s = WEBrick::HTTPServer.new(
        Port: PORT, BindAddress: '127.0.0.1', DocumentRoot: @www_root,
        Logger: Log.new(nil, BasicLog::FATAL), AccessLog: []
      )

      # 302 → file:///abs/path/to/simple.css.
      # Against unfixed code this triggers File.read on the local file
      # and the response is parsed into rules. Post-fix it must raise
      # before reaching File.read.
      s.mount_proc('/redirect-to-file') do |_request, response|
        response['Location'] = "file://#{@fixture_file}"
        raise WEBrick::HTTPStatus::TemporaryRedirect
      end

      # 302 → gopher://example.com/. Non-http(s) redirect target.
      s.mount_proc('/redirect-to-gopher') do |_request, response|
        response['Location'] = 'gopher://example.com/'
        raise WEBrick::HTTPStatus::TemporaryRedirect
      end

      begin
        s.start
      ensure
        s.shutdown
      end
    end

    sleep 1
  end

  def teardown
    @server_thread.kill
    @server_thread.join(5)
    @server_thread = nil
  end

  # Reject every outbound TCP primitive used by Ruby HTTP libraries.
  # Mocha verifies expectations at end-of-test, so any escape attempt
  # surfaces as an "unsatisfied expectations" failure regardless of
  # which HTTP library made the call.
  def expect_no_outbound_tcp
    TCPSocket.expects(:new).never
    TCPSocket.expects(:open).never
    Socket.expects(:tcp).never
  end

  # ---- (1) Loopback / private addresses refused by default ----

  def test_load_uri_refuses_loopback_by_default
    expect_no_outbound_tcp
    err = assert_raises(CssParser::RemoteFileError) do
      @cp.load_uri!("#{@uri_base}/simple.css")
    end
    assert_includes err.message, '127.0.0.1'
  end

  def test_load_uri_refuses_localhost_hostname_by_default
    # `localhost` resolves to a loopback address; resolution-time check
    # must catch it, not just the literal IP.
    expect_no_outbound_tcp
    assert_raises(CssParser::RemoteFileError) do
      @cp.load_uri!("#{@loopback_base}/simple.css")
    end
  end

  def test_at_import_to_loopback_is_refused_by_default
    expect_no_outbound_tcp
    css_block = %(@import "#{@uri_base}/simple.css";)
    assert_raises(CssParser::RemoteFileError) do
      @cp.add_block!(css_block, base_uri: 'http://example.com/')
    end
  end

  def test_load_uri_refuses_link_local_imds_by_default
    # 169.254.169.254 is the AWS/GCP/Azure IMDS address. No real request
    # should be attempted — the address check must reject it before
    # any TCP connect.
    expect_no_outbound_tcp
    assert_raises(CssParser::RemoteFileError) do
      @cp.load_uri!('http://169.254.169.254/latest/meta-data/')
    end
  end

  def test_load_uri_refuses_rfc1918_by_default
    expect_no_outbound_tcp
    assert_raises(CssParser::RemoteFileError) do
      @cp.load_uri!('http://10.0.0.1/x.css')
    end
  end

  # ---- (2) Opt-in flags: defaults and per-flag opt-in ----

  def test_allow_local_network_default_is_false
    # Encoded so a future maintainer can't flip the default without
    # consciously changing this test.
    cp = Parser.new
    assert_equal false, cp.instance_variable_get(:@options)[:allow_local_network]
  end

  def test_allow_file_uris_default_is_false
    cp = Parser.new
    assert_equal false, cp.instance_variable_get(:@options)[:allow_file_uris]
  end

  def test_allow_local_network_opt_in_permits_loopback
    cp = Parser.new(allow_local_network: true)
    cp.load_uri!("#{@uri_base}/simple.css")
    assert_equal 'margin: 0px;', cp.find_by_selector('p').join(' ')
  end

  def test_allow_file_uris_opt_in_permits_file_scheme
    cp = Parser.new(allow_file_uris: true)
    cp.load_uri!("file://#{@fixture_file}")
    assert_equal 'margin: 0px;', cp.find_by_selector('p').join(' ')
  end

  # ---- (3) Flag independence: each flag only grants its own threat surface ----

  def test_allow_local_network_does_not_permit_file_uris
    # Setting `allow_local_network: true` re-enables HTTP-to-private-IPs,
    # but `file://` via load_uri! is gated by a separate option and
    # must remain refused.
    File.expects(:read).never
    cp = Parser.new(allow_local_network: true)
    assert_raises(CssParser::RemoteFileError) do
      cp.load_uri!("file://#{@fixture_file}")
    end
  end

  def test_allow_file_uris_does_not_permit_local_network
    # Setting `allow_file_uris: true` re-enables `file://`, but HTTP
    # to private IPs is gated by a separate option and must remain
    # refused. Test against IMDS to make the SSRF concern visible.
    expect_no_outbound_tcp
    cp = Parser.new(allow_file_uris: true)
    assert_raises(CssParser::RemoteFileError) do
      cp.load_uri!('http://169.254.169.254/latest/meta-data/')
    end
  end

  # ---- (4) Cross-scheme redirect to file:// blocked ----

  def test_redirect_to_file_scheme_is_refused
    # The pre-fix bug: a 302 Location: file://... triggers File.read on
    # the redirect target. After the fix the redirect must be rejected
    # before any File.read happens — and this remains true even on the
    # `allow_local_network: true` opt-in path (which uses plain
    # Net::HTTP with manual redirect handling).
    File.expects(:read).never

    err = assert_raises(CssParser::RemoteFileError) do
      Parser.new(allow_local_network: true, allow_file_uris: true)
            .load_uri!("#{@uri_base}/redirect-to-file")
    end
    refute_includes err.message.downcase, 'simple.css',
      'error must surface the redirect URL, not silently follow into File.read'
  end

  def test_redirect_to_file_scheme_via_import_is_refused
    File.expects(:read).never

    css_block = %(@import "#{@uri_base}/redirect-to-file";)
    assert_raises(CssParser::RemoteFileError) do
      Parser.new(allow_local_network: true, allow_file_uris: true)
            .add_block!(css_block, base_uri: 'http://example.com/')
    end
  end

  def test_direct_file_scheme_via_load_uri_refused_by_default
    # `load_uri!('file://...')` would otherwise be a local-file-read
    # primitive whenever the URI argument is influenced by user input
    # (e.g. resolved from a CSS @import against an attacker-controlled
    # base_uri). Gated behind `allow_file_uris` independently of any
    # SSRF protection.
    File.expects(:read).never
    assert_raises(CssParser::RemoteFileError) do
      @cp.load_uri!("file://#{@fixture_file}")
    end
  end

  def test_load_file_is_not_gated
    # `load_file!` takes an explicit path from the caller, not a URI
    # that might have been influenced by an attacker. It is the safe
    # local-file API and must keep working with the default Parser.
    @cp.load_file!(@fixture_file)
    assert_equal 'margin: 0px;', @cp.find_by_selector('p').join(' ')
  end

  # ---- (5) Non-http(s) schemes rejected by read_remote_file ----

  def test_redirect_to_non_http_scheme_is_refused
    # Pre-fix: the gopher:// Location is passed straight into
    # Net::HTTP.new (because the code only special-cases https and file),
    # which then attempts gopher's default port 70 against example.com.
    # Post-fix: rejected by scheme check on the redirect hop.
    #
    # We can't socket-assert on "no connect to example.com" here because
    # the *initial* fetch to the WEBrick redirector IS a legitimate TCP
    # call that mocha would otherwise flag as unexpected. The
    # `assert_raises` is the signal that matters; the gopher port being
    # unreachable in pre-fix gives a passing-by-accident, which becomes
    # passing-by-design post-fix.
    assert_raises(CssParser::RemoteFileError) do
      Parser.new(allow_local_network: true)
            .load_uri!("#{@uri_base}/redirect-to-gopher")
    end
  end

  def test_direct_non_http_scheme_is_refused
    expect_no_outbound_tcp
    assert_raises(CssParser::RemoteFileError) do
      @cp.load_uri!('gopher://example.com/')
    end
  end

  # ---- (5) Resolution-time IP check (defeats CNAME / DNS-rebinding) ----

  def test_load_uri_refuses_hostname_that_resolves_to_loopback
    # A naive literal-hostname blocklist would let this through:
    # "evil.example.com" looks public. But the fix must resolve the
    # hostname and reject based on the *resolved* IP — otherwise a
    # CNAME or an attacker-controlled A record pointing at 127.0.0.1
    # trivially bypasses the loopback check.
    #
    # We stub Resolv (the resolver ssrf_filter uses) so the fix sees
    # 127.0.0.1 for this hostname.
    #
    # Pre-fix doesn't do its own resolution — it hands the hostname
    # directly to Net::HTTP, which goes through TCPSocket.open with
    # the literal hostname string. The `expect_no_outbound_tcp` guard
    # catches that call.
    #
    # Post-fix via ssrf_filter: Resolv is consulted, sees 127.0.0.1,
    # rejects before any TCP primitive is invoked.
    Resolv.stubs(:getaddresses).with('evil.example.com').returns(['127.0.0.1'])
    expect_no_outbound_tcp

    assert_raises(CssParser::RemoteFileError) do
      @cp.load_uri!('http://evil.example.com/foo.css')
    end
  end
end
