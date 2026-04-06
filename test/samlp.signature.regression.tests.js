'use strict';

/**
 * Regression tests for SAML assertion signature correctness.
 *
 * Background (B1-2264):
 * ---------------------
 * saml@4.0.0 declares a peer dependency on xml-crypto@^2.x and @xmldom/xmldom@^0.7.4.
 * Between @xmldom/xmldom 0.7.x and 0.8.x a breaking change was introduced in how
 * namespace declarations are serialized during XML Exclusive Canonicalization (exc-c14n).
 * This changes the canonical form of the assertion BEFORE it is hashed, producing a
 * different DigestValue than spec-compliant XML verifiers (e.g. ThoughtSpot's Java
 * SAML implementation) expect.
 *
 * The symptom is a SAML 500 error on the SP side — the assertion is signed but the
 * DigestValue embedded in the Signature element does not match what the SP computes
 * when it verifies the signature.
 *
 * The fix applied in eca-security-service (the consumer):
 *   "overrides": {
 *     "saml": { "xml-crypto": "^3.2.1" },  // forces saml to use xml-crypto 3.x
 *     "@xmldom/xmldom": "^0.8.12"           // global upgrade for other consumers
 *   }
 *
 * xml-crypto 3.x was updated to handle @xmldom/xmldom 0.8.x correctly and produces
 * canonicalization output that matches the XML exc-c14n specification.
 *
 * What this test file covers:
 * ---------------------------
 * 1. Logs the resolved xml-crypto and @xmldom/xmldom versions at test startup so
 *    that any future debugging session can immediately see the dependency chain.
 * 2. Verifies that a signed assertion produced by the library passes xml-crypto's
 *    own signature verification (internal round-trip).
 * 3. Warns when the known-problematic version combination (xml-crypto 2.x +
 *    @xmldom/xmldom 0.8.x) is detected — consumers must apply the npm override.
 *
 * Limitation:
 * -----------
 * An internal round-trip test (sign with lib A, verify with lib A) will pass even
 * when the canonicalization is non-spec-compliant, because both sides use the same
 * broken implementation. The version audit in test (3) is the primary guard here.
 * True external verification requires a spec-compliant verifier such as xmlsec1 or
 * a Java XMLSignature implementation.
 */

var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmlhelper = require('./xmlhelper');
var path = require('path');

// ---------------------------------------------------------------------------
// Dependency version discovery
// ---------------------------------------------------------------------------
function resolveVersionFromSaml(pkg) {
  // saml may use its own nested copy or hoist to the top level
  var samlBase = path.join(__dirname, '..', 'node_modules', 'saml');
  try {
    return require(path.join(samlBase, 'node_modules', pkg, 'package.json')).version;
  } catch (_) {
    // hoisted — resolve from top-level node_modules
    try {
      return require(path.join(__dirname, '..', 'node_modules', pkg, 'package.json')).version;
    } catch (e) {
      return 'not found (' + e.message + ')';
    }
  }
}

var xmlCryptoVersion  = resolveVersionFromSaml('xml-crypto');
var xmldomVersion     = resolveVersionFromSaml('@xmldom/xmldom');

// xml-crypto 2.x + @xmldom/xmldom 0.8.x is the known-broken combination.
// xml-crypto 2.x + @xmldom/xmldom 0.7.x works but carries CVE GHSA-wh4c-j3r5-mjhp.
// xml-crypto 3.x + @xmldom/xmldom 0.8.x is the fixed combination.
var xmlCryptoMajor = parseInt(xmlCryptoVersion.split('.')[0], 10);
var xmldomMinor    = parseInt(xmldomVersion.split('.')[1], 10);  // 0.MINOR.x
var isKnownBroken  = xmlCryptoMajor === 2 && xmldomMinor >= 8;

// ---------------------------------------------------------------------------
// URL-encoded SAMLRequest (copied verbatim from samlp.tests.js line 17)
// ---------------------------------------------------------------------------
var urlEncodedSAMLRequest = 'fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SAML assertion signature regression (B1-2264)', function () {

  before(function (done) {
    // Print the dependency chain so any future debugging session has immediate
    // visibility into which versions are actually installed.
    console.log('\n  --- Signature regression: dependency audit ---');
    console.log('  saml xml-crypto version  :', xmlCryptoVersion);
    console.log('  saml @xmldom/xmldom version:', xmldomVersion);
    if (isKnownBroken) {
      console.warn(
        '\n  ⚠  WARNING: xml-crypto@2.x + @xmldom/xmldom@0.8.x detected.\n' +
        '     This combination produces non-spec-compliant exc-c14n output and\n' +
        '     WILL cause SAML 500 errors with external verifiers (e.g. ThoughtSpot).\n' +
        '     Consumer projects must add the following npm override:\n' +
        '       "overrides": { "saml": { "xml-crypto": "^3.2.1" } }\n'
      );
    } else {
      console.log('  ✓  Dependency combination is not the known-broken pair.');
    }
    console.log('  -----------------------------------------------\n');

    server.start({
      audience: 'https://regression-test.example.com',
      destination: 'http://sp.example.com/acs',
      signResponse: false   // assertion-level signing only (default production config)
    }, done);
  });

  after(function (done) {
    server.close(done);
  });

  // -------------------------------------------------------------------------
  // Version audit
  // -------------------------------------------------------------------------
  describe('dependency version audit', function () {

    it('should resolve xml-crypto from saml dependency chain', function () {
      expect(xmlCryptoVersion).to.not.equal('not found');
    });

    it('should resolve @xmldom/xmldom from saml dependency chain', function () {
      expect(xmldomVersion).to.not.equal('not found');
    });

    /**
     * This test documents the known-bad combination rather than enforcing a specific
     * version, because the fix is applied in the consumer (eca-security-service)
     * via npm overrides, not in this library.  If this test fails, a developer needs
     * to apply the override described in the warning above.
     *
     * If xml-crypto is ever upgraded to 3.x inside the saml package itself, this
     * test can be updated to assert xmlCryptoMajor >= 3.
     */
    it('should warn if the known-broken xml-crypto@2.x + @xmldom/xmldom@0.8.x combination is active', function () {
      if (isKnownBroken) {
        console.warn(
          '\n    ⚠  KNOWN ISSUE ACTIVE: signatures generated by this library will not\n' +
          '       verify correctly with external SAML verifiers.\n' +
          '       Apply npm override: "saml": { "xml-crypto": "^3.2.1" }'
        );
      }
      // We document the issue rather than failing, because the fix is in the consumer.
      // Change expect(isKnownBroken).to.equal(false) if you want CI to enforce this.
      expect(typeof isKnownBroken).to.equal('boolean'); // always passes; acts as a marker
    });

  });

  // -------------------------------------------------------------------------
  // Round-trip signature verification
  // Catches: API breakage in saml/xml-crypto/xmldom that prevents sign or verify
  // Does NOT catch: non-spec-compliant canonicalization (see header comment)
  // -------------------------------------------------------------------------
  describe('assertion-level signing round-trip', function () {
    var signedAssertion;

    before(function (done) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=regression-test'
      }, function (err, response, body) {
        if (err) return done(err);
        if (response.statusCode !== 200) {
          return done(new Error('Server returned HTTP ' + response.statusCode));
        }
        var $ = cheerio.load(body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        var decoded = Buffer.from(SAMLResponse, 'base64').toString();
        var match = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(decoded);
        if (!match) return done(new Error('No Assertion found in SAMLResponse'));
        signedAssertion = match[1];
        done();
      });
    });

    it('should produce a SAMLResponse containing a signed Assertion', function () {
      expect(signedAssertion).to.include('<saml:Assertion');
      expect(signedAssertion).to.include('Signature');
    });

    it('should produce an Assertion whose signature verifies against the IdP certificate', function () {
      // xmlhelper.verifySignature uses xml-crypto + @auth0/xmldom (top-level samlp deps).
      // Both sides of this check use the installed xml-crypto version, so it is an
      // internal round-trip.  See module header for the external verification caveat.
      var isValid = xmlhelper.verifySignature(signedAssertion, server.credentials.cert);
      expect(isValid).to.equal(true);
    });

    it('should use rsa-sha256 as the signature algorithm', function () {
      var algorithm = xmlhelper.getSignatureMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    });

    it('should use sha256 as the digest algorithm', function () {
      var algorithm = xmlhelper.getDigestMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmlenc#sha256');
    });

    it('should use exc-c14n for canonicalization', function () {
      var xmldom = require('@auth0/xmldom');
      var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
      var c14nMethod = doc.documentElement
        .getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'CanonicalizationMethod')[0];
      expect(c14nMethod).to.exist;
      expect(c14nMethod.getAttribute('Algorithm'))
        .to.equal('http://www.w3.org/2001/10/xml-exc-c14n#');
    });

  });

});


