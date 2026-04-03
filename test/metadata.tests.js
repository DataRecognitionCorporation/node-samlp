var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var xmldom = require('@auth0/xmldom');

function certToPem (cert) {
  var pem = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(cert.toString());
  if (pem.length > 0) {
    return pem[1].replace(/[\n|\r\n]/g, '');
  }
  return null;
}

describe('samlp metadata', function () {
  before(function (done) {
    server.start(done);
  });

  after(function (done) {
    server.close(done);
  });

  describe('request to metadata', function (){
    var doc, content;
    before(function (done) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp/FederationMetadata/2007-06/FederationMetadata.xml'
      }, function (err, response, b){
        if(err) return done(err);
        content = b;
        doc = new xmldom.DOMParser().parseFromString(b).documentElement;
        done();
      });
    });

    it('should have the redirect endpoint url', function(){
      expect(doc.getElementsByTagName('SingleSignOnService')[0].getAttribute('Binding'))
        .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');

      expect(doc.getElementsByTagName('SingleSignOnService')[0].getAttribute('Location'))
        .to.equal('http://localhost:5050/samlp/123');
    });

    it('should have the POST endpoint url', function(){
      expect(doc.getElementsByTagName('SingleSignOnService')[1].getAttribute('Binding'))
        .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');

      expect(doc.getElementsByTagName('SingleSignOnService')[1].getAttribute('Location'))
        .to.equal('http://localhost:5050/login/callback');
    });

    it('should have the logout endpoint url', function(){
      expect(doc.getElementsByTagName('SingleSignOnService')[0].getAttribute('Binding'))
        .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');

      expect(doc.getElementsByTagName('SingleLogoutService')[0].getAttribute('Location'))
        .to.equal('http://localhost:5050/logout');
    });

    it('should have the claim types', function(){
      expect(doc.getElementsByTagName('Attribute'))
        .to.not.be.empty;
    });

    it('should have the issuer', function(){
      expect(doc.getAttribute('entityID'))
        .to.equal('urn:fixture-test');
    });

    it('should have the pem', function(){
      expect(doc.getElementsByTagName('X509Certificate')[0].textContent)
        .to.equal(certToPem(server.credentials.cert));
    });

    it('should not contain blank line', function(){
      expect(content)
        .to.not.contain('\n\s*\n');
    });

  });

  // DRC: x-forwarded-host is intentionally NOT applied to the host portion of
  // metadata URLs. Use options.absoluteUrls=true with absolute endpointPath
  // values when deploying behind a reverse proxy that changes the hostname.
  // x-forwarded-proto IS respected for the protocol portion.
  describe('request to metadata with proxy', function () {
    var docHost, docProto;
    before(function (done) {
      // Test that x-forwarded-host does NOT change the host in URLs
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp/FederationMetadata/2007-06/FederationMetadata.xml',
        headers: {
          'X-Forwarded-Host': 'myserver.com'
        }
      }, function (err, response, b) {
        if (err) return done(err);
        docHost = new xmldom.DOMParser().parseFromString(b).documentElement;

        // Test that x-forwarded-proto DOES change the protocol in URLs
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/samlp/FederationMetadata/2007-06/FederationMetadata.xml',
          headers: {
            'X-Forwarded-Proto': 'https'
          }
        }, function (err2, response2, b2) {
          if (err2) return done(err2);
          docProto = new xmldom.DOMParser().parseFromString(b2).documentElement;
          done();
        });
      });
    });

    it('should ignore x-forwarded-host and use the actual request host', function () {
      expect(docHost.getElementsByTagName('SingleSignOnService')[0].getAttribute('Location'))
        .to.equal('http://localhost:5050/samlp/123');
    });

    it('should ignore x-forwarded-host for the POST endpoint url', function () {
      expect(docHost.getElementsByTagName('SingleSignOnService')[1].getAttribute('Location'))
        .to.equal('http://localhost:5050/login/callback');
    });

    it('should ignore x-forwarded-host for the logout endpoint url', function () {
      expect(docHost.getElementsByTagName('SingleLogoutService')[0].getAttribute('Location'))
        .to.equal('http://localhost:5050/logout');
    });

    it('should use x-forwarded-proto for the protocol in endpoint urls', function () {
      expect(docProto.getElementsByTagName('SingleSignOnService')[0].getAttribute('Location'))
        .to.equal('https://localhost:5050/samlp/123');
    });

  });
});
